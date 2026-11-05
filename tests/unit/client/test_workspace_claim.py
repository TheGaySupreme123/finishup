"""A client's workspace claim: keyed by the target's salt over the shared canonical root (ADR-051)."""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.workspace_root import (
    CanonicalWorkspaceRoot,
    RepositoryIdentityError,
    canonical_workspace_root,
    workspace_identity_preimage,
)
from finishup.client.workspace_claim import (
    WORKSPACE_CLAIM_DOMAIN,
    WORKSPACE_CLAIM_SALT_BYTES,
    new_claim_salt,
    workspace_claim,
    workspace_claim_for_root,
)
from finishup.ports.control import WorkspaceClaim, WorkspaceLocator

_SALT_A = bytes(range(32))
_SALT_B = bytes(range(32, 64))


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _git(*arguments: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=FinishUP Test",
            "-c",
            "user.email=test@finishup.invalid",
            *arguments,
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"},
    )


def _repository(path: Path) -> Path:
    path.mkdir()
    _git("-C", os.fspath(path), "init")
    (path / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    _git("-C", os.fspath(path), "add", "tracked.txt")
    _git("-C", os.fspath(path), "commit", "-m", "initial")
    return path


def test_the_digest_is_the_domain_separated_hmac_of_the_shared_preimage(tmp_path: Path) -> None:
    root = CanonicalWorkspaceRoot("directory", tmp_path)
    claim = workspace_claim_for_root(root, _SALT_A)
    expected = hmac.new(
        _SALT_A,
        b"yoetz/workspace-claim/v1\x00directory\x00" + os.fsencode(tmp_path),
        hashlib.sha256,
    ).hexdigest()
    assert claim == WorkspaceClaim(identity_kind="directory", digest="sha256:" + expected)
    assert WORKSPACE_CLAIM_DOMAIN + workspace_identity_preimage(root) == (
        b"yoetz/workspace-claim/v1\x00directory\x00" + os.fsencode(tmp_path)
    )


def test_two_machines_claim_the_same_path_with_unrelated_digests(tmp_path: Path) -> None:
    root = CanonicalWorkspaceRoot("git_common_root", tmp_path / ".git")
    first = workspace_claim_for_root(root, _SALT_A)
    second = workspace_claim_for_root(root, _SALT_B)
    assert first.identity_kind == second.identity_kind == "git_common_root"
    assert first.digest != second.digest
    # The same salt and path always give the same claim: a target reaches its own tasks again.
    assert workspace_claim_for_root(root, _SALT_A) == first


def test_the_kind_is_part_of_the_claim(tmp_path: Path) -> None:
    directory = workspace_claim_for_root(CanonicalWorkspaceRoot("directory", tmp_path), _SALT_A)
    common = workspace_claim_for_root(CanonicalWorkspaceRoot("git_common_root", tmp_path), _SALT_A)
    assert directory.digest != common.digest


def test_no_path_reaches_any_representation_of_the_claim(tmp_path: Path) -> None:
    secret_dir = tmp_path / "private-project-name"
    secret_dir.mkdir()
    claim = workspace_claim_for_root(CanonicalWorkspaceRoot("directory", secret_dir), _SALT_A)
    assert "private-project-name" not in repr(claim)
    assert claim.digest not in repr(claim)
    assert "private-project-name" not in claim.digest


@pytest.mark.parametrize(
    "salt",
    [b"", b"\x00" * 31, b"\x00" * 33, "0" * 32, bytearray(32), None],
)
def test_a_salt_is_exactly_thirty_two_bytes(tmp_path: Path, salt: object) -> None:
    with pytest.raises(ValueError, match="workspace_claim_salt_invalid"):
        workspace_claim_for_root(CanonicalWorkspaceRoot("directory", tmp_path), cast(bytes, salt))


def test_a_root_must_be_the_shared_rule_value(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="workspace_root_invalid"):
        workspace_claim_for_root(cast(CanonicalWorkspaceRoot, tmp_path), _SALT_A)


def test_new_salts_are_fresh_and_sized() -> None:
    first, second = new_claim_salt(), new_claim_salt()
    assert len(first) == len(second) == WORKSPACE_CLAIM_SALT_BYTES
    assert first != second


@pytest.mark.anyio
async def test_any_directory_of_a_repository_claims_the_same_workspace(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "repository")
    nested = repository / "src" / "deep"
    nested.mkdir(parents=True)
    linked = tmp_path / "linked"
    _git("-C", os.fspath(repository), "branch", "other")
    _git("-C", os.fspath(repository), "worktree", "add", os.fspath(linked), "other")

    claims = {
        await workspace_claim(WorkspaceLocator(os.fspath(path)), _SALT_A)
        for path in (repository, nested, linked)
    }
    assert len(claims) == 1
    (claim,) = claims
    root = await canonical_workspace_root(WorkspaceLocator(os.fspath(repository)))
    assert claim == workspace_claim_for_root(root, _SALT_A)
    assert claim.identity_kind == "git_common_root"
    other_machine = await workspace_claim(WorkspaceLocator(os.fspath(repository)), _SALT_B)
    assert other_machine.digest != claim.digest


@pytest.mark.anyio
async def test_a_plain_directory_claims_its_resolved_self(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    claim = await workspace_claim(WorkspaceLocator(os.fspath(plain)), _SALT_A)
    root = CanonicalWorkspaceRoot("directory", plain.resolve())
    assert claim == workspace_claim_for_root(root, _SALT_A)


@pytest.mark.anyio
async def test_an_unresolvable_locator_raises_its_closed_token(tmp_path: Path) -> None:
    with pytest.raises(RepositoryIdentityError) as raised:
        await workspace_claim(WorkspaceLocator(os.fspath(tmp_path / "missing")), _SALT_A)
    assert raised.value.reason == "repository_locator_unavailable"
    assert "missing" not in str(raised.value)


@pytest.mark.anyio
async def test_the_salt_is_checked_before_anything_is_read(tmp_path: Path) -> None:
    # A bad salt is refused even for a locator that would not resolve: nothing is read first.
    with pytest.raises(ValueError, match="workspace_claim_salt_invalid"):
        await workspace_claim(WorkspaceLocator(os.fspath(tmp_path / "missing")), b"short")
