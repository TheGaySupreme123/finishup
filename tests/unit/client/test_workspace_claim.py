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
    WORKSPACE_WORKTREE_DOMAIN,
    new_claim_salt,
    workspace_claim,
    workspace_claim_for_root,
    worktree_digest,
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
    claim = workspace_claim_for_root(root, _SALT_A, os.fspath(tmp_path))
    expected = hmac.new(
        _SALT_A,
        b"yoetz/workspace-claim/v1\x00directory\x00" + os.fsencode(tmp_path),
        hashlib.sha256,
    ).hexdigest()
    worktree = hmac.new(
        _SALT_A, b"yoetz/workspace-worktree/v1\x00" + os.fsencode(tmp_path), hashlib.sha256
    ).hexdigest()
    assert claim == WorkspaceClaim(
        identity_kind="directory", digest="sha256:" + expected, worktree="sha256:" + worktree
    )
    assert WORKSPACE_CLAIM_DOMAIN + workspace_identity_preimage(root) == (
        b"yoetz/workspace-claim/v1\x00directory\x00" + os.fsencode(tmp_path)
    )
    assert WORKSPACE_WORKTREE_DOMAIN == b"yoetz/workspace-worktree/v1\x00"
    assert claim.worktree != claim.digest  # its own domain, even over the same directory


def test_the_worktree_digest_names_only_a_normal_absolute_directory(tmp_path: Path) -> None:
    assert worktree_digest(os.fspath(tmp_path), _SALT_A) != worktree_digest(
        os.fspath(tmp_path), _SALT_B
    )
    for invalid in ("relative/dir", os.fspath(tmp_path) + "/", os.fspath(tmp_path) + "/./x"):
        with pytest.raises(ValueError, match="workspace_worktree_invalid"):
            worktree_digest(invalid, _SALT_A)
    with pytest.raises(ValueError, match="workspace_claim_salt_invalid"):
        worktree_digest(os.fspath(tmp_path), b"short")


def test_two_machines_claim_the_same_path_with_unrelated_digests(tmp_path: Path) -> None:
    root = CanonicalWorkspaceRoot("git_common_root", tmp_path / ".git")
    first = workspace_claim_for_root(root, _SALT_A, os.fspath(tmp_path))
    second = workspace_claim_for_root(root, _SALT_B, os.fspath(tmp_path))
    assert first.identity_kind == second.identity_kind == "git_common_root"
    assert first.digest != second.digest and first.worktree != second.worktree
    # The same salt and path always give the same claim: a target reaches its own tasks again.
    assert workspace_claim_for_root(root, _SALT_A, os.fspath(tmp_path)) == first


def test_the_kind_is_part_of_the_claim(tmp_path: Path) -> None:
    here = os.fspath(tmp_path)
    directory = workspace_claim_for_root(
        CanonicalWorkspaceRoot("directory", tmp_path), _SALT_A, here
    )
    common = workspace_claim_for_root(
        CanonicalWorkspaceRoot("git_common_root", tmp_path), _SALT_A, here
    )
    assert directory.digest != common.digest


def test_no_path_reaches_any_representation_of_the_claim(tmp_path: Path) -> None:
    secret_dir = tmp_path / "private-project-name"
    secret_dir.mkdir()
    claim = workspace_claim_for_root(
        CanonicalWorkspaceRoot("directory", secret_dir), _SALT_A, os.fspath(secret_dir)
    )
    assert "private-project-name" not in repr(claim)
    assert claim.digest not in repr(claim) and claim.worktree not in repr(claim)
    assert "private-project-name" not in claim.digest + claim.worktree


@pytest.mark.parametrize(
    "salt",
    [b"", b"\x00" * 31, b"\x00" * 33, "0" * 32, bytearray(32), None],
)
def test_a_salt_is_exactly_thirty_two_bytes(tmp_path: Path, salt: object) -> None:
    with pytest.raises(ValueError, match="workspace_claim_salt_invalid"):
        workspace_claim_for_root(
            CanonicalWorkspaceRoot("directory", tmp_path), cast(bytes, salt), os.fspath(tmp_path)
        )


def test_a_root_must_be_the_shared_rule_value(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="workspace_root_invalid"):
        workspace_claim_for_root(cast(CanonicalWorkspaceRoot, tmp_path), _SALT_A, "/")


def test_new_salts_are_fresh_and_sized() -> None:
    first, second = new_claim_salt(), new_claim_salt()
    assert len(first) == len(second) == WORKSPACE_CLAIM_SALT_BYTES
    assert first != second


@pytest.mark.anyio
async def test_every_worktree_of_a_repository_claims_it_and_names_its_own_worktree(
    tmp_path: Path,
) -> None:
    """One repository is one claim; each worktree the agent serves has its own digest."""

    repository = _repository(tmp_path / "repository")
    nested = repository / "src" / "deep"
    nested.mkdir(parents=True)
    linked = tmp_path / "linked"
    _git("-C", os.fspath(repository), "branch", "other")
    _git("-C", os.fspath(repository), "worktree", "add", os.fspath(linked), "other")

    claims = {
        path: await workspace_claim(WorkspaceLocator(os.fspath(path)), _SALT_A)
        for path in (repository, nested, linked)
    }
    assert len({(claim.identity_kind, claim.digest) for claim in claims.values()}) == 1
    claim = claims[repository]
    root = await canonical_workspace_root(WorkspaceLocator(os.fspath(repository)))
    assert claim == workspace_claim_for_root(root, _SALT_A, os.fspath(repository))
    assert claim.identity_kind == "git_common_root"
    # The worktree digest is over the very directory each agent serves.
    for path, each in claims.items():
        assert each.worktree == worktree_digest(os.fspath(path), _SALT_A)
    assert claims[linked].worktree != claim.worktree
    other_machine = await workspace_claim(WorkspaceLocator(os.fspath(repository)), _SALT_B)
    assert other_machine.digest != claim.digest


@pytest.mark.anyio
async def test_a_plain_directory_claims_its_resolved_self(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    claim = await workspace_claim(WorkspaceLocator(os.fspath(plain)), _SALT_A)
    root = CanonicalWorkspaceRoot("directory", plain.resolve())
    assert claim == workspace_claim_for_root(root, _SALT_A, os.fspath(plain))


@pytest.mark.anyio
async def test_an_unresolvable_locator_raises_its_closed_token(tmp_path: Path) -> None:
    with pytest.raises(RepositoryIdentityError) as raised:
        await workspace_claim(WorkspaceLocator(os.fspath(tmp_path / "missing")), _SALT_A)
    assert raised.value.reason == "repository_locator_unavailable"
    assert "missing" not in str(raised.value)


@pytest.mark.anyio
async def test_the_filesystem_root_is_never_claimed(tmp_path: Path) -> None:
    # A CLI or bridge started at ``/`` sends ``/`` as its locator; the shared root rule would
    # resolve it as a plain directory, but no claim (and so no agent) is ever made for it, as a
    # hook or an MCP root never binds it (ADR-051). The refusal comes before anything is read.
    with pytest.raises(RepositoryIdentityError) as raised:
        await workspace_claim(WorkspaceLocator("/"), _SALT_A)
    assert raised.value.reason == "repository_locator_invalid"
    with pytest.raises(ValueError, match="workspace_worktree_invalid"):
        worktree_digest("/", _SALT_A)
    with pytest.raises(ValueError, match="workspace_worktree_invalid"):
        workspace_claim_for_root(CanonicalWorkspaceRoot("directory", Path("/")), _SALT_A, "/")


@pytest.mark.anyio
async def test_the_salt_is_checked_before_anything_is_read(tmp_path: Path) -> None:
    # A bad salt is refused even for a locator that would not resolve: nothing is read first.
    with pytest.raises(ValueError, match="workspace_claim_salt_invalid"):
        await workspace_claim(WorkspaceLocator(os.fspath(tmp_path / "missing")), b"short")


@pytest.mark.anyio
async def test_the_remote_binding_claims_and_optionally_serves_the_workspace(
    tmp_path: Path,
) -> None:
    from finishup.client.remote_binding import remote_workspace_binding
    from finishup.client.workspace_agent import WorkspaceAgentHandler

    repository = _repository(tmp_path / "repository")
    locator = WorkspaceLocator(os.fspath(repository))
    expected = await workspace_claim(locator, _SALT_A)

    claim_only = await remote_workspace_binding(locator, _SALT_A, serve_workspace=False)
    assert claim_only.claim == expected and claim_only.agent is None

    served = await remote_workspace_binding(
        locator, _SALT_A, protected=(os.fspath(tmp_path / "state"),)
    )
    assert served.claim == expected
    assert type(served.agent) is WorkspaceAgentHandler
    assert served.agent.declaration.operations[0] == "capture"
    with pytest.raises(ValueError, match="workspace_claim_salt_invalid"):
        await remote_workspace_binding(locator, b"short")
