"""The shared canonical-root rule (ADR-051) and its byte-identical service commitment."""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
from pathlib import Path

import pytest

from finishup.adapters import repository_identity, workspace_root
from finishup.adapters.repository_identity import resolve_repository_privacy_context
from finishup.adapters.workspace_root import (
    CanonicalWorkspaceRoot,
    RepositoryIdentityError,
    canonical_workspace_root,
    workspace_identity_preimage,
)
from finishup.ports.control import WorkspaceLocator
from finishup.ports.keys import REPOSITORY_PRIVACY_MAC_DOMAIN


class _MacKey:
    def mac(self, domain: bytes, message: bytes) -> str:
        digest = hmac.new(b"installation-test-key", domain + message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"


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


def _repository(path: Path) -> None:
    path.mkdir()
    _git("-C", os.fspath(path), "init")
    (path / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    _git("-C", os.fspath(path), "add", "tracked.txt")
    _git("-C", os.fspath(path), "commit", "-m", "initial")


def _layouts(tmp_path: Path) -> dict[str, Path]:
    repository = tmp_path / "repository"
    _repository(repository)
    nested = repository / "nested" / "deeper"
    nested.mkdir(parents=True)
    linked = tmp_path / "linked"
    _git("-C", os.fspath(repository), "branch", "other")
    _git("-C", os.fspath(repository), "worktree", "add", os.fspath(linked), "other")
    alias = tmp_path / "alias"
    alias.symlink_to(repository, target_is_directory=True)
    plain = tmp_path / "plain"
    plain.mkdir()
    return {
        "repository": repository,
        "nested": nested,
        "linked": linked,
        "alias": alias,
        "plain": plain,
    }


@pytest.mark.anyio
async def test_the_shared_rule_names_git_common_roots_and_plain_directories(
    tmp_path: Path,
) -> None:
    layouts = _layouts(tmp_path)
    repository = layouts["repository"].resolve()
    for name in ("repository", "nested", "linked", "alias"):
        root = await canonical_workspace_root(WorkspaceLocator(os.fspath(layouts[name])))
        assert root == CanonicalWorkspaceRoot("git_common_root", repository / ".git"), name
    plain = await canonical_workspace_root(WorkspaceLocator(os.fspath(layouts["plain"])))
    assert plain == CanonicalWorkspaceRoot("directory", layouts["plain"].resolve())
    assert workspace_identity_preimage(plain) == b"directory\x00" + os.fsencode(
        layouts["plain"].resolve()
    )
    # The directory never reaches a representation.
    assert "plain" not in repr(plain)


@pytest.mark.anyio
async def test_the_service_commitment_is_the_installation_mac_of_the_shared_preimage(
    tmp_path: Path,
) -> None:
    """The extraction kept every commitment byte-identical: same preimage, same MAC domain."""

    layouts = _layouts(tmp_path)
    key = _MacKey()
    for name, path in layouts.items():
        locator = WorkspaceLocator(os.fspath(path))
        root = await canonical_workspace_root(locator)
        context = await resolve_repository_privacy_context(locator, key)
        expected_message = (
            root.identity_kind.encode("ascii") + b"\x00" + os.fsencode(root.directory)
        )
        assert workspace_identity_preimage(root) == expected_message, name
        assert context.commitment == key.mac(REPOSITORY_PRIVACY_MAC_DOMAIN, expected_message)
        assert context.identity_kind == root.identity_kind
        assert context.workspace_locator is locator


@pytest.mark.anyio
async def test_failures_are_the_same_closed_type_on_both_modules(tmp_path: Path) -> None:
    assert repository_identity.RepositoryIdentityError is RepositoryIdentityError
    assert repository_identity.root_owned_checkout is workspace_root.root_owned_checkout
    missing = tmp_path / "private-secret-name"
    with pytest.raises(RepositoryIdentityError) as caught:
        await canonical_workspace_root(WorkspaceLocator(os.fspath(missing)))
    assert caught.value.reason == "repository_locator_unavailable"
    assert "private-secret-name" not in f"{caught.value!r} {caught.value}"
    regular = tmp_path / "file.txt"
    regular.write_text("x", encoding="utf-8")
    with pytest.raises(RepositoryIdentityError) as not_directory:
        await canonical_workspace_root(WorkspaceLocator(os.fspath(regular)))
    assert not_directory.value.reason == "repository_locator_invalid"


def test_the_canonical_root_value_is_strict() -> None:
    with pytest.raises(ValueError, match="workspace_identity_kind_invalid"):
        CanonicalWorkspaceRoot("client_claim", Path("/x"))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="workspace_root_invalid"):
        CanonicalWorkspaceRoot("directory", Path("relative"))
    with pytest.raises(TypeError, match="workspace_root_invalid"):
        workspace_identity_preimage(("directory", Path("/x")))  # type: ignore[arg-type]
