"""Private repository locator canonicalization and opaque installation binding."""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path
from typing import Final

from yoetz.adapters.git_rev_parse import absolute_rev_parse_path
from yoetz.adapters.git_version import (
    GIT_VERSION_UNSUPPORTED,
    git_version_async,
    git_version_supported,
)
from yoetz.ports.control import RepositoryPrivacyContext, WorkspaceLocator
from yoetz.ports.keys import REPOSITORY_PRIVACY_MAC_DOMAIN, MacKeyHandle

__all__ = ["RepositoryIdentityError", "resolve_repository_privacy_context"]

_GIT_TIMEOUT_SECONDS: Final = 2.0
_MAX_GIT_OUTPUT_BYTES: Final = 16_384
_REASONS: Final = frozenset(
    {
        "repository_locator_invalid",
        "repository_locator_unavailable",
        "repository_identity_unavailable",
        # The system Git is older than the documented minimum (``git_version``).
        GIT_VERSION_UNSUPPORTED,
    }
)


class RepositoryIdentityError(Exception):
    """Bounded repository-identity failure which never includes the raw locator."""

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if reason not in _REASONS:
            raise ValueError("repository_identity_reason_invalid")
        self.reason = reason
        super().__init__(reason)


def _resolved_directory(locator: WorkspaceLocator) -> Path:
    if type(locator) is not WorkspaceLocator:
        raise RepositoryIdentityError("repository_locator_invalid")
    try:
        resolved = Path(locator.path).resolve(strict=True)
    except OSError, RuntimeError:
        raise RepositoryIdentityError("repository_locator_unavailable") from None
    if not resolved.is_dir():
        raise RepositoryIdentityError("repository_locator_invalid")
    return resolved


def _git_environment() -> dict[str, str]:
    # ``GIT_CONFIG_GLOBAL`` exists only since Git 2.32; ``HOME`` and ``XDG_CONFIG_HOME`` keep an
    # older Git from reading a global configuration either.
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "XDG_CONFIG_HOME": os.devnull,
    }


_HEAD_PROBE_BYTES: Final = 256
_HEX: Final = frozenset(b"0123456789abcdef")


def _is_git_directory(candidate: Path) -> bool:
    """Whether ``candidate`` is itself a Git directory, as Git's own discovery decides.

    A bare repository (and a ``.git`` directory entered directly) has no ``.git`` child: Git
    recognises it by ``objects/`` and ``refs/`` directories beside a ``HEAD`` that is a symbolic
    ref (``ref: refs/...``) or an object id.
    """

    try:
        if not ((candidate / "objects").is_dir() and (candidate / "refs").is_dir()):
            return False
        with (candidate / "HEAD").open("rb") as handle:
            head = handle.read(_HEAD_PROBE_BYTES).rstrip(b"\n")
    except OSError:
        return False
    if head.startswith(b"ref: refs/"):
        return True
    return len(head) in {40, 64} and set(head) <= _HEX


def _has_git_marker(directory: Path) -> bool:
    """Whether Git would find a repository at ``directory`` or any directory above it."""

    return any(
        (candidate / ".git").exists() or _is_git_directory(candidate)
        for candidate in (directory, *directory.parents)
    )


async def _bounded_git_common_directory(directory: Path) -> Path | None:
    executable = shutil.which("git", path=os.defpath)
    if executable is None:
        if _has_git_marker(directory):
            raise RepositoryIdentityError("repository_identity_unavailable")
        return None
    if not git_version_supported(await git_version_async(executable)):
        # Below the minimum the identity is not vouched for (Git before 2.13, for one, printed
        # ``--git-common-dir`` relative to the top level rather than to the directory it ran in,
        # which would commit a different repository). A directory with no Git marker (no
        # ``.git`` at or above it, and not inside a bare repository or other Git directory)
        # keeps its plain directory identity, exactly as on a machine without Git.
        if _has_git_marker(directory):
            raise RepositoryIdentityError(GIT_VERSION_UNSUPPORTED)
        return None
    try:
        process = await asyncio.create_subprocess_exec(
            executable,
            "-c",
            # Empty disables fsmonitor on every Git; ``false`` is a hook command before 2.36.
            "core.fsmonitor=",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "credential.helper=",
            "-C",
            os.fspath(directory),
            "rev-parse",
            "--is-inside-work-tree",
            "--is-bare-repository",
            # No ``--path-format=absolute``: Git before 2.31 echoes it as an extra output line
            # (#1040). ``--git-common-dir`` has no absolute spelling there; a relative answer is
            # relative to ``directory`` (where ``-C`` started Git) and is resolved against it.
            "--git-common-dir",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=_git_environment(),
        )
    except OSError:
        raise RepositoryIdentityError("repository_identity_unavailable") from None
    assert process.stdout is not None
    output = bytearray()
    try:
        async with asyncio.timeout(_GIT_TIMEOUT_SECONDS):
            while True:
                chunk = await process.stdout.read(4096)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > _MAX_GIT_OUTPUT_BYTES:
                    raise RepositoryIdentityError("repository_identity_unavailable")
            return_code = await process.wait()
    except TimeoutError:
        process.kill()
        await process.wait()
        raise RepositoryIdentityError("repository_identity_unavailable") from None
    except BaseException:
        if process.returncode is None:
            process.kill()
            await process.wait()
        raise
    if return_code != 0:
        if _has_git_marker(directory):
            raise RepositoryIdentityError("repository_identity_unavailable")
        return None
    try:
        inside_work_tree, bare_repository, common_raw = bytes(output).splitlines()
        if inside_work_tree not in {b"true", b"false"} or bare_repository not in {
            b"true",
            b"false",
        }:
            raise ValueError
        common_directory = absolute_rev_parse_path(common_raw, directory).resolve(strict=True)
    except OSError, RuntimeError, UnicodeError, ValueError:
        raise RepositoryIdentityError("repository_identity_unavailable") from None
    if not common_directory.is_dir() or (inside_work_tree, bare_repository) == (b"false", b"false"):
        raise RepositoryIdentityError("repository_identity_unavailable")
    return common_directory


async def resolve_repository_privacy_context(
    locator: WorkspaceLocator,
    key: MacKeyHandle,
) -> RepositoryPrivacyContext:
    """Resolve a transient locator and retain only an installation-keyed commitment."""

    directory = _resolved_directory(locator)
    common_directory = await _bounded_git_common_directory(directory)
    identity_kind = "git_common_root" if common_directory is not None else "directory"
    canonical_directory = common_directory if common_directory is not None else directory
    message = identity_kind.encode("ascii") + b"\x00" + os.fsencode(canonical_directory)
    return RepositoryPrivacyContext(
        commitment=key.mac(REPOSITORY_PRIVACY_MAC_DOMAIN, message),
        identity_kind=identity_kind,
        # Kept in memory beside the commitment it produced; see RepositoryPrivacyContext.
        workspace_locator=locator,
    )
