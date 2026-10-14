"""Private repository locator canonicalization and opaque installation binding."""

from __future__ import annotations

import asyncio
import os
import shutil
import stat
from pathlib import Path
from typing import Final

from yoetz.adapters.git_rev_parse import absolute_rev_parse_path
from yoetz.adapters.git_version import (
    GIT_VERSION_UNSUPPORTED,
    git_version_async,
    git_version_supported,
)
from yoetz.config.foreign_write import (
    project_root_admitted,
    superuser_checkout_marker,
    writable_by_others,
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


# Git reads at most this much of ``HEAD`` (``validate_headref``'s 256-byte buffer, less its NUL)
# and of a ``commondir`` file this module accepts.
_HEAD_PROBE_BYTES: Final = 255
_COMMONDIR_PROBE_BYTES: Final = 4_096
_HEX: Final = frozenset(b"0123456789abcdefABCDEF")
# Git's own ``isspace`` (``GIT_SPACE``): space, tab, line feed and carriage return.
_GIT_SPACE: Final = b" \t\n\r"
_OPEN_FLAGS: Final = (
    os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | os.O_CLOEXEC
)


def _read_regular_file(path: Path, limit: int) -> bytes | None:
    """Up to ``limit`` bytes of a regular file, or None for anything else; never blocks.

    The open is non-blocking and refuses a link, and the type is checked on the opened
    descriptor, so a FIFO, socket or device swapped in after any earlier ``lstat`` is never read.
    """

    try:
        descriptor = os.open(path, _OPEN_FLAGS)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None
        return os.read(descriptor, limit)
    except OSError:
        return None
    finally:
        os.close(descriptor)


def _head_is_valid(head: Path) -> bool | None:
    """Git's ``validate_headref``: True, False, or None for a HEAD it would block on.

    A symbolic link is valid when its target starts with ``refs/`` (the branch need not exist).
    A regular file is valid when it reads ``ref:``, optional Git whitespace, then ``refs/``; or
    when its first 40 bytes are hexadecimal in either case (Git checks only the object id's
    length, so a longer SHA-256 id passes too). A FIFO, socket or device is never opened for a
    blocking read; Git itself would wait on it, so it is reported as undecidable (None).
    """

    try:
        facts = os.lstat(head)
    except OSError:
        return False
    if stat.S_ISLNK(facts.st_mode):
        try:
            target = os.fsencode(os.readlink(head))
        except OSError:
            return False
        return target[:_HEAD_PROBE_BYTES].startswith(b"refs/")
    if stat.S_ISDIR(facts.st_mode):
        return False
    if not stat.S_ISREG(facts.st_mode):
        return None
    data = _read_regular_file(head, _HEAD_PROBE_BYTES)
    if data is None:
        return False
    # Git treats the buffer as a C string.
    text = data.split(b"\x00", 1)[0]
    if text.startswith(b"ref:") and text[4:].lstrip(_GIT_SPACE).startswith(b"refs/"):
        return True
    return len(text) >= 40 and set(text[:40]) <= _HEX


def _common_directory(candidate: Path) -> Path | None:
    """The directory Git reads ``objects/`` and ``refs/`` from for ``candidate``, or None.

    A linked worktree's Git directory names its repository's common directory in
    ``commondir``; any other Git directory is its own. Only a regular, non-link ``commondir``
    is read, without blocking, up to a bound. None means this module cannot decide what Git
    would make of the pointer, not that Git rejects it: Git follows a linked ``commondir``,
    blocks on a FIFO, stops at an embedded NUL and fails on an empty one. The caller refuses
    such a candidate rather than reading it as a plain directory.
    """

    pointer = candidate / "commondir"
    try:
        os.lstat(pointer)
    except FileNotFoundError:
        return candidate
    except OSError:
        return None
    data = _read_regular_file(pointer, _COMMONDIR_PROBE_BYTES)
    if data is None:
        return None
    text = data.rstrip(b"\r\n")
    if not text or b"\x00" in text:
        return None
    named = Path(os.fsdecode(text))
    return named if named.is_absolute() else candidate / named


def _is_git_directory(candidate: Path) -> bool:
    """Whether ``candidate`` is itself a Git directory, as Git's ``is_git_directory`` decides.

    A bare repository (and a ``.git`` directory entered directly) has no ``.git`` child: Git
    recognises it by a valid ``HEAD`` (``_head_is_valid``) and searchable ``objects`` and
    ``refs`` in its common directory. Where this cannot be decided without following a link or
    blocking (a ``HEAD`` that is a FIFO, socket or device beside ``objects`` and ``refs``, or a
    valid ``HEAD`` beside a ``commondir`` that is not a plain readable pointer) the answer is
    yes: the locator is then refused with a typed error, never committed as a plain directory
    whose identity a supported Git would not give it.
    """

    head = _head_is_valid(candidate / "HEAD")
    if head is False:
        return False
    common = _common_directory(candidate)
    if common is None:
        return True
    return os.access(common / "objects", os.X_OK) and os.access(common / "refs", os.X_OK)


def _another_owners_checkout(directory: Path) -> bool:
    """Whether Git's ownership guard refuses ``directory`` only because root owns the checkout.

    Git (2.35.2 and later) refuses a repository whose working tree or ``.git`` is not owned by
    the running user ("dubious ownership"), and this module runs Git without any configuration
    that could set ``safe.directory``. A container image built as root keeps ``/app`` and
    ``/app/.git`` root-owned and runs the agent as a non-root ``USER``; in a sticky root-owned
    ``/app`` the agent's own ``git init`` is refused the same way, because the working tree is
    root's. True when the nearest ``.git`` Git would find sits in a directory the project-root
    rule admits, the marker is the user's own and unshared or root's checkout marker
    (``superuser_checkout_marker``), and root owns at least one of the two. Such a checkout keeps
    the plain ``directory`` identity, as workspace binding already treats it (ADR-007,
    2026-10-14); Git is not run against it. Anything owned by another non-root account is not
    matched and stays refused when Git refuses it.
    """

    if not hasattr(os, "geteuid"):
        return False
    euid = os.geteuid()
    for candidate in (directory, *directory.parents):
        try:
            marker = (candidate / ".git").lstat()
        except FileNotFoundError:
            if _is_git_directory(candidate):
                return False
            continue
        except OSError:
            return False
        try:
            worktree = candidate.stat()
        except OSError:
            return False
        if marker.st_uid == euid:
            if stat.S_ISLNK(marker.st_mode) or writable_by_others(marker):
                return False
        elif not superuser_checkout_marker(marker):
            return False
        if not project_root_admitted(worktree):
            return False
        # Admitted owners are this user or root; Git refuses when either is root's.
        return marker.st_uid != euid or worktree.st_uid != euid
    return False


def _has_git_marker(directory: Path) -> bool:
    """Whether Git would find a repository at ``directory`` or any directory above it."""

    return any(
        (candidate / ".git").exists() or _is_git_directory(candidate)
        for candidate in (directory, *directory.parents)
    )


async def _bounded_git_common_directory(directory: Path) -> Path | None:
    if _another_owners_checkout(directory):
        return None
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
