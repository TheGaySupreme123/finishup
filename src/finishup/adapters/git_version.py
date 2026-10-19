"""The oldest Git FinishUP supports, and the one bounded probe that reads the installed version.

FinishUP runs the system Git it finds on ``os.defpath`` (never a ``PATH`` the caller controls). The
documented minimum is Git 2.25, the Git of Ubuntu 20.04 and of images built on it such as
``condaforge/miniforge3:24.9.2-0`` (ADR-031). Every Git argument the adapters pass works there:

- ``rev-parse --path-format`` (2.31) is never passed; ``--absolute-git-dir`` and
  ``--show-toplevel`` print absolute paths on every supported Git, and a relative
  ``--git-common-dir`` is resolved against the directory Git ran in (``git_rev_parse``).
- ``rev-parse --end-of-options`` (2.30) is never passed; every revision the capture names is
  built from a fixed spelling or a hexadecimal object id and is refused if it begins with ``-``.
- ``diff --no-relative`` (2.28) is never passed; ``-c diff.relative=false`` overrides a
  repository's ``diff.relative`` on Git that knows it and is an inert key on Git that does not.
- ``config --show-scope`` (2.26) is never passed; ``--show-origin`` (2.8) separates the runner's
  own ``-c`` values from repository configuration.
- ``GIT_CONFIG_GLOBAL`` (2.32) is not relied on alone: the hardened runners also point ``HOME``
  and ``XDG_CONFIG_HOME`` at ``os.devnull``, so an older Git reads no global configuration
  either (it would otherwise read a ``.gitconfig`` from whatever ``HOME`` named).
- ``core.fsmonitor`` is pinned to the empty value, which disables it on every Git; ``false``
  disables it only from 2.36 and is run as a hook command named ``false`` before that.

Below the minimum the adapters refuse with the closed token ``git_version_unsupported`` instead
of failing as an unexplained ``git_failed``. A version the probe cannot read (an unusual vendor
string, a probe that timed out) is not refused: every later Git call still fails closed on output
it does not expect.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
from typing import Final

__all__ = [
    "GIT_VERSION_UNSUPPORTED",
    "MINIMUM_GIT_VERSION",
    "MINIMUM_GIT_VERSION_TEXT",
    "GitVersion",
    "GitVersionUnsupported",
    "git_version",
    "git_version_async",
    "git_version_supported",
    "parse_git_version",
    "require_supported_git",
]

type GitVersion = tuple[int, int, int]

MINIMUM_GIT_VERSION: Final[GitVersion] = (2, 25, 0)
MINIMUM_GIT_VERSION_TEXT: Final = "2.25"
GIT_VERSION_UNSUPPORTED: Final = "git_version_unsupported"

_PROBE_TIMEOUT_SECONDS: Final = 2.0
_MAX_PROBE_OUTPUT_BYTES: Final = 256
# ``git version 2.25.1``, ``git version 2.39.3 (Apple Git-146)``, ``git version 2.45.1.windows.1``.
_VERSION_LINE: Final = re.compile(rb"\Agit version ([0-9]{1,4})\.([0-9]{1,4})(?:\.([0-9]{1,6}))?")
# Keyed by the executable's path and file identity, so replacing Git in place is noticed.
type _Identity = tuple[str, int, int, int, int]
_PROBED: dict[_Identity, GitVersion | None] = {}


class GitVersionUnsupported(ValueError):
    """The system Git is older than ``MINIMUM_GIT_VERSION``; carries only the closed token."""

    def __init__(self) -> None:
        super().__init__(GIT_VERSION_UNSUPPORTED)


def parse_git_version(raw: bytes) -> GitVersion | None:
    """Return ``(major, minor, patch)`` from ``git --version`` output, or None when unreadable."""

    if type(raw) is not bytes:
        return None
    match = _VERSION_LINE.match(raw)
    if match is None:
        return None
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch or b"0")


def git_version_supported(version: GitVersion | None) -> bool:
    """True unless ``version`` is known and older than the documented minimum."""

    return version is None or version >= MINIMUM_GIT_VERSION


def _identity(executable: str) -> _Identity | None:
    try:
        facts = os.stat(executable)
    except OSError:
        return None
    return (executable, facts.st_dev, facts.st_ino, facts.st_mtime_ns, facts.st_size)


def _probe_environment() -> dict[str, str]:
    # ``git --version`` reads no configuration; the environment is fixed anyway.
    return {
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "XDG_CONFIG_HOME": os.devnull,
    }


def git_version(
    executable: str, *, timeout_seconds: float = _PROBE_TIMEOUT_SECONDS
) -> GitVersion | None:
    """Read and cache the version of the Git at ``executable``; None when it cannot be read."""

    identity = _identity(executable)
    if identity is None:
        return None
    if identity in _PROBED:
        return _PROBED[identity]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            (executable, "--version"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_probe_environment(),
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    version = parse_git_version(completed.stdout[:_MAX_PROBE_OUTPUT_BYTES])
    _PROBED[identity] = version
    return version


async def git_version_async(
    executable: str, *, timeout_seconds: float = _PROBE_TIMEOUT_SECONDS
) -> GitVersion | None:
    """``git_version`` for an event loop: the probe never blocks it."""

    identity = _identity(executable)
    if identity is None:
        return None
    if identity in _PROBED:
        return _PROBED[identity]
    try:
        process = await asyncio.create_subprocess_exec(
            executable,
            "--version",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=_probe_environment(),
        )
    except OSError:
        return None
    assert process.stdout is not None
    try:
        async with asyncio.timeout(timeout_seconds):
            output = await process.stdout.read(_MAX_PROBE_OUTPUT_BYTES)
            returncode = await process.wait()
    except TimeoutError:
        process.kill()
        await process.wait()
        return None
    except BaseException:
        if process.returncode is None:
            process.kill()
            await process.wait()
        raise
    if returncode != 0:
        return None
    version = parse_git_version(output)
    _PROBED[identity] = version
    return version


def require_supported_git(executable: str) -> None:
    """Raise ``GitVersionUnsupported`` when the Git at ``executable`` is below the minimum."""

    if not git_version_supported(git_version(executable)):
        raise GitVersionUnsupported
