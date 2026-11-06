"""An owner-only ambient home for server-target tests (ADR-051).

Target roots live beneath the ambient state directory and the selection in the ambient config
directory, so each test gets its own owner-only home outside shared temp (the runtime refuses a
root under ``/tmp``), with every isolation-root variable unset and the selection memo reset.

A target root's longest endpoint must fit the ``sun_path`` bound the runtime enforces
(``target_root_too_long``). CI isolates ``$HOME`` beneath a long job temp directory, where a root
named after it may not fit; the home is then the account's own passwd home, which is as private.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest

from finishup.config.installation import instance_root_fits
from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES, reset_selection_memo

__all__ = ["ambient_home"]

_PREFIX = ".yz-target-test-"
# The deepest root a test makes, ``<home>/<prefix><8 random>/state/finishup/servers/t_<8 hex>``:
# a ``local`` target's, held to the runtime's own instance bound, the strictest a target meets.
_DEEPEST_ROOT = Path("state", "finishup", "servers", "t_00000000")


def _fits(base: Path) -> bool:
    return instance_root_fits(base / f"{_PREFIX}00000000" / _DEEPEST_ROOT)


def _test_home_base() -> Path:
    """``$HOME``, or the account's passwd home when an isolated ``$HOME`` is too long."""

    candidates = [Path.home()]
    try:
        import pwd

        candidates.append(Path(pwd.getpwuid(os.getuid()).pw_dir))
    except (ImportError, KeyError):
        pass
    for base in candidates:
        if base.is_dir() and _fits(base):
            return base
    raise RuntimeError("no home directory is short enough for a server-target test root")


@contextmanager
def ambient_home(monkeypatch: pytest.MonkeyPatch) -> Generator[Path]:
    root = Path(tempfile.mkdtemp(prefix=_PREFIX, dir=_test_home_base()))
    root.chmod(0o700)
    for name in ISOLATED_ROOT_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    for variable, leaf in (
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_RUNTIME_DIR", "run"),
    ):
        (root / leaf).mkdir(mode=0o700)
        monkeypatch.setenv(variable, str(root / leaf))
    reset_selection_memo()
    try:
        yield root
    finally:
        reset_selection_memo()
        shutil.rmtree(root, ignore_errors=True)
