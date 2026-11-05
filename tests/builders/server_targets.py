"""An owner-only ambient home for server-target tests (ADR-051).

Target roots live beneath the ambient state directory and the selection in the ambient config
directory, so each test gets its own owner-only home outside shared temp (the runtime refuses a
root under ``/tmp``), with every isolation-root variable unset and the selection memo reset.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest

from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES, reset_selection_memo

__all__ = ["ambient_home"]


@contextmanager
def ambient_home(monkeypatch: pytest.MonkeyPatch) -> Generator[Path]:
    root = Path(tempfile.mkdtemp(prefix=".yz-target-test-", dir=Path.home()))
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
