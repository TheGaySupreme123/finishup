"""Hermetic process environment for every case under ``tests/subprocess``.

Child processes spawned through ``helpers.child.spawn_installed`` or ``isolated_environment``
already receive a minimal, owner-only environment. The in-process cases (``CliRunner`` driving
``finishup.cli.app``) do not: the product resolves its default configuration, state, cache, and
runtime endpoints from the pytest process environment, so without this fixture they read the
developer's real ``config.toml`` and can even reach the developer's running service (issue #551).
"""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

_ISOLATION_PARENT = (".cache", "finishup-subprocess-isolation")
_XDG_ROOTS = (
    ("XDG_CACHE_HOME", "cache"),
    ("XDG_CONFIG_HOME", "config"),
    ("XDG_DATA_HOME", "data"),
)
_RUNTIME_PREFIX = "finishup-rt-"


def _short_runtime_root() -> Path:
    """A private, uniquely named socket directory whose endpoint paths fit ``sun_path``."""

    # macOS resolves ``/tmp`` through a symlink that path safety refuses; ``/private/tmp`` is the
    # same directory without it. ``mkdtemp`` creates the directory owner-only (0700).
    parent = Path("/private/tmp") if Path("/private/tmp").is_dir() else Path("/tmp")
    return Path(tempfile.mkdtemp(prefix=_RUNTIME_PREFIX, dir=parent))


@pytest.fixture(autouse=True)
def _hermetic_finishup_environment(  # pyright: ignore[reportUnusedFunction]
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """Rebase ``HOME`` and every XDG root onto private per-test directories; drop product variables.

    This is the same contract the ``cli-mcp-subprocess`` CI job applies to the whole job
    (``HOME``, ``XDG_CONFIG_HOME``, ``XDG_DATA_HOME``, ``XDG_CACHE_HOME`` under the job temp),
    extended with a private per-test ``XDG_RUNTIME_DIR`` so endpoint resolution cannot fall back
    to a platform default (on Linux that would be the real ``/run/user/<uid>``), and with a
    scrub of inherited ``FINISHUP_*`` and legacy ``YOETZ_*`` variables so neither a developer's
    exports nor the CI job's own ``FINISHUP_CANDIDATE_PYTHON`` reaches the strict config loader,
    which refuses every unknown name under either prefix (ADR-048). Underscore-prefixed harness variables such
    as ``_FINISHUP_TEST_INSTALLATION`` are not product configuration and survive.

    ``XDG_STATE_HOME`` is unset rather than pinned, matching CI: ``state_dir()`` then follows
    ``HOME`` on both platforms, which cases that rebase ``HOME`` themselves and read the state
    tree back (``test_hooks_cli``) depend on.

    The tree lives under the real ``~/.cache/finishup-subprocess-isolation`` rather than pytest's
    ``tmp_path``: ``verify_private_local_bundle`` rejects shared temp (Linux ``/tmp``), and
    ``isolated_environment`` derives its own child installation tree from ``Path.home()`` at
    call time, so the override must itself be a location path safety accepts. ``platformdirs``
    honours the XDG variables on macOS as well as Linux, so resolution is identical on both.

    The runtime directory holds only the service's sockets, so it lives in a short owner-only
    temp directory instead, as ``isolated_environment`` already does for its children: an
    in-process case can spawn a real service on demand (``test_service_startup_failure``), and
    beneath the deep tree its endpoint paths grow past ``sun_path`` (108 bytes on Linux, 104 on
    macOS), so ``bind`` fails as ``endpoint_unsafe`` before the service reaches what the case
    tests. ``test_the_hermetic_runtime_fits_every_service_endpoint`` holds that bound.
    """

    base = Path.home().joinpath(*_ISOLATION_PARENT)
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    base.chmod(0o700)
    root = Path(tempfile.mkdtemp(prefix="hermetic-", dir=base))
    root.chmod(0o700)
    home = root / "home"
    for directory in (home, *(root / name for _, name in _XDG_ROOTS)):
        directory.mkdir(mode=0o700)
    runtime = _short_runtime_root()

    for name in tuple(os.environ):
        # The strict loader reads the legacy ``YOETZ_`` spellings too (ADR-048).
        if name.startswith(("FINISHUP_", "YOETZ_")):
            monkeypatch.delenv(name)
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setenv("HOME", os.fspath(home))
    for variable, name in _XDG_ROOTS:
        monkeypatch.setenv(variable, os.fspath(root / name))
    monkeypatch.setenv("XDG_RUNTIME_DIR", os.fspath(runtime))
    try:
        yield
    finally:
        shutil.rmtree(runtime, ignore_errors=True)
        shutil.rmtree(root, ignore_errors=True)
