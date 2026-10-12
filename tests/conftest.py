"""Shared deterministic pytest support for all Yoetz test suites."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from builders import clock as clock_builder_module
from builders import events as event_builder_module
from builders import ids as id_builder_module
from builders import operations as operation_builder_module
from fixture_loader import FixtureLoader, build_fixture_loader


@pytest.fixture(autouse=True)
def _isolated_diagnostic_log(  # pyright: ignore[reportUnusedFunction]
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep the durable diagnostic ring out of the developer's real log directory.

    ``append_diagnostic_record`` defaults to the platform ``log_dir()``, so any test exercising a
    path that records one appends to the machine's own ``service.diagnostics.jsonl``. Individual
    tests that assert on records already redirect it; this makes the default safe for the ones
    that only pass through. A test that sets its own ``log_dir`` still wins, because its
    ``monkeypatch`` is applied after this fixture and undone before it.

    The import is deliberately inside the fixture. The portable console-boundary job runs
    ``tests/unit/cli/test_trusted_console.py`` with pytest alone and no project dependencies, and
    this file is a ``conftest`` on that path; importing the diagnostics module at module scope
    pulls in ``platformdirs`` through ``yoetz.config.paths`` and breaks collection there.
    """

    try:
        import yoetz.observability.diagnostics as diagnostics_module
    except ImportError:
        return  # No project dependencies installed, so there is no durable sink to redirect.

    root = tmp_path_factory.mktemp("diagnostics")
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: Path(root))


@pytest.fixture(autouse=True)
def _isolated_command_identity_key() -> Iterator[None]:  # pyright: ignore[reportUnusedFunction]
    """Undo a service composition's process-wide command-identity key after each test (#977).

    The ready composition registers the installation key so planned-verification facts can be
    computed; without this reset a later test in the same process would see those facts appear
    in status and check output depending only on test order.
    """

    try:
        import yoetz.kernel.task_facts as task_facts_module
    except ImportError:
        yield
        return
    saved = task_facts_module._COMMAND_IDENTITY_KEY[0]  # pyright: ignore[reportPrivateUsage]
    yield
    task_facts_module.register_command_identity_key(saved)


@pytest.fixture(autouse=True)
def _isolated_hook_pass_timing(  # pyright: ignore[reportUnusedFunction]
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep the per-pass hook timing aggregate out of the developer's real state directory.

    Every host hook entry folds its pass into ``hook-pass-timing.json`` under the platform
    ``state_dir()`` unless a test passes its own ``_state`` (issue #915). Many hook tests drive
    an entry with a fake inner handler and no ``_state``; without this redirect they would write
    into a live install's state. Tests that pass ``_state`` are unaffected. The import is inside
    the fixture for the same dependency-free collection reason as the diagnostic log above.
    """

    try:
        import yoetz.cli.hook_timing as hook_timing_module
    except ImportError:
        return

    root = tmp_path_factory.mktemp("hook-pass-timing")
    root.chmod(0o700)
    monkeypatch.setattr(hook_timing_module, "state_dir", lambda: Path(root))


@pytest.fixture(scope="session")
def fixture_loader() -> FixtureLoader:
    """Expose the lazy read-only loader without touching Wave A resources at collection."""

    return build_fixture_loader()


@pytest.fixture(scope="session")
def id_builders() -> ModuleType:
    return id_builder_module


@pytest.fixture(scope="session")
def clock_builders() -> ModuleType:
    return clock_builder_module


@pytest.fixture(scope="session")
def event_builders() -> ModuleType:
    return event_builder_module


@pytest.fixture(scope="session")
def operation_builders() -> ModuleType:
    return operation_builder_module
