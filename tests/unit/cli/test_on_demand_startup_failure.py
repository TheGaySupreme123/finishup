"""CLI commands that start the service on demand name a startup failure (#1040, review).

``finishup service restart`` and the MCP bridge already rendered the ``service_unavailable`` error an
on-demand start raises when the spawned service records a startup failure. Setup's on-demand
starts and its post-configuration restart caught that error and said only that the service was
not reachable; these cases hold them to the same line, with their own exit codes unchanged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import finishup.cli.app as app_module
import finishup.observability.diagnostics as diagnostics
import finishup.service.client as client_module
from finishup.adapters.control.unix_socket import LocalControlTransportError
from finishup.cli import setup
from finishup.cli.bootstrap import control_failure
from finishup.ports.control import ControlError
from finishup.service.startup_failure import record_startup_failure

_SPAWN_ID = "err_11111111-2222-4333-8444-555555555555"
_EXPECTED = (
    "service_unavailable: the local service exited while starting (stage: activation; "
    "exception_local_control_transport_error; runtime_directory_unsafe); "
    f"correlation_id {_SPAWN_ID}; read it with "
    f"'finishup service diagnostics --correlation-id {_SPAWN_ID}'"
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def startup_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ControlError:
    """The error on-demand start raises once its spawned service recorded a startup failure."""

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    record_startup_failure(
        LocalControlTransportError("runtime_directory_unsafe"),
        stage="activation",
        correlation_id=_SPAWN_ID,
        reason_code="runtime_directory_unsafe",
        unexpected=True,
    )
    return ControlError(
        "service_unavailable", retryable=False, correlation_id=_SPAWN_ID, phase="activation"
    )


def _failing_on_demand(error: ControlError, calls: list[str]) -> Any:
    async def on_demand(kind: Any, **_kwargs: Any) -> Any:
        del kind
        calls.append("spawn")
        raise error

    return on_demand


def test_the_shared_line_is_the_one_service_restart_prints(startup_error: ControlError) -> None:
    from finishup.cli.bootstrap import spawned_startup_failure_line

    printed: list[str] = []

    assert control_failure(startup_error, stderr_writer=printed.append) == 20
    assert printed == [_EXPECTED]
    assert spawned_startup_failure_line(startup_error) == _EXPECTED
    assert spawned_startup_failure_line(ControlError("service_unavailable")) is None
    assert spawned_startup_failure_line(RuntimeError("not a control error")) is None


@pytest.mark.anyio
async def test_setup_on_demand_start_names_the_startup_failure(
    startup_error: ControlError,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        client_module, "connect_service_on_demand", _failing_on_demand(startup_error, calls)
    )
    capsys.readouterr()  # the structural line recording the failure, when a sink is installed

    service = await setup._service_reachability(start_if_absent=True)  # pyright: ignore[reportPrivateUsage]

    assert service == {"reachable": False, "state": None, "vault_mode": None}
    assert calls == ["spawn"]
    assert capsys.readouterr().err.splitlines() == [_EXPECTED]


@pytest.mark.anyio
async def test_setup_llm_set_names_the_startup_failure_and_keeps_exit_20(
    startup_error: ControlError,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(setup, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(
        client_module, "connect_service_on_demand", _failing_on_demand(startup_error, [])
    )
    capsys.readouterr()

    assert await setup.run_provider_setup() == 20

    err = capsys.readouterr().err.splitlines()
    assert err == [_EXPECTED, "provider_setup_failed: service_unavailable"]


class _Holder:
    async def stop(self) -> None:
        return None

    async def close(self) -> None:
        return None


@pytest.mark.anyio
@pytest.mark.parametrize("report", [True, False])
async def test_semantic_restart_stops_at_a_startup_failure_and_names_it(
    report: bool,
    startup_error: ControlError,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A successor that records a startup failure fails the same way on every spawn."""

    async def holder(*_args: Any, **_kwargs: Any) -> _Holder:
        return _Holder()

    calls: list[str] = []
    monkeypatch.setattr(app_module, "build_service_client", holder)
    monkeypatch.setattr(
        client_module, "connect_service_on_demand", _failing_on_demand(startup_error, calls)
    )
    capsys.readouterr()

    service = await setup.restart_service_for_semantic_composition(report_startup_failure=report)

    assert service == {"reachable": False, "state": None, "vault_mode": None}
    assert calls == ["spawn"]
    # The full-screen window owns the terminal and passes report_startup_failure=False.
    assert capsys.readouterr().err.splitlines() == ([_EXPECTED] if report else [])
