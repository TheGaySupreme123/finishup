"""``finishup service restart`` replaces even a service this CLI cannot handshake with."""

from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

import finishup.cli.app as module
import finishup.service.client as client_module
from finishup.ports.control import ControlError, ServiceState, ServiceStatus


def _status() -> ServiceStatus:
    return ServiceStatus(
        protocol_version="1.0",
        service_version="0.1.0",
        service_instance_id="svc_d8a497df-f110-4d87-89dd-8b0a45d9f980",
        service_generation="76",
        state=ServiceState.LOCKED,
        state_reason="none",
        vault_mode="uninitialized",
        capabilities=(),
        session_monitor="unavailable",
    )


class _Successor:
    async def service_status(self) -> ServiceStatus:
        return _status()

    async def close(self) -> None:
        return None


def test_restart_supersedes_an_incompatible_holder_then_starts_this_installation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    async def refused(**_kwargs: Any) -> Any:
        raise ControlError("service_incompatible", retryable=True)

    async def supersede(*, deadline: float, replace_newer: bool = False) -> bool:
        # An explicit human restart is the one path that may replace a newer holder (#820).
        events.append(f"supersede:{replace_newer}")
        return True

    async def released(pid: int, *, deadline: float) -> bool:
        events.append(f"released:{pid}")
        return True

    async def on_demand(kind: Any, **kwargs: Any) -> Any:
        events.append(f"spawn:{kwargs.get('supersede_incompatible')}")
        return _Successor()

    monkeypatch.setattr(module, "build_service_client", refused)
    monkeypatch.setattr(module, "_singleton_holder_pid", lambda: 4242)
    monkeypatch.setattr(client_module, "supersede_incompatible_service", supersede)
    monkeypatch.setattr(client_module, "wait_for_singleton_release", released)
    monkeypatch.setattr(client_module, "connect_service_on_demand", on_demand)

    result = CliRunner().invoke(module.app, ["service", "restart", "--json"])

    assert result.exit_code == 0, result.output
    assert events == ["supersede:True", "released:4242", "spawn:False"]
    assert '"state":"locked"' in result.output


def test_restart_reports_an_incompatible_holder_it_cannot_identify(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def refused(**_kwargs: Any) -> Any:
        raise ControlError("service_incompatible", retryable=True)

    async def no_candidate(*, deadline: float, replace_newer: bool = False) -> bool:
        return False

    async def must_not_spawn(kind: Any, **kwargs: Any) -> Any:
        raise AssertionError("no successor may start beside an unidentified holder")

    monkeypatch.setattr(module, "build_service_client", refused)
    monkeypatch.setattr(module, "_singleton_holder_pid", lambda: None)
    monkeypatch.setattr(client_module, "supersede_incompatible_service", no_candidate)
    monkeypatch.setattr(client_module, "connect_service_on_demand", must_not_spawn)

    result = CliRunner().invoke(module.app, ["service", "restart"])

    assert result.exit_code != 0
    assert "service_incompatible" in result.output
    assert "finishup service restart" in result.output
