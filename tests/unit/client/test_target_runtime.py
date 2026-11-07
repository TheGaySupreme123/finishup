"""``TargetRuntime`` dispatch: local and connector runtimes; an unregistered kind fails closed."""

from __future__ import annotations

from pathlib import Path

import pytest

from finishup.client import target_runtime
from finishup.client.target_runtime import (
    LocalTargetRuntime,
    ProbeResult,
    TargetRuntimeError,
    register_target_runtime,
    runtime_for,
)


def test_the_local_kind_has_the_built_in_runtime() -> None:
    assert isinstance(runtime_for("local"), LocalTargetRuntime)


@pytest.mark.parametrize("kind", ["local_port", "ssh", "https"])
def test_remote_kinds_run_through_the_connector(kind: str) -> None:
    """Approach A registers the connector runtime for every remote kind."""

    from finishup.client.connector_runtime import ConnectorTargetRuntime

    assert isinstance(runtime_for(kind), ConnectorTargetRuntime)  # type: ignore[arg-type]


@pytest.mark.parametrize("kind", ["local_port", "ssh", "https"])
def test_an_unregistered_remote_kind_is_a_closed_refusal(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    loaders = dict(target_runtime._RUNTIME_LOADERS)  # pyright: ignore[reportPrivateUsage]
    del loaders[kind]
    monkeypatch.setattr(target_runtime, "_RUNTIME_LOADERS", loaders)
    with pytest.raises(TargetRuntimeError) as raised:
        runtime_for(kind)  # type: ignore[arg-type]
    assert (raised.value.reason, raised.value.phase) == (
        "remote_unreachable",
        "runtime_unavailable",
    )


def test_an_approach_registers_its_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Runtime:
        def ensure_ready(self, root: Path | None) -> None:
            del root

        def stop(self, root: Path | None) -> None:
            del root

        def probe(self, root: Path | None) -> ProbeResult:
            del root
            return ProbeResult("ready", samples=1, round_trip_p95_ms=3)

    monkeypatch.setattr(target_runtime, "_RUNTIME_LOADERS", dict(target_runtime._RUNTIME_LOADERS))  # pyright: ignore[reportPrivateUsage]
    register_target_runtime("ssh", _Runtime)
    assert runtime_for("ssh").probe(Path("/x")).outcome == "ready"


@pytest.mark.parametrize(
    "arguments",
    [
        {"outcome": "maybe"},
        {"outcome": "ready", "reason": "Free text"},
        {"outcome": "ready", "phase": "has space"},
        {"outcome": "ready", "round_trip_p95_ms": -1},
    ],
)
def test_probe_results_carry_only_closed_tokens(arguments: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        ProbeResult(**arguments)  # type: ignore[arg-type]


def test_runtime_errors_carry_only_closed_tokens() -> None:
    with pytest.raises(ValueError):
        TargetRuntimeError("Not a token")
    with pytest.raises(ValueError):
        TargetRuntimeError("remote_unreachable", phase="no spaces allowed")
    error = TargetRuntimeError("remote_unreachable", phase="runtime_unavailable")
    assert str(error) == "remote_unreachable:runtime_unavailable"


@pytest.mark.parametrize(
    ("samples", "expected"),
    [([0.001], 1), ([0.001] * 19 + [0.5], 1), ([0.001] * 18 + [0.4, 0.5], 400)],
)
def test_p95_is_nearest_rank(samples: list[float], expected: int) -> None:
    assert target_runtime._p95(samples) == expected  # pyright: ignore[reportPrivateUsage]


def test_the_connector_probe_times_only_warm_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A just-started connector's first call opens its upstream; the probe does not time it.

    Found in the real-environment run: with ten samples the p95 is the slowest call, so the one
    cold call made ``server test`` warn that agent tools would be denied right after ``server
    connect``, while every later probe read about 30 ms.
    """

    import finishup.client.connector_runtime as connector_runtime
    import finishup.service.client as service_client
    from finishup.client.target_runtime import PROBE_SAMPLES
    from finishup.ports.control import ServiceState, ServiceStatus

    clock = [100.0]
    calls: list[int] = []
    status = ServiceStatus(
        protocol_version="1.0",
        service_version="0.3.0",
        service_instance_id="svc_00000000-0000-4000-8000-000000000081",
        service_generation="1",
        state=ServiceState.READY,
        state_reason="none",
        vault_mode="passphrase",
        capabilities=("workflow",),
        session_monitor="unavailable",
    )

    class _Client:
        async def service_status(self) -> ServiceStatus:
            # The first call is the cold one: 900 ms; every later call takes 20 ms.
            clock[0] += 0.9 if not calls else 0.02
            calls.append(1)
            return status

        async def close(self) -> None:
            return None

    async def on_demand(*_args: object, **_kwargs: object) -> _Client:
        return _Client()

    monkeypatch.setattr(service_client, "connect_service_on_demand", on_demand)
    monkeypatch.setattr(connector_runtime.time, "monotonic", lambda: clock[0])
    result = connector_runtime.ConnectorTargetRuntime().probe(tmp_path)
    assert len(calls) == PROBE_SAMPLES + 1
    assert (result.outcome, result.samples, result.round_trip_p95_ms) == (
        "ready",
        PROBE_SAMPLES,
        20,
    )
