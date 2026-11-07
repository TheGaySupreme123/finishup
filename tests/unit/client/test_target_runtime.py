"""``TargetRuntime`` dispatch: local is built in; B registers the remote kinds; none fails closed."""

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
def test_an_unregistered_remote_kind_is_a_closed_refusal(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(target_runtime, "_RUNTIME_LOADERS", {"local": LocalTargetRuntime})
    with pytest.raises(TargetRuntimeError) as raised:
        runtime_for(kind)  # type: ignore[arg-type]
    assert (raised.value.reason, raised.value.phase) == (
        "remote_unreachable",
        "runtime_unavailable",
    )


@pytest.mark.parametrize(
    ("kind", "runtime"),
    [
        ("ssh", "SshTargetRuntime"),
        ("https", "HttpsTargetRuntime"),
        ("local_port", "HttpsTargetRuntime"),
    ],
)
def test_the_direct_dial_topology_registers_every_remote_kind(kind: str, runtime: str) -> None:
    assert type(runtime_for(kind)).__name__ == runtime  # type: ignore[arg-type]


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
