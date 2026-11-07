"""How a client makes one server target usable, stops it, and probes it (ADR-051).

``finishup server connect``, ``disconnect``, ``test`` and ``status`` dispatch through
``TargetRuntime`` by target kind. The foundation ships the ``local`` runtime: a named local server
(or the everyday one) whose service starts on demand exactly like today's. The direct-dial
topology (approach B) registers its remote runtimes in ``_RUNTIME_LOADERS``: ``ssh`` (the
target's persistent OpenSSH master) and ``https``/``local_port`` (the gateway itself), loaded from
``finishup.client.direct_runtime`` only when used. A kind with no registered runtime fails with the
closed reason ``remote_unreachable`` in phase ``runtime_unavailable``, never a silent fallback to a
local service.

Runtimes are synchronous: the CLI calls them outside its event loop, and the terminal interface
calls them from a worker thread. Every failure is a ``TargetRuntimeError`` carrying closed tokens.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Protocol

from finishup.client.targets import TargetKind
from finishup.protocol.errors import REMOTE_CONNECTION_PHASES

__all__ = [
    "PROBE_SAMPLES",
    "LocalTargetRuntime",
    "ProbeOutcome",
    "ProbeResult",
    "TargetRuntime",
    "TargetRuntimeError",
    "probe_service",
    "register_target_runtime",
    "runtime_for",
]

type ProbeOutcome = Literal["ready", "reachable", "not_running", "unavailable"]

# Status round trips a probe times, for the p95 that ``server test`` compares with hook budgets.
PROBE_SAMPLES: Final = 10
_PROBE_CONNECT_SECONDS: Final = 5.0
_START_SECONDS: Final = 30.0
_TOKEN: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)


class TargetRuntimeError(Exception):
    """A bounded runtime failure: a closed ``reason`` and an optional closed ``phase``."""

    reason: str
    phase: str | None

    def __init__(self, reason: str, *, phase: str | None = None) -> None:
        if not _TOKEN.match(reason) or (phase is not None and not _TOKEN.match(phase)):
            raise ValueError("target_runtime_reason_invalid")
        self.reason = reason
        self.phase = phase
        super().__init__(reason if phase is None else f"{reason}:{phase}")


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """What one probe observed. Every text field is a closed token or a service-minted value."""

    outcome: ProbeOutcome
    reason: str | None = None
    phase: str | None = None
    service_version: str | None = None
    service_instance_id: str | None = None
    service_state: str | None = None
    vault_mode: str | None = None
    round_trip_p95_ms: int | None = None
    samples: int = 0

    def __post_init__(self) -> None:
        if self.outcome not in {"ready", "reachable", "not_running", "unavailable"}:
            raise ValueError("probe_outcome_invalid")
        for token in (self.reason, self.phase):
            if token is not None and not _TOKEN.match(token):
                raise ValueError("probe_reason_invalid")
        if self.round_trip_p95_ms is not None and self.round_trip_p95_ms < 0:
            raise ValueError("probe_timing_invalid")


class TargetRuntime(Protocol):
    """Make a target usable, stop what this client started for it, and probe it.

    ``root`` is the target root; ``None`` names the everyday local server.
    """

    def ensure_ready(self, root: Path | None) -> None: ...

    def stop(self, root: Path | None) -> None: ...

    def probe(self, root: Path | None) -> ProbeResult: ...


def _p95(samples: list[float]) -> int:
    ordered = sorted(samples)
    index = max(0, -(-95 * len(ordered) // 100) - 1)
    return round(ordered[index] * 1000)


class LocalTargetRuntime:
    """The everyday server and named local servers: an on-demand service per root.

    Each operation resolves ``root`` as the selection for its duration
    (``config.paths.selection_override``), so the endpoint, lock, and spawned service are that
    root's own, whichever target this process itself has selected.
    """

    def ensure_ready(self, root: Path | None) -> None:
        import anyio

        from finishup.config.paths import selection_override
        from finishup.ports.control import ControlClientKind, ControlError
        from finishup.service.client import connect_service_on_demand

        async def start() -> None:
            client = await connect_service_on_demand(
                ControlClientKind.CLI, workspace_locator=None, timeout_seconds=_START_SECONDS
            )
            await client.close()

        with selection_override(root):
            try:
                anyio.run(start)
            except ControlError as error:
                raise TargetRuntimeError(error.reason) from None

    def stop(self, root: Path | None) -> None:
        import anyio

        from finishup.config.paths import selection_override
        from finishup.ports.control import ControlClientKind, ControlError
        from finishup.service.client import connect_service

        async def stop() -> None:
            try:
                with anyio.fail_after(_PROBE_CONNECT_SECONDS):
                    client = await connect_service(ControlClientKind.CLI, workspace_locator=None)
            except ControlError as error:
                if error.reason == "service_unavailable":
                    return
                raise
            try:
                await client.stop()
            finally:
                await client.close()

        with selection_override(root):
            try:
                anyio.run(stop)
            except ControlError as error:
                raise TargetRuntimeError(error.reason) from None
            except TimeoutError:
                raise TargetRuntimeError("service_unavailable", phase="timeout") from None

    def probe(self, root: Path | None) -> ProbeResult:
        return probe_service(root)


def probe_service(root: Path | None) -> ProbeResult:
    """Connect to ``root``'s server (as its selection) and time ``PROBE_SAMPLES`` status calls.

    The connection goes through whatever transport the root's record names, so the same probe
    serves a local service and a remote one. A remote connection's failure keeps its closed
    remote phase (``remote_service_not_running`` reads as ``not_running``); a local one reports
    exactly as before.
    """

    import anyio

    from finishup.config.paths import selection_override
    from finishup.ports.control import ControlClientKind, ControlError, ServiceState
    from finishup.service.client import connect_service

    async def probe() -> ProbeResult:
        try:
            with anyio.fail_after(_PROBE_CONNECT_SECONDS):
                client = await connect_service(ControlClientKind.CLI, workspace_locator=None)
        except ControlError as error:
            if error.phase in REMOTE_CONNECTION_PHASES:
                remote: ProbeOutcome = (
                    "not_running" if error.phase == "remote_service_not_running" else "unavailable"
                )
                return ProbeResult(remote, reason=error.reason, phase=error.phase)
            outcome: ProbeOutcome = (
                "not_running" if error.reason == "service_unavailable" else "unavailable"
            )
            return ProbeResult(outcome, reason=error.reason)
        except TimeoutError:
            return ProbeResult("unavailable", reason="service_unavailable", phase="timeout")
        samples: list[float] = []
        try:
            status = None
            for _sample in range(PROBE_SAMPLES):
                started = time.monotonic()
                status = await client.service_status()
                samples.append(time.monotonic() - started)
        except ControlError as error:
            return ProbeResult("unavailable", reason=error.reason)
        finally:
            await client.close()
        assert status is not None
        return ProbeResult(
            "ready" if status.state is ServiceState.READY else "reachable",
            service_version=status.service_version,
            service_instance_id=status.service_instance_id,
            service_state=status.state.value,
            vault_mode=status.vault_mode,
            round_trip_p95_ms=_p95(samples),
            samples=len(samples),
        )

    with selection_override(root):
        return anyio.run(probe)


def _ssh_runtime() -> TargetRuntime:
    from finishup.client.direct_runtime import SshTargetRuntime

    return SshTargetRuntime()


def _https_runtime() -> TargetRuntime:
    from finishup.client.direct_runtime import HttpsTargetRuntime

    return HttpsTargetRuntime()


# Kind -> loader. The foundation ships ``local``; the direct-dial topology adds its remote kinds.
_RUNTIME_LOADERS: dict[str, Callable[[], TargetRuntime]] = {
    "local": LocalTargetRuntime,
    "ssh": _ssh_runtime,
    "https": _https_runtime,
    "local_port": _https_runtime,
}


def register_target_runtime(kind: TargetKind, loader: Callable[[], TargetRuntime]) -> None:
    """Register (or replace) the runtime loader for one target kind."""

    _RUNTIME_LOADERS[kind] = loader


def runtime_for(kind: TargetKind) -> TargetRuntime:
    """The runtime for ``kind``; ``remote_unreachable``/``runtime_unavailable`` when none."""

    loader = _RUNTIME_LOADERS.get(kind)
    if loader is None:
        raise TargetRuntimeError("remote_unreachable", phase="runtime_unavailable")
    return loader()
