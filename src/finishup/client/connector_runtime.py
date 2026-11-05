"""``TargetRuntime`` for remote targets in approach A: the connector is what this client runs.

``finishup server connect``, ``disconnect``, ``test`` and ``status`` reach a remote target
(``ssh``, ``https``, ``local_port``) through this runtime:

* ``ensure_ready`` starts the target root's connector when none runs and waits for its status to
  say ``ready``; a closed remote phase (``remote_unreachable``, ``remote_auth_failed``, …) is
  reported as it is;
* ``stop`` signals only the pid stamped in the connector's held lock, and for an SSH target asks
  the master to exit through its control socket (``ssh -O exit``) — never by process pattern;
* ``probe`` connects through the connector like any client, then times ``PROBE_SAMPLES``
  ``service_status`` round trips for the p95 that ``server test`` compares with hook budgets.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Final

from finishup.client.target_runtime import (
    PROBE_SAMPLES,
    ProbeResult,
    TargetRuntimeError,
)

__all__ = ["ConnectorTargetRuntime"]

_READY_SECONDS: Final = 30.0
_PROBE_SECONDS: Final = 20.0
_POLL_SECONDS: Final = 0.05


def _p95(samples: list[float]) -> int:
    ordered = sorted(samples)
    index = max(0, -(-95 * len(ordered) // 100) - 1)
    return round(ordered[index] * 1000)


def _remote_root(root: Path | None) -> Path:
    if root is None:
        raise TargetRuntimeError("remote_unreachable", phase="runtime_unavailable")
    return root


class ConnectorTargetRuntime:
    """The ``ssh``, ``https`` and ``local_port`` runtime: one connector per target root."""

    def ensure_ready(self, root: Path | None) -> None:
        from finishup.client.connector_status import (
            connector_holder,
            read_connector_status,
            spawn_connector,
        )

        target = _remote_root(root)
        if connector_holder(target) is None:
            try:
                spawn_connector(target)
            except OSError:
                raise TargetRuntimeError("service_unavailable", phase="connector_start") from None
        deadline = time.monotonic() + _READY_SECONDS
        while time.monotonic() < deadline:
            holder = connector_holder(target)
            status = read_connector_status(target)
            if holder is not None and status is not None and status.pid == holder.pid:
                if status.phase == "ready":
                    return
                if status.phase == "unavailable" and status.reason is not None:
                    raise TargetRuntimeError(status.reason)
            time.sleep(_POLL_SECONDS)
        raise TargetRuntimeError("service_unavailable", phase="timeout")

    def stop(self, root: Path | None) -> None:
        from finishup.client.connector_status import stop_connector
        from finishup.client.ssh_upstream import MASTER_NAME, UpstreamUnavailable, control_argv
        from finishup.client.targets import TargetError, read_target

        target = _remote_root(root)
        if not stop_connector(target):
            raise TargetRuntimeError("service_unavailable", phase="connector_stop")
        try:
            record = read_target(target)
        except TargetError:
            return
        if record is None or record.kind != "ssh" or not (target / "run" / MASTER_NAME).exists():
            return
        # A master that outlived its connector (killed hard) is asked to exit through its own
        # control socket.
        try:
            from finishup.client.ssh_upstream import resolve_ssh

            argv = control_argv(resolve_ssh(), target, record, "exit")
        except UpstreamUnavailable:
            return
        subprocess.run(  # noqa: S603 - fixed argv, no shell
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5.0,
            check=False,
        )

    def probe(self, root: Path | None) -> ProbeResult:
        import anyio

        from finishup.config.paths import selection_override
        from finishup.ports.control import ControlClientKind, ControlError, ServiceState
        from finishup.service.client import connect_service_on_demand

        target = _remote_root(root)

        async def probe() -> ProbeResult:
            try:
                client = await connect_service_on_demand(
                    ControlClientKind.CLI, workspace_locator=None, timeout_seconds=_PROBE_SECONDS
                )
            except ControlError as error:
                return ProbeResult("unavailable", reason=error.phase or error.reason)
            samples: list[float] = []
            try:
                status = None
                for _sample in range(PROBE_SAMPLES):
                    started = time.monotonic()
                    status = await client.service_status()
                    samples.append(time.monotonic() - started)
            except ControlError as error:
                return ProbeResult("unavailable", reason=error.phase or error.reason)
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

        with selection_override(target):
            return anyio.run(probe)
