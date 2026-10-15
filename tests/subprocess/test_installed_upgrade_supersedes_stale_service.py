"""An upgraded installation must replace a stale running service on its first call.

The 2026-08-27 Claude Code dogfood installed a new FinishUP build while the previous build's
service still owned the one per-user control endpoint. The handshake pins the schema-manifest
digest, so the old service rejected every hello from the new bridge, the new CLI could not even
ask it to stop, and the agent saw an opaque ``INTERNAL_ERROR``. This test runs a real daemon
that advertises a foreign manifest digest, then proves the current installation's on-demand
connect supersedes it (bounded shutdown of the holder, successor spawned, connection served)
inside one startup budget.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

from test_process_owner_fencing import (
    cleanup_environment,
    isolated_environment,
    run_client,
    terminate_service,
)

_FOREIGN_DIGEST = "sha256:" + "f" * 64

# The real production daemon, presenting a schema-manifest digest of another installation in
# both places an incompatible peer would: its handshake and its singleton stamp.
_STALE_DAEMON_PROBE = rf"""
import finishup.protocol.schemas as schemas
import finishup.service.control_protocol as control_protocol
schemas.schema_manifest_digest = lambda: "{_FOREIGN_DIGEST}"
control_protocol._manifest_digest = lambda: "{_FOREIGN_DIGEST}"
from finishup.service.daemon import main
main()
"""

# A status probe that speaks the stale daemon's digest, used only to wait for its readiness.
_STALE_STATUS_PROBE = rf"""
import anyio, json
import finishup.service.control_protocol as control_protocol
control_protocol._manifest_digest = lambda: "{_FOREIGN_DIGEST}"
from finishup.ports.control import ControlClientKind
from finishup.service.client import connect_service

async def run():
    client = await connect_service(ControlClientKind.CLI)
    try:
        status = await client.service_status()
        print(json.dumps({{"state": status.state.value}}))
    finally:
        await client.close()

anyio.run(run)
"""

_CURRENT_ON_DEMAND_PROBE = r"""
import anyio, json, time
from finishup.config.paths import state_dir
from finishup.ports.control import ControlClientKind, ControlError
from finishup.service.client import connect_service_on_demand
from finishup.service.lifecycle import SINGLETON_LOCK_NAME, probe_singleton_holder_identity

async def run():
    started = time.monotonic()
    outcome, reason, state = "connected", None, None
    try:
        client = await connect_service_on_demand(ControlClientKind.CLI, timeout_seconds=30.0)
        try:
            state = (await client.service_status()).state.value
        finally:
            await client.close()
    except ControlError as exc:
        outcome, reason = "failed", exc.reason
    holder = probe_singleton_holder_identity(state_dir() / SINGLETON_LOCK_NAME)
    print(json.dumps({
        "outcome": outcome,
        "reason": reason,
        "state": state,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "holder_pid": None if holder is None else holder.pid,
        "holder_digest": None if holder is None else holder.schema_manifest_digest,
    }, separators=(",", ":"), sort_keys=True), flush=True)

anyio.run(run)
"""


def _run_probe(environment: dict[str, str], probe: str, *, timeout: float) -> dict[str, object]:
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and in-repo probe
        (sys.executable, "-I", "-c", probe),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=environment,
        close_fds=True,
        timeout=timeout,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-4_096:]
    decoded = json.loads(completed.stdout)
    assert type(decoded) is dict
    return cast(dict[str, object], decoded)


def _wait_for_stale_ready(environment: dict[str, str], daemon: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        assert daemon.poll() is None, "stale daemon exited before becoming ready"
        try:
            observed = subprocess.run(  # noqa: S603 - fixed interpreter and in-repo probe
                (sys.executable, "-I", "-c", _STALE_STATUS_PROBE),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env=environment,
                close_fds=True,
                timeout=max(0.5, deadline - time.monotonic()),
                check=False,
            )
        except subprocess.TimeoutExpired:
            continue
        if observed.returncode == 0:
            return
        time.sleep(0.05)
    raise AssertionError("stale daemon never became ready")


def _wait_for_exit(pid: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return True
        time.sleep(0.05)
    return False


def test_first_on_demand_connect_after_an_upgrade_replaces_the_stale_service(
    tmp_path: Path,
) -> None:
    environment = isolated_environment(tmp_path / "installation")
    stale = subprocess.Popen(  # noqa: S603 - fixed interpreter and in-repo probe
        (sys.executable, "-I", "-c", _STALE_DAEMON_PROBE),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=environment,
        close_fds=True,
        start_new_session=True,
    )
    successor_pid: int | None = None
    try:
        _wait_for_stale_ready(environment, stale)
        # Control: the current installation's plain connect is refused as incompatible.
        refused = run_client(environment, "status", timeout=15.0)
        assert refused.returncode != 0
        assert b"service_incompatible" in refused.stderr

        observed = _run_probe(environment, _CURRENT_ON_DEMAND_PROBE, timeout=60.0)

        assert observed["outcome"] == "connected", observed
        assert observed["state"] in {"locked", "ready"}, observed
        assert observed["holder_digest"] != _FOREIGN_DIGEST, observed
        holder_pid = observed["holder_pid"]
        assert type(holder_pid) is int and holder_pid != stale.pid, observed
        successor_pid = holder_pid
        # The stale holder took its ordinary bounded shutdown path, not a kill.
        _stale_stdout, stale_stderr = stale.communicate(timeout=30)
        assert stale.returncode == 0, stale_stderr[-4_096:]
        assert type(observed["elapsed_ms"]) is int and observed["elapsed_ms"] < 30_000
        # And the compatible successor now answers this installation's ordinary client.
        status = run_client(environment, "status", timeout=15.0)
        assert status.returncode == 0, status.stderr[-4_096:]
    finally:
        terminate_service(stale)
        if stale.stderr is not None:
            stale.stderr.close()
        if successor_pid is not None:
            stopped = run_client(environment, "stop", timeout=15.0)
            if stopped.returncode != 0 or not _wait_for_exit(successor_pid, timeout=15.0):
                try:
                    os.kill(successor_pid, signal.SIGKILL)
                except OSError:
                    pass
                _wait_for_exit(successor_pid, timeout=5.0)
        cleanup_environment(environment)
