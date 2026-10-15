"""An in-place upgrade switches services on the next session and never moves backwards (#820).

``finishup upgrade --accept`` no longer asks for hosts and the service to be stopped. Sessions that
were open keep the running service; the MCP bridge of the next session retires it when its
package is older, even when the wire contract is unchanged. A client from before the upgrade
must never replace a newer service. These tests run the real production daemon under a patched
package version and drive the current installation's on-demand connect against it.
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

from finishup import __version__

_OLDER_VERSION = "0.0.1"
_NEWER_VERSION = "99.0.0"
_FOREIGN_DIGEST = "sha256:" + "e" * 64


def _daemon_probe(version: str, *, foreign_digest: bool) -> str:
    """The real daemon, stamping and answering as another package version."""

    digest = (
        rf"""
import finishup.protocol.schemas as schemas
import finishup.service.control_protocol as control_protocol
schemas.schema_manifest_digest = lambda: "{_FOREIGN_DIGEST}"
control_protocol._manifest_digest = lambda: "{_FOREIGN_DIGEST}"
"""
        if foreign_digest
        else ""
    )
    return rf"""
import finishup
finishup.__version__ = "{version}"
{digest}
from finishup.service.daemon import main
main()
"""


def _on_demand_probe(kind: str) -> str:
    return rf"""
import anyio, json
from finishup.config.paths import state_dir
from finishup.ports.control import ControlClientKind, ControlError
from finishup.service.client import connect_service_on_demand
from finishup.service.lifecycle import SINGLETON_LOCK_NAME, probe_singleton_holder_identity

async def run():
    outcome, reason, version = "connected", None, None
    try:
        client = await connect_service_on_demand(
            ControlClientKind.{kind}, timeout_seconds=30.0
        )
        try:
            # The bridge kind may not call service status; its hello carries the version.
            status = client.hello_service_status
            version = None if status is None else status.service_version
        finally:
            await client.close()
    except ControlError as exc:
        outcome, reason = "failed", exc.reason
    holder = probe_singleton_holder_identity(state_dir() / SINGLETON_LOCK_NAME)
    print(json.dumps({{
        "outcome": outcome,
        "reason": reason,
        "service_version": version,
        "holder_pid": None if holder is None else holder.pid,
        "holder_version": None if holder is None else holder.service_version,
    }}, separators=(",", ":"), sort_keys=True), flush=True)

anyio.run(run)
"""


def _spawn_daemon(environment: dict[str, str], probe: str) -> subprocess.Popen[bytes]:
    return subprocess.Popen(  # noqa: S603 - fixed interpreter and in-repo probe
        (sys.executable, "-I", "-c", probe),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=environment,
        close_fds=True,
        start_new_session=True,
    )


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


def _holder_version(environment: dict[str, str]) -> str | None:
    probe = r"""
import json
from finishup.config.paths import state_dir
from finishup.service.lifecycle import SINGLETON_LOCK_NAME, probe_singleton_holder_identity
holder = probe_singleton_holder_identity(state_dir() / SINGLETON_LOCK_NAME)
print(json.dumps(None if holder is None else holder.service_version))
"""
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and in-repo probe
        (sys.executable, "-I", "-c", probe),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=environment,
        close_fds=True,
        timeout=15.0,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-4_096:]
    return cast(str | None, json.loads(completed.stdout))


def _wait_for_stamp(
    environment: dict[str, str], daemon: subprocess.Popen[bytes], version: str
) -> None:
    """Observe the daemon's own singleton stamp; the stamp is written once it owns the lock."""

    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        assert daemon.poll() is None, "daemon exited before stamping its holder identity"
        if _holder_version(environment) == version:
            return
        time.sleep(0.05)
    raise AssertionError("daemon never stamped its holder identity")


def _wait_for_exit(pid: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return True
        time.sleep(0.05)
    return False


def _stop_successor(environment: dict[str, str], pid: int | None) -> None:
    if pid is None:
        return
    stopped = run_client(environment, "stop", timeout=15.0)
    if stopped.returncode != 0 or not _wait_for_exit(pid, timeout=15.0):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        _wait_for_exit(pid, timeout=5.0)


def test_next_session_bridge_retires_an_older_compatible_service(tmp_path: Path) -> None:
    environment = isolated_environment(tmp_path / "installation")
    older = _spawn_daemon(environment, _daemon_probe(_OLDER_VERSION, foreign_digest=False))
    successor_pid: int | None = None
    try:
        _wait_for_stamp(environment, older, _OLDER_VERSION)

        # An open session's CLI or hook keeps the compatible older service it found.
        kept = _run_probe(environment, _on_demand_probe("CLI"), timeout=60.0)
        assert kept["outcome"] == "connected", kept
        assert kept["service_version"] == _OLDER_VERSION, kept
        assert kept["holder_pid"] == older.pid, kept
        assert older.poll() is None

        # The bridge of the next session retires it and runs the installed package.
        switched = _run_probe(environment, _on_demand_probe("MCP_BRIDGE"), timeout=60.0)
        assert switched["outcome"] == "connected", switched
        assert switched["service_version"] == __version__, switched
        assert switched["holder_version"] == __version__, switched
        holder_pid = switched["holder_pid"]
        assert type(holder_pid) is int and holder_pid != older.pid, switched
        successor_pid = holder_pid
        # The older service took its ordinary bounded shutdown, not a kill.
        _stdout, stderr = older.communicate(timeout=30)
        assert older.returncode == 0, stderr[-4_096:]
    finally:
        terminate_service(older)
        if older.stderr is not None:
            older.stderr.close()
        _stop_successor(environment, successor_pid)
        cleanup_environment(environment)


def test_a_client_from_before_the_upgrade_never_replaces_a_newer_service(
    tmp_path: Path,
) -> None:
    environment = isolated_environment(tmp_path / "installation")
    newer = _spawn_daemon(environment, _daemon_probe(_NEWER_VERSION, foreign_digest=True))
    try:
        _wait_for_stamp(environment, newer, _NEWER_VERSION)

        # This installation is the older one here: its bridge must report, not supersede.
        refused = _run_probe(environment, _on_demand_probe("MCP_BRIDGE"), timeout=60.0)
        assert refused["outcome"] == "failed", refused
        assert refused["reason"] == "service_incompatible", refused
        assert refused["holder_pid"] == newer.pid, refused
        assert refused["holder_version"] == _NEWER_VERSION, refused
        assert newer.poll() is None
    finally:
        terminate_service(newer)
        if newer.stderr is not None:
            newer.stderr.close()
        cleanup_environment(environment)
