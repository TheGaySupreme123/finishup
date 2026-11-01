"""Cross-process clean reopen and ordinary-client reconnect recovery."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from test_process_owner_fencing import (
    cleanup_environment,
    isolated_environment,
    spawn_service,
    stop_service_public,
    terminate_service,
    wait_status,
)

_DROP_CLIENT = r"""
import anyio, os
from finishup.ports.control import ControlClientKind
from finishup.service.client import connect_service

async def run():
    await connect_service(ControlClientKind.CLI)
    os._exit(91)

anyio.run(run)
"""


def test_clean_stop_reopen_advances_once_and_preserves_installation(tmp_path: Path) -> None:
    environment = isolated_environment(tmp_path / "installation")
    first = spawn_service(environment)
    second: subprocess.Popen[bytes] | None = None
    try:
        before = wait_status(environment, (first,))
        stop_service_public(environment, first)

        second = spawn_service(environment)
        after = wait_status(environment, (second,))
        assert after["generation"] == before["generation"] + 1
        assert after["instance_id"] != before["instance_id"]
        assert after["state"] == before["state"] == "locked"

        stop_service_public(environment, second)
    finally:
        terminate_service(first)
        if second is not None:
            terminate_service(second)
        cleanup_environment(environment)


def test_client_eof_does_not_change_generation_and_fresh_client_reconnects(
    tmp_path: Path,
) -> None:
    environment = isolated_environment(tmp_path / "installation")
    service = spawn_service(environment)
    try:
        before = wait_status(environment, (service,))
        dropped = subprocess.run(
            (sys.executable, "-I", "-c", _DROP_CLIENT),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=environment,
            close_fds=True,
            timeout=10,
            check=False,
        )
        assert dropped.returncode == 91
        assert dropped.stdout == dropped.stderr == b""

        after = wait_status(environment, (service,))
        assert after == before
        stop_service_public(environment, service)
    finally:
        terminate_service(service)
        cleanup_environment(environment)


def test_release_daemon_ignores_forged_fault_environment() -> None:
    from helpers.fault_controller import assert_fault_hooks_unavailable_in_release

    assert_fault_hooks_unavailable_in_release(
        {
            "HOME": os.environ.get("HOME", "/nonexistent"),
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
    )
