"""A real ``finishup connector run`` process carries a client's session over an SSH stand-in.

ADR-051, approach A, end to end through the process boundary: a client of a selected SSH target
connects on demand, which spawns the connector as its own process (``python -m finishup
connector run --root R``, scrubbed environment). The connector starts the OpenSSH stand-in as its
master, binds the target root's control endpoint, and relays the session byte for byte to a
scripted daemon on the "server" socket. Stopping the target signals only the connector's
stamped pid; it records ``stopped`` and removes its endpoint, and the master exits through its
control socket.

Run with ``env -u FINISHUP_ISOLATED_ROOT -u YOETZ_ISOLATED_ROOT``.
"""

from __future__ import annotations

import asyncio
import os
import pwd
import shutil
import tempfile
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from builders.control_relay import ScriptedDaemon, serve_unix, write_fake_ssh
from finishup.client import targets
from finishup.client.connector_runtime import ConnectorTargetRuntime
from finishup.client.connector_status import connector_holder, read_connector_status
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import ControlClientKind
from finishup.service.client import connect_service_on_demand


@pytest.fixture
def short_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A short owner-only state root: target sockets must fit ``sun_path``."""

    real_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    root = Path(tempfile.mkdtemp(prefix=".yz-cp-", dir=real_home))
    root.chmod(0o700)
    (root / "state").mkdir(mode=0o700)
    monkeypatch.setenv("XDG_STATE_HOME", str(root / "state"))
    bin_dir = root / "bin"
    write_fake_ssh(bin_dir)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}")
    reset_selection_memo()
    try:
        yield root
    finally:
        reset_selection_memo()
        shutil.rmtree(root, ignore_errors=True)


def test_a_spawned_connector_relays_a_session_and_stops_by_its_stamped_pid(
    short_state: Path,
) -> None:
    with targets.registry_lock():
        record, root = targets.new_remote_target(
            "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/fu/bin/finishup"
        )
        record = replace(record, remote_endpoint=str(short_state / "d.sock"))
        targets.write_target(root, record)
        targets.write_selection(record)
    reset_selection_memo()
    daemon = ScriptedDaemon()

    async def exercise() -> int:
        server = await serve_unix(short_state / "d.sock", daemon)
        try:
            client = await connect_service_on_demand(ControlClientKind.CLI, timeout_seconds=30.0)
            try:
                status = await client.service_status()
                assert status.service_instance_id.startswith("svc_")
            finally:
                await client.close()
        finally:
            holder = connector_holder(root)
            assert holder is not None
            await asyncio.to_thread(ConnectorTargetRuntime().stop, root)
            server.cancel()
            await asyncio.gather(server, return_exceptions=True)
        return holder.pid

    pid = asyncio.run(exercise())
    assert pid != os.getpid()
    assert daemon.connections == 1
    deadline = time.monotonic() + 10
    while connector_holder(root) is not None and time.monotonic() < deadline:
        time.sleep(0.05)
    assert connector_holder(root) is None
    status = read_connector_status(root)
    assert status is not None
    assert (status.phase, status.reason, status.pid) == ("stopped", "stop_requested", pid)
    assert not (root / "run" / "control.sock").exists()
    assert not (root / "run" / "upstream.sock").exists()
    stderr = (root / "log" / "connector.stderr").read_bytes()
    assert b"lab.example" not in stderr
