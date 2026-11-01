"""The documented cold-start path must survive a daemon that is slow to become serviceable.

A control socket is listening from the moment it is bound, so publishing one before the daemon
can answer a handshake gave a client an accepted-but-silent connection and a five-second wait it
could not tell apart from a wedged owner. The first tool call of a fresh session is the one most
likely to land in that window.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

from test_process_owner_fencing import (
    cleanup_environment,
    isolated_environment,
    terminate_service,
)

# Longer than the client's five-second per-attempt handshake bound: the whole point is that the
# window is wider than one attempt, exactly as the 2026-08-13 cold start was.
_ACTIVATION_DELAY_SECONDS = 7.0

# A daemon whose ready activation is slow, built on the real lifecycle, the real endpoint binder,
# and the real singleton lock path a spawned successor would contend for.
_SLOW_DAEMON_PROBE = r"""
import asyncio, os
from datetime import UTC, datetime
from pathlib import Path

from finishup.adapters.control.unix_socket import bind_control_listener
from finishup.config.paths import state_dir
from finishup.service.daemon import ServiceComposition, ServiceDaemon
from finishup.service.lifecycle import ServiceLifecycle

DELAY = float(os.environ["_FINISHUP_TEST_ACTIVATION_DELAY"])

class Clock:
    def now_utc(self): return datetime(2026, 8, 13, tzinfo=UTC)
    def monotonic_seconds(self): return 1.0

class Store:
    def advance(self, instance_id): return 1

class Mode:
    value = "os_keyring"

class Vault:
    ready = True
    generation = 3
    mode = Mode()
    async def lock(self): self.ready = False
    async def close(self): self.ready = False

class ReadyApplication:
    async def load_publish_response(self, *args, **kwargs): return None
    async def store_publish_response(self, *args, **kwargs): return None
    def projection_binding_facts(self, *args, **kwargs): return None
    async def project_result_for_client(self, *args, **kwargs): return None
    async def close(self): return None

class DeferredListener:
    def __init__(self):
        self.listener = None
        self.closed = False
    def install(self, listener):
        if self.listener is not None or self.closed:
            raise RuntimeError("listener_install_invalid")
        self.listener = listener
    async def accept(self):
        if self.listener is None or self.closed:
            raise RuntimeError("listener_unavailable")
        return await self.listener.accept()
    async def aclose(self):
        if self.closed:
            return
        self.closed = True
        listener, self.listener = self.listener, None
        if listener is not None:
            await listener.aclose()

async def factory(service_generation, vault_generation):
    await asyncio.sleep(DELAY)
    return ReadyApplication()

async def run():
    listener = DeferredListener()
    async def publish(_instance):
        listener.install(await bind_control_listener())
    async def cleanup(_instance):
        await listener.aclose()
    lifecycle = ServiceLifecycle(Clock(), generation_store=Store(),
        process_start_identity_commitment="sha256:" + "4" * 64,
        singleton_lock_path=state_dir() / "service.lock",
        endpoint_publisher=publish, endpoint_cleanup=cleanup)
    await lifecycle.acquire_singleton()
    print("acquired", flush=True)
    composition = ServiceComposition(
        lifecycle=lifecycle,
        control_listener=listener,
        secret_ingress_listener=None,
        human_control_listener=None,
        human_control_service=None,
        session_monitor=None,
        human_connection_handler=None,
        vault=Vault(),
        ready_application_factory=factory,
    )
    await ServiceDaemon(_composition=composition).serve()

asyncio.run(run())
"""

# Binds and listens on the fixed control endpoint, accepts one connection, and never answers.
_SILENT_OWNER_PROBE = r"""
import os, socket, time
from platformdirs import PlatformDirs

runtime = PlatformDirs(appname="finishup", appauthor=False, roaming=False).user_runtime_path
runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
os.chmod(runtime, 0o700)
path = runtime / "control.sock"
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(str(path))
os.chmod(path, 0o600)
server.listen(1)
print("ready", flush=True)
connection, _peer = server.accept()
time.sleep(15)
connection.close()
server.close()
"""

_ON_DEMAND_PROBE = r"""
import anyio, json, time

from finishup.config.paths import log_dir
from finishup.ports.control import ControlClientKind, ControlError
from finishup.service.client import connect_service_on_demand

async def run():
    started = time.monotonic()
    outcome = "connected"
    reason = None
    try:
        client = await connect_service_on_demand(
            ControlClientKind.MCP_BRIDGE, timeout_seconds=30.0
        )
        await client.close()
    except ControlError as exc:
        outcome = "failed"
        reason = exc.reason
    elapsed_ms = int((time.monotonic() - started) * 1000)
    print(json.dumps({
        "outcome": outcome,
        "reason": reason,
        "elapsed_ms": elapsed_ms,
        "spawned": (log_dir() / "service.stderr.jsonl").exists(),
    }, separators=(",", ":"), sort_keys=True), flush=True)

anyio.run(run)
"""


def _run_on_demand(environment: dict[str, str], *, timeout: float) -> dict[str, object]:
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and in-repo probe
        (sys.executable, "-I", "-c", _ON_DEMAND_PROBE),
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


def _read_ready_line(
    process: subprocess.Popen[bytes], *, expected: bytes, timeout: float, stderr_path: Path
) -> None:
    assert process.stdout is not None
    readable, _, _ = select.select((process.stdout,), (), (), timeout)
    if readable:
        observed = process.stdout.readline()
        if observed == expected:
            return
    else:
        observed = b"<timeout>"
    stderr = stderr_path.read_bytes()[-4_096:] if stderr_path.exists() else b""
    raise AssertionError(
        f"probe readiness mismatch: expected {expected!r}, got {observed!r}; stderr={stderr!r}"
    )


def test_slow_activation_first_on_demand_connect_succeeds_within_the_budget(
    tmp_path: Path,
) -> None:
    environment = isolated_environment(tmp_path / "installation")
    environment["_FINISHUP_TEST_ACTIVATION_DELAY"] = str(_ACTIVATION_DELAY_SECONDS)
    stderr_path = tmp_path / "slow-daemon.stderr"
    stderr_stream = stderr_path.open("wb")
    owner = subprocess.Popen(  # noqa: S603 - fixed interpreter and in-repo probe
        (sys.executable, "-I", "-c", _SLOW_DAEMON_PROBE),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=stderr_stream,
        env=environment,
        close_fds=True,
        start_new_session=True,
    )
    try:
        _read_ready_line(owner, expected=b"acquired\n", timeout=10.0, stderr_path=stderr_path)

        observed = _run_on_demand(environment, timeout=45.0)

        assert observed["outcome"] == "connected", observed
        elapsed_ms = observed["elapsed_ms"]
        assert type(elapsed_ms) is int
        # The isolated client pays its own imports before this timer begins, so
        # a lower elapsed bound would depend on machine speed. The live owner
        # and successful connection pin the behavioral contract instead.
        assert owner.poll() is None, stderr_path.read_text(encoding="utf-8", errors="replace")
        assert elapsed_ms < 30_000
    finally:
        terminate_service(owner)
        if owner.stdout is not None:
            owner.stdout.close()
        stderr_stream.close()
        cleanup_environment(environment)


def test_pre_existing_silent_owner_still_fails_fast_without_a_successor(tmp_path: Path) -> None:
    environment = isolated_environment(tmp_path / "installation")
    stderr_path = tmp_path / "silent-owner.stderr"
    stderr_stream = stderr_path.open("wb")
    listener = subprocess.Popen(  # noqa: S603 - fixed interpreter and in-repo probe
        (sys.executable, "-I", "-c", _SILENT_OWNER_PROBE),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=stderr_stream,
        env=environment,
        close_fds=True,
        start_new_session=True,
    )
    try:
        _read_ready_line(listener, expected=b"ready\n", timeout=5.0, stderr_path=stderr_path)
        started = time.monotonic()

        observed = _run_on_demand(environment, timeout=20.0)

        assert time.monotonic() - started < 8.0
        assert observed["outcome"] == "failed", observed
        assert observed["reason"] == "service_unavailable"
        # A successor cannot repair a pre-existing owner; starting one only races the singleton.
        assert observed["spawned"] is False
    finally:
        if listener.poll() is None:
            os.killpg(listener.pid, 9)
            listener.wait(timeout=5)
        if listener.stdout is not None:
            listener.stdout.close()
        stderr_stream.close()
        cleanup_environment(environment)
