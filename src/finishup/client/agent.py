"""The workspace agent of a remote server target: ``finishup agent run --root <target root>``.

A server on another machine checks the agent's work through this process (ADR-051). It is a
long-lived, pull-based client of the server's network API, one per target root:

* Client processes note each workspace they work in (``note_workspace``: an owner-only record of
  the path under ``<target root>/state/agent-workspaces/``; the path never leaves this machine)
  and start the agent when none runs (``ensure_agent``).
* For each noted workspace the agent claims it (a keyed digest, ``client.remote_workspace``),
  registers with ``POST /v1/agents``, long-polls ``GET /v1/agents/{id}/work`` for the server's
  ``workspace_call`` frames, answers each in a worker thread with ``WorkspaceAgentHandler`` (the
  real local adapters and their fences), and sends the ``workspace_reply`` with
  ``POST /v1/agents/{id}/replies``. Inline calls (a check a client is waiting on) and background
  calls (a review that runs on after the call returned) arrive the same way.
* For each noted workspace it also delivers what the hooks captured and could not deliver
  themselves (``CapturedObservationDelivery``: the shared ``ClientObservationDrain`` over a
  claim-bound connection, every row attested from this client's own store).
* It holds ``<target root>/state/agent.lock`` (an exclusive lock stamped with its pid), ends a
  workspace 15 minutes after its last note, and exits after 15 minutes without workspaces or on
  ``SIGTERM`` (``stop_agent`` signals the stamped pid; nothing is killed by name).

Records carry closed tokens only; no path, claim, call argument or server name is logged.
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import hashlib
import os
import secrets
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast

from finishup.client.remote_workspace import (
    CapturedObservationDelivery,
    WorkspaceCallHandler,
    claim_for_workspace,
    handler_for_workspace,
)
from finishup.client.targets import ServerTarget, TargetError, read_target
from finishup.config.paths import PathSafetyError, ensure_owner_only_dir
from finishup.domain.values import JsonObject, freeze_json
from finishup.observability.logging import record_bounded_event_without_raising
from finishup.ports.control import WorkspaceCall, WorkspaceClaim, WorkspaceLocator
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

__all__ = [
    "AGENT_LOCK_NAME",
    "AGENT_WORKSPACES_DIR",
    "IDLE_EXIT_SECONDS",
    "WorkspaceAgentLoop",
    "agent_pid",
    "ensure_agent",
    "note_workspace",
    "run_workspace_agent",
    "stop_agent",
]

AGENT_LOCK_NAME: Final = "agent.lock"
AGENT_WORKSPACES_DIR: Final = "agent-workspaces"
AGENT_WORKSPACE_SCHEMA: Final = "yoetz.agent-workspace/1"
# A workspace stays served this long after the last client process noted it; the agent exits
# this long after its last workspace ended.
WORKSPACE_IDLE_SECONDS: Final = 900.0
IDLE_EXIT_SECONDS: Final = 900.0
_SCAN_SECONDS: Final = 2.0
_POLL_WAIT_MS: Final = 20_000
_MAX_CONCURRENT_CALLS: Final = 4
_RETRY_SECONDS: Final = (1.0, 2.0, 5.0, 10.0, 30.0)
_MAX_RECORD_BYTES: Final = 16_384
_MAX_WORK_BYTES: Final = 64 * 1024 * 1024
_COMPONENT: Final = "client.agent"


def _record(operation: str, reason: str) -> None:
    record_bounded_event_without_raising(component=_COMPONENT, operation=operation, reason=reason)


def _workspaces_dir(root: Path) -> Path:
    return root / "state" / AGENT_WORKSPACES_DIR


def note_workspace(root: Path, locator: WorkspaceLocator) -> None:
    """Note that a client process works in ``locator`` for this remote target root.

    The record is owner-only client state beside the target; touching it keeps the workspace
    served. A failure here never fails the caller's own request.
    """

    if type(locator) is not WorkspaceLocator:
        raise TypeError("workspace_locator_invalid")
    directory = _workspaces_dir(root)
    name = "w_" + hashlib.sha256(os.fsencode(locator.path)).hexdigest()[:32] + ".json"
    path = directory / name
    body = canonical_encode({"path": locator.path, "schema": AGENT_WORKSPACE_SCHEMA}) + b"\n"
    with contextlib.suppress(OSError, PathSafetyError):
        ensure_owner_only_dir(directory)
        try:
            facts = path.lstat()
        except FileNotFoundError:
            facts = None
        if facts is not None and stat.S_ISREG(facts.st_mode) and facts.st_size == len(body):
            os.utime(path, follow_symlinks=False)
            return
        temporary = directory / f".{name}.{secrets.token_hex(4)}.tmp"
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        try:
            os.write(descriptor, body)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)


def _noted_workspaces(root: Path, *, now: float) -> tuple[dict[str, WorkspaceLocator], list[Path]]:
    """Live noted workspaces by record name, and the records that went idle."""

    live: dict[str, WorkspaceLocator] = {}
    idle: list[Path] = []
    try:
        entries = list(os.scandir(_workspaces_dir(root)))
    except OSError:
        return live, idle
    for entry in entries:
        if not entry.name.startswith("w_") or not entry.name.endswith(".json"):
            continue
        try:
            facts = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
            or facts.st_size > _MAX_RECORD_BYTES
        ):
            continue
        if now - facts.st_mtime >= WORKSPACE_IDLE_SECONDS:
            idle.append(Path(entry.path))
            continue
        try:
            value = strict_json_parse(Path(entry.path).read_bytes().rstrip(b"\n"))
            document = cast(dict[str, JsonValue], value)
            if type(value) is not dict or document.get("schema") != AGENT_WORKSPACE_SCHEMA:
                continue
            live[entry.name] = WorkspaceLocator(path=cast(str, document["path"]))
        except (OSError, ValueError, TypeError, KeyError):
            continue
    return live, idle


# --- singleton and process lifetime -----------------------------------------------------------


def _lock_path(root: Path) -> Path:
    return root / "state" / AGENT_LOCK_NAME


def _open_lock(root: Path) -> int:
    ensure_owner_only_dir(root / "state")
    descriptor = os.open(
        _lock_path(root), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    facts = os.fstat(descriptor)
    if not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid():
        os.close(descriptor)
        raise OSError("agent_lock_unsafe")
    return descriptor


def agent_pid(root: Path) -> int | None:
    """The pid stamped by the running agent of ``root``, or ``None`` when none holds the lock."""

    try:
        descriptor = _open_lock(root)
    except (OSError, PathSafetyError):
        return None
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            stamp = os.pread(descriptor, 32, 0).decode("ascii", "replace").strip()
            return int(stamp) if stamp.isdigit() else None
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return None
    finally:
        os.close(descriptor)


def _agent_environment() -> dict[str, str]:
    """The agent's environment: inherited, minus secret-shaped names and FinishUP roots.

    The agent is told its root by ``--root``; an inherited isolation root must not redirect it.
    """

    from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES

    markers = ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "APIKEY", "CREDENTIAL")
    return {
        name: value
        for name, value in os.environ.items()
        if name not in ISOLATED_ROOT_ENV_NAMES and not any(m in name.upper() for m in markers)
    }


def ensure_agent(root: Path) -> bool:
    """Start the agent of ``root`` unless one holds its lock; ``True`` when one was started.

    Non-blocking: the spawned agent takes the lock itself, and a second spawn that loses the race
    exits at once.
    """

    if agent_pid(root) is not None:
        return False
    try:
        ensure_owner_only_dir(root / "log")
        log = os.open(
            root / "log" / "agent.stderr.log",
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
    except (OSError, PathSafetyError):
        return False
    try:
        subprocess.Popen(  # noqa: S603 - fixed interpreter, module and arguments
            (sys.executable, "-m", "finishup", "agent", "run", "--root", os.fspath(root)),
            close_fds=True,
            env=_agent_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=log,
            start_new_session=True,
        )
    except OSError:
        return False
    finally:
        os.close(log)
    return True


def stop_agent(root: Path) -> bool:
    """Ask the running agent of ``root`` to stop by its stamped pid; ``True`` when one was."""

    pid = agent_pid(root)
    if pid is None or pid <= 1 or pid == os.getpid():
        return False
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.kill(pid, signal.SIGTERM)
        return True
    return False


# --- the loop -------------------------------------------------------------------------------


class _AgentApi:
    """The agent's side of the network API: register, poll, reply, end."""

    def __init__(self, http: Any, headers: dict[str, str]) -> None:
        self._http = http
        self._headers = headers

    def _with_claim(self, claim: WorkspaceClaim) -> dict[str, str]:
        from finishup.service.network_protocol import HEADER_CLAIM, encode_claim_header

        return {**self._headers, HEADER_CLAIM: encode_claim_header(claim)}

    async def register(self, claim: WorkspaceClaim, handler: WorkspaceCallHandler) -> Any:
        from finishup.service.network_protocol import (
            agent_declaration_document,
            parse_agent_registration,
        )

        response = await self._http.request(
            "POST",
            "/v1/agents",
            content=agent_declaration_document(handler.declaration),
            headers={**self._with_claim(claim), "content-type": "application/json"},
        )
        if response.status_code != 201:
            raise _AgentRetry("registration_refused")
        try:
            return parse_agent_registration(response.content)
        except ValueError:
            raise _AgentRetry("registration_invalid") from None

    async def work(self, agent_id: str) -> tuple[WorkspaceCall, ...] | None:
        """Pending calls; ``None`` when the server no longer knows this agent."""

        from finishup.service.control_protocol import parse_workspace_call
        from finishup.service.network_protocol import parse_agent_work

        response = await self._http.request(
            "GET", f"/v1/agents/{agent_id}/work?wait_ms={_POLL_WAIT_MS}", headers=self._headers
        )
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise _AgentRetry("work_refused")
        try:
            work = parse_agent_work(response.content, max_bytes=_MAX_WORK_BYTES)
            calls: list[WorkspaceCall] = []
            for frame in work.calls:
                frozen = freeze_json(dict(frame))
                if type(frozen) is not JsonObject:
                    raise ValueError("call_invalid")
                calls.append(parse_workspace_call(frozen))
        except Exception:
            raise _AgentRetry("work_invalid") from None
        return tuple(calls)

    async def reply(self, agent_id: str, body: bytes) -> bool:
        response = await self._http.request(
            "POST",
            f"/v1/agents/{agent_id}/replies",
            content=body,
            headers={**self._headers, "content-type": "application/json"},
        )
        return response.status_code == 202

    async def end(self, agent_id: str) -> None:
        with contextlib.suppress(Exception):
            await self._http.request("DELETE", f"/v1/agents/{agent_id}", headers=self._headers)


class _AgentRetry(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class _Delivery(Protocol):
    """Background delivery of one workspace's captured observation (``remote_workspace``)."""

    async def deliver(self) -> object: ...

    async def close(self) -> None: ...


type _ClaimFactory = Callable[[ServerTarget, WorkspaceLocator], Awaitable[WorkspaceClaim | None]]
type _HandlerFactory = Callable[[WorkspaceLocator, Path], WorkspaceCallHandler | None]
type _DeliveryFactory = Callable[[ServerTarget, Path, WorkspaceLocator, WorkspaceClaim], _Delivery]


def _captured_observation_delivery(
    record: ServerTarget, root: Path, locator: WorkspaceLocator, claim: WorkspaceClaim
) -> _Delivery:
    return CapturedObservationDelivery(record, root, locator, claim)


@dataclass(slots=True)
class _Served:
    task: asyncio.Task[None]
    agent_id: str | None = None


class WorkspaceAgentLoop:
    """Serve every noted workspace of one remote target until idle or stopped."""

    def __init__(
        self,
        root: Path,
        record: ServerTarget,
        *,
        http: Any | None = None,
        headers: dict[str, str] | None = None,
        claim_factory: _ClaimFactory = claim_for_workspace,
        handler_factory: _HandlerFactory = handler_for_workspace,
        delivery_factory: _DeliveryFactory = _captured_observation_delivery,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        scan_seconds: float = _SCAN_SECONDS,
        idle_exit_seconds: float = IDLE_EXIT_SECONDS,
    ) -> None:
        self._root = root
        self._record = record
        self._http = http
        self._headers = headers
        self._claim_factory = claim_factory
        self._handler_factory = handler_factory
        self._delivery_factory = delivery_factory
        self._clock = clock
        self._wall_clock = wall_clock
        self._scan_seconds = scan_seconds
        self._idle_exit_seconds = idle_exit_seconds
        self._served: dict[str, _Served] = {}
        self._stopping = asyncio.Event()
        self._calls = asyncio.Semaphore(_MAX_CONCURRENT_CALLS)

    def stop(self) -> None:
        self._stopping.set()

    def _open(self) -> _AgentApi:
        if self._http is None or self._headers is None:
            from finishup.client.rest_client import open_rest_http

            self._http, self._headers = open_rest_http(self._record, self._root)
        return _AgentApi(self._http, self._headers)

    async def run(self) -> int:
        api = self._open()
        idle_since = self._clock()
        try:
            while not self._stopping.is_set():
                live, idle = _noted_workspaces(self._root, now=self._wall_clock())
                for path in idle:
                    with contextlib.suppress(OSError):
                        path.unlink()
                for name in tuple(self._served):
                    if name not in live:
                        await self._end(api, name)
                for name, locator in live.items():
                    served = self._served.get(name)
                    if served is None or served.task.done():
                        self._served[name] = _Served(
                            asyncio.create_task(self._serve(api, name, locator))
                        )
                if self._served:
                    idle_since = self._clock()
                elif self._clock() - idle_since >= self._idle_exit_seconds:
                    _record("workspace_agent_exit", "idle")
                    break
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(self._scan_seconds):
                        await self._stopping.wait()
        finally:
            for name in tuple(self._served):
                await self._end(api, name)
            if self._http is not None:
                with contextlib.suppress(Exception):
                    await self._http.aclose()
        return 0

    async def _end(self, api: _AgentApi, name: str) -> None:
        served = self._served.pop(name, None)
        if served is None:
            return
        served.task.cancel()
        await asyncio.gather(served.task, return_exceptions=True)
        if served.agent_id is not None:
            await api.end(served.agent_id)

    async def _serve(self, api: _AgentApi, name: str, locator: WorkspaceLocator) -> None:
        try:
            claim = await self._claim_factory(self._record, locator)
            handler = None if claim is None else self._handler_factory(locator, self._root)
        except asyncio.CancelledError:
            raise
        except Exception:
            claim = handler = None
        if claim is None or handler is None:
            # Nothing can answer for this workspace: the server's calls end typed.
            _record("workspace_agent_register", "workspace_agent_unavailable")
            await self._stopping.wait()
            return
        delivery = self._delivery_factory(self._record, self._root, locator, claim)
        delivering = asyncio.create_task(self._deliver(delivery))
        try:
            await self._register_and_poll(api, name, claim, handler)
        finally:
            delivering.cancel()
            await asyncio.gather(delivering, return_exceptions=True)
            with contextlib.suppress(Exception):
                await delivery.close()

    async def _deliver(self, delivery: _Delivery) -> None:
        """Deliver this workspace's captured observation once per scan, until stopped."""

        while not self._stopping.is_set():
            try:
                await delivery.deliver()
            except asyncio.CancelledError:
                raise
            except Exception:
                _record("workspace_agent_drain", "drain_failed")
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(self._scan_seconds):
                    await self._stopping.wait()

    async def _register_and_poll(
        self, api: _AgentApi, name: str, claim: WorkspaceClaim, handler: WorkspaceCallHandler
    ) -> None:
        attempt = 0
        while not self._stopping.is_set():
            try:
                registration = await api.register(claim, handler)
                self._served[name].agent_id = registration.agent_id
                _record("workspace_agent_register", "registered")
                attempt = 0
                await self._poll(api, registration.agent_id, registration.workspace_handle, handler)
                _record("workspace_agent_register", "agent_unknown")
            except asyncio.CancelledError:
                raise
            except Exception as error:
                reason = error.reason if isinstance(error, _AgentRetry) else "remote_unreachable"
                _record("workspace_agent_poll", reason)
                delay = _RETRY_SECONDS[min(attempt, len(_RETRY_SECONDS) - 1)]
                attempt += 1
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(delay):
                        await self._stopping.wait()

    async def _poll(
        self, api: _AgentApi, agent_id: str, handle: str, handler: WorkspaceCallHandler
    ) -> None:
        pending: set[asyncio.Task[None]] = set()
        try:
            while not self._stopping.is_set():
                calls = await api.work(agent_id)
                if calls is None:
                    return
                for call in calls:
                    task = asyncio.create_task(self._answer(api, agent_id, handle, handler, call))
                    pending.add(task)
                    task.add_done_callback(pending.discard)
        finally:
            for task in tuple(pending):
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    async def _answer(
        self,
        api: _AgentApi,
        agent_id: str,
        handle: str,
        handler: WorkspaceCallHandler,
        call: WorkspaceCall,
    ) -> None:
        from finishup.service.control_protocol import workspace_reply_frame

        async with self._calls:
            reply = await asyncio.to_thread(handler.answer, call, workspace_handle=handle)
        body = canonical_encode(dict(workspace_reply_frame(reply)))
        if not await api.reply(agent_id, body):
            _record("workspace_agent_reply", "reply_refused")


def run_workspace_agent(root: Path) -> int:
    """The ``finishup agent run`` body: hold the lock, serve until idle or ``SIGTERM``."""

    try:
        record = read_target(root)
    except TargetError:
        record = None
    if record is None or not record.is_remote:
        _record("workspace_agent_start", "target_not_remote")
        return 2
    try:
        descriptor = _open_lock(root)
    except (OSError, PathSafetyError):
        _record("workspace_agent_start", "agent_lock_unsafe")
        return 20
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        os.ftruncate(descriptor, 0)
        os.pwrite(descriptor, f"{os.getpid()}\n".encode("ascii"), 0)

        async def main() -> int:
            loop = WorkspaceAgentLoop(root, record)
            running = asyncio.get_running_loop()
            for signum in (signal.SIGTERM, signal.SIGINT):
                running.add_signal_handler(signum, loop.stop)
            return await loop.run()

        return asyncio.run(main())
    finally:
        with contextlib.suppress(OSError):
            os.ftruncate(descriptor, 0)
        os.close(descriptor)
