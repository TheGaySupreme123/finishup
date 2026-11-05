"""``finishup connector``: the vault-less relay behind a remote target's control endpoint.

Approach A of ADR-051 (the edge relay). Every client surface — hooks, the MCP bridge, the CLI and
the terminal interface — keeps dialling ``<target root>/run/control.sock`` exactly as it dials a
local service. For a remote target that endpoint is served by this process, one per target root:

* it holds the root's singleton lock (``state/connector.lock``, stamped) and binds the endpoint
  with the same owner-only checks and peer-UID authentication as the service;
* for an ``ssh`` target it keeps one OpenSSH master warm and pumps each local connection's bytes
  to its own channel of that master, parsing nothing but the first frame (the hello);
* for an ``https`` or ``local_port`` target it maps each local connection onto one session of the
  HTTPS binding v1 against ``finishup service gateway`` on the server host;
* it alone reads an HTTPS target's API key;
* it writes ``state/connector-status.json`` (closed tokens only) so a client whose connection
  failed can name the remote phase, and it exits after 15 idle minutes.

A hello that names a ``workspace_locator`` is refused here for every kind: a path on this machine
never travels to a server on another one. Server-to-client frames (``workspace_call``) and the
client's ``workspace_reply`` frames pass through both relays unchanged.

The connector is started on demand by ``finishup.service.client`` and by ``finishup server
connect``; it never starts, stops or supersedes a FinishUP service, except that for an SSH
target it may run the server's own ``<launcher> service start`` once when the remote endpoint
is missing (an idle-stopped service).
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol, cast

from finishup import __version__
from finishup.adapters.control.unix_socket import (
    AuthenticatedUnixStream,
    EndpointKind,
    LocalControlTransportError,
    UnixEndpointListener,
    bind_control_listener,
    connect_owner_only_endpoint,
    remove_stale_endpoint,
)
from finishup.client.connector_status import (
    CONNECTOR_IDLE_SECONDS,
    ConnectorLock,
    ConnectorLockBusy,
    ConnectorPhase,
    ConnectorStatus,
    new_status,
    now_stamp,
    read_connector_status,
    write_connector_status,
)
from finishup.client.ssh_upstream import SshMaster, UpstreamUnavailable
from finishup.client.targets import ServerTarget
from finishup.ports.control import WorkspaceClaim, WorkspaceIdentityKind
from finishup.service.control_protocol import (
    ControlFrame,
    ControlProtocolError,
    encode_control_frame,
    read_control_frame,
)

__all__ = [
    "AGENT_LEASE_SECONDS",
    "BackgroundAgent",
    "Connector",
    "open_background_agent",
    "run_connector",
    "run_connector_process",
]

# How long the connector keeps a background workspace agent after that workspace's last hello.
AGENT_LEASE_SECONDS: Final = 900.0
_HELLO_SECONDS: Final = 10.0
_LOCK_RETRY_SECONDS: Final = 0.5
_TICK_SECONDS: Final = 1.0
_PUMP_CHUNK: Final = 65_536
# One extra remote ``service start`` per this window at most (an SSH target whose service
# stopped while idle).
_RESTART_WINDOW_SECONDS: Final = 30.0


class BackgroundAgent(Protocol):
    """A long-lived connection that answers workspace calls for one claimed workspace."""

    @property
    def alive(self) -> bool: ...

    async def aclose(self) -> None: ...


async def open_background_agent(root: Path, claim: WorkspaceClaim) -> BackgroundAgent | None:
    """Open the connector's long-lived workspace agent for ``claim``; ``None`` when none can be.

    Integration point — wired after split/client and split/server merge. The connector holds one
    background agent per claimed workspace it has relayed, for ``AGENT_LEASE_SECONDS`` after that
    workspace's last hello, so a detached server job (the AI-powered review loop, observation
    verification) still reaches the workspace after the client call that started it returned.
    The split/client implementation resolves ``claim`` to the workspace root this client claimed
    (client-side state; the claim is a keyed digest, never a path), builds its
    ``WorkspaceAgentHandler`` and connects a ``ServiceClient`` to ``root``'s own control endpoint
    (through this connector) with ``workspace_claim=claim`` and the handler's
    ``workspace_agent`` declaration, serving ``workspace_call`` frames until closed.
    """

    del root, claim
    return None


@dataclass(slots=True)
class _ClaimLease:
    claim: WorkspaceClaim
    last_seen: float
    agent: BackgroundAgent | None = None
    opening: bool = False


@dataclass(slots=True)
class _Credential:
    """The HTTPS key, read once from the platform store or owner-only file and kept in memory."""

    reader: Callable[[], str]
    value: str | None = field(default=None, repr=False)

    def read(self) -> str:
        if self.value is None:
            self.value = self.reader()
        return self.value

    def forget(self) -> None:
        self.value = None


def _claim_from(frame: ControlFrame) -> WorkspaceClaim | None:
    """The hello's validated workspace claim (the frame already passed the hello schema)."""

    raw = frame.get("workspace_claim")
    if raw is None:
        return None
    source = cast(Mapping[str, str], raw)
    return WorkspaceClaim(
        identity_kind=cast(WorkspaceIdentityKind, source["identity_kind"]),
        digest=source["digest"],
    )


class Connector:
    """One target root's relay: listener, upstream, status, claim leases and idle exit."""

    def __init__(
        self,
        root: Path,
        record: ServerTarget,
        *,
        idle_seconds: float = CONNECTOR_IDLE_SECONDS,
        ssh: str | None = None,
        https_transport: object | None = None,
        credential: Callable[[], str] | None = None,
        agent_opener: Callable[[Path, WorkspaceClaim], Awaitable[BackgroundAgent | None]]
        | None = None,
    ) -> None:
        if not record.is_remote:
            raise ValueError("target_not_remote")
        self._root = root
        self._record = record
        self._idle_seconds = idle_seconds
        self._ssh = SshMaster(root, record, ssh=ssh) if record.kind == "ssh" else None
        self._https_transport = https_transport
        self._credential = _Credential(credential or self._stored_credential)
        self._https: object | None = None
        self._agent_opener = agent_opener or open_background_agent
        self._status: ConnectorStatus | None = read_connector_status(root)
        self._started_at = now_stamp()
        self._active = 0
        self._last_activity = time.monotonic()
        self._claims: dict[str, _ClaimLease] = {}
        self._stop = asyncio.Event()
        self._stop_reason = "stop_requested"
        self._connections: set[asyncio.Task[None]] = set()
        self._last_restart = -_RESTART_WINDOW_SECONDS

    # -- status -----------------------------------------------------------------------------

    def _write_status(self, phase: ConnectorPhase, reason: str | None) -> None:
        previous = self._status
        if (
            previous is not None
            and previous.started_at == self._started_at
            and (previous.phase, previous.reason) == (phase, reason)
        ):
            return
        correlation_id = None
        if phase == "unavailable" and reason is not None:
            from finishup.observability.logging import record_public_error_without_raising

            correlation_id = record_public_error_without_raising(
                component="client.connector", operation="connector_upstream", reason=reason
            )
        status = new_status(
            self._status, phase, reason, correlation_id=correlation_id, started_at=self._started_at
        )
        write_connector_status(self._root, status)
        self._status = status

    async def _unavailable(self, reason: str) -> None:
        if reason == "remote_auth_failed":
            # A key rotated with ``server login`` is read again on the next connection.
            self._credential.forget()
        self._write_status("unavailable", reason)

    async def _ready(self) -> None:
        self._write_status("ready", None)

    # -- upstream ---------------------------------------------------------------------------

    def _stored_credential(self) -> str:
        from finishup.client.credentials import KeyringOrFileCredential

        return KeyringOrFileCredential(
            self._record.target_id, self._root, recorded=self._record.credential
        ).read()

    def _https_upstream(self) -> object:
        if self._https is None:
            from finishup.client.https_upstream import HttpsUpstream

            self._https = HttpsUpstream(
                self._record,
                self._credential.read,
                transport=cast(object, self._https_transport),  # pyright: ignore[reportArgumentType]
            )
        return self._https

    async def warm(self) -> None:
        """Bring the upstream up once (master or server-info check); record the outcome."""

        try:
            if self._ssh is not None:
                await self._ssh.ensure()
            else:
                from finishup.client.https_upstream import HttpsUpstream
                from finishup.protocol.schemas import schema_manifest_digest

                info = await cast(HttpsUpstream, self._https_upstream()).server_info()
                if info.get("schema_manifest_digest") != schema_manifest_digest():
                    raise UpstreamUnavailable("remote_incompatible")
        except UpstreamUnavailable as error:
            await self._unavailable(error.reason)
            return
        await self._ready()

    # -- claims -----------------------------------------------------------------------------

    async def _observe_claim(self, claim: WorkspaceClaim) -> None:
        now = time.monotonic()
        lease = self._claims.get(claim.digest)
        if lease is None:
            lease = _ClaimLease(claim, now)
            self._claims[claim.digest] = lease
        lease.last_seen = now
        if (lease.agent is not None and lease.agent.alive) or lease.opening:
            return
        lease.opening = True
        try:
            lease.agent = await self._agent_opener(self._root, claim)
        except Exception:
            lease.agent = None
        finally:
            lease.opening = False

    async def _expire_claims(self) -> None:
        now = time.monotonic()
        for digest, lease in tuple(self._claims.items()):
            if now - lease.last_seen < AGENT_LEASE_SECONDS:
                continue
            self._claims.pop(digest, None)
            if lease.agent is not None:
                with contextlib.suppress(Exception):
                    await lease.agent.aclose()

    # -- one local connection ---------------------------------------------------------------

    async def _serve_local(self, local: AuthenticatedUnixStream) -> None:
        self._active += 1
        self._last_activity = time.monotonic()
        try:
            try:
                async with asyncio.timeout(_HELLO_SECONDS):
                    hello = await read_control_frame(local)
            except (TimeoutError, ControlProtocolError, LocalControlTransportError):
                return
            if "connection_nonce" not in hello or hello.get("workspace_locator") is not None:
                # Not a hello, or a hello naming a path on this machine: never forwarded.
                return
            claim = _claim_from(hello)
            if claim is not None:
                asyncio.ensure_future(self._observe_claim(claim))
            encoded = encode_control_frame(hello)
            if self._ssh is not None:
                await self._relay_ssh(local, encoded)
            else:
                from finishup.client.https_upstream import HttpsUpstream, relay_https_connection

                await relay_https_connection(
                    local,
                    cast(HttpsUpstream, self._https_upstream()),
                    hello,
                    encoded[4:],
                    on_unavailable=self._unavailable,
                    on_ready=self._ready,
                )
        except Exception:
            # A relay fault ends this connection only; the client sees its stream close.
            pass
        finally:
            with contextlib.suppress(Exception):
                await local.aclose()
            self._active -= 1
            self._last_activity = time.monotonic()

    async def _open_ssh_channel(self, hello: bytes) -> tuple[AuthenticatedUnixStream, bytes]:
        """Connect one channel, send the hello, and return it with the first answered bytes."""

        assert self._ssh is not None
        for attempt in range(2):
            await self._ssh.ensure()
            try:
                upstream = await connect_owner_only_endpoint(self._ssh.upstream_path)
            except LocalControlTransportError:
                # The master's forward is gone (a dropped connection): restart it once.
                await self._ssh.close()
                if attempt == 0:
                    continue
                raise UpstreamUnavailable("remote_unreachable") from None
            try:
                await upstream.send_all(hello)
                first = await upstream.receive(_PUMP_CHUNK)
            except LocalControlTransportError:
                first = b""
            if first:
                return upstream, first
            await upstream.aclose()
            # sshd could not reach the server's endpoint: its service is not running. Start it
            # once with the server's own launcher, then try the channel again.
            now = time.monotonic()
            if attempt == 0 and now - self._last_restart >= _RESTART_WINDOW_SECONDS:
                self._last_restart = now
                if await self._ssh.run_remote("service", "start") == 0:
                    continue
            break
        raise UpstreamUnavailable("remote_service_not_running")

    async def _relay_ssh(self, local: AuthenticatedUnixStream, hello: bytes) -> None:
        try:
            upstream, first = await self._open_ssh_channel(hello)
        except UpstreamUnavailable as error:
            await self._unavailable(error.reason)
            return
        await self._ready()
        try:
            await local.send_all(first)
            await _pump_both(local, upstream)
        finally:
            with contextlib.suppress(Exception):
                await upstream.aclose()

    # -- lifetime ---------------------------------------------------------------------------

    def request_stop(self, reason: str = "stop_requested") -> None:
        self._stop_reason = reason
        self._stop.set()

    async def _accept(self, listener: UnixEndpointListener) -> None:
        while not self._stop.is_set():
            try:
                stream = await listener.accept()
            except LocalControlTransportError as error:
                if error.reason == "listener_closed":
                    return
                continue
            task = asyncio.create_task(self._serve_local(stream))
            self._connections.add(task)
            task.add_done_callback(self._connections.discard)

    async def _watch(self) -> None:
        while not self._stop.is_set():
            await asyncio.sleep(_TICK_SECONDS)
            await self._expire_claims()
            idle = time.monotonic() - self._last_activity
            if self._active == 0 and idle >= self._idle_seconds:
                self.request_stop("idle_timeout")

    async def serve(self, listener: UnixEndpointListener) -> str:
        """Serve until stopped or idle; return the closed reason the process stopped for."""

        self._write_status("starting", None)
        accept = asyncio.create_task(self._accept(listener))
        warm = asyncio.create_task(self.warm())
        watch = asyncio.create_task(self._watch())
        try:
            await self._stop.wait()
        finally:
            for task in (accept, warm, watch):
                task.cancel()
            await asyncio.gather(accept, warm, watch, return_exceptions=True)
            with contextlib.suppress(Exception):
                await listener.aclose()
            for task in tuple(self._connections):
                task.cancel()
            await asyncio.gather(*self._connections, return_exceptions=True)
            for lease in self._claims.values():
                if lease.agent is not None:
                    with contextlib.suppress(Exception):
                        await lease.agent.aclose()
            if self._ssh is not None:
                with contextlib.suppress(Exception):
                    await self._ssh.close()
            if self._https is not None:
                from finishup.client.https_upstream import HttpsUpstream

                with contextlib.suppress(Exception):
                    await cast(HttpsUpstream, self._https).aclose()
            self._write_status("stopped", self._stop_reason)
        return self._stop_reason


async def _pump(source: AuthenticatedUnixStream, sink: AuthenticatedUnixStream) -> None:
    while chunk := await source.receive(_PUMP_CHUNK):
        await sink.send_all(chunk)
    with contextlib.suppress(LocalControlTransportError):
        await sink.shutdown_write()


async def _pump_both(local: AuthenticatedUnixStream, upstream: AuthenticatedUnixStream) -> None:
    """Copy bytes both ways, unparsed, until either side ends; a failure ends both."""

    tasks = (
        asyncio.create_task(_pump(local, upstream)),
        asyncio.create_task(_pump(upstream, local)),
    )
    try:
        # Each side's end of stream is passed on as a half-close; the peer then ends its own
        # direction. A failure in either direction ends both.
        await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def _bind(lock: ConnectorLock) -> UnixEndpointListener:
    try:
        return await bind_control_listener()
    except LocalControlTransportError as error:
        if error.reason != "endpoint_exists":
            raise
    # A previous connector or service left the endpoint behind; only the lock holder clears it.
    await remove_stale_endpoint(EndpointKind.CONTROL, lock)
    return await bind_control_listener()


async def run_connector_process(root: Path, record: ServerTarget) -> int:
    """The connector process body: lock, bind, serve, release. Exit 0 also when one runs."""

    from finishup.protocol.schemas import schema_manifest_digest

    lock = ConnectorLock(root)
    deadline = time.monotonic() + _LOCK_RETRY_SECONDS
    while True:
        try:
            lock.acquire(version=__version__, schema_manifest_digest=schema_manifest_digest())
            break
        except ConnectorLockBusy:
            if time.monotonic() >= deadline:
                return 0
            await asyncio.sleep(0.05)
    try:
        listener = await _bind(lock)
        connector = Connector(root, record)
        loop = asyncio.get_running_loop()
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            with contextlib.suppress(NotImplementedError, RuntimeError):
                loop.add_signal_handler(number, connector.request_stop)
        await connector.serve(listener)
        return 0
    except LocalControlTransportError:
        status = read_connector_status(root)
        write_connector_status(
            root,
            new_status(status, "stopped", "connector_failed", started_at=now_stamp()),
        )
        return 20
    finally:
        lock.release()


def run_connector(root: Path) -> int:
    """``finishup connector run --root R``: serve one remote target root in the foreground.

    ``R`` must be a remote target's own root beneath this machine's server registry. An isolation
    variable or runtime pin naming another root refuses (exit 2); the connector never serves a
    root its process would not resolve. Exit 0 when it stopped (or another connector already
    serves the root), 20 when the endpoint could not be bound.
    """

    from finishup.client.targets import TargetError, read_target, target_root
    from finishup.config.paths import PathSafetyError, isolated_root, selection_override

    if not root.is_absolute():
        return 2
    try:
        record = read_target(root)
        if record is None or not record.is_remote or target_root(record.target_id) != root:
            return 2
        explicit = isolated_root()
    except (TargetError, PathSafetyError):
        return 2
    if explicit is not None and explicit != root:
        return 2
    with selection_override(root):
        return asyncio.run(run_connector_process(root, record))
