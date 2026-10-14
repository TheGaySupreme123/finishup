"""A ready service that fails its own side of a handshake says so, honestly, end to end (#1040).

tb4n5 (wdm-design, Git 2.25): once the vault was ready the repository-identity resolver failed on
every hello, the service closed each connection without a trace, and every client reported
``service_incompatible`` naming the service's own pid and version. Here a real ready daemon gets an
injected resolver failure: the daemon records the closed reason without the locator, and the
client, MCP and CLI name a failed handshake rather than another installation.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Buffer
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

import finishup.mcp.server as bridge
import finishup.observability.diagnostics as diagnostics
import finishup.service.client as client_module
import finishup.service.daemon as daemon_module
from builders.multi_agent import INSTANCE_ID, multi_agent_service
from finishup import __version__
from finishup.adapters.repository_identity import RepositoryIdentityError
from finishup.cli.bootstrap import control_failure
from finishup.ports.control import ControlClientKind, RepositoryPrivacyContext, WorkspaceLocator
from finishup.protocol.schemas import schema_manifest_digest
from finishup.service.control_protocol import ControlProtocolError, client_handshake
from finishup.service.daemon import ServiceComposition, ServiceDaemon
from finishup.service.lifecycle import ServiceLifecycle, SingletonHolder

pytestmark = pytest.mark.anyio

_LOCATOR_TEXT = "private-locator-text-never-recorded"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class _Clock:
    instant: datetime = datetime(2026, 10, 13, tzinfo=UTC)

    def now_utc(self) -> datetime:
        return self.instant

    def monotonic_seconds(self) -> float:
        return self.instant.timestamp()


class _Generations:
    def advance(self, instance_id: str) -> int:
        assert instance_id == INSTANCE_ID
        return 1


class _Listener:
    def __init__(self) -> None:
        self._closed = asyncio.Event()

    async def accept(self) -> object:
        await self._closed.wait()
        raise RuntimeError("closed")

    async def aclose(self) -> None:
        self._closed.set()


class _Monitor:
    class _Capability:
        active = False

    capability = _Capability()

    async def start(self, callback: object) -> None:
        del callback

    async def close(self) -> None:
        return None


class _Stream:
    """One end of an in-memory connection whose close reaches the peer as end of stream."""

    def __init__(self, peer_identity: object) -> None:
        self.peer_identity = peer_identity
        self.other: _Stream | None = None
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._buffer = bytearray()

    async def receive(self, max_bytes: int) -> bytes:
        while not self._buffer:
            chunk = await self._queue.get()
            if not chunk:
                return b""
            self._buffer.extend(chunk)
        chunk = bytes(self._buffer[:max_bytes])
        del self._buffer[:max_bytes]
        return chunk

    async def send_all(self, data: Buffer) -> None:
        assert self.other is not None
        await self.other._queue.put(bytes(data))

    async def aclose(self) -> None:
        assert self.other is not None
        self.other._queue.put_nowait(b"")


def _pair() -> tuple[_Stream, _Stream]:
    client = _Stream(object())
    server = _Stream(object())
    client.other = server
    server.other = client
    return client, server


def _records(root: Path) -> list[dict[str, object]]:
    path = diagnostics.diagnostic_log_path(root=root)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines() if line]


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (
            RepositoryIdentityError("git_version_unsupported"),
            {"reason": "handshake_service_fault", "reason_code": "git_version_unsupported"},
        ),
        (
            RuntimeError(f"/{_LOCATOR_TEXT}: fatal: not a git repository"),
            {"reason": "exception_runtime_error", "phase": "handshake"},
        ),
    ],
)
async def test_a_ready_service_names_its_own_handshake_fault(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    raised: Exception,
    expected: dict[str, object],
) -> None:
    log_root = tmp_path / "logs"
    log_root.mkdir()
    monkeypatch.setattr(diagnostics, "log_dir", lambda: log_root)

    async def failing_resolver(locator: WorkspaceLocator, key: object) -> RepositoryPrivacyContext:
        del locator, key
        raise raised

    monkeypatch.setattr(daemon_module, "resolve_repository_privacy_context", failing_resolver)

    async with multi_agent_service(tmp_path / "state") as service:
        lifecycle = ServiceLifecycle(
            _Clock(),
            generation_store=_Generations(),
            process_start_identity_commitment="sha256:" + "e" * 64,
            instance_id=INSTANCE_ID,
            singleton_lock_path=tmp_path / "handshake-daemon.lock",
        )
        daemon = ServiceDaemon(
            _composition=ServiceComposition(
                lifecycle=lifecycle,
                control_listener=_Listener(),  # pyright: ignore[reportArgumentType]
                secret_ingress_listener=None,
                human_control_listener=None,
                human_control_service=None,
                session_monitor=_Monitor(),  # pyright: ignore[reportArgumentType]
                vault=service.vault,  # pyright: ignore[reportArgumentType]
                application=cast(Any, service.app),
            )
        )
        await daemon.start()
        try:
            client_stream, server_stream = _pair()
            served = asyncio.create_task(
                daemon._serve_control_connection(server_stream)  # pyright: ignore[reportPrivateUsage]
            )
            locator = WorkspaceLocator(f"/{_LOCATOR_TEXT}")
            with pytest.raises(ControlProtocolError) as rejected:
                await client_handshake(
                    client_stream,  # pyright: ignore[reportArgumentType]
                    ControlClientKind.CLI,
                    __version__,
                    workspace_locator=locator,
                )
            await asyncio.wait_for(served, timeout=5.0)
        finally:
            await daemon.close()

    # The peer saw only the close.
    assert rejected.value.reason == "handshake_rejected"
    service_records = [
        record
        for record in _records(log_root)
        if record.get("component") == "service.daemon"
        and record.get("operation") == "control_handshake"
    ]
    assert len(service_records) == 1
    assert expected.items() <= service_records[0].items()
    assert _LOCATOR_TEXT not in diagnostics.diagnostic_log_path(root=log_root).read_text(
        encoding="ascii"
    )

    # This installation's own holder: never "another installation", never a restart remedy.
    holder = SingletonHolder(
        pid=626,
        instance_id=INSTANCE_ID,
        schema_manifest_digest=schema_manifest_digest(),
        service_version=__version__,
    )
    monkeypatch.setattr(client_module, "service_holder_identity", lambda: holder)
    monkeypatch.setattr(client_module, "_system_git_below_minimum", lambda: False)
    error = client_module._unanswered_hello(locator)  # pyright: ignore[reportPrivateUsage]
    assert (error.reason, error.phase, error.retryable) == (
        "service_unavailable",
        "handshake",
        False,
    )
    printed: list[str] = []
    assert control_failure(error, stderr_writer=printed.append) == 20
    assert printed[0].startswith("service_unavailable: service_handshake_failed: ")
    assert "'finishup service diagnostics'" in printed[0]
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        error, request_id=None, operation="start"
    )
    structured = cast(dict[str, object], result.structuredContent)
    rendered = json.dumps(structured)
    assert "service_handshake_failed" in rendered
    assert "service_incompatible" not in rendered
