"""The daemon hands a claim-bound connection's identity to observation ingest, and only that.

ADR-051 decision 12: a claim-bound row goes to its claim's client-attested store, so its ingest
needs the connection's claim; every other connection's ingest is called exactly as before.
"""

from __future__ import annotations

import pytest

from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlCallRequest,
    ControlMethod,
    RepositoryPrivacyContext,
    WorkspaceLocator,
)
from finishup.protocol.ids import IdKind, new_id
from finishup.service.daemon import ServiceDaemon

pytestmark = pytest.mark.anyio

_COMMITMENT = "hmac-sha256:" + "0a" * 32


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _ingest() -> ControlCallRequest:
    return ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=new_id(IdKind.SERVICE_INSTANCE),
        service_generation="1",
        method=ControlMethod.OBSERVATION_INGEST,
        body=JsonObject({"codex_session_id": "codex-session-1"}),
    )


async def test_only_a_claim_bound_ingest_receives_its_connection_identity() -> None:
    calls: list[dict[str, object]] = []

    async def handler(_body: object, **kwargs: object) -> object:
        calls.append(kwargs)
        return None

    invoke = ServiceDaemon._invoke_ready_handler  # pyright: ignore[reportPrivateUsage]
    claim = RepositoryPrivacyContext(
        _COMMITMENT, "client_claim", workspace_handle="client:0123456789abcdef"
    )
    local = RepositoryPrivacyContext(
        _COMMITMENT, "git_common_root", WorkspaceLocator("/srv/dev/project")
    )
    await invoke(handler, _ingest(), None)
    await invoke(handler, _ingest(), local)
    await invoke(handler, _ingest(), claim)

    assert calls == [{}, {}, {"repository_privacy_context": claim}]
