"""The gateway's HTTPS binding v1, in process over ``httpx.ASGITransport`` (ADR-051, approach A).

Every status of the binding, the ``Origin`` and locator refusals, key scopes (an out-of-scope call
is a synthesized ``method_forbidden`` result that never reaches the daemon), long-polls for
results and server frames, at-most-once delivery, session bounds and expiry, revocation closing
sessions, a stale gateway, and payload-free audit lines.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import httpx
import pytest

from builders.control_relay import (
    CLAIM_DIGEST,
    SERVICE_ID,
    WORKTREE_DIGEST,
    ScriptedDaemon,
    call_request,
    memory_pair,
    rpc_id,
)
from builders.server_targets import ambient_home
from finishup.gateway.app import GatewayApp, build_gateway_app
from finishup.gateway.keys import create_key, revoke_key
from finishup.ports.control import ControlMethod
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.rest_binding import (
    MAX_SESSIONS_PER_KEY,
    RestErrorContract,
    ServerInfoContract,
)
from finishup.protocol.schemas import load_schema_catalog, validate_schema_instance
from finishup.service.control_protocol import decode_control_frame, encode_control_frame

_BASE = "https://gw.example"


class _Audit:
    def __init__(self) -> None:
        self.records: list[dict[str, JsonValue]] = []

    def write(self, record: dict[str, JsonValue]) -> None:
        self.records.append(record)


@dataclass
class _Gateway:
    state: GatewayApp
    client: httpx.AsyncClient
    daemon: ScriptedDaemon
    audit: _Audit
    keys: Path
    agent_key: str
    operator_key: str
    served: list[asyncio.Task[None]] = field(default_factory=list[asyncio.Task[None]])

    def headers(self, key: str | None = None, **extra: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {key or self.agent_key}",
            "FinishUP-Binding": "1.0",
            **extra,
        }


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


async def _gateway(home: Path, **options: object) -> _Gateway:
    keys = home / "gateway"
    _agent, agent_key = create_key(keys, label="agent", scope="agent")
    _operator, operator_key = create_key(keys, label="operator", scope="operator")
    daemon = ScriptedDaemon()
    served: list[asyncio.Task[None]] = []

    async def connect_upstream() -> object:
        client, server = memory_pair()
        served.append(asyncio.create_task(daemon.serve(server)))
        return client

    audit = _Audit()
    state, app = build_gateway_app(
        keys_directory=keys,
        connect_upstream=connect_upstream,  # type: ignore[arg-type]
        audit=audit,
        **options,  # type: ignore[arg-type]
    )
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=_BASE)
    return _Gateway(state, client, daemon, audit, keys, agent_key, operator_key, served)


@pytest.fixture
async def gateway(home: Path) -> AsyncIterator[_Gateway]:
    built = await _gateway(home)
    try:
        yield built
    finally:
        await built.client.aclose()
        await built.state.sessions.close_all()
        await asyncio.gather(*built.served, return_exceptions=True)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _hello(*, agent: bool = False, locator: bool = False, digest: str | None = None) -> bytes:
    hello: dict[str, JsonValue] = {
        "protocol_version": "1.0",
        "client_kind": "cli",
        "client_version": "0.1.0",
        "connection_nonce": "2e" * 32,
        "schema_manifest_digest": digest or load_schema_catalog().manifest_digest,
    }
    if locator:
        hello["workspace_locator"] = {"schema_version": "1.0.0", "path": "/home/owner/repo"}
    if agent:
        hello["workspace_claim"] = {
            "schema_version": "1.0.0",
            "identity_kind": "directory",
            "digest": CLAIM_DIGEST,
            "worktree": WORKTREE_DIGEST,
        }
        hello["workspace_agent"] = {
            "schema_version": "1.0.0",
            "operations": ["read_task_base"],
            "max_reply_bytes": 65_536,
        }
    return encode_control_frame(hello)[4:]


def _call(sequence: int, method: ControlMethod = ControlMethod.SERVICE_STATUS) -> bytes:
    return encode_control_frame(call_request(sequence, method))[4:]


def _reason(response: httpx.Response) -> str:
    document = json.loads(response.content)
    RestErrorContract.model_validate(document)
    return cast(str, document["reason"])


async def _open(gateway: _Gateway, *, agent: bool = False, key: str | None = None) -> str:
    response = await gateway.client.post(
        "/v1/sessions", content=_hello(agent=agent), headers=gateway.headers(key)
    )
    assert response.status_code == 201, response.content
    location = response.headers["Location"]
    decode_control_frame(len(response.content).to_bytes(4, "big") + response.content)
    return location.rsplit("/", 1)[1]


@pytest.mark.anyio
async def test_server_info_names_release_digest_key_and_scope(gateway: _Gateway) -> None:
    response = await gateway.client.get("/v1/server", headers=gateway.headers())
    assert response.status_code == 200
    info = json.loads(response.content)
    ServerInfoContract.model_validate(info)
    assert info["schema_manifest_digest"] == load_schema_catalog().manifest_digest
    assert info["scope"] == "agent" and info["bindings"] == ["1.0"]
    assert response.content == canonical_encode(info)
    assert b'agent"' not in response.content.replace(b'"scope":"agent"', b"")  # no label


@pytest.mark.anyio
async def test_origin_is_refused_before_authentication(gateway: _Gateway) -> None:
    for headers in (
        {"Origin": "https://evil.example"},
        gateway.headers(Origin="https://evil.example"),
    ):
        response = await gateway.client.get("/v1/server", headers=headers)
        assert response.status_code == 403
        assert _reason(response) == "origin_forbidden"


@pytest.mark.anyio
async def test_nothing_answers_without_a_valid_key_and_binding(gateway: _Gateway) -> None:
    for headers in ({}, {"Authorization": "Basic abc"}, gateway.headers("fuk_0_bad")):
        response = await gateway.client.get("/v1/server", headers=headers)
        assert response.status_code == 401
        assert _reason(response) == "api_key_invalid"
    missing_binding = {"Authorization": f"Bearer {gateway.agent_key}"}
    response = await gateway.client.get("/v1/server", headers=missing_binding)
    assert response.status_code == 400 and _reason(response) == "frame_invalid"
    response = await gateway.client.post("/v1/sessions", content=_hello())
    assert response.status_code == 401
    assert gateway.daemon.connections == 0


@pytest.mark.anyio
async def test_a_hello_naming_a_path_is_refused_and_never_forwarded(gateway: _Gateway) -> None:
    response = await gateway.client.post(
        "/v1/sessions", content=_hello(locator=True), headers=gateway.headers()
    )
    assert response.status_code == 403
    assert _reason(response) == "workspace_locator_forbidden"
    assert gateway.daemon.connections == 0
    garbage = await gateway.client.post("/v1/sessions", content=b"{}", headers=gateway.headers())
    assert garbage.status_code == 400 and _reason(garbage) == "frame_invalid"


@pytest.mark.anyio
async def test_a_manifest_mismatch_returns_the_daemons_hello_result(gateway: _Gateway) -> None:
    response = await gateway.client.post(
        "/v1/sessions", content=_hello(digest="sha256:" + "0" * 64), headers=gateway.headers()
    )
    assert response.status_code == 409
    answer = json.loads(response.content)
    validate_schema_instance("control-hello-result", "2.10.0", answer)
    assert answer["schema_manifest_digest"] == load_schema_catalog().manifest_digest
    assert len(gateway.state.sessions) == 0


@pytest.mark.anyio
async def test_a_call_in_scope_reaches_the_daemon_and_returns_its_exact_result(
    gateway: _Gateway,
) -> None:
    sid = await _open(gateway)
    response = await gateway.client.post(
        f"/v1/sessions/{sid}/calls?wait_ms=5000", content=_call(1), headers=gateway.headers()
    )
    assert response.status_code == 200
    assert response.content == gateway.daemon.sent[-1]
    assert gateway.daemon.received()[-1] == _call(1)


@pytest.mark.anyio
async def test_an_out_of_scope_call_is_a_synthesized_refusal_never_forwarded(
    gateway: _Gateway,
) -> None:
    sid = await _open(gateway)
    response = await gateway.client.post(
        f"/v1/sessions/{sid}/calls?wait_ms=5000",
        content=_call(2, ControlMethod.SERVICE_LOCK),
        headers=gateway.headers(),
    )
    assert response.status_code == 200
    result = json.loads(response.content)
    validate_schema_instance("control-result", "2.10.0", result)
    assert result == {
        "body": {"code": "method_forbidden", "retryable": False},
        "method": "service_lock",
        "outcome": "error",
        "protocol_version": "1.0",
        "rpc_id": rpc_id(2),
        "service_generation": "1",
        "service_instance_id": SERVICE_ID,
    }
    assert len(gateway.daemon.received()) == 1  # the hello only
    # The operator sees the scope refusal in the audit line, by its closed token.
    refused = gateway.audit.records[-1]
    assert (refused["route"], refused["method"], refused["status"], refused["reason"]) == (
        "calls",
        "service_lock",
        200,
        "method_forbidden",
    )
    operator_sid = await _open(gateway, key=gateway.operator_key)
    allowed = await gateway.client.post(
        f"/v1/sessions/{operator_sid}/calls?wait_ms=5000",
        content=_call(3, ControlMethod.SERVICE_LOCK),
        headers=gateway.headers(gateway.operator_key),
    )
    assert allowed.status_code == 200
    assert json.loads(allowed.content)["body"]["code"] == "vault_locked"


@pytest.mark.anyio
async def test_never_over_https_methods_are_refused_for_every_scope(gateway: _Gateway) -> None:
    from finishup.protocol.rest_binding import method_allowed

    for method in (
        ControlMethod.SERVICE_STOP,
        ControlMethod.BACKUP_EXECUTE,
        ControlMethod.RESTORE_PREVIEW,
        ControlMethod.MIGRATE_EXECUTE,
        ControlMethod.INTEGRATION_PREVIEW,
        ControlMethod.OBSERVATION_PAUSE,
        ControlMethod.OBSERVATION_RESUME,
        ControlMethod.OBSERVATION_REVOKE,
    ):
        for scope in ("agent", "operator"):
            assert not method_allowed(scope, method, claim_bound=True)
    assert method_allowed("agent", ControlMethod.OBSERVATION_INGEST, claim_bound=True)
    assert not method_allowed("operator", ControlMethod.OBSERVATION_INGEST, claim_bound=False)


@pytest.mark.anyio
async def test_a_pending_call_long_polls_and_is_delivered_at_most_once(gateway: _Gateway) -> None:
    sid = await _open(gateway)
    slow = encode_control_frame(call_request(0x51F0, ControlMethod.STATUS))[4:]
    first = await gateway.client.post(
        f"/v1/sessions/{sid}/calls?wait_ms=0", content=slow, headers=gateway.headers()
    )
    assert first.status_code == 202
    duplicate = await gateway.client.post(
        f"/v1/sessions/{sid}/calls?wait_ms=0", content=slow, headers=gateway.headers()
    )
    assert duplicate.status_code == 202
    pending = await gateway.client.get(
        f"/v1/sessions/{sid}/results/{rpc_id(0x51F0)}?wait_ms=0", headers=gateway.headers()
    )
    assert pending.status_code == 202
    cancel = encode_control_frame(
        {
            "kind": "cancel",
            "protocol_version": "1.0",
            "rpc_id": rpc_id(0x5200),
            "service_instance_id": SERVICE_ID,
            "service_generation": "1",
            "target_rpc_id": rpc_id(0x51F0),
        }
    )[4:]
    cancelled = await gateway.client.post(
        f"/v1/sessions/{sid}/cancel", content=cancel, headers=gateway.headers()
    )
    assert cancelled.status_code == 202
    done = await gateway.client.get(
        f"/v1/sessions/{sid}/results/{rpc_id(0x51F0)}?wait_ms=5000", headers=gateway.headers()
    )
    assert done.status_code == 200
    assert json.loads(done.content)["body"]["code"] == "request_cancelled"
    # The call reached the daemon once; a delivered rpc_id is never accepted again.
    calls = [frame for frame in gateway.daemon.received() if b'"kind":"call"' in frame]
    assert calls == [slow]
    again = await gateway.client.post(
        f"/v1/sessions/{sid}/calls?wait_ms=0", content=slow, headers=gateway.headers()
    )
    assert again.status_code == 400 and _reason(again) == "frame_invalid"
    # A delivered result stays readable for a while (an answer lost in transit is polled again),
    # and reading it never sends the call to the daemon again.
    reread = await gateway.client.get(
        f"/v1/sessions/{sid}/results/{rpc_id(0x51F0)}?wait_ms=0", headers=gateway.headers()
    )
    assert reread.status_code == 200 and reread.content == done.content
    assert [frame for frame in gateway.daemon.received() if b'"kind":"call"' in frame] == [slow]
    unknown = await gateway.client.get(
        f"/v1/sessions/{sid}/results/{rpc_id(0x51F1)}?wait_ms=0", headers=gateway.headers()
    )
    assert unknown.status_code == 400 and _reason(unknown) == "frame_invalid"


def _cancel(target: int, sequence: int = 0x5200) -> bytes:
    return encode_control_frame(
        {
            "kind": "cancel",
            "protocol_version": "1.0",
            "rpc_id": rpc_id(sequence),
            "service_instance_id": SERVICE_ID,
            "service_generation": "1",
            "target_rpc_id": rpc_id(target),
        }
    )[4:]


@pytest.mark.anyio
async def test_a_cancel_the_daemon_would_refuse_is_never_forwarded(gateway: _Gateway) -> None:
    """The service ends a connection whose cancel names a call it is not running, and every call
    on it with it; over HTTPS a cancel easily arrives after its call finished."""

    sid = await _open(gateway)
    finished = await gateway.client.post(
        f"/v1/sessions/{sid}/calls?wait_ms=5000", content=_call(7), headers=gateway.headers()
    )
    assert finished.status_code == 200
    refused = await gateway.client.post(
        f"/v1/sessions/{sid}/calls?wait_ms=5000",
        content=_call(8, ControlMethod.SERVICE_LOCK),
        headers=gateway.headers(),
    )
    assert json.loads(refused.content)["body"]["code"] == "method_forbidden"
    for late in (_cancel(7, 0x5201), _cancel(8, 0x5202)):
        cancelled = await gateway.client.post(
            f"/v1/sessions/{sid}/cancel", content=late, headers=gateway.headers()
        )
        assert cancelled.status_code == 202
    assert not any(b'"kind":"cancel"' in frame for frame in gateway.daemon.received())
    # The session and its daemon connection are still alive.
    after = await gateway.client.post(
        f"/v1/sessions/{sid}/calls?wait_ms=5000", content=_call(9), headers=gateway.headers()
    )
    assert after.status_code == 200
    assert gateway.daemon.connections == 1


@pytest.mark.anyio
async def test_a_cancel_that_overtook_its_call_follows_it_to_the_daemon(gateway: _Gateway) -> None:
    """A call and its cancel are separate HTTP requests: the daemon still sees call, then cancel."""

    sid = await _open(gateway)
    early = await gateway.client.post(
        f"/v1/sessions/{sid}/cancel", content=_cancel(0x51F0), headers=gateway.headers()
    )
    assert early.status_code == 202
    assert len(gateway.daemon.received()) == 1  # held: the daemon has only the hello
    slow = encode_control_frame(call_request(0x51F0, ControlMethod.STATUS))[4:]
    answered = await gateway.client.post(
        f"/v1/sessions/{sid}/calls?wait_ms=5000", content=slow, headers=gateway.headers()
    )
    assert answered.status_code == 200
    assert json.loads(answered.content)["body"]["code"] == "request_cancelled"
    assert gateway.daemon.received()[1:] == [slow, _cancel(0x51F0)]


@pytest.mark.anyio
async def test_server_frames_long_poll_and_replies_reach_the_daemon(gateway: _Gateway) -> None:
    sid = await _open(gateway, agent=True)
    empty = await gateway.client.get(
        f"/v1/sessions/{sid}/frames?wait_ms=0", headers=gateway.headers()
    )
    assert empty.status_code == 204 and empty.content == b""
    called = await gateway.client.post(
        f"/v1/sessions/{sid}/calls?wait_ms=5000", content=_call(4), headers=gateway.headers()
    )
    assert called.status_code == 200
    frame = await gateway.client.get(
        f"/v1/sessions/{sid}/frames?wait_ms=5000", headers=gateway.headers()
    )
    assert frame.status_code == 200
    call = json.loads(frame.content)
    validate_schema_instance("control-result", "2.10.0", call)
    assert call["kind"] == "workspace_call" and frame.content in gateway.daemon.sent
    reply = encode_control_frame(
        {
            "kind": "workspace_reply",
            "protocol_version": "1.0",
            "call_id": call["call_id"],
            "outcome": "unavailable",
            "result": None,
            "reason": "not_git",
        }
    )[4:]
    posted = await gateway.client.post(
        f"/v1/sessions/{sid}/frames", content=reply, headers=gateway.headers()
    )
    assert posted.status_code == 202
    for _attempt in range(100):
        if gateway.daemon.replies:
            break
        await asyncio.sleep(0.01)
    assert gateway.daemon.received()[-1] == reply

    plain = await _open(gateway)
    refused = await gateway.client.post(
        f"/v1/sessions/{plain}/frames", content=reply, headers=gateway.headers()
    )
    assert refused.status_code == 400 and _reason(refused) == "frame_invalid"


@pytest.mark.anyio
async def test_sessions_are_bound_to_their_key_bounded_and_closed_by_delete(
    gateway: _Gateway,
) -> None:
    sid = await _open(gateway)
    foreign = await gateway.client.post(
        f"/v1/sessions/{sid}/calls?wait_ms=0",
        content=_call(5),
        headers=gateway.headers(gateway.operator_key),
    )
    assert foreign.status_code == 404 and _reason(foreign) == "session_unknown"
    deleted = await gateway.client.delete(f"/v1/sessions/{sid}", headers=gateway.headers())
    assert deleted.status_code == 204
    after = await gateway.client.post(
        f"/v1/sessions/{sid}/calls?wait_ms=0", content=_call(6), headers=gateway.headers()
    )
    assert after.status_code == 404
    for _index in range(MAX_SESSIONS_PER_KEY):
        await _open(gateway)
    limited = await gateway.client.post("/v1/sessions", content=_hello(), headers=gateway.headers())
    assert limited.status_code == 429 and _reason(limited) == "session_limit"
    # Another key's budget is its own.
    await _open(gateway, key=gateway.operator_key)


@pytest.mark.anyio
async def test_idle_sessions_expire_and_close_their_upstream(home: Path) -> None:
    built = await _gateway(home, idle_seconds=0.0)
    try:
        sid = await _open(built)
        await built.state.sweep()
        response = await built.client.post(
            f"/v1/sessions/{sid}/calls?wait_ms=0", content=_call(7), headers=built.headers()
        )
        assert response.status_code == 404 and _reason(response) == "session_unknown"
        async with asyncio.timeout(5):
            await asyncio.gather(*built.served)
    finally:
        await built.client.aclose()


@pytest.mark.anyio
async def test_revoking_a_key_fails_its_next_request_and_closes_its_sessions(
    gateway: _Gateway,
) -> None:
    sid = await _open(gateway)
    record_id = gateway.agent_key.split("_")[1]
    revoke_key(gateway.keys, record_id)
    response = await gateway.client.post(
        f"/v1/sessions/{sid}/calls?wait_ms=0", content=_call(8), headers=gateway.headers()
    )
    assert response.status_code == 401 and _reason(response) == "api_key_revoked"
    await gateway.state.sweep()
    assert len(gateway.state.sessions) == 0


@pytest.mark.anyio
async def test_a_stale_gateway_stops_instead_of_relaying(home: Path) -> None:
    stale: list[bool] = []
    built = await _gateway(home, on_stale=lambda: stale.append(True))
    built.state._digest = "sha256:" + "9" * 64  # pyright: ignore[reportPrivateUsage]
    try:
        response = await built.client.post(
            "/v1/sessions", content=_hello(), headers=built.headers()
        )
        assert response.status_code == 503 and _reason(response) == "service_unavailable"
        assert stale == [True]
    finally:
        await built.client.aclose()


@pytest.mark.anyio
async def test_an_oversized_body_is_refused(gateway: _Gateway) -> None:
    response = await gateway.client.post(
        "/v1/sessions", content=b"x" * 6_291_457, headers=gateway.headers()
    )
    assert response.status_code == 413 and _reason(response) == "frame_too_large"


@pytest.mark.anyio
async def test_audit_lines_carry_closed_tokens_only(gateway: _Gateway) -> None:
    sid = await _open(gateway)
    await gateway.client.post(
        f"/v1/sessions/{sid}/calls?wait_ms=5000", content=_call(9), headers=gateway.headers()
    )
    await gateway.client.get("/v1/server", headers={"Origin": "https://evil.example"})
    assert gateway.audit.records
    # The whole secret (``fuk_<key id>_<secret>``): base64url may itself contain "_".
    secret = gateway.agent_key.split("_", 2)[2]
    for record in gateway.audit.records:
        assert set(record) == {
            "event",
            "correlation_id",
            "route",
            "key_id",
            "method",
            "status",
            "reason",
        }
        text = json.dumps(record)
        for forbidden in (sid, secret, "evil.example", 'agent"', "gw.example"):
            assert forbidden not in text.replace('"route": "sessions"', "")


@pytest.mark.anyio
async def test_a_flood_without_a_key_cannot_grow_the_audit(
    gateway: _Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Anyone who reaches the listener can send requests; a refusal of one no key authenticated
    is audited at most once per reason per window, and the rest are counted, not written."""

    import finishup.gateway.app as gateway_app

    for _attempt in range(50):
        refused = await gateway.client.get("/v1/server", headers={"Authorization": "Bearer x"})
        assert refused.status_code == 401
        forbidden = await gateway.client.get("/v1/server", headers={"Origin": "https://x.example"})
        assert forbidden.status_code == 403
    assert [(record["event"], record["reason"]) for record in gateway.audit.records] == [
        ("gateway_request", "api_key_invalid"),
        ("gateway_request", "origin_forbidden"),
    ]
    # Authenticated requests are audited one line each, as before.
    for _attempt in range(3):
        await gateway.client.get("/v1/server", headers=gateway.headers())
    assert len(gateway.audit.records) == 5
    # The next window writes the count of what the previous one did not.
    monkeypatch.setattr(gateway_app, "UNAUTHENTICATED_AUDIT_SECONDS", 0.0)
    await gateway.client.get("/v1/server", headers={"Authorization": "Bearer x"})
    assert gateway.audit.records[-2:] == [
        {"event": "gateway_refusals_suppressed", "reason": "api_key_invalid", "count": 49},
        {
            "event": "gateway_request",
            "correlation_id": gateway.audit.records[-1]["correlation_id"],
            "route": "server",
            "key_id": None,
            "method": None,
            "status": 401,
            "reason": "api_key_invalid",
        },
    ]


def test_the_audit_file_rotates_once_it_reaches_its_bound(tmp_path: Path) -> None:
    from finishup.gateway.app import FileAuditSink

    path = tmp_path / "log" / "gateway-audit.jsonl"
    sink = FileAuditSink(path, rotate_bytes=200)
    record: dict[str, JsonValue] = {"event": "gateway_request", "reason": None, "status": 200}
    line = len(json.dumps(record, separators=(",", ":"))) + 1
    for _line in range(100):
        sink.write(record)
    rotated = path.with_name("gateway-audit.jsonl.1")
    assert path.stat().st_size < 200 + line
    assert rotated.stat().st_size < 200 + line
    assert path.stat().st_mode & 0o777 == 0o600
    assert {json.loads(text)["event"] for text in path.read_text().splitlines()} == {
        "gateway_request"
    }
