"""Envelope-first publish recovery must not mask a known authoring error (issues #65, #239).

When body validation fails, the bridge still looks up the request_id so a committed operation can
be recovered. Only an authoritative found state replaces the field-pointed INVALID_REQUEST. An
unavailable recovery oracle annotates that result with a durability caveat — never the nested
status read's "no durable state changed / new request_id" message, and never an uncertain
OPERATION_PENDING in place of the certain answer the bridge already holds. A declared dry run
cannot append at all, so it never pays for the lookup.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import cast

import pytest
from mcp import types

import finishup.mcp.server as bridge
from finishup.ports.control import ControlError
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

_REQUEST = "req_00000000-0000-4000-8000-000000000065"
_SESSION = "ses_00000000-0000-4000-8000-000000000001"
_WRITER = "wri_00000000-0000-4000-8000-000000000001"
_EVENT = "evt_00000000-0000-4000-8000-000000000001"
_DIGEST = "sha256:" + "a" * 64
# Dogfood-shaped authority: fails the actor_id pattern (whitespace), not a non-string type that
# confuses the event-schema oneOf into pointing at /event_drafts/0/schema/name.
_MALFORMED_AUTHORITY = "bad authority"
_HOSTILE_PAYLOAD = "SECRET_MUST_NOT_LEAK"
# The public message bound the protocol validator enforces.
_MAX_MESSAGE_BYTES = 4096


def _malformed_decision_arguments(
    *,
    request_id: str = _REQUEST,
    dry_run: bool | None = None,
    authority: object = _MALFORMED_AUTHORITY,
) -> dict[str, object]:
    arguments: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "session_id": _SESSION,
        "writer_id": _WRITER,
        "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
        "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "event_drafts": [
            {
                "event_id": _EVENT,
                "schema": {"name": "decision_recorded", "version": "1.0.0"},
                "occurred_at": "2026-01-01T00:00:00.000Z",
                "causal_parents": [],
                "payload": {
                    "statement": "ship it",
                    "rationale": "because",
                    "authority": authority,
                },
                "artifact_refs": [],
                "evidence_refs": [],
            }
        ],
    }
    if dry_run is not None:
        arguments["dry_run"] = dry_run
    return arguments


def _operation_wire(state: str) -> dict[str, object]:
    page: dict[str, object] = {
        "operation_request_id": _REQUEST,
        "found": state != "absent",
        "state": state,
    }
    if state != "absent":
        page["operation_kind"] = "publish_work"
    if state == "complete":
        page["outcome"] = "accepted"
        page["subject_frontier"] = {"sequence": "1", "head_digest": _DIGEST}
        page["result_frontier"] = {"sequence": "1", "head_digest": _DIGEST}
        page["accepted_events"] = [
            {
                "event_id": _EVENT,
                "entry_digest": _DIGEST,
                "ingestion_sequence": "1",
                "writer_sequence": "1",
                "projection_status": "projected",
            }
        ]
    return {"ok": True, "page": page}


def _install_recovery_oracle(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status_wire: Mapping[str, object] | None = None,
    raise_on_status: BaseException | None = None,
) -> list[object]:
    """Drive the recovery status path without a live service client."""

    seen: list[object] = []

    async def ensure(_runtime: object = bridge.BRIDGE_RUNTIME, **_kwargs: object) -> object:
        return object()

    async def invoke(
        _runtime: object,
        request: object,
        _call: Callable[[object, object], Awaitable[object]],
        _request_id: object = None,
    ) -> object:
        seen.append(request)
        if raise_on_status is not None:
            raise raise_on_status
        return object()

    def wire(model: object) -> dict[str, object]:
        del model
        if status_wire is None:
            raise AssertionError("public_model_to_wire should not run without a status wire")
        return dict(status_wire)

    monkeypatch.setattr(bridge, "ensure_service_client", ensure)
    monkeypatch.setattr(bridge, "_invoke_with_reconnect", invoke)
    if status_wire is not None:
        monkeypatch.setattr(bridge, "public_model_to_wire", wire)
    return seen


def _error(result: types.CallToolResult) -> dict[str, object]:
    structured = cast(dict[str, object], result.structuredContent)
    return cast(dict[str, object], structured["error"])


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_malformed_authority_absent_returns_field_pointer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Authoritative absence yields the original dogfood field pointer, not recovery noise."""

    _install_recovery_oracle(monkeypatch, status_wire=_operation_wire("absent"))
    runtime = bridge.build_bridge_runtime()
    arguments = _malformed_decision_arguments()

    result = await bridge.dispatch_publish_work(arguments, runtime)

    assert result.isError is True
    error = _error(result)
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    assert error["retryable"] is False
    assert result.structuredContent is not None
    assert result.structuredContent["request_id"] == _REQUEST
    details = cast(dict[str, object], error["safe_details"])
    assert details["fields"] == ["/event_drafts/0/payload/authority"]
    assert details["reasons"] == ["invalid_type_or_value"]
    assert _HOSTILE_PAYLOAD not in str(result.structuredContent)
    assert _MALFORMED_AUTHORITY not in str(result.structuredContent)
    assert "No durable state changed" not in cast(str, error["message"])
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_completed_operation_wins_over_invalid_retry_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PR #47 guarantee: a committed request_id recovers even when the retry body is malformed."""

    _install_recovery_oracle(monkeypatch, status_wire=_operation_wire("complete"))
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_publish_work(_malformed_decision_arguments(), runtime)

    assert result.isError is True
    error = _error(result)
    assert error["code"] == PublicErrorCode.REQUEST_IDENTITY_CONFLICT.value
    assert result.structuredContent is not None
    assert result.structuredContent["request_id"] == _REQUEST
    details = cast(dict[str, object], error["safe_details"])
    assert details["reason_code"] == "request_identity_conflict"
    assert details["count"] == 1
    assert details["sequence"] == 1
    assert details["head_digest"] == _DIGEST
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_pending_operation_retains_bounded_pending_meaning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_recovery_oracle(monkeypatch, status_wire=_operation_wire("pending"))
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_publish_work(_malformed_decision_arguments(), runtime)

    error = _error(result)
    assert error["code"] == PublicErrorCode.OPERATION_PENDING.value
    assert error["retryable"] is True
    assert "still pending" in cast(str, error["message"])
    assert result.structuredContent is not None
    assert result.structuredContent["request_id"] == _REQUEST
    # Must not be the recovery-unavailable shape.
    assert error.get("safe_details") is None or "operation_recovery_unavailable" not in str(
        error.get("safe_details")
    )
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_quarantined_operation_retains_storage_corrupt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_recovery_oracle(monkeypatch, status_wire=_operation_wire("quarantined"))
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_publish_work(_malformed_decision_arguments(), runtime)

    error = _error(result)
    assert error["code"] == PublicErrorCode.STORAGE_CORRUPT.value
    assert result.structuredContent is not None
    assert result.structuredContent["request_id"] == _REQUEST
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_read_projection_failed_returns_operation_recovery_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dogfood defect: nested status read failure must not become the outer publish result."""

    _install_recovery_oracle(
        monkeypatch,
        raise_on_status=ControlError(
            "read_projection_failed",
            retryable=True,
            correlation_id="err_00000000-0000-4000-8000-000000000096",
        ),
    )
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_publish_work(_malformed_decision_arguments(), runtime)

    assert result.isError is True
    error = _error(result)
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    assert error["retryable"] is False
    assert result.structuredContent is not None
    assert result.structuredContent["request_id"] == _REQUEST
    details = cast(dict[str, object], error["safe_details"])
    assert details["reason_code"] == "operation_recovery_unavailable"
    assert details["fields"] == ["/event_drafts/0/payload/authority"]
    message = cast(str, error["message"])
    # Both certain facts, in that order; never a bare same-id retry the invalid body cannot pass.
    assert "The tool arguments are invalid." in message
    assert "could not be checked" in message
    assert "Retry with the same request_id." not in message
    assert "No durable state changed" not in message
    assert "new request_id" not in message
    assert "read_projection_failed" not in message
    assert _MALFORMED_AUTHORITY not in message
    assert _HOSTILE_PAYLOAD not in str(result.structuredContent)
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_public_operation_error_during_recovery_is_unavailable_not_nested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_recovery_oracle(
        monkeypatch,
        raise_on_status=PublicOperationError(
            PublicErrorCode.INTERNAL_ERROR,
            "Nested internal failure must not become outer durability advice.",
            True,
            safe_details={"reason_code": "read_projection_failed"},
        ),
    )
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_publish_work(_malformed_decision_arguments(), runtime)

    error = _error(result)
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    assert error["retryable"] is False
    details = cast(dict[str, object], error["safe_details"])
    assert details["reason_code"] == "operation_recovery_unavailable"
    assert details["fields"] == ["/event_drafts/0/payload/authority"]
    assert "Nested internal failure" not in cast(str, error["message"])
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_connection_failure_during_recovery_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_recovery_oracle(
        monkeypatch,
        raise_on_status=ControlError("service_unavailable", retryable=True),
    )
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_publish_work(_malformed_decision_arguments(), runtime)

    error = _error(result)
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    assert error["retryable"] is False
    details = cast(dict[str, object], error["safe_details"])
    assert details["reason_code"] == "operation_recovery_unavailable"
    assert details["fields"] == ["/event_drafts/0/payload/authority"]
    assert result.structuredContent is not None
    assert result.structuredContent["request_id"] == _REQUEST
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_dry_run_validation_failure_skips_the_recovery_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dry run appends nothing, so no prior operation can change the answer (issue #239)."""

    seen = _install_recovery_oracle(monkeypatch, status_wire=_operation_wire("absent"))
    runtime = bridge.build_bridge_runtime()
    arguments = _malformed_decision_arguments(dry_run=True)

    result = await bridge.dispatch_publish_work(arguments, runtime)

    assert seen == []
    error = _error(result)
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    assert error["retryable"] is False
    details = cast(dict[str, object], error["safe_details"])
    assert details["fields"] == ["/event_drafts/0/payload/authority"]
    # No claim about durable append / frontier / request-id consumption.
    message = cast(str, error["message"])
    assert "No durable state changed" not in message
    assert "accepted" not in message.lower() or "invalid" in message.lower()
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_dry_run_validation_failure_never_contacts_the_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 2026-08-13 dogfood shape: a dry run must not reach the client factory at all."""

    async def refuse(_runtime: object = bridge.BRIDGE_RUNTIME) -> object:
        raise AssertionError("recovery must not run for a dry run")

    monkeypatch.setattr(bridge, "ensure_service_client", refuse)
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_publish_work(
        _malformed_decision_arguments(dry_run=True), runtime
    )

    error = _error(result)
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    assert error["retryable"] is False
    details = cast(dict[str, object], error["safe_details"])
    assert details["fields"] == ["/event_drafts/0/payload/authority"]
    blob = str(result.structuredContent)
    assert "operation_recovery_unavailable" not in blob
    assert "OPERATION_PENDING" not in blob
    assert _MALFORMED_AUTHORITY not in blob
    assert len(cast(str, error["message"]).encode("utf-8")) <= _MAX_MESSAGE_BYTES
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_non_dry_run_validation_failure_with_unreachable_oracle_keeps_invalid_request_primary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both certain facts, and a remedy the caller can actually complete (issue #239)."""

    _install_recovery_oracle(
        monkeypatch,
        raise_on_status=ControlError("service_unavailable", retryable=True),
    )
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_publish_work(_malformed_decision_arguments(), runtime)

    error = _error(result)
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    assert error["retryable"] is False
    details = cast(dict[str, object], error["safe_details"])
    assert details["fields"] == ["/event_drafts/0/payload/authority"]
    assert details["reasons"] == ["invalid_type_or_value"]
    assert details["reason_code"] == "operation_recovery_unavailable"
    # `safe_details` keys travel in ASCII order (docs/INTERFACES.md); literal insertion order put
    # `reason_code` last, which is the one shape this map is documented never to take.
    assert list(details) == sorted(details)
    message = cast(str, error["message"])
    assert "The tool arguments are invalid." in message
    assert "the local service was unreachable" in message
    assert "Retry with the same request_id." not in message
    assert len(message.encode("utf-8")) <= _MAX_MESSAGE_BYTES
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
@pytest.mark.parametrize("dry_run", ["true", 1, "True", [True]])
async def test_a_dry_run_declaration_must_be_a_literal_boolean(
    monkeypatch: pytest.MonkeyPatch, dry_run: object
) -> None:
    """A malformed dry_run is part of why the body is invalid; it buys no durability shortcut."""

    seen = _install_recovery_oracle(monkeypatch, status_wire=_operation_wire("absent"))
    runtime = bridge.build_bridge_runtime()
    arguments = _malformed_decision_arguments()
    arguments["dry_run"] = dry_run

    result = await bridge.dispatch_publish_work(arguments, runtime)

    assert len(seen) == 1
    assert _error(result)["code"] == PublicErrorCode.INVALID_REQUEST.value
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_a_committed_operation_is_not_consulted_for_a_dry_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Declared behaviour change: a preview makes no durability claim, so it asks none."""

    seen = _install_recovery_oracle(monkeypatch, status_wire=_operation_wire("complete"))
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_publish_work(
        _malformed_decision_arguments(dry_run=True), runtime
    )

    assert seen == []
    error = _error(result)
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    assert error["code"] != PublicErrorCode.REQUEST_IDENTITY_CONFLICT.value
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_locationless_validation_failure_still_carries_the_availability_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With nothing locatable the caveat is all there is to say, and it stays machine-readable."""

    _install_recovery_oracle(
        monkeypatch,
        raise_on_status=ControlError("service_unavailable", retryable=True),
    )

    def unlocatable(_exc: object) -> tuple[dict[str, str], ...]:
        return ()

    monkeypatch.setattr(bridge, "safe_validation_locations", unlocatable)
    runtime = bridge.build_bridge_runtime()

    result = await bridge.dispatch_publish_work(_malformed_decision_arguments(), runtime)

    error = _error(result)
    assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
    details = cast(dict[str, object], error["safe_details"])
    assert details == {
        "continuation": "recovery_check_then_correct",
        "reason_code": "operation_recovery_unavailable",
    }
    await bridge.close_bridge_runtime(runtime)


@pytest.mark.anyio
async def test_hostile_authority_text_never_appears_in_unavailable_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_recovery_oracle(
        monkeypatch,
        raise_on_status=ControlError("read_projection_failed", retryable=True),
    )
    runtime = bridge.build_bridge_runtime()
    arguments = _malformed_decision_arguments(authority=f"x {_HOSTILE_PAYLOAD} y")

    result = await bridge.dispatch_publish_work(arguments, runtime)

    blob = str(result.structuredContent)
    assert _HOSTILE_PAYLOAD not in blob
    error = _error(result)
    details = cast(dict[str, object], error["safe_details"])
    assert details["reason_code"] == "operation_recovery_unavailable"
    assert details["fields"] == ["/event_drafts/0/payload/authority"]
    await bridge.close_bridge_runtime(runtime)
