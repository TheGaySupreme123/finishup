"""A claim-bound client's observation attestation: closed shape, exact codec (ADR-051 #12)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import Any, cast

import pytest

from finishup.domain.observation import (
    ObservationClientAttestation,
    ObservationClientRoute,
    ObservationCursor,
    ObservationEnvelope,
    ObservationIngestRequest,
    ObservationSource,
    observation_client_attestation_from_json,
    observation_client_attestation_to_json,
    observation_ingest_request_from_json,
    observation_ingest_request_to_json,
)
from finishup.domain.values import JsonObject, JsonValue, Timestamp, freeze_json
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.schemas import validate_schema_instance

_SESSION = "hmac-sha256:" + "5e" * 32
_ROUTE = ObservationClientRoute(
    task_id="tsk_00000000-0000-4000-8000-000000000a01",
    session_id="ses_00000000-0000-4000-8000-000000000a01",
    writer_id="wri_00000000-0000-4000-8000-000000000a01",
)
_ATTESTATION = ObservationClientAttestation(
    consent="active",
    granted_at=Timestamp("2026-11-05T11:00:00.000Z"),
    content_capture_profiles=("claude-code-ordinary-observation-v1",),
    authority_generation="sha256:" + "a6" * 32,
    check_policy_digest="sha256:" + "c4" * 32,
    route=_ROUTE,
)


def _request(attestation: ObservationClientAttestation | None) -> ObservationIngestRequest:
    return ObservationIngestRequest(
        codex_session_id="claude-session-a01",
        envelope=ObservationEnvelope(
            session_commitment=_SESSION,
            event_kind="PostToolUse",
            source_identity="hook:claude-session-a01:1",
            source=ObservationSource.CLAUDE_HOOK,
            cursor=ObservationCursor(1, 0, 1, _SESSION, "claude-code-hooks-ordinary-v2"),
            receipt_time=Timestamp("2026-11-05T12:00:00.000Z"),
            structural_payload=JsonObject({}),
            content_object_refs=(),
            gap_codes=(),
        ),
        client_attestation=attestation,
    )


def _frame(body: JsonObject) -> dict[str, JsonValue]:
    return {
        "body": body,
        "kind": "call",
        "method": "observation_ingest",
        "protocol_version": "1.0",
        "rpc_id": "rpc_00000000-0000-4000-8000-000000000a01",
        "service_generation": "1",
        "service_instance_id": "svc_00000000-0000-4000-8000-000000000a01",
    }


@pytest.mark.parametrize("route", [_ROUTE, None])
def test_an_attested_request_round_trips_exactly(route: ObservationClientRoute | None) -> None:
    request = _request(replace(_ATTESTATION, route=route))
    encoded = observation_ingest_request_to_json(request)
    decoded = observation_ingest_request_from_json(freeze_json(dict(encoded)))
    assert decoded == request
    assert canonical_encode(observation_ingest_request_to_json(decoded)) == canonical_encode(
        encoded
    )
    validate_schema_instance("control-request", "2.10.0", _frame(encoded))


def test_an_unattested_request_keeps_its_exact_bytes() -> None:
    encoded = observation_ingest_request_to_json(_request(None))
    assert "client_attestation" not in encoded
    # Byte-identical to the shape every pre-2.10 client sends.
    validate_schema_instance("control-request", "2.9.0", _frame(encoded))


def test_the_attestation_names_every_member_explicitly() -> None:
    attestation = replace(
        _ATTESTATION,
        content_capture_profiles=(),
        authority_generation=None,
        check_policy_digest=None,
        route=None,
    )
    encoded = observation_client_attestation_to_json(attestation)
    assert set(encoded) == {
        "schema_version",
        "consent",
        "granted_at",
        "content_capture_profiles",
        "authority_generation",
        "check_policy_digest",
        "route",
    }
    assert encoded["schema_version"] == "1.0.0"
    assert observation_client_attestation_from_json(encoded) == attestation


def _fields(**change: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "consent": _ATTESTATION.consent,
        "granted_at": _ATTESTATION.granted_at,
        "content_capture_profiles": _ATTESTATION.content_capture_profiles,
        "authority_generation": _ATTESTATION.authority_generation,
        "check_policy_digest": _ATTESTATION.check_policy_digest,
        "route": _ATTESTATION.route,
    }
    fields.update(change)
    return fields


@pytest.mark.parametrize(
    "change",
    [
        {"consent": "granted"},
        {"content_capture_profiles": ("unknown-profile-v1",)},
        {
            "content_capture_profiles": (
                "cursor-ordinary-observation-v1",
                "claude-code-ordinary-observation-v1",
            )
        },
        {"authority_generation": "sha256:short"},
        {"check_policy_digest": "hmac-sha256:" + "0" * 64},
        {"granted_at": "2026-11-05T11:00:00.000Z"},
        {"route": "tsk_00000000-0000-4000-8000-000000000a01"},
    ],
)
def test_an_attestation_outside_its_closed_shape_is_refused(change: dict[str, object]) -> None:
    with pytest.raises(ProtocolValueError):
        ObservationClientAttestation(**cast(dict[str, Any], _fields(**change)))


def test_a_route_with_a_foreign_id_is_refused() -> None:
    with pytest.raises(ProtocolValueError):
        ObservationClientRoute(_ROUTE.session_id, _ROUTE.session_id, _ROUTE.writer_id)


def _drop_route(raw: dict[str, Any]) -> None:
    raw.pop("route")


def _add_path(raw: dict[str, Any]) -> None:
    raw["path"] = "/srv/dev/project"


def _bump_version(raw: dict[str, Any]) -> None:
    raw["schema_version"] = "2.0.0"


def _route_path(raw: dict[str, Any]) -> None:
    raw["route"] = {**raw["route"], "workspace": "/srv/dev"}


@pytest.mark.parametrize("mutate", [_drop_route, _add_path, _bump_version, _route_path])
def test_a_malformed_attestation_body_is_refused(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    raw: dict[str, Any] = dict(observation_client_attestation_to_json(_ATTESTATION))
    raw["route"] = dict(cast(JsonObject, raw["route"]))
    mutate(raw)
    with pytest.raises(ProtocolValueError):
        observation_client_attestation_from_json(freeze_json(raw))
    body: dict[str, Any] = dict(observation_ingest_request_to_json(_request(None)))
    body["client_attestation"] = raw
    with pytest.raises(ProtocolValueError):
        validate_schema_instance("control-request", "2.10.0", _frame(cast(JsonObject, body)))


def test_a_null_attestation_member_is_not_an_absent_one() -> None:
    body: dict[str, Any] = dict(observation_ingest_request_to_json(_request(None)))
    body["client_attestation"] = None
    with pytest.raises(ProtocolValueError):
        observation_ingest_request_from_json(freeze_json(body))
