"""Property strategies for the six public operation requests and their near misses."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Final, cast

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from builders.clock import format_utc_millis
from builders.events import build_event_draft
from builders.ids import event_id, finding_id, request_id, session_id, task_id, writer_id
from builders.operations import (
    JsonValue,
    check_request,
    publish_work_request,
    receipt_request,
    respond_request,
    start_request,
    status_request,
)
from property.strategies.events import event_schema_version_for, strategy_valid_event_payloads
from yoetz.domain.events import ClientKind, IntegrationKind, encode_payload
from yoetz.domain.values import ActorType

__all__ = [
    "strategy_check_requests",
    "strategy_publish_work_requests",
    "strategy_receipt_requests",
    "strategy_respond_requests",
    "strategy_start_requests",
    "strategy_status_requests",
]

_TEXT_ALPHABET = st.characters(codec="utf-8", blacklist_characters="\x00")
_ACTOR_ALPHABET: Final[str] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
_SCHEMA_VERSION: Final = "1.0.0"
_ACTOR_TYPES: Final = tuple(ActorType)
_CLIENT_KINDS: Final = tuple(ClientKind)
_INTEGRATION_KINDS: Final = tuple(IntegrationKind)

# The exact non-default (required) top-level wire keys per request model in
# ``protocol/models.py``, used only to name one missing-field near miss at a time.
_REQUIRED_FIELDS: Final[dict[str, frozenset[str]]] = {
    "start": frozenset(
        {
            "protocol_version",
            "schema_version",
            "request_id",
            "actor",
            "client",
            "mode",
            "task_title",
            "requested_view",
        }
    ),
    "publish_work": frozenset(
        {
            "protocol_version",
            "schema_version",
            "request_id",
            "actor",
            "client",
            "session_id",
            "writer_id",
            "expected_frontier",
            "event_drafts",
        }
    ),
    "check": frozenset(
        {
            "protocol_version",
            "schema_version",
            "request_id",
            "actor",
            "client",
            "session_id",
            "writer_id",
            "expected_frontier",
            "mode",
        }
    ),
    "respond": frozenset(
        {
            "protocol_version",
            "schema_version",
            "request_id",
            "actor",
            "client",
            "session_id",
            "writer_id",
            "expected_frontier",
            "finding_id",
            "finding_frontier",
            "disposition",
        }
    ),
    "status": frozenset(
        {
            "protocol_version",
            "schema_version",
            "request_id",
            "actor",
            "client",
            "session_id",
            "writer_id",
            "view",
            "limit",
        }
    ),
    "receipt": frozenset(
        {
            "protocol_version",
            "schema_version",
            "request_id",
            "actor",
            "client",
            "task_id",
            "session_id",
            "writer_id",
            "expected_frontier",
            "format",
            "include",
            "redaction_profile",
        }
    ),
}


def _short_text(min_size: int, max_size: int) -> SearchStrategy[str]:
    return st.text(_TEXT_ALPHABET, min_size=min_size, max_size=max_size)


def _actor_id_text() -> SearchStrategy[str]:
    return st.text(alphabet=_ACTOR_ALPHABET, min_size=1, max_size=32)


def _seed() -> SearchStrategy[str]:
    return st.integers(min_value=1, max_value=1_000_000).map(str)


def _digest_str() -> SearchStrategy[str]:
    return st.text(alphabet="0123456789abcdef", min_size=64, max_size=64).map(
        lambda hex_text: f"sha256:{hex_text}"
    )


def _timestamp_wire() -> SearchStrategy[str]:
    return st.datetimes(
        min_value=datetime(2020, 1, 1),  # noqa: DTZ001 - always bound to UTC below
        max_value=datetime(2035, 1, 1),  # noqa: DTZ001
        timezones=st.just(UTC),
    ).map(format_utc_millis)


@st.composite
def _frontier_wire(draw: st.DrawFn) -> dict[str, JsonValue]:
    if draw(st.booleans()):
        return {"sequence": "0", "head_digest": "genesis"}
    sequence = draw(st.integers(min_value=1, max_value=1_000_000))
    return {"sequence": str(sequence), "head_digest": draw(_digest_str())}


@st.composite
def _event_draft_wire(draw: st.DrawFn) -> dict[str, JsonValue]:
    """Build one schema-valid event draft by reusing the events strategy's real payloads."""

    family, payload = draw(strategy_valid_event_payloads)
    payload_json = cast(Mapping[str, JsonValue], encode_payload(payload))
    return build_event_draft(
        event_id=event_id(draw(_seed())),
        schema_name=family,
        schema_version=event_schema_version_for(payload),
        occurred_at=draw(_timestamp_wire()),
        causal_parents=(),
        payload=payload_json,
        artifact_refs=(),
        evidence_refs=(),
    )


@st.composite
def _actor_wire(draw: st.DrawFn) -> dict[str, JsonValue]:
    return {
        "actor_id": draw(_actor_id_text()),
        "actor_type": draw(st.sampled_from(_ACTOR_TYPES)).value,
    }


@st.composite
def _client_wire(draw: st.DrawFn) -> dict[str, JsonValue]:
    return {
        "kind": draw(st.sampled_from(_CLIENT_KINDS)).value,
        "version": draw(_short_text(1, 16)),
        "integration": draw(st.sampled_from(_INTEGRATION_KINDS)).value,
    }


def _near_miss(
    draw: st.DrawFn,
    wire: dict[str, JsonValue],
    required: frozenset[str],
) -> tuple[dict[str, JsonValue], str | None]:
    """Return the request unchanged, or with exactly one named contract rule broken."""

    if draw(st.booleans()):
        return dict(wire), None
    mutation = draw(
        st.sampled_from(("missing_required_field", "unknown_field", "wrong_schema_version"))
    )
    mutated = dict(wire)
    if mutation == "missing_required_field":
        field = draw(st.sampled_from(sorted(required)))
        del mutated[field]
    elif mutation == "unknown_field":
        mutated["__strategy_probe_extra_field__"] = True
    else:
        mutated["schema_version"] = "9.9.9"
    return mutated, mutation


@st.composite
def _start_requests(draw: st.DrawFn) -> tuple[dict[str, JsonValue], str | None]:
    identity: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "actor": draw(_actor_wire()),
        "client": draw(_client_wire()),
    }
    mode = draw(st.sampled_from(("attach", "create", "create_or_attach")))
    fields: dict[str, JsonValue] = {
        "mode": mode,
        "task_title": draw(_short_text(1, 64)),
        "requested_view": "compact",
    }
    # ``external_ref``/``workspace_ref`` are mutually dependent (both or neither), and ``attach``
    # additionally requires either an explicit session or that paired ref (the start-request
    # schema's ``dependentRequired`` plus its one ``mode == "attach"`` cross-field rule).
    include_refs = draw(st.booleans())
    include_session = draw(st.booleans()) if mode != "attach" else not include_refs
    if include_refs:
        fields["external_ref"] = draw(_short_text(1, 32))
        fields["workspace_ref"] = draw(_short_text(1, 32))
    if include_session:
        fields["session_id"] = session_id(draw(_seed()))
    wire = start_request(
        schema_version=_SCHEMA_VERSION,
        request_id=request_id(draw(_seed())),
        identity=identity,
        fields=fields,
    )
    return _near_miss(draw, wire, _REQUIRED_FIELDS["start"])


@st.composite
def _publish_work_requests(draw: st.DrawFn) -> tuple[dict[str, JsonValue], str | None]:
    identity: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "actor": draw(_actor_wire()),
        "client": draw(_client_wire()),
        "session_id": session_id(draw(_seed())),
        "writer_id": writer_id(draw(_seed())),
    }
    frontier: dict[str, JsonValue] = {
        "expected_frontier": None if draw(st.booleans()) else draw(_frontier_wire())
    }
    drafts = cast(
        tuple[JsonValue, ...],
        tuple(draw(st.lists(_event_draft_wire(), min_size=1, max_size=3))),
    )
    wire = publish_work_request(
        schema_version=_SCHEMA_VERSION,
        request_id=request_id(draw(_seed())),
        identity=identity,
        frontier=frontier,
        fields={"event_drafts": cast(JsonValue, drafts)},
    )
    return _near_miss(draw, wire, _REQUIRED_FIELDS["publish_work"])


@st.composite
def _check_requests(draw: st.DrawFn) -> tuple[dict[str, JsonValue], str | None]:
    identity: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "actor": draw(_actor_wire()),
        "client": draw(_client_wire()),
        "session_id": session_id(draw(_seed())),
        "writer_id": writer_id(draw(_seed())),
    }
    frontier: dict[str, JsonValue] = {"expected_frontier": draw(_frontier_wire())}
    fields: dict[str, JsonValue] = {
        "mode": draw(
            st.sampled_from(("deterministic_only", "semantic_if_configured", "semantic_required"))
        )
    }
    if draw(st.booleans()):
        fields["scope"] = cast(JsonValue, {"claim_ids": [], "obligation_ids": []})
    if draw(st.booleans()):
        fields["max_findings"] = str(draw(st.integers(min_value=1, max_value=10)))
    if draw(st.booleans()):
        fields["policy_packs"] = cast(
            JsonValue,
            draw(
                st.sampled_from(
                    (
                        ["work-integrity/0.3.0"],
                        ["research-evidence/0.2.0"],
                        ["research-evidence/0.2.0", "work-integrity/0.3.0"],
                    )
                )
            ),
        )
    wire = check_request(
        schema_version=_SCHEMA_VERSION,
        request_id=request_id(draw(_seed())),
        identity=identity,
        frontier=frontier,
        fields=fields,
    )
    return _near_miss(draw, wire, _REQUIRED_FIELDS["check"])


@st.composite
def _respond_requests(draw: st.DrawFn) -> tuple[dict[str, JsonValue], str | None]:
    identity: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "actor": draw(_actor_wire()),
        "client": draw(_client_wire()),
        "session_id": session_id(draw(_seed())),
        "writer_id": writer_id(draw(_seed())),
        "finding_id": finding_id(draw(_seed())),
    }
    frontier: dict[str, JsonValue] = {
        "expected_frontier": draw(_frontier_wire()),
        "finding_frontier": draw(_frontier_wire()),
    }
    disposition = draw(
        st.sampled_from(("acknowledged", "provenance_disputed", "rejected", "waived"))
    )
    fields: dict[str, JsonValue] = {"disposition": disposition}
    if disposition in {"provenance_disputed", "rejected", "waived"}:
        fields["reason"] = draw(_short_text(1, 32))
    elif draw(st.booleans()):
        fields["reason"] = draw(_short_text(1, 32))
    if disposition == "waived":
        fields["waiver_scope"] = "finding_only"
        if draw(st.booleans()):
            fields["waiver_expiry"] = draw(_timestamp_wire())
    wire = respond_request(
        schema_version=_SCHEMA_VERSION,
        request_id=request_id(draw(_seed())),
        identity=identity,
        frontier=frontier,
        fields=fields,
    )
    return _near_miss(draw, wire, _REQUIRED_FIELDS["respond"])


@st.composite
def _status_requests(draw: st.DrawFn) -> tuple[dict[str, JsonValue], str | None]:
    identity: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "actor": draw(_actor_wire()),
        "client": draw(_client_wire()),
        "session_id": session_id(draw(_seed())),
        "writer_id": writer_id(draw(_seed())),
    }
    view = draw(
        st.sampled_from(
            (
                "assignment",
                "candidate_findings",
                "compact",
                "evidence",
                "findings",
                "history",
                "obligations",
                "versions",
            )
        )
    )
    fields: dict[str, JsonValue] = {
        "view": view,
        "limit": str(draw(st.integers(min_value=1, max_value=100))),
    }
    if view in {
        "assignment",
        "candidate_findings",
        "evidence",
        "findings",
        "history",
        "obligations",
    }:
        if draw(st.booleans()):
            fields["filter"] = {}
    frontier: dict[str, JsonValue] = {
        "at_frontier": str(draw(st.integers(min_value=0, max_value=1_000_000)))
    }
    wire = status_request(
        schema_version=_SCHEMA_VERSION,
        request_id=request_id(draw(_seed())),
        identity=identity,
        frontier=frontier,
        fields=fields,
    )
    return _near_miss(draw, wire, _REQUIRED_FIELDS["status"])


@st.composite
def _receipt_requests(draw: st.DrawFn) -> tuple[dict[str, JsonValue], str | None]:
    identity: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "actor": draw(_actor_wire()),
        "client": draw(_client_wire()),
        "task_id": task_id(draw(_seed())),
        "session_id": session_id(draw(_seed())),
        "writer_id": writer_id(draw(_seed())),
    }
    frontier: dict[str, JsonValue] = {"expected_frontier": draw(_frontier_wire())}
    fields: dict[str, JsonValue] = {
        "format": draw(st.sampled_from(("json", "markdown", "text"))),
        "include": draw(st.sampled_from(("summary", "standard", "full"))),
        "redaction_profile": draw(
            st.sampled_from(("full_local", "default_local_export", "redacted_share"))
        ),
    }
    wire = receipt_request(
        schema_version=_SCHEMA_VERSION,
        request_id=request_id(draw(_seed())),
        identity=identity,
        frontier=frontier,
        fields=fields,
    )
    return _near_miss(draw, wire, _REQUIRED_FIELDS["receipt"])


strategy_start_requests: SearchStrategy[tuple[dict[str, JsonValue], str | None]] = _start_requests()
strategy_publish_work_requests: SearchStrategy[tuple[dict[str, JsonValue], str | None]] = (
    _publish_work_requests()
)
strategy_check_requests: SearchStrategy[tuple[dict[str, JsonValue], str | None]] = _check_requests()
strategy_respond_requests: SearchStrategy[tuple[dict[str, JsonValue], str | None]] = (
    _respond_requests()
)
strategy_status_requests: SearchStrategy[tuple[dict[str, JsonValue], str | None]] = (
    _status_requests()
)
strategy_receipt_requests: SearchStrategy[tuple[dict[str, JsonValue], str | None]] = (
    _receipt_requests()
)
