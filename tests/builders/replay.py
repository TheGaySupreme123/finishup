"""Decode the frozen replay fixtures into exact accepted-record values."""

from __future__ import annotations

from dataclasses import fields, replace
from typing import Any, cast

from finishup.domain.events import (
    PAYLOAD_TYPES,
    AcceptedEvent,
    EventSchema,
    LedgerChain,
    LedgerRecord,
    PayloadRef,
    ProjectionLocator,
    RedactionState,
    SessionOpenedPayload,
    UnknownEvent,
    WriterChain,
    accepted_record_digest_preimage,
    compute_entry_digest,
    decode_payload,
    encode_payload,
)
from finishup.domain.values import (
    Actor,
    ActorType,
    actor_id,
    event_id,
    freeze_json,
    object_id,
    request_id,
    session_id,
    task_id,
    timestamp_from_string,
    writer_id,
)
from finishup.protocol.canonical import JsonValue as CanonicalJsonValue
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.coverage import (
    AuthorshipAssurance,
    Coverage,
    PublicationChannel,
    coverage_from_json,
)
from fixture_loader import load_fixture_json


def _schema(row: dict[str, Any]) -> EventSchema:
    envelope = cast(dict[str, Any], row["envelope"])
    wire = cast(dict[str, Any], envelope["schema"])
    return EventSchema(cast(str, wire["name"]), cast(str, wire["version"]))


def _locator(row: dict[str, Any], schema: EventSchema) -> ProjectionLocator:
    envelope = cast(dict[str, Any], row["envelope"])
    payload = cast(dict[str, Any], row["payload"])
    family = schema.name
    if family in {"plan_published", "plan_revised"}:
        logical_key: str | None = str(payload["plan_version"])
    elif family == "obligation_published":
        logical_key = cast(str, payload["obligation_id"])
    elif family in {"assignment_recorded", "decision_recorded", "check_recorded"}:
        logical_key = cast(str, envelope["event_id"])
    elif family == "action_recorded":
        logical_key = cast(str, payload["action_id"])
    elif family == "result_recorded":
        logical_key = cast(str, payload["result_id"])
    elif family == "evidence_recorded":
        logical_key = cast(str, payload["evidence_id"])
    elif family == "claim_recorded":
        logical_key = cast(str, payload["claim_id"])
    elif family in {"finding_recorded", "response_recorded"}:
        logical_key = cast(str, payload["finding_id"])
    else:
        logical_key = None
    if family == "redaction_recorded":
        event_targets = tuple(cast(list[str], payload["target_event_ids"]))
        object_targets = tuple(cast(list[str], payload["target_object_ids"]))
    else:
        event_targets = ()
        object_targets = ()
    return ProjectionLocator(
        schema=schema,
        logical_key=logical_key,
        canonical_payload_digest=cast(str, row["canonical_payload_digest"]),
        redaction_target_event_ids=cast(Any, event_targets),
        redaction_target_object_ids=cast(Any, object_targets),
    )


def _coverage(value: object) -> Coverage:
    return coverage_from_json(cast(CanonicalJsonValue, freeze_json(value)))


def _record(row: dict[str, Any]) -> LedgerRecord:
    envelope = cast(dict[str, Any], row["envelope"])
    author = cast(dict[str, Any], envelope["author"])
    writer = cast(dict[str, Any], envelope["writer"])
    ledger = cast(dict[str, Any], envelope["ledger"])
    payload_ref = cast(dict[str, Any], envelope["payload_ref"])
    schema = _schema(row)
    common: dict[str, Any] = {
        "event_id": event_id(envelope["event_id"]),
        "task_id": task_id(envelope["task_id"]),
        "session_id": session_id(envelope["session_id"]),
        "schema": schema,
        "author": Actor(
            actor_id(author["actor_id"]),
            ActorType(author["actor_type"]),
            AuthorshipAssurance(author["assurance"]),
        ),
        "writer": WriterChain(
            writer_id(writer["writer_id"]),
            int(writer["sequence"]),
            cast(str, writer["previous_entry_digest"]),
        ),
        "ledger": LedgerChain(
            int(ledger["ingestion_sequence"]),
            cast(str, ledger["previous_entry_digest"]),
            timestamp_from_string(ledger["accepted_at"]),
        ),
        "operation_id": request_id(envelope["operation_id"]),
        "occurred_at": timestamp_from_string(envelope["occurred_at"]),
        "causal_parents": cast(Any, tuple(cast(list[str], envelope["causal_parents"]))),
        "publication_channel": PublicationChannel(envelope["publication_channel"]),
        "coverage": _coverage(envelope["coverage"]),
        "payload_ref": PayloadRef(
            object_id(payload_ref["object_id"]),
            cast(str, payload_ref["media_type"]),
            cast(int, payload_ref["plaintext_size"]),
            cast(str, payload_ref["commitment"]),
        ),
        "redaction": RedactionState(envelope["redaction"]),
        "artifact_refs": cast(Any, tuple(cast(list[str], envelope["artifact_refs"]))),
        "evidence_refs": cast(Any, tuple(cast(list[str], envelope["evidence_refs"]))),
        "entry_digest": cast(str, envelope["entry_digest"]),
    }
    if schema in PAYLOAD_TYPES:
        return AcceptedEvent(
            **common,
            payload=decode_payload(schema, freeze_json(row["payload"])),
            projection_locator=_locator(row, schema),
        )
    digest = cast(str, row["canonical_payload_digest"])
    return UnknownEvent(
        **common,
        payload=freeze_json(row["payload"]),
        projection_locator=ProjectionLocator(schema, None, digest),
        canonical_payload_digest=digest,
    )


def replay_records(name: str) -> tuple[LedgerRecord, ...]:
    """Return one frozen replay vector's accepted prefix."""

    document = cast(
        dict[str, Any],
        load_fixture_json(f"replay/{name}.case.json"),
    )
    raw_input = cast(dict[str, Any], document["input"])
    rows = cast(list[dict[str, Any]], raw_input["accepted_entries"])
    return tuple(_record(row) for row in rows)


def genesis_session_opened() -> AcceptedEvent:
    """The released ``session_opened`` 1.0.0 genesis record of the all-families fixture."""

    record = replay_records("all-event-families")[0]
    assert type(record) is AcceptedEvent
    assert type(record.payload) is SessionOpenedPayload
    return record


def genesis_session_opened_variant(
    *,
    version: str,
    statement: str | None,
    redaction: RedactionState = RedactionState.PRESENT,
) -> AcceptedEvent:
    """The genesis ``session_opened`` re-minted at ``version`` with a valid entry digest."""

    base = genesis_session_opened()
    schema = EventSchema("session_opened", version)
    readable = replace(cast(SessionOpenedPayload, base.payload), task_statement=statement)
    payload = readable if redaction is RedactionState.PRESENT else None
    values: dict[str, object] = {
        field.name: getattr(base, field.name) for field in fields(AcceptedEvent) if field.init
    }
    values.update(
        schema=schema,
        payload=payload,
        redaction=redaction,
        projection_locator=replace(
            base.projection_locator,
            schema=schema,
            canonical_payload_digest=canonical_digest(encode_payload(readable)),
        ),
    )
    # The digest preimage is the record itself, so compute it over an unvalidated copy and then
    # construct the real record, which re-validates every invariant including the digest.
    unvalidated = object.__new__(AcceptedEvent)
    for field in fields(AcceptedEvent):
        object.__setattr__(
            unvalidated, field.name, values.get(field.name, getattr(base, field.name))
        )
    values["entry_digest"] = compute_entry_digest(accepted_record_digest_preimage(unvalidated))
    return AcceptedEvent(**values)  # type: ignore[arg-type]
