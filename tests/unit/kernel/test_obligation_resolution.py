"""Obligation resolution is a one-way open→resolved transition with repeated meaning fields."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from finishup.domain.events import (
    AcceptedEvent,
    EventSchema,
    LedgerChain,
    ObligationPublishedPayload,
    ObligationResolutionMismatch,
    ObligationStatus,
    PayloadRef,
    ProjectionLocator,
    RedactionState,
    RequestedItem,
    RequestedItemKind,
    WriterChain,
    encode_payload,
    media_type_for,
    obligation_meaning_field_diffs,
    public_error_for_obligation_resolution_mismatch,
)
from finishup.domain.values import (
    Actor,
    ActorType,
    actor_id,
    event_id,
    evidence_id,
    object_id,
    obligation_id,
    request_id,
    session_id,
    task_id,
    timestamp_from_string,
    writer_id,
)
from finishup.kernel.reducers import empty_replay_index, extend_replay_index, reduce_event, replay
from finishup.protocol.canonical import canonical_digest, entry_digest
from finishup.protocol.coverage import (
    AuthorshipAssurance,
    PublicationChannel,
    coverage_for_channel,
    coverage_to_json,
)
from finishup.protocol.errors import PublicErrorCode

_OBL_ID = obligation_id("obl_00000000-0000-4000-8000-000000000001")
_EVD_ID = evidence_id("evd_00000000-0000-4000-8000-000000000001")
_EVD_ID_2 = evidence_id("evd_00000000-0000-4000-8000-000000000002")
_SOURCE_EVT = event_id("evt_00000000-0000-4000-8000-000000000099")
_TASK = "tsk_00000000-0000-4000-8000-000000000001"
_SESSION = "ses_00000000-0000-4000-8000-000000000001"
_WRITER = "wri_00000000-0000-4000-8000-000000000001"
_OP = "req_00000000-0000-4000-8000-000000000001"
_COMMITMENT = "hmac-sha256:" + "ab" * 32

_MEANING_FIELDS = (
    "acceptance_criteria",
    "description",
    "evidence_expectation",
    "requested_items",
    "source_refs",
)


def _open_payload(**overrides: Any) -> ObligationPublishedPayload:
    base = ObligationPublishedPayload(
        obligation_id=_OBL_ID,
        description="Close the loop with exact evidence.",
        evidence_expectation="A named test run at the claimed state.",
        status=ObligationStatus.OPEN,
        acceptance_criteria="The focused slice is green.",
        requested_items=(RequestedItem(RequestedItemKind.COMMAND, "pytest -q"),),
        source_refs=(_SOURCE_EVT,),
        resolution_evidence_refs=(),
    )
    return replace(base, **overrides) if overrides else base


def _resolved_payload(**overrides: Any) -> ObligationPublishedPayload:
    base = ObligationPublishedPayload(
        obligation_id=_OBL_ID,
        description="Close the loop with exact evidence.",
        evidence_expectation="A named test run at the claimed state.",
        status=ObligationStatus.RESOLVED,
        acceptance_criteria="The focused slice is green.",
        requested_items=(RequestedItem(RequestedItemKind.COMMAND, "pytest -q"),),
        source_refs=(_SOURCE_EVT,),
        resolution_evidence_refs=(_EVD_ID,),
    )
    return replace(base, **overrides) if overrides else base


def _accepted(
    payload: ObligationPublishedPayload,
    *,
    sequence: int,
    previous_digest: str,
    event_tail: int,
) -> AcceptedEvent:
    schema = EventSchema("obligation_published", "1.0.0")
    event = event_id(f"evt_00000000-0000-4000-8000-{event_tail:012d}")
    object_ref = object_id(f"obj_00000000-0000-4000-8000-{event_tail:012d}")
    payload_digest = canonical_digest(encode_payload(payload))
    author = Actor(
        actor_id("agt_fixture"),
        ActorType.LOGICAL_AGENT,
        AuthorshipAssurance.SELF_ASSERTED,
    )
    occurred = timestamp_from_string("2026-07-19T12:00:00.000Z")
    coverage = coverage_for_channel(PublicationChannel.LOCAL_CLI)
    media_type = media_type_for("obligation_published")
    writer_prev = previous_digest if sequence > 1 else "genesis"
    preimage = {
        "protocol": "yoetz.event",
        "protocol_version": "0.1",
        "event_id": event,
        "task_id": _TASK,
        "session_id": _SESSION,
        "schema": {"name": schema.name, "version": schema.version},
        "author": {
            "actor_id": author.actor_id,
            "actor_type": author.actor_type.value,
            "assurance": author.assurance.value,
        },
        "writer": {
            "writer_id": _WRITER,
            "sequence": str(sequence),
            "previous_entry_digest": writer_prev,
        },
        "ledger": {
            "ingestion_sequence": str(sequence),
            "previous_entry_digest": previous_digest,
            "accepted_at": occurred.wire,
        },
        "operation_id": _OP,
        "occurred_at": occurred.wire,
        "causal_parents": (),
        "publication_channel": PublicationChannel.LOCAL_CLI.value,
        "coverage": coverage_to_json(coverage),
        "payload_ref": {
            "object_id": object_ref,
            "media_type": media_type,
            "plaintext_size": 1,
            "commitment": _COMMITMENT,
            "encryption_format": "yoetz-object/1",
        },
        "redaction": "present",
        "artifact_refs": (),
        "evidence_refs": (),
    }
    digest = entry_digest(preimage)
    return AcceptedEvent(
        event_id=event,
        schema=schema,
        task_id=task_id(_TASK),
        session_id=session_id(_SESSION),
        writer=WriterChain(writer_id(_WRITER), sequence, writer_prev),
        author=author,
        operation_id=request_id(_OP),
        occurred_at=occurred,
        causal_parents=(),
        publication_channel=PublicationChannel.LOCAL_CLI,
        coverage=coverage,
        payload_ref=PayloadRef(object_ref, media_type, 1, _COMMITMENT),
        redaction=RedactionState.PRESENT,
        artifact_refs=(),
        evidence_refs=(),
        ledger=LedgerChain(sequence, previous_digest, occurred),
        entry_digest=digest,
        payload=payload,
        projection_locator=ProjectionLocator(
            schema=schema,
            logical_key=_OBL_ID,
            canonical_payload_digest=payload_digest,
            redaction_target_event_ids=(),
            redaction_target_object_ids=(),
        ),
    )


def _chain(*payloads: ObligationPublishedPayload) -> tuple[AcceptedEvent, ...]:
    records: list[AcceptedEvent] = []
    previous = "genesis"
    for index, payload in enumerate(payloads, start=1):
        record = _accepted(payload, sequence=index, previous_digest=previous, event_tail=index)
        records.append(record)
        previous = record.entry_digest
    return tuple(records)


def test_exact_repeat_plus_resolved_and_evidence_is_accepted() -> None:
    open_payload = _open_payload()
    resolved = _resolved_payload()
    state = replay(_chain(open_payload, resolved))
    record = state.obligations[_OBL_ID]
    assert record.payload is not None
    assert record.payload.status is ObligationStatus.RESOLVED
    assert record.payload.resolution_evidence_refs == (_EVD_ID,)
    assert record.payload.description == open_payload.description
    assert record.payload.acceptance_criteria == open_payload.acceptance_criteria


@pytest.mark.parametrize("field_name", _MEANING_FIELDS)
def test_changing_each_meaning_field_returns_typed_mismatch(field_name: str) -> None:
    open_payload = _open_payload()
    if field_name == "description":
        resolved = _resolved_payload(description="Changed description.")
    elif field_name == "evidence_expectation":
        resolved = _resolved_payload(evidence_expectation="Shortened.")
    elif field_name == "acceptance_criteria":
        resolved = _resolved_payload(acceptance_criteria=None)
    elif field_name == "requested_items":
        resolved = _resolved_payload(requested_items=())
    elif field_name == "source_refs":
        resolved = _resolved_payload(source_refs=())
    else:
        raise AssertionError(field_name)

    assert field_name in obligation_meaning_field_diffs(open_payload, resolved)
    with pytest.raises(ObligationResolutionMismatch) as caught:
        replay(_chain(open_payload, resolved))
    assert caught.value.reason_code == "obligation_resolution_mismatch"
    assert caught.value.invariant == "meaning_fields_must_repeat"
    assert field_name in caught.value.differing_fields
    public = public_error_for_obligation_resolution_mismatch(caught.value, event_index=1)
    assert public.code is PublicErrorCode.EVENT_INVALID
    assert public.safe_details["reason_code"] == "obligation_resolution_mismatch"
    assert public.safe_details["field"] == "/event_drafts/1/payload"
    assert "meaning_fields_must_repeat" in public.message
    assert field_name in public.message
    assert "Changed description" not in public.message
    assert "Shortened" not in public.message
    assert "Close the loop" not in public.message


def test_changing_only_status_and_resolution_evidence_refs_is_accepted() -> None:
    open_payload = _open_payload()
    resolved = replace(
        open_payload,
        status=ObligationStatus.RESOLVED,
        resolution_evidence_refs=(_EVD_ID,),
    )
    state = replay(_chain(open_payload, resolved))
    record = state.obligations[_OBL_ID]
    assert record.payload is not None
    assert record.payload.status is ObligationStatus.RESOLVED


def test_open_to_open_duplicate_is_rejected() -> None:
    open_payload = _open_payload()
    with pytest.raises(ObligationResolutionMismatch) as caught:
        replay(_chain(open_payload, open_payload))
    assert caught.value.invariant == "open_to_resolved_only"
    assert caught.value.differing_fields == ("status",)


def test_resolved_to_resolved_mutation_is_rejected() -> None:
    open_payload = _open_payload()
    first = _resolved_payload(resolution_evidence_refs=(_EVD_ID,))
    second = _resolved_payload(resolution_evidence_refs=(_EVD_ID_2,))
    with pytest.raises(ObligationResolutionMismatch) as caught:
        replay(_chain(open_payload, first, second))
    assert caught.value.invariant == "open_to_resolved_only"
    assert caught.value.differing_fields == ("status",)


def test_resolved_to_open_reopens_it() -> None:
    """tb4n2 R2 (#1022, ADR-041): a resolution whose work no longer holds can be reopened."""

    open_payload = _open_payload()
    resolved = _resolved_payload()
    reopen = _open_payload()
    record = replay(_chain(open_payload, resolved, reopen)).obligations[_OBL_ID]
    assert record.payload is not None
    assert record.payload.status is ObligationStatus.OPEN
    # Meaning fields must still repeat when reopening.
    with pytest.raises(ObligationResolutionMismatch) as caught:
        replay(_chain(open_payload, resolved, _open_payload(description="other prose")))
    assert caught.value.invariant == "meaning_fields_must_repeat"


def test_public_error_never_embeds_field_values() -> None:
    secret = "never-echo-this-obligation-prose"
    open_payload = _open_payload(description=secret)
    resolved = _resolved_payload(description="other prose")
    with pytest.raises(ObligationResolutionMismatch) as caught:
        replay(_chain(open_payload, resolved))
    public = public_error_for_obligation_resolution_mismatch(caught.value, event_index=0)
    rendered = public.message + repr(dict(public.safe_details))
    assert secret not in rendered
    assert "other prose" not in rendered


def test_reduce_event_attaches_event_id_for_draft_attribution() -> None:
    open_payload = _open_payload()
    bad = _resolved_payload(description="mutated")
    records = _chain(open_payload, bad)
    state = replay(records[:1])
    index = empty_replay_index()
    for record in records[:1]:
        index = extend_replay_index(index, record)
    next_index = extend_replay_index(index, records[1])
    with pytest.raises(ObligationResolutionMismatch) as caught:
        reduce_event(state, records[1], next_index)
    assert caught.value.event_id == records[1].event_id
