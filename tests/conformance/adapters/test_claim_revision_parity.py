"""Memory and SQLite durable append project the same claim-correction error."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

import pytest

from builders.ledger_adapters import append_command, memory_adapter, sqlite_adapter
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    EventDraft,
    EventPayload,
    EventSchema,
    ResultOutcome,
    ResultRecordedPayload,
    encode_payload,
    media_type_for,
)
from yoetz.domain.values import (
    Actor,
    ActorType,
    action_id,
    actor_id,
    claim_id,
    event_id,
    obligation_id,
    result_id,
    timestamp_from_string,
)
from yoetz.ports.ledger import AppendCommand, AppendEntry, LedgerPort, OperationKind
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectSource, ObjectStorePort
from yoetz.protocol.canonical import canonical_encode
from yoetz.protocol.coverage import AuthorshipAssurance, PublicationChannel, coverage_for_channel
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError

pytestmark = pytest.mark.anyio

_ACTION = action_id("act_00000000-0000-4000-8000-000000000901")
_RESULT = result_id("res_00000000-0000-4000-8000-000000000901")
_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000901")
_OLD_CLAIM = claim_id("clm_00000000-0000-4000-8000-000000000901")
_NEW_CLAIM = claim_id("clm_00000000-0000-4000-8000-000000000902")
_NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)


async def _append_payloads(
    ledger: LedgerPort,
    payloads: tuple[tuple[EventSchema, EventPayload], ...],
    *,
    request_tail: int,
    event_tail: int,
) -> None:
    author = Actor(
        actor_id("agt_fixture"),
        ActorType.LOGICAL_AGENT,
        AuthorshipAssurance.SELF_ASSERTED,
    )
    objects = cast(ObjectStorePort, getattr(ledger, "_objects"))
    seed = append_command()
    entries: list[AppendEntry] = []
    for offset, (schema, payload) in enumerate(payloads):
        draft = EventDraft(
            event_id(f"evt_00000000-0000-4000-8000-{event_tail + offset:012d}"),
            schema,
            timestamp_from_string("2026-07-19T12:00:00.000Z"),
            (),
            payload,
            (),
            (),
        )
        media = media_type_for(schema.name)
        payload_bytes = canonical_encode(encode_payload(payload))
        staged = await objects.stage(
            ObjectSource(data=payload_bytes, declared_size=len(payload_bytes)),
            ObjectMetadata(ObjectKind.EVENT_PAYLOAD, media, seed.task_id, _NOW),
        )
        ref = await objects.finalize(staged)
        entries.append(
            AppendEntry(
                draft,
                author,
                ref,
                ref.commitment,
                media,
                ref.plaintext_size,
                PublicationChannel.LOCAL_CLI,
                coverage_for_channel(PublicationChannel.LOCAL_CLI),
                "projected",
            )
        )
    frontier = await ledger.load_frontier()
    digest_hex = f"{request_tail:064x}"[-64:]
    await ledger.append_batch(
        AppendCommand(
            seed.task_id,
            seed.session_id,
            seed.writer_id,
            f"req_00000000-0000-4000-8000-{request_tail:012d}",
            OperationKind.PUBLISH_WORK,
            "sha256:" + digest_hex,
            frontier.sequence,
            tuple(entries),
        )
    )


def _initial_payloads() -> tuple[tuple[EventSchema, EventPayload], ...]:
    return (
        (
            EventSchema("action_recorded", "1.0.0"),
            ActionRecordedPayload(
                action_id=_ACTION,
                action_kind=ActionKind.OTHER,
                description="Attempt the bounded work.",
                obligation_refs=(_OBLIGATION,),
            ),
        ),
        (
            EventSchema("result_recorded", "1.0.0"),
            ResultRecordedPayload(
                result_id=_RESULT,
                action_id=_ACTION,
                outcome=ResultOutcome.PARTIAL,
                summary="The work completed only in part.",
            ),
        ),
        (
            EventSchema("claim_recorded", "1.0.0"),
            ClaimRecordedPayload(
                claim_id=_OLD_CLAIM,
                claim_kind=ClaimKind.COMPLETION,
                statement="The bounded work is complete.",
                supporting_refs=(_RESULT,),
                obligation_refs=(_OBLIGATION,),
            ),
        ),
    )


def _incomplete_replacement() -> ClaimRecordedPayloadV1_1:
    return ClaimRecordedPayloadV1_1(
        claim_id=_NEW_CLAIM,
        claim_kind=ClaimKind.COMPLETION,
        statement="The scope is complete subject to recorded limitations.",
        supporting_refs=(),
        obligation_refs=(_OBLIGATION,),
        limitation_refs=(),
        supersedes_claim_refs=(_OLD_CLAIM,),
    )


async def test_claim_revision_mismatch_is_identical_on_durable_adapters() -> None:
    failures: list[PublicOperationError] = []
    for factory in (memory_adapter, sqlite_adapter):
        seed = append_command()
        ledger = factory(seed)
        await _append_payloads(ledger, _initial_payloads(), request_tail=901, event_tail=901)
        with pytest.raises(PublicOperationError) as caught:
            await _append_payloads(
                ledger,
                ((EventSchema("claim_recorded", "1.1.0"), _incomplete_replacement()),),
                request_tail=902,
                event_tail=904,
            )
        failures.append(caught.value)

    for error in failures:
        assert error.code is PublicErrorCode.EVENT_INVALID
        # ADR-030: the invariant is carried structurally, not only inside the message, so both
        # adapters must agree on the typed detail as well as the prose.
        assert error.safe_details == {
            "count": 1,
            "invariant": "limitation_refs_complete",
            "reason_code": "claim_revision_mismatch",
            "field": "/event_drafts/0/payload/limitation_refs",
        }
        assert "limitation_refs_complete" in error.message
        # The rejection names the exact live result the claim still owes (benchmark full3: agents
        # could not see hook-observed failures and over- or under-listed them across retries).
        assert f"Missing 1: {_RESULT}." in error.message
    assert failures[0].message == failures[1].message
