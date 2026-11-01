"""Memory and SQLite durable append project the same obligation-resolution error."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

import pytest

from builders.ledger_adapters import append_command, memory_adapter, sqlite_adapter
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EventDraft,
    EventPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    RequestedItem,
    RequestedItemKind,
    encode_payload,
    media_type_for,
)
from finishup.domain.values import (
    Actor,
    ActorType,
    action_id,
    actor_id,
    event_id,
    evidence_id,
    obligation_id,
    timestamp_from_string,
)
from finishup.ports.ledger import AppendCommand, AppendEntry, LedgerPort, OperationKind
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectSource, ObjectStorePort
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.coverage import AuthorshipAssurance, PublicationChannel, coverage_for_channel
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

pytestmark = pytest.mark.anyio

_OBL = obligation_id("obl_00000000-0000-4000-8000-000000000801")
_EVD = evidence_id("evd_00000000-0000-4000-8000-000000000802")
_NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)


def _open_payload() -> ObligationPublishedPayload:
    return ObligationPublishedPayload(
        obligation_id=_OBL,
        description="Close the loop with exact evidence.",
        evidence_expectation="A named test run at the claimed state.",
        status=ObligationStatus.OPEN,
        acceptance_criteria="The focused slice is green.",
        requested_items=(RequestedItem(RequestedItemKind.COMMAND, "pytest -q"),),
    )


def _bad_resolution() -> ObligationPublishedPayload:
    return ObligationPublishedPayload(
        obligation_id=_OBL,
        description="Close the loop with exact evidence.",
        evidence_expectation="Shortened.",
        status=ObligationStatus.RESOLVED,
        resolution_evidence_refs=(_EVD,),
    )


async def _append_payload(
    ledger: LedgerPort,
    payload: EventPayload,
    *,
    request_tail: int,
    event_tail: int,
    family: str = "obligation_published",
    observed: bool = False,
    parent: int | None = None,
) -> None:
    author = Actor(
        actor_id("yoetz:observation-coordinator" if observed else "agt_fixture"),
        ActorType.HARNESS if observed else ActorType.LOGICAL_AGENT,
        AuthorshipAssurance.HARNESS_OBSERVED if observed else AuthorshipAssurance.SELF_ASSERTED,
    )
    draft = EventDraft(
        event_id(f"evt_00000000-0000-4000-8000-{event_tail:012d}"),
        EventSchema(family, "1.0.0"),
        timestamp_from_string("2026-07-19T12:00:00.000Z"),
        () if parent is None else (event_id(f"evt_00000000-0000-4000-8000-{parent:012d}"),),
        payload,
        (),
        (),
    )
    objects = cast(ObjectStorePort, getattr(ledger, "_objects"))
    seed = append_command()
    media = media_type_for(family)
    payload_bytes = canonical_encode(encode_payload(payload))
    staged = await objects.stage(
        ObjectSource(data=payload_bytes, declared_size=len(payload_bytes)),
        ObjectMetadata(ObjectKind.EVENT_PAYLOAD, media, seed.task_id, _NOW),
    )
    ref = await objects.finalize(staged)
    channel = PublicationChannel.HOOK_OBSERVED if observed else PublicationChannel.LOCAL_CLI
    entry = AppendEntry(
        draft,
        author,
        ref,
        ref.commitment,
        media,
        ref.plaintext_size,
        channel,
        coverage_for_channel(channel),
        "projected",
    )
    frontier = await ledger.load_frontier()
    digest_hex = f"{request_tail:064x}"[-64:]
    command = AppendCommand(
        seed.task_id,
        seed.session_id,
        seed.writer_id,
        f"req_00000000-0000-4000-8000-{request_tail:012d}",
        OperationKind.PUBLISH_WORK,
        "sha256:" + digest_hex,
        frontier.sequence,
        (entry,),
    )
    await ledger.append_batch(command)


@pytest.mark.parametrize("adapter_name", ("memory", "sqlite"))
async def test_obligation_resolution_mismatch_on_durable_append(adapter_name: str) -> None:
    seed = append_command()
    ledger = memory_adapter(seed) if adapter_name == "memory" else sqlite_adapter(seed)
    await _append_payload(ledger, _open_payload(), request_tail=801, event_tail=802)
    with pytest.raises(PublicOperationError) as caught:
        await _append_payload(ledger, _bad_resolution(), request_tail=803, event_tail=804)
    error = caught.value
    assert error.code is PublicErrorCode.EVENT_INVALID
    assert error.safe_details["reason_code"] == "obligation_resolution_mismatch"
    assert error.safe_details["field"] == "/event_drafts/0/payload"
    assert "meaning_fields_must_repeat" in error.message
    assert "acceptance_criteria" in error.message
    assert "evidence_expectation" in error.message
    assert "Shortened" not in error.message


async def test_memory_and_sqlite_emit_identical_public_error_contract() -> None:
    failures: list[PublicOperationError] = []
    for factory in (memory_adapter, sqlite_adapter):
        seed = append_command()
        ledger = factory(seed)
        await _append_payload(ledger, _open_payload(), request_tail=811, event_tail=812)
        with pytest.raises(PublicOperationError) as caught:
            await _append_payload(ledger, _bad_resolution(), request_tail=813, event_tail=814)
        failures.append(caught.value)
    assert failures[0].code is failures[1].code is PublicErrorCode.EVENT_INVALID
    assert dict(failures[0].safe_details) == dict(failures[1].safe_details)
    assert failures[0].message == failures[1].message


async def test_command_reconciliation_status_has_memory_sqlite_parity() -> None:
    from finishup.ports.ledger import ProjectionView
    from finishup.protocol.models import StatusObligationItemModel

    outputs: list[dict[str, object]] = []
    for factory in (memory_adapter, sqlite_adapter):
        seed = append_command()
        ledger = factory(seed)
        await _append_payload(ledger, _open_payload(), request_tail=821, event_tail=822)
        observed = ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-000000000823"),
            ActionKind.COMMAND,
            "Synthetic observation",
            command="pytest tests/other.py",
        )
        await _append_payload(
            ledger,
            observed,
            request_tail=823,
            event_tail=824,
            family="action_recorded",
            observed=True,
        )
        assertion = ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-000000000825"),
            ActionKind.EDIT,
            "Incorrectly copied requested command",
            attempted_items=("pytest -q",),
        )
        await _append_payload(
            ledger,
            assertion,
            request_tail=825,
            event_tail=826,
            family="action_recorded",
            parent=824,
        )
        page = await ledger.load_projection(seed.session_id, ProjectionView.OBLIGATIONS)
        assert page is not None
        row = cast(tuple[StatusObligationItemModel, ...], page.state)[0]
        assert row.unattempted_items == ()
        assert row.command_attempts[0].relation == "asserted_observed_mismatch"
        outputs.append(row.model_dump(mode="json"))
    assert outputs[0] == outputs[1]
