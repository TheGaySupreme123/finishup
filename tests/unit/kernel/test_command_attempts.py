"""Exact command evidence relation, including spoofing and unavailable observation."""

from __future__ import annotations

from dataclasses import fields, replace
from typing import cast

import pytest

from builders.policy_cases import act, evt, make_case, obl, obligation_record, record
from builders.replay import replay_records
from finishup.domain.events import (
    AcceptedEvent,
    ActionKind,
    ActionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    ProjectionLocator,
    RequestedItem,
    RequestedItemKind,
    accepted_record_digest_preimage,
    encode_payload,
    media_type_for,
)
from finishup.domain.values import Actor, ActorType, actor_id
from finishup.kernel.command_attempts import command_attempts
from finishup.kernel.projections import projection_from_snapshot, projection_snapshot
from finishup.protocol.canonical import canonical_digest, entry_digest
from finishup.protocol.coverage import AuthorshipAssurance, PublicationChannel


def _event(
    payload: ActionRecordedPayload, number: int, *, observed: bool, parent: int | None = None
) -> AcceptedEvent:
    base = cast(AcceptedEvent, replay_records("projection-rebuild")[0])
    schema = EventSchema("action_recorded", "1.0.0")
    channel = PublicationChannel.HOOK_OBSERVED if observed else PublicationChannel.COOPERATIVE_MCP
    assurance = (
        AuthorshipAssurance.HARNESS_OBSERVED if observed else AuthorshipAssurance.SELF_ASSERTED
    )
    changes = dict(
        payload_ref=replace(base.payload_ref, media_type=media_type_for("action_recorded")),
        coverage=replace(
            base.coverage, publication_channels=(channel,), authorship_assurance=assurance
        ),
        event_id=evt(number),
        schema=schema,
        payload=payload,
        projection_locator=ProjectionLocator(
            schema, payload.action_id, canonical_digest(encode_payload(payload))
        ),
        ledger=replace(
            base.ledger, ingestion_sequence=number, previous_entry_digest="sha256:" + "1" * 64
        ),
        causal_parents=() if parent is None else (evt(parent),),
        author=Actor(
            actor_id("yoetz:observation-coordinator"),
            ActorType.HARNESS,
            AuthorshipAssurance.HARNESS_OBSERVED if observed else AuthorshipAssurance.SELF_ASSERTED,
        ),
        publication_channel=PublicationChannel.HOOK_OBSERVED
        if observed
        else PublicationChannel.COOPERATIVE_MCP,
    )
    # Compute the envelope digest before constructing the validating accepted-event value.
    values = {field.name: getattr(base, field.name) for field in fields(base)}
    values.update(changes)
    draft = object.__new__(AcceptedEvent)
    for key, value in values.items():
        object.__setattr__(draft, key, value)
    values["entry_digest"] = entry_digest(accepted_record_digest_preimage(draft))
    return AcceptedEvent(**{field.name: values[field.name] for field in fields(base) if field.init})


@pytest.mark.parametrize(
    ("command", "relation"),
    [
        ("pytest tests/a.py", "matching_observed_attempt"),
        ("pytest tests/b.py", "asserted_observed_mismatch"),
        ("env -u FINISHUP_ISOLATED_ROOT pytest tests/a.py", "asserted_observed_mismatch"),
        ("pytest  tests/a.py", "asserted_observed_mismatch"),
        ("omitted:structural", "unknown"),
    ],
)
def test_exact_linked_observation_does_not_infer_shell_equivalence(
    command: str, relation: str
) -> None:
    requested = "pytest tests/a.py"
    obligation = ObligationPublishedPayload(
        obl(1),
        "Test",
        "Command evidence",
        ObligationStatus.OPEN,
        requested_items=(RequestedItem(RequestedItemKind.COMMAND, requested),),
    )
    observed = ActionRecordedPayload(
        act(2), ActionKind.COMMAND, "Observed attempt", command=command
    )
    asserted = ActionRecordedPayload(
        act(3), ActionKind.EDIT, "Copied command label", attempted_items=(requested,)
    )
    state = make_case(
        obligations={obl(1): obligation_record(obligation, 1)},
        actions={act(2): record(observed, 2), act(3): record(asserted, 3)},
    ).projection
    events = (_event(observed, 2, observed=True), _event(asserted, 3, observed=False, parent=2))
    result = command_attempts(state, events, obl(1))[0]
    assert result.relation == relation
    assert result.observed_event_ids == (evt(2),)
    assert result.asserted_action_ids == (act(3),)
    restored = projection_from_snapshot(projection_snapshot(state))
    assert command_attempts(restored, events, obl(1)) == (result,)
    # A caller using the coordinator's name cannot award itself observation authority.
    spoof = (_event(observed, 2, observed=False), events[1])
    assert command_attempts(state, spoof, obl(1))[0].relation == "unknown"
    # Unrelated observations, even an exact match, are not silently correlated by time.
    unlinked = (events[0], _event(asserted, 3, observed=False))
    assert command_attempts(state, unlinked, obl(1))[0].relation == "unknown"
    assert command_attempts(state, (), obl(1))[0].relation == "unknown"
    redacted_state = replace(
        state,
        actions={
            act(2): replace(state.actions[act(2)], payload=None, redacted=True),
            act(3): state.actions[act(3)],
        },
    )
    # Historical accepted bytes must not defeat the current redaction projection.
    assert command_attempts(redacted_state, events, obl(1))[0].relation == "unknown"
