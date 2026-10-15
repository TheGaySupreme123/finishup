"""Replay invariants for append-only claim correction (ADR-025, issue #432).

Every case here drives the same pure `replay()` path the dry-run, memory append, and SQLite append
share, so an append these vectors reject is an append no surface can record.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from finishup.domain.events import (
    AcceptedEvent,
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    ClaimRecordedPayloadV1_1,
    ClaimRevisionMismatch,
    EventPayload,
    EventSchema,
    LedgerChain,
    LedgerRecord,
    PayloadRef,
    ProjectionLocator,
    RedactionMethod,
    RedactionReasonCategory,
    RedactionRecordedPayload,
    RedactionState,
    ResultOutcome,
    ResultRecordedPayload,
    WriterChain,
    encode_payload,
    media_type_for,
)
from finishup.domain.values import (
    Actor,
    ActorType,
    ClaimId,
    EventId,
    ObligationId,
    ResultId,
    action_id,
    actor_id,
    claim_id,
    event_id,
    object_id,
    obligation_id,
    request_id,
    result_id,
    session_id,
    task_id,
    timestamp_from_string,
    writer_id,
)
from finishup.kernel.claims import effective_claim_ids
from finishup.kernel.reducers import replay
from finishup.protocol.canonical import canonical_digest, canonical_encode, entry_digest
from finishup.protocol.coverage import (
    AuthorshipAssurance,
    PublicationChannel,
    coverage_for_channel,
    coverage_to_json,
)

_TASK = task_id("tsk_00000000-0000-4000-8000-000000000001")
_SESSION = session_id("ses_00000000-0000-4000-8000-000000000001")
_WRITER = writer_id("wri_00000000-0000-4000-8000-000000000001")
_OPERATION = request_id("req_00000000-0000-4000-8000-000000000001")
_AUTHOR = Actor(
    actor_id("agt_claim_correction"),
    ActorType.LOGICAL_AGENT,
    AuthorshipAssurance.SELF_ASSERTED,
)
_NOW = timestamp_from_string("2026-08-30T00:00:00.000Z")
_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")
_MISSING_ACTION = action_id("act_00000000-0000-4000-8000-0000000009ff")


def _act(number: int) -> str:
    return f"act_00000000-0000-4000-8000-{number:012d}"


def _res(number: int) -> ResultId:
    return result_id(f"res_00000000-0000-4000-8000-{number:012d}")


def _clm(number: int) -> ClaimId:
    return claim_id(f"clm_00000000-0000-4000-8000-{number:012d}")


def _evt(sequence: int) -> EventId:
    return event_id(f"evt_00000000-0000-4000-8000-{sequence:012d}")


def _logical_key(schema: EventSchema, payload: EventPayload) -> str | None:
    if schema.name == "action_recorded":
        return str(payload.action_id)  # type: ignore[attr-defined]
    if schema.name == "result_recorded":
        return str(payload.result_id)  # type: ignore[attr-defined]
    if schema.name == "claim_recorded":
        return str(payload.claim_id)  # type: ignore[attr-defined]
    if schema.name == "obligation_published":
        return str(payload.obligation_id)  # type: ignore[attr-defined]
    if schema.name in {"plan_published", "plan_revised"}:
        return str(payload.plan_version)  # type: ignore[attr-defined]
    return None


def _accepted(
    sequence: int,
    schema: EventSchema,
    payload: EventPayload,
    previous: str,
) -> AcceptedEvent:
    encoded = canonical_encode(encode_payload(payload))
    targets: tuple[EventId, ...] = ()
    if type(payload) is RedactionRecordedPayload:
        targets = payload.target_event_ids
    identifier = _evt(sequence)
    object_reference = object_id(f"obj_00000000-0000-4000-8000-{sequence:012d}")
    commitment = "hmac-sha256:" + f"{sequence:064x}"
    media = media_type_for(schema.name)
    # The digest preimage carries exactly the structural fields the domain record serializes, so
    # build it once here rather than constructing a record with a placeholder digest.
    preimage = {
        "protocol": "yoetz.event",
        "protocol_version": "0.1",
        "event_id": identifier,
        "task_id": _TASK,
        "session_id": _SESSION,
        "schema": {"name": schema.name, "version": schema.version},
        "author": {
            "actor_id": _AUTHOR.actor_id,
            "actor_type": _AUTHOR.actor_type.value,
            "assurance": _AUTHOR.assurance.value,
        },
        "writer": {
            "writer_id": _WRITER,
            "sequence": str(sequence),
            "previous_entry_digest": previous,
        },
        "ledger": {
            "ingestion_sequence": str(sequence),
            "previous_entry_digest": previous,
            "accepted_at": _NOW.wire,
        },
        "operation_id": _OPERATION,
        "occurred_at": _NOW.wire,
        "causal_parents": (),
        "publication_channel": PublicationChannel.LOCAL_CLI.value,
        "coverage": coverage_to_json(coverage_for_channel(PublicationChannel.LOCAL_CLI)),
        "payload_ref": {
            "object_id": object_reference,
            "media_type": media,
            "plaintext_size": len(encoded),
            "commitment": commitment,
            "encryption_format": "yoetz-object/1",
        },
        "redaction": "present",
        "artifact_refs": (),
        "evidence_refs": (),
    }
    return AcceptedEvent(
        event_id=identifier,
        task_id=_TASK,
        session_id=_SESSION,
        schema=schema,
        author=_AUTHOR,
        writer=WriterChain(_WRITER, sequence, previous),
        ledger=LedgerChain(sequence, previous, _NOW),
        operation_id=_OPERATION,
        occurred_at=_NOW,
        causal_parents=(),
        publication_channel=PublicationChannel.LOCAL_CLI,
        coverage=coverage_for_channel(PublicationChannel.LOCAL_CLI),
        payload_ref=PayloadRef(object_reference, media, len(encoded), commitment),
        redaction=RedactionState.PRESENT,
        artifact_refs=(),
        evidence_refs=(),
        entry_digest=entry_digest(preimage),
        payload=payload,
        projection_locator=ProjectionLocator(
            schema=schema,
            logical_key=_logical_key(schema, payload),
            canonical_payload_digest=canonical_digest(encode_payload(payload)),
            redaction_target_event_ids=targets,
            redaction_target_object_ids=(),
        ),
    )


def _chain(*payloads: tuple[EventSchema, EventPayload]) -> tuple[LedgerRecord, ...]:
    records: list[LedgerRecord] = []
    previous = "genesis"
    for sequence, (schema, payload) in enumerate(payloads, 1):
        record = _accepted(sequence, schema, payload, previous)
        records.append(record)
        previous = record.entry_digest
    return tuple(records)


def _extend(
    records: tuple[LedgerRecord, ...],
    *payloads: tuple[EventSchema, EventPayload],
) -> tuple[LedgerRecord, ...]:
    extended = list(records)
    previous = extended[-1].entry_digest
    for offset, (schema, payload) in enumerate(payloads, 1):
        record = _accepted(len(extended) + 1, schema, payload, previous)
        del offset
        extended.append(record)
        previous = record.entry_digest
    return tuple(extended)


_ACTION_SCHEMA = EventSchema("action_recorded", "1.0.0")
_RESULT_SCHEMA = EventSchema("result_recorded", "1.0.0")
_CLAIM_V1_SCHEMA = EventSchema("claim_recorded", "1.0.0")
_CLAIM_V1_1_SCHEMA = EventSchema("claim_recorded", "1.1.0")
_REDACTION_SCHEMA = EventSchema("redaction_recorded", "1.0.0")


def _action(
    number: int, obligations: tuple[ObligationId, ...] = (_OBLIGATION,)
) -> ActionRecordedPayload:
    return ActionRecordedPayload(
        action_id=action_id(_act(number)),
        action_kind=ActionKind.OTHER,
        description="Attempt the bounded work.",
        obligation_refs=obligations,
    )


def _result(
    number: int,
    outcome: ResultOutcome,
    *,
    action: str | None = None,
) -> ResultRecordedPayload:
    return ResultRecordedPayload(
        result_id=_res(number),
        action_id=action_id(action if action is not None else _act(number)),
        outcome=outcome,
        summary="Recorded outcome.",
    )


def _redaction(*targets: EventId) -> RedactionRecordedPayload:
    return RedactionRecordedPayload(
        target_event_ids=targets,
        target_object_ids=(),
        method=RedactionMethod.LOGICAL_REDACTION,
        reason_category=RedactionReasonCategory.SECRET,
        authority=actor_id("agt_claim_correction"),
        remaining_gap="One event payload is no longer readable.",
    )


def _completion(
    number: int,
    *,
    limitations: tuple[ResultId, ...] = (),
    supersedes: tuple[ClaimId, ...] = (),
    statement: str = "The bounded scope is complete.",
    supporting: tuple[ResultId, ...] = (),
) -> ClaimRecordedPayloadV1_1:
    return ClaimRecordedPayloadV1_1(
        claim_id=_clm(number),
        claim_kind=ClaimKind.COMPLETION,
        statement=statement,
        supporting_refs=supporting,
        obligation_refs=(_OBLIGATION,),
        limitation_refs=limitations,
        supersedes_claim_refs=supersedes,
    )


def test_unknown_result_has_a_disclosure_channel_and_is_never_required() -> None:
    """#432: an `unknown` outcome must be nameable in limitation_refs.

    `claim_discloses_result` consults only `limitation_refs` for v1.1, and the limitation policy
    treats a relevant `unknown` result as limiting. Rejecting it from `limitation_refs` therefore
    left `material_limitation_omitted` permanently unresolvable, which is the trap #432 removes.
    An `unknown` outcome is still never *required* -- ADR-025 does not upgrade it into a typed
    partial or failure.
    """

    prefix = (
        (_ACTION_SCHEMA, _action(1)),
        (_RESULT_SCHEMA, _result(1, ResultOutcome.UNKNOWN)),
    )
    disclosed = replay(
        _chain(*prefix, (_CLAIM_V1_1_SCHEMA, _completion(1, limitations=(_res(1),))))
    )
    assert effective_claim_ids(disclosed) == frozenset({_clm(1)})

    silent = replay(_chain(*prefix, (_CLAIM_V1_1_SCHEMA, _completion(1))))
    assert effective_claim_ids(silent) == frozenset({_clm(1)})


def test_success_results_are_still_rejected_from_limitation_refs() -> None:
    with pytest.raises(ClaimRevisionMismatch) as caught:
        replay(
            _chain(
                (_ACTION_SCHEMA, _action(1)),
                (_RESULT_SCHEMA, _result(1, ResultOutcome.SUCCESS)),
                (_CLAIM_V1_1_SCHEMA, _completion(1, limitations=(_res(1),))),
            )
        )
    assert caught.value.invariant == "limitation_refs_must_be_relevant_non_success_results"


def test_partial_result_with_a_tombstoned_action_stays_recordable() -> None:
    """A redacted action must not make every completion claim unrecordable.

    Relevance treats a result whose action record is unreadable as conservatively task-wide, so
    `limitation_refs_complete` demands it. An authorability rule that additionally required a
    readable action rejected the very same reference, leaving neither `limitation_refs=[res]` nor
    `limitation_refs=[]` acceptable.
    """

    events = _chain(
        (_ACTION_SCHEMA, _action(1)),
        (_RESULT_SCHEMA, _result(1, ResultOutcome.PARTIAL)),
        (_REDACTION_SCHEMA, _redaction(_evt(1))),
        (_CLAIM_V1_1_SCHEMA, _completion(1, limitations=(_res(1),))),
    )
    state = replay(events)
    assert state.actions[action_id(_act(1))].payload is None
    assert effective_claim_ids(state) == frozenset({_clm(1)})

    with pytest.raises(ClaimRevisionMismatch) as caught:
        replay(_extend(events[:3], (_CLAIM_V1_1_SCHEMA, _completion(1))))
    assert caught.value.invariant == "limitation_refs_complete"


def test_partial_result_with_no_recorded_action_stays_recordable() -> None:
    state = replay(
        _chain(
            (_RESULT_SCHEMA, _result(1, ResultOutcome.PARTIAL, action=str(_MISSING_ACTION))),
            (_CLAIM_V1_1_SCHEMA, _completion(1, limitations=(_res(1),))),
        )
    )
    assert _MISSING_ACTION not in state.actions
    assert effective_claim_ids(state) == frozenset({_clm(1)})


def test_supersession_survives_redacting_the_correcting_claim() -> None:
    """C0 <- C1 <- C2, then redact C1: C0 must not come back as a current claim.

    The revision edge is recorded on the target at ingestion. Deriving it from the replacement's
    live `supersedes_claim_refs` instead resurrected C0 the moment a redaction tombstoned C1's
    payload, putting two contradictory completion claims in the effective set.
    """

    chain = _chain(
        (_ACTION_SCHEMA, _action(1)),
        (_RESULT_SCHEMA, _result(1, ResultOutcome.SUCCESS)),
        (
            _CLAIM_V1_SCHEMA,
            ClaimRecordedPayload(
                claim_id=_clm(0),
                claim_kind=ClaimKind.COMPLETION,
                statement="Everything in scope is complete.",
                supporting_refs=(_res(1),),
                obligation_refs=(_OBLIGATION,),
            ),
        ),
        (
            _CLAIM_V1_1_SCHEMA,
            _completion(
                1,
                supersedes=(_clm(0),),
                statement="Complete, with the integration caveat named.",
                supporting=(_res(1),),
            ),
        ),
        (
            _CLAIM_V1_1_SCHEMA,
            _completion(
                2,
                supersedes=(_clm(1),),
                statement="Complete for the narrowed scope only.",
            ),
        ),
    )
    before = replay(chain)
    assert effective_claim_ids(before) == frozenset({_clm(2)})

    after = replay(_extend(chain, (_REDACTION_SCHEMA, _redaction(_evt(4)))))
    assert after.claims[_clm(1)].payload is None
    assert after.claims[_clm(0)].superseded_by_claim_id == _clm(1)
    assert effective_claim_ids(after) == frozenset({_clm(2)})


def test_a_redacted_replacement_does_not_free_its_target_for_a_second_correction() -> None:
    chain = _chain(
        (_ACTION_SCHEMA, _action(1)),
        (_RESULT_SCHEMA, _result(1, ResultOutcome.SUCCESS)),
        (
            _CLAIM_V1_SCHEMA,
            ClaimRecordedPayload(
                claim_id=_clm(0),
                claim_kind=ClaimKind.COMPLETION,
                statement="Everything in scope is complete.",
                supporting_refs=(_res(1),),
                obligation_refs=(_OBLIGATION,),
            ),
        ),
        (
            _CLAIM_V1_1_SCHEMA,
            _completion(
                1, supersedes=(_clm(0),), statement="Narrowed once.", supporting=(_res(1),)
            ),
        ),
        (_REDACTION_SCHEMA, _redaction(_evt(4))),
    )
    with pytest.raises(ClaimRevisionMismatch) as caught:
        replay(
            _extend(
                chain,
                (
                    _CLAIM_V1_1_SCHEMA,
                    _completion(2, supersedes=(_clm(0),), statement="Narrowed twice."),
                ),
            )
        )
    assert caught.value.invariant == "superseded_claim_must_be_effective"


def test_republishing_a_superseded_v1_claim_id_does_not_make_it_current_again() -> None:
    """A v1.0 claim id may be re-published; that never undoes an applied correction."""

    chain = _chain(
        (_ACTION_SCHEMA, _action(1)),
        (_RESULT_SCHEMA, _result(1, ResultOutcome.SUCCESS)),
        (
            _CLAIM_V1_SCHEMA,
            ClaimRecordedPayload(
                claim_id=_clm(0),
                claim_kind=ClaimKind.COMPLETION,
                statement="Everything in scope is complete.",
                supporting_refs=(_res(1),),
                obligation_refs=(_OBLIGATION,),
            ),
        ),
        (
            _CLAIM_V1_1_SCHEMA,
            _completion(
                1, supersedes=(_clm(0),), statement="Narrowed once.", supporting=(_res(1),)
            ),
        ),
        (
            _CLAIM_V1_SCHEMA,
            ClaimRecordedPayload(
                claim_id=_clm(0),
                claim_kind=ClaimKind.COMPLETION,
                statement="Restated after the correction.",
                supporting_refs=(_res(1),),
                obligation_refs=(_OBLIGATION,),
            ),
        ),
    )
    state = replay(chain)
    assert state.claims[_clm(0)].superseded_by_claim_id == _clm(1)
    assert effective_claim_ids(state) == frozenset({_clm(1)})


@pytest.mark.parametrize("legacy", (False, True))
@pytest.mark.parametrize("scoped_replacement", (False, True))
def test_empty_prior_scope_has_an_explicit_append_only_repair(
    legacy: bool, scoped_replacement: bool
) -> None:
    empty = replace(_completion(0), obligation_refs=())
    if legacy:
        old: ClaimRecordedPayload = ClaimRecordedPayload(
            claim_id=empty.claim_id,
            claim_kind=empty.claim_kind,
            statement=empty.statement,
            supporting_refs=(_OBLIGATION,),
        )
        schema = _CLAIM_V1_SCHEMA
    else:
        old = replace(empty, supporting_refs=(_OBLIGATION,))
        schema = _CLAIM_V1_1_SCHEMA
    prefix = _chain((schema, old))
    correction = replace(
        _completion(1, supersedes=(_clm(0),), statement="Corrected explicit scope."),
        obligation_refs=(_OBLIGATION,) if scoped_replacement else (),
    )
    state = replay(_extend(prefix, (_CLAIM_V1_1_SCHEMA, correction)))
    assert effective_claim_ids(state) == frozenset({_clm(1)})
    assert state.claims[_clm(0)].payload == old
    assert state.claims[_clm(0)].source_event_id == prefix[0].event_id
    assert state.claims[_clm(0)].superseded_by_claim_id == _clm(1)


def test_mixed_empty_and_scoped_targets_converge_without_weakening_overlap() -> None:
    prefix = _chain(
        (_CLAIM_V1_1_SCHEMA, replace(_completion(0), obligation_refs=())),
        (_CLAIM_V1_1_SCHEMA, _completion(1)),
    )
    correction = _completion(2, supersedes=(_clm(0), _clm(1)))
    state = replay(_extend(prefix, (_CLAIM_V1_1_SCHEMA, correction)))
    assert effective_claim_ids(state) == frozenset({_clm(2)})
    assert state.claims[_clm(0)].superseded_by_claim_id == _clm(2)
    assert state.claims[_clm(1)].superseded_by_claim_id == _clm(2)
    for refs in ((), (obligation_id("obl_00000000-0000-4000-8000-000000000002"),)):
        with pytest.raises(ClaimRevisionMismatch) as rejected:
            replay(_extend(prefix, (_CLAIM_V1_1_SCHEMA, replace(correction, obligation_refs=refs))))
        assert rejected.value.invariant == "scope_overlap_required"
    with pytest.raises(ClaimRevisionMismatch) as stale:
        replay(
            _extend(
                prefix,
                (_CLAIM_V1_1_SCHEMA, correction),
                (_CLAIM_V1_1_SCHEMA, _completion(3, supersedes=(_clm(0),))),
            )
        )

    assert stale.value.invariant == "superseded_claim_must_be_effective"


def test_empty_scope_repair_preserves_limitation_and_noop_checks() -> None:
    prefix = _chain(
        (_ACTION_SCHEMA, _action(1)),
        (_RESULT_SCHEMA, _result(1, ResultOutcome.PARTIAL)),
        (_CLAIM_V1_1_SCHEMA, replace(_completion(0, limitations=(_res(1),)), obligation_refs=())),
    )
    with pytest.raises(ClaimRevisionMismatch) as incomplete:
        replay(_extend(prefix, (_CLAIM_V1_1_SCHEMA, _completion(1, supersedes=(_clm(0),)))))
    assert incomplete.value.invariant == "limitation_refs_complete"
    corrected = _completion(1, supersedes=(_clm(0),), limitations=(_res(1),))
    state = replay(_extend(prefix, (_CLAIM_V1_1_SCHEMA, corrected)))
    assert state.claims[_clm(1)].payload == corrected
    with pytest.raises(ClaimRevisionMismatch) as noop:
        replay(_extend(prefix, (_CLAIM_V1_1_SCHEMA, replace(corrected, obligation_refs=()))))

    assert noop.value.invariant == "replacement_must_change_effective_claim"


def test_a_plan_supersession_carries_the_claim_scope_to_its_replacement() -> None:
    """tb4n5 react-lead-form (ADR-033 amendment): a conditional output declared as a ``file`` is
    corrected by superseding its obligation with one that models it as a ``change`` item. When the
    claim named only the superseded obligation, its honest replacement names only the replacement,
    which shares no id with it; the recorded plan supersession is the overlap. Without that
    supersession a disjoint replacement is still refused."""

    from finishup.domain.events import (
        ObligationChange,
        ObligationChangeKind,
        ObligationPublishedPayload,
        ObligationStatus,
        PlanPublishedPayload,
        PlanRevisedPayload,
    )

    replacement = obligation_id("obl_00000000-0000-4000-8000-000000000002")
    obligation_schema = EventSchema("obligation_published", "1.0.0")

    def published(obligation: ObligationId) -> ObligationPublishedPayload:
        return ObligationPublishedPayload(
            obligation_id=obligation,
            description="Quarantine malformed ledgers.",
            evidence_expectation="The regression suite.",
            status=ObligationStatus.OPEN,
        )

    prefix = _chain(
        (obligation_schema, published(_OBLIGATION)),
        (EventSchema("plan_published", "1.0.0"), PlanPublishedPayload(1, "Plan", (_OBLIGATION,))),
        (_CLAIM_V1_1_SCHEMA, _completion(0)),
        (obligation_schema, published(replacement)),
    )
    correction = replace(
        _completion(1, supersedes=(_clm(0),), statement="Conditional output re-modelled."),
        obligation_refs=(replacement,),
    )
    with pytest.raises(ClaimRevisionMismatch) as disjoint:
        replay(_extend(prefix, (_CLAIM_V1_1_SCHEMA, correction)))
    assert disjoint.value.invariant == "scope_overlap_required"

    revised = _extend(
        prefix,
        (
            EventSchema("plan_revised", "1.0.0"),
            PlanRevisedPayload(
                plan_version=2,
                supersedes_plan_version=1,
                reason="The quarantine log is conditional runtime output.",
                summary="Model it as a change item.",
                obligation_changes=(
                    ObligationChange(
                        _OBLIGATION,
                        ObligationChangeKind.SUPERSEDED,
                        "Conditional runtime output.",
                        (replacement,),
                    ),
                ),
            ),
        ),
    )
    state = replay(_extend(revised, (_CLAIM_V1_1_SCHEMA, correction)))
    assert effective_claim_ids(state) == frozenset({_clm(1)})
    assert state.claims[_clm(0)].superseded_by_claim_id == _clm(1)
    # The supersession carries the scope to the replacement only, never to an unrelated id.
    unrelated = replace(
        correction, obligation_refs=(obligation_id("obl_00000000-0000-4000-8000-000000000003"),)
    )
    with pytest.raises(ClaimRevisionMismatch) as still_disjoint:
        replay(_extend(revised, (_CLAIM_V1_1_SCHEMA, unrelated)))
    assert still_disjoint.value.invariant == "scope_overlap_required"


def _published(obligation: ObligationId) -> tuple[EventSchema, EventPayload]:
    from finishup.domain.events import ObligationPublishedPayload, ObligationStatus

    return (
        EventSchema("obligation_published", "1.0.0"),
        ObligationPublishedPayload(
            obligation_id=obligation,
            description="Quarantine malformed ledgers.",
            evidence_expectation="The regression suite.",
            status=ObligationStatus.OPEN,
        ),
    )


def _superseded(
    version: int, old: ObligationId, new: ObligationId
) -> tuple[EventSchema, EventPayload]:
    from finishup.domain.events import ObligationChange, ObligationChangeKind, PlanRevisedPayload

    return (
        EventSchema("plan_revised", "1.0.0"),
        PlanRevisedPayload(
            plan_version=version,
            supersedes_plan_version=version - 1,
            reason="Conditional runtime output re-modelled as a change item.",
            summary="Correction",
            obligation_changes=(
                ObligationChange(
                    old, ObligationChangeKind.SUPERSEDED, "Conditional output.", (new,)
                ),
            ),
        ),
    )


@pytest.mark.parametrize("outcome", [ResultOutcome.FAILURE, ResultOutcome.PARTIAL])
@pytest.mark.parametrize("depth", [1, 2])
def test_a_plan_supersession_never_drops_a_required_failure_disclosure(
    outcome: ResultOutcome, depth: int
) -> None:
    """Checker reproduction (#2): a failure on O1, claimed with it in ``limitation_refs``; O1
    superseded by O2 (or O2 by O3); the replacement claim scoped to the replacement must still
    disclose the failure, and naming it there must be admissible. Relevance follows the
    supersession ancestry, transitively, in both the required and the authorable calculation."""

    from finishup.domain.events import PlanPublishedPayload

    chain = tuple(obligation_id(f"obl_00000000-0000-4000-8000-00000000010{n}") for n in range(3))
    obligations = chain[: depth + 1]
    newest = obligations[-1]
    prefix = _chain(
        _published(obligations[0]),
        (EventSchema("plan_published", "1.0.0"), PlanPublishedPayload(1, "Plan", obligations[:1])),
        (_ACTION_SCHEMA, _action(1, (obligations[0],))),
        (_RESULT_SCHEMA, _result(1, outcome)),
        (
            _CLAIM_V1_1_SCHEMA,
            replace(_completion(0, limitations=(_res(1),)), obligation_refs=(obligations[0],)),
        ),
    )
    revised = _extend(
        prefix,
        *(_published(obligation) for obligation in obligations[1:]),
        *(
            _superseded(version, old, new)
            for version, (old, new) in enumerate(zip(obligations, obligations[1:], strict=False), 2)
        ),
    )
    silent = replace(
        _completion(1, supersedes=(_clm(0),), statement="Re-modelled."),
        obligation_refs=(newest,),
    )
    with pytest.raises(ClaimRevisionMismatch) as dropped:
        replay(_extend(revised, (_CLAIM_V1_1_SCHEMA, silent)))
    assert dropped.value.invariant == "limitation_refs_complete"
    disclosed = replace(silent, limitation_refs=(_res(1),))
    state = replay(_extend(revised, (_CLAIM_V1_1_SCHEMA, disclosed)))
    assert effective_claim_ids(state) == frozenset({_clm(1)})
    assert state.claims[_clm(1)].payload == disclosed


def test_a_fresh_claim_over_a_replacement_still_replays_and_its_relevance_follows_ancestry() -> (
    None
):
    """Replay compatibility: a fresh (non-replacing) claim over O2 that omits a failure recorded
    on the superseded O1 was admitted before this change, so replay keeps admitting it. The
    omission is not lost: check-time relevance (``kernel.claims.result_is_relevant_to_claim``,
    which the work-integrity failed-work rule reads) follows the same supersession ancestry."""

    from finishup.domain.events import PlanPublishedPayload
    from finishup.kernel.claims import result_is_relevant_to_claim

    old, new = (obligation_id(f"obl_00000000-0000-4000-8000-00000000020{n}") for n in range(2))
    prefix = _chain(
        _published(old),
        (EventSchema("plan_published", "1.0.0"), PlanPublishedPayload(1, "Plan", (old,))),
        (_ACTION_SCHEMA, _action(1, (old,))),
        (_RESULT_SCHEMA, _result(1, ResultOutcome.FAILURE)),
        _published(new),
        _superseded(2, old, new),
    )
    fresh = replace(_completion(0), obligation_refs=(new,))
    state = replay(_extend(prefix, (_CLAIM_V1_1_SCHEMA, fresh)))
    assert state.claims[_clm(0)].payload == fresh
    assert result_is_relevant_to_claim(state, state.claims[_clm(0)], _res(1)) is True
