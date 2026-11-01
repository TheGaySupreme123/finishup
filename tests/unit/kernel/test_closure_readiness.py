"""Closure readiness as a checklist: the kernel split and its per-request facts (issue #913)."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from builders.replay import replay_records
from finishup.domain.events import (
    AcceptedEvent,
    ActionKind,
    ActionRecordedPayload,
    CheckMode,
    CheckRecordedPayload,
    LedgerRecord,
    _review_input_manifest_from_json,  # pyright: ignore[reportPrivateUsage]
    encode_payload,
)
from finishup.domain.findings import SemanticDispatchKind, SemanticProvenance
from finishup.domain.values import JsonValue as DomainJsonValue
from finishup.domain.values import event_id, finding_id, obligation_id
from finishup.kernel.closure_readiness import (
    ClosureReadinessFacts,
    _review_deferred,  # pyright: ignore[reportPrivateUsage]
    closure_readiness_facts,
    derive_closure_readiness,
    live_lineage_blockers,
)
from finishup.kernel.projections import ProjectionState, observation_limitation_finding_ids
from finishup.kernel.receipt_capacity import receipt_blocking_finding_count
from finishup.kernel.reducers import invalidates_recorded_check, replay
from finishup.ports.semantic import SamplingParams
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.coverage import CheckType
from finishup.protocol.models import SemanticReason, SemanticStatus

_FINDING = finding_id("fnd_91300000-0000-4000-8000-000000000001")
_OTHER_FINDING = finding_id("fnd_91300000-0000-4000-8000-000000000002")
_OBLIGATION = obligation_id("obl_91300000-0000-4000-8000-000000000003")
_DIGEST = "sha256:" + "5" * 64
# The standing Codex host gaps plus the deliberate local-only choice (DeepSWE v2 bandit B).
_BANDIT_B_GAPS = (
    "content_unselected",
    "host_outcome_unavailable",
    "semantic_review_not_requested",
    "unpaired_event",
)


def _facts(**changes: object) -> ClosureReadinessFacts:
    base = ClosureReadinessFacts(
        check_applicability="applicable",
        semantic_review_current=False,
        receipt_blocking_finding_ids=(),
        acknowledged_finding_ids=(),
        acknowledged_obligation_ids=(),
    )
    return replace(base, **changes)  # type: ignore[arg-type]


def test_only_standing_limitations_read_ready_with_limitations() -> None:
    split = derive_closure_readiness(
        ("coverage_gaps_declared",), _BANDIT_B_GAPS, _facts(), semantic_review_required=False
    )
    assert split.state == "ready_with_limitations"
    assert split.agent_actionable == ()
    assert split.standing_limitations == _BANDIT_B_GAPS
    assert split.acknowledged_not_done == ()


def test_no_gaps_and_nothing_left_reads_ready() -> None:
    split = derive_closure_readiness((), (), _facts(), semantic_review_required=False)
    assert split.state == "ready"
    assert split.agent_actionable == split.standing_limitations == ()


@pytest.mark.parametrize(
    "condition",
    (
        "obligations_open",
        "findings_unanswered",
        "receipt_findings_unresolved",
        "no_plan_published",
        "no_obligations_declared",
        "projection_stale",
    ),
)
def test_open_work_stays_agent_actionable_beside_standing_gaps(condition: str) -> None:
    split = derive_closure_readiness(
        (condition, "coverage_gaps_declared"),
        _BANDIT_B_GAPS,
        _facts(receipt_blocking_finding_ids=(_FINDING,)),
        semantic_review_required=False,
    )
    assert split.state == "action_required"
    assert split.agent_actionable == (condition,)
    assert split.standing_limitations == _BANDIT_B_GAPS


def test_actionable_gap_codes_stay_agent_actionable() -> None:
    split = derive_closure_readiness(
        ("coverage_gaps_declared",),
        (*_BANDIT_B_GAPS, "completion_plan_not_claimed", "check_coverage:missing_ref"),
        _facts(),
        semantic_review_required=False,
    )
    assert split.state == "action_required"
    assert split.agent_actionable == ("completion_plan_not_claimed", "missing_ref")


@pytest.mark.parametrize("applicability", ("not_recorded", "not_applicable"))
def test_a_missing_or_superseded_check_is_the_one_recheck_readiness_asks_for(
    applicability: str,
) -> None:
    split = derive_closure_readiness(
        ("coverage_gaps_declared",),
        _BANDIT_B_GAPS,
        _facts(check_applicability=applicability),
        semantic_review_required=False,
    )
    assert split.state == "action_required"
    assert split.agent_actionable == ("check_" + applicability,)


def test_an_unreadable_check_payload_is_disclosed_not_rechecked() -> None:
    split = derive_closure_readiness(
        (), (), _facts(check_applicability="payload_unavailable"), semantic_review_required=False
    )
    assert split.state == "ready_with_limitations"
    assert split.standing_limitations == ("check_payload_unavailable",)


@pytest.mark.parametrize(
    ("required", "current", "state"),
    (
        (False, False, "ready_with_limitations"),
        (True, True, "ready_with_limitations"),
        (True, False, "action_required"),
    ),
)
def test_semantic_review_not_requested_follows_the_route(
    required: bool, current: bool, state: str
) -> None:
    split = derive_closure_readiness(
        ("coverage_gaps_declared",),
        _BANDIT_B_GAPS,
        _facts(semantic_review_current=current),
        semantic_review_required=required,
    )
    assert split.state == state
    assert ("semantic_review_not_requested" in split.agent_actionable) is (
        state == "action_required"
    )


def test_only_an_acknowledgement_moves_a_receipt_blocking_finding_off_the_agent_list() -> None:
    blocking = ("receipt_findings_unresolved", "coverage_gaps_declared")
    partly = derive_closure_readiness(
        blocking,
        _BANDIT_B_GAPS,
        _facts(
            receipt_blocking_finding_ids=(_FINDING, _OTHER_FINDING),
            acknowledged_finding_ids=(_FINDING,),
        ),
        semantic_review_required=False,
    )
    assert partly.state == "action_required"
    assert partly.agent_actionable == ("receipt_findings_unresolved",)
    assert partly.acknowledged_not_done == (_FINDING,)

    fully = derive_closure_readiness(
        blocking,
        _BANDIT_B_GAPS,
        _facts(
            receipt_blocking_finding_ids=(_FINDING,),
            acknowledged_finding_ids=(_FINDING,),
            acknowledged_obligation_ids=(_OBLIGATION,),
        ),
        semantic_review_required=False,
    )
    assert fully.state == "ready_with_limitations"
    assert fully.agent_actionable == ()
    assert fully.acknowledged_not_done == (_FINDING, _OBLIGATION)
    assert fully.acknowledged_not_done_count == 2


def test_an_obligation_acknowledgement_never_clears_an_open_obligation() -> None:
    """PR #937 review F2: the obligation seam may name an item but never reads it as done.

    #997 (slice C) clears ``obligations_open`` only when the derived facts also say no readable
    or unreadable open obligation remains; a fact set that does not say (as here) leaves
    ``obligations_open`` agent-actionable.
    """

    split = derive_closure_readiness(
        ("obligations_open", "coverage_gaps_declared"),
        _BANDIT_B_GAPS,
        _facts(acknowledged_obligation_ids=(_OBLIGATION,)),
        semantic_review_required=False,
    )
    assert split.state == "action_required"
    assert split.agent_actionable == ("obligations_open",)


def test_missing_facts_never_assume_an_acknowledgement() -> None:
    split = derive_closure_readiness(
        ("receipt_findings_unresolved", "coverage_gaps_declared"),
        _BANDIT_B_GAPS,
        None,
        semantic_review_required=False,
    )
    assert split.agent_actionable == ("receipt_findings_unresolved",)
    assert split.acknowledged_not_done == ()


def test_unknown_code_is_named_and_keeps_the_task_actionable() -> None:
    split = derive_closure_readiness(
        ("coverage_gaps_declared",),
        (*_BANDIT_B_GAPS, "gap_from_a_newer_build"),
        _facts(),
        semantic_review_required=False,
    )
    assert split.state == "action_required"
    assert split.agent_actionable == ("unclassified_gap:gap_from_a_newer_build",)


def _provenance() -> SemanticProvenance:
    return SemanticProvenance(
        provider="fake",
        endpoint_profile_id="fake",
        endpoint_profile_version="1.0.0",
        model="fake/model",
        sdk_version="1.0.0",
        prompt_digest=_DIGEST,
        schema_digest=_DIGEST,
        policy_digest=_DIGEST,
        privacy_policy_digest=_DIGEST,
        sampling_params=SamplingParams(128),
        latency_ms=1,
        semantic_attempt_id="att_00000000-0000-4000-8000-000000000001",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id="egr_00000000-0000-4000-8000-000000000001",
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id="fake-1",
        egress_authorization_id="aut_00000000-0000-4000-8000-000000000001",
        request_commitment="hmac-sha256:" + "b" * 64,
    )


def _retarget_action(
    source: LedgerRecord, payload: ActionRecordedPayload, sequence: int
) -> AcceptedEvent:
    """Copy one action so it follows a check, with a valid entry digest."""

    from dataclasses import fields

    from finishup.domain.events import accepted_record_digest_preimage, compute_entry_digest

    base = cast(AcceptedEvent, source)
    values: dict[str, object] = {
        field.name: getattr(base, field.name) for field in fields(AcceptedEvent) if field.init
    }
    values.update(
        ledger=replace(base.ledger, ingestion_sequence=sequence),
        payload=payload,
        projection_locator=replace(
            base.projection_locator,
            canonical_payload_digest=canonical_digest(encode_payload(payload)),
        ),
    )
    unvalidated = object.__new__(AcceptedEvent)
    for field in fields(AcceptedEvent):
        object.__setattr__(
            unvalidated, field.name, values.get(field.name, getattr(base, field.name))
        )
    values["entry_digest"] = compute_entry_digest(accepted_record_digest_preimage(unvalidated))
    return AcceptedEvent(**values)  # type: ignore[arg-type]


def _append_check(
    source: LedgerRecord,
    payload: CheckRecordedPayload,
    sequence: int,
    *,
    appended_id: str = "evt_00000000-0000-4000-8000-00000000f0c1",
) -> AcceptedEvent:
    """A second check after *source*, with its own event id and entry digest."""

    from dataclasses import fields

    from finishup.domain.events import accepted_record_digest_preimage, compute_entry_digest

    base = cast(AcceptedEvent, source)
    values: dict[str, object] = {
        field.name: getattr(base, field.name) for field in fields(AcceptedEvent) if field.init
    }
    appended = event_id(appended_id)
    values.update(
        event_id=appended,
        ledger=replace(base.ledger, ingestion_sequence=sequence),
        payload=payload,
        projection_locator=replace(
            base.projection_locator,
            logical_key=appended,
            canonical_payload_digest=canonical_digest(encode_payload(payload)),
        ),
    )
    unvalidated = object.__new__(AcceptedEvent)
    for field in fields(AcceptedEvent):
        object.__setattr__(
            unvalidated, field.name, values.get(field.name, getattr(base, field.name))
        )
    values["entry_digest"] = compute_entry_digest(accepted_record_digest_preimage(unvalidated))
    return AcceptedEvent(**values)  # type: ignore[arg-type]


def _prefix_through_check() -> tuple[LedgerRecord, ...]:
    records = replay_records("all-event-families")
    index = next(
        position
        for position, record in enumerate(records)
        if type(record) is AcceptedEvent and type(record.payload) is CheckRecordedPayload
    )
    return tuple(records[: index + 1])


def test_facts_follow_the_receipt_applicability_rule_on_a_real_replay() -> None:
    prefix = _prefix_through_check()
    facts = closure_readiness_facts(replay(prefix), prefix)
    assert facts.check_applicability == "applicable"

    genesis = tuple(record for record in prefix if record.schema.name == "session_opened")
    assert closure_readiness_facts(replay(genesis), genesis).check_applicability == "not_recorded"

    records = tuple(replay_records("all-event-families"))
    projection = replay(records)
    full = closure_readiness_facts(projection, records)
    # The receipt-blocking set is exactly the one the compact row counts.
    assert len(full.receipt_blocking_finding_ids) == receipt_blocking_finding_count(projection)
    # Nothing in a recorded ledger is acknowledged unless a response says so.
    assert full.acknowledged_finding_ids == ()


def test_semantic_currency_needs_a_completed_review_with_no_later_material_change() -> None:
    prefix = _prefix_through_check()
    check = cast(AcceptedEvent, prefix[-1])
    payload = cast(CheckRecordedPayload, check.payload)
    assert payload.semantic_status is not SemanticStatus.SUCCEEDED
    assert closure_readiness_facts(replay(prefix), prefix).semantic_review_current is False

    reviewed_payload = replace(
        payload,
        mode=CheckMode.SEMANTIC_REQUIRED,
        semantic_status=SemanticStatus.SUCCEEDED,
        semantic_reason=SemanticReason.SEMANTIC_COMPLETED,
        semantic_provenance=_provenance(),
        coverage=replace(
            payload.coverage,
            check_types=(CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED),
        ),
    )
    succeeded = replace(
        check,
        payload=reviewed_payload,
        projection_locator=replace(
            check.projection_locator,
            canonical_payload_digest=canonical_digest(encode_payload(reviewed_payload)),
        ),
    )
    reviewed = (*prefix[:-1], succeeded)
    assert closure_readiness_facts(replay(prefix), reviewed).semantic_review_current is True
    records = tuple(replay_records("all-event-families"))
    later = records[len(prefix) :]
    limitations = observation_limitation_finding_ids(replay(prefix), (*reviewed, *later))
    material = next(
        position
        for position, record in enumerate(later)
        if invalidates_recorded_check(
            record,
            check.ledger.ingestion_sequence,
            payload.returned_finding_ids,
            limitation_finding_ids=limitations,
            projection=replay(prefix),
        )
    )
    suffix = later[: material + 1]
    assert (
        closure_readiness_facts(replay(prefix), (*reviewed, *suffix)).semantic_review_current
        is False
    )


def test_a_check_in_flight_is_never_nothing_further_to_do() -> None:
    split = derive_closure_readiness(
        ("coverage_gaps_declared",),
        _BANDIT_B_GAPS,
        _facts(),
        semantic_review_required=False,
        check_in_flight=True,
    )
    assert split.state == "action_required"
    assert split.agent_actionable == ("check_in_progress",)
    assert split.standing_limitations == _BANDIT_B_GAPS


def test_only_recorded_lineage_facts_can_be_disclosed_limitations() -> None:
    # A live token is actionable until a recorded evaluation carries its code.
    assert live_lineage_blockers(
        ("lineage_child_read_gap", "lineage_child_coverage_gap"), _BANDIT_B_GAPS
    ) == ("lineage_child_coverage_gap", "lineage_child_read_gap")
    recorded = (*_BANDIT_B_GAPS, "lineage_child_coverage_gap", "lineage_child_unavailable")
    assert (
        live_lineage_blockers(("lineage_child_read_gap", "lineage_child_coverage_gap"), recorded)
        == ()
    )
    split = derive_closure_readiness(
        ("coverage_gaps_declared",),
        _BANDIT_B_GAPS,
        _facts(),
        semantic_review_required=False,
        live_blockers=("lineage_child_read_gap",),
    )
    assert split.state == "action_required"
    assert split.agent_actionable == ("lineage_child_read_gap",)
    assert "lineage_child_read_gap" not in split.standing_limitations


def _with_check_payload(
    prefix: tuple[LedgerRecord, ...], **changes: object
) -> tuple[LedgerRecord, ...]:
    check = cast(AcceptedEvent, prefix[-1])
    payload = replace(cast(CheckRecordedPayload, check.payload), **changes)  # type: ignore[arg-type]
    rewritten = replace(
        check,
        payload=payload,
        projection_locator=replace(
            check.projection_locator,
            canonical_payload_digest=canonical_digest(encode_payload(payload)),
        ),
    )
    return (*prefix[:-1], rewritten)


def _manifest(review_phase: str | None) -> dict[str, object]:
    section: dict[str, object] = {
        "content_bytes": 0,
        "content_digest": None,
        "item_ids": [],
        "omission_reasons": [],
        "omitted_refs": [],
        "revision": None,
        "source_refs": [],
        "status": "missing",
    }
    manifest: dict[str, object] = {
        "schema": "yoetz.review-input-manifest/1",
        "specification": section,
        "current_diff": section,
        "caller_evidence": section,
        "latest_verification": section,
        "prior_finding_context": section,
        "phase": "provider_bound",
        "missing_inputs": [],
        "selected_item_count": 0,
        "selected_excerpt_bytes": 0,
        "omitted_item_count": 0,
    }
    if review_phase is not None:
        manifest["review_phase"] = review_phase
    return manifest


def _reviewed(
    prefix: tuple[LedgerRecord, ...], review_phase: str | None
) -> tuple[LedgerRecord, ...]:
    payload = cast(CheckRecordedPayload, cast(AcceptedEvent, prefix[-1]).payload)
    return _with_check_payload(
        prefix,
        mode=CheckMode.SEMANTIC_REQUIRED,
        semantic_status=SemanticStatus.SUCCEEDED,
        semantic_reason=SemanticReason.SEMANTIC_COMPLETED,
        semantic_provenance=_provenance(),
        review_input_manifest=_review_input_manifest_from_json(
            cast(DomainJsonValue, _manifest(review_phase))
        ),
        coverage=replace(
            payload.coverage,
            check_types=(CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED),
        ),
    )


def test_a_routine_review_leaves_the_closing_review_actionable() -> None:
    """TB4 tb4f1 (issue #976): the receipt is the last step, so the last review judges completion.

    atrx-vep-crispr closed after two routine reviews; nothing asked for a completeness review.
    """

    prefix = _prefix_through_check()
    routine = _reviewed(prefix, "routine")
    facts = closure_readiness_facts(replay(routine), routine)
    assert facts.semantic_review_used is True
    assert facts.closing_review_current is False
    split = derive_closure_readiness((), (), facts, semantic_review_required=False)
    assert "closing_review_required" in split.agent_actionable
    assert split.state == "action_required"

    closing = _reviewed(prefix, "final")
    closed = closure_readiness_facts(replay(closing), closing)
    assert closed.closing_review_current is True
    split = derive_closure_readiness((), (), closed, semantic_review_required=True)
    assert "closing_review_required" not in split.agent_actionable


def test_closing_review_goes_stale_after_a_material_change() -> None:
    """Bookkeeping that supersedes a check does not by itself demand another closing review.

    A real edit still does. ``invalidates_recorded_check`` is unchanged, so the check itself
    goes inapplicable; only the closing-review currency uses the narrower delta.
    """

    prefix = _prefix_through_check()
    closing = _reviewed(prefix, "final")
    check = cast(AcceptedEvent, closing[-1])
    payload = cast(CheckRecordedPayload, check.payload)
    records = tuple(replay_records("all-event-families"))
    later = records[len(prefix) :]
    limitations = observation_limitation_finding_ids(replay(prefix), (*closing, *later))
    state = replay(prefix)
    material = next(
        position
        for position, record in enumerate(later)
        if invalidates_recorded_check(
            record,
            check.ledger.ingestion_sequence,
            payload.returned_finding_ids,
            limitation_finding_ids=limitations,
            projection=state,
        )
    )
    bookkeeping = (*closing, *later[: material + 1])
    facts = closure_readiness_facts(state, bookkeeping)
    assert facts.closing_review_current is True
    assert facts.check_applicability == "not_applicable"
    source = next(
        record
        for record in prefix
        if record.schema.name == "action_recorded" and type(record.payload) is ActionRecordedPayload
    )
    edited = replace(
        cast(ActionRecordedPayload, source.payload),
        action_kind=ActionKind.EDIT,
    )
    edit = _retarget_action(source, edited, check.ledger.ingestion_sequence + 1)
    rearmed = closure_readiness_facts(state, (*closing, edit))
    assert rearmed.closing_review_current is False
    assert rearmed.check_applicability == "not_applicable"
    split = derive_closure_readiness((), (), rearmed, semantic_review_required=True)
    assert "closing_review_required" in split.agent_actionable
    assert "semantic_coordinator_failure" not in split.standing_limitations


def test_an_unchanged_coordinator_failure_is_a_named_limitation() -> None:
    """The newest check failed in the coordinator and nothing material followed it.

    That is not another identical closing review. A later edit asks again and drops the limit.
    """

    prefix = _prefix_through_check()
    failed = _with_check_payload(
        prefix,
        mode=CheckMode.SEMANTIC_REQUIRED,
        semantic_status=SemanticStatus.FAILED,
        semantic_reason=SemanticReason.COORDINATOR_FAILURE,
        semantic_provenance=None,
    )
    facts = closure_readiness_facts(replay(failed), failed)
    assert facts.closing_review_current is True
    assert facts.coordinator_failure_unchanged is True
    split = derive_closure_readiness((), (), facts, semantic_review_required=True)
    assert "closing_review_required" not in split.agent_actionable
    assert "semantic_coordinator_failure" in split.standing_limitations

    check = cast(AcceptedEvent, failed[-1])
    source = next(
        record
        for record in prefix
        if record.schema.name == "action_recorded" and type(record.payload) is ActionRecordedPayload
    )
    edited = replace(cast(ActionRecordedPayload, source.payload), action_kind=ActionKind.EDIT)
    edit = _retarget_action(source, edited, check.ledger.ingestion_sequence + 1)
    after = closure_readiness_facts(replay(failed), (*failed, edit))
    assert after.coordinator_failure_unchanged is False
    assert after.closing_review_current is False
    asked = derive_closure_readiness((), (), after, semantic_review_required=True)
    assert "closing_review_required" in asked.agent_actionable
    assert "semantic_coordinator_failure" not in asked.standing_limitations


def test_an_appended_check_keeps_the_failed_coordinator_attempt() -> None:
    """History is the failed check plus what follows it, not a replacement of the failure.

    Bookkeeping after the failure stays a named limitation and does not ask for the same
    closing review. A material edit asks again. A later successful final review clears the flag.
    """

    prefix = _prefix_through_check()
    failed = _with_check_payload(
        prefix,
        mode=CheckMode.SEMANTIC_REQUIRED,
        semantic_status=SemanticStatus.FAILED,
        semantic_reason=SemanticReason.COORDINATOR_FAILURE,
        semantic_provenance=None,
    )
    state = replay(failed)
    baseline = closure_readiness_facts(state, failed)
    assert baseline.closing_material_frontier is not None
    check = cast(AcceptedEvent, failed[-1])
    sequence = check.ledger.ingestion_sequence + 1
    source = next(
        record
        for record in prefix
        if record.schema.name == "action_recorded" and type(record.payload) is ActionRecordedPayload
    )
    bookkeeping = _retarget_action(
        source,
        replace(
            cast(ActionRecordedPayload, source.payload),
            action_kind=ActionKind.OTHER,
            command=None,
        ),
        sequence,
    )
    unchanged = closure_readiness_facts(state, (*failed, bookkeeping))
    assert unchanged.coordinator_failure_unchanged is True
    assert unchanged.closing_material_frontier == baseline.closing_material_frontier
    assert unchanged.closing_review_current is True
    held = derive_closure_readiness((), (), unchanged, semantic_review_required=True)
    assert "semantic_coordinator_failure" in held.standing_limitations
    assert "closing_review_required" not in held.agent_actionable

    edited = _retarget_action(
        source,
        replace(cast(ActionRecordedPayload, source.payload), action_kind=ActionKind.EDIT),
        sequence,
    )
    moved = closure_readiness_facts(state, (*failed, edited))
    assert moved.coordinator_failure_unchanged is False
    # The synthetic edit is past this projection's frontier. Status cuts the prefix at the
    # frontier before this call, so the remembered sequence stays put until that replay.
    assert moved.closing_material_frontier == baseline.closing_material_frontier
    assert moved.closing_review_current is False
    asked = derive_closure_readiness((), (), moved, semantic_review_required=True)
    assert "closing_review_required" in asked.agent_actionable
    assert "semantic_coordinator_failure" not in asked.standing_limitations

    failed_payload = cast(CheckRecordedPayload, check.payload)
    succeeded = _append_check(
        check,
        replace(
            failed_payload,
            mode=CheckMode.SEMANTIC_REQUIRED,
            semantic_status=SemanticStatus.SUCCEEDED,
            semantic_reason=SemanticReason.SEMANTIC_COMPLETED,
            semantic_provenance=_provenance(),
            review_input_manifest=_review_input_manifest_from_json(
                cast(DomainJsonValue, _manifest("final"))
            ),
            coverage=replace(
                failed_payload.coverage,
                check_types=(CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED),
            ),
        ),
        sequence,
    )
    cleared = closure_readiness_facts(state, (*failed, succeeded))
    assert cleared.coordinator_failure_unchanged is False
    assert cleared.closing_material_frontier == baseline.closing_material_frontier
    assert cleared.closing_review_current is True
    done = derive_closure_readiness((), (), cleared, semantic_review_required=True)
    assert "closing_review_required" not in done.agent_actionable
    assert "semantic_coordinator_failure" not in done.standing_limitations
    assert failed[-1].event_id != succeeded.event_id


def test_a_later_final_review_clears_an_older_coordinator_failure() -> None:
    prefix = _prefix_through_check()
    failed = _with_check_payload(
        prefix,
        mode=CheckMode.SEMANTIC_REQUIRED,
        semantic_status=SemanticStatus.FAILED,
        semantic_reason=SemanticReason.COORDINATOR_FAILURE,
        semantic_provenance=None,
    )
    # A successful final review recorded on the same check payload position is the current one
    # when it is the newest check. Build it as a replacement of the failure, which is newest.
    closing = _reviewed(prefix, "final")
    facts = closure_readiness_facts(replay(closing), closing)
    assert facts.coordinator_failure_unchanged is False
    assert facts.closing_review_current is True
    # The failed payload alone, with no later success, is the limitation. Sanity: the two
    # prefixes differ by that check.
    assert failed[-1].payload != closing[-1].payload


def test_an_undeliverable_review_attempt_is_not_asked_for_again() -> None:
    """A privacy- or provider-blocked attempt discloses its own limit; a recheck cannot remove it."""

    prefix = _prefix_through_check()
    blocked = _with_check_payload(
        prefix,
        mode=CheckMode.SEMANTIC_REQUIRED,
        semantic_status=SemanticStatus.BLOCKED_FORBIDDEN_DATA,
        semantic_reason=SemanticReason.NEVER_SEND_DETECTED,
    )
    facts = closure_readiness_facts(replay(blocked), blocked)
    assert facts.closing_review_current is True
    split = derive_closure_readiness((), (), facts, semantic_review_required=True)
    assert "closing_review_required" not in split.agent_actionable


def test_a_deterministic_only_route_never_asks_for_a_closing_review() -> None:
    prefix = _prefix_through_check()
    facts = closure_readiness_facts(replay(prefix), prefix)
    assert facts.semantic_review_used is False
    split = derive_closure_readiness((), (), facts, semantic_review_required=False)
    assert "closing_review_required" not in split.agent_actionable
    required = derive_closure_readiness((), (), facts, semantic_review_required=True)
    assert "closing_review_required" in required.agent_actionable


def _always(value: bool) -> object:
    def stopped(records: object) -> bool:
        del records
        return value

    return stopped


def test_a_review_round_stopped_for_an_insufficient_packet_is_not_asked_for_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tb4n1 D3: retro-console-soc ran 13 closing reviews, 12 of them ``insufficient_packet``.

    Once the reviewer twice could not assess the same content, the check skips the review and
    records ``semantic_review_skipped_insufficient_packet``; neither a current review nor a
    closing review is demanded again, and the gap stays a standing limit.
    """

    prefix = _prefix_through_check()
    payload = cast(CheckRecordedPayload, cast(AcceptedEvent, prefix[-1]).payload)
    stopped = _with_check_payload(
        prefix,
        mode=CheckMode.SEMANTIC_REQUIRED,
        semantic_status=SemanticStatus.NOT_REQUESTED,
        semantic_reason=SemanticReason.DETERMINISTIC_MODE,
        coverage=replace(
            payload.coverage,
            known_gaps=tuple(
                sorted(
                    {
                        *payload.coverage.known_gaps,
                        "semantic_review_not_requested",
                        "semantic_review_skipped_insufficient_packet",
                    }
                )
            ),
        ),
    )
    import finishup.kernel.closure_readiness as readiness

    # The round is still stopped (two insufficient reviews, no edit since): see test_review_round.
    monkeypatch.setattr(readiness, "review_round_stopped", _always(True))
    facts = closure_readiness_facts(replay(stopped), stopped)
    assert facts.closing_review_current is True
    assert facts.semantic_review_current is True
    split = derive_closure_readiness(
        (),
        ("semantic_review_not_requested", "semantic_review_skipped_insufficient_packet"),
        facts,
        semantic_review_required=True,
    )
    assert "closing_review_required" not in split.agent_actionable
    assert "semantic_review_not_requested" not in split.agent_actionable
    assert "semantic_review_skipped_insufficient_packet" in split.standing_limitations

    # An edit since re-armed the round: the skipped check is no longer the current review.
    monkeypatch.setattr(readiness, "review_round_stopped", _always(False))
    rearmed = closure_readiness_facts(replay(stopped), stopped)
    assert rearmed.closing_review_current is False
    assert rearmed.semantic_review_current is False
    # A plain deterministic-only check carries no such marker and does not stop the round.
    plain = _with_check_payload(
        prefix,
        mode=CheckMode.SEMANTIC_REQUIRED,
        semantic_status=SemanticStatus.NOT_REQUESTED,
        semantic_reason=SemanticReason.DETERMINISTIC_MODE,
    )
    assert closure_readiness_facts(replay(plain), plain).closing_review_current is False


def _deferred_payload(
    payload: CheckRecordedPayload, *, route_required: bool = True
) -> CheckRecordedPayload:
    """A check that deferred its review before the first material edit (issue #1046)."""

    return replace(
        payload,
        mode=CheckMode.SEMANTIC_IF_CONFIGURED,
        semantic_status=SemanticStatus.NOT_REQUESTED,
        semantic_reason=SemanticReason.DETERMINISTIC_MODE,
        semantic_route_required=None if route_required else False,
        coverage=replace(
            payload.coverage,
            known_gaps=tuple(
                sorted(
                    {
                        *payload.coverage.known_gaps,
                        "semantic_review_deferred_before_first_edit",
                        "semantic_review_not_requested",
                    }
                )
            ),
        ),
    )


def _deferred(prefix: tuple[LedgerRecord, ...]) -> tuple[LedgerRecord, ...]:
    """The prefix's check deferred, on a route that requires review (the field is absent)."""

    payload = cast(CheckRecordedPayload, cast(AcceptedEvent, prefix[-1]).payload)
    deferred = _deferred_payload(payload)
    return _with_check_payload(prefix, **{name: getattr(deferred, name) for name in _CHANGED})


_CHANGED = ("mode", "semantic_status", "semantic_reason", "coverage")


_DEFERRAL_GAPS = ("semantic_review_deferred_before_first_edit", "semantic_review_not_requested")


def test_a_deferred_required_review_asks_for_the_closing_review() -> None:
    """Issue #1046 (review): where review is required, work that is not an edit is still reviewed.

    Every routine check before the first edit defers, so no review ever completes. A deferral on
    a check whose route requires review stands in for the review the task owes: readiness asks for
    the closing review even under a policy that leaves review optional (the check asked for
    ``semantic_required``), and the actionable missing review no longer hides
    ``closing_review_required``, the Stop gate's review token (a routine check would defer again).
    """

    deferred = _deferred(_prefix_through_check())
    facts = closure_readiness_facts(replay(deferred), deferred)
    assert facts.semantic_review_used is True
    assert facts.semantic_review_deferred is True
    assert facts.closing_review_current is False

    optional = derive_closure_readiness((), _DEFERRAL_GAPS, facts, semantic_review_required=False)
    assert optional.agent_actionable == ("closing_review_required",)

    required = derive_closure_readiness((), _DEFERRAL_GAPS, facts, semantic_review_required=True)
    assert required.agent_actionable == ("semantic_review_not_requested", "closing_review_required")


def test_a_deferral_where_review_is_optional_asks_for_nothing() -> None:
    """Review of #1046: a check that recorded ``semantic_route_required: false`` deferred a review
    nobody requires; like a ``deterministic_only`` check there it is disclosed and asks for no
    closing review, so an optional reviewer that cannot answer never keeps one demanded (the
    end-to-end shape is ``tests/integration/closure/test_review_deferral_shape.py``)."""

    payload = cast(CheckRecordedPayload, cast(AcceptedEvent, _prefix_through_check()[-1]).payload)
    assert _review_deferred(_deferred_payload(payload)) is True
    assert _review_deferred(_deferred_payload(payload, route_required=False)) is False
    # Facts that say no review was used or deferred ask for nothing on a route that does not
    # require review.
    facts = _facts(closing_review_current=False)
    split = derive_closure_readiness((), _DEFERRAL_GAPS, facts, semantic_review_required=False)
    assert split.agent_actionable == ()
    assert split.state == "ready_with_limitations"
    assert set(_DEFERRAL_GAPS) <= set(split.standing_limitations)


def test_only_a_deferral_lifts_the_missing_review_s_hold_on_the_closing_review() -> None:
    """Controls: a local-only check still lets the missing review stand alone (issue #976)."""

    prefix = _prefix_through_check()
    plain = _with_check_payload(
        prefix,
        mode=CheckMode.DETERMINISTIC_ONLY,
        semantic_status=SemanticStatus.NOT_REQUESTED,
        semantic_reason=SemanticReason.DETERMINISTIC_MODE,
    )
    facts = closure_readiness_facts(replay(plain), plain)
    assert (facts.semantic_review_used, facts.semantic_review_deferred) == (False, False)
    split = derive_closure_readiness(
        (), ("semantic_review_not_requested",), facts, semantic_review_required=True
    )
    assert split.agent_actionable == ("semantic_review_not_requested",)
    assert (
        "closing_review_required"
        not in derive_closure_readiness(
            (), (), facts, semantic_review_required=False
        ).agent_actionable
    )
    # A hand-built fact set that does not say keeps the pre-#1046 answer.
    assert _facts().semantic_review_deferred is False


# --- n7 RC1 (#1105): a closing review that ended without a judgment -------------------------


def _closing_review_then(
    status: SemanticStatus,
    reason: SemanticReason,
    *,
    phase: str = "final",
    material_between: bool = True,
) -> tuple[ProjectionState, tuple[LedgerRecord, ...], LedgerRecord]:
    """A succeeded final review, an optional material command, then a review with no judgment."""

    prefix = _prefix_through_check()
    closing = _reviewed(prefix, "final")
    check = cast(AcceptedEvent, closing[-1])
    sequence = check.ledger.ingestion_sequence
    source = next(
        record
        for record in prefix
        if record.schema.name == "action_recorded" and type(record.payload) is ActionRecordedPayload
    )
    # An observed command with no workspace-effect fact: material, so the first review is stale.
    command = _retarget_action(
        source,
        replace(cast(ActionRecordedPayload, source.payload), action_kind=ActionKind.COMMAND),
        sequence + 1,
    )
    payload = cast(CheckRecordedPayload, check.payload)
    unjudged = _append_check(
        check,
        replace(
            payload,
            semantic_status=status,
            semantic_reason=reason,
            # A retry budget spent, or a credential missing, before dispatch records no provider
            # provenance.
            semantic_provenance=None
            if reason
            in {SemanticReason.RETRY_BUDGET_EXHAUSTED, SemanticReason.CREDENTIAL_UNAVAILABLE}
            else replace(_provenance(), status=status, reason=reason),
            review_input_manifest=_review_input_manifest_from_json(
                cast(DomainJsonValue, _manifest(phase))
            ),
        ),
        sequence + 2,
    )
    middle: tuple[LedgerRecord, ...] = (command,) if material_between else ()
    return replay(closing), (*closing, *middle, unjudged), source


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (SemanticStatus.UNAVAILABLE, SemanticReason.OUTCOME_UNKNOWN),
        (SemanticStatus.UNAVAILABLE, SemanticReason.RETRY_BUDGET_EXHAUSTED),
        (SemanticStatus.UNAVAILABLE, SemanticReason.TRANSPORT_UNAVAILABLE),
        (SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT),
        # Refused before dispatch, and a quota whose continuation says to wait: still no
        # judgment, and the Stop text defers to that check's own continuation.
        (SemanticStatus.UNAVAILABLE, SemanticReason.CREDENTIAL_UNAVAILABLE),
        (SemanticStatus.UNAVAILABLE, SemanticReason.PROVIDER_QUOTA_EXHAUSTED),
    ],
)
def test_a_closing_review_without_a_judgment_is_not_asked_again(
    status: SemanticStatus, reason: SemanticReason
) -> None:
    """The newest final review ran on this state and returned no judgment.

    Before n7 the walk skipped it and fell back to the older, staled review, so the Stop gate
    asked for "the closing review" again while the check's own continuation allowed one new
    check and then a disclosed local-only finish.
    """

    state, records, _source = _closing_review_then(status, reason)
    facts = closure_readiness_facts(state, records)
    assert facts.closing_review_current is True
    assert facts.closing_review_no_judgment is True
    assert facts.coordinator_failure_unchanged is False
    split = derive_closure_readiness((), (), facts, semantic_review_required=True)
    assert "closing_review_required" not in split.agent_actionable
    assert "semantic_review_no_judgment" in split.standing_limitations
    assert "semantic_coordinator_failure" not in split.standing_limitations


def test_a_closing_review_without_a_judgment_then_a_material_change_asks_again() -> None:
    state, records, source = _closing_review_then(
        SemanticStatus.UNAVAILABLE, SemanticReason.OUTCOME_UNKNOWN
    )
    sequence = cast(AcceptedEvent, records[-1]).ledger.ingestion_sequence + 1
    edit = _retarget_action(
        source,
        replace(cast(ActionRecordedPayload, source.payload), action_kind=ActionKind.EDIT),
        sequence,
    )
    after = closure_readiness_facts(state, (*records, edit))
    assert after.closing_review_current is False
    assert after.closing_review_no_judgment is False
    asked = derive_closure_readiness((), (), after, semantic_review_required=True)
    assert "closing_review_required" in asked.agent_actionable
    assert "semantic_review_no_judgment" not in asked.standing_limitations


def test_a_newer_refused_closing_review_decides_over_an_older_one_without_a_judgment() -> None:
    """Only the newest current closing-review attempt can stop the request (goal-r1-3)."""

    state, records, _source = _closing_review_then(
        SemanticStatus.UNAVAILABLE, SemanticReason.OUTCOME_UNKNOWN
    )
    unjudged = cast(AcceptedEvent, records[-1])
    refused = _append_check(
        unjudged,
        replace(
            cast(CheckRecordedPayload, unjudged.payload),
            semantic_status=SemanticStatus.REFUSED,
            semantic_reason=SemanticReason.PROVIDER_REFUSED,
            semantic_provenance=replace(
                _provenance(),
                status=SemanticStatus.REFUSED,
                reason=SemanticReason.PROVIDER_REFUSED,
            ),
        ),
        unjudged.ledger.ingestion_sequence + 1,
        appended_id="evt_00000000-0000-4000-8000-00000000f0c2",
    )
    facts = closure_readiness_facts(state, (*records, refused))
    assert facts.closing_review_no_judgment is False
    assert facts.closing_review_current is False
    split = derive_closure_readiness((), (), facts, semantic_review_required=True)
    assert "closing_review_required" in split.agent_actionable
    assert "semantic_review_no_judgment" not in split.standing_limitations


@pytest.mark.parametrize("with_manifest", [False, True])
@pytest.mark.parametrize("required", [True, False])
def test_a_local_only_check_after_a_closing_review_without_a_judgment_keeps_the_flag(
    with_manifest: bool, required: bool
) -> None:
    """Review round 3: following the continuation's "go local-only" asks for no closing review."""

    state, records, _source = _closing_review_then(
        SemanticStatus.UNAVAILABLE, SemanticReason.OUTCOME_UNKNOWN
    )
    unjudged = cast(AcceptedEvent, records[-1])
    local = _append_check(
        unjudged,
        replace(
            cast(CheckRecordedPayload, unjudged.payload),
            mode=CheckMode.DETERMINISTIC_ONLY,
            semantic_status=SemanticStatus.NOT_REQUESTED,
            semantic_reason=SemanticReason.DETERMINISTIC_MODE,
            semantic_provenance=None,
            review_input_manifest=_review_input_manifest_from_json(
                cast(DomainJsonValue, _manifest("final"))
            )
            if with_manifest
            else None,
        ),
        unjudged.ledger.ingestion_sequence + 1,
        appended_id="evt_00000000-0000-4000-8000-00000000f0c3",
    )
    facts = closure_readiness_facts(state, (*records, local))
    assert facts.closing_review_current is True
    assert facts.closing_review_no_judgment is True
    split = derive_closure_readiness((), (), facts, semantic_review_required=required)
    assert "closing_review_required" not in split.agent_actionable
    assert "semantic_review_no_judgment" in split.standing_limitations


def test_a_closing_review_without_a_judgment_an_older_current_review_still_wins() -> None:
    state, records, _source = _closing_review_then(
        SemanticStatus.UNAVAILABLE, SemanticReason.OUTCOME_UNKNOWN, material_between=False
    )
    facts = closure_readiness_facts(state, records)
    assert facts.closing_review_current is True
    assert facts.closing_review_no_judgment is False
    split = derive_closure_readiness((), (), facts, semantic_review_required=True)
    assert "semantic_review_no_judgment" not in split.standing_limitations


def test_a_mid_task_check_without_a_judgment_changes_nothing() -> None:
    state, records, _source = _closing_review_then(
        SemanticStatus.UNAVAILABLE, SemanticReason.OUTCOME_UNKNOWN, phase="routine"
    )
    facts = closure_readiness_facts(state, records)
    assert facts.closing_review_current is False
    assert facts.closing_review_no_judgment is False
    split = derive_closure_readiness((), (), facts, semantic_review_required=True)
    assert "closing_review_required" in split.agent_actionable
    assert "semantic_review_no_judgment" not in split.standing_limitations


def _capacity_refused_closing_review(
    *, material_after: bool
) -> tuple[ProjectionState, tuple[LedgerRecord, ...]]:
    """A closing review refused as ``failed`` / ``case_capacity_exceeded`` (0fb47f325)."""

    state, records, source = _closing_review_then(
        SemanticStatus.UNAVAILABLE, SemanticReason.OUTCOME_UNKNOWN
    )
    unjudged = cast(AcceptedEvent, records[-1])
    refused = replace(
        cast(CheckRecordedPayload, unjudged.payload),
        semantic_status=SemanticStatus.FAILED,
        semantic_reason=SemanticReason.CASE_CAPACITY_EXCEEDED,
        semantic_provenance=None,
    )
    records = (*records[:-1], _append_check(unjudged, refused, unjudged.ledger.ingestion_sequence))
    if material_after:
        sequence = records[-1].ledger.ingestion_sequence + 1
        edit = _retarget_action(
            source,
            replace(cast(ActionRecordedPayload, source.payload), action_kind=ActionKind.EDIT),
            sequence,
        )
        records = (*records, edit)
    return state, records


def test_a_capacity_refused_closing_review_on_an_unchanged_case_is_not_asked_again() -> None:
    """#1118: a size refusal is retryable, but the same case is refused again.

    0fb47f325 made it ``failed`` (retryable) instead of an undeliverable ``blocked_by_policy``, so
    the Stop gate kept asking for the closing review and every unchanged recheck was refused
    again. With nothing material after it, it ends disclosed as ``semantic_review_no_judgment``.
    """

    state, records = _capacity_refused_closing_review(material_after=False)
    facts = closure_readiness_facts(state, records)
    assert facts.closing_review_current is True
    assert facts.closing_review_no_judgment is True
    split = derive_closure_readiness((), (), facts, semantic_review_required=True)
    assert "closing_review_required" not in split.agent_actionable
    assert "semantic_review_no_judgment" in split.standing_limitations


def test_a_capacity_refused_closing_review_is_asked_again_after_a_material_change() -> None:
    state, records = _capacity_refused_closing_review(material_after=True)
    facts = closure_readiness_facts(state, records)
    assert facts.closing_review_current is False
    asked = derive_closure_readiness((), (), facts, semantic_review_required=True)
    assert "closing_review_required" in asked.agent_actionable


def _answered_state(kind: object, disposition: object) -> ProjectionState:
    """One current finding of ``kind`` with the agent's reasoned ``disposition`` and nothing else."""

    from builders.policy_cases import evd, finding_record, fnd, obl, record
    from finishup.domain.events import ResponseRecordedPayload
    from finishup.domain.findings import (
        FINDING_KIND_TRAITS,
        Finding,
        FindingKind,
        FindingOrigin,
        ResponseDisposition,
        finding_policy_identity,
    )
    from finishup.domain.values import Frontier
    from finishup.kernel.projections import empty_projection_state
    from finishup.protocol.coverage import (
        ArtifactObservation,
        AuthorshipAssurance,
        Coverage,
        EvidenceImmutability,
        LedgerFreshness,
        PublicationChannel,
    )

    assert type(kind) is FindingKind and type(disposition) is ResponseDisposition
    policy_id, policy_version = finding_policy_identity(kind)
    finding = Finding(
        finding_id=fnd(1),
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="A recorded note.",
        detail="Answer it.",
        subject_refs=(obl(1),),
        policy_id=policy_id,
        policy_version=policy_version,
        subject_frontier=Frontier(3, _DIGEST),
        coverage=Coverage(
            publication_channels=(PublicationChannel.ENGINE_DERIVED,),
            authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
            artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
            evidence_immutability=EvidenceImmutability.METADATA_ONLY,
            ledger_freshness=LedgerFreshness.CURRENT,
            check_types=(CheckType.DETERMINISTIC,),
            known_gaps=(),
        ),
    )
    response = ResponseRecordedPayload(
        fnd(1),
        Frontier(3, _DIGEST),
        disposition,
        "A recorded reason.",
        evidence_refs=(evd(1),) if disposition is ResponseDisposition.SELF_VERIFIED else (),
    )
    return replace(
        empty_projection_state(),
        frontier=8,
        head_digest=_DIGEST,
        findings={fnd(1): finding_record(finding, 4)},
        responses={fnd(1): record(response, 6)},
        freshness=LedgerFreshness.CURRENT,
    )


@pytest.mark.parametrize("kind", ("ledger_stale_or_incomplete", "decision_needed"))
@pytest.mark.parametrize("disposition", ("self_verified", "acknowledged_not_done"))
def test_an_answered_process_note_is_no_readiness_limitation(kind: str, disposition: str) -> None:
    """D8 (#1243): ``closure_prepare`` printed clean and, in the same body, ``finding_self_verified``.

    A process note the classifier leaves out is never listed as settled, so readiness reads
    ``ready`` exactly where the prediction reads clean.
    """

    from finishup.domain.findings import FindingKind, ResponseDisposition
    from finishup.kernel.closure_readiness import FINDING_SELF_VERIFIED_GAP, closure_readiness_facts

    state = _answered_state(FindingKind(kind), ResponseDisposition(disposition))
    # The state holds no check record; read it as covered so only the answered note is judged.
    facts = replace(closure_readiness_facts(state, ()), check_applicability="applicable")
    assert facts.self_verified_finding_ids == ()
    assert facts.acknowledged_finding_ids == ()
    split = derive_closure_readiness((), (), facts, semantic_review_required=False)
    assert FINDING_SELF_VERIFIED_GAP not in split.standing_limitations
    assert (split.state, split.acknowledged_not_done) == ("ready", ())


def test_a_self_verified_agent_work_finding_stays_a_readiness_limitation() -> None:
    from builders.policy_cases import fnd
    from finishup.domain.findings import FindingKind, ResponseDisposition
    from finishup.kernel.closure_readiness import FINDING_SELF_VERIFIED_GAP, closure_readiness_facts

    state = _answered_state(
        FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS, ResponseDisposition.SELF_VERIFIED
    )
    facts = replace(closure_readiness_facts(state, ()), check_applicability="applicable")
    assert facts.self_verified_finding_ids == (fnd(1),)
    split = derive_closure_readiness((), (), facts, semantic_review_required=False)
    assert FINDING_SELF_VERIFIED_GAP in split.standing_limitations
    assert split.state == "ready_with_limitations"
