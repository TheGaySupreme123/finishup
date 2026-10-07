"""Closure readiness as a checklist: the kernel split and its per-request facts (issue #913)."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from builders.replay import replay_records
from yoetz.domain.events import (
    AcceptedEvent,
    CheckMode,
    CheckRecordedPayload,
    LedgerRecord,
    _review_input_manifest_from_json,  # pyright: ignore[reportPrivateUsage]
    encode_payload,
)
from yoetz.domain.findings import SemanticDispatchKind, SemanticProvenance
from yoetz.domain.values import JsonValue as DomainJsonValue
from yoetz.domain.values import finding_id, obligation_id
from yoetz.kernel.closure_readiness import (
    ClosureReadinessFacts,
    closure_readiness_facts,
    derive_closure_readiness,
    live_lineage_blockers,
)
from yoetz.kernel.projections import observation_limitation_finding_ids
from yoetz.kernel.receipt_capacity import receipt_blocking_finding_count
from yoetz.kernel.reducers import invalidates_recorded_check, replay
from yoetz.ports.semantic import SamplingParams
from yoetz.protocol.canonical import canonical_digest
from yoetz.protocol.coverage import CheckType
from yoetz.protocol.models import SemanticReason, SemanticStatus

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
    prefix = _prefix_through_check()
    closing = _reviewed(prefix, "final")
    check = cast(AcceptedEvent, closing[-1])
    payload = cast(CheckRecordedPayload, check.payload)
    records = tuple(replay_records("all-event-families"))
    later = records[len(prefix) :]
    limitations = observation_limitation_finding_ids(replay(prefix), (*closing, *later))
    material = next(
        position
        for position, record in enumerate(later)
        if invalidates_recorded_check(
            record,
            check.ledger.ingestion_sequence,
            payload.returned_finding_ids,
            limitation_finding_ids=limitations,
        )
    )
    stale = (*closing, *later[: material + 1])
    assert closure_readiness_facts(replay(prefix), stale).closing_review_current is False


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
