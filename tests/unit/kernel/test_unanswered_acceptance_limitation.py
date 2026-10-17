"""An unanswered once-delivered invitation remains an explicit verification limit (F2)."""

# pyright: reportPrivateUsage=false
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

from builders.observed_runs import INSTALLATION_KEY
from finishup.cli.closure_gate import closure_gate_from_readiness
from finishup.cli.render import render_closure_readiness_lines, render_human_check
from finishup.domain.events import DecisionRecordedPayload, EventSchema, PlanPublishedPayload
from finishup.domain.receipts import (
    UNRESOLVED_VERIFICATION_LIMITATION,
    receipt_document_to_json,
    render_receipt_human,
)
from finishup.domain.values import Frontier, actor_id
from finishup.kernel.claim_verification import (
    UNRESOLVED_VERIFICATION_GAP,
    claim_verification_report,
    unresolved_verification_obligations,
)
from finishup.kernel.closure_readiness import closure_readiness_facts, derive_closure_readiness
from finishup.kernel.closure_verdict import rechecks_from_closures
from finishup.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    CaseGap,
    build_deterministic_case,
)
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import register_command_identity_key
from finishup.mcp.summaries import summary_for_check, summary_for_receipt, summary_for_status
from finishup.protocol.models import CheckSuccessModel, StatusClosureReadinessModel
from finishup.protocol.readiness_text import admissible_verification_sentence
from unit.kernel.test_receipt_builder import _build, _context, _coverage
from unit.kernel.test_tb4n5_acceptance_risk import _CLEAN, _SELF, _ledger


def test_second_identical_stop_is_allowed_with_the_verification_limit_preserved() -> None:
    register_command_identity_key(INSTALLATION_KEY)
    try:
        ledger = _ledger()
        state = replay(ledger.prefix)
        facts = closure_readiness_facts(state, ledger.prefix)
        assert facts.obligation_closures is not None
        rechecks = rechecks_from_closures(facts.obligation_closures, facts, acknowledged_count=0)
        readiness = SimpleNamespace(
            state="ready_with_limitations",
            agent_actionable=(),
            open_obligation_count="0",
            receipt_blocking_finding_count="0",
            acknowledged_obligation_count="0",
            closing_material_frontier="3",
            rechecks=rechecks,
            admissible_verification=tuple(
                SimpleNamespace(obligation_id=str(ref), refs=refs)
                for ref, refs in facts.admissible_verification or ()
            ),
        )
        kwargs: dict[str, Any] = dict(
            frontier_sequence="100",
            frontier_digest="sha256:" + "a" * 64,
            observation_pending=False,
            final_message="All criteria are met.",
        )
        first = closure_gate_from_readiness(readiness, **kwargs)
        assert first is not None and "acceptance_recheck" in first.items
        assert (
            closure_gate_from_readiness(
                readiness, reasked_blockers=frozenset(first.blocker_keys), **kwargs
            )
            is None
        )
        _lines, limitation = claim_verification_report(state, ledger.prefix)
        assert f"Unresolved verification limitation for {_SELF}" in limitation
        assert "unanswered acceptance invitation does not establish coverage" in limitation
        # It is ledger-derived: delivery memory never converts it to an accepted answer.
        case = build_deterministic_case(state, ledger.prefix, CaseAvailabilityFacts())
        assert any(
            gap.code == UNRESOLVED_VERIFICATION_GAP and str(_SELF) in gap.subject_refs
            for gap in case.gaps
        )
        split = derive_closure_readiness((), (), facts, semantic_review_required=False)
        assert UNRESOLVED_VERIFICATION_GAP in split.standing_limitations
        sentence = admissible_verification_sentence(readiness)
        assert f"Unresolved verification limitation for {_SELF}" in sentence

        context = replace(
            _context(
                coverage=replace(_coverage(), known_gaps=("check_not_recorded",)),
                gaps=(CaseGap("check_not_recorded", "check_not_recorded", ()),),
            ),
            projection=state,
            records=ledger.prefix,
            subject_frontier=Frontier(state.frontier, state.head_digest),
        )
        receipt = _build(context)
        assert receipt.conclusion.value != "no_unresolved_deterministic_findings"
        document = receipt_document_to_json(receipt)
        assert limitation in str(document)
        assert limitation in render_receipt_human(receipt, markdown=True)
        assert limitation in render_receipt_human(receipt, markdown=False)
        wire = {
            "conclusion": receipt.conclusion.value,
            "frontier": {"sequence": "100", "head_digest": "sha256:" + "a" * 64},
            "coverage": {"known_gaps": [UNRESOLVED_VERIFICATION_GAP]},
            "document": document,
        }
        summary = summary_for_receipt(wire)
        assert "Unresolved verification limitation" in summary
        assert str(_SELF) in summary
        readiness_wire: dict[str, Any] = {
            "state": readiness.state,
            "agent_actionable": [],
            "standing_limitations": [UNRESOLVED_VERIFICATION_GAP],
            "acknowledged_not_done_count": "0",
            "rechecks": [
                {"kind": row.kind, "rule": row.rule, "key": row.key, "subjects": list(row.subjects)}
                for row in rechecks
            ],
            "admissible_verification": [
                {"obligation_id": str(ref), "refs": list(refs)}
                for ref, refs in facts.admissible_verification or ()
            ],
        }
        for render in (summary_for_status,):
            text = render({"closure_readiness": readiness_wire})
            assert "Unresolved verification limitation" in text
        check_summary = summary_for_check(
            {
                "verdict": "insufficient_coverage",
                "coverage": {"known_gaps": [UNRESOLVED_VERIFICATION_GAP]},
            }
        )
        assert UNRESOLVED_VERIFICATION_LIMITATION in check_summary
        check = CheckSuccessModel.model_construct(
            verdict="insufficient_coverage",
            semantic_status="not_requested",
            semantic_reason="deterministic_mode",
            semantic_route_required=False,
            findings=(),
            review_mode=None,
            totals=None,
            observations_awaited=None,
            review_input_manifest=None,
            semantic_provenance=None,
            suppressed_count=0,
            coverage=SimpleNamespace(known_gaps=(UNRESOLVED_VERIFICATION_GAP,)),
        )
        assert UNRESOLVED_VERIFICATION_LIMITATION in render_human_check(check)
        cli_readiness = StatusClosureReadinessModel.model_construct(
            **readiness_wire, acknowledged_not_done=()
        )
        assert f"Unresolved verification limitation for {_SELF}" in " ".join(
            render_closure_readiness_lines(cli_readiness)
        )
    finally:
        register_command_identity_key(None)


def test_recorded_limit_clears_the_unanswered_limitation_without_a_new_stop_block() -> None:
    register_command_identity_key(INSTALLATION_KEY)
    try:
        ledger = _ledger()
        ledger.append(
            EventSchema("decision_recorded", "1.0.0"),
            DecisionRecordedPayload(
                statement=f"finishup-verification-limit:{_SELF}",
                rationale="Unavailable private verifier.",
                authority=actor_id("agt_codex"),
            ),
            observed=False,
        )
        state = replay(ledger.prefix)
        assert _SELF not in unresolved_verification_obligations(state, ledger.prefix)
        _lines, limitation = claim_verification_report(state, ledger.prefix)
        assert "Unresolved verification limitation" not in limitation
        facts = closure_readiness_facts(state, ledger.prefix)
        split = derive_closure_readiness((), (), facts, semantic_review_required=False)
        assert UNRESOLVED_VERIFICATION_GAP not in split.standing_limitations
        assert facts.obligation_closures is not None
        rechecks = rechecks_from_closures(facts.obligation_closures, facts, acknowledged_count=0)
        assert all(str(_SELF) not in row.subjects for row in rechecks if row.kind == "acceptance")
    finally:
        register_command_identity_key(None)


def test_non_risky_work_has_no_unanswered_limitation_or_acceptance_invitation() -> None:
    register_command_identity_key(INSTALLATION_KEY)
    try:
        ledger = _ledger()
        ledger.append(
            EventSchema("plan_published", "1.0.0"),
            PlanPublishedPayload(2, "Plan", (_CLEAN,)),
            observed=False,
        )
        state = replay(ledger.prefix)
        assert unresolved_verification_obligations(state, ledger.prefix) == ()
        assert claim_verification_report(state, ledger.prefix) == ((), "")
        facts = closure_readiness_facts(state, ledger.prefix)
        split = derive_closure_readiness((), (), facts, semantic_review_required=False)
        assert UNRESOLVED_VERIFICATION_GAP not in split.standing_limitations
        assert facts.obligation_closures is not None
        rechecks = rechecks_from_closures(facts.obligation_closures, facts, acknowledged_count=0)
        assert all(row.kind != "acceptance" for row in rechecks)
    finally:
        register_command_identity_key(None)
