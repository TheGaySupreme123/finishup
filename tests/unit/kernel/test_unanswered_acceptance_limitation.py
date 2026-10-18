"""Acceptance-provenance risk is a receipt coverage limit, never a Stop item (ADR-033 D1, F2).

A flagged resolved obligation with neither an admissible observed link nor a recorded
verification limit bounds the receipt (``unresolved_verification_limitation``). Status, the check
and the receipt read one set (ADR-046), and every rendering carries the limit: the receipt JSON,
markdown and text, the MCP receipt, check and status summaries, the CLI status lines and the
terminal interface's receipt view. The Stop gate never asks about it.
"""

# pyright: reportPrivateUsage=false
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

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
from finishup.kernel.acceptance_risk import EVIDENCE_SELF_ASSERTED_ONLY
from finishup.kernel.claim_verification import (
    UNRESOLVED_VERIFICATION_GAP,
    claim_verification_report,
    unresolved_acceptance_risk,
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
from finishup.protocol.readiness_text import acceptance_risk_note
from finishup.tui.models import ReceiptSummary
from finishup.tui.render import render_receipt
from unit.kernel import test_tb4n5_verification_link_bound as bound
from unit.kernel.test_receipt_builder import _build, _context, _coverage
from unit.kernel.test_tb4n5_acceptance_risk import _CLEAN, _SELF, _ledger

_SENTENCE = (
    f"Acceptance provenance not established for {_SELF}: no admissible observed verification"
    " link or recorded verification limit; the receipt records this as a coverage limit."
)


def _flat(lines: tuple[str, ...] | list[str]) -> str:
    return " ".join(" ".join(lines).split())


def _readiness_wire(standing: tuple[str, ...], risk: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "declared_obligation_count": "4",
        "no_obligations_reason": None,
        "open_obligation_count": "0",
        "unanswered_finding_count": "0",
        "receipt_blocking_finding_count": "0",
        "blocking_conditions": [],
        "state": "ready_with_limitations",
        "gap_classification_version": "8",
        "agent_actionable": [],
        "standing_limitations": list(standing),
        "acknowledged_not_done": [],
        "acknowledged_not_done_count": "0",
        "acceptance_risk": [
            {"obligation_id": str(obligation), "reasons": list(reasons)}
            for obligation, reasons in risk
        ],
    }


def test_status_check_and_receipt_share_one_unresolved_set() -> None:
    """R5 regression: nine flagged obligations, each with its own observed run. Status used to
    read the eight-capped admissible list and report a limit the receipt and the check lacked."""

    register_command_identity_key(INSTALLATION_KEY)
    try:
        ledger, _runs = bound._ledger()
        state = replay(ledger.prefix)
        facts = closure_readiness_facts(state, ledger.prefix)
        assert len(facts.acceptance_risk_obligation_ids or ()) == 9
        assert facts.unresolved_acceptance_risk == ()
        assert unresolved_verification_obligations(state, ledger.prefix) == ()
        split = derive_closure_readiness((), (), facts, semantic_review_required=False)
        assert UNRESOLVED_VERIFICATION_GAP not in split.standing_limitations
        case = build_deterministic_case(state, ledger.prefix, CaseAvailabilityFacts())
        assert all(gap.code != UNRESOLVED_VERIFICATION_GAP for gap in case.gaps)

        ledger = _ledger()
        state = replay(ledger.prefix)
        facts = closure_readiness_facts(state, ledger.prefix)
        expected = ((_SELF, (EVIDENCE_SELF_ASSERTED_ONLY,)),)
        assert facts.unresolved_acceptance_risk == expected
        assert unresolved_acceptance_risk(state, ledger.prefix) == expected
        assert unresolved_verification_obligations(state, ledger.prefix) == (_SELF,)
        split = derive_closure_readiness((), (), facts, semantic_review_required=False)
        assert UNRESOLVED_VERIFICATION_GAP in split.standing_limitations
        case = build_deterministic_case(state, ledger.prefix, CaseAvailabilityFacts())
        assert [
            gap.subject_refs for gap in case.gaps if gap.code == UNRESOLVED_VERIFICATION_GAP
        ] == [(_SELF,)]
    finally:
        register_command_identity_key(None)


def test_coverage_limit_in_every_receipt_rendering() -> None:
    register_command_identity_key(INSTALLATION_KEY)
    try:
        ledger = _ledger()
        state = replay(ledger.prefix)
        case = build_deterministic_case(state, ledger.prefix, CaseAvailabilityFacts())
        gaps = tuple(gap for gap in case.gaps if gap.code == UNRESOLVED_VERIFICATION_GAP)
        assert gaps
        _lines, limitation = claim_verification_report(state, ledger.prefix)
        assert limitation == _SENTENCE
        assert "invitation" not in limitation

        # No check recorded in this unit ledger: the receipt also carries check_not_recorded.
        context = replace(
            _context(
                coverage=replace(
                    _coverage(), known_gaps=("check_not_recorded", UNRESOLVED_VERIFICATION_GAP)
                ),
                gaps=(CaseGap("check_not_recorded", "check_not_recorded", ()), *gaps),
            ),
            projection=state,
            records=ledger.prefix,
            subject_frontier=Frontier(state.frontier, state.head_digest),
        )
        receipt = _build(context)
        assert receipt.conclusion.value == "insufficient_coverage"
        document = cast(dict[str, Any], receipt_document_to_json(receipt))
        assert {"code": UNRESOLVED_VERIFICATION_GAP, "subject_refs": [str(_SELF)]} in document[
            "gaps"
        ]
        assert UNRESOLVED_VERIFICATION_GAP in document["coverage"]["known_gaps"]
        assert _SENTENCE in str(document)
        markdown = render_receipt_human(receipt, markdown=True)
        text = render_receipt_human(receipt, markdown=False)
        assert _SENTENCE in _flat(markdown.splitlines())
        assert _SENTENCE in _flat(text.splitlines())

        wire = {
            "conclusion": receipt.conclusion.value,
            "frontier": {"sequence": "100", "head_digest": "sha256:" + "a" * 64},
            "coverage": {"known_gaps": [UNRESOLVED_VERIFICATION_GAP]},
            "document": document,
        }
        summary = summary_for_receipt(wire)
        assert _SENTENCE in summary
        assert "invitation" not in summary

        # The terminal interface's receipt view renders the same document lines.
        tui = ReceiptSummary(
            subject_id="tsk_00000000-0000-4000-8000-000000000001",
            verdict=receipt.conclusion.value,
            coverage=(UNRESOLVED_VERIFICATION_GAP,),
            limitations=(UNRESOLVED_VERIFICATION_GAP,),
            rendered_lines=tuple(markdown.splitlines()),
        )
        assert _SENTENCE in _flat(render_receipt(tui, 100))
        without_document = replace(tui, rendered_lines=())
        assert UNRESOLVED_VERIFICATION_GAP in _flat(render_receipt(without_document, 100))

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
    finally:
        register_command_identity_key(None)


def test_status_names_it_once_and_the_stop_gate_never_asks() -> None:
    register_command_identity_key(INSTALLATION_KEY)
    try:
        ledger = _ledger()
        state = replay(ledger.prefix)
        facts = closure_readiness_facts(state, ledger.prefix)
        assert facts.obligation_closures is not None
        rechecks = rechecks_from_closures(facts.obligation_closures, facts, acknowledged_count=0)
        assert all(row.kind != "acceptance" for row in rechecks)
        risk = facts.unresolved_acceptance_risk or ()
        readiness_wire = _readiness_wire((UNRESOLVED_VERIFICATION_GAP,), risk)
        typed = StatusClosureReadinessModel.model_validate(readiness_wire)
        note = acceptance_risk_note(typed)
        assert note.startswith("Acceptance provenance (a receipt coverage limit, not a Stop item):")
        assert f"{_SELF} ({EVIDENCE_SELF_ASSERTED_ONLY})" in note
        status_text = summary_for_status({"closure_readiness": readiness_wire})
        cli_text = "\n".join(render_closure_readiness_lines(typed))
        for text in (status_text, cli_text):
            assert text.count("Acceptance provenance") == 1
            assert str(_SELF) in text
            assert "finishup-acceptance" not in text
        # A first and a repeated Stop, active or not, are never continued for it.
        for active in (False, True):
            gate = closure_gate_from_readiness(
                SimpleNamespace(
                    **{**readiness_wire, "rechecks": rechecks},
                ),
                frontier_sequence="100",
                frontier_digest="sha256:" + "a" * 64,
                observation_pending=False,
                active_stop=active,
            )
            assert gate is None
    finally:
        register_command_identity_key(None)


def test_recorded_limit_clears_the_coverage_limit() -> None:
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
        assert "Acceptance provenance not established" not in limitation
        facts = closure_readiness_facts(state, ledger.prefix)
        assert facts.unresolved_acceptance_risk == ()
        split = derive_closure_readiness((), (), facts, semantic_review_required=False)
        assert UNRESOLVED_VERIFICATION_GAP not in split.standing_limitations
    finally:
        register_command_identity_key(None)


def test_non_risky_work_has_no_coverage_limit() -> None:
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
        assert facts.unresolved_acceptance_risk == ()
        split = derive_closure_readiness((), (), facts, semantic_review_required=False)
        assert UNRESOLVED_VERIFICATION_GAP not in split.standing_limitations
    finally:
        register_command_identity_key(None)
