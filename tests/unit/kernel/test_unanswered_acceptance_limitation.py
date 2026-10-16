"""An unanswered once-delivered invitation remains an explicit verification limit (F2)."""

# pyright: reportPrivateUsage=false
from dataclasses import replace
from types import SimpleNamespace

from builders.observed_runs import INSTALLATION_KEY
from finishup.cli.closure_gate import closure_gate_from_readiness
from finishup.domain.receipts import receipt_document_to_json, render_receipt_human
from finishup.domain.values import Frontier
from finishup.kernel.claim_verification import (
    UNRESOLVED_VERIFICATION_GAP,
    claim_verification_report,
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
from finishup.mcp.summaries import summary_for_receipt, summary_for_status
from finishup.protocol.readiness_text import admissible_verification_sentence
from unit.kernel.test_receipt_builder import _build, _context, _coverage
from unit.kernel.test_tb4n5_acceptance_risk import _SELF, _ledger


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
        kwargs = dict(
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
        lines, limitation = claim_verification_report(state, ledger.prefix)
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
        assert f"Unresolved verification limitation for {_SELF}" in summary
        readiness_wire = {
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
            assert f"Unresolved verification limitation for {_SELF}" in text
    finally:
        register_command_identity_key(None)
