"""Which resolved obligations the ledger flags, and what that flag does (tb4n5 #1050, ADR-033 D1).

Owner decision 2026-10-13: flag only resolved obligations whose recorded resolution the ledger
itself flags - a requested item never attempted, evidence not linked to a declared item, or only
self-asserted evidence. Owner decision D1 (2026-10-18): a flag is never a Stop item. A flagged
obligation with neither an admissible observed link nor a recorded verification limit is the
receipt's coverage limit, and status reads that same set. These build one ledger with a clean
obligation and one per flag, and check the flags, the coverage-limit set, and that no surface
announces an acceptance re-read.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayloadV1_1,
    DecisionRecordedPayload,
    EventSchema,
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceImmutability,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.domain.values import (
    EvidenceId,
    ObligationId,
    ResultId,
    action_id,
    actor_id,
    claim_id,
    evidence_id,
    obligation_id,
    result_id,
)
from finishup.kernel.acceptance_risk import (
    EVIDENCE_NOT_LINKED,
    EVIDENCE_SELF_ASSERTED_ONLY,
    ITEM_NEVER_ATTEMPTED,
    acceptance_risk,
)
from finishup.kernel.claim_verification import (
    CLAIM_VERIFICATION_HEADER,
    claim_verification_lines,
    unresolved_acceptance_risk,
    unresolved_verification_obligations,
)
from finishup.kernel.closure_readiness import closure_readiness_facts
from finishup.kernel.closure_verdict import rechecks_from_closures
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import register_command_identity_key
from finishup.kernel.verification_link import admissible_verification_refs
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.readiness_text import acceptance_risk_note, recheck_note

_CLEAN: ObligationId = obligation_id("obl_00000000-0000-4000-8000-00000000c001")
_SELF: ObligationId = obligation_id("obl_00000000-0000-4000-8000-00000000c002")
_NEVER: ObligationId = obligation_id("obl_00000000-0000-4000-8000-00000000c003")
_OFF: ObligationId = obligation_id("obl_00000000-0000-4000-8000-00000000c004")
_OBLIGATION = EventSchema("obligation_published", "1.0.0")
_OBLIGATION_V1_1 = EventSchema("obligation_published", "1.1.0")
_ACTION = EventSchema("action_recorded", "1.0.0")
_RESULT = EventSchema("result_recorded", "1.0.0")
_EVIDENCE = EventSchema("evidence_recorded", "1.1.0")


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _obligation(
    identifier: ObligationId,
    items: tuple[RequestedItem, ...],
    status: ObligationStatus = ObligationStatus.OPEN,
    resolution: tuple[ResultId | EvidenceId, ...] = (),
) -> ObligationPublishedPayload:
    return ObligationPublishedPayload(
        obligation_id=identifier,
        description="Deliver the requested outcome",
        evidence_expectation="A recorded run",
        status=status,
        requested_items=items,
        resolution_evidence_refs=resolution,
    )


def _output(value: str) -> RequestedItem:
    return RequestedItem(RequestedItemKind.FILE, value, RequestedItemRole.OUTPUT)


_CLEAN_ITEMS = (RequestedItem(RequestedItemKind.COMMAND, "pytest -q"), _output("out/report.txt"))
_NEVER_ITEMS = (_output("out/missing.txt"),)
_OFF_ITEMS = (_output("out/summary.md"),)


def _ledger() -> ObservedLedger:
    """A clean resolution and one resolution per flag, all in one plan."""

    ledger = ObservedLedger()
    for identifier, items in (
        (_CLEAN, _CLEAN_ITEMS),
        (_SELF, ()),
        (_NEVER, _NEVER_ITEMS),
        (_OFF, _OFF_ITEMS),
    ):
        ledger.append(_OBLIGATION_V1_1, _obligation(identifier, items), observed=False)
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_CLEAN, _SELF, _NEVER, _OFF)),
        observed=False,
    )
    # The agent writes the report and the summary; nothing ever writes out/missing.txt.
    ledger.append(
        _ACTION,
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-00000000d001"),
            ActionKind.EDIT,
            "Wrote the report",
            obligation_refs=(_CLEAN,),
            attempted_items=("out/report.txt",),
        ),
        observed=False,
    )
    ledger.append(
        _ACTION,
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-00000000d002"),
            ActionKind.EDIT,
            "Wrote the summary",
            obligation_refs=(_OFF,),
            attempted_items=("out/summary.md",),
        ),
        observed=False,
    )
    tests = ledger.passes("pytest -q")  # the observed run of the requested command
    bench = ledger.passes("python bench.py --direct")  # an observed run naming nothing declared
    # The self-asserted resolution: the agent's own action and result, nothing observed.
    ledger.append(
        _ACTION,
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-00000000d003"),
            ActionKind.OTHER,
            "Checked the behaviour by hand",
            obligation_refs=(_SELF,),
        ),
        observed=False,
    )
    asserted = result_id("res_00000000-0000-4000-8000-00000000d003")
    ledger.append(
        _RESULT,
        ResultRecordedPayload(
            asserted,
            action_id("act_00000000-0000-4000-8000-00000000d003"),
            ResultOutcome.SUCCESS,
            summary="Looked right",
        ),
        observed=False,
    )
    note = evidence_id("evd_00000000-0000-4000-8000-00000000d004")
    ledger.append(
        _EVIDENCE,
        EvidenceRecordedPayload(
            evidence_id=note,
            evidence_kind=EvidenceKind.TEST_RESULT,
            strength=EvidenceImmutability.CONTENT_DIGEST,
            observed_at=ledger.records[-1].occurred_at,
            content_digest=canonical_digest({"note": "self"}),
            digest_binding=EvidenceDigestBinding(
                subject=EvidenceDigestSubject.TEST_STDOUT,
                content_availability=EvidenceContentAvailability.DIGEST_ONLY,
                byte_count=10,
                provenance=EvidenceDigestProvenance.CALLER_ASSERTED,
            ),
        ),
        observed=False,
    )
    for identifier, items, resolution in (
        (_CLEAN, _CLEAN_ITEMS, (tests,)),
        (_SELF, (), (note, asserted)),
        (_NEVER, _NEVER_ITEMS, (tests,)),
        (_OFF, _OFF_ITEMS, (bench,)),
    ):
        ledger.append(
            _OBLIGATION_V1_1,
            _obligation(identifier, items, ObligationStatus.RESOLVED, resolution),
            observed=False,
        )
    return ledger


def test_each_flag_is_named_and_the_clean_resolution_is_not() -> None:
    ledger = _ledger()
    state = replay(ledger.prefix)
    flagged = dict(acceptance_risk(state, ledger.prefix, (_CLEAN, _SELF, _NEVER, _OFF)))
    assert _CLEAN not in flagged
    assert flagged[_SELF] == (EVIDENCE_SELF_ASSERTED_ONLY,)
    assert flagged[_NEVER] == (ITEM_NEVER_ATTEMPTED, EVIDENCE_NOT_LINKED)
    assert flagged[_OFF] == (EVIDENCE_NOT_LINKED,)


def test_the_flags_reach_status_as_the_receipt_coverage_set_and_never_as_a_recheck() -> None:
    """D1: the flagged set is still computed, but it bounds the receipt instead of asking a Stop.
    Only the self-asserted resolution lacks an admissible observed link, so it alone is the
    coverage limit; the two flagged resolutions that cite an observed run are not."""

    ledger = _ledger()
    state = replay(ledger.prefix)
    facts = closure_readiness_facts(state, ledger.prefix)
    assert facts.acceptance_risk_obligation_ids == tuple(
        sorted((_SELF, _NEVER, _OFF), key=str.encode)
    )
    assert facts.unresolved_acceptance_risk == ((_SELF, (EVIDENCE_SELF_ASSERTED_ONLY,)),)
    assert unresolved_acceptance_risk(state, ledger.prefix) == facts.unresolved_acceptance_risk
    assert unresolved_verification_obligations(state, ledger.prefix) == (_SELF,)
    # The status cap of eight is gone with the attestation: the field is not computed.
    assert facts.admissible_verification is None
    assert facts.obligation_closures is not None
    kinds = {
        item.kind
        for item in rechecks_from_closures(facts.obligation_closures, facts, acknowledged_count=0)
    }
    assert "acceptance" not in kinds


def test_verdict_emits_no_acceptance_recheck() -> None:
    """For computed facts and for a hand-built fact set that predates the flag rule."""

    from dataclasses import replace

    ledger = _ledger()
    state = replay(ledger.prefix)
    facts = closure_readiness_facts(state, ledger.prefix)
    assert facts.obligation_closures is not None
    for variant in (
        facts,
        replace(facts, acceptance_risk_obligation_ids=None, unresolved_acceptance_risk=None),
        None,
    ):
        rows = rechecks_from_closures(facts.obligation_closures, variant, acknowledged_count=0)
        assert all(item.kind != "acceptance" for item in rows)


def test_only_clean_resolutions_have_no_coverage_limit() -> None:
    ledger = _ledger()
    # Keep only the clean obligation in the plan: nothing the ledger flags is resolved.
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(2, "Plan", (_CLEAN,)),
        observed=False,
    )
    state = replay(ledger.prefix)
    facts = closure_readiness_facts(state, ledger.prefix)
    assert facts.acceptance_risk_obligation_ids == ()
    assert facts.unresolved_acceptance_risk == ()
    assert acceptance_risk_note({"acceptance_risk": ()}) == ""


@pytest.mark.parametrize("host", [None, "codex", "claude", "cursor", "generic"])
def test_no_status_note_announces_an_acceptance_reread(host: str | None) -> None:
    """An ``acceptance`` entry (from an earlier service) is never announced, on any host: the
    gate does not ask it. The provenance sentence is host-independent."""

    flagged = {
        "kind": "acceptance",
        "key": "accept:00000000",
        "rule": "resolved_obligations_acceptance_risk",
    }
    assert recheck_note({"rechecks": [flagged]}, host=host) is None
    ack = {"kind": "acknowledgement", "key": f"ack:{_SELF}", "rule": "x"}
    note = recheck_note({"rechecks": [flagged, ack]}, host=host)
    assert note == (
        "At Stop you will be asked once to re-read: obligations you recorded as not done."
        " closure_readiness.rechecks lists each with its key."
    )


def test_claim_verification_lines_name_each_flag_and_a_recorded_limit() -> None:
    """The receipt pairing is the ledger's, not a generic all-met claim (#1079)."""

    ledger = _ledger()
    state = replay(ledger.prefix)
    assert claim_verification_lines(state, ()) == ()
    lines = claim_verification_lines(state, ledger.prefix)
    assert lines[0] == CLAIM_VERIFICATION_HEADER
    body = "\n".join(lines)
    assert str(_CLEAN) not in body
    linked = dict(
        admissible_verification_refs(state, ledger.prefix, (_SELF, _NEVER, _OFF), limit=None)
    )
    assert _SELF not in linked
    assert f"{_SELF} {EVIDENCE_SELF_ASSERTED_ONLY} no_verification_limit" in lines
    assert (
        f"{_NEVER} {ITEM_NEVER_ATTEMPTED},{EVIDENCE_NOT_LINKED} linked {','.join(linked[_NEVER])}"
        in lines
    )
    assert f"{_OFF} {EVIDENCE_NOT_LINKED} linked {','.join(linked[_OFF])}" in lines
    assert all(ref.startswith("res_") for ref in (*linked[_NEVER], *linked[_OFF]))
    ledger.append(
        EventSchema("decision_recorded", "1.0.0"),
        DecisionRecordedPayload(
            statement=f"finishup-verification-limit:{_SELF}",
            rationale="The private verifier is not in this workspace.",
            authority=actor_id("agt_codex"),
        ),
        observed=False,
    )
    state = replay(ledger.prefix)
    facts = closure_readiness_facts(state, ledger.prefix)
    # The recorded limit lifts the coverage limit; the flag itself stays on the ledger.
    assert facts.unresolved_acceptance_risk == ()
    assert _SELF in (facts.acceptance_risk_obligation_ids or ())
    limited = claim_verification_lines(state, ledger.prefix)
    assert f"{_SELF} {EVIDENCE_SELF_ASSERTED_ONLY} verification_limit" in limited


_NOTE = "evd_00000000-0000-4000-8000-00000000d004"
_ASSERTED = "res_00000000-0000-4000-8000-00000000d003"
_MISSING = "evd_00000000-0000-4000-8000-00000000ffff"


def test_a_cited_id_must_be_an_observed_verification_for_that_obligation() -> None:
    """Only an observed verification linked to that obligation lifts the coverage limit (#1079).

    The self-asserted ``evd_`` and ``res_`` do not, even though the obligation cites them. The
    observed runs cited by the other flagged obligations stay admissible. A published
    verification-limit decision lifts it for that obligation.
    """

    ledger = _ledger()
    state = replay(ledger.prefix)
    linked = dict(
        admissible_verification_refs(state, ledger.prefix, (_SELF, _NEVER, _OFF), limit=None)
    )
    assert _SELF not in linked
    assert _NOTE not in {ref for refs in linked.values() for ref in refs}
    assert _ASSERTED not in {ref for refs in linked.values() for ref in refs}
    assert linked[_OFF]
    assert linked[_NEVER]
    assert set(linked[_OFF]).isdisjoint(linked[_NEVER])
    assert all(_MISSING not in refs for refs in linked.values())
    facts = closure_readiness_facts(state, ledger.prefix)
    assert tuple(obligation for obligation, _ in facts.unresolved_acceptance_risk or ()) == (_SELF,)
    ledger.append(
        EventSchema("decision_recorded", "1.0.0"),
        DecisionRecordedPayload(
            statement=f"finishup-verification-limit:{_SELF}",
            rationale="The private verifier is not in this workspace.",
            authority=actor_id("agt_codex"),
        ),
        observed=False,
    )
    state = replay(ledger.prefix)
    assert closure_readiness_facts(state, ledger.prefix).unresolved_acceptance_risk == ()


def test_an_empty_scope_claim_does_not_lend_its_ids() -> None:
    """A completion claim that names no obligation lends no supporting id (#1079).

    The reviewer's probe appended "all met" with ``obligation_refs=()`` and supporting refs
    ``(_NOTE, foreign observed result)``. Neither becomes admissible for any obligation. The
    foreign observed result is admissible for ``_NEVER`` only after a later claim lists that
    obligation.
    """

    ledger = _ledger()
    foreign = ledger.passes("printf observed-foreign")
    note = evidence_id(_NOTE)
    ledger.append(
        EventSchema("claim_recorded", "1.1.0"),
        ClaimRecordedPayloadV1_1(
            claim_id=claim_id("clm_00000000-0000-4000-8000-0000000000a1"),
            claim_kind=ClaimKind.COMPLETION,
            statement="all met",
            supporting_refs=(note, foreign),
            obligation_refs=(),
        ),
        observed=False,
    )
    state = replay(ledger.prefix)
    linked = dict(admissible_verification_refs(state, ledger.prefix, (_CLEAN, _SELF, _NEVER, _OFF)))
    assert all(_NOTE not in refs for refs in linked.values())
    assert all(str(foreign) not in refs for refs in linked.values())
    facts = closure_readiness_facts(state, ledger.prefix)
    # The empty-scope claim lends nothing: the coverage limit still names the self-asserted one.
    assert tuple(obligation for obligation, _ in facts.unresolved_acceptance_risk or ()) == (_SELF,)
    ledger.append(
        EventSchema("claim_recorded", "1.1.0"),
        ClaimRecordedPayloadV1_1(
            claim_id=claim_id("clm_00000000-0000-4000-8000-0000000000a2"),
            claim_kind=ClaimKind.COMPLETION,
            statement="The never-attempted item is met by the observed run.",
            supporting_refs=(foreign,),
            obligation_refs=(_NEVER,),
        ),
        observed=False,
    )
    named = replay(ledger.prefix)
    admitted = dict(
        admissible_verification_refs(named, ledger.prefix, (_CLEAN, _SELF, _NEVER, _OFF))
    )
    assert str(foreign) in admitted[_NEVER]
    assert all(
        str(foreign) not in refs for obligation, refs in admitted.items() if obligation != _NEVER
    )
    assert all(_NOTE not in refs for refs in admitted.values())


def test_decision_line_counts_unattempted_items_by_the_work_integrity_rule() -> None:
    """#1139 (PR #1216 review): the ledger line uses ``requested_item_never_attempted``'s test.

    ``_CLEAN``'s command is credited by the hook-observed ``pytest -q`` run alone (no attempted
    item names it), and a ``./``-prefixed attempted path is the same requested file. Only
    ``_NEVER``'s output stays unattempted, so the line and the acceptance flag agree.
    """

    from finishup.kernel.acceptance_risk import unattempted_requested_items
    from finishup.kernel.evidence_basis import decision_status_line

    ledger = _ledger()
    ledger.append(
        _ACTION,
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-00000000d009"),
            ActionKind.EDIT,
            "Wrote the summary again",
            obligation_refs=(_OFF,),
            attempted_items=("./out/summary.md",),
        ),
        observed=False,
    )
    state = replay(ledger.prefix)
    obligations = (_CLEAN, _SELF, _NEVER, _OFF)
    assert unattempted_requested_items(state, ledger.prefix, obligations) == ((_NEVER, 1),)
    flagged = dict(acceptance_risk(state, ledger.prefix, obligations))
    assert ITEM_NEVER_ATTEMPTED in flagged[_NEVER]
    assert all(ITEM_NEVER_ATTEMPTED not in flagged.get(key, ()) for key in (_CLEAN, _OFF))
    line = decision_status_line(state, ledger.prefix, reviewer=False)
    assert f"1 requested item unattempted ({_NEVER})" in line


def test_a_same_path_attempt_is_not_unattempted() -> None:
    """``solve.sage`` requested, ``./solve.sage`` attempted: the same file (ADR-045)."""

    from finishup.kernel.acceptance_risk import unattempted_requested_items

    ledger = ObservedLedger()
    ledger.append(_OBLIGATION_V1_1, _obligation(_NEVER, (_output("solve.sage"),)), observed=False)
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_NEVER,)),
        observed=False,
    )
    state = replay(ledger.prefix)
    assert unattempted_requested_items(state, ledger.prefix, (_NEVER,)) == ((_NEVER, 1),)
    ledger.append(
        _ACTION,
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-00000000d010"),
            ActionKind.EDIT,
            "Wrote the solver",
            obligation_refs=(_NEVER,),
            attempted_items=("./solve.sage",),
        ),
        observed=False,
    )
    state = replay(ledger.prefix)
    assert unattempted_requested_items(state, ledger.prefix, (_NEVER,)) == ()
