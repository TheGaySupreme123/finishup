"""The acceptance re-read names only the obligations the ledger flags (tb4n5, #1050, ADR-033).

Owner decision 2026-10-13: re-read only resolved obligations whose recorded resolution the ledger
itself flags - a requested item never attempted, evidence not linked to a declared item, or only
self-asserted evidence - and drop the word-coverage rule. These build one ledger with a clean
obligation and one per flag, and check that the clean one no longer triggers the re-read while
each flagged one still does, that the re-read's key names exactly the flagged set, and that a
ledger with only clean resolutions announces no acceptance re-read at all.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
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
from yoetz.domain.values import (
    EvidenceId,
    ObligationId,
    ResultId,
    action_id,
    evidence_id,
    obligation_id,
    result_id,
)
from yoetz.kernel.acceptance_risk import (
    EVIDENCE_NOT_LINKED,
    EVIDENCE_SELF_ASSERTED_ONLY,
    ITEM_NEVER_ATTEMPTED,
    acceptance_risk,
)
from yoetz.kernel.closure_readiness import closure_readiness_facts
from yoetz.kernel.closure_verdict import (
    ACCEPTANCE_RISK_RULE,
    rechecks_from_closures,
)
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import register_command_identity_key
from yoetz.protocol.canonical import canonical_digest
from yoetz.protocol.readiness_text import recheck_note

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


def test_the_announced_reread_names_exactly_the_flagged_set() -> None:
    ledger = _ledger()
    state = replay(ledger.prefix)
    facts = closure_readiness_facts(state, ledger.prefix)
    assert facts.acceptance_risk_obligation_ids == tuple(
        sorted((_SELF, _NEVER, _OFF), key=str.encode)
    )
    assert facts.obligation_closures is not None
    (acceptance,) = (
        item
        for item in rechecks_from_closures(facts.obligation_closures, facts, acknowledged_count=0)
        if item.kind == "acceptance"
    )
    assert acceptance.rule == ACCEPTANCE_RISK_RULE
    assert acceptance.subjects == tuple(
        str(item) for item in sorted((_SELF, _NEVER, _OFF), key=str.encode)
    )
    assert str(_CLEAN) not in acceptance.subjects


def test_only_clean_resolutions_announce_no_acceptance_reread() -> None:
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
    assert facts.obligation_closures is not None
    kinds = {
        item.kind
        for item in rechecks_from_closures(facts.obligation_closures, facts, acknowledged_count=0)
    }
    assert "acceptance" not in kinds


def test_a_hand_built_fact_set_without_the_list_keeps_every_resolved_obligation() -> None:
    ledger = _ledger()
    state = replay(ledger.prefix)
    facts = closure_readiness_facts(state, ledger.prefix)
    from dataclasses import replace

    legacy = replace(facts, acceptance_risk_obligation_ids=None)
    assert legacy.obligation_closures is not None
    (acceptance,) = (
        item
        for item in rechecks_from_closures(legacy.obligation_closures, legacy, acknowledged_count=0)
        if item.kind == "acceptance"
    )
    assert acceptance.rule == "resolved_obligations_acceptance_reread"
    assert str(_CLEAN) in acceptance.subjects


def test_the_status_note_names_the_flagged_reread_and_the_line_that_answers_it() -> None:
    ledger = _ledger()
    state = replay(ledger.prefix)
    facts = closure_readiness_facts(state, ledger.prefix)
    assert facts.obligation_closures is not None
    rechecks = [
        {"kind": item.kind, "key": item.key, "rule": item.rule}
        for item in rechecks_from_closures(facts.obligation_closures, facts, acknowledged_count=0)
    ]
    note = recheck_note({"rechecks": rechecks})
    assert note is not None
    assert "the resolved obligations Yoetz flags" in note
    assert "`yoetz-acceptance:<obligation id>:met`" in note
    # An older service's re-read keeps its sentence.
    legacy = recheck_note(
        {"rechecks": [{"kind": "acceptance", "rule": "resolved_obligations_acceptance_reread"}]}
    )
    assert legacy is not None
    assert "the acceptance criteria of your resolved obligations" in legacy
