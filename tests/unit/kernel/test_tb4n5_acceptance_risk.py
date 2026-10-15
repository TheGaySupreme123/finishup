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
from types import SimpleNamespace

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.cli.closure_gate import closure_gate_from_readiness
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
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
)
from finishup.kernel.closure_readiness import closure_readiness_facts
from finishup.kernel.closure_verdict import (
    ACCEPTANCE_RISK_RULE,
    rechecks_from_closures,
)
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import register_command_identity_key
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.readiness_text import recheck_note

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
    assert "the resolved obligations FinishUP flags" in note
    assert "`finishup-acceptance:<obligation id>:met:<evd_ or res_ id>`" in note
    assert "saying every criterion is met does not" in note
    # An older service's re-read keeps its sentence.
    legacy = recheck_note(
        {"rechecks": [{"kind": "acceptance", "rule": "resolved_obligations_acceptance_reread"}]}
    )
    assert legacy is not None
    assert "the acceptance criteria of your resolved obligations" in legacy


def test_the_status_note_names_the_line_only_where_the_host_can_deliver_it() -> None:
    """#1050 follow-up: Cursor's Stop receives no final message, so its note never names the
    `finishup-acceptance` line; a host-unknown surface names which hosts read it; Codex and Claude
    Code (and the MCP summaries, which never serve Cursor) keep the line unchanged."""

    rechecks = {
        "rechecks": [
            {
                "kind": "acceptance",
                "key": "accept:00000000",
                "rule": "resolved_obligations_acceptance_risk",
            }
        ]
    }
    default = recheck_note(rechecks)
    assert default is not None
    for host in ("codex", "claude"):
        assert recheck_note(rechecks, host=host) == default
    cursor = recheck_note(rechecks, host="cursor")
    assert cursor is not None
    assert "finishup-acceptance" not in cursor
    assert "Cursor passes FinishUP no final answer" in cursor
    assert "the resolved obligations FinishUP flags" in cursor
    generic = recheck_note(rechecks, host="generic")
    assert generic is not None
    assert (
        "on Codex and Claude Code a line `finishup-acceptance:<obligation id>:met:<evd_ or res_ id>`"
        in generic
    )
    assert "saying every criterion is met does not" in generic
    assert "finishup-acceptance" not in cursor
    assert "Cursor passes no final answer" in generic
    # An older service's unflagged re-read names no line on any host.
    legacy = {
        "rechecks": [{"kind": "acceptance", "rule": "resolved_obligations_acceptance_reread"}]
    }
    assert recheck_note(legacy, host="cursor") == recheck_note(legacy)


def test_claim_verification_lines_name_each_flag_and_a_recorded_limit() -> None:
    """The receipt pairing is the ledger's, not a generic all-met claim (#1079)."""

    ledger = _ledger()
    state = replay(ledger.prefix)
    assert claim_verification_lines(state, ()) == ()
    lines = claim_verification_lines(state, ledger.prefix)
    assert lines[0] == CLAIM_VERIFICATION_HEADER
    body = "\n".join(lines)
    assert str(_CLEAN) not in body
    facts = closure_readiness_facts(state, ledger.prefix)
    assert facts.admissible_verification is not None
    linked = dict(facts.admissible_verification)
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
    assert facts.obligation_closures is not None
    subjects = {
        item
        for row in rechecks_from_closures(facts.obligation_closures, facts, acknowledged_count=0)
        if row.kind == "acceptance"
        for item in row.subjects
    }
    assert str(_SELF) not in subjects
    assert str(_NEVER) in subjects
    limited = claim_verification_lines(state, ledger.prefix)
    assert f"{_SELF} {EVIDENCE_SELF_ASSERTED_ONLY} verification_limit" in limited


_NOTE = "evd_00000000-0000-4000-8000-00000000d004"
_ASSERTED = "res_00000000-0000-4000-8000-00000000d003"
_MISSING = "evd_00000000-0000-4000-8000-00000000ffff"
_GATE_DIGEST = "sha256:" + "d" * 64


def test_a_cited_id_must_be_an_observed_verification_for_that_obligation() -> None:
    """The flagged line needs an observed verification linked to that obligation (#1079).

    The self-asserted ``evd_`` and ``res_`` stay unattested even though the obligation cites
    them. The observed runs cited by the other flagged obligations stay admissible. A missing
    id is not. The legacy ``yoetz-`` spelling uses the same list. Cursor, which has no final
    message, is answered by those observed links and still asks the self-asserted obligation.
    A published verification-limit decision leaves that obligation's recheck.
    """

    ledger = _ledger()
    state = replay(ledger.prefix)
    facts = closure_readiness_facts(state, ledger.prefix)
    assert facts.admissible_verification is not None
    linked = dict(facts.admissible_verification)
    assert _SELF not in linked
    assert _NOTE not in {ref for refs in linked.values() for ref in refs}
    assert _ASSERTED not in {ref for refs in linked.values() for ref in refs}
    assert linked[_OFF]
    assert linked[_NEVER]
    assert set(linked[_OFF]).isdisjoint(linked[_NEVER])
    assert _CLEAN not in linked
    assert all(_MISSING not in refs for refs in linked.values())
    foreign = next(iter(linked[_OFF]))
    assert facts.obligation_closures is not None
    readiness = SimpleNamespace(
        state="ready_with_limitations",
        agent_actionable=(),
        open_obligation_count="0",
        receipt_blocking_finding_count="0",
        rechecks=rechecks_from_closures(facts.obligation_closures, facts, acknowledged_count=0),
        admissible_verification=tuple(
            SimpleNamespace(obligation_id=str(obligation), refs=refs)
            for obligation, refs in facts.admissible_verification
        ),
    )
    message = (
        f"yoetz-acceptance:{_SELF}:met:{_NOTE}\n"
        f"finishup-acceptance:{_NEVER}:met:{_ASSERTED}\n"
        f"finishup-acceptance:{_OFF}:met:{foreign}\n"
        f"finishup-acceptance:{_NEVER}:met:{_MISSING}"
    )
    gate = closure_gate_from_readiness(
        readiness,
        frontier_sequence="7",
        frontier_digest=_GATE_DIGEST,
        observation_pending=False,
        final_message=message,
    )
    assert gate is not None
    assert f"obligation(s) {_SELF}, {_NEVER}:" in gate.text or (
        str(_SELF) in gate.text and str(_NEVER) in gate.text
    )
    assert str(_OFF) not in gate.text
    assert f"`{_NOTE}` is not linked to obligation `{_SELF}`." in gate.text
    assert f"`{_ASSERTED}` is not linked to obligation `{_NEVER}`." in gate.text
    assert f"`{_MISSING}` is not linked to obligation `{_NEVER}`." in gate.text
    covered = closure_gate_from_readiness(
        readiness,
        frontier_sequence="7",
        frontier_digest=_GATE_DIGEST,
        observation_pending=False,
        final_message=(
            f"finishup-verification-limit:{_SELF}\n"
            f"finishup-acceptance:{_NEVER}:met:{next(iter(linked[_NEVER]))}\n"
            f"yoetz-acceptance:{_OFF}:met:{foreign}"
        ),
    )
    assert covered is None
    cursor = closure_gate_from_readiness(
        readiness,
        frontier_sequence="7",
        frontier_digest=_GATE_DIGEST,
        observation_pending=False,
        final_message=None,
        host="cursor",
    )
    assert cursor is not None
    assert str(_SELF) in cursor.text
    assert str(_OFF) not in cursor.text
    assert str(_NEVER) not in cursor.text
