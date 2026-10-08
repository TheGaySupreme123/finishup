"""Replay two TB4 tb4f1 deterministic traces through the task facts and the Stop gate (#977).

The fixtures under ``tests/fixtures/tb4_replay/`` reduce each attempt's ``agent/codex.txt`` and its
exported obligations view to structure: the order of observed commands (runner class, exit
status, closed runtime facts), edits, accepted published actions, checks and the final stop.
Command text survives only where it equals an obligation's requested command. The tests rebuild
the ledger the way the coordinator materializes it, then ask what this build would have told the
agent at each check and at the final Stop.

* pretrain-shard-corruption (deterministic, reward 0): the agent stopped with three open
  obligations after asking an absent user for the original data; its planned verification
  ``bash /app/run_pretrain.sh`` only ever ran wrapped with a redirect into ``/tmp``.
* atrx-vep-crispr (deterministic, reward 0): ``/app/output/mutation.report.json`` was never
  written, yet a published action named the obligation's inputs and the agent stopped.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from yoetz.application.check import CheckScope, run_deterministic_policies
from yoetz.cli.closure_gate import BLOCKER_RECHECK_ITEM, closure_gate_from_readiness
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    ResultOutcome,
    ResultRecordedPayload,
)
from yoetz.domain.findings import FindingKind
from yoetz.domain.values import ObligationId, action_id, obligation_id, result_id
from yoetz.kernel.closure_readiness import closure_readiness_facts, derive_closure_readiness
from yoetz.kernel.deterministic_checks import (
    REQUESTED_OUTPUT_ABSENT_FACT,
    CaseAvailabilityFacts,
    build_deterministic_case,
)
from yoetz.kernel.policies.work_integrity import work_integrity_findings
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import (
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
    WRITE_OUTSIDE_WORKSPACE_GAP,
    RequestedOutputState,
    confirmed_blocked_obligation_ids,
    open_effective_obligations,
    register_command_identity_key,
    requested_output_facts,
    task_fact_signals,
)
from yoetz.protocol.policy_packs import current_policy_pack

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "tb4_replay"
_PACKS = (current_policy_pack("research-evidence"), current_policy_pack("work-integrity"))


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


@dataclass
class _Replay:
    ledger: ObservedLedger
    obligations: tuple[ObligationId, ...]
    check_findings: list[tuple[FindingKind, ...]]


def _outcome(exit_status: int | None) -> ResultOutcome:
    if exit_status is None:
        return ResultOutcome.UNKNOWN
    return ResultOutcome.SUCCESS if exit_status == 0 else ResultOutcome.FAILURE


def _requested(item: dict[str, str]) -> RequestedItem:
    return RequestedItem(RequestedItemKind(item["item_kind"]), item["value"])


def _kinds(ledger: ObservedLedger) -> tuple[FindingKind, ...]:
    records = ledger.prefix
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    assessments, _executions = run_deterministic_policies(case, CheckScope((), ()), _PACKS)
    return tuple(item.candidate.kind for item in assessments)


def _replay(name: str) -> tuple[_Replay, dict[str, Any]]:
    fixture: dict[str, Any] = json.loads((_FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    ledger = ObservedLedger()
    ids = tuple(obligation_id(item["obligation_id"]) for item in fixture["obligations"])
    checks: list[tuple[FindingKind, ...]] = []
    actions = 0
    for event in fixture["events"]:
        kind = event["kind"]
        if kind == "plan":
            for item in fixture["obligations"]:
                ledger.append(
                    EventSchema("obligation_published", "1.0.0"),
                    ObligationPublishedPayload(
                        obligation_id=obligation_id(item["obligation_id"]),
                        description="Replayed obligation",
                        evidence_expectation="Replayed",
                        status=ObligationStatus.OPEN,
                        requested_items=tuple(
                            _requested(value) for value in item["requested_items"]
                        ),
                    ),
                    observed=False,
                )
            ledger.append(
                EventSchema("plan_published", "1.0.0"),
                PlanPublishedPayload(1, "Replayed plan", tuple(sorted(ids))),
                observed=False,
            )
        elif kind == "command":
            ledger.run(
                event["planned_command"] or f"replayed-command-{event['event']}",
                _outcome(event["exit_status"]),
                exit_status=event["exit_status"],
                runner=event["runner"],
                write_outside_workspace=event["write_outside_workspace"],
                install_target=event["install_target"],
            )
        elif kind == "edit":
            ledger.edit(write_outside_workspace=event["outside_workspace"])
        elif kind == "published_action":
            actions += 1
            ledger.append(
                EventSchema("action_recorded", "1.0.0"),
                ActionRecordedPayload(
                    action_id(f"act_00000000-0000-4000-8000-{900000 + actions:012d}"),
                    ActionKind.OTHER,
                    "Replayed published action",
                    obligation_refs=tuple(
                        sorted(obligation_id(ref) for ref in event["obligation_refs"])
                    ),
                    attempted_items=tuple(sorted(set(event["attempted_items"]))),
                ),
                observed=False,
            )
            ledger.append(
                EventSchema("result_recorded", "1.0.0"),
                ResultRecordedPayload(
                    result_id(f"res_00000000-0000-4000-8000-{900000 + actions:012d}"),
                    action_id(f"act_00000000-0000-4000-8000-{900000 + actions:012d}"),
                    ResultOutcome.PARTIAL,
                ),
                observed=False,
            )
        elif kind == "check":
            checks.append(_kinds(ledger))
        elif kind == "receipt":
            # The exported end state: obligations the agent resolved are resolved here too.
            ledger.append(
                EventSchema("action_recorded", "1.0.0"),
                ActionRecordedPayload(
                    action_id("act_00000000-0000-4000-8000-000000999999"),
                    ActionKind.OTHER,
                    "Replayed resolution support",
                ),
                observed=False,
            )
            support = result_id("res_00000000-0000-4000-8000-000000999999")
            ledger.append(
                EventSchema("result_recorded", "1.0.0"),
                ResultRecordedPayload(
                    support,
                    action_id("act_00000000-0000-4000-8000-000000999999"),
                    ResultOutcome.SUCCESS,
                ),
                observed=False,
            )
            for item in fixture["obligations"]:
                if item["status"] != "resolved":
                    continue
                ledger.append(
                    EventSchema("obligation_published", "1.0.0"),
                    ObligationPublishedPayload(
                        obligation_id=obligation_id(item["obligation_id"]),
                        description="Replayed obligation",
                        evidence_expectation="Replayed",
                        status=ObligationStatus.RESOLVED,
                        requested_items=tuple(
                            _requested(value) for value in item["requested_items"]
                        ),
                        resolution_evidence_refs=(support,),
                    ),
                    observed=False,
                )
    return _Replay(ledger, ids, checks), fixture


def _stop_gate(
    replayed: _Replay,
    output_states: dict[tuple[ObligationId, int], RequestedOutputState],
    *,
    reasked: frozenset[str] = frozenset(),
) -> tuple[Any, Any]:
    records = replayed.ledger.prefix
    projection = replay(records)
    signals = task_fact_signals(projection, records)
    case = build_deterministic_case(projection, records, CaseAvailabilityFacts())
    absent, markers = requested_output_facts(
        projection,
        output_states,
        blocked=confirmed_blocked_obligation_ids((gap.code, gap.subject_refs) for gap in case.gaps),
    )
    findings = work_integrity_findings(case, absent_outputs=frozenset(absent))
    blocking_findings = [
        item
        for item in findings
        if item.candidate.kind is FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED
        and any(
            fact.fact_code == REQUESTED_OUTPUT_ABSENT_FACT for fact in item.basis.observed_facts
        )
    ]
    open_obligations = open_effective_obligations(projection)
    conditions: list[str] = []
    if open_obligations:
        conditions.append("obligations_open")
    if blocking_findings:
        conditions.append("receipt_findings_unresolved")
    facts = closure_readiness_facts(projection, records)
    readiness = derive_closure_readiness(
        conditions,
        (*signals.codes, *(code for code, _ in markers)),
        facts,
        semantic_review_required=False,
    )
    view = SimpleNamespace(
        state=readiness.state,
        agent_actionable=readiness.agent_actionable,
        open_obligation_count=str(len(open_obligations)),
        receipt_blocking_finding_count=str(len(blocking_findings)),
        blocked_obligations=tuple(
            SimpleNamespace(obligation_id=obligation, blocker_kind=kind, decision_event_id=event)
            for obligation, kind, event in facts.blocked_obligation_details
        ),
    )
    gate = closure_gate_from_readiness(
        view,
        frontier_sequence=str(projection.frontier),
        frontier_digest=projection.head_digest,
        observation_pending=False,
        reasked_blockers=reasked,
    )
    return gate, signals


def test_pretrain_shard_corruption_det_would_have_been_continued_at_stop() -> None:
    replayed, fixture = _replay("pretrain_shard_corruption_det")

    # Plan-stage noise is gone: the first check ran before any edit or published action.
    assert FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED not in replayed.check_findings[0]

    states = {
        (obligation_id(item["obligation_id"]), index): RequestedOutputState(
            "inside", exists=True, ignored=False, changed=True
        )
        for item in fixture["obligations"]
        for index, value in enumerate(item["requested_items"])
        if value["item_kind"] == "file"
    }
    gate, signals = _stop_gate(replayed, states)

    # Its planned verification only ever ran wrapped with a redirect, so the exact command was
    # never observed; the redirect itself wrote outside the workspace.
    assert PLANNED_VERIFICATION_NOT_OBSERVED_GAP in signals.codes
    assert WRITE_OUTSIDE_WORKSPACE_GAP in signals.codes
    assert gate is not None
    assert gate.items == ("obligations_open", PLANNED_VERIFICATION_NOT_OBSERVED_GAP)
    # The export recorded open_obligation_count 3 at session end.
    assert "Remaining: 3 open obligation(s)" in gate.text
    # Repair first; the blocker exit is offered only because obligations are open, and an
    # inherent verification limit or a best-effort choice is disclosed, never blocked (#984, #995).
    assert gate.text.index("Finish each open obligation") < gate.text.index("yoetz-blocker:")
    assert "yoetz-assumption:<obligation id>" in gate.text
    # #997 review: the acknowledgement is offered only after a blocker challenge, not here.
    assert "acknowledged_not_done" not in gate.text
    assert len(gate.text) <= 2_000


def test_atrx_vep_crispr_det_missing_report_blocks_the_receipt_and_continues_the_agent() -> None:
    replayed, fixture = _replay("atrx_vep_crispr_det")

    assert FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED not in replayed.check_findings[0]
    states: dict[tuple[ObligationId, int], RequestedOutputState] = {}
    for item in fixture["obligations"]:
        for index, value in enumerate(item["requested_items"]):
            if value["item_kind"] != "file":
                continue
            written = not value["value"].startswith("/app/output/")
            states[(obligation_id(item["obligation_id"]), index)] = RequestedOutputState(
                "inside", exists=written, ignored=False, changed=False if written else None
            )
    gate, _signals = _stop_gate(replayed, states)

    assert gate is not None
    assert gate.items == ("obligations_open", "receipt_findings_unresolved")
    # The export recorded open_obligation_count 5 at session end.
    assert "Remaining: 5 open obligation(s); 1 receipt-blocking finding(s)" in gate.text
    # #984: findings are repaired first, then self-verified when only a Yoetz limit remains.
    assert "repair what you can" in gate.text
    assert "respond `self_verified`" in gate.text
    assert gate.text.index("repair what you can") < gate.text.index("`acknowledged_not_done`")


def test_atrx_findings_without_open_obligations_offer_no_blocker() -> None:
    """With only a receipt-blocking finding left, the gate never offers a yoetz-blocker (#984)."""

    view = SimpleNamespace(
        state="action_required",
        agent_actionable=("receipt_findings_unresolved",),
        open_obligation_count="0",
        receipt_blocking_finding_count="1",
        blocked_obligations=(),
    )
    gate = closure_gate_from_readiness(
        view, frontier_sequence="40", frontier_digest="d", observation_pending=False
    )
    assert gate is not None
    assert gate.items == ("receipt_findings_unresolved",)
    assert "respond `self_verified`" in gate.text
    assert "yoetz-blocker:<" not in gate.text
    assert "publish decision_recorded" not in gate.text


_BLOCKER_BATCHES = [0]


def _declare_blocker(replayed: _Replay, rationale: str) -> tuple[ObligationId, ...]:
    """Publish the blocker decision in its own publish batch, as an agent's publish_work does."""

    from yoetz.domain.events import DecisionRecordedPayload
    from yoetz.domain.values import actor_id

    _BLOCKER_BATCHES[0] += 1
    projection = replay(replayed.ledger.prefix)
    open_obligations = tuple(sorted(open_effective_obligations(projection)))
    replayed.ledger.append(
        EventSchema("decision_recorded", "1.0.0"),
        DecisionRecordedPayload(
            statement="yoetz-blocker:dependency_unavailable",
            rationale=rationale,
            authority=actor_id("agt_codex"),
            affected_obligation_ids=open_obligations,
        ),
        observed=False,
        operation=f"req_98500000-0000-4000-8000-{_BLOCKER_BATCHES[0]:012d}",
    )
    return open_obligations


def test_tb4v1_pretrain_blocker_for_a_missing_snapshot_is_rechecked_once() -> None:
    """tb4v1: the agent declared ``dependency_unavailable`` for "no original snapshot found"
    although the task said the data was recoverable. Yoetz cannot judge that claim, so the next
    Stop re-asks it once, naming each obligation and the claimed kind."""

    replayed, _fixture = _replay("pretrain_shard_corruption_det")
    blocked = _declare_blocker(replayed, "No original snapshot found.")
    gate, _signals = _stop_gate(replayed, {})

    assert gate is not None
    # #985: a first blocker is only claimed, so it is still agent work beside the re-ask.
    assert gate.items[-1] == BLOCKER_RECHECK_ITEM
    assert "obligation_blocker_unconfirmed" in gate.items
    for obligation in blocked:
        assert f"{obligation} (dependency_unavailable)" in gate.text
    # Re-pinned against the current re-check text: repair first, recoverable data and a Yoetz
    # limit are not blockers, and how to confirm is said only in the challenge (#985, #984).
    assert "Continue that work unless it is genuinely outside your control" in gate.text
    assert "a Yoetz limit never is" in gate.text
    assert "same yoetz-blocker line again in a later" in gate.text


def test_a_genuine_blocker_lets_pretrain_stop_after_one_recheck() -> None:
    replayed, _fixture = _replay("pretrain_shard_corruption_det")
    _declare_blocker(replayed, "Replay: every open obligation declared blocked.")
    first, _signals = _stop_gate(replayed, {})
    assert first is not None
    # Stopping again without confirming leaves the claimed blocker as agent work (#985).
    unconfirmed, _signals = _stop_gate(replayed, {}, reasked=frozenset(first.blocker_keys))
    assert unconfirmed is not None
    assert "obligation_blocker_unconfirmed" in unconfirmed.items
    # The agent keeps its position after the challenge: the same line in a later decision
    # confirms it, and the blocker is then honoured, never a loop.
    _declare_blocker(replayed, "Replay: confirmed after the re-ask.")
    second, _signals = _stop_gate(replayed, {}, reasked=frozenset(first.blocker_keys))
    assert second is None


def _readiness(replayed: _Replay) -> Any:
    from dataclasses import replace

    records = replayed.ledger.prefix
    projection = replay(records)
    signals = task_fact_signals(projection, records)
    conditions = ("obligations_open",) if open_effective_obligations(projection) else ()
    # The real attempt had recorded checks; the replay keeps only their findings, so the check
    # condition is taken as applicable here to isolate the blocker semantics.
    facts = replace(closure_readiness_facts(projection, records), check_applicability="applicable")
    return derive_closure_readiness(
        conditions, signals.codes, facts, semantic_review_required=False
    )


def test_tb4n1_pretrain_det_blocker_is_claimed_until_confirmed() -> None:
    """tb4n1 pretrain-shard-corruption (deterministic, reward 0; #985 C4).

    Readiness was ``action_required [obligations_open, planned_verification_not_observed]`` at
    09:09 and, after one ``yoetz-blocker:dependency_unavailable`` ("authoritative historical
    source") on every open obligation, ``ready_with_limitations []`` by 09:27:30 although the main
    deliverable was not done. A first blocker is now only claimed: still agent work. Only the same
    line again in a later decision (after the publish-time challenge and the Stop re-ask) turns it
    into a disclosed limitation.
    """

    replayed, _fixture = _replay("pretrain_shard_corruption_det")
    before = _readiness(replayed)
    assert before.state == "action_required"
    assert before.agent_actionable == ("obligations_open", PLANNED_VERIFICATION_NOT_OBSERVED_GAP)

    _declare_blocker(replayed, "dependency_unavailable: authoritative historical source")
    claimed = _readiness(replayed)
    assert claimed.state == "action_required"
    assert "obligations_open" not in claimed.agent_actionable
    assert "obligation_blocker_unconfirmed" in claimed.agent_actionable
    # A claimed blocker suppresses nothing: the planned verification is still owed.
    assert PLANNED_VERIFICATION_NOT_OBSERVED_GAP in claimed.agent_actionable
    assert "obligation_blocked_outside_agent_control" not in claimed.standing_limitations

    _declare_blocker(replayed, "dependency_unavailable: authoritative historical source")
    confirmed = _readiness(replayed)
    assert confirmed.state == "ready_with_limitations"
    assert confirmed.agent_actionable == ()
    assert "obligation_blocked_outside_agent_control" in confirmed.standing_limitations


def test_a_blocker_naming_only_finished_obligations_has_no_effect() -> None:
    """tb4n1: 31 of 38 blocker attempts named only resolved obligations to excuse findings
    Yoetz could not clear (#985 C3). Such a blocker changes no readiness and no gap."""

    from yoetz.domain.events import DecisionRecordedPayload
    from yoetz.domain.values import actor_id
    from yoetz.domain.values import event_id as make_event_id
    from yoetz.kernel.task_facts import (
        BLOCKER_NOTICE_WITHOUT_EFFECT,
        OBLIGATION_BLOCKED_GAP,
        OBLIGATION_BLOCKER_UNCONFIRMED_GAP,
        blocker_publication_notices,
    )

    replayed, fixture = _replay("pretrain_shard_corruption_det")
    row = next(item for item in fixture["obligations"] if item["status"] == "resolved")
    resolved = obligation_id(row["obligation_id"])
    # The replay's receipt step already resolved it, as the agent had.
    assert resolved not in open_effective_obligations(replay(replayed.ledger.prefix))
    before = _readiness(replayed)
    payload = DecisionRecordedPayload(
        statement="Closure is blocked by Yoetz review limits.\nyoetz-blocker:authority",
        rationale="coverage:content_redacted prevents a qualifying closure",
        authority=actor_id("agt_codex"),
        affected_obligation_ids=(resolved,),
    )
    replayed.ledger.append(EventSchema("decision_recorded", "1.0.0"), payload, observed=False)
    records = replayed.ledger.prefix
    projection = replay(records)
    after = _readiness(replayed)
    assert after == before
    codes = set(task_fact_signals(projection, records).codes)
    assert not codes & {OBLIGATION_BLOCKED_GAP, OBLIGATION_BLOCKER_UNCONFIRMED_GAP}
    assert closure_readiness_facts(projection, records).blocked_obligation_ids == ()
    decision = make_event_id(str(replayed.ledger.records[-1].event_id))
    [notice] = blocker_publication_notices(projection, ((decision, payload),))
    assert (notice.obligation_id, notice.kind, notice.notice) == (
        resolved,
        "authority",
        BLOCKER_NOTICE_WITHOUT_EFFECT,
    )
