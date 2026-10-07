"""The declared delivered set and ``declared_output_removed`` (ADR-035, issue #1005)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from types import MappingProxyType, SimpleNamespace

import pytest

from builders.observed_runs import ObservedLedger
from yoetz.domain.events import (
    DecisionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
)
from yoetz.domain.values import ObligationId, actor_id, obligation_id
from yoetz.kernel import delivered_set
from yoetz.kernel.closure_readiness import GAP_CLASSIFICATION, GapClass
from yoetz.kernel.delivered_set import (
    DECLARED_OUTPUT_REMOVED_GAP,
    declared_delivered_items,
    declared_output_removed,
)
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import (
    AGENT_ACTIONABLE_TASK_FACT_GAPS,
    STOP_GATE_TOKENS,
    RequestedOutputState,
)

_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")


def _projection(*items: RequestedItem, blocker: bool = False) -> ProjectionState:
    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.0.0"),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description="Deliver the outputs",
            evidence_expectation="The files",
            status=ObligationStatus.OPEN,
            requested_items=items,
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )
    if blocker:
        ledger.append(
            EventSchema("decision_recorded", "1.0.0"),
            DecisionRecordedPayload(
                statement="Blocked.\nyoetz-blocker:consent",
                rationale="The operator holds the consent.",
                authority=actor_id("agt_codex"),
                affected_obligation_ids=(_OBLIGATION,),
            ),
            observed=False,
        )
    return replay(ledger.prefix)


def _file(value: str) -> RequestedItem:
    return RequestedItem(RequestedItemKind.FILE, value)


_GONE = RequestedOutputState("inside", exists=False, deleted=True)


def test_gap_is_agent_actionable_and_continues_the_stop_gate() -> None:
    assert DECLARED_OUTPUT_REMOVED_GAP == "declared_output_removed"
    assert DECLARED_OUTPUT_REMOVED_GAP in AGENT_ACTIONABLE_TASK_FACT_GAPS
    assert GAP_CLASSIFICATION[DECLARED_OUTPUT_REMOVED_GAP] is GapClass.AGENT_ACTIONABLE
    assert DECLARED_OUTPUT_REMOVED_GAP in STOP_GATE_TOKENS


def test_declared_set_is_file_items_only() -> None:
    projection = _projection(
        RequestedItem(RequestedItemKind.COMMAND, "pytest -q"),
        _file("/app/cracker.py"),
        RequestedItem(RequestedItemKind.URL, "https://example.invalid/spec"),
    )
    assert declared_delivered_items(projection) == ((_OBLIGATION, 1, "file", "/app/cracker.py"),)


def test_deleted_declared_file_is_removed() -> None:
    projection = _projection(_file("report.json"))
    assert declared_output_removed(projection, {(_OBLIGATION, 0): _GONE}) == (_OBLIGATION,)


def test_renamed_away_declared_file_is_removed() -> None:
    """music-harmony: ``R`` with the declared path as original reads as deleted and absent."""

    projection = _projection(_file("/app/harmony.musicxml"))
    # requested_output_states marks a rename's original path ``deleted``.
    renamed = RequestedOutputState("inside", exists=False, deleted=True, changed=False)
    assert declared_output_removed(projection, {(_OBLIGATION, 0): renamed}) == (_OBLIGATION,)


@pytest.mark.parametrize(
    "state",
    [
        RequestedOutputState("inside", exists=True, changed=True),  # still delivered
        RequestedOutputState("inside", exists=False),  # never in the base: requested_output_absent
        RequestedOutputState("inside", exists=None, deleted=True),  # read blocked
        RequestedOutputState("outside"),
        RequestedOutputState("unverified"),
    ],
)
def test_no_removal_without_a_read_proving_it(state: RequestedOutputState) -> None:
    projection = _projection(_file("report.json"))
    assert declared_output_removed(projection, {(_OBLIGATION, 0): state}) == ()


def test_undeclared_file_is_ignored() -> None:
    """A deleted file no requested item names is not part of the declared set."""

    projection = _projection(_file("report.json"))
    assert declared_output_removed(projection, {(_OBLIGATION, 1): _GONE}) == ()
    assert declared_output_removed(projection, {}) == ()


def test_blocked_obligation_is_skipped() -> None:
    projection = _projection(_file("report.json"), blocker=True)
    assert declared_delivered_items(projection) == ()
    assert declared_output_removed(projection, {(_OBLIGATION, 0): _GONE}) == ()


@dataclass(frozen=True)
class _RoledItem:
    """The obligation_published 1.1.0 item shape (PL6-1/PL6-2): kind, value and optional role."""

    item_kind: str
    value: str
    role: str | None = None


def test_input_role_is_ignored_and_directory_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    obligation: ObligationId = _OBLIGATION
    items = (
        _RoledItem("file", "/app/data/input.csv", "input"),
        _RoledItem("file", "/app/out.json", "output"),
        _RoledItem("directory", "/app/results/", "output"),
        _RoledItem("directory", "/app/fixtures/", "input"),
        _RoledItem("file", "/app/legacy.txt"),
    )
    projection = SimpleNamespace(
        obligations={obligation: SimpleNamespace(payload=SimpleNamespace(requested_items=items))}
    )

    def effective(_projection: object) -> tuple[ObligationId, ...]:
        return (obligation,)

    def blocked(_projection: object) -> MappingProxyType[ObligationId, str]:
        return MappingProxyType({})

    monkeypatch.setattr(delivered_set, "effective_obligations", effective)
    monkeypatch.setattr(delivered_set, "blocked_obligations", blocked)

    rows = declared_delivered_items(projection)  # type: ignore[arg-type]
    assert [(index, kind) for _o, index, kind, _v in rows] == [
        (1, "file"),
        (2, "directory"),
        (4, "file"),
    ]
    # A deleted input is not a removed deliverable.
    assert declared_output_removed(projection, {(obligation, 0): _GONE}) == ()  # type: ignore[arg-type]
    assert declared_output_removed(projection, {(obligation, 2): _GONE}) == (obligation,)  # type: ignore[arg-type]


def test_check_reports_the_gap_beside_requested_output_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.application import check, check_change

    projection = _projection(_file("/app/harmony.musicxml"), _file("/app/missing.txt"))

    async def states(**_kwargs: object) -> dict[tuple[ObligationId, int], RequestedOutputState]:
        return {
            (_OBLIGATION, 0): _GONE,
            (_OBLIGATION, 1): RequestedOutputState("inside", exists=False),
        }

    monkeypatch.setattr(check_change, "requested_output_states", states)
    _evaluator, gaps, absent = asyncio.run(
        check._requested_output_inputs(  # pyright: ignore[reportPrivateUsage]
            SimpleNamespace(projection=projection),  # type: ignore[arg-type]
            None,
            None,
            None,
            "req_00000000-0000-4000-8000-000000000001",
        )
    )
    assert gaps == (DECLARED_OUTPUT_REMOVED_GAP,)
    assert absent is True
