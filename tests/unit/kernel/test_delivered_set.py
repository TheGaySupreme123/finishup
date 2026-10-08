"""The declared delivered set and ``declared_output_removed`` (ADR-035, issue #1005)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from types import MappingProxyType, SimpleNamespace
from typing import cast

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
    DECLARED_OUTPUT_CONTENT_MOVED_GAP,
    DECLARED_OUTPUT_REMOVED_GAP,
    content_moved_declared_items,
    declared_delivered_items,
    declared_output_removed,
)
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import (
    AGENT_ACTIONABLE_TASK_FACT_GAPS,
    STANDING_TASK_FACT_GAPS,
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


@pytest.fixture(autouse=True)
def declared_outputs(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Treat role-less 1.0.0 items as ``output`` here; L6's 1.1.0 role is not on this branch."""

    def output_role(item: object) -> object:
        return getattr(item, "role", None) or "output"

    name = cast(str, getattr(request, "node").name)
    if name != "test_input_role_is_ignored_and_directory_counts":
        monkeypatch.setattr(delivered_set, "item_role", output_role)


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
    # L4 #985: a blocker the agent only claimed suppresses nothing; a confirmed one (the check
    # passes the case's confirmed set) skips the obligation.
    assert declared_delivered_items(projection) != ()
    confirmed = {_OBLIGATION}
    assert declared_delivered_items(projection, blocked=confirmed) == ()
    assert declared_output_removed(projection, {(_OBLIGATION, 0): _GONE}, blocked=confirmed) == ()


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

    def blocked(_projection: object, _batches: object) -> MappingProxyType[ObligationId, str]:
        return MappingProxyType({})

    monkeypatch.setattr(delivered_set, "effective_obligations", effective)
    monkeypatch.setattr(delivered_set, "blocked_obligations", blocked)

    rows = declared_delivered_items(projection)  # type: ignore[arg-type]
    # A role-less item may be an input or a file the task asks to delete: never declared.
    assert [(index, kind) for _o, index, kind, _v in rows] == [
        (1, "file"),
        (2, "directory"),
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
            SimpleNamespace(projection=projection, coverage_by_ref={}, gaps=()),  # type: ignore[arg-type]
            None,
            None,
            None,
            "req_00000000-0000-4000-8000-000000000001",
        )
    )
    assert gaps == (DECLARED_OUTPUT_REMOVED_GAP,)
    # L6 E4 (#989): no completion claim and no agent work on the obligation yet, so the absent
    # ``missing.txt`` is not reported; the removed deliverable is still disclosed above.
    assert absent is False


def test_a_new_deliverable_written_in_the_session_and_now_gone_is_removed() -> None:
    """tb4n1 music-harmony: harmony.musicxml was a new file, written, then moved out of /app."""

    from yoetz.domain.events import ActionKind, ActionRecordedPayload
    from yoetz.domain.values import action_id

    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.0.0"),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description="Deliver the score",
            evidence_expectation="The file",
            status=ObligationStatus.OPEN,
            requested_items=(_file("/app/harmony.musicxml"),),
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-000000000001"),
            ActionKind.EDIT,
            "Wrote the score",
            obligation_refs=(_OBLIGATION,),
            attempted_items=("/app/harmony.musicxml",),
        ),
        observed=False,
    )
    projection = replay(ledger.prefix)
    never_tracked = RequestedOutputState("inside", exists=False)
    assert declared_output_removed(projection, {(_OBLIGATION, 0): never_tracked}) == (_OBLIGATION,)

    # The check reports it once, as removed, not also as an absent output (round-3 review).
    from yoetz.application import check, check_change

    async def states(**_kwargs: object) -> dict[tuple[ObligationId, int], RequestedOutputState]:
        return {(_OBLIGATION, 0): never_tracked}

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(check_change, "requested_output_states", states)
        _evaluator, gaps, absent = asyncio.run(
            check._requested_output_inputs(  # pyright: ignore[reportPrivateUsage]
                SimpleNamespace(projection=projection, coverage_by_ref={}, gaps=()),  # type: ignore[arg-type]
                None,
                None,
                None,
                "req_00000000-0000-4000-8000-000000000001",
            )
        )
    assert DECLARED_OUTPUT_REMOVED_GAP in gaps
    assert absent is False
    # Never written in the session: an absent output, not a removed deliverable.
    assert (
        declared_output_removed(
            _projection(_file("/app/harmony.musicxml")), {(_OBLIGATION, 0): never_tracked}
        )
        == ()
    )


def _shrunk(base: int, lost: int, elsewhere: int) -> RequestedOutputState:
    return RequestedOutputState(
        "inside",
        exists=True,
        changed=True,
        base_lines=base,
        lines_lost=lost,
        undeclared_lines_added=elsewhere,
    )


def test_content_moved_is_a_standing_disclosure_never_a_stop_gate_token() -> None:
    assert DECLARED_OUTPUT_CONTENT_MOVED_GAP == "declared_output_content_moved"
    assert DECLARED_OUTPUT_CONTENT_MOVED_GAP in STANDING_TASK_FACT_GAPS
    assert DECLARED_OUTPUT_CONTENT_MOVED_GAP not in AGENT_ACTIONABLE_TASK_FACT_GAPS
    assert DECLARED_OUTPUT_CONTENT_MOVED_GAP not in STOP_GATE_TOKENS
    assert GAP_CLASSIFICATION[DECLARED_OUTPUT_CONTENT_MOVED_GAP] is GapClass.STANDING_LIMITATION


@pytest.mark.parametrize(
    ("state", "moved"),
    [
        (_shrunk(201, 200, 200), True),  # interleaved-vigenere
        (_shrunk(40, 20, 10), True),  # exactly at every threshold
        (_shrunk(40, 19, 19), False),  # under the 20-line floor
        (_shrunk(41, 20, 20), False),  # under half of the base
        (_shrunk(200, 150, 74), False),  # under half of the loss reappeared elsewhere
        (_shrunk(200, 150, 0), False),  # a plain deletion
        (RequestedOutputState("inside", exists=True, changed=True), False),  # not read
        (
            RequestedOutputState(
                "inside",
                exists=False,
                deleted=True,
                base_lines=200,
                lines_lost=200,
                undeclared_lines_added=200,
            ),
            False,  # removed, not shrunk: declared_output_removed owns it
        ),
    ],
)
def test_content_moved_rule(state: RequestedOutputState, moved: bool) -> None:
    projection = _projection(_file("/app/cracker.py"))
    expected = ((_OBLIGATION, 0),) if moved else ()
    assert content_moved_declared_items(projection, {(_OBLIGATION, 0): state}) == expected


def test_content_moved_skips_role_less_and_blocked_items(monkeypatch: pytest.MonkeyPatch) -> None:
    state = {(_OBLIGATION, 0): _shrunk(201, 200, 200)}
    blocked = _projection(_file("/app/cracker.py"), blocker=True)
    assert content_moved_declared_items(blocked, state, blocked={_OBLIGATION}) == ()

    def no_role(item: object) -> object:
        del item
        return None

    monkeypatch.setattr(delivered_set, "item_role", no_role)
    assert content_moved_declared_items(_projection(_file("/app/cracker.py")), state) == ()


def test_check_adds_content_moved_as_a_disclosure(monkeypatch: pytest.MonkeyPatch) -> None:
    from yoetz.application import check, check_change

    projection = _projection(_file("/app/cracker.py"))

    async def states(**_kwargs: object) -> dict[tuple[ObligationId, int], RequestedOutputState]:
        return {(_OBLIGATION, 0): _shrunk(201, 200, 200)}

    monkeypatch.setattr(check_change, "requested_output_states", states)
    _evaluator, gaps, absent = asyncio.run(
        check._requested_output_inputs(  # pyright: ignore[reportPrivateUsage]
            SimpleNamespace(projection=projection, coverage_by_ref={}, gaps=()),  # type: ignore[arg-type]
            None,
            None,
            None,
            "req_00000000-0000-4000-8000-000000000001",
        )
    )
    assert gaps == (DECLARED_OUTPUT_CONTENT_MOVED_GAP,)
    assert absent is False


def test_content_moved_never_fires_the_stop_gate_and_is_noted_when_it_fires() -> None:
    from yoetz.cli.closure_gate import closure_gate_from_readiness

    def readiness(state: str, actionable: tuple[str, ...]) -> SimpleNamespace:
        return SimpleNamespace(
            state=state,
            agent_actionable=actionable,
            standing_limitations=(DECLARED_OUTPUT_CONTENT_MOVED_GAP,),
            open_obligation_count=1,
            receipt_blocking_finding_count=0,
            blocked_obligations=(),
        )

    for alone in (
        readiness("ready_with_limitations", ()),
        readiness("action_required", (DECLARED_OUTPUT_CONTENT_MOVED_GAP,)),
    ):
        assert (
            closure_gate_from_readiness(
                alone, frontier_sequence="7", frontier_digest="d", observation_pending=False
            )
            is None
        )
    gate = closure_gate_from_readiness(
        readiness("action_required", ("obligations_open",)),
        frontier_sequence="7",
        frontier_digest="d",
        observation_pending=False,
    )
    assert gate is not None
    assert gate.items == ("obligations_open",)
    assert "content may have moved out of a delivered file into an undelivered one" in gate.text
