"""The declared delivered set and ``declared_output_removed`` (ADR-035, issue #1005)."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import dataclass
from types import MappingProxyType, SimpleNamespace
from typing import cast

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from yoetz.domain.events import (
    DecisionRecordedPayload,
    DeliverableState,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
)
from yoetz.domain.values import ObligationId, actor_id, event_id, obligation_id
from yoetz.kernel import delivered_set
from yoetz.kernel.closure_readiness import GAP_CLASSIFICATION, GapClass
from yoetz.kernel.delivered_set import (
    DECLARED_OUTPUT_CONTENT_MOVED_GAP,
    DECLARED_OUTPUT_EMPTIED_GAP,
    DECLARED_OUTPUT_REMOVED_GAP,
    DeliverableSnapshot,
    assess_deliverables,
    content_moved_declared_items,
    declared_delivered_items,
    declared_output_removed,
    deliverable_lineage,
    emptied_declared_items,
)
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import (
    AGENT_ACTIONABLE_TASK_FACT_GAPS,
    STANDING_TASK_FACT_GAPS,
    STOP_GATE_TOKENS,
    RequestedOutputState,
    deliverable_path_identity,
    register_command_identity_key,
)
from yoetz.protocol.errors import ProtocolValueError

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
def installation_key() -> Iterator[None]:
    """The path history is keyed with the installation key (ADR-045)."""

    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _earlier(
    relative: str,
    *,
    size: int = 14_900,
    lines: int | None = 310,
    basis: str = "delivered",
    frontier: int = 12,
    index: int = 0,
) -> DeliverableSnapshot:
    """An earlier check's recorded reading of *relative* that held content (ADR-045)."""

    return DeliverableSnapshot(
        DeliverableState(
            obligation_id=_OBLIGATION,
            item_index=index,
            path_key=deliverable_path_identity(relative),
            size_bytes=size,
            lines=lines,
            basis=basis,
        ),
        event_id("evt_00000000-0000-4000-8000-0000000000c1"),
        frontier,
    )


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
    _evaluator, gaps, absent, _states, _files = asyncio.run(
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
        _evaluator, gaps, absent, _states, _files = asyncio.run(
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
    _evaluator, gaps, absent, _states, _files = asyncio.run(
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


def test_undeclared_reference_inputs_pick_existing_declared_files() -> None:
    from yoetz.domain.events import RequestedItemRole
    from yoetz.kernel.delivered_set import undeclared_reference_inputs
    from yoetz.kernel.task_facts import (
        DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP,
        STANDING_TASK_FACT_GAPS,
    )

    # tb4n4 (#1044): agent work and a Stop-gate token, no longer a standing disclosure.
    assert DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP not in STANDING_TASK_FACT_GAPS
    assert DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP in STOP_GATE_TOKENS
    assert DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP in AGENT_ACTIONABLE_TASK_FACT_GAPS
    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.1.0"),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description="Deliver the outputs",
            evidence_expectation="The files",
            status=ObligationStatus.OPEN,
            requested_items=(
                _file("/app/cracker.py"),
                _file("/app/gone.py"),
                RequestedItem(
                    RequestedItemKind.FILE, "/app/words.txt", role=RequestedItemRole.INPUT
                ),
                RequestedItem(RequestedItemKind.DIRECTORY, "/app/models"),
            ),
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )
    projection = replay(ledger.prefix)
    existing = RequestedOutputState("inside", exists=True)
    states = {
        (_OBLIGATION, 0): existing,
        (_OBLIGATION, 1): _GONE,
        (_OBLIGATION, 2): existing,
        (_OBLIGATION, 3): existing,
    }
    deliverables, declared = undeclared_reference_inputs(projection, states)
    # Only an existing declared output file is read; every file/directory value is declared.
    assert deliverables == ("/app/cracker.py",)
    assert declared == ("/app/cracker.py", "/app/gone.py", "/app/words.txt", "/app/models")
    assert undeclared_reference_inputs(projection, states, blocked=(_OBLIGATION,))[0] == ()
    outside = {(_OBLIGATION, 0): RequestedOutputState("outside")}
    assert undeclared_reference_inputs(projection, outside)[0] == ()


def test_check_adds_undeclared_reference_and_names_it_on_the_deliverable_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tb4n4 (#1044): the fact is raised and the referencing deliverable's recorded state names
    the undeclared files (sorted, bounded), which is what the receipt and the Stop gate print."""

    from yoetz.application import check, check_change
    from yoetz.kernel.delivered_set import undeclared_reference_rows
    from yoetz.kernel.task_facts import DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP

    projection = _projection(_file("/app/cracker.py"))

    async def states(**_kwargs: object) -> dict[tuple[ObligationId, int], RequestedOutputState]:
        return {
            (_OBLIGATION, 0): RequestedOutputState(
                "inside", exists=True, size_bytes=120, lines=6, relative="cracker.py"
            )
        }

    async def references(**_kwargs: object) -> tuple[tuple[str, str], ...]:
        return (
            ("cracker.py", "english_words.npz"),
            ("cracker.py", "english_ngrams.npz"),
            ("cracker.py", "bad\nname.npz"),
        )

    monkeypatch.setattr(check_change, "requested_output_states", states)
    monkeypatch.setattr(check_change, "undeclared_references", references)
    _evaluator, gaps, absent, recorded, _files = asyncio.run(
        check._requested_output_inputs(  # pyright: ignore[reportPrivateUsage]
            SimpleNamespace(projection=projection, coverage_by_ref={}, gaps=()),  # type: ignore[arg-type]
            None,
            None,
            None,
            "req_00000000-0000-4000-8000-000000000001",
        )
    )
    assert gaps == (DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP,)
    assert absent is False
    (state,) = recorded
    # A path that cannot be named (a control character) is counted, never recorded.
    assert state.undeclared_references == ("english_ngrams.npz", "english_words.npz")
    assert state.undeclared_reference_count == 3
    assert DeliverableState.from_wire(state.as_wire()) == state
    assert undeclared_reference_rows(recorded) == (
        (str(_OBLIGATION), 0, ("english_ngrams.npz", "english_words.npz"), 3),
    )


def test_a_recorded_undeclared_reference_is_a_plain_bounded_path() -> None:
    for bad in ("/app/model.npz", "a//b", "../model.npz", "a/./b", "x" * 257, "tab\there"):
        with pytest.raises(ProtocolValueError):
            DeliverableState(_OBLIGATION, 0, undeclared_references=(bad,))
    with pytest.raises(ProtocolValueError):  # canonical order
        DeliverableState(_OBLIGATION, 0, undeclared_references=("b.npz", "a.npz"))
    with pytest.raises(ProtocolValueError):  # a count only when it says more than the list
        DeliverableState(
            _OBLIGATION, 0, undeclared_references=("a.npz",), undeclared_reference_count=1
        )
    state = DeliverableState(_OBLIGATION, 0, undeclared_references=("models/a.npz", "z.npz"))
    assert state.as_wire()["undeclared_references"] == ("models/a.npz", "z.npz")


# --- declared_output_emptied (tb4n2 R2, issue #1022, ADR-035 amendment) -------------------------


def _resolved_projection(
    *items: RequestedItem,
    status: ObligationStatus = ObligationStatus.RESOLVED,
    assumption: bool = False,
) -> ProjectionState:
    from yoetz.domain.values import evidence_id

    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.1.0"),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description="Deliver standalone Sage CLI at /app/solve.sage",
            evidence_expectation="The file runs",
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
    if status is ObligationStatus.RESOLVED:
        ledger.append(
            EventSchema("obligation_published", "1.1.0"),
            ObligationPublishedPayload(
                obligation_id=_OBLIGATION,
                description="Deliver standalone Sage CLI at /app/solve.sage",
                evidence_expectation="The file runs",
                status=ObligationStatus.RESOLVED,
                requested_items=items,
                resolution_evidence_refs=(evidence_id("evd_00000000-0000-4000-8000-000000000009"),),
            ),
            observed=False,
        )
    if assumption:
        ledger.append(
            EventSchema("decision_recorded", "1.0.0"),
            DecisionRecordedPayload(
                statement=f"The task asks for an empty file.\nyoetz-assumption:{_OBLIGATION}",
                rationale="The task statement says the file must be empty.",
                authority=actor_id("agt_codex"),
            ),
            observed=False,
        )
    return replay(ledger.prefix)


def _sized(size: int | None, **fields: object) -> RequestedOutputState:
    return RequestedOutputState("inside", exists=True, changed=True, size_bytes=size, **fields)  # type: ignore[arg-type]


def test_emptied_is_agent_actionable_and_continues_the_stop_gate() -> None:
    assert DECLARED_OUTPUT_EMPTIED_GAP == "declared_output_emptied"
    assert DECLARED_OUTPUT_EMPTIED_GAP in AGENT_ACTIONABLE_TASK_FACT_GAPS
    assert DECLARED_OUTPUT_EMPTIED_GAP in STOP_GATE_TOKENS
    assert GAP_CLASSIFICATION[DECLARED_OUTPUT_EMPTIED_GAP] is GapClass.AGENT_ACTIONABLE


def test_formal_crypto_resolved_obligation_over_a_zero_byte_deliverable_is_emptied() -> None:
    """tb4n2 formal-crypto S: ``write_bytes(b'')`` on the delivered solve.sage, 6/6 resolved.

    ADR-045: the file is only "emptied" with proof it held content earlier (an earlier check read
    it); a 0-byte read alone is also what a file created empty looks like.
    """

    projection = _resolved_projection(_file("/app/solve.sage"))
    history = (_earlier("solve.sage"),)
    empty = {(_OBLIGATION, 0): _sized(0, relative="solve.sage")}
    assert emptied_declared_items(projection, empty, history=history) == ((_OBLIGATION, 0),)
    assert emptied_declared_items(projection, empty) == ()
    full = {(_OBLIGATION, 0): _sized(14_900, relative="solve.sage")}
    assert emptied_declared_items(projection, full, history=history) == ()


@pytest.mark.parametrize(
    "state",
    [
        _sized(None),
        RequestedOutputState("inside", exists=False, deleted=True),
        RequestedOutputState("outside"),
        RequestedOutputState("unverified"),
        RequestedOutputState("inside", exists=None),
    ],
)
def test_emptied_needs_a_read_proving_it(state: RequestedOutputState) -> None:
    projection = _resolved_projection(_file("/app/solve.sage"))
    assert emptied_declared_items(projection, {(_OBLIGATION, 0): state}) == ()


def test_an_open_unclaimed_obligation_is_still_the_plan() -> None:
    projection = _resolved_projection(_file("/app/solve.sage"), status=ObligationStatus.OPEN)
    assert emptied_declared_items(projection, {(_OBLIGATION, 0): _sized(0)}) == ()


def test_an_unrelated_assumption_never_hides_an_emptied_deliverable() -> None:
    """Codex review: a best-effort disclosure must not disable the incomplete-work check."""

    projection = _resolved_projection(_file("/app/cracker.py"), assumption=True)
    states = {(_OBLIGATION, 0): _sized(0, relative="cracker.py")}
    history = (_earlier("cracker.py"),)
    assert emptied_declared_items(projection, states, history=history) == ((_OBLIGATION, 0),)


def test_a_conventionally_empty_deliverable_is_never_emptied() -> None:
    projection = _resolved_projection(_file("/app/pkg/__init__.py"))
    assert emptied_declared_items(projection, {(_OBLIGATION, 0): _sized(0)}) == ()


def test_a_split_into_another_declared_output_is_not_truncation() -> None:
    """Codex review: a 201-line file split into a second declared output is a refactor."""

    projection = _resolved_projection(_file("/app/cracker.py"), _file("/app/english_model.py"))
    wrapper = _sized(40, base_lines=201, lines_lost=199, undeclared_lines_added=0)
    states = {(_OBLIGATION, 0): wrapper, (_OBLIGATION, 1): _sized(9_000)}
    assert emptied_declared_items(projection, states) == ()
    unchanged = RequestedOutputState("inside", exists=True, changed=False, size_bytes=9_000)
    states[(_OBLIGATION, 1)] = unchanged
    assert emptied_declared_items(projection, states) == ((_OBLIGATION, 0),)


@pytest.mark.parametrize(
    ("base", "lost", "elsewhere", "emptied"),
    [
        (200, 195, 0, True),  # truncated to under a tenth, nothing moved out
        (200, 181, 0, True),
        (200, 180, 0, False),  # kept exactly a tenth
        (19, 19, 0, False),  # too small to judge as truncated (not 0 bytes)
        (200, 195, 195, False),  # the content-moved shape stays the standing disclosure
    ],
)
def test_truncation_rule(base: int, lost: int, elsewhere: int, emptied: bool) -> None:
    projection = _resolved_projection(_file("/app/cracker.py"))
    state = _sized(512, base_lines=base, lines_lost=lost, undeclared_lines_added=elsewhere)
    assert bool(emptied_declared_items(projection, {(_OBLIGATION, 0): state})) is emptied


def test_check_adds_emptied_and_every_stop_voices_it_without_a_rider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Producer to gate, end to end (tb4n3 RC-8, formal-crypto S).

    Replaces ``test_check_adds_emptied_and_the_gate_names_it``, which asserted that the emptied
    gate text carried the A-12 ``acceptance_criteria`` sentence: that rode on the token by
    accident and is the coupling the gate no longer has (the acceptance re-read is its own
    announced readiness item). What must hold is the contract the owner asked for: the check
    produces the gap, the real readiness derivation lists it agent-actionable, the first-Stop gate
    names it, and a Stop the host already continued (every later Stop of formal-crypto S) voices
    it once, by key, instead of staying silent.
    """

    from yoetz.application import check, check_change
    from yoetz.cli.closure_gate import closure_gate_from_readiness
    from yoetz.kernel.closure_readiness import ClosureReadinessFacts, derive_closure_readiness

    projection = _resolved_projection(_file("/app/solve.sage"))

    async def states(**_kwargs: object) -> dict[tuple[ObligationId, int], RequestedOutputState]:
        return {(_OBLIGATION, 0): _sized(0, relative="solve.sage")}

    monkeypatch.setattr(check_change, "requested_output_states", states)
    outputs = asyncio.run(
        check._requested_output_inputs(  # pyright: ignore[reportPrivateUsage]
            SimpleNamespace(projection=projection, coverage_by_ref={}, gaps=()),  # type: ignore[arg-type]
            None,
            None,
            None,
            "req_00000000-0000-4000-8000-000000000001",
            (_earlier("solve.sage"),),
        )
    )
    gaps = outputs.gaps
    assert DECLARED_OUTPUT_EMPTIED_GAP in gaps
    (recorded,) = outputs.states
    assert (recorded.change, recorded.proof, recorded.prior_size_bytes) == (
        "emptied",
        "earlier_check",
        14_900,
    )
    split = derive_closure_readiness(
        ("coverage_gaps_declared",),
        tuple(gaps),
        ClosureReadinessFacts(
            check_applicability="applicable",
            semantic_review_current=True,
            receipt_blocking_finding_ids=(),
            acknowledged_finding_ids=(),
            acknowledged_obligation_ids=(),
            open_obligations_unreadable=False,
            closing_review_current=True,
            semantic_review_used=True,
        ),
        semantic_review_required=False,
    )
    assert split.state == "action_required"
    assert DECLARED_OUTPUT_EMPTIED_GAP in split.agent_actionable
    readiness = SimpleNamespace(
        state=split.state,
        agent_actionable=split.agent_actionable,
        standing_limitations=split.standing_limitations,
        open_obligation_count="0",
        receipt_blocking_finding_count="0",
        rechecks=(),
    )
    first = closure_gate_from_readiness(
        readiness, frontier_sequence="9", frontier_digest="d", observation_pending=False
    )
    assert first is not None
    assert DECLARED_OUTPUT_EMPTIED_GAP in first.items
    assert "no longer counts as delivered" in first.text
    assert "You withdrew a deliverable" in first.text
    # No unannounced rider: the acceptance re-read is not part of this gate.
    assert "acceptance_criteria" not in first.text
    assert not any(key.startswith("accept:") for key in first.blocker_keys)

    # A later Stop the host already continued: voiced once per key, then never again.
    silent = closure_gate_from_readiness(
        readiness,
        frontier_sequence="10",
        frontier_digest="d",
        observation_pending=False,
        reasked_blockers=frozenset(first.blocker_keys),
        active_stop=True,
    )
    assert silent is None
    voiced = closure_gate_from_readiness(
        readiness,
        frontier_sequence="10",
        frontier_digest="d",
        observation_pending=False,
        active_stop=True,
    )
    assert voiced is not None
    assert voiced.items == (DECLARED_OUTPUT_EMPTIED_GAP,)
    assert "You withdrew a deliverable" in voiced.text


def test_an_overlapping_declaration_of_the_same_file_is_not_another_output() -> None:
    """Codex review 2: the file and its declared directory, or two spellings, are one path."""

    projection = _resolved_projection(
        _file("/app/src/cracker.py"),
        RequestedItem(RequestedItemKind.DIRECTORY, "/app/src"),
        _file("src/cracker.py"),
    )
    truncated = RequestedOutputState(
        "inside",
        exists=True,
        changed=True,
        size_bytes=40,
        base_lines=200,
        lines_lost=199,
        undeclared_lines_added=0,
        relative="src/cracker.py",
    )
    states = {
        (_OBLIGATION, 0): truncated,
        (_OBLIGATION, 1): RequestedOutputState(
            "inside", exists=True, changed=False, relative="src"
        ),
        (_OBLIGATION, 2): truncated,
    }
    assert emptied_declared_items(projection, states) == ((_OBLIGATION, 0), (_OBLIGATION, 2))
    # Codex review 3: a changed declared directory may hold the split-out content (a refactor),
    # so truncation is not raised; an emptied (0-byte) file still is.
    states[(_OBLIGATION, 1)] = RequestedOutputState(
        "inside", exists=True, changed=True, relative="src"
    )
    assert emptied_declared_items(projection, states) == ()
    states[(_OBLIGATION, 0)] = _sized(0, relative="src/cracker.py")
    history = (_earlier("src/cracker.py"),)
    assert emptied_declared_items(projection, states, history=history) == (
        (_OBLIGATION, 0),
        (_OBLIGATION, 2),
    )


# --- tb4n3 RC-5 (issue #1028, ADR-045): the fact follows the path, not the obligation ------------

_OTHER_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000002")


def _lifecycle(
    *statuses: ObligationStatus,
    fallback: bool = False,
    decision: str | None = None,
    path: str = "/app/solve.sage",
) -> ProjectionState:
    """One obligation declaring *path* moving through *statuses*, optionally a second "empty
    fallback" obligation (resolved) on the same path, optionally a decision."""

    from yoetz.domain.values import evidence_id

    ledger = ObservedLedger()
    item = RequestedItem(RequestedItemKind.FILE, path)
    for status in statuses:
        ledger.append(
            EventSchema("obligation_published", "1.1.0"),
            ObligationPublishedPayload(
                obligation_id=_OBLIGATION,
                description="Deliver the solver",
                evidence_expectation="The file runs",
                status=status,
                requested_items=(item,),
                resolution_evidence_refs=(
                    (evidence_id("evd_00000000-0000-4000-8000-000000000009"),)
                    if status is ObligationStatus.RESOLVED
                    else ()
                ),
                acknowledged_not_done_reason=(
                    "Not solved for every input."
                    if status is ObligationStatus.ACKNOWLEDGED_NOT_DONE
                    else None
                ),
            ),
            observed=False,
        )
    refs = [_OBLIGATION]
    if fallback:
        refs.append(_OTHER_OBLIGATION)
        for status in (ObligationStatus.OPEN, ObligationStatus.RESOLVED):
            ledger.append(
                EventSchema("obligation_published", "1.1.0"),
                ObligationPublishedPayload(
                    obligation_id=_OTHER_OBLIGATION,
                    description="Deliver an empty solve.sage under the task's fallback clause",
                    evidence_expectation="The file is empty",
                    status=status,
                    requested_items=(item,),
                    resolution_evidence_refs=(
                        (evidence_id("evd_00000000-0000-4000-8000-000000000019"),)
                        if status is ObligationStatus.RESOLVED
                        else ()
                    ),
                ),
                observed=False,
            )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", tuple(sorted(refs))),
        observed=False,
    )
    if decision is not None:
        ledger.append(
            EventSchema("decision_recorded", "1.0.0"),
            DecisionRecordedPayload(
                statement=f"{decision}\nyoetz-assumption:{_OBLIGATION}",
                rationale="The task allows an empty file.",
                authority=actor_id("agt_codex"),
            ),
            observed=False,
        )
    return replay(ledger.prefix)


_ACK = ObligationStatus.ACKNOWLEDGED_NOT_DONE
_OPEN = ObligationStatus.OPEN
_RESOLVED = ObligationStatus.RESOLVED


def _emptied_solver(**fields: object) -> dict[tuple[ObligationId, int], RequestedOutputState]:
    return {(_OBLIGATION, 0): _sized(0, relative="solve.sage", **fields)}


def test_republishing_the_obligation_not_done_cannot_clear_a_withdrawn_deliverable() -> None:
    """formal-crypto S: the old fact was cleared by the ``acknowledged_not_done`` republish."""

    projection = _lifecycle(_OPEN, _RESOLVED, _ACK)
    history = (_earlier("solve.sage"),)
    assert emptied_declared_items(projection, _emptied_solver(), history=history) == (
        (_OBLIGATION, 0),
    )


def test_a_new_resolved_empty_fallback_obligation_cannot_clear_it_either() -> None:
    projection = _lifecycle(_OPEN, _RESOLVED, _ACK, fallback=True)
    history = (_earlier("solve.sage"),)
    states = {
        (_OBLIGATION, 0): _sized(0, relative="solve.sage"),
        (_OTHER_OBLIGATION, 0): _sized(0, relative="solve.sage"),
    }
    fired = emptied_declared_items(projection, states, history=history)
    assert fired == ((_OBLIGATION, 0), (_OTHER_OBLIGATION, 0))
    # And not without proof: the fallback obligation alone, on a file never seen with content.
    assert emptied_declared_items(projection, states) == ()


def test_work_in_progress_on_an_undelivered_path_is_not_a_withdrawal() -> None:
    """The obligation was never resolved and nothing was verified: the agent is still writing."""

    projection = _lifecycle(_OPEN)
    open_history = (_earlier("solve.sage", basis="present"),)
    assert emptied_declared_items(projection, _emptied_solver(), history=open_history) == ()
    # The same file recorded while a passing verification run was on the record is a delivery.
    verified = (_earlier("solve.sage", basis="verified"),)
    assert emptied_declared_items(projection, _emptied_solver(), history=verified) == (
        (_OBLIGATION, 0),
    )
    assert (
        emptied_declared_items(projection, _emptied_solver(), history=open_history, verified=True)
        == ()
    )  # a verified *now* does not make the earlier reading a delivery


def test_an_assumption_that_names_the_path_is_the_one_exit() -> None:
    history = (_earlier("solve.sage"),)
    named = _lifecycle(_OPEN, _RESOLVED, decision="The task allows /app/solve.sage to be empty.")
    assert emptied_declared_items(named, _emptied_solver(), history=history) == ()
    relative = _lifecycle(_OPEN, _RESOLVED, decision="solve.sage must be empty by design.")
    assert emptied_declared_items(relative, _emptied_solver(), history=history) == ()
    # Naming nothing, or another file, or only part of a longer path, hides nothing.
    for text in (
        "A best-effort choice.",
        "The task allows /app/other.sage to be empty.",
        "The task allows /app/solve.sage.bak to be empty.",
        "The task allows /srv/app/solve.sage2 to be empty.",
    ):
        unrelated = _lifecycle(_OPEN, _RESOLVED, decision=text)
        assert emptied_declared_items(unrelated, _emptied_solver(), history=history) == (
            (_OBLIGATION, 0),
        ), text


def test_the_accepted_state_stays_on_the_record() -> None:
    from yoetz.kernel.delivered_set import assess_deliverables

    projection = _lifecycle(_OPEN, _RESOLVED, decision="/app/solve.sage may be empty.")
    assessment = assess_deliverables(
        projection, _emptied_solver(), history=(_earlier("solve.sage"),)
    )
    assert assessment.emptied == ()
    (state,) = assessment.states
    assert (state.change, state.proof) == ("emptied", "earlier_check")
    assert state.accepted_by is not None


def test_a_stub_cut_of_a_new_file_needs_the_earlier_reading_and_a_tenth_left() -> None:
    projection = _lifecycle(_OPEN, _RESOLVED)
    stub = {
        (_OBLIGATION, 0): _sized(14, lines=1, relative="solve.sage"),
    }
    history = (_earlier("solve.sage", size=9_800, lines=300),)
    assert emptied_declared_items(projection, stub) == ()
    assert emptied_declared_items(projection, stub, history=history) == ((_OBLIGATION, 0),)
    # A real rewrite that keeps more than a tenth is not a truncation.
    rewrite = {(_OBLIGATION, 0): _sized(2_000, lines=60, relative="solve.sage")}
    assert emptied_declared_items(projection, rewrite, history=history) == ()
    # A short file cut to a few lines is below the floor.
    short = (_earlier("solve.sage", size=400, lines=12),)
    assert emptied_declared_items(projection, stub, history=short) == ()


def test_an_unread_line_count_falls_back_to_a_tenth_of_the_bytes() -> None:
    projection = _lifecycle(_OPEN, _RESOLVED)
    history = (_earlier("solve.sage", size=30_000, lines=None),)
    cut = {(_OBLIGATION, 0): _sized(900, relative="solve.sage")}
    assert emptied_declared_items(projection, cut, history=history) == ((_OBLIGATION, 0),)
    small = (_earlier("solve.sage", size=1_500, lines=None),)
    assert emptied_declared_items(projection, cut, history=small) == ()


def test_a_declared_file_gone_after_an_earlier_reading_is_removed() -> None:
    projection = _lifecycle(_OPEN, _RESOLVED)
    gone = {(_OBLIGATION, 0): RequestedOutputState("inside", exists=False, relative="solve.sage")}
    from yoetz.kernel.delivered_set import removed_declared_items

    assert removed_declared_items(projection, gone) == ()
    assert removed_declared_items(projection, gone, history=(_earlier("solve.sage"),)) == (
        (_OBLIGATION, 0),
    )


def test_a_history_for_another_path_proves_nothing() -> None:
    projection = _lifecycle(_OPEN, _RESOLVED)
    assert (
        emptied_declared_items(projection, _emptied_solver(), history=(_earlier("other.sage"),))
        == ()
    )


# --- Codex review round 1 (issue #1028) --------------------------------------------------------


def test_a_clipped_line_count_read_is_unknown_not_a_truncation() -> None:
    """Moving 195 of a solver's 200 lines into an untracked file beyond the read bound: the
    undeclared growth is a lower bound, so it can prove a move but never rule one out."""

    projection = _lifecycle(_OPEN, _RESOLVED)
    history = (_earlier("solve.sage", size=9_800, lines=300),)
    stub = {(_OBLIGATION, 0): _sized(14, lines=1, relative="solve.sage")}
    assert emptied_declared_items(projection, stub, history=history) == ((_OBLIGATION, 0),)
    clipped = {(_OBLIGATION, 0): _sized(14, lines=1, relative="solve.sage", counts_truncated=True)}
    assert emptied_declared_items(projection, clipped, history=history) == ()
    # An emptied file stays emptied: a clipped read cannot move bytes into a 0-byte file.
    zero = {(_OBLIGATION, 0): _sized(0, lines=0, relative="solve.sage", counts_truncated=True)}
    assert emptied_declared_items(projection, zero, history=history) == ((_OBLIGATION, 0),)


def test_content_moved_covers_a_file_the_task_base_does_not_hold() -> None:
    """A new 300-line solver cut to one line with 300 lines added elsewhere is disclosed (ADR-035)."""

    projection = _lifecycle(_OPEN, _RESOLVED)
    history = (_earlier("solve.sage", size=9_800, lines=300),)
    moved = {
        (_OBLIGATION, 0): _sized(14, lines=1, relative="solve.sage", undeclared_lines_added=300)
    }
    assert content_moved_declared_items(projection, moved, history=history) == ((_OBLIGATION, 0),)
    assert content_moved_declared_items(projection, moved) == ()
    # And the move is not also a withdrawal.
    assert emptied_declared_items(projection, moved, history=history) == ()
    # Growth that does not match the loss is no move.
    elsewhere = {
        (_OBLIGATION, 0): _sized(14, lines=1, relative="solve.sage", undeclared_lines_added=20)
    }
    assert content_moved_declared_items(projection, elsewhere, history=history) == ()


def test_a_truncation_cites_the_reading_it_compared_against() -> None:
    """Readings of 300, then 60, then 20 lines: the fact compares with 300 and says so."""

    projection = _lifecycle(_OPEN, _RESOLVED)
    first = _earlier("solve.sage", size=9_800, lines=300, frontier=10)
    second = _earlier("solve.sage", size=2_000, lines=60, frontier=20)
    third = DeliverableSnapshot(
        second.state, event_id("evt_00000000-0000-4000-8000-0000000000c2"), 30
    )
    now = {(_OBLIGATION, 0): _sized(500, lines=20, relative="solve.sage")}
    assessment = assess_deliverables(projection, now, history=(first, second, third))
    (recorded,) = assessment.states
    assert recorded.change == "truncated"
    assert (recorded.prior_lines, recorded.prior_frontier) == (300, 10)
    (lineage,) = deliverable_lineage(None, 40, assessment.states)
    assert (lineage.prior_lines, lineage.prior_frontier) == (300, 10)


def test_a_removal_proved_only_by_a_published_edit_still_has_lineage() -> None:
    """A new file written in the session and gone before its first check: no earlier reading and
    no tracked deletion, but the removal is recorded and explained like the other routes."""

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
    gone = {
        (_OBLIGATION, 0): RequestedOutputState("inside", exists=False, relative="harmony.musicxml")
    }
    assessment = assess_deliverables(replay(ledger.prefix), gone)
    assert assessment.removed == ((_OBLIGATION, 0),)
    (recorded,) = assessment.states
    assert recorded.change == "removed"
    (lineage,) = deliverable_lineage(None, 12, assessment.states)
    assert (lineage.code, lineage.state) == (DECLARED_OUTPUT_REMOVED_GAP, "removed")
