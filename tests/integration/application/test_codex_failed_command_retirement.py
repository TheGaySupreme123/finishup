"""Codex retire-on-pass reads the outcome the ledger finally records for a call (#1104, D2).

Codex 0.159 states no exit in a shell call's ``PostToolUse``: the hook result is ``unknown`` and
the exit arrives on the session stream, joined to the call (an outcome correction, #1001), or the
stream's copy of the call commits first and carries the outcome itself. These replays drive
0.159-shaped hook payloads (no exit anywhere in ``tool_response``; derived from the recorded
0.157.1 shapes in ``fixtures/observations/codex-post-tool-outcomes-0.157.1.case.json`` with the
exit removed, raw 0.159 hook stdin capture pending) and rollout ``CommandExecution`` items through
the real hook ingress, stream reader, coordinator and ledger. The observation-authored finding is
then appended exactly as the coordinator writes it (its subject refs are the events the failed
call materialized), and the production replay decides whether a later pass retired it.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from collections.abc import Callable
from typing import cast

import pytest

from builders.codex_replay import Replay as _Replay
from builders.codex_replay import (
    command_execution,
    exec_cell,
    exec_cell_output,
    replay_cell,  # noqa: F401  # pyright: ignore[reportUnusedImport]  (registers the ``replay`` fixture)
    session_start,
    sweep_all,
)
from builders.observed_runs import ObservedLedger, omitted_results
from finishup.domain.events import (
    AcceptedEvent,
    ActionRecordedPayload,
    EventPayload,
    ResultOutcome,
    ResultRecordedPayload,
)
from finishup.domain.values import EventId, FindingId
from finishup.kernel.closure_class import finding_closure
from finishup.kernel.finding_todo import FindingTodoState, finding_todo_state
from finishup.kernel.observed_failures import observed_action_runner_class
from finishup.kernel.reducers import replay as replay_ledger
from finishup.kernel.task_facts import (
    planned_verification_passed,
    register_command_identity_key,
    requested_planned_command,
)

pytestmark = pytest.mark.anyio

_VERSION = "0.159.3"
_COMMAND = "npm run test-type"
_RED_AT = "2026-09-29T17:58:10.000Z"
_GREEN_AT = "2026-09-29T17:59:10.000Z"


def _direct_post_response(call: str) -> str:
    """A direct ``exec_command`` result as Codex 0.159 hands it to ``PostToolUse``: no exit."""

    return (
        f"Chunk ID: {call[-6:]}\nWall time: 0.2034 seconds\nOriginal token count: 4\n"
        "Output:\npublic synthetic output\n"
    )


def _code_mode_post_response(call: str) -> str:
    """A code-mode ``tools.exec_command`` result in 0.159: the JSON chunk, with no ``exit_code``."""

    return json.dumps(
        {
            "chunk_id": call[-6:],
            "original_token_count": 12,
            "output": "public synthetic output",
            "wall_time_seconds": 2.5,
        }
    )


def _direct_run(
    cell: _Replay, call: str, exit_code: int | None, timestamp: str, command: str = _COMMAND
) -> None:
    """A direct shell call: its hook pair and, when it exits, the rollout's item for it."""

    tool_input = {"command": command}
    cell.hook("PreToolUse", tool_name="Bash", tool_use_id=call, tool_input=tool_input)
    cell.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id=call,
        tool_input=tool_input,
        tool_response=_direct_post_response(call),
    )
    if exit_code is not None:
        cell.append(command_execution(call, command, exit_code, timestamp))


def _code_mode_run(cell: _Replay, n: int, exit_code: int, timestamp: str) -> None:
    """One code-mode cell whose nested ``tools.exec_command`` the rollout completes."""

    cell_id, nested = f"call_cell{n:02d}", f"call_nested{n:02d}"
    tool_input = {"command": _COMMAND}
    cell.append(
        exec_cell(
            cell_id,
            f"await tools.exec_command({json.dumps(tool_input)});\n",
            timestamp,
            item_id=f"ctc_cell{n:02d}",
        )
    )
    cell.hook("PreToolUse", tool_name="Bash", tool_use_id=nested, tool_input=tool_input)
    cell.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id=nested,
        tool_input=tool_input,
        tool_response=_code_mode_post_response(nested),
    )
    cell.append(
        command_execution(nested, _COMMAND, exit_code, timestamp),
        exec_cell_output(cell_id, '{"ok":true}', timestamp, item_id=f"ctco_cell{n:02d}"),
    )


def _stream_only_run(cell: _Replay, item: str, exit_code: int, timestamp: str) -> None:
    """The stream's copy commits first and carries the outcome itself."""

    cell.append(command_execution(item, _COMMAND, exit_code, timestamp))


def _observed_rows(cell: _Replay) -> list[AcceptedEvent]:
    return [
        row
        for row in cell.ledger._state.records
        if type(row) is AcceptedEvent and row.schema.name in {"action_recorded", "result_recorded"}
    ]


def _results(rows: list[AcceptedEvent]) -> list[ResultRecordedPayload]:
    return [
        cast(ResultRecordedPayload, row.payload)
        for row in rows
        if row.schema.name == "result_recorded"
    ]


class _Recorded:
    """The task ledger's observed rows with the coordinator's finding after the failed call."""

    def __init__(
        self,
        red: list[AcceptedEvent],
        later: list[AcceptedEvent],
        *,
        name: str,
        planned: tuple[str, ...] = (),
        plan_at: str = "start",
    ) -> None:
        """``plan_at`` places the plan: ``start`` (before every row), ``before_correction``
        (after the later call's hook rows, before its joined outcome) or ``end``."""

        self.ledger = ObservedLedger()
        if planned and plan_at == "start":
            self.ledger.plan(*planned)
        events: dict[EventId, EventId] = {}
        for row in red:
            events[row.event_id] = self.ledger.append(
                row.schema, cast(EventPayload, row.payload), observed=True
            )
        # What the coordinator names: the call's action and hook result, or (a stream-first
        # commit) the stream copy's own events; ``correction`` names only the joined outcome.
        named = [events[row.event_id] for row in red]
        if name == "correction":
            named = [events[red[-1].event_id]]
        self.finding: FindingId = self.ledger.advice_finding(tuple(named))
        self.passing: dict[str, EventId] = {}
        for index, row in enumerate(later):
            if planned and plan_at == "before_correction" and index == len(later) - 1:
                self.ledger.plan(*planned)
            appended = self.ledger.append(
                row.schema, cast(EventPayload, row.payload), observed=True
            )
            payload = row.payload
            if type(payload) is ResultRecordedPayload:
                self.passing[f"{payload.outcome.value}:{payload.exit_status}"] = appended
        if planned and plan_at == "end":
            self.ledger.plan(*planned)

    def basis(self) -> str | None:
        state = replay_ledger(self.ledger.prefix)
        closure = finding_closure(state, self.finding)
        return None if closure is None else closure.basis

    def retired_by(self) -> EventId | None:
        return replay_ledger(self.ledger.prefix).findings[self.finding].retired_by_event_id


async def _red_then(
    cell: _Replay, red: Callable[[], None], green: Callable[[], None]
) -> tuple[list[AcceptedEvent], list[AcceptedEvent]]:
    """Run the failing call, drain it, then the later call; the observed rows of each."""

    session_start(cell, cli_version=_VERSION)
    red()
    cell.hook("Stop", last_assistant_message="Checking.", stop_hook_active=False)
    await sweep_all(cell)
    red_rows = _observed_rows(cell)
    green()
    cell.hook("Stop", last_assistant_message="Tests pass.", stop_hook_active=False)
    await sweep_all(cell)
    return red_rows, _observed_rows(cell)[len(red_rows) :]


@pytest.mark.parametrize("name", ["call", "correction"])
async def test_direct_exec_command_pass_joined_from_the_stream_retires_the_finding(
    replay: _Replay, name: str
) -> None:
    red, later = await _red_then(
        replay,
        lambda: _direct_run(replay, "call_red", 1, _RED_AT),
        lambda: _direct_run(replay, "call_green", 0, _GREEN_AT),
    )
    # The hook rows are never rewritten: unknown, then the joined correction, per call.
    assert [(item.outcome, item.exit_status) for item in _results(red)] == [
        (ResultOutcome.UNKNOWN, None),
        (ResultOutcome.FAILURE, 1),
    ]
    assert [(item.outcome, item.exit_status) for item in _results(later)] == [
        (ResultOutcome.UNKNOWN, None),
        (ResultOutcome.SUCCESS, 0),
    ]
    recorded = _Recorded(red, later, name=name)
    assert recorded.basis() == "retired_by_passing_run"
    assert recorded.retired_by() == recorded.passing["success:0"]


async def test_code_mode_exec_cell_pass_retires_the_finding(replay: _Replay) -> None:
    red, later = await _red_then(
        replay,
        lambda: _code_mode_run(replay, 1, 2, _RED_AT),
        lambda: _code_mode_run(replay, 2, 0, _GREEN_AT),
    )
    assert (ResultOutcome.FAILURE, 2) in [(r.outcome, r.exit_status) for r in _results(red)]
    assert (ResultOutcome.SUCCESS, 0) in [(r.outcome, r.exit_status) for r in _results(later)]
    recorded = _Recorded(red, later, name="call")
    assert recorded.basis() == "retired_by_passing_run"
    assert recorded.retired_by() == recorded.passing["success:0"]


async def test_stream_first_copy_retires_the_finding(replay: _Replay) -> None:
    red, later = await _red_then(
        replay,
        lambda: _stream_only_run(replay, "exec-1104-red", 1, _RED_AT),
        lambda: _stream_only_run(replay, "exec-1104-green", 0, _GREEN_AT),
    )
    assert [(r.outcome, r.exit_status) for r in _results(red)] == [(ResultOutcome.FAILURE, 1)]
    recorded = _Recorded(red, later, name="call")
    assert recorded.basis() == "retired_by_passing_run"
    assert recorded.retired_by() == recorded.passing["success:0"]


@pytest.mark.parametrize("name", ["call", "correction"])
async def test_a_passing_planned_verification_joined_from_the_stream_retires_another_failure(
    replay: _Replay, name: str
) -> None:
    """Owner decision 2026-10-18: a failed ``npm ci`` is retired by the plan's verification
    ``npm run test-type`` passing later. Codex 0.159 states neither exit in ``PostToolUse``; both
    reach the ledger through the session stream's correction joined by call id."""

    register_command_identity_key(replay.store.key_material())
    try:
        red, later = await _red_then(
            replay,
            lambda: _direct_run(replay, "call_red", 1, _RED_AT, command="npm ci"),
            lambda: _direct_run(replay, "call_green", 0, _GREEN_AT),
        )
        assert [(item.outcome, item.exit_status) for item in _results(later)] == [
            (ResultOutcome.UNKNOWN, None),
            (ResultOutcome.SUCCESS, 0),
        ]
        recorded = _Recorded(red, later, name=name, planned=(_COMMAND,))
        assert recorded.basis() == "retired_by_planned_verification"
        assert recorded.retired_by() == recorded.passing["success:0"]
        unplanned = _Recorded(red, later, name=name)
        assert unplanned.basis() == "open_unanswered"
    finally:
        register_command_identity_key(None)


@pytest.mark.parametrize("plan_at", ["end", "before_correction"])
async def test_a_plan_published_after_the_pass_retires_nothing(
    replay: _Replay, plan_at: str
) -> None:
    """Owner decision 2026-10-18 (#1104): the obligation must be effective when the run passed.
    On Codex 0.159 the run passed when its ``PostToolUse`` landed (no exit stated); its exit is
    the stream correction joined later. A plan published after the correction, or between the
    hook result and the correction, was not effective then and retires nothing."""

    register_command_identity_key(replay.store.key_material())
    try:
        red, later = await _red_then(
            replay,
            lambda: _direct_run(replay, "call_red", 1, _RED_AT, command="npm ci"),
            lambda: _direct_run(replay, "call_green", 0, _GREEN_AT),
        )
        assert [(item.outcome, item.exit_status) for item in _results(later)] == [
            (ResultOutcome.UNKNOWN, None),
            (ResultOutcome.SUCCESS, 0),
        ]
        recorded = _Recorded(red, later, name="call", planned=(_COMMAND,), plan_at=plan_at)
        assert recorded.retired_by() is None
        assert recorded.basis() == "open_unanswered"
    finally:
        register_command_identity_key(None)


@pytest.mark.parametrize("planned", ["true", "ls -la"])
async def test_a_planned_command_that_is_no_verifier_retires_nothing(
    replay: _Replay, planned: str
) -> None:
    """Owner decision 2026-10-18 (#1104): the passing planned run must be a verifier (runner
    class test, build, lint or typecheck). The hook records ``exploration`` for ``true`` and
    ``ls``, so their joined passes clear no earlier failure."""

    register_command_identity_key(replay.store.key_material())
    try:
        red, later = await _red_then(
            replay,
            lambda: _direct_run(replay, "call_red", 1, _RED_AT, command="npm ci"),
            lambda: _direct_run(replay, "call_green", 0, _GREEN_AT, command=planned),
        )
        assert (ResultOutcome.SUCCESS, 0) in [(r.outcome, r.exit_status) for r in _results(later)]
        (action,) = [
            cast(ActionRecordedPayload, row.payload)
            for row in later
            if row.schema.name == "action_recorded"
        ]
        # Not vacuous: the run matches the planned command; only its runner class refuses it.
        assert observed_action_runner_class(action.description) == "exploration"
        command = requested_planned_command(planned)
        assert command is not None
        assert planned_verification_passed(action.command, (command,))
        recorded = _Recorded(red, later, name="call", planned=(planned,))
        assert recorded.retired_by() is None
        assert recorded.basis() == "open_unanswered"
    finally:
        register_command_identity_key(None)


def _hook_only(cell: _Replay, call: str, command: str) -> None:
    """A direct shell call's hook pair alone: its exit reaches the stream later (or never)."""

    _direct_run(cell, call, None, _RED_AT, command=command)


@pytest.mark.parametrize("planned_first", [True, False])
async def test_a_lagging_correction_retires_only_a_pass_begun_after_the_failure(
    replay: _Replay, planned_first: bool
) -> None:
    """#1104 round 1: ordering is by the passing call, not by its correction. Both calls' hooks
    land first (Codex 0.159 states no exit), then the stream's corrections: the failure, then the
    planned verification's success. A planned call the hook recorded before the failed call
    finished began before the failure and repairs nothing, though its exit lands after it; one
    recorded after the failed call's hook result retires it even when both exits lag."""

    register_command_identity_key(replay.store.key_material())
    try:
        session_start(replay, cli_version=_VERSION)
        first, second = (
            (("call_green", _COMMAND), ("call_red", "npm ci"))
            if planned_first
            else (("call_red", "npm ci"), ("call_green", _COMMAND))
        )
        _hook_only(replay, *first)
        _hook_only(replay, *second)
        replay.hook("Stop", last_assistant_message="Running.", stop_hook_active=False)
        await sweep_all(replay)
        replay.append(command_execution("call_red", "npm ci", 1, _RED_AT))
        replay.hook("Stop", last_assistant_message="Checking.", stop_hook_active=False)
        await sweep_all(replay)
        red = _observed_rows(replay)
        assert [(item.outcome, item.exit_status) for item in _results(red)] == [
            (ResultOutcome.UNKNOWN, None),
            (ResultOutcome.UNKNOWN, None),
            (ResultOutcome.FAILURE, 1),
        ]
        replay.append(command_execution("call_green", _COMMAND, 0, _GREEN_AT))
        replay.hook("Stop", last_assistant_message="Tests pass.", stop_hook_active=False)
        await sweep_all(replay)
        later = _observed_rows(replay)[len(red) :]
        assert [(item.outcome, item.exit_status) for item in _results(later)] == [
            (ResultOutcome.SUCCESS, 0)
        ]
        recorded = _Recorded(red, later, name="call", planned=(_COMMAND,))
        if planned_first:
            assert recorded.retired_by() is None
            assert recorded.basis() == "open_unanswered"
        else:
            assert recorded.basis() == "retired_by_planned_verification"
            assert recorded.retired_by() == recorded.passing["success:0"]
    finally:
        register_command_identity_key(None)


async def test_an_unknown_planned_verification_never_retires_another_failure(
    replay: _Replay,
) -> None:
    """The planned verification's exit never reached FinishUP: its pass is unknown, not a pass."""

    register_command_identity_key(replay.store.key_material())
    try:
        red, later = await _red_then(
            replay,
            lambda: _direct_run(replay, "call_red", 1, _RED_AT, command="npm ci"),
            lambda: _direct_run(replay, "call_green", None, _GREEN_AT),
        )
        recorded = _Recorded(red, later, name="call", planned=(_COMMAND,))
        assert recorded.retired_by() is None
        assert recorded.basis() == "open_unanswered"
    finally:
        register_command_identity_key(None)


async def test_an_unknown_outcome_never_retires_the_finding(replay: _Replay) -> None:
    """A rerun whose exit never reaches FinishUP (no stream item) proves nothing."""

    red, later = await _red_then(
        replay,
        lambda: _direct_run(replay, "call_red", 1, _RED_AT),
        lambda: _direct_run(replay, "call_green", None, _GREEN_AT),
    )
    assert [(r.outcome, r.exit_status) for r in _results(later)] == [(ResultOutcome.UNKNOWN, None)]
    recorded = _Recorded(red, later, name="call")
    state = replay_ledger(recorded.ledger.prefix)
    assert recorded.retired_by() is None
    assert finding_todo_state(state, recorded.finding) is FindingTodoState.OPEN
    assert recorded.basis() == "open_unanswered"


@pytest.mark.parametrize(("exit_code", "omitted"), [(143, False), (1, True)])
async def test_a_stopped_own_job_is_judged_by_the_joined_stream_exit(
    replay: _Replay, exit_code: int, omitted: bool
) -> None:
    """The hook records the shape (no exit), the stream's correction states the exit (#1104)."""

    server = "python app.py & sleep 2; curl -s localhost:8000; kill $!; wait $!"
    session_start(replay, cli_version=_VERSION)
    tool_input = {"command": server}
    replay.hook("PreToolUse", tool_name="Bash", tool_use_id="call_srv", tool_input=tool_input)
    replay.hook(
        "PostToolUse",
        tool_name="Bash",
        tool_use_id="call_srv",
        tool_input=tool_input,
        tool_response=_direct_post_response("call_srv"),
    )
    replay.append(command_execution("call_srv", server, exit_code, _RED_AT))
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    await sweep_all(replay)
    rows = _observed_rows(replay)
    ledger = ObservedLedger()
    for row in rows:
        ledger.append(row.schema, cast(EventPayload, row.payload), observed=True)
    corrected = next(
        item.result_id for item in _results(rows) if item.outcome is ResultOutcome.FAILURE
    )
    ledger.claim()
    assert omitted_results(ledger) == ((corrected,) if omitted else ())


@pytest.mark.parametrize(("exit_code", "omitted"), [(143, False), (1, True)])
async def test_a_stopped_own_job_committed_stream_first_keeps_the_same_judgment(
    replay: _Replay, exit_code: int, omitted: bool
) -> None:
    """Stream-first (#1104 round 1): the stream copy carries the stop shape in its own commitment
    list, so the ledger readers and the advice rule judge the call exactly as the hook-first one.
    """

    from finishup.kernel.policies.observation_advice import _failed_commands

    server = "python app.py & sleep 2; curl -s localhost:8000; kill $!; wait $!"
    session_start(replay, cli_version=_VERSION)
    replay.append(command_execution("exec-1104-srv", server, exit_code, _RED_AT))
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    await sweep_all(replay)
    rows = _observed_rows(replay)
    results = _results(rows)
    assert [(item.outcome, item.exit_status) for item in results] == [
        (ResultOutcome.FAILURE, exit_code)
    ]
    ledger = ObservedLedger()
    for row in rows:
        ledger.append(row.schema, cast(EventPayload, row.payload), observed=True)
    ledger.claim()
    assert omitted_results(ledger) == ((results[0].result_id,) if omitted else ())
    # The advice rule reads the same stored envelopes; a stream copy alone never raises a
    # failed-command finding on 0.159 (its tool name is not a command tool), and the stop
    # shape it carries is the one the ledger readers used.
    from finishup.domain.process_control import process_control_from_commitments

    envelopes = replay.store.list_envelopes(replay.commitment)
    shapes = {
        process_control_from_commitments(
            item.structural_payload.get("command_commitment"),
            item.structural_payload.get("command_segment_commitments"),
        )
        for item in envelopes
        if item.structural_payload.get("command_commitment") is not None
    }
    assert shapes == {"stop_own_job_term"}
    assert _failed_commands(envelopes) == []
