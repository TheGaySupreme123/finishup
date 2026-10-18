"""Host parity for failure supersession from real host hook payloads (#909).

Each case starts at a host normalizer (Claude Code or Cursor ordinary profile, which already record
failures today), materializes the recorded envelopes exactly as the coordinator does, and appends
the drafts as service-stamped hook observations before a cooperative completion claim. The same
kernel predicate then decides the findings, the claim-revision invariant, and the receipt, so a
red -> green cycle is clean and a red-latest run is one finding on every host.
"""

from __future__ import annotations

import io
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest

from builders.codex_rollout import encode_lines, item_completed, session_meta
from builders.observed_runs import ObservedLedger, omissions, omitted_results, receipt_limitations
from finishup.adapters.integrations.codex_session_stream import SessionStreamReader
from finishup.adapters.integrations.observation_local import (
    STREAM_MAPPING_VERSION,
    LocalObservationStore,
)
from finishup.application.observation_materialize import materialize_observation_envelope
from finishup.cli import observe_hooks
from finishup.domain.events import ActionRecordedPayload, EventPayload, ResultRecordedPayload
from finishup.domain.observation import ObservationCursor, ObservationSource
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.domain.values import JsonValue, ResultId
from finishup.kernel.closure_class import finding_closure
from finishup.kernel.finding_todo import FindingTodoState, finding_todo_state
from finishup.kernel.observed_failures import observed_action_process_control
from finishup.kernel.reducers import replay
from finishup.protocol.canonical import canonical_encode

_TASK = "tsk_00000000-0000-4000-8000-000000000909"
_CANARY = "zq909hostcanary"
type _Emit = Callable[[str, Mapping[str, object]], None]


def _host(tmp_path: Path, host: str) -> tuple[_Emit, Callable[[], ObservedLedger]]:
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    def emit(event: str, payload: Mapping[str, object]) -> None:
        if host == "codex":
            assert (
                observe_hooks.handle_observe(
                    event_name=event,
                    stdin_bytes=canonical_encode(cast(JsonValue, payload)),
                    stdout=io.BytesIO(),
                    workspace=str(tmp_path),
                    _state=state,
                    skip_service=True,
                    source=ObservationSource.CODEX_HOOK,
                )
                == 0
            )
            return
        handler = (
            observe_hooks.handle_claude_observe
            if host == "claude"
            else observe_hooks.handle_cursor_observe
        )
        assert (
            handler(
                event_name=event,
                stdin_bytes=canonical_encode(cast(JsonValue, payload)),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=state,
                skip_service=True,
                observation_profile=(
                    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
                    if host == "claude"
                    else CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
                ),
            )
            == 0
        )

    def ledger() -> ObservedLedger:
        built = ObservedLedger()
        for envelope in LocalObservationStore(_state=state).list_envelopes(workspace):
            batch = materialize_observation_envelope(envelope, task_id=_TASK)
            for item in batch.drafts:
                if item.draft.schema.name in {"action_recorded", "result_recorded"}:
                    built.append(
                        item.draft.schema, cast(EventPayload, item.draft.payload), observed=True
                    )
        assert _CANARY.encode() not in b"".join(
            path.read_bytes() for path in state.rglob("*") if path.is_file()
        )
        return built

    return emit, ledger


def _claude_bash(
    emit: _Emit, call: str, command: str, *, failed: bool, exit_code: int | None = None
) -> None:
    session = {"session_id": "claude-909", "tool_name": "Bash", "tool_use_id": call}
    tool_input = {"command": command, "description": "Run tests"}
    emit("PreToolUse", {**session, "hook_event_name": "PreToolUse", "tool_input": tool_input})
    if failed:
        emit(
            "PostToolUseFailure",
            {
                **session,
                "hook_event_name": "PostToolUseFailure",
                "tool_input": tool_input,
                "error": f"Exit code {exit_code or 1}\n{_CANARY} FAILED",
            },
        )
    else:
        emit(
            "PostToolUse",
            {
                **session,
                "hook_event_name": "PostToolUse",
                "tool_input": tool_input,
                "tool_response": {
                    "stdout": f"{_CANARY} passed",
                    "stderr": "",
                    "interrupted": False,
                },
            },
        )


def _claude_edit(emit: _Emit, call: str) -> None:
    session = {"session_id": "claude-909", "tool_name": "Edit", "tool_use_id": call}
    tool_input = {"file_path": "src/module.py", "old_string": "a", "new_string": "b"}
    emit("PreToolUse", {**session, "hook_event_name": "PreToolUse", "tool_input": tool_input})
    emit(
        "PostToolUse",
        {
            **session,
            "hook_event_name": "PostToolUse",
            "tool_input": tool_input,
            "tool_response": {"filePath": "src/module.py", "success": True},
        },
    )


def _cursor_shell(emit: _Emit, call: str, command: str, *, exit_code: int) -> None:
    base = {
        "session_id": "cursor-909",
        "conversation_id": "cursor-909-conversation",
        "tool_name": "Shell",
        "tool_use_id": call,
    }
    tool_input = {"command": command}
    emit("preToolUse", {**base, "hook_event_name": "preToolUse", "tool_input": tool_input})
    emit(
        "postToolUse",
        {
            **base,
            "hook_event_name": "postToolUse",
            "tool_input": tool_input,
            "tool_output": f'{{"exitCode":{exit_code},"stdout":"{_CANARY}"}}',
        },
    )


def _results(ledger: ObservedLedger) -> dict[ResultId, ActionRecordedPayload]:
    actions = {
        cast(ActionRecordedPayload, record.payload).action_id: cast(
            ActionRecordedPayload, record.payload
        )
        for record in ledger.records
        if record.schema.name == "action_recorded"
    }
    return {
        cast(ResultRecordedPayload, record.payload).result_id: actions[
            cast(ResultRecordedPayload, record.payload).action_id
        ]
        for record in ledger.records
        if record.schema.name == "result_recorded"
    }


def test_claude_red_green_rerun_is_clean_and_red_latest_is_one_finding(tmp_path: Path) -> None:
    emit, build = _host(tmp_path, "claude")
    _claude_bash(emit, "toolu-red", f"pytest -q tests/{_CANARY}.py", failed=True)
    _claude_bash(emit, "toolu-green", f"pytest  -q tests/{_CANARY}.py", failed=False)
    clean = build()
    actions = list(_results(clean).values())
    assert actions[0].command == actions[1].command
    assert actions[0].command is not None and actions[0].command.startswith("omitted:hmac-sha256:")
    assert (
        # The hook appends the effective user it ran as (ADR-033 runtime facts), which depends
        # on the test process, not on the host.
        actions[0].description.removesuffix(" (user root)").removesuffix(" (user non_root)")
        == "Observed command via Claude Code hook (tool Bash) (runner test)"
    )
    clean.claim(versioned=True)
    assert omissions(clean) == ()
    assert "1 was later passed by the same command" in receipt_limitations(clean)

    _claude_bash(emit, "toolu-other", "pytest -q tests/other.py", failed=True)
    red_latest = build()
    red_result = list(_results(red_latest))[-1]
    red_latest.claim()
    assert omitted_results(red_latest) == (red_result,)


def _planned_retirement(
    tmp_path: Path, build: Callable[[], ObservedLedger], red: ObservedLedger, planned: str
) -> None:
    """Replay the host's rows behind a plan requesting ``planned``, with the coordinator's finding
    after the failed call, and assert the later pass retired it as the planned verification."""

    from finishup.domain.values import EventId
    from finishup.kernel.task_facts import register_command_identity_key

    rows = build().records
    register_command_identity_key(LocalObservationStore(_state=tmp_path / "state").key_material())
    try:
        ledger = ObservedLedger()
        ledger.plan(planned)
        appended = [
            ledger.append(row.schema, cast(EventPayload, row.payload), observed=True)
            for row in rows[: len(red.records)]
        ]
        finding = ledger.advice_finding(tuple(appended))
        passing: list[EventId] = [
            ledger.append(row.schema, cast(EventPayload, row.payload), observed=True)
            for row in rows[len(red.records) :]
        ]
        state = replay(ledger.prefix)
        assert state.findings[finding].retired_by_event_id == passing[-1]
        assert finding_todo_state(state, finding) is FindingTodoState.VERIFIED_RESOLVED
        closure = finding_closure(state, finding)
        assert closure is not None and closure.basis == "retired_by_planned_verification"
    finally:
        register_command_identity_key(None)


def test_claude_passing_planned_verification_retires_an_unrelated_failure(
    tmp_path: Path,
) -> None:
    """Owner decision 2026-10-18 (#1104): Claude Code states the exits in ``PostToolUseFailure``
    and ``PostToolUse``; a failed ``pip install`` is retired by the plan's verification passing
    later, and the finding names that kind of pass."""

    emit, build = _host(tmp_path, "claude")
    planned = f"pytest -q tests/{_CANARY}.py"
    _claude_bash(emit, "toolu-install", "pip install -e .", failed=True)
    red = build()
    _claude_bash(emit, "toolu-tests", f"cd /app && {planned}", failed=False)
    _planned_retirement(tmp_path, build, red, planned)


def test_cursor_passing_planned_verification_retires_an_unrelated_failure(
    tmp_path: Path,
) -> None:
    """The same decision on Cursor, whose ``postToolUse`` states ``exitCode``."""

    emit, build = _host(tmp_path, "cursor")
    planned = f"npm test -- {_CANARY}"
    _cursor_shell(emit, "cursor-install", "npm ci", exit_code=1)
    red = build()
    _cursor_shell(emit, "cursor-tests", planned, exit_code=0)
    _planned_retirement(tmp_path, build, red, planned)


def test_claude_failure_then_observed_edit_stays_outstanding(tmp_path: Path) -> None:
    emit, build = _host(tmp_path, "claude")
    _claude_bash(emit, "toolu-red", f"npm test -- {_CANARY}", failed=True)
    _claude_edit(emit, "toolu-edit")
    ledger = build()
    failed_result = next(iter(_results(ledger)))
    ledger.claim(versioned=True, limitations=(failed_result,))
    assert omissions(ledger) == ()
    assert "hook-observed failing" in receipt_limitations(ledger)


def test_cursor_red_green_rerun_is_clean_and_different_command_is_not(tmp_path: Path) -> None:
    emit, build = _host(tmp_path, "cursor")
    _cursor_shell(emit, "cursor-red", f"npm test -- {_CANARY}", exit_code=1)
    _cursor_shell(emit, "cursor-green", f"npm test --  {_CANARY}", exit_code=0)
    clean = build()
    clean.claim(versioned=True)
    assert omissions(clean) == ()

    _cursor_shell(emit, "cursor-red-2", "npm run lint", exit_code=2)
    _cursor_shell(emit, "cursor-green-2", "npm run build", exit_code=0)
    ledger = build()
    lint_failure = list(_results(ledger))[2]
    ledger.claim()
    assert omitted_results(ledger) == (lint_failure,)


def _codex_exec(emit: _Emit, call: str, command: str, *, exit_code: int) -> None:
    """A code-mode ``tools.exec_command`` hook pair in the recorded 0.157.1 shape (OUT-001)."""

    base = {"session_id": "codex-909-910", "turn_id": "turn-1", "tool_name": "Bash"}
    tool_input = {"command": command}
    emit(
        "PreToolUse",
        {**base, "hook_event_name": "PreToolUse", "tool_use_id": call, "tool_input": tool_input},
    )
    emit(
        "PostToolUse",
        {
            **base,
            "hook_event_name": "PostToolUse",
            "tool_use_id": call,
            "tool_input": tool_input,
            # The exit is stated only inside tool_response; no top-level exit_status (#910).
            "tool_response": (
                '{"chunk_id":"d74c6f","wall_time_seconds":23.226037979,'
                f'"exit_code":{exit_code},"original_token_count":1919,"output":"{_CANARY}"}}'
            ),
        },
    )


def test_codex_red_green_rerun_is_clean_and_red_latest_is_one_finding(tmp_path: Path) -> None:
    """#910 with #909: Codex's recorded outcomes feed the same supersession rule."""

    emit, build = _host(tmp_path, "codex")
    _codex_exec(emit, "call-red", f"npm run test-type -- {_CANARY}", exit_code=2)
    _codex_exec(emit, "call-green", f"npm run  test-type -- {_CANARY}", exit_code=0)
    clean = build()
    results = _results(clean)
    assert len(results) == 2
    red, green = results.values()
    assert red.command == green.command
    assert red.command is not None and red.command.startswith("omitted:hmac-sha256:")
    assert (
        red.description.removesuffix(" (user root)").removesuffix(" (user non_root)")
        == "Observed command via Codex hook (tool Bash) (runner test)"
    )
    clean.claim(versioned=True)
    assert omissions(clean) == ()
    assert "1 was later passed by the same command" in receipt_limitations(clean)

    _codex_exec(emit, "call-red-latest", "cargo test", exit_code=101)
    red_latest = build()
    red_result = list(_results(red_latest))[-1]
    red_latest.claim()
    assert omitted_results(red_latest) == (red_result,)


def test_codex_stream_rerun_carries_the_hook_command_identity(tmp_path: Path) -> None:
    """A rollout ``CommandExecution`` commits to the same identity as its hook copy (#910).

    Until #917 pairs the two paths, a command observed on both is two results; the shared identity
    lets a passing rerun seen on either path supersede a failure seen on either path.
    """

    emit, build = _host(tmp_path, "codex")
    command = f"npm run test-type -- {_CANARY}"
    _codex_exec(emit, "call-red", command, exit_code=2)
    _codex_exec(emit, "call-green", command, exit_code=0)
    ledger = build()
    store = LocalObservationStore(_state=tmp_path / "state")
    lines = [
        session_meta(cli_version="0.157.1", history_mode="paginated"),
        *(
            item_completed(
                {
                    "command": ["/bin/bash", "-lc", command],
                    "cwd": "file:///app",
                    "exit_code": exit_code,
                    "id": f"exec-{index:08x}-0000-4000-8000-000000000910",
                    "source": "unified_exec_startup",
                    "status": "failed" if exit_code else "completed",
                    "stdout": _CANARY,
                    "type": "CommandExecution",
                }
            )
            for index, exit_code in ((1, 2), (2, 0))
        ),
    ]
    path = tmp_path / "rollout.jsonl"
    path.write_bytes(encode_lines(*lines))
    reader = SessionStreamReader(
        session_commitment="hmac-sha256:" + "5" * 64,
        profile=None,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=0,
            event_position=0,
            last_source_commitment="hmac-sha256:" + "0" * 64,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
        key_material=store.key_material(),
    )
    stream = [e for e in reader.advance(path).envelopes if e.event_kind == "item_completed"]
    assert len(stream) == 2
    assert _CANARY not in repr([dict(item.structural_payload) for item in stream])
    for envelope in stream:
        batch = materialize_observation_envelope(envelope, task_id=_TASK)
        for item in batch.drafts:
            ledger.append(item.draft.schema, cast(EventPayload, item.draft.payload), observed=True)
    actions = list(_results(ledger).values())
    assert len(actions) == 4
    assert len({action.command for action in actions}) == 1
    ledger.claim(versioned=True)
    assert omissions(ledger) == ()


def _codex_patch(emit: _Emit, call: str, tool_response: str) -> None:
    base = {"session_id": "codex-909-910", "turn_id": "turn-1", "tool_name": "apply_patch"}
    patch = {"command": "*** Begin Patch\n*** Update File: src/a.py\n@@\n-a\n+b\n*** End Patch"}
    emit(
        "PreToolUse",
        {**base, "hook_event_name": "PreToolUse", "tool_use_id": call, "tool_input": patch},
    )
    emit(
        "PostToolUse",
        {
            **base,
            "hook_event_name": "PostToolUse",
            "tool_use_id": call,
            "tool_input": patch,
            "tool_response": tool_response,
        },
    )


def test_codex_patch_never_retires_a_failure_without_a_covering_rerun(tmp_path: Path) -> None:
    """#909 x #910: an edit result does not prove that a failed check was rerun."""

    emit, build = _host(tmp_path, "codex")
    _codex_exec(emit, "call-red", f"npm run test-type -- {_CANARY}", exit_code=2)
    _codex_patch(emit, "call-patch-unknown", "Patch queued")
    unknown_edit = build()
    red = list(_results(unknown_edit))[0]
    unknown_edit.claim()
    # The failure stays live; the outcome-less patch result is a limitation of its own.
    assert red in omitted_results(unknown_edit)

    _codex_patch(
        emit,
        "call-patch-applied",
        "Exit code: 0\nWall time: 0 seconds\nOutput:\nSuccess. Updated the following files:\n"
        "M src/a.py\n",
    )
    applied = build()
    applied.claim(versioned=True, limitations=(red,))
    # A patch that states ``Exit code: 0`` still needs an explicit acknowledgement or rerun.
    assert red not in omitted_results(applied)
    assert "hook-observed failing" in receipt_limitations(applied)


# --- failures that carry no failed-work duty (#1104) ------------------------------------------

_SERVER = "python app.py & sleep 2; curl -s localhost:8000; kill $!; wait $!"


def _codex_shell(emit: _Emit, call: str, command: str, *, exit_code: int) -> None:
    """A direct Codex shell hook pair in the recorded 0.157.1 ``Process exited`` shape."""

    base = {"session_id": "codex-1104", "turn_id": "turn-1", "tool_name": "Bash"}
    tool_input = {"command": command}
    emit(
        "PreToolUse",
        {**base, "hook_event_name": "PreToolUse", "tool_use_id": call, "tool_input": tool_input},
    )
    emit(
        "PostToolUse",
        {
            **base,
            "hook_event_name": "PostToolUse",
            "tool_use_id": call,
            "tool_input": tool_input,
            "tool_response": (
                f"Chunk ID: 5e0c7a\nWall time: 2.2 seconds\nProcess exited with code {exit_code}\n"
                f"Original token count: 4\nOutput:\n{_CANARY}\n"
            ),
        },
    )


def _run_on(host: str, emit: _Emit, call: str, command: str, exit_code: int) -> None:
    if host == "claude":
        _claude_bash(emit, call, command, failed=exit_code != 0, exit_code=exit_code)
    elif host == "cursor":
        _cursor_shell(emit, call, command, exit_code=exit_code)
    else:
        _codex_shell(emit, call, command, exit_code=exit_code)


@pytest.mark.parametrize("host", ["claude", "cursor", "codex"])
def test_read_only_chain_failure_carries_exploration_runner_class(
    tmp_path: Path, host: str
) -> None:
    emit, build = _host(tmp_path, host)
    _run_on(host, emit, "call-read", f"cd /app && ls {_CANARY}-missing", 2)
    ledger = build()
    (action,) = _results(ledger).values()
    assert "(runner exploration)" in action.description
    ledger.claim()
    assert omissions(ledger) == ()


@pytest.mark.parametrize("host", ["claude", "cursor", "codex"])
@pytest.mark.parametrize(("exit_code", "omitted"), [(143, False), (1, True)])
def test_background_kill_failure_carries_process_control(
    tmp_path: Path, host: str, exit_code: int, omitted: bool
) -> None:
    emit, build = _host(tmp_path, host)
    _run_on(host, emit, "call-server", _SERVER, exit_code)
    ledger = build()
    ((result, action),) = _results(ledger).items()
    # The shape rides inside the command's commitment list, not the description (#1104 round 1).
    assert observed_action_process_control(action) == "stop_own_job_term"
    assert "(process" not in action.description
    ledger.claim()
    # Claude Code's ``PostToolUseFailure`` states no exit status (only error text, which FinishUP
    # never parses), so the exemption, which needs exactly 128 + signal, never applies there.
    stated = host != "claude"
    assert omitted_results(ledger) == ((result,) if omitted or not stated else ())


# --- retire on pass from each host's real handler (#1104 round 1) -----------------------------


@pytest.mark.parametrize("host", ["claude", "cursor", "codex"])
@pytest.mark.parametrize(
    ("passing", "retired"),
    [
        (f"pytest -q tests/{_CANARY}.py", True),
        (f"cd /app && pytest -q tests/{_CANARY}.py > log.txt 2>&1", True),
        # A segment run behind an assignment is a different command.
        (f"PYTEST_ADDOPTS=--collect-only pytest -q tests/{_CANARY}.py", False),
        # A pass of another command never retires it.
        ("pytest -q tests/other.py", False),
    ],
)
def test_a_later_pass_retires_the_hosts_failed_command_finding(
    tmp_path: Path, host: str, passing: str, retired: bool
) -> None:
    """Fail, then pass, through each host's real handler; the finding is the coordinator's shape
    (observation-authored, naming the failed call's action and result events)."""

    emit, build = _host(tmp_path, host)
    _run_on(host, emit, "call-red", f"pytest -q tests/{_CANARY}.py", 1)
    red = build()
    (failed,) = _results(red)
    _run_on(host, emit, "call-green", passing, 0)
    ledger = ObservedLedger()
    finding = None
    for record in build().records:
        ledger.append(record.schema, cast(EventPayload, record.payload), observed=True)
        payload = record.payload
        if type(payload) is ResultRecordedPayload and payload.result_id == failed:
            finding = ledger.advice_finding(ledger.events_of(failed))
    assert finding is not None
    state = replay(ledger.prefix)
    closure = finding_closure(state, finding)
    assert closure is not None
    if retired:
        assert closure.basis == "retired_by_passing_run"
        assert finding_todo_state(state, finding) is FindingTodoState.VERIFIED_RESOLVED
    else:
        assert closure.basis == "open_unanswered"
        assert finding_todo_state(state, finding) is FindingTodoState.OPEN
