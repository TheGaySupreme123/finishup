"""Every host hook pass is timed, and observation-only motion is no hook notice (issue #915).

Payloads follow the current host hook contracts rather than pre-normalised envelopes:

* Codex 0.157.1 code mode: one ``exec`` cell makes nested ``apply_patch``, ``exec_command`` and
  ``mcp__finishup__status`` calls, each firing its own ``PreToolUse``/``PostToolUse`` with the
  generated hook input fields (``session_id``, ``turn_id``, ``transcript_path``, ``cwd``,
  ``model``, ``permission_mode``, ``tool_name``, ``tool_input``, ``tool_use_id`` and, after the
  call, ``tool_response``).
* Claude Code ``PostToolUse`` with ``tool_use_id`` for a plugin-scoped FinishUP tool (structural
  profile) and for ``Bash`` (ordinary profile).
* Cursor 3.17 ``postToolUse`` (ordinary profile) and ``afterMCPExecution`` (structural profile)
  keyed by ``conversation_id``.
"""

from __future__ import annotations

import io
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.integrations.observation_local import (
    AdviceDelivery,
    LocalObservationStore,
)
from finishup.application import observation_advice
from finishup.cli import observe as observe_cli
from finishup.cli import observe_hooks
from finishup.cli.hook_diagnostics import hook_diagnostic_summary
from finishup.cli.hook_timing import hook_pass_timing_summary
from finishup.domain.observation import AdviceSnapshot
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.protocol.canonical import JsonValue, canonical_encode

_CODEX_SESSION = "019a0000-0000-7000-8000-000000000915"
_REPOSITORY = Path(__file__).resolve().parents[3]


def _consented(tmp_path: Path) -> tuple[LocalObservationStore, str]:
    store = LocalObservationStore(_state=tmp_path)
    commitment = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(commitment)
    return store, commitment


def _codex(
    event: str,
    tool_name: str,
    tool_use_id: str,
    tool_input: JsonValue,
    workspace: Path,
    response: JsonValue | None = None,
) -> bytes:
    payload: dict[str, JsonValue] = {
        "session_id": _CODEX_SESSION,
        "transcript_path": f"{workspace}/.codex/sessions/rollout-2026-09-29.jsonl",
        "cwd": str(workspace),
        "hook_event_name": event,
        "model": "gpt-6-sol",
        "permission_mode": "default",
        "turn_id": "turn-7",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": tool_use_id,
    }
    if response is not None:
        payload["tool_response"] = response
    return json.dumps(payload).encode()


def _code_mode_cell(workspace: Path) -> list[tuple[str, str, JsonValue, JsonValue]]:
    """The nested calls of one Codex code-mode ``exec`` cell, in the order they ran."""

    patch = (
        "*** Begin Patch\n"
        f"*** Update File: {workspace}/bandit/plugins/tainted_injection.py\n"
        "@@ def check():\n"
        "-    return sink(value)\n"
        "+    return sink(sanitize(value))\n"
        "*** End Patch\n"
    )
    return [
        (
            "apply_patch",
            "call_915_patch",
            {"command": patch},
            "Exit code: 0\nWall time: 0.0 seconds\nOutput:\nSuccess. Updated the following files:\n"
            "M bandit/plugins/tainted_injection.py\n",
        ),
        (
            "exec_command",
            "call_915_exec",
            {"cmd": "python -m pytest -q tests/unit/test_taint.py", "yield_time_ms": 10_000},
            "Exit code: 0\nWall time: 1.2 seconds\nOutput:\n3 passed in 0.41s\n",
        ),
        (
            "mcp__finishup__status",
            "call_915_status",
            {"request": {"session_id": "ses_00000000-0000-4000-8000-000000000915"}},
            {"content": [], "structuredContent": {"ok": True}, "isError": False},
        ),
    ]


def _entries(state: Path) -> dict[tuple[str, str, str], Mapping[str, object]]:
    summary = hook_pass_timing_summary(_state=state)
    return {
        (cast(str, entry["host"]), cast(str, entry["event"]), cast(str, entry["path"])): entry
        for entry in cast(tuple[Mapping[str, object], ...], summary["entries"])
    }


def _assert_no_per_pass_rows(state: Path) -> None:
    """Rows stay reserved for over-budget passes: none is a routine, in-budget pass."""

    summary = hook_diagnostic_summary(_state=state)
    reasons = cast(Mapping[str, Mapping[str, object]], summary["reasons"])
    over_budget = cast(int, reasons.get("hook_budget_exceeded", {}).get("count", 0))
    assert cast(Mapping[str, object], summary["timings"])["count"] == over_budget


def test_codex_code_mode_nested_calls_are_each_one_timed_pass_without_rows(
    tmp_path: Path,
) -> None:
    _consented(tmp_path)
    cell = _code_mode_cell(tmp_path)
    for tool_name, tool_use_id, tool_input, response in cell:
        for event, body in (
            ("PreToolUse", _codex("PreToolUse", tool_name, tool_use_id, tool_input, tmp_path)),
            (
                "PostToolUse",
                _codex("PostToolUse", tool_name, tool_use_id, tool_input, tmp_path, response),
            ),
        ):
            stdout = io.BytesIO()
            assert (
                observe_hooks.handle_codex_observe(
                    event_name=event,
                    stdin_bytes=body,
                    stdout=stdout,
                    workspace=str(tmp_path),
                    _state=tmp_path,
                    skip_service=True,
                )
                == 0
            )
            assert stdout.getvalue().endswith(b"\n")

    entries = _entries(tmp_path)
    assert set(entries) == {("codex", "PreToolUse", "observe"), ("codex", "PostToolUse", "observe")}
    for entry in entries.values():
        assert entry["count"] == len(cell)
        assert cast(Mapping[str, int], entry["outcomes"])["ingested"] == len(cell)
        assert entry["p50_ms_at_most"] is not None
        assert entry["p95_ms_at_most"] is not None
        assert entry["max_ms"] is not None
    _assert_no_per_pass_rows(tmp_path)


def test_codex_sample_is_the_host_entry_to_pass_end_interval(tmp_path: Path) -> None:
    ticks = iter((10.0, 10.25))

    assert (
        observe_hooks.handle_codex_observe(
            event_name="PostToolUse",
            stdin_bytes=_codex("PostToolUse", "exec_command", "call_1", {"cmd": "ls"}, tmp_path),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
            _monotonic=lambda: next(ticks),
        )
        == 0
    )

    entry = _entries(tmp_path)[("codex", "PostToolUse", "observe")]
    assert entry["max_ms"] == 250
    # Nothing was consented, so the pass ended before capture and is named so.
    assert cast(Mapping[str, int], entry["outcomes"])["not_ingested"] == 1


def test_codex_pass_that_faults_is_counted_as_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("private detail")

    # Codex observation reads through the skim-aware ingress since tb4n1 (B5).
    monkeypatch.setattr(observe_hooks, "read_hook_ingress", broken)
    stdout = io.BytesIO()
    assert (
        observe_hooks.handle_codex_observe(
            event_name="PostToolUse",
            stdin_bytes=b"{}",
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    assert stdout.getvalue() == b"{}\n"
    entry = _entries(tmp_path)[("codex", "PostToolUse", "observe")]
    assert cast(Mapping[str, int], entry["outcomes"])["failed"] == 1
    raw = (tmp_path / "observation" / "hook-pass-timing.json").read_text()
    assert "private detail" not in raw


def test_nested_and_service_replay_passes_never_count_as_host_passes(tmp_path: Path) -> None:
    """The service replays legacy spool rows through the same pass; that is not host cost."""

    _consented(tmp_path)
    assert (
        observe_hooks.handle_observe(
            event_name="PostToolUse",
            stdin_bytes=_codex("PostToolUse", "exec_command", "call_2", {"cmd": "ls"}, tmp_path),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    assert hook_pass_timing_summary(_state=tmp_path)["status"] == "absent"


def test_claude_structural_and_ordinary_tool_hooks_are_separate_paths(tmp_path: Path) -> None:
    _consented(tmp_path)
    structural: dict[str, JsonValue] = {
        "session_id": "5b3c1d2e-0000-4000-8000-000000000915",
        "transcript_path": "/Users/{user}/.claude/projects/proj/session.jsonl",
        "cwd": str(tmp_path),
        "permission_mode": "default",
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__plugin_finishup_finishup__status",
        "tool_input": {"request": {}},
        "tool_response": {"ok": True},
        "tool_use_id": "toolu_01STATUS",
    }
    ordinary: dict[str, JsonValue] = {
        **structural,
        "tool_name": "Bash",
        "tool_input": {"command": "pytest -q", "description": "Run tests"},
        "tool_response": {"stdout": "3 passed", "stderr": "", "interrupted": False},
        "tool_use_id": "toolu_01BASH",
    }
    for payload, profile in (
        (structural, None),
        (ordinary, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID),
    ):
        assert (
            observe_hooks.handle_claude_observe(
                event_name="PostToolUse",
                stdin_bytes=canonical_encode(cast(JsonValue, payload)),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
                observation_profile=profile,
            )
            == 0
        )
    # A generic tool on the structural profile is filtered at ingress but still costs a process.
    assert (
        observe_hooks.handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(cast(JsonValue, ordinary)),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )

    entries = _entries(tmp_path)
    assert set(entries) == {
        ("claude", "PostToolUse", "structural"),
        ("claude", "PostToolUse", "ordinary"),
    }
    assert entries[("claude", "PostToolUse", "structural")]["outcomes"] == {
        "ingested": 1,
        "followup_deferred": 0,
        "not_ingested": 1,
        "failed": 0,
    }
    assert (
        cast(Mapping[str, int], entries[("claude", "PostToolUse", "ordinary")]["outcomes"])[
            "ingested"
        ]
        == 1
    )
    _assert_no_per_pass_rows(tmp_path)


def test_cursor_tool_and_mcp_hooks_are_timed_per_raw_event_and_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    _consented(tmp_path)
    base: dict[str, object] = {
        "conversation_id": "cursor-conv-915",
        "generation_id": "gen-1",
        "model": "claude-opus-4-7-thinking-max",
        "cursor_version": "3.17.8",
        "workspace_roots": [str(tmp_path.resolve())],
        "user_email": None,
        "transcript_path": None,
    }
    calls: list[tuple[str, dict[str, object], str | None]] = [
        (
            "preToolUse",
            {"tool_name": "Shell", "tool_use_id": "t1", "tool_input": {"command": "ls"}},
            CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        ),
        (
            "postToolUse",
            {
                "tool_name": "Shell",
                "tool_use_id": "t1",
                "tool_input": {"command": "ls"},
                "tool_output": '{"exitCode":0}',
                "duration": 12,
            },
            CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        ),
        (
            "afterMCPExecution",
            {"tool_name": "MCP:fixture_echo", "result_json": "fixture result", "duration": 3.5},
            None,
        ),
    ]
    outputs: dict[str, object] = {}
    for event, fields, profile in calls:
        stdout = io.BytesIO()
        assert (
            observe_hooks.handle_cursor_observe(
                event_name=event,
                # Plain JSON bytes as Cursor writes them, fractional duration included.
                stdin_bytes=json.dumps({**base, "hook_event_name": event, **fields}).encode(),
                stdout=stdout,
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
                observation_profile=profile,
            )
            == 0
        )
        outputs[event] = json.loads(stdout.getvalue())

    assert outputs["preToolUse"] == {"permission": "allow"}
    entries = _entries(tmp_path)
    assert set(entries) == {
        ("cursor", "preToolUse", "ordinary"),
        ("cursor", "postToolUse", "ordinary"),
        ("cursor", "afterMCPExecution", "structural"),
    }
    assert all(entry["count"] == 1 for entry in entries.values())
    _assert_no_per_pass_rows(tmp_path)


def test_legacy_spool_counts_every_pass_and_keeps_rows_for_hard_cap_breaches_only(
    tmp_path: Path,
) -> None:
    _consented(tmp_path)
    body = _codex("PostToolUse", "exec_command", "call_3", {"cmd": "ls"}, tmp_path)
    for _ in range(3):
        assert (
            observe_hooks.handle_spool(
                event_name="PostToolUse",
                stdin_bytes=body,
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path,
                _monotonic=iter((0.0, 0.04, 0.04)).__next__,
            )
            == 0
        )
    entry = _entries(tmp_path)[("codex", "PostToolUse", "sync_fallback_spool")]
    assert entry["count"] == 3
    assert cast(Mapping[str, int], entry["outcomes"])["ingested"] == 3
    assert entry["hard_cap_breach_count"] == 0
    summary = hook_diagnostic_summary(_state=tmp_path)
    assert cast(Mapping[str, object], summary["timings"])["count"] == 0

    assert (
        observe_hooks.handle_spool(
            event_name="PostToolUse",
            stdin_bytes=body,
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            _monotonic=iter((0.0, 0.61, 0.61)).__next__,
        )
        == 0
    )
    entry = _entries(tmp_path)[("codex", "PostToolUse", "sync_fallback_spool")]
    assert entry["count"] == 4
    assert entry["hard_cap_breach_count"] == 1
    summary = hook_diagnostic_summary(_state=tmp_path)
    timings = cast(Mapping[str, object], summary["timings"])
    assert timings["count"] == 1
    assert (
        cast(
            Mapping[str, object],
            cast(Mapping[str, object], timings["paths"])["sync_fallback_spool"],
        )["recent_hard_cap_breach_count"]
        == 1
    )
    assert "hook_slo_breached" in cast(Mapping[str, object], summary["reasons"])


def test_legacy_spool_breach_row_and_aggregate_share_one_endpoint(tmp_path: Path) -> None:
    """A slow host pipe cannot make the aggregate report a breach the row history lacks."""

    _consented(tmp_path)
    clock = [0.0]

    class _SlowPipe(io.BytesIO):
        def write(self, data: bytes, /) -> int:  # type: ignore[override]
            clock[0] += 0.03
            return super().write(data)

    assert (
        observe_hooks.handle_spool(
            event_name="PostToolUse",
            stdin_bytes=_codex("PostToolUse", "exec_command", "call_6", {"cmd": "ls"}, tmp_path),
            stdout=_SlowPipe(),
            workspace=str(tmp_path),
            _state=tmp_path,
            # 480 ms of work before the host's stdout write, 30 ms spent in the write itself.
            _entry_monotonic=-0.48,
            _monotonic=lambda: clock[0],
        )
        == 0
    )

    entry = _entries(tmp_path)[("codex", "PostToolUse", "sync_fallback_spool")]
    assert entry["max_ms"] == 510
    assert entry["hard_cap_breach_count"] == 1
    summary = hook_diagnostic_summary(_state=tmp_path)
    timings = cast(Mapping[str, object], summary["timings"])
    assert timings["count"] == 1
    assert timings["max_ms"] == 510
    reasons = cast(Mapping[str, Mapping[str, object]], summary["reasons"])
    assert reasons["hook_slo_breached"]["count"] == 1


def _pending_observation_motion(
    store: LocalObservationStore, commitment: str, session: str
) -> None:
    store.bind_codex_session(commitment, session)
    store.note_frontier_motion(
        commitment,
        session,
        from_sequence=2,
        to_sequence=11,
        head_digest="sha256:" + "9" * 64,
        observation_record_count=9,
        task_id="tsk_frontier_915",
    )


def _post_tool_use(host: str, tmp_path: Path) -> bytes:
    stdout = io.BytesIO()
    if host == "codex":
        observe_hooks.handle_codex_observe(
            event_name="PostToolUse",
            stdin_bytes=_codex(
                "PostToolUse", "exec_command", "call_4", {"cmd": "ls"}, tmp_path, "Exit code: 0\n"
            ),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
    elif host == "claude":
        observe_hooks.handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(
                {
                    "session_id": "claude-915",
                    "cwd": str(tmp_path),
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "ls"},
                    "tool_response": {"stdout": "", "stderr": "", "interrupted": False},
                    "tool_use_id": "toolu_01LS",
                }
            ),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
            observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        )
    else:
        observe_hooks.handle_cursor_observe(
            event_name="postToolUse",
            stdin_bytes=canonical_encode(
                {
                    "conversation_id": "cursor-915",
                    "hook_event_name": "postToolUse",
                    "cursor_version": "3.17.8",
                    "workspace_roots": [str(tmp_path.resolve())],
                    "tool_name": "Read",
                    "tool_use_id": "t9",
                    "tool_output": "{}",
                }
            ),
            stdout=stdout,
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
            observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        )
    return stdout.getvalue()


def _hook_context(host: str, emitted: bytes) -> str:
    document = cast(Mapping[str, object], json.loads(emitted))
    if host == "cursor":
        context = document.get("additional_context")
    else:
        output = document.get("hookSpecificOutput")
        context = (
            cast(Mapping[str, object], output).get("additionalContext")
            if isinstance(output, dict)
            else None
        )
    return "" if context is None else cast(str, context)


_HOST_SESSIONS = {
    "codex": _CODEX_SESSION,
    "claude": "claude:claude-915",
    "cursor": "cursor:cursor-915",
}


@pytest.mark.parametrize("host", sorted(_HOST_SESSIONS))
def test_observation_only_frontier_motion_is_no_hook_notice_on_any_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    store, commitment = _consented(tmp_path)
    _pending_observation_motion(store, commitment, _HOST_SESSIONS[host])

    emitted = _post_tool_use(host, tmp_path)

    # Observation-health and frontier plumbing remain local/operator-facing (#974).
    assert _hook_context(host, emitted) == ""
    assert b"frontier moved" not in emitted
    assert b"run status" not in emitted


@pytest.mark.parametrize("host", sorted(_HOST_SESSIONS))
def test_pending_advice_is_still_delivered_on_the_next_post_tool_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    """Dropping the notice delays nothing else: pending advice keeps its channel and commit."""

    monkeypatch.delenv("CURSOR_PROJECT_DIR", raising=False)
    store, commitment = _consented(tmp_path)
    _pending_observation_motion(store, commitment, _HOST_SESSIONS[host])
    advice = AdviceDelivery(
        snapshot=cast(AdviceSnapshot, object()),
        item=None,
        delivery_identity="deliver-915",
        text="FinishUP: Unresolved failed command observed. Next: resolve_failed_command.",
    )
    commits: list[str] = []

    def fake_peek(self: LocalObservationStore, workspace: str, **_kwargs: object) -> AdviceDelivery:
        del self, workspace
        return advice

    def fake_commit(
        self: LocalObservationStore, workspace: str, identity: str, **_kwargs: object
    ) -> None:
        del self, workspace
        commits.append(identity)

    monkeypatch.setattr(LocalObservationStore, "peek_advice_for_delivery", fake_peek)
    monkeypatch.setattr(LocalObservationStore, "commit_advice_delivery", fake_commit)

    emitted = cast(Mapping[str, object], json.loads(_post_tool_use(host, tmp_path)))

    context = (
        emitted["additional_context"]
        if host == "cursor"
        else cast(Mapping[str, object], emitted["hookSpecificOutput"])["additionalContext"]
    )
    assert cast(str, context) == advice.text
    assert commits == ["deliver-915"]


# An instruction to call the MCP ``status`` operation; the host-shell ``finishup observe status`` and
# provider status commands are different things and stay allowed.
_STATUS_INSTRUCTION = re.compile(r"\b(?:run|call|read|re-read|check)\s+`?status\b", re.IGNORECASE)


def test_no_per_call_hook_text_tells_the_agent_to_run_status_between_tool_calls() -> None:
    workflow = (_REPOSITORY / "guidance" / "workflow.md").read_text(encoding="utf-8")
    status_row = next(line for line in workflow.splitlines() if line.startswith("| `status` |"))
    # The guidance this pins: status runs at recovery points and before completion claims only.
    assert "Not between routine tool calls." in status_row

    assert not hasattr(observe_hooks, "_frontier_motion_context")
    texts = [
        observation_advice._hook_next_sentence(token)  # pyright: ignore[reportPrivateUsage]
        for token in sorted(observation_advice._VALID_ADVICE_NEXT_ACTIONS)  # pyright: ignore[reportPrivateUsage]
    ]
    assert texts
    for text in texts:
        assert _STATUS_INSTRUCTION.search(text) is None, text


def test_observe_status_reports_pass_timing_in_json_and_text(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_inspection(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("status must not inspect activation without an exact executable")

    monkeypatch.setattr(observe_cli, "inspect_activation", unexpected_inspection)
    _consented(tmp_path)
    observe_hooks.handle_codex_observe(
        event_name="PostToolUse",
        stdin_bytes=_codex("PostToolUse", "apply_patch", "call_5", {"command": ""}, tmp_path),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )

    assert (
        observe_cli.observe_status(workspace=str(tmp_path), json_output=True, _state=tmp_path) == 0
    )
    payload = json.loads(capsys.readouterr().out)
    pass_timings = payload["hook_diagnostics"]["pass_timings"]
    assert pass_timings["status"] == "retained"
    assert pass_timings["measured_from"] == "console_entry"
    (entry,) = pass_timings["entries"]
    assert (entry["host"], entry["event"], entry["path"], entry["count"]) == (
        "codex",
        "PostToolUse",
        "observe",
        1,
    )
    assert set(entry) >= {"p50_ms_at_most", "p95_ms_at_most", "max_ms", "recent", "outcomes"}

    assert (
        observe_cli.observe_status(workspace=str(tmp_path), json_output=False, _state=tmp_path) == 0
    )
    lines = capsys.readouterr().out.splitlines()
    timing_line = next(line for line in lines if line.startswith("hook_pass_timing: "))
    assert "codex PostToolUse observe: n=1 " in timing_line
    assert "percentiles are histogram bucket bounds" in timing_line
    diagnostics_line = next(line for line in lines if line.startswith("hook_diagnostics: "))
    assert "pass_timings" not in diagnostics_line


def test_observe_status_reports_the_tb4n5_local_accounts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Attempt endings, local retention, held rollout rows and delivery lag are exported (tb4n5)."""

    def unexpected_inspection(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("status must not inspect activation without an exact executable")

    monkeypatch.setattr(observe_cli, "inspect_activation", unexpected_inspection)
    _consented(tmp_path)

    assert (
        observe_cli.observe_status(workspace=str(tmp_path), json_output=True, _state=tmp_path) == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["pending_attempt_endings"] == {"counts": {}, "open": 0, "recent": []}
    assert payload["local_retention"] == {"dedup_fence": None, "envelope_ring": None}
    assert payload["held_rollout_items"] == {"count": 0, "oldest_read_at": None}
    assert payload["delivery_lag"]["measured"] == "enqueue_to_accept"
    assert payload["delivery_lag"]["count"] == 0

    assert (
        observe_cli.observe_status(workspace=str(tmp_path), json_output=False, _state=tmp_path) == 0
    )
    lines = capsys.readouterr().out.splitlines()
    assert "pending_attempt_endings: none (open: 0; recent: none)" in lines
    assert "local_retention: none" in lines
    assert "held_rollout_items: 0" in lines
    assert "delivery_lag: no accepted rows measured" in lines


def test_claude_pass_whose_fault_escapes_is_counted_as_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(**_kwargs: object) -> int:
        raise RuntimeError("private detail")

    monkeypatch.setattr(observe_hooks, "_handle_claude_observe", broken)
    with pytest.raises(RuntimeError):
        observe_hooks.handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=b"{}",
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )

    entry = _entries(tmp_path)[("claude", "PostToolUse", "structural")]
    assert cast(Mapping[str, int], entry["outcomes"])["failed"] == 1
