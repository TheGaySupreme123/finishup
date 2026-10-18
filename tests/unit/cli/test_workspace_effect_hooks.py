"""Each host's pre/post tool hooks carry the before/after workspace fact (PR #1080 round 5).

The real host normalizers run with host-shaped payloads, an isolated state directory and no
service. Between the ``PreToolUse`` and ``PostToolUse`` passes the test does what the host's tool
call would do to the workspace; the stored post envelope must then carry the closed
``workspace_effect`` token, and materialization must put it on the observed result.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_materialize import materialize_observation_envelope
from finishup.cli import observe_hooks
from finishup.domain.events import ResultRecordedPayload
from finishup.domain.observation import ObservationEnvelope
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.domain.values import JsonValue
from finishup.domain.workspace_effect import workspace_effect_from_result_summary
from finishup.protocol.canonical import canonical_encode

_TASK = "tsk_00000000-0000-4000-8000-000000001080"


def _codex(event: str, call: str, command: str, **extra: object) -> dict[str, object]:
    # Codex 0.159 hook stdin for unified exec (fixture OUT-004): ``Bash`` with ``{"command"}``,
    # and a post whose ``tool_response`` is the command's output only, sent once it has exited.
    payload: dict[str, object] = {
        "session_id": "01a006a4-1111-4111-8111-000000001080",
        "turn_id": "turn-1",
        "transcript_path": None,
        "cwd": "/ignored",
        "hook_event_name": event,
        "model": "gpt-5",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": call,
    }
    if event == "PostToolUse":
        payload["tool_response"] = ""
    payload.update(extra)
    return payload


def _claude(event: str, call: str, command: str, **extra: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "hook_event_name": event,
        "session_id": "claude-1080",
        "tool_name": "Bash",
        "tool_use_id": call,
        "tool_input": {"command": command},
    }
    if event == "PostToolUse":
        payload["tool_response"] = {"stdout": "", "stderr": "", "interrupted": False}
    payload.update(extra)
    return payload


def _cursor(event: str, call: str, command: str, **extra: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "hook_event_name": event,
        "session_id": "cursor-1080",
        "conversation_id": "cursor-1080-conversation",
        "generation_id": "generation-1080",
        "tool_name": "Shell",
        "tool_use_id": call,
        "tool_input": {"command": command},
    }
    if event == "postToolUse":
        payload["tool_output"] = '{"exitCode":0,"stdout":""}'
    payload.update(extra)
    return payload


Emit = Callable[[str, Mapping[str, object]], None]
Shape = Callable[..., dict[str, object]]


def _host(name: str, workspace: Path, state: Path) -> tuple[Emit, str, str, Shape]:
    def codex(event: str, payload: Mapping[str, object]) -> None:
        assert (
            observe_hooks.handle_observe(
                event_name=None,
                stdin_bytes=json.dumps(payload).encode(),
                stdout=io.BytesIO(),
                workspace=str(workspace),
                _state=state,
                skip_service=True,
            )
            == 0
        )

    def claude(event: str, payload: Mapping[str, object]) -> None:
        assert (
            observe_hooks.handle_claude_observe(
                event_name=event,
                stdin_bytes=canonical_encode(cast(JsonValue, payload)),
                stdout=io.BytesIO(),
                workspace=str(workspace),
                _state=state,
                skip_service=True,
                observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )

    def cursor(event: str, payload: Mapping[str, object]) -> None:
        assert (
            observe_hooks.handle_cursor_observe(
                event_name=event,
                stdin_bytes=canonical_encode(cast(JsonValue, payload)),
                stdout=io.BytesIO(),
                workspace=str(workspace),
                _state=state,
                skip_service=True,
                observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )

    hosts: dict[str, tuple[Emit, str, str, Shape]] = {
        "codex": (codex, "PreToolUse", "PostToolUse", _codex),
        "claude": (claude, "PreToolUse", "PostToolUse", _claude),
        "cursor": (cursor, "preToolUse", "postToolUse", _cursor),
    }
    return hosts[name]


def _setup(tmp_path: Path) -> tuple[Path, Path, str]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "deliverable.txt").write_text("reviewed\n")
    # The state directory sits inside the workspace on purpose: FinishUP's own writes during
    # the hook passes must never read as a workspace change.
    state = workspace / ".finishup-state"
    store = LocalObservationStore(_state=state)
    commitment = store.workspace_commitment(str(workspace.resolve()))
    store.grant_consent(commitment)
    return workspace, state, commitment


def _posts(state: Path, commitment: str) -> list[ObservationEnvelope]:
    return [
        envelope
        for envelope in LocalObservationStore(_state=state).list_envelopes(commitment)
        if envelope.event_kind in {"PostToolUse", "postToolUse"}
    ]


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
@pytest.mark.parametrize(
    "command,change,expected",
    [
        ("date -u", None, "unchanged"),
        ("git status --short", None, "unchanged"),
        ("sed -n '1,5p' deliverable.txt", None, "unchanged"),
        ("python gen.py", "write", "changed"),
        ("ls", "write", "changed"),
    ],
)
def test_each_host_records_the_workspace_effect_of_a_call(
    tmp_path: Path, host: str, command: str, change: str | None, expected: str
) -> None:
    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, shape = _host(host, workspace, state)
    emit(pre, shape(pre, f"{host}-call", command))
    if change == "write":
        (workspace / "deliverable.txt").write_text("rewritten by the call\n")
    emit(post, shape(post, f"{host}-call", command))
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == expected
    # A read-shaped shell call that changed the workspace is never folded into a routine summary.
    if expected != "unchanged":
        assert envelope.structural_payload.get("action") not in {
            "routine_read",
            "routine_read_detailed",
        }
    batch = materialize_observation_envelope(envelope, task_id=_TASK)
    (result,) = [
        cast(ResultRecordedPayload, item.draft.payload)
        for item in batch.drafts
        if item.draft.schema.name == "result_recorded"
    ]
    assert workspace_effect_from_result_summary(result.summary) == expected


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
def test_a_post_without_its_pre_snapshot_is_unavailable(tmp_path: Path, host: str) -> None:
    workspace, state, commitment = _setup(tmp_path)
    emit, _pre, post, shape = _host(host, workspace, state)
    emit(post, shape(post, f"{host}-lonely", "date -u"))
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unavailable"
    # A missing pre-call snapshot is a per-call fact on the result, never a diagnostic row.
    diagnostics = state / "observation" / "hook-diagnostics.jsonl"
    reasons = (
        [json.loads(line)["reason"] for line in diagnostics.read_text().splitlines()]
        if diagnostics.exists()
        else []
    )
    assert not [reason for reason in reasons if reason.startswith("workspace_fingerprint_")]


def test_a_codex_call_still_running_is_unavailable(tmp_path: Path) -> None:
    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, _shape = _host("codex", workspace, state)
    emit(pre, _codex(pre, "codex-running", "python server.py"))
    emit(
        post,
        _codex(
            post,
            "codex-running",
            "python server.py",
            tool_response="Chunk ID: abc\nProcess running with session ID 7\nOutput:\n",
        ),
    )
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unavailable"


def test_a_claude_background_launch_is_unavailable(tmp_path: Path) -> None:
    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, _shape = _host("claude", workspace, state)
    background = {"command": "npm run dev", "run_in_background": True}
    emit(pre, _claude(pre, "claude-bg", "npm run dev", tool_input=background))
    emit(post, _claude(post, "claude-bg", "npm run dev", tool_input=background))
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unavailable"


def test_a_third_party_tool_is_fingerprinted_and_finishup_tools_are_not(tmp_path: Path) -> None:
    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, _shape = _host("claude", workspace, state)
    tool: dict[str, object] = {
        "hook_event_name": pre,
        "session_id": "claude-1080",
        "tool_name": "mcp__files__write_file",
        "tool_use_id": "claude-mcp",
        "tool_input": {"path": "deliverable.txt"},
    }
    emit(pre, tool)
    (workspace / "deliverable.txt").write_text("written by an MCP server\n")
    emit(post, {**tool, "hook_event_name": post, "tool_response": {"content": []}})
    own: dict[str, object] = {
        "hook_event_name": pre,
        "session_id": "claude-1080",
        "tool_name": "mcp__plugin_finishup_finishup__status",
        "tool_use_id": "claude-own",
        "tool_input": {},
    }
    emit(pre, own)
    emit(post, {**own, "hook_event_name": post, "tool_response": {"content": []}})
    posts = {
        envelope.structural_payload["tool_name"]: envelope.structural_payload
        for envelope in _posts(state, commitment)
    }
    assert posts["mcp__files__write_file"]["workspace_effect"] == "changed"
    assert "workspace_effect" not in posts["mcp__plugin_finishup_finishup__status"]


def test_a_host_payload_cannot_supply_the_fact(tmp_path: Path) -> None:
    workspace, state, commitment = _setup(tmp_path)
    emit, _pre, post, _shape = _host("codex", workspace, state)
    emit(post, _codex(post, "codex-forged", "python gen.py", workspace_effect="unchanged"))
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unavailable"


def test_a_pre_snapshot_finished_after_the_host_window_is_withdrawn(tmp_path: Path) -> None:
    """A host may run the call once its pre-hook timeout passes; such a snapshot is not trusted."""

    import time

    from finishup.cli.workspace_effect_hook import workspace_fingerprint_pass

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "file.txt").write_text("reviewed")
    common = {
        "call_identity": "codex\x00session\x00call",
        "workspace_locator": str(workspace),
        "workspace_commitment": "hmac-sha256:" + "a" * 64,
        "key_material": b"k" * 32,
        "observation_root": tmp_path / "observation",
        "complete": True,
    }
    late = workspace_fingerprint_pass(
        "PreToolUse",
        host_deadline=time.monotonic() - 1,
        **common,  # type: ignore[arg-type]
    )
    assert late is not None and (late.effect, late.reason) == ("unavailable", "timeout")
    after = workspace_fingerprint_pass("PostToolUse", **common)  # type: ignore[arg-type]
    assert after is not None and (after.effect, after.reason) == ("unavailable", "timeout")
    on_time = workspace_fingerprint_pass(
        "PreToolUse",
        host_deadline=time.monotonic() + 30,
        **common,  # type: ignore[arg-type]
    )
    assert on_time is None
    after = workspace_fingerprint_pass("PostToolUse", **common)  # type: ignore[arg-type]
    assert after is not None and after.effect == "unchanged"


def test_a_workspace_beyond_the_bound_is_diagnosed_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.adapters import workspace_fingerprint

    workspace, state, commitment = _setup(tmp_path)
    for index in range(20):
        (workspace / f"f{index}").write_text(str(index))
    monkeypatch.setattr(workspace_fingerprint, "MAX_ENTRIES", 5)
    emit, pre, post, shape = _host("claude", workspace, state)
    for call in ("a", "b", "c"):
        emit(pre, shape(pre, call, "date -u"))
        emit(post, shape(post, call, "date -u"))
    posts = _posts(state, commitment)
    assert [envelope.structural_payload["workspace_effect"] for envelope in posts] == [
        "unavailable"
    ] * 3
    diagnostics = state / "observation" / "hook-diagnostics.jsonl"
    reasons = [json.loads(line)["reason"] for line in diagnostics.read_text().splitlines()]
    assert reasons.count("workspace_fingerprint_too_large") == 1


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
@pytest.mark.parametrize(
    "command", ["./server &", "npm run dev & sleep 1", "nohup python worker.py", "setsid ./daemon"]
)
def test_a_command_that_may_outlive_its_call_is_unavailable(
    tmp_path: Path, host: str, command: str
) -> None:
    """A background or detached process can write after the post-call snapshot (PR #1080)."""

    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, shape = _host(host, workspace, state)
    emit(pre, shape(pre, f"{host}-bg", command))
    emit(post, shape(post, f"{host}-bg", command))
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unavailable"


# --- PR #1080 round 6: the round-5 review's host-level cases --------------------------------


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
@pytest.mark.parametrize(
    "directory", ["node_modules", ".venv", "venv", "__pycache__", ".pytest_cache"]
)
def test_a_script_writing_inside_a_dependency_or_cache_directory_is_changed(
    tmp_path: Path, host: str, directory: str
) -> None:
    """Review finding 3: an ordinary script replacing ``<dir>/answer.txt`` is a workspace change."""

    import shlex
    import subprocess
    import sys

    workspace, state, commitment = _setup(tmp_path)
    target = workspace / directory / "answer.txt"
    target.parent.mkdir()
    target.write_text("reviewed")
    (workspace / "generate.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(target.relative_to(workspace))!r}).write_text('UNREVIEWED')\n"
    )
    command = f"{shlex.quote(sys.executable)} generate.py"
    emit, pre, post, shape = _host(host, workspace, state)
    emit(pre, shape(pre, f"{host}-dep", command))
    subprocess.run([sys.executable, "generate.py"], cwd=workspace, check=True)
    emit(post, shape(post, f"{host}-dep", command))
    (envelope,) = _posts(state, commitment)
    assert target.read_text() == "UNREVIEWED"
    assert envelope.structural_payload["workspace_effect"] == "changed"


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
def test_a_launcher_whose_child_outlives_it_is_unavailable(tmp_path: Path, host: str) -> None:
    """Review finding 2: the launcher exits 0, its new-session child writes after the post hook."""

    import shlex
    import sys

    from unit.adapters.test_workspace_fingerprint import (
        _process_table_readable,  # pyright: ignore[reportPrivateUsage]
        launch_lingering_worker,
        release_worker,
    )

    if not _process_table_readable():
        pytest.skip("no readable process table here")
    workspace, state, commitment = _setup(tmp_path)
    command = f"{shlex.quote(sys.executable)} launch.py 5 6"
    emit, pre, post, shape = _host(host, workspace, state)
    emit(pre, shape(pre, f"{host}-launch", command))
    release_write, done_read = launch_lingering_worker(workspace)
    try:
        emit(post, shape(post, f"{host}-launch", command))
        before_release = (workspace / "deliverable.txt").read_text()
    finally:
        release_worker(release_write, done_read)
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unavailable"
    assert before_release == "reviewed\n"
    assert (workspace / "deliverable.txt").read_text() == "LATE UNREVIEWED"


def _late_pass_common(tmp_path: Path) -> dict[str, object]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "answer").write_text("already changed after the host stopped waiting")
    return {
        "call_identity": "late-call",
        "workspace_locator": str(workspace),
        "workspace_commitment": "hmac-sha256:" + "a" * 64,
        "key_material": b"k" * 32,
        "observation_root": tmp_path / "observation",
        "complete": True,
    }


def test_a_late_pre_pass_killed_right_after_storing_leaves_nothing_usable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review finding 4 (interruption boundary): a late capture is never stored at all."""

    import time

    from finishup.adapters.workspace_fingerprint import WorkspaceFingerprintStore
    from finishup.cli.workspace_effect_hook import workspace_fingerprint_pass

    common = _late_pass_common(tmp_path)
    real_store = WorkspaceFingerprintStore._store  # pyright: ignore[reportPrivateUsage]

    def killed_after_store(self: WorkspaceFingerprintStore, path: Path, snapshot: object) -> None:
        real_store(self, path, snapshot)  # type: ignore[arg-type]
        if path.parent.name == "pending":
            raise KeyboardInterrupt("simulated host hook termination")

    monkeypatch.setattr(WorkspaceFingerprintStore, "_store", killed_after_store)
    late = workspace_fingerprint_pass(
        "PreToolUse",
        host_deadline=time.monotonic() - 1,
        **common,  # type: ignore[arg-type]
    )
    assert late is not None and (late.effect, late.reason) == ("unavailable", "timeout")
    after = workspace_fingerprint_pass("PostToolUse", **common)  # type: ignore[arg-type]
    assert after is not None and after.effect == "unavailable"


def test_a_post_pass_racing_a_late_pre_pass_cannot_consume_its_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review finding 4 (interleaving): the post pass runs while the late pre pass is paused."""

    import threading
    import time

    from finishup.adapters.workspace_fingerprint import WorkspaceFingerprintStore
    from finishup.cli.workspace_effect_hook import workspace_fingerprint_pass

    common = _late_pass_common(tmp_path)
    captured = threading.Event()
    release = threading.Event()
    published: list[str] = []
    real_store = WorkspaceFingerprintStore._store  # pyright: ignore[reportPrivateUsage]
    real_walk = WorkspaceFingerprintStore._walk  # pyright: ignore[reportPrivateUsage]

    def store(self: WorkspaceFingerprintStore, path: Path, snapshot: object) -> None:
        if path.parent.name == "pending":
            published.append(path.name)
        real_store(self, path, snapshot)  # type: ignore[arg-type]

    def paused_walk(self: WorkspaceFingerprintStore, *args: object, **kwargs: object) -> object:
        snapshot = real_walk(self, *args, **kwargs)  # type: ignore[arg-type]
        if threading.current_thread().name == "late-pre":
            # The late pre pass has captured; let the post pass run before it continues.
            captured.set()
            assert release.wait(timeout=30)
        return snapshot

    monkeypatch.setattr(WorkspaceFingerprintStore, "_store", store)
    monkeypatch.setattr(WorkspaceFingerprintStore, "_walk", paused_walk)
    results: list[object] = []
    thread = threading.Thread(
        target=lambda: results.append(
            workspace_fingerprint_pass(
                "PreToolUse",
                host_deadline=time.monotonic() - 1,
                **common,  # type: ignore[arg-type]
            )
        ),
        name="late-pre",
    )
    thread.start()
    try:
        assert captured.wait(timeout=30)
        during = workspace_fingerprint_pass("PostToolUse", **common)  # type: ignore[arg-type]
    finally:
        release.set()
        thread.join(timeout=30)
    assert not thread.is_alive()
    assert during is not None and during.effect == "unavailable"
    (late,) = results
    assert getattr(late, "reason", None) == "timeout"
    assert published == []
    after = workspace_fingerprint_pass("PostToolUse", **common)  # type: ignore[arg-type]
    assert after is not None and after.effect == "unavailable"


def test_an_unreadable_process_table_is_unavailable_and_diagnosed_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A host or platform that hides the process table cannot rule out a lingering writer."""

    from types import SimpleNamespace

    from finishup.adapters import process_lifetime

    monkeypatch.setattr(process_lifetime, "sys", SimpleNamespace(platform="sunos5"))
    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, shape = _host("cursor", workspace, state)
    for call in ("a", "b", "c"):
        emit(pre, shape(pre, call, "date -u"))
        emit(post, shape(post, call, "date -u"))
    posts = _posts(state, commitment)
    assert [envelope.structural_payload["workspace_effect"] for envelope in posts] == [
        "unavailable"
    ] * 3
    diagnostics = state / "observation" / "hook-diagnostics.jsonl"
    reasons = [json.loads(line)["reason"] for line in diagnostics.read_text().splitlines()]
    assert reasons.count("workspace_fingerprint_process_table_unreadable") == 1


# --- n7 RC1 (#1105): the Codex 0.159 completion fact ------------------------------------------


def _readings(state: Path, commitment: str) -> dict[str, object]:
    from finishup.adapters.workspace_fingerprint import (
        reading_tally_summary,
        workspace_fingerprint_dir,
    )

    return dict(reading_tally_summary(workspace_fingerprint_dir(state / "observation", commitment)))


def test_a_codex_0159_read_is_unchanged_and_its_outcome_stays_unknown(tmp_path: Path) -> None:
    """The ``Bash`` post is the completion fact; it states no exit, so no success is invented."""

    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, _shape = _host("codex", workspace, state)
    command = "rg -n reviewed deliverable.txt"
    emit(pre, _codex(pre, "call_rg", command))
    emit(post, _codex(post, "call_rg", command, tool_response="1:reviewed\n"))
    (envelope,) = _posts(state, commitment)
    structural = envelope.structural_payload
    assert structural["workspace_effect"] == "unchanged"
    assert "success" not in structural and "exit_status" not in structural
    # A read whose exit Codex has not stated is never folded into a "proven" routine summary.
    assert structural.get("action") not in {"routine_read", "routine_read_detailed"}
    batch = materialize_observation_envelope(envelope, task_id=_TASK)
    (result,) = [
        cast(ResultRecordedPayload, item.draft.payload)
        for item in batch.drafts
        if item.draft.schema.name == "result_recorded"
    ]
    assert result.outcome.value == "unknown"
    assert workspace_effect_from_result_summary(result.summary) == "unchanged"
    tally = _readings(state, commitment)
    assert cast(dict[str, object], tally["all"])["unchanged"] == 1


def test_a_codex_0159_write_is_changed(tmp_path: Path) -> None:
    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, _shape = _host("codex", workspace, state)
    emit(pre, _codex(pre, "call_gen", "python gen.py"))
    (workspace / "deliverable.txt").write_text("rewritten by the call\n")
    emit(post, _codex(post, "call_gen", "python gen.py"))
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "changed"


def test_a_codex_exec_command_spelling_is_not_a_completion_fact(tmp_path: Path) -> None:
    """Only the documented ``Bash`` unified-exec post is the completion fact; nothing else is."""

    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, _shape = _host("codex", workspace, state)
    legacy = {"tool_name": "exec_command", "tool_input": {"cmd": "date -u"}}
    emit(pre, _codex(pre, "call_legacy", "date -u", **legacy))
    emit(post, _codex(post, "call_legacy", "date -u", **legacy))
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unavailable"
    reasons = cast(dict[str, object], _readings(state, commitment)["all"])["unavailable_reasons"]
    assert reasons == {"call_incomplete": 1}


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
@pytest.mark.parametrize(
    "command",
    [
        "curl -s 'https://example.invalid/x?a=1&b=2'",
        "sed 's/reviewed/&!/' deliverable.txt",
        "grep -n '&&' deliverable.txt",
        "cat deliverable.txt 2>&1 | head -1",
    ],
)
def test_a_quoted_ampersand_is_not_a_background_launch(
    tmp_path: Path, host: str, command: str
) -> None:
    """#1089 item 1: shell grammar, not a pattern, decides whether a call backgrounds."""

    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, shape = _host(host, workspace, state)
    emit(pre, shape(pre, f"{host}-quoted", command))
    emit(post, shape(post, f"{host}-quoted", command))
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unchanged"


@pytest.mark.parametrize("command", ["bash -c 'npm run dev &'", 'eval "./server &"'])
def test_an_ampersand_handed_to_a_shell_is_still_a_background_launch(
    tmp_path: Path, command: str
) -> None:
    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, _shape = _host("codex", workspace, state)
    emit(pre, _codex(pre, "call_bg", command))
    emit(post, _codex(post, "call_bg", command))
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unavailable"
    reasons = cast(dict[str, object], _readings(state, commitment)["all"])["unavailable_reasons"]
    assert reasons == {"background_launch": 1}


def test_a_codex_launcher_whose_child_outlives_it_is_process_lingering(tmp_path: Path) -> None:
    """The completion fact is necessary, not sufficient: a lingering child keeps it unavailable."""

    import shlex
    import sys

    from unit.adapters.test_workspace_fingerprint import (
        _process_table_readable,  # pyright: ignore[reportPrivateUsage]
        launch_lingering_worker,
        release_worker,
    )

    if not _process_table_readable():
        pytest.skip("no readable process table here")
    workspace, state, commitment = _setup(tmp_path)
    command = f"{shlex.quote(sys.executable)} launch.py 5 6"
    emit, pre, post, _shape = _host("codex", workspace, state)
    emit(pre, _codex(pre, "call_launch", command))
    release_write, done_read = launch_lingering_worker(workspace)
    try:
        emit(post, _codex(post, "call_launch", command))
    finally:
        release_worker(release_write, done_read)
    (envelope,) = _posts(state, commitment)
    assert envelope.structural_payload["workspace_effect"] == "unavailable"
    tally = _readings(state, commitment)
    reasons = cast(dict[str, object], tally["all"])["unavailable_reasons"]
    assert reasons == {"process_lingering": 1}
    (latest,) = cast(tuple[dict[str, object], ...], tally["recent_readings"])
    assert (latest["reason"], latest["call"]) == ("process_lingering", "call_launch")


def test_cursor_generic_mcp_finishup_spelling_takes_no_snapshot(tmp_path: Path) -> None:
    """#1091 N6: Cursor's ``MCP:<tool>`` spelling of FinishUP's own call is not fingerprinted."""

    workspace, state, commitment = _setup(tmp_path)
    emit, pre, post, _shape = _host("cursor", workspace, state)
    own: dict[str, object] = {
        "hook_event_name": pre,
        "session_id": "cursor-1080",
        "conversation_id": "cursor-1080-conversation",
        "generation_id": "generation-1080",
        "tool_name": "MCP:check",
        "tool_use_id": "cursor-own",
        "tool_input": {},
    }
    emit(pre, own)
    pending = list((state / "observation" / "workspace-fingerprints").rglob("pending/*.bin"))
    assert pending == []
    emit(post, {**own, "hook_event_name": post, "tool_output": '{"content":[]}'})
    (envelope,) = _posts(state, commitment)
    assert "workspace_effect" not in envelope.structural_payload


def test_observe_status_attributes_each_reading_to_its_reason(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``observe status`` names how many calls compared and why the rest did not (n7 RC1).

    JSON carries the bounded tally with each call id; the text is one line of closed tokens and
    counts, never a path or a command.
    """

    from finishup.cli import observe as observe_cli

    workspace, state, _commitment = _setup(tmp_path)
    emit, pre, post, _shape = _host("codex", workspace, state)
    for call, command in (("call_read", "rg -n reviewed ."), ("call_bg", "npm run dev &")):
        emit(pre, _codex(pre, call, command))
        emit(post, _codex(post, call, command))

    assert observe_cli.observe_status(workspace=str(workspace), json_output=True, _state=state) == 0
    readings = json.loads(capsys.readouterr().out)["workspace_effect_readings"]
    assert readings["status"] == "retained"
    assert readings["all"] == {
        "unchanged": 1,
        "changed": 0,
        "unavailable": 1,
        "unavailable_reasons": {"background_launch": 1},
    }
    assert [
        (item["call"], item["effect"], item["reason"]) for item in readings["recent_readings"]
    ] == [
        ("call_read", "unchanged", None),
        ("call_bg", "unavailable", "background_launch"),
    ]

    assert (
        observe_cli.observe_status(workspace=str(workspace), json_output=False, _state=state) == 0
    )
    lines = capsys.readouterr().out.splitlines()
    (line,) = [item for item in lines if item.startswith("workspace_effect: ")]
    assert line.startswith(
        "workspace_effect: unchanged 1, changed 0, unverified 1 (background_launch 1) since "
    )
    assert line.endswith("; last 64 calls kept")
    for private in ("npm", "rg ", "reviewed", str(workspace)):
        assert private not in line
