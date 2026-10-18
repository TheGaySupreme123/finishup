"""The rollout copy of a direct Codex shell call carries its hook copy's identity (n7 RC2, #1106).

Driven by OUT-005 (``observations/codex-shell-call-identity-0.159.0.case.json``): each hook payload
goes through the real hook handler, each rollout row through the real session-stream reader with
the same local store key, and both copies of a call must commit to the same command, segments,
runner class and relative write scope. The exit code is read only from the Codex-written
``function_call_output`` header, and only for the output of a Codex shell call.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any, Final, cast

import pytest

from builders.codex_rollout import encode_lines, function_call, function_call_output, session_meta
from finishup.adapters.importers.codex_jsonl import CodexParsedRecord
from finishup.adapters.integrations.codex_session_stream import (
    CodexSessionStreamLocator,
    SessionStreamReader,
    reconcile_session_stream,
    structural_from_stream_record,
)
from finishup.adapters.integrations.observation_local import (
    STREAM_MAPPING_VERSION,
    LocalObservationStore,
)
from finishup.cli.observe_hooks import command_identity_fields_for_payload, handle_observe
from finishup.cli.runtime_facts import runtime_structural_facts
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationSource,
)
from finishup.domain.observation_selection import command_runner_class
from finishup.domain.values import JsonObject
from finishup.protocol.canonical import JsonValue, canonical_encode
from fixture_loader import load_fixture_json

_CASE: Final = "observations/codex-shell-call-identity-0.159.0.case.json"
_EMPTY: Final = "hmac-sha256:" + "0" * 64
_KEY: Final = b"k" * 32
_IDENTITY_KEYS: Final = (
    "command_commitment",
    "command_segment_commitments",
    "command_composition",
    "runner_class",
    "write_scope",
)


def _case() -> dict[str, Any]:
    return cast(dict[str, Any], load_fixture_json(_CASE))


def _variants() -> list[str]:
    return sorted(cast(dict[str, Any], _case()["input"]["hook"]))


def _identity(structural: JsonObject) -> dict[str, JsonValue]:
    return {
        key: list(value) if isinstance(value, (list, tuple)) else value
        for key in _IDENTITY_KEYS
        if (value := structural.get(key)) is not None
    }


def _stream_rows(tmp_path: Path, key: bytes) -> tuple[ObservationEnvelope, ...]:
    lines = cast(list[dict[str, Any]], _case()["input"]["rollout"]["lines"])
    path = tmp_path / "rollout.jsonl"
    path.write_bytes(
        b"".join(json.dumps(line, separators=(",", ":")).encode() + b"\n" for line in lines)
    )
    reader = SessionStreamReader(
        session_commitment="hmac-sha256:" + "a" * 64,
        profile=None,
        cursor=ObservationCursor(1, 0, 0, _EMPTY, STREAM_MAPPING_VERSION),
        key_material=key,
    )
    return reader.advance(path).envelopes


@pytest.mark.parametrize("variant", _variants())
def test_shell_function_call_carries_the_hook_command_identity(
    tmp_path: Path, variant: str
) -> None:
    case = _case()
    payload = cast(dict[str, Any], case["input"]["hook"][variant]["payload"])
    expected = case["expected"]["calls"][variant]
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    pre = {key: value for key, value in payload.items() if key != "tool_response"}
    pre["hook_event_name"] = "PreToolUse"
    for event, body in (("PreToolUse", pre), ("PostToolUse", payload)):
        assert (
            handle_observe(
                event_name=event,
                stdin_bytes=canonical_encode(cast(JsonValue, body)),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=state,
                skip_service=True,
                source=ObservationSource.CODEX_HOOK,
            )
            == 0
        )
    hook = {
        envelope.event_kind: envelope
        for envelope in LocalObservationStore(_state=state).list_envelopes(workspace)
        if envelope.structural_payload.get("tool_call_id") == expected["tool_call_id"]
    }
    stream = {
        envelope.structural_payload.get("action"): envelope
        for envelope in _stream_rows(tmp_path, store.key_material())
        if envelope.structural_payload.get("tool_call_id") == expected["tool_call_id"]
    }
    call = stream["function_call"]
    hook_pre = _identity(hook["PreToolUse"].structural_payload)
    assert hook_pre["runner_class"] == expected["runner_class"]
    assert hook_pre.get("write_scope") == expected["write_scope"]
    assert _identity(call.structural_payload) == hook_pre
    assert call.structural_payload["tool_name"] == "exec_command"
    # The compound-outcome gap belongs to a result: never to the call's own row.
    assert ObservationGapCode.COMPOUND_OUTCOME_UNAVAILABLE.value not in call.gap_codes
    # The output row names no tool: its header exit is kept only after pairing (below).
    assert "exit_status" not in stream["function_call_output"].structural_payload
    assert "exit_status" not in hook["PostToolUse"].structural_payload
    dumped = json.dumps([dict(item.structural_payload) for item in stream.values()]).encode()
    assert b"PLACEHOLDER" not in dumped and b"pytest" not in dumped


def test_the_paired_output_header_is_the_call_exit(tmp_path: Path) -> None:
    """Reconcile pairs each output with its call and keeps the header's exit for a shell call."""

    case = _case()
    lines = cast(list[dict[str, Any]], case["input"]["rollout"]["lines"])
    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    session_id = "n7-shell-call-identity"
    (sessions / f"rollout-{session_id}.jsonl").write_bytes(encode_lines(*lines))
    store = LocalObservationStore(_state=tmp_path / "state")
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    result = reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )
    assert result["resolved"] is True
    outputs = {
        row.envelope.structural_payload.get("tool_call_id"): row.envelope.structural_payload
        for row in store.list_pending_outbox_rows(workspace)
        if row.envelope.structural_payload.get("action") == "function_call_output"
    }
    for facts in case["expected"]["calls"].values():
        output = outputs[facts["tool_call_id"]]
        assert output.get("tool_name") == "exec_command"
        assert output.get("exit_status") == facts["exit_status"]


def _record(item_type: str, payload: dict[str, Any]) -> CodexParsedRecord:
    return CodexParsedRecord(
        1,
        0,
        200,
        "response_item",
        item_type,
        JsonObject({"type": "response_item", "payload": payload}),
    )


def test_a_legacy_shell_argv_call_commits_like_its_hook() -> None:
    argv = ["bash", "-lc", "python -m pytest -q 2>&1 | tail -5"]
    structural, gaps = structural_from_stream_record(
        _record(
            "function_call",
            {
                "type": "function_call",
                "name": "shell",
                "call_id": "call_argv",
                "arguments": json.dumps({"command": argv}),
            },
        ),
        key_material=_KEY,
    )
    hook = command_identity_fields_for_payload(
        JsonObject({"tool_name": "shell", "tool_input": JsonObject({"command": tuple(argv)})}),
        _KEY,
    )
    assert structural["command_commitment"] == hook["command_commitment"]
    assert list(cast(list[str], structural["command_segment_commitments"])) == list(
        cast(list[str], hook["command_segment_commitments"])
    )
    assert structural["runner_class"] == "test"
    assert ObservationGapCode.COMPOUND_OUTCOME_UNAVAILABLE.value not in gaps


@pytest.mark.parametrize(
    ("item_type", "payload"),
    [
        # A code-mode cell's input is a script, never a command.
        (
            "custom_tool_call",
            {"type": "custom_tool_call", "name": "exec", "call_id": "c1", "input": "pytest -q"},
        ),
        # A poll names a process, not a command.
        (
            "function_call",
            {
                "type": "function_call",
                "name": "write_stdin",
                "call_id": "c2",
                "arguments": json.dumps({"session_id": 7, "chars": "pytest -q\n"}),
            },
        ),
        # Another server's tool whose argument happens to be named ``cmd``.
        (
            "function_call",
            {
                "type": "function_call",
                "name": "mcp__other__run",
                "call_id": "c3",
                "arguments": json.dumps({"cmd": "pytest -q"}),
            },
        ),
        (
            "function_call_output",
            {"type": "function_call_output", "call_id": "c4", "output": "pytest -q"},
        ),
    ],
)
def test_code_mode_cells_polls_mcp_tools_and_outputs_carry_no_command_identity(
    item_type: str, payload: dict[str, Any]
) -> None:
    structural, _gaps = structural_from_stream_record(
        _record(item_type, payload), key_material=_KEY
    )
    for key in _IDENTITY_KEYS:
        assert key not in structural, key


def test_a_shell_call_without_key_material_still_carries_its_runner_class() -> None:
    structural, _gaps = structural_from_stream_record(
        _record(
            "function_call",
            {
                "type": "function_call",
                "name": "exec_command",
                "call_id": "c5",
                "arguments": json.dumps({"cmd": "pytest -q"}),
            },
        )
    )
    assert "command_commitment" not in structural
    assert structural["runner_class"] == command_runner_class({"command": "pytest -q"}) == "test"


@pytest.mark.parametrize(
    ("tool", "output", "exit_status"),
    [
        (
            "exec_command",
            "Chunk ID: ab\nWall time: 0.1 seconds\nProcess exited with code 2\nOutput:\nx\n",
            2,
        ),
        ("exec_command", "Wall time: 0.1 seconds\nProcess exited with code 0\nOutput:", 0),
        ("shell", "Exit code: 101\nWall time: 1.2 seconds\nOutput:\nboom\n", 101),
        # A running process states no exit.
        (
            "exec_command",
            "Chunk ID: ab\nWall time: 10.0 seconds\nProcess running with session ID 4\n"
            "Original token count: 0\nOutput:\n",
            None,
        ),
        # Header text inside the output, or an unknown line before ``Output:``, is not the header.
        ("exec_command", "Output:\nProcess exited with code 0\n", None),
        (
            "exec_command",
            "Wall time: 0.1 seconds\nProcess exited with code 0\nnote\nOutput:\n",
            None,
        ),
        ("exec_command", "Wall time: 0.1 seconds\nProcess exited with code 300\nOutput:\n", None),
        # Only a Codex shell call's output: an MCP or code-mode tool's own text never counts.
        ("mcp__other__run", "Wall time: 0.1 seconds\nProcess exited with code 0\nOutput:\n", None),
        ("write_stdin", "Wall time: 0.1 seconds\nProcess exited with code 0\nOutput:\n", None),
    ],
)
def test_only_a_shell_call_output_header_states_an_exit(
    tmp_path: Path, tool: str, output: str, exit_status: int | None
) -> None:
    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    session_id = "n7-exit-header"
    (sessions / f"rollout-{session_id}.jsonl").write_bytes(
        encode_lines(
            session_meta(),
            function_call(name=tool, call_id="call_x", arguments='{"cmd":"true"}'),
            function_call_output(call_id="call_x", output=output, exit_code=None),
        )
    )
    store = LocalObservationStore(_state=tmp_path / "state")
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment(session_id)
    store.bind_session(workspace, session)
    reconcile_session_stream(
        store,
        workspace_commitment=workspace,
        session_commitment=session,
        codex_session_id=session_id,
        locator=CodexSessionStreamLocator(home),
    )
    outputs = [
        row.envelope.structural_payload
        for row in store.list_pending_outbox_rows(workspace)
        if row.envelope.structural_payload.get("action") == "function_call_output"
    ]
    assert len(outputs) == 1
    assert outputs[0].get("exit_status") == exit_status


_DIFF: Final = "--- a/src/x.py\n+++ b/src/x.py\n@@ -1 +1 @@\n-a\n+# it's\n"


@pytest.mark.parametrize(
    "script",
    [
        "git apply <<'EOF'\n" + _DIFF + "EOF\npytest -q",
        "git apply <<EOF\n" + _DIFF + "EOF",
        "apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: src/x.py\n@@\n-a\n+it's\n"
        "*** End Patch\nEOF\npytest -q",
    ],
    ids=["git-apply-then-test", "git-apply-alone", "apply-patch-then-test"],
)
def test_an_argv_command_execution_names_its_heredoc_patch_write(script: str) -> None:
    """A rollout ``CommandExecution`` records ``['/bin/bash', '-lc', CMD]`` (#1106 r1).

    The heredoc sits inside the quoted script, so the write reader goes through that one host
    shell layer, as the argv shape of OUT-001 (``codex-post-tool-outcomes-0.157.1``) records it.
    """

    record = CodexParsedRecord(
        1,
        0,
        200,
        "event_msg",
        "CommandExecution",
        JsonObject(
            {
                "payload": {
                    "item": {
                        "id": "exec-argv",
                        "type": "CommandExecution",
                        "command": ["/bin/bash", "-lc", script],
                        "exit_code": 0,
                        "status": "completed",
                    },
                    "type": "item_completed",
                }
            }
        ),
    )
    structural, _gaps = structural_from_stream_record(record, key_material=_KEY)
    assert structural["write_scope"] == "workspace"
    if "pytest" in script:
        assert structural["runner_class"] == "test"


def _command_execution(script: str, cwd: object) -> CodexParsedRecord:
    item: dict[str, Any] = {
        "id": "exec-cwd",
        "type": "CommandExecution",
        "command": ["/bin/bash", "-lc", script],
        "exit_code": 0,
        "status": "completed",
    }
    if cwd is not None:
        item["cwd"] = cwd
    return CodexParsedRecord(
        1,
        0,
        200,
        "event_msg",
        "CommandExecution",
        JsonObject({"payload": {"item": item, "type": "item_completed"}}),
    )


@pytest.mark.parametrize(
    ("cwd", "scope"),
    [
        (None, "docs"),
        ("file:///repo", "docs"),
        ("/repo/docs", "docs"),
        ("file:///repo/tests", "workspace"),
        ("file://localhost/repo/tests", "workspace"),
        ("/repo/tests", "workspace"),
        ("file:///elsewhere", "workspace"),
        ("https://example.invalid/repo", "workspace"),
        ("tests", "workspace"),
        (7, "workspace"),
    ],
)
def test_a_command_execution_places_a_relative_write_under_its_own_cwd(
    cwd: object, scope: str
) -> None:
    """correctness-r3-2: the completed item names the directory it ran in (``file:///app``)."""

    from finishup.cli.observe_hooks import (
        _stream_command_facts,  # pyright: ignore[reportPrivateUsage]
    )

    record = _command_execution("printf 'x\\n' > README.md", cwd)
    structural, _gaps = structural_from_stream_record(
        record, key_material=_KEY, command_facts=_stream_command_facts("/repo", "/repo")
    )
    assert structural.get("write_scope") == scope
    # Read outside a hook, only a relative write under a stated directory is claimed.
    outside, _gaps = structural_from_stream_record(record, key_material=_KEY)
    if cwd in {"file:///repo/tests", "/repo/tests"}:
        assert outside.get("write_scope") == "workspace"


@pytest.mark.parametrize(
    ("session_cwd", "scope"),
    [
        ("/repo", "docs"),
        ("/repo/docs", "docs"),
        ("/repo/tests", "workspace"),
        ("/elsewhere", "workspace"),
        (None, "workspace"),
    ],
)
def test_a_stream_call_with_no_workdir_runs_in_the_hooks_session_cwd(
    session_cwd: str | None, scope: str
) -> None:
    """correctness-r4-1: a Codex call that states no ``workdir`` runs in the session ``cwd``.

    The hook copy places ``printf x > README.md`` under that ``cwd`` (a ``tests/`` session makes
    it test data), so the stream copy the same hook reconciles must too, or the action's class
    would depend on which copy arrived first. With no session ``cwd`` known, the write is
    unplaced: an ordinary edit, never documentation.
    """

    from finishup.cli.observe_hooks import (
        _stream_command_facts,  # pyright: ignore[reportPrivateUsage]
    )

    command = "printf x > README.md"
    hook = {"cwd": session_cwd} if session_cwd is not None else {}
    for record in (
        _command_execution(command, None),
        CodexParsedRecord(
            1,
            0,
            200,
            "response_item",
            "function_call",
            JsonObject(
                {
                    "payload": {
                        "type": "function_call",
                        "name": "exec_command",
                        "call_id": "c-r4",
                        "arguments": json.dumps({"cmd": command}),
                    },
                    "type": "response_item",
                }
            ),
        ),
    ):
        facts = _stream_command_facts("/repo", session_cwd)
        structural, _gaps = structural_from_stream_record(
            record, key_material=_KEY, command_facts=facts
        )
        assert structural.get("write_scope") == scope, record.item_type
        # The hook copy of the same call (payload ``cwd``) carries the same class.
        hook_facts = runtime_structural_facts(
            {**hook, "tool_input": {"command": command}},
            tool_name="Bash",
            workspace_locator="/repo",
            inside=lambda value: value.startswith("/repo/"),
            call_directory_unknown=session_cwd is None,
        )
        assert hook_facts.get("write_scope") == scope
        # Read outside a hook, the session ``cwd`` is unknown: never documentation.
        outside, _gaps = structural_from_stream_record(record, key_material=_KEY)
        assert outside.get("write_scope") == "workspace", record.item_type


def _row(call_id: str, name: str, arguments: object) -> bytes:
    payload = {
        "type": "response_item",
        "payload": {
            "type": "function_call",
            "call_id": call_id,
            "name": name,
            "arguments": arguments if type(arguments) is str else json.dumps(arguments),
        },
    }
    return json.dumps(payload).encode() + b"\n"


@pytest.mark.parametrize(
    ("rows", "call_id", "expected"),
    [
        (
            [_row("c1", "exec_command", {"cmd": "x", "workdir": "/w/tests"})],
            "c1",
            (True, "/w/tests"),
        ),
        ([_row("c1", "exec_command", {"cmd": "x"})], "c1", (False, None)),
        ([_row("c1", "exec_command", {"cmd": "x", "workdir": None})], "c1", (False, None)),
        ([_row("c1", "shell", {"command": ["ls"], "workdir": 7})], "c1", (True, None)),
        ([_row("c1", "exec_command", "{not json")], "c1", (True, None)),
        ([_row("c1", "exec_command", {"cmd": "x", "workdir": "/w"})], "c2", None),
        ([_row("c1", "apply_patch", {"workdir": "/w"})], "c1", None),
        ([_row("c10", "exec_command", {"workdir": "/w"})], "c1", None),
        (
            [
                _row("c1", "exec_command", {"cmd": "x", "workdir": "/old"}),
                _row("c2", "exec_command", {"cmd": "y", "workdir": "/w"}),
            ],
            "c1",
            (True, "/old"),
        ),
        ([b'{"partial": \n'], "c1", None),
        ([_row("c1", "exec_command", {"workdir": "/w"})], "bad id!", None),
    ],
)
def test_a_codex_hook_reads_only_its_own_calls_workdir(
    tmp_path: Path, rows: list[bytes], call_id: str, expected: object
) -> None:
    """goal-r3-3: the hook finds its own call's ``function_call`` row; anything else is ``None``."""

    from finishup.adapters.integrations.codex_session_stream import codex_call_workdir

    path = tmp_path / "rollout.jsonl"
    path.write_bytes(b"".join(rows))
    assert codex_call_workdir(path, call_id) == expected
    assert codex_call_workdir(tmp_path / "absent.jsonl", call_id) is None


def test_a_codex_hook_reads_only_the_rollout_tail(tmp_path: Path) -> None:
    from finishup.adapters.integrations import codex_session_stream

    path = tmp_path / "rollout.jsonl"
    early = _row("c1", "exec_command", {"cmd": "x", "workdir": "/w"})
    filler = b'{"type":"event_msg","payload":{"x":"' + b"a" * (2 << 20) + b'"}}\n'
    path.write_bytes(early + filler)
    assert codex_session_stream.codex_call_workdir(path, "c1") is None
    path.write_bytes(filler + early)
    assert codex_session_stream.codex_call_workdir(path, "c1") == (True, "/w")
