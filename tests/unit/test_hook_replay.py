"""The hook replay harness rebuilds host payloads faithfully and compares runs honestly (#1083).

``scripts/hook_replay.py`` feeds recorded hook payloads through two provisioned builds. These cases
hold its pure parts: the Codex payloads it rebuilds from a rollout, the native sessions it takes
from the repository's recorded shapes, the environment every instance process gets, the budgets it
pins, and the comparison that may rename only values a single run generated.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

from finishup.cli import observe_hooks

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "hook_replay.py"
_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "observations"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("hook_replay", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["hook_replay"] = module
    spec.loader.exec_module(module)
    return module


_MODULE = _load()


def _line(kind: str, payload: dict[str, Any]) -> str:
    return json.dumps({"payload": payload, "timestamp": "2026-10-16T10:00:00.000Z", "type": kind})


def _rollout() -> list[str]:
    return [
        _line("session_meta", {"cwd": "/app", "id": "sess-1", "runtime_workspace_roots": ["/app"]}),
        _line(
            "turn_context",
            {
                "approval_policy": "never",
                "cwd": "/app",
                "model": "gpt-test",
                "sandbox_policy": {"type": "danger-full-access"},
                "turn_id": "turn-1",
                "workspace_roots": ["/app"],
            },
        ),
        _line(
            "response_item",
            {
                "content": [
                    {
                        "text": "<environment_context>/app</environment_context>",
                        "type": "input_text",
                    }
                ],
                "role": "user",
                "type": "message",
            },
        ),
        _line(
            "response_item",
            {
                "content": [{"text": "Fix the bug", "type": "input_text"}],
                "role": "user",
                "type": "message",
            },
        ),
        _line(
            "response_item",
            {
                "arguments": json.dumps({"cmd": "pytest -q"}),
                "call_id": "c1",
                "name": "exec_command",
                "type": "function_call",
            },
        ),
        _line(
            "response_item",
            {
                "arguments": json.dumps({"view": "compact"}),
                "call_id": "c2",
                "name": "status",
                "namespace": "mcp__finishup",
                "type": "function_call",
            },
        ),
        _line(
            "response_item",
            {
                "arguments": json.dumps({"chars": ""}),
                "call_id": "c3",
                "name": "write_stdin",
                "type": "function_call",
            },
        ),
        _line(
            "response_item",
            {
                "call_id": "c1",
                "output": "Process exited with code 1\nOutput:\nFAILED\n",
                "type": "function_call_output",
            },
        ),
        _line(
            "response_item",
            {
                "call_id": "c2",
                "output": 'Wall time: 0.1 seconds\nOutput:\n{"ok":false}',
                "type": "function_call_output",
            },
        ),
        _line("response_item", {"call_id": "c3", "output": "", "type": "function_call_output"}),
        _line(
            "response_item",
            {
                "content": [{"text": "Done.", "type": "output_text"}],
                "role": "assistant",
                "type": "message",
            },
        ),
    ]


def test_codex_callbacks_follow_the_rollout_and_its_recorded_shapes() -> None:
    items, transcript = _MODULE.codex_corpus(
        _rollout(), name="codex1", workspace="codex1", max_calls=10
    )
    labels = [item["label"].split("/", 3)[3] for item in items]
    # Parallel calls: both Pre callbacks fire before either output lands; write_stdin has no
    # recorded hook shape in this repository and is not invented.
    assert labels == [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse/Bash",
        "PreToolUse/mcp__finishup__status",
        "PostToolUse/Bash",
        "PostToolUse/mcp__finishup__status",
        "Stop",
        "SessionEnd",
    ]
    payloads = [json.loads(item["stdin"]) for item in items]
    assert payloads[1]["prompt"] == "Fix the bug"
    assert payloads[2]["tool_input"] == {"command": "pytest -q"}
    assert payloads[2]["permission_mode"] == "bypassPermissions"
    assert payloads[2]["cwd"] == _MODULE.WORKSPACE
    assert payloads[2]["transcript_path"] == _MODULE.TRANSCRIPT
    assert payloads[4]["tool_response"] == "Process exited with code 1\nOutput:\nFAILED\n"
    assert payloads[5]["tool_response"] == {
        "content": [{"text": '{"ok":false}', "type": "text"}],
        "isError": True,
        "structuredContent": {"ok": False},
    }
    assert payloads[6]["last_assistant_message"] == ""
    assert payloads[6]["stop_hook_active"] is False
    uptos = [item["transcript"]["upto"] for item in items]
    assert uptos == sorted(uptos)
    assert len(transcript) == uptos[-1]
    assert json.loads(transcript[0])["payload"]["cwd"] == _MODULE.WORKSPACE
    assert json.loads(transcript[1])["payload"]["workspace_roots"] == [_MODULE.WORKSPACE]


def test_codex_start_calls_also_reach_the_start_correlation_hook() -> None:
    rollout = _rollout()
    rollout[5] = rollout[5].replace('"name": "status"', '"name": "start"')
    items, _ = _MODULE.codex_corpus(rollout, name="codex1", workspace="codex1", max_calls=10)
    argvs = [item["argv"] for item in items if "PostToolUse" in item["label"]]
    assert ["hooks", "post-tool-use"] in argvs


def test_native_sessions_replay_the_recorded_fixture_payloads() -> None:
    claude = _MODULE.claude_corpus()
    recorded = json.loads((_FIXTURES / "claude-code-bash-outcomes.case.json").read_text())
    expected = _MODULE._rehome(
        recorded["input"]["hook"]["post_tool_use_bash"]["payload"], "/workspace/project"
    )
    assert json.loads(claude[4]["stdin"]) == expected
    assert claude[4]["argv"][-1] == recorded["input"]["observation_profile"]
    cursor = _MODULE.cursor_corpus()
    recorded = json.loads((_FIXTURES / "cursor-shell-outcomes.case.json").read_text())
    expected = _MODULE._rehome(
        recorded["input"]["hook"]["post_tool_use_shell_with_exit_code"]["payload"],
        "/workspace/project",
    )
    assert json.loads(cursor[3]["stdin"]) == expected
    assert cursor[0]["argv"] == ["hooks", "startup-context", "--host", "cursor"]


def test_every_instance_process_gets_a_private_home_and_no_keychain(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for name in (
        "FINISHUP_ISOLATED_ROOT",
        "YOETZ_ISOLATED_ROOT",
        "PYTHONPATH",
        "CODEX_HOME",
        "CLAUDE_CONFIG_DIR",
    ):
        monkeypatch.setenv(name, "/ambient")
    env = _MODULE.instance_env(tmp_path, {"CURSOR_PROJECT_DIR": "/w"})
    assert env["HOME"] == str(tmp_path)
    assert env["CODEX_HOME"] == str(tmp_path / ".codex")
    assert env["PYTHON_KEYRING_BACKEND"] == "keyring.backends.fail.Keyring"
    assert env["CURSOR_PROJECT_DIR"] == "/w"
    assert not {
        "FINISHUP_ISOLATED_ROOT",
        "YOETZ_ISOLATED_ROOT",
        "PYTHONPATH",
        "CLAUDE_CONFIG_DIR",
    } & set(env)


def test_pinned_budgets_name_real_hook_budgets_and_only_widen_them() -> None:
    for name, value in _MODULE.PINNED_HOOK_BUDGETS.items():
        shipped = getattr(observe_hooks, name)
        assert type(shipped) is type(value), name
        assert value >= shipped, name


def _run(stdout: list[str], history: list[Any]) -> dict[str, Any]:
    return {
        "items": [
            {
                "label": f"codex/x/{index}",
                "workspace": "w",
                "returncode": 0,
                "stdout": text,
                "stderr": "",
                "host": "codex",
                "event": "PreToolUse",
                "elapsed_ms": float(index + 1),
            }
            for index, text in enumerate(stdout)
        ],
        "ledgers": {"w": {"mapped": True, "history": history, "head_frontier": None}},
    }


def test_runs_that_differ_only_in_generated_values_compare_identical() -> None:
    first = _run(
        [
            "task tsk_11111111-1111-4111-8111-111111111111 at 2026-10-16T10:00:00.000Z",
            "ses_22222222-2222-4222-8222-222222222222",
        ],
        [{"event_id": "evt_33333333-3333-4333-8333-333333333333", "digest": "sha256:" + "a" * 64}],
    )
    second = _run(
        [
            "task tsk_44444444-4444-4444-8444-444444444444 at 2026-10-16T11:22:33.456Z",
            "ses_55555555-5555-4555-8555-555555555555",
        ],
        [{"event_id": "evt_66666666-6666-4666-8666-666666666666", "digest": "sha256:" + "b" * 64}],
    )
    result = _MODULE.compare_runs(first, second)
    assert result["identical"], result


def test_a_value_both_runs_saw_is_compared_verbatim() -> None:
    shared = "sha256:" + "c" * 64
    other = "sha256:" + "d" * 64
    first = _run([f"{shared} then {other}"], [])
    second = _run([f"{other} then {shared}"], [])
    result = _MODULE.compare_runs(first, second)
    assert not result["identical"]
    assert result["workspaces"]["w"]["mismatches"][0]["part"].endswith("stdout")


def test_a_changed_reused_identifier_is_not_hidden_by_renaming() -> None:
    # Each run reuses one generated id twice; the second run points its second use elsewhere.
    first = _run(
        ["tsk_11111111-1111-4111-8111-111111111111", "tsk_11111111-1111-4111-8111-111111111111"], []
    )
    second = _run(
        ["tsk_44444444-4444-4444-8444-444444444444", "tsk_77777777-7777-4777-8777-777777777777"], []
    )
    assert not _MODULE.compare_runs(first, second)["identical"]


def test_text_outside_generated_values_must_match_exactly() -> None:
    first = _run(['{"decision":"block"}'], [])
    second = _run(["{}"], [])
    assert not _MODULE.compare_runs(first, second)["identical"]


def test_latency_reports_nearest_rank_percentiles() -> None:
    old = _run([str(index) for index in range(10)], [])
    new = _run([str(index) for index in range(10)], [])
    for item in new["items"]:
        item["elapsed_ms"] = cast(float, item["elapsed_ms"]) - 1
    rows = {(row["host"], row["event"]): row for row in _MODULE.latency_table(old, new)}
    row = rows[("codex", "PreToolUse")]
    assert row["n"] == 10
    assert row["old_median_ms"] == 5.5 and row["new_median_ms"] == 4.5
    assert row["old_p90_ms"] == 9.0 and row["new_p90_ms"] == 8.0
    assert row["median_saved_ms"] == 1.0


def test_probe_versions_are_the_current_request_schemas() -> None:
    from finishup.protocol import schemas

    current = schemas.request_result_schema_versions(schemas.load_schema_catalog())
    for name, version in _MODULE._PROBE_VERSIONS.items():
        assert current[name] == version, name


def test_a_probe_prints_every_error_field_from_a_fresh_process() -> None:
    import subprocess

    items = {item["label"]: item for item in _MODULE.probe_items()}
    assert all(item["runner"] == "python" for item in items.values())
    outcomes: dict[str, dict[str, Any]] = {}
    for label in (
        "probe/coverage-valid",
        "probe/start-unpaired-workspace-ref",
        "probe/float-value",
    ):
        done = subprocess.run(
            [sys.executable, "-I", "-c", _MODULE._PROBE],
            input=items[label]["stdin"].encode(),
            capture_output=True,
            check=True,
        )
        outcomes[label] = json.loads(done.stdout)
    assert outcomes["probe/coverage-valid"] == {"outcome": "accepted"}
    paired = outcomes["probe/start-unpaired-workspace-ref"]
    assert paired["outcome"] == "SchemaInstanceInvalid"
    assert ["external_ref"] in [path for path, _reason in paired["location_reasons"]]
    assert outcomes["probe/float-value"] == {
        "outcome": "ProtocolValueError",
        "reason_code": "float_forbidden",
    }


def test_which_events_share_a_millisecond_is_not_compared() -> None:
    first = _run(["at 2026-10-16T10:00:00.001Z", "at 2026-10-16T10:00:00.001Z"], [])
    second = _run(["at 2026-10-16T11:00:00.001Z", "at 2026-10-16T11:00:00.002Z"], [])
    assert _MODULE.compare_runs(first, second)["identical"]


def test_the_paused_background_passes_exist_on_the_service() -> None:
    from finishup.service.daemon import ServiceDaemon

    for name in (
        "_bounded_observation_sweep",
        "_bounded_lineage_recovery",
        "_bounded_coordination_sweep",
    ):
        assert name in _MODULE._SERVICE_BOOTSTRAP
        assert callable(getattr(ServiceDaemon, name))
    compile(_MODULE._SERVICE_BOOTSTRAP, "service-bootstrap", "exec")
    compile(_MODULE._PINNED_BOOTSTRAP, "pinned-bootstrap", "exec")
