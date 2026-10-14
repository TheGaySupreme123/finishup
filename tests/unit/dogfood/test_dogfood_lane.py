"""Bounded unit coverage for the unattended dogfood lane tooling (scripts/dogfood_ci).

The lane itself needs a runner, host CLIs, and a disposable instance; these tests lock the pure
pieces that decide what a lane reports: result parsing, frontier discovery, redaction, the
connection-mode choice per platform, the verdict rule (agent failure is not catastrophic unless
strict), and the pseudo-terminal ceremony driver against a harmless stand-in child.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import textwrap
from pathlib import Path
from types import ModuleType
from typing import Any, cast
from unittest.mock import Mock

import pytest

_SCRIPTS = Path(__file__).parents[3] / "scripts" / "dogfood_ci"


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"dogfood_ci_{name}", _SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"dogfood_ci_{name}"] = module
    spec.loader.exec_module(module)
    return module


_LANE = _load("lane")
_CEREMONY = _load("ceremony")


def _namespace(tmp_path: Path, **overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "host": "codex",
        "checkout": str(tmp_path / "checkout"),
        "base": str(tmp_path / "base"),
        "tag": "df",
        "evidence": str(tmp_path / "evidence"),
        "python": "3.14.6",
        "host_path": None,
        "host_config_root": None,
        "project": str(tmp_path / "project"),
        "connection_mode": "auto",
        "semantic_model": "accounts/fireworks/models/minimax-m3",
        "agent_model": None,
        "cursor_model": "gpt-5.6-luna-low",
        "agent_timeout": 5.0,
        "strict_agent": False,
        "skip_agent": True,
        "skip_restart": True,
        "allow_dirty": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_find_frontier_prefers_result_frontier_and_parse_json_tolerates_prefix() -> None:
    result = {
        "subject_frontier": {"sequence": "1", "head_digest": "sha256:" + "a" * 64},
        "result_frontier": {"sequence": "2", "head_digest": "sha256:" + "b" * 64},
    }
    assert _LANE._find_frontier(result) == result["result_frontier"]
    assert _LANE._find_frontier(
        {"nested": [{"frontier": {"sequence": "0", "head_digest": "genesis"}}]}
    ) == {
        "sequence": "0",
        "head_digest": "genesis",
    }
    assert _LANE._find_frontier({"x": 1}) is None
    assert _LANE._parse_json('human line\n{"ok": true}\n') == {"ok": True}
    assert _LANE._parse_json("not json") is None
    assert _LANE._find_key({"a": {"b": {"c": 3}}}, "c") == 3


def test_semantic_provenance_provider_supports_current_and_legacy_field_names() -> None:
    assert _LANE._semantic_provenance_provider({"provider": "fireworks"}) == "fireworks"
    assert _LANE._semantic_provenance_provider({"provider_id": "fireworks"}) == "fireworks"
    assert (
        _LANE._semantic_provenance_provider(
            {"provider": "fireworks", "runtime": {"provider_id": "legacy"}}
        )
        == "legacy"
    )
    assert _LANE._semantic_provenance_provider({"provider": ""}) is None


def test_redaction_masks_secrets_and_runner_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DOGFOOD_VAULT_PASSPHRASE", "vault-pass-phrase-0123456789")
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw_secret_key_value")
    monkeypatch.setenv("DOGFOOD_OS_PASSWORD", "os-password-value")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path / "runner-temp"))
    monkeypatch.delenv("CURSOR_API_KEY", raising=False)
    lane = _LANE.Lane(_namespace(tmp_path))
    text = (
        f"key fw_secret_key_value pass vault-pass-phrase-0123456789 os os-password-value "
        f"home {Path.home()} base {tmp_path / 'base'} temp {tmp_path / 'runner-temp'}/x"
    )
    redacted = cast(str, lane.redact(text))
    assert "fw_secret_key_value" not in redacted
    assert "vault-pass-phrase" not in redacted
    assert "os-password-value" not in redacted
    assert str(tmp_path / "base") not in redacted
    assert "<base>" in redacted and "<runner-temp>/x" in redacted and "<home>" in redacted
    nested = lane._redact_obj({"a": ["fw_secret_key_value", {"b": str(tmp_path / "base")}]})
    assert nested == {"a": ["<secret>", {"b": "<base>"}]}


@pytest.mark.parametrize(
    ("host", "system", "os_password", "expected"),
    [
        ("codex", "Darwin", "", "setup-run"),
        ("codex", "Linux", "", "setup-run"),
        ("claude", "Linux", "pw", "setup-run"),
        ("claude", "Linux", "", "plugin-dir"),
        ("claude", "Darwin", "pw", "plugin-dir"),
        ("cursor", "Linux", "pw", "setup-run"),
        ("cursor", "Darwin", "pw", "mcp-only"),
        ("cursor", "Linux", "", "mcp-only"),
    ],
)
def test_connection_mode_follows_platform_and_os_presence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    host: str,
    system: str,
    os_password: str,
    expected: str,
) -> None:
    monkeypatch.setattr(_LANE.platform, "system", lambda: system)
    if os_password:
        monkeypatch.setenv("DOGFOOD_OS_PASSWORD", os_password)
    else:
        monkeypatch.delenv("DOGFOOD_OS_PASSWORD", raising=False)
    lane = _LANE.Lane(_namespace(tmp_path, host=host))
    assert lane.connection_mode == expected
    explicit = _LANE.Lane(_namespace(tmp_path, host=host, connection_mode="none"))
    assert explicit.connection_mode == "none"


def test_verdict_treats_agent_failure_as_non_catastrophic_unless_strict(tmp_path: Path) -> None:
    lane = _LANE.Lane(_namespace(tmp_path))
    (tmp_path / "evidence").mkdir()
    lane._record("provision", "install", status="pass")
    lane._record("agent_run", "native", status="fail", exit_code=3, reason="agent_exit_3")
    lane.agent = {"ran": True, "exit_code": 3, "mapping_present": False}
    body = cast(dict[str, Any], lane.report())
    assert body["verdict"] == {
        "catastrophic": False,
        "catastrophic_steps": [],
        "failed_steps": ["agent_run"],
        "agent_ok": False,
        "strict_agent": False,
        "green": True,
    }
    lane.strict_agent = True
    assert lane.report()["verdict"]["green"] is False
    unrun = _LANE.Lane(_namespace(tmp_path, strict_agent=True, skip_agent=False))
    unrun._record("provision", "install", status="pass")
    assert unrun.report()["verdict"]["green"] is False, "strict mode must not pass an unrun agent"
    skipped = _LANE.Lane(_namespace(tmp_path, strict_agent=True, skip_agent=True))
    skipped._record("provision", "install", status="pass")
    assert skipped.report()["verdict"]["green"] is True
    lane._record("observe_drain_after_probe_verdict", "ledger", status="fail", reason="not_drained")
    strict_off = _LANE.Lane(_namespace(tmp_path))
    strict_off.steps = lane.steps
    strict_off.agent = lane.agent
    verdict = strict_off.report()["verdict"]
    assert verdict["catastrophic"] is True
    assert verdict["catastrophic_steps"] == ["observe_drain_after_probe_verdict"]
    assert verdict["green"] is False
    written = json.loads((tmp_path / "evidence" / "01-provision.json").read_text())
    assert written["step"] == "provision"


def test_catastrophic_diagnostics_are_detected_from_hook_reasons() -> None:
    status = {
        "hook_diagnostics": {"reasons": {"service_unavailable": 2, "workspace_unconsented": 1}}
    }
    assert _LANE.Lane._catastrophic_diagnostics(status) == ["service_unavailable"]
    assert _LANE.Lane._catastrophic_diagnostics({"hook_diagnostics": {"reasons": {}}}) == []
    assert _LANE.Lane._catastrophic_diagnostics(None) == ["observe_status_unavailable"]


def test_prompt_names_tool_hint_workspace_and_external_ref() -> None:
    prompt = _LANE._PROMPT_TEMPLATE.format(
        tool_hint="plugin_yoetz_yoetz", workspace="/w", external_ref="native-claude-1"
    )
    assert "plugin_yoetz_yoetz" in prompt and "'/w'" in prompt and "native-claude-1" in prompt
    assert "single_atomic_change" in prompt and prompt.endswith("Do not create or edit files.")
    assert "task_statement set to this entire user message verbatim" in prompt
    assert "YOETZ_NATIVE_BINDING" in prompt and "exactly these keys" in prompt
    assert "recovering incomplete pages before continuing" in prompt
    assert "mode 'semantic_required'" in prompt


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
@pytest.mark.parametrize("mapped", [False, True])
def test_ledger_probe_supplies_full_statement_on_create_and_attach(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: str, mapped: bool
) -> None:
    from yoetz.protocol.models import StartRequestModel

    lane = _LANE.Lane(_namespace(tmp_path, host=host))
    lane.launcher = tmp_path / "isolated-runtime" / "bin" / "yoetz"
    session_id = "ses_5b435d29-4f13-4349-b301-b385af5fc4ea"
    monkeypatch.setattr(
        lane,
        "_hook_session_start_probe",
        Mock(return_value={"session_id": session_id} if mapped else None),
    )
    captured: list[dict[str, Any]] = []

    def start_only(*args: object, **kwargs: Any) -> tuple[None, None]:
        assert args[0] == "ledger_start"
        captured.append(json.loads(kwargs["stdin"]))
        return None, None

    monkeypatch.setattr(lane, "_yoetz", start_only)
    lane.phase_ledger_probe()
    request = StartRequestModel.model_validate(captured[0])
    assert request.mode == ("attach" if mapped else "create")
    assert request.task_statement == _LANE._LEDGER_TASK_STATEMENT
    assert request.task_statement != request.task_title
    if mapped:
        assert request.session_id == session_id


_CHILD = textwrap.dedent(
    """
    import sys
    sys.stdout.write("Yoetz trusted foreground ceremony\\n")
    sys.stdout.write("Passphrase (16-1024 UTF-8 bytes; no control characters): ")
    sys.stdout.flush()
    first = sys.stdin.readline().strip()
    sys.stdout.write("Confirm passphrase (16-1024 UTF-8 bytes; no control characters): ")
    sys.stdout.flush()
    second = sys.stdin.readline().strip()
    sys.stdout.write("Decision [approve/deny]: ")
    sys.stdout.flush()
    decision = sys.stdin.readline().strip()
    ok = first == second == "correct-horse-battery-staple" and decision == "approve"
    sys.stdout.write('{"state": "%s"}\\n' % ("ready" if ok else "rejected"))
    raise SystemExit(0 if ok else 3)
    """
)


@pytest.mark.skipif(sys.platform == "win32", reason="pty is POSIX-only")
def test_ceremony_driver_answers_prompts_once_and_masks_secrets(tmp_path: Path) -> None:
    child = tmp_path / "child.py"
    child.write_text(_CHILD, encoding="utf-8")
    replies = [
        _CEREMONY.Reply(r"Decision \[approve/deny\]: ", "approve", secret=False),
        _CEREMONY.Reply(r"Passphrase \(", "correct-horse-battery-staple"),
        _CEREMONY.Reply(r"Confirm passphrase", "correct-horse-battery-staple"),
    ]
    result = _CEREMONY.run_ceremony([sys.executable, str(child)], replies, timeout=30.0)
    assert result.exit_code == 0, result.transcript
    assert result.timed_out is False
    assert result.answered == [
        r"Passphrase \(",
        r"Confirm passphrase",
        r"Decision \[approve/deny\]: ",
    ]
    assert "correct-horse-battery-staple" not in result.transcript
    assert "<secret>" in result.transcript
    assert '{"state": "ready"}' in result.transcript


@pytest.mark.skipif(sys.platform == "win32", reason="pty is POSIX-only")
def test_ceremony_driver_reports_timeout_and_child_failure(tmp_path: Path) -> None:
    sleeper = tmp_path / "sleep.py"
    sleeper.write_text("import time; time.sleep(30)\n", encoding="utf-8")
    result = _CEREMONY.run_ceremony([sys.executable, str(sleeper)], [], timeout=0.5)
    assert result.timed_out is True and result.exit_code == 124
    child = tmp_path / "child.py"
    child.write_text(_CHILD, encoding="utf-8")
    wrong = [
        _CEREMONY.Reply(r"Passphrase \(", "one-passphrase-value-here"),
        _CEREMONY.Reply(r"Confirm passphrase", "another-passphrase-value"),
        _CEREMONY.Reply(r"Decision \[approve/deny\]: ", "approve", secret=False),
    ]
    failed = _CEREMONY.run_ceremony([sys.executable, str(child)], wrong, timeout=30.0)
    assert failed.exit_code == 3 and '{"state": "rejected"}' in failed.transcript


def test_prompt_regexes_match_the_product_prompts_as_rendered() -> None:
    """Lock every lane regex to the real prompt text, rendered the way the product renders it."""

    import re

    import typer
    from typer.testing import CliRunner

    from yoetz.cli import unlock

    app = typer.Typer()

    @app.command()
    def render() -> None:
        typer.confirm("Use this recommended privacy policy?", default=True)
        typer.prompt("Choose a privacy option", default="3")
        typer.confirm("Create this exact privacy proposal (Assisted review)?", default=False)

    assert render is not None
    rendered = CliRunner().invoke(app, [], input="n\n3\ny\n").output
    for pattern in (
        _LANE.PROMPT_PRIVACY_RECOMMENDED,
        _LANE.PROMPT_PRIVACY_CHOICE,
        _LANE.PROMPT_PRIVACY_CREATE,
    ):
        assert re.search(pattern, rendered), (pattern, rendered)

    privacy_source = (Path(__file__).parents[3] / "src/yoetz/cli/privacy_setup.py").read_text(
        "utf-8"
    )
    for literal in (
        '"Use this recommended privacy policy?"',
        '"Choose a privacy option"',
        'f"Create this exact privacy proposal ({_RECIPE_LABELS[recipe]})?"',
    ):
        assert literal in privacy_source, literal

    passphrase_prompt = cast(str, getattr(unlock, "_passphrase_prompt")("Passphrase"))
    confirm_prompt = cast(str, getattr(unlock, "_passphrase_prompt")("Confirm passphrase"))
    assert re.search(_LANE.PROMPT_PASSPHRASE, passphrase_prompt)
    assert re.search(_LANE.PROMPT_CONFIRM_PASSPHRASE, confirm_prompt)
    assert not re.search(_LANE.PROMPT_CONFIRM_PASSPHRASE, passphrase_prompt)

    sources = {
        "unlock": (Path(__file__).parents[3] / "src/yoetz/cli/unlock.py").read_text("utf-8"),
        "privacy_control": (
            Path(__file__).parents[3] / "src/yoetz/cli/privacy_control.py"
        ).read_text("utf-8"),
        "linux_presence": (
            Path(__file__).parents[3] / "src/yoetz/adapters/integrations/linux_artifact_presence.py"
        ).read_text("utf-8"),
    }
    assert '"Provider credential: "' in sources["unlock"]
    assert re.search(_LANE.PROMPT_PROVIDER_CREDENTIAL, "Provider credential: ")
    assert '"Decision [approve/deny]: "' in sources["unlock"]
    assert '"Decision [approve/deny/edit]: "' in sources["privacy_control"]
    assert re.search(_LANE.PROMPT_DECISION, "Decision [approve/deny]: ")
    assert re.search(_LANE.PROMPT_DECISION, "Decision [approve/deny/edit]: ")
    assert 'f"Password for {account}: "' in sources["linux_presence"]
    assert re.search(_LANE.PROMPT_PAM_PASSWORD, "Password for runner: ")


_NATIVE_IDS = {
    "task_id": "tsk_00000000-0000-4000-8000-000000000001",
    "session_id": "ses_00000000-0000-4000-8000-000000000002",
    "writer_id": "wri_00000000-0000-4000-8000-000000000003",
}
_NATIVE_START_FRONTIER = {"sequence": "1", "head_digest": "sha256:" + "a" * 64}


def _native_binding(*, frontier: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        **_NATIVE_IDS,
        "frontier": dict(frontier or _NATIVE_START_FRONTIER),
    }


def _native_output(
    host: str,
    text: str,
    *,
    binding: dict[str, Any] | None = None,
) -> str:
    if host == "codex":
        return "\n".join(
            json.dumps(event)
            for event in [
                {"type": "turn.started"},
                {"type": "item.completed", "item": {"type": "agent_message", "text": text}},
                {"type": "turn.completed"},
            ]
        )
    result = text
    if binding is not None:
        result = f"YOETZ_NATIVE_BINDING {json.dumps(binding, separators=(',', ':'))}\n{text}"
    return json.dumps({"type": "result", "subtype": "success", "is_error": False, "result": result})


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
@pytest.mark.parametrize(
    "text,expected",
    [
        ("DONE", True),
        ("Coverage limitation disclosed. DONE", True),
        ("Probe completed.\n\nDONE\n", True),
        ("The required Yoetz MCP tools are not available in this session.", False),
        ("NOT_DONE", False),
        ("   ", False),
        ('The prompt says "DONE".', False),
        ("DONE\nCoverage limitation: check_not_recorded.", True),
    ],
)
def test_native_completion_requires_standalone_marker_in_final_response(
    host: str, text: str, expected: bool
) -> None:
    assert _LANE._native_done(host, _native_output(host, text)) is expected


@pytest.mark.parametrize("host", ["claude", "cursor"])
def test_native_result_error_and_malformed_output_cannot_supply_completion(host: str) -> None:
    for output in [
        "DONE",
        '{"result":"DONE"}',
        "[]",
        "not json",
        _native_output(host, "DONE") + "bad",
    ]:
        assert _LANE._native_done(host, output) is False
    result = json.loads(_native_output(host, "DONE"))
    result["is_error"] = True
    assert _LANE._native_done(host, json.dumps(result)) is False
    result["is_error"] = False
    result["subtype"] = "error_max_turns"
    assert _LANE._native_done(host, json.dumps(result)) is False


@pytest.mark.parametrize("host", ["claude", "cursor"])
def test_native_binding_marker_is_a_strict_locator(host: str) -> None:
    output = _native_output(host, "DONE", binding=_native_binding())
    parsed = _LANE._native_binding_marker(host, output)
    assert parsed is not None
    assert parsed["source"] == "final_marker"
    assert parsed["task_id"] == _NATIVE_IDS["task_id"]
    assert parsed["frontier"] == _NATIVE_START_FRONTIER
    assert _LANE._native_binding_marker(host, _native_output(host, "DONE")) is None
    marker = json.loads(output)["result"].splitlines()[0]
    malformed = _native_output(
        host,
        "DONE",
        binding={**_native_binding(), "unexpected": True},
    )
    assert _LANE._native_binding_marker(host, malformed) is None
    with_source = _native_output(host, "DONE", binding={**_native_binding(), "source": "fake"})
    assert _LANE._native_binding_marker(host, with_source) is None
    duplicate_key_payload = (
        '{"task_id":"'
        + _NATIVE_IDS["task_id"]
        + '","task_id":"'
        + _NATIVE_IDS["task_id"]
        + '","session_id":"'
        + _NATIVE_IDS["session_id"]
        + '","writer_id":"'
        + _NATIVE_IDS["writer_id"]
        + '","frontier":{"sequence":"1","head_digest":"sha256:'
        + "a" * 64
        + '"}}'
    )
    duplicate_key = json.dumps(
        {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "result": f"YOETZ_NATIVE_BINDING {duplicate_key_payload}\nDONE",
        }
    )
    assert _LANE._native_binding_marker(host, duplicate_key) is None
    duplicate = json.loads(output)
    duplicate["result"] = f"{marker}\n{marker}\nDONE"
    assert _LANE._native_binding_marker(host, json.dumps(duplicate)) is None


def test_codex_completion_ignores_tool_output_and_requires_completed_turn() -> None:
    tool_done = json.dumps(
        {
            "type": "item.completed",
            "item": {"type": "command_execution", "aggregated_output": "DONE"},
        }
    )
    assert _LANE._native_done("codex", tool_done + '\n{"type":"turn.completed"}') is False
    good = _native_output("codex", "DONE")
    assert _LANE._native_done("codex", good.rsplit("\n", 1)[0]) is False
    for suffix in [
        '{"type":"turn.failed"}',
        '{"type":"error"}',
        '{"type":"turn.started"}',
        '{"type":"item.completed","item":{"type":"agent_message","text":"Unavailable"}}',
        "malformed",
    ]:
        assert _LANE._native_done("codex", good + "\n" + suffix) is False


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029"])
def test_codex_completion_keeps_unicode_separators_inside_json_records(separator: str) -> None:
    final = f"Coverage{separator}is bounded.\nDONE"
    output = _native_output("codex", final).replace(json.dumps(separator)[1:-1], separator) + "\n"
    assert _LANE._native_done("codex", output) is True
    workflow = _codex_probe_output(final).replace(json.dumps(separator)[1:-1], separator) + "\n"
    assert _LANE._codex_workflow_completed(workflow) is True
    # The same scalar outside a JSON string is malformed input, not an empty line.
    assert _LANE._native_done("codex", output + separator + "\n") is False
    assert _LANE._codex_workflow_completed(workflow + separator + "\n") is False
    record = {"ok": True, "message": f"one{separator}record"}
    prefixed = "Preparing result\n" + json.dumps(record, ensure_ascii=False) + "\n"
    assert _LANE._parse_json(prefixed) == record


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
@pytest.mark.parametrize("done", [False, True])
def test_native_phase_requires_completion_even_with_preexisting_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    host: str,
    done: bool,
) -> None:
    lane = _LANE.Lane(_namespace(tmp_path, host=host, strict_agent=True, skip_agent=False))
    lane.evidence.mkdir()
    monkeypatch.setattr(lane, "_agent_command", Mock(return_value=(["native"], {}, None)))
    output = _native_output(host, "DONE" if done else "Yoetz MCP tools unavailable")
    if host == "codex" and done:
        output = _codex_probe_output("Coverage is bounded; the probe completed.")
    monkeypatch.setattr(lane, "_run", Mock(return_value=(0, output, "", 1)))
    monkeypatch.setattr(lane, "_observe_status", Mock(return_value={"mapping_present": True}))
    monkeypatch.setattr(lane, "_observe_drain", Mock(return_value=None))
    monkeypatch.setattr(lane, "_yoetz", Mock(return_value=(0, {})))
    lane.phase_native_agent()
    verdict = lane.report()["verdict"]
    expected = done if host == "codex" else False
    assert verdict["agent_ok"] is expected
    assert verdict["green"] is expected
    step = next(s for s in lane.steps if s.name == "agent_run")
    assert step.status == ("pass" if expected else "fail")
    assert step.reason == (None if expected else "agent_completion_missing")
    if host != "codex":
        verification = lane.agent["native_provider_verification"]
        assert verification["reason"] == "native_binding_marker_missing"
    lane.strict_agent = False
    assert lane.report()["verdict"]["green"] is True
    assert lane.report()["verdict"]["agent_ok"] is expected


@pytest.mark.parametrize("host", ["codex", "claude", "cursor"])
def test_native_launch_resolves_pinned_runtime_before_ambient_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    host: str,
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "ambient-bin"))
    lane = _LANE.Lane(_namespace(tmp_path, host=host, host_path="/synthetic/host"))
    lane.launcher = tmp_path / "disposable" / "runtime" / "bin" / "yoetz"
    lane.fireworks_key = "synthetic-provider-key"
    lane.cursor_key = "synthetic-cursor-key"
    argv, env, reason = lane._agent_command()
    assert argv is not None and reason is None
    assert env["PATH"].split(_LANE.os.pathsep) == [
        str(lane.launcher.parent),
        str(tmp_path / "ambient-bin"),
    ]
    child = _LANE._clean_env(env, drop=_LANE._LANE_SECRET_ENV)
    assert child["PATH"] == env["PATH"]
    assert "DOGFOOD_VAULT_PASSPHRASE" not in child
    assert "DOGFOOD_OS_PASSWORD" not in child
    assert "--dangerously-bypass-approvals-and-sandbox" not in argv
    assert "--approve-for-me" not in argv


def test_codex_setup_run_grants_only_project_check_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    codex_home = tmp_path / "codex-home"
    lane = _LANE.Lane(
        _namespace(
            tmp_path,
            host="codex",
            connection_mode="setup-run",
            host_config_root=str(codex_home),
        )
    )
    lane.launcher = tmp_path / "isolated-runtime" / "bin" / "yoetz"
    lane.project.mkdir(parents=True)
    lane.evidence.mkdir(parents=True)
    lane.fireworks_key = "synthetic-provider-key"
    monkeypatch.setattr(lane, "_write_codex_provider_config", Mock())
    digest = "sha256:" + "a" * 64
    calls: list[tuple[str, list[str]]] = []
    admission_envs: dict[str, dict[str, str] | None] = {}

    responses: dict[str, dict[str, Any]] = {
        "host_preview": {
            "plan": {
                "request_id": "req_setup",
                "preview_digest": "sha256:" + "b" * 64,
                "requires_os_presence": False,
                "host_version": "0.157.1",
            }
        },
        "host_accept": {"outcome": "completed"},
        "host_status": {},
        "codex_mcp_status": {},
        "codex_admission_preview": {
            "preview_digest": digest,
            "route": {"observed": True, "owner": "external", "route_profile": "policy"},
        },
        "codex_admission_grant": {
            "host": "codex",
            "action": "grant",
            "state_after": "present",
        },
        "codex_admission_status": {
            "admission": {"state": "present", "entries": [{"detail": "external"}]}
        },
    }

    def fake_yoetz(
        name: str, _phase: str, args: list[str], **kwargs: Any
    ) -> tuple[Mock, dict[str, Any]]:
        calls.append((name, args))
        if name.startswith("codex_admission_"):
            admission_envs[name] = kwargs.get("env")
        return Mock(exit_code=0), responses[name]

    monkeypatch.setattr(lane, "_yoetz", fake_yoetz)
    lane._connect_setup_run("connect")

    assert [name for name, _ in calls] == [
        "host_preview",
        "host_accept",
        "host_status",
        "codex_mcp_status",
        "codex_admission_preview",
        "codex_admission_grant",
        "codex_admission_status",
    ]
    grant_argv = calls[5][1]
    assert grant_argv[grant_argv.index("--preview-digest") + 1] == digest
    assert grant_argv[grant_argv.index("--project-root") + 1] == str(lane.project)
    assert admission_envs == {
        "codex_admission_preview": {"CODEX_HOME": str(codex_home)},
        "codex_admission_grant": {"CODEX_HOME": str(codex_home)},
        "codex_admission_status": {"CODEX_HOME": str(codex_home)},
    }
    assert lane.identity["codex_admission"] == {
        "owner": "external",
        "route_profile": "policy",
        "state": "present",
        "tool": "check",
    }


def test_codex_setup_run_does_not_admit_unpermitted_private_recipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lane = _LANE.Lane(_namespace(tmp_path, host="codex", connection_mode="setup-run"))
    lane.launcher = tmp_path / "isolated-runtime" / "bin" / "yoetz"
    lane.project.mkdir(parents=True)
    lane.evidence.mkdir(parents=True)
    calls: list[str] = []

    responses: dict[str, dict[str, Any]] = {
        "host_preview": {
            "plan": {
                "request_id": "req_setup",
                "preview_digest": "sha256:" + "b" * 64,
                "requires_os_presence": False,
            }
        },
        "host_accept": {"outcome": "completed"},
        "host_status": {},
        "codex_mcp_status": {},
    }

    def fake_yoetz(
        name: str, _phase: str, _args: list[str], **_kwargs: Any
    ) -> tuple[Mock, dict[str, Any]]:
        calls.append(name)
        return Mock(exit_code=0), responses[name]

    monkeypatch.setattr(lane, "_yoetz", fake_yoetz)
    lane._connect_setup_run("connect")

    assert "codex_admission_preview" not in calls
    assert next(step for step in lane.steps if step.name == "codex_admission").reason == (
        "FIREWORKS_API_KEY_unset"
    )


@pytest.mark.parametrize("terminal", ["retry_pending", "pass_limit"])
def test_drain_observes_background_completion_before_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal: str,
) -> None:
    lane = _LANE.Lane(_namespace(tmp_path))
    lane.evidence.mkdir()
    pending = {"terminal": terminal, "pending_after": 7}
    drained = {"terminal": "drained", "pending_after": 0}
    invoke = Mock(side_effect=[(Mock(exit_code=0), pending), (Mock(exit_code=0), drained)])
    monkeypatch.setattr(lane, "_yoetz", invoke)
    monkeypatch.setattr(_LANE.time, "sleep", Mock())
    assert lane._observe_drain("drain", "native", fatal=False) == drained
    assert invoke.call_count == 2
    assert lane.steps[-1].status == "pass"
    assert lane.steps[-1].summary["polls"] == 2


@pytest.mark.parametrize(
    "result",
    [None, {"terminal": "service_unavailable"}, {"terminal": "drained", "pending_after": 1}],
)
def test_drain_does_not_retry_invalid_or_nonretryable_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    result: dict[str, object] | None,
) -> None:
    lane = _LANE.Lane(_namespace(tmp_path))
    lane.evidence.mkdir()
    invoke = Mock(return_value=(Mock(exit_code=0), result))
    monkeypatch.setattr(lane, "_yoetz", invoke)
    lane._observe_drain("drain", "native", fatal=False)
    assert invoke.call_count == 1
    assert lane.steps[-1].status == "fail"


def test_drain_deadline_never_turns_pending_into_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lane = _LANE.Lane(_namespace(tmp_path))
    lane.evidence.mkdir()
    invoke = Mock(
        return_value=(Mock(exit_code=0), {"terminal": "retry_pending", "pending_after": 7})
    )
    monkeypatch.setattr(lane, "_yoetz", invoke)
    monkeypatch.setattr(_LANE.time, "monotonic", Mock(side_effect=[0.0, 0.0, 60.0, 60.0]))
    monkeypatch.setattr(_LANE.time, "sleep", Mock())
    lane._observe_drain("drain", "native", fatal=False)
    assert invoke.call_count == 1
    assert lane.steps[-1].status == "fail"
    assert lane.steps[-1].reason == "not_drained"


def test_drain_nonzero_exit_cannot_claim_drained(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lane = _LANE.Lane(_namespace(tmp_path))
    lane.evidence.mkdir()
    invoke = Mock(return_value=(Mock(exit_code=1), {"terminal": "drained", "pending_after": 0}))
    monkeypatch.setattr(lane, "_yoetz", invoke)
    lane._observe_drain("drain", "native", fatal=False)
    assert invoke.call_count == 1
    assert lane.steps[-1].status == "fail"


def _codex_probe_events() -> list[dict[str, Any]]:
    binding = {"task_id": "tsk_probe", "session_id": "ses_probe", "writer_id": "wri_probe"}
    values: list[tuple[str, dict[str, Any], dict[str, Any]]] = [
        ("start", {}, {"ok": True, **binding}),
        (
            "publish_work",
            binding,
            {
                "ok": True,
                **binding,
                "outcome": "accepted",
                "accepted_events": [
                    {"schema_name": "plan_published", "projection_status": "projected"}
                ],
            },
        ),
        (
            "check",
            binding,
            {
                "ok": True,
                "task_id": "tsk_probe",
                "session_id": "ses_probe",
                "semantic_status": "succeeded",
            },
        ),
        (
            "receipt",
            binding,
            {
                "ok": True,
                "task_id": "tsk_probe",
                "session_id": "ses_probe",
                "receipt_id": "rcp_probe",
            },
        ),
    ]
    return [
        {
            "type": "item.completed",
            "item": {
                "type": "mcp_tool_call",
                "server": "yoetz",
                "tool": tool,
                "arguments": dict(args),
                "status": "completed",
                "error": None,
                "result": {"structured_content": result},
            },
        }
        for tool, args, result in values
    ]


def _codex_probe_output(final: str, events: list[dict[str, Any]] | None = None) -> str:
    return "\n".join(
        json.dumps(event)
        for event in [
            {"type": "turn.started"},
            *(events if events is not None else _codex_probe_events()),
            {"type": "item.completed", "item": {"type": "agent_message", "text": final}},
            {"type": "turn.completed"},
        ]
    )


@pytest.mark.parametrize(
    "final",
    ["DONE", "DONE — coverage is bounded.", "The probe finished; a coverage limitation remains."],
)
def test_codex_completion_uses_correlated_mcp_results_not_wording(final: str) -> None:
    assert _LANE._codex_workflow_completed(_codex_probe_output(final)) is True
    assert _LANE._codex_workflow_completed(_native_output("codex", "DONE")) is False


@pytest.mark.parametrize("omitted", [0, 1, 2, 3])
def test_codex_workflow_requires_every_successful_step(omitted: int) -> None:
    events = _codex_probe_events()
    del events[omitted]
    assert _LANE._codex_workflow_completed(_codex_probe_output("DONE", events)) is False


@pytest.mark.parametrize(
    "mutation",
    [
        "other_server",
        "in_progress",
        "error",
        "not_ok",
        "wrong_session",
        "wrong_writer",
        "wrong_result_writer",
        "wrong_task",
        "no_plan",
        "dry_run",
        "no_receipt",
    ],
)
def test_codex_workflow_rejects_uncorrelated_or_unaccepted_results(mutation: str) -> None:
    events = _codex_probe_events()
    item = events[1]["item"]
    result = item["result"]["structured_content"]
    if mutation == "other_server":
        item["server"] = "other"
    elif mutation == "in_progress":
        item["status"] = "in_progress"
    elif mutation == "error":
        item["error"] = {"message": "failed"}
    elif mutation == "not_ok":
        result["ok"] = False
    elif mutation == "wrong_session":
        item["arguments"]["session_id"] = "ses_other"
    elif mutation == "wrong_writer":
        item["arguments"]["writer_id"] = "wri_other"
    elif mutation == "wrong_result_writer":
        result["writer_id"] = "wri_other"
    elif mutation == "wrong_task":
        events[3]["item"]["arguments"]["task_id"] = "tsk_other"
    elif mutation == "no_plan":
        result["accepted_events"] = []
    elif mutation == "dry_run":
        result["outcome"] = "dry_run"
    elif mutation == "no_receipt":
        del events[3]["item"]["result"]["structured_content"]["receipt_id"]
    assert _LANE._codex_workflow_completed(_codex_probe_output("DONE", events)) is False


def test_codex_workflow_requires_exact_statement_and_terminal_check() -> None:
    events = _codex_probe_events()
    events[0]["item"]["arguments"]["task_statement"] = "full probe request"
    checked = events[2]["item"]["result"]["structured_content"]
    output = _codex_probe_output("DONE", events)
    assert _LANE._codex_workflow_completed(output, "full probe request") is False
    checked["review_input_manifest"] = {
        "schema": "yoetz.review-input-manifest/1",
        "phase": "provider_bound",
        "specification": {
            "status": "complete",
            "revision": 1,
            "item_ids": ["statement"],
            "content_bytes": len(b"full probe request"),
            "content_digest": "sha256:" + hashlib.sha256(b"full probe request").hexdigest(),
        },
    }
    output = _codex_probe_output("DONE", events)
    assert _LANE._codex_workflow_completed(output, "full probe request") is True
    assert _LANE._codex_workflow_completed(output, "changed probe request") is False
    events[2]["item"]["result"]["structured_content"]["semantic_status"] = "awaiting_human"
    assert _LANE._codex_workflow_completed(_codex_probe_output("DONE", events)) is False


@pytest.mark.parametrize(
    "suffix", ['{"type":"turn.failed"}', '{"type":"turn.started"}', "bad json"]
)
def test_codex_workflow_requires_completed_native_turn(suffix: str) -> None:
    assert _LANE._codex_workflow_completed(_codex_probe_output("DONE") + "\n" + suffix) is False


@pytest.mark.parametrize(
    "defect",
    [None, "composed", "missing", "title_only", "digest", "length", "revision", "selection"],
)
def test_semantic_specification_requires_exact_provider_bound_input(defect: str | None) -> None:
    statement = "Complete request with Unicode: שלום\u2028second line"
    raw = statement.encode("utf-8")
    specification: dict[str, Any] = {
        "status": "complete",
        "content_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "content_bytes": len(raw),
        "revision": 3,
        "item_ids": ["task-statement"],
    }
    manifest: dict[str, Any] = {
        "schema": "yoetz.review-input-manifest/1",
        "phase": "provider_bound",
        "specification": specification,
    }
    result: dict[str, Any] = {"review_input_manifest": manifest}
    if defect == "composed":
        manifest["phase"] = "composed"
    elif defect == "missing":
        result.clear()
    elif defect == "title_only":
        specification["status"] = "title_only"
    elif defect == "digest":
        specification["content_digest"] = "sha256:" + "0" * 64
    elif defect == "length":
        specification["content_bytes"] = len(statement)
    elif defect == "revision":
        specification["revision"] = None
    elif defect == "selection":
        specification["item_ids"] = []
    assert _LANE._specification_manifest_matches(result, statement) is (defect is None)


@pytest.mark.parametrize(
    "item_ids",
    [
        ["task-statement", "task-statement"],
        ["task statement"],
        ["x" * 129],
        ["task-statement"] * 65,
    ],
)
def test_semantic_specification_rejects_untyped_or_unbounded_item_ids(
    item_ids: list[str],
) -> None:
    statement = "typed item IDs"
    raw = statement.encode("utf-8")
    result = {
        "review_input_manifest": {
            "schema": "yoetz.review-input-manifest/1",
            "phase": "provider_bound",
            "specification": {
                "status": "complete",
                "content_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "content_bytes": len(raw),
                "revision": 1,
                "item_ids": item_ids,
            },
        }
    }
    assert _LANE._specification_manifest_matches(result, statement) is False


def _provider_bound_history_manifest(
    statement: str, *, digest: str | None = None
) -> dict[str, Any]:
    raw = statement.encode("utf-8")
    section = {
        "status": "missing",
        "content_bytes": 0,
        "content_digest": None,
        "item_ids": [],
        "omission_reasons": ["not_selected"],
        "omitted_refs": [],
        "source_refs": [],
        "revision": None,
    }
    return {
        "schema": "yoetz.review-input-manifest/1",
        "phase": "provider_bound",
        "specification": {
            "status": "complete",
            "revision": 4,
            "item_ids": ["task-statement"],
            "content_bytes": len(raw),
            "content_digest": digest or "sha256:" + hashlib.sha256(raw).hexdigest(),
            "omission_reasons": [],
            "omitted_refs": [],
            "source_refs": ["task-statement"],
        },
        "current_diff": section,
        "caller_evidence": section,
        "latest_verification": section,
        "prior_finding_context": section,
        "missing_inputs": [],
        "selected_item_count": 1,
        "selected_excerpt_bytes": len(raw),
        "omitted_item_count": 0,
    }


def _history_item(
    schema_name: str,
    sequence: str,
    *,
    publication_channel: str,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    versions = {
        "session_opened": "1.2.0",
        "plan_published": "1.0.0",
        "check_recorded": "1.3.0",
        "receipt_recorded": "1.0.0",
    }
    actors = {
        "session_opened": "harness:dogfood-native",
        "plan_published": "harness:dogfood-native",
        "check_recorded": "yoetz.engine",
        "receipt_recorded": "yoetz.engine",
    }
    item: dict[str, Any] = {
        "event_id": f"evt_00000000-0000-4000-8000-{int(sequence):012d}",
        "schema_name": schema_name,
        "schema_version": versions[schema_name],
        "actor_id": actors[schema_name],
        "publication_channel": publication_channel,
        "ingestion_sequence": sequence,
        "occurred_at": "2026-10-03T12:00:00.000Z",
        "accepted_at": "2026-10-03T12:00:00.000Z",
        "occurred_at_consistency": "within_forward_skew_allowance",
        "projection_status": "projected",
        "summary_code": schema_name,
    }
    if manifest is not None:
        item["review_input_manifest"] = manifest
    return item


def _history_status_page(
    ids: dict[str, str],
    frontier: dict[str, str],
    items: list[dict[str, Any]],
    next_cursor: str | None,
) -> dict[str, Any]:
    return {
        "ok": True,
        **ids,
        "requested_frontier": dict(frontier),
        "page": {"items": items, "next_cursor": next_cursor},
    }


def _history_fixture(
    statement: str,
    *,
    current_items: list[dict[str, Any]],
    current_frontier: dict[str, str] | None = None,
    next_cursor: str | None = None,
    second_page: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    marker = _native_binding()
    marker_frontier = cast(dict[str, str], marker["frontier"])
    current = current_frontier or {
        "sequence": "9",
        "head_digest": "sha256:" + "b" * 64,
    }
    responses = [
        _history_status_page(_NATIVE_IDS, marker_frontier, [], None),
        _history_status_page(_NATIVE_IDS, current, current_items, next_cursor),
    ]
    if second_page is not None:
        responses.append(second_page)
    return marker, responses


def test_native_provider_history_reads_marked_session_without_postrun_attach(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    statement = "Claude/Cursor provider-bound statement with Unicode: שלום"
    lane = _LANE.Lane(_namespace(tmp_path, host="claude"))
    lane.evidence.mkdir()
    current = {"sequence": "9", "head_digest": "sha256:" + "b" * 64}
    items = [
        _history_item("session_opened", "2", publication_channel="cooperative_mcp"),
        _history_item("plan_published", "3", publication_channel="cooperative_mcp"),
        _history_item(
            "check_recorded",
            "5",
            publication_channel="engine_derived",
            manifest=_provider_bound_history_manifest(statement),
        ),
        _history_item("receipt_recorded", "7", publication_channel="engine_derived"),
    ]
    marker, responses = _history_fixture(statement, current_items=items, current_frontier=current)
    calls: list[tuple[str, dict[str, Any]]] = []

    def operator(
        name: str, _phase: str, _args: list[str], **kwargs: Any
    ) -> tuple[Mock, dict[str, Any]]:
        calls.append((name, json.loads(kwargs["stdin"])))
        return Mock(exit_code=0), responses.pop(0)

    monkeypatch.setattr(lane, "_yoetz", operator)
    assert lane._verify_native_provider_statement("native", statement, marker) is True
    assert [name for name, _ in calls] == ["native_history_marker_frontier", "native_history_1"]
    assert all("mode" not in request for _, request in calls)
    assert calls[0][1]["at_frontier"] == marker["frontier"]["sequence"]
    assert "filter" not in calls[1][1]
    assert calls[1][1]["session_id"] == _NATIVE_IDS["session_id"]
    assert lane.native_provider_verification["plan_sequence"] == "3"
    assert lane.native_provider_verification["first_provider_bound_sequence"] == "5"
    assert lane.native_provider_verification["receipt_sequence"] == "7"
    assert lane.steps[-1].status == "pass"


def test_native_provider_history_rejects_fake_marker_without_native_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lane = _LANE.Lane(_namespace(tmp_path, host="cursor"))
    lane.evidence.mkdir()
    marker, responses = _history_fixture(
        "missing native events",
        current_items=[_history_item("session_opened", "2", publication_channel="cooperative_mcp")],
    )
    calls: list[str] = []

    def operator(
        name: str, _phase: str, _args: list[str], **kwargs: Any
    ) -> tuple[Mock, dict[str, Any]]:
        calls.append(name)
        if name.startswith("native_history"):
            return Mock(exit_code=0), responses.pop(0)
        return Mock(exit_code=0), {}

    monkeypatch.setattr(lane, "_yoetz", operator)
    assert (
        lane._verify_native_provider_statement("native", "missing native events", marker) is False
    )
    assert calls == ["native_history_marker_frontier", "native_history_1"]
    assert lane.native_provider_verification["reason"] == "native_plan_absent"


def test_native_provider_history_ignores_rows_at_or_before_marker_frontier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A complete older session history must not prove a fresh native run."""

    statement = "fresh native statement"
    lane = _LANE.Lane(_namespace(tmp_path, host="claude"))
    lane.evidence.mkdir()
    marker = _native_binding(frontier={"sequence": "7", "head_digest": "sha256:" + "7" * 64})
    old_history = [
        _history_item("plan_published", "2", publication_channel="cooperative_mcp"),
        _history_item(
            "check_recorded",
            "3",
            publication_channel="engine_derived",
            manifest=_provider_bound_history_manifest(statement),
        ),
        _history_item("receipt_recorded", "4", publication_channel="engine_derived"),
    ]
    responses = iter(
        [
            _history_status_page(_NATIVE_IDS, marker["frontier"], [], None),
            _history_status_page(
                _NATIVE_IDS,
                {"sequence": "8", "head_digest": "sha256:" + "8" * 64},
                [
                    *old_history,
                    _history_item("session_opened", "8", publication_channel="cooperative_mcp"),
                ],
                None,
            ),
        ]
    )
    monkeypatch.setattr(
        lane,
        "_yoetz",
        Mock(side_effect=[(Mock(exit_code=0), response) for response in responses]),
    )

    assert lane._verify_native_provider_statement("native", statement, marker) is False
    assert lane.native_provider_verification["reason"] == "native_plan_absent"


def test_native_provider_history_requires_receipt_and_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    statement = "receipt is required"
    lane = _LANE.Lane(_namespace(tmp_path, host="claude"))
    lane.evidence.mkdir()
    marker = _native_binding()
    current = {"sequence": "9", "head_digest": "sha256:" + "c" * 64}
    base = [
        _history_item("session_opened", "2", publication_channel="cooperative_mcp"),
        _history_item("plan_published", "3", publication_channel="cooperative_mcp"),
        _history_item(
            "check_recorded",
            "5",
            publication_channel="engine_derived",
            manifest=_provider_bound_history_manifest(statement),
        ),
    ]
    responses = iter(
        [
            _history_status_page(_NATIVE_IDS, marker["frontier"], [], None),
            _history_status_page(_NATIVE_IDS, current, base, None),
        ]
    )
    monkeypatch.setattr(
        lane,
        "_yoetz",
        Mock(side_effect=[(Mock(exit_code=0), response) for response in responses]),
    )
    assert lane._verify_native_provider_statement("native", statement, marker) is False
    assert lane.native_provider_verification["reason"] == "native_receipt_absent"

    wrong_order = [
        *base,
        _history_item("receipt_recorded", "4", publication_channel="engine_derived"),
    ]
    responses = iter(
        [
            _history_status_page(_NATIVE_IDS, marker["frontier"], [], None),
            _history_status_page(_NATIVE_IDS, current, wrong_order, None),
        ]
    )
    lane.native_provider_verification = {}
    monkeypatch.setattr(
        lane,
        "_yoetz",
        Mock(side_effect=[(Mock(exit_code=0), response) for response in responses]),
    )
    assert lane._verify_native_provider_statement("native", statement, marker) is False
    verification = cast(dict[str, Any], getattr(lane, "native_provider_verification", {}))
    assert verification["reason"] == "native_workflow_order_invalid"


def test_native_provider_history_rejects_first_manifest_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    statement = "exact statement"
    lane = _LANE.Lane(_namespace(tmp_path, host="claude"))
    lane.evidence.mkdir()
    marker = _native_binding()
    current = {"sequence": "9", "head_digest": "sha256:" + "d" * 64}
    items = [
        _history_item("session_opened", "2", publication_channel="cooperative_mcp"),
        _history_item("plan_published", "3", publication_channel="cooperative_mcp"),
        _history_item(
            "check_recorded",
            "5",
            publication_channel="engine_derived",
            manifest=_provider_bound_history_manifest(statement, digest="sha256:" + "0" * 64),
        ),
        _history_item("receipt_recorded", "7", publication_channel="engine_derived"),
    ]
    responses = iter(
        [
            _history_status_page(_NATIVE_IDS, marker["frontier"], [], None),
            _history_status_page(_NATIVE_IDS, current, items, None),
        ]
    )
    monkeypatch.setattr(
        lane,
        "_yoetz",
        Mock(side_effect=[(Mock(exit_code=0), response) for response in responses]),
    )
    assert lane._verify_native_provider_statement("native", statement, marker) is False
    assert lane.native_provider_verification["reason"] == "native_provider_bound_manifest_mismatch"


def test_native_provider_history_rejects_later_valid_check_after_early_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A later matching check cannot hide the first provider-bound check's mismatch."""

    statement = "first provider-bound check wins"
    lane = _LANE.Lane(_namespace(tmp_path, host="cursor"))
    lane.evidence.mkdir()
    marker = _native_binding()
    current = {"sequence": "9", "head_digest": "sha256:" + "d" * 64}
    items = [
        _history_item("session_opened", "2", publication_channel="cooperative_mcp"),
        _history_item("plan_published", "3", publication_channel="cooperative_mcp"),
        _history_item(
            "check_recorded",
            "5",
            publication_channel="engine_derived",
            manifest=_provider_bound_history_manifest(statement, digest="sha256:" + "0" * 64),
        ),
        _history_item(
            "check_recorded",
            "6",
            publication_channel="engine_derived",
            manifest=_provider_bound_history_manifest(statement),
        ),
        _history_item("receipt_recorded", "7", publication_channel="engine_derived"),
    ]
    responses = iter(
        [
            _history_status_page(_NATIVE_IDS, marker["frontier"], [], None),
            _history_status_page(_NATIVE_IDS, current, items, None),
        ]
    )
    monkeypatch.setattr(
        lane,
        "_yoetz",
        Mock(side_effect=[(Mock(exit_code=0), response) for response in responses]),
    )

    assert lane._verify_native_provider_statement("native", statement, marker) is False
    assert lane.native_provider_verification["reason"] == "native_provider_bound_manifest_mismatch"
    assert lane.native_provider_verification["first_provider_bound_sequence"] == "5"


def test_native_provider_history_exhausts_paged_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    statement = "paged native statement"
    lane = _LANE.Lane(_namespace(tmp_path, host="cursor"))
    lane.evidence.mkdir()
    marker = _native_binding()
    current = {"sequence": "9", "head_digest": "sha256:" + "e" * 64}
    first_page = [
        _history_item("session_opened", "2", publication_channel="cooperative_mcp"),
        _history_item("plan_published", "3", publication_channel="cooperative_mcp"),
        _history_item(
            "check_recorded",
            "5",
            publication_channel="engine_derived",
            manifest=_provider_bound_history_manifest(statement),
        ),
    ]
    second_page = _history_status_page(
        _NATIVE_IDS,
        current,
        [_history_item("receipt_recorded", "7", publication_channel="engine_derived")],
        None,
    )
    responses = [
        _history_status_page(_NATIVE_IDS, marker["frontier"], [], None),
        _history_status_page(_NATIVE_IDS, current, first_page, "cursor-next"),
        second_page,
    ]
    calls: list[tuple[str, dict[str, Any]]] = []

    def operator(
        name: str, _phase: str, _args: list[str], **kwargs: Any
    ) -> tuple[Mock, dict[str, Any]]:
        calls.append((name, json.loads(kwargs["stdin"])))
        return Mock(exit_code=0), responses.pop(0)

    monkeypatch.setattr(lane, "_yoetz", operator)
    assert lane._verify_native_provider_statement("native", statement, marker) is True
    assert lane.native_provider_verification["history_pages"] == 2
    assert calls[2][1]["cursor"] == "cursor-next"


def test_native_provider_history_requires_locator_before_any_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lane = _LANE.Lane(_namespace(tmp_path, host="claude"))
    lane.evidence.mkdir()
    invoke = Mock()
    monkeypatch.setattr(lane, "_yoetz", invoke)
    assert lane._verify_native_provider_statement("native", "no locator") is False
    assert invoke.call_count == 0
    assert lane.native_provider_verification["reason"] == "native_binding_marker_missing"


def test_native_binding_prefers_exact_observation_locator() -> None:
    observed = {
        "adapter": {
            "external_ref": "native-claude-stamp",
            "native_binding": {**_native_binding(), "source": "adapter"},
        }
    }
    assert _LANE._native_binding_from_observation(observed) is None
    result = _LANE._native_binding_from_observation(
        observed, external_ref="native-claude-stamp", workspace="/native"
    )
    assert result is not None
    assert result["source"] == "observation"
    assert result["task_id"] == _NATIVE_IDS["task_id"]
    direct = {**_native_binding(), "native_external_ref": "native-claude-stamp"}
    assert (
        _LANE._native_binding_from_observation(direct, external_ref="native-claude-stamp") == result
    )


def test_native_phase_uses_locator_and_read_only_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    statement = "native phase statement"
    lane = _LANE.Lane(_namespace(tmp_path, host="claude", strict_agent=True, skip_agent=False))
    lane.evidence.mkdir()
    marker = _native_binding()
    output = _native_output("claude", "DONE", binding=marker)
    current = {"sequence": "9", "head_digest": "sha256:" + "f" * 64}
    items = [
        _history_item("session_opened", "2", publication_channel="cooperative_mcp"),
        _history_item("plan_published", "3", publication_channel="cooperative_mcp"),
        _history_item(
            "check_recorded",
            "5",
            publication_channel="engine_derived",
            manifest=_provider_bound_history_manifest(statement),
        ),
        _history_item("receipt_recorded", "7", publication_channel="engine_derived"),
    ]
    responses = [
        _history_status_page(_NATIVE_IDS, marker["frontier"], [], None),
        _history_status_page(_NATIVE_IDS, current, items, None),
    ]
    calls: list[str] = []
    monkeypatch.setattr(lane, "_agent_command", Mock(return_value=(["native"], {}, None)))
    monkeypatch.setattr(lane, "_run", Mock(return_value=(0, output, "", 1)))
    monkeypatch.setattr(lane, "_observe_status", Mock(return_value={"mapping_present": True}))
    monkeypatch.setattr(lane, "_observe_drain", Mock(return_value=None))
    stale = {
        "task_id": "tsk_00000000-0000-4000-8000-000000000004",
        "session_id": "ses_00000000-0000-4000-8000-000000000005",
        "writer_id": "wri_00000000-0000-4000-8000-000000000006",
        "external_ref": "dogfood-ci-claude-stale-probe",
    }
    lane.observation = {"earlier_ledger_probe": stale}

    def operator(
        name: str, _phase: str, _args: list[str], **kwargs: Any
    ) -> tuple[Mock, dict[str, Any]]:
        calls.append(name)
        if name.startswith("native_history"):
            return Mock(exit_code=0), responses.pop(0)
        return Mock(exit_code=0), {}

    monkeypatch.setattr(lane, "_yoetz", operator)
    lane.native_prompt = statement
    lane.phase_native_agent()
    assert lane.report()["verdict"]["agent_ok"] is True
    process_steps = [step for step in lane.steps if step.name == "native_process_result"]
    assert len(process_steps) == 1
    assert process_steps[0].status == "pass"
    assert process_steps[0].summary["binding_marker_present"] is True
    assert calls[:2] == ["native_history_marker_frontier", "native_history_1"]
    assert lane.native_provider_verification["task_id"] == marker["task_id"]
    assert "native_operator_attach" not in calls
    assert "start" not in calls
