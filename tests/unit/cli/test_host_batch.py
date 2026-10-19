"""A batch approval binds every member before any host can be changed (#1119)."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any, cast

import anyio
import pytest
from typer.testing import CliRunner

from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.application.host_connection import ConnectionError, ConnectionPlan, plan_digest
from finishup.cli import host_connection
from finishup.cli.app import app
from finishup.protocol.canonical import JsonValue, canonical_digest

REQUEST = "req_cc8c2c7e-1246-4ed2-9e48-05a69fbb1d90"


@pytest.fixture
def batch_hosts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    hosts = (
        HostInstallation(
            "claude", tmp_path / "Claude Code", "2.1.241", tmp_path / "claude", "Claude Code"
        ),
        HostInstallation(
            "cursor-cli",
            tmp_path / "cursor-agent",
            "1.0.0",
            tmp_path / "cursor",
            "Cursor Agent CLI",
        ),
    )
    state: dict[str, Any] = {
        "hosts": hosts,
        "applied": [],
        "changed": set(),
        "fail": None,
        "unchanged": set(),
    }
    launcher = tmp_path / "finishup"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    monkeypatch.setattr(host_connection, "invoking_launcher", lambda: (str(launcher),))
    monkeypatch.setattr(host_connection, "refuse_unservable_runtime", lambda: None)
    monkeypatch.setattr(host_connection, "discover_hosts", lambda: hosts)
    monkeypatch.setattr(
        "finishup.adapters.integrations.host_discovery.discover_hosts", lambda: hosts
    )

    def select(
        host: str, executable: Path | None = None, config_root: Path | None = None
    ) -> HostInstallation:
        return next(
            item
            for item in hosts
            if item.host == host
            and (executable is None or executable == item.executable)
            and (config_root is None or config_root == item.config_root)
        )

    def prepare(item: HostInstallation, project: Path, **kwargs: Any) -> ConnectionPlan:
        body: dict[str, JsonValue] = {
            "schema": "yoetz.host-connection-plan/1",
            "host_version": item.version,
            "connection_observed": False,
            "host": item.host,
            "executable": str(item.executable),
            "config_root": str(item.config_root),
            "project_root": str(project),
            "request_id": kwargs["request_value"],
            "route_profile": kwargs.get("route") or "strict",
            "action": kwargs["action"],
            "changes": [] if item.host in state["unchanged"] else ["install_plugin"],
            "state_before": "changed" if item.host in state["changed"] else "absent",
            "requires_os_presence": False,
        }
        body["preview_digest"] = plan_digest(body, {})
        return ConnectionPlan(
            body,
            lambda: {"configured": item.host in state["applied"], "connection_observed": False},
            lambda: None,
        )

    def apply(plan: ConnectionPlan, refresh: Any) -> dict[str, JsonValue]:
        if refresh().digest != plan.digest:
            raise ConnectionError("connection_preview_stale")
        if plan.body["host"] == state["fail"]:
            raise ConnectionError("connection_outcome_unknown")
        state["applied"].append(plan.body["host"])
        return {"configured": True, "connection_observed": False}

    monkeypatch.setattr(host_connection, "select_installation", select)
    monkeypatch.setattr(host_connection, "prepare_selected", prepare)
    monkeypatch.setattr(host_connection, "apply_selected", apply)
    return state


def invoke_batch(tmp_path: Path, **kwargs: Any) -> int:
    from finishup.cli.host_batch import run_host_batch

    async def run() -> int:
        return await run_host_batch(hosts=["all"], project=tmp_path, json_output=True, **kwargs)

    return anyio.run(run)


def test_preview_binds_sorted_members_and_pins_every_installation(
    batch_hosts: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert invoke_batch(tmp_path, request_value=REQUEST) == 0
    report = json.loads(capsys.readouterr().out)
    assert batch_hosts["applied"] == []
    members = report["members"]
    expected = sorted(
        [
            {
                "host": row["host"],
                "installation_path": row["plan"]["executable"],
                "request_id": row["plan"]["request_id"],
                "preview_digest": row["plan"]["preview_digest"],
            }
            for row in members
        ],
        key=lambda row: (
            row["host"],
            row["installation_path"],
            row["request_id"],
            row["preview_digest"],
        ),
    )
    assert report["preview_digest"] == canonical_digest(cast(JsonValue, expected))
    command = shlex.split(report["next_step"])
    assert (
        command.count("--host")
        == command.count("--host-path")
        == command.count("--host-config-root")
        == 2
    )
    assert "all" not in command
    assert str(tmp_path) in command
    assert REQUEST in command
    assert report["preview_digest"] in command


def test_bare_accept_cannot_apply_batch(
    batch_hosts: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert invoke_batch(tmp_path, accept=True) == 3
    assert json.loads(capsys.readouterr().out)["outcome"] == "preview"
    assert batch_hosts["applied"] == []


def test_stale_last_member_refuses_before_first_write(
    batch_hosts: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    invoke_batch(tmp_path, request_value=REQUEST)
    digest = json.loads(capsys.readouterr().out)["preview_digest"]
    batch_hosts["changed"].add("cursor-cli")
    assert invoke_batch(tmp_path, request_value=REQUEST, preview_digest=digest, accept=True) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["reason"] == "connection_preview_stale"
    assert batch_hosts["applied"] == []


def test_failure_reports_applied_failed_and_rest_with_fresh_continuation(
    batch_hosts: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    invoke_batch(tmp_path, request_value=REQUEST)
    digest = json.loads(capsys.readouterr().out)["preview_digest"]
    batch_hosts["fail"] = "cursor-cli"
    assert invoke_batch(tmp_path, request_value=REQUEST, preview_digest=digest, accept=True) == 1
    report = json.loads(capsys.readouterr().out)
    assert [row["outcome"] for row in report["members"]] == ["completed", "incomplete"]
    assert batch_hosts["applied"] == ["claude"]
    assert "--host cursor-cli" in report["next_step"]
    assert "--host claude" not in report["next_step"]
    assert "--accept" not in report["next_step"]


@pytest.mark.parametrize("action", ["run", "disconnect", "status"])
def test_cli_accepts_all_and_repeated_hosts(
    batch_hosts: dict[str, Any], tmp_path: Path, action: str
) -> None:
    for selection in (["--host", "all"], ["--host", "claude", "--host", "cursor-cli"]):
        result = CliRunner().invoke(
            app, ["setup", action, *selection, "--project", str(tmp_path), "--json"]
        )
        assert result.exit_code == 0, result.output
        report = json.loads(result.stdout)
        assert [row["host"] for row in report["members"]] == ["claude", "cursor-cli"]
        if action == "status":
            assert report["outcome"] == "status"
    assert batch_hosts["applied"] == []


def test_interactive_batch_has_one_combined_approval(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from finishup.cli.host_batch import run_host_batch

    questions: list[str] = []

    def approve(question: str, **_kwargs: Any) -> bool:
        questions.append(question)
        return True

    monkeypatch.setattr("typer.confirm", approve)

    async def run() -> int:
        return await run_host_batch(hosts=["all"], project=tmp_path, interactive=True)

    assert anyio.run(run) == 0
    assert len(questions) == 1
    output = capsys.readouterr().out
    assert "Claude Code" in output and "Cursor Agent CLI" in output
    assert batch_hosts["applied"] == ["claude", "cursor-cli"]


@pytest.mark.parametrize("action", ["run", "disconnect"])
def test_the_returned_command_replays_exact_batch_acceptance(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    action: str,
) -> None:
    from finishup.protocol.host_connection import HostConnectionBatchReport

    result = CliRunner().invoke(
        app,
        [
            "setup",
            action,
            "--host",
            "all",
            "--project",
            str(tmp_path),
            "--route-profile",
            "policy",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    preview = json.loads(result.stdout)
    HostConnectionBatchReport.model_validate(preview)
    command = shlex.split(preview["next_step"])[1:]
    applied = CliRunner().invoke(app, [*command, "--json"])
    assert applied.exit_code == 0, applied.output
    report = json.loads(applied.stdout)
    HostConnectionBatchReport.model_validate(report)
    assert report["outcome"] == "completed"
    assert batch_hosts["applied"] == ["claude", "cursor-cli"]
    assert all(row["plan"]["route_profile"] == "policy" for row in report["members"])
    assert all(
        row["plan"]["action"] == ("connect" if action == "run" else "disconnect")
        for row in report["members"]
    )


def test_all_with_only_one_installation_keeps_combined_digest_on_replay(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(host_connection, "discover_hosts", lambda: batch_hosts["hosts"][:1])
    preview = CliRunner().invoke(
        app, ["setup", "run", "--host", "all", "--project", str(tmp_path), "--json"]
    )
    assert preview.exit_code == 0, preview.output
    command = shlex.split(json.loads(preview.stdout)["next_step"])[1:]
    assert "--batch" in command
    result = CliRunner().invoke(app, [*command, "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["outcome"] == "completed"


def test_status_reports_other_hosts_even_if_one_preview_fails(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    original = host_connection.prepare_selected

    def prepare(item: HostInstallation, *args: Any, **kwargs: Any) -> ConnectionPlan:
        if item.host == "claude":
            raise OSError("/private/user-controlled-secret")
        return original(item, *args, **kwargs)

    monkeypatch.setattr(host_connection, "prepare_selected", prepare)
    assert invoke_batch(tmp_path, status_only=True) == 1
    output = capsys.readouterr().out
    report = json.loads(output)
    assert [row["outcome"] for row in report["members"]] == ["incomplete", "status"]
    assert "user-controlled-secret" not in output
    assert batch_hosts["applied"] == []


def test_preparation_failure_names_failed_member_and_unattempted_members(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(*args: Any, **kwargs: Any) -> ConnectionPlan:
        raise ConnectionError("connection_modified_plugin")

    monkeypatch.setattr(host_connection, "prepare_selected", fail)
    assert invoke_batch(tmp_path, accept=True) == 1
    report = json.loads(capsys.readouterr().out)
    assert [row["outcome"] for row in report["members"]] == ["incomplete", "not_attempted"]
    assert batch_hosts["applied"] == []


def test_batch_os_authentication_stays_on_main_thread_and_names_each_host(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import threading

    original = host_connection.prepare_selected
    main_thread = threading.get_ident()

    def prepare(*args: Any, **kwargs: Any) -> ConnectionPlan:
        plan = original(*args, **kwargs)
        plan.body["requires_os_presence"] = True
        plan.body["preview_digest"] = plan_digest(plan.body, {})
        return plan

    def apply(plan: ConnectionPlan, refresh: Any) -> dict[str, JsonValue]:
        assert threading.get_ident() == main_thread
        assert refresh().digest == plan.digest
        return {"configured": True}

    monkeypatch.setattr(host_connection, "prepare_selected", prepare)
    monkeypatch.setattr(host_connection, "apply_selected", apply)
    invoke_batch(tmp_path, request_value=REQUEST)
    digest = json.loads(capsys.readouterr().out)["preview_digest"]
    assert invoke_batch(tmp_path, request_value=REQUEST, preview_digest=digest, accept=True) == 0
    output = capsys.readouterr()
    assert "Claude Code: operating-system authentication" in output.err
    assert "Cursor Agent CLI: operating-system authentication" in output.err
    json.loads(output.out)


def test_prompt_wizard_asks_review_once_for_all_selected_hosts(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.cli import setup

    asked: list[str] = []
    applied_privacy: list[Path | None] = []
    monkeypatch.setattr(setup, "_is_interactive_terminal", lambda: True)

    def answer(*args: object, **kwargs: object) -> int:
        return 1

    def approve(*args: object, **kwargs: object) -> bool:
        return True

    monkeypatch.setattr("typer.prompt", answer)
    monkeypatch.setattr("typer.confirm", approve)
    monkeypatch.setattr(
        setup, "_choose_review_mode", lambda: asked.append("review") or "local_only"
    )
    monkeypatch.setattr(setup, "_write_setup_marker", approve)

    async def privacy(project: Path | None) -> int:
        applied_privacy.append(project)
        return 0

    monkeypatch.setattr(setup, "_run_local_only_privacy_setup", privacy)

    async def run() -> int:
        return await setup.run_setup_wizard(
            non_interactive=False,
            codex_path=None,
            codex_home=None,
            accept=False,
            json_output=False,
            project=tmp_path,
        )

    assert anyio.run(run) == 0
    assert asked == ["review"]
    assert applied_privacy == [tmp_path.resolve()]
    assert batch_hosts["applied"] == ["claude", "cursor-cli"]


@pytest.mark.parametrize("ready", [True, False])
def test_a_strict_batch_setup_completes_only_with_a_ready_vault(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ready: bool,
) -> None:
    """An explicit strict route skips the review question but still needs a ready vault."""

    from finishup.cli import setup

    markers: list[str] = []
    monkeypatch.setattr(setup, "_is_interactive_terminal", lambda: True)

    def answer(*args: object, **kwargs: object) -> int:
        return 1

    def approve(*args: object, **kwargs: object) -> bool:
        return True

    monkeypatch.setattr("typer.prompt", answer)
    monkeypatch.setattr("typer.confirm", approve)

    def never_asked() -> str:
        raise AssertionError("an explicit route profile asks no review question")

    monkeypatch.setattr(setup, "_choose_review_mode", never_asked)
    monkeypatch.setattr(setup, "_write_setup_marker", markers.append)

    async def vault() -> setup.VaultReadiness:
        return setup.VaultReadiness(ready, None if ready else "vault_not_ready", "owner_file", {})

    monkeypatch.setattr(setup, "ensure_vault_ready", vault)

    async def run() -> int:
        return await setup.run_setup_wizard(
            non_interactive=False,
            codex_path=None,
            codex_home=None,
            accept=False,
            json_output=False,
            route_profile="strict",
            project=tmp_path,
        )

    assert anyio.run(run) == (0 if ready else 20)
    assert markers == (["complete"] if ready else [])
    assert batch_hosts["applied"] == ["claude", "cursor-cli"]


def test_text_batch_status_prints_each_member_status(capsys: pytest.CaptureFixture[str]) -> None:
    from finishup.cli.host_batch import emit_batch

    emit_batch(
        {"members": [{"host": "claude", "outcome": "status", "status": {"configured": True}}]},
        json_output=False,
    )

    out = capsys.readouterr().out
    assert "claude: status" in out
    assert "'configured': True" in out
    assert "A fresh session is required" in out


def test_prompt_subset_rejects_empty_out_of_range_and_non_numbers(
    batch_hosts: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.cli import setup

    answers = iter([2, "", "9", "a", "2,2"])

    def answer(*args: object, **kwargs: object) -> int | str:
        return next(answers)

    monkeypatch.setattr("typer.prompt", answer)
    assert setup._choose_setup_installations(batch_hosts["hosts"]) == batch_hosts["hosts"][1:]  # pyright: ignore[reportPrivateUsage]


def test_batch_golden_vector_matches_digest_and_closed_schema() -> None:
    from jsonschema import Draft202012Validator

    from finishup.protocol.host_connection import HostConnectionBatchReport

    root = Path(__file__).resolve().parents[3]
    fixture = json.loads((root / "fixtures/canonical/host-connection-batch.case.json").read_bytes())
    report = fixture["report"]
    HostConnectionBatchReport.model_validate(report)
    assert report["preview_digest"] == canonical_digest(fixture["digest_members"])
    schema = json.loads(
        (root / "schemas/integrations/host-connection-batch-1.0.0.schema.json").read_bytes()
    )
    Draft202012Validator(schema).validate(report)  # pyright: ignore[reportUnknownMemberType]


def test_failed_middle_member_leaves_the_tail_unattempted(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    hosts = (
        *batch_hosts["hosts"],
        HostInstallation(
            "cursor-ide", tmp_path / "cursor", "1.0.0", tmp_path / "cursor-ide", "Cursor IDE"
        ),
    )
    monkeypatch.setattr(host_connection, "discover_hosts", lambda: hosts)
    invoke_batch(tmp_path, request_value=REQUEST)
    digest = json.loads(capsys.readouterr().out)["preview_digest"]
    batch_hosts["fail"] = "cursor-cli"
    assert invoke_batch(tmp_path, request_value=REQUEST, preview_digest=digest, accept=True) == 1
    report = json.loads(capsys.readouterr().out)
    assert [row["outcome"] for row in report["members"]] == [
        "completed",
        "incomplete",
        "not_attempted",
    ]
    assert batch_hosts["applied"] == ["claude"]
    assert "--host cursor-ide" in report["next_step"]


def test_codex_keeps_its_composition_and_event_loop_off_the_main_thread(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import threading

    hosts = (
        *batch_hosts["hosts"],
        HostInstallation("codex", tmp_path / "codex", "0.162.1", tmp_path / "codex-home", "Codex"),
    )
    monkeypatch.setattr(host_connection, "discover_hosts", lambda: hosts)
    original_prepare = host_connection.prepare_selected
    original_apply = host_connection.apply_selected
    main_thread = threading.get_ident()
    activation = {
        "preview_digest": "sha256:" + "1" * 64,
        "skill_preview_digest": "sha256:" + "2" * 64,
        "activation_preview_digest": "sha256:" + "3" * 64,
        "policy_digest": "4" * 64,
    }

    def prepare(item: HostInstallation, project: Path, **kwargs: Any) -> ConnectionPlan:
        if item.host == "codex":
            assert threading.get_ident() != main_thread
        plan = original_prepare(item, project, **kwargs)
        if item.host == "codex":
            plan.body["codex_plan"] = cast(JsonValue, activation)
            plan.body["preview_digest"] = plan_digest(plan.body, {})
        return plan

    def apply(plan: ConnectionPlan, refresh: Any) -> dict[str, JsonValue]:
        assert (threading.get_ident() == main_thread) is (plan.body["host"] != "codex")
        if plan.body["host"] == "codex":
            assert plan.body["codex_plan"] == activation
        return original_apply(plan, refresh)

    monkeypatch.setattr(host_connection, "prepare_selected", prepare)
    monkeypatch.setattr(host_connection, "apply_selected", apply)
    invoke_batch(tmp_path, request_value=REQUEST)
    digest = json.loads(capsys.readouterr().out)["preview_digest"]
    assert invoke_batch(tmp_path, request_value=REQUEST, preview_digest=digest, accept=True) == 0
    assert batch_hosts["applied"] == ["claude", "codex", "cursor-cli"]


def test_an_earlier_member_cannot_authorize_changed_later_preimages(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    original_apply = host_connection.apply_selected

    def apply(plan: ConnectionPlan, refresh: Any) -> dict[str, JsonValue]:
        status = original_apply(plan, refresh)
        if plan.body["host"] == "claude":
            batch_hosts["changed"].add("cursor-cli")
        return status

    monkeypatch.setattr(host_connection, "apply_selected", apply)
    invoke_batch(tmp_path, request_value=REQUEST)
    digest = json.loads(capsys.readouterr().out)["preview_digest"]
    assert invoke_batch(tmp_path, request_value=REQUEST, preview_digest=digest, accept=True) == 1
    report = json.loads(capsys.readouterr().out)
    assert [row["outcome"] for row in report["members"]] == ["completed", "incomplete"]
    assert report["members"][1]["reason"] == "connection_preview_stale"
    assert "--accept" not in report["next_step"]
    assert batch_hosts["applied"] == ["claude"]


def test_invalid_request_identity_is_not_echoed_in_the_batch_report(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from finishup.protocol.host_connection import HostConnectionBatchReport

    assert invoke_batch(tmp_path, request_value="/private/user-controlled-invalid-identity") == 1
    output = capsys.readouterr().out
    assert "user-controlled-invalid-identity" not in output
    HostConnectionBatchReport.model_validate_json(output)
    assert batch_hosts["applied"] == []


def test_single_host_json_keeps_its_existing_terminal_behavior(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.cli import setup

    monkeypatch.setattr(setup, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(setup, "_choose_review_mode", lambda: "local_only")

    def connect(**kwargs: object) -> int:
        assert kwargs["interactive"] is True
        return 1

    monkeypatch.setattr(host_connection, "run_host_connection", connect)

    async def run() -> int:
        return await setup.run_setup_wizard(
            non_interactive=False,
            codex_path=None,
            codex_home=None,
            accept=False,
            json_output=True,
            host="claude",
            project=tmp_path,
        )

    assert anyio.run(run) == 1


def test_batch_json_on_a_terminal_previews_without_questions(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from finishup.cli import setup

    monkeypatch.setattr(setup, "_is_interactive_terminal", lambda: True)

    def forbidden(*args: object, **kwargs: object) -> str:
        raise AssertionError("JSON batches must not ask setup questions")

    monkeypatch.setattr(setup, "_choose_review_mode", forbidden)
    monkeypatch.setattr("typer.prompt", forbidden)
    monkeypatch.setattr("typer.confirm", forbidden)

    async def run() -> int:
        return await setup.run_setup_wizard(
            non_interactive=False,
            codex_path=None,
            codex_home=None,
            accept=False,
            json_output=True,
            host=("claude", "cursor-cli"),
            project=tmp_path,
        )

    assert anyio.run(run) == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "preview"
    assert batch_hosts["applied"] == []


def test_codex_discovery_and_explicit_batch_replay_keep_the_same_visible_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.cli.host_batch import select_installations

    target = tmp_path / "real-codex"
    target.write_text("#!/bin/sh\nexit 0\n")
    target.chmod(0o700)
    visible = tmp_path / "codex"
    visible.symlink_to(target)
    home = tmp_path / "codex-home"
    discovered = HostInstallation("codex", visible, "0.162.1", home, "Codex")
    monkeypatch.setattr(host_connection, "discover_hosts", lambda: (discovered,))

    def version(path: Path) -> str:
        assert path == visible
        return "0.162.1"

    monkeypatch.setattr(host_connection, "probe_version", version)
    assert select_installations(["all"]) == select_installations(["codex"], [visible], [home])


def test_an_unchanged_member_that_changes_mid_batch_is_stale_not_unchanged(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Review of #1119: an already-connected agent is re-checked when its turn comes."""

    batch_hosts["unchanged"].add("cursor-cli")
    original_apply = host_connection.apply_selected

    def apply(plan: ConnectionPlan, refresh: Any) -> dict[str, JsonValue]:
        status = original_apply(plan, refresh)
        if plan.body["host"] == "claude":
            batch_hosts["changed"].add("cursor-cli")
        return status

    monkeypatch.setattr(host_connection, "apply_selected", apply)
    invoke_batch(tmp_path, request_value=REQUEST)
    digest = json.loads(capsys.readouterr().out)["preview_digest"]
    assert invoke_batch(tmp_path, request_value=REQUEST, preview_digest=digest, accept=True) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["outcome"] == "incomplete"
    assert [row["outcome"] for row in report["members"]] == ["completed", "incomplete"]
    assert report["members"][1]["reason"] == "connection_preview_stale"
    assert "--accept" not in report["next_step"]


def test_a_text_disconnect_with_codex_previews_without_connect_details(
    batch_hosts: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Review of #1119: disconnect plans carry no Codex activation plan to render."""

    from finishup.cli.host_batch import run_host_batch

    codex = HostInstallation("codex", tmp_path / "codex", "0.162.1", tmp_path / ".codex", "Codex")
    hosts = (*batch_hosts["hosts"], codex)
    monkeypatch.setattr(host_connection, "discover_hosts", lambda: hosts)
    monkeypatch.setattr(
        "finishup.adapters.integrations.host_discovery.discover_hosts", lambda: hosts
    )
    original_select = host_connection.select_installation

    def select(
        host: str, executable: Path | None = None, config_root: Path | None = None
    ) -> HostInstallation:
        return codex if host == "codex" else original_select(host, executable, config_root)

    monkeypatch.setattr(host_connection, "select_installation", select)

    async def run() -> int:
        return await run_host_batch(
            hosts=["all"], project=tmp_path, json_output=False, action="disconnect"
        )

    assert anyio.run(run) == 0
    out = capsys.readouterr().out
    assert "Codex" in out
    assert batch_hosts["applied"] == []


def test_a_json_preview_continuation_stays_json(
    batch_hosts: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    invoke_batch(tmp_path, request_value=REQUEST)
    assert "--json" in shlex.split(json.loads(capsys.readouterr().out)["next_step"])
