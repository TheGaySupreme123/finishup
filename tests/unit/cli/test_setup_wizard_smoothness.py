"""First-run setup friction found walking ``finishup setup run`` in a test instance."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import anyio
import pytest

from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.cli import host_connection
from finishup.cli import setup as wizard


def _ignore(*_args: object, **_kwargs: object) -> None:
    return None


def _empty_answer(*_args: object, **_kwargs: object) -> str:
    return ""


def _codex_subscription_choice(*_args: object, **_kwargs: object) -> str:
    return "codex_subscription"


def _connected(*_args: object, **_kwargs: object) -> int:
    return 0


def _config(**fields: object) -> Callable[..., object]:
    def load(*_args: object, **_kwargs: object) -> object:
        return SimpleNamespace(**fields)

    return load


def _which(path: Path | None) -> Callable[[str], str | None]:
    def which(_name: str) -> str | None:
        return None if path is None else str(path)

    return which


def _wizard(project: Path | None, *, json_output: bool = False) -> int:
    async def run() -> int:
        return await wizard.run_setup_wizard(
            non_interactive=False,
            codex_path=None,
            codex_home=None,
            accept=False,
            json_output=json_output,
            host="claude",
            project=project,
        )

    return anyio.run(run)


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    return home


def _record_connections(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    connected: list[Path] = []

    def connect(**kwargs: object) -> int:
        project = kwargs["project"]
        assert isinstance(project, Path)
        connected.append(project)
        return 0

    async def no_privacy_step(*_args: object, **_kwargs: object) -> int:
        return 0

    monkeypatch.setattr(host_connection, "run_host_connection", connect)
    monkeypatch.setattr(wizard, "_write_setup_marker", _ignore)
    monkeypatch.setattr(wizard, "_choose_review_mode", lambda: "local_only")
    # The privacy and provider steps after a connection are covered elsewhere; never start a
    # service from these cases.
    monkeypatch.setattr(wizard, "_run_local_only_privacy_setup", no_privacy_step)
    monkeypatch.setattr(wizard, "run_provider_setup", no_privacy_step)
    return connected


def test_an_unconnectable_folder_stops_with_a_next_step_not_internal_error(
    monkeypatch: pytest.MonkeyPatch, home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    connected = _record_connections(monkeypatch)
    monkeypatch.setattr(wizard, "_is_interactive_terminal", lambda: False)

    assert _wizard(home, json_output=True) == 1

    report = json.loads(capsys.readouterr().out)
    assert report["outcome"] == "incomplete"
    assert report["reason"] == "workspace_locator_invalid"
    assert "--project" in report["next_step"]
    assert connected == []


def test_the_folder_is_checked_before_any_setup_question(
    monkeypatch: pytest.MonkeyPatch, home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    connected = _record_connections(monkeypatch)
    asked: list[str] = []

    def review_mode() -> str:
        asked.append("review_mode")
        return "local_only"

    monkeypatch.setattr(wizard, "_choose_review_mode", review_mode)
    monkeypatch.setattr(wizard, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr("typer.prompt", _empty_answer)

    assert _wizard(home) == 1

    out = capsys.readouterr().out
    assert "workspace_locator_invalid" in out
    assert "inside the project folder" in out
    assert asked == []
    assert connected == []


def test_a_terminal_user_can_name_the_project_folder_instead(
    monkeypatch: pytest.MonkeyPatch, home: Path, tmp_path: Path
) -> None:
    connected = _record_connections(monkeypatch)
    project = tmp_path / "project"
    project.mkdir()
    answers = iter([str(home), str(project)])
    monkeypatch.setattr(wizard, "_is_interactive_terminal", lambda: True)

    def answer(*_args: object, **_kwargs: object) -> str:
        return next(answers)

    monkeypatch.setattr("typer.prompt", answer)

    assert _wizard(home) == 0
    assert connected == [project.resolve()]


@pytest.mark.parametrize("review", ["local_only", "agent_opt_in", "ai_powered"])
def test_the_privacy_step_governs_the_folder_the_user_typed(
    monkeypatch: pytest.MonkeyPatch, home: Path, tmp_path: Path, review: str
) -> None:
    # Run from the home folder, the owner names the project; the privacy policy that follows must
    # be the one for that project, not for the current directory.
    connected = _record_connections(monkeypatch)
    governed: list[Path | None] = []

    async def local_only(project: Path | None) -> int:
        governed.append(project)
        return 0

    async def provider(**kwargs: object) -> int:
        project = kwargs.get("project")
        assert project is None or isinstance(project, Path)
        governed.append(project)
        return 0

    monkeypatch.setattr(wizard, "_run_local_only_privacy_setup", local_only)
    monkeypatch.setattr(wizard, "run_provider_setup", provider)
    monkeypatch.setattr(wizard, "_choose_review_mode", lambda: review)
    project = tmp_path / "project"
    project.mkdir()
    answers = iter([str(project)])
    monkeypatch.setattr(wizard, "_is_interactive_terminal", lambda: True)

    def answer(*_args: object, **_kwargs: object) -> str:
        return next(answers)

    monkeypatch.setattr("typer.prompt", answer)

    assert _wizard(home) == 0
    assert connected == [project.resolve()]
    assert governed == [project.resolve()]


def test_the_offered_codex_is_the_one_a_plain_codex_command_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    older = HostInstallation("codex", tmp_path / "a" / "codex", "0.153.4", tmp_path, "Codex")
    newer = HostInstallation("codex", tmp_path / "b" / "codex", "0.162.1", tmp_path, "Codex")
    claude = HostInstallation("claude", tmp_path / "claude", "2.1.0", tmp_path, "Claude Code")
    monkeypatch.setattr(wizard.shutil, "which", _which(newer.executable))

    assert wizard._default_installation_choice((older, newer, claude)) == 2  # pyright: ignore[reportPrivateUsage]

    monkeypatch.setattr(wizard.shutil, "which", _which(None))
    assert wizard._default_installation_choice((older, newer, claude)) == 1  # pyright: ignore[reportPrivateUsage]


def test_a_completed_codex_subscription_setup_reports_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The Codex subscription credential is Codex's own sign-in, never a stored API key; setup
    # used to print "Credential: unknown" and exit 20 after a successful sign-in.
    _codex_provider_run(
        monkeypatch,
        _approved,
        status={"model": "gpt-6-luna", "model_fallback_from": "gpt-6.1-sol"},
    )

    assert anyio.run(wizard.run_provider_setup) == 0

    out = capsys.readouterr().out
    assert "held by Codex's own ChatGPT sign-in" in out
    assert "Model: gpt-6-luna (suggested gpt-6.1-sol is not listed by this Codex)" in out
    assert "Preview Codex MCP registration" not in out


def test_a_failed_codex_subscription_setup_names_the_next_step(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def reachable(**_kwargs: object) -> dict[str, object]:
        return {"reachable": True, "state": "ready"}

    async def provider_setup(
        service: dict[str, object], **_kwargs: object
    ) -> tuple[dict[str, object], dict[str, object]]:
        return service, {
            "binding": "failed",
            "credential": "external_runtime_oauth",
            "credential_reason": "codex_model_unavailable",
        }

    monkeypatch.setattr(wizard, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(wizard, "_service_reachability", reachable)
    monkeypatch.setattr(wizard, "_interactive_provider_setup", provider_setup)

    assert anyio.run(wizard.run_provider_setup) == 20

    out = capsys.readouterr().out
    assert "Reason: codex_model_unavailable" in out
    assert "Next: " in out
    assert "--model" in out


def test_an_unreadable_configuration_keeps_the_api_key_question(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The provider step reads the configuration to tell a Codex subscription (no key) from an API
    # key provider. An unreadable configuration must fall back to the API-key question, not fail
    # on the error class itself (a function-local import used to shadow it, leaving it unbound).
    from finishup.cli import privacy_setup
    from finishup.config.models import ConfigError

    async def reachable(**_kwargs: object) -> dict[str, object]:
        return {"reachable": True, "state": "ready"}

    def unreadable(*_args: object, **_kwargs: object) -> object:
        raise ConfigError("config_value_invalid")

    async def privacy(**_kwargs: object) -> object:
        return type("Report", (), {"outcome": "configured", "reason": None})()

    async def provider_setup(
        service: dict[str, object], **kwargs: object
    ) -> tuple[dict[str, object], dict[str, object]]:
        before_credential = cast(Callable[[], Awaitable[str | None]], kwargs["before_credential"])
        assert await before_credential() is None
        return service, {"binding": "configured", "credential": "stored"}

    monkeypatch.setattr(wizard, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(wizard, "_service_reachability", reachable)
    monkeypatch.setattr(wizard, "load_config", unreadable)
    monkeypatch.setattr(wizard, "_prompt_credential_probe_authorization", lambda: False)
    monkeypatch.setattr(privacy_setup, "run_privacy_setup", privacy)
    monkeypatch.setattr(wizard, "_interactive_provider_setup", provider_setup)
    monkeypatch.setattr(wizard, "_emit_provider_setup_layer_report", _ignore)

    assert anyio.run(wizard.run_provider_setup) == 0
    assert "before the API key can be tested" in capsys.readouterr().out


# --- review round 1: an incomplete privacy step is never reported as success ---------------------


def _codex_provider_run(
    monkeypatch: pytest.MonkeyPatch,
    privacy: Callable[..., Awaitable[object]],
    *,
    status: dict[str, object] | None = None,
) -> list[str]:
    """Drive the real Codex-subscription branch of the provider step; return markers written."""

    from finishup.cli import codex_subscription, privacy_setup, provider_binding

    markers: list[str] = []

    async def ready(**_kwargs: object) -> dict[str, object]:
        return {"reachable": True, "state": "ready"}

    async def restarted() -> dict[str, object]:
        return {"reachable": True, "state": "ready"}

    async def signed_in() -> dict[str, object]:
        return {
            "model": "gpt-6.1-sol",
            "model_available": True,
            "auth_mode": "chatgpt",
            **(status or {}),
        }

    def marker(outcome: str) -> bool:
        markers.append(outcome)
        return True

    monkeypatch.setattr(wizard, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(wizard, "_service_reachability", ready)
    monkeypatch.setattr(wizard, "_restart_service_for_semantic_composition", restarted)
    monkeypatch.setattr(
        provider_binding, "prompt_provider_endpoint_binding", _codex_subscription_choice
    )
    monkeypatch.setattr(codex_subscription, "prompt_codex_subscription_setup", signed_in)
    monkeypatch.setattr(wizard, "load_config", _config(external_runtime=object()))
    monkeypatch.setattr(privacy_setup, "run_privacy_setup", privacy)
    monkeypatch.setattr(wizard, "_write_setup_marker", marker)
    return markers


async def _declined(**_kwargs: object) -> object:
    return SimpleNamespace(
        outcome="cancelled", reason="privacy_decision_not_approved", profile="private"
    )


async def _raising(**_kwargs: object) -> object:
    raise ValueError("privacy_setup_service_error")


async def _approved(**_kwargs: object) -> object:
    return SimpleNamespace(outcome="configured", reason=None, profile="assisted_review")


def test_a_declined_privacy_step_after_codex_sign_in_is_incomplete(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _codex_provider_run(monkeypatch, _declined)

    assert anyio.run(wizard.run_provider_setup) == 20

    out = capsys.readouterr().out
    assert "Reason: privacy_decision_not_approved" in out
    assert "Privacy policy: cancelled" in out
    assert "finishup --privacy" in out
    assert "start a fresh agent session" not in out


def test_a_failed_privacy_step_after_codex_sign_in_is_reported_as_failed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _codex_provider_run(monkeypatch, _raising)

    assert anyio.run(wizard.run_provider_setup) == 20

    out = capsys.readouterr().out
    assert "Privacy policy: failed" in out
    assert "not_attempted" not in out
    assert "finishup --privacy" in out


@pytest.mark.parametrize("privacy", [_declined, _raising])
def test_the_host_wizard_does_not_mark_setup_complete_without_a_privacy_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, privacy: Callable[..., Awaitable[object]]
) -> None:
    markers = _codex_provider_run(monkeypatch, privacy)
    monkeypatch.setattr(host_connection, "run_host_connection", _connected)
    monkeypatch.setattr(wizard, "_choose_review_mode", lambda: "ai_powered")
    project = tmp_path / "project"
    project.mkdir()

    assert _wizard(project) == 20
    assert markers == []


def test_a_completed_codex_sign_in_reports_its_own_layers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    markers = _codex_provider_run(monkeypatch, _approved)

    assert anyio.run(wizard.run_provider_setup) == 0

    out = capsys.readouterr().out
    assert "FinishUP never reads it" in out
    assert "Privacy policy: configured" in out
    assert "Live AI-powered review: not demonstrated" in out
    assert "vault credential storage" not in out
    assert "SDK extra" not in out
    assert "_semantic_not_configured" not in out
    assert "start a fresh agent session" in out
    assert markers == []


# --- review round 1: the Codex-only path checks the folder first and keeps it --------------------


@dataclass
class _CodexOnlyRun:
    asked: list[str]
    reviewed: list[str]
    workspaces: dict[str, object]


def _codex_only(
    monkeypatch: pytest.MonkeyPatch, home: Path, tmp_path: Path, review: str
) -> _CodexOnlyRun:
    """Only Codex is installed, so setup takes the Codex wizard rather than the agent list."""

    from finishup.adapters.integrations import host_discovery
    from finishup.cli import privacy_setup
    from finishup.ports.harness_mcp import HarnessBinary, HarnessId

    run = _CodexOnlyRun([], [], {})
    executable = tmp_path / "bin" / "codex"
    binary = HarnessBinary(HarnessId.CODEX, str(executable), "0.162.1", "supported")
    codex_home = home / ".codex"
    monkeypatch.chdir(home)
    monkeypatch.setattr(
        host_discovery,
        "discover_hosts",
        lambda: (HostInstallation("codex", executable, "0.162.1", codex_home, "Codex"),),
    )
    monkeypatch.setattr(wizard, "discover_codex_binaries", lambda: (binary,))
    monkeypatch.setattr(wizard, "default_codex_home", lambda: codex_home)
    monkeypatch.setattr(wizard, "_is_interactive_terminal", lambda: True)

    def confirm(text: str, *_args: object, **_kwargs: object) -> bool:
        run.asked.append(text)
        return False

    def choose_review() -> str:
        run.reviewed.append(review)
        return review

    async def register(*_args: object, **kwargs: object) -> dict[str, object]:
        run.workspaces["registration"] = kwargs.get("workspace")
        return {"outcome": "registered", "state": None, "reason": None}

    async def unreachable(**_kwargs: object) -> dict[str, object]:
        return {"reachable": False}

    async def privacy(**kwargs: object) -> object:
        run.workspaces["privacy"] = kwargs.get("workspace_locator")
        return SimpleNamespace(
            outcome="configured", profile="private", proposal_id=None, reason=None
        )

    vault_calls: list[str] = []

    async def provider(
        service: dict[str, object], **kwargs: object
    ) -> tuple[dict[str, object], dict[str, object]]:
        if kwargs.get("storage_only"):
            # Issue #1119: a local-only answer creates the vault with no question.
            vault_calls.append("storage_only")
            return service, {"binding": "skipped", "credential": "skipped"}
        run.workspaces["provider"] = kwargs.get("project")
        before_credential = cast(Callable[[], Awaitable[str | None]], kwargs["before_credential"])
        await before_credential()
        return service, {"binding": "skipped", "credential": "skipped"}

    def readiness(**kwargs: object) -> dict[str, object]:
        run.workspaces["readiness"] = kwargs.get("workspace")
        return {}

    # The real integration-layer inspection runs; only the two file inspections it makes are
    # replaced, to record the folder they look at.
    def skill_inspection(target: object, _source: object) -> object:
        run.workspaces["skill"] = Path(cast(str, getattr(target, "project_root")))
        return SimpleNamespace(state=SimpleNamespace(value="absent"), installed_digest=None)

    def plugin_inspection(target: object) -> object:
        run.workspaces["plugin"] = Path(cast(str, getattr(target, "project_root")))
        return SimpleNamespace(
            presence=SimpleNamespace(value="absent"), trust_observable=False, installed_digest=None
        )

    async def recommendations(**kwargs: object) -> dict[str, object]:
        run.workspaces["recommendations"] = kwargs.get("workspace")
        return {"outcome": "refreshed", "pending": []}

    async def no_update(**_kwargs: object) -> dict[str, object]:
        return {}

    monkeypatch.setattr("typer.confirm", confirm)
    monkeypatch.setattr(wizard, "_choose_review_mode", choose_review)
    monkeypatch.setattr(wizard, "_register_step", register)
    monkeypatch.setattr(wizard, "_service_reachability", unreachable)
    monkeypatch.setattr(privacy_setup, "run_privacy_setup", privacy)
    monkeypatch.setattr(wizard, "_interactive_provider_setup", provider)
    monkeypatch.setattr(wizard, "_prompt_credential_probe_authorization", lambda: False)
    monkeypatch.setattr(wizard, "_readiness_layers", readiness)
    monkeypatch.setattr(wizard, "_refresh_setup_recommendations", recommendations)
    monkeypatch.setattr(wizard, "_resolve_setup_package_update", no_update)
    monkeypatch.setattr(wizard, "inspect_destination", skill_inspection)
    monkeypatch.setattr(wizard, "inspect_plugin", plugin_inspection)
    monkeypatch.setattr(wizard, "_write_setup_marker", _ignore)
    monkeypatch.setattr(wizard, "_emit_human_report", _ignore)
    return run


def _codex_wizard(*, json_output: bool = False, non_interactive: bool = False) -> int:
    async def run() -> int:
        return await wizard.run_setup_wizard(
            non_interactive=non_interactive,
            codex_path=None,
            codex_home=None,
            accept=False,
            json_output=json_output,
        )

    return anyio.run(run)


@pytest.mark.parametrize("review", ["local_only", "ai_powered"])
def test_codex_only_setup_from_home_checks_the_folder_before_any_question(
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    review: str,
) -> None:
    run = _codex_only(monkeypatch, home, tmp_path, review)

    def prompt(text: str, *_args: object, **_kwargs: object) -> str:
        run.asked.append(text)
        return ""

    monkeypatch.setattr("typer.prompt", prompt)

    assert _codex_wizard() == 1

    out = capsys.readouterr().out
    assert "workspace_locator_invalid" in out
    assert "inside the project folder" in out
    assert run.asked == ["Project folder to connect (Enter to stop)"]
    assert run.reviewed == []
    assert run.workspaces == {}


def test_codex_only_setup_from_home_refuses_without_a_terminal(
    monkeypatch: pytest.MonkeyPatch, home: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run = _codex_only(monkeypatch, home, tmp_path, "local_only")
    monkeypatch.setattr(wizard, "_is_interactive_terminal", lambda: False)

    assert _codex_wizard(json_output=True, non_interactive=True) == 1

    report = json.loads(capsys.readouterr().out)
    assert (report["host"], report["outcome"]) == ("codex", "incomplete")
    assert report["reason"] == "workspace_locator_invalid"
    assert "--project" in report["next_step"]
    assert run.workspaces == {}


@pytest.mark.parametrize("review", ["local_only", "ai_powered"])
def test_codex_only_setup_keeps_the_folder_the_user_typed(
    monkeypatch: pytest.MonkeyPatch, home: Path, tmp_path: Path, review: str
) -> None:
    from finishup.cli import provider_status

    run = _codex_only(monkeypatch, home, tmp_path, review)
    project = tmp_path / "project"
    project.mkdir()

    def prompt(text: str, *_args: object, **kwargs: object) -> str:
        run.asked.append(text)
        if text.startswith("Project folder"):
            return str(project)
        default = kwargs.get("default")
        return "1" if default is None else str(default)

    async def ready(**_kwargs: object) -> dict[str, object]:
        return {"reachable": True, "state": "ready"}

    vault_calls: list[str] = []

    async def provider(
        service: dict[str, object], **kwargs: object
    ) -> tuple[dict[str, object], dict[str, object]]:
        if kwargs.get("storage_only"):
            # Issue #1119: a local-only answer creates the vault with no question.
            vault_calls.append("storage_only")
            return service, {"binding": "skipped", "credential": "skipped"}
        run.workspaces["provider"] = kwargs.get("project")
        before_credential = cast(Callable[[], Awaitable[str | None]], kwargs["before_credential"])
        assert await before_credential() is None
        return service, {"binding": "configured", "credential": "external_runtime_oauth"}

    async def status_report(**kwargs: object) -> dict[str, object]:
        run.workspaces["provider_status"] = kwargs.get("workspace_locator")
        return {"semantic_ready": True}

    monkeypatch.setattr("typer.prompt", prompt)
    monkeypatch.setattr(wizard, "_service_reachability", ready)
    monkeypatch.setattr(wizard, "_interactive_provider_setup", provider)
    monkeypatch.setattr(provider_status, "provider_status_report", status_report)

    assert _codex_wizard() == 0

    assert run.asked[0] == "Project folder to connect (Enter to stop)"
    assert run.reviewed == [review]
    expected = {"registration", "privacy", "readiness", "recommendations", "skill", "plugin"}
    if review == "ai_powered":
        expected |= {"provider", "provider_status"}
    assert set(run.workspaces) == expected
    assert all(value == project.resolve() for value in run.workspaces.values())
    assert vault_calls == (["storage_only"] if review == "local_only" else [])


def test_the_api_key_credential_target_names_the_folder_the_user_typed(
    monkeypatch: pytest.MonkeyPatch, home: Path, tmp_path: Path
) -> None:
    import finishup.cli.provider_status as provider_status
    import finishup.config.load as config_load
    from finishup.cli import privacy_setup, provider_binding, unlock
    from finishup.config.write import fireworks_provider

    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(home)
    provider = fireworks_provider(model="accounts/fireworks/models/example")
    seen: dict[str, object] = {}

    async def ready(**_kwargs: object) -> dict[str, object]:
        return {"reachable": True, "state": "ready"}

    async def privacy(**kwargs: object) -> object:
        seen["privacy"] = kwargs.get("workspace_locator")
        return SimpleNamespace(outcome="configured", reason=None)

    async def snapshot(workspace_locator: Path | None = None) -> object:
        seen["snapshot"] = workspace_locator
        return SimpleNamespace(bound_scope={"workspace_ref_commitment": "hmac-sha256:" + "0" * 64})

    async def store(_target: object, *_args: object) -> object:
        return SimpleNamespace(activation_status="stored")

    async def no_status() -> dict[str, object]:
        return {}

    monkeypatch.setattr(wizard, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(wizard, "_service_reachability", ready)
    monkeypatch.setattr(wizard, "_restart_service_for_semantic_composition", ready)
    monkeypatch.setattr(wizard, "load_config", _config(external_runtime=None))
    monkeypatch.setattr(config_load, "load_config", _config(provider=provider))
    monkeypatch.setattr(wizard, "_prompt_credential_probe_authorization", lambda: True)

    def bind(_choice: object, model: str) -> tuple[Path, object]:
        assert model == "accounts/fireworks/models/example"
        return tmp_path / "config.toml", provider

    monkeypatch.setattr(provider_binding, "apply_provider_endpoint_choice", bind)
    monkeypatch.setattr(privacy_setup, "run_privacy_setup", privacy)
    monkeypatch.setattr(privacy_setup, "get_privacy_setup_snapshot", snapshot)
    monkeypatch.setattr(unlock, "set_provider_credential", store)
    monkeypatch.setattr(provider_status, "provider_status_report", no_status)
    monkeypatch.setattr(wizard, "_emit_hidden_credential_transition", _ignore)

    async def run() -> int:
        return await wizard.run_provider_setup(
            provider="fireworks", model="accounts/fireworks/models/example", project=project
        )

    assert anyio.run(run) == 0
    assert seen == {"privacy": project, "snapshot": project}


def test_the_codex_wizard_offers_the_codex_a_plain_codex_command_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.ports.harness_mcp import HarnessBinary, HarnessId

    older = HarnessBinary(HarnessId.CODEX, str(tmp_path / "a" / "codex"), "0.157.1", "supported")
    newer = HarnessBinary(HarnessId.CODEX, str(tmp_path / "b" / "codex"), "0.162.1", "supported")
    defaults: list[object] = []

    def prompt(_text: str, *_args: object, **kwargs: object) -> str:
        defaults.append(kwargs.get("default"))
        return str(kwargs.get("default"))

    monkeypatch.setattr("typer.prompt", prompt)
    monkeypatch.setattr(wizard.shutil, "which", _which(Path(newer.executable_path)))

    chosen = wizard._choose_binary((older, newer), codex_path=None, interactive=True)  # pyright: ignore[reportPrivateUsage]

    assert chosen == newer
    assert defaults == ["2"]


# --- review round 2: the Codex-only wizard gates on the privacy outcome too ----------------------


def _codex_wizard_with_codex_sign_in(
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    tmp_path: Path,
    privacy: Callable[..., Awaitable[object]],
    *,
    semantic_ready: bool,
) -> list[str]:
    """Only Codex installed, run from the project, AI-powered review on every task, real provider
    step through a Codex sign-in; returns the setup markers written."""

    from finishup.cli import privacy_setup, provider_status

    run = _codex_only(monkeypatch, home, tmp_path, "ai_powered")
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    markers = _codex_provider_run(monkeypatch, privacy)

    def prompt(_text: str, *_args: object, **kwargs: object) -> str:
        default = kwargs.get("default")
        return "1" if default is None else str(default)

    async def status_report(**_kwargs: object) -> dict[str, object]:
        return {"semantic_ready": semantic_ready}

    monkeypatch.setattr("typer.prompt", prompt)
    monkeypatch.setattr(wizard, "_interactive_provider_setup", _REAL_PROVIDER_SETUP)
    monkeypatch.setattr(privacy_setup, "run_privacy_setup", privacy)
    monkeypatch.setattr(provider_status, "provider_status_report", status_report)
    del run
    return markers


_REAL_PROVIDER_SETUP = wizard._interactive_provider_setup  # pyright: ignore[reportPrivateUsage]


async def _declined_with_profile(**_kwargs: object) -> object:
    return SimpleNamespace(
        outcome="cancelled",
        reason="privacy_decision_not_approved",
        profile="private",
        proposal_id=None,
    )


async def _approved_with_profile(**_kwargs: object) -> object:
    return SimpleNamespace(
        outcome="configured", reason=None, profile="assisted_review", proposal_id=None
    )


@pytest.mark.parametrize("semantic_ready", [False, True])
@pytest.mark.parametrize(
    ("privacy", "outcome"), [(_declined_with_profile, "cancelled"), (_raising, "failed")]
)
def test_the_codex_wizard_is_incomplete_when_the_privacy_step_is_not_approved(
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    privacy: Callable[..., Awaitable[object]],
    outcome: str,
    semantic_ready: bool,
) -> None:
    markers = _codex_wizard_with_codex_sign_in(
        monkeypatch, home, tmp_path, privacy, semantic_ready=semantic_ready
    )

    assert _codex_wizard() == 20

    out = capsys.readouterr().out
    assert f"Privacy policy: {outcome}" in out
    assert "finishup --privacy" in out
    assert "FinishUP never reads it" not in out
    assert markers == []


def test_the_codex_wizard_reports_codex_layers_after_a_complete_sign_in(
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    markers: list[str] = []
    _codex_wizard_with_codex_sign_in(
        monkeypatch, home, tmp_path, _approved_with_profile, semantic_ready=True
    )

    def marker(outcome: str) -> bool:
        markers.append(outcome)
        return True

    monkeypatch.setattr(wizard, "_write_setup_marker", marker)

    assert _codex_wizard() == 0

    out = capsys.readouterr().out
    assert "FinishUP never reads it" in out
    assert "Privacy policy: configured" in out
    assert markers == ["registered"]


# --- review round 2: next steps name only what this run actually left undone ---------------------


def test_an_api_key_left_unstored_by_a_declined_privacy_step_is_named(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import finishup.config.load as config_load
    from finishup.cli import privacy_setup, provider_binding
    from finishup.config.write import fireworks_provider

    provider = fireworks_provider(model="accounts/fireworks/models/example")

    async def ready(**_kwargs: object) -> dict[str, object]:
        return {"reachable": True, "state": "ready"}

    def bind(_choice: object, model: str) -> tuple[Path, object]:
        del model
        return tmp_path / "config.toml", provider

    monkeypatch.setattr(wizard, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(wizard, "_service_reachability", ready)
    monkeypatch.setattr(wizard, "_restart_service_for_semantic_composition", ready)
    monkeypatch.setattr(wizard, "load_config", _config(external_runtime=None))
    monkeypatch.setattr(config_load, "load_config", _config(provider=provider))
    monkeypatch.setattr(wizard, "_prompt_credential_probe_authorization", lambda: False)
    monkeypatch.setattr(provider_binding, "apply_provider_endpoint_choice", bind)
    monkeypatch.setattr(privacy_setup, "run_privacy_setup", _declined)

    async def run() -> int:
        return await wizard.run_provider_setup(
            provider="fireworks", model="accounts/fireworks/models/example"
        )

    assert anyio.run(run) == 20

    out = capsys.readouterr().out
    assert "Privacy policy: cancelled" in out
    assert "finishup --privacy" in out
    assert "finishup provider credential set" in out


def test_no_privacy_next_step_when_the_privacy_step_never_ran(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import finishup.config.load as config_load
    from finishup.cli import privacy_setup, provider_binding
    from finishup.config.write import fireworks_provider

    provider = fireworks_provider(model="accounts/fireworks/models/example")

    async def starting(**_kwargs: object) -> dict[str, object]:
        return {"reachable": True, "state": "starting"}

    def bind(_choice: object, model: str) -> tuple[Path, object]:
        del model
        return tmp_path / "config.toml", provider

    async def never(**_kwargs: object) -> object:
        raise AssertionError("the privacy step must not run before the service is ready")

    monkeypatch.setattr(wizard, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(wizard, "_service_reachability", starting)
    monkeypatch.setattr(config_load, "load_config", _config(provider=provider))
    monkeypatch.setattr(provider_binding, "apply_provider_endpoint_choice", bind)
    monkeypatch.setattr(privacy_setup, "run_privacy_setup", never)

    async def run() -> int:
        return await wizard.run_provider_setup(
            provider="fireworks", model="accounts/fireworks/models/example"
        )

    assert anyio.run(run) == 20

    out = capsys.readouterr().out
    assert "Reason: service_not_ready" in out
    assert "Privacy policy" not in out
    assert "finishup --privacy" not in out


# --- review round 3: next steps print once, and only for what this run left undone ----------------


def test_a_skipped_provider_names_the_provider_step_not_the_privacy_step(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from finishup.cli import privacy_setup, provider_binding

    async def ready(**_kwargs: object) -> dict[str, object]:
        return {"reachable": True, "state": "ready"}

    async def never(**_kwargs: object) -> object:
        raise AssertionError("the privacy step must not run without a provider")

    def skipped(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(wizard, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(wizard, "_service_reachability", ready)
    monkeypatch.setattr(provider_binding, "prompt_provider_endpoint_binding", skipped)
    monkeypatch.setattr(privacy_setup, "run_privacy_setup", never)

    assert anyio.run(wizard.run_provider_setup) == 20

    out = capsys.readouterr().out
    assert "Provider binding: skipped" in out
    assert "privacy_setup_incomplete" not in out
    assert "finishup --privacy" not in out
    assert "finishup provider endpoint" in out


def test_the_codex_wizard_prints_each_privacy_and_credential_step_once(
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import finishup.config.load as config_load
    from finishup.cli import privacy_setup, provider_binding, provider_status
    from finishup.config.write import fireworks_provider

    _codex_only(monkeypatch, home, tmp_path, "ai_powered")
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    provider = fireworks_provider(model="accounts/fireworks/models/example")

    def prompt(_text: str, *_args: object, **kwargs: object) -> str:
        default = kwargs.get("default")
        return "1" if default is None else str(default)

    async def ready(**_kwargs: object) -> dict[str, object]:
        return {"reachable": True, "state": "ready"}

    async def restarted() -> dict[str, object]:
        return {"reachable": True, "state": "ready"}

    def bind(*_args: object, **_kwargs: object) -> Path:
        return tmp_path / "config.toml"

    async def status_report(**_kwargs: object) -> dict[str, object]:
        return {
            "semantic_ready": False,
            "blockers": [
                {"condition": "provider_credential", "state": "not_connected"},
                {"condition": "llm_inference_channel", "state": "disabled"},
            ],
        }

    monkeypatch.setattr("typer.prompt", prompt)
    monkeypatch.setattr(wizard, "_service_reachability", ready)
    monkeypatch.setattr(wizard, "_restart_service_for_semantic_composition", restarted)
    monkeypatch.setattr(wizard, "_interactive_provider_setup", _REAL_PROVIDER_SETUP)
    monkeypatch.setattr(wizard, "load_config", _config(external_runtime=None))
    monkeypatch.setattr(config_load, "load_config", _config(provider=provider))
    monkeypatch.setattr(provider_binding, "prompt_provider_endpoint_binding", bind)
    monkeypatch.setattr(privacy_setup, "run_privacy_setup", _declined_with_profile)
    monkeypatch.setattr(provider_status, "provider_status_report", status_report)
    monkeypatch.setattr(wizard, "_emit_human_report", _REAL_HUMAN_REPORT)

    assert _codex_wizard() == 20

    out = capsys.readouterr().out
    assert out.count("finishup --privacy") == 1
    assert out.count("finishup provider credential set") == 1
    assert out.index("finishup --privacy") < out.index("finishup provider credential set")


_REAL_HUMAN_REPORT = wizard._emit_human_report  # pyright: ignore[reportPrivateUsage]
