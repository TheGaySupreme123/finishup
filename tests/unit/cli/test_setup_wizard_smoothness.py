"""First-run setup friction found walking ``finishup setup run`` in a test instance."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import anyio
import pytest

from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.cli import host_connection
from finishup.cli import setup as wizard


def _ignore(*_args: object, **_kwargs: object) -> None:
    return None


def _empty_answer(*_args: object, **_kwargs: object) -> str:
    return ""


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

    monkeypatch.setattr(host_connection, "run_host_connection", connect)
    monkeypatch.setattr(wizard, "_write_setup_marker", _ignore)
    monkeypatch.setattr(wizard, "_choose_review_mode", lambda: "local_only")
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
    async def reachable(**_kwargs: object) -> dict[str, object]:
        return {"reachable": True, "state": "ready"}

    async def provider_setup(
        service: dict[str, object], **_kwargs: object
    ) -> tuple[dict[str, object], dict[str, object]]:
        return service, {
            "binding": "configured",
            "credential": "external_runtime_oauth",
            "model": "gpt-6-luna",
            "model_fallback_from": "gpt-6.1-sol",
        }

    monkeypatch.setattr(wizard, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(wizard, "_service_reachability", reachable)
    monkeypatch.setattr(wizard, "_interactive_provider_setup", provider_setup)
    monkeypatch.setattr(wizard, "_emit_provider_setup_layer_report", _ignore)

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
