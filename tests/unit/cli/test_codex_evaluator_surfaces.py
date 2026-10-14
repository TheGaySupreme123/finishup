"""Issue #855: every operator surface carries the same evaluator cause and continuation.

The terminal interface runtime, the prompt-loop menu, and the upgrade plan are exercised against
stubbed subscription functions; nothing here reads a real configuration or starts Codex.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from finishup.application import upgrade
from finishup.cli import codex_subscription
from finishup.cli import menu as menu_module
from finishup.tui.runtime import FinishUpRuntime, RuntimeError_


def test_tui_defaults_offer_only_the_eligible_runtime_and_keep_the_effort(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(codex_subscription, "default_codex_evaluator_executable", lambda: None)
    monkeypatch.setattr(codex_subscription, "default_codex_home", lambda: tmp_path / "home")
    monkeypatch.setattr(codex_subscription, "default_codex_subscription_model", lambda: "m")
    monkeypatch.setattr(
        codex_subscription, "default_codex_subscription_reasoning_effort", lambda: "xhigh"
    )

    executable, home, model, effort = FinishUpRuntime(cwd=tmp_path).codex_subscription_defaults()

    # No admitted runtime: the field stays empty rather than offering a newer host binary.
    assert (executable, home, model, effort) == ("", str(tmp_path / "home"), "m", "xhigh")

    retained = tmp_path / "bundle" / "codex"
    monkeypatch.setattr(codex_subscription, "default_codex_evaluator_executable", lambda: retained)
    assert FinishUpRuntime(cwd=tmp_path).codex_subscription_defaults()[0] == str(retained)


@pytest.mark.anyio
async def test_tui_failures_carry_the_subscription_next_step(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def stranded() -> dict[str, object]:
        raise ValueError("codex_runtime_executable_changed")

    monkeypatch.setattr(codex_subscription, "codex_subscription_status", stranded)

    with pytest.raises(RuntimeError_) as raised:
        await FinishUpRuntime(cwd=tmp_path).codex_subscription_status()

    assert raised.value.reason == "codex_runtime_executable_changed"
    (detail,) = raised.value.details
    assert "finishup provider codex-subscription repair" in detail


def test_tui_repair_plan_refusal_is_bounded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def refuse(**_kwargs: object) -> dict[str, object]:
        raise OSError("/private/path/that/must/not/leak")

    monkeypatch.setattr(codex_subscription, "codex_subscription_repair_plan", refuse)

    with pytest.raises(RuntimeError_) as raised:
        FinishUpRuntime(cwd=tmp_path).codex_subscription_repair_plan()

    assert raised.value.reason == "codex_runtime_unavailable"
    assert "/private/path" not in " ".join((raised.value.message, *raised.value.details))


def test_menu_renders_the_exact_subscription_cause(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def stranded() -> object:
        raise ValueError("codex_runtime_profile_outdated")

    menu_module._run_subscription(stranded)  # pyright: ignore[reportPrivateUsage]

    stderr = capsys.readouterr().err
    assert stderr.startswith("codex_subscription: codex_runtime_profile_outdated: ")
    assert "finishup provider codex-subscription repair" in stderr
    assert "invalid_request" not in stderr


def test_menu_offers_repair_and_runtime_status(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []

    def plan(**_kwargs: object) -> dict[str, object]:
        calls.append("plan")
        return {"state_before": "codex_runtime_executable_changed"}

    async def repair(**_kwargs: object) -> dict[str, object]:
        calls.append("repair")
        return {"login_reused": True}

    async def restart() -> dict[str, object]:
        calls.append("restart")
        return {"reachable": True}

    def runtime_status(**_kwargs: object) -> dict[str, object]:
        calls.append("runtime_status")
        return {"next_command": None}

    monkeypatch.setattr(codex_subscription, "codex_subscription_repair_plan", plan)
    monkeypatch.setattr(codex_subscription, "codex_subscription_repair", repair)
    monkeypatch.setattr(codex_subscription, "codex_evaluator_runtime_status", runtime_status)
    monkeypatch.setattr("finishup.cli.setup.restart_service_for_semantic_composition", restart)
    answers = iter(["8", "9"])

    def ask(_choices: tuple[str, ...]) -> str:
        return next(answers)

    def confirm(*_args: object, **_kwargs: object) -> bool:
        return True

    monkeypatch.setattr(menu_module, "_ask", ask)
    monkeypatch.setattr("typer.confirm", confirm)

    menu_module._provider_menu()  # pyright: ignore[reportPrivateUsage]
    menu_module._provider_menu()  # pyright: ignore[reportPrivateUsage]

    assert calls == ["plan", "repair", "restart", "runtime_status"]
    output = capsys.readouterr().out
    assert "8  Repair the Codex evaluator binding" in output
    assert "9  Codex evaluator runtime status" in output


def test_upgrade_plan_verifies_the_evaluator_after_activation() -> None:
    from finishup.cli.app import app

    steps = upgrade.build_upgrade_plan(["cursor"], {})
    titles = [step.title for step in steps]
    assert titles[-2:] == ["Activate and verify", "AI-powered review evaluator"]
    evaluator = steps[-1]
    assert evaluator.commands == (
        ("finishup", "provider", "codex-subscription", "runtime", "status", "--json"),
    )
    assert "does not check sign-in" in evaluator.detail
    assert "never signs in" in evaluator.detail
    assert CliRunner().invoke(app, [*evaluator.commands[0][1:-1], "--help"]).exit_code == 0
