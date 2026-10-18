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


# -- interactive defaults keep newest-first fallback (round-2 finding 4) -------------------------


def test_setup_executable_selection_pins_only_a_typed_different_path(tmp_path: Path) -> None:
    offered = tmp_path / "bundle" / "codex"
    typed = tmp_path / "elsewhere" / "codex"
    select = codex_subscription.setup_executable_selection

    assert select(str(offered), offered) is None
    assert select(offered, offered) is None
    assert select("", offered) is None
    assert select("   ", None) is None
    assert select(None, offered) is None
    assert select(str(typed), offered) == typed
    assert select(str(typed), None) == typed


@pytest.mark.anyio
async def test_tui_accepting_the_offered_runtime_keeps_newest_first_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.cli import setup as setup_module

    offered = tmp_path / "bundle" / "codex"
    typed = tmp_path / "elsewhere" / "codex"
    seen: list[Path | None] = []

    async def setup(*, executable: Path | None, **_kwargs: object) -> dict[str, object]:
        seen.append(executable)
        return {"runtime_version": "0.159.0"}

    async def restart(**_kwargs: object) -> None:
        return None

    monkeypatch.setattr(codex_subscription, "default_codex_evaluator_executable", lambda: offered)
    monkeypatch.setattr(codex_subscription, "default_codex_home", lambda: tmp_path / "home")
    monkeypatch.setattr(codex_subscription, "default_codex_subscription_model", lambda: "m")
    monkeypatch.setattr(
        codex_subscription, "default_codex_subscription_reasoning_effort", lambda: "xhigh"
    )
    monkeypatch.setattr(codex_subscription, "codex_subscription_setup", setup)
    monkeypatch.setattr(setup_module, "restart_service_for_semantic_composition", restart)
    runtime = FinishUpRuntime(cwd=tmp_path)
    executable, home, model, effort = runtime.codex_subscription_defaults()

    await runtime.setup_codex_subscription(executable, home, model, effort)
    await runtime.setup_codex_subscription(str(typed), home, model, effort)

    # The accepted default is discovery (None: newest first, falling back on failure); only a
    # path the owner typed instead pins setup to that one runtime.
    assert seen == [None, typed]


@pytest.mark.anyio
async def test_cli_prompt_accepting_the_offered_runtime_keeps_newest_first_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    offered = tmp_path / "bundle" / "codex"
    typed = tmp_path / "elsewhere" / "codex"
    seen: list[Path | None] = []
    previewed: list[Path] = []
    typed_answer: list[str] = []

    def prompt(message: str, **kwargs: object) -> str:
        if message == "Codex evaluator executable" and typed_answer:
            return typed_answer[0]
        default = kwargs.get("default")
        return "browser" if default is None else str(default)

    def preview(*, executable: Path, **_kwargs: object) -> dict[str, object]:
        previewed.append(executable)
        return {
            "executable_path": str(executable),
            "runtime_version": "0.162.1",
            "runtime_floor": "0.157.1",
            "runtime_source_identity": "openai-codex-npm-darwin-arm64-0.162.1",
            "executable_sha256": "sha256:" + "a" * 64,
            "code_mode_host_sha256": "sha256:" + "b" * 64,
            "capability_profile": "codex-evaluator/capability/v3",
            "capability_evidence_expires_at": "2026-11-30T00:00:00Z",
            "codex_home": str(tmp_path / "home"),
            "disconnect_command": "finishup provider codex disconnect",
            "rollback_command": "finishup provider codex rollback",
        }

    async def setup(*, executable: Path | None, **_kwargs: object) -> dict[str, object]:
        seen.append(executable)
        return {}

    def confirm(message: str, **_kwargs: object) -> bool:
        return message == "Continue to Codex sign-in?"

    monkeypatch.setattr(codex_subscription, "default_codex_evaluator_executable", lambda: offered)
    monkeypatch.setattr(codex_subscription, "default_codex_home", lambda: tmp_path / "home")
    monkeypatch.setattr(codex_subscription, "codex_subscription_preview", preview)
    monkeypatch.setattr(codex_subscription, "runtime_bundle", lambda: tmp_path / "bundle")
    monkeypatch.setattr(codex_subscription, "codex_subscription_setup", setup)
    monkeypatch.setattr("typer.prompt", prompt)
    monkeypatch.setattr("typer.confirm", confirm)

    await codex_subscription.prompt_codex_subscription_setup()
    typed_answer.append(str(typed))
    await codex_subscription.prompt_codex_subscription_setup()

    # The preview still shows the runtime that would be bound; setup keeps the fallback.
    assert previewed == [offered, typed]
    assert seen == [None, typed]


def test_setup_keeps_only_a_closed_codex_sandbox_reason() -> None:
    # ADR-006 (2026-10-14): `finishup setup` keeps why Codex's Linux sandbox is unverified, so a
    # missing system bubblewrap is disclosed beside `codex_sandbox_unavailable`.
    from finishup.cli.setup import (
        _sandbox_unavailable_reason,  # pyright: ignore[reportPrivateUsage]
    )

    for reason in ("bubblewrap_missing", "user_namespaces_unavailable"):
        status = {"codex_sandbox_unavailable": True, "codex_sandbox_unavailable_reason": reason}
        assert _sandbox_unavailable_reason(status) == reason
    assert _sandbox_unavailable_reason({"codex_sandbox_unavailable": True}) is None
    assert (
        _sandbox_unavailable_reason(
            {"codex_sandbox_unavailable": False, "codex_sandbox_unavailable_reason": "x"}
        )
        is None
    )
    assert (
        _sandbox_unavailable_reason(
            {"codex_sandbox_unavailable": True, "codex_sandbox_unavailable_reason": "canary"}
        )
        is None
    )
