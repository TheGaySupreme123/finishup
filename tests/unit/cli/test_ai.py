"""Issue #1119: short commands reuse the trusted ceremonies without secret inputs."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from finishup.cli import ai, ai_setup, privacy_setup, provider_status, setup, unlock
from finishup.cli import app as cli
from finishup.config.models import FinishUpConfig
from finishup.config.write import official_openai_provider, write_config_toml
from finishup.domain.privacy import ConversationReview
from finishup.protocol.canonical import JsonValue


@pytest.fixture(autouse=True)
def fake_readiness_reload(monkeypatch: pytest.MonkeyPatch) -> None:
    """No key-command test may restart the maintainer's service."""

    async def reload(**_kwargs: object) -> dict[str, JsonValue]:
        return {"reachable": True, "state": "ready"}

    monkeypatch.setattr(setup, "restart_service_for_semantic_composition", reload)


def test_ai_commands_are_discoverable_and_key_accepts_no_secret_input() -> None:
    runner = CliRunner()
    result = runner.invoke(cli.app, ["ai", "--help"])
    assert result.exit_code == 0, result.output
    for name in ("setup", "key", "model", "status", "on", "off"):
        assert name in result.output
    for arguments in (
        ["key", "secret-canary"],
        ["key", "--key", "secret-canary"],
        ["key", "--file", "key.txt"],
        ["key", "--stdin"],
        ["setup", "secret-canary"],
        ["on", "secret-canary"],
        ["off", "secret-canary"],
        ["status", "secret-canary"],
    ):
        result = runner.invoke(cli.app, ["ai", *arguments])
        assert result.exit_code == 2
        # Review of #1119: a pasted key is never echoed back into the terminal or a transcript.
        assert "secret-canary" not in result.output
        assert "secret-canary" not in (result.stderr if result.stderr_bytes is not None else "")


@pytest.mark.parametrize(("stored", "action"), [(False, "set"), (True, "rotate")])
def test_ai_key_selects_set_or_rotate_and_uses_only_hidden_entry(
    monkeypatch: pytest.MonkeyPatch, stored: bool, action: str
) -> None:
    calls: list[str] = []

    async def status(**_: object) -> dict[str, object]:
        return {
            "credential_connected": stored,
            "endpoint": {
                "provider_id": "openai",
                "credential_authority": "finishup_vault_api_credential",
            },
        }

    async def target(chosen: str, **_: object) -> tuple[object, None]:
        calls.append(chosen)
        return SimpleNamespace(action=chosen), None

    async def ceremony(
        target: object, credential: object, reauthentication: object
    ) -> dict[str, str]:
        assert credential is None
        assert reauthentication is None
        return {"activation_status": "stored"}

    monkeypatch.setattr(provider_status, "provider_status_report", status)
    monkeypatch.setattr(cli, "_provider_credential_target", target)
    monkeypatch.setattr(unlock, "set_provider_credential", ceremony)
    monkeypatch.setattr(unlock, "rotate_provider_credential", ceremony)
    monkeypatch.setattr(unlock, "load_auto_unlock_reauthentication", lambda: None)
    result = CliRunner().invoke(cli.app, ["ai", "key"])
    assert result.exit_code == 0, result.output
    assert calls == [action]
    assert "encrypted local vault" in result.output


def test_ai_key_unknown_presence_never_guesses_set(monkeypatch: pytest.MonkeyPatch) -> None:

    async def status(**_: object) -> dict[str, object]:
        return {
            "credential_connected": None,
            "endpoint": {"credential_authority": "finishup_vault_api_credential"},
        }

    monkeypatch.setattr(provider_status, "provider_status_report", status)
    result = CliRunner().invoke(cli.app, ["ai", "key"])
    assert result.exit_code != 0
    assert "unknown" in result.output


@pytest.mark.parametrize(
    ("command", "setting"),
    [("off", ConversationReview.LOCAL_ONLY), ("on", ConversationReview.LOCAL_AGENT_OPT_IN)],
)
def test_ai_mode_commands_reuse_the_reauthenticated_policy_path(
    monkeypatch: pytest.MonkeyPatch, command: str, setting: ConversationReview
) -> None:
    calls: list[ConversationReview] = []

    async def change(value: ConversationReview) -> object:
        calls.append(value)
        return SimpleNamespace(outcome="configured", reason=None)

    monkeypatch.setattr(privacy_setup, "run_conversation_review_change", change)
    result = CliRunner().invoke(cli.app, ["ai", command])
    assert result.exit_code == 0, result.output
    assert calls == [setting]
    if command == "off":
        assert "key stays stored" in result.output.lower()
        assert "no" in result.output.lower() and "remov" in result.output.lower()


def test_ai_setup_reuses_the_guided_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[ConversationReview] = []

    async def guided(**kwargs: object) -> int:
        setting = kwargs["conversation_review"]
        assert isinstance(setting, ConversationReview)
        calls.append(setting)
        return 0

    monkeypatch.setattr(setup, "run_provider_setup", guided)
    result = CliRunner().invoke(cli.app, ["ai", "setup"])
    assert result.exit_code == 0, result.output
    # Review of #1119: "every task" is one flow, so a "Not now" answer inside it stays local.
    result = CliRunner().invoke(cli.app, ["ai", "setup", "--every-task"])
    assert result.exit_code == 0, result.output
    assert calls == [ConversationReview.LOCAL_AGENT_OPT_IN, ConversationReview.AI_POWERED]


def test_ai_status_is_short_nonsecret_and_preserves_unknowns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    async def status(**_: object) -> dict[str, object]:
        return {
            "endpoint": {
                "provider_id": "openai",
                "model": "gpt-6.1-sol",
                "credential_authority": "finishup_vault_api_credential",
            },
            "credential_connected": None,
            "llm_inference_enabled": True,
            "repository_grant_state": "missing",
        }

    async def snapshot(*_: object) -> object:
        from dataclasses import replace

        from builders.privacy_policies import minimal_external_policy

        return SimpleNamespace(
            composed_policy=replace(
                minimal_external_policy(),
                conversation_review=ConversationReview.LOCAL_AGENT_OPT_IN,
            )
        )

    monkeypatch.setattr(provider_status, "provider_status_report", status)
    monkeypatch.setattr(privacy_setup, "get_privacy_setup_snapshot", snapshot)
    result = CliRunner().invoke(cli.app, ["ai", "status", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["review_mode"] == "local_agent_opt_in"
    assert payload["key_stored"] is None
    assert payload["privacy_permits_sending"] is False
    assert payload["model"] == "gpt-6.1-sol"
    assert "credential" not in payload
    human = CliRunner().invoke(cli.app, ["ai", "status"])
    assert human.exit_code == 0
    assert "unknown" in human.stdout
    assert len(human.stdout.splitlines()) == 1


@pytest.mark.parametrize(
    ("arguments", "answer", "selected"),
    [
        (["gpt-6-luna"], None, "gpt-6-luna"),
        ([], "3\n", "gpt-6-luna"),
        (["gpt-6.1-sol"], None, None),
    ],
)
def test_model_change_keeps_old_binding_and_runs_hidden_key_entry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    arguments: list[str],
    answer: str | None,
    selected: str | None,
) -> None:
    config_path = tmp_path / "config.toml"
    write_config_toml(
        FinishUpConfig(
            profile="local-openai", provider=official_openai_provider(model="gpt-6.1-sol")
        ),
        path=config_path,
    )
    import finishup.config.write as writers

    real_snapshot = writers.config_write_snapshot
    real_write = writers.write_config_toml_if_unchanged

    def write(config: FinishUpConfig, *, expected_bytes: bytes | None) -> Path:
        return real_write(config, path=config_path, expected_bytes=expected_bytes)

    monkeypatch.setattr(writers, "config_write_snapshot", lambda: real_snapshot(config_path))
    monkeypatch.setattr(writers, "write_config_toml_if_unchanged", write)
    keys: list[str] = []

    def key() -> None:
        from finishup.config.load import load_config

        provider = load_config({}, {}, config_path).provider
        assert provider is not None
        keys.append(provider.model)

    async def restart(**_: object) -> dict[str, object]:
        return {"reachable": True, "state": "ready"}

    monkeypatch.setattr(ai, "key", key)
    monkeypatch.setattr(setup, "restart_service_for_semantic_composition", restart)
    result = CliRunner().invoke(cli.app, ["ai", "model", *arguments], input=answer)
    assert result.exit_code == 0, result.output
    assert keys == ([] if selected is None else [selected])
    if selected is None:
        assert "unchanged" in result.output
        return
    assert "bound to" in result.output and "model" in result.output
    assert "enter" in result.output.lower()
    assert "old" in result.output.lower()


def test_a_cancelled_key_entry_restores_the_working_model(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Review of #1119: cancelling the new model's key leaves the old model and key active."""

    import typer

    config_path = tmp_path / "config.toml"
    write_config_toml(
        FinishUpConfig(
            profile="local-openai", provider=official_openai_provider(model="gpt-6.1-sol")
        ),
        path=config_path,
    )
    import finishup.config.write as writers

    real_snapshot = writers.config_write_snapshot
    real_write = writers.write_config_toml_if_unchanged

    def write(config: FinishUpConfig, *, expected_bytes: bytes | None) -> Path:
        return real_write(config, path=config_path, expected_bytes=expected_bytes)

    monkeypatch.setattr(writers, "config_write_snapshot", lambda: real_snapshot(config_path))
    monkeypatch.setattr(writers, "write_config_toml_if_unchanged", write)

    def cancelled_key() -> None:
        raise typer.Exit(130)

    monkeypatch.setattr(ai, "key", cancelled_key)
    result = CliRunner().invoke(cli.app, ["ai", "model", "gpt-6-astra"])

    from finishup.config.load import load_config

    provider = load_config({}, {}, config_path).provider
    assert result.exit_code == 130
    assert provider is not None and provider.model == "gpt-6.1-sol"
    assert "previous model is active again" in result.output


def test_reviewer_question_has_three_plain_choices_and_reasks_invalid_input(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    replies = iter(["invalid", "3"])

    def prompt(*_args: object, **_kwargs: object) -> str:
        return next(replies)

    monkeypatch.setattr("typer.prompt", prompt)
    assert ai_setup.prompt_reviewer_connection() == "local_only"
    output = capsys.readouterr().out
    assert "How should FinishUP reach an AI reviewer?" in output
    assert "Sign in with your ChatGPT subscription (uses Codex)" in output
    assert "Use an API key" in output
    assert "Not now — stay local for now" in output


@pytest.mark.anyio
async def test_not_now_records_local_only_without_prompting_for_a_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ai_setup, "prompt_reviewer_binding", lambda: "local_only")
    recorded: list[Path | None] = []

    async def local(project: Path | None) -> int:
        recorded.append(project)
        return 0

    monkeypatch.setattr(setup, "_run_local_only_privacy_setup", local)
    service: dict[str, JsonValue] = {"reachable": True, "state": "ready"}
    _, report = await setup._interactive_provider_setup(service)  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    assert recorded == [None]
    assert report["review_mode"] == "local_only"
    assert report["local_only_recorded"] is True
    assert report["credential"] == "skipped"


def test_ai_status_golden_vector_has_a_closed_schema() -> None:
    from finishup.protocol.errors import ProtocolValueError
    from finishup.protocol.schemas import validate_schema_instance

    root = Path(__file__).resolve().parents[3]
    payload = json.loads((root / "fixtures/integrations/ai-status.case.json").read_bytes())
    validate_schema_instance("ai-status", "1.0.0", payload)
    payload["credential"] = "secret-canary"
    with pytest.raises(ProtocolValueError, match="schema_instance_invalid"):
        validate_schema_instance("ai-status", "1.0.0", payload)


@pytest.mark.anyio
async def test_chatgpt_reviewer_does_not_open_an_api_provider_picker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ai_setup, "prompt_reviewer_connection", lambda: "codex_subscription")
    assert ai_setup.prompt_reviewer_binding() == "codex_subscription"


def test_api_reviewer_opens_only_the_api_picker(monkeypatch: pytest.MonkeyPatch) -> None:
    from finishup.cli import provider_binding

    monkeypatch.setattr(ai_setup, "prompt_reviewer_connection", lambda: "api_key")
    calls: list[dict[str, object]] = []

    def binding(**kwargs: object) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(provider_binding, "prompt_provider_endpoint_binding", binding)
    assert ai_setup.prompt_reviewer_binding() is None
    assert calls == [{"show_standalone_next_step": False, "api_only": True}]


def test_ai_on_cannot_claim_success_after_a_declined_privacy_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def decline(_setting: ConversationReview) -> object:
        return SimpleNamespace(outcome="declined", reason="cancelled")

    monkeypatch.setattr(privacy_setup, "run_conversation_review_change", decline)
    result = CliRunner().invoke(cli.app, ["ai", "on"])
    assert result.exit_code != 0
    assert "was not changed" in result.output
    assert "is selected" not in result.output


@pytest.mark.anyio
async def test_ai_key_uses_the_api_fallback_presence_when_codex_is_primary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def status(**_: object) -> dict[str, object]:
        return {
            "endpoint": {"credential_authority": "external_runtime_oauth"},
            "credential_connected": True,
            "fallback_endpoint": {"credential_authority": "finishup_vault_api_credential"},
            "fallback_credential_connected": False,
        }

    monkeypatch.setattr(provider_status, "provider_status_report", status)
    assert await ai.key_action() == "set"


@pytest.mark.anyio
@pytest.mark.parametrize("matches", [True, False])
async def test_ai_status_requires_privacy_permission_for_the_exact_model(
    monkeypatch: pytest.MonkeyPatch,
    matches: bool,
) -> None:
    from builders.privacy_policies import minimal_external_policy

    policy = minimal_external_policy()

    async def status(**_: object) -> dict[str, object]:
        return {
            "endpoint": {
                "provider_id": "fireworks",
                "model": "accounts/fireworks/models/minimax-m3"
                if matches
                else "accounts/fireworks/models/kimi-k3",
                "endpoint_profile_id": "fireworks-responses",
                "endpoint_profile_version": "1.0.0",
                "credential_authority": "finishup_vault_api_credential",
            },
            "credential_connected": True,
            "llm_inference_enabled": True,
            "repository_grant_state": "granted",
        }

    async def snapshot(*_: object) -> object:
        return SimpleNamespace(composed_policy=policy)

    monkeypatch.setattr(provider_status, "provider_status_report", status)
    monkeypatch.setattr(privacy_setup, "get_privacy_setup_snapshot", snapshot)
    assert (await ai.ai_status_report())["privacy_permits_sending"] is matches


def test_ai_key_reloads_readiness_after_the_hidden_ceremony(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    async def status(**_: object) -> dict[str, object]:
        return {
            "credential_connected": False,
            "endpoint": {"credential_authority": "finishup_vault_api_credential"},
        }

    def ceremony(_action: str) -> None:
        events.append("hidden-entry")

    async def reload(**_: object) -> dict[str, JsonValue]:
        events.append("reload")
        return {"reachable": True, "state": "ready"}

    monkeypatch.setattr(provider_status, "provider_status_report", status)
    monkeypatch.setattr(cli, "run_configured_provider_credential", ceremony)
    monkeypatch.setattr(setup, "restart_service_for_semantic_composition", reload)
    result = CliRunner().invoke(cli.app, ["ai", "key"])
    assert result.exit_code == 0, result.output
    assert events == ["hidden-entry", "reload"]
