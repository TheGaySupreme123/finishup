"""CLI coverage for ``finishup provider endpoint`` selectors and interactive gating.

Pins the interactive-picker predicate so ``--grok`` matches ``--fireworks``
shape, mutual exclusion across shorthand/provider/origin combinations, alias
resolution for Grok/xAI, and interactive menu choice 6.
"""

from __future__ import annotations

import contextlib
import json
import re
import sys
import tomllib
from collections.abc import Generator, Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import finishup.cli.app as cli
import finishup.cli.provider_binding as provider_binding
import finishup.config.write as write_module
from finishup.config.write import PROVIDER_PRESETS, grok_provider, provider_preset

_RUNNER = CliRunner()
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _plain(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)


@pytest.fixture
def endpoint_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Redirect service-owned config.toml writes into the test sandbox."""

    target = tmp_path / "config.toml"

    def _config_path(*, _probe: object | None = None) -> Path:
        del _probe
        return target

    def _ensure(path: Path, *, _probe: object | None = None) -> Path:
        del _probe
        path.mkdir(parents=True, exist_ok=True)
        return path

    monkeypatch.setattr(write_module, "config_file_path", _config_path)
    monkeypatch.setattr(write_module, "ensure_owner_only_dir", _ensure)
    monkeypatch.setattr(provider_binding, "config_file_path", _config_path)
    return target


@pytest.fixture
def tty_streams(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make CliRunner isolation report an interactive TTY for stdin/stdout."""

    import typer.testing as typer_testing

    original = typer_testing.CliRunner.isolation

    @contextlib.contextmanager
    def isolation_tty(
        self: CliRunner,
        input: str | bytes | None = None,
        env: Mapping[str, str | None] | None = None,
        color: bool = False,
    ) -> Generator[Any]:
        with original(self, input=input, env=env, color=color) as streams:
            monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
            monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
            yield streams

    monkeypatch.setattr(typer_testing.CliRunner, "isolation", isolation_tty)
    yield


def test_explicit_provider_without_model_uses_model_picker_not_generic_picker(
    tty_streams: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Explicit selectors share the model picker without reopening the provider menu."""

    provider_prompt_calls: list[str] = []
    model_prompt_calls: list[str] = []

    def fake_provider_prompt(*, path: Path | None = None) -> Path | None:
        del path
        provider_prompt_calls.append("prompt")
        return None

    def fake_model_prompt(choice: str) -> None:
        model_prompt_calls.append(choice)
        return None

    monkeypatch.setattr(
        provider_binding,
        "prompt_provider_endpoint_binding",
        fake_provider_prompt,
    )
    monkeypatch.setattr(provider_binding, "prompt_provider_model", fake_model_prompt)

    fireworks = _RUNNER.invoke(cli.app, ["provider", "endpoint", "--fireworks"])
    grok = _RUNNER.invoke(cli.app, ["provider", "endpoint", "--grok"])

    assert fireworks.exit_code == 2
    assert grok.exit_code == 2
    assert "invalid_request" in _plain(fireworks.output)
    assert "invalid_request" in _plain(grok.output)
    assert provider_prompt_calls == []
    assert model_prompt_calls == ["fireworks", "grok"]
    assert "LLM endpoint" not in _plain(fireworks.output)
    assert "LLM endpoint" not in _plain(grok.output)


def test_bare_interactive_endpoint_enters_generic_picker(
    tty_streams: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no selector, a TTY still opens the reviewed-provider menu."""

    prompt_calls: list[str] = []

    def fake_prompt(*, path: Path | None = None) -> Path | None:
        del path
        prompt_calls.append("prompt")
        return None

    monkeypatch.setattr(provider_binding, "prompt_provider_endpoint_binding", fake_prompt)

    result = _RUNNER.invoke(cli.app, ["provider", "endpoint"])
    assert result.exit_code == 0
    assert prompt_calls == ["prompt"]


def test_non_tty_bare_endpoint_is_usage_failure() -> None:
    """Non-interactive streams keep the usage-failure path (no menu)."""

    result = _RUNNER.invoke(cli.app, ["provider", "endpoint"])
    assert result.exit_code == 2
    assert "invalid_request" in _plain(result.output)


def test_provider_catalog_exposes_the_installed_presets_and_suggestions() -> None:
    """The agent-start command derives its output from the packaged preset catalog."""

    result = _RUNNER.invoke(cli.app, ["provider", "catalog", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["schema"] == "yoetz.provider-catalog/1"
    assert payload["limitations"] == [
        "catalog_support_is_not_account_entitlement",
        "catalog_support_is_not_live_provider_proof",
    ]
    assert [entry["preset"] for entry in payload["presets"]] == list(PROVIDER_PRESETS)
    for entry in payload["presets"]:
        preset = PROVIDER_PRESETS[entry["preset"]]
        assert entry["provider_id"] == preset.provider_id
        assert entry["endpoint_profile_id"] == preset.endpoint_profile_id
        assert entry["endpoint_profile_version"] == preset.endpoint_profile_version
        assert entry["suggested_models"] == list(preset.suggested_models)
        assert entry["custom_model_id_supported"] is True


def test_non_tty_grok_without_model_is_usage_failure() -> None:
    result = _RUNNER.invoke(cli.app, ["provider", "endpoint", "--grok"])
    assert result.exit_code == 2
    assert "invalid_request" in _plain(result.output)


def test_no_interactive_provider_without_model_is_usage_failure(
    tty_streams: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    prompted: list[str] = []

    def fake_model_prompt(choice: str) -> None:
        prompted.append(choice)

    monkeypatch.setattr(provider_binding, "prompt_provider_model", fake_model_prompt)

    result = _RUNNER.invoke(
        cli.app,
        ["provider", "endpoint", "--provider", "anthropic", "--no-interactive"],
    )

    assert result.exit_code == 2
    assert "invalid_request" in _plain(result.output)
    assert prompted == []


@pytest.mark.parametrize(
    "args",
    [
        ["--official", "--fireworks", "--model", "m"],
        ["--official", "--grok", "--model", "m"],
        ["--fireworks", "--grok", "--model", "m"],
        ["--official", "--provider", "openai", "--model", "m"],
        ["--fireworks", "--provider", "fireworks", "--model", "m"],
        ["--grok", "--provider", "grok", "--model", "m"],
        ["--official", "--https-origin", "https://llm.example.com", "--model", "m"],
        ["--fireworks", "--https-origin", "https://llm.example.com", "--model", "m"],
        ["--grok", "--https-origin", "https://llm.example.com", "--model", "m"],
        [
            "--provider",
            "openai",
            "--https-origin",
            "https://llm.example.com",
            "--model",
            "m",
        ],
    ],
)
def test_selector_mutual_exclusion_matrix(args: list[str]) -> None:
    """Shorthands, ``--provider``, and ``--https-origin`` are pairwise exclusive."""

    result = _RUNNER.invoke(cli.app, ["provider", "endpoint", *args])
    assert result.exit_code == 2
    assert "invalid_request" in _plain(result.output)


@pytest.mark.parametrize("alias", ["grok", "xai", "x-ai"])
def test_provider_aliases_resolve_to_same_grok_preset(endpoint_config: Path, alias: str) -> None:
    result = _RUNNER.invoke(
        cli.app,
        [
            "provider",
            "endpoint",
            "--provider",
            alias,
            "--model",
            "grok-4.5",
            "--json",
        ],
    )
    assert result.exit_code == 0
    assert endpoint_config.is_file()
    loaded = tomllib.loads(endpoint_config.read_text(encoding="utf-8"))
    provider = loaded["provider"]
    expected = grok_provider(model="grok-4.5")
    assert provider["provider_id"] == expected.provider_id
    assert provider["endpoint_profile_id"] == expected.endpoint_profile_id
    assert provider["endpoint_profile_version"] == expected.endpoint_profile_version
    assert provider["model"] == "grok-4.5"
    assert provider["capability_profile"] == expected.capability_profile
    assert provider_preset(alias).choice == "grok"


def test_grok_shorthand_writes_same_preset_as_provider_alias(
    endpoint_config: Path,
) -> None:
    result = _RUNNER.invoke(
        cli.app,
        ["provider", "endpoint", "--grok", "--model", "grok-4.5", "--json"],
    )
    assert result.exit_code == 0
    loaded = tomllib.loads(endpoint_config.read_text(encoding="utf-8"))
    assert loaded["provider"]["provider_id"] == "xai"
    assert loaded["provider"]["endpoint_profile_id"] == "xai-openai-chat-completions"
    assert loaded["provider"]["model"] == "grok-4.5"


def test_endpoint_write_preserves_an_existing_storage_data_dir(
    endpoint_config: Path, tmp_path: Path
) -> None:
    """A valid ``storage.data_dir`` base must survive a provider-binding write (#520).

    Hand-parsed strict validation rejected this valid file, and the swallowed failure
    silently replaced the operator's configuration with defaults — dropping ``data_dir``.
    """

    endpoint_config.write_text(
        'schema_version = "1"\n'
        'profile = "strict-local"\n'
        "\n"
        "[storage]\n"
        f'data_dir = "{tmp_path / "state"}"\n',
        encoding="utf-8",
    )

    result = _RUNNER.invoke(
        cli.app,
        ["provider", "endpoint", "--grok", "--model", "grok-4.5", "--json"],
    )

    assert result.exit_code == 0
    loaded = tomllib.loads(endpoint_config.read_text(encoding="utf-8"))
    assert loaded["storage"]["data_dir"] == str(tmp_path / "state")
    assert loaded["provider"]["provider_id"] == "xai"


def test_endpoint_write_refuses_an_invalid_base_instead_of_discarding_it(
    endpoint_config: Path,
) -> None:
    """An unloadable config is a bounded refusal, never silently replaced with defaults."""

    original = "[storage]\ndata_dir = 5\n"
    endpoint_config.write_text(original, encoding="utf-8")

    result = _RUNNER.invoke(
        cli.app,
        ["provider", "endpoint", "--grok", "--model", "grok-4.5", "--json"],
    )

    assert result.exit_code == 2
    assert "invalid_request: config_value_invalid" in result.stderr
    assert endpoint_config.read_text(encoding="utf-8") == original


@pytest.mark.parametrize(
    "choice",
    [
        "openai",
        "fireworks",
        "anthropic",
        "gemini",
        "openrouter",
        "grok",
        "vercel-ai-gateway",
    ],
)
def test_scripted_explicit_model_remains_exact_for_every_preset(
    endpoint_config: Path,
    choice: str,
) -> None:
    model = f"owner-supplied/{choice}"
    result = _RUNNER.invoke(
        cli.app,
        [
            "provider",
            "endpoint",
            "--provider",
            choice,
            "--model",
            model,
            "--no-interactive",
            "--json",
        ],
    )

    assert result.exit_code == 0
    loaded = tomllib.loads(endpoint_config.read_text(encoding="utf-8"))
    assert loaded["provider"]["model"] == model


def test_explicit_interactive_provider_uses_shared_model_picker(
    endpoint_config: Path,
    tty_streams: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompted: list[str] = []

    def fake_model_prompt(choice: str) -> str:
        prompted.append(choice)
        return "claude-opus-4-8"

    monkeypatch.setattr(provider_binding, "prompt_provider_model", fake_model_prompt)
    result = _RUNNER.invoke(
        cli.app,
        ["provider", "endpoint", "--provider", "anthropic", "--json"],
    )

    assert result.exit_code == 0
    assert prompted == ["anthropic"]
    loaded = tomllib.loads(endpoint_config.read_text(encoding="utf-8"))
    assert loaded["provider"]["model"] == "claude-opus-4-8"


@pytest.mark.parametrize("choice", list(PROVIDER_PRESETS))
def test_every_reviewed_provider_picker_has_suggestions_and_custom_entry(
    choice: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    echoes: list[str] = []

    def fake_echo(value: object = "", **_kwargs: object) -> None:
        echoes.append(str(value))

    def choose_default(*_args: object, **_kwargs: object) -> str:
        return "1"

    monkeypatch.setattr(provider_binding.typer, "echo", fake_echo)
    monkeypatch.setattr(provider_binding.typer, "prompt", choose_default)

    selected = provider_binding.prompt_provider_model(choice)

    assert selected == provider_preset(choice).default_model
    assert any("Custom model ID" in line for line in echoes)
    assert any("availability depends on your account" in line for line in echoes)


def test_model_picker_accepts_custom_model_id(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = iter(("c", "future-model-id"))

    def answer_prompt(*_args: object, **_kwargs: object) -> str:
        return next(answers)

    monkeypatch.setattr(provider_binding.typer, "prompt", answer_prompt)

    assert provider_binding.prompt_provider_model("openai") == "future-model-id"


@pytest.mark.parametrize("answers", [("c", ""), ("99",)])
def test_model_picker_fails_closed_on_empty_or_invalid_selection(
    answers: tuple[str, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supplied = iter(answers)
    errors: list[str] = []

    def answer_prompt(*_args: object, **_kwargs: object) -> str:
        return next(supplied)

    def capture_error(value: object = "", **kwargs: object) -> None:
        if kwargs.get("err") is True:
            errors.append(str(value))

    monkeypatch.setattr(provider_binding.typer, "prompt", answer_prompt)
    monkeypatch.setattr(provider_binding.typer, "echo", capture_error)

    assert provider_binding.prompt_provider_model("openai") is None
    assert errors and errors[-1].startswith("invalid_request:")


def test_interactive_menu_choice_6_writes_grok_preset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Menu option 6 is Grok/xAI and must write the reviewed nonsecret preset."""

    target = tmp_path / "config.toml"
    prompts: list[str] = []
    echoes: list[str] = []

    def fake_prompt(text: str, default: object = ..., **_kwargs: object) -> str:
        prompts.append(text)
        if text == "Select":
            return "6"
        if text == "Select model":
            return "1"
        raise AssertionError(f"unexpected prompt: {text!r}")

    def fake_echo(msg: object = "", **_kwargs: object) -> None:
        del _kwargs
        echoes.append(str(msg))

    monkeypatch.setattr(provider_binding.typer, "prompt", fake_prompt)
    monkeypatch.setattr(provider_binding.typer, "echo", fake_echo)

    written = provider_binding.prompt_provider_endpoint_binding(path=target)
    assert written == target
    assert target.is_file()
    assert any(p == "Select" for p in prompts)
    assert any(p == "Select model" for p in prompts)
    loaded = tomllib.loads(target.read_text(encoding="utf-8"))
    assert loaded["provider"]["provider_id"] == "xai"
    assert loaded["provider"]["endpoint_profile_id"] == "xai-openai-chat-completions"
    assert loaded["provider"]["model"] == provider_preset("grok").default_model
    joined = "\n".join(echoes)
    assert "xai" in joined
    assert "xai-openai-chat-completions" in joined
    assert "Custom model ID" in joined
    assert "next: run 'finishup provider credential set'" in joined


def test_composed_endpoint_binding_suppresses_standalone_next_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "config.toml"
    answers = iter(("2", "1"))
    echoes: list[str] = []

    def fake_prompt(*_args: object, **_kwargs: object) -> str:
        return next(answers)

    def fake_echo(value: object = "", **_kwargs: object) -> None:
        echoes.append(str(value))

    monkeypatch.setattr(provider_binding.typer, "prompt", fake_prompt)
    monkeypatch.setattr(provider_binding.typer, "echo", fake_echo)

    written = provider_binding.prompt_provider_endpoint_binding(
        path=target,
        show_standalone_next_step=False,
    )

    assert written == target
    assert target.is_file()
    assert all("next: run 'finishup provider credential set'" not in line for line in echoes)
