"""Interactive nonsecret LLM endpoint binding for reviewed provider presets.

Writes service-owned ``config.toml`` only. Credentials remain on the confidential
``finishup provider credential`` ceremony path.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final, Literal

import typer

from finishup.config.load import load_config
from finishup.config.models import ConfigError, FinishUpConfig, ProviderProfileConfig
from finishup.config.paths import config_file_path
from finishup.config.write import (
    anthropic_provider,
    fireworks_provider,
    google_gemini_provider,
    grok_provider,
    official_openai_provider,
    openrouter_provider,
    owner_declared_openai_provider,
    provider_preset,
    semantic_fallback_primary_config,
    semantic_fallback_removed_config,
    vercel_ai_gateway_provider,
    write_config_toml,
    write_provider_binding,
)

__all__ = [
    "NEXT_CREDENTIAL",
    "ProviderEndpointChoice",
    "apply_provider_endpoint_choice",
    "prompt_provider_endpoint_binding",
    "prompt_provider_model",
    "remove_semantic_fallback",
    "set_semantic_fallback_primary",
]


def remove_semantic_fallback(*, path: Path | None = None) -> tuple[Path, FinishUpConfig]:
    """Drop the fallback endpoint and its selector; the primary keeps serving alone (#582)."""

    updated = semantic_fallback_removed_config(_load_base(path))
    return write_config_toml(updated, path=path), updated


def set_semantic_fallback_primary(
    primary: Literal["api_provider", "codex_subscription"], *, path: Path | None = None
) -> tuple[Path, FinishUpConfig]:
    """Swap which bound endpoint serves first; both stay bound and approved (#582)."""

    updated = semantic_fallback_primary_config(_load_base(path), primary)
    return write_config_toml(updated, path=path), updated


ProviderEndpointChoice = Literal[
    "official_openai",
    "fireworks",
    "anthropic",
    "google_gemini",
    "openrouter",
    "grok",
    "vercel_ai_gateway",
    "owner_declared",
]

NEXT_CREDENTIAL: Final = (
    "run 'finishup provider credential set' from a local terminal to provision the "
    "provider credential through the confidential ceremony"
)


def _load_base(path: Path | None) -> FinishUpConfig:
    """Load the exact write-target config through the canonical loader; never guess.

    Strict raw-TOML validation rejected valid files whose ``storage.data_dir`` string the
    canonical loader converts to ``Path`` first, and swallowing that failure silently replaced
    the operator's configuration with defaults — so a provider-binding write would drop the very
    settings it must preserve (#520). An unloadable config now surfaces as its bounded
    ``ConfigError``, which every caller already reports as ``invalid_request``.
    """

    return load_config({}, {}, config_file_path() if path is None else path)


def apply_provider_endpoint_choice(
    choice: ProviderEndpointChoice,
    *,
    model: str,
    https_origin: str | None = None,
    path: Path | None = None,
    as_fallback: bool = False,
) -> tuple[Path, ProviderProfileConfig]:
    """Validate and write the selected nonsecret provider binding.

    ``as_fallback`` declares this API provider as the fallback behind the already-bound Codex
    subscription (issue #582) instead of replacing it.
    """

    if not model:
        raise ConfigError("config_value_invalid")
    if choice == "official_openai":
        provider = official_openai_provider(model=model)
    elif choice == "fireworks":
        provider = fireworks_provider(model=model)
    elif choice == "anthropic":
        provider = anthropic_provider(model=model)
    elif choice == "google_gemini":
        provider = google_gemini_provider(model=model)
    elif choice == "openrouter":
        provider = openrouter_provider(model=model)
    elif choice == "grok":
        provider = grok_provider(model=model)
    elif choice == "vercel_ai_gateway":
        provider = vercel_ai_gateway_provider(model=model)
    else:
        if https_origin is None:
            raise ConfigError("https_origin_invalid")
        provider = owner_declared_openai_provider(model=model, https_origin=https_origin)
    written = write_provider_binding(
        provider, path=path, base=_load_base(path), as_fallback=as_fallback
    )
    return written, provider


def prompt_provider_model(choice: str) -> str | None:
    """Select a repository-reviewed suggestion or enter an explicit custom model ID."""

    preset = provider_preset(choice)
    typer.echo("")
    typer.echo(f"  Suggested {preset.provider_id} models")
    typer.echo("  Repository-reviewed convenience list; availability depends on your account.")
    for index, model_id in enumerate(preset.suggested_models, start=1):
        typer.echo(f"  {index}  {model_id}")
    typer.echo("  c  Custom model ID")
    raw = typer.prompt("Select model", default="1").strip().lower()
    if raw in {"c", "custom", "manual"}:
        custom = typer.prompt("  Custom model id", show_default=False).strip()
        if not custom:
            typer.echo("invalid_request: model_id_required", err=True)
            return None
        return custom
    if raw.isdecimal() and 1 <= int(raw) <= len(preset.suggested_models):
        return preset.suggested_models[int(raw) - 1]
    typer.echo("invalid_request: choose a listed model number or c", err=True)
    return None


def prompt_provider_endpoint_binding(
    *,
    path: Path | None = None,
    show_standalone_next_step: bool = True,
) -> Path | Literal["codex_subscription"] | None:
    """Prompt for a reviewed provider preset or custom origin; never asks for secrets.

    ``show_standalone_next_step`` is false only when a composed setup flow owns the next
    transition. Standalone endpoint setup keeps the repair command, while the wizard avoids
    implying that it stopped before its policy and confidential-credential phases.
    """

    typer.echo("")
    typer.echo("LLM endpoint (nonsecret)")
    typer.echo("  1  Official OpenAI (api.openai.com)")
    typer.echo("  2  Fireworks AI (api.fireworks.ai/inference/v1)")
    typer.echo("  3  Anthropic Claude (OpenAI-compatible Chat Completions)")
    typer.echo("  4  Google Gemini (OpenAI-compatible Chat Completions)")
    typer.echo("  5  OpenRouter (OpenAI-compatible Chat Completions)")
    typer.echo("  6  Grok / xAI (OpenAI-compatible Chat Completions)")
    typer.echo("  7  Vercel AI Gateway (OpenAI-compatible Responses)")
    typer.echo("  8  Custom OpenAI-compatible HTTPS origin")
    typer.echo("  9  Codex with ChatGPT subscription (Codex-managed OAuth; no API key)")
    typer.echo("  s  Skip for now")
    raw = typer.prompt("Select", default="s").strip().lower()
    if raw in {"s", "skip", ""}:
        return None
    allowed = {"1", "2", "3", "4", "5", "6", "7", "8", "9"}
    if raw not in allowed:
        typer.echo("invalid_request: choose 1, 2, 3, 4, 5, 6, 7, 8, 9, or s", err=True)
        return None
    if raw == "9":
        return "codex_subscription"

    choices: dict[str, ProviderEndpointChoice] = {
        "1": "official_openai",
        "2": "fireworks",
        "3": "anthropic",
        "4": "google_gemini",
        "5": "openrouter",
        "6": "grok",
        "7": "vercel_ai_gateway",
        "8": "owner_declared",
    }
    choice = choices[raw]
    preset = None if choice == "owner_declared" else provider_preset(choice)
    if preset is None:
        model = typer.prompt("  Model id", show_default=False).strip()
    else:
        selected = prompt_provider_model(preset.choice)
        if selected is None:
            return None
        model = selected
    try:
        if choice == "owner_declared":
            origin = typer.prompt(
                "  HTTPS origin (https://host[:port] only; no path, userinfo, or secrets)"
            ).strip()
            written, provider = apply_provider_endpoint_choice(
                "owner_declared", model=model, https_origin=origin, path=path
            )
        else:
            written, provider = apply_provider_endpoint_choice(choice, model=model, path=path)
    except ConfigError as error:
        typer.echo(f"invalid_request: {error.reason_code}", err=True)
        return None

    typer.echo(f"  wrote provider binding to {written}")
    typer.echo(
        f"  {provider.provider_id} / {provider.endpoint_profile_id}@"
        f"{provider.endpoint_profile_version} model={provider.model}"
    )
    if provider.owner_declared_endpoint is not None:
        typer.echo(f"  https_origin={provider.owner_declared_endpoint.https_origin}")
        typer.echo(
            "  note: owner-declared hosts use unknown data-use posture and never inherit "
            "the assisted recommendation badge"
        )
    if show_standalone_next_step:
        typer.echo(f"  next: {NEXT_CREDENTIAL}")
    return written
