"""Short owner commands composed from existing provider and privacy ceremonies.

No command here accepts, reads, copies, or serializes a provider secret.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Annotated, Any, Final, Literal, NoReturn, cast

import typer

from finishup.cli.bootstrap import control_failure, stdout_json
from finishup.config.models import ConfigError, ExternalRuntimeProfileConfig
from finishup.domain.privacy import ConversationReview, EgressChannel
from finishup.ports.control import ControlError
from finishup.protocol.canonical import JsonValue

ai_app = typer.Typer(
    help="Set up optional AI review, enter a key safely, or change models.", no_args_is_help=True
)


def _run[T](operation: Callable[[], Awaitable[T]]) -> T:
    from finishup.cli.app import run_async

    return run_async(operation)


def _fail(message: str) -> NoReturn:
    typer.echo(message, err=True)
    raise typer.Exit(20)


def _usage_error(message: str) -> NoReturn:
    typer.echo(message, err=True)
    raise typer.Exit(2)


# Commands that take no arguments accept and discard extra ones instead of letting Click echo them
# back: a key pasted after `finishup ai key` must never be repeated into a terminal or transcript.
_NO_EXTRA_ARGS: Final = {"allow_extra_args": True, "ignore_unknown_options": True}


def _refuse_extra_arguments(context: typer.Context) -> None:
    if context.args:
        _usage_error(
            "This command takes no arguments, and FinishUP never accepts a key on the command "
            "line. Run it on its own and type the key at the hidden prompt. If you pasted a key, "
            "clear it from your shell history and replace it at your provider."
        )


@ai_app.command("setup", context_settings=_NO_EXTRA_ARGS)
def setup(
    context: typer.Context,
    every_task: Annotated[
        bool,
        typer.Option(
            "--every-task",
            help="Review every task with AI, instead of letting your agent turn it on when it helps.",
        ),
    ] = False,
) -> None:
    """Choose ChatGPT or an API key, then approve privacy in the trusted terminal."""

    _refuse_extra_arguments(context)

    from finishup.cli.setup import run_provider_setup

    code = _run(
        lambda: run_provider_setup(
            conversation_review=ConversationReview.AI_POWERED
            if every_task
            else ConversationReview.LOCAL_AGENT_OPT_IN
        )
    )
    raise typer.Exit(code)


async def _configured_key() -> tuple[Mapping[str, Any], bool | None]:
    """Read presence only; unknown must never turn a rotation into an initial write."""

    from finishup.cli.provider_status import provider_status_report

    report = await provider_status_report()
    endpoint = report.get("endpoint")
    if not isinstance(endpoint, Mapping):
        _fail("Choose a reviewer first: finishup ai setup")
    stored = report.get("credential_connected")
    if endpoint.get("credential_authority") != "finishup_vault_api_credential":
        fallback = report.get("fallback_endpoint")
        if (
            not isinstance(fallback, Mapping)
            or fallback.get("credential_authority") != "finishup_vault_api_credential"
        ):
            _fail(
                "ChatGPT sign-in belongs to Codex. Use finishup provider codex-subscription setup."
            )
        endpoint = fallback
        stored = report.get("fallback_credential_connected")
    return endpoint, stored if type(stored) is bool else None


async def key_action() -> Literal["set", "rotate"]:
    """Read presence only; unknown must never become an initial write."""

    _endpoint, stored = await _configured_key()
    if type(stored) is not bool:
        _fail("Key stored: unknown. Run finishup service unlock, then finishup ai key.")
    return "rotate" if stored else "set"


@ai_app.command("key", context_settings=_NO_EXTRA_ARGS)
def key_command(context: typer.Context) -> None:
    """Enter or replace the stored key. Use finishup ai forget-key to remove it."""

    _refuse_extra_arguments(context)
    key()


def key() -> None:
    """Hidden key entry for the configured provider; also the last step of ``ai model``."""

    from finishup.cli.app import run_configured_provider_credential

    try:
        action = _run(key_action)
    except ControlError as error:
        raise typer.Exit(control_failure(error, json_output=False)) from None
    except (ConfigError, OSError, ValueError):
        _fail("The provider configuration could not be read. Run finishup ai setup.")
    typer.echo("Your API key goes into the encrypted local vault.")
    run_configured_provider_credential(action)
    from finishup.cli.setup import restart_service_for_semantic_composition

    try:
        service = _run(restart_service_for_semantic_composition)
    except (ControlError, OSError, ValueError):
        _fail(
            "Key entry completed, but readiness could not reload. Run finishup service unlock, then finishup ai status."
        )
    if service.get("state") != "ready":
        _fail(
            "Key entry completed; unlock FinishUP before using it: finishup service unlock, then finishup ai status."
        )


async def remove_configured_provider_credential(target: object) -> None:
    """Enter only the trusted owner ceremony; removal never collects a provider secret."""

    from finishup.cli.unlock import load_auto_unlock_reauthentication, remove_provider_credential
    from finishup.service.confidential_protocol import ProviderCredentialTarget

    if type(target) is not ProviderCredentialTarget:
        raise ValueError("provider_credential_target_invalid")
    await remove_provider_credential(target, load_auto_unlock_reauthentication())


async def forget_key() -> Literal["removed", "cancelled", "removed_not_ready"]:
    """Shared trusted-terminal flow for both CLI names and the full-screen handoff."""

    from finishup.cli.setup import restart_service_for_semantic_composition
    from finishup.cli.unlock import HumanCeremonyCliError
    from finishup.service.confidential_client import ConfidentialClientError
    from finishup.service.confidential_protocol import ProviderCredentialTarget
    from finishup.service.vault import provider_credential_profile_binding

    try:
        endpoint, stored = await _configured_key()
        if stored is False:
            _fail("record_missing: no key is stored for this provider and model.")
        if stored is None:
            _fail("Key stored: unknown. Run finishup service unlock, then finishup ai status.")
        binding = provider_credential_profile_binding(
            cast(str, endpoint.get("provider_id")),
            cast(str, endpoint.get("model")),
            cast(str, endpoint.get("endpoint_profile_id")),
            cast(str, endpoint.get("endpoint_profile_version")),
        )
        target = ProviderCredentialTarget(
            "remove",
            binding.provider_id,
            binding.model_id,
            binding.endpoint_profile_id,
            binding.endpoint_profile_version,
            binding.purpose,
            binding.authorization_scope_digest,
            binding.purpose_digest,
        )
        typer.echo(f"Provider: {endpoint.get('provider_id')}; model: {endpoint.get('model')}.")
        if not typer.confirm("Remove the stored key for this provider and model?", default=False):
            typer.echo("The stored key was kept.")
            return "cancelled"
        await remove_configured_provider_credential(target)
    except ControlError as error:
        raise typer.Exit(control_failure(error, json_output=False)) from None
    except (HumanCeremonyCliError, ConfidentialClientError) as error:
        if error.reason == "record_missing":
            _fail("record_missing: no key is stored for this provider and model.")
        _fail(
            "Key removal was not confirmed. Run finishup service unlock, then "
            "finishup provider status --json (it reports the API fallback key too)."
        )
    except (ConfigError, OSError, ValueError):
        _fail(
            "Key removal was not confirmed. Run finishup provider status --json "
            "(it reports the API fallback key too)."
        )
    typer.echo(
        "The stored key was removed. AI-powered review cannot use this provider and model "
        "until you enter a key again with finishup ai key; keys you stored for other models "
        "stay stored. If the key may have leaked, also revoke it at the provider."
    )
    try:
        service = await restart_service_for_semantic_composition()
    except (ControlError, OSError, ValueError):
        typer.echo(
            "Key removal completed, but readiness could not reload. Run finishup ai status.",
            err=True,
        )
        return "removed_not_ready"
    if service.get("state") != "ready":
        typer.echo("Key removal completed; unlock FinishUP, then run finishup ai status.", err=True)
        return "removed_not_ready"
    return "removed"


@ai_app.command("forget-key", context_settings=_NO_EXTRA_ARGS)
def forget_key_command(context: typer.Context) -> None:
    """Remove the configured provider's key after owner reauthentication."""

    _refuse_extra_arguments(context)
    if _run(forget_key) == "removed_not_ready":
        raise typer.Exit(20)


def register_credential_remove(credential_app: typer.Typer) -> None:
    """Register the provider spelling with the same non-echoing argument boundary."""

    credential_app.command("remove", context_settings=_NO_EXTRA_ARGS)(forget_key_command)


async def ai_status_report() -> dict[str, JsonValue]:
    """A bounded read, without provider login, dispatch, secret reads, or service startup."""

    from finishup.cli.privacy_setup import get_privacy_setup_snapshot
    from finishup.cli.provider_status import provider_status_report

    report = await provider_status_report()
    raw_endpoint = report.get("endpoint")
    endpoint: Mapping[str, object] = (
        cast(Mapping[str, object], raw_endpoint) if isinstance(raw_endpoint, Mapping) else {}
    )
    review_mode: str | None = None
    network: bool | None = None
    binding_permitted: bool | None = None
    try:
        snapshot = await get_privacy_setup_snapshot(Path.cwd())
        review_mode = snapshot.composed_policy.effective_conversation_review.value
        network = snapshot.composed_policy.network_egress_permitted
        llm = next(
            channel
            for channel in snapshot.composed_policy.channel_policies
            if channel.channel is EgressChannel.LLM_INFERENCE
        )
        binding_permitted = llm.enabled and any(
            endpoint.get("provider_id") == binding.provider_id
            and endpoint.get("model") == binding.model_id
            and endpoint.get("endpoint_profile_id") == binding.endpoint_profile_id
            and endpoint.get("endpoint_profile_version") == binding.endpoint_profile_version
            for binding in llm.authorized_provider_bindings
        )
    except (ControlError, OSError, ValueError):
        pass
    authority = endpoint.get("credential_authority")
    stored = (
        report.get("credential_connected")
        if authority == "finishup_vault_api_credential"
        else False
    )
    enabled = report.get("llm_inference_enabled")
    grant = report.get("repository_grant_state")
    permits = (
        False
        if network is False
        or binding_permitted is False
        or review_mode == "local_only"
        or enabled is False
        or grant == "missing"
        else (
            True
            if network is True
            and binding_permitted is True
            and enabled is True
            and grant == "granted"
            else None
        )
    )
    from finishup.protocol.ai_status import AIStatus

    summary = {
        "schema": "finishup.ai-status/1",
        "review_mode": review_mode,
        "reviewer": endpoint.get("provider_id")
        if type(endpoint.get("provider_id")) is str
        else None,
        "model": endpoint.get("model") if type(endpoint.get("model")) is str else None,
        "key_stored": stored if type(stored) is bool else None,
        "privacy_permits_sending": permits,
    }
    return cast(dict[str, JsonValue], AIStatus.model_validate(summary).model_dump(by_alias=True))


def _yes_no_unknown(value: JsonValue) -> str:
    return "yes" if value is True else "no" if value is False else "unknown"


@ai_app.command("status", context_settings=_NO_EXTRA_ARGS)
def status(
    context: typer.Context,
    json_output: Annotated[bool, typer.Option("--json", help="Emit nonsecret JSON.")] = False,
) -> None:
    """Show review mode, reviewer, model, key presence, and privacy permission."""

    _refuse_extra_arguments(context)

    try:
        report = _run(ai_status_report)
    except ControlError as error:
        raise typer.Exit(control_failure(error, json_output=json_output)) from None
    except (ConfigError, OSError, ValueError):
        _fail("AI review status is unavailable; run finishup provider status for details.")
    if json_output:
        stdout_json(report)
        return
    modes = {
        "local_only": "local only",
        "local_agent_opt_in": "agent opt-in",
        "local_owner_approval": "owner approval",
        "ai_powered": "AI-powered on every task",
    }
    typer.echo(
        f"Review: {modes.get(str(report['review_mode']), 'unknown')}; "
        f"reviewer: {report['reviewer'] or 'not configured'}; model: {report['model'] or 'not configured'}; "
        f"key stored: {_yes_no_unknown(report['key_stored'])}; "
        f"privacy permits sending: {_yes_no_unknown(report['privacy_permits_sending'])}. "
        "finishup ai key replaces a stored key; finishup ai forget-key removes it."
    )


def _change_mode(setting: ConversationReview) -> None:
    from finishup.cli.privacy_setup import run_conversation_review_change
    from finishup.cli.unlock import HumanCeremonyCliError

    try:
        report = _run(lambda: run_conversation_review_change(setting))
    except ControlError as error:
        raise typer.Exit(control_failure(error, json_output=False)) from None
    except (HumanCeremonyCliError, OSError, ValueError):
        _fail("Review mode was not changed. Complete the trusted local privacy ceremony.")
    if getattr(report, "outcome", None) not in {"configured", "unchanged"}:
        _fail("Review mode was not changed. Complete the trusted local privacy ceremony.")
    if getattr(report, "reason", None) == "repository_privacy_grant_missing":
        _fail(
            "This repository's setting was not recorded. Run finishup ai off in your own terminal."
        )
    if setting is ConversationReview.LOCAL_ONLY:
        typer.echo(
            "AI-powered review is off here; the key stays stored. Use finishup ai forget-key to remove it locally; revoke the key with your provider to invalidate it."
        )
    else:
        typer.echo(
            "Agent opt-in is selected here. Review still needs a configured reviewer and privacy permission; run finishup ai status."
        )


@ai_app.command("off", context_settings=_NO_EXTRA_ARGS)
def off(context: typer.Context) -> None:
    """Use local checks only in this repository; keep the stored key."""

    _refuse_extra_arguments(context)

    _change_mode(ConversationReview.LOCAL_ONLY)


@ai_app.command("on", context_settings=_NO_EXTRA_ARGS)
def on(context: typer.Context) -> None:
    """Let agents opt in to review; widening still requires your reauthentication."""

    _refuse_extra_arguments(context)

    _change_mode(ConversationReview.LOCAL_AGENT_OPT_IN)


def _select_model(models: tuple[str, ...], current: str) -> str:
    choices = tuple(dict.fromkeys((*models, current)))
    for index, model_id in enumerate(choices, 1):
        typer.echo(f"  {index}) {model_id}" + (" (current)" if model_id == current else ""))
    typer.echo("  c) Type another model ID")
    default = str(choices.index(current) + 1)
    raw = typer.prompt("Select model", default=default).strip()
    if raw == "c":
        return typer.prompt("Model ID", show_default=False).strip()
    if raw.isascii() and raw.isdecimal() and 1 <= int(raw) <= len(choices):
        return choices[int(raw) - 1]
    raise ValueError("model_selection_invalid")


@ai_app.command("model")
def model(
    model_id: Annotated[
        str | None, typer.Argument(help="Exact model ID, or omit to choose.")
    ] = None,
) -> None:
    """Switch model; an API key remains bound to its old model until entered again."""

    from finishup.cli.setup import restart_service_for_semantic_composition
    from finishup.config.models import primary_external_endpoint
    from finishup.config.write import (
        PROVIDER_PRESETS,
        config_write_snapshot,
        render_config_toml,
        write_config_toml_if_unchanged,
    )

    written_bytes: bytes | None = None
    try:
        config, expected_bytes = config_write_snapshot()
        endpoint = primary_external_endpoint(config)
        if endpoint is None:
            _fail("Choose a reviewer first: finishup ai setup")
        models = (
            ("gpt-6.1-sol", "gpt-6-luna")
            if isinstance(endpoint, ExternalRuntimeProfileConfig)
            else next(
                (
                    preset.suggested_models
                    for preset in PROVIDER_PRESETS.values()
                    if preset.endpoint_profile_id == endpoint.endpoint_profile_id
                ),
                (),
            )
        )
        selected = _select_model(models, endpoint.model) if model_id is None else model_id.strip()
        if not selected:
            raise ValueError("model_id_required")
        if selected == endpoint.model:
            typer.echo("The current model is unchanged; its key stays stored.")
            return
        if isinstance(endpoint, ExternalRuntimeProfileConfig):
            from finishup.cli.codex_subscription import codex_subscription_setup

            _run(
                lambda: codex_subscription_setup(
                    executable=Path(endpoint.executable_path),
                    codex_home=Path(endpoint.codex_home),
                    model=selected,
                    reasoning_effort=endpoint.reasoning_effort,
                    routine_reasoning_effort=endpoint.routine_reasoning_effort,
                    login_mode="browser",
                    open_browser=False,
                    switch_account=False,
                )
            )
        else:
            typer.echo(
                "The key is bound to the provider, endpoint, and model. The old key stays stored "
                "for the old model; enter it again for this model with finishup ai key."
            )
            updated_provider = endpoint.model_copy(update={"model": selected})
            updated = config.model_copy(update={"provider": updated_provider})
            # The exact bytes this command writes, computed from the same rendering the locked
            # write uses rather than re-read afterwards: a rollback may replace only these, never
            # a change another writer made after the write lock was released.
            written_bytes = render_config_toml(updated).encode("utf-8")
            # Full config validation and a locked preimage comparison precede replacement.
            write_config_toml_if_unchanged(updated, expected_bytes=expected_bytes)
    except (ConfigError, OSError, ValueError):
        _fail("Model setup did not complete. Check the model ID and run finishup ai status.")
    try:
        service = _run(restart_service_for_semantic_composition)
    except (ControlError, OSError, ValueError):
        service = None
    if service is not None and service.get("state") == "locked":
        # A passphrase vault with no stored copy locks on every restart; unlock it here so key
        # entry is reached instead of leaving the new model selected without a key.
        from finishup.cli.unlock import HumanCeremonyCliError, unlock_vault

        try:
            unlocked = _run(unlock_vault)
        except (ControlError, HumanCeremonyCliError, OSError, ValueError):
            unlocked = None
        if getattr(unlocked, "state", None) == "ready":
            service = {**service, "state": "ready"}
    if service is None or service.get("state") != "ready":
        if written_bytes is not None:
            # Put the working model back so a later `ai model` with this ID is not "unchanged"
            # while its key was never entered.
            _restore_previous_model(config, written_bytes)
            raise typer.Exit(20)
        _fail(
            "The model was saved, but FinishUP is not ready. Unlock it and run finishup ai status."
        )
    if isinstance(endpoint, ExternalRuntimeProfileConfig):
        typer.echo(
            "Codex model changed; Codex keeps its own ChatGPT sign-in. Review remains subject to privacy permission."
        )
        return
    typer.echo(
        "The model change does not approve privacy; review any needed permission with finishup --privacy."
    )
    try:
        key()
    except (typer.Exit, typer.Abort, KeyboardInterrupt) as stopped:
        if isinstance(stopped, typer.Exit) and stopped.exit_code == 0:
            raise
        _restore_previous_model(config, written_bytes)
        raise


def _restore_previous_model(previous: object, written_bytes: bytes | None) -> None:
    """Put the working model back when the new model's key was not entered (review of #1119).

    The old key stays bound to the old model, so restoring the binding restores a working
    reviewer instead of leaving a model active without a key. The restore replaces only the
    configuration this command wrote; if anything else changed it meanwhile, it stops and says so.
    """

    from finishup.cli.setup import restart_service_for_semantic_composition
    from finishup.config.write import write_config_toml_if_unchanged

    try:
        write_config_toml_if_unchanged(cast(Any, previous), expected_bytes=written_bytes)
    except ConfigError:
        typer.echo(
            "Key entry did not finish, and the settings changed meanwhile, so the previous model "
            "was not restored automatically. Run finishup ai model to choose it again.",
            err=True,
        )
        return
    except OSError:
        typer.echo(
            "Key entry did not finish, and the previous model could not be restored "
            "automatically. Run finishup ai model to choose it again.",
            err=True,
        )
        return
    try:
        service = _run(restart_service_for_semantic_composition)
    except (ControlError, OSError, ValueError):
        service = {}
    if service.get("state") != "ready":
        typer.echo(
            "Key entry did not finish, so the previous model is selected again with its stored "
            "key, but FinishUP is not ready to use it yet: run finishup service unlock, then "
            "finishup ai status.",
            err=True,
        )
        return
    typer.echo(
        "Key entry did not finish, so the previous model is active again with its stored key.",
        err=True,
    )
