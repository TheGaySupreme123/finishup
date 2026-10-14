"""Interactive terminal menu over the existing command tree.

Bare ``finishup`` in a terminal (after first-run setup) and the explicit
``finishup menu`` command open one navigable screen for the operations users
otherwise assemble from subcommands: harness (Codex) MCP registration, the
provider-credential ceremonies, privacy inspection, and service lifecycle.
The menu adds no authority: every mutation keeps its preview/confirm gate,
trusted ceremonies still run through ``cli/unlock.py`` on the controlling
TTY, no service is ever spawned, and no secret enters a menu prompt.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from collections.abc import Awaitable, Callable
from typing import Final, Literal, cast

import click
import typer

from finishup import __version__
from finishup.cli.bootstrap import plain_json
from finishup.cli.render import bounded_failure_line, ceremony_refusal_line
from finishup.domain.values import JsonObject
from finishup.ports.control import ControlError
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PublicErrorCode
from finishup.service.control_protocol import public_error_code_for_control_reason

__all__ = ["menu_available", "run_menu"]

_HARNESS: Final = "codex"
_BACK: Final = "b"
_QUIT: Final = "q"


def menu_available() -> bool:
    """True only when stdin and stdout are both real TTYs."""

    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except OSError, ValueError:
        return False


def _control_guidance(error: ControlError) -> str:
    code = public_error_code_for_control_reason(error.reason)
    return {
        PublicErrorCode.VAULT_LOCKED: (
            "vault_locked: unlock from this menu (Service -> Unlock vault) "
            "or run 'finishup service unlock' "
            "(uses the platform credential store when auto-unlock is provisioned)"
        ),
        PublicErrorCode.SERVICE_UNAVAILABLE: (
            "service_unavailable: run 'finishup service run' under your selected user supervisor"
        ),
    }.get(code, f"{code.value.lower()}: the local request could not be completed")


def _plain(value: object) -> JsonValue:
    """The menu shares the CLI's one conversion.

    This used to be a byte-identical copy of :func:`finishup.cli.bootstrap.plain_json`, so the
    missing ``datetime`` case of issue #731 had to be fixed twice.  Delegating keeps the menu
    and the command graph on the same supported result vocabulary.
    """

    return plain_json(value)


def _show(value: object) -> None:
    typer.echo(json.dumps(_plain(value), ensure_ascii=False, indent=2, sort_keys=True))


def _run(operation: Callable[[], Awaitable[None]]) -> None:
    """One event-loop bridge per action; bounded guidance instead of exiting the menu."""

    from finishup.cli.app import run_async

    async def wrapped() -> int:
        try:
            await operation()
        except ControlError as error:
            typer.echo(_control_guidance(error), err=True)
        return 0

    run_async(wrapped)


def _run_subscription(operation: Callable[[], Awaitable[object]]) -> None:
    """Subscription actions report their exact bounded cause and next step (#855).

    The generic ceremony renderer knows only shared CLI remediations, so an evaluator-runtime
    refusal such as a replaced executable would otherwise read as invalid input.
    """

    from finishup.cli.app import run_async
    from finishup.cli.codex_subscription import subscription_failure_line

    async def wrapped() -> int:
        try:
            _show(await operation())
        except ControlError as error:
            typer.echo(_control_guidance(error), err=True)
        except (OSError, TimeoutError, ValueError) as error:
            typer.echo(subscription_failure_line(error), err=True)
        return 0

    run_async(wrapped)


def _run_ceremony(operation: Callable[[], Awaitable[object]]) -> None:
    from finishup.cli.app import run_async
    from finishup.cli.unlock import HumanCeremonyCliError
    from finishup.service.confidential_client import ConfidentialClientError

    async def wrapped() -> int:
        try:
            _show(await operation())
        except ControlError as error:
            typer.echo(_control_guidance(error), err=True)
        except (OSError, ValueError) as error:
            # Bounded setup tokens the menu itself raises deserve their next step, not a
            # generic input complaint the operator cannot act on.
            reason = str(error)
            line = bounded_failure_line(reason)
            typer.echo(
                line if line != reason else "invalid_request: the ceremony input is invalid",
                err=True,
            )
        except HumanCeremonyCliError as error:
            if error.reason in {"cancelled", "interrupted"}:
                typer.echo("cancelled", err=True)
            elif error.reason in {"preview_invalid", "result_invalid"}:
                typer.echo(
                    "internal_error: the confidential ceremony could not be completed", err=True
                )
            else:
                line = bounded_failure_line(error.reason)
                typer.echo(
                    line
                    if line != error.reason
                    else "invalid_request: the ceremony input is invalid",
                    err=True,
                )
        except ConfidentialClientError as error:
            if error.reason == "cancelled":
                typer.echo("cancelled", err=True)
            else:
                refusal = ceremony_refusal_line(error.reason)
                typer.echo(
                    refusal
                    or "service_unavailable: the confidential ceremony could not be completed",
                    err=True,
                )
        return 0

    run_async(wrapped)


# Fixed words for what the legacy ``yoetz`` MCP key holds (ADR-048); never host-supplied text.
_LEGACY_REGISTRATION_TEXT: Final = {
    "legacy_only": "registered under the earlier name yoetz (setup migrates it)",
    "duplicate": "also registered under the earlier name yoetz (setup removes it)",
    "foreign": "the earlier name yoetz holds an entry FinishUP cannot prove is its own (kept)",
}


@dataclasses.dataclass(frozen=True, slots=True)
class _Overview:
    service_line: str
    harness_lines: tuple[str, ...]
    setup_line: str


async def _service_summary() -> str:
    from finishup.cli.app import build_service_client

    try:
        client = await build_service_client()
        try:
            status = await client.service_status()
        finally:
            await client.close()
    except ControlError:
        return "not reachable — start it with 'finishup service run'"
    return f"reachable ({status.state.value}, vault: {status.vault_mode})"


async def _harness_summary() -> tuple[str, ...]:
    from finishup.adapters.integrations.codex_discovery import discover_codex_binaries
    from finishup.adapters.integrations.codex_mcp import CodexMcpAdapter
    from finishup.application.harness_mcp import HarnessMcpService
    from finishup.ports.harness_mcp import McpRegistrationError

    binaries = discover_codex_binaries()
    if not binaries:
        return ("no codex executable found on PATH",)
    service = HarnessMcpService(CodexMcpAdapter())
    lines: list[str] = []
    for binary in binaries:
        version = binary.reported_version or "unknown version"
        try:
            observation = await service.observe(binary)
            state = observation.state.value
            if observation.isolation_binding is not None:
                state += f", isolation: {observation.isolation_binding}"
            legacy = _LEGACY_REGISTRATION_TEXT.get(observation.legacy_registration)
            if legacy is not None:
                state += f", {legacy}"
        except McpRegistrationError as error:
            state = f"unknown ({error.reason.value})"
        lines.append(f"codex ({version}) — MCP registration: {state}")
    return tuple(lines)


def _gather_overview() -> _Overview:
    from finishup.cli.setup import setup_marker_present

    lines: dict[str, object] = {}

    async def collect() -> int:
        lines["service"] = await _service_summary()
        lines["harness"] = await _harness_summary()
        return 0

    from finishup.cli.app import run_async

    run_async(collect)
    setup_line = "complete" if setup_marker_present() else "not completed — option 2 runs it"
    return _Overview(
        service_line=cast(str, lines["service"]),
        harness_lines=cast(tuple[str, ...], lines["harness"]),
        setup_line=setup_line,
    )


def _print_home(overview: _Overview) -> None:
    typer.echo("")
    typer.echo(f"FinishUP {__version__} — local evidence ledger and review engine")
    typer.echo("")
    typer.echo(f"  Service    {overview.service_line}")
    for line in overview.harness_lines:
        typer.echo(f"  Harness    {line}")
    typer.echo(f"  First-run  {overview.setup_line}")
    typer.echo("")
    typer.echo("  1  Refresh status      re-probe the summary above")
    typer.echo("  2  Setup wizard        guided harness discovery and MCP registration")
    typer.echo("  3  Harness connection  inspect or register the Codex integration")
    typer.echo("  4  LLM provider        provision or rotate a provider credential")
    typer.echo("  5  Privacy             inspect policy and setup posture")
    typer.echo("  6  Service             unlock, lock, or stop the local service")
    typer.echo("  q  Quit")
    typer.echo("")


def _ask(choices: tuple[str, ...]) -> str:
    while True:
        raw = cast(str, typer.prompt("Select")).strip().lower()
        if raw in choices:
            return raw
        typer.echo(f"  choose one of: {', '.join(choices)}")


def _run_wizard() -> None:
    from finishup.cli.app import run_async
    from finishup.cli.setup import run_setup_wizard

    run_async(
        lambda: run_setup_wizard(
            non_interactive=False,
            codex_path=None,
            codex_home=None,
            accept=False,
            json_output=False,
        )
    )


def _harness_registration(action: str) -> None:
    from finishup.cli.app import run_async
    from finishup.cli.setup import integrate_mcp

    run_async(
        lambda: integrate_mcp(
            action,
            _HARNESS,
            codex_path=None,
            accept=False,
            preview_digest=None,
            json_output=False,
        )
    )


async def _skill_action(action: str) -> None:
    from finishup.cli.app import build_service_client

    request = JsonObject({"action": action, "harness": _HARNESS, "kind": "skill"})
    method = "integration_preview" if action == "preview" else "integration_execute"
    client = await build_service_client()
    try:
        result = await getattr(client, method)(request)
    finally:
        await client.close()
    _show(result)


def _harness_menu() -> None:
    typer.echo("")
    typer.echo(f"Harness connection ({_HARNESS})")
    typer.echo("  1  Registration status   is the finishup MCP server registered?")
    typer.echo("  2  Preview registration  show the exact proposed change")
    typer.echo("  3  Install registration  confirm before anything is applied")
    typer.echo("  4  Skill status")
    typer.echo("  5  Skill preview")
    typer.echo("  6  Skill install")
    typer.echo("  7  Skill remove")
    typer.echo("  b  Back")
    choice = _ask(("1", "2", "3", "4", "5", "6", "7", _BACK))
    if choice == _BACK:
        return
    if choice in {"1", "2", "3"}:
        _harness_registration({"1": "status", "2": "preview", "3": "install"}[choice])
        return
    action = {"4": "status", "5": "preview", "6": "install", "7": "remove"}[choice]
    _run(lambda: _skill_action(action))


def _provider_menu() -> None:
    typer.echo("")
    typer.echo("LLM provider connection")
    typer.echo("  API credentials and Codex-managed ChatGPT login are separate authorities.")
    typer.echo("  1  OpenAI API / compatible API (choose provider and model)")
    typer.echo("  2  Add API key for the configured provider")
    typer.echo("  3  Replace API key for the configured provider")
    typer.echo("  4  Codex with ChatGPT subscription (guided login)")
    typer.echo("  5  Codex subscription status")
    typer.echo("  6  Disconnect dedicated Codex home")
    typer.echo("  7  Roll back FinishUP's Codex binding only")
    typer.echo("  8  Repair the Codex evaluator binding (keeps sign-in and settings)")
    typer.echo("  9  Codex evaluator runtime status (no sign-in check)")
    typer.echo("  b  Back")
    choice = _ask(("1", "2", "3", "4", "5", "6", "7", "8", "9", _BACK))
    if choice == _BACK:
        return
    if choice == "1":
        from finishup.cli.provider_binding import prompt_provider_endpoint_binding

        selected = prompt_provider_endpoint_binding()
        if selected == "codex_subscription":
            typer.echo("Use menu option 4 to continue with Codex-managed sign-in.")
        return
    if choice in {"4", "5", "6", "7", "8", "9"}:
        from finishup.cli.codex_subscription import (
            codex_evaluator_runtime_status,
            codex_subscription_disconnect,
            codex_subscription_repair,
            codex_subscription_repair_plan,
            codex_subscription_rollback,
            codex_subscription_status,
            prompt_codex_subscription_setup,
        )

        if choice == "4":

            async def setup_subscription() -> object:
                from finishup.cli.codex_subscription import subscription_failure_reason
                from finishup.cli.setup import restart_service_for_semantic_composition

                try:
                    result = await prompt_codex_subscription_setup()
                    await restart_service_for_semantic_composition()
                    return result
                except (OSError, TimeoutError, ValueError) as error:
                    raise ValueError(subscription_failure_reason(error)) from error

            _run_subscription(setup_subscription)
        elif choice == "5":
            _run_subscription(codex_subscription_status)
        elif choice == "8":

            async def repair_subscription() -> object:
                from finishup.cli.setup import restart_service_for_semantic_composition

                _show(codex_subscription_repair_plan())
                if not typer.confirm(
                    "Rebind to FinishUP's retained runtime, keeping the sign-in and settings?",
                    default=False,
                ):
                    raise ValueError("cancelled")
                result = await codex_subscription_repair()
                await restart_service_for_semantic_composition()
                return result

            _run_subscription(repair_subscription)
        elif choice == "9":

            async def runtime_status() -> object:
                return codex_evaluator_runtime_status()

            _run_subscription(runtime_status)
        elif choice == "6":
            if typer.confirm(
                "Log out only the dedicated evaluator home and remove its binding?",
                default=False,
            ):

                async def disconnect_subscription() -> object:
                    from finishup.cli.codex_subscription import subscription_failure_reason
                    from finishup.cli.setup import restart_service_for_semantic_composition

                    try:
                        result = await codex_subscription_disconnect()
                        await restart_service_for_semantic_composition()
                        return result
                    except (OSError, TimeoutError, ValueError) as error:
                        raise ValueError(subscription_failure_reason(error)) from error

                _run_subscription(disconnect_subscription)
        else:

            async def rollback_subscription() -> object:
                from finishup.cli.codex_subscription import subscription_failure_reason
                from finishup.cli.setup import restart_service_for_semantic_composition

                try:
                    result = codex_subscription_rollback()
                    await restart_service_for_semantic_composition()
                    return result
                except (OSError, ValueError) as error:
                    raise ValueError(subscription_failure_reason(error)) from error

            _run_subscription(rollback_subscription)
        return
    action: Literal["set", "rotate"] = "set" if choice == "2" else "rotate"
    from finishup.config.load import load_config
    from finishup.service.confidential_protocol import ProviderCredentialTarget
    from finishup.service.vault import provider_credential_profile_binding

    async def run_credential_ceremony() -> object:
        from finishup.cli.privacy_setup import get_privacy_setup_snapshot
        from finishup.cli.unlock import (
            load_auto_unlock_reauthentication,
            rotate_provider_credential,
            set_provider_credential,
        )

        provider = load_config({}, {}, None).provider
        if provider is None:
            raise ValueError("provider_not_configured")
        binding = provider_credential_profile_binding(
            provider.provider_id,
            provider.model,
            provider.endpoint_profile_id,
            provider.endpoint_profile_version,
        )
        snapshot = await get_privacy_setup_snapshot()
        repository_commitment = snapshot.bound_scope.get("workspace_ref_commitment")
        if type(repository_commitment) is not str:
            raise ValueError("repository_privacy_scope_unavailable")
        target = ProviderCredentialTarget(
            action=action,
            provider_id=binding.provider_id,
            model_id=binding.model_id,
            endpoint_profile_id=binding.endpoint_profile_id,
            endpoint_profile_version=binding.endpoint_profile_version,
            purpose=binding.purpose,
            scope_digest=binding.authorization_scope_digest,
            purpose_digest=binding.purpose_digest,
            repository_privacy_commitment=repository_commitment,
        )
        operation = set_provider_credential if action == "set" else rotate_provider_credential
        # A Keychain-provisioned vault has a passphrase the human never saw; supply it here so
        # the ceremony asks only for the provider key.
        return await operation(target, None, load_auto_unlock_reauthentication())

    _run_ceremony(run_credential_ceremony)


async def _privacy_show(method: str) -> None:
    from finishup.cli.app import build_service_client

    request = JsonObject({})
    if method == "privacy_get_effective":
        from finishup.cli.provider_status import MachineScopeError, machine_scope_request

        # The frozen request schema requires a machine scope; it is a local construction, so a
        # broken installation marker is reported here without any service request (issue #517).
        try:
            request = machine_scope_request()
        except MachineScopeError as error:
            typer.echo(f"machine_scope_unavailable: {error.reason}: {error.remediation}", err=True)
            return
    client = await build_service_client()
    try:
        result = await getattr(client, method)(request)
    finally:
        await client.close()
    _show(result)


def _privacy_menu() -> None:
    typer.echo("")
    typer.echo("Privacy")
    typer.echo("  1  Show effective policy")
    typer.echo("  2  Show setup posture")
    typer.echo("  b  Back")
    typer.echo("  (policy changes stay explicit: 'finishup privacy setup|propose|tighten',")
    typer.echo("   receipts via 'finishup privacy receipts list|get')")
    choice = _ask(("1", "2", _BACK))
    if choice == _BACK:
        return
    method = "privacy_get_effective" if choice == "1" else "privacy_get_setup"
    _run(lambda: _privacy_show(method))


async def _service_simple(method: str) -> None:
    from finishup.cli.app import build_service_client

    client = await build_service_client()
    try:
        result = await getattr(client, method)()
    finally:
        await client.close()
    _show(result)


def _service_unlock() -> None:
    from finishup.cli.app import build_service_client, run_async

    state: dict[str, object] = {}

    async def probe() -> int:
        try:
            client = await build_service_client()
            try:
                state["status"] = await client.service_status()
            finally:
                await client.close()
        except ControlError as error:
            state["error"] = error
        return 0

    run_async(probe)
    error = state.get("error")
    if isinstance(error, ControlError):
        typer.echo(_control_guidance(error), err=True)
        return
    vault_mode = getattr(state.get("status"), "vault_mode", None)
    from finishup.cli import unlock

    if vault_mode == "os_keyring":
        _run_ceremony(unlock.retry_keyring)
    elif vault_mode == "passphrase":
        _run_ceremony(unlock.unlock_vault)
    else:
        typer.echo(
            "vault_locked: the vault is uninitialized; choose 'Initialize passphrase vault'",
            err=True,
        )


def _service_menu() -> None:
    typer.echo("")
    typer.echo("Service")
    typer.echo("  1  Status")
    typer.echo("  2  Unlock vault")
    typer.echo("  3  Initialize passphrase vault (first install only)")
    typer.echo("  4  Lock now")
    typer.echo("  5  Stop the service")
    typer.echo("  b  Back")
    choice = _ask(("1", "2", "3", "4", "5", _BACK))
    if choice == _BACK:
        return
    if choice == "1":
        _run(lambda: _service_simple("service_status"))
    elif choice == "2":
        _service_unlock()
    elif choice == "3":
        from finishup.cli import unlock

        _run_ceremony(unlock.initialize_passphrase_vault)
    elif choice == "4":
        _run(lambda: _service_simple("lock"))
    elif typer.confirm("Stop the local service now?", default=False):
        _run(lambda: _service_simple("stop"))


def run_menu() -> int:
    """Drive the interactive menu until the user quits; requires a real terminal."""

    if not menu_available():
        typer.echo(
            "invalid_request: the interactive menu needs a terminal; see 'finishup --help'",
            err=True,
        )
        return 2
    overview = _gather_overview()
    while True:
        _print_home(overview)
        try:
            choice = _ask(("1", "2", "3", "4", "5", "6", _QUIT))
            if choice == _QUIT:
                return 0
            if choice == "1":
                overview = _gather_overview()
            elif choice == "2":
                _run_wizard()
                overview = _gather_overview()
            elif choice == "3":
                _harness_menu()
            elif choice == "4":
                _provider_menu()
            elif choice == "5":
                _privacy_menu()
            else:
                _service_menu()
        except click.exceptions.Abort, EOFError:
            typer.echo("")
            return 0
