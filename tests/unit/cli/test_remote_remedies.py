"""Every surface names the remote phase on a server on another machine (ADR-051, approach C).

On a remote target root no local service exists, so the CLI, the menu, setup, the MCP bridge,
the hook contexts and the terminal interface name the failure's remote phase with its ADR-030
directive (from ``protocol.recovery``, never restated), and a locked server vault as its owner's
to unlock on the server host. None tells the user to run a local ``service run`` or ``service
unlock``, and none prints a host, user or target name. A local root's output is unchanged.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from builders.server_targets import ambient_home
from finishup.cli import hooks as hooks_module
from finishup.cli import menu as menu_module
from finishup.cli import setup as cli_setup
from finishup.cli.bootstrap import control_failure
from finishup.client import targets
from finishup.client.remote_remedy import (
    REMOTE_LOCKED_SUMMARY,
    remote_connection_phase,
    remote_remedy,
)
from finishup.config.paths import reset_selection_memo
from finishup.mcp import server as mcp_server
from finishup.ports.control import ControlError
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.recovery import directive_for
from finishup.tui import runtime as tui_runtime

_NAME = "qzxnamed"
_HOST = "qzxhost.example"
_PHASES = (
    ("remote_unreachable", "remote_server_test"),
    ("remote_auth_failed", "remote_credential_repair"),
    ("remote_identity_changed", "remote_identity_verify"),
    ("remote_service_not_running", "remote_service_start_required"),
    ("remote_incompatible", "remote_release_mismatch"),
)
_LOCAL_REMEDIES = ("service run", "service unlock", "service restart", "auto-unlock")


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def remote_root(home: Path) -> None:
    del home
    with targets.registry_lock():
        record, _root = targets.new_remote_target(_NAME, "https", base_url=f"https://{_HOST}")
        targets.write_selection(record)
    reset_selection_memo()


def _phase_error(phase: str) -> ControlError:
    return ControlError("service_unavailable", retryable=True, phase=phase)


def _assert_remote_words(text: str) -> None:
    for local in _LOCAL_REMEDIES:
        assert local not in text, text
    assert _HOST not in text and _NAME not in text, text


def _cli(error: ControlError, *, json_output: bool = False) -> tuple[str, list[JsonValue]]:
    lines: list[str] = []
    payloads: list[JsonValue] = []
    control_failure(
        error,
        json_output=json_output,
        stderr_writer=lines.append,
        stdout_writer=payloads.append,
    )
    return "\n".join(lines), payloads


# --- the shared remedy --------------------------------------------------------------------------


@pytest.mark.parametrize(("phase", "token"), _PHASES)
def test_a_remote_phase_names_its_own_directive(home: Path, phase: str, token: str) -> None:
    del home
    error = _phase_error(phase)
    assert remote_connection_phase(error) == phase
    remedy = remote_remedy(error)
    assert remedy is not None and remedy.reason == phase
    assert remedy.directive is directive_for(token)


def test_a_local_root_has_no_remote_remedy(home: Path) -> None:
    del home
    assert remote_remedy(ControlError("service_unavailable", retryable=True)) is None
    assert remote_remedy(ControlError("vault_locked", retryable=False)) is None
    assert remote_remedy(ControlError("frame_invalid")) is None


@pytest.mark.usefixtures("remote_root")
def test_on_a_remote_root_a_closed_connection_and_a_locked_vault_are_remote() -> None:
    closed = remote_remedy(ControlError("service_unavailable", retryable=True))
    assert closed is not None and closed.reason == "remote_unreachable"
    locked = remote_remedy(ControlError("vault_locked", retryable=False))
    assert locked is not None and locked.directive is None
    assert locked.summary == REMOTE_LOCKED_SUMMARY


# --- the CLI ------------------------------------------------------------------------------------


@pytest.mark.parametrize(("phase", "token"), _PHASES)
def test_the_cli_names_the_phase_and_its_directive(home: Path, phase: str, token: str) -> None:
    del home
    text, payloads = _cli(_phase_error(phase), json_output=True)
    assert text.startswith(f"service_unavailable: {phase}: ")
    directive = directive_for(token)
    assert directive is not None and directive.directive in text
    _assert_remote_words(text)
    payload = cast(dict[str, Any], payloads[0])
    assert payload["phase"] == phase and payload["reason"] == "service_unavailable"
    assert payload["recovery"]["continuation"] == token


def test_the_cli_keeps_its_local_text_on_a_local_root(home: Path) -> None:
    del home
    text, _ = _cli(ControlError("service_unavailable", retryable=True))
    assert text == (
        "service_unavailable: run 'finishup service run' under your selected user supervisor"
    )


@pytest.mark.usefixtures("remote_root")
def test_the_cli_sends_a_locked_server_vault_to_its_owner() -> None:
    text, _ = _cli(ControlError("vault_locked", retryable=False))
    assert text == f"vault_locked: vault_locked: {REMOTE_LOCKED_SUMMARY}"
    _assert_remote_words(text)


@pytest.mark.usefixtures("remote_root")
def test_the_menu_and_setup_name_the_remote_remedy() -> None:
    guidance = menu_module._control_guidance(_phase_error("remote_auth_failed"))  # pyright: ignore[reportPrivateUsage]
    assert guidance.startswith("remote_auth_failed: ")
    _assert_remote_words(guidance)
    steps = cli_setup._service_next_steps({"reachable": False, "state": None})  # pyright: ignore[reportPrivateUsage]
    directive = directive_for("remote_server_test")
    assert directive is not None and steps == (directive.directive,)
    assert cli_setup._service_next_steps({"reachable": True, "state": "locked"}) == (  # pyright: ignore[reportPrivateUsage]
        REMOTE_LOCKED_SUMMARY,
    )
    for step in steps:
        _assert_remote_words(step)


def test_the_menu_and_setup_keep_their_local_text(home: Path) -> None:
    del home
    guidance = menu_module._control_guidance(ControlError("service_unavailable", retryable=True))  # pyright: ignore[reportPrivateUsage]
    assert "finishup service run" in guidance
    steps = cli_setup._service_next_steps({"reachable": False, "state": None})  # pyright: ignore[reportPrivateUsage]
    assert steps == (cli_setup._NEXT_SERVICE, cli_setup._NEXT_UNLOCK)  # pyright: ignore[reportPrivateUsage]


# --- the MCP bridge -----------------------------------------------------------------------------


@pytest.mark.parametrize(("phase", "token"), _PHASES)
def test_the_bridge_reports_the_phase_with_its_continuation(
    home: Path, phase: str, token: str
) -> None:
    del home
    result = mcp_server._control_error_result(_phase_error(phase), new_id(IdKind.REQUEST), "start")  # pyright: ignore[reportPrivateUsage]
    error = cast(dict[str, Any], result.structuredContent)["error"]
    assert error["code"] == "SERVICE_UNAVAILABLE"
    assert error["safe_details"]["reason_code"] == phase
    assert error["safe_details"]["continuation"] == token
    _assert_remote_words(error["message"])


@pytest.mark.usefixtures("remote_root")
def test_the_bridge_sends_a_locked_server_vault_to_its_owner() -> None:
    result = mcp_server._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("vault_locked", retryable=False), new_id(IdKind.REQUEST), "start"
    )
    error = cast(dict[str, Any], result.structuredContent)["error"]
    assert error["code"] == "VAULT_LOCKED"
    assert "server host" in error["message"]
    _assert_remote_words(error["message"])


def test_the_bridge_keeps_its_local_text_on_a_local_root(home: Path) -> None:
    del home
    result = mcp_server._control_error_result(  # pyright: ignore[reportPrivateUsage]
        ControlError("service_unavailable", retryable=True), new_id(IdKind.REQUEST), "start"
    )
    error = cast(dict[str, Any], result.structuredContent)["error"]
    assert "'finishup service run'" in error["message"]


# --- the hooks ----------------------------------------------------------------------------------


@pytest.mark.parametrize(("phase", "token"), _PHASES)
def test_the_hook_context_names_the_phase_continuation(home: Path, phase: str, token: str) -> None:
    del home
    outcome = hooks_module.StatusOutcome(
        "unavailable",
        remote_reason=hooks_module._remote_reason(_phase_error(phase)),  # pyright: ignore[reportPrivateUsage]
    )
    context = hooks_module.unavailable_context(outcome)
    assert context.endswith(f" Continuation: {token}.")
    assert len(context.encode()) <= 512
    _assert_remote_words(context)


@pytest.mark.usefixtures("remote_root")
def test_the_hook_context_sends_a_locked_server_vault_to_its_owner() -> None:
    reason = hooks_module._remote_reason(ControlError("vault_locked", retryable=False))  # pyright: ignore[reportPrivateUsage]
    context = hooks_module.locked_context(
        hooks_module.StatusOutcome("locked", remote_reason=reason)
    )
    assert "server host" in context
    _assert_remote_words(context)


def test_the_hook_contexts_are_unchanged_on_a_local_root(home: Path) -> None:
    del home
    error = ControlError("service_unavailable", retryable=True)
    assert hooks_module._remote_reason(error) is None  # pyright: ignore[reportPrivateUsage]
    outcome = hooks_module.StatusOutcome("unavailable")
    assert hooks_module.unavailable_context(outcome) == hooks_module._UNAVAILABLE_CONTEXT  # pyright: ignore[reportPrivateUsage]
    assert hooks_module.locked_context(outcome) == hooks_module._LOCKED_CONTEXT  # pyright: ignore[reportPrivateUsage]


def _auto_attach(error: ControlError) -> Any:  # noqa: ANN401
    import asyncio

    from finishup.cli import observe_hooks

    async def connect(_kind: object) -> object:
        raise error

    return asyncio.run(
        observe_hooks._try_auto_start(  # pyright: ignore[reportPrivateUsage]
            "claude:qzx-session",
            _state=None,
            harness_id="claude",
            workspace_locator="/qzx/workspace",
            connect=connect,  # type: ignore[arg-type]
        )
    )


@pytest.mark.parametrize(("phase", "token"), _PHASES)
def test_a_failed_auto_attach_names_the_remote_phase(home: Path, phase: str, token: str) -> None:
    # Found in the real-environment run: SessionStart told the agent to "finish service startup"
    # while an HTTPS server was down, a remedy no command on this machine can apply.
    from finishup.cli import observe_hooks

    del home
    outcome = _auto_attach(_phase_error(phase))
    assert (outcome.mapping, outcome.reason, outcome.remote_phase) == (
        None,
        "service_unavailable",
        phase,
    )
    context = observe_hooks._attachment_recovery_context(  # pyright: ignore[reportPrivateUsage]
        outcome.reason, remote_phase=outcome.remote_phase
    )
    assert context.startswith(f"FinishUP attachment pending: {phase}.")
    assert context.endswith(f" Continuation: {token}. ")
    assert "service startup" not in context
    _assert_remote_words(context)


@pytest.mark.usefixtures("remote_root")
def test_a_closed_auto_attach_connection_on_a_remote_root_is_unreachable() -> None:
    outcome = _auto_attach(ControlError("service_unavailable", retryable=True))
    assert outcome.remote_phase == "remote_unreachable"


def test_a_failed_auto_attach_keeps_its_local_context_on_a_local_root(home: Path) -> None:
    from finishup.cli import observe_hooks

    del home
    outcome = _auto_attach(ControlError("service_unavailable", retryable=True))
    assert (outcome.reason, outcome.remote_phase) == ("service_unavailable", None)
    context = observe_hooks._attachment_recovery_context(outcome.reason)  # pyright: ignore[reportPrivateUsage]
    assert context.startswith("FinishUP attachment pending: service_unavailable.")
    with pytest.raises(ValueError, match="auto_attach_outcome_invalid"):
        observe_hooks.AutoAttachOutcome(None, "service_unavailable", remote_phase="vault_locked")


# --- the terminal interface ---------------------------------------------------------------------


@pytest.mark.parametrize(("phase", "token"), _PHASES)
def test_the_terminal_interface_names_the_phase(home: Path, phase: str, token: str) -> None:
    del home
    failure = tui_runtime._connect_failure(_phase_error(phase))  # pyright: ignore[reportPrivateUsage]
    directive = directive_for(token)
    assert failure.reason == phase
    assert directive is not None and failure.details == (directive.directive,)
    _assert_remote_words(failure.message)


def test_the_terminal_interface_keeps_its_local_text(home: Path) -> None:
    del home
    failure = tui_runtime._connect_failure(ControlError("service_unavailable", retryable=True))  # pyright: ignore[reportPrivateUsage]
    assert (failure.reason, failure.message) == (
        "service_unavailable",
        "the local FinishUP service is not reachable",
    )
