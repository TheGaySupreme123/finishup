"""Every client surface names a remote target's failure by its phase and ADR-030 directive.

ADR-051, approach A. With a remote target selected, the CLI, the menu, setup's next steps, the
MCP bridge, the hook contexts and the terminal interface say which remote phase failed (or that
the remote server's vault is locked) with the directive from ``finishup.protocol.recovery``.
None of them tells the user to run a local ``service run`` or ``service unlock``, and none
prints a host or a target name. With a local root every one of them keeps its exact text.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

from builders.server_targets import ambient_home
from finishup.client import targets
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import ControlError
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import REASON_CODE_CONTINUATIONS, REMOTE_CONNECTION_PHASES
from finishup.protocol.recovery import RECOVERY_DIRECTIVES

_LOCKED_TOKEN = "remote_vault_unlock_required"
_LOCAL_COMMANDS = ("service run", "service unlock", "service restart", "auto-unlock")
_NAMES = ("lab.example", "lab")


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def remote(home: Path) -> Path:
    with targets.registry_lock():
        record, root = targets.new_remote_target(
            "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/fu/bin/finishup"
        )
        targets.write_selection(record)
    reset_selection_memo()
    return root


def _clean(text: str) -> None:
    for command in _LOCAL_COMMANDS:
        # A command, not prose that happens to contain it ("no local service runs for it").
        assert re.search(rf"\b{re.escape(command)}\b", text) is None, text
    for name in _NAMES:
        assert f" {name} " not in f" {text} ", text


def test_the_remote_lock_has_its_own_registered_directive() -> None:
    directive = RECOVERY_DIRECTIVES[_LOCKED_TOKEN]
    assert "server host" in directive.directive
    _clean(directive.directive)
    from finishup.protocol.recovery import continuation_for_local_reason

    assert continuation_for_local_reason("remote_vault_locked") == _LOCKED_TOKEN


@pytest.mark.parametrize("phase", sorted(REMOTE_CONNECTION_PHASES))
def test_a_remote_phase_is_named_with_its_directive(remote: Path, phase: str) -> None:
    from finishup.cli.remote_remedy import remote_failure, remote_remedy_line

    error = ControlError("service_unavailable", retryable=True, phase=phase)
    directive = RECOVERY_DIRECTIVES[REASON_CODE_CONTINUATIONS[phase]]
    assert remote_failure(error) == (phase, directive)
    line = remote_remedy_line(error)
    assert line == f"{phase}: {directive.directive}"
    _clean(cast(str, line))


def test_a_local_root_keeps_every_local_text(home: Path) -> None:
    from finishup.cli.bootstrap import control_failure
    from finishup.cli.hooks import (
        _LOCKED_CONTEXT,  # pyright: ignore[reportPrivateUsage]
        _UNAVAILABLE_CONTEXT,  # pyright: ignore[reportPrivateUsage]
        locked_context,
        unavailable_context,
    )
    from finishup.cli.menu import _control_guidance  # pyright: ignore[reportPrivateUsage]
    from finishup.cli.observe_hooks import (
        _attachment_recovery_context,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.cli.remote_remedy import (
        remote_locked_directive,
        remote_remedy_line,
        remote_unreachable_directive,
    )
    from finishup.mcp import server as bridge

    locked = ControlError("vault_locked")
    assert remote_remedy_line(locked) is None
    assert remote_locked_directive() is None and remote_unreachable_directive() is None
    lines: list[str] = []
    control_failure(locked, json_output=False, stderr_writer=lines.append)
    assert "finishup service unlock" in "\n".join(lines)
    assert "finishup service unlock" in _control_guidance(locked)
    assert locked_context() == _LOCKED_CONTEXT
    assert unavailable_context(None) == _UNAVAILABLE_CONTEXT
    assert "finish service startup" in _attachment_recovery_context("service_unavailable")
    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        locked, request_id=None, operation="start"
    )
    public = cast(dict[str, object], cast(dict[str, object], result.structuredContent)["error"])
    assert "finishup service unlock" in cast(str, public["message"])
    assert "safe_details" not in public


@pytest.mark.parametrize("phase", sorted(REMOTE_CONNECTION_PHASES))
def test_the_cli_never_says_nothing_was_recorded_for_a_remote_phase(
    remote: Path, phase: str
) -> None:
    """A connection lost mid-call may already have delivered it; only the directive guides."""

    from finishup.cli.bootstrap import control_failure

    lines: list[str] = []
    error = ControlError("service_unavailable", retryable=True, phase=phase)
    control_failure(error, json_output=False, stderr_writer=lines.append)
    text = "\n".join(lines)
    first = text.splitlines()[0]
    assert first == (
        f"service_unavailable: {phase}: the selected FinishUP server could not serve this "
        "connection"
    )
    directive = RECOVERY_DIRECTIVES[REASON_CODE_CONTINUATIONS[phase]]
    assert directive.directive in text
    assert "nothing was recorded" not in first
    _clean(text)


def test_a_locked_remote_server_is_unlocked_there_on_every_surface(remote: Path) -> None:
    from finishup.cli.bootstrap import control_failure
    from finishup.cli.hooks import locked_context
    from finishup.cli.menu import _control_guidance  # pyright: ignore[reportPrivateUsage]
    from finishup.cli.remote_remedy import remote_locked_directive
    from finishup.mcp import server as bridge
    from finishup.tui.runtime import _connect_failure  # pyright: ignore[reportPrivateUsage]

    directive = RECOVERY_DIRECTIVES[_LOCKED_TOKEN]
    assert remote_locked_directive() == directive
    locked = ControlError("vault_locked", correlation_id="err_00000000-0000-4000-8000-0000000000e3")

    lines: list[str] = []
    documents: list[JsonValue] = []
    control_failure(
        locked, json_output=True, stderr_writer=lines.append, stdout_writer=documents.append
    )
    text = "\n".join(lines)
    assert directive.directive in text and "vault_locked" in text
    _clean(text)
    (document,) = documents
    payload = cast(dict[str, JsonValue], document)
    assert payload["reason"] == "vault_locked"
    assert cast(dict[str, JsonValue], payload["recovery"])["continuation"] == _LOCKED_TOKEN

    guidance = _control_guidance(locked)
    assert guidance == f"vault_locked: {directive.directive}"

    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        locked, request_id=None, operation="check"
    )
    public = cast(dict[str, object], cast(dict[str, object], result.structuredContent)["error"])
    assert public["message"] == directive.directive
    assert public["code"] == "VAULT_LOCKED"
    assert public["safe_details"] == {"continuation": _LOCKED_TOKEN}

    context = locked_context()
    assert context.endswith(f" Continuation: {_LOCKED_TOKEN}.")
    _clean(context)

    failure = _connect_failure(locked)
    assert failure.reason == "vault_locked"
    assert failure.details == (directive.directive,)


def test_hooks_name_the_remote_phase_and_its_token(remote: Path) -> None:
    from finishup.cli.hooks import unavailable_context
    from finishup.cli.observe_hooks import (
        _attachment_recovery_context,  # pyright: ignore[reportPrivateUsage]
    )

    for phase in sorted(REMOTE_CONNECTION_PHASES):
        context = unavailable_context(phase)
        assert f"({phase})" in context
        assert context.endswith(f" Continuation: {REASON_CODE_CONTINUATIONS[phase]}.")
        assert len(context.encode("ascii")) <= 512
        _clean(context)
    attach = _attachment_recovery_context("service_unavailable")
    assert "selected FinishUP server" in attach and "service startup" not in attach
    _clean(attach)


def test_a_hook_status_read_keeps_the_remote_phase(remote: Path) -> None:
    import asyncio

    from finishup.adapters.integrations.codex_lifecycle import LifecycleMapping
    from finishup.cli.hooks import _read_status  # pyright: ignore[reportPrivateUsage]

    async def refuse(*_args: object, **_kwargs: object) -> Any:  # noqa: ANN401
        raise ControlError("service_unavailable", retryable=True, phase="remote_auth_failed")

    mapping = LifecycleMapping(
        mapping_version=1,
        codex_session_id="session-1",
        finishup_task_id="tsk_00000000-0000-4000-8000-000000000001",
        finishup_session_id="ses_00000000-0000-4000-8000-000000000001",
        finishup_writer_id="wrt_00000000-0000-4000-8000-000000000001",
        last_frontier=None,
    )
    outcome = asyncio.run(_read_status(mapping, connect=refuse))
    assert (outcome.kind, outcome.phase) == ("unavailable", "remote_auth_failed")


def test_the_terminal_interface_names_a_remote_phase(remote: Path) -> None:
    from finishup.tui.runtime import _connect_failure  # pyright: ignore[reportPrivateUsage]

    failure = _connect_failure(
        ControlError("service_unavailable", retryable=True, phase="remote_incompatible")
    )
    directive = RECOVERY_DIRECTIVES[REASON_CODE_CONTINUATIONS["remote_incompatible"]]
    assert failure.reason == "remote_incompatible"
    assert failure.details == (directive.directive,)
    _clean(failure.message)


def test_the_menu_names_an_unreachable_remote_server(
    remote: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    from finishup.cli import menu

    async def refuse(*_args: object, **_kwargs: object) -> object:
        raise ControlError("service_unavailable", retryable=True, phase="remote_unreachable")

    monkeypatch.setattr("finishup.cli.app.build_service_client", refuse)
    summary = asyncio.run(menu._service_summary())  # pyright: ignore[reportPrivateUsage]
    directive = RECOVERY_DIRECTIVES[REASON_CODE_CONTINUATIONS["remote_unreachable"]]
    assert summary == f"not reachable — remote_unreachable: {directive.directive}"
    _clean(summary)
