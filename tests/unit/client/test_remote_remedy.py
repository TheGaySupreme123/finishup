"""Every surface names a remote target's failure with its phase, never a local remedy (ADR-051).

On a remote root the CLI, the menu, setup, the MCP bridge, the hooks and the terminal interface
name the closed remote phase with its ADR-030 directive (``protocol.recovery``), a claim this
computer could not make as this folder's, and a locked server vault as the server owner's. None
of them tells the user to run a local ``service run`` or ``service unlock``, and none prints the
target's host or name. On a local root every one of them is unchanged.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest

from builders.server_targets import ambient_home
from finishup.cli import bootstrap, hooks, menu, setup
from finishup.client import targets
from finishup.client.remote_remedy import (
    REMOTE_DRAINING_SUMMARY,
    REMOTE_LOCKED_SUMMARY,
    REMOTE_UNAVAILABLE_SUMMARY,
    REMOTE_UNCLAIMABLE_SUMMARY,
    remote_remedy,
)
from finishup.config.paths import reset_selection_memo
from finishup.mcp import server as bridge
from finishup.ports.control import ControlError, ControlMethod, ControlResult
from finishup.protocol.recovery import directive_for
from finishup.tui import runtime as tui_runtime

_LOCAL_REMEDIES = ("service run", "service unlock", "service restart", "local terminal")
_HOST_AND_NAME = ("lab.example", "owner@", "'lab'", " lab ")


@pytest.fixture
def remote(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, _root = targets.new_remote_target(
                "lab", "ssh", user="owner", host="lab.example", port=22
            )
            targets.write_selection(record)
        reset_selection_memo()
        yield


@pytest.fixture
def local(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    with ambient_home(monkeypatch):
        reset_selection_memo()
        yield


def _clean(text: str) -> None:
    lowered = text.lower()
    for phrase in _LOCAL_REMEDIES:
        assert phrase not in lowered, (phrase, text)
    for leak in _HOST_AND_NAME:
        assert leak not in text, (leak, text)


_PHASED = ControlError("service_unavailable", retryable=True, phase="remote_auth_failed")
_BARE = ControlError("service_unavailable", retryable=True)
_LOCKED = ControlError("vault_locked", retryable=False)
_UNCLAIMABLE = ControlError("service_unavailable", retryable=False, phase="handshake")
_OLD_GIT = ControlError("service_unavailable", retryable=False, phase="handshake_git_version")
# The server answered that it is shutting down or restarting.
_DRAINING = ControlError("service_draining", retryable=True)


def test_the_remedy_names_the_phase_its_directive_and_the_owner(remote: None) -> None:
    del remote
    phased = remote_remedy(_PHASED)
    assert phased is not None and phased.reason == "remote_auth_failed"
    assert phased.directive == directive_for("remote_credential_repair")
    bare = remote_remedy(_BARE)
    assert bare is not None and bare.reason == "remote_unreachable"
    assert bare.summary == REMOTE_UNAVAILABLE_SUMMARY
    assert bare.directive == directive_for("remote_server_test")
    locked = remote_remedy(_LOCKED)
    assert locked is not None and (locked.reason, locked.summary) == (
        "vault_locked",
        REMOTE_LOCKED_SUMMARY,
    )
    unclaimable = remote_remedy(_UNCLAIMABLE)
    assert unclaimable is not None and unclaimable.summary == REMOTE_UNCLAIMABLE_SUMMARY
    old_git = remote_remedy(_OLD_GIT)
    assert old_git is not None and old_git.directive == directive_for("system_git_upgrade_required")
    draining = remote_remedy(_DRAINING)
    assert draining is not None
    assert (draining.reason, draining.summary, draining.directive) == (
        "service_draining",
        REMOTE_DRAINING_SUMMARY,
        None,
    )
    assert remote_remedy(ControlError("frame_invalid")) is None


def test_a_local_root_has_no_remote_remedy(local: None) -> None:
    del local
    assert remote_remedy(_BARE) is None
    assert remote_remedy(_LOCKED) is None
    assert remote_remedy(_UNCLAIMABLE) is None
    assert remote_remedy(_DRAINING) is None
    # A phase that only a remote connection carries is remote by construction.
    assert remote_remedy(_PHASED) is not None


@pytest.mark.parametrize("error", [_PHASED, _BARE, _LOCKED, _UNCLAIMABLE, _DRAINING])
def test_the_cli_names_the_remote_remedy(remote: None, error: ControlError) -> None:
    del remote
    lines: list[str] = []
    documents: list[object] = []
    code = bootstrap.control_failure(
        error, json_output=True, stderr_writer=lines.append, stdout_writer=documents.append
    )
    assert code != 0
    text = "\n".join(lines)
    _clean(text)
    (document,) = documents
    assert type(document) is dict
    assert document["reason"] == error.reason
    _clean(json.dumps(document))


def test_the_cli_keeps_its_local_remedy_on_a_local_root(local: None) -> None:
    del local
    lines: list[str] = []
    bootstrap.control_failure(_LOCKED, stderr_writer=lines.append)
    assert lines[0].startswith("vault_locked: run `finishup service unlock` on a local terminal")


@pytest.mark.parametrize("error", [_PHASED, _BARE, _LOCKED, _DRAINING])
def test_the_menu_and_setup_name_the_remote_remedy(remote: None, error: ControlError) -> None:
    del remote
    _clean(menu._control_guidance(error))  # pyright: ignore[reportPrivateUsage]
    for service in (
        {"reachable": False, "state": None},
        {"reachable": True, "state": "locked"},
    ):
        steps = setup._service_next_steps(service)  # pyright: ignore[reportPrivateUsage]
        assert steps
        for step in steps:
            _clean(step)


def test_setup_keeps_its_local_next_steps_on_a_local_root(local: None) -> None:
    del local
    steps = setup._service_next_steps({"reachable": False, "state": None})  # pyright: ignore[reportPrivateUsage]
    assert steps == (
        "run 'finishup service run' under your selected user supervisor",
        "run 'finishup service unlock' from a local terminal if the vault is locked",
    )


@pytest.mark.parametrize("error", [_PHASED, _BARE, _LOCKED, _UNCLAIMABLE, _DRAINING])
def test_the_bridge_names_the_remote_remedy(remote: None, error: ControlError) -> None:
    del remote
    result = bridge._control_error_result(error, None, "start")  # pyright: ignore[reportPrivateUsage]
    assert result.isError
    text = "".join(getattr(item, "text", "") for item in result.content)
    _clean(text)
    structured = json.dumps(result.structuredContent)
    _clean(structured)
    if error.phase == "remote_auth_failed":
        assert "remote_auth_failed" in structured
        assert "remote_credential_repair" in structured


@pytest.mark.parametrize(
    "phase", ["remote_unreachable", "remote_auth_failed", "remote_service_not_running"]
)
def test_a_lost_connection_never_claims_that_nothing_was_recorded(remote: None, phase: str) -> None:
    # A remote connection can end after a call was sent (a dropped network, a revoked key), so
    # its remedy keeps the same-request replay open instead of saying nothing was recorded.
    del remote
    lost = ControlError("service_unavailable", retryable=True, phase=phase)
    remedy = remote_remedy(lost)
    assert remedy is not None and remedy.directive is not None
    for text in (remedy.summary, remedy.directive.directive):
        assert "nothing was recorded" not in text, text
    assert "same request id" in remedy.summary
    result = bridge._control_error_result(lost, None, "publish_work")  # pyright: ignore[reportPrivateUsage]
    text = "".join(getattr(item, "text", "") for item in result.content)
    assert "nothing was recorded" not in text
    structured = json.dumps(result.structuredContent)
    assert "nothing was recorded" not in structured
    assert "same request_id" in structured


def test_a_draining_server_is_waited_for_never_restarted_or_called_unreachable(
    remote: None,
) -> None:
    del remote
    lines: list[str] = []
    bootstrap.control_failure(_DRAINING, stderr_writer=lines.append)
    result = bridge._control_error_result(_DRAINING, None, "check")  # pyright: ignore[reportPrivateUsage]
    structured = json.dumps(result.structuredContent)
    for text in ("\n".join(lines), structured):
        # Never the local wording ("the local service is draining ... start it again").
        assert "the local service is" not in text.lower(), text
        assert "remote_unreachable" not in text and "start it again" not in text, text
    assert "same request_id" in structured and "service_draining" in structured


@pytest.mark.parametrize("method", list(ControlMethod))
def test_no_service_can_answer_service_unavailable(method: ControlMethod) -> None:
    # Every ``service_unavailable`` a remote client sees is its own connection's: a service
    # cannot answer one (the control-result error codes exclude it), which is why a remote root
    # reads a phase-less one as ``remote_unreachable`` and never as the server's own answer.
    from finishup.protocol.ids import IdKind, new_id
    from finishup.service.control_protocol import ControlProtocolError, validate_result

    answer = ControlResult(
        protocol_version="1.0",
        rpc_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=new_id(IdKind.SERVICE_INSTANCE),
        service_generation="1",
        method=method,
        outcome="error",
        body=ControlError("service_unavailable", retryable=True),
    )
    with pytest.raises(ControlProtocolError):
        validate_result(answer)


def test_the_hooks_name_the_remote_remedy(remote: None) -> None:
    del remote
    unavailable = hooks.unavailable_context(
        hooks.StatusOutcome("unavailable", remote_reason="remote_service_not_running")
    )
    assert unavailable.endswith("Continuation: remote_service_start_required.")
    locked = hooks.locked_context(hooks.StatusOutcome("locked", remote_reason="vault_locked"))
    for context in (unavailable, locked):
        _clean(context)
    # A local root's contexts are byte-identical to before.
    assert hooks.unavailable_context(hooks.StatusOutcome("unavailable")) == (
        hooks._UNAVAILABLE_CONTEXT  # pyright: ignore[reportPrivateUsage]
    )
    assert hooks.locked_context(hooks.StatusOutcome("locked")) == (
        hooks._LOCKED_CONTEXT  # pyright: ignore[reportPrivateUsage]
    )


@pytest.mark.parametrize("error", [_PHASED, _BARE, _LOCKED, _DRAINING])
def test_the_terminal_interface_names_the_remote_remedy(remote: None, error: ControlError) -> None:
    del remote
    failure = tui_runtime._connect_failure(error)  # pyright: ignore[reportPrivateUsage]
    _clean(str(failure))
    for detail in getattr(failure, "details", ()):
        _clean(detail)
