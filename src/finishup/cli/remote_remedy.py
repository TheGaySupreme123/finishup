"""The remedy a client surface names when the selected server is on another machine (ADR-051).

The CLI, the menu, setup and the terminal interface decide it here. A remote connection phase,
or a locked vault on the remote server, is named by its closed token and its ADR-030 directive
from ``finishup.protocol.recovery``: never a local-service command (``service run``,
``service unlock``) and never a host or a target name. A local root gets None from every
function, so its surfaces keep their exact text.
"""

from __future__ import annotations

from finishup.client.targets import active_target_is_remote
from finishup.ports.control import ControlError
from finishup.protocol.errors import REASON_CODE_CONTINUATIONS, REMOTE_CONNECTION_PHASES
from finishup.protocol.recovery import (
    RecoveryDirective,
    continuation_for_local_reason,
    directive_for,
)

__all__ = [
    "remote_failure",
    "remote_locked_directive",
    "remote_remedy_line",
    "remote_summary",
    "remote_unreachable_directive",
]

# A remote phase's one-line summary, before its directive. This computer refusing to connect
# while it is zero-network (ADR-051 decision 8) is not the server failing to serve.
_ZERO_NETWORK_SUMMARY = (
    "this computer's FinishUP is set to make no network connections, so nothing was sent to the "
    "selected FinishUP server"
)
_REMOTE_SUMMARY = "the selected FinishUP server could not serve this connection"


def remote_summary(phase: str | None) -> str:
    """The fixed summary a surface shows for a remote phase (the CLI line, the terminal)."""

    return _ZERO_NETWORK_SUMMARY if phase == "zero_network_remote_selected" else _REMOTE_SUMMARY


def _directive(token: str | None) -> RecoveryDirective:
    directive = directive_for(token)
    if directive is None:
        raise RuntimeError("remote_directive_unregistered")
    return directive


def remote_unreachable_directive() -> RecoveryDirective | None:
    """The directive for a remote target that could not be reached; None for a local root."""

    if not active_target_is_remote():
        return None
    return _directive(REASON_CODE_CONTINUATIONS["remote_unreachable"])


def remote_locked_directive() -> RecoveryDirective | None:
    """The directive for a remote target whose vault is locked; None for a local root."""

    if not active_target_is_remote():
        return None
    return _directive(continuation_for_local_reason("remote_vault_locked"))


def remote_failure(error: BaseException) -> tuple[str, RecoveryDirective] | None:
    """The closed reason and directive a remote target's failure is named by, or None.

    ``service_unavailable`` with a remote phase is named by that phase; ``vault_locked`` while a
    remote target is selected is the remote server's lock. Anything else keeps its local text.
    """

    if not isinstance(error, ControlError):
        return None
    if error.reason == "service_unavailable" and error.phase in REMOTE_CONNECTION_PHASES:
        return error.phase, _directive(REASON_CODE_CONTINUATIONS[error.phase])
    if error.reason == "vault_locked":
        locked = remote_locked_directive()
        if locked is not None:
            return "vault_locked", locked
    return None


def remote_remedy_line(error: BaseException) -> str | None:
    """One bounded line, ``<reason>: <directive>``, for a remote target's failure; else None."""

    named = remote_failure(error)
    if named is None:
        return None
    reason, directive = named
    return f"{reason}: {directive.directive}"
