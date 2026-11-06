"""The fixed words of a receipt whose workspace provenance is unknown (ADR-051, decision D4).

A receipt reads the record that opened its task's session to say where the task's workspace
evidence was read. When that record cannot be read, the receipt is still built and says what
happened, why it matters and whether a retry can help. These are those words, in every rendering:
the text and markdown "Workspace evidence" section, and the ``workspace_provenance`` member every
receipt format carries. Fixed words and closed tokens only; no host, user, path or target name
ever joins them. Standard library only, so the protocol models can admit exactly these values.

Two causes are told apart, each with its own closed ``reason`` and its own last line:

* ``session_opening_unreadable`` (passing): the ledger read failed, or the record did not load
  (its payload object could not be read when the ledger opened the task). A retry, or a restart
  of the server's service that reopens the task, can clear it, so its last line says to retry.
* ``session_opening_unrecoverable`` (lasting): the record is redacted or erased, its key is gone,
  or it is in a format this FinishUP version cannot decode. No retry or restart reads it, so its
  last line says it will not become readable again and the receipt will keep saying so, and gives
  no retry or restart advice.

Both share the first two lines; the first is also the marker a client reads to keep its own
"read on the client machine" line off a receipt that carries it.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Literal

__all__ = [
    "SESSION_OPENING_UNREADABLE",
    "SESSION_OPENING_UNRECOVERABLE",
    "WORKSPACE_PROVENANCE_REASONS",
    "WORKSPACE_PROVENANCE_UNKNOWN",
    "WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE",
    "WORKSPACE_PROVENANCE_UNKNOWN_LASTING_LINE",
    "WORKSPACE_PROVENANCE_UNKNOWN_LINE",
    "WORKSPACE_PROVENANCE_UNKNOWN_RETRY_LINE",
    "WorkspaceProvenanceReason",
    "workspace_provenance_unknown_lines",
    "workspace_provenance_unknown_notice",
    "workspace_provenance_unknown_wire",
]

# What happened, for either cause. It is also the marker a client reads to keep its own "read on
# the client machine" line off a receipt that carries it.
WORKSPACE_PROVENANCE_UNKNOWN_LINE: Final = (
    "Provenance unknown: the record of how this task's session was opened could not be read "
    "from the server's ledger."
)
# Why it matters, for either cause.
WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE: Final = (
    "Why it matters: FinishUP cannot confirm whether this task's workspace evidence was read on "
    "the client machine."
)
# What to do, for a passing cause only: a retry, or a restart that reopens the task, can clear it.
WORKSPACE_PROVENANCE_UNKNOWN_RETRY_LINE: Final = (
    "What to do: run receipt again. If this persists, restart the server's FinishUP service "
    "(`finishup service restart` on the server host), then run receipt again."
)
# Why it lasts, for a lasting cause only: no retry or restart advice, because neither helps.
WORKSPACE_PROVENANCE_UNKNOWN_LASTING_LINE: Final = (
    "Why it lasts: the record is redacted or erased, its key is gone, or it is in a format this "
    "FinishUP version cannot decode, so it will not become readable again and this task's "
    "receipts will keep saying so. Running receipt again or restarting the service will not "
    "change this."
)

# The ``status`` member: the one provenance a receipt result names.
WORKSPACE_PROVENANCE_UNKNOWN: Final = "unknown"

# The closed ``reason`` tokens of ``workspace_provenance``.
type WorkspaceProvenanceReason = Literal[
    "session_opening_unreadable", "session_opening_unrecoverable"
]
# Passing: the ledger read failed or the record did not load; a retry or a restart can clear it.
SESSION_OPENING_UNREADABLE: Final = "session_opening_unreadable"
# Lasting: redacted or erased, its key gone, or a format this version cannot decode.
SESSION_OPENING_UNRECOVERABLE: Final = "session_opening_unrecoverable"
WORKSPACE_PROVENANCE_REASONS: Final[tuple[WorkspaceProvenanceReason, ...]] = (
    SESSION_OPENING_UNREADABLE,
    SESSION_OPENING_UNRECOVERABLE,
)

_LINES: Final[Mapping[str, tuple[str, str, str]]] = MappingProxyType(
    {
        SESSION_OPENING_UNREADABLE: (
            WORKSPACE_PROVENANCE_UNKNOWN_LINE,
            WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE,
            WORKSPACE_PROVENANCE_UNKNOWN_RETRY_LINE,
        ),
        SESSION_OPENING_UNRECOVERABLE: (
            WORKSPACE_PROVENANCE_UNKNOWN_LINE,
            WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE,
            WORKSPACE_PROVENANCE_UNKNOWN_LASTING_LINE,
        ),
    }
)


def workspace_provenance_unknown_lines(reason: object) -> tuple[str, str, str]:
    """The three fixed lines for ``reason``: what happened, why it matters, and what to do (a
    passing cause) or why it lasts (a lasting one). Any other value is ``ValueError``."""

    if type(reason) is not str or reason not in _LINES:
        raise ValueError("workspace_provenance_reason_invalid")
    return _LINES[reason]


def workspace_provenance_unknown_notice(reason: object) -> str:
    """The ``notice`` member for ``reason``: its three lines joined by newlines."""

    return "\n".join(workspace_provenance_unknown_lines(reason))


def workspace_provenance_unknown_wire(reason: WorkspaceProvenanceReason) -> dict[str, str]:
    """The ``workspace_provenance`` member of a receipt whose provenance is unknown."""

    return {
        "status": WORKSPACE_PROVENANCE_UNKNOWN,
        "reason": reason,
        "notice": workspace_provenance_unknown_notice(reason),
    }
