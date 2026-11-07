"""The fixed words of a receipt whose workspace provenance is unknown (ADR-051, decision D4).

A receipt reads the record that opened its task's session to say where the task's workspace
evidence was read. When that record cannot be read, the receipt is still built and says what
happened, why it matters and whether a retry can help. These are those words, in every rendering:
the text and markdown "Workspace evidence" section, and the ``workspace_provenance`` member every
receipt format carries. Fixed words and closed tokens only; no host, user, path or target name
ever joins them. Standard library only, so the protocol models can admit exactly these values.

Each cause the server can tell apart has its own closed ``reason`` and its own last line, which
says only what is true of that cause (decision D4b):

* ``session_opening_unreadable`` (passing): the ledger read failed, or the record's stored copy
  could not be read for a reason that can pass (a storage fault) when the ledger opened the task.
  A retry, or a restart of the server's service that reopens the task, can clear it, so its last
  line says to retry and then restart.
* ``session_opening_copy_unverifiable`` (lasting while the copy is bad): the server's stored copy
  of the record is missing or fails its integrity check. Opening the task again reads the same
  bytes, so no retry or restart reads it, and the receipts keep saying so for as long as that
  copy is missing or fails the check.
* ``session_opening_redacted`` and ``session_opening_erased`` (lasting): the record was redacted,
  or erased. It will not become readable again, so the last line says so and that the task's
  receipts will keep saying so.
* ``session_opening_key_unavailable`` (lasting while the key is missing): the server does not have
  the key that decrypts the record. No retry or restart reads it, and the receipts keep saying so
  while that key is unavailable.
* ``session_opening_format_unknown`` (lasting on this version): the record is in a format this
  FinishUP version cannot decode. No retry or restart reads it; a server running a FinishUP
  version that knows the format does, so the last line says the receipts keep saying so until
  then.

A lasting cause's last line gives no retry or restart advice, because neither helps. Every reason
shares the first two lines; the first is also the marker a client reads to keep its own "read on
the client machine" line off a receipt that carries it.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Literal

__all__ = [
    "SESSION_OPENING_COPY_UNVERIFIABLE",
    "SESSION_OPENING_ERASED",
    "SESSION_OPENING_FORMAT_UNKNOWN",
    "SESSION_OPENING_KEY_UNAVAILABLE",
    "SESSION_OPENING_REDACTED",
    "SESSION_OPENING_UNREADABLE",
    "WORKSPACE_PROVENANCE_COPY_UNVERIFIABLE_LINE",
    "WORKSPACE_PROVENANCE_ERASED_LINE",
    "WORKSPACE_PROVENANCE_FORMAT_UNKNOWN_LINE",
    "WORKSPACE_PROVENANCE_KEY_UNAVAILABLE_LINE",
    "WORKSPACE_PROVENANCE_REASONS",
    "WORKSPACE_PROVENANCE_REDACTED_LINE",
    "WORKSPACE_PROVENANCE_UNKNOWN",
    "WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE",
    "WORKSPACE_PROVENANCE_UNKNOWN_LINE",
    "WORKSPACE_PROVENANCE_UNKNOWN_RETRY_LINE",
    "WorkspaceProvenanceReason",
    "workspace_provenance_unknown_lines",
    "workspace_provenance_unknown_notice",
    "workspace_provenance_unknown_wire",
]

# What happened, for every cause. It is also the marker a client reads to keep its own "read on
# the client machine" line off a receipt that carries it.
WORKSPACE_PROVENANCE_UNKNOWN_LINE: Final = (
    "Provenance unknown: the record of how this task's session was opened could not be read "
    "from the server's ledger."
)
# Why it matters, for every cause.
WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE: Final = (
    "Why it matters: FinishUP cannot confirm whether this task's workspace evidence was read on "
    "the client machine."
)
# What to do, for a passing cause only: a retry, or a restart that reopens the task, can clear it.
WORKSPACE_PROVENANCE_UNKNOWN_RETRY_LINE: Final = (
    "What to do: run receipt again. If this persists, restart the server's FinishUP service "
    "(`finishup service restart` on the server host), then run receipt again."
)
# Why it lasts, one line per lasting cause, each true of that cause alone. None gives retry or
# restart advice, because neither helps.
WORKSPACE_PROVENANCE_REDACTED_LINE: Final = (
    "Why it lasts: the record was redacted, so it will not become readable again and this task's "
    "receipts will keep saying so. Running receipt again or restarting the service will not "
    "change this."
)
WORKSPACE_PROVENANCE_ERASED_LINE: Final = (
    "Why it lasts: the record was erased, so it will not become readable again and this task's "
    "receipts will keep saying so. Running receipt again or restarting the service will not "
    "change this."
)
WORKSPACE_PROVENANCE_KEY_UNAVAILABLE_LINE: Final = (
    "Why it lasts: the server does not have the key that decrypts the record, so running receipt "
    "again or restarting the service will not read it, and this task's receipts will keep saying "
    "so while that key is unavailable."
)
WORKSPACE_PROVENANCE_FORMAT_UNKNOWN_LINE: Final = (
    "Why it lasts: the record is in a format this FinishUP version cannot decode, so running "
    "receipt again or restarting the service will not read it, and this task's receipts will "
    "keep saying so until the server runs a FinishUP version that knows this format."
)
WORKSPACE_PROVENANCE_COPY_UNVERIFIABLE_LINE: Final = (
    "Why it lasts: the server's stored copy of the record is missing or fails its integrity "
    "check, so running receipt again or restarting the service will not read it, and this task's "
    "receipts will keep saying so for as long as that copy is missing or fails the check."
)

# The ``status`` member: the one provenance a receipt result names.
WORKSPACE_PROVENANCE_UNKNOWN: Final = "unknown"

# The closed ``reason`` tokens of ``workspace_provenance``, one per cause.
type WorkspaceProvenanceReason = Literal[
    "session_opening_unreadable",
    "session_opening_redacted",
    "session_opening_erased",
    "session_opening_key_unavailable",
    "session_opening_format_unknown",
    "session_opening_copy_unverifiable",
]
# Passing: the ledger read failed or the record did not load; a retry or a restart can clear it.
SESSION_OPENING_UNREADABLE: Final = "session_opening_unreadable"
# Lasting: the record was redacted (envelope state ``logically_redacted``).
SESSION_OPENING_REDACTED: Final = "session_opening_redacted"
# Lasting: the record was erased (envelope state ``erased_claimed``).
SESSION_OPENING_ERASED: Final = "session_opening_erased"
# Lasting while the key is missing (envelope state ``key_unavailable``).
SESSION_OPENING_KEY_UNAVAILABLE: Final = "session_opening_key_unavailable"
# Lasting on this version: a format this FinishUP version cannot decode.
SESSION_OPENING_FORMAT_UNKNOWN: Final = "session_opening_format_unknown"
# Lasting while the copy is bad: the stored copy is missing or fails its integrity check.
SESSION_OPENING_COPY_UNVERIFIABLE: Final = "session_opening_copy_unverifiable"
WORKSPACE_PROVENANCE_REASONS: Final[tuple[WorkspaceProvenanceReason, ...]] = (
    SESSION_OPENING_UNREADABLE,
    SESSION_OPENING_REDACTED,
    SESSION_OPENING_ERASED,
    SESSION_OPENING_KEY_UNAVAILABLE,
    SESSION_OPENING_FORMAT_UNKNOWN,
    SESSION_OPENING_COPY_UNVERIFIABLE,
)

_LAST_LINES: Final[Mapping[str, str]] = MappingProxyType(
    {
        SESSION_OPENING_UNREADABLE: WORKSPACE_PROVENANCE_UNKNOWN_RETRY_LINE,
        SESSION_OPENING_REDACTED: WORKSPACE_PROVENANCE_REDACTED_LINE,
        SESSION_OPENING_ERASED: WORKSPACE_PROVENANCE_ERASED_LINE,
        SESSION_OPENING_KEY_UNAVAILABLE: WORKSPACE_PROVENANCE_KEY_UNAVAILABLE_LINE,
        SESSION_OPENING_FORMAT_UNKNOWN: WORKSPACE_PROVENANCE_FORMAT_UNKNOWN_LINE,
        SESSION_OPENING_COPY_UNVERIFIABLE: WORKSPACE_PROVENANCE_COPY_UNVERIFIABLE_LINE,
    }
)


def workspace_provenance_unknown_lines(reason: object) -> tuple[str, str, str]:
    """The three fixed lines for ``reason``: what happened, why it matters, and what to do (a
    passing cause) or why it lasts (a lasting one). Any other value is ``ValueError``."""

    if type(reason) is not str or reason not in _LAST_LINES:
        raise ValueError("workspace_provenance_reason_invalid")
    return (
        WORKSPACE_PROVENANCE_UNKNOWN_LINE,
        WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE,
        _LAST_LINES[reason],
    )


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
