"""The fixed words of a receipt whose workspace provenance is unknown (ADR-051, decision D4).

A receipt reads the record that opened its task's session to say where the task's workspace
evidence was read. When that record cannot be read (the ledger read fails, or the record is
redacted, has no readable key, lost its payload object, or is a version this service cannot
decode), the receipt is still built and says what happened, why it matters and what to do. These
are those words, in every rendering: the text and markdown "Workspace evidence" section, and the
``workspace_provenance`` member every receipt format carries. Fixed words and closed tokens only;
no host, user, path or target name ever joins them. Standard library only, so the protocol models
can admit exactly these values.
"""

from __future__ import annotations

from typing import Final, Literal

__all__ = [
    "WORKSPACE_PROVENANCE_REASONS",
    "WORKSPACE_PROVENANCE_UNKNOWN",
    "WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE",
    "WORKSPACE_PROVENANCE_UNKNOWN_LINE",
    "WORKSPACE_PROVENANCE_UNKNOWN_LINES",
    "WORKSPACE_PROVENANCE_UNKNOWN_NOTICE",
    "WORKSPACE_PROVENANCE_UNKNOWN_RETRY_LINE",
    "WorkspaceProvenanceReason",
    "workspace_provenance_unknown_wire",
]

# What happened. It is also the marker a client reads to keep its own "read on the client machine"
# line off a receipt that carries it.
WORKSPACE_PROVENANCE_UNKNOWN_LINE: Final = (
    "Provenance unknown: the record of how this task's session was opened could not be read "
    "from the server's ledger."
)
# Why it matters.
WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE: Final = (
    "Why it matters: FinishUP cannot confirm whether this task's workspace evidence was read on "
    "the client machine."
)
# What to do.
WORKSPACE_PROVENANCE_UNKNOWN_RETRY_LINE: Final = (
    "What to do: run receipt again. If this persists, restart the server's FinishUP service "
    "(`finishup service restart` on the server host), then run receipt again."
)
WORKSPACE_PROVENANCE_UNKNOWN_LINES: Final = (
    WORKSPACE_PROVENANCE_UNKNOWN_LINE,
    WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE,
    WORKSPACE_PROVENANCE_UNKNOWN_RETRY_LINE,
)
# The ``notice`` member of the receipt result's ``workspace_provenance``: the same three lines.
WORKSPACE_PROVENANCE_UNKNOWN_NOTICE: Final = "\n".join(WORKSPACE_PROVENANCE_UNKNOWN_LINES)
# The ``status`` member: the one provenance a receipt result names.
WORKSPACE_PROVENANCE_UNKNOWN: Final = "unknown"

# The closed ``reason`` tokens of ``workspace_provenance``. ``session_opening_unreadable``: the
# record that opened the task's session could not be read or could not say whether the session is
# claim-bound.
type WorkspaceProvenanceReason = Literal["session_opening_unreadable"]
WORKSPACE_PROVENANCE_REASONS: Final[tuple[WorkspaceProvenanceReason, ...]] = (
    "session_opening_unreadable",
)


def workspace_provenance_unknown_wire() -> dict[str, str]:
    """The ``workspace_provenance`` member of a receipt whose provenance is unknown."""

    return {
        "status": WORKSPACE_PROVENANCE_UNKNOWN,
        "reason": WORKSPACE_PROVENANCE_REASONS[0],
        "notice": WORKSPACE_PROVENANCE_UNKNOWN_NOTICE,
    }
