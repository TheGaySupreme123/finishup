"""The verification rerun question (#1143, #1241) and how an agent's answer is shown.

One owner of what identifies the deterministic rerun question and of the bounded, one-line form
an agent's own reason takes on local renderings (D4 and D10 in #1247). The reason is the agent's
self-reported text: it is shown only in fenced prose leaves of local receipts and status, never in
a structural field, a log line or an error, and never sent anywhere new.
"""

from __future__ import annotations

from typing import Final

from finishup.domain.findings import Finding, FindingKind, FindingOrigin

__all__ = [
    "FRESHNESS_QUESTION_SUMMARY",
    "MAX_AGENT_REASON_BYTES",
    "bounded_agent_reason",
    "is_freshness_question",
]

# The deterministic question's fixed summary. It is the finding's identity on replay: the fact
# that raised it is an event fact, not part of the recorded finding.
FRESHNESS_QUESTION_SUMMARY: Final = "Is a verification rerun needed after the recorded changes?"
MAX_AGENT_REASON_BYTES: Final = 240


def is_freshness_question(finding: Finding) -> bool:
    """True for the deterministic verification rerun question (never a reviewer concern)."""

    return (
        finding.kind is FindingKind.LEDGER_STALE_OR_INCOMPLETE
        and finding.origin is FindingOrigin.DETERMINISTIC
        and finding.summary == FRESHNESS_QUESTION_SUMMARY
    )


def bounded_agent_reason(text: str, limit: int = MAX_AGENT_REASON_BYTES) -> str:
    """One line of the agent's own reason, at most *limit* UTF-8 bytes, ellipsis when clipped."""

    line = " ".join(text.split())
    if len(line.encode("utf-8")) <= limit:
        return line
    clipped = line.encode("utf-8")[: max(0, limit - 3)].decode("utf-8", errors="ignore")
    return clipped.rstrip() + "..."
