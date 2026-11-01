"""#1240 D5: the receipt reply's closing line for the agent (fixed words and counts only).

The receipt reply asks the agent to tell the user the receipt's conclusion in its final message and
to name the reviewer notes still unanswered or declined. FinishUP composes the line from the
conclusion token and its own counts; it never carries participant text, injects nothing into the
conversation and never reads the final message (ADR-033 D1). Free of pydantic so every surface
(service, bridge, CLI) can compose and re-gate it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final

__all__ = [
    "CLOSING_PROMPT_PATTERN",
    "closing_prompt",
    "declined_note_count",
    "safe_closing_prompt",
]

_CONCLUSIONS: Final = (
    "insufficient_coverage",
    "no_unresolved_deterministic_findings",
    "unresolved_findings_remain",
)
_COUNT: Final = r"(?:0|[1-9][0-9]{0,18})"
_LEAD: Final = "Tell the user in your final message: receipt conclusion "
_NAME_EACH: Final = "; name each note not answered or declined"
CLOSING_PROMPT_PATTERN: Final = (
    "^"
    + re.escape(_LEAD)
    + "(?:"
    + "|".join(_CONCLUSIONS)
    + ")"
    + rf"(?:; reviewer notes: {_COUNT}, not answered: {_COUNT}(?:, declined: {_COUNT})?)?"
    + rf"(?:{re.escape(_NAME_EACH)})?\.$"
)
_LINE: Final = re.compile(CLOSING_PROMPT_PATTERN, re.ASCII)
# The receipt Summary's reviewer-note tally (``kernel.correctness_advisories``
# ``advisory_tally_sentence``): fixed labels and counts, composed by FinishUP alone.
_TALLY: Final = re.compile(
    rf" Reviewer notes: ({_COUNT}); not answered: ({_COUNT})"
    rf"(?: \([1-9][0-9]{{0,18}} material\))?(?:; answered: ([a-z0-9 ,]+))?\.",
    re.ASCII,
)
_DECLINED: Final = re.compile(r"(?:^|, )([1-9][0-9]{0,18}) declined(?:, |$)", re.ASCII)


def _count(value: object) -> int | None:
    if type(value) is not str or re.fullmatch(_COUNT, value, re.ASCII) is None:
        return None
    return int(value)


def declined_note_count(summary_body: object, *, total: int, unanswered: int) -> int | None:
    """How many reviewer notes the Summary tally names as declined, or ``None`` when unknown.

    Only FinishUP's own tally sentence is read, and only when its counts agree with the receipt's
    structural counts; any other shape is unknown rather than guessed.
    """

    if type(summary_body) is not str:
        return None
    found = _TALLY.search(summary_body)
    if found is None or int(found.group(1)) != total or int(found.group(2)) != unanswered:
        return None
    answered = found.group(3)
    if answered is None:
        return 0
    declined = _DECLINED.search(answered)
    return 0 if declined is None else int(declined.group(1))


def closing_prompt(
    conclusion: object, counts: Mapping[str, object] | None, *, declined: int | None = None
) -> str:
    """The closing line for one receipt, or ``""`` when the conclusion is not a known token."""

    if type(conclusion) is not str or conclusion not in _CONCLUSIONS:
        return ""
    line = _LEAD + conclusion
    open_or_declined = False
    if counts is not None:
        total = _count(counts.get("total"))
        unanswered = _count(counts.get("no_recorded_response"))
        if total is not None and unanswered is not None:
            line += f"; reviewer notes: {total}, not answered: {unanswered}"
            if declined is not None:
                line += f", declined: {declined}"
            open_or_declined = unanswered > 0 or bool(declined)
    if open_or_declined:
        line += _NAME_EACH
    line += "."
    return line if _LINE.fullmatch(line) is not None else ""


def safe_closing_prompt(value: object) -> str:
    """The line when ``value`` is exactly one well-formed closing line; otherwise empty."""

    return value if type(value) is str and _LINE.fullmatch(value) is not None else ""
