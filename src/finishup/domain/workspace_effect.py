"""The closed workspace-effect fact of one observed tool call (PR #1080, ADR-033 amendment).

The hook compares a fingerprint of the project workspace taken before the host runs a call with
one taken after it (``adapters.workspace_fingerprint``) and sends one closed structural token,
``workspace_effect``, on the call's ``PostToolUse`` envelope:

* ``unchanged`` - both snapshots were complete and nothing in the workspace differs;
* ``changed`` - an entry was added, removed or modified;
* ``unavailable`` - FinishUP could not establish the comparison (no pre-call snapshot, a call the
  host reports as still running, a workspace beyond the walk bounds, an unreadable directory).

Materialization appends the token to the observed result's summary in one closed suffix form
(`` (workspace unchanged)``, `` (workspace changed)``, `` (workspace unverified)``), and the kernel
reads it back only from service-stamped observation results. Only ``unchanged`` can make an
observed command non-material for the closing review; ``unavailable`` reads exactly like
``changed`` there. No path, digest or command text is part of the fact.
"""

from __future__ import annotations

import re
from typing import Final

__all__ = [
    "WORKSPACE_CHANGED",
    "WORKSPACE_EFFECTS",
    "WORKSPACE_EFFECT_KEY",
    "WORKSPACE_UNAVAILABLE",
    "WORKSPACE_UNCHANGED",
    "result_summary_with_workspace_effect",
    "workspace_effect_from_result_summary",
]

WORKSPACE_EFFECT_KEY: Final = "workspace_effect"
WORKSPACE_UNCHANGED: Final = "unchanged"
WORKSPACE_CHANGED: Final = "changed"
WORKSPACE_UNAVAILABLE: Final = "unavailable"
WORKSPACE_EFFECTS: Final = frozenset(
    {WORKSPACE_UNCHANGED, WORKSPACE_CHANGED, WORKSPACE_UNAVAILABLE}
)

# The summary word for each effect. ``unavailable`` reads "unverified" to a person: the workspace
# may well be unchanged, FinishUP just could not establish it.
_SUMMARY_WORDS: Final = {
    WORKSPACE_UNCHANGED: "unchanged",
    WORKSPACE_CHANGED: "changed",
    WORKSPACE_UNAVAILABLE: "unverified",
}
_SUMMARY_EFFECTS: Final = {word: effect for effect, word in _SUMMARY_WORDS.items()}
_SUMMARY_SUFFIX_RE: Final = re.compile(r" \(workspace (unchanged|changed|unverified)\)\Z", re.ASCII)


def result_summary_with_workspace_effect(summary: str, effect: object) -> str:
    """Append the closed workspace suffix to an observed result summary when *effect* is known."""

    if type(effect) is not str or effect not in _SUMMARY_WORDS:
        return summary
    return f"{summary} (workspace {_SUMMARY_WORDS[effect]})"


def workspace_effect_from_result_summary(summary: object) -> str | None:
    """Read back the workspace effect ``result_summary_with_workspace_effect`` wrote, or ``None``."""

    if type(summary) is not str:
        return None
    match = _SUMMARY_SUFFIX_RE.search(summary)
    return None if match is None else _SUMMARY_EFFECTS[match.group(1)]
