"""Eligibility for the bounded local verdict used by deterministic-only checks (#971).

The local verdict is a statement about the deterministic scope, not a claim that the work is
correct or that a provider reviewed it.  Every coverage gap remains on the result and receipt.
Only the small set of advisory/standing gaps may accompany the scoped result; counters from the
frozen case keep missing work from being mistaken for a clean local check.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final, cast

from yoetz.domain.check_totals import validate_check_totals
from yoetz.domain.findings import FINDING_KIND_TRAITS, Finding
from yoetz.domain.receipts import (
    PREEXISTING_TEST_INFORMATIONAL_GAPS,
    SEMANTIC_REVIEW_NOT_REQUESTED_GAP,
)
from yoetz.kernel.closure_readiness import GAP_CLASSIFICATION, GapClass
from yoetz.kernel.finding_resolution import (
    DETERMINISTIC_PROOF_TOLERATED_GAPS,
    SEMANTIC_ONLY_GAPS,
)
from yoetz.kernel.plan_drift import PLAN_DRIFT_ADVISORY_GAPS
from yoetz.kernel.task_facts import STANDING_TASK_FACT_GAPS
from yoetz.protocol.coverage import Coverage

__all__ = [
    "CLEAN_COMPATIBLE_GAPS",
    "DETERMINISTIC_SCOPED_STANDING_GAPS",
    "HOST_OBSERVATION_GUARDED_GAPS",
    "commands_complete",
    "deterministic_scope_is_clean",
]


# The one list of gaps a clean deterministic conclusion may carry (issue #986): the receipt's
# ``no_unresolved_deterministic_findings`` and the scoped local verdict both read it, so the two
# can no longer disagree. Derived, not hand-kept: a code qualifies when closure readiness
# classifies it as a standing limitation (no agent action removes it) AND a local absence proof
# tolerates it (it never hides rows a local pack judges: host pairing loss, an unstated host
# outcome, an unreadable captured object, deliberate content selection, plan-drift and task-fact
# disclosures). Gaps that describe only the AI-powered review are excluded: whether a missing or
# weakened review bounds the conclusion is the route's question, not a local one, so they keep
# their existing treatment. The advisory sets the receipt already tolerated stay members.
# Every member stays disclosed on the result and the receipt; this only decides whether it
# bounds the conclusion.
CLEAN_COMPATIBLE_GAPS: Final = frozenset(
    {
        *(
            code
            for code, assigned in GAP_CLASSIFICATION.items()
            if assigned is GapClass.STANDING_LIMITATION
            and code in DETERMINISTIC_PROOF_TOLERATED_GAPS
            and code not in SEMANTIC_ONLY_GAPS
            # Review-dialogue and review-selection bounds (``semantic_*``) also describe only
            # the AI-powered review; evidence-strength labels (``evidence_*``) bound what the
            # cited evidence proves, so a clean conclusion never hides them either.
            and not code.startswith(("semantic_", "evidence_"))
        ),
        *PLAN_DRIFT_ADVISORY_GAPS,
        *PREEXISTING_TEST_INFORMATIONAL_GAPS,
        *STANDING_TASK_FACT_GAPS,
    }
)
# The scoped local verdict of a deterministic-only check adds the one review gap such a check
# always carries: it asked for no AI-powered review. Unknown, actionable, or material coverage
# loss keeps the ordinary insufficient-coverage verdict.
DETERMINISTIC_SCOPED_STANDING_GAPS: Final = CLEAN_COMPATIBLE_GAPS | frozenset(
    {SEMANTIC_REVIEW_NOT_REQUESTED_GAP}
)


def _counter(totals: Mapping[str, object], group: str, key: str) -> int | None:
    values = totals.get(group)
    if not isinstance(values, Mapping):
        return None
    value = cast(Mapping[str, object], values).get(key)
    if type(value) is not str or not value.isascii() or not value.isdecimal():
        return None
    return int(value)


# Host-observation members of the list are clean-compatible only where the check that carried
# them also proved, from its frozen-case counters, that no observed command has an unknown or live
# failed outcome (``commands_complete``). A receipt therefore treats them as advisory only when
# the applicable check's own coverage already carried them (#986).
HOST_OBSERVATION_GUARDED_GAPS: Final = CLEAN_COMPATIBLE_GAPS & frozenset(
    {"captured_object_unavailable", "host_outcome_unavailable", "unpaired_event"}
)


def commands_complete(totals: Mapping[str, object]) -> bool:
    """True when the case's command counters show no unknown and no live failed outcome."""

    return all(_counter(totals, "commands", key) == 0 for key in ("unknown", "live_failed"))


def deterministic_scope_is_clean(
    *,
    coverage: Coverage,
    totals: Mapping[str, object],
    findings: Sequence[Finding],
) -> bool:
    """Return whether a deterministic-only check may use its scoped local verdict.

    The caller supplies totals built from the same frozen case and all candidate findings before
    the public finding cap.  Thus a suppressed actionable finding, an unattempted requested item,
    or a relevant live failure cannot disappear behind the returned finding list.
    """

    if type(coverage) is not Coverage:
        return False
    try:
        checked = validate_check_totals(totals)
    except ValueError:
        return False
    if not set(coverage.known_gaps) <= DETERMINISTIC_SCOPED_STANDING_GAPS:
        return False
    if any(type(finding) is not Finding for finding in findings):
        return False
    if any(FINDING_KIND_TRAITS[finding.kind][1] for finding in findings):
        return False
    values = checked
    if _counter(values, "obligations", "scope_known") != 1:
        return False
    if any(_counter(values, "obligations", key) not in {0} for key in ("open", "unreadable")):
        return False
    if _counter(values, "requested_items", "unattempted") != 0:
        return False
    # Unknown and live outcomes cannot establish that the local command set is complete. The
    # host-outcome gap itself is a standing disclosure (#986), so this counter is what keeps an
    # unknown outcome from reading as a clean local check.
    if any(_counter(values, "commands", key) not in {0} for key in ("unknown", "live_failed")):
        return False
    # A pre-existing test edit is a standing informational fact only when its disposition is
    # justified. Unknown or unjustified edits remain actionable even if the public finding cap
    # does not return their integrity finding.
    if any(_counter(values, "test_edits", key) not in {0} for key in ("unjustified", "unknown")):
        return False
    return True
