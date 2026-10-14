"""Eligibility for the bounded local verdict used by deterministic-only checks (#971).

The local verdict is a statement about the deterministic scope, not a claim that the work is
correct or that a provider reviewed it.  Every coverage gap remains on the result and receipt.
Only the small set of advisory/standing gaps may accompany the scoped result; counters from the
frozen case keep missing work from being mistaken for a clean local check.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Final, cast

from finishup.domain.check_totals import validate_check_totals
from finishup.domain.findings import Finding, finding_demands_work, is_limitation_request
from finishup.domain.receipts import SEMANTIC_REVIEW_NOT_REQUESTED_GAP
from finishup.kernel.gap_effect import GAP_EFFECT_TABLE, GapContext, judge_gaps
from finishup.protocol.coverage import Coverage

__all__ = [
    "CLEAN_COMPATIBLE_GAPS",
    "DETERMINISTIC_SCOPED_STANDING_GAPS",
    "HOST_OBSERVATION_GUARDED_GAPS",
    "commands_complete",
    "deterministic_scope_is_clean",
    "gaps_are_clean",
]


# The gaps a clean conclusion may carry whatever the route says: those the one table of gap
# effects (``kernel.gap_effect``, ADR-046) discloses on both routes, never as a bound. Derived,
# not hand-kept, so the receipt, the check verdict and the scoped local verdict can no longer
# disagree (issue #986). A gap whose effect depends on the route or the check (a missing review,
# a FinishUP packet budget, a host-observation gap) is judged by ``gaps_are_clean`` with a context.
# Every member stays disclosed on the result and the receipt; this only decides whether it bounds.
CLEAN_COMPATIBLE_GAPS: Final = frozenset(
    code
    for code, row in GAP_EFFECT_TABLE.items()
    if row.d_route in {"D", "G"}
    and row.review_route in {"D", "G"}
    and row.rule != "G13"  # readiness-only tokens are never recorded as coverage gaps
)
# Kept for callers that name the scoped list: the scoped local verdict of a deterministic-only
# check adds the one review gap such a check always carries (it asked for no review) when the
# route did not require one. ``gaps_are_clean`` decides that by the route, not by this set.
DETERMINISTIC_SCOPED_STANDING_GAPS: Final = CLEAN_COMPATIBLE_GAPS | frozenset(
    {SEMANTIC_REVIEW_NOT_REQUESTED_GAP}
)
# Host-observation gaps are clean-compatible only where the check that carried them also proved,
# from its frozen-case counters, that no observed command has an unknown or live failed outcome
# (``commands_complete``). The table marks them with the ``G`` effect (#986).
HOST_OBSERVATION_GUARDED_GAPS: Final = frozenset(
    code for code, row in GAP_EFFECT_TABLE.items() if row.d_route == "G" or row.review_route == "G"
)


def _counter(totals: Mapping[str, object], group: str, key: str) -> int | None:
    values = totals.get(group)
    if not isinstance(values, Mapping):
        return None
    value = cast(Mapping[str, object], values).get(key)
    if type(value) is not str or not value.isascii() or not value.isdecimal():
        return None
    return int(value)


def commands_complete(totals: Mapping[str, object]) -> bool:
    """True when the case's command counters show no unknown and no live failed outcome."""

    return all(_counter(totals, "commands", key) == 0 for key in ("unknown", "live_failed"))


def gaps_are_clean(
    known_gaps: Iterable[str],
    totals: Mapping[str, object],
    *,
    route_requires_review: bool,
    review_succeeded: bool = False,
    reviewer_reported_insufficiency: bool = False,
) -> bool:
    """Whether every gap of one check is only disclosed, never a bound (ADR-046).

    The check verdict's cleanliness is the receipt's: the same table, the same context. The route
    is the one the check will record (``semantic_route_required``), the host-observation guard is
    this check's own coverage plus its command counters, and a FinishUP review-packet budget is
    disclosed only when the review succeeded and the reviewer reported no insufficiency.
    """

    codes = tuple(known_gaps)
    context = GapContext(
        route_requires_review=route_requires_review,
        review_succeeded=review_succeeded,
        reviewer_reported_insufficiency=reviewer_reported_insufficiency,
        check_carried=frozenset(codes),
        commands_complete=commands_complete(totals),
    )
    return not any(effect.kind.bounds for effect in judge_gaps(codes, context))


def deterministic_scope_is_clean(
    *,
    coverage: Coverage,
    totals: Mapping[str, object],
    findings: Sequence[Finding],
    route_requires_review: bool = False,
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
    if not gaps_are_clean(
        coverage.known_gaps, checked, route_requires_review=route_requires_review
    ):
        return False
    if any(type(finding) is not Finding for finding in findings):
        return False
    # A limitation request asks for a disclosure, not work, but it can never read as clean.
    if any(finding_demands_work(finding) or is_limitation_request(finding) for finding in findings):
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
