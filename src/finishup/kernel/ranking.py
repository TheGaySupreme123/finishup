"""Pure stable finding ranking, capping, diversity, and verdict selection."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final

from finishup.domain.findings import (
    CheckVerdict,
    Finding,
    FindingOrigin,
    RankedFindings,
    finding_demands_work,
    is_limitation_request,
    rank_key,
)
from finishup.domain.receipts import (
    COMPLETION_SCOPE_DECLARED_NONE_GAP,
    COMPLETION_SCOPE_UNDECLARED_GAP,
)
from finishup.protocol.coverage import Coverage, weakest
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import MAX_FINDINGS_LIMIT

__all__ = [
    "CheckCompleteness",
    "RankingContext",
    "rank_findings",
]

_MATERIAL_CHALLENGE_PRIORITIES: Final = frozenset({1, 2})
_COMPLETION_SCOPE_GAPS: Final = frozenset(
    {COMPLETION_SCOPE_DECLARED_NONE_GAP, COMPLETION_SCOPE_UNDECLARED_GAP}
)


class CheckCompleteness(str, Enum):  # noqa: UP042 - exact internal contract token
    COMPLETE = "complete"
    # Deterministic-only checks may have the standing absence-of-semantic-review limitation while
    # still reporting a bounded local result.  This is an internal ranking state; the public
    # coverage vector continues to carry every gap and the receipt remains coverage-bounded.
    SCOPED_COMPLETE = "scoped_complete"
    COVERAGE_INCOMPLETE = "coverage_incomplete"
    REQUIRED_INCOMPLETE = "required_incomplete"


@dataclass(frozen=True, slots=True)
class RankingContext:
    coverage: Coverage
    completeness: CheckCompleteness

    def __post_init__(self) -> None:
        if type(self.coverage) is not Coverage or type(self.completeness) is not CheckCompleteness:
            raise ProtocolValueError("invalid_ranked_findings")
        if (
            self.completeness is CheckCompleteness.COVERAGE_INCOMPLETE
            and not self.coverage.known_gaps
        ):
            raise ProtocolValueError("invalid_ranked_findings")


def _validate_inputs(
    deterministic: tuple[Finding, ...],
    semantic: tuple[Finding, ...],
    context: RankingContext,
    max_findings: int,
) -> tuple[Finding, ...]:
    if (
        type(deterministic) is not tuple
        or type(semantic) is not tuple
        or type(context) is not RankingContext
        or type(max_findings) is not int
        or not 1 <= max_findings <= MAX_FINDINGS_LIMIT
    ):
        raise ProtocolValueError("invalid_ranked_findings")
    if any(type(finding) is not Finding for finding in deterministic + semantic):
        raise ProtocolValueError("invalid_ranked_findings")
    if any(finding.origin is not FindingOrigin.DETERMINISTIC for finding in deterministic):
        raise ProtocolValueError("invalid_ranked_findings")
    if any(finding.origin is not FindingOrigin.SEMANTIC_MODEL_DERIVED for finding in semantic):
        raise ProtocolValueError("invalid_ranked_findings")

    findings = deterministic + semantic
    ids = tuple(finding.finding_id for finding in findings)
    if len(ids) != len(set(ids)):
        raise ProtocolValueError("invalid_ranked_findings")
    for finding in findings:
        if weakest(context.coverage, finding.coverage) != context.coverage:
            raise ProtocolValueError("invalid_ranked_findings")
    return findings


def _selected_with_diversity(
    ordered: tuple[Finding, ...],
    semantic: tuple[Finding, ...],
    max_findings: int,
) -> tuple[Finding, ...]:
    """Reserve part of the cap for material AI-powered challenges the kind order would evict.

    ``rank_key`` puts origin ninth of ten, so finding kind dominates and enough local
    findings out-rank every AI-powered one. That ordering is deliberate and is left alone. What
    changes here is how many reserved seats survive it: the rescue used to be exactly one, so a
    reviewer that raised two or three material challenges had all but the best silently folded
    into ``suppressed_count``. Up to half the cap is now reservable, which keeps local
    findings in the majority while letting more than one challenge be seen.

    ``max_findings == 1`` reserves nothing and stays local-only, unchanged from before:
    the single seat goes to the highest-ranked finding, because reserving it would mean returning
    an AI-powered challenge in place of every local finding rather than alongside them.
    """

    selected = ordered[:max_findings]
    if max_findings < 2:
        return selected
    material_challenges = sorted(
        (finding for finding in semantic if finding.priority in _MATERIAL_CHALLENGE_PRIORITIES),
        key=rank_key,
    )
    if not material_challenges:
        return selected
    reserved = material_challenges[: max_findings // 2]
    reserved_ids = {finding.finding_id for finding in reserved}
    if reserved_ids <= {finding.finding_id for finding in selected}:
        return selected
    kept = [finding for finding in selected if finding.finding_id not in reserved_ids]
    room = max_findings - len(reserved)
    return tuple(sorted((*reserved, *kept[:room]), key=rank_key))


def _verdict(
    selected: tuple[Finding, ...],
    context: RankingContext,
) -> CheckVerdict:
    if _COMPLETION_SCOPE_GAPS & set(context.coverage.known_gaps):
        # Empty completion scope is a verdict-level coverage boundary, not a policy finding.
        # Preserve selected findings for disposition, but never let one upgrade either closed
        # scope gap into an action-required completion verdict.
        return CheckVerdict.INSUFFICIENT_COVERAGE
    if context.completeness is CheckCompleteness.REQUIRED_INCOMPLETE:
        return CheckVerdict.INCOMPLETE_CHECK
    if any(finding_demands_work(finding) for finding in selected):
        return CheckVerdict.ACTION_REQUIRED
    if context.completeness is CheckCompleteness.COVERAGE_INCOMPLETE or any(
        is_limitation_request(finding) for finding in selected
    ):
        # A reviewer's limitation request asks the agent to state a limit, not to do work: it can
        # never read as clean and never demands repair (ADR-046, owner decision Q4).
        return CheckVerdict.INSUFFICIENT_COVERAGE
    if context.completeness is CheckCompleteness.SCOPED_COMPLETE:
        # A non-actionable coverage finding can remain visible beside a scoped result.  It does
        # not make the local work actionable, but the selected row is still returned rather than
        # tripping the complete-context invariant below.
        return CheckVerdict.NO_ISSUE_DETECTED
    if selected:
        raise ProtocolValueError("invalid_ranked_findings")
    return CheckVerdict.NO_ISSUE_DETECTED


def rank_findings(
    deterministic: tuple[Finding, ...],
    semantic: tuple[Finding, ...],
    context: RankingContext,
    max_findings: int,
) -> RankedFindings:
    """Return the registered stable, bounded finding selection and conservative verdict."""

    findings = _validate_inputs(deterministic, semantic, context, max_findings)
    ordered = tuple(sorted(findings, key=rank_key))
    selected = _selected_with_diversity(ordered, semantic, max_findings)
    return RankedFindings(
        findings=selected,
        suppressed_count=len(findings) - len(selected),
        verdict=_verdict(selected, context),
        coverage=context.coverage,
    )
