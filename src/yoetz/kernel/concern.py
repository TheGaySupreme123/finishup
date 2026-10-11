"""Concern identity for reviewer findings (tb4n3 RC-7, issue #1030, ADR-040 amendment).

The reviewer re-raises one concern under new finding ids because every earlier rule keyed the
concern on the *kind* of finding and on an asymmetric subject set (an obligation set on one side,
a raw event set on the other). ``concern_key`` is the one symmetric identity both sides use, and
``same_concern`` is the one overlap rule:

* The key's ``obligations`` are the obligations the subjects concern: the ``obl_`` ids a finding
  names, else the obligations a cited claim declares (``obligation_refs``), else those a cited
  event recorded. A claim is first mapped to the claim that currently supersedes it, so
  re-publishing a claim never makes a new concern.
* The key's ``refs`` are the remaining subjects (claims normalised, events and obligations kept)
  without the *anchors*: the events every obligation lists as its source (the task statement or
  session start), which every finding cites and which therefore say nothing about a concern.
* Two keys name one concern when their obligations overlap, or, when either side has none, when
  one side's refs contain the other's. Overlap is deliberately loose, because one concern is
  re-raised under changing wording; the risk (two real concerns on one obligation folded) is
  disclosed through ``semantic_restatements_suppressed`` and bounded by the material rule
  (``application.review_concern``), which keeps anything newer and concern-relevant as new.

The requirement-family kinds fold across kinds (a limitation request raised as
``task_requirement_unmet`` after ``completion_with_open_obligations`` is the same concern); every
other kind folds only onto its own.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, cast

from yoetz.domain.findings import FindingKind
from yoetz.domain.values import ClaimId
from yoetz.kernel.projections import ProjectionState

__all__ = [
    "REQUIREMENT_FAMILY_KINDS",
    "ConcernKey",
    "anchor_refs",
    "concern_key",
    "current_claim",
    "equal_concern",
    "kinds_comparable",
    "same_concern",
    "subject_obligations",
]

# The kinds that fold across kinds: each says a stated requirement is not delivered, or that a
# claim still covers one that is not. ``evidence_does_not_support_claim`` joins them only when the
# subjects name obligations (D-3 of the tb4n3 dialogue analysis); every other kind, a
# ``code_defect`` or a claim without admissible evidence for example, folds only onto its own.
REQUIREMENT_FAMILY_KINDS: Final = frozenset(
    {
        FindingKind.TASK_REQUIREMENT_UNMET,
        FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
        FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
    }
)


def kinds_comparable(
    first: FindingKind, second: FindingKind, *, obligation_concern: bool = False
) -> bool:
    """Whether two finding kinds may name one concern.

    The same kind always may. The requirement-family kinds may across kinds, and so may
    ``evidence_does_not_support_claim`` when ``obligation_concern`` says both concerns name
    obligations.
    """

    if first is second:
        return True
    family = REQUIREMENT_FAMILY_KINDS
    if obligation_concern:
        family = family | {FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM}
    return first in family and second in family


def current_claim(projection: ProjectionState, ref: str) -> str:
    """The claim that currently supersedes *ref* (itself when none does); bounded, cycle-safe."""

    current = ref
    seen: set[str] = set()
    while current not in seen and len(seen) < 64:
        seen.add(current)
        row = projection.claims.get(cast(ClaimId, current))
        following = None if row is None else row.superseded_by_claim_id
        if following is None:
            return current
        current = str(following)
    return current


@dataclass(frozen=True, slots=True)
class ConcernKey:
    """What one set of finding subjects is about (see the module docstring)."""

    obligations: frozenset[str]
    refs: frozenset[str]


def anchor_refs(projection: ProjectionState) -> frozenset[str]:
    """The events every obligation names as its source: the task statement or session start.

    A finding cites them to ground itself in the task, not to say which concern it raises, so
    they never count when two subject sets are compared.
    """

    anchors: set[str] = set()
    for record in projection.obligations.values():
        if record.payload is not None:
            anchors.update(str(ref) for ref in record.payload.source_refs)
    return frozenset(anchors)


def subject_obligations(projection: ProjectionState, refs: Iterable[str]) -> frozenset[str]:
    """The obligations a subject set concerns: named, else declared by a cited claim or event."""

    items = tuple(refs)
    direct = frozenset(ref for ref in items if ref.startswith("obl_"))
    if direct:
        return direct
    derived: set[str] = set()
    event_to_obligation = {
        str(record.source_event_id): str(key)
        for key, record in projection.obligations.items()
        if record.payload is not None
    }
    event_to_claim = {
        str(record.source_event_id): record
        for record in projection.claims.values()
        if record.payload is not None
    }
    for ref in items:
        if ref.startswith("clm_"):
            claim = projection.claims.get(cast(ClaimId, current_claim(projection, ref)))
            if claim is not None and claim.payload is not None:
                derived.update(str(item) for item in claim.payload.obligation_refs)
        elif ref.startswith("evt_"):
            if ref in event_to_obligation:
                derived.add(event_to_obligation[ref])
            claim_record = event_to_claim.get(ref)
            if claim_record is not None and claim_record.payload is not None:
                derived.update(str(item) for item in claim_record.payload.obligation_refs)
    return frozenset(derived)


def concern_key(projection: ProjectionState, refs: Iterable[str]) -> ConcernKey:
    """The symmetric concern identity of one finding's (or challenge's) subject refs."""

    items = tuple(refs)
    anchors = anchor_refs(projection)
    normalised = frozenset(
        current_claim(projection, ref) if ref.startswith("clm_") else ref
        for ref in items
        if ref not in anchors
    )
    return ConcernKey(subject_obligations(projection, items), normalised)


def same_concern(first: ConcernKey, second: ConcernKey) -> bool:
    """Whether two keys name one concern: obligation overlap, else subject containment."""

    if first.obligations and second.obligations:
        return bool(first.obligations & second.obligations)
    if not first.refs or not second.refs:
        return False
    return first.refs <= second.refs or second.refs <= first.refs


def equal_concern(first: ConcernKey, second: ConcernKey) -> bool:
    """Whether two keys name the very same concern: the same obligations, else the same refs.

    The rule for an open, rulable finding: a narrower or wider challenge is a distinct issue.
    """

    if first.obligations or second.obligations:
        return first.obligations == second.obligations
    return bool(first.refs) and first.refs == second.refs
