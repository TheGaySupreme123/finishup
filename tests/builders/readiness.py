"""Closure-readiness wire builder for tests that hand-author a status result.

Status producers derive the checklist fields (``state``, ``agent_actionable``, …) from the same
blocking conditions and gaps; hand-authored vectors use this helper so they stay consistent with
``yoetz.kernel.closure_readiness`` instead of restating the split in every test.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

from yoetz.kernel.closure_readiness import (
    GAP_CLASSIFICATION_VERSION,
    ClosureReadinessFacts,
    derive_closure_readiness,
)


def with_checklist(
    readiness: Mapping[str, Any],
    *,
    gaps: Sequence[str] = (),
    facts: ClosureReadinessFacts | None = None,
    semantic_review_required: bool = False,
) -> dict[str, Any]:
    """Return ``readiness`` with the checklist fields the service would derive for it."""

    result = dict(readiness)
    conditions = tuple(cast(Sequence[str], result.get("blocking_conditions", ())))
    if "readiness_unknown" in conditions:
        result.update(
            state="unknown",
            gap_classification_version=GAP_CLASSIFICATION_VERSION,
            agent_actionable=["readiness_unknown"],
            standing_limitations=[],
            acknowledged_not_done=[],
            acknowledged_not_done_count="0",
            blocked_obligations=[],
        )
        return result
    split = derive_closure_readiness(
        conditions, gaps, facts, semantic_review_required=semantic_review_required
    )
    result.update(
        state=split.state,
        gap_classification_version=GAP_CLASSIFICATION_VERSION,
        agent_actionable=list(split.agent_actionable),
        standing_limitations=list(split.standing_limitations),
        acknowledged_not_done=list(split.acknowledged_not_done),
        acknowledged_not_done_count=str(split.acknowledged_not_done_count),
        blocked_obligations=[
            {"obligation_id": obligation, "blocker_kind": kind, "decision_event_id": event}
            for obligation, kind, event in (
                () if facts is None else facts.blocked_obligation_details
            )
        ],
    )
    return result
