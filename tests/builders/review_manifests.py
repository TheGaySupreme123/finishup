"""Provider-bound review-input manifests for scripted AI-powered review successes.

A successful review without the exact provider-bound manifest is disclosed as
``semantic_provider_input_manifest_missing`` (#965). Scripted evaluators that stand in for a
real provider call return this minimal, schema-valid manifest so their success stays a clean
success; it describes an empty packet and never stands in for real provider bytes.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, cast

from finishup.application.missing_for_assessment import (
    ReviewFollowUp,
    ReviewFollowUpItem,
    observed_enrichment_refs,
)
from finishup.domain.values import JsonObject
from finishup.kernel.projections import ProjectionState


def provider_bound_manifest() -> JsonObject:
    section = JsonObject(
        {
            "status": "missing",
            "source_refs": [],
            "item_ids": [],
            "omitted_refs": [],
            "omission_reasons": [],
            "revision": None,
            "content_digest": None,
            "content_bytes": 0,
        }
    )
    return JsonObject(
        {
            "schema": "yoetz.review-input-manifest/1",
            "phase": "provider_bound",
            "specification": section,
            "current_diff": section,
            "caller_evidence": section,
            "latest_verification": section,
            "prior_finding_context": section,
            "missing_inputs": [],
            "selected_item_count": 0,
            "selected_excerpt_bytes": 0,
            "omitted_item_count": 0,
        }
    )


def follow_up_round(
    *items: tuple[str, tuple[str, ...], Iterable[str]],
    shown: frozenset[str] | None = None,
    shown_parts: frozenset[str] | None = None,
) -> ReviewFollowUp:
    """A first in-check follow-up round, given ``(kind, targets, sources)`` per item.

    #1118 unit 4 deleted the planner that once chose a round; recorded follow-up jobs still
    decode and compose, so their tests state the round they compose directly.
    """

    return ReviewFollowUp(
        1,
        tuple(
            ReviewFollowUpItem(cast(Any, kind), targets, frozenset(sources))
            for kind, targets, sources in items
        ),
        shown or frozenset(),
        shown_parts=shown_parts or frozenset(),
    )


def run_sources(projection: ProjectionState, result_ref: str, allowed: frozenset[str]) -> set[str]:
    """The rows one recorded run holds: its result, action, the action's cited evidence and the
    hook-captured output linked to that action."""

    (payload,) = (
        row.payload
        for key, row in projection.results.items()
        if str(key) == result_ref and row.payload is not None
    )
    refs = {result_ref, str(payload.action_id)}
    for row in projection.results.values():
        if row.payload is not None and row.payload.action_id == payload.action_id:
            refs.update(str(ref) for ref in row.payload.evidence_refs)
    action = projection.actions.get(payload.action_id)
    if action is not None:
        refs.update(observed_enrichment_refs(projection).get(str(action.source_event_id), ()))
    return refs & allowed
