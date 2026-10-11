"""Status wires for the bounded MCP text tests (tb4n3 RC-6 check_cause, RC-5 fact_lineage).

One closure-readiness wire per view, with an optional ``check_cause`` and ``fact_lineage``, shaped
like the service's status result so the byte-bounded text builders read exactly what they read in
production. Ids are fixed so a test can assert on the rendered sentences.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from yoetz.domain.values import event_id, obligation_id
from yoetz.kernel.fact_lineage import FactLineage, lineage_to_wire

__all__ = [
    "BOUNDING",
    "HEAD",
    "SUPERSEDED",
    "VIEWS",
    "emptied_lineage",
    "matched_by_prefix_lineage",
    "status_wire",
]

HEAD = "sha256:" + "0" * 64
PROJECT = "prj_59000000-0000-4000-8000-000000000001"
VIEWS = ("compact", "advice", "lineage", "project", "operation")

SUPERSEDED: dict[str, Any] = {
    "effect": "superseded",
    "event_id": "evt_00000000-0000-4000-8000-000000000009",
    "ledger_sequence": "12",
    "check_event_id": "evt_00000000-0000-4000-8000-000000000003",
    "check_subject_frontier": "7",
    "family": "action_recorded",
    "material_class": "edit_or_write",
    "rule": "observed_counting_edit",
    "tool": "apply_patch",
}
BOUNDING: dict[str, Any] = {
    **SUPERSEDED,
    "effect": "bounds_conclusion",
    "material_class": "other",
    "rule": "unclassified_observed_action",
    "tool": "exec_command",
}

_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-0000000000f1")


def emptied_lineage() -> FactLineage:
    """Why ``declared_output_emptied`` fired: the deliverable held content, then none."""

    return FactLineage(
        code="declared_output_emptied",
        rule="deliverable_path_history",
        state="emptied",
        obligation_id=_OBLIGATION,
        item_index=0,
        check_event_id=event_id("evt_00000000-0000-4000-8000-0000000000f2"),
        frontier=340,
        prior_event_id=event_id("evt_00000000-0000-4000-8000-0000000000f3"),
        prior_frontier=312,
        prior_size_bytes=15_975,
        prior_lines=310,
        now_size_bytes=0,
        now_lines=0,
        proof="earlier_check",
        basis="delivered",
    )


def matched_by_prefix_lineage() -> FactLineage:
    """Why ``planned_verification_matched_by_prefix`` stands as a disclosure."""

    return FactLineage(
        code="planned_verification_matched_by_prefix",
        rule="planned_command_match",
        state="matched_prefix",
        obligation_id=_OBLIGATION,
        item_index=1,
        frontier=210,
        proof="observed_run",
        source_event_ids=(event_id("evt_00000000-0000-4000-8000-0000000000f4"),),
    )


def _page(view: str) -> dict[str, Any] | None:
    lineage: dict[str, Any] = {"parent_task_id": None, "children": [{}, {}], "annotations": []}
    pages: dict[str, dict[str, Any]] = {
        "compact": {"items": [{"freshness": "current", "open_obligations": []}]},
        "advice": {"items": []},
        "lineage": lineage,
        # An ordinary active project page: members, detections, receipts and coverage rows.
        "project": {
            "project_id": PROJECT,
            "membership_generation": "3",
            "grant_state": "active",
            "members": [{}] * 3,
            "detections": [{}],
            "receipts": [{}] * 2,
            "coverage": [{}] * 2,
            "lineage": lineage,
        },
        # A completed semantic check; the edit that followed it is the cause.
        "operation": {
            "state": "completed",
            "operation_kind": "semantic_check",
            "semantic_progress": {
                "phase": "review",
                "attempt_ordinal": "2",
                "condition": "terminal",
                "elapsed_ms": "91234",
                "terminal_outcome": "completed",
                "terminal_reason": "review_complete",
            },
        },
    }
    return pages.get(view)


def status_wire(
    *,
    state: str,
    view: str,
    cause: Any = None,
    lineage: Sequence[FactLineage] = (),
    actionable: Sequence[str] | None = None,
    standing: Sequence[str] | None = None,
) -> dict[str, Any]:
    """A status result for ``view`` whose closure readiness is in ``state``.

    By default an ``action_required`` readiness lists ``check_not_applicable`` and a
    ``ready_with_limitations`` one lists the standing earlier-frontier code, the two tokens a
    ``check_cause`` explains. ``lineage`` becomes ``closure_readiness.fact_lineage`` in wire form.
    """

    action = state == "action_required"
    if actionable is None:
        actionable = ["check_not_applicable"] if action else []
    if standing is None:
        standing = [] if action else ["check_current_as_of_earlier_frontier"]
    readiness: dict[str, Any] = {
        "state": state,
        "open_obligation_count": "0",
        "unanswered_finding_count": "0",
        "receipt_blocking_finding_count": "0",
        "acknowledged_not_done_count": "0",
        "agent_actionable": list(actionable),
        "standing_limitations": list(standing),
    }
    if cause is not None:
        readiness["check_cause"] = cause
    if lineage:
        readiness["fact_lineage"] = [lineage_to_wire(item) for item in lineage]
    wire: dict[str, Any] = {
        "view": view,
        "head_frontier": {"sequence": "9", "head_digest": HEAD},
        "closure_readiness": readiness,
        "gaps": [],
    }
    page = _page(view)
    if page is not None:
        wire["page"] = page
    return wire
