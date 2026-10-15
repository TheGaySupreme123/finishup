"""Real ``status`` results (compact and obligations views) for hook and recap tests (#1027).

The post-compaction recap reads typed ``StatusResultModel`` branches, so its tests hand it the
protocol models themselves, validated from wire dicts, never attribute stand-ins. Ids are minted
once per call so a test can assert on them.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from builders.readiness import with_checklist
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import StatusResultModel

__all__ = ["CompactStatus", "compact_status", "obligations_status"]

_ZERO = "sha256:" + "0" * 64


def _coverage() -> dict[str, Any]:
    return {
        "publication_channels": ["cooperative_mcp", "hook_observed"],
        "authorship_assurance": "self_asserted",
        "artifact_observation": "published_only",
        "evidence_immutability": "metadata_only",
        "ledger_freshness": "current",
        "check_types": ["deterministic"],
        "known_gaps": [],
    }


def _privacy() -> dict[str, Any]:
    return {
        "sink": "agent_context",
        "local_disclosure_receipt_id": new_id(IdKind.EGRESS_RECEIPT),
        "policy_id": new_id(IdKind.PRIVACY_POLICY),
        "policy_version": "1",
        "policy_digest": _ZERO,
        "included_categories": [],
        "blocked_categories": [],
        "omitted_pointers": [],
        "projection_commitment": "hmac-sha256:" + "1" * 64,
    }


def _envelope(
    view: str,
    page: Mapping[str, Any],
    readiness: Mapping[str, Any],
    ids: tuple[str, str, str],
    sequence: str,
    digest: str,
) -> dict[str, Any]:
    frontier = {"sequence": sequence, "head_digest": digest}
    task_id, session_id, writer_id = ids
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "ok": True,
        "task_id": task_id,
        "session_id": session_id,
        "writer_id": writer_id,
        "view": view,
        "requested_frontier": dict(frontier),
        "head_frontier": dict(frontier),
        "subject_frontier": dict(frontier),
        "result_frontier": dict(frontier),
        "projection_lag": "0",
        "projection_version": "0.1.0",
        "rebuild_state": "current",
        "page": dict(page),
        "coverage": _coverage(),
        "gaps": [],
        "import_status": {
            "pending_count": "0",
            "terminal_count": "0",
            "phase": None,
            "report_evidence_id": None,
            "source_identity_digest": None,
        },
        "closure_readiness": dict(readiness),
        "privacy_projection": _privacy(),
    }


@dataclass(frozen=True, slots=True)
class CompactStatus:
    """A validated compact status result plus the ids it names."""

    result: StatusResultModel
    task_id: str
    session_id: str
    writer_id: str
    sequence: str
    digest: str
    obligation_ids: tuple[str, ...] = field(default=())
    finding_ids: tuple[str, ...] = field(default=())
    check_event_id: str | None = None


def compact_status(
    *,
    sequence: str = "604",
    digest: str | None = None,
    open_obligations: Sequence[str | None] = (),
    declared: int | None = None,
    findings: Sequence[tuple[str, int, str | None]] = (),
    receipt_blocking: int = 0,
    latest_check: tuple[str, str] | None = None,
    title: str | None = "Port the streaming parser",
    plan_event: bool = True,
    acknowledged_not_done: int = 0,
    readiness_conditions: Sequence[str] | None = None,
    gaps: Sequence[str] = (),
    ids: tuple[str, str, str] | None = None,
) -> CompactStatus:
    """Build a compact status result.

    ``open_obligations`` lists each description (``None`` for a withheld one); ``findings`` is
    ``(kind, priority, summary or None for withheld)``; ``latest_check`` is
    ``(verdict, checked_frontier_sequence)``.
    """

    digest = digest or "sha256:" + "c6a3f00a" * 8
    ids = ids or (new_id(IdKind.TASK), new_id(IdKind.SESSION), new_id(IdKind.WRITER))
    omitted_obligation = {
        "category": "obligation_text",
        "omitted": True,
        "reason": "local_disclosure_not_authorized",
    }
    omitted_finding = {
        "category": "finding_summary",
        "omitted": True,
        "reason": "local_disclosure_not_authorized",
    }
    obligation_rows: list[dict[str, Any]] = []
    obligation_ids: list[str] = []
    for text in open_obligations:
        obligation_id = new_id(IdKind.OBLIGATION)
        obligation_ids.append(obligation_id)
        value = text if text is not None else omitted_obligation
        obligation_rows.append(
            {
                "obligation_id": obligation_id,
                "description": value,
                "evidence_expectation": value,
            }
        )
    finding_rows: list[dict[str, Any]] = []
    finding_ids: list[str] = []
    for kind, priority, summary in findings:
        finding_id = new_id(IdKind.FINDING)
        finding_ids.append(finding_id)
        value = summary if summary is not None else omitted_finding
        finding_rows.append(
            {
                "finding_id": finding_id,
                "kind": kind,
                "priority": priority,
                "summary": value,
                "detail": value,
            }
        )
    open_count = len(obligation_rows)
    declared_count = declared if declared is not None else max(open_count, 1)
    item: dict[str, Any] = {
        "task_id": ids[0],
        "session_id": ids[1],
        "task_title": title
        if title is not None
        else {
            "category": "task_description",
            "omitted": True,
            "reason": "local_disclosure_not_authorized",
        },
        "current_plan_event_id": new_id(IdKind.EVENT) if plan_event else None,
        "declared_obligation_count": str(declared_count if plan_event else 0),
        "no_obligations_reason": None,
        "open_obligation_count": str(open_count),
        "unanswered_finding_count": str(len(finding_rows)),
        "receipt_blocking_finding_count": str(receipt_blocking),
        "open_obligations": obligation_rows,
        "unanswered_findings": finding_rows,
        "freshness": "current",
        "coverage": _coverage(),
        "gaps": list(gaps),
    }
    check_event_id = None
    if latest_check is not None:
        check_event_id = new_id(IdKind.EVENT)
        item["latest_check"] = {
            "check_event_id": check_event_id,
            "checked_frontier": {"sequence": latest_check[1], "head_digest": _ZERO},
            "verdict": latest_check[0],
        }
    conditions = list(
        readiness_conditions
        if readiness_conditions is not None
        else [
            *(["obligations_open"] if open_count else []),
            *(["findings_unanswered"] if finding_rows else []),
            *(["receipt_findings_unresolved"] if receipt_blocking else []),
            *([] if plan_event else ["no_plan_published"]),
        ]
        or ["coverage_gaps_declared"]
    )
    readiness = with_checklist(
        {
            "declared_obligation_count": item["declared_obligation_count"],
            "no_obligations_reason": None,
            "open_obligation_count": item["open_obligation_count"],
            "unanswered_finding_count": item["unanswered_finding_count"],
            "receipt_blocking_finding_count": item["receipt_blocking_finding_count"],
            "blocking_conditions": conditions,
            "acknowledged_obligation_count": str(acknowledged_not_done),
        },
        gaps=gaps,
    )
    wire = _envelope(
        "compact",
        {"items": [item], "next_cursor": None},
        readiness,
        ids,
        sequence,
        digest,
    )
    return CompactStatus(
        result=StatusResultModel.model_validate(wire),
        task_id=ids[0],
        session_id=ids[1],
        writer_id=ids[2],
        sequence=sequence,
        digest=digest,
        obligation_ids=tuple(obligation_ids),
        finding_ids=tuple(finding_ids),
        check_event_id=check_event_id,
    )


def obligations_status(
    compact: CompactStatus,
    obligations: Sequence[
        tuple[str, Sequence[tuple[str, str | None, str | None]]]
        | tuple[str, Sequence[tuple[str, str | None, str | None]], bool | None]
    ],
    *,
    sequence: str | None = None,
    next_cursor: str | None = None,
) -> StatusResultModel:
    """An obligations view page.

    Each obligation is ``(status, [(item_kind, value or None for withheld, role)])`` or the same
    with a third ``in_current_plan`` element (default ``True``; ``None`` leaves it absent, as an
    older service or an unreadable plan scope does). ``sequence`` is the page's own head frontier
    (default the compact status's), ``next_cursor`` marks a page with more behind it.
    """

    rows: list[dict[str, Any]] = []
    for entry in obligations:
        status, requested = entry[0], entry[1]
        current: bool | None = entry[2] if len(entry) == 3 else True  # type: ignore[misc]
        row: dict[str, Any] = {
            "obligation_id": new_id(IdKind.OBLIGATION),
            "status": status,
            "description": "Synthetic obligation",
            "evidence_expectation": "Observed",
            "source_refs": [],
            "assigned_actor_ids": [],
            "evidence_refs": [],
            "revision_event_id": None,
            "requested_items": [
                {
                    "item_kind": kind,
                    "value": value
                    if value is not None
                    else {
                        "category": "obligation_text",
                        "omitted": True,
                        "reason": "local_disclosure_not_authorized",
                    },
                    **({"role": role} if role is not None else {}),
                }
                for kind, value, role in requested
            ],
        }
        if status == "acknowledged_not_done":
            row["acknowledged_not_done_reason"] = "Synthetic reason"
        if current is not None:
            row["in_current_plan"] = current
        rows.append(row)
    readiness = with_checklist(
        {
            "declared_obligation_count": str(len(rows)),
            "no_obligations_reason": None,
            "open_obligation_count": "0",
            "unanswered_finding_count": "0",
            "receipt_blocking_finding_count": "0",
            "blocking_conditions": ["coverage_gaps_declared"],
        }
    )
    wire = _envelope(
        "obligations",
        {"items": rows, "next_cursor": next_cursor},
        readiness,
        (compact.task_id, compact.session_id, compact.writer_id),
        sequence or compact.sequence,
        compact.digest,
    )
    return StatusResultModel.model_validate(wire)
