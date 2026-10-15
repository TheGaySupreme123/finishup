"""Hook-side adapter for the post-compaction recap (ADR-044, issue #1027).

A resumed-after-compaction ``SessionStart`` already reads the mapped session's compact ``status``.
This module turns that one result (and, when time allows, one ``obligations`` view) into
:class:`~finishup.domain.compaction_recap.RecapFacts` and renders the bounded recap. It adds no
service operation and no classification: every value is read off the status result the hook
already holds, under the same privacy projection ``status`` applies (a withheld description or
path stays withheld).

The readers are duck-typed on purpose: the hook tests, and an older service that omits an optional
field, hand this a result that lacks some attributes, and a missing fact must read as "not
reported" rather than raise inside a host-visible hook.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from typing import Final, cast

from finishup.domain.compaction_recap import (
    RECAP_LIMIT,
    RecapCheck,
    RecapDeliverable,
    RecapFacts,
    RecapFinding,
    RecapObligation,
    compose_compaction_recap,
)

__all__ = [
    "compact_recap_text",
    "pending_work_rows",
    "recap_facts_from_status",
    "recap_with_deliverables",
]

# Rows that carry no ledger work: a lifecycle or prompt event the ledger never records as a
# tool call, so its being undelivered cannot make a recap fact stale.
_LIFECYCLE_KINDS: Final = frozenset(
    {
        "PermissionRequest",
        "PostCompact",
        "PreCompact",
        "SessionEnd",
        "SessionStart",
        "Stop",
        "UserPromptSubmit",
    }
)

_DELIVERABLE_KINDS: Final = frozenset({"file", "directory"})
_MAX_DELIVERABLES: Final = 12


def _text(value: object) -> str | None:
    """A disclosed string, or ``None`` for a withheld (omitted-content) value."""

    return value if type(value) is str else None


def _int(value: object) -> int | None:
    if type(value) is str and value.isdecimal():
        return int(value)
    if type(value) is int and not isinstance(value, bool):
        return value
    return None


def _items(value: object) -> tuple[object, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(cast("Sequence[object]", value))
    return ()


def recap_facts_from_status(
    branch: object,
    *,
    task_id: str,
    session_id: str,
    writer_id: str,
) -> RecapFacts | None:
    """Read the recap facts off one successful compact ``status`` result, or ``None``.

    ``None`` means the result carried no head frontier to anchor the recap on; the hook then
    keeps its ordinary startup context.
    """

    head = getattr(branch, "head_frontier", None)
    sequence = _text(getattr(head, "sequence", None))
    digest = _text(getattr(head, "head_digest", None))
    if sequence is None or digest is None:
        return None
    page = getattr(branch, "page", None)
    page_items = _items(getattr(page, "items", None))
    item = page_items[0] if page_items else None
    readiness = getattr(branch, "closure_readiness", None)

    obligations = tuple(
        RecapObligation(
            obligation_id=str(getattr(row, "obligation_id", "")),
            description=_text(getattr(row, "description", None)),
        )
        for row in _items(getattr(item, "open_obligations", None))
        if _text(getattr(row, "obligation_id", None)) is not None
    )
    findings = tuple(
        RecapFinding(
            finding_id=str(getattr(row, "finding_id", "")),
            kind=_text(getattr(row, "kind", None)) or "finding",
            priority=_int(getattr(row, "priority", None)) or 3,
            summary=_text(getattr(row, "summary", None)),
        )
        for row in _items(getattr(item, "unanswered_findings", None))
        if _text(getattr(row, "finding_id", None)) is not None
    )
    latest = getattr(item, "latest_check", None)
    check = None
    if latest is not None:
        check_event = _text(getattr(latest, "check_event_id", None))
        check_frontier = _text(getattr(getattr(latest, "checked_frontier", None), "sequence", None))
        verdict = _text(getattr(latest, "verdict", None))
        if check_event is not None and check_frontier is not None and verdict is not None:
            check = RecapCheck(check_event, check_frontier, verdict)
    actionable = tuple(
        token
        for token in _items(getattr(readiness, "agent_actionable", None))
        if type(token) is str
    )
    state = _text(getattr(readiness, "state", None))
    blocked = getattr(readiness, "blocked_obligations", None)
    title = _text(getattr(item, "task_title", None))
    return RecapFacts(
        task_id=task_id,
        session_id=session_id,
        writer_id=writer_id,
        head_sequence=sequence,
        head_digest=digest,
        plan_event_id=_text(getattr(item, "current_plan_event_id", None)),
        declared_obligations=_int(getattr(item, "declared_obligation_count", None)),
        open_obligations_total=_int(getattr(item, "open_obligation_count", None)),
        acknowledged_not_done=_int(getattr(readiness, "acknowledged_obligation_count", None)),
        task_title=title,
        obligations=obligations,
        unanswered_findings_total=_int(getattr(item, "unanswered_finding_count", None)),
        # ADR-046: findings to do (the counter every surface prints); an earlier status that
        # carries only the wire count keeps reporting that.
        receipt_blocking_findings=_int(
            getattr(getattr(readiness, "finding_counts", None), "to_do", None)
        )
        if getattr(readiness, "finding_counts", None) is not None
        else _int(getattr(item, "receipt_blocking_finding_count", None)),
        findings=findings,
        check=check,
        no_check_recorded="check_not_recorded" in actionable,
        readiness_state=state,
        agent_actionable=actionable,
        blocked_obligations=len(_items(blocked)) if blocked is not None else None,
        predicted_conclusion=_text(
            getattr(getattr(readiness, "predicted_receipt", None), "conclusion", None)
        ),
    )


def recap_with_deliverables(
    facts: RecapFacts, pages: Sequence[object], *, more_pages: bool = False
) -> RecapFacts:
    """Add the declared deliverables read off the ``obligations`` view pages (first page first).

    A declared deliverable is a requested ``file`` or ``directory`` item with role ``output`` of
    an obligation in the current plan's effective scope (``in_current_plan``), the definition the
    readiness facts use (``task_facts.declared_output_items``). The view lists every obligation
    ever published, so a row the service did not mark as part of the current plan (a waived or
    superseded one, or an older service that does not say) is never claimed as a deliverable.
    ``more_pages`` records that the view has pages that were not read.
    """

    if not pages:
        return facts
    rows: list[RecapDeliverable] = []
    scope_unknown = False
    for branch in pages:
        page = getattr(branch, "page", None)
        if page is None:
            return facts
        for obligation in _items(getattr(page, "items", None)):
            obligation_id = _text(getattr(obligation, "obligation_id", None))
            if obligation_id is None:
                continue
            current = getattr(obligation, "in_current_plan", None)
            if current is None:
                scope_unknown = True
                continue
            if current is not True:
                continue
            status = _text(getattr(obligation, "status", None)) or "unreported"
            for requested in _items(getattr(obligation, "requested_items", None)):
                if (
                    _text(getattr(requested, "item_kind", None)) in _DELIVERABLE_KINDS
                    and _text(getattr(requested, "role", None)) == "output"
                ):
                    rows.append(
                        RecapDeliverable(
                            obligation_id, status, _text(getattr(requested, "value", None))
                        )
                    )
    sequence = _text(getattr(getattr(pages[0], "head_frontier", None), "sequence", None))
    return replace(
        _replace_deliverables(facts, rows),
        deliverables_sequence=sequence,
        deliverables_partial=more_pages,
        deliverables_scope_unknown=scope_unknown,
    )


def _replace_deliverables(facts: RecapFacts, rows: Sequence[RecapDeliverable]) -> RecapFacts:
    return replace(
        facts,
        deliverables=tuple(rows[:_MAX_DELIVERABLES]),
        deliverables_total=len(rows),
    )


def compact_recap_text(facts: RecapFacts, *, pending_rows: int | None = None) -> str:
    """Render the recap, naming undelivered local observation rows when there are any."""

    return compose_compaction_recap(
        replace(facts, pending_observation_rows=pending_rows), limit=RECAP_LIMIT
    )


def pending_work_rows(
    store: object, workspace_commitment: str | None, codex_session_id: str
) -> int | None:
    """Count this session's undelivered local rows that would add ledger work, or ``None``.

    A local read of the durable outbox only; it never opens the service. ``None`` (the outbox was
    not readable) leaves the recap without a staleness note rather than claiming none.
    """

    if workspace_commitment is None:
        return None
    lister = getattr(store, "list_pending_outbox_rows", None)
    if not callable(lister):
        return None
    try:
        rows = cast(
            "Sequence[object]", lister(workspace_commitment, codex_session_id=codex_session_id)
        )
        return sum(
            1
            for row in rows
            if getattr(getattr(row, "envelope", None), "event_kind", None) not in _LIFECYCLE_KINDS
        )
    except Exception:
        return None
