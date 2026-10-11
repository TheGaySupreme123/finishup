"""The post-compaction recap: what Yoetz knows, re-stated for an agent that lost its context.

ADR-044 (issue #1027, tb4n3 N3-7 owner decision). After a host compacts its context the agent
resumes with a summary of its own work and no memory of the Yoetz state it held. The compaction
start (Codex ``SessionStart`` source ``compact``, Claude Code the same) already tells it to use its
held ids for ``status``; the recap hands it the receipt-style facts up front so it resumes with what
Yoetz knows instead of having to rediscover it.

This module is pure. It composes text from plain values the hook adapter read off one compact
``status`` result (and, when time allows, one ``obligations`` view) of the mapped session. It
opens no connection, reads no ledger, and invents no classification: readiness ``state`` and
``agent_actionable`` are the ones ``status`` returned, and the next action is a plain-words
rendering of that state.

Every line ends with ``[source ...]`` naming where the fact came from (the status view and the
frontier it was read at, the recorded check event, or the hook mapping). A fact the status did not
carry is said to be unavailable, never filled in. The recap is bounded: required lines are always
present; optional lines yield to the budget in priority order and the text names what was omitted.
It records nothing, claims nothing, and is not evidence; ``status`` is the live read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from yoetz.domain.bounded_text import Part, compose_parts, list_variants

__all__ = [
    "RECAP_CONTEXT_LIMIT",
    "RECAP_LIMIT",
    "RecapCheck",
    "RecapDeliverable",
    "RecapFacts",
    "RecapFinding",
    "RecapObligation",
    "compose_compaction_recap",
]

# The recap's own budget, in characters (== bytes: the text is ASCII). The whole SessionStart
# context (the held-ids cue, the admission notice, this recap) stays under RECAP_CONTEXT_LIMIT.
RECAP_LIMIT: Final = 2_400
RECAP_CONTEXT_LIMIT: Final = 4_000

_EXCERPT_CHARS: Final = 80
_WHITESPACE: Final = re.compile(r"\s+")
_NEXT_ACTION: Final = {
    "action_required": (
        "next: resolve the agent-actionable items above; status (held ids) lists each with "
        "its detail."
    ),
    "ready_with_limitations": (
        "next: nothing blocks completion; disclose the standing limitations in the receipt "
        "when the work is done."
    ),
    "ready": "next: when the work is complete, request the receipt.",
    "unknown": "next: call status with the held ids; readiness is unknown at this frontier.",
}
_NEXT_UNREPORTED: Final = (
    "next: call status with the held ids; this status did not report readiness."
)


@dataclass(frozen=True, slots=True)
class RecapObligation:
    """One open obligation. ``description`` is ``None`` when the status withheld its text."""

    obligation_id: str
    description: str | None


@dataclass(frozen=True, slots=True)
class RecapFinding:
    """One finding awaiting the agent's response. ``summary`` is ``None`` when withheld."""

    finding_id: str
    kind: str
    priority: int
    summary: str | None


@dataclass(frozen=True, slots=True)
class RecapCheck:
    """The latest recorded check: its event id, the frontier it examined and its verdict."""

    event_id: str
    frontier_sequence: str
    verdict: str


@dataclass(frozen=True, slots=True)
class RecapDeliverable:
    """One declared output (a requested file or directory with role ``output``)."""

    obligation_id: str
    obligation_status: str
    value: str | None


@dataclass(frozen=True, slots=True)
class RecapFacts:
    """Everything the recap states, as read off the status results; ``None`` means not reported."""

    task_id: str
    session_id: str
    writer_id: str
    head_sequence: str
    head_digest: str
    plan_event_id: str | None = None
    declared_obligations: int | None = None
    open_obligations_total: int | None = None
    acknowledged_not_done: int | None = None
    task_title: str | None = None
    obligations: tuple[RecapObligation, ...] = ()
    unanswered_findings_total: int | None = None
    receipt_blocking_findings: int | None = None
    findings: tuple[RecapFinding, ...] = ()
    check: RecapCheck | None = None
    # ``True`` when the compact status itself reports that no check was ever recorded.
    no_check_recorded: bool = False
    # ``None`` means the obligations view was not read (so deliverables are unavailable).
    deliverables: tuple[RecapDeliverable, ...] | None = None
    deliverables_total: int | None = None
    readiness_state: str | None = None
    agent_actionable: tuple[str, ...] = ()
    blocked_obligations: int | None = None
    # Hook rows of this session still in the local outbox when the status was read: the ledger
    # facts above may lag them. ``None`` means the outbox was not read.
    pending_observation_rows: int | None = None


def _excerpt(text: str | None) -> str:
    if text is None:
        return "(text withheld by the disclosure policy)"
    flat = _WHITESPACE.sub(" ", text).strip().replace('"', "'")
    if len(flat) > _EXCERPT_CHARS:
        flat = flat[: _EXCERPT_CHARS - 3].rstrip() + "..."
    return f'"{flat}"' if flat else "(no text)"


def _count(value: int | None) -> str:
    return "unreported" if value is None else str(value)


def _source(view: str, sequence: str) -> str:
    return f"[source status {view} @{sequence}]"


def _short_digest(digest: str) -> str:
    return digest if len(digest) <= 22 else digest[:22]


def compose_compaction_recap(facts: RecapFacts, *, limit: int = RECAP_LIMIT) -> str:
    """Compose the bounded, ASCII, source-labelled recap for one resumed session. Never raises."""

    seq = facts.head_sequence
    compact = _source("compact", seq)
    header = (
        "Yoetz recap after context compaction. Each line below was read from the task ledger "
        "through status just now and names its source."
    )
    ids = (
        f"ids: task {facts.task_id}, session {facts.session_id}, writer {facts.writer_id} "
        "[source hook mapping]; use these held ids for status and do not start a sibling task."
    )
    frontier = (
        f"frontier: {seq} ({_short_digest(facts.head_digest)}) "
        "[source status compact head frontier]."
    )
    state = facts.readiness_state
    next_text = _NEXT_ACTION[state] if state in _NEXT_ACTION else _NEXT_UNREPORTED
    next_line = f"{next_text} [source status compact closure_readiness @{seq}]"
    tail = (
        "This recap is a read of status, not a new claim or evidence; call status for the "
        "live state before relying on a line."
    )
    # Optional sections in the order they are read, each with the priority that decides who is
    # granted room first (lower first): what the agent must answer, then what it must finish.
    # What the agent must answer or finish (findings, open obligations) is required in its
    # shortest form (a count with a pointer to ask status) and upgraded first; the rest is
    # optional and named in the omission note when the budget cannot hold it.
    sections: tuple[tuple[str, int, bool, tuple[str, ...]], ...] = (
        ("plan", 4, False, _plan_variants(facts, compact)),
        ("readiness", 6, False, _readiness_variants(facts, seq)),
        ("open obligations", 2, True, _obligation_variants(facts, compact)),
        ("findings", 1, True, _finding_variants(facts, compact)),
        ("last check", 3, False, (_check_line(facts, seq),)),
        ("declared deliverables", 5, False, _deliverable_variants(facts, seq)),
    )
    names = [name for name, _priority, _required, _variants in sections]
    omitted: list[str] = []
    text = ""
    for _attempt in range(3):
        note = f"Omitted for space, ask status: {', '.join(omitted)}." if omitted else ""
        parts = [Part((header,), required=True), Part((ids,), required=True)]
        parts.append(Part((frontier,), required=True))
        parts.extend(
            Part(variants, required=required, priority=priority)
            for _name, priority, required, variants in sections
        )
        parts.append(Part((next_line,), required=True))
        if facts.pending_observation_rows:
            parts.append(
                Part(
                    (
                        f"Note: {facts.pending_observation_rows} local observation row(s) were "
                        "not yet in the ledger when this was read [source local outbox]; the "
                        "facts above may lag the latest work.",
                    ),
                    required=True,
                )
            )
        if note:
            parts.append(Part((note,), required=True))
        parts.append(Part((tail,), required=True))
        composition = compose_parts(parts, limit, sep="\n")
        text = composition.text
        first_section = 3
        dropped = [
            names[index - first_section]
            for index in composition.dropped
            if first_section <= index < first_section + len(sections)
        ]
        if not dropped or sorted(dropped) == sorted(omitted):
            break
        omitted = [name for name in names if name in dropped]
    return text


def _plan_variants(facts: RecapFacts, compact: str) -> tuple[str, ...]:
    if (
        facts.declared_obligations is None
        and facts.open_obligations_total is None
        and facts.plan_event_id is None
    ):
        return (f"plan: not reported by this status. {compact}",)
    bits = [
        f"{_count(facts.declared_obligations)} declared",
        f"{_count(facts.open_obligations_total)} open",
    ]
    if facts.acknowledged_not_done:
        bits.append(f"{facts.acknowledged_not_done} acknowledged not done")
    plan_event = f"plan event {facts.plan_event_id}" if facts.plan_event_id else "no plan published"
    short = f"plan: {', '.join(bits)} obligations ({plan_event}). {compact}"
    if not facts.task_title:
        return (short,)
    return (
        f"plan: {', '.join(bits)} obligations ({plan_event}). "
        f"Task text: {_excerpt(facts.task_title)}. {compact}",
        short,
    )


def _readiness_variants(facts: RecapFacts, sequence: str) -> tuple[str, ...]:
    if facts.readiness_state is None:
        return (f"readiness: not reported by this status [source status compact @{sequence}].",)
    blocked = (
        f"; blocked obligations {facts.blocked_obligations}" if facts.blocked_obligations else ""
    )
    source = f"{blocked} [source status compact closure_readiness @{sequence}]."
    return list_variants(
        f"readiness: {facts.readiness_state}; agent-actionable: ",
        list(facts.agent_actionable) or ["none"],
        suffix=source,
        more="; +{n} more",
    )


def _obligation_variants(facts: RecapFacts, compact: str) -> tuple[str, ...]:
    total = facts.open_obligations_total
    items = facts.obligations
    if not items and not total:
        return (f"open obligations: none {compact}.",) if total == 0 else ()
    head = f"open obligations ({_count(total if total is not None else len(items))}): "
    rendered = [f"{item.obligation_id} {_excerpt(item.description)}" for item in items]
    ids_only = [item.obligation_id for item in items]
    more_total = (total or len(items)) - len(items)
    unshown = f"; +{more_total} more (ask status)" if more_total > 0 else ""
    variants = list(
        list_variants(
            head,
            rendered,
            joiner="; ",
            more="; +{n} more (ask status)",
            suffix=f" {compact}.",
        )
    )
    if more_total > 0:
        variants = [v.replace(f" {compact}.", f"{unshown} {compact}.", 1) for v in variants]
    variants.append(f"{head}{', '.join(ids_only)}{unshown} {compact}.")
    variants.append(f"open obligations: {_count(total)} open (ask status for ids) {compact}.")
    return tuple(dict.fromkeys(variants))


def _finding_variants(facts: RecapFacts, compact: str) -> tuple[str, ...]:
    total = facts.unanswered_findings_total
    items = facts.findings
    if not items:
        if total == 0:
            return (f"findings awaiting your response: none {compact}.",)
        return ()
    blocking = (
        ""
        if facts.receipt_blocking_findings is None
        else f"; {facts.receipt_blocking_findings} receipt-blocking"
    )
    head = f"findings awaiting your response ({_count(total)}{blocking}; reviewer text, advisory): "
    rendered = [
        f"{item.finding_id} p{item.priority} {item.kind} {_excerpt(item.summary)}" for item in items
    ]
    shown_more = max(0, (total or len(items)) - len(items))
    unshown = f"; +{shown_more} more (ask status)" if shown_more else ""
    variants = [
        v.replace(f" {compact}.", f"{unshown} {compact}.", 1) if unshown else v
        for v in list_variants(
            head, rendered, joiner="; ", more="; +{n} more (ask status)", suffix=f" {compact}."
        )
    ]
    ids_only = ", ".join(f"{item.finding_id} p{item.priority} {item.kind}" for item in items)
    variants.append(f"{head}{ids_only}{unshown} {compact}.")
    variants.append(
        f"findings awaiting your response: {_count(total)}{blocking} (ask status for ids) {compact}."
    )
    return tuple(dict.fromkeys(variants))


def _check_line(facts: RecapFacts, sequence: str) -> str:
    check = facts.check
    if check is not None:
        return (
            f"last check: {check.verdict} on frontier {check.frontier_sequence} "
            f"(check event {check.event_id}) [source status compact latest_check @{sequence}]."
        )
    if facts.no_check_recorded:
        return (
            "last check: none recorded [source status compact closure_readiness "
            f"check_not_recorded @{sequence}]."
        )
    return f"last check: not reported by this status [source status compact @{sequence}]."


def _deliverable_variants(facts: RecapFacts, sequence: str) -> tuple[str, ...]:
    source = f"[source status obligations @{sequence}]"
    items = facts.deliverables
    if items is None:
        return (
            "declared deliverables: unavailable, the obligations view was not read "
            f"[source status compact @{sequence}].",
        )
    if not items:
        return (f"declared deliverables: none declared {source}.",)
    total = facts.deliverables_total if facts.deliverables_total is not None else len(items)
    rendered = [
        f"{item.value if item.value is not None else '(path withheld)'} "
        f"({item.obligation_id} {item.obligation_status})"
        for item in items
    ]
    shown_more = max(0, total - len(items))
    unshown = f"; +{shown_more} more (ask status)" if shown_more else ""
    head = f"declared deliverables ({total}): "
    variants = [
        v.replace(f" {source}.", f"{unshown} {source}.", 1) if unshown else v
        for v in list_variants(
            head, rendered, joiner="; ", more="; +{n} more (ask status)", suffix=f" {source}."
        )
    ]
    variants.append(f"declared deliverables: {total} (ask status obligations) {source}.")
    return tuple(dict.fromkeys(variants))
