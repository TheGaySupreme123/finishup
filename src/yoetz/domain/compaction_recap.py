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
from dataclasses import dataclass, replace
from typing import Final

from yoetz.domain.bounded_text import Part, ascii_safe, compose_parts, list_variants, quoted_path

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
    # The head frontier of the obligations read (its own, not the compact read's), whether more
    # pages exist than were read, and whether the view could not tell the current plan's
    # obligations from historical ones (then no deliverable is claimed).
    deliverables_sequence: str | None = None
    deliverables_partial: bool = False
    deliverables_scope_unknown: bool = False
    readiness_state: str | None = None
    agent_actionable: tuple[str, ...] = ()
    blocked_obligations: int | None = None
    # ADR-046: the receipt conclusion the compact status predicts for this frontier; ``None``
    # means this status did not report one (an earlier build, or an unreadable case).
    predicted_conclusion: str | None = None
    # Hook rows of this session still in the local outbox when the status was read: the ledger
    # facts above may lag them. ``None`` means the outbox was not read.
    pending_observation_rows: int | None = None


_TOKEN_UNSAFE: Final = re.compile(r"[^A-Za-z0-9._:/@+=-]")
_TOKEN_CHARS: Final = 128


def _tok(value: str | None) -> str:
    """An identifier, code or digest as one safe token: no whitespace, quote or control character.

    Every value the recap interpolates outside a quoted excerpt passes through here, so a field
    that carries anything but its documented shape cannot start a line of its own or forge a
    source label.
    """

    if value is None:
        return ""
    return _TOKEN_UNSAFE.sub("?", value)[:_TOKEN_CHARS]


def _clean_facts(facts: RecapFacts) -> RecapFacts:
    """Return ``facts`` with every identifier-like string reduced to a safe token."""

    return replace(
        facts,
        task_id=_tok(facts.task_id),
        session_id=_tok(facts.session_id),
        writer_id=_tok(facts.writer_id),
        head_sequence=_tok(facts.head_sequence),
        head_digest=_tok(facts.head_digest),
        plan_event_id=None if facts.plan_event_id is None else _tok(facts.plan_event_id),
        obligations=tuple(
            replace(item, obligation_id=_tok(item.obligation_id)) for item in facts.obligations
        ),
        findings=tuple(
            replace(item, finding_id=_tok(item.finding_id), kind=_tok(item.kind))
            for item in facts.findings
        ),
        check=None
        if facts.check is None
        else RecapCheck(
            _tok(facts.check.event_id),
            _tok(facts.check.frontier_sequence),
            _tok(facts.check.verdict),
        ),
        deliverables=None
        if facts.deliverables is None
        else tuple(
            replace(
                item,
                obligation_id=_tok(item.obligation_id),
                obligation_status=_tok(item.obligation_status),
            )
            for item in facts.deliverables
        ),
        deliverables_sequence=None
        if facts.deliverables_sequence is None
        else _tok(facts.deliverables_sequence),
        readiness_state=None if facts.readiness_state is None else _tok(facts.readiness_state),
        agent_actionable=tuple(_tok(token) for token in facts.agent_actionable),
        predicted_conclusion=None
        if facts.predicted_conclusion is None
        else _tok(facts.predicted_conclusion),
    )


def _flat_text(text: str) -> str:
    """User text as one ASCII line that cannot contain a double quote.

    Typographic quotes fold to ``"`` when text becomes ASCII, so the fold runs first and the quote
    replacement after it: no quote character, ASCII or not, can close the excerpt it sits in.
    """

    return _WHITESPACE.sub(" ", ascii_safe(text)).strip().replace('"', "'")


def _excerpt(text: str | None) -> str:
    if text is None:
        return "(text withheld by the disclosure policy)"
    flat = _flat_text(text)
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

    facts = _clean_facts(facts)
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
    # Sections the note names are left out of the composition, so the note is true by
    # construction. A fixed point on "what the composition dropped" is not guaranteed (the note
    # takes room, which can change what fits), so the set only grows: every pass either drops
    # nothing more, or adds at least one section, and the loop ends within len(sections) + 1.
    omitted: list[str] = []
    text = ""
    for _attempt in range(len(sections) + 1):
        included = [section for section in sections if section[0] not in omitted]
        note = f"Omitted for space, ask status: {', '.join(omitted)}." if omitted else ""
        parts = [Part((header,), required=True), Part((ids,), required=True)]
        parts.append(Part((frontier,), required=True))
        parts.extend(
            Part(variants, required=required, priority=priority)
            for _name, priority, required, variants in included
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
            included[index - first_section][0]
            for index in composition.dropped
            if first_section <= index < first_section + len(included)
        ]
        if not dropped:
            break
        omitted = [name for name in names if name in omitted or name in dropped]
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
    predicted = (
        ""
        if facts.predicted_conclusion is None
        else f"; receipt would read {facts.predicted_conclusion}"
    )
    return list_variants(
        f"readiness: {facts.readiness_state}{predicted}; agent-actionable: ",
        list(facts.agent_actionable) or ["none"],
        suffix=source,
        more="; +{n} more",
    )


def _obligation_variants(facts: RecapFacts, compact: str) -> tuple[str, ...]:
    total = facts.open_obligations_total
    items = facts.obligations
    if not items:
        # No preview rows: a zero count says none, a positive count (rows the status did not
        # preview, for example withheld ones) is still stated, and an unreported one is silent.
        if total == 0:
            return (f"open obligations: none {compact}.",)
        if total:
            return (f"open obligations: {total} open (ask status for ids) {compact}.",)
        return ()
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
    blocking = (
        ""
        if facts.receipt_blocking_findings is None
        else f"; {facts.receipt_blocking_findings} to do"
    )
    if not items:
        # Unanswered findings the compact preview does not list (withheld or past its bound) are
        # still counted; an unreported count stays silent, a zero count says none.
        if total == 0:
            return (f"findings awaiting your response: none {compact}.",)
        if total:
            return (
                f"findings awaiting your response: {total}{blocking} "
                f"(ask status for ids) {compact}.",
            )
        return ()
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
    # The obligations view is its own read, at its own head frontier; label it with that one.
    own = facts.deliverables_sequence or sequence
    source = f"[source status obligations @{own}]"
    items = facts.deliverables
    if items is None:
        return (
            "declared deliverables: unavailable, the obligations view was not read "
            f"[source status compact @{sequence}].",
        )
    if facts.deliverables_scope_unknown:
        return (
            "declared deliverables: unavailable, the obligations view did not say which "
            f"obligations belong to the current plan {source}.",
        )
    partial = (
        "; the obligations view has more pages than were read, ask status obligations"
        if facts.deliverables_partial
        else ""
    )
    if not items:
        if facts.deliverables_partial:
            return (
                f"declared deliverables: none in the obligations read so far{partial} {source}.",
            )
        return (f"declared deliverables: none declared {source}.",)
    total = facts.deliverables_total if facts.deliverables_total is not None else len(items)
    rendered = [
        f"{_quoted_path(item.value)} ({item.obligation_id} {item.obligation_status})"
        for item in items
    ]
    shown_more = max(0, total - len(items))
    unshown = f"; +{shown_more} more (ask status)" if shown_more else ""
    head = f"declared deliverables ({'at least ' if facts.deliverables_partial else ''}{total}): "
    variants = [
        v.replace(f" {source}.", f"{unshown}{partial} {source}.", 1) if unshown or partial else v
        for v in list_variants(
            head, rendered, joiner="; ", more="; +{n} more (ask status)", suffix=f" {source}."
        )
    ]
    variants.append(f"declared deliverables: {total} (ask status obligations){partial} {source}.")
    return tuple(dict.fromkeys(variants))


def _quoted_path(value: str | None) -> str:
    """A requested path as one quoted single-line excerpt; a path is user text, not a token."""

    return quoted_path(value)
