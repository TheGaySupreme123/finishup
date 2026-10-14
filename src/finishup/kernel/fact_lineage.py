"""Where a derived fact came from (ADR-045, tb4n3 RC-5).

Owner rule: "if we add facts or info it has lineage and where from". A task fact is a closed code,
and a code alone cannot say why it fired. A ``FactLineage`` is the small typed record that does:
the rule that produced the fact, the obligation item it is about, the check (event id and subject
frontier) that observed the current state, the prior state it was compared with ("15975 bytes at
frontier 312"), the proof that made the comparison valid, and the ledger events it rests on.

Everything here is a closed token, a count or an id. No path, command text or prose is stored or
rendered: a path is only ever a keyed commitment (``DeliverableState.path_key``), and the item an
agent must look at is named by obligation id and item index, which ``status view=obligations``
resolves. ``lineage_text`` is the one renderer every surface (status, check result, Stop-gate
text, receipt) uses, so the answer is the same everywhere.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, cast

from finishup.domain.values import EventId, ObligationId, event_id, obligation_id

__all__ = [
    "FACT_LINEAGE_BASES",
    "FACT_LINEAGE_PROOFS",
    "FACT_LINEAGE_RULES",
    "FACT_LINEAGE_STATES",
    "MAX_FACT_LINEAGE_ITEMS",
    "MAX_LINEAGE_SOURCES",
    "RULE_COMMAND_MATCH",
    "RULE_COMMAND_UNMATCHED",
    "RULE_DELIVERABLE_PATH_HISTORY",
    "RULE_DELIVERABLE_READ",
    "RULE_EDIT_AFTER_RUN",
    "FactLineage",
    "lineage_from_wire",
    "lineage_text",
    "lineage_texts",
    "lineage_to_wire",
]

# Closed rule names. A rule is versioned by its name: a changed meaning gets a new name.
RULE_DELIVERABLE_PATH_HISTORY: Final = "deliverable_path_history"
RULE_DELIVERABLE_READ: Final = "deliverable_read"
RULE_COMMAND_MATCH: Final = "planned_command_match"
RULE_COMMAND_UNMATCHED: Final = "planned_command_unmatched"
RULE_EDIT_AFTER_RUN: Final = "edit_after_verification_run"
FACT_LINEAGE_RULES: Final = (
    RULE_DELIVERABLE_PATH_HISTORY,
    RULE_DELIVERABLE_READ,
    RULE_COMMAND_MATCH,
    RULE_COMMAND_UNMATCHED,
    RULE_EDIT_AFTER_RUN,
)
# What the rule concluded about the subject.
FACT_LINEAGE_STATES: Final = (
    "emptied",
    "truncated",
    "removed",
    "accepted",
    "unreviewable",
    "matched_exact",
    "matched_normalized",
    "matched_prefix",
    "matched_flags",
    "matched_agent_link",
    "unmatched",
    "failed",
    "stale",
    "edited_after",
)
# How the comparison was made valid (earlier content known, or which run established the match).
FACT_LINEAGE_PROOFS: Final = ("task_base", "earlier_check", "observed_run")
FACT_LINEAGE_BASES: Final = ("delivered", "verified", "present")
MAX_LINEAGE_SOURCES: Final = 8
MAX_FACT_LINEAGE_ITEMS: Final = 64
_MAX_COUNT: Final = 9_007_199_254_740_991


@dataclass(frozen=True, slots=True)
class FactLineage:
    """The provenance of one derived fact. Frozen, closed, bounded, ASCII-renderable."""

    code: str
    rule: str
    state: str
    obligation_id: ObligationId | None = None
    item_index: int | None = None
    check_event_id: EventId | None = None
    frontier: int | None = None
    prior_event_id: EventId | None = None
    prior_frontier: int | None = None
    prior_size_bytes: int | None = None
    prior_lines: int | None = None
    now_size_bytes: int | None = None
    now_lines: int | None = None
    proof: str | None = None
    basis: str | None = None
    source_event_ids: tuple[EventId, ...] = ()
    accepted_by: EventId | None = None

    def __post_init__(self) -> None:
        if type(self.code) is not str or not self.code or len(self.code) > 128:
            raise ValueError("fact_lineage_invalid")
        if self.rule not in FACT_LINEAGE_RULES or self.state not in FACT_LINEAGE_STATES:
            raise ValueError("fact_lineage_invalid")
        if self.proof is not None and self.proof not in FACT_LINEAGE_PROOFS:
            raise ValueError("fact_lineage_invalid")
        if self.basis is not None and self.basis not in FACT_LINEAGE_BASES:
            raise ValueError("fact_lineage_invalid")
        if self.obligation_id is not None:
            object.__setattr__(self, "obligation_id", obligation_id(self.obligation_id))
        if self.item_index is not None and (
            self.obligation_id is None
            or type(self.item_index) is not int
            or not 0 <= self.item_index <= 63
        ):
            raise ValueError("fact_lineage_invalid")
        for name in ("check_event_id", "prior_event_id", "accepted_by"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, event_id(value))
        for name in (
            "frontier",
            "prior_frontier",
            "prior_size_bytes",
            "prior_lines",
            "now_size_bytes",
            "now_lines",
        ):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or not 0 <= value <= _MAX_COUNT):
                raise ValueError("fact_lineage_invalid")
        sources = tuple(event_id(item) for item in self.source_event_ids)
        if len(sources) > MAX_LINEAGE_SOURCES or sources != tuple(
            sorted(set(sources), key=str.encode)
        ):
            raise ValueError("fact_lineage_invalid")
        object.__setattr__(self, "source_event_ids", sources)

    @property
    def sort_key(self) -> tuple[bytes, bytes, int, bytes]:
        return (
            self.code.encode(),
            b"" if self.obligation_id is None else str(self.obligation_id).encode(),
            -1 if self.item_index is None else self.item_index,
            self.rule.encode(),
        )


def _plural(count: int, singular: str) -> str:
    return f"{count} {singular}" if count == 1 else f"{count} {singular}s"


def _size(bytes_: int | None, lines: int | None) -> str:
    parts: list[str] = []
    if bytes_ is not None:
        parts.append(_plural(bytes_, "byte"))
    if lines is not None:
        parts.append(_plural(lines, "line"))
    return " / ".join(parts) if parts else "an unread size"


def _subject(item: FactLineage) -> str:
    if item.obligation_id is None:
        return "the task"
    suffix = "" if item.item_index is None else f" requested item {item.item_index}"
    return f"{item.obligation_id}{suffix}"


def lineage_text(item: FactLineage) -> str:
    """One plain ASCII sentence saying why the fact fired. The same text on every surface."""

    if type(item) is not FactLineage:
        raise TypeError("fact_lineage_invalid")
    # The observing check is named by its subject frontier: the check result is that check and
    # does not know its own event id, so the sentence leaves the id to the structured record and
    # reads the same on every surface.
    where = "" if item.frontier is None else f" at frontier {item.frontier}"
    if item.rule == RULE_DELIVERABLE_PATH_HISTORY:
        prior = ""
        if item.prior_frontier is not None or item.prior_size_bytes is not None:
            prior_where = (
                "" if item.prior_frontier is None else f" at frontier {item.prior_frontier}"
            )
            prior_check = "" if item.prior_event_id is None else f", check {item.prior_event_id}"
            prior = (
                f"; it held {_size(item.prior_size_bytes, item.prior_lines)}{prior_where}"
                f"{prior_check}"
            )
        elif item.proof == "task_base":
            prior = "; it held content at the task base"
        verb = {
            "emptied": "now holds",
            "truncated": "now holds",
            "removed": "is now absent",
            "accepted": "now holds",
        }.get(item.state, "now holds")
        reading = (
            "" if item.state == "removed" else f" {_size(item.now_size_bytes, item.now_lines)}"
        )
        basis = {
            "delivered": "an obligation declaring this path was resolved or claimed",
            "verified": "a verification run passed while it had content",
            "present": "it had content",
        }.get(item.basis or "", "")
        basis_text = f" Counted as a delivery because {basis}." if basis else ""
        accepted = (
            f" Accepted by decision {item.accepted_by}: the path is named in a finishup-assumption."
            if item.accepted_by is not None
            else ""
        )
        return (
            f"Why: the declared output of {_subject(item)} {verb}{reading}{where}"
            f"{prior}.{basis_text}{accepted} Rule {item.rule}."
        )
    if item.rule == RULE_COMMAND_MATCH and item.state in {"failed", "stale"}:
        events = ", ".join(str(ref) for ref in item.source_event_ids)
        refs = f" Events: {events}." if events else ""
        if item.state == "failed":
            happened = "the observed run of the planned command"
            happened += f" of {_subject(item)} failed{where}."
        else:
            # ``frontier`` is the last run of the planned command, ``prior_frontier`` the edit.
            after = (
                ""
                if item.prior_frontier is None
                else f"; an observed edit followed at frontier {item.prior_frontier}"
            )
            happened = f"the planned command of {_subject(item)} was last run{where}{after}."
        return f"Why: {happened}{refs} Rule {item.rule}."
    if item.rule == RULE_COMMAND_MATCH:
        by = {
            "matched_exact": "an exact match",
            "matched_normalized": "a match after dropping wrappers (timeout, env, nice)",
            "matched_prefix": "a match on the command's leading arguments only",
            "matched_flags": "a match on its program and flags only",
            "matched_agent_link": "a link you published between the run and the command",
        }.get(item.state, "a match")
        sources = ", ".join(str(ref) for ref in item.source_event_ids)
        ran = f" Observed run(s): {sources}." if sources else ""
        disclosed = (
            " It counts as run but is disclosed, not clean verification."
            if item.state in {"matched_prefix", "matched_flags", "matched_agent_link"}
            else ""
        )
        return (
            f"Why: the planned command of {_subject(item)} was matched by {by}.{ran}{disclosed}"
            f" Rule {item.rule}."
        )
    if item.rule == RULE_COMMAND_UNMATCHED:
        return (
            f"Why: no observed run matched the planned command of {_subject(item)}"
            f"{where}. Rule {item.rule}."
        )
    if item.rule == RULE_EDIT_AFTER_RUN:
        sources = ", ".join(str(ref) for ref in item.source_event_ids)
        refs = f" Events: {sources}." if sources else ""
        ran = (
            ""
            if item.prior_frontier is None
            else f", the last verification run being at frontier {item.prior_frontier}"
        )
        return (
            f"Why: an observed edit{where} followed the last verification run{ran}.{refs}"
            f" Rule {item.rule}."
        )
    return f"Why: {item.code} ({item.state}) about {_subject(item)}{where}. Rule {item.rule}."


_WIRE_COUNTS: Final = (
    "frontier",
    "prior_frontier",
    "prior_size_bytes",
    "prior_lines",
    "now_size_bytes",
    "now_lines",
)
_WIRE_IDS: Final = ("obligation_id", "check_event_id", "prior_event_id", "accepted_by")
_WIRE_TOKENS: Final = ("proof", "basis")


def lineage_to_wire(item: FactLineage) -> dict[str, str | list[str]]:
    """The wire object of one lineage (``FactLineageModel``): counts as canonical decimal strings.

    Absent optionals are omitted, never null, like every optional wire field.
    """

    wire: dict[str, str | list[str]] = {"code": item.code, "rule": item.rule, "state": item.state}
    for name in _WIRE_IDS + _WIRE_TOKENS:
        value = getattr(item, name)
        if value is not None:
            wire[name] = str(value)
    for name in _WIRE_COUNTS:
        value = getattr(item, name)
        if value is not None:
            wire[name] = str(value)
    if item.item_index is not None:
        wire["item_index"] = str(item.item_index)
    if item.source_event_ids:
        wire["source_event_ids"] = [str(ref) for ref in item.source_event_ids]
    return wire


def lineage_from_wire(value: object) -> FactLineage:
    """A ``FactLineage`` from its wire object or a ``FactLineageModel`` (attributes), or raise."""

    def get(name: str) -> object:
        if isinstance(value, Mapping):
            return cast(Mapping[str, object], value).get(name)
        return getattr(value, name, None)

    def count(name: str) -> int | None:
        raw = get(name)
        if raw is None:
            return None
        if type(raw) is int:
            return raw
        if type(raw) is str and raw.isascii() and raw.isdecimal():
            return int(raw)
        raise ValueError("fact_lineage_invalid")

    def text(name: str) -> str | None:
        raw = get(name)
        if raw is None:
            return None
        if type(raw) is not str:
            raise ValueError("fact_lineage_invalid")
        return raw

    code, rule, state = text("code"), text("rule"), text("state")
    if code is None or rule is None or state is None:
        raise ValueError("fact_lineage_invalid")
    sources = get("source_event_ids") or ()
    if not isinstance(sources, (tuple, list)):
        raise ValueError("fact_lineage_invalid")
    obligation = text("obligation_id")
    check = text("check_event_id")
    prior = text("prior_event_id")
    accepted = text("accepted_by")
    return FactLineage(
        code=code,
        rule=rule,
        state=state,
        obligation_id=None if obligation is None else obligation_id(obligation),
        item_index=count("item_index"),
        check_event_id=None if check is None else event_id(check),
        frontier=count("frontier"),
        prior_event_id=None if prior is None else event_id(prior),
        prior_frontier=count("prior_frontier"),
        prior_size_bytes=count("prior_size_bytes"),
        prior_lines=count("prior_lines"),
        now_size_bytes=count("now_size_bytes"),
        now_lines=count("now_lines"),
        proof=text("proof"),
        basis=text("basis"),
        source_event_ids=tuple(
            event_id(ref) for ref in cast(Sequence[object], sources) if type(ref) is str
        ),
        accepted_by=None if accepted is None else event_id(accepted),
    )


def lineage_texts(items: Iterable[FactLineage], code: str | None = None) -> tuple[str, ...]:
    """Sentences for *items* (optionally one fact code), in stable order, duplicates dropped."""

    selected = sorted(
        (item for item in items if code is None or item.code == code), key=lambda i: i.sort_key
    )
    return tuple(dict.fromkeys(lineage_text(item) for item in selected))
