"""The declared delivered set and the fact that a declared deliverable was removed (ADR-035).

TB4 run tb4n1 (#983, #1005) showed agents reshaping their deliverables to fit an AI-powered review:
one moved a statistics table out of the delivered ``cracker.py`` into an undelivered file, another
moved the delivered ``harmony.musicxml`` out of the workspace. Review limits never justify that.

The **declared delivered set** is every effective obligation's ``requested_items`` entry whose item
kind is ``file`` or ``directory`` and whose role is ``output``. On ``obligation_published`` 1.0.0
an item carries no role and a ``file`` item may be an input or an output, so a role-less item is
never declared (a task that asks for a deletion or rename must not be told to restore it); the
``role`` and ``directory`` exist only from 1.1.0 (PL6-1/PL6-2). Both are read by their wire
value so this module works on either version. Obligations a blocker decision names are skipped,
as for every requested-output fact.

``declared_output_removed`` is raised when the check-time, metadata-only workspace read
(``application.check_change.requested_output_states``) shows a declared item inside the checked
repository that no longer exists because the check-time change deletes it or renames it away
(``D``, or ``R`` with the declared path as the original), or that no longer exists after an edit
action of the session named it (a new deliverable written, then moved away: music-harmony). It is
agent-actionable: restore the delivered file, or correct the requested item when the task really
asked for the deletion.

``declared_output_emptied`` (tb4n2 R2, ADR-035 amendment; tb4n3 RC-5, ADR-045) is a *change*
fact, so it is computed from history and keyed on the **path**, never on the obligation. Each check
records, per declared output file, its size and line count (``DeliverableState`` on
``check_recorded``). ``deliverable_state_change`` compares the file as the check reads it now with
those earlier readings and the task base, and answers ``emptied``, ``truncated``, ``removed``,
``unchanged`` or ``None`` (unknown). A file is only "emptied" or "truncated" with **proof of earlier
content**: a tracked file with lines at the task base, or an earlier check that read it with
content. A file created empty (``apt-packages.txt`` for a task that needs no packages), a file only
ever seen empty and a truncated capture prove nothing and never fire. Because the history is the
path's, republishing the obligation ``acknowledged_not_done``, or declaring a new "deliver an empty
file" obligation on the same path, cannot clear it (formal-crypto S emptied a working solver and
cleared the old rule that way). It fires when the path is delivered now (an obligation declaring it
is resolved or claimed complete) or was delivered earlier (an earlier check recorded it with
content while delivered, or while a passing verification run was observed). The one exit is a
``finishup-assumption:<obligation id>`` decision of an obligation declaring the path whose statement
or rationale names that exact path: the task asked for this file to be empty. A disclosure line
that does not name the path never hides it. While the fact stands the obligation is not counted as
delivered; it is agent-actionable and a Stop-gate token, and it carries a ``FactLineage``.

``declared_output_content_moved`` is the non-blocking disclosure for content moved out of a
declared file that still exists (interleaved-vigenere). A bounded line-count read of the
check-time change sets ``base_lines``, ``lines_lost`` and ``undeclared_lines_added`` on the
state of a declared file the change modified; ``content_moved_declared_items`` applies the
deterministic rule below. It is a standing disclosure: it never fires the Stop gate.

The module reads and returns closed values only: ``DeliverableState`` records hold sizes, counts,
ids and a keyed path commitment, never a path.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from finishup.domain.events import (
    AcceptedEvent,
    ActionKind,
    CheckRecordedPayload,
    ClaimKind,
    DecisionRecordedPayload,
    DeliverableState,
    LedgerRecord,
    ObligationStatus,
)
from finishup.domain.values import EventId, ObligationId
from finishup.kernel.claims import effective_claim_items
from finishup.kernel.command_attempts import attempted_items_for_obligation
from finishup.kernel.fact_lineage import (
    RULE_DELIVERABLE_PATH_HISTORY,
    RULE_DELIVERABLE_READ,
    FactLineage,
)
from finishup.kernel.projections import ProjectionState
from finishup.kernel.task_facts import (
    DECLARED_OUTPUT_CONTENT_MOVED_GAP,
    DECLARED_OUTPUT_EMPTIED_GAP,
    DECLARED_OUTPUT_NOT_REVIEWABLE_GAP,
    DECLARED_OUTPUT_REMOVED_GAP,
    RequestedOutputState,
    blocked_obligations,
    deliverable_path_identity,
    disclosure_line_obligations,
    effective_obligations,
)

__all__ = [
    "CONTENT_MOVED_MIN_LINES",
    "DECLARED_OUTPUT_CONTENT_MOVED_GAP",
    "DECLARED_OUTPUT_EMPTIED_GAP",
    "DECLARED_OUTPUT_REMOVED_GAP",
    "DeliverableAssessment",
    "DeliverableChange",
    "DeliverableSnapshot",
    "assess_deliverables",
    "content_moved_declared_items",
    "declared_delivered_items",
    "deliverable_history",
    "deliverable_lineage",
    "deliverable_state_change",
    "emptied_declared_items",
    "declared_output_removed",
    "removed_declared_items",
    "UndeclaredReferenceRow",
    "ambiguous_reference_count",
    "undeclared_reference_inputs",
    "undeclared_reference_rows",
]

_DECLARED_KINDS: Final = frozenset({"file", "directory"})
_NO_BATCHES: Final[Mapping[EventId, str]] = MappingProxyType({})

# The content-moved rule (ADR-035), deliberately conservative: a declared file lost at least this
# many lines and at least half of its task-base lines, and the same change added at least half as
# many lines to files outside the declared delivered set.
CONTENT_MOVED_MIN_LINES: Final = 20
# The truncation rule of ``declared_output_emptied``: a tracked declared file that kept fewer than
# one line in this many of its task-base lines.
EMPTIED_KEPT_FRACTION: Final = 10
# Files that are conventionally empty; a 0-byte one is never "emptied".
_CONVENTIONALLY_EMPTY: Final = frozenset(
    {"__init__.py", "py.typed", ".gitkeep", ".keep", ".nojekyll"}
)


def _wire(value: object) -> object:
    return getattr(value, "value", value)


def item_role(item: object) -> object:
    """A requested item's role by wire value; ``None`` before ``obligation_published`` 1.1.0."""

    return _wire(getattr(item, "role", None))


def declared_delivered_items(
    projection: ProjectionState,
    *,
    blocked: Iterable[ObligationId] | None = None,
) -> tuple[tuple[ObligationId, int, str, str], ...]:
    """``(obligation, item index, item kind, value)`` for the declared delivered set.

    Obligations a *confirmed* blocker names are excluded (#985). ``blocked`` is that set when
    the caller has it (a check passes the case's confirmed markers); without it, confirmation is
    read with no publish-batch boundaries. Order follows the effective obligations and items.
    """

    excluded = frozenset(
        blocked_obligations(projection, _NO_BATCHES) if blocked is None else blocked
    )
    rows: list[tuple[ObligationId, int, str, str]] = []
    for obligation in effective_obligations(projection):
        if obligation in excluded:
            continue
        payload = projection.obligations[obligation].payload
        if payload is None:
            continue
        for index, item in enumerate(payload.requested_items):
            kind = _wire(item.item_kind)
            if kind not in _DECLARED_KINDS or item_role(item) != "output":
                continue
            rows.append((obligation, index, str(kind), item.value))
    return tuple(rows)


def declared_output_removed(
    projection: ProjectionState,
    states: Mapping[tuple[ObligationId, int], RequestedOutputState],
    *,
    blocked: Iterable[ObligationId] | None = None,
) -> tuple[ObligationId, ...]:
    """Obligations with a declared delivered item ``removed_declared_items`` names."""

    return tuple(
        sorted(
            {
                obligation
                for obligation, _index in removed_declared_items(
                    projection, states, blocked=blocked
                )
            },
            key=str.encode,
        )
    )


def removed_declared_items(
    projection: ProjectionState,
    states: Mapping[tuple[ObligationId, int], RequestedOutputState],
    *,
    blocked: Iterable[ObligationId] | None = None,
    history: Sequence[DeliverableSnapshot] = (),
) -> tuple[tuple[ObligationId, int], ...]:
    """Declared delivered items the check-time change deleted or renamed away, that an earlier
    check read with content and that are now gone, or that an edit action of the session wrote
    and that are now gone.

    A state FinishUP could not read (``unverified``, ``outside``, or an unknown existence) never
    raises the fact; neither does a declared item that still exists. The caller reports such an
    item only as ``declared_output_removed``, never also as an absent output. The history route
    (ADR-045) catches a created-then-moved file whose path the agent spelled differently from
    the obligation's value, which the exact-value edit rule below misses.
    """

    removed: list[tuple[ObligationId, int]] = []
    edited: dict[ObligationId, frozenset[str]] = {}
    for obligation, index, _kind, value in declared_delivered_items(projection, blocked=blocked):
        state = states.get((obligation, index))
        if state is None or state.location != "inside" or state.exists is not False:
            continue
        if state.deleted:
            removed.append((obligation, index))
            continue
        if _held_content(_path_history(state, history)) is not None:
            removed.append((obligation, index))
            continue
        if obligation not in edited:
            edited[obligation] = attempted_items_for_obligation(
                projection, obligation, action_kind=ActionKind.EDIT
            )
        # Written in this session, now gone. Exact value match, as for the other output facts.
        if value in edited[obligation]:
            removed.append((obligation, index))
    return tuple(removed)


def content_moved_declared_items(
    projection: ProjectionState,
    states: Mapping[tuple[ObligationId, int], RequestedOutputState],
    *,
    blocked: Iterable[ObligationId] | None = None,
    history: Sequence[DeliverableSnapshot] = (),
) -> tuple[tuple[ObligationId, int], ...]:
    """Declared delivered files whose content the check-time change moved to undeclared files.

    An item qualifies when its state is ``inside``, still exists, was not deleted, and its
    line-count fields are all known with ``lines_lost >= CONTENT_MOVED_MIN_LINES``,
    ``2 * lines_lost >= base_lines`` and ``2 * undeclared_lines_added >= lines_lost``. Lines moved
    into another declared output, or a shrink with no matching growth outside the declared set,
    never qualify. Integer arithmetic only, so the answer is deterministic. A file the task base
    does not hold (created in this task) is measured against its largest earlier recorded
    reading, so a new solver whose lines moved to an undeclared file is disclosed too (ADR-045).
    """

    moved: list[tuple[ObligationId, int]] = []
    for obligation, index, _kind, _value in declared_delivered_items(projection, blocked=blocked):
        state = states.get((obligation, index))
        if (
            state is None
            or state.location != "inside"
            or state.exists is not True
            or state.deleted
            or state.undeclared_lines_added is None
        ):
            continue
        if _content_moved(state, _path_history(state, history)):
            moved.append((obligation, index))
    return tuple(moved)


def _content_moved(state: RequestedOutputState, history: Sequence[DeliverableSnapshot]) -> bool:
    if state.undeclared_lines_added is None:
        return False
    if state.base_lines is not None and state.lines_lost is not None:
        reference, lost = state.base_lines, state.lines_lost
    else:
        reference = 0
        lost = 0
    held_lines = max((item.state.lines or 0 for item in history), default=0)
    lines = _current_lines(state)
    if lines is not None and held_lines > reference:
        reference, lost = held_lines, held_lines - lines
    if reference <= 0:
        return False
    return _content_moved_shape(lost, reference, state.undeclared_lines_added)


def _content_moved_shape(lost: int, reference: int, undeclared_added: int | None) -> bool:
    """The ADR-035 content-moved rule on plain numbers: the lost lines reappear elsewhere."""

    return (
        undeclared_added is not None
        and lost >= CONTENT_MOVED_MIN_LINES
        and 2 * lost >= reference
        and 2 * undeclared_added >= lost
    )


def _delivered_obligations(projection: ProjectionState) -> frozenset[ObligationId]:
    """Obligations the record presents as delivered: ``resolved``, or named by an effective
    completion claim, unless acknowledged as not done."""

    claimed: set[ObligationId] = set()
    for _key, record in effective_claim_items(projection):
        claim = record.payload
        if claim is not None and claim.claim_kind is ClaimKind.COMPLETION:
            claimed.update(claim.obligation_refs)
    delivered: set[ObligationId] = set()
    for obligation in effective_obligations(projection):
        payload = projection.obligations[obligation].payload
        if payload is None or payload.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE:
            continue
        if payload.status is ObligationStatus.RESOLVED or obligation in claimed:
            delivered.add(obligation)
    return frozenset(delivered)


# ---------------------------------------------------------------------------------------------
# History (ADR-045)
# ---------------------------------------------------------------------------------------------

# A truncated file needs at least this much earlier content to be judged: a 10-line file cut to
# 3 lines is a rewrite, not a withdrawal. Same floor as the content-moved rule.
TRUNCATED_MIN_LINES: Final = CONTENT_MOVED_MIN_LINES
# The byte-based fallback when no line count could be read for the current or earlier state.
TRUNCATED_MIN_BYTES: Final = 2_048


@dataclass(frozen=True, slots=True)
class DeliverableSnapshot:
    """One earlier recorded reading of a declared output file: the state and the check it is in."""

    state: DeliverableState
    event_id: EventId
    frontier: int


@dataclass(frozen=True, slots=True)
class DeliverableChange:
    """What ``deliverable_state_change`` concluded.

    ``kind`` is ``emptied``, ``truncated``, ``removed`` or ``unchanged``. ``proof`` says how
    earlier content is known (``task_base``: a tracked file with lines at the task base;
    ``earlier_check``: an earlier check read it with content), ``prior`` is the last earlier
    reading that held content (``None`` for a task-base proof) and ``reference_lines`` the largest
    line count known.
    """

    kind: str
    proof: str | None = None
    prior: DeliverableSnapshot | None = None
    reference_lines: int | None = None
    reference_bytes: int | None = None


def deliverable_history(records: Iterable[LedgerRecord]) -> tuple[DeliverableSnapshot, ...]:
    """Every ``DeliverableState`` the accepted ``check_recorded`` events of a prefix hold.

    In ledger order, so ``snapshots[-1]`` is the newest reading. A snapshot's ``frontier`` is the
    subject frontier of its check (the ledger state the check examined). Redacted or unreadable
    check payloads contribute nothing: a missing history only costs proof, never invents any.
    """

    snapshots: list[DeliverableSnapshot] = []
    for record in records:
        if (
            type(record) is not AcceptedEvent
            or record.schema.name != "check_recorded"
            or type(record.payload) is not CheckRecordedPayload
        ):
            continue
        for state in record.payload.deliverable_states:
            snapshots.append(
                DeliverableSnapshot(
                    state, record.event_id, record.payload.subject_frontier.sequence
                )
            )
    return tuple(snapshots)


def _path_history(
    state: RequestedOutputState, history: Sequence[DeliverableSnapshot]
) -> tuple[DeliverableSnapshot, ...]:
    """The earlier readings of the very path *state* describes, whichever obligation declared it."""

    if not history or state.relative is None:
        return ()
    key = deliverable_path_identity(state.relative)
    if key is None:
        return ()
    return tuple(item for item in history if item.state.path_key == key)


def _held_content(snapshots: Sequence[DeliverableSnapshot]) -> DeliverableSnapshot | None:
    """The newest earlier reading that held content, or ``None``."""

    for item in reversed(snapshots):
        if (item.state.size_bytes or 0) > 0:
            return item
    return None


def _peak_content(snapshots: Sequence[DeliverableSnapshot]) -> DeliverableSnapshot | None:
    """The earlier reading with the most lines (the newest on a tie), or ``None``."""

    best: DeliverableSnapshot | None = None
    for item in snapshots:
        if (item.state.size_bytes or 0) <= 0:
            continue
        if best is None or (item.state.lines or 0) >= (best.state.lines or 0):
            best = item
    return best


def _current_lines(state: RequestedOutputState) -> int | None:
    if state.lines is not None:
        return state.lines
    if state.base_lines is not None and state.lines_lost is not None:
        return max(0, state.base_lines - state.lines_lost)
    return None


def deliverable_state_change(
    state: RequestedOutputState,
    history: Sequence[DeliverableSnapshot],
    *,
    name: str = "",
    other_growth: int | None = 0,
) -> DeliverableChange | None:
    """How a declared output file changed against its recorded history (ADR-045).

    ``state`` is the check-time read; ``history`` the earlier readings of the same path (use
    ``_path_history``), oldest first; ``name`` the file's last path component, for the
    conventionally-empty allow-list. ``other_growth`` is how many lines the *other* declared
    outputs gained in the same change (``None``: unknown, so a truncation is never raised).

    * ``removed``: the file is gone and the task base tracked it, or an earlier reading held
      content;
    * ``emptied``: 0 bytes, with proof of earlier content (a tracked file with lines at the task
      base, or an earlier reading with content). A file never seen non-empty is ``None``: created
      empty is not withdrawn;
    * ``truncated``: at least ``TRUNCATED_MIN_LINES`` lines were known earlier and fewer than one
      line in ``EMPTIED_KEPT_FRACTION`` remain (or, when no lines were read, a tenth of the bytes
      of a file of at least ``TRUNCATED_MIN_BYTES``), unless the content-moved shape holds or
      another declared output gained about as many lines (a split into another deliverable is a
      refactor);
    * ``unchanged``: the file holds content and none of the above applies;
    * ``None``: unknown. An unread size, a path outside the checked repository, an unverified read
      and a file that never held content prove nothing, and a truncated capture is unknown, not
      changed.
    """

    if state.location != "inside":
        return None
    path_history = history
    held = _held_content(history)
    if state.exists is False:
        if state.deleted:
            return DeliverableChange(
                "removed", "task_base" if held is None else "earlier_check", held
            )
        if held is not None:
            return DeliverableChange("removed", "earlier_check", held)
        return None
    if state.exists is not True or state.size_bytes is None:
        return None
    base = state.base_lines or 0
    held_lines = max((item.state.lines or 0 for item in history), default=0)
    held_bytes = max((item.state.size_bytes or 0 for item in history), default=0)
    if state.size_bytes == 0:
        if name in _CONVENTIONALLY_EMPTY:
            return DeliverableChange("unchanged")
        if held is not None:
            return DeliverableChange(
                "emptied", "earlier_check", held, max(base, held_lines) or None, held_bytes or None
            )
        if base > 0:
            return DeliverableChange("emptied", "task_base", None, base, None)
        return None
    lines = _current_lines(state)
    reference = max(base, held_lines)
    if (
        lines is not None
        and reference >= TRUNCATED_MIN_LINES
        and EMPTIED_KEPT_FRACTION * lines < reference
    ):
        lost = reference - lines
        if _content_moved_shape(lost, reference, state.undeclared_lines_added):
            return DeliverableChange("unchanged")
        if state.counts_truncated:
            # The line-count read left files out: the lines may have moved there, and a lower
            # bound cannot say they did not. Unknown, not changed.
            return None
        if other_growth is None or 2 * other_growth >= lost:
            return DeliverableChange("unchanged")
        from_history = held is not None and held_lines >= base
        return DeliverableChange(
            "truncated",
            "earlier_check" if from_history else "task_base",
            # The reading the comparison used: the largest known, not merely the newest.
            _peak_content(path_history) if from_history else None,
            reference,
            held_bytes or None,
        )
    if (
        lines is None
        and held is not None
        and held_bytes >= TRUNCATED_MIN_BYTES
        and EMPTIED_KEPT_FRACTION * state.size_bytes < held_bytes
        and (other_growth is not None and other_growth <= 0)
    ):
        if state.counts_truncated:
            return None
        return DeliverableChange(
            "truncated",
            "earlier_check",
            _peak_content(path_history),
            held_lines or None,
            held_bytes,
        )
    return DeliverableChange("unchanged")


# ---------------------------------------------------------------------------------------------
# The exit: a finishup-assumption decision that names the path
# ---------------------------------------------------------------------------------------------

_PATH_CHARS: Final = r"A-Za-z0-9_.\-/~"


def _names_path(text: str, names: Sequence[str]) -> bool:
    """Whether *text* holds any of *names* as a whole path token (not part of a longer path)."""

    for name in names:
        if not name:
            continue
        pattern = rf"(?<![{_PATH_CHARS}]){re.escape(name)}(?![{_PATH_CHARS}])"
        if re.search(pattern, text) is not None:
            return True
    return False


def path_assumption(
    projection: ProjectionState,
    declaring: Iterable[ObligationId],
    names: Sequence[str],
) -> EventId | None:
    """The earliest unsuperseded ``finishup-assumption`` decision that accepts an emptied path.

    The decision must carry the line ``finishup-assumption:<obligation id>`` (either spelling,
    ``disclosure_line_obligations``) for an obligation that declares the path, and its statement or rationale must name the declared value or the
    root-relative path as a whole token. A disclosure that names no path never qualifies (a
    best-effort note must not disable the incomplete-work check, Codex review).
    """

    obligations = frozenset(declaring)
    rows = sorted(
        (
            (row.source_frontier, event_id, row.payload)
            for event_id, row in projection.decisions.items()
            if type(row.payload) is DecisionRecordedPayload and row.superseded_by_event_id is None
        ),
        key=lambda item: (item[0], str(item[1]).encode()),
    )
    for _position, event_id, payload in rows:
        assert payload is not None
        if not any(
            kind == "assumption" and obligation in obligations
            for kind, obligation in disclosure_line_obligations(payload.statement)
        ):
            continue
        if _names_path(payload.statement, names) or _names_path(payload.rationale, names):
            return event_id
    return None


# ---------------------------------------------------------------------------------------------
# Assessment: one answer per declared path for a check
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DeliverableAssessment:
    """What one check concludes about its declared output files.

    ``states`` are the ``DeliverableState`` records the check persists (history for the next
    check and lineage for every surface); ``emptied`` the ``(obligation, item index)`` pairs the
    fact ``declared_output_emptied`` names (emptied or truncated, not accepted); ``removed`` the
    pairs the history route adds to ``declared_output_removed``.
    """

    states: tuple[DeliverableState, ...] = ()
    emptied: tuple[tuple[ObligationId, int], ...] = ()
    removed: tuple[tuple[ObligationId, int], ...] = ()


def _file_name(value: str) -> str:
    return value.rstrip("/").rsplit("/", 1)[-1]


@dataclass(frozen=True, slots=True)
class _PathVerdict:
    basis: str
    change: DeliverableChange | None
    accepted: EventId | None
    fires: bool


def _gained_lines(
    state: RequestedOutputState | None,
    kind: str,
    history: Sequence[DeliverableSnapshot],
) -> int | None:
    """Lines one declared output gained in this change; ``None`` when that cannot be told.

    A file with a readable line count gained what it now holds beyond its largest earlier reading
    (or task-base count). A file or declared directory that changed with no readable count may have
    absorbed the lines of a split (a refactor), so its growth is unknown, and the caller then
    never calls a sibling's shrink a truncation (the same caution the content-moved rule takes).
    """

    if state is None or state.location != "inside" or state.exists is not True:
        return 0
    if kind == "file":
        lines = _current_lines(state)
        if lines is not None:
            earlier = max(
                (item.state.lines or 0 for item in _path_history(state, history)), default=0
            )
            return max(0, lines - max(earlier, state.base_lines or 0))
    return 0 if state.changed is False else None


def assess_deliverables(
    projection: ProjectionState,
    states: Mapping[tuple[ObligationId, int], RequestedOutputState],
    *,
    blocked: Iterable[ObligationId] | None = None,
    history: Sequence[DeliverableSnapshot] = (),
    verified: bool = False,
) -> DeliverableAssessment:
    """Assess every declared output file against its history (ADR-045).

    One answer per **path**: the rows that declare the same file (several obligations, an
    absolute and a relative spelling) share one history, one verdict and one exit. A file fires
    ``declared_output_emptied`` when ``deliverable_state_change`` says ``emptied`` or
    ``truncated`` and it counts as a delivery: an obligation declaring the path is resolved or
    claimed complete now, or an earlier reading of the path was recorded as delivered or verified.
    The obligation's status does not matter beyond that, so ``acknowledged_not_done`` and a new
    "empty fallback" obligation on the same path cannot clear it. ``verified`` says a passing
    verification run was observed in the ledger.
    """

    rows = declared_delivered_items(projection, blocked=blocked)
    delivered = _delivered_obligations(projection)

    def path_of(row: tuple[ObligationId, int, str, str]) -> str:
        state = states.get((row[0], row[1]))
        return row[3].rstrip("/") if state is None or state.relative is None else state.relative

    paths: dict[str, list[tuple[ObligationId, int, str, str]]] = {}
    for row in rows:
        paths.setdefault(path_of(row), []).append(row)
    gained = {
        path: _gained_lines(
            states.get((group[0][0], group[0][1])),
            group[0][2],
            _path_history(state, history)
            if (state := states.get((group[0][0], group[0][1]))) is not None
            else (),
        )
        for path, group in paths.items()
    }
    verdicts: dict[str, _PathVerdict] = {}
    for path, group in paths.items():
        first = group[0]
        state = states.get((first[0], first[1]))
        if first[2] != "file" or state is None or state.location != "inside":
            continue
        path_history = _path_history(state, history)
        others = [growth for other, growth in gained.items() if other != path]
        other_growth = (
            None
            if any(item is None for item in others)
            else sum(item for item in others if item is not None)
        )
        change = deliverable_state_change(
            state, path_history, name=_file_name(first[3]), other_growth=other_growth
        )
        now_delivered = any(item[0] in delivered for item in group)
        earlier_delivery = any(
            item.state.basis in {"delivered", "verified"} and (item.state.size_bytes or 0) > 0
            for item in path_history
        )
        basis = (
            "delivered"
            if now_delivered
            else "verified"
            if verified and (state.size_bytes or 0) > 0
            else "present"
        )
        withdrawn = (
            change is not None
            and change.kind in {"emptied", "truncated"}
            and (now_delivered or earlier_delivery)
        )
        if withdrawn and not now_delivered:
            # What made the path count as delivered was recorded at an earlier check; the state
            # says so (the lineage names it), and a state with no content never counts again.
            basis = (
                "delivered"
                if any(
                    item.state.basis == "delivered" and (item.state.size_bytes or 0) > 0
                    for item in path_history
                )
                else "verified"
            )
        if change is not None and change.kind in {"emptied", "truncated"} and not withdrawn:
            # Never delivered (an open obligation's work in progress): not a withdrawal.
            change = None
        accepted = (
            path_assumption(
                projection,
                (item[0] for item in group),
                tuple(
                    dict.fromkeys(
                        (*(item[3].rstrip("/") for item in group), *filter(None, [state.relative]))
                    )
                ),
            )
            if withdrawn
            else None
        )
        verdicts[path] = _PathVerdict(basis, change, accepted, withdrawn and accepted is None)
    recorded: list[DeliverableState] = []
    emptied: list[tuple[ObligationId, int]] = []
    removed = removed_declared_items(projection, states, blocked=blocked, history=history)
    for obligation, index, kind, value in rows:
        verdict = verdicts.get(path_of((obligation, index, kind, value)))
        state = states.get((obligation, index))
        if verdict is None or state is None:
            continue
        key = deliverable_path_identity(state.relative) if state.relative is not None else None
        change = verdict.change
        if change is None and (obligation, index) in removed:
            # A published edit named the file and it is gone, with no earlier reading or tracked
            # deletion to prove it: the removal is still recorded, so every surface can say why.
            change = DeliverableChange("removed")
        recorded.append(
            _record(obligation, index, state, key, verdict.basis, change, verdict.accepted)
        )
        if verdict.fires:
            emptied.append((obligation, index))
    return DeliverableAssessment(
        tuple(
            sorted(recorded, key=lambda item: (str(item.obligation_id).encode(), item.item_index))
        )[:64],
        tuple(emptied),
        removed,
    )


def _record(
    obligation: ObligationId,
    index: int,
    state: RequestedOutputState,
    key: str | None,
    basis: str,
    change: DeliverableChange | None,
    accepted: EventId | None,
) -> DeliverableState:
    prior = None if change is None else change.prior
    return DeliverableState(
        obligation_id=obligation,
        item_index=index,
        path_key=key,
        size_bytes=state.size_bytes if state.exists is True else None,
        lines=_current_lines(state) if state.exists is True else None,
        base_lines=state.base_lines,
        basis=basis,
        change=None if change is None else change.kind,
        proof=None if change is None or change.kind == "unchanged" else change.proof,
        prior_size_bytes=None if prior is None else prior.state.size_bytes,
        prior_lines=(
            None if prior is None else prior.state.lines if prior.state.lines is not None else None
        ),
        prior_event_id=None if prior is None else prior.event_id,
        prior_frontier=None if prior is None else prior.frontier,
        accepted_by=accepted,
    )


def deliverable_lineage(
    check_event_id: EventId | None, frontier: int, states: Iterable[DeliverableState]
) -> tuple[FactLineage, ...]:
    """The ``FactLineage`` of every deliverable fact a check recorded.

    ``declared_output_emptied`` (emptied or truncated) and ``declared_output_removed`` come from a
    state's ``change``; ``declared_output_not_reviewable`` from ``unreviewable``. A state a
    ``finishup-assumption`` decision accepted is not a fact and carries none (the receipt names the
    assumption itself). ``frontier`` is the check's subject frontier.
    """

    output: list[FactLineage] = []
    for item in states:
        if item.unreviewable:
            output.append(
                FactLineage(
                    code=DECLARED_OUTPUT_NOT_REVIEWABLE_GAP,
                    rule=RULE_DELIVERABLE_READ,
                    state="unreviewable",
                    obligation_id=item.obligation_id,
                    item_index=item.item_index,
                    check_event_id=check_event_id,
                    frontier=frontier,
                    now_size_bytes=item.size_bytes,
                    now_lines=item.lines,
                )
            )
        if item.change not in {"emptied", "truncated", "removed"} or item.accepted_by is not None:
            continue
        code = (
            DECLARED_OUTPUT_REMOVED_GAP if item.change == "removed" else DECLARED_OUTPUT_EMPTIED_GAP
        )
        earlier = item.proof == "earlier_check"
        output.append(
            FactLineage(
                code=code,
                rule=RULE_DELIVERABLE_PATH_HISTORY,
                state=item.change,
                obligation_id=item.obligation_id,
                item_index=item.item_index,
                check_event_id=check_event_id,
                frontier=frontier,
                prior_event_id=item.prior_event_id,
                prior_frontier=item.prior_frontier,
                prior_size_bytes=item.prior_size_bytes if earlier else None,
                prior_lines=item.prior_lines if earlier else None,
                now_size_bytes=item.size_bytes,
                now_lines=item.lines,
                proof=item.proof,
                basis=item.basis,
            )
        )
    return tuple(output)


type UndeclaredReferenceRow = tuple[str, int | None, tuple[str, ...], int]


def ambiguous_reference_count(states: Iterable[DeliverableState]) -> int:
    """How many created files the recorded deliverables name only ambiguously (tb4n5).

    The sum of ``undeclared_reference_ambiguous`` over the check's deliverable states, each keyed
    path counted once: the count ``deliverable_references_ambiguous_name`` discloses.
    """

    seen: set[str] = set()
    total = 0
    for state in states:
        if state.undeclared_reference_ambiguous is None:
            continue
        key = state.path_key or f"{state.obligation_id}:{state.item_index}"
        if key in seen:
            continue
        seen.add(key)
        total += state.undeclared_reference_ambiguous
    return total


def undeclared_reference_rows(
    states: Iterable[DeliverableState],
) -> tuple[UndeclaredReferenceRow, ...]:
    """``(obligation id, item index, paths, total)`` of each recorded deliverable that names
    files the change created and no item declares (tb4n4, #1044), in the check's own order.

    A file that several items declare shares one keyed path, so its references are listed once,
    under the first item that declares it. The input of ``undeclared_reference_variants``, the one
    sentence the receipt and the Stop gate print, and of status ``undeclared_references``.
    """

    rows: list[UndeclaredReferenceRow] = []
    seen: set[str] = set()
    for state in states:
        if not state.undeclared_references and state.undeclared_reference_count is None:
            continue
        key = state.path_key or f"{state.obligation_id}:{state.item_index}"
        if key in seen:
            continue
        seen.add(key)
        total = state.undeclared_reference_count or len(state.undeclared_references)
        rows.append(
            (str(state.obligation_id), state.item_index, state.undeclared_references, total)
        )
    return tuple(rows)


def emptied_declared_items(
    projection: ProjectionState,
    states: Mapping[tuple[ObligationId, int], RequestedOutputState],
    *,
    blocked: Iterable[ObligationId] | None = None,
    history: Sequence[DeliverableSnapshot] = (),
    verified: bool = False,
) -> tuple[tuple[ObligationId, int], ...]:
    """Declared delivered files that are now empty or truncated, with proof of earlier content.

    The ``emptied`` list of ``assess_deliverables``: a file withdrawn after it was delivered. A
    file created empty, never seen with content, unread, outside the repository, or accepted by a
    ``finishup-assumption`` decision that names its path is never in it.
    """

    return assess_deliverables(
        projection, states, blocked=blocked, history=history, verified=verified
    ).emptied


def undeclared_reference_inputs(
    projection: ProjectionState,
    states: Mapping[tuple[ObligationId, int], RequestedOutputState],
    *,
    blocked: Iterable[ObligationId] | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The inputs of the ``deliverable_references_undeclared_file`` read (tb4n2 R2).

    Returns ``(deliverables, declared)``: the values of declared delivered ``file`` items whose
    check-time state is ``inside``, existing and not deleted, of obligations neither blocked nor
    ``acknowledged_not_done``; and the value of every ``file`` or ``directory`` item of every
    effective obligation, whatever its role, which the caller excludes from the referenced
    candidates (a declared input or output was delivered or is expected). Values are deduplicated
    in first-seen order; nothing is read here.
    """

    deliverables: dict[str, None] = {}
    for obligation, index, kind, value in declared_delivered_items(projection, blocked=blocked):
        payload = projection.obligations[obligation].payload
        if (
            kind != "file"
            or payload is None
            or payload.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE
        ):
            continue
        state = states.get((obligation, index))
        if state is None or state.location != "inside" or state.exists is not True or state.deleted:
            continue
        deliverables[value] = None
    declared: dict[str, None] = {}
    for obligation in effective_obligations(projection):
        payload = projection.obligations[obligation].payload
        if payload is None:
            continue
        for item in payload.requested_items:
            if _wire(item.item_kind) in _DECLARED_KINDS:
                declared[item.value] = None
    return tuple(deliverables), tuple(declared)
