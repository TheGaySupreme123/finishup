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

``declared_output_emptied`` (tb4n2 R2, ADR-035 amendment) re-derives a resolved obligation from
the current deliverable instead of trusting its latched status. It is raised when a declared
``file`` of an obligation that is ``resolved``, or that an effective completion claim names, is now
an existing regular file of 0 bytes (not a conventionally empty name such as ``__init__.py``), or
a tracked file that kept under a tenth of its (at least ``CONTENT_MOVED_MIN_LINES``) task-base
lines without the content-moved shape below and with no other declared output changed. While it
stands that obligation is no longer counted as delivered: the fact is agent-actionable and a
Stop-gate token. It clears at the next check once the file is restored, or once the obligation is
republished open or ``acknowledged_not_done``; a disclosure line never clears it (formal-crypto S
emptied its delivered ``solve.sage`` after a finding, with six obligations still recorded
resolved).

``declared_output_content_moved`` is the non-blocking disclosure for content moved out of a
declared file that still exists (interleaved-vigenere). A bounded line-count read of the
check-time change sets ``base_lines``, ``lines_lost`` and ``undeclared_lines_added`` on the
state of a declared file the change modified; ``content_moved_declared_items`` applies the
deterministic rule below. It is a standing disclosure: it never fires the Stop gate.

Nothing is stored; the result is closed codes only.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Final

from yoetz.domain.events import ActionKind, ClaimKind, ObligationStatus
from yoetz.domain.values import EventId, ObligationId
from yoetz.kernel.claims import effective_claim_items
from yoetz.kernel.command_attempts import attempted_items_for_obligation
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.task_facts import (
    DECLARED_OUTPUT_CONTENT_MOVED_GAP,
    DECLARED_OUTPUT_EMPTIED_GAP,
    DECLARED_OUTPUT_REMOVED_GAP,
    RequestedOutputState,
    blocked_obligations,
    effective_obligations,
)

__all__ = [
    "CONTENT_MOVED_MIN_LINES",
    "DECLARED_OUTPUT_CONTENT_MOVED_GAP",
    "DECLARED_OUTPUT_EMPTIED_GAP",
    "DECLARED_OUTPUT_REMOVED_GAP",
    "content_moved_declared_items",
    "declared_delivered_items",
    "emptied_declared_items",
    "declared_output_removed",
    "removed_declared_items",
    "undeclared_reference_inputs",
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
) -> tuple[tuple[ObligationId, int], ...]:
    """Declared delivered items the check-time change deleted or renamed away, or that an edit
    action of the session wrote and that are now gone.

    A state Yoetz could not read (``unverified``, ``outside``, or an unknown existence) never
    raises the fact; neither does a declared item that still exists. The caller reports such an
    item only as ``declared_output_removed``, never also as an absent output.
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
) -> tuple[tuple[ObligationId, int], ...]:
    """Declared delivered files whose content the check-time change moved to undeclared files.

    An item qualifies when its state is ``inside``, still exists, was not deleted, and its
    line-count fields are all known with ``lines_lost >= CONTENT_MOVED_MIN_LINES``,
    ``2 * lines_lost >= base_lines`` and ``2 * undeclared_lines_added >= lines_lost``. Lines moved
    into another declared output, or a shrink with no matching growth outside the declared set,
    never qualify. Integer arithmetic only, so the answer is deterministic.
    """

    moved: list[tuple[ObligationId, int]] = []
    for obligation, index, _kind, _value in declared_delivered_items(projection, blocked=blocked):
        state = states.get((obligation, index))
        if (
            state is None
            or state.location != "inside"
            or state.exists is not True
            or state.deleted
            or state.base_lines is None
            or state.lines_lost is None
            or state.undeclared_lines_added is None
        ):
            continue
        if _content_moved(state):
            moved.append((obligation, index))
    return tuple(moved)


def _content_moved(state: RequestedOutputState) -> bool:
    if state.base_lines is None or state.lines_lost is None or state.undeclared_lines_added is None:
        return False
    lost = state.lines_lost
    return (
        lost >= CONTENT_MOVED_MIN_LINES
        and 2 * lost >= state.base_lines
        and 2 * state.undeclared_lines_added >= lost
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


def _overlaps(left: str, right: str) -> bool:
    if left in {".", ""} or right in {".", ""}:
        return True
    left, right = left.rstrip("/"), right.rstrip("/")
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def _distinct_paths(
    state: RequestedOutputState, value: str, other: RequestedOutputState, other_value: str
) -> bool:
    """Whether another declared item names a different path than *state*'s file.

    The same file declared twice (absolute and relative) or a declared directory holding it is
    the same deliverable, never "another declared output changed" (Codex review 2).
    """

    if state.relative is not None and other.relative is not None:
        return not _overlaps(state.relative, other.relative)
    return not _overlaps(value, other_value)


def emptied_declared_items(
    projection: ProjectionState,
    states: Mapping[tuple[ObligationId, int], RequestedOutputState],
    *,
    blocked: Iterable[ObligationId] | None = None,
) -> tuple[tuple[ObligationId, int], ...]:
    """Declared delivered files of a delivered obligation that are now empty or truncated.

    Only an ``inside`` state that exists, was not deleted, and is a regular file qualifies:

    * 0 bytes, unless its name is conventionally empty (``__init__.py``, ``py.typed``,
      ``.gitkeep``, ``.keep``, ``.nojekyll``);
    * or truncated: ``base_lines >= CONTENT_MOVED_MIN_LINES`` with fewer than one line in
      ``EMPTIED_KEPT_FRACTION`` kept, not the content-moved shape (the standing
      ``declared_output_content_moved`` disclosure), and no *other* declared delivered item
      changed in the same change: a split into another declared output is a refactor, and its
      growth is not counted in ``undeclared_lines_added``, so it is never read as truncation.

    An unread size or line count never raises it. Deliberately conservative: a wrong
    agent-actionable fact would steer the agent away from finished work.
    """

    delivered = _delivered_obligations(projection)
    if not delivered:
        return ()
    rows = declared_delivered_items(projection, blocked=blocked)
    emptied: list[tuple[ObligationId, int]] = []
    for obligation, index, kind, value in rows:
        if kind != "file" or obligation not in delivered:
            continue
        state = states.get((obligation, index))
        if state is None or state.location != "inside" or state.exists is not True or state.deleted:
            continue
        if state.size_bytes == 0:
            if value.rstrip("/").rsplit("/", 1)[-1] not in _CONVENTIONALLY_EMPTY:
                emptied.append((obligation, index))
            continue
        other_declared_changed = any(
            (other := states.get((other_obligation, other_index))) is not None
            and other.changed is not False
            and _distinct_paths(state, value, other, other_value)
            for other_obligation, other_index, _other_kind, other_value in rows
        )
        if (
            state.base_lines is not None
            and state.lines_lost is not None
            and state.base_lines >= CONTENT_MOVED_MIN_LINES
            and EMPTIED_KEPT_FRACTION * (state.base_lines - state.lines_lost) < state.base_lines
            and not _content_moved(state)
            and not other_declared_changed
        ):
            emptied.append((obligation, index))
    return tuple(emptied)


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
