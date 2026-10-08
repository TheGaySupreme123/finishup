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

``declared_output_content_moved`` is the non-blocking disclosure for content moved out of a
declared file that still exists (interleaved-vigenere). A bounded line-count read of the
check-time change sets ``base_lines``, ``lines_lost`` and ``undeclared_lines_added`` on the
state of a declared file the change modified; ``content_moved_declared_items`` applies the
deterministic rule below. It is a standing disclosure: it never fires the Stop gate.

Nothing is stored; the result is closed codes only.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from yoetz.domain.events import ActionKind
from yoetz.domain.values import ObligationId
from yoetz.kernel.command_attempts import attempted_items_for_obligation
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.task_facts import (
    DECLARED_OUTPUT_CONTENT_MOVED_GAP,
    DECLARED_OUTPUT_REMOVED_GAP,
    RequestedOutputState,
    blocked_obligations,
    effective_obligations,
)

__all__ = [
    "CONTENT_MOVED_MIN_LINES",
    "DECLARED_OUTPUT_CONTENT_MOVED_GAP",
    "DECLARED_OUTPUT_REMOVED_GAP",
    "content_moved_declared_items",
    "declared_delivered_items",
    "declared_output_removed",
    "removed_declared_items",
]

_DECLARED_KINDS: Final = frozenset({"file", "directory"})
# The content-moved rule (ADR-035), deliberately conservative: a declared file lost at least this
# many lines and at least half of its task-base lines, and the same change added at least half as
# many lines to files outside the declared delivered set.
CONTENT_MOVED_MIN_LINES: Final = 20


def _wire(value: object) -> object:
    return getattr(value, "value", value)


def item_role(item: object) -> object:
    """A requested item's role by wire value; ``None`` before ``obligation_published`` 1.1.0."""

    return _wire(getattr(item, "role", None))


def declared_delivered_items(
    projection: ProjectionState,
) -> tuple[tuple[ObligationId, int, str, str], ...]:
    """``(obligation, item index, item kind, value)`` for the declared delivered set.

    Blocked obligations are excluded. Order follows the effective obligations and item order.
    """

    blocked = blocked_obligations(projection)
    rows: list[tuple[ObligationId, int, str, str]] = []
    for obligation in effective_obligations(projection):
        if obligation in blocked:
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
) -> tuple[ObligationId, ...]:
    """Obligations with a declared delivered item ``removed_declared_items`` names."""

    return tuple(
        sorted(
            {obligation for obligation, _index in removed_declared_items(projection, states)},
            key=str.encode,
        )
    )


def removed_declared_items(
    projection: ProjectionState,
    states: Mapping[tuple[ObligationId, int], RequestedOutputState],
) -> tuple[tuple[ObligationId, int], ...]:
    """Declared delivered items the check-time change deleted or renamed away, or that an edit
    action of the session wrote and that are now gone.

    A state Yoetz could not read (``unverified``, ``outside``, or an unknown existence) never
    raises the fact; neither does a declared item that still exists. The caller reports such an
    item only as ``declared_output_removed``, never also as an absent output.
    """

    removed: list[tuple[ObligationId, int]] = []
    edited: dict[ObligationId, frozenset[str]] = {}
    for obligation, index, _kind, value in declared_delivered_items(projection):
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
) -> tuple[tuple[ObligationId, int], ...]:
    """Declared delivered files whose content the check-time change moved to undeclared files.

    An item qualifies when its state is ``inside``, still exists, was not deleted, and its
    line-count fields are all known with ``lines_lost >= CONTENT_MOVED_MIN_LINES``,
    ``2 * lines_lost >= base_lines`` and ``2 * undeclared_lines_added >= lines_lost``. Lines moved
    into another declared output, or a shrink with no matching growth outside the declared set,
    never qualify. Integer arithmetic only, so the answer is deterministic.
    """

    moved: list[tuple[ObligationId, int]] = []
    for obligation, index, _kind, _value in declared_delivered_items(projection):
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
        lost = state.lines_lost
        if (
            lost >= CONTENT_MOVED_MIN_LINES
            and 2 * lost >= state.base_lines
            and 2 * state.undeclared_lines_added >= lost
        ):
            moved.append((obligation, index))
    return tuple(moved)
