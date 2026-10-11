"""tb4n3 RC-5 (ADR-045): a present-but-not-reviewed deliverable is named, not silently skipped."""

from __future__ import annotations

from yoetz.application import check
from yoetz.domain.events import DeliverableState
from yoetz.domain.values import obligation_id
from yoetz.kernel.delivered_set import deliverable_lineage
from yoetz.kernel.task_facts import DECLARED_OUTPUT_NOT_REVIEWABLE_GAP

_OBL = obligation_id("obl_00000000-0000-4000-8000-0000000000b1")


def _mark(
    names: tuple[str, ...], binary: frozenset[str], text: frozenset[str]
) -> tuple[tuple[DeliverableState, ...], bool]:
    states = tuple(
        DeliverableState(obligation_id=_OBL, item_index=index, size_bytes=10, basis="present")
        for index, _name in enumerate(names)
    )
    files = tuple((_OBL, index, name) for index, name in enumerate(names))
    return check._mark_unreviewable(states, files, binary, text)  # pyright: ignore[reportPrivateUsage]


def test_a_binary_declared_output_is_marked_when_a_review_ran() -> None:
    states, found = _mark(
        ("harmony.mxl", "notes.md", "solver", "part.step"),
        frozenset({"solver"}),
        frozenset({"part.step"}),
    )
    assert found
    # ``.mxl`` is a binary suffix the change did not list; ``solver`` is binary by Git's sniff;
    # ``.step`` is text by the same sniff; ``notes.md`` is text by its suffix.
    assert [state.unreviewable for state in states] == [True, False, True, False]


def test_nothing_is_marked_for_text_deliverables() -> None:
    states, found = _mark(("solve.sage", "out.json"), frozenset(), frozenset())
    assert not found
    assert not any(state.unreviewable for state in states)


def test_the_lineage_names_the_unreviewed_item() -> None:
    states, _found = _mark(("harmony.mxl",), frozenset(), frozenset())
    (fact,) = deliverable_lineage(None, 41, states)
    assert (fact.code, fact.state, fact.item_index, fact.frontier) == (
        DECLARED_OUTPUT_NOT_REVIEWABLE_GAP,
        "unreviewable",
        0,
        41,
    )
