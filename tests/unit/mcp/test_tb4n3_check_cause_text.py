"""tb4n3 RC-6 (#1029) x RC-2 (#1025): the lineage sentence in the bounded status text.

Provenance. Lane LO added the ``closure_readiness.check_cause`` lineage sentence to the byte-
bounded MCP status text and, after Codex round 3, reserved it ahead of the closure boilerplate on
every status view; lane LB then rebuilt every summary on the bounded composer. Codex re-review of
LO's reservation found two defects, both reproduced here against the merged composer:

* the reservation displaced the closure state and the stop instruction ("Request the receipt.")
  on an ordinary active ``project`` page with an ``exec_command`` bounding cause;
* on ``operation`` views the operation-progress text outranked the cause, so a completed semantic
  check followed by ``apply_patch`` listed ``check_not_applicable`` with no edit record.

The merged order is: core (view and frontier, the closure state, the stop instruction, the
agent-actionable items, the operation fallback) is reserved first; the cause is the next priority;
every boilerplate sentence (the counts sentence of the full directive, the generic closure
sentence, the operation-progress text) is granted behind it. The cause is optional, so it can
never displace core; a sweep over every bound proves both halves.
"""

# pyright: reportPrivateUsage=false
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from builders.status_text import BOUNDING, HEAD, SUPERSEDED, VIEWS, status_wire
from finishup.mcp import summaries
from finishup.mcp.summaries import (
    _check_cause_variants,
    _operation_progress_clause,
    render_safe_compact_summary,
    render_safe_compact_summary_detailed,
)
from finishup.protocol.readiness_text import readiness_directive

_STOP = "Request the receipt."
_SHORT_STOP = "Nothing further to do. Request the receipt."
_COUNTS_SENTENCE = "will be disclosed on the receipt"
_OPERATION_FALLBACK = "semantic progress: see structured page;"


def _wire(*, state: str, view: str, cause: Any) -> dict[str, Any]:
    return status_wire(state=state, view=view, cause=cause)


def _at(monkeypatch: pytest.MonkeyPatch, bound: int, wire: dict[str, Any]) -> str:
    with monkeypatch.context() as patch:
        patch.setattr(summaries, "_MAX_SUMMARY_BYTES", bound)
        return render_safe_compact_summary(wire)


def _sweep(monkeypatch: pytest.MonkeyPatch, wire: dict[str, Any]) -> Iterator[tuple[int, str]]:
    """Every bound from the real size down to the documented last-resort cut, with its text."""

    bound = len(render_safe_compact_summary(wire))
    while bound > 0:
        text = _at(monkeypatch, bound, wire)
        if "..." in text:
            return  # below the required core the composer cuts; the core order no longer applies
        assert len(text) <= bound, bound
        yield bound, text
        bound -= 1


def _core(state: str, text: str) -> bool:
    """The state, its stop instruction or action items: what no lineage may displace."""

    if f"Closure: {state}." not in text:
        return False
    if state == "ready_with_limitations":
        return _STOP in text
    return "Agent-actionable: check_not_applicable" in text


_CASES = [
    pytest.param("action_required", SUPERSEDED, "Why check_not_applicable: ", id="superseded"),
    pytest.param(
        "ready_with_limitations",
        BOUNDING,
        "Why check_current_as_of_earlier_frontier: ",
        id="bounding",
    ),
]


@pytest.mark.parametrize("view", VIEWS)
@pytest.mark.parametrize(("state", "cause", "lead"), _CASES)
def test_every_status_view_carries_the_full_lineage_sentence_at_the_real_bound(
    state: str, cause: dict[str, Any], lead: str, view: str
) -> None:
    wire = _wire(state=state, view=view, cause=cause)
    text = render_safe_compact_summary(wire)
    full, short = _check_cause_variants(wire)
    assert full in text and short not in text
    assert text.startswith(f"Status view: {view};") and text.isascii()
    assert full.startswith(lead)
    assert _core(state, text)
    # The cause explains the closure checklist, so it follows it.
    assert text.index("Closure: ") < text.index(lead)
    if view == "operation":
        assert "operation state: completed" in text


def test_an_active_project_page_never_loses_its_stop_instruction_to_the_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Codex re-review P2 (1): ready_with_limitations + an exec_command bounding cause on an
    ordinary active project page gave the cause without the closure state or "Request the
    receipt.". The cause is never required, so at no bound can it appear without them."""

    wire = _wire(state="ready_with_limitations", view="project", cause=BOUNDING)
    full, short = _check_cause_variants(wire)
    assert "exec_command" in full and "exec_command" in short

    real = render_safe_compact_summary(wire)
    assert _core("ready_with_limitations", real) and full in real
    assert _COUNTS_SENTENCE in real  # at the real bound the counts sentence has room too

    tight = _at(monkeypatch, 512, wire)
    assert len(tight) <= 512
    assert _core("ready_with_limitations", tight)
    assert "Status view: project; frontier: 9; head_digest: " + HEAD in tight

    texts = dict(_sweep(monkeypatch, wire))
    assert texts and all(_core("ready_with_limitations", text) for text in texts.values())
    with_cause = [bound for bound, text in texts.items() if short in text or full in text]
    assert with_cause, "the cause never appeared"
    # The smallest bound that shows the cause carries the short form, not the counts sentence.
    witness = texts[min(with_cause)]
    assert short in witness and _COUNTS_SENTENCE not in witness


def test_the_operation_view_keeps_the_cause_ahead_of_the_progress_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Codex re-review P2 (2): a completed semantic check followed by apply_patch listed
    ``check_not_applicable`` with no cause, edit record or tested frontier, because the
    operation-progress text took the room first. The progress text is granted behind the cause."""

    wire = _wire(state="action_required", view="operation", cause=SUPERSEDED)
    full, short = _check_cause_variants(wire)
    progress = _operation_progress_clause(wire).strip()
    assert progress.startswith("operation state: completed")

    real = render_safe_compact_summary(wire)
    assert progress in real and full in real and _core("action_required", real)

    # 512 holds the core and the short form but not the progress text: the fallback stands in
    # for the progress text and the lineage is present.
    tight = _at(monkeypatch, 512, wire)
    assert len(tight) <= 512 and short in tight
    assert progress not in tight and _OPERATION_FALLBACK in tight
    assert _core("action_required", tight)

    # Room for the full sentence but not for the progress text: the cause is still first.
    roomy_for_cause = len(real) - len(progress) + len(_OPERATION_FALLBACK)
    boilerplate = len(readiness_directive("action_required")) + 1
    text = _at(monkeypatch, roomy_for_cause - boilerplate, wire)
    assert full in text and progress not in text and _core("action_required", text)


@pytest.mark.parametrize("view", VIEWS)
@pytest.mark.parametrize(("state", "cause", "lead"), _CASES)
def test_the_cause_is_the_next_priority_after_the_core_at_every_bound(
    monkeypatch: pytest.MonkeyPatch,
    state: str,
    cause: dict[str, Any],
    lead: str,
    view: str,
) -> None:
    """Sweep every bound from the real size down to the composer's last-resort cut.

    Core (state, stop instruction or action items, frontier) is present at every bound and the
    cause never appears without it. A boilerplate sentence is present while the cause is absent
    only when the cause could not have fit even without that sentence: the cause outranks the
    counts sentence, the generic closure sentence and the operation-progress text."""

    wire = _wire(state=state, view=view, cause=cause)
    full, short = _check_cause_variants(wire)
    # (marker found in the text, characters the sentence adds beyond what core already holds)
    boilerplates: list[tuple[str, int]] = []
    if state == "ready_with_limitations":
        counts = readiness_directive(state, standing=1, acknowledged="0")
        boilerplates.append((_COUNTS_SENTENCE, len(counts) - len(_SHORT_STOP)))
    else:
        generic = readiness_directive(state)
        boilerplates.append((generic, len(generic) + 1))
    if view == "operation":
        progress = _operation_progress_clause(wire).strip()
        boilerplates.append(("operation state:", len(progress) - len(_OPERATION_FALLBACK)))

    seen_cause = seen_cause_alone = False
    for bound, text in _sweep(monkeypatch, wire):
        assert _core(state, text), bound
        if full in text or short in text:
            seen_cause = True
            seen_cause_alone |= all(marker not in text for marker, _ in boilerplates)
            continue
        for marker, extra in boilerplates:
            if marker in text:
                # Without that sentence the short form still would not have fit.
                assert len(text) - extra + 1 + len(short) > bound, (bound, marker)
    assert seen_cause and seen_cause_alone


@pytest.mark.parametrize(("state", "cause", "lead"), _CASES)
def test_a_malformed_cause_adds_nothing_and_a_crashing_one_is_named(
    monkeypatch: pytest.MonkeyPatch, state: str, cause: dict[str, Any], lead: str
) -> None:
    for broken in (
        {**cause, "effect": "never_heard_of_it"},
        {**cause, "ledger_sequence": 12},
        {**cause, "tool": 7},
        {**cause, "rule": "café"},
        {"effect": "superseded"},
        "not a mapping",
    ):
        text = render_safe_compact_summary(_wire(state=state, view="compact", cause=broken))
        assert "Why check_" not in text and "Closure: " + state in text, broken
    absent = render_safe_compact_summary(_wire(state=state, view="compact", cause=None))
    assert "Why check_" not in absent

    def explode(**_kwargs: object) -> str:
        raise RuntimeError("cause-defect")

    monkeypatch.setattr(summaries, "check_cause_sentence", explode)
    rendered = render_safe_compact_summary_detailed(_wire(state=state, view="compact", cause=cause))
    assert "summary_render_failed:status.check_cause" in rendered.text
    assert "Closure: " + state in rendered.text and "Why check_" not in rendered.text
    assert [site for site, _ in rendered.failures] == ["status.check_cause"]
