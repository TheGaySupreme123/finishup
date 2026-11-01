"""tb4n3 RC-5 (#1028) x RC-2 (#1025) x RC-6 (#1029): the "Why" of a derived fact in the bounded text.

Provenance. Lane LF added ``fact_lineage`` (ADR-045) and appended its first sentence to the MCP
status text by string concatenation; lane LB rebuilt every summary on the bounded composer, and
lane LO added the ``check_cause`` lineage of the check's applicability. This file locks the merged
order of the status text: core (view and frontier, the closure state, the stop instruction, the
agent-actionable items) first; then the cause; then the fact's "Why"; then every boilerplate
sentence. The "Why" is optional, so a tight bound drops it before anything required or the cause,
and the check text keeps its verdict, next instruction and frontier whatever the lineage costs.
"""

# pyright: reportPrivateUsage=false
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from builders.status_text import (
    BOUNDING,
    HEAD,
    SUPERSEDED,
    VIEWS,
    emptied_lineage,
    matched_by_prefix_lineage,
    status_wire,
)
from finishup.kernel.fact_lineage import lineage_text, lineage_to_wire
from finishup.mcp import summaries
from finishup.mcp.summaries import (
    _check_cause_variants,
    _operation_progress_clause,
    render_safe_compact_summary,
    render_safe_compact_summary_detailed,
    summary_for_check,
)
from finishup.protocol.readiness_text import readiness_directive

EMPTIED = lineage_text(emptied_lineage())
PREFIX = lineage_text(matched_by_prefix_lineage())
_STOP = "Request the receipt."
_SHORT_STOP = "Nothing further to do. Request the receipt."
_COUNTS_SENTENCE = "will be disclosed on the receipt"
_OPERATION_FALLBACK = "semantic progress: see structured page;"

# (readiness state, the cause beside it, the derived-fact lineage, the tokens the text lists)
_CASES = [
    pytest.param(
        "action_required",
        SUPERSEDED,
        emptied_lineage,
        EMPTIED,
        id="emptied-deliverable",
    ),
    pytest.param(
        "ready_with_limitations",
        BOUNDING,
        matched_by_prefix_lineage,
        PREFIX,
        id="prefix-matched-command",
    ),
]


def _wire(state: str, view: str, cause: Any, fact: Any) -> dict[str, Any]:
    if state == "action_required":
        return status_wire(
            state=state,
            view=view,
            cause=cause,
            lineage=[fact()],
            actionable=["check_not_applicable", "declared_output_emptied"],
        )
    return status_wire(
        state=state,
        view=view,
        cause=cause,
        lineage=[fact()],
        standing=["check_current_as_of_earlier_frontier", "planned_verification_matched_by_prefix"],
    )


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


@pytest.mark.parametrize("view", VIEWS)
@pytest.mark.parametrize(("state", "cause", "fact", "why"), _CASES)
def test_every_status_view_says_why_the_listed_fact_fired_at_the_real_bound(
    state: str, cause: dict[str, Any], fact: Any, why: str, view: str
) -> None:
    wire = _wire(state, view, cause, fact)
    text = render_safe_compact_summary(wire)
    full, _ = _check_cause_variants(wire)
    assert text.isascii() and _core(state, text)
    # Both lineages travel: the cause of the check's applicability, then the fact's provenance.
    assert full in text and why in text
    assert text.index("Closure: ") < text.index(full) < text.index(why)


@pytest.mark.parametrize("view", VIEWS)
@pytest.mark.parametrize(("state", "cause", "fact", "why"), _CASES)
def test_the_fact_why_ranks_between_the_cause_and_the_boilerplate_at_every_bound(
    monkeypatch: pytest.MonkeyPatch,
    state: str,
    cause: dict[str, Any],
    fact: Any,
    why: str,
    view: str,
) -> None:
    """Sweep every bound from the real size down to the composer's last-resort cut.

    Core is present at every bound; the fact's "Why" never appears without the cause beside it
    (it is granted after the cause); and a boilerplate sentence (the generic closure sentence, the
    counts sentence of the full directive, the operation-progress text) is present beside a missing
    "Why" only when the "Why" could not have fit even without that sentence."""

    wire = _wire(state, view, cause, fact)
    full, short = _check_cause_variants(wire)
    # (marker found in the text, characters the sentence adds beyond what core already holds)
    boilerplates: list[tuple[str, int]] = []
    if state == "ready_with_limitations":
        counts = readiness_directive(state, standing=2, acknowledged="0")
        boilerplates.append((_COUNTS_SENTENCE, len(counts) - len(_SHORT_STOP)))
    else:
        generic = readiness_directive(state)
        boilerplates.append((generic, len(generic) + 1))
    if view == "operation":
        progress = _operation_progress_clause(wire).strip()
        boilerplates.append(("operation state:", len(progress) - len(_OPERATION_FALLBACK)))

    seen_why = seen_why_without_boilerplate = seen_cause_without_why = False
    for bound, text in _sweep(monkeypatch, wire):
        assert _core(state, text), bound
        has_cause = full in text or short in text
        if why in text:
            seen_why = True
            assert has_cause, bound  # the "Why" is granted after the cause
            seen_why_without_boilerplate |= all(marker not in text for marker, _ in boilerplates)
            continue
        seen_cause_without_why |= has_cause
        for marker, extra in boilerplates:
            if marker in text:
                # Without that sentence the "Why" still would not have fit.
                assert len(text) - extra + 1 + len(why) > bound, (bound, marker)
    # The whole range was visited: the "Why" is there at the real bound, goes before the cause,
    # and was kept at some bound that had already dropped the boilerplate.
    assert seen_why and seen_cause_without_why and seen_why_without_boilerplate


@pytest.mark.parametrize(("state", "cause", "fact", "why"), _CASES)
def test_a_tight_bound_drops_the_fact_why_before_the_cause_and_the_core(
    monkeypatch: pytest.MonkeyPatch, state: str, cause: dict[str, Any], fact: Any, why: str
) -> None:
    wire = _wire(state, "compact", cause, fact)
    real = render_safe_compact_summary(wire)
    full, short = _check_cause_variants(wire)
    assert why in real and full in real

    tight = _at(monkeypatch, 512, wire)
    assert len(tight) <= 512 and tight.isascii()
    assert _core(state, tight)
    assert "Status view: compact; frontier: 9; head_digest: " + HEAD in tight
    assert why not in tight
    assert short in tight  # the cause outlives the "Why": only its short form fits


def test_a_fact_without_a_cause_still_says_why_and_never_displaces_the_stop_instruction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wire = status_wire(
        state="ready_with_limitations",
        view="project",
        lineage=[matched_by_prefix_lineage()],
        standing=["planned_verification_matched_by_prefix"],
    )
    assert PREFIX in render_safe_compact_summary(wire)
    with_why = [(bound, text) for bound, text in _sweep(monkeypatch, wire) if PREFIX in text]
    assert with_why
    for bound, text in _sweep(monkeypatch, wire):
        assert _core("ready_with_limitations", text), bound
    # The smallest bound that shows the "Why" carries the short stop instruction, not the counts.
    witness = min(with_why)[1]
    assert _SHORT_STOP in witness and _COUNTS_SENTENCE not in witness


@pytest.mark.parametrize("state", ("action_required", "ready_with_limitations"))
def test_a_malformed_lineage_adds_nothing_and_a_crashing_one_is_named(
    monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    for broken in (
        [{"code": "declared_output_emptied"}],
        ["not a mapping", 7, None],
        [{**lineage_to_wire(emptied_lineage()), "rule": "unknown_rule"}],
        "not a list",
    ):
        wire = status_wire(state=state, view="compact")
        wire["closure_readiness"]["fact_lineage"] = broken
        text = render_safe_compact_summary(wire)
        assert "Why: " not in text and f"Closure: {state}." in text, broken
    no_lineage = render_safe_compact_summary(status_wire(state=state, view="compact"))
    assert "Why: " not in no_lineage

    def explode(*_args: object, **_kwargs: object) -> tuple[str, ...]:
        raise RuntimeError("lineage-defect")

    monkeypatch.setattr(summaries, "lineage_texts", explode)
    rendered = render_safe_compact_summary_detailed(
        status_wire(state=state, view="compact", lineage=[emptied_lineage()])
    )
    assert "summary_render_failed:status.fact_lineage" in rendered.text
    assert f"Closure: {state}." in rendered.text and "Why: " not in rendered.text
    assert [site for site, _ in rendered.failures] == ["status.fact_lineage"]


def _check_envelope(**extra: Any) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "verdict": "insufficient_coverage",
        "findings": [],
        "suppressed_count": "0",
        "semantic_status": "not_requested",
        "semantic_reason": "deterministic_mode",
        "result_frontier": {"sequence": "351", "head_digest": HEAD},
        "coverage": {"known_gaps": ["declared_output_emptied", "semantic_review_not_requested"]},
        "fact_lineage": [lineage_to_wire(emptied_lineage())],
    }
    envelope.update(extra)
    return envelope


def test_the_check_text_says_why_beside_the_gap_it_reports_and_keeps_its_core_when_tight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = _check_envelope()
    text = summary_for_check(envelope)
    assert EMPTIED in text and text.isascii()
    assert "frontier: 351; head_digest: " + HEAD in text

    with monkeypatch.context() as patch:
        patch.setattr(summaries, "_MAX_SUMMARY_BYTES", 512)
        tight = summary_for_check(envelope)
    assert len(tight) <= 512 and EMPTIED not in tight
    assert "frontier: 351; head_digest: " + HEAD in tight
    assert "insufficient_coverage" in tight

    # Provenance for a fact the check does not report is not shown.
    quiet = _check_envelope(coverage={"known_gaps": ["semantic_review_not_requested"]})
    assert EMPTIED not in summary_for_check(quiet)
    # An unreadable lineage adds nothing and costs nothing.
    broken = summary_for_check(_check_envelope(fact_lineage=[{"code": "declared_output_emptied"}]))
    assert "Why: " not in broken and "insufficient_coverage" in broken
