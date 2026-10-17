"""Offline evaluation set for the reviewer's standing instruction (issue #1082).

The N6 D-lane audit investigated ten reviewer misses plus one hidden-verifier case. In nine of the
ten, the decisive material was in the packet, and the reviewer reasoned inside the agent's premise,
method or self-written validator. ``tests/fixtures/reviewer_accuracy/n6_cases.json`` binds each
case to the lens or section of the instruction that targets it and to the exact directive
sentences that should have caught it. These tests make no provider call. They prove only that the
instruction carries each directive where the case says, not that a model follows it; a live replay
is the separate procedure in ``docs/runbooks/reviewer-instruction-evaluation.md``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.providers.openai_chat_completions import CHAT_COMPLETIONS_INSTRUCTION
from finishup.adapters.providers.openai_responses import (
    REVIEWER_GROUNDING_RULES,
    REVIEWER_LENSES,
    SEMANTIC_REVIEW_INSTRUCTION,
)

_FIXTURE = Path(__file__).resolve().parents[3] / "fixtures" / "reviewer_accuracy" / "n6_cases.json"
_CASES = cast(list[dict[str, object]], json.loads(_FIXTURE.read_text("utf-8"))["cases"])

# The instruction sections a case may name besides the lenses, by their heading.
_SECTIONS = {
    "procedure": "How to review",
    "grounding": "Ground every conclusion",
    "missing_content": "Missing content",
    "earlier_findings": "Earlier findings",
}

# The lens or section that must answer each class of miss. A case is covered when its declared
# lenses include at least one of these for its primary miss.
_MISS_TARGETS = {
    "adopted_agent_premise": {"premise", "blockers"},
    "boundary_not_tested": {"boundaries"},
    "trusted_agent_validator": {"own_checks"},
    "adopted_agent_method": {"method"},
    "environment_portability": {"environment"},
    "numeric_plausibility": {"numbers"},
    "insufficient_packet_suppressed_visible_defect": {"missing_content"},
    "ungrounded_reassurance": {"grounding"},
    "hidden_verifier_quirk": {"grounding"},
}


def _collapsed(text: str) -> str:
    return " ".join(text.split())


def _section_text(heading: str) -> str:
    marker = f"## {heading}\n"
    start = SEMANTIC_REVIEW_INSTRUCTION.index(marker)
    end = SEMANTIC_REVIEW_INSTRUCTION.find("\n## ", start + len(marker))
    return SEMANTIC_REVIEW_INSTRUCTION[start : None if end < 0 else end]


def _target_text(target: str) -> str:
    if target in REVIEWER_LENSES:
        return REVIEWER_LENSES[target]
    return _section_text(_SECTIONS[target])


def _case_ids() -> list[str]:
    return [cast(str, case["case"]) for case in _CASES]


def test_the_evaluation_set_is_the_investigated_cases() -> None:
    assert len(_CASES) == 11
    assert len(set(_case_ids())) == 11
    hidden = [case["case"] for case in _CASES if case["reviewer_detectable"] is False]
    # Only the hidden-verifier case was beyond any packet; the other ten were reviewable.
    assert hidden == ["music-harmony"]
    detectable = [case for case in _CASES if case["reviewer_detectable"] is True]
    with_material = [case for case in detectable if case["decisive_material_in_packet"] != "no"]
    assert len(with_material) == len(detectable) == 10


@pytest.mark.parametrize("case", _CASES, ids=_case_ids())
def test_each_case_names_a_lens_that_targets_its_miss(case: dict[str, object]) -> None:
    lenses = set(cast(list[str], case["lenses"]))
    known = set(REVIEWER_LENSES) | set(_SECTIONS)
    assert lenses and lenses <= known, lenses - known
    assert lenses & _MISS_TARGETS[cast(str, case["miss"])], case["miss"]
    for secondary in cast(list[str], case["secondary"]):
        assert secondary in _MISS_TARGETS, secondary


@pytest.mark.parametrize("case", _CASES, ids=_case_ids())
def test_each_directive_is_in_the_instruction_under_a_named_lens(case: dict[str, object]) -> None:
    whole = _collapsed(SEMANTIC_REVIEW_INSTRUCTION)
    targets = cast(list[str], case["lenses"])
    for directive in cast(list[str], case["directives"]):
        assert _collapsed(directive) in whole, directive
        assert any(_collapsed(directive) in _collapsed(_target_text(t)) for t in targets), directive
    # Every provider path sends the same bytes.
    assert CHAT_COMPLETIONS_INSTRUCTION.startswith(SEMANTIC_REVIEW_INSTRUCTION)


def test_every_lens_is_used_and_carries_a_failure_example() -> None:
    used = {lens for case in _CASES for lens in cast(list[str], case["lenses"])}
    assert set(REVIEWER_LENSES) <= used
    for name, text in REVIEWER_LENSES.items():
        # A judgment lesson that cannot be encoded as a check gets a failure example.
        assert "Example: " in text, name
        assert _collapsed(text) in _collapsed(_section_text("Lenses")), name


def test_the_procedure_precedes_the_reference_material() -> None:
    order = [
        SEMANTIC_REVIEW_INSTRUCTION.index(f"## {heading}\n")
        for heading in (
            "Read the task first",
            "How to review",
            "Lenses",
            "Ground every conclusion",
            "Missing content",
            "Reading the packet",
        )
    ]
    assert order == sorted(order)
    assert SEMANTIC_REVIEW_INSTRUCTION.startswith("You are a verifying reviewer")
    for rule in REVIEWER_GROUNDING_RULES:
        assert rule in _section_text("Ground every conclusion")


def test_the_instruction_names_no_evaluation_case() -> None:
    """The directives are generic: the instruction is never fitted to the evaluation set."""

    text = SEMANTIC_REVIEW_INSTRUCTION.casefold()
    for case in _case_ids():
        assert case not in text, case
    # The distinctive domain word of each case; generic words such as "dispatch" or "filter"
    # are ordinary review vocabulary.
    for term in (
        "atrx",
        "crispr",
        "vep",
        "biped",
        "cargo",
        "fuel",
        "foodstuff",
        "becquerel",
        "gsea",
        "proteom",
        "htmlparser",
        "vigenere",
        "harmony",
        "roman numeral",
        "polymorph",
        "wavenumber",
    ):
        assert term not in text, term
