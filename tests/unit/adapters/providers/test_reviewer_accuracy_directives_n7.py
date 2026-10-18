"""Offline evaluation cases for the n7 reviewer misses (issue #1108) and #1094 R2-N1.

``tests/fixtures/reviewer_accuracy/n7_cases.json`` binds each pattern to the instruction section
or lens that targets it and to the exact directive sentences: a reviewer that abstained on a
check's observed output, re-listed an item the next packet supplied, deferred to a disclosure the
packet's own material contradicted, or raised a delivery risk on an input the task supplies.
These tests make no provider call; they prove only that the instruction carries each directive
where the case says. A live replay is ``docs/runbooks/reviewer-instruction-evaluation.md``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.providers.openai_chat_completions import CHAT_COMPLETIONS_INSTRUCTION
from finishup.adapters.providers.openai_responses import (
    REVIEWER_LENSES,
    SEMANTIC_REVIEW_INSTRUCTION,
)

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "reviewer_accuracy"
_DOCUMENT = cast(dict[str, object], json.loads((_FIXTURES / "n7_cases.json").read_text("utf-8")))
_CASES = cast(list[dict[str, object]], _DOCUMENT["cases"])
_N6_CASES = cast(
    list[dict[str, object]],
    json.loads((_FIXTURES / "n6_cases.json").read_text("utf-8"))["cases"],
)

_SECTIONS = {
    "grounding": "Ground every conclusion",
    "review_phase": "Review phase",
    "reading_the_packet": "Reading the packet",
}

_MISS_TARGETS = {
    "abstained_on_observed_output": {"grounding", "own_checks"},
    "relisted_supplied_material": {"reading_the_packet"},
    "deferred_to_disclosure": {"review_phase", "blockers"},
    "delivery_risk_on_correct_work": {"environment"},
    "trusted_agent_validator": {"own_checks"},
    "adopted_agent_premise": {"blockers"},
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


def test_the_set_shares_the_n6_schema_and_names_new_cases() -> None:
    assert _DOCUMENT["schema"] == "finishup.test.reviewer-accuracy-cases/1"
    assert len(set(_case_ids())) == len(_CASES) == 4
    assert not set(_case_ids()) & {cast(str, case["case"]) for case in _N6_CASES}
    # Every n7 miss had the decisive fact in the packet: the reviewer judged wrongly with it.
    assert all(case["decisive_material_in_packet"] == "yes" for case in _CASES)


@pytest.mark.parametrize("case", _CASES, ids=_case_ids())
def test_each_case_names_a_target_for_its_miss(case: dict[str, object]) -> None:
    lenses = set(cast(list[str], case["lenses"]))
    assert lenses and lenses <= set(REVIEWER_LENSES) | set(_SECTIONS), lenses
    assert lenses & _MISS_TARGETS[cast(str, case["miss"])], case["miss"]
    for secondary in cast(list[str], case["secondary"]):
        assert secondary in _MISS_TARGETS, secondary


@pytest.mark.parametrize("case", _CASES, ids=_case_ids())
def test_each_directive_is_in_the_instruction_under_a_named_target(case: dict[str, object]) -> None:
    whole = _collapsed(SEMANTIC_REVIEW_INSTRUCTION)
    targets = cast(list[str], case["lenses"])
    for directive in cast(list[str], case["directives"]):
        assert _collapsed(directive) in whole, directive
        assert any(_collapsed(directive) in _collapsed(_target_text(t)) for t in targets), directive
    assert CHAT_COMPLETIONS_INSTRUCTION.startswith(SEMANTIC_REVIEW_INSTRUCTION)


def test_every_n6_directive_still_holds() -> None:
    """The n7 rewrites keep each sentence the N6 evaluation set pins (issue #1082)."""

    whole = _collapsed(SEMANTIC_REVIEW_INSTRUCTION)
    for case in _N6_CASES:
        for directive in cast(list[str], case["directives"]):
            assert _collapsed(directive) in whole, directive


def test_the_instruction_names_no_n7_case() -> None:
    text = SEMANTIC_REVIEW_INSTRUCTION.casefold()
    for case in _case_ids():
        assert case not in text, case
    for term in ("max_err", "currencies", "daily rates", "212 passed", "/tmp"):
        assert term not in text, term
