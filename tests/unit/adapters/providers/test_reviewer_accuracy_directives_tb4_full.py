"""Offline evaluation cases for the TB4 full-sol reviewer misses (issue #1245).

``tests/fixtures/reviewer_accuracy/tb4_full_cases.json`` binds two patterns to the exact directive
sentences that target them, in the packet-only instruction, the reviewer-loop instruction every
review uses, and the closing review's acknowledged-obligation question: a review that agreed a
requested output should be withheld because two supplied inputs conflicted, and advice to test a
boundary value the visible interface cannot reach. These tests make no provider call; they prove
only that each directive is present where the case says. A live replay is
``docs/runbooks/reviewer-instruction-evaluation.md``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.providers.openai_responses import (
    REVIEWER_LENSES,
    SEMANTIC_REVIEW_INSTRUCTION,
)
from finishup.adapters.providers.reviewer_reply import REVIEWER_LOOP_INSTRUCTION
from finishup.application.semantic_case import ACKNOWLEDGED_REVIEW_INSTRUCTION

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "reviewer_accuracy"
_DOCUMENT = cast(
    dict[str, object], json.loads((_FIXTURES / "tb4_full_cases.json").read_text("utf-8"))
)
_CASES = cast(list[dict[str, object]], _DOCUMENT["cases"])
_SECTIONS = {"procedure": "How to review"}


def _collapsed(text: str) -> str:
    return " ".join(text.split())


def _target_text(target: str) -> str:
    if target in REVIEWER_LENSES:
        return REVIEWER_LENSES[target]
    marker = f"## {_SECTIONS[target]}\n"
    start = SEMANTIC_REVIEW_INSTRUCTION.index(marker)
    end = SEMANTIC_REVIEW_INSTRUCTION.find("\n## ", start + len(marker))
    return SEMANTIC_REVIEW_INSTRUCTION[start : None if end < 0 else end]


def _case_ids() -> list[str]:
    return [cast(str, case["case"]) for case in _CASES]


def test_the_set_shares_the_schema_and_names_new_cases() -> None:
    assert _DOCUMENT["schema"] == "finishup.test.reviewer-accuracy-cases/1"
    assert len(set(_case_ids())) == len(_CASES) == 2
    earlier = {
        cast(str, case["case"])
        for name in ("n6_cases.json", "n7_cases.json")
        for case in json.loads((_FIXTURES / name).read_text("utf-8"))["cases"]
    }
    assert not set(_case_ids()) & earlier
    assert all(case["decisive_material_in_packet"] == "yes" for case in _CASES)


@pytest.mark.parametrize("case", _CASES, ids=_case_ids())
def test_each_directive_is_in_the_packet_only_instruction_under_its_target(
    case: dict[str, object],
) -> None:
    whole = _collapsed(SEMANTIC_REVIEW_INSTRUCTION)
    targets = cast(list[str], case["lenses"])
    for directive in cast(list[str], case["directives"]):
        assert _collapsed(directive) in whole, directive
        assert any(_collapsed(directive) in _collapsed(_target_text(t)) for t in targets), directive


@pytest.mark.parametrize("case", _CASES, ids=_case_ids())
def test_each_loop_directive_is_in_the_instruction_every_review_uses(
    case: dict[str, object],
) -> None:
    """#1245: the loop instruction had dropped both rules the packet-only instruction states."""

    loop = _collapsed(REVIEWER_LOOP_INSTRUCTION)
    directives = cast(list[str], case["loop_directives"])
    assert directives
    for directive in directives:
        assert _collapsed(directive) in loop, directive
    assert cast(str, case["case"]) not in loop.casefold()


@pytest.mark.parametrize("case", _CASES, ids=_case_ids())
def test_each_closing_question_directive_is_in_the_acknowledged_question(
    case: dict[str, object],
) -> None:
    question = _collapsed(ACKNOWLEDGED_REVIEW_INSTRUCTION)
    for directive in cast(list[str], case["acknowledged_directives"]):
        assert _collapsed(directive) in question, directive
    assert cast(str, case["case"]) not in question.casefold()


def test_the_instructions_name_no_case_and_no_paraphrased_task() -> None:
    for text in (SEMANTIC_REVIEW_INSTRUCTION, REVIEWER_LOOP_INSTRUCTION):
        folded = text.casefold()
        for case in _case_ids():
            assert case not in folded, case
        for term in ("exon", "transcript", "annotation cache", "token budget"):
            assert term not in folded, term
