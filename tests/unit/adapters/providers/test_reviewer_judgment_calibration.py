"""Offline TB4 judgment calibration: directives and wire handling, never model-quality claims."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from finishup.adapters.providers.openai_chat_completions import CHAT_COMPLETIONS_INSTRUCTION
from finishup.adapters.providers.openai_responses import (
    REVIEWER_ACCEPTANCE_INSTRUCTION,
    REVIEWER_JUDGMENT_CALIBRATION,
    SEMANTIC_REVIEW_INSTRUCTION,
    normalize_judgment,
)
from finishup.adapters.providers.reviewer_reply import REVIEWER_LOOP_INSTRUCTION
from finishup.application.semantic_case import REVIEW_PHASE_QUESTIONS, review_question_set
from finishup.domain.findings import FindingKind

_FIXTURE = (
    Path(__file__).resolve().parents[3] / "fixtures/reviewer_accuracy/tb4_judgment_cases.json"
)
_DATA: dict[str, Any] = json.loads(_FIXTURE.read_text())
_TEXT = " ".join(SEMANTIC_REVIEW_INSTRUCTION.split())


@pytest.mark.parametrize("case", _DATA["cases"], ids=lambda case: case["case"])
def test_each_investigated_judgment_pattern_has_its_calibration_directive(
    case: dict[str, Any],
) -> None:
    for directive in case["directives"]:
        assert directive in _TEXT
    assert CHAT_COMPLETIONS_INSTRUCTION.startswith(SEMANTIC_REVIEW_INSTRUCTION)
    assert REVIEWER_JUDGMENT_CALIBRATION in REVIEWER_LOOP_INSTRUCTION
    assert REVIEWER_ACCEPTANCE_INSTRUCTION in REVIEWER_LOOP_INSTRUCTION


@pytest.mark.parametrize("boundary", _DATA["acceptance_boundaries"].values())
def test_closing_review_challenges_the_decisive_measurement(boundary: str) -> None:
    assert boundary in _TEXT
    assert "strongest evidence gap and one cheap discriminating check" in _TEXT
    assert "A gap alone is not proof of failure" in _TEXT
    assert "decisive measurement or assumption" in REVIEW_PHASE_QUESTIONS["final"]
    assert "gap alone is not proof of failure" in REVIEW_PHASE_QUESTIONS["final"]


def test_input_root_instruction_preserves_owner_admission() -> None:
    assert "task-declared input paths beneath roots the owner already admitted" in _TEXT
    assert "use those aliases and declared paths" in _TEXT
    assert "not permission to read another root" in _TEXT
    assert "ask the agent to copy it into scope" in _TEXT


def test_test_quality_advice_preserves_optional_discriminating_checks() -> None:
    # The always-sent instructions carry none of the #1170 rules (the #1173 read budget); the
    # discriminating-check summary rule rides the test-quality question with the manifest rules.
    assert REVIEWER_ACCEPTANCE_INSTRUCTION in REVIEWER_LOOP_INSTRUCTION
    assert CHAT_COMPLETIONS_INSTRUCTION.startswith(SEMANTIC_REVIEW_INSTRUCTION)
    for instruction in (REVIEWER_LOOP_INSTRUCTION, SEMANTIC_REVIEW_INSTRUCTION):
        assert "Discriminating check" not in instruction
        assert "agent-declared manifest" not in instruction
        # #1145: the linked-check rule rides the question too, so the cached prefix is unchanged.
        assert "Counter-example" not in instruction
    question = " ".join(review_question_set("final", test_manifests=True)[-1].split())
    for rule in (
        "begin the first line of review_summary with 'Discriminating check: <one concrete check>'",
        "message_to_main_agent ending 'Counter-example: <an input or probe to run>'",
        "do not invent a test when no useful discriminator exists",
        "an agent-declared manifest is not independent proof",
        "any expected value copied from the answer",
    ):
        assert rule in question


def test_active_challenge_rule_does_not_turn_an_advisory_choice_into_a_repair() -> None:
    """#1151 review: the compact core must agree with the appended calibration rules."""

    constraints = " ".join(
        REVIEWER_LOOP_INSTRUCTION.partition("## Constraints\n")[2].partition("\n## ")[0].split()
    )
    assert "For decision_needed, present a choice, never a repair." in constraints
    assert "Otherwise name the repair or exact missing artifact." in constraints
    assert "Up to 3 distinct challenges." in constraints
    assert "each telling the agent the repair" not in constraints


def test_decision_needed_normalizes_through_the_shared_provider_contract() -> None:
    judgment = normalize_judgment(
        {
            "judgment": {
                "conclusion": "challenges_returned",
                "review_summary": "Choose the reference.",
                "verified": [],
                "prior_finding_verdicts": [],
                "missing_for_assessment": [],
                "reviewer_challenges": [
                    {
                        "finding_kind": "decision_needed",
                        "summary": "Conflicting reference models",
                        "cited_refs": ["obl_00000000-0000-4000-8000-000000000001"],
                        "discrepancy": "Task wording supports the longer model.",
                        "alternative_interpretation": "The supplied file supports the shorter model.",
                        "message_to_main_agent": "Destructive change: replacing the supplied reference loses its passing check. Compare both models with the validator; you decide and record it with respond.",
                        "requested_next_step": "answer_question",
                        "uncertainty": "Both models are plausible.",
                        "snippet": "The supplied file supports the shorter model.",
                        "restates": None,
                    }
                ],
            }
        }
    )
    assert judgment.challenges[0].finding_kind is FindingKind.DECISION_NEEDED
    assert judgment.challenges[0].requested_next_step == "answer_question"
    assert judgment.challenges[0].message_to_main_agent.startswith("Destructive change:")
