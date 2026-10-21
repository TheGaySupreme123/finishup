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
from finishup.application.semantic_case import REVIEW_PHASE_QUESTIONS
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
