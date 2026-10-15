"""Snapshot of the reviewer's task-statement rule (issue #908).

The instruction is pinned byte for byte: the reviewer reads the task statement as the
specification, never asks for behaviour the statement excludes (the termenv Ascii tail), cites
the statement for an omitted requirement, and weighs an agent-transcribed statement as the
agent's account. Every adapter that composes its own system instruction carries the same rule.
"""

from __future__ import annotations

from finishup.adapters.providers import openai_chat_completions
from finishup.adapters.providers.openai_responses import (
    SEMANTIC_REVIEW_INSTRUCTION,
    TASK_STATEMENT_REVIEW_INSTRUCTION,
)

_EXPECTED = (
    "The task_statement section, when present, is the specification: what the user asked for. "
    "Items in the goal section are the agent plan (the agent's own summary), never the user's "
    "request. When they differ, the task statement wins over the plan. A plan or diff that omits "
    "or contradicts a stated requirement is a material discrepancy; cite the task statement's "
    "source ref when it is citable. Never request behaviour the task statement excludes, and do "
    "not fill a gap in the statement with general expectations it does not state. Weigh a "
    "statement whose source is agent_transcribed as the agent's account of the request, and one "
    "whose source is task_title_only as a title, not a specification. Without a task statement, "
    "say that the user's request was unavailable rather than treating the plan as the request."
)


def test_task_statement_rule_is_pinned() -> None:
    assert TASK_STATEMENT_REVIEW_INSTRUCTION == _EXPECTED


def test_every_system_instruction_carries_the_rule_unchanged() -> None:
    assert SEMANTIC_REVIEW_INSTRUCTION.endswith(" " + _EXPECTED)
    assert SEMANTIC_REVIEW_INSTRUCTION.count(_EXPECTED) == 1
    chat = getattr(openai_chat_completions, "_SYSTEM_INSTRUCTION")
    assert type(chat) is str
    assert chat.count(_EXPECTED) == 1


def test_rule_forbids_the_termenv_style_contradiction() -> None:
    # The E1 finding asked for an Ascii tail the user excluded; the rule names that case.
    assert "Never request behaviour the task statement excludes" in _EXPECTED
    assert "the task statement wins over the plan" in _EXPECTED
    assert "agent plan (the agent's own summary)" in _EXPECTED
    assert "agent_transcribed" in _EXPECTED
