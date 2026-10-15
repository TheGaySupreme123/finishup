"""#997 review follow-ups: the closing review and publish refusals for acknowledged obligations."""

from __future__ import annotations

from finishup.application.publish_work import _event_invalid  # pyright: ignore[reportPrivateUsage]
from finishup.application.semantic_case import review_question_set

_OBLIGATION = "obl_00000000-0000-4000-8000-000000000001"


def test_the_closing_review_tests_an_acknowledged_obligation_against_the_task() -> None:
    final = review_question_set("final", (), (_OBLIGATION,))
    question = final[-1]
    assert f"Obligations acknowledged as not done: {_OBLIGATION}" in question
    assert "challenge it" in question
    # The routine phase never judges it, and nothing is asked without one.
    assert not any(
        _OBLIGATION in item for item in review_question_set("routine", (), (_OBLIGATION,))
    )
    assert len(review_question_set("final")) == len(final) - 1


def test_a_wrong_obligation_version_names_the_1_1_0_correction() -> None:
    error = _event_invalid(
        "invalid_event_schema", event_index=0, schema_name="obligation_published"
    )
    # Issue #1023: 1.1.0 is a superset, so the hint names it as always safe for any obligation.
    assert "obligation_published/1.0.0 cannot carry" in error.message
    assert "obligation_published/1.1.0" in error.message
    assert "1.1.0 is always safe" in error.message
