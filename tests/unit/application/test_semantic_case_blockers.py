"""The closing review's blocker question stays bounded and names only ids (#976, #977)."""

from __future__ import annotations

from finishup.application.semantic_case import (
    MAX_REVIEWED_BLOCKERS,
    REVIEW_PHASE_QUESTIONS,
    review_question_set,
)
from finishup.protocol.models import MAX_REVIEW_TEXT_BYTES


def _ids(prefix: str, count: int, offset: int = 0) -> tuple[str, ...]:
    return tuple(
        f"{prefix}_97600000-0000-4000-8000-{offset + index:012d}" for index in range(count)
    )


def test_only_the_final_phase_asks_about_blockers() -> None:
    blockers = (("evt_97600000-0000-4000-8000-000000000001", "consent", _ids("obl", 1)),)
    assert review_question_set("routine", blockers) == review_question_set("routine")
    final = review_question_set("final", blockers)
    assert final[:-1] == review_question_set("final")
    assert final[0] == REVIEW_PHASE_QUESTIONS["final"]
    assert final[-1].startswith("Recorded blockers: decision evt_")
    assert "finishup-blocker:consent" in final[-1]
    assert "citable_refs" in final[-1]


def test_the_blocker_question_stays_within_the_review_text_bound() -> None:
    decisions = _ids("evt", 40)
    blockers = tuple(
        (decision, "dependency_unavailable", _ids("obl", 64, offset=1000 * (index + 1)))
        for index, decision in enumerate(decisions)
    )
    question = review_question_set("final", blockers)[-1]
    assert len(question.encode("utf-8")) < MAX_REVIEW_TEXT_BYTES * 3 // 4
    assert "(+56 more)" in question
    assert "more blocker decisions)" in question
    assert question.count("declares finishup-blocker:") <= MAX_REVIEWED_BLOCKERS


def test_a_genuine_credential_blocker_on_the_main_deliverable_may_stand() -> None:
    """#978: the main deliverable calls for scrutiny, not an automatic challenge. A recoverable
    outcome or an unattempted prerequisite forces one; a genuine credential blocker may stand."""

    from finishup.adapters.providers.openai_responses import SEMANTIC_REVIEW_INSTRUCTION
    from finishup.application.semantic_case import BLOCKER_REVIEW_INSTRUCTION

    blockers = (("evt_97800000-0000-4000-8000-000000000001", "credential", _ids("obl", 1)),)
    question = review_question_set("final", blockers)[-1]
    assert question.endswith(BLOCKER_REVIEW_INSTRUCTION)
    forced, _, rest = BLOCKER_REVIEW_INSTRUCTION.partition("When the blocked obligation is")
    assert "main deliverable" not in forced
    assert "the data recoverable" in forced
    assert "has not attempted the obvious prerequisite" in forced
    assert "scrutinise the blocker closely" in rest
    assert "(authority, consent, a credential" in rest
    assert "stands as a disclosed limitation even then" in rest
    # The provider instruction says the same and never forces a challenge on the deliverable.
    assert (
        "required, not optional, when the blocked obligation is" not in SEMANTIC_REVIEW_INSTRUCTION
    )
    assert "main deliverable deserves close scrutiny" in SEMANTIC_REVIEW_INSTRUCTION
    assert "stays a disclosed limitation even there" in SEMANTIC_REVIEW_INSTRUCTION
