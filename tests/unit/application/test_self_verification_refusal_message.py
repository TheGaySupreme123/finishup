"""tb4n2 R5 (issue #1023): a ``self_verified`` refusal names its blocking reasons and the exits."""

from __future__ import annotations

import unicodedata

from finishup.application.respond import self_verification_refusal_message
from finishup.domain.findings import FindingOrigin
from finishup.kernel.self_verification import NO_RECORDED_LIMIT, disqualifying_reasons

_MESSAGE_BOUND_BYTES = 4096


def _assert_bounded(message: str) -> None:
    assert len(message.encode("utf-8")) <= _MESSAGE_BOUND_BYTES
    assert not any(unicodedata.category(character) == "Cc" for character in message)


def test_the_disqualifying_reasons_are_the_recorded_tokens_in_order() -> None:
    reasons = (
        "coverage:content_redacted",
        "issue_returned_again",
        "coverage:completion_plan_not_claimed",
        "issue_returned_again",
    )
    blocking = disqualifying_reasons(reasons, FindingOrigin.DETERMINISTIC)
    # Standing FinishUP limits are not blocking; duplicates collapse in recorded order.
    assert blocking == ("issue_returned_again", "coverage:completion_plan_not_claimed")
    assert disqualifying_reasons((), FindingOrigin.DETERMINISTIC) == (NO_RECORDED_LIMIT,)
    assert disqualifying_reasons(("coverage:content_redacted",), FindingOrigin.DETERMINISTIC) == ()


def test_the_message_names_the_tokens_a_next_step_per_family_and_the_limit_exit() -> None:
    message = self_verification_refusal_message(
        ("issue_returned_again", "coverage:completion_plan_not_claimed")
    )
    assert "issue_returned_again" in message
    assert "coverage:completion_plan_not_claimed" in message
    assert "the check still sees the issue: repair it, then check" in message
    assert "must name every plan obligation not acknowledged as not done" in message
    assert "finishup-verification-limit:<obligation id>" in message
    assert "Do not retry self_verified" in message
    _assert_bounded(message)


def test_an_unhinted_coverage_code_still_gets_a_coverage_next_step() -> None:
    message = self_verification_refusal_message(("coverage:missing_ref",))
    assert "coverage:missing_ref" in message
    assert "a listed coverage code is work you can do" in message
    # A hinted coverage family does not also get the generic coverage hint.
    hinted = self_verification_refusal_message(("coverage:edited_after_last_verification",))
    assert "re-run your planned verification" in hinted
    assert "a listed coverage code is work you can do" not in hinted


def test_no_recorded_reason_still_names_the_exits() -> None:
    for blocking in ((), (NO_RECORDED_LIMIT,)):
        message = self_verification_refusal_message(blocking)
        assert message.startswith("Not a FinishUP limit")
        assert "finishup-verification-limit:" in message
        _assert_bounded(message)


def test_the_message_is_bounded_with_many_long_tokens() -> None:
    blocking = tuple(f"coverage:{index:02d}_" + "x" * 110 for index in range(32))
    message = self_verification_refusal_message(blocking)
    _assert_bounded(message)
    # Only the first eight are spelled out; the rest are counted and pointed at safe_details.
    assert blocking[7] in message
    assert blocking[8] not in message
    assert "and 24 more (safe_details.blocking_reasons)" in message


def test_a_command_attempt_mismatch_names_the_link_that_clears_it() -> None:
    """tb4n4 kv (#1049): the generic coverage hint left the agent looping on this code."""

    message = self_verification_refusal_message(("coverage:command_attempt_mismatch",))
    assert "publish an action_recorded of kind command" in message
    assert "attempted_items" in message and "causal_parents" in message
    assert "belongs in the obligation's description or acceptance_criteria" in message
    assert "a listed coverage code is work you can do" not in message
    _assert_bounded(message)


def test_every_hint_family_at_once_stays_bounded() -> None:
    from finishup.application.respond import (
        _BLOCKING_HINTS,  # pyright: ignore[reportPrivateUsage]
    )

    tokens = tuple(sorted({token for family, _hint in _BLOCKING_HINTS for token in family}))
    message = self_verification_refusal_message(tokens)
    for _family, hint in _BLOCKING_HINTS:
        assert hint in message
    _assert_bounded(message)
