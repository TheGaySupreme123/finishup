from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy

_NAMED = tuple(
    profile for profile in ReviewContextProfile if profile is not ReviewContextProfile.CUSTOM
)


@given(st.sampled_from(_NAMED), st.sampled_from(_NAMED))
def test_review_selector_meet_is_commutative_and_idempotent(
    left_profile: ReviewContextProfile, right_profile: ReviewContextProfile
) -> None:
    left = ReviewSelectionPolicy.for_profile(left_profile)
    right = ReviewSelectionPolicy.for_profile(right_profile)

    assert left.meet(right) == right.meet(left)
    assert left.meet(left) == left


@given(st.sampled_from(_NAMED), st.sampled_from(_NAMED), st.sampled_from(_NAMED))
def test_review_selector_meet_is_associative(
    first_profile: ReviewContextProfile,
    second_profile: ReviewContextProfile,
    third_profile: ReviewContextProfile,
) -> None:
    first = ReviewSelectionPolicy.for_profile(first_profile)
    second = ReviewSelectionPolicy.for_profile(second_profile)
    third = ReviewSelectionPolicy.for_profile(third_profile)

    assert first.meet(second).meet(third) == first.meet(second.meet(third))
