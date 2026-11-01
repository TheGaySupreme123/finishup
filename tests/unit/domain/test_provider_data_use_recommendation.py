"""The practical Assisted threshold is exact and independent of advisory caveat fields."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

from finishup.domain.privacy import ProviderDataUseProfile

_NOW = datetime(2026, 8, 5, tzinfo=UTC)
_DIGEST = "sha256:" + "1" * 64


def _profile(
    *,
    days: int,
    human_access: Literal["prohibited", "restricted", "permitted", "unknown"] = "restricted",
) -> ProviderDataUseProfile:
    return ProviderDataUseProfile(
        "threshold-test",
        "1.0.0",
        "prohibited",
        "bounded",
        days,
        human_access,
        _NOW - timedelta(days=1),
        _NOW + timedelta(days=1),
        _DIGEST,
    )


def test_bounded_retention_must_not_exceed_thirty_days() -> None:
    assert _profile(days=30).recommendation_eligible(_NOW)
    assert not _profile(days=31).recommendation_eligible(_NOW)


def test_human_access_is_disclosed_but_not_a_substitute_threshold() -> None:
    assert _profile(days=30, human_access="unknown").recommendation_eligible(_NOW)


def test_record_never_applies_before_its_fixed_review_time() -> None:
    assert not _profile(days=30).recommendation_eligible(_NOW - timedelta(days=2))
