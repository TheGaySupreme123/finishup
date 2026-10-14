from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from finishup.domain.privacy import PrivacyProfile, ReviewContextProfile

_ROOT = Path(__file__).resolve().parents[3]


def test_fixture_profiles_match_the_closed_public_vocabulary() -> None:
    expected = {
        "PRIV-001-local-only.case.json": "local_only",
        "PRIV-002-confirm-every-request.case.json": "confirm_every_request",
        "PRIV-003-minimal-external.case.json": "minimal_external",
        "PRIV-004-trusted-provider.case.json": "trusted_provider",
    }
    assert set(expected.values()) == {profile.value for profile in PrivacyProfile}
    for filename, profile in expected.items():
        fixture = cast(
            dict[str, object],
            json.loads((_ROOT / "fixtures/privacy" / filename).read_text()),
        )
        input_value = cast(dict[str, object], fixture["input"])
        policies = cast(dict[str, object], input_value["policies"])
        observed: set[str] = set()
        for raw_policy in policies.values():
            if type(raw_policy) is not dict:
                continue
            profile_value = cast(dict[str, object], raw_policy).get("profile")
            if type(profile_value) is str:
                observed.add(profile_value)
        assert profile in observed


def test_review_context_profiles_are_complete_and_distinct_from_disclosure_profiles() -> None:
    assert {profile.value for profile in ReviewContextProfile} == {
        "structural",
        "goal_aware",
        "assisted",
        "expanded",
        "custom",
    }
    assert not (
        {profile.value for profile in ReviewContextProfile}
        & {profile.value for profile in PrivacyProfile}
    )
