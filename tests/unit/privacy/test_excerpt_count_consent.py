"""Privacy policy 1.2.0 lifts the Expanded excerpt count without widening an approval (#907 1b).

The Expanded preset's count becomes the protocol maximum from 1.2.0 on; its byte budget and the
Assisted preset stay as they were. An approval made under the 1.1.0 preset keeps its exact bytes,
digest and 16-excerpt limit until its owner approves the new recipe through the ceremony, and
approving the earlier preset again is a narrowing that restores the released bytes.
"""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from builders.privacy_policies import minimal_external_policy
from finishup.adapters.privacy.catalog import (
    decode_privacy_policy_canonical,
    encode_privacy_policy_json,
)
from finishup.application.privacy_policy import privacy_policy_changes
from finishup.cli.app import (
    _effective_excerpt_limits_line,  # pyright: ignore[reportPrivateUsage]
)
from finishup.cli.privacy_setup import (
    _render_review,  # pyright: ignore[reportPrivateUsage]
    policy_excerpt_limits_disclosure,
)
from finishup.cli.unlock import (
    _privacy_policy_change_text,  # pyright: ignore[reportPrivateUsage]
    _task_statement_change_note,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.privacy import (
    PRE_1_2_MAX_EXCERPTS,
    PrivacyPolicy,
    PrivacyPolicyPresetVersion,
    ReviewContextProfile,
    ReviewSelectionPolicy,
    review_selection_policy_schema_version,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.models import MAX_REVIEW_EXCERPTS
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance
from finishup.service.confidential_protocol import PrivacyPolicyDecisionPreview


def _expanded(preset_version: PrivacyPolicyPresetVersion = "1.2.0") -> PrivacyPolicy:
    return replace(
        minimal_external_policy(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=ReviewSelectionPolicy.for_profile(
            ReviewContextProfile.EXPANDED, preset_version=preset_version
        ),
    )


def test_only_the_1_2_0_expanded_preset_lifts_the_count_and_bytes_stay() -> None:
    assert MAX_REVIEW_EXCERPTS == 64 and PRE_1_2_MAX_EXCERPTS == 16
    legacy = ReviewSelectionPolicy.for_profile(
        ReviewContextProfile.EXPANDED, preset_version="1.1.0"
    )
    current = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
    assert (legacy.max_excerpts, current.max_excerpts) == (16, MAX_REVIEW_EXCERPTS)
    for selection in (legacy, current):
        assert (selection.max_excerpt_bytes, selection.max_total_excerpt_bytes) == (16_384, 131_072)
        assert ReviewSelectionPolicy.is_profile_preset(ReviewContextProfile.EXPANDED, selection)
    for version in ("1.1.0", "1.2.0"):
        assisted = ReviewSelectionPolicy.for_profile(
            ReviewContextProfile.ASSISTED, preset_version=version
        )
        assert assisted.max_excerpts == 16
    with pytest.raises(ValueError):
        replace(current, max_excerpts=MAX_REVIEW_EXCERPTS + 1)


def test_a_count_above_16_needs_the_1_2_0_wire_even_without_new_sections() -> None:
    legacy = ReviewSelectionPolicy.for_profile(
        ReviewContextProfile.EXPANDED, preset_version="1.1.0"
    )
    assert review_selection_policy_schema_version(legacy) == "1.1.0"
    assert review_selection_policy_schema_version(replace(legacy, max_excerpts=17)) == "1.2.0"
    assert review_selection_policy_schema_version(replace(legacy, max_excerpts=16)) == "1.1.0"


def test_a_stored_1_1_0_expanded_policy_keeps_its_exact_bytes_and_16_excerpts() -> None:
    legacy = _expanded("1.1.0")
    wire = encode_privacy_policy_json(legacy)

    assert wire["schema_version"] == "1.1.0"
    validate_schema_instance("privacy-policy", "1.1.0", wire)
    decoded = decode_privacy_policy_canonical(canonical_encode(wire))
    assert decoded == legacy
    assert canonical_encode(cast(JsonValue, encode_privacy_policy_json(decoded))) == (
        canonical_encode(cast(JsonValue, wire))
    )
    assert decoded.review_selection.max_excerpts == 16


def test_an_older_service_rejects_the_1_2_0_expanded_wire_cleanly() -> None:
    current = _expanded()
    wire = encode_privacy_policy_json(current)
    assert wire["schema_version"] == "1.2.0"
    validate_schema_instance("privacy-policy", "1.2.0", wire)
    # The released 1.1.0 schema bounds the count at 16 and pins the Expanded preset, so a 0.2.5
    # boundary refuses the document instead of reading 64 as within its approval.
    relabelled = cast(JsonValue, {**wire, "schema_version": "1.1.0"})
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("privacy-policy", "1.1.0", relabelled)
    # A stored row stamped 1.1.0 that carries more than 16 excerpts is corrupt, never a widening.
    count_only = encode_privacy_policy_json(
        replace(
            _expanded("1.1.0"),
            review_context_profile=ReviewContextProfile.CUSTOM,
            review_selection=replace(
                ReviewSelectionPolicy.for_profile(
                    ReviewContextProfile.EXPANDED, preset_version="1.1.0"
                ),
                max_excerpts=32,
            ),
        )
    )
    assert count_only["schema_version"] == "1.2.0"
    with pytest.raises(ValueError, match="privacy_policy_row_corrupt"):
        decode_privacy_policy_canonical(
            canonical_encode(cast(JsonValue, {**count_only, "schema_version": "1.1.0"}))
        )


def test_moving_to_the_new_count_is_a_widening_the_ceremony_names_in_words() -> None:
    changes = privacy_policy_changes(_expanded("1.1.0"), _expanded())
    count = next(change for change in changes if change.field == "max_excerpts")
    assert count.widens
    assert not any(
        change.field in {"max_excerpt_bytes", "max_total_excerpt_bytes"} for change in changes
    )
    text = _privacy_policy_change_text(
        PrivacyPolicyDecisionPreview("pending-1", "sha256:" + "b" * 64, changes)
    )
    assert "Maximum excerpts" in text
    assert (
        "max_excerpts: more excerpts may be sent in one review; each stays within the "
        "per-excerpt and total byte limits, which this change does not raise." in text
    )


def test_approving_the_earlier_preset_again_is_a_narrowing_back_to_the_released_bytes() -> None:
    legacy = _expanded("1.1.0")
    released = encode_privacy_policy_json(legacy)

    back = privacy_policy_changes(_expanded(), legacy)
    assert back and not any(change.widens for change in back)
    count = next(change for change in back if change.field == "max_excerpts")
    assert _task_statement_change_note(count) == (
        "max_excerpts: at most 16 excerpts will be sent in one review."
    )
    restored = encode_privacy_policy_json(
        replace(_expanded(), review_selection=legacy.review_selection)
    )
    assert restored == released
    assert canonical_digest(cast(JsonValue, restored)) == canonical_digest(
        cast(JsonValue, released)
    )


def test_privacy_show_renders_current_beside_proposed_limits() -> None:
    def line(policy: PrivacyPolicy) -> str:
        body = cast(
            JsonValue, {"schema_version": "1.0.0", "policy": encode_privacy_policy_json(policy)}
        )
        text = _effective_excerpt_limits_line(body)
        assert text is not None
        return text

    assert line(_expanded("1.1.0")) == (
        "Excerpt limits: current 16 excerpts, 16 KiB each, 128 KiB in total; proposed by the "
        "current expanded recipe: 64 excerpts, 16 KiB each, 128 KiB in total. Nothing changes "
        "until you approve it with 'finishup --privacy'; approving nothing keeps the current limits"
    )
    assert line(_expanded()) == (
        "Excerpt limits: 64 excerpts, 16 KiB each, 128 KiB in total (the current expanded recipe)"
    )
    assert line(minimal_external_policy()) == (
        "Excerpt limits: 16 excerpts, 16 KiB each, 128 KiB in total (the current assisted recipe)"
    )
    assert _effective_excerpt_limits_line(cast(JsonValue, {"policy": {}})) is None
    assert policy_excerpt_limits_disclosure(_expanded("1.1.0")).startswith("current 16 excerpts")


def test_the_approval_draft_shows_the_count_it_would_approve(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _render_review(_expanded())
    assert (
        "  Maximum: 64 excerpts, 16 KiB each, 128 KiB in total; 256 KiB / 4096 tokens per case"
        in capsys.readouterr().out
    )


def test_a_move_that_also_raises_the_byte_limits_never_claims_they_stay() -> None:
    goal_aware = replace(
        minimal_external_policy(),
        review_context_profile=ReviewContextProfile.GOAL_AWARE,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE),
    )
    changes = privacy_policy_changes(goal_aware, _expanded())
    assert any(
        change.field in {"max_excerpt_bytes", "max_total_excerpt_bytes"} and change.widens
        for change in changes
    )
    text = _privacy_policy_change_text(
        PrivacyPolicyDecisionPreview("pending-1", "sha256:" + "b" * 64, changes)
    )
    assert "which this change does not raise" not in text
    assert (
        "max_excerpts: more excerpts may be sent in one review; each stays within the "
        "per-excerpt and total byte limits shown on this screen." in text
    )


def test_limits_that_are_not_whole_kib_print_exact_bytes() -> None:
    custom = replace(
        _expanded(),
        review_context_profile=ReviewContextProfile.CUSTOM,
        review_selection=replace(
            ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
            max_excerpts=3,
            max_excerpt_bytes=1_000,
            max_total_excerpt_bytes=2_500,
        ),
    )
    assert policy_excerpt_limits_disclosure(custom) == (
        "3 excerpts, 1,000 bytes each, 2,500 bytes in total"
    )
