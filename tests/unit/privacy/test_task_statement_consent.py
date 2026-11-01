"""Consent for the task statement is its own review section in privacy policy 1.2.0 (issue #908).

An approval given for the agent's plan (``goal``) never covers the user's own words: presets from
1.2.0 on name ``task_statement``, an approval made under the 1.1.0 presets keeps its exact bytes
and digest and sends nothing, and the approval screen says in words what the new section sends.
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
    _effective_task_statement_line,  # pyright: ignore[reportPrivateUsage]
)
from finishup.cli.privacy_setup import policy_task_statement_disclosure
from finishup.cli.unlock import (
    _privacy_policy_change_text,  # pyright: ignore[reportPrivateUsage]
    _task_statement_change_note,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.privacy import (
    CURRENT_PRIVACY_POLICY_PRESET_VERSION,
    PRIVACY_POLICY_PRESET_VERSIONS,
    PrivacyPolicy,
    ReviewContextProfile,
    ReviewSelectionPolicy,
    review_selection_policy_schema_version,
)
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.models import DataCategory
from finishup.protocol.schemas import SchemaInstanceInvalid, validate_schema_instance
from finishup.service.confidential_protocol import PrivacyPolicyDecisionPreview

_GOAL_PROFILES = (
    ReviewContextProfile.GOAL_AWARE,
    ReviewContextProfile.ASSISTED,
    ReviewContextProfile.EXPANDED,
)


def _legacy(policy: PrivacyPolicy) -> PrivacyPolicy:
    return replace(
        policy,
        review_selection=ReviewSelectionPolicy.for_profile(
            policy.review_context_profile, preset_version="1.1.0"
        ),
    )


def test_current_goal_aware_presets_name_the_section_and_structural_never_does() -> None:
    assert CURRENT_PRIVACY_POLICY_PRESET_VERSION == "1.2.0"
    for profile in _GOAL_PROFILES:
        current = ReviewSelectionPolicy.for_profile(profile)
        legacy = ReviewSelectionPolicy.for_profile(profile, preset_version="1.1.0")
        assert "task_statement" in current.sections
        assert "task_statement" not in legacy.sections
        # The newer preset is exactly the older one plus the section, so it reads as a widening.
        assert set(current.sections) - set(legacy.sections) == {"task_statement"}
        assert ReviewSelectionPolicy.is_profile_preset(profile, current)
        assert ReviewSelectionPolicy.is_profile_preset(profile, legacy)
        assert DataCategory.TASK_DESCRIPTION in current.required_categories()
    for version in PRIVACY_POLICY_PRESET_VERSIONS:
        structural = ReviewSelectionPolicy.for_profile(
            ReviewContextProfile.STRUCTURAL, preset_version=version
        )
        assert "task_statement" not in structural.sections


def test_an_approval_made_before_the_section_keeps_its_exact_bytes_and_sends_nothing() -> None:
    legacy = _legacy(minimal_external_policy())
    wire = encode_privacy_policy_json(legacy)

    assert wire["schema_version"] == "1.1.0"
    validate_schema_instance("privacy-policy", "1.1.0", wire)
    decoded = decode_privacy_policy_canonical(canonical_encode(wire))
    assert decoded == legacy
    assert encode_privacy_policy_json(decoded) == wire
    assert canonical_digest(cast(JsonValue, encode_privacy_policy_json(decoded))) == (
        canonical_digest(cast(JsonValue, wire))
    )
    assert "task_statement" not in decoded.review_selection.sections
    assert policy_task_statement_disclosure(decoded).startswith("not sent. This policy was")


def test_a_current_approval_is_the_1_2_0_wire_and_the_1_1_0_schema_cannot_express_it() -> None:
    current = minimal_external_policy()
    wire = encode_privacy_policy_json(current)

    assert review_selection_policy_schema_version(current.review_selection) == "1.2.0"
    assert wire["schema_version"] == "1.2.0"
    validate_schema_instance("privacy-policy", "1.2.0", wire)
    downgraded = {**wire, "schema_version": "1.1.0"}
    with pytest.raises(SchemaInstanceInvalid):
        validate_schema_instance("privacy-policy", "1.1.0", cast(JsonValue, downgraded))
    # A stored 1.1.0 row can never name the section: reading one would widen an old approval.
    with pytest.raises(ValueError, match="privacy_policy_row_corrupt"):
        decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, downgraded)))
    assert policy_task_statement_disclosure(current).startswith("sent. The agent's transcription")


def test_moving_to_the_section_is_a_widening_the_approval_screen_names_in_words() -> None:
    legacy = _legacy(minimal_external_policy())
    current = minimal_external_policy()

    changes = privacy_policy_changes(legacy, current)
    sections = next(change for change in changes if change.field == "sections")
    assert sections.widens
    text = _privacy_policy_change_text(
        PrivacyPolicyDecisionPreview("pending-1", "sha256:" + "b" * 64, changes)
    )
    assert "Review sections built" in text
    assert (
        "task_statement: the agent's transcription of the user's request (or the task title "
        "when none was supplied) will be sent to the reviewer. The host-captured user prompt "
        "is not used." in text
    )

    # Removing the section is a tightening (no approval screen), but its words stay fixed too.
    removal = next(
        change for change in privacy_policy_changes(current, legacy) if change.field == "sections"
    )
    assert not removal.widens
    note = _task_statement_change_note(removal)
    assert note is not None and "will stop being sent; it stays in the local task record" in note


def test_disclosure_names_a_channel_that_blocks_task_description() -> None:
    current = minimal_external_policy()
    blocked = replace(
        current,
        channel_policies=tuple(
            replace(
                channel,
                allowed_categories=tuple(
                    item
                    for item in channel.allowed_categories
                    if item is not DataCategory.TASK_DESCRIPTION
                ),
            )
            for channel in current.channel_policies
        ),
    )
    text = policy_task_statement_disclosure(blocked)
    assert text.startswith("not sent. The task_statement section is selected")
    assert "host-captured user prompt is never used" in text


def test_privacy_show_line_is_plain_for_both_wire_versions() -> None:
    current = minimal_external_policy()
    for policy, prefix in (
        (current, "Task statement: sent."),
        (_legacy(current), "Task statement: not sent. This policy was approved before"),
    ):
        body = cast(
            JsonValue, {"schema_version": "1.0.0", "policy": encode_privacy_policy_json(policy)}
        )
        line = _effective_task_statement_line(body)
        assert line is not None and line.startswith(prefix)
        assert "host-captured user prompt is never used" in line
    assert _effective_task_statement_line(cast(JsonValue, {"policy": {}})) is None


def test_a_channel_that_withholds_task_description_drops_the_section_for_delivery() -> None:
    from finishup.domain.task_statement import review_selection_for_delivery

    current = minimal_external_policy()
    assert review_selection_for_delivery(current) == current.review_selection
    blocked = replace(
        current,
        channel_policies=tuple(
            replace(
                channel,
                allowed_categories=tuple(
                    item
                    for item in channel.allowed_categories
                    if item is not DataCategory.TASK_DESCRIPTION
                ),
            )
            for channel in current.channel_policies
        ),
    )
    delivered = review_selection_for_delivery(blocked)
    assert "task_statement" not in delivered.sections
    assert set(current.review_selection.sections) - set(delivered.sections) == {"task_statement"}
    # Only the statement's own section moves; the goal stays for the generic withheld disclosure.
    assert "goal" in delivered.sections
