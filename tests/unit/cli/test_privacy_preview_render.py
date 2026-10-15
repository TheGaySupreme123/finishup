"""The trusted terminal names every widening, in words, before it asks.

This closes the last link of the trace: a widening the classifier recognizes produces a change,
the preview type accepts only a complete change set, and the renderer must have a fixed label for
every field it is handed. Any dimension that reaches approval without appearing on screen fails
here rather than on a user's terminal.

Labels are asserted as literal wording. The whole point of this screen is that a person can read
it, so its text is a product promise and not an implementation detail.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from builders.privacy_widenings import WIDENING_CASES
from finishup.application.privacy_policy import privacy_policy_changes
from finishup.cli.unlock import (
    HumanCeremonyCliError,
    _privacy_policy_change_text,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.privacy import (
    PRIVACY_CHANGE_FIELDS,
    AuthorizationScope,
    AuthorizationScopeKind,
    PrivacyPolicy,
    PrivacyPolicyChange,
    PrivacyPolicyChangeValue,
    sort_privacy_changes,
)
from finishup.service.confidential_protocol import (
    PrivacyPolicyDecisionPreview,
    PrivacyPolicyTransitionPreviewMember,
)

_DIGEST = "sha256:" + "b" * 64


def _rendered(current: PrivacyPolicy, candidate: PrivacyPolicy) -> str:
    changes = privacy_policy_changes(current, candidate)
    preview = PrivacyPolicyDecisionPreview("pending-1", _DIGEST, changes)
    return _privacy_policy_change_text(preview)


@pytest.mark.parametrize(
    ("current", "candidate", "label"),
    [(current, candidate, label) for _name, current, candidate, _identity, label in WIDENING_CASES],
    ids=[name for name, *_rest in WIDENING_CASES],
)
def test_the_trusted_screen_names_the_consequential_field_in_plain_english(
    current: PrivacyPolicy, candidate: PrivacyPolicy, label: str
) -> None:
    text = _rendered(current, candidate)

    assert label in text, f"the widened field is not named on the approval screen: {label}"
    assert "(!)" in text, "no change is marked as making privacy less restrictive"
    assert "->" in text


def test_the_digest_is_labelled_as_evidence_rather_than_as_the_description() -> None:
    """The old screen showed a digest and two often-empty lists, and nothing else.

    A digest commits to bytes; it does not tell a human what they are agreeing to. It stays, and
    it says what it is.
    """

    changes = (
        PrivacyPolicyChange(
            "global",
            "network_egress",
            None,
            PrivacyPolicyChangeValue.of_flag(False),
            PrivacyPolicyChangeValue.of_flag(True),
            True,
        ),
    )
    text = _privacy_policy_change_text(PrivacyPolicyDecisionPreview("pending-1", _DIGEST, changes))

    assert "It is integrity evidence," in text
    assert "not a description of the change; the lines above are the change." in text
    assert f"Diff digest: {_DIGEST}" in text


def test_a_simultaneous_tightening_is_shown_but_never_marked_as_widening() -> None:
    changes = sort_privacy_changes(
        (
            PrivacyPolicyChange(
                "global",
                "network_egress",
                None,
                PrivacyPolicyChangeValue.of_flag(False),
                PrivacyPolicyChangeValue.of_flag(True),
                True,
            ),
            PrivacyPolicyChange(
                "agent_context",
                "categories",
                None,
                PrivacyPolicyChangeValue.of_labels(("claim_text", "declared_file_type")),
                PrivacyPolicyChangeValue.of_labels(("declared_file_type",)),
                False,
            ),
        )
    )

    text = _privacy_policy_change_text(PrivacyPolicyDecisionPreview("pending-1", _DIGEST, changes))

    assert "1 of 2 changes below make it less restrictive" in text
    tightening = next(
        line for line in text.splitlines() if "Information released to the agent host" in line
    )
    assert "(!)" not in tightening
    assert "claim_text, declared_file_type -> declared_file_type" in tightening


def test_every_field_the_wire_may_carry_has_a_fixed_label_and_a_group() -> None:
    """The wire vocabulary, the label table, and the screen's groups are the same set.

    A field with no group would be dropped silently — the exact defect being repaired — and a
    group entry with no field is presentation for a dimension the protocol no longer carries.
    Equality is asserted in both directions so neither can drift as either one grows.
    """

    import finishup.cli.unlock as module

    allowlisted = {
        (area, field) for area, fields in PRIVACY_CHANGE_FIELDS.items() for field in fields
    }
    grouped = [
        member
        for _heading, members in module._CHANGE_GROUPS  # pyright: ignore[reportPrivateUsage]
        for member in members
    ]
    assert set(module._CHANGE_LABELS) == allowlisted  # pyright: ignore[reportPrivateUsage]
    assert set(grouped) == allowlisted
    assert len(grouped) == len(allowlisted), "a field appears under more than one heading"

    for area, fields in PRIVACY_CHANGE_FIELDS.items():
        for field in fields:
            change = PrivacyPolicyChange(
                area,  # pyright: ignore[reportArgumentType]
                field,
                "llm_inference" if area == "channel" else None,
                PrivacyPolicyChangeValue.of_count(1),
                PrivacyPolicyChangeValue.of_count(2),
                True,
            )
            text = _privacy_policy_change_text(
                PrivacyPolicyDecisionPreview("pending-1", _DIGEST, (change,))
            )
            assert "1 -> 2" in text, f"{area}.{field} did not render"


def test_a_field_the_screen_cannot_place_fails_closed_instead_of_disappearing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.unlock as module

    trimmed = tuple(
        (heading, tuple(member for member in members if member != ("global", "network_egress")))
        for heading, members in module._CHANGE_GROUPS  # pyright: ignore[reportPrivateUsage]
    )
    monkeypatch.setattr(module, "_CHANGE_GROUPS", trimmed)

    preview = PrivacyPolicyDecisionPreview(
        "pending-1",
        _DIGEST,
        (
            PrivacyPolicyChange(
                "global",
                "network_egress",
                None,
                PrivacyPolicyChangeValue.of_flag(False),
                PrivacyPolicyChangeValue.of_flag(True),
                True,
            ),
        ),
    )

    with pytest.raises(HumanCeremonyCliError, match="preview_invalid"):
        _privacy_policy_change_text(preview)


def test_compound_approval_names_machine_ceiling_and_repository_insert_without_identity() -> None:
    from finishup.application.privacy_policy import private_repository_baseline

    changes = (
        PrivacyPolicyChange(
            "global",
            "network_egress",
            None,
            PrivacyPolicyChangeValue.of_flag(False),
            PrivacyPolicyChangeValue.of_flag(True),
            True,
        ),
    )
    candidate = next(
        candidate
        for name, _current, candidate, *_rest in WIDENING_CASES
        if name == "channel_enabled"
    )
    candidate = replace(
        candidate,
        effective_scope=AuthorizationScope(
            AuthorizationScopeKind.WORKSPACE,
            candidate.effective_scope.installation_id,
            "hmac-sha256:" + "c" * 64,
        ),
    )
    baseline = private_repository_baseline(candidate)
    insert_changes = privacy_policy_changes(baseline, candidate)
    assert baseline.effective_scope == candidate.effective_scope
    assert baseline.network_egress_permitted is False
    preview = PrivacyPolicyDecisionPreview(
        "pending-1",
        _DIGEST,
        (),
        (
            PrivacyPolicyTransitionPreviewMember("machine_ceiling", "replace", changes),
            PrivacyPolicyTransitionPreviewMember("repository_grant", "insert", insert_changes),
        ),
    )

    text = _privacy_policy_change_text(preview)

    assert "Installation-wide ceiling (replace)" in text
    assert "Repository grant (insert)" in text
    assert "Before: no repository grant; external model review is off." in text
    assert "After: insert a repository grant bounded by the installation ceiling." in text
    assert "Information allowed (External model review): Not applicable ->" in text
    assert "Sensitivity allowed (External model review): Not applicable ->" in text
    assert "Provider and model (External model review): Not applicable -> fireworks /" in text
    assert "Confirmation (External model review): Not applicable -> No confirmation" in text
    assert text.count("sha256:") == 1
    assert "/Users/" not in text
    assert "hmac-sha256:" not in text


def test_repository_replacement_renders_the_exact_row_diff() -> None:
    changes = (
        PrivacyPolicyChange(
            "global",
            "network_egress",
            None,
            PrivacyPolicyChangeValue.of_flag(False),
            PrivacyPolicyChangeValue.of_flag(True),
            True,
        ),
    )
    preview = PrivacyPolicyDecisionPreview(
        "pending-1",
        _DIGEST,
        (),
        (PrivacyPolicyTransitionPreviewMember("repository_grant", "replace", changes),),
    )

    text = _privacy_policy_change_text(preview)

    assert "Repository grant (replace)" in text
    assert "exact existing grant" in text
    assert "Data leaving this computer: Not allowed -> Allowed" in text
