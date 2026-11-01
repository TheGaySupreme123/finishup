"""One comparison decides both "is this a widening?" and "what does the human see?".

The defect this file pins: the classifier recognized widenings across the whole policy while
the human-readable summary reported only newly added data categories and broadened scopes. A
proposal that removed per-request confirmation, raised a byte ceiling, swapped the destination
provider, disabled the data-use-evidence requirement, or relaxed the review selector was
therefore routed to the trusted approval ceremony *and* rendered as an empty screen.

The repair is structural rather than a longer summary: :func:`privacy_policy_changes` is the
single source of truth, and ``_is_tightening`` is defined as "no returned change widens". A
dimension can no longer be classified without also being displayable.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from builders.privacy_policies import (
    disabled_channel,
    local_only_policy,
    minimal_external_policy,
)
from builders.privacy_widenings import WIDENING_CASES, with_llm
from finishup.application.privacy_policy import is_privacy_tightening, privacy_policy_changes
from finishup.domain.privacy import (
    _CHANGE_IMPACT,  # pyright: ignore[reportPrivateUsage]
    MAX_PRIVACY_CHANGES,
    MAX_PRIVACY_LABEL_BYTES,
    PRIVACY_CHANGE_FIELDS,
    PrivacyPolicy,
    PrivacyPolicyChange,
    PrivacyPolicyChangeValue,
    PrivacyProfile,
    ProviderBinding,
    privacy_change_order,
    sort_privacy_changes,
    validate_privacy_change_set,
)
from finishup.protocol.models import DataCategory


def _external() -> PrivacyPolicy:
    return minimal_external_policy()


@pytest.mark.parametrize(
    ("current", "candidate", "expected"),
    [
        (current, candidate, identity)
        for _name, current, candidate, identity, _label in WIDENING_CASES
    ],
    ids=[name for name, *_rest in WIDENING_CASES],
)
def test_every_classified_widening_produces_a_matching_before_after_change(
    current: PrivacyPolicy, candidate: PrivacyPolicy, expected: tuple[str, str, str]
) -> None:
    """The regression: each of these was a widening that the old summary could not name.

    ``preview_removed``, ``max_bytes_raised``, ``max_tokens_raised``,
    ``authorization_ttl_raised``, ``provider_swapped``, ``data_class_added``,
    ``purpose_added``, ``data_use_evidence_dropped``, and ``review_selector_relaxed`` all
    returned ``((), ())`` from ``privacy_widening_summary`` while ``_is_tightening`` said
    "widening" — an approval screen with nothing on it.
    """

    assert is_privacy_tightening(current, candidate) is False

    changes = {change.identity: change for change in privacy_policy_changes(current, candidate)}

    assert expected in changes, f"{expected} was classified as widening but not displayed"
    named = changes[expected]
    assert named.widens is True
    assert named.before != named.after
    assert any(change.widens for change in changes.values())


def test_a_widening_that_adds_no_category_or_scope_is_still_fully_described() -> None:
    """The narrowest form of the original failure, asserted end to end.

    Only ``preview_required`` moves. No category is added and no scope is broadened, so the
    old summary was empty in both tuples; this is exactly the screen a human approved.
    """

    current = with_llm(_external(), preview_required=True)
    candidate = with_llm(_external(), preview_required=False)

    changes = privacy_policy_changes(current, candidate)

    assert is_privacy_tightening(current, candidate) is False
    assert len(changes) == 1
    assert changes[0].identity == ("channel", "preview_required", "llm_inference")
    assert changes[0].before == PrivacyPolicyChangeValue.of_flag(True)
    assert changes[0].after == PrivacyPolicyChangeValue.of_flag(False)


# ---------------------------------------------------------------------------
# Classification is defined by the diff, not merely consistent with it
# ---------------------------------------------------------------------------


def test_an_unchanged_policy_produces_no_changes_and_classifies_as_tightening() -> None:
    policy = minimal_external_policy()

    assert privacy_policy_changes(policy, policy) == ()
    assert is_privacy_tightening(policy, policy) is True


def test_a_pure_tightening_reports_changes_but_none_that_widen() -> None:
    current = minimal_external_policy()
    candidate = with_llm(current, allowed_categories=(DataCategory.BOUNDED_STRUCTURAL_METADATA,))

    changes = privacy_policy_changes(current, candidate)

    assert changes != ()
    assert not any(change.widens for change in changes)
    assert is_privacy_tightening(current, candidate) is True


def test_disabling_a_channel_is_a_tightening_that_still_names_every_lost_ceiling() -> None:
    current = minimal_external_policy()
    candidate = replace(
        current,
        profile=PrivacyProfile.LOCAL_ONLY,
        network_egress_permitted=False,
        require_current_provider_data_use_evidence=False,
        channel_policies=tuple(
            disabled_channel(channel.channel) for channel in current.channel_policies
        ),
    )

    changes = privacy_policy_changes(current, candidate)

    assert is_privacy_tightening(current, candidate) is True
    identities = {change.identity for change in changes}
    assert ("channel", "enabled", "llm_inference") in identities
    assert ("channel", "provider", "llm_inference") in identities
    # A channel that is off carries no ceiling, which is distinct from a ceiling of nothing.
    provider = next(change for change in changes if change.field == "provider")
    assert provider.after.kind == "none"


def test_a_mixed_proposal_shows_the_tightening_alongside_the_widening() -> None:
    """A widening does not get to hide behind a simultaneous tightening, or vice versa."""

    current = with_llm(_external(), preview_required=True)
    candidate = with_llm(
        current,
        preview_required=False,
        allowed_categories=(DataCategory.BOUNDED_STRUCTURAL_METADATA,),
    )

    changes = privacy_policy_changes(current, candidate)
    kinds = {change.identity: change.widens for change in changes}

    assert is_privacy_tightening(current, candidate) is False
    assert kinds[("channel", "preview_required", "llm_inference")] is True
    assert kinds[("channel", "categories", "llm_inference")] is False


def test_lineage_only_fields_are_never_reported_as_a_change() -> None:
    """Version, digest, issue time, and the supersedes link always differ on a candidate."""

    current = local_only_policy()
    candidate = replace(
        current,
        version=current.version + 1,
        policy_digest="sha256:" + "9" * 64,
        supersedes_policy_digest=current.policy_digest,
        created_at=current.created_at.replace(year=current.created_at.year + 1),
    )

    assert privacy_policy_changes(current, candidate) == ()
    assert is_privacy_tightening(current, candidate) is True


# ---------------------------------------------------------------------------
# Ordering, bounds, and the closed vocabulary
# ---------------------------------------------------------------------------


def test_widenings_sort_before_tightenings_most_consequential_first() -> None:
    changes = privacy_policy_changes(local_only_policy(), minimal_external_policy())

    assert [change.widens for change in changes] == sorted(
        (change.widens for change in changes), reverse=True
    )
    assert changes[0].identity == ("global", "network_egress", "")
    assert changes[1].identity == ("channel", "enabled", "llm_inference")
    assert changes[2].identity == ("channel", "provider", "llm_inference")


def test_the_order_is_total_and_stable_regardless_of_construction_order() -> None:
    changes = privacy_policy_changes(local_only_policy(), minimal_external_policy())

    assert sort_privacy_changes(tuple(reversed(changes))) == changes
    keys = [privacy_change_order(change) for change in changes]
    assert keys == sorted(keys)
    assert len(set(keys)) == len(keys)


def test_every_allowlisted_field_has_exactly_one_place_in_the_reading_order() -> None:
    """The vocabulary and the reading order are the same set, not merely overlapping.

    A field with no rank cannot be ordered deterministically; a rank with no field is a
    dimension someone removed from the classifier and left in the presentation. Both are the
    kind of drift that produced the original defect, so this asserts equality.
    """

    allowlisted = {
        (area, field) for area, fields in PRIVACY_CHANGE_FIELDS.items() for field in fields
    }
    assert set(_CHANGE_IMPACT) == allowlisted
    assert len(set(_CHANGE_IMPACT.values())) == len(_CHANGE_IMPACT)

    for area, field in sorted(allowlisted):
        change = PrivacyPolicyChange(
            area,  # pyright: ignore[reportArgumentType]
            field,
            "llm_inference" if area == "channel" else None,
            PrivacyPolicyChangeValue.of_flag(False),
            PrivacyPolicyChangeValue.of_flag(True),
            True,
        )
        assert privacy_change_order(change)[1] >= 0


def test_a_change_may_not_claim_a_field_outside_its_area() -> None:
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        PrivacyPolicyChange(
            "global",
            "max_bytes",
            None,
            PrivacyPolicyChangeValue.of_count(1),
            PrivacyPolicyChangeValue.of_count(2),
            True,
        )


def test_only_a_channel_change_carries_a_subject() -> None:
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        PrivacyPolicyChange(
            "global",
            "network_egress",
            "llm_inference",
            PrivacyPolicyChangeValue.of_flag(False),
            PrivacyPolicyChangeValue.of_flag(True),
            True,
        )
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        PrivacyPolicyChange(
            "channel",
            "enabled",
            None,
            PrivacyPolicyChangeValue.of_flag(False),
            PrivacyPolicyChangeValue.of_flag(True),
            True,
        )


def test_a_change_whose_sides_are_equal_is_not_a_change() -> None:
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        PrivacyPolicyChange(
            "global",
            "network_egress",
            None,
            PrivacyPolicyChangeValue.of_flag(True),
            PrivacyPolicyChangeValue.of_flag(True),
            False,
        )


def test_not_applicable_is_distinct_from_permitting_nothing() -> None:
    assert PrivacyPolicyChangeValue.absent() != PrivacyPolicyChangeValue.of_labels(())


@pytest.mark.parametrize(
    "value",
    [
        "has space",
        "control\x07char",
        "escape\x1b[31m",
        "newline\nsplit",
        # `$` in Python matches before a single trailing newline; the pattern is anchored with
        # `\A`/`\Z` so neither `fullmatch` nor a future `match` can admit one.
        "trailing\n",
        "x" * (MAX_PRIVACY_LABEL_BYTES + 1),
    ],
)
def test_a_label_that_could_repaint_a_terminal_is_rejected(value: str) -> None:
    """These values reach a raw ``/dev/tty`` write with no capability negotiation."""

    with pytest.raises(ValueError, match="invalid_privacy_value"):
        PrivacyPolicyChangeValue.of_labels((value,))


def test_a_value_may_not_carry_a_payload_its_kind_does_not_own() -> None:
    for kwargs in (
        {"kind": "none", "flag": True},
        {"kind": "flag", "count": 1},
        {"kind": "count", "labels": ("a",)},
        {"kind": "labels", "flag": False},
        {"kind": "flag"},
        {"kind": "count"},
        {"kind": "unknown"},
    ):
        with pytest.raises(ValueError, match="invalid_privacy_value"):
            PrivacyPolicyChangeValue(**kwargs)  # pyright: ignore[reportArgumentType]


def test_a_change_set_rejects_duplicates_misordering_and_oversize() -> None:
    widening = PrivacyPolicyChange(
        "global",
        "network_egress",
        None,
        PrivacyPolicyChangeValue.of_flag(False),
        PrivacyPolicyChangeValue.of_flag(True),
        True,
    )
    tightening = PrivacyPolicyChange(
        "agent_context",
        "categories",
        None,
        PrivacyPolicyChangeValue.of_labels(("claim_text",)),
        PrivacyPolicyChangeValue.of_labels(()),
        False,
    )

    validate_privacy_change_set((widening, tightening), require_widening=True)
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        validate_privacy_change_set((widening, widening))
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        validate_privacy_change_set((tightening, widening))
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        validate_privacy_change_set((tightening,), require_widening=True)
    # An identical proposal is a legitimate empty diff; a widening preview of one is not.
    validate_privacy_change_set(())
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        validate_privacy_change_set((), require_widening=True)
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        validate_privacy_change_set((widening,) * (MAX_PRIVACY_CHANGES + 1))


def test_the_widest_possible_diff_stays_inside_the_structural_bound() -> None:
    """Every dimension moving at once is still a bounded, renderable set."""

    changes = privacy_policy_changes(local_only_policy(), minimal_external_policy())

    assert 0 < len(changes) <= MAX_PRIVACY_CHANGES


def test_a_maximal_provider_binding_still_produces_a_renderable_diff() -> None:
    """Every binding field is independently bounded at 128 bytes by its own validator.

    Joining the endpoint profile and its version into one label could exceed the label bound
    and raise, which the daemon turns into `target_invalid` — leaving a human unable to approve
    a policy that is entirely legitimate. One label per field keeps the longest label at one
    prefix plus one field.
    """

    current = minimal_external_policy()
    maximal = ProviderBinding("p" * 128, "m" * 128, "e" * 128, "1" * 128, "external")
    candidate = with_llm(current, provider_binding=maximal)

    changes = privacy_policy_changes(current, candidate)

    provider = next(change for change in changes if change.field == "provider")
    assert provider.widens is True
    assert f"provider:{'p' * 128}" in provider.after.labels
    assert f"endpoint_version:{'1' * 128}" in provider.after.labels
    assert all(
        len(label.encode("utf-8")) <= MAX_PRIVACY_LABEL_BYTES for label in provider.after.labels
    )
