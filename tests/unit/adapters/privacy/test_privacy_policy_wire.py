"""Domain PrivacyPolicy ↔ wire privacy-policy compatibility codec."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from builders.privacy_policies import local_only_policy, minimal_external_policy
from finishup.adapters.privacy.catalog import (
    decode_privacy_policy_canonical,
    encode_privacy_policy_json,
)
from finishup.domain.privacy import ReviewSelectionPolicy
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.schemas import validate_schema_instance


def test_encode_local_only_matches_wire_schema() -> None:
    wire = encode_privacy_policy_json(local_only_policy())
    validate_schema_instance("privacy-policy", "1.1.0", wire)
    assert wire["schema_version"] == "1.1.0"
    assert "agent_context_categories" not in wire
    ceilings = wire["local_sink_category_ceilings"]
    assert type(ceilings) is dict
    assert set(cast(dict[str, JsonValue], ceilings)) == {
        "local_model",
        "agent_context",
        "trusted_human_control",
    }
    channels = wire["channel_policies"]
    assert type(channels) is list
    assert [cast(dict[str, JsonValue], item)["channel"] for item in channels] == [
        "capability_testing",
        "crash_diagnostics",
        "llm_inference",
        "product_telemetry",
        "update_checks",
    ]


def test_wire_round_trip_preserves_domain_policy() -> None:
    original = minimal_external_policy()
    wire = encode_privacy_policy_json(original)
    # The current Assisted preset names the task_statement section, a 1.2.0-only field.
    assert wire["schema_version"] == "1.2.0"
    validate_schema_instance("privacy-policy", "1.2.0", wire)
    decoded = decode_privacy_policy_canonical(canonical_encode(wire))
    assert decoded == original


def test_domain_desired_state_shape_still_decodes(tmp_path: Path) -> None:
    from finishup.config.privacy_desired import (
        load_privacy_desired_canonical,
        write_privacy_desired_toml,
    )

    original = local_only_policy()
    path = write_privacy_desired_toml(original, tmp_path / "desired.toml")
    decoded = decode_privacy_policy_canonical(load_privacy_desired_canonical(path))
    assert decoded == original


def test_wire_decode_rejects_a_missing_never_send_deny_list() -> None:
    """``never_send`` is a const deny list; absence must not decode as a valid policy."""

    wire = dict(encode_privacy_policy_json(local_only_policy()))
    del wire["never_send"]
    with pytest.raises(ValueError, match="privacy_policy_row_corrupt"):
        decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, wire)))


def test_wire_decode_rejects_a_weakened_never_send_deny_list() -> None:
    wire = dict(encode_privacy_policy_json(local_only_policy()))
    never_send = cast(list[JsonValue], wire["never_send"])
    wire["never_send"] = never_send[1:]
    with pytest.raises(ValueError, match="privacy_policy_row_corrupt"):
        decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, wire)))


def test_wire_decode_rejects_an_unsupported_schema_version() -> None:
    wire = dict(encode_privacy_policy_json(local_only_policy()))
    wire["schema_version"] = "2.0.0"
    with pytest.raises(ValueError, match="privacy_policy_row_corrupt"):
        decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, wire)))


def test_released_wire_policy_still_decodes() -> None:
    # A released 1.0.0 document carries the preset of its time, without task_statement.
    policy = minimal_external_policy()
    original = replace(
        policy,
        review_selection=ReviewSelectionPolicy.for_profile(
            policy.review_context_profile, preset_version="1.1.0"
        ),
    )
    wire = encode_privacy_policy_json(original)
    wire["schema_version"] = "1.0.0"
    validate_schema_instance("privacy-policy", "1.0.0", wire)
    assert decode_privacy_policy_canonical(canonical_encode(wire)) == original
