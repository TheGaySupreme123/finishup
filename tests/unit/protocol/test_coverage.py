from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, is_dataclass
from itertools import pairwise
from types import MappingProxyType
from typing import cast

import pytest

import finishup.protocol.coverage as coverage_module
from finishup.protocol.canonical import JsonValue
from finishup.protocol.coverage import (
    ARTIFACT_OBSERVATION_ORDER,
    AUTHORSHIP_ASSURANCE_ORDER,
    COVERAGE_DEFAULTS_BY_CHANNEL,
    EVIDENCE_IMMUTABILITY_ORDER,
    LEDGER_FRESHNESS_ORDER,
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
    coverage_for_channel,
    coverage_from_json,
    coverage_to_json,
    weakest,
)
from finishup.protocol.errors import ProtocolValueError


class _StringSubclass(str):
    pass


class _TupleSubclass(tuple[object, ...]):
    pass


class _SpoofedPublicationChannel:
    value = "cooperative_mcp"

    @property
    def __class__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> type[PublicationChannel]:
        return PublicationChannel


class _SpoofedCoverage:
    @property
    def __class__(  # pyright: ignore[reportIncompatibleMethodOverride]
        self,
    ) -> type[Coverage]:
        return Coverage


def _assert_reason(exc_info: pytest.ExceptionInfo[ProtocolValueError], reason: str) -> None:
    assert exc_info.value.reason_code == reason
    assert exc_info.value.args == (reason,)


def _base(**changes: object) -> Coverage:
    values: dict[str, object] = {
        "publication_channels": (PublicationChannel.LOCAL_CLI,),
        "authorship_assurance": AuthorshipAssurance.SELF_ASSERTED,
        "artifact_observation": ArtifactObservation.PUBLISHED_ONLY,
        "evidence_immutability": EvidenceImmutability.METADATA_ONLY,
        "ledger_freshness": LedgerFreshness.CURRENT,
        "check_types": (CheckType.NONE,),
        "known_gaps": (),
    }
    values.update(changes)
    return Coverage(
        publication_channels=cast(tuple[PublicationChannel, ...], values["publication_channels"]),
        authorship_assurance=cast(AuthorshipAssurance, values["authorship_assurance"]),
        artifact_observation=cast(ArtifactObservation, values["artifact_observation"]),
        evidence_immutability=cast(EvidenceImmutability, values["evidence_immutability"]),
        ledger_freshness=cast(LedgerFreshness, values["ledger_freshness"]),
        check_types=cast(tuple[CheckType, ...], values["check_types"]),
        known_gaps=cast(tuple[str, ...], values["known_gaps"]),
    )


def test_ordered_dimensions_sort_as_defined() -> None:
    expected_orders = (
        (
            AuthorshipAssurance,
            AUTHORSHIP_ASSURANCE_ORDER,
            (
                "self_asserted",
                "harness_observed",
                "locally_authenticated",
                "service_authenticated",
                "cryptographically_attested",
            ),
        ),
        (
            ArtifactObservation,
            ARTIFACT_OBSERVATION_ORDER,
            (
                "published_only",
                "import_observed",
                "hook_observed",
                "content_captured",
                "artifact_verified",
                "independently_reproduced",
            ),
        ),
        (
            EvidenceImmutability,
            EVIDENCE_IMMUTABILITY_ORDER,
            (
                "mutable_reference",
                "metadata_only",
                "content_digest",
                "immutable_snapshot",
                "independently_reproduced",
            ),
        ),
        (
            LedgerFreshness,
            LEDGER_FRESHNESS_ORDER,
            (
                "unknown",
                "redacted_gap",
                "partial",
                "stale_after_material_change",
                "current",
            ),
        ),
    )
    for enum_type, order, expected_values in expected_orders:
        members = tuple(enum_type)
        assert tuple(member.value for member in members) == expected_values
        assert tuple(order) == members
        assert tuple(order.values()) == tuple(range(len(members)))
        assert isinstance(order, MappingProxyType)
        assert all(left < right for left, right in pairwise(members))
        assert all(right > left for left, right in pairwise(members))
        assert members[0] <= members[0]
        assert members[-1] >= members[-1]
    with pytest.raises(TypeError):
        _ = AuthorshipAssurance.SELF_ASSERTED < ArtifactObservation.PUBLISHED_ONLY
    with pytest.raises(TypeError):
        _ = AuthorshipAssurance.SELF_ASSERTED < "service_authenticated"


def test_coverage_is_frozen_slotted_value_in_exact_field_order() -> None:
    value = _base()
    expected_fields = (
        "publication_channels",
        "authorship_assurance",
        "artifact_observation",
        "evidence_immutability",
        "ledger_freshness",
        "check_types",
        "known_gaps",
    )
    assert is_dataclass(value)
    assert Coverage.__slots__ == expected_fields
    assert tuple(field.name for field in fields(value)) == expected_fields
    with pytest.raises(FrozenInstanceError):
        setattr(value, "known_gaps", ("changed",))


def test_coverage_json_round_trip_is_exact() -> None:
    wire: dict[str, JsonValue] = {
        "publication_channels": ["codex_jsonl_import", "local_cli"],
        "authorship_assurance": "self_asserted",
        "artifact_observation": "import_observed",
        "evidence_immutability": "metadata_only",
        "ledger_freshness": "partial",
        "check_types": ["deterministic", "semantic_model_derived"],
        "known_gaps": ["alpha_gap", "beta_gap"],
    }
    decoded = coverage_from_json(wire)
    assert decoded == Coverage(
        publication_channels=(
            PublicationChannel.CODEX_JSONL_IMPORT,
            PublicationChannel.LOCAL_CLI,
        ),
        authorship_assurance=AuthorshipAssurance.SELF_ASSERTED,
        artifact_observation=ArtifactObservation.IMPORT_OBSERVED,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.PARTIAL,
        check_types=(CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED),
        known_gaps=("alpha_gap", "beta_gap"),
    )
    encoded = coverage_to_json(decoded)
    assert encoded == wire
    assert tuple(encoded) == (
        "publication_channels",
        "authorship_assurance",
        "artifact_observation",
        "evidence_immutability",
        "ledger_freshness",
        "check_types",
        "known_gaps",
    )
    assert all(
        type(encoded[key]) is list for key in ("publication_channels", "check_types", "known_gaps")
    )
    assert coverage_from_json(MappingProxyType(wire)) == decoded
    tuple_wire: dict[str, JsonValue] = dict(wire)
    tuple_wire["publication_channels"] = ("codex_jsonl_import", "local_cli")
    tuple_wire["check_types"] = ("deterministic", "semantic_model_derived")
    tuple_wire["known_gaps"] = ("alpha_gap", "beta_gap")
    assert coverage_from_json(MappingProxyType(tuple_wire)) == decoded


@pytest.mark.parametrize(
    "wire",
    (
        None,
        [],
        {},
        {
            "publication_channels": ["local_cli"],
            "authorship_assurance": "self_asserted",
            "artifact_observation": "published_only",
            "evidence_immutability": "metadata_only",
            "ledger_freshness": "current",
            "check_types": ["none"],
            "known_gaps": [],
            "extra": True,
        },
        {
            "publication_channels": "local_cli",
            "authorship_assurance": "self_asserted",
            "artifact_observation": "published_only",
            "evidence_immutability": "metadata_only",
            "ledger_freshness": "current",
            "check_types": ["none"],
            "known_gaps": [],
        },
        {
            "publication_channels": ["unknown"],
            "authorship_assurance": "self_asserted",
            "artifact_observation": "published_only",
            "evidence_immutability": "metadata_only",
            "ledger_freshness": "current",
            "check_types": ["none"],
            "known_gaps": [],
        },
        {
            "publication_channels": ["local_cli"],
            "authorship_assurance": _StringSubclass("self_asserted"),
            "artifact_observation": "published_only",
            "evidence_immutability": "metadata_only",
            "ledger_freshness": "current",
            "check_types": ["none"],
            "known_gaps": [],
        },
    ),
)
def test_coverage_json_rejects_noncanonical_shapes(wire: object) -> None:
    with pytest.raises(ProtocolValueError) as exc_info:
        coverage_from_json(cast(JsonValue, wire))
    _assert_reason(exc_info, "invalid_coverage_value")


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("publication_channels", ["local_cli", "local_cli"], "duplicate_set_member"),
        (
            "publication_channels",
            ["local_cli", "cooperative_mcp"],
            "unsorted_set_field",
        ),
        ("check_types", ["none", "none"], "duplicate_set_member"),
        (
            "check_types",
            ["semantic_model_derived", "deterministic"],
            "unsorted_set_field",
        ),
        ("known_gaps", ["Bad"], "invalid_known_gap"),
        ("known_gaps", ["same_gap", "same_gap"], "duplicate_set_member"),
        ("known_gaps", ["z_gap", "a_gap"], "unsorted_set_field"),
    ),
)
def test_coverage_json_propagates_constructor_owned_set_reasons(
    field: str,
    value: object,
    reason: str,
) -> None:
    wire: dict[str, object] = {
        "publication_channels": ["local_cli"],
        "authorship_assurance": "self_asserted",
        "artifact_observation": "published_only",
        "evidence_immutability": "metadata_only",
        "ledger_freshness": "current",
        "check_types": ["none"],
        "known_gaps": [],
    }
    wire[field] = value
    with pytest.raises(ProtocolValueError) as exc_info:
        coverage_from_json(cast(JsonValue, wire))
    _assert_reason(exc_info, reason)


def test_coverage_json_encoder_rejects_foreign_runtime_types() -> None:
    for invalid in ("coverage", _SpoofedCoverage()):
        with pytest.raises(ProtocolValueError) as exc_info:
            coverage_to_json(cast(Coverage, invalid))
        _assert_reason(exc_info, "invalid_coverage_value")


def test_weakest_merge_is_componentwise_and_lossless() -> None:
    left = Coverage(
        publication_channels=(PublicationChannel.COOPERATIVE_MCP,),
        authorship_assurance=AuthorshipAssurance.LOCALLY_AUTHENTICATED,
        artifact_observation=ArtifactObservation.CONTENT_CAPTURED,
        evidence_immutability=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        ledger_freshness=LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE,
        check_types=(CheckType.DETERMINISTIC,),
        known_gaps=("alpha_gap", "shared_gap"),
    )
    right = Coverage(
        publication_channels=(PublicationChannel.CODEX_JSONL_IMPORT,),
        authorship_assurance=AuthorshipAssurance.SELF_ASSERTED,
        artifact_observation=ArtifactObservation.IMPORT_OBSERVED,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.PARTIAL,
        check_types=(CheckType.NONE,),
        known_gaps=("beta_gap", "shared_gap"),
    )
    merged = weakest(left, right)
    assert merged == Coverage(
        publication_channels=(
            PublicationChannel.CODEX_JSONL_IMPORT,
            PublicationChannel.COOPERATIVE_MCP,
        ),
        authorship_assurance=AuthorshipAssurance.SELF_ASSERTED,
        artifact_observation=ArtifactObservation.IMPORT_OBSERVED,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.PARTIAL,
        check_types=(CheckType.DETERMINISTIC,),
        known_gaps=("alpha_gap", "beta_gap", "shared_gap"),
    )
    assert weakest(left, right) == weakest(right, left)
    assert weakest(left, left) == left

    semantic = _base(check_types=(CheckType.SEMANTIC_MODEL_DERIVED,))
    combined = weakest(left, semantic)
    assert combined.check_types == (
        CheckType.DETERMINISTIC,
        CheckType.SEMANTIC_MODEL_DERIVED,
    )


def test_known_gaps_union_boundaries_and_overflow_fail_closed() -> None:
    first_32 = tuple(f"gap_{index:03d}" for index in range(32))
    final_32 = tuple(f"gap_{index:03d}" for index in range(32, 64))
    boundary = weakest(_base(known_gaps=first_32), _base(known_gaps=final_32))
    assert boundary.known_gaps == first_32 + final_32
    assert len(boundary.known_gaps) == 64

    first_64 = tuple(f"first_{index:03d}" for index in range(64))
    second_64 = tuple(f"second_{index:03d}" for index in range(64))
    first = _base(known_gaps=first_64)
    second = _base(known_gaps=second_64)
    for left, right in ((first, second), (second, first)):
        with pytest.raises(ProtocolValueError) as exc_info:
            weakest(left, right)
        _assert_reason(exc_info, "invalid_known_gap")

    overlapping = _base(known_gaps=first_64)
    one_new = _base(known_gaps=("third_000",))
    with pytest.raises(ProtocolValueError) as sixty_five_exc:
        weakest(overlapping, one_new)
    _assert_reason(sixty_five_exc, "invalid_known_gap")


def test_six_channel_defaults_are_exact() -> None:
    expected = {
        PublicationChannel.COOPERATIVE_MCP: (
            AuthorshipAssurance.SELF_ASSERTED,
            ArtifactObservation.PUBLISHED_ONLY,
            EvidenceImmutability.METADATA_ONLY,
            LedgerFreshness.CURRENT,
            (),
        ),
        PublicationChannel.LOCAL_CLI: (
            AuthorshipAssurance.SELF_ASSERTED,
            ArtifactObservation.PUBLISHED_ONLY,
            EvidenceImmutability.METADATA_ONLY,
            LedgerFreshness.CURRENT,
            (),
        ),
        PublicationChannel.CODEX_JSONL_IMPORT: (
            AuthorshipAssurance.SELF_ASSERTED,
            ArtifactObservation.IMPORT_OBSERVED,
            EvidenceImmutability.METADATA_ONLY,
            LedgerFreshness.PARTIAL,
            ("import_source_range_not_universal",),
        ),
        PublicationChannel.HOOK_OBSERVED: (
            AuthorshipAssurance.HARNESS_OBSERVED,
            ArtifactObservation.HOOK_OBSERVED,
            EvidenceImmutability.METADATA_ONLY,
            LedgerFreshness.CURRENT,
            (),
        ),
        PublicationChannel.ENGINE_DERIVED: (
            AuthorshipAssurance.SERVICE_AUTHENTICATED,
            ArtifactObservation.PUBLISHED_ONLY,
            EvidenceImmutability.METADATA_ONLY,
            LedgerFreshness.CURRENT,
            (),
        ),
        PublicationChannel.HUMAN_IMPORT: (
            AuthorshipAssurance.SELF_ASSERTED,
            ArtifactObservation.IMPORT_OBSERVED,
            EvidenceImmutability.METADATA_ONLY,
            LedgerFreshness.PARTIAL,
            ("human_import_scope_not_universal",),
        ),
    }
    assert isinstance(COVERAGE_DEFAULTS_BY_CHANNEL, MappingProxyType)
    assert tuple(COVERAGE_DEFAULTS_BY_CHANNEL) == tuple(PublicationChannel)
    for channel, dimensions in expected.items():
        value = coverage_for_channel(channel)
        assert value is COVERAGE_DEFAULTS_BY_CHANNEL[channel]
        assert value.publication_channels == (channel,)
        assert (
            value.authorship_assurance,
            value.artifact_observation,
            value.evidence_immutability,
            value.ledger_freshness,
            value.known_gaps,
        ) == dimensions
        assert value.check_types == (CheckType.NONE,)


@pytest.mark.parametrize(
    ("changes", "reason"),
    (
        ({"publication_channels": ()}, "empty_publication_channels"),
        ({"publication_channels": []}, "invalid_publication_channels"),
        (
            {"publication_channels": (_SpoofedPublicationChannel(),)},
            "invalid_publication_channels",
        ),
        (
            {"publication_channels": (PublicationChannel.LOCAL_CLI,) * 2},
            "duplicate_set_member",
        ),
        (
            {
                "publication_channels": (
                    PublicationChannel.LOCAL_CLI,
                    PublicationChannel.COOPERATIVE_MCP,
                )
            },
            "unsorted_set_field",
        ),
        ({"authorship_assurance": "self_asserted"}, "invalid_coverage_value"),
        ({"artifact_observation": "published_only"}, "invalid_coverage_value"),
        ({"evidence_immutability": "metadata_only"}, "invalid_coverage_value"),
        ({"ledger_freshness": "current"}, "invalid_coverage_value"),
        ({"check_types": ()}, "empty_check_types"),
        ({"check_types": []}, "invalid_check_types"),
        ({"check_types": ("none",)}, "invalid_check_types"),
        ({"check_types": (CheckType.NONE,) * 2}, "duplicate_set_member"),
        (
            {"check_types": (CheckType.SEMANTIC_MODEL_DERIVED, CheckType.DETERMINISTIC)},
            "unsorted_set_field",
        ),
        (
            {"check_types": (CheckType.DETERMINISTIC, CheckType.NONE)},
            "invalid_check_types",
        ),
        ({"known_gaps": []}, "invalid_known_gap"),
        ({"known_gaps": tuple(f"gap_{index:03d}" for index in range(65))}, "invalid_known_gap"),
        ({"known_gaps": ("Bad",)}, "invalid_known_gap"),
        ({"known_gaps": ("a" * 129,)}, "invalid_known_gap"),
        ({"known_gaps": (_StringSubclass("valid_gap"),)}, "invalid_known_gap"),
        ({"known_gaps": ("same_gap", "same_gap")}, "duplicate_set_member"),
        ({"known_gaps": ("z_gap", "a_gap")}, "unsorted_set_field"),
    ),
)
def test_coverage_constructor_rejects_noncanonical_values(
    changes: dict[str, object],
    reason: str,
) -> None:
    with pytest.raises(ProtocolValueError) as exc_info:
        _base(**changes)
    _assert_reason(exc_info, reason)


def test_constructor_validation_order_and_exact_container_authority() -> None:
    with pytest.raises(ProtocolValueError) as first_exc:
        _base(
            publication_channels=(),
            authorship_assurance="bad",
            check_types=(),
            known_gaps=("Bad",),
        )
    _assert_reason(first_exc, "empty_publication_channels")

    with pytest.raises(ProtocolValueError) as ordered_exc:
        _base(authorship_assurance="bad", check_types=(), known_gaps=("Bad",))
    _assert_reason(ordered_exc, "invalid_coverage_value")

    tuple_subclass = _TupleSubclass((PublicationChannel.LOCAL_CLI,))
    with pytest.raises(ProtocolValueError) as tuple_exc:
        _base(publication_channels=tuple_subclass)
    _assert_reason(tuple_exc, "invalid_publication_channels")


def test_helper_wrong_types_fail_before_duck_typed_access() -> None:
    for invalid_channel in ("local_cli", _SpoofedPublicationChannel()):
        with pytest.raises(ProtocolValueError) as exc_info:
            coverage_for_channel(cast(PublicationChannel, invalid_channel))
        _assert_reason(exc_info, "invalid_coverage_value")

    valid = _base()
    for left, right in (
        (cast(Coverage, _SpoofedCoverage()), valid),
        (valid, cast(Coverage, _SpoofedCoverage())),
    ):
        with pytest.raises(ProtocolValueError) as exc_info:
            weakest(left, right)
        _assert_reason(exc_info, "invalid_coverage_value")


def test_no_averaging_or_strengthening_surface_exists() -> None:
    for forbidden in ("average", "average_coverage", "coverage_score", "strongest"):
        assert not hasattr(coverage_module, forbidden)
    for channel in PublicationChannel:
        default = coverage_for_channel(channel)
        assert weakest(default, default) == default
