"""Coverage honesty lattice and conservative channel baselines."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType, NotImplementedType
from typing import Final, cast

from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "ARTIFACT_OBSERVATION_ORDER",
    "AUTHORSHIP_ASSURANCE_ORDER",
    "COVERAGE_DEFAULTS_BY_CHANNEL",
    "EVIDENCE_IMMUTABILITY_ORDER",
    "LEDGER_FRESHNESS_ORDER",
    "MAX_KNOWN_GAPS",
    "ArtifactObservation",
    "AuthorshipAssurance",
    "CheckType",
    "Coverage",
    "EvidenceImmutability",
    "LedgerFreshness",
    "PublicationChannel",
    "coverage_from_json",
    "coverage_for_channel",
    "coverage_to_json",
    "weakest",
]

MAX_KNOWN_GAPS: Final = 64


class PublicationChannel(str, Enum):  # noqa: UP042 - wire values require str-valued Enum
    COOPERATIVE_MCP = "cooperative_mcp"
    LOCAL_CLI = "local_cli"
    CODEX_JSONL_IMPORT = "codex_jsonl_import"
    HOOK_OBSERVED = "hook_observed"
    ENGINE_DERIVED = "engine_derived"
    HUMAN_IMPORT = "human_import"


class _OrderedCoverageEnum(Enum):
    def _other_rank(self, other: object) -> int | NotImplementedType:
        if type(self) is not type(other):
            return NotImplemented
        return _ordered_rank(cast(_OrderedCoverageEnum, other))

    def __lt__(self, other: object) -> bool | NotImplementedType:
        other_rank = self._other_rank(other)
        if other_rank is NotImplemented:
            return NotImplemented
        return _ordered_rank(self) < other_rank

    def __le__(self, other: object) -> bool | NotImplementedType:
        other_rank = self._other_rank(other)
        if other_rank is NotImplemented:
            return NotImplemented
        return _ordered_rank(self) <= other_rank

    def __gt__(self, other: object) -> bool | NotImplementedType:
        other_rank = self._other_rank(other)
        if other_rank is NotImplemented:
            return NotImplemented
        return _ordered_rank(self) > other_rank

    def __ge__(self, other: object) -> bool | NotImplementedType:
        other_rank = self._other_rank(other)
        if other_rank is NotImplemented:
            return NotImplemented
        return _ordered_rank(self) >= other_rank


class AuthorshipAssurance(_OrderedCoverageEnum):
    SELF_ASSERTED = "self_asserted"
    HARNESS_OBSERVED = "harness_observed"
    LOCALLY_AUTHENTICATED = "locally_authenticated"
    SERVICE_AUTHENTICATED = "service_authenticated"
    CRYPTOGRAPHICALLY_ATTESTED = "cryptographically_attested"


class ArtifactObservation(_OrderedCoverageEnum):
    PUBLISHED_ONLY = "published_only"
    IMPORT_OBSERVED = "import_observed"
    HOOK_OBSERVED = "hook_observed"
    CONTENT_CAPTURED = "content_captured"
    ARTIFACT_VERIFIED = "artifact_verified"
    INDEPENDENTLY_REPRODUCED = "independently_reproduced"


class EvidenceImmutability(_OrderedCoverageEnum):
    MUTABLE_REFERENCE = "mutable_reference"
    METADATA_ONLY = "metadata_only"
    CONTENT_DIGEST = "content_digest"
    IMMUTABLE_SNAPSHOT = "immutable_snapshot"
    INDEPENDENTLY_REPRODUCED = "independently_reproduced"


class LedgerFreshness(_OrderedCoverageEnum):
    UNKNOWN = "unknown"
    REDACTED_GAP = "redacted_gap"
    PARTIAL = "partial"
    STALE_AFTER_MATERIAL_CHANGE = "stale_after_material_change"
    CURRENT = "current"


class CheckType(str, Enum):  # noqa: UP042 - wire values require str-valued Enum
    NONE = "none"
    DETERMINISTIC = "deterministic"
    SEMANTIC_MODEL_DERIVED = "semantic_model_derived"


AUTHORSHIP_ASSURANCE_ORDER: Final[MappingProxyType[AuthorshipAssurance, int]] = MappingProxyType(
    {
        AuthorshipAssurance.SELF_ASSERTED: 0,
        AuthorshipAssurance.HARNESS_OBSERVED: 1,
        AuthorshipAssurance.LOCALLY_AUTHENTICATED: 2,
        AuthorshipAssurance.SERVICE_AUTHENTICATED: 3,
        AuthorshipAssurance.CRYPTOGRAPHICALLY_ATTESTED: 4,
    }
)
ARTIFACT_OBSERVATION_ORDER: Final[MappingProxyType[ArtifactObservation, int]] = MappingProxyType(
    {
        ArtifactObservation.PUBLISHED_ONLY: 0,
        ArtifactObservation.IMPORT_OBSERVED: 1,
        ArtifactObservation.HOOK_OBSERVED: 2,
        ArtifactObservation.CONTENT_CAPTURED: 3,
        ArtifactObservation.ARTIFACT_VERIFIED: 4,
        ArtifactObservation.INDEPENDENTLY_REPRODUCED: 5,
    }
)
EVIDENCE_IMMUTABILITY_ORDER: Final[MappingProxyType[EvidenceImmutability, int]] = MappingProxyType(
    {
        EvidenceImmutability.MUTABLE_REFERENCE: 0,
        EvidenceImmutability.METADATA_ONLY: 1,
        EvidenceImmutability.CONTENT_DIGEST: 2,
        EvidenceImmutability.IMMUTABLE_SNAPSHOT: 3,
        EvidenceImmutability.INDEPENDENTLY_REPRODUCED: 4,
    }
)
LEDGER_FRESHNESS_ORDER: Final[MappingProxyType[LedgerFreshness, int]] = MappingProxyType(
    {
        LedgerFreshness.UNKNOWN: 0,
        LedgerFreshness.REDACTED_GAP: 1,
        LedgerFreshness.PARTIAL: 2,
        LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE: 3,
        LedgerFreshness.CURRENT: 4,
    }
)

_GAP_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,127}$", re.ASCII)
_CHECK_TYPE_SHAPES: Final[frozenset[tuple[CheckType, ...]]] = frozenset(
    {
        (CheckType.NONE,),
        (CheckType.DETERMINISTIC,),
        (CheckType.SEMANTIC_MODEL_DERIVED,),
        (CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED),
    }
)
_COVERAGE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "publication_channels",
        "authorship_assurance",
        "artifact_observation",
        "evidence_immutability",
        "ledger_freshness",
        "check_types",
        "known_gaps",
    }
)


def _ordered_rank(value: _OrderedCoverageEnum) -> int:
    if type(value) is AuthorshipAssurance:
        return AUTHORSHIP_ASSURANCE_ORDER[value]
    if type(value) is ArtifactObservation:
        return ARTIFACT_OBSERVATION_ORDER[value]
    if type(value) is EvidenceImmutability:
        return EVIDENCE_IMMUTABILITY_ORDER[value]
    if type(value) is LedgerFreshness:
        return LEDGER_FRESHNESS_ORDER[value]
    raise TypeError("coverage_order_type_invalid")


def _validate_sorted_enum_tuple(
    values: tuple[object, ...],
    expected_type: type[Enum],
    invalid_reason: str,
) -> None:
    previous_value: str | None = None
    for member in values:
        if type(member) is not expected_type:
            raise ProtocolValueError(invalid_reason)
        wire_value = member.value
        if type(wire_value) is not str:
            raise ProtocolValueError(invalid_reason)
        if previous_value is not None:
            if wire_value == previous_value:
                raise ProtocolValueError("duplicate_set_member")
            if wire_value.encode("ascii") < previous_value.encode("ascii"):
                raise ProtocolValueError("unsorted_set_field")
        previous_value = wire_value


def _validate_publication_channels(value: object) -> None:
    if type(value) is not tuple:
        raise ProtocolValueError("invalid_publication_channels")
    channels = cast(tuple[object, ...], value)
    if not channels:
        raise ProtocolValueError("empty_publication_channels")
    _validate_sorted_enum_tuple(
        channels,
        PublicationChannel,
        "invalid_publication_channels",
    )


def _validate_check_types(value: object) -> None:
    if type(value) is not tuple:
        raise ProtocolValueError("invalid_check_types")
    checks = cast(tuple[object, ...], value)
    if not checks:
        raise ProtocolValueError("empty_check_types")
    _validate_sorted_enum_tuple(checks, CheckType, "invalid_check_types")
    if cast(tuple[CheckType, ...], checks) not in _CHECK_TYPE_SHAPES:
        raise ProtocolValueError("invalid_check_types")


def _validate_known_gaps(value: object) -> None:
    if type(value) is not tuple:
        raise ProtocolValueError("invalid_known_gap")
    gaps = cast(tuple[object, ...], value)
    if len(gaps) > MAX_KNOWN_GAPS:
        raise ProtocolValueError("invalid_known_gap")
    previous: str | None = None
    for gap in gaps:
        if type(gap) is not str or _GAP_PATTERN.fullmatch(gap) is None:
            raise ProtocolValueError("invalid_known_gap")
        if previous is not None:
            if gap == previous:
                raise ProtocolValueError("duplicate_set_member")
            if gap.encode("ascii") < previous.encode("ascii"):
                raise ProtocolValueError("unsorted_set_field")
        previous = gap


@dataclass(frozen=True, slots=True)
class Coverage:
    publication_channels: tuple[PublicationChannel, ...]
    authorship_assurance: AuthorshipAssurance
    artifact_observation: ArtifactObservation
    evidence_immutability: EvidenceImmutability
    ledger_freshness: LedgerFreshness
    check_types: tuple[CheckType, ...]
    known_gaps: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_publication_channels(self.publication_channels)
        if type(self.authorship_assurance) is not AuthorshipAssurance:
            raise ProtocolValueError("invalid_coverage_value")
        if type(self.artifact_observation) is not ArtifactObservation:
            raise ProtocolValueError("invalid_coverage_value")
        if type(self.evidence_immutability) is not EvidenceImmutability:
            raise ProtocolValueError("invalid_coverage_value")
        if type(self.ledger_freshness) is not LedgerFreshness:
            raise ProtocolValueError("invalid_coverage_value")
        _validate_check_types(self.check_types)
        _validate_known_gaps(self.known_gaps)


def _actual_mapping(value: object) -> bool:
    try:
        return issubclass(type(value), Mapping)
    except BaseException:
        return False


def _coverage_json_object(value: object) -> Mapping[object, object]:
    if not _actual_mapping(value):
        raise ProtocolValueError("invalid_coverage_value")
    source = cast(Mapping[object, object], value)
    try:
        keys = tuple(source)
    except Exception as exc:
        raise ProtocolValueError("invalid_coverage_value") from exc
    if (
        len(keys) != len(_COVERAGE_KEYS)
        or any(type(key) is not str for key in keys)
        or frozenset(cast(tuple[str, ...], keys)) != _COVERAGE_KEYS
    ):
        raise ProtocolValueError("invalid_coverage_value")
    return source


def _coverage_json_field(source: Mapping[object, object], key: str) -> object:
    try:
        return source[key]
    except Exception as exc:
        raise ProtocolValueError("invalid_coverage_value") from exc


def _coverage_json_array(source: Mapping[object, object], key: str) -> tuple[object, ...]:
    value = _coverage_json_field(source, key)
    if type(value) is list:
        return tuple(cast(list[object], value))
    if type(value) is tuple:
        return cast(tuple[object, ...], value)
    raise ProtocolValueError("invalid_coverage_value")


def _coverage_json_enum[T: Enum](value: object, enum_type: type[T]) -> T:
    if type(value) is not str:
        raise ProtocolValueError("invalid_coverage_value")
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ProtocolValueError("invalid_coverage_value") from exc


def coverage_from_json(value: JsonValue) -> Coverage:
    """Decode the exact closed coverage JSON object without normalizing its sets."""

    source = _coverage_json_object(value)
    channels = tuple(
        _coverage_json_enum(member, PublicationChannel)
        for member in _coverage_json_array(source, "publication_channels")
    )
    authorship = _coverage_json_enum(
        _coverage_json_field(source, "authorship_assurance"),
        AuthorshipAssurance,
    )
    observation = _coverage_json_enum(
        _coverage_json_field(source, "artifact_observation"),
        ArtifactObservation,
    )
    immutability = _coverage_json_enum(
        _coverage_json_field(source, "evidence_immutability"),
        EvidenceImmutability,
    )
    freshness = _coverage_json_enum(
        _coverage_json_field(source, "ledger_freshness"),
        LedgerFreshness,
    )
    checks = tuple(
        _coverage_json_enum(member, CheckType)
        for member in _coverage_json_array(source, "check_types")
    )
    gaps = _coverage_json_array(source, "known_gaps")
    return Coverage(
        publication_channels=channels,
        authorship_assurance=authorship,
        artifact_observation=observation,
        evidence_immutability=immutability,
        ledger_freshness=freshness,
        check_types=checks,
        known_gaps=cast(tuple[str, ...], gaps),
    )


def coverage_to_json(coverage: Coverage) -> dict[str, JsonValue]:
    """Encode an exact coverage value as the closed schema object."""

    if type(coverage) is not Coverage:
        raise ProtocolValueError("invalid_coverage_value")
    return {
        "publication_channels": [member.value for member in coverage.publication_channels],
        "authorship_assurance": coverage.authorship_assurance.value,
        "artifact_observation": coverage.artifact_observation.value,
        "evidence_immutability": coverage.evidence_immutability.value,
        "ledger_freshness": coverage.ledger_freshness.value,
        "check_types": [member.value for member in coverage.check_types],
        "known_gaps": list(coverage.known_gaps),
    }


def _coverage(
    channel: PublicationChannel,
    authorship: AuthorshipAssurance,
    observation: ArtifactObservation,
    immutability: EvidenceImmutability,
    freshness: LedgerFreshness,
    gaps: tuple[str, ...] = (),
) -> Coverage:
    return Coverage(
        publication_channels=(channel,),
        authorship_assurance=authorship,
        artifact_observation=observation,
        evidence_immutability=immutability,
        ledger_freshness=freshness,
        check_types=(CheckType.NONE,),
        known_gaps=gaps,
    )


COVERAGE_DEFAULTS_BY_CHANNEL: Final[MappingProxyType[PublicationChannel, Coverage]] = (
    MappingProxyType(
        {
            PublicationChannel.COOPERATIVE_MCP: _coverage(
                PublicationChannel.COOPERATIVE_MCP,
                AuthorshipAssurance.SELF_ASSERTED,
                ArtifactObservation.PUBLISHED_ONLY,
                EvidenceImmutability.METADATA_ONLY,
                LedgerFreshness.CURRENT,
            ),
            PublicationChannel.LOCAL_CLI: _coverage(
                PublicationChannel.LOCAL_CLI,
                AuthorshipAssurance.SELF_ASSERTED,
                ArtifactObservation.PUBLISHED_ONLY,
                EvidenceImmutability.METADATA_ONLY,
                LedgerFreshness.CURRENT,
            ),
            PublicationChannel.CODEX_JSONL_IMPORT: _coverage(
                PublicationChannel.CODEX_JSONL_IMPORT,
                AuthorshipAssurance.SELF_ASSERTED,
                ArtifactObservation.IMPORT_OBSERVED,
                EvidenceImmutability.METADATA_ONLY,
                LedgerFreshness.PARTIAL,
                ("import_source_range_not_universal",),
            ),
            PublicationChannel.HOOK_OBSERVED: _coverage(
                PublicationChannel.HOOK_OBSERVED,
                AuthorshipAssurance.HARNESS_OBSERVED,
                ArtifactObservation.HOOK_OBSERVED,
                EvidenceImmutability.METADATA_ONLY,
                LedgerFreshness.CURRENT,
            ),
            PublicationChannel.ENGINE_DERIVED: _coverage(
                PublicationChannel.ENGINE_DERIVED,
                AuthorshipAssurance.SERVICE_AUTHENTICATED,
                ArtifactObservation.PUBLISHED_ONLY,
                EvidenceImmutability.METADATA_ONLY,
                LedgerFreshness.CURRENT,
            ),
            PublicationChannel.HUMAN_IMPORT: _coverage(
                PublicationChannel.HUMAN_IMPORT,
                AuthorshipAssurance.SELF_ASSERTED,
                ArtifactObservation.IMPORT_OBSERVED,
                EvidenceImmutability.METADATA_ONLY,
                LedgerFreshness.PARTIAL,
                ("human_import_scope_not_universal",),
            ),
        }
    )
)


def _weaker[T: _OrderedCoverageEnum](
    left: T,
    right: T,
    order: MappingProxyType[T, int],
) -> T:
    if order[left] <= order[right]:
        return left
    return right


def weakest(a: Coverage, b: Coverage) -> Coverage:
    """Merge two values without strengthening or dropping representable gaps."""

    if type(a) is not Coverage or type(b) is not Coverage:
        raise ProtocolValueError("invalid_coverage_value")
    channels = tuple(
        sorted(
            set(a.publication_channels) | set(b.publication_channels),
            key=lambda channel: channel.value.encode("ascii"),
        )
    )
    check_set = set(a.check_types) | set(b.check_types)
    if check_set - {CheckType.NONE}:
        check_set.discard(CheckType.NONE)
    checks = tuple(sorted(check_set, key=lambda check: check.value.encode("ascii")))
    gap_set = set(a.known_gaps) | set(b.known_gaps)
    if len(gap_set) > MAX_KNOWN_GAPS:
        raise ProtocolValueError("invalid_known_gap")
    gaps = tuple(sorted(gap_set, key=lambda gap: gap.encode("ascii")))
    return Coverage(
        publication_channels=channels,
        authorship_assurance=_weaker(
            a.authorship_assurance,
            b.authorship_assurance,
            AUTHORSHIP_ASSURANCE_ORDER,
        ),
        artifact_observation=_weaker(
            a.artifact_observation,
            b.artifact_observation,
            ARTIFACT_OBSERVATION_ORDER,
        ),
        evidence_immutability=_weaker(
            a.evidence_immutability,
            b.evidence_immutability,
            EVIDENCE_IMMUTABILITY_ORDER,
        ),
        ledger_freshness=_weaker(
            a.ledger_freshness,
            b.ledger_freshness,
            LEDGER_FRESHNESS_ORDER,
        ),
        check_types=checks,
        known_gaps=gaps,
    )


def coverage_for_channel(channel: PublicationChannel) -> Coverage:
    """Return the exact conservative baseline guaranteed by a publication channel."""

    if type(channel) is not PublicationChannel:
        raise ProtocolValueError("invalid_coverage_value")
    return COVERAGE_DEFAULTS_BY_CHANNEL[channel]
