"""Honesty conformance: weaker coverage never yields a stronger public conclusion.

These tests systematically weaken one coverage dimension at a time (authorship assurance,
artifact observation, evidence immutability, ledger freshness) and prove the merged ``weakest``
result, the retained ``known_gaps`` labels, and a finding's ``rank_key`` ordering all track the
weaker input -- never the stronger one. They also prove imported and redacted material can never
be strengthened back to current/complete coverage by combining it with stronger evidence.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from itertools import pairwise
from typing import cast

import pytest

from builders import ids as id_builders
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    Finding,
    FindingKind,
    FindingOrigin,
    rank_key,
)
from finishup.domain.values import (
    Frontier,
)
from finishup.domain.values import (
    finding_id as domain_finding_id,
)
from finishup.domain.values import (
    obligation_id as domain_obligation_id,
)
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
    weakest,
)

_DIGEST = "sha256:" + "5" * 64

# Mirrors the closed work-integrity/research-evidence partition owned by
# ``finishup.domain.findings`` (private there); duplicated here only to route valid
# ``policy_id``/``policy_version`` pairs into constructed probe findings.
_WORK_INTEGRITY_KINDS = frozenset(
    {
        FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
        FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
        FindingKind.FAILED_WORK_OMITTED,
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
        FindingKind.RESULT_WITHOUT_ACTION,
        FindingKind.ACTION_WITHOUT_RESULT,
        FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
        FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED,
        FindingKind.LEDGER_STALE_OR_INCOMPLETE,
        FindingKind.WEAK_OR_STALE_RESPONSE,
    }
)
_COORDINATION_KINDS = frozenset({FindingKind.COORDINATION_OVERLAP})

_DIMENSION_ATTRIBUTES = (
    "authorship_assurance",
    "artifact_observation",
    "evidence_immutability",
    "ledger_freshness",
)


def _coverage(**overrides: object) -> Coverage:
    values: dict[str, object] = {
        "publication_channels": (PublicationChannel.ENGINE_DERIVED,),
        "authorship_assurance": AuthorshipAssurance.SERVICE_AUTHENTICATED,
        "artifact_observation": ArtifactObservation.ARTIFACT_VERIFIED,
        "evidence_immutability": EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        "ledger_freshness": LedgerFreshness.CURRENT,
        "check_types": (CheckType.DETERMINISTIC,),
        "known_gaps": (),
    }
    values.update(overrides)
    return Coverage(
        publication_channels=cast(tuple[PublicationChannel, ...], values["publication_channels"]),
        authorship_assurance=cast(AuthorshipAssurance, values["authorship_assurance"]),
        artifact_observation=cast(ArtifactObservation, values["artifact_observation"]),
        evidence_immutability=cast(EvidenceImmutability, values["evidence_immutability"]),
        ledger_freshness=cast(LedgerFreshness, values["ledger_freshness"]),
        check_types=cast(tuple[CheckType, ...], values["check_types"]),
        known_gaps=cast(tuple[str, ...], values["known_gaps"]),
    )


def _policy_identity(kind: FindingKind) -> tuple[str, str]:
    return (
        ("work-integrity", "0.1.0")
        if kind in _WORK_INTEGRITY_KINDS
        else ("coordination", "0.1.0")
        if kind in _COORDINATION_KINDS
        else ("research-evidence", "0.1.0")
    )


def _finding(kind: FindingKind, coverage: Coverage, seed: str) -> Finding:
    policy_id, policy_version = _policy_identity(kind)
    priority, _ = FINDING_KIND_TRAITS[kind]
    return Finding(
        finding_id=domain_finding_id(
            id_builders.finding_id(f"coverage-weakening-{kind.value}-{seed}")
        ),
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=priority,
        summary="Coverage weakening probe finding.",
        detail="Constructed only to compare rank_key ordering across coverage strength.",
        subject_refs=(
            domain_obligation_id(id_builders.obligation_id(f"coverage-weakening-{kind.value}")),
        ),
        policy_id=policy_id,
        policy_version=policy_version,
        subject_frontier=Frontier(1, _DIGEST),
        coverage=coverage,
        provenance=None,
    )


def _check_dimension_weakening[T: Enum](
    attribute: str, enum_type: type[T], order: Mapping[T, int]
) -> None:
    ordered_members = tuple(sorted(enum_type, key=lambda member: order[member]))
    assert len(ordered_members) >= 2

    for weaker, stronger in pairwise(ordered_members):
        assert order[weaker] < order[stronger]
        strong_cov = _coverage(**{attribute: stronger})
        weak_cov = _coverage(**{attribute: weaker})
        merged_forward = weakest(strong_cov, weak_cov)
        merged_backward = weakest(weak_cov, strong_cov)

        # Order of arguments never matters, and the weaker member always wins.
        assert merged_forward == merged_backward
        assert getattr(merged_forward, attribute) is weaker

        # No other dimension moved: both inputs shared the same baseline elsewhere.
        for other_attribute in _DIMENSION_ATTRIBUTES:
            if other_attribute != attribute:
                assert getattr(merged_forward, other_attribute) == getattr(
                    strong_cov, other_attribute
                )

    # Merging the strongest and weakest values on the ladder always collapses to the weakest.
    strongest_member = ordered_members[-1]
    weakest_member = ordered_members[0]
    collapsed = weakest(
        _coverage(**{attribute: strongest_member}),
        _coverage(**{attribute: weakest_member}),
    )
    assert getattr(collapsed, attribute) is weakest_member

    # Weakening never round-trips back to strength: re-merging with the strong value again
    # cannot undo the earlier weakening (monotonic, not oscillating).
    re_merged = weakest(collapsed, _coverage(**{attribute: strongest_member}))
    assert getattr(re_merged, attribute) is weakest_member


def test_dimension_by_dimension_weakening() -> None:
    """Weakening exactly one dimension always makes ``weakest`` follow the weaker value."""

    _check_dimension_weakening(
        "authorship_assurance", AuthorshipAssurance, AUTHORSHIP_ASSURANCE_ORDER
    )
    _check_dimension_weakening(
        "artifact_observation", ArtifactObservation, ARTIFACT_OBSERVATION_ORDER
    )
    _check_dimension_weakening(
        "evidence_immutability", EvidenceImmutability, EVIDENCE_IMMUTABILITY_ORDER
    )
    _check_dimension_weakening("ledger_freshness", LedgerFreshness, LEDGER_FRESHNESS_ORDER)


def test_imported_partial_and_redacted_material_stays_weak() -> None:
    """Combining imported or redacted coverage with stronger evidence never restores strength."""

    strong = COVERAGE_DEFAULTS_BY_CHANNEL[PublicationChannel.ENGINE_DERIVED]
    assert strong.ledger_freshness is LedgerFreshness.CURRENT
    assert strong.known_gaps == ()

    independently_verified = _coverage(
        authorship_assurance=AuthorshipAssurance.CRYPTOGRAPHICALLY_ATTESTED,
        artifact_observation=ArtifactObservation.INDEPENDENTLY_REPRODUCED,
        evidence_immutability=EvidenceImmutability.INDEPENDENTLY_REPRODUCED,
        ledger_freshness=LedgerFreshness.CURRENT,
        known_gaps=(),
    )

    for channel, expected_gap in (
        (PublicationChannel.CODEX_JSONL_IMPORT, "import_source_range_not_universal"),
        (PublicationChannel.HUMAN_IMPORT, "human_import_scope_not_universal"),
    ):
        imported = COVERAGE_DEFAULTS_BY_CHANNEL[channel]
        assert imported.ledger_freshness is LedgerFreshness.PARTIAL
        assert imported.artifact_observation is ArtifactObservation.IMPORT_OBSERVED
        assert imported.known_gaps == (expected_gap,)

        for stronger in (strong, independently_verified):
            merged = weakest(stronger, imported)
            assert merged.ledger_freshness is LedgerFreshness.PARTIAL
            # The merged observation is never stronger than the import's own weak value (it may be
            # even weaker, e.g. an engine-derived default whose own observation ordinal is lower).
            assert (
                ARTIFACT_OBSERVATION_ORDER[merged.artifact_observation]
                <= ARTIFACT_OBSERVATION_ORDER[imported.artifact_observation]
            )
            assert expected_gap in merged.known_gaps
            # The strongest possible other evidence still cannot erase the import gap.
            assert (
                weakest(merged, independently_verified).ledger_freshness is LedgerFreshness.PARTIAL
            )

        # Against evidence that is strictly stronger on every dimension, the import's own
        # artifact-observation value survives unchanged -- it is not further weakened either.
        merged_against_strongest = weakest(independently_verified, imported)
        assert merged_against_strongest.artifact_observation is ArtifactObservation.IMPORT_OBSERVED

    redacted = _coverage(
        ledger_freshness=LedgerFreshness.REDACTED_GAP,
        known_gaps=("content_unavailable_redacted",),
    )
    assert (
        LEDGER_FRESHNESS_ORDER[LedgerFreshness.REDACTED_GAP]
        < LEDGER_FRESHNESS_ORDER[LedgerFreshness.PARTIAL]
    )
    for other in (
        strong,
        independently_verified,
        COVERAGE_DEFAULTS_BY_CHANNEL[PublicationChannel.CODEX_JSONL_IMPORT],
    ):
        merged = weakest(other, redacted)
        assert merged.ledger_freshness is LedgerFreshness.REDACTED_GAP
        assert "content_unavailable_redacted" in merged.known_gaps


@pytest.mark.parametrize("kind", tuple(FindingKind))
def test_result_language_tracks_weakest_coverage(kind: FindingKind) -> None:
    """A finding's rank always follows its weakest coverage, never a stronger wished-for one."""

    strong = _coverage()
    weak = _coverage(
        authorship_assurance=AuthorshipAssurance.SELF_ASSERTED,
        artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
        evidence_immutability=EvidenceImmutability.MUTABLE_REFERENCE,
        ledger_freshness=LedgerFreshness.PARTIAL,
        known_gaps=("source_unavailable",),
    )
    strong_finding = _finding(kind, strong, "strong")
    weak_finding = _finding(kind, weak, "weak")

    # Same kind (same fixed priority/actionable prefix); only coverage strength differs, and the
    # stronger-covered finding always sorts ahead of (ranks better than) the weaker one.
    assert rank_key(strong_finding) < rank_key(weak_finding)

    merged = weakest(strong, weak)
    assert merged.authorship_assurance is weak.authorship_assurance
    assert merged.artifact_observation is weak.artifact_observation
    assert merged.evidence_immutability is weak.evidence_immutability
    assert merged.ledger_freshness is weak.ledger_freshness
    assert merged.known_gaps == weak.known_gaps

    # A finding stamped with the merged (necessarily weakest) coverage never outranks the
    # originally weak finding -- merging with something stronger provided no upgrade.
    merged_finding = _finding(kind, merged, "merged")
    assert rank_key(merged_finding)[:-1] == rank_key(weak_finding)[:-1]
