from __future__ import annotations

from string import ascii_lowercase, digits

from hypothesis import given
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from finishup.protocol.coverage import (
    ARTIFACT_OBSERVATION_ORDER,
    AUTHORSHIP_ASSURANCE_ORDER,
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
    weakest,
)


def _ascii_sort_key(value: str) -> bytes:
    return value.encode("ascii")


def _channel_tuples() -> SearchStrategy[tuple[PublicationChannel, ...]]:
    return st.lists(
        st.sampled_from(tuple(PublicationChannel)),
        min_size=1,
        max_size=len(PublicationChannel),
        unique=True,
    ).map(lambda values: tuple(sorted(values, key=lambda item: _ascii_sort_key(item.value))))


def _join_gap_token(first: str, suffix: str) -> str:
    return first + suffix


def _gap_tokens() -> SearchStrategy[str]:
    return st.builds(
        _join_gap_token,
        st.sampled_from(tuple(ascii_lowercase)),
        st.text(alphabet=ascii_lowercase + digits + "_", min_size=0, max_size=15),
    )


def _gap_tuples() -> SearchStrategy[tuple[str, ...]]:
    return st.lists(_gap_tokens(), max_size=5, unique=True).map(
        lambda values: tuple(sorted(values, key=_ascii_sort_key))
    )


_CHECK_SHAPES: tuple[tuple[CheckType, ...], ...] = (
    (CheckType.NONE,),
    (CheckType.DETERMINISTIC,),
    (CheckType.SEMANTIC_MODEL_DERIVED,),
    (CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED),
)

_COVERAGES: SearchStrategy[Coverage] = st.builds(
    Coverage,
    publication_channels=_channel_tuples(),
    authorship_assurance=st.sampled_from(tuple(AuthorshipAssurance)),
    artifact_observation=st.sampled_from(tuple(ArtifactObservation)),
    evidence_immutability=st.sampled_from(tuple(EvidenceImmutability)),
    ledger_freshness=st.sampled_from(tuple(LedgerFreshness)),
    check_types=st.sampled_from(_CHECK_SHAPES),
    known_gaps=_gap_tuples(),
)


@given(_COVERAGES, _COVERAGES, _COVERAGES)
def test_weakest_merge_is_commutative_and_associative(
    first: Coverage,
    second: Coverage,
    third: Coverage,
) -> None:
    assert weakest(first, second) == weakest(second, first)
    assert weakest(weakest(first, second), third) == weakest(first, weakest(second, third))


@given(_COVERAGES)
def test_weakest_merge_is_idempotent(value: Coverage) -> None:
    assert weakest(value, value) == value


@given(_COVERAGES, _COVERAGES)
def test_gaps_union_and_sorting_are_stable(left: Coverage, right: Coverage) -> None:
    merged = weakest(left, right)
    expected = tuple(sorted(set(left.known_gaps) | set(right.known_gaps), key=_ascii_sort_key))
    assert merged.known_gaps == expected
    assert len(merged.known_gaps) == len(set(merged.known_gaps))


@given(_COVERAGES, _COVERAGES)
def test_merge_never_strengthens_ordered_dimensions(left: Coverage, right: Coverage) -> None:
    merged = weakest(left, right)
    assert AUTHORSHIP_ASSURANCE_ORDER[merged.authorship_assurance] <= min(
        AUTHORSHIP_ASSURANCE_ORDER[left.authorship_assurance],
        AUTHORSHIP_ASSURANCE_ORDER[right.authorship_assurance],
    )
    assert ARTIFACT_OBSERVATION_ORDER[merged.artifact_observation] <= min(
        ARTIFACT_OBSERVATION_ORDER[left.artifact_observation],
        ARTIFACT_OBSERVATION_ORDER[right.artifact_observation],
    )
    assert EVIDENCE_IMMUTABILITY_ORDER[merged.evidence_immutability] <= min(
        EVIDENCE_IMMUTABILITY_ORDER[left.evidence_immutability],
        EVIDENCE_IMMUTABILITY_ORDER[right.evidence_immutability],
    )
    assert LEDGER_FRESHNESS_ORDER[merged.ledger_freshness] <= min(
        LEDGER_FRESHNESS_ORDER[left.ledger_freshness],
        LEDGER_FRESHNESS_ORDER[right.ledger_freshness],
    )


def test_channel_defaults_do_not_strengthen_input() -> None:
    for channel in PublicationChannel:
        baseline = coverage_for_channel(channel)
        strongest_same_channel = Coverage(
            publication_channels=(channel,),
            authorship_assurance=AuthorshipAssurance.CRYPTOGRAPHICALLY_ATTESTED,
            artifact_observation=ArtifactObservation.INDEPENDENTLY_REPRODUCED,
            evidence_immutability=EvidenceImmutability.INDEPENDENTLY_REPRODUCED,
            ledger_freshness=LedgerFreshness.CURRENT,
            check_types=(CheckType.NONE,),
            known_gaps=(),
        )
        assert weakest(baseline, strongest_same_channel) == baseline
