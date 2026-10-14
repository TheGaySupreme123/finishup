"""Focused eligibility tests for the deterministic-only scoped verdict (#971)."""

from __future__ import annotations

from yoetz.domain.check_totals import CHECK_TOTAL_KEYS
from yoetz.domain.findings import FINDING_KIND_TRAITS, Finding, FindingKind, FindingOrigin
from yoetz.domain.values import Frontier, finding_id, obligation_id
from yoetz.kernel.deterministic_scope import deterministic_scope_is_clean
from yoetz.kernel.ranking import CheckCompleteness, RankingContext, rank_findings
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)

_DIGEST = "sha256:" + "1" * 64


def _coverage(*gaps: str) -> Coverage:
    return Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.ARTIFACT_VERIFIED,
        evidence_immutability=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        ledger_freshness=LedgerFreshness.CURRENT,
        check_types=(CheckType.DETERMINISTIC,),
        known_gaps=tuple(sorted(gaps)),
    )


def _totals(**overrides: int) -> dict[str, dict[str, str]]:
    groups = {group: {key: "0" for key in keys} for group, keys in CHECK_TOTAL_KEYS.items()}
    groups["obligations"]["scope_known"] = "1"
    for location, value in overrides.items():
        group, key = location.split(".", 1)
        groups[group][key] = str(value)
    return groups


def _actionable_finding() -> Finding:
    kind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
    return Finding(
        finding_id=finding_id("fnd_00000000-0000-4000-8000-000000000001"),
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="finding",
        detail="detail",
        subject_refs=(obligation_id("obl_00000000-0000-4000-8000-000000000001"),),
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=Frontier(1, _DIGEST),
        coverage=_coverage("semantic_review_not_requested"),
        provenance=None,
    )


def test_scope_allows_only_standing_gaps() -> None:
    assert deterministic_scope_is_clean(
        coverage=_coverage(
            "semantic_review_not_requested",
            "plan_unrefined_before_first_edit",
            "preexisting_test_modified",
        ),
        totals=_totals(),
        findings=(),
    )
    # #986: standing host-observation gaps a local absence proof tolerates may accompany the
    # scoped verdict; the command counters still keep an unknown outcome from reading clean.
    assert deterministic_scope_is_clean(
        coverage=_coverage("host_outcome_unavailable", "unpaired_event"),
        totals=_totals(),
        findings=(),
    )
    # A standing gap a local proof does not tolerate, or an actionable one, still blocks it.
    for gap in ("observation_input_loss", "check_not_recorded"):
        assert not deterministic_scope_is_clean(
            coverage=_coverage(gap),
            totals=_totals(),
            findings=(),
        )


def test_scope_rejects_recorded_work_that_still_needs_attention() -> None:
    for override in (
        "obligations.scope_known",
        "obligations.open",
        "obligations.unreadable",
        "requested_items.unattempted",
        "commands.live_failed",
        "commands.unknown",
        "test_edits.unjustified",
        "test_edits.unknown",
    ):
        assert not deterministic_scope_is_clean(
            coverage=_coverage("semantic_review_not_requested"),
            totals=_totals(**{override: 0 if override == "obligations.scope_known" else 1}),
            findings=(),
        )
    assert not deterministic_scope_is_clean(
        coverage=_coverage("semantic_review_not_requested"),
        totals=_totals(),
        findings=(_actionable_finding(),),
    )


def test_scoped_ranking_returns_local_verdict_and_keeps_actionable_findings_actionable() -> None:
    coverage = _coverage("semantic_review_not_requested")
    clean = rank_findings(
        (),
        (),
        RankingContext(coverage, CheckCompleteness.SCOPED_COMPLETE),
        3,
    )
    assert clean.verdict.value == "no_issue_detected"
    actionable = _actionable_finding()
    ranked = rank_findings(
        (actionable,),
        (),
        RankingContext(coverage, CheckCompleteness.SCOPED_COMPLETE),
        3,
    )
    assert ranked.verdict.value == "action_required"
