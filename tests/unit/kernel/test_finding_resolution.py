"""The proof-based finding-resolution relation and its projection fold (issue #458).

A finding stays visible forever; whether it is *current* changes only when a later check whose
recorded state contains the finding, whose matching policy pack ran to completion with nothing
suppressed, whose scope covers the finding's subject, and whose coverage carries no weakening gap
for the finding's proof class did not return the same issue again. Everything else — responses,
weak or scoped-away checks, failed packs, suppression, stale freshness, unreadable rows — leaves
the finding exactly as it was.
"""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest

from builders.policy_cases import act, clm, evt, finding_record, fnd, obl
from finishup.domain.events import (
    CheckChangePartialFile,
    CheckChangeShownFiles,
    CheckMode,
    CheckRecordedPayload,
    PolicyVersion,
)
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    CheckVerdict,
    Finding,
    FindingKind,
    FindingOrigin,
    SemanticDispatchKind,
    SemanticProvenance,
)
from finishup.domain.receipts import (
    CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP,
    CHECK_TIME_CHANGE_GAPS,
    CHECK_TIME_CHANGE_REDACTED_GAP,
    CHECK_TIME_CHANGE_TRUNCATED_GAP,
    CHECK_TIME_CHANGE_UNAVAILABLE_GAP,
)
from finishup.domain.values import FindingId, Frontier
from finishup.kernel.finding_resolution import (
    SEMANTIC_FINDING_CAPTURE_BASELINE_GAPS,
    apply_check_resolution,
    finding_is_resolved,
    issue_key,
    qualifying_check_resolves,
    reopen_findings_resolved_by,
    resolved_finding_ids,
)
from finishup.kernel.plan_drift import PLAN_DRIFT_GAPS
from finishup.kernel.projections import (
    MAX_CHECK_CHANGE_RAISING_CHECKS,
    FindingProjectionRecord,
    ProjectionState,
    empty_projection_state,
    projection_from_snapshot,
    projection_snapshot,
)
from finishup.ports.semantic import SamplingParams
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from finishup.protocol.models import (
    CheckPolicyExecutionModel,
    CheckScopeModel,
    SemanticReason,
    SemanticStatus,
)

_DIGEST = "sha256:" + "1" * 64
_WORK = ("work-integrity", "0.1.0")
_RESEARCH = ("research-evidence", "0.1.0")


def _coverage(
    *,
    gaps: tuple[str, ...] = (),
    freshness: LedgerFreshness | None = None,
    semantic: bool = False,
) -> Coverage:
    if freshness is None:
        freshness = LedgerFreshness.PARTIAL if gaps else LedgerFreshness.CURRENT
    checks = (CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED)
    return Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=freshness,
        check_types=checks if semantic else (CheckType.DETERMINISTIC,),
        known_gaps=tuple(sorted(gaps, key=str.encode)),
    )


def _finding(
    number: int = 1,
    *,
    kind: FindingKind = FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
    subject_refs: tuple[object, ...] = (obl(1),),
    origin: FindingOrigin = FindingOrigin.DETERMINISTIC,
    policy_id: str = "work-integrity",
) -> Finding:
    provenance = None
    if origin is FindingOrigin.SEMANTIC_MODEL_DERIVED:
        provenance = _provenance()
    return Finding(
        finding_id=fnd(number),
        kind=kind,
        origin=origin,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="A completion claim covers an open obligation.",
        detail="Resolve or revise the obligation before claiming completion.",
        subject_refs=subject_refs,  # type: ignore[arg-type]
        policy_id=policy_id,
        policy_version="0.1.0",
        subject_frontier=Frontier(3, _DIGEST),
        coverage=_coverage(semantic=origin is FindingOrigin.SEMANTIC_MODEL_DERIVED),
        provenance=provenance,
    )


def _provenance() -> SemanticProvenance:
    return SemanticProvenance(
        provider="fake",
        endpoint_profile_id="fake",
        endpoint_profile_version="1.0.0",
        model="fake/model",
        sdk_version="1.0.0",
        prompt_digest=_DIGEST,
        schema_digest=_DIGEST,
        policy_digest=_DIGEST,
        privacy_policy_digest=_DIGEST,
        sampling_params=SamplingParams(128),
        latency_ms=1,
        semantic_attempt_id="att_00000000-0000-4000-8000-000000000001",
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id="egr_00000000-0000-4000-8000-000000000001",
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id="fake-1",
        egress_authorization_id="aut_00000000-0000-4000-8000-000000000001",
        request_commitment="hmac-sha256:" + "b" * 64,
    )


def _execution(policy: tuple[str, str], outcome: str, reason: str) -> CheckPolicyExecutionModel:
    return CheckPolicyExecutionModel(
        policy_id=policy[0],  # type: ignore[arg-type]
        policy_version=policy[1],  # type: ignore[arg-type]
        outcome=outcome,  # type: ignore[arg-type]
        reason=reason,  # type: ignore[arg-type]
    )


def _check(
    *,
    tested: int = 8,
    returned: tuple[object, ...] = (),
    suppressed: int = 0,
    coverage: Coverage | None = None,
    scope: CheckScopeModel | None = None,
    work_outcome: tuple[str, str] = ("run", "completed"),
    policies: tuple[tuple[str, str], ...] = (_RESEARCH, _WORK),
    semantic: tuple[SemanticStatus, SemanticReason] = (
        SemanticStatus.NOT_REQUESTED,
        SemanticReason.DETERMINISTIC_MODE,
    ),
) -> CheckRecordedPayload:
    executions = tuple(
        _execution(policy, *work_outcome)
        if policy == _WORK
        else _execution(policy, "run", "completed")
        for policy in policies
    )
    verdict = CheckVerdict.ACTION_REQUIRED if returned else CheckVerdict.NO_ISSUE_DETECTED
    if coverage is None:
        coverage = _coverage(
            gaps=()
            if semantic[0] is SemanticStatus.SUCCEEDED
            else ("semantic_review_not_requested",),
            semantic=semantic[0] is SemanticStatus.SUCCEEDED,
        )
    return CheckRecordedPayload(
        mode=(
            CheckMode.SEMANTIC_REQUIRED
            if semantic[0] is SemanticStatus.SUCCEEDED
            else CheckMode.DETERMINISTIC_ONLY
        ),
        policies=tuple(PolicyVersion(*policy) for policy in policies),
        scope=CheckScopeModel(claim_ids=(), obligation_ids=()) if scope is None else scope,
        policy_executions=executions,
        subject_frontier=Frontier(tested, _DIGEST),
        verdict=verdict,
        returned_finding_ids=returned,  # type: ignore[arg-type]
        suppressed_count=suppressed,
        coverage=coverage,
        semantic_status=semantic[0],
        semantic_reason=semantic[1],
        engine_version="0.1.0",
        projection_version="yoetz/0.1.0",
        semantic_provenance=_provenance() if semantic[0] is SemanticStatus.SUCCEEDED else None,
    )


_SEMANTIC_OK = (SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED)


def _changed_state(check: CheckRecordedPayload, *, recorded_at: int = 4) -> ProjectionState:
    """The pre-check projection with one new action recorded after the finding (issue #884)."""

    from builders.policy_cases import act, record
    from finishup.domain.events import ActionKind, ActionRecordedPayload

    changed = record(ActionRecordedPayload(act(9), ActionKind.EDIT, "Repair"), recorded_at + 1)
    return replace(
        empty_projection_state(),
        frontier=max(check.subject_frontier.sequence, recorded_at + 1),
        head_digest=_DIGEST,
        actions={act(9): changed},
    )


def _resolves(
    finding: Finding,
    check: CheckRecordedPayload,
    *,
    recorded_at: int = 4,
    changed: bool = True,
) -> bool:
    """Resolve with a material change after the finding unless ``changed`` is false."""

    state = _changed_state(check, recorded_at=recorded_at) if changed else None
    return qualifying_check_resolves(finding, recorded_at, check, frozenset(), proof_state=state)


def test_the_happy_path_resolves_a_deterministic_finding() -> None:
    assert _resolves(_finding(), _check()) is True


def test_a_check_that_never_saw_the_finding_cannot_speak_to_it() -> None:
    """The tested frontier precedes the finding's own record: the state it checked lacks it."""

    assert _resolves(_finding(), _check(tested=3), recorded_at=4) is False
    assert _resolves(_finding(), _check(tested=4), recorded_at=4) is True


def test_a_check_returning_the_same_issue_refires_rather_than_resolves() -> None:
    finding = _finding()
    successor = _finding(2)  # same issue key under a fresh id
    assert issue_key(successor) == issue_key(finding)
    keys = frozenset({issue_key(successor)})
    assert qualifying_check_resolves(finding, 4, _check(returned=(fnd(2),)), keys) is False


def test_suppression_leaves_absence_unproven() -> None:
    assert _resolves(_finding(), _check(suppressed=1)) is False


@pytest.mark.parametrize(
    "outcome",
    (
        ("skipped", "material_unavailable"),
        ("skipped", "scope_excluded"),
        ("failed", "policy_failure"),
    ),
)
def test_a_pack_that_did_not_complete_proves_nothing(outcome: tuple[str, str]) -> None:
    assert _resolves(_finding(), _check(work_outcome=outcome)) is False


def test_a_check_that_did_not_run_the_owning_pack_proves_nothing() -> None:
    assert _resolves(_finding(), _check(policies=(_RESEARCH,))) is False


def test_scope_must_name_one_of_the_findings_subjects() -> None:
    finding = _finding(subject_refs=(obl(1),))
    on_target = CheckScopeModel(claim_ids=(), obligation_ids=(obl(1),))
    elsewhere = CheckScopeModel(claim_ids=(clm(9),), obligation_ids=(obl(2),))
    assert _resolves(finding, _check(scope=on_target)) is True
    assert _resolves(finding, _check(scope=elsewhere)) is False


@pytest.mark.parametrize(
    "freshness",
    (
        LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE,
        LedgerFreshness.REDACTED_GAP,
        LedgerFreshness.UNKNOWN,
    ),
)
def test_unproven_freshness_cannot_resolve(freshness: LedgerFreshness) -> None:
    coverage = _coverage(gaps=("semantic_review_not_requested",), freshness=freshness)
    assert _resolves(_finding(), _check(coverage=coverage)) is False


@pytest.mark.parametrize(
    "gap",
    ("redacted_event", "event_payload_unavailable", "missing_ref", "completion_scope_undeclared"),
)
def test_a_non_semantic_gap_weakens_every_proof_class(gap: str) -> None:
    coverage = _coverage(gaps=("semantic_review_not_requested", gap))
    assert _resolves(_finding(), _check(coverage=coverage)) is False


@pytest.mark.parametrize(
    "gap",
    (
        "semantic_review_not_requested",
        "semantic_review_not_configured",
        "semantic_relevance_review_not_run",
        "optional_semantic_review_blocked_by_policy",
        "semantic_review_skipped_insufficient_packet",
        # The check-time change is AI-powered review input only (ADR-031).
        *sorted(CHECK_TIME_CHANGE_GAPS),
    ),
)
def test_semantic_absence_does_not_weaken_a_deterministic_proof(gap: str) -> None:
    """A local finding is proven absent by the local pack, not by the reviewer."""

    assert _resolves(_finding(), _check(coverage=_coverage(gaps=(gap,)))) is True


_TEST_EDIT_ACCOUNTING = (
    "preexisting_test_baseline_unknown",
    "preexisting_test_deleted",
    "preexisting_test_modified",
    "preexisting_test_renamed",
    "preexisting_test_skip_unknown",
    "preexisting_test_skipped",
)


def _test_edit_finding() -> Finding:
    return replace(
        _finding(kind=FindingKind.TASK_REQUIREMENT_UNMET, policy_id="research-evidence"),
        summary="An existing test file was edited without a recorded justification.",
    )


def _statement_finding() -> Finding:
    from finishup.domain.task_statement import TASK_STATEMENT_UNMAPPED_SUMMARY

    return replace(
        _finding(
            kind=FindingKind.TASK_REQUIREMENT_UNMET,
            policy_id="research-evidence",
            subject_refs=(evt(1),),
        ),
        summary=TASK_STATEMENT_UNMAPPED_SUMMARY,
    )


@pytest.mark.parametrize("gap", _TEST_EDIT_ACCOUNTING)
def test_test_edit_accounting_limits_only_the_test_edit_finding_by_basis(gap: str) -> None:
    """Structural test-edit accounting (ADR-032) bounds only the rule that reads it (TB4 D1).

    Tolerance follows the finding's basis, not its kind. Only the unjustified test-edit finding
    is bounded by an unknown edit baseline; its informational counts never hide an unjustified
    edit. The statement-based requirement finding and an AI-powered requirement finding judge
    material the accounting never touches, so a standing accounting limit must not make their
    repair permanently unresolvable.
    """

    local = _coverage(gaps=("semantic_review_not_requested", gap))
    assert _resolves(_finding(), _check(coverage=local)) is True
    reviewed = _coverage(gaps=(gap,), semantic=True)
    semantic = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    assert _resolves(semantic, _check(semantic=_SEMANTIC_OK, coverage=reviewed)) is True
    test_edit_bounded = gap == "preexisting_test_baseline_unknown"
    assert _resolves(_test_edit_finding(), _check(coverage=local)) is not test_edit_bounded
    assert _resolves(_statement_finding(), _check(coverage=local)) is True
    semantic_requirement = _finding(
        kind=FindingKind.TASK_REQUIREMENT_UNMET,
        origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        policy_id="research-evidence",
    )
    assert _resolves(semantic_requirement, _check(semantic=_SEMANTIC_OK, coverage=reviewed)) is True


def test_an_unknown_requirement_summary_reads_as_the_strict_test_edit_basis() -> None:
    """A summary that is not a statement wording fails closed to the test-edit basis."""

    local = _coverage(gaps=("semantic_review_not_requested", "preexisting_test_baseline_unknown"))
    unknown = _finding(kind=FindingKind.TASK_REQUIREMENT_UNMET, policy_id="research-evidence")
    assert _resolves(unknown, _check(coverage=local)) is False


def test_a_declared_empty_scope_never_traps_a_repaired_finding() -> None:
    """A no-material-work task keeps its scope disclosure but can clear repaired findings."""

    declared = _coverage(gaps=("completion_scope_declared_none", "semantic_review_not_requested"))
    undeclared = _coverage(gaps=("completion_scope_undeclared", "semantic_review_not_requested"))
    assert _resolves(_finding(), _check(coverage=declared)) is True
    assert _resolves(_statement_finding(), _check(coverage=declared)) is True
    reviewed = _coverage(gaps=("completion_scope_declared_none",), semantic=True)
    semantic = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    assert _resolves(semantic, _check(semantic=_SEMANTIC_OK, coverage=reviewed)) is True
    # An undeclared scope stays agent work for every row except the answered statement finding.
    assert _resolves(_statement_finding(), _check(coverage=undeclared)) is True
    assert _resolves(_finding(), _check(coverage=undeclared)) is False


def test_a_still_unmapped_statement_blocks_the_statement_finding() -> None:
    """Material that contradicts the repair keeps the statement finding open (TB4 D1)."""

    from finishup.kernel.finding_resolution import resolution_blockers

    gaps = ("instruction_requirement_unmapped", "semantic_review_not_requested")
    check = _check(coverage=_coverage(gaps=gaps))
    assert resolution_blockers(_statement_finding(), 4, check, frozenset()) == (
        "coverage:instruction_requirement_unmapped",
    )
    # Plan drift stays a tolerated diagnostic for every other local finding.
    assert _resolves(_finding(), check) is True


@pytest.mark.parametrize("gap", ("command_attempt_uncorroborated", "command_attempt_mismatch"))
def test_command_gaps_do_not_bound_findings_whose_basis_ignores_commands(gap: str) -> None:
    """A requested-command corroboration gap bounds only rules that read commands (TB4 D1).

    Hook observation records a keyed commitment instead of command text, so a requested command
    item stays uncorroborated for the whole task. The statement and test-edit findings and the
    other command-independent local rules must still resolve once repaired; rules that read
    command attempts keep the strict treatment.
    """

    from finishup.kernel.finding_resolution import resolution_blockers

    check = _check(coverage=_coverage(gaps=(gap, "semantic_review_not_requested")))
    for finding in (
        _statement_finding(),
        _test_edit_finding(),
        _finding(),
        _finding(kind=FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE, subject_refs=(clm(1),)),
    ):
        assert resolution_blockers(finding, 4, check, frozenset()) == (), finding.kind
    requested = _finding(kind=FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED)
    assert resolution_blockers(requested, 4, check, frozenset()) == (
        "command_relation_independence_unproven",
        "coverage:" + gap,
    )
    # A requested-item finding whose obligation requests no command is not about commands; one
    # whose obligation requests a command keeps the strict treatment.
    state = _command_proof_state()
    assert resolution_blockers(requested, 4, check, frozenset(), proof_state=state) == ()
    command_requested = replace(requested, subject_refs=(obl(2),))
    assert resolution_blockers(command_requested, 4, check, frozenset(), proof_state=state)


def test_semantic_findings_tolerate_command_gaps_only_off_command_material() -> None:
    from builders.policy_cases import record, res
    from finishup.domain.events import (
        ActionKind,
        ActionRecordedPayload,
        ResultOutcome,
        ResultRecordedPayload,
    )
    from finishup.kernel.finding_resolution import resolution_blockers

    state = _command_proof_state()
    coverage = _coverage(gaps=("command_attempt_uncorroborated",), semantic=True)
    check = _assessed(_check(tested=100, semantic=_SEMANTIC_OK, coverage=coverage))
    command_action = ActionRecordedPayload(act(2), ActionKind.COMMAND, "Ran tests", command="x")
    state = replace(
        state,
        actions={**state.actions, act(2): record(command_action, 30)},
        results={
            **state.results,
            res(2): record(ResultRecordedPayload(res(2), act(2), ResultOutcome.SUCCESS), 31),
        },
    )
    off = replace(_finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED), subject_refs=(obl(1),))
    on_obligation = replace(off, subject_refs=(obl(2),))
    on_action = replace(off, subject_refs=(evt(30),))
    on_result = replace(off, subject_refs=(evt(31),))
    assert "coverage:command_attempt_uncorroborated" not in resolution_blockers(
        off, 4, check, frozenset(), proof_state=state
    )
    for finding in (on_obligation, on_action, on_result):
        assert "coverage:command_attempt_uncorroborated" in resolution_blockers(
            finding, 4, check, frozenset(), proof_state=state
        ), finding.subject_refs
    # Without the pre-check projection nothing is proven.
    assert "coverage:command_attempt_uncorroborated" in resolution_blockers(
        off, 4, check, frozenset()
    )


def test_an_unjustified_test_edit_still_blocks_every_proof() -> None:
    gap = "preexisting_test_edit_unjustified"
    assert _resolves(_finding(), _check(coverage=_coverage(gaps=(gap,)))) is False
    semantic = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    reviewed = _coverage(gaps=(gap,), semantic=True)
    assert _resolves(semantic, _check(semantic=_SEMANTIC_OK, coverage=reviewed)) is False


@pytest.mark.parametrize("gap", sorted(PLAN_DRIFT_GAPS))
def test_advisory_plan_drift_never_vetoes_a_local_absence_proof(gap: str) -> None:
    """Plan drift is a planning-trace diagnostic; it stays disclosed but proves nothing absent."""

    coverage = _coverage(gaps=("semantic_review_not_requested", gap))
    assert _resolves(_finding(), _check(coverage=coverage)) is True
    reviewed = _coverage(gaps=(gap,), semantic=True)
    semantic = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    assert _resolves(semantic, _check(semantic=_SEMANTIC_OK, coverage=reviewed)) is False


def test_registration_drift_check_resolves_deterministic_never_semantic() -> None:
    """Issue #537: a drift check resolves like a plain ceiling check.

    The drift gap rides alongside the ceiling gap, so the pair still tolerates
    local proof — and still proves nothing about an AI-powered finding.
    """

    from finishup.domain.receipts import (
        OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,
        OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP,
    )

    drift_check_gaps = (
        OPTIONAL_SEMANTIC_REVIEW_BLOCKED_BY_POLICY_GAP,
        OPTIONAL_SEMANTIC_REVIEW_REGISTRATION_DRIFT_GAP,
    )
    assert _resolves(_finding(), _check(coverage=_coverage(gaps=drift_check_gaps))) is True
    semantic = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    weakened = _coverage(gaps=drift_check_gaps, semantic=True)
    assert _resolves(semantic, _check(semantic=_SEMANTIC_OK, coverage=weakened)) is False


@pytest.mark.parametrize(
    "gap",
    (
        "evidence_content_digest_only",
        "evidence_content_withheld",
        "evidence_digest_subject_legacy_unknown",
    ),
)
def test_evidence_strength_gaps_bound_the_receipt_but_not_the_proof(gap: str) -> None:
    """Digest-only evidence is readable ledger state the pack judged; it stays a receipt limit."""

    assert _resolves(_finding(), _check(coverage=_coverage(gaps=(gap,)))) is True
    semantic = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    coverage = _coverage(gaps=(gap,), semantic=True)
    assert _resolves(semantic, _check(semantic=_SEMANTIC_OK, coverage=coverage)) is True


@pytest.mark.parametrize(
    ("gap", "freshness"),
    (
        ("captured_object_unavailable", LedgerFreshness.REDACTED_GAP),
        ("content_unselected", LedgerFreshness.PARTIAL),
        ("host_outcome_unavailable", LedgerFreshness.PARTIAL),
        ("unpaired_event", LedgerFreshness.PARTIAL),
    ),
)
def test_each_host_observation_gap_preserves_clean_deterministic_proof(
    gap: str, freshness: LedgerFreshness
) -> None:
    coverage = _coverage(
        gaps=(gap, "semantic_review_not_requested"),
        freshness=freshness,
    )
    assert _resolves(_finding(), _check(coverage=coverage)) is True


@pytest.mark.parametrize(
    "gap",
    (
        "captured_object_unavailable",
        "content_unselected",
        "host_outcome_unavailable",
        "unpaired_event",
    ),
)
def test_hook_observed_finding_coverage_preserves_clean_deterministic_proof(gap: str) -> None:
    """Issue #547: derived hook coverage may carry the host gap onto the finding itself."""

    finding = replace(
        _finding(),
        coverage=_coverage(gaps=(gap,), freshness=LedgerFreshness.PARTIAL),
    )
    check_coverage = _coverage(
        gaps=(gap, "semantic_review_not_requested"),
        freshness=LedgerFreshness.PARTIAL,
    )

    assert _resolves(finding, _check(coverage=check_coverage)) is True


@pytest.mark.parametrize(
    "freshness",
    (LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE, LedgerFreshness.UNKNOWN),
)
def test_host_observation_gaps_do_not_admit_stale_or_unknown_freshness(
    freshness: LedgerFreshness,
) -> None:
    """Only ``redacted_gap`` is admitted; the other unproven freshnesses stay fail-closed (#538)."""

    coverage = _coverage(
        gaps=("captured_object_unavailable", "unpaired_event"),
        freshness=freshness,
    )
    assert _resolves(_finding(), _check(coverage=coverage)) is False


def test_host_observation_gaps_do_not_veto_clean_deterministic_proof() -> None:
    """Combined host limits remain on the check without making repair unprovable (#538)."""

    coverage = _coverage(
        gaps=(
            "captured_object_unavailable",
            "content_unselected",
            "host_outcome_unavailable",
            "semantic_review_not_requested",
            "unpaired_event",
        ),
        freshness=LedgerFreshness.REDACTED_GAP,
    )

    assert _resolves(_finding(), _check(coverage=coverage)) is True
    research_finding = _finding(
        kind=FindingKind.MATERIAL_LIMITATION_OMITTED,
        subject_refs=(clm(1),),
        policy_id="research-evidence",
    )
    assert _resolves(research_finding, _check(coverage=coverage)) is True
    semantic = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    assert _resolves(semantic, _check(semantic=_SEMANTIC_OK, coverage=coverage)) is False

    unreadable_finding = replace(
        _finding(),
        coverage=_coverage(
            gaps=("captured_object_unavailable",),
            freshness=LedgerFreshness.REDACTED_GAP,
        ),
    )
    assert _resolves(unreadable_finding, _check(coverage=coverage)) is False
    partial_host_coverage = _coverage(gaps=("unpaired_event",))
    assert _resolves(unreadable_finding, _check(coverage=partial_host_coverage)) is False

    hidden_event = _coverage(
        gaps=(*coverage.known_gaps, "redacted_event"),
        freshness=LedgerFreshness.REDACTED_GAP,
    )
    assert _resolves(_finding(), _check(coverage=hidden_event)) is False


def test_a_semantic_finding_needs_a_completed_semantic_review() -> None:
    finding = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    assert _resolves(finding, _check()) is False, "local-only proof is the wrong class"
    assert _resolves(finding, _check(semantic=_SEMANTIC_OK)) is True


@pytest.mark.parametrize(
    "gap",
    (
        "semantic_review_context_withheld",
        "semantic_challenges_rejected",
        "semantic_packet_insufficient",
    ),
)
def test_a_weakened_semantic_review_cannot_resolve_a_semantic_finding(gap: str) -> None:
    finding = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    coverage = _coverage(gaps=(gap,), semantic=True)
    assert _resolves(finding, _check(semantic=_SEMANTIC_OK, coverage=coverage)) is False
    # The same weakened review still proves a local issue absent.
    assert _resolves(_finding(), _check(semantic=_SEMANTIC_OK, coverage=coverage)) is True


@pytest.mark.parametrize(
    "gap",
    ("task_statement_unavailable", "task_statement_not_authorized", "task_statement_not_supplied"),
)
def test_a_review_without_the_task_statement_never_newly_resolves_a_semantic_finding(
    gap: str,
) -> None:
    """Issue #908: a missing statement is a semantic-only limit.

    A local issue is still proven absent by its pack; a semantic issue raised with the statement
    in hand cannot be closed by a review that lacked it.
    """

    finding = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    coverage = _coverage(gaps=(gap,), semantic=True)
    assert _resolves(finding, _check(semantic=_SEMANTIC_OK, coverage=coverage)) is False
    assert _resolves(_finding(), _check(semantic=_SEMANTIC_OK, coverage=coverage)) is True


def test_apply_marks_the_qualifying_row_and_reopens_returned_rows() -> None:
    proven_earlier = finding_record(
        _finding(2, subject_refs=(obl(2),)), 5, resolved_by_check_event_id=evt(6)
    )
    findings = {fnd(1): finding_record(_finding(1), 4), fnd(2): proven_earlier}

    apply_check_resolution(findings, _check(returned=(fnd(2),)), evt(9))

    assert findings[fnd(1)].resolved_by_check_event_id == evt(9)
    assert findings[fnd(2)].resolved_by_check_event_id is None, "returned again: current"


def test_apply_resolves_nothing_when_a_returned_row_is_unreadable() -> None:
    """An unreadable returned finding might be this very issue; the check cannot say."""

    findings = {
        fnd(1): finding_record(_finding(1), 4),
        fnd(2): replace(
            finding_record(_finding(2, subject_refs=(obl(2),)), 5), payload=None, redacted=True
        ),
    }
    apply_check_resolution(findings, _check(returned=(fnd(2),)), evt(9))
    assert findings[fnd(1)].resolved_by_check_event_id is None


def test_apply_never_re_resolves_or_weakens_an_existing_proof() -> None:
    findings = {fnd(1): finding_record(_finding(1), 4, resolved_by_check_event_id=evt(6))}
    apply_check_resolution(findings, _check(suppressed=3), evt(9))
    assert findings[fnd(1)].resolved_by_check_event_id == evt(6), "a weak later check does nothing"


def test_reopen_drops_only_proof_from_the_named_events() -> None:
    findings = {
        fnd(1): finding_record(_finding(1), 4, resolved_by_check_event_id=evt(6)),
        fnd(2): finding_record(
            _finding(2, subject_refs=(obl(2),)), 5, resolved_by_check_event_id=evt(7)
        ),
    }
    reopen_findings_resolved_by(findings, frozenset({evt(6)}))
    assert findings[fnd(1)].resolved_by_check_event_id is None
    assert findings[fnd(2)].resolved_by_check_event_id == evt(7)


def test_finding_is_resolved_reads_the_record_and_the_shared_rule() -> None:
    state = replace(
        empty_projection_state(),
        frontier=9,
        head_digest=_DIGEST,
        findings={
            fnd(1): finding_record(_finding(1), 4, resolved_by_check_event_id=evt(6)),
            fnd(2): finding_record(_finding(2, subject_refs=(obl(2),)), 5),
        },
        freshness=LedgerFreshness.CURRENT,
    )
    assert finding_is_resolved(state, fnd(1)) is True
    assert finding_is_resolved(state, fnd(2)) is False
    assert finding_is_resolved(state, fnd(3)) is False
    assert resolved_finding_ids(state) == frozenset({fnd(1)})


def test_snapshot_round_trips_resolution_and_omits_it_when_absent() -> None:
    """Old snapshots stay byte-identical: the key appears only once a row is resolved."""

    current = finding_record(_finding(1), 4)
    resolved = finding_record(
        _finding(2, subject_refs=(obl(2),)), 5, resolved_by_check_event_id=evt(6)
    )
    state = replace(
        empty_projection_state(),
        frontier=9,
        head_digest=_DIGEST,
        findings={fnd(1): current, fnd(2): resolved},
        freshness=LedgerFreshness.CURRENT,
    )
    snapshot = projection_snapshot(state)
    rows = snapshot["findings"]
    assert isinstance(rows, dict)
    assert "resolved_by_check_event_id" not in rows[fnd(1)]  # type: ignore[operator]
    assert rows[fnd(2)]["resolved_by_check_event_id"] == evt(6)  # type: ignore[index]
    decoded = projection_from_snapshot(snapshot)
    assert decoded == state
    assert type(decoded.findings[fnd(2)]) is FindingProjectionRecord
    assert canonical_encode(projection_snapshot(decoded)) == canonical_encode(snapshot)


def test_snapshot_rejects_a_null_resolution_key() -> None:
    state = replace(
        empty_projection_state(),
        frontier=9,
        head_digest=_DIGEST,
        findings={fnd(1): finding_record(_finding(1), 4)},
        freshness=LedgerFreshness.CURRENT,
    )
    snapshot = projection_snapshot(state)
    rows = snapshot["findings"]
    assert isinstance(rows, dict)
    rows[fnd(1)]["resolved_by_check_event_id"] = None  # type: ignore[index]
    with pytest.raises(ValueError, match="invalid_projection_state"):
        projection_from_snapshot(snapshot)


@pytest.mark.parametrize(
    "gap",
    [
        "host_outcome_unavailable",
        "unpaired_event",
        "semantic_case_content_over_item_limit",
        "semantic_case_finding_refs_over_limit",
        "semantic_missing_non_convergent",
        "semantic_provider_input_manifest_missing",
        "semantic_provider_input_manifest_invalid",
        "semantic_provider_input_manifest_parse_failed",
        "semantic_provider_input_manifest_mismatch",
        "semantic_provider_input_manifest_recovery_failed",
        "semantic_review_refs_reduced",
        "semantic_review_snippet_invalid",
    ],
)
def test_resolution_explains_only_disqualifying_semantic_gaps(gap: str) -> None:
    """Without an explicit reviewer ruling these gaps block AI-powered proof.

    ``semantic_review_refs_reduced`` stays here deliberately: only an explicit ``fixed`` ruling
    tolerates it (issue #976 D4, ``test_a_fixed_ruling_resolves_despite_citations_the_fence_reduced``).
    """

    from finishup.kernel.finding_resolution import resolution_blockers

    finding = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    check = _check(
        semantic=_SEMANTIC_OK,
        coverage=_coverage(
            gaps=tuple(sorted((gap, "evidence_content_digest_only"))), semantic=True
        ),
    )
    state = _changed_state(check)
    assert resolution_blockers(finding, 4, check, frozenset(), proof_state=state) == (
        "coverage:" + gap,
    )
    assert not _resolves(finding, check)
    tolerated = _check(
        semantic=_SEMANTIC_OK,
        coverage=_coverage(gaps=("evidence_content_digest_only",), semantic=True),
    )
    assert resolution_blockers(finding, 4, tolerated, frozenset(), proof_state=state) == ()
    assert _resolves(finding, tolerated)
    # Without a material change after the finding, a review that merely did not repeat the issue
    # proves nothing.
    assert resolution_blockers(finding, 4, tolerated, frozenset()) == (
        "no_material_change_since_finding",
    )


def test_resolution_explanation_preserves_scope_policy_suppression_and_refire() -> None:
    from finishup.kernel.finding_resolution import resolution_blockers

    finding = _finding()
    check = _check(
        suppressed=1,
        policies=(_RESEARCH,),
        scope=CheckScopeModel(claim_ids=(clm(99),), obligation_ids=()),
    )
    reasons = resolution_blockers(finding, 4, check, frozenset({issue_key(finding)}))
    assert reasons == (
        "issue_returned_again",
        "findings_suppressed",
        "matching_policy_not_completed",
        "subject_outside_checked_scope",
    )


def _command_proof_state() -> ProjectionState:
    from builders.policy_cases import act, make_case, obligation_record, plan_record, record, res
    from finishup.domain.events import (
        ActionKind,
        ActionRecordedPayload,
        ObligationPublishedPayload,
        ObligationStatus,
        PlanPublishedPayload,
        RequestedItem,
        RequestedItemKind,
        ResultOutcome,
        ResultRecordedPayload,
    )

    return make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Plan", (obl(1), obl(2))), 1)},
        obligations={
            obl(1): obligation_record(
                ObligationPublishedPayload(obl(1), "Edit", "Result", ObligationStatus.OPEN), 2
            ),
            obl(2): obligation_record(
                ObligationPublishedPayload(
                    obl(2),
                    "Test",
                    "Result",
                    ObligationStatus.RESOLVED,
                    requested_items=(
                        RequestedItem(RequestedItemKind.COMMAND, "pytest unrelated.py"),
                    ),
                    resolution_evidence_refs=(res(2),),
                ),
                3,
            ),
        },
        actions={
            act(1): record(
                ActionRecordedPayload(act(1), ActionKind.EDIT, "Edit", obligation_refs=(obl(1),)),
                10,
            )
        },
        results={res(1): record(ResultRecordedPayload(res(1), act(1), ResultOutcome.SUCCESS), 20)},
    ).projection


@pytest.mark.parametrize("gap", ("command_attempt_uncorroborated", "command_attempt_mismatch"))
def test_command_gap_only_allows_proven_independent_action_result(gap: str) -> None:
    from finishup.kernel.finding_resolution import resolution_blockers

    finding = _finding(kind=FindingKind.ACTION_WITHOUT_RESULT, subject_refs=(evt(10),))
    check = _check(tested=100, coverage=_coverage(gaps=(gap,)))
    state = _command_proof_state()
    assert resolution_blockers(finding, 4, check, frozenset(), proof_state=state) == ()
    assert qualifying_check_resolves(finding, 4, check, frozenset(), proof_state=state)
    assert not qualifying_check_resolves(finding, 4, check, frozenset())


def test_command_gap_relation_through_resolution_result_blocks_independence() -> None:
    """A command obligation's result link is an explicit relation to the action too."""
    from builders.policy_cases import obligation_record, res
    from finishup.kernel.finding_resolution import resolution_blockers

    state = _command_proof_state()
    command_obligation = state.obligations[obl(2)]
    assert command_obligation.payload is not None
    state = replace(
        state,
        obligations={
            **state.obligations,
            obl(2): obligation_record(
                replace(command_obligation.payload, resolution_evidence_refs=(res(1),)),
                command_obligation.source_frontier,
            ),
        },
    )
    finding = _finding(kind=FindingKind.ACTION_WITHOUT_RESULT, subject_refs=(evt(10),))
    check = _check(tested=100, coverage=_coverage(gaps=("command_attempt_uncorroborated",)))
    reasons = resolution_blockers(finding, 4, check, frozenset(), proof_state=state)
    assert "command_relation_overlaps_obligation:" + obl(2) in reasons


def test_explanation_cache_is_scoped_to_the_candidate_check() -> None:
    """Two checks can share a subject frontier without sharing a pre-check projection."""
    from types import SimpleNamespace
    from typing import cast

    from finishup.domain.events import LedgerRecord
    from finishup.kernel.finding_resolution import (
        _historical_proof_state,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.kernel.projections import empty_projection_state

    replayed: list[tuple[int, ...]] = []

    def fake_replay(events: tuple[LedgerRecord, ...]) -> ProjectionState:
        replayed.append(tuple(event.ledger.ingestion_sequence for event in events))
        return empty_projection_state()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("finishup.kernel.reducers.replay", fake_replay)
    try:
        check = cast(
            CheckRecordedPayload,
            SimpleNamespace(subject_frontier=SimpleNamespace(sequence=1, head_digest=_DIGEST)),
        )
        records = cast(
            tuple[LedgerRecord, ...],
            tuple(
                SimpleNamespace(ledger=SimpleNamespace(ingestion_sequence=sequence))
                for sequence in (1, 2)
            ),
        )
        first = cast(LedgerRecord, SimpleNamespace(ledger=SimpleNamespace(ingestion_sequence=2)))
        second = cast(LedgerRecord, SimpleNamespace(ledger=SimpleNamespace(ingestion_sequence=3)))
        cache: dict[tuple[int, int, str], ProjectionState | None] = {}
        _historical_proof_state(check, first, records, cache)
        _historical_proof_state(check, second, records, cache)
    finally:
        monkeypatch.undo()
    assert replayed == [(1,), (1, 2)]


@pytest.mark.parametrize(
    "weakness",
    (
        "missing_result",
        "late_result",
        "unbound_action",
        "unreadable_result",
        "unknown_plan",
        "missing_obligation",
        "overlap",
        "original_gap",
        "semantic",
        "other_kind",
        "refired",
        "suppressed",
        "stale",
        "scoped_away",
    ),
)
def test_command_partition_never_upgrades_weak_or_overlapping_proof(weakness: str) -> None:
    from builders.policy_cases import act, record, res
    from finishup.kernel.finding_resolution import resolution_blockers

    state = _command_proof_state()
    finding = _finding(kind=FindingKind.ACTION_WITHOUT_RESULT, subject_refs=(evt(10),))
    check = _check(tested=100, coverage=_coverage(gaps=("command_attempt_uncorroborated",)))
    keys: frozenset[tuple[object, ...]] = frozenset()
    if weakness == "missing_result":
        state = replace(state, results={})
    elif weakness == "late_result":
        check = _check(tested=15, coverage=check.coverage)
    elif weakness in {"unbound_action", "overlap"}:
        action = state.actions[act(1)]
        assert action.payload is not None
        state = replace(
            state,
            actions={
                act(1): record(
                    replace(
                        action.payload,
                        obligation_refs=() if weakness == "unbound_action" else (obl(2),),
                    ),
                    10,
                )
            },
        )
    elif weakness == "unreadable_result":
        state = replace(
            state, results={res(1): replace(state.results[res(1)], payload=None, redacted=True)}
        )
    elif weakness == "unknown_plan":
        state = replace(state, plans={})
    elif weakness == "missing_obligation":
        state = replace(state, obligations={obl(2): state.obligations[obl(2)]})
    elif weakness == "original_gap":
        finding = replace(finding, coverage=_coverage(gaps=("missing_ref",)))
    elif weakness == "semantic":
        finding = _finding(
            kind=FindingKind.ACTION_WITHOUT_RESULT,
            subject_refs=(evt(10),),
            origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        )
    elif weakness == "other_kind":
        finding = _finding(kind=FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED, subject_refs=(obl(2),))
    elif weakness == "refired":
        keys = frozenset({issue_key(finding)})
    elif weakness == "suppressed":
        check = replace(check, suppressed_count=1)
    elif weakness == "stale":
        check = replace(
            check,
            coverage=_coverage(
                gaps=check.coverage.known_gaps,
                freshness=LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE,
            ),
        )
    elif weakness == "scoped_away":
        check = replace(check, scope=CheckScopeModel(claim_ids=(clm(99),), obligation_ids=()))
    reasons = resolution_blockers(finding, 4, check, keys, proof_state=state)
    assert reasons
    if weakness == "overlap":
        assert "command_relation_overlaps_obligation:" + obl(2) in reasons


_CAPTURE_GAP_SETS = (
    ("truncated_payload",),
    ("content_capture_unavailable",),
    ("content_capture_unavailable", "truncated_payload"),
)


@pytest.mark.parametrize("shape", ("unbound_action", "unknown_plan", "overlap", "bound"))
@pytest.mark.parametrize("gaps", _CAPTURE_GAP_SETS)
def test_a_linked_result_resolves_action_without_result_under_capture_gaps(
    shape: str, gaps: tuple[str, ...]
) -> None:
    """tb4n5 react S (``fnd_da264f65``), owner decision 2026-10-13 ("under capture gaps").

    The agent linked the result, yet ``truncated_payload`` and ``content_capture_unavailable``
    kept the finding open, so the agent had to answer ``self_verified`` and the receipt read
    "FinishUP could not prove". The rule reads only the action and result rows, so a readable link
    proves the issue absent whatever obligations the action names; the gaps stay on the check and
    its receipt.
    """
    from builders.policy_cases import act, record
    from finishup.kernel.finding_resolution import resolution_blockers

    state = _command_proof_state()
    if shape in {"unbound_action", "overlap"}:
        action = state.actions[act(1)]
        assert action.payload is not None
        state = replace(
            state,
            actions={
                act(1): record(
                    replace(
                        action.payload,
                        obligation_refs=() if shape == "unbound_action" else (obl(2),),
                        attempted_items=("solve.sage",) if shape == "unbound_action" else (),
                    ),
                    10,
                )
            },
        )
    elif shape == "unknown_plan":
        state = replace(state, plans={})
    finding = _finding(kind=FindingKind.ACTION_WITHOUT_RESULT, subject_refs=(evt(10),))
    check = _check(tested=100, coverage=_coverage(gaps=gaps))
    assert resolution_blockers(finding, 4, check, frozenset(), proof_state=state) == ()
    assert qualifying_check_resolves(finding, 4, check, frozenset(), proof_state=state)
    # Without the tested state the link is unproven and the gaps keep blocking.
    assert not qualifying_check_resolves(finding, 4, check, frozenset())
    # Only the local action/result rule gets this: any other kind keeps the gaps as vetoes.
    other = _finding(kind=FindingKind.FAILED_WORK_OMITTED, subject_refs=(evt(10),))
    assert resolution_blockers(other, 4, check, frozenset(), proof_state=state)


@pytest.mark.parametrize(
    "weakness",
    ("missing_result", "late_result", "unreadable_result", "unreadable_action", "foreign_result"),
)
def test_a_capture_gap_needs_an_exact_readable_link(weakness: str) -> None:
    from builders.policy_cases import act, record, res
    from finishup.domain.events import ResultOutcome, ResultRecordedPayload
    from finishup.kernel.finding_resolution import resolution_blockers

    state = _command_proof_state()
    check = _check(tested=100, coverage=_coverage(gaps=("truncated_payload",)))
    if weakness == "missing_result":
        state = replace(state, results={})
    elif weakness == "late_result":
        check = _check(tested=15, coverage=check.coverage)
    elif weakness == "unreadable_result":
        state = replace(
            state, results={res(1): replace(state.results[res(1)], payload=None, redacted=True)}
        )
    elif weakness == "unreadable_action":
        state = replace(
            state, actions={act(1): replace(state.actions[act(1)], payload=None, redacted=True)}
        )
    elif weakness == "foreign_result":
        state = replace(
            state,
            results={
                res(1): record(ResultRecordedPayload(res(1), act(9), ResultOutcome.SUCCESS), 20)
            },
        )
    finding = _finding(kind=FindingKind.ACTION_WITHOUT_RESULT, subject_refs=(evt(10),))
    assert "coverage:truncated_payload" in resolution_blockers(
        finding, 4, check, frozenset(), proof_state=state
    )


@pytest.mark.parametrize("gap", ("command_attempt_uncorroborated", "command_attempt_mismatch"))
def test_a_linked_result_does_not_widen_the_command_gap_partition(gap: str) -> None:
    """Owner decision line 12 names capture gaps only: command gaps keep #682's partition.

    tb4n5 formal S (``fnd_478fd885``: an action with no obligation refs, ``command_attempt_mismatch``)
    stays open with ``command_relation_independence_unproven`` even with the result linked, and
    a command gap beside a capture gap still blocks unless the partition proves independence.
    """
    from builders.policy_cases import act, record
    from finishup.kernel.finding_resolution import resolution_blockers

    state = _command_proof_state()
    action = state.actions[act(1)]
    assert action.payload is not None
    unbound = replace(
        state,
        actions={
            act(1): record(
                replace(action.payload, obligation_refs=(), attempted_items=("solve.sage",)), 10
            )
        },
    )
    finding = _finding(kind=FindingKind.ACTION_WITHOUT_RESULT, subject_refs=(evt(10),))
    for gaps in ((gap,), (gap, "truncated_payload")):
        check = _check(tested=100, coverage=_coverage(gaps=gaps))
        reasons = resolution_blockers(finding, 4, check, frozenset(), proof_state=unbound)
        assert "command_relation_independence_unproven" in reasons, gaps
        assert "coverage:truncated_payload" not in reasons, gaps
    # A proven independent partition and a proven link together resolve it.
    both = _check(tested=100, coverage=_coverage(gaps=(gap, "truncated_payload")))
    assert resolution_blockers(finding, 4, both, frozenset(), proof_state=state) == ()


def test_independent_command_gap_can_coexist_with_tolerated_host_gaps() -> None:
    finding = _finding(kind=FindingKind.ACTION_WITHOUT_RESULT, subject_refs=(evt(10),))
    check = _check(
        tested=100,
        coverage=_coverage(
            gaps=("command_attempt_uncorroborated", "content_unselected"),
            freshness=LedgerFreshness.REDACTED_GAP,
        ),
    )
    assert qualifying_check_resolves(
        finding, 4, check, frozenset(), proof_state=_command_proof_state()
    )


def _coordination_explanation_state(
    *, resolved_at: int | None, closure_at: int | None, kind: FindingKind
) -> tuple[ProjectionState, tuple[object, ...]]:
    """A finding derived from the context at 3, a check at 5, and an optional closure (#842)."""

    from types import SimpleNamespace

    from builders.policy_cases import record
    from finishup.domain.coordination import CoordinationGapCode, OverlapKind
    from finishup.domain.events import CoordinationContextRecordedPayload

    context = CoordinationContextRecordedPayload(
        detection_id=evt(1),
        project_id="prj_20000000-0000-4000-8000-000000000001",
        membership_generation=4,
        left_task_id="tsk_20000000-0000-4000-8000-000000000001",  # type: ignore[arg-type]
        right_task_id="tsk_20000000-0000-4000-8000-000000000002",  # type: ignore[arg-type]
        recipient_task_id="tsk_20000000-0000-4000-8000-000000000001",  # type: ignore[arg-type]
        counterpart_task_id="tsk_20000000-0000-4000-8000-000000000002",  # type: ignore[arg-type]
        source_task_id="tsk_20000000-0000-4000-8000-000000000002",  # type: ignore[arg-type]
        overlap_kind=OverlapKind.PHYSICAL,
        resource_identities=("sha256:" + "a" * 64,),
        resource_count=1,
        source_repository_commitment="hmac-sha256:" + "b" * 64,
        source_workspace_commitment="hmac-sha256:" + "c" * 64,
        source_route_generation=1,
        source_attributable_paths=True,
        context_digest="sha256:" + "d" * 64,
    )
    contexts = {evt(3): record(context, 3)}
    if closure_at is not None:
        closure = replace(
            context,
            resource_identities=(),
            resource_count=0,
            source_attributable_paths=False,
            gap_codes=(CoordinationGapCode.REVOKED,),
            context_digest="sha256:" + "e" * 64,
        )
        contexts[evt(closure_at)] = record(closure, closure_at)
    policy = ("coordination", "0.1.0") if kind is FindingKind.COORDINATION_OVERLAP else _WORK
    finding = _finding(kind=kind, subject_refs=(evt(3),), policy_id=policy[0])
    state = replace(
        empty_projection_state(),
        frontier=20,
        head_digest=_DIGEST,
        findings={
            fnd(1): finding_record(
                finding,
                4,
                resolved_by_check_event_id=None if resolved_at is None else evt(resolved_at),
            )
        },
        coordination_contexts=contexts,
    )
    checks = tuple(
        SimpleNamespace(
            event_id=evt(sequence),
            schema=SimpleNamespace(name="check_recorded"),
            ledger=SimpleNamespace(ingestion_sequence=sequence),
            payload=_check(tested=sequence, policies=(policy,)),
        )
        for sequence in sorted({5, *(() if resolved_at is None else (resolved_at,))})
    )
    return state, checks


def test_resolution_explanation_names_a_superseded_coordination_generation() -> None:
    from typing import cast

    from finishup.domain.events import LedgerRecord
    from finishup.kernel.finding_resolution import finding_resolution_explanation

    state, records = _coordination_explanation_state(
        resolved_at=12, closure_at=10, kind=FindingKind.COORDINATION_OVERLAP
    )
    explanation = finding_resolution_explanation(
        state, fnd(1), cast(tuple[LedgerRecord, ...], records)
    )
    assert explanation == (
        f"Resolved by qualifying check {evt(12)} after project coordination generation 4 was "
        "superseded; the context is retained as history, not as a current coordination "
        "obligation."
    )


def test_resolution_before_the_closure_keeps_the_ordinary_explanation() -> None:
    """A disposition-backed resolution that predates the closure is not re-described."""

    from typing import cast

    from finishup.domain.events import LedgerRecord
    from finishup.kernel.finding_resolution import finding_resolution_explanation

    state, records = _coordination_explanation_state(
        resolved_at=8, closure_at=10, kind=FindingKind.COORDINATION_OVERLAP
    )
    explanation = finding_resolution_explanation(
        state, fnd(1), cast(tuple[LedgerRecord, ...], records)
    )
    assert explanation == f"Resolved by qualifying check {evt(8)}; retained as history."


def test_unresolved_superseded_finding_points_at_the_next_qualifying_check() -> None:
    from typing import cast

    from finishup.domain.events import LedgerRecord
    from finishup.kernel.finding_resolution import finding_resolution_explanation

    state, records = _coordination_explanation_state(
        resolved_at=None, closure_at=10, kind=FindingKind.COORDINATION_OVERLAP
    )
    explanation = finding_resolution_explanation(
        state, fnd(1), cast(tuple[LedgerRecord, ...], records)
    )
    assert explanation.startswith(
        "Unresolved: project coordination generation 4 was superseded, so this is historical "
        "context rather than a current coordination obligation"
    )
    assert "can resolve it" in explanation


@pytest.mark.parametrize(
    ("closure_at", "kind"),
    ((None, FindingKind.COORDINATION_OVERLAP), (10, FindingKind.ACTION_WITHOUT_RESULT)),
)
def test_supersession_wording_needs_a_closure_for_that_coordination_finding(
    closure_at: int | None, kind: FindingKind
) -> None:
    from typing import cast

    from finishup.domain.events import LedgerRecord
    from finishup.kernel.finding_resolution import finding_resolution_explanation

    state, records = _coordination_explanation_state(
        resolved_at=12, closure_at=closure_at, kind=kind
    )
    explanation = finding_resolution_explanation(
        state, fnd(1), cast(tuple[LedgerRecord, ...], records)
    )
    assert explanation == f"Resolved by qualifying check {evt(12)}; retained as history."


@pytest.mark.parametrize(
    "gap",
    [
        "captured_object_unavailable",
        "content_unselected",
        "host_outcome_unavailable",
        "unpaired_event",
        "content_capture_unavailable",
        "semantic_case_content_over_item_limit",
    ],
)
def test_completed_semantic_recheck_can_retain_original_readable_capture_limits(gap: str) -> None:
    coverage = _coverage(gaps=(gap,), semantic=True, freshness=LedgerFreshness.PARTIAL)
    original = replace(_finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED), coverage=coverage)
    later = replace(
        _check(semantic=_SEMANTIC_OK, coverage=coverage),
        semantic_conclusion="no_material_discrepancy",
    )
    assert _resolves(original, later) is True
    # The same review over unchanged state is a re-roll, not proof (issue #884).
    assert _resolves(original, later, changed=False) is False
    # A legacy check did not record whether it was unassessable: no inferred success.
    assert _resolves(original, _check(semantic=_SEMANTIC_OK, coverage=coverage)) is False
    assert _resolves(original, replace(later, semantic_conclusion="insufficient_packet")) is False
    # A new capture weakness is not licensed by an originally unbounded finding.
    assert (
        _resolves(
            _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED),
            _check(semantic=_SEMANTIC_OK, coverage=coverage),
        )
        is False
    )
    # An acknowledgement/local check cannot supply the independent semantic proof.
    assert _resolves(original, _check(coverage=coverage)) is False
    assert original.coverage.known_gaps == (gap,)


@pytest.mark.parametrize(
    "gap",
    [
        "semantic_packet_insufficient",
        "semantic_case_finding_refs_over_limit",
        "semantic_review_context_withheld",
        "semantic_challenges_rejected",
        "truncated_payload",
        "event_payload_unavailable",
        "redacted_event",
        "missing_ref",
        "observation_input_loss",
        CHECK_TIME_CHANGE_TRUNCATED_GAP,
        CHECK_TIME_CHANGE_REDACTED_GAP,
        CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP,
    ],
)
def test_matching_material_gaps_never_become_semantic_absence_proof(gap: str) -> None:
    from finishup.kernel.finding_resolution import resolution_blockers

    coverage = _coverage(gaps=(gap,), semantic=True, freshness=LedgerFreshness.PARTIAL)
    original = replace(_finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED), coverage=coverage)
    # An assessable conclusion and a material change reach the capture-baseline branch, so the
    # original gap alone is what must keep blocking.
    later = replace(
        _check(semantic=_SEMANTIC_OK, coverage=coverage),
        semantic_conclusion="no_material_discrepancy",
    )
    blockers = resolution_blockers(
        original, 4, later, frozenset(), proof_state=_changed_state(later)
    )
    assert "coverage:" + gap in blockers
    assert "no_material_change_since_finding" not in blockers
    assert _resolves(original, later) is False


def test_redacted_freshness_from_a_recorded_captured_object_gap_is_a_baseline() -> None:
    """The deterministic case caps freshness at redacted_gap for captured_object_unavailable."""

    coverage = _coverage(
        gaps=("captured_object_unavailable",),
        semantic=True,
        freshness=LedgerFreshness.REDACTED_GAP,
    )
    original = replace(_finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED), coverage=coverage)
    later = replace(
        _check(semantic=_SEMANTIC_OK, coverage=coverage),
        semantic_conclusion="no_material_discrepancy",
    )
    assert _resolves(original, later) is True
    assert _resolves(original, later, changed=False) is False
    # Not recorded on the original finding: still unproven.
    fresh = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    assert _resolves(fresh, later) is False
    # A redaction with its own gap code is never explained by the capture baseline.
    hidden = _coverage(
        gaps=("captured_object_unavailable", "redacted_object"),
        semantic=True,
        freshness=LedgerFreshness.REDACTED_GAP,
    )
    assert _resolves(original, replace(later, coverage=hidden)) is False


def test_semantic_resolution_needs_new_work_or_a_subject_revision() -> None:
    from builders.policy_cases import claim_record
    from finishup.domain.events import ClaimKind, ClaimRecordedPayload
    from finishup.kernel.finding_resolution import resolution_blockers

    original = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED, subject_refs=(clm(1),))
    later = replace(_check(semantic=_SEMANTIC_OK), semantic_conclusion="no_material_discrepancy")
    base = replace(empty_projection_state(), frontier=8, head_digest=_DIGEST)
    # Nothing new, or only a record older than the finding: no proof.
    assert resolution_blockers(original, 4, later, frozenset(), proof_state=base) == (
        "no_material_change_since_finding",
    )
    unrelated = claim_record(
        ClaimRecordedPayload(
            clm(2), ClaimKind.COMPLETION, "Other", (obl(2),), obligation_refs=(obl(2),)
        ),
        6,
    )
    assert not qualifying_check_resolves(
        original, 4, later, frozenset(), proof_state=replace(base, claims={clm(2): unrelated})
    )
    revised = claim_record(
        ClaimRecordedPayload(
            clm(1), ClaimKind.COMPLETION, "Revised", (obl(1),), obligation_refs=(obl(1),)
        ),
        6,
    )
    assert qualifying_check_resolves(
        original, 4, later, frozenset(), proof_state=replace(base, claims={clm(1): revised})
    )
    # A change after the checked frontier is not part of the tested state.
    late = _changed_state(later, recorded_at=8)
    assert late.frontier == 9 and later.subject_frontier.sequence == 8
    assert not qualifying_check_resolves(original, 4, later, frozenset(), proof_state=late)


@pytest.mark.parametrize(
    "freshness",
    [
        LedgerFreshness.REDACTED_GAP,
        LedgerFreshness.UNKNOWN,
        LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE,
    ],
)
def test_capture_baseline_cannot_rehabilitate_unreadable_original_proof(
    freshness: LedgerFreshness,
) -> None:
    coverage = _coverage(gaps=("content_unselected",), semantic=True, freshness=freshness)
    original = replace(_finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED), coverage=coverage)
    later = replace(coverage, ledger_freshness=LedgerFreshness.PARTIAL)
    assert _resolves(original, _check(semantic=_SEMANTIC_OK, coverage=later)) is False


def test_unassessable_conclusion_blocks_proof_even_without_a_coverage_gap() -> None:
    original = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    later = replace(_check(semantic=_SEMANTIC_OK), semantic_conclusion="insufficient_packet")
    assert _resolves(original, later) is False


def _ruled(
    check: CheckRecordedPayload, *rulings: tuple[int, str], conclusion: str
) -> CheckRecordedPayload:
    from finishup.domain.findings import PriorFindingVerdictRecord

    return replace(
        check,
        semantic_conclusion=conclusion,
        prior_finding_verdicts=tuple(
            PriorFindingVerdictRecord(fnd(number), verdict) for number, verdict in sorted(rulings)
        ),
    )


def test_a_fixed_ruling_resolves_even_when_the_packet_as_a_whole_was_insufficient() -> None:
    """kea fnd_866db2dd (issue #905): a repaired real defect stayed open forever.

    The recheck after the repair concluded ``insufficient_packet`` for the packet as a whole,
    which vetoed every open AI-powered finding. A per-finding ``fixed`` ruling on material
    recorded after the finding now resolves that finding, while a sibling the same review could
    not assess keeps the whole-packet veto and a sibling ruled unassessable is blocked by name.
    """

    from finishup.kernel.finding_resolution import resolution_blockers

    gapped = _coverage(
        gaps=("semantic_packet_insufficient",), semantic=True, freshness=LedgerFreshness.PARTIAL
    )
    repaired = _finding(1, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    sibling = _finding(2, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED, subject_refs=(obl(2),))
    silent = _finding(3, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED, subject_refs=(obl(3),))
    check = _ruled(
        _check(semantic=_SEMANTIC_OK, coverage=gapped),
        (1, "fixed"),
        (2, "unassessable"),
        conclusion="insufficient_packet",
    )
    state = _changed_state(check)

    assert resolution_blockers(repaired, 4, check, frozenset(), proof_state=state) == ()
    assert _resolves(repaired, check) is True
    assert "reviewer_verdict_unassessable" in resolution_blockers(
        sibling, 4, check, frozenset(), proof_state=state
    )
    silent_blockers = resolution_blockers(silent, 4, check, frozenset(), proof_state=state)
    assert "semantic_packet_insufficient" in silent_blockers
    assert "coverage:semantic_packet_insufficient" in silent_blockers


def test_a_fixed_ruling_never_bypasses_material_change_freshness_or_a_re_raise() -> None:
    from finishup.kernel.finding_resolution import issue_key, resolution_blockers

    finding = _finding(1, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    check = _ruled(
        _check(semantic=_SEMANTIC_OK), (1, "fixed"), conclusion="no_material_discrepancy"
    )
    # A ruling over unchanged state is a re-roll, not proof.
    assert _resolves(finding, check, changed=False) is False
    # The same review re-raising the issue contradicts its own ruling: nothing resolves.
    assert "issue_returned_again" in resolution_blockers(
        finding, 4, check, frozenset({issue_key(finding)}), proof_state=_changed_state(check)
    )
    stale = replace(
        check,
        coverage=_coverage(semantic=True, freshness=LedgerFreshness.STALE_AFTER_MATERIAL_CHANGE),
    )
    assert _resolves(finding, stale) is False
    # Rulings exist only on a recorded, succeeded review conclusion.
    with pytest.raises(ValueError):
        replace(check, semantic_conclusion=None)


@pytest.mark.parametrize("verdict", ["still_present", "answered_not_fixed"])
def test_any_other_ruling_blocks_its_own_finding_even_under_an_assessable_review(
    verdict: str,
) -> None:
    from finishup.kernel.finding_resolution import resolution_blockers

    finding = _finding(1, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    check = _ruled(
        _check(semantic=_SEMANTIC_OK), (1, verdict), conclusion="no_material_discrepancy"
    )
    assert resolution_blockers(
        finding, 4, check, frozenset(), proof_state=_changed_state(check)
    ) == (f"reviewer_verdict_{verdict}",)
    # A ruling speaks only for its own finding: an unruled sibling still resolves as before.
    sibling = _finding(2, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED, subject_refs=(obl(2),))
    assert _resolves(sibling, check) is True


def test_a_ruling_on_a_local_finding_is_ignored_by_local_proof() -> None:
    local = _finding(1)
    check = _ruled(
        _check(semantic=_SEMANTIC_OK), (1, "still_present"), conclusion="no_material_discrepancy"
    )
    assert _resolves(local, check) is True


def test_a_withdrawn_ruling_accepts_a_rejection_without_lifting_the_packet_veto() -> None:
    """The owner's rule: a reasoned rejection not re-raised counts as accepted (issue #905).

    ``withdrawn`` must not block what an assessable recheck over changed state already resolves,
    and it is no licence to resolve under a whole-packet ``insufficient_packet``.
    """

    from finishup.kernel.finding_resolution import resolution_blockers

    finding = _finding(1, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    assessable = _ruled(
        _check(semantic=_SEMANTIC_OK), (1, "withdrawn"), conclusion="no_material_discrepancy"
    )
    assert _resolves(finding, assessable) is True
    gapped = _coverage(
        gaps=("semantic_packet_insufficient",), semantic=True, freshness=LedgerFreshness.PARTIAL
    )
    unassessable = _ruled(
        _check(semantic=_SEMANTIC_OK, coverage=gapped),
        (1, "withdrawn"),
        conclusion="insufficient_packet",
    )
    assert "semantic_packet_insufficient" in resolution_blockers(
        finding, 4, unassessable, frozenset(), proof_state=_changed_state(unassessable)
    )


_NAMED_MISSING_GAPS = (
    "semantic_missing_agent_suppliable",
    "semantic_missing_already_supplied",
    "semantic_missing_items_rejected",
    "semantic_missing_structurally_unavailable",
)


@pytest.mark.parametrize("gap", _NAMED_MISSING_GAPS)
def test_named_missing_items_weigh_like_the_insufficient_packet_they_ride_beside(gap: str) -> None:
    """Issue #907: every 1.1.0 ``insufficient_packet`` names items, adding one of these gaps.

    They describe the same whole-packet answer, so a local issue is still proven absent and a
    ``fixed`` ruling still resolves its own finding, exactly as without the named items.
    """

    from finishup.kernel.finding_resolution import resolution_blockers

    coverage = _coverage(gaps=("semantic_packet_insufficient", gap), semantic=True)
    assert _resolves(_finding(), _check(semantic=_SEMANTIC_OK, coverage=coverage)) is True
    assert (
        _resolves(
            _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED),
            _check(semantic=_SEMANTIC_OK, coverage=coverage),
        )
        is False
    )
    gapped = _coverage(
        gaps=("semantic_packet_insufficient", gap), semantic=True, freshness=LedgerFreshness.PARTIAL
    )
    repaired = _finding(1, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    check = _ruled(
        _check(semantic=_SEMANTIC_OK, coverage=gapped),
        (1, "fixed"),
        conclusion="insufficient_packet",
    )
    assert (
        resolution_blockers(repaired, 4, check, frozenset(), proof_state=_changed_state(check))
        == ()
    )


@pytest.mark.parametrize(
    "gap", ["semantic_prior_findings_over_limit", "semantic_prior_verdicts_unsupported"]
)
def test_an_unruled_finding_the_review_may_not_have_assessed_never_resolves(gap: str) -> None:
    """Greptile P1 on #905: silence about a finding left out of the packet, or whose ruling was
    dropped, is not assessment. It blocks that finding; ruled siblings keep their own effect."""

    from finishup.kernel.finding_resolution import resolution_blockers

    incomplete = _coverage(gaps=(gap,), semantic=True, freshness=LedgerFreshness.PARTIAL)
    unruled = _finding(1, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    ruled = _finding(2, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED, subject_refs=(obl(2),))
    local = _finding(3, subject_refs=(obl(3),))
    check = _ruled(
        _check(semantic=_SEMANTIC_OK, coverage=incomplete),
        (2, "fixed"),
        conclusion="no_material_discrepancy",
    )
    state = _changed_state(check)

    assert resolution_blockers(unruled, 4, check, frozenset(), proof_state=state) == (
        "reviewer_assessment_incomplete",
    )
    assert _resolves(unruled, check) is False
    # The gap is a disclosure, not a veto: a finding the review did rule on still resolves.
    assert resolution_blockers(ruled, 4, check, frozenset(), proof_state=state) == ()
    assert _resolves(ruled, check) is True
    # Local proof never depended on the reviewer.
    assert "reviewer_assessment_incomplete" not in resolution_blockers(
        local, 4, check, frozenset(), proof_state=state
    )


def test_an_unruled_finding_still_follows_the_ordinary_rules_on_a_complete_review() -> None:
    from finishup.kernel.finding_resolution import resolution_blockers

    finding = _finding(1, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    check = _ruled(_check(semantic=_SEMANTIC_OK), conclusion="no_material_discrepancy")
    state = _changed_state(check)
    assert resolution_blockers(finding, 4, check, frozenset(), proof_state=state) == ()


# --- Issue #907: excerpts the packet budget cut (``content_unselected``) --------------------------


def test_a_cited_fixed_ruling_resolves_despite_excerpts_the_budget_cut() -> None:
    """The reviewer ruled the finding fixed on cited, packet-fenced material it was shown.

    The finding was raised before the task crossed the excerpt cap, so its own coverage has no
    ``content_unselected`` baseline; the repair check does. The explicit ruling still closes it.
    """

    from finishup.kernel.finding_resolution import resolution_blockers

    finding = _finding(1, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    assert "content_unselected" not in finding.coverage.known_gaps
    for conclusion in ("no_material_discrepancy", "insufficient_packet"):
        cut = _coverage(
            gaps=("content_unselected", "semantic_packet_insufficient")
            if conclusion == "insufficient_packet"
            else ("content_unselected",),
            semantic=True,
        )
        check = _ruled(
            _check(semantic=_SEMANTIC_OK, coverage=cut), (1, "fixed"), conclusion=conclusion
        )
        state = _changed_state(check)
        assert resolution_blockers(finding, 4, check, frozenset(), proof_state=state) == ()
        assert _resolves(finding, check) is True
    # Beside a disclosed partial dialogue view the ruled finding is still ruled, so
    # ``reviewer_assessment_incomplete`` (issue #905) does not apply to it.
    partial = _coverage(
        gaps=("content_unselected", "semantic_prior_findings_over_limit"), semantic=True
    )
    ruled = _ruled(
        _check(semantic=_SEMANTIC_OK, coverage=partial),
        (1, "fixed"),
        conclusion="no_material_discrepancy",
    )
    assert (
        resolution_blockers(finding, 4, ruled, frozenset(), proof_state=_changed_state(ruled)) == ()
    )


def test_silence_never_closes_an_ai_finding_over_excerpts_the_budget_cut() -> None:
    """Intentional (#904 classification): without a ruling, a selection gap blocks AI proof.

    Only the explicit ``fixed`` ruling tolerates ``content_unselected``; silence, ``withdrawn``,
    ``still_present`` and ``unassessable`` keep it blocking, and a local finding is unaffected.
    """

    from finishup.kernel.finding_resolution import resolution_blockers

    finding = _finding(1, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    cut = _coverage(gaps=("content_unselected",), semantic=True)
    silent = _ruled(
        _check(semantic=_SEMANTIC_OK, coverage=cut), conclusion="no_material_discrepancy"
    )
    state = _changed_state(silent)
    assert resolution_blockers(finding, 4, silent, frozenset(), proof_state=state) == (
        "coverage:content_unselected",
    )
    assert _resolves(finding, silent) is False
    for verdict, extra in (
        ("withdrawn", ()),
        ("still_present", ("reviewer_verdict_still_present",)),
        ("unassessable", ("reviewer_verdict_unassessable",)),
    ):
        check = _ruled(
            _check(semantic=_SEMANTIC_OK, coverage=cut),
            (1, verdict),
            conclusion="no_material_discrepancy",
        )
        blockers = resolution_blockers(
            finding, 4, check, frozenset(), proof_state=_changed_state(check)
        )
        assert blockers == (*extra, "coverage:content_unselected")
    # Local proof never depended on the reviewer or on what the packet carried.
    assert _resolves(_finding(), silent) is True


@pytest.mark.parametrize(
    "gap",
    [
        "write_outside_workspace",
        "obligation_blocked_outside_agent_control",
        # Issue #1046 (tb4n4): the environment family. A container task runs as root; the
        # reviewer ruled the finding fixed and the agent answered self_verified anyway.
        "verification_only_as_root",
        "install_into_private_env",
        "install_into_yoetz_runtime",
        "planned_verification_agent_linked",
        "planned_verification_matched_by_prefix",
        "planned_verification_outcome_unknown",
        "planned_verification_unobservable",
    ],
)
def test_task_facts_about_the_work_never_bound_a_fixed_ruling(gap: str) -> None:
    """Issue #1000 (tb4n1 interleaved-vigenere): the reviewer ruled its finding fixed, but the
    later check carried ``write_outside_workspace``, a fact about where the agent wrote, not about
    what the reviewer was shown, and the finding stayed open. Issue #1046 extends it to every
    environment fact (tb4n4: ``verification_only_as_root``)."""

    from finishup.kernel.finding_resolution import resolution_blockers

    finding = _finding(1, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    coverage = _coverage(gaps=(gap,), semantic=True, freshness=LedgerFreshness.PARTIAL)
    check = _ruled(
        _check(semantic=_SEMANTIC_OK, coverage=coverage),
        (1, "fixed"),
        conclusion="no_material_discrepancy",
    )
    assert (
        resolution_blockers(finding, 4, check, frozenset(), proof_state=_changed_state(check)) == ()
    )
    assert _resolves(finding, check) is True
    # Only an explicit ``fixed`` ruling tolerates them: a review silent on the finding, or one
    # ruling it otherwise, keeps the task fact blocking its absence proof.
    for rulings, extra in (
        ((), ()),
        (((1, "still_present"),), ("reviewer_verdict_still_present",)),
    ):
        check = _ruled(
            _check(semantic=_SEMANTIC_OK, coverage=coverage),
            *rulings,
            conclusion="no_material_discrepancy",
        )
        assert resolution_blockers(
            finding, 4, check, frozenset(), proof_state=_changed_state(check)
        ) == (*extra, f"coverage:{gap}")
        assert _resolves(finding, check) is False


@pytest.mark.parametrize(
    "gap",
    [
        # About the deliverable or what the reviewer was shown, never the environment.
        "requested_output_unchanged",
        "declared_output_not_reviewable",
        "deliverable_references_undeclared_file",
        # Agent-actionable: the agent removes it by its own action.
        "edited_after_last_verification",
        "planned_verification_failed",
    ],
)
def test_facts_about_the_deliverable_still_bound_a_fixed_ruling(gap: str) -> None:
    """Issue #1046 stops at the environment family: a fixed ruling never outranks a fact about the
    deliverable, about what the reviewer could see, or about work the agent still owes."""

    from finishup.kernel.finding_resolution import resolution_blockers

    finding = _finding(1, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    coverage = _coverage(gaps=(gap,), semantic=True, freshness=LedgerFreshness.PARTIAL)
    check = _ruled(
        _check(semantic=_SEMANTIC_OK, coverage=coverage),
        (1, "fixed"),
        conclusion="no_material_discrepancy",
    )
    assert resolution_blockers(
        finding, 4, check, frozenset(), proof_state=_changed_state(check)
    ) == (f"coverage:{gap}",)
    assert _resolves(finding, check) is False


def test_a_fixed_ruling_resolution_names_the_environment_facts_it_did_not_wait_for() -> None:
    """Issue #1046: the resolved finding's explanation says the environment facts stay disclosed
    on the receipt, so closing the finding never reads as FinishUP having verified them away."""

    from types import SimpleNamespace

    from finishup.domain.events import LedgerRecord
    from finishup.kernel.finding_resolution import finding_resolution_explanation

    finding = _finding(1, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    coverage = _coverage(
        gaps=("content_unselected", "verification_only_as_root"),
        semantic=True,
        freshness=LedgerFreshness.PARTIAL,
    )
    check = _ruled(
        _check(tested=9, semantic=_SEMANTIC_OK, coverage=coverage),
        (1, "fixed"),
        conclusion="no_material_discrepancy",
    )
    state = replace(
        empty_projection_state(),
        frontier=9,
        head_digest=_DIGEST,
        findings={fnd(1): finding_record(finding, 4, resolved_by_check_event_id=evt(9))},
    )
    records = (
        SimpleNamespace(
            event_id=evt(9),
            schema=SimpleNamespace(name="check_recorded"),
            ledger=SimpleNamespace(ingestion_sequence=9),
            payload=check,
        ),
    )
    explanation = finding_resolution_explanation(
        state, fnd(1), cast(tuple[LedgerRecord, ...], records)
    )
    assert explanation == (
        f"Resolved by qualifying check {evt(9)}: the reviewer ruled it fixed on material "
        "recorded after the finding; retained as history. The environment facts that check "
        "recorded (verification_only_as_root) did not hold it open; the receipt still "
        "discloses them."
    )


def test_a_fixed_ruling_resolves_despite_citations_the_fence_reduced() -> None:
    """TB4 tb4n1 music-harmony / interleaved-vigenere (issue #976, D4).

    The reviewer ruled its own finding ``fixed`` on cited material recorded after it, but the same
    review cited an unsent ref elsewhere, so the check carries ``semantic_review_refs_reduced``
    (with the budget-cut excerpts every long session has). The gap says the reviewer cited more
    than it was shown, not that it saw less: the explicit ruling resolves the finding. Without a
    ``fixed`` ruling the gap still blocks (see the disqualifying-gap test above).
    """

    from finishup.kernel.finding_resolution import resolution_blockers

    finding = _finding(1, origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    reduced = _coverage(
        gaps=("content_unselected", "semantic_review_refs_reduced"),
        semantic=True,
        freshness=LedgerFreshness.PARTIAL,
    )
    for conclusion in ("no_material_discrepancy", "challenges_returned"):
        check = _ruled(
            _check(semantic=_SEMANTIC_OK, coverage=reduced), (1, "fixed"), conclusion=conclusion
        )
        state = _changed_state(check)
        assert resolution_blockers(finding, 4, check, frozenset(), proof_state=state) == ()
        assert _resolves(finding, check) is True
    # Silence or any other ruling keeps the reduction disqualifying for AI-powered proof.
    for rulings, extra in (
        ((), ()),
        (((1, "withdrawn"),), ()),
        (((1, "still_present"),), ("reviewer_verdict_still_present",)),
    ):
        check = _ruled(
            _check(semantic=_SEMANTIC_OK, coverage=reduced),
            *rulings,
            conclusion="no_material_discrepancy",
        )
        blockers = resolution_blockers(
            finding, 4, check, frozenset(), proof_state=_changed_state(check)
        )
        assert blockers == (
            *extra,
            "coverage:content_unselected",
            "coverage:semantic_review_refs_reduced",
        )
    # A fixed ruling never bypasses a re-raise or the material-change rule.
    fixed = _ruled(
        _check(semantic=_SEMANTIC_OK, coverage=reduced),
        (1, "fixed"),
        conclusion="no_material_discrepancy",
    )
    assert _resolves(finding, fixed, changed=False) is False


@pytest.mark.parametrize(
    ("first_statement_sequence", "resolves"),
    [
        # No event able to carry a statement yet, or the first came after the raising review's
        # frontier (3): that review predates the statement, so the later one saw no less.
        (None, True),
        (4, True),
        # The raising review's frontier already held a statement-capable event: it may have had
        # the statement, so a review without it proves nothing.
        (3, False),
        (1, False),
        # A caller that does not know the history never tolerates the codes.
        ("unknown", False),
    ],
)
def test_a_finding_raised_before_the_task_statement_resolves_within_that_baseline(
    first_statement_sequence: int | None | str, resolves: bool
) -> None:
    """Issue #908: pre-statement AI-powered findings are not trapped by the new gaps."""

    from finishup.kernel.finding_resolution import _raised_before_task_statement  # pyright: ignore

    finding = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    coverage = _coverage(
        gaps=("task_statement_not_authorized", "task_statement_unavailable"), semantic=True
    )
    check = replace(
        _check(semantic=_SEMANTIC_OK, coverage=coverage),
        semantic_conclusion="no_material_discrepancy",
    )
    before = _raised_before_task_statement(finding, first_statement_sequence)  # type: ignore[arg-type]
    state = _changed_state(check, recorded_at=4)
    assert (
        qualifying_check_resolves(
            finding, 4, check, frozenset(), proof_state=state, raised_before_task_statement=before
        )
        is resolves
    )


def test_no_check_time_change_code_is_a_semantic_capture_baseline() -> None:
    """Issue #883: check-time limits are governed by the shown-file rule, never stamped."""

    assert not SEMANTIC_FINDING_CAPTURE_BASELINE_GAPS & CHECK_TIME_CHANGE_GAPS


_FILE_A = "hmac-sha256:" + "a" * 64
_FILE_B = "hmac-sha256:" + "b" * 64
_FILE_C = "hmac-sha256:" + "c" * 64
_RAISING_EVENT = evt(5)
_REPAIR_EVENT = evt(9)


def _partial(
    commitment: str,
    shown: int,
    redactions: int = 0,
    admitted: bool = False,
    clean: int | None = None,
) -> CheckChangePartialFile:
    """A partial view; without markers the whole shown length is clean, with them none is."""

    if clean is None:
        clean = shown if redactions == 0 else 0
    return CheckChangePartialFile(commitment, shown, redactions, admitted, clean)


def _files(
    full: tuple[str, ...] = (),
    partial: tuple[tuple[str, int] | tuple[str, int, int], ...] = (),
    *,
    complete: bool = True,
    views: tuple[CheckChangePartialFile, ...] = (),
) -> CheckChangeShownFiles:
    """A shown-files record; a partial entry is (commitment, shown bytes[, redacted spans])."""

    return CheckChangeShownFiles(
        full,
        tuple(_partial(entry[0], entry[1], entry[2] if len(entry) > 2 else 0) for entry in partial)
        + views,
        complete=complete,
    )


def _raise_then_repair(
    *,
    raising_gaps: tuple[str, ...] = (),
    raising_files: CheckChangeShownFiles | None = None,
    raising_conclusion: str | None = "challenges_returned",
    repair_gaps: tuple[str, ...],
    repair_files: CheckChangeShownFiles | None,
) -> dict[FindingId, FindingProjectionRecord]:
    """Fold the check whose review raised an AI-powered finding, then a later repair check."""

    findings = {fnd(1): finding_record(_finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED), 4)}
    raising = replace(
        _check(
            tested=3,
            returned=(fnd(1),),
            semantic=_SEMANTIC_OK,
            coverage=_coverage(gaps=raising_gaps, semantic=True),
        ),
        semantic_conclusion=raising_conclusion,
        check_change_files=raising_files,
    )
    apply_check_resolution(findings, raising, _RAISING_EVENT)
    repair = replace(
        _check(semantic=_SEMANTIC_OK, coverage=_coverage(gaps=repair_gaps, semantic=True)),
        semantic_conclusion="no_material_discrepancy",
        check_change_files=repair_files,
    )
    apply_check_resolution(findings, repair, _REPAIR_EVENT, proof_state=_changed_state(repair))
    return findings


def test_large_change_truncated_on_both_checks_resolves_when_the_file_was_shown_in_both() -> None:
    findings = _raise_then_repair(
        raising_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        raising_files=_files(full=(_FILE_A,), partial=((_FILE_B, 900),)),
        repair_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        repair_files=_files(full=(_FILE_A, _FILE_B), partial=((_FILE_C, 10),)),
    )

    record = findings[fnd(1)]
    assert record.check_change_raising_check_event_ids == (_RAISING_EVENT,)
    assert record.check_change_raised_files == _files(full=(_FILE_A,), partial=((_FILE_B, 900),))
    assert record.resolved_by_check_event_id == _REPAIR_EVENT
    assert record.resolution_depends_on_check_event_ids == (_RAISING_EVENT,)


@pytest.mark.parametrize(
    "repair_files",
    [
        _files(full=(_FILE_B,), partial=((_FILE_A, 399),)),  # less of the file arrived
        _files(full=(_FILE_B,)),  # the file did not arrive at all
        _files(full=(_FILE_B,), complete=False),  # a partial record without the file
        None,  # no record of which files arrived
    ],
    ids=("shorter", "absent", "incomplete_without_it", "unrecorded"),
)
def test_file_the_raising_review_saw_but_the_repair_did_not_see_whole_blocks(
    repair_files: CheckChangeShownFiles | None,
) -> None:
    findings = _raise_then_repair(
        raising_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        raising_files=_files(partial=((_FILE_A, 400),)),
        repair_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        repair_files=repair_files,
    )

    assert findings[fnd(1)].resolved_by_check_event_id is None


def test_pre_upgrade_finding_resolves_under_a_truncated_repair() -> None:
    """A raising check from before ADR-031 carried no check-time material: R is empty."""

    findings = _raise_then_repair(
        raising_conclusion=None,
        repair_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP, CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP),
        repair_files=_files(full=(_FILE_C,), partial=((_FILE_A, 5),)),
    )

    assert findings[fnd(1)].check_change_raised_files == _files()
    assert findings[fnd(1)].resolved_by_check_event_id == _REPAIR_EVENT


def test_unavailable_raising_change_resolves_under_an_unavailable_repair() -> None:
    findings = _raise_then_repair(
        raising_gaps=(CHECK_TIME_CHANGE_UNAVAILABLE_GAP,),
        repair_gaps=(CHECK_TIME_CHANGE_UNAVAILABLE_GAP,),
        repair_files=None,
    )

    assert findings[fnd(1)].resolved_by_check_event_id == _REPAIR_EVENT


def test_repair_that_lost_a_change_the_raising_review_saw_blocks() -> None:
    findings = _raise_then_repair(
        raising_files=_files(full=(_FILE_A,)),
        repair_gaps=(CHECK_TIME_CHANGE_UNAVAILABLE_GAP,),
        repair_files=None,
    )

    assert findings[fnd(1)].resolved_by_check_event_id is None


def test_base_unavailable_legacy_task_resolves_when_the_file_was_shown_in_both() -> None:
    """Same HEAD base on both checks: the file commits the same way (ADR-031)."""

    findings = _raise_then_repair(
        raising_gaps=(CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP,),
        raising_files=_files(full=(_FILE_A,)),
        repair_gaps=(CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP,),
        repair_files=_files(full=(_FILE_A,)),
    )

    assert findings[fnd(1)].resolved_by_check_event_id == _REPAIR_EVENT


def test_base_unavailable_repair_after_head_moved_blocks() -> None:
    """HEAD moved: the same path under the new base is a different commitment."""

    findings = _raise_then_repair(
        raising_gaps=(CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP,),
        raising_files=_files(full=(_FILE_A,)),
        repair_gaps=(CHECK_TIME_CHANGE_BASE_UNAVAILABLE_GAP,),
        repair_files=_files(full=(_FILE_B,)),
    )

    assert findings[fnd(1)].resolved_by_check_event_id is None


def test_redacted_span_in_the_repairs_copy_of_the_file_blocks() -> None:
    findings = _raise_then_repair(
        raising_files=_files(full=(_FILE_A,)),
        repair_gaps=(CHECK_TIME_CHANGE_REDACTED_GAP,),
        repair_files=_files(full=(_FILE_B,), partial=((_FILE_A, 10_000),)),
    )

    assert findings[fnd(1)].resolved_by_check_event_id is None


def test_raising_check_that_carried_parts_without_a_record_is_unknown_and_blocks() -> None:
    """0.3 development-build rows: parts reached the packet, no files were recorded."""

    findings = _raise_then_repair(
        raising_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        repair_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        repair_files=_files(full=(_FILE_A, _FILE_B)),
    )

    assert findings[fnd(1)].check_change_raised_files is None
    assert findings[fnd(1)].resolved_by_check_event_id is None


def test_repair_with_a_complete_change_needs_no_shown_file_proof() -> None:
    findings = _raise_then_repair(
        raising_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        repair_gaps=(),
        repair_files=_files(full=(_FILE_B,)),
    )

    record = findings[fnd(1)]
    assert record.resolved_by_check_event_id == _REPAIR_EVENT
    assert record.resolution_depends_on_check_event_ids == ()


def test_redacting_the_raising_check_reopens_a_resolution_that_depended_on_it() -> None:
    findings = _raise_then_repair(
        raising_files=_files(full=(_FILE_A,)),
        repair_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        repair_files=_files(full=(_FILE_A,)),
    )
    assert findings[fnd(1)].resolved_by_check_event_id == _REPAIR_EVENT

    reopen_findings_resolved_by(findings, frozenset({_RAISING_EVENT}))

    record = findings[fnd(1)]
    assert record.resolved_by_check_event_id is None
    assert record.resolution_depends_on_check_event_ids == ()
    assert record.check_change_raising_check_event_ids == (_RAISING_EVENT,)
    assert record.check_change_raised_files is None  # unknown from now on
    # A later truncated repair can no longer lean on the redacted check's files.
    again = replace(
        _check(
            tested=10,
            semantic=_SEMANTIC_OK,
            coverage=_coverage(gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,), semantic=True),
        ),
        semantic_conclusion="no_material_discrepancy",
        check_change_files=_files(full=(_FILE_A,)),
    )
    apply_check_resolution(findings, again, evt(11), proof_state=_changed_state(again))
    assert findings[fnd(1)].resolved_by_check_event_id is None


def test_redacting_the_repair_check_reopens_as_before() -> None:
    findings = _raise_then_repair(
        raising_files=_files(full=(_FILE_A,)),
        repair_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        repair_files=_files(full=(_FILE_A,)),
    )

    reopen_findings_resolved_by(findings, frozenset({_REPAIR_EVENT}))

    record = findings[fnd(1)]
    assert record.resolved_by_check_event_id is None
    assert record.check_change_raised_files == _files(full=(_FILE_A,))


def test_check_time_raise_facts_round_trip_through_the_projection_snapshot() -> None:
    findings = _raise_then_repair(
        raising_files=_files(full=(_FILE_A,), partial=((_FILE_B, 77),)),
        repair_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        repair_files=_files(full=(_FILE_A, _FILE_B)),
    )
    state = replace(empty_projection_state(), frontier=9, head_digest=_DIGEST, findings=findings)

    decoded = projection_from_snapshot(projection_snapshot(state))

    assert decoded == state
    assert decoded.findings[fnd(1)].check_change_raised_files == _files(
        full=(_FILE_A,), partial=((_FILE_B, 77),)
    )


@pytest.mark.parametrize(
    ("repair_bytes", "resolved"), [(4_096, True), (4_095, True), (4_094, False)]
)
def test_file_straddling_the_packet_edge_on_both_checks_compares_shown_bytes(
    repair_bytes: int, resolved: bool
) -> None:
    """A large change almost always cuts one file at the packet edge on both checks."""

    findings = _raise_then_repair(
        raising_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        raising_files=_files(full=(_FILE_A,), partial=((_FILE_B, 4_095),)),
        repair_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        repair_files=_files(full=(_FILE_A,), partial=((_FILE_B, repair_bytes),)),
    )

    assert (findings[fnd(1)].resolved_by_check_event_id == _REPAIR_EVENT) is resolved


def test_repair_record_past_its_file_bound_still_proves_the_files_it_holds() -> None:
    """Only the shown files count; a repair may keep the first 128 and still cover R."""

    findings = _raise_then_repair(
        raising_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        raising_files=_files(full=(_FILE_A,)),
        repair_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        repair_files=_files(full=(_FILE_A, _FILE_C), complete=False),
    )

    assert findings[fnd(1)].resolved_by_check_event_id == _REPAIR_EVENT


def test_raising_record_past_its_file_bound_is_unknown_and_blocks() -> None:
    findings = _raise_then_repair(
        raising_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        raising_files=_files(full=(_FILE_A,), complete=False),
        repair_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        repair_files=_files(full=(_FILE_A, _FILE_B, _FILE_C)),
    )

    assert findings[fnd(1)].check_change_raised_files is None
    assert findings[fnd(1)].resolved_by_check_event_id is None


def test_few_shown_files_of_a_change_with_many_changed_files_resolve() -> None:
    """More than 128 changed files, a handful shown: the record holds only the shown ones."""

    findings = _raise_then_repair(
        raising_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        raising_files=_files(full=(_FILE_A,), partial=((_FILE_B, 2_000),)),
        repair_gaps=(CHECK_TIME_CHANGE_TRUNCATED_GAP,),
        repair_files=_files(full=(_FILE_A, _FILE_B)),
    )

    assert findings[fnd(1)].resolved_by_check_event_id == _REPAIR_EVENT


def test_repair_that_saw_a_raising_partial_file_redacted_earlier_blocks() -> None:
    findings = _raise_then_repair(
        raising_files=_files(partial=((_FILE_A, 3_000),)),
        repair_gaps=(CHECK_TIME_CHANGE_REDACTED_GAP,),
        repair_files=_files(partial=((_FILE_A, 1_200),)),
    )

    assert findings[fnd(1)].resolved_by_check_event_id is None


def _review(
    tested: int,
    attempt: int,
    files: CheckChangeShownFiles | None,
    *,
    returned: tuple[object, ...] = (),
    gaps: tuple[str, ...] = (CHECK_TIME_CHANGE_TRUNCATED_GAP,),
    conclusion: str = "challenges_returned",
) -> CheckRecordedPayload:
    provenance = replace(
        _provenance(), semantic_attempt_id=f"att_00000000-0000-4000-8000-{attempt:012x}"
    )
    return replace(
        _check(
            tested=tested,
            returned=returned,
            semantic=_SEMANTIC_OK,
            coverage=_coverage(gaps=gaps, semantic=True),
        ),
        semantic_conclusion=conclusion,
        semantic_provenance=provenance,
        check_change_files=files,
    )


def _raise_reraise(
    first: CheckChangeShownFiles, second: CheckChangeShownFiles
) -> dict[FindingId, FindingProjectionRecord]:
    """C1 raises the finding; C2, a later review, returns the same finding id again."""

    findings = {fnd(1): finding_record(_finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED), 4)}
    apply_check_resolution(findings, _review(3, 1, first, returned=(fnd(1),)), evt(5))
    apply_check_resolution(findings, _review(6, 2, second, returned=(fnd(1),)), evt(7))
    return findings


def _repair_with(
    findings: dict[FindingId, FindingProjectionRecord], files: CheckChangeShownFiles
) -> FindingProjectionRecord:
    repair = _review(8, 3, files, conclusion="no_material_discrepancy")
    apply_check_resolution(findings, repair, evt(9), proof_state=_changed_state(repair))
    return findings[fnd(1)]


def test_a_re_raise_widens_what_the_repair_must_have_seen() -> None:
    """Probe: C1 saw A, C2 re-raised after seeing B in part, C3 shows only A: not resolved."""

    findings = _raise_reraise(
        _files(full=(_FILE_A,)), _files(full=(_FILE_A,), partial=((_FILE_B, 900),))
    )
    record = findings[fnd(1)]
    assert record.check_change_raising_check_event_ids == (evt(5), evt(7))
    assert record.check_change_raised_files == _files(full=(_FILE_A,), partial=((_FILE_B, 900),))

    assert _repair_with(dict(findings), _files(full=(_FILE_A,))).resolved_by_check_event_id is None
    resolved = _repair_with(dict(findings), _files(full=(_FILE_A,), partial=((_FILE_B, 900),)))
    assert resolved.resolved_by_check_event_id == evt(9)
    assert resolved.resolution_depends_on_check_event_ids == (evt(5), evt(7))


@pytest.mark.parametrize(
    ("repair_entry", "resolved"),
    [((_FILE_B, 900, 1), True), ((_FILE_B, 900, 2), False), ((_FILE_B, 899, 0), False)],
)
def test_merged_raising_views_keep_the_stronger_requirement_per_file(
    repair_entry: tuple[str, int, int], resolved: bool
) -> None:
    findings = _raise_reraise(
        _files(partial=((_FILE_B, 500, 2),)), _files(partial=((_FILE_B, 900, 1),))
    )
    assert findings[fnd(1)].check_change_raised_files == _files(partial=((_FILE_B, 900, 1),))

    record = _repair_with(findings, _files(partial=(repair_entry,)))

    assert (record.resolved_by_check_event_id == evt(9)) is resolved


def test_a_file_one_raising_review_saw_whole_must_be_whole_in_the_repair() -> None:
    findings = _raise_reraise(_files(partial=((_FILE_A, 100),)), _files(full=(_FILE_A,)))
    assert findings[fnd(1)].check_change_raised_files == _files(full=(_FILE_A,))

    assert (
        _repair_with(findings, _files(partial=((_FILE_A, 9_000),))).resolved_by_check_event_id
        is None
    )


def test_redacting_a_re_raising_check_makes_r_unknown_and_reopens() -> None:
    findings = _raise_reraise(_files(full=(_FILE_A,)), _files(full=(_FILE_A,)))
    record = _repair_with(findings, _files(full=(_FILE_A,)))
    assert record.resolved_by_check_event_id == evt(9)

    reopen_findings_resolved_by(findings, frozenset({evt(7)}))

    assert findings[fnd(1)].resolved_by_check_event_id is None
    assert findings[fnd(1)].check_change_raised_files is None


def test_partial_file_needs_the_whole_shown_length_not_the_prefix_before_a_redaction() -> None:
    """Probe: a fully admitted 3038 B section with one redacted span is n=3038, k=1, not n=67."""

    raising = _files(partial=((_FILE_A, 3_038, 1),))
    findings = _raise_reraise(raising, raising)

    assert (
        _repair_with(
            dict(findings), _files(partial=((_FILE_A, 100, 1),))
        ).resolved_by_check_event_id
        is None
    )
    # The redaction persists and the repair saw at least as much: covered.
    assert _repair_with(
        dict(findings), _files(partial=((_FILE_A, 3_100, 1),))
    ).resolved_by_check_event_id == evt(9)


def test_a_redaction_new_in_the_repair_blocks() -> None:
    findings = _raise_reraise(
        _files(partial=((_FILE_A, 3_000, 0),)), _files(partial=((_FILE_A, 3_000, 0),))
    )

    record = _repair_with(findings, _files(partial=((_FILE_A, 5_000, 1),)))

    assert record.resolved_by_check_event_id is None


def test_edge_cut_raise_is_covered_by_a_longer_repair_whose_first_n_bytes_are_clean() -> None:
    """L1: the raising view stopped before a marker the repair later showed."""

    findings = _raise_reraise(
        _files(views=(_partial(_FILE_A, 995),)), _files(views=(_partial(_FILE_A, 995),))
    )

    record = _repair_with(findings, _files(views=(_partial(_FILE_A, 4_322, 1, False, 2_100),)))

    assert record.resolved_by_check_event_id == evt(9)


def test_whole_section_raise_is_covered_by_a_shrunk_whole_repair_with_the_same_markers() -> None:
    """L2: the fix shortened the diff; the persistent redaction stays at one span."""

    raised = _partial(_FILE_A, 3_000, 1, True, 67)
    findings = _raise_reraise(_files(views=(raised,)), _files(views=(raised,)))

    record = _repair_with(findings, _files(views=(_partial(_FILE_A, 2_400, 1, True, 67),)))

    assert record.resolved_by_check_event_id == evt(9)


@pytest.mark.parametrize(
    "repair",
    [
        _partial(_FILE_A, 2_400, 2, True, 50),  # whole, but more hidden and not clean for n
        _partial(_FILE_A, 2_400, 1, False, 67),  # shorter and not the whole section
    ],
    ids=("more_redactions", "shorter_cut"),
)
def test_whole_or_shorter_repair_views_that_hide_more_still_block(
    repair: CheckChangePartialFile,
) -> None:
    raised = _partial(_FILE_A, 3_000, 1, True, 67)
    findings = _raise_reraise(_files(views=(raised,)), _files(views=(raised,)))

    assert _repair_with(findings, _files(views=(repair,))).resolved_by_check_event_id is None


def test_contributors_past_the_bound_make_r_unknown() -> None:
    findings = {fnd(1): finding_record(_finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED), 4)}
    files = _files(full=(_FILE_A,))
    for index in range(MAX_CHECK_CHANGE_RAISING_CHECKS):
        apply_check_resolution(
            findings, _review(3, index + 1, files, returned=(fnd(1),)), evt(100 + index)
        )
    assert len(findings[fnd(1)].check_change_raising_check_event_ids) == 64
    assert findings[fnd(1)].check_change_raised_files == files

    apply_check_resolution(findings, _review(3, 999, files, returned=(fnd(1),)), evt(999))

    record = findings[fnd(1)]
    assert len(record.check_change_raising_check_event_ids) == 64
    assert record.check_change_raised_files is None


def test_merged_requirement_may_outgrow_one_event_row_up_to_its_own_bound() -> None:
    def record(offset: int, count: int) -> CheckChangeShownFiles:
        return _files(full=tuple(f"hmac-sha256:{offset + index:064x}" for index in range(count)))

    merged = record(0, 128)
    for batch in range(1, 8):
        step = merged.merged(record(batch * 128, 128))
        assert step is not None
        merged = step
    assert len(merged.fully_shown) == 1_024
    assert merged.merged(record(10_000, 1)) is None
    # The same wide requirement survives the projection snapshot.
    findings = {
        fnd(1): replace(
            finding_record(_finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED), 4),
            check_change_raising_check_event_ids=(evt(5),),
            check_change_raised_files=merged,
        )
    }
    state = replace(empty_projection_state(), frontier=9, head_digest=_DIGEST, findings=findings)
    assert projection_from_snapshot(projection_snapshot(state)) == state


# --- R945-02 (maintainer decision 2026-09-30): view commitments bind where spans and hunks lie --

_VIEW_1 = "hmac-sha256:" + "1" * 64
_VIEW_2 = "hmac-sha256:" + "2" * 64


def _viewed(
    shown: int, redactions: int, admitted: bool, clean: int, view: str | None
) -> CheckChangePartialFile:
    return CheckChangePartialFile(_FILE_A, shown, redactions, admitted, clean, view)


def test_a_moved_redaction_with_equal_counts_is_not_covered() -> None:
    """The reviewer's exact probe, now with the view commitment each check records."""

    raised = CheckChangeShownFiles((), (_viewed(100, 1, False, 20, _VIEW_1),), True)
    moved = CheckChangeShownFiles((), (_viewed(100, 1, False, 80, _VIEW_2),), True)
    same = CheckChangeShownFiles((), (_viewed(100, 1, False, 20, _VIEW_1),), True)

    assert not moved.covers(raised)
    assert same.covers(raised)
    assert CheckChangeShownFiles((_FILE_A,), (), True).covers(raised)  # whole still covers


def test_a_moved_packet_edge_hunk_with_a_longer_view_is_not_covered() -> None:
    raised = CheckChangeShownFiles((), (_viewed(995, 0, False, 995, _VIEW_1),), True)
    longer = CheckChangeShownFiles((), (_viewed(4_322, 0, False, 4_322, _VIEW_2),), True)

    assert not longer.covers(raised)


def test_a_repair_record_without_a_view_never_covers_a_committed_raise() -> None:
    raised = CheckChangeShownFiles((), (_viewed(100, 1, True, 20, _VIEW_1),), True)
    legacy_repair = CheckChangeShownFiles((), (_viewed(100, 1, True, 20, None),), True)

    assert not legacy_repair.covers(raised)


def test_raises_with_different_views_merge_into_a_whole_file_requirement() -> None:
    first = CheckChangeShownFiles((), (_viewed(500, 1, True, 20, _VIEW_1),), True)
    second = CheckChangeShownFiles((), (_viewed(500, 1, True, 20, _VIEW_2),), True)

    merged = first.merged(second)

    assert merged == CheckChangeShownFiles((_FILE_A,), (), True)
    assert first.merged(first) == first


def test_legacy_raise_falls_back_and_is_reported_unverified() -> None:
    legacy = CheckChangeShownFiles((), (_viewed(100, 1, False, 20, None),), True)
    committed = CheckChangeShownFiles((), (_viewed(100, 1, False, 20, _VIEW_1),), True)
    repair = CheckChangeShownFiles((), (_viewed(100, 1, False, 20, _VIEW_2),), True)

    assert repair.covers(legacy)  # the old length/count comparison
    assert legacy.has_unverified_views()
    assert not committed.has_unverified_views()
    assert not CheckChangeShownFiles((_FILE_A,), (), True).has_unverified_views()


def test_view_commitment_round_trips_and_legacy_rows_still_decode() -> None:
    from finishup.domain.events import check_change_files_from_json, check_change_files_to_json

    committed = CheckChangeShownFiles((), (_viewed(100, 1, False, 20, _VIEW_1),), True)
    wire = check_change_files_to_json(committed)
    assert check_change_files_from_json(wire) == committed
    legacy = CheckChangeShownFiles((), (_viewed(100, 1, False, 20, None),), True)
    legacy_wire = check_change_files_to_json(legacy)
    partial = legacy_wire["partially_shown"]
    assert isinstance(partial, tuple) and "view_commitment" not in partial[0]
    assert check_change_files_from_json(legacy_wire) == legacy


def test_resolution_through_a_legacy_raise_is_marked_unverified() -> None:
    from finishup.kernel.finding_resolution import check_change_resolution_unverified

    legacy = _files(views=(_viewed(3_000, 1, True, 67, None),))
    findings = _raise_reraise(legacy, legacy)
    record = _repair_with(findings, _files(views=(_viewed(3_000, 1, True, 67, _VIEW_1),)))
    assert record.resolved_by_check_event_id == evt(9)
    assert check_change_resolution_unverified(record)

    committed = _files(views=(_viewed(3_000, 1, True, 67, _VIEW_1),))
    findings = _raise_reraise(committed, committed)
    record = _repair_with(findings, committed)
    assert record.resolved_by_check_event_id == evt(9)
    assert not check_change_resolution_unverified(record)


def test_receipt_discloses_a_resolution_through_a_legacy_raise() -> None:
    from finishup.application.receipt import (
        _check_change_resolution_gaps,  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    )
    from finishup.domain.receipts import (
        CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP,
        check_time_change_gap_sentence,
    )
    from finishup.kernel.receipt_builder import ReceiptFindingState

    legacy = _files(views=(_viewed(3_000, 1, True, 67, None),))
    findings = _raise_reraise(legacy, legacy)
    _repair_with(findings, _files(views=(_viewed(3_000, 1, True, 67, _VIEW_1),)))
    projection = replace(
        empty_projection_state(), frontier=20, head_digest=_DIGEST, findings=findings
    )

    gaps = _check_change_resolution_gaps(projection, (ReceiptFindingState(fnd(1), True),))

    assert [gap.code for gap in gaps] == [CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP]
    sentence = check_time_change_gap_sentence(CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP)
    assert sentence is not None and "only the lengths and counts" in sentence
    assert not _check_change_resolution_gaps(projection, (ReceiptFindingState(fnd(1), False),))


def _legacy_resolved_projection(count: int) -> tuple[ProjectionState, tuple[object, ...]]:
    from finishup.domain.events import encode_payload
    from finishup.kernel.ranking import rank_key
    from finishup.kernel.receipt_builder import ReceiptFindingState
    from finishup.protocol.canonical import canonical_digest

    legacy = _files(views=(_viewed(3_000, 1, True, 67, None),))
    findings = _raise_reraise(legacy, legacy)
    template = _repair_with(findings, _files(views=(_viewed(3_000, 1, True, 67, _VIEW_1),)))
    assert template.payload is not None
    many: dict[FindingId, FindingProjectionRecord] = {}
    for index in range(1, count + 1):
        identifier = fnd(index)
        payload = replace(template.payload, finding_id=identifier, subject_refs=(obl(index),))
        many[identifier] = replace(
            template,
            payload=payload,
            payload_digest=canonical_digest(encode_payload(payload)),
        )
    projection = replace(empty_projection_state(), frontier=20, head_digest=_DIGEST, findings=many)
    ordered = sorted(many.values(), key=lambda item: rank_key(cast(Finding, item.payload)))
    states = tuple(
        ReceiptFindingState(cast(Finding, item.payload).finding_id, True) for item in ordered
    )
    return projection, states


def test_legacy_disclosure_is_one_task_wide_gap_however_many_findings_it_covers() -> None:
    """65 affected findings still build a receipt: one gap row, never one per finding."""

    from finishup.application.receipt import (
        _check_change_resolution_gaps,  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    )
    from finishup.domain.receipts import CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP
    from finishup.kernel.finding_resolution import unverified_resolution_finding_ids
    from finishup.kernel.receipt_builder import ReceiptFindingState

    projection, states = _legacy_resolved_projection(65)
    typed_states = cast(tuple[ReceiptFindingState, ...], states)

    gaps = _check_change_resolution_gaps(projection, typed_states)

    assert [(gap.marker, gap.code) for gap in gaps] == [
        (CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP, CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP)
    ]
    resolved = (state.finding_id for state in typed_states if state.resolved)
    assert len(unverified_resolution_finding_ids(projection, resolved)) == 65


def test_receipt_names_legacy_resolutions_boundedly_in_one_gap() -> None:
    """A receipt section holds at most 64 findings; 20 show the bounded id list."""

    from finishup.domain.receipts import (
        CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP,
        render_receipt_human,
    )
    from finishup.kernel.deterministic_checks import CaseAvailabilityFacts, CaseGap
    from finishup.kernel.receipt_builder import ReceiptBuildContext, ReceiptFindingState

    projection, states = _legacy_resolved_projection(20)
    from finishup.protocol.coverage import weakest

    coverage = _coverage(
        gaps=(CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP, "check_not_recorded"),
        freshness=projection.freshness,
    )
    for record in projection.findings.values():
        assert record.payload is not None
        coverage = weakest(coverage, record.payload.coverage)
    context = ReceiptBuildContext(
        projection=projection,
        subject_frontier=Frontier(20, _DIGEST),
        availability=CaseAvailabilityFacts(),
        coverage=coverage,
        gaps=(
            CaseGap("check_not_recorded", "check_not_recorded", ()),
            CaseGap(
                CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP,
                CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP,
                (),
            ),
        ),
        finding_states=cast(tuple[ReceiptFindingState, ...], states),
        applicable_check=None,
    )

    from unit.kernel.test_receipt_builder import _build  # pyright: ignore[reportPrivateUsage]

    receipt = _build(context)

    (gap,) = [
        item for item in receipt.gaps if item.code == CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP
    ]
    assert gap.detail is not None and "20 resolved AI-powered findings" in gap.detail
    for markdown in (True, False):
        text = render_receipt_human(receipt, markdown=markdown)
        assert "20 resolved AI-powered findings" in text
        assert str(fnd(1)) in text and "and 4 more" in text


# Issue #904: a bounded AI-powered review selection is disclosure, not a veto on repair proof.
_SCOPE_REDUCED = "semantic_reference_scope_reduced"
# The agent-visible gaps of an ordinary semantic check in a long hook-observed session.
_LONG_SESSION_REVIEW_GAPS = (
    "content_unselected",
    "evidence_content_digest_only",
    "host_outcome_unavailable",
    _SCOPE_REDUCED,
    "unpaired_event",
)


def _assessed(check: CheckRecordedPayload) -> CheckRecordedPayload:
    return replace(check, semantic_conclusion="no_material_discrepancy")


def _in_view(*refs: str) -> tuple[str, ...]:
    return tuple(sorted(set(refs), key=str.encode))


# What an ordinary reduced packet carried: the finding's own prior-finding row, its subject and
# ``_changed_state``'s repair.
_REPAIR_IN_VIEW: tuple[str, ...] = (obl(1), act(9), fnd(1))


def _review_check(
    *gaps: str, tested: int = 8, included: tuple[str, ...] | None = _REPAIR_IN_VIEW
) -> CheckRecordedPayload:
    """A completed, assessable semantic check whose coverage carries exactly *gaps*.

    A reduced-scope check records *included* as its packet's included references (issue #904);
    ``None`` models a check with no such record.
    """

    coverage = _coverage(gaps=gaps, semantic=True, freshness=LedgerFreshness.PARTIAL)
    check = _assessed(_check(tested=tested, semantic=_SEMANTIC_OK, coverage=coverage))
    if _SCOPE_REDUCED in gaps and included is not None:
        check = replace(check, semantic_included_refs=_in_view(*included))
    return check


def _semantic_finding(*gaps: str) -> Finding:
    """An AI-powered finding whose own recorded coverage carries exactly *gaps*."""

    coverage = _coverage(gaps=gaps, semantic=True, freshness=LedgerFreshness.PARTIAL)
    return replace(_finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED), coverage=coverage)


def _blockers(
    finding: Finding,
    check: CheckRecordedPayload,
    *,
    raised_under_reduced_scope: bool = False,
) -> tuple[str, ...]:
    from finishup.kernel.finding_resolution import resolution_blockers

    return resolution_blockers(
        finding,
        4,
        check,
        frozenset(),
        proof_state=_changed_state(check),
        raised_under_reduced_scope=raised_under_reduced_scope,
    )


def test_a_reduced_review_scope_never_weakens_local_proof() -> None:
    """The local-check case is not reduced (ADR-006), so only the review packet is bounded."""

    finding = _finding()
    readable = _check(semantic=_SEMANTIC_OK, coverage=_coverage(semantic=True))
    reduced = _check(
        semantic=_SEMANTIC_OK,
        coverage=_coverage(gaps=(_SCOPE_REDUCED,), semantic=True),
    )
    assert _blockers(finding, readable) == ()
    assert _blockers(finding, reduced) == ()
    assert _resolves(finding, reduced) is True
    # The same holds when the bounded review itself did not run to completion.
    not_run = _check(
        coverage=_coverage(gaps=(_SCOPE_REDUCED, "semantic_relevance_review_not_run")),
    )
    assert _blockers(finding, not_run) == ()


def test_the_dateutil_local_finding_shape_resolves_under_a_reduced_review_scope() -> None:
    """dateutil ``fnd_2c29e40c``: its only blocker was ``semantic_reference_scope_reduced``."""

    finding = replace(
        _finding(kind=FindingKind.LEDGER_STALE_OR_INCOMPLETE),
        coverage=_coverage(
            gaps=("evidence_content_digest_only",), freshness=LedgerFreshness.CURRENT
        ),
    )
    later = _review_check(*_LONG_SESSION_REVIEW_GAPS)
    assert _blockers(finding, later) == ()
    assert _resolves(finding, later) is True
    # Not returned is still required; the interim leaves a truncated payload blocking.
    assert not qualifying_check_resolves(finding, 4, later, frozenset({issue_key(finding)}))
    truncated = _review_check(*_LONG_SESSION_REVIEW_GAPS, "truncated_payload")
    assert _blockers(finding, truncated) == ("coverage:truncated_payload",)


def test_a_semantic_finding_stamped_with_the_scope_resolves_under_the_same_limit() -> None:
    """A post-upgrade finding records the reduced scope its review ran under (issue #904)."""

    original = _semantic_finding(
        "content_unselected", "host_outcome_unavailable", _SCOPE_REDUCED, "unpaired_event"
    )
    later = _review_check(*_LONG_SESSION_REVIEW_GAPS)
    assert _blockers(original, later) == ()
    assert _resolves(original, later) is True
    # Every other requirement stands: a re-roll, an unassessable answer, an unfinished review.
    assert _resolves(original, later, changed=False) is False
    insufficient = replace(
        later,
        semantic_conclusion="insufficient_packet",
        coverage=replace(
            later.coverage,
            known_gaps=tuple(sorted((*later.coverage.known_gaps, "semantic_packet_insufficient"))),
        ),
    )
    assert _blockers(original, insufficient) == (
        "semantic_packet_insufficient",
        "coverage:content_unselected",
        "coverage:host_outcome_unavailable",
        "coverage:semantic_packet_insufficient",
        "coverage:" + _SCOPE_REDUCED,
        "coverage:unpaired_event",
    )
    assert _resolves(original, _check(coverage=later.coverage)) is False


def test_a_new_reduced_review_scope_still_blocks_semantic_proof() -> None:
    """A review that saw the whole ledger raised it; a bounded later review is a new limit."""

    original = _semantic_finding("content_unselected", "host_outcome_unavailable", "unpaired_event")
    later = _review_check(*_LONG_SESSION_REVIEW_GAPS)
    assert _blockers(original, later) == ("coverage:" + _SCOPE_REDUCED,)
    assert _resolves(original, later) is False


def test_a_pre_upgrade_finding_uses_its_raising_checks_recorded_scope() -> None:
    """Lifecycle fallback: the raising check recorded the code the finding could not carry."""

    original = _semantic_finding("content_unselected", "host_outcome_unavailable", "unpaired_event")
    later = _review_check(*_LONG_SESSION_REVIEW_GAPS)
    assert _blockers(original, later, raised_under_reduced_scope=True) == ()
    assert qualifying_check_resolves(
        original,
        4,
        later,
        frozenset(),
        proof_state=_changed_state(later),
        raised_under_reduced_scope=True,
    )
    # The fallback supplies only the scope code: no other limitation and no other requirement.
    truncated = _review_check(*_LONG_SESSION_REVIEW_GAPS, "truncated_payload")
    assert _blockers(original, truncated, raised_under_reduced_scope=True) == (
        "coverage:truncated_payload",
    )
    assert _blockers(
        original,
        replace(later, semantic_conclusion=None, semantic_included_refs=None),
        raised_under_reduced_scope=True,
    ) == (
        "coverage:content_unselected",
        "coverage:host_outcome_unavailable",
        "coverage:" + _SCOPE_REDUCED,
        "coverage:unpaired_event",
    )
    # The finding's recorded coverage is never rewritten.
    assert _SCOPE_REDUCED not in original.coverage.known_gaps


def _raising_check(*gaps: str) -> CheckRecordedPayload:
    """The completed review that raised ``_semantic_finding`` at subject frontier 3."""

    return _review_check(*gaps, tested=3)


def test_apply_records_the_raising_check_only_for_a_reduced_scope_review() -> None:
    raised = _semantic_finding("content_unselected", "host_outcome_unavailable", "unpaired_event")
    local = _finding(2, subject_refs=(obl(2),))
    assert raised.subject_frontier == local.subject_frontier == _raising_check().subject_frontier
    findings = {fnd(1): finding_record(raised, 4), fnd(2): finding_record(local, 4)}

    apply_check_resolution(
        findings, replace(_raising_check(), returned_finding_ids=(fnd(1), fnd(2))), evt(5)
    )
    assert findings[fnd(1)].reduced_scope_raising_check_event_id is None, "scope was not reduced"

    apply_check_resolution(
        findings,
        replace(_raising_check(*_LONG_SESSION_REVIEW_GAPS), returned_finding_ids=(fnd(1), fnd(2))),
        evt(6),
    )
    assert findings[fnd(1)].reduced_scope_raising_check_event_id == evt(6)
    assert findings[fnd(2)].reduced_scope_raising_check_event_id is None, "local proof needs none"

    # A later check that returns the same row again is not the check that raised it.
    later_return = replace(
        _review_check(*_LONG_SESSION_REVIEW_GAPS), returned_finding_ids=(fnd(1),)
    )
    fresh = {fnd(1): finding_record(raised, 4)}
    apply_check_resolution(fresh, later_return, evt(9))
    assert fresh[fnd(1)].reduced_scope_raising_check_event_id is None


def test_the_recorded_raising_scope_resolves_through_the_fold_until_redacted() -> None:
    raised = _semantic_finding("content_unselected", "host_outcome_unavailable", "unpaired_event")
    findings = {fnd(1): finding_record(raised, 4)}
    raising = replace(_raising_check(*_LONG_SESSION_REVIEW_GAPS), returned_finding_ids=(fnd(1),))
    apply_check_resolution(findings, raising, evt(5))
    assert findings[fnd(1)].reduced_scope_raising_check_event_id == evt(5)

    # Redacting the raising check removes the fallback: its coverage is no longer readable.
    redacted = dict(findings)
    reopen_findings_resolved_by(redacted, frozenset({evt(5)}))
    assert redacted[fnd(1)].reduced_scope_raising_check_event_id is None
    later = _review_check(*_LONG_SESSION_REVIEW_GAPS)
    apply_check_resolution(redacted, later, evt(9), proof_state=_changed_state(later))
    assert redacted[fnd(1)].resolved_by_check_event_id is None

    apply_check_resolution(findings, later, evt(9), proof_state=_changed_state(later))
    assert findings[fnd(1)].resolved_by_check_event_id == evt(9)
    assert findings[fnd(1)].resolution_raising_check_event_id == evt(5), "proof read the raiser"
    # Redacting the raising check after resolution reopens the row: that proof read the raising
    # check's recorded scope, and unreadable proof is no proof.
    reopen_findings_resolved_by(findings, frozenset({evt(5)}))
    assert findings[fnd(1)].resolved_by_check_event_id is None
    assert findings[fnd(1)].resolution_raising_check_event_id is None
    assert findings[fnd(1)].reduced_scope_raising_check_event_id is None
    # The reopened row now meets later reviews without the fallback: the scope code blocks.
    again = _review_check(*_LONG_SESSION_REVIEW_GAPS, tested=10)
    apply_check_resolution(findings, again, evt(11), proof_state=_changed_state(again))
    assert findings[fnd(1)].resolved_by_check_event_id is None


@pytest.mark.parametrize("independent", ["stamped_finding", "unreduced_proving_check"])
def test_redacting_the_raising_check_keeps_a_proof_that_never_read_it(independent: str) -> None:
    """Only a resolution that needed the raising check's scope reopens when it is redacted."""

    gaps = ["content_unselected", "host_outcome_unavailable", "unpaired_event"]
    later_gaps = list(_LONG_SESSION_REVIEW_GAPS)
    if independent == "stamped_finding":
        gaps.append(_SCOPE_REDUCED)  # Post-upgrade: the finding's own coverage carries it.
    else:
        later_gaps.remove(_SCOPE_REDUCED)  # The proving review was not reduced at all.
    findings = {fnd(1): finding_record(_semantic_finding(*gaps), 4)}
    raising = replace(_raising_check(*_LONG_SESSION_REVIEW_GAPS), returned_finding_ids=(fnd(1),))
    apply_check_resolution(findings, raising, evt(5))
    assert findings[fnd(1)].reduced_scope_raising_check_event_id == evt(5)
    later = _review_check(*later_gaps)
    apply_check_resolution(findings, later, evt(9), proof_state=_changed_state(later))
    assert findings[fnd(1)].resolved_by_check_event_id == evt(9)
    assert findings[fnd(1)].resolution_raising_check_event_id is None

    reopen_findings_resolved_by(findings, frozenset({evt(5)}))
    assert findings[fnd(1)].resolved_by_check_event_id == evt(9)
    assert findings[fnd(1)].reduced_scope_raising_check_event_id is None
    # Redacting the proving check still reopens it.
    reopen_findings_resolved_by(findings, frozenset({evt(9)}))
    assert findings[fnd(1)].resolved_by_check_event_id is None


def test_a_returned_row_drops_the_raising_check_its_old_proof_relied_on() -> None:
    record = replace(
        finding_record(_semantic_finding("content_unselected"), 4),
        resolved_by_check_event_id=evt(9),
        reduced_scope_raising_check_event_id=evt(5),
        resolution_raising_check_event_id=evt(5),
    )
    findings = {fnd(1): record}
    apply_check_resolution(findings, _check(returned=(fnd(1),)), evt(11))
    assert findings[fnd(1)].resolved_by_check_event_id is None
    assert findings[fnd(1)].resolution_raising_check_event_id is None
    assert findings[fnd(1)].reduced_scope_raising_check_event_id == evt(5)


def test_snapshot_round_trips_the_raising_scope_and_omits_it_when_absent() -> None:
    raised = _semantic_finding("content_unselected")
    plain = finding_record(_finding(2, subject_refs=(obl(2),)), 5)
    recorded = replace(finding_record(raised, 4), reduced_scope_raising_check_event_id=evt(6))
    state = replace(
        empty_projection_state(),
        frontier=9,
        head_digest=_DIGEST,
        findings={fnd(1): recorded, fnd(2): plain},
        freshness=LedgerFreshness.CURRENT,
    )
    snapshot = projection_snapshot(state)
    rows = snapshot["findings"]
    assert isinstance(rows, dict)
    assert "reduced_scope_raising_check_event_id" not in rows[fnd(2)]  # type: ignore[operator]
    assert rows[fnd(1)]["reduced_scope_raising_check_event_id"] == evt(6)  # type: ignore[index]
    decoded = projection_from_snapshot(snapshot)
    assert decoded == state
    assert canonical_encode(projection_snapshot(decoded)) == canonical_encode(snapshot)
    rows[fnd(1)]["reduced_scope_raising_check_event_id"] = None  # type: ignore[index]
    with pytest.raises(ValueError, match="invalid_projection_state"):
        projection_from_snapshot(snapshot)

    relied = replace(
        recorded, resolved_by_check_event_id=evt(9), resolution_raising_check_event_id=evt(6)
    )
    relied_state = replace(state, findings={fnd(1): relied, fnd(2): plain})
    relied_snapshot = projection_snapshot(relied_state)
    relied_rows = relied_snapshot["findings"]
    assert isinstance(relied_rows, dict)
    assert "resolution_raising_check_event_id" not in relied_rows[fnd(2)]  # type: ignore[operator]
    assert relied_rows[fnd(1)]["resolution_raising_check_event_id"] == evt(6)  # type: ignore[index]
    assert projection_from_snapshot(relied_snapshot) == relied_state
    # A relied-on raising check without the resolution it supported is not a valid record.
    with pytest.raises(ValueError, match="invalid_projection_state"):
        replace(relied, resolved_by_check_event_id=None)
    del relied_rows[fnd(1)]["resolved_by_check_event_id"]  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="invalid_projection_state"):
        projection_from_snapshot(relied_snapshot)


# drizzle ``fnd_8d68fbc3``: raised by a review whose coverage carried a gap outside the baseline.
_DRIZZLE_RAISED_UNDER = (
    "completion_plan_not_claimed",
    "content_unselected",
    "evidence_content_digest_only",
    "host_outcome_unavailable",
    "semantic_case_content_over_item_limit",
    "unpaired_event",
)
_DRIZZLE_LATER_REVIEW = (
    "content_unselected",
    "evidence_content_digest_only",
    "host_outcome_unavailable",
    "semantic_case_content_over_item_limit",
    _SCOPE_REDUCED,
    "unpaired_event",
)


@pytest.mark.parametrize(
    "beyond_baseline",
    ["completion_plan_not_claimed", "redacted_object", "missing_ref"],
)
def test_a_lapsed_limit_beyond_the_baseline_makes_the_baseline_readable(
    beyond_baseline: str,
) -> None:
    """Secondary edge: the first later check without that limit saw at least as much."""

    raised_under = (
        *(gap for gap in _DRIZZLE_RAISED_UNDER if gap != "completion_plan_not_claimed"),
        beyond_baseline,
    )
    original = _semantic_finding(*raised_under)
    later = _review_check(*_DRIZZLE_LATER_REVIEW)
    assert _blockers(original, later, raised_under_reduced_scope=True) == ()
    # Post-upgrade the scope is stamped instead; the answer is the same.
    stamped = _semantic_finding(*raised_under, _SCOPE_REDUCED)
    assert _blockers(stamped, later) == ()
    # The interim still refuses a truncated payload.
    truncated = _review_check(*_DRIZZLE_LATER_REVIEW, "truncated_payload")
    assert _blockers(stamped, truncated) == ("coverage:truncated_payload",)

    # While the limitation is still present it keeps blocking, exactly as before.
    still = _review_check(*_DRIZZLE_LATER_REVIEW, beyond_baseline)
    assert _blockers(original, still, raised_under_reduced_scope=True) == tuple(
        "coverage:" + gap
        for gap in sorted(
            {*_DRIZZLE_LATER_REVIEW, beyond_baseline} - {"evidence_content_digest_only"}
        )
    )


def test_a_lapsed_limit_never_rehabilitates_unproven_original_freshness() -> None:
    original = replace(
        _semantic_finding(*_DRIZZLE_RAISED_UNDER),
        coverage=_coverage(
            gaps=_DRIZZLE_RAISED_UNDER, semantic=True, freshness=LedgerFreshness.REDACTED_GAP
        ),
    )
    later = _review_check(*_DRIZZLE_LATER_REVIEW)
    assert _blockers(original, later, raised_under_reduced_scope=True) == tuple(
        "coverage:" + gap for gap in _DRIZZLE_LATER_REVIEW if gap != "evidence_content_digest_only"
    )


@pytest.mark.parametrize(
    "gap",
    [
        "content_redacted",
        "event_payload_unavailable",
        "redacted_event",
        "redacted_object",
        "truncated_payload",
        "semantic_packet_insufficient",
        "semantic_review_context_withheld",
        "semantic_challenges_rejected",
    ],
)
def test_a_newly_appearing_real_limit_still_blocks_semantic_proof(gap: str) -> None:
    """Regression: the scope tolerance does not open the closed default (issue #904)."""

    original = _semantic_finding(*_LONG_SESSION_REVIEW_GAPS)
    later = _review_check(*_LONG_SESSION_REVIEW_GAPS, gap)
    blockers = _blockers(original, later, raised_under_reduced_scope=True)
    assert "coverage:" + gap in blockers
    assert "coverage:" + _SCOPE_REDUCED not in blockers
    assert _resolves(original, later) is False


def test_capture_failures_block_local_proof_too() -> None:
    """The interim tolerance is the selection code alone; truncation waits for its source test."""

    from finishup.kernel.finding_resolution import CAPTURE_FAILURE_GAPS

    for gap in sorted(CAPTURE_FAILURE_GAPS):
        later = _review_check(*_LONG_SESSION_REVIEW_GAPS, gap)
        assert _blockers(_finding(), later) == ("coverage:" + gap,), gap


def test_selection_and_capture_failure_classes_are_disjoint_and_closed() -> None:
    from finishup.application.check import SEMANTIC_CASE_CONTENT_GAPS
    from finishup.domain.receipts import SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP
    from finishup.kernel.finding_resolution import (
        CAPTURE_FAILURE_GAPS,
        REVIEW_SELECTION_GAPS,
        SEMANTIC_FINDING_CAPTURE_BASELINE_GAPS,
        SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP,
    )

    assert SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP == _SCOPE_REDUCED
    assert SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP in REVIEW_SELECTION_GAPS
    assert not REVIEW_SELECTION_GAPS & CAPTURE_FAILURE_GAPS
    assert REVIEW_SELECTION_GAPS <= SEMANTIC_FINDING_CAPTURE_BASELINE_GAPS
    assert not CAPTURE_FAILURE_GAPS & SEMANTIC_FINDING_CAPTURE_BASELINE_GAPS

    # Every code a review packet can fold into check coverage has a decided resolution class:
    # (blocks local proof, tolerated for semantic proof when unchanged from the finding's own
    # recorded baseline). A new packet code fails here until someone decides its row.
    decided = {
        "captured_object_unavailable": (False, True),
        "content_capture_unavailable": (True, True),
        "content_unselected": (False, True),
        # Capture-time redaction of a high-confidence secret shape (issue #982): local packs never
        # read the bytes it replaced, so it never vetoes local proof; for AI-powered proof it is a
        # recorded capture baseline like any other native capture limit.
        "content_redacted": (False, True),
        # Egress withholding of one item (issue #982): semantic-only, an AI-powered baseline.
        "semantic_review_item_withheld": (False, True),
        "truncated_payload": (True, False),
        "semantic_case_finding_refs_over_limit": (False, False),
        SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP: (False, True),
        SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP: (False, True),
        # A task-named outside input the owner has not admitted (issue #1102): AI-powered review
        # input only, so never a local veto; an AI-powered baseline like the task statement's.
        "task_input_outside_not_admitted": (False, True),
    }
    # Structural test-edit accounting (ADR-032, #961) is decided by kind rather than baseline: the
    # standing accounting limits bound only ``task_requirement_unmet``, while the actionable
    # unjustified-edit code blocks every proof until its decision is recorded.
    test_edit_accounting = {
        "preexisting_test_baseline_unknown",
        "preexisting_test_deleted",
        "preexisting_test_modified",
        "preexisting_test_renamed",
        "preexisting_test_skip_unknown",
        "preexisting_test_skipped",
    }
    test_edit_actionable = {"preexisting_test_edit_unjustified"}
    # In-place egress redaction of a credential-like value (issue #982, owner decision B2) bounds
    # only what the external model saw, and only the value: it weakens neither proof class.
    egress_value_redaction = {"semantic_review_value_redacted"}
    packet_codes = SEMANTIC_CASE_CONTENT_GAPS | {
        SEMANTIC_CASE_CONTENT_OVER_ITEM_LIMIT_GAP,
        SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP,
    }
    assert packet_codes == (
        set(decided) | test_edit_accounting | test_edit_actionable | egress_value_redaction
    )
    for code in sorted(egress_value_redaction):
        later = _review_check(code)
        assert _blockers(_finding(), later) == (), code
        assert _blockers(_semantic_finding(), later) == (), code
    requirement = replace(
        _test_edit_finding(),
        coverage=_coverage(semantic=True, freshness=LedgerFreshness.PARTIAL),
    )
    for code in sorted(test_edit_accounting):
        later = _review_check(code)
        assert _blockers(_finding(), later) == (), code
        assert _blockers(_semantic_finding(), later) == (), code
        # Only the test-edit finding is bounded, and only by an unknown edit baseline.
        expected = ("coverage:" + code,) if code == "preexisting_test_baseline_unknown" else ()
        assert _blockers(requirement, later) == expected, code
    for code in sorted(test_edit_actionable):
        later = _review_check(code)
        assert _blockers(_finding(), later) == ("coverage:" + code,), code
        assert _blockers(_semantic_finding(), later) == ("coverage:" + code,), code
    for code, (blocks_local, unchanged_tolerated) in decided.items():
        later = _review_check(code)
        assert bool(_blockers(_finding(), later)) is blocks_local, code
        assert (not _blockers(_semantic_finding(code), later)) is unchanged_tolerated, code
        assert _blockers(_semantic_finding(), later) == ("coverage:" + code,), code
        if code in REVIEW_SELECTION_GAPS:
            assert (blocks_local, unchanged_tolerated) == (False, True), code
        if code in CAPTURE_FAILURE_GAPS:
            assert (blocks_local, unchanged_tolerated) == (True, False), code


def _answered_state(
    check: CheckRecordedPayload, *, cites: str, redacted_evidence: bool = False
) -> ProjectionState:
    """``_changed_state`` plus repair evidence and a response to ``fnd(1)`` citing *cites*.

    The evidence ``evd(7)`` and the result ``res(7)``, which links it, are recorded after the
    finding and before the checked frontier; the response cites one of them.
    """

    from builders.policy_cases import evd, evidence_record, record, res
    from finishup.domain.events import (
        EvidenceKind,
        EvidenceRecordedPayload,
        ResponseRecordedPayload,
        ResultOutcome,
        ResultRecordedPayload,
    )
    from finishup.domain.findings import ResponseDisposition
    from finishup.domain.values import timestamp_from_string

    state = _changed_state(check)
    evidence = evidence_record(
        EvidenceRecordedPayload(
            evidence_id=evd(7),
            evidence_kind=EvidenceKind.TEST_RESULT,
            strength=EvidenceImmutability.METADATA_ONLY,
            observed_at=timestamp_from_string("2026-01-01T00:00:00.000Z"),
            reference="repair-test-log",
        ),
        6,
    )
    if redacted_evidence:
        evidence = replace(evidence, payload=None, redacted=True)
    result = record(
        ResultRecordedPayload(res(7), act(9), ResultOutcome.SUCCESS, 0, evidence_refs=(evd(7),)),
        7,
    )
    response = record(
        ResponseRecordedPayload(
            finding_id=fnd(1),
            finding_frontier=Frontier(4, _DIGEST),
            disposition=ResponseDisposition.ACKNOWLEDGED,
            evidence_refs=(cites,),  # type: ignore[arg-type]
        ),
        8,
    )
    return replace(
        state,
        frontier=max(state.frontier, 8),
        evidence={evd(7): evidence},
        results={res(7): result},
        responses={fnd(1): response},
    )


def test_a_reduced_review_without_the_repair_in_view_cannot_resolve_a_semantic_finding() -> None:
    """PR930-F1: the same reduced-scope code on a later review is not proof that it saw the repair.

    The finding was raised under a reduced scope, the agent made a material change, and a later
    completed review under the same bound did not return the issue. Nothing records that the later
    packet carried that change, so the scope code keeps blocking and stays on the receipt.
    """

    original = _semantic_finding(
        "content_unselected", "host_outcome_unavailable", _SCOPE_REDUCED, "unpaired_event"
    )
    omitted = ("finding_material_outside_reduced_review_scope", "coverage:" + _SCOPE_REDUCED)
    unrecorded = _review_check(*_LONG_SESSION_REVIEW_GAPS, included=None)
    assert _blockers(original, unrecorded) == omitted
    assert _resolves(original, unrecorded) is False
    # The lifecycle fallback supplies the baseline code, never the missing relevance proof.
    unstamped = _semantic_finding(
        "content_unselected", "host_outcome_unavailable", "unpaired_event"
    )
    assert _blockers(unstamped, unrecorded, raised_under_reduced_scope=True) == omitted

    # The recorded packet must carry the finding's subject and the change made after it.
    repair_omitted = _review_check(*_LONG_SESSION_REVIEW_GAPS, included=(obl(1), obl(2), fnd(1)))
    assert _blockers(original, repair_omitted) == omitted
    subject_omitted = _review_check(*_LONG_SESSION_REVIEW_GAPS, included=(act(9), fnd(1)))
    assert _blockers(original, subject_omitted) == omitted
    # The finding's own prior-finding row must have been sent (issue #947).
    row_omitted = _review_check(*_LONG_SESSION_REVIEW_GAPS, included=(obl(1), act(9)))
    assert _blockers(original, row_omitted) == omitted
    # The change may be named by its logical row or by the event that recorded it.
    by_event = _review_check(*_LONG_SESSION_REVIEW_GAPS, included=(obl(1), evt(5), fnd(1)))
    assert _blockers(original, by_event) == ()
    assert _blockers(original, _review_check(*_LONG_SESSION_REVIEW_GAPS)) == ()

    # Without a material change the missing repair is the only thing named.
    assert _blockers(original, unrecorded)  # sanity: still blocked
    from finishup.kernel.finding_resolution import resolution_blockers

    unchanged = replace(_changed_state(unrecorded), actions={})
    assert resolution_blockers(original, 4, unrecorded, frozenset(), proof_state=unchanged) == (
        "no_material_change_since_finding",
    )


@pytest.mark.parametrize("cites", ["evidence", "result"])
def test_a_reduced_review_must_carry_the_repair_evidence_the_response_links(cites: str) -> None:
    """Relevance includes the repair the agent answered with, not only the finding's subjects."""

    from builders.policy_cases import evd, res
    from finishup.kernel.finding_resolution import resolution_blockers

    original = _semantic_finding(
        "content_unselected", "host_outcome_unavailable", _SCOPE_REDUCED, "unpaired_event"
    )
    cited = evd(7) if cites == "evidence" else res(7)
    omitted = ("finding_material_outside_reduced_review_scope", "coverage:" + _SCOPE_REDUCED)

    def blockers(check: CheckRecordedPayload, **state: bool) -> tuple[str, ...]:
        answered = _answered_state(check, cites=cited, **state)
        return resolution_blockers(original, 4, check, frozenset(), proof_state=answered)

    # The subject and a change were in view, but not the linked repair evidence.
    assert blockers(_review_check(*_LONG_SESSION_REVIEW_GAPS)) == omitted
    with_repair = _review_check(*_LONG_SESSION_REVIEW_GAPS, included=(*_REPAIR_IN_VIEW, evd(7)))
    assert blockers(with_repair) == ()
    # Unreadable repair evidence cannot be shown to have been in view.
    assert blockers(with_repair, redacted_evidence=True) == omitted
    # An unreduced review saw the whole frontier and needs no record.
    unreduced = _review_check(*[gap for gap in _LONG_SESSION_REVIEW_GAPS if gap != _SCOPE_REDUCED])
    assert blockers(unreduced) == ()


def test_the_included_reference_record_is_bound_to_a_completed_reduced_review() -> None:
    from finishup.domain.events import EventSchema, decode_payload, encode_payload
    from finishup.protocol.errors import ProtocolValueError

    reduced = _review_check(*_LONG_SESSION_REVIEW_GAPS)
    assert reduced.semantic_included_refs == _in_view(*_REPAIR_IN_VIEW)
    encoded = encode_payload(reduced)
    assert decode_payload(EventSchema("check_recorded", "1.3.0"), encoded) == reduced
    unreduced = _review_check("content_unselected")
    assert "semantic_included_refs" not in encode_payload(unreduced)  # type: ignore[operator]
    for invalid in (
        {"semantic_included_refs": _in_view(*_REPAIR_IN_VIEW)[::-1]},  # not ASCII-sorted
        {"semantic_included_refs": ()},  # empty is not a record
        {"semantic_included_refs": ("free text",)},
        {"semantic_included_refs": _REPAIR_IN_VIEW, "semantic_conclusion": None},
    ):
        with pytest.raises(ProtocolValueError):
            replace(reduced, **invalid)  # type: ignore[arg-type]
    with pytest.raises(ProtocolValueError):
        replace(unreduced, semantic_included_refs=_in_view(*_REPAIR_IN_VIEW))


def test_an_unrecorded_sent_packet_is_disclosed_and_blocks_only_semantic_proof() -> None:
    """``semantic_included_refs_not_recorded`` limits the reduced review, never the local case."""

    from finishup.domain.events import SEMANTIC_INCLUDED_REFS_NOT_RECORDED_GAP

    later = _review_check(
        *_LONG_SESSION_REVIEW_GAPS, SEMANTIC_INCLUDED_REFS_NOT_RECORDED_GAP, included=None
    )
    assert _blockers(_finding(), later) == ()
    stamped = _semantic_finding(
        "content_unselected", "host_outcome_unavailable", _SCOPE_REDUCED, "unpaired_event"
    )
    assert _blockers(stamped, later) == (
        "finding_material_outside_reduced_review_scope",
        "coverage:" + SEMANTIC_INCLUDED_REFS_NOT_RECORDED_GAP,
        "coverage:" + _SCOPE_REDUCED,
    )


# Issue #947: a long session's repair evicts the finding's subjects from the bounded review
# packet. The recheck saw the finding's own row (its statement, subject list and the agent's
# answer), the repair and a change made after the finding; a subject is then accounted when it was
# sent (a record's carried content counts for the event that recorded it), was superseded by a sent
# claim, or is an action, result or evidence event older than every history row the packet carried
# and listed by ref in that sent row.
_LISTED = 8


def _evicted_state(
    *,
    extra_actions: dict[str, int] | None = None,
    claim_superseded: bool = True,
) -> ProjectionState:
    """A long session at frontier 14 whose finding ``fnd(1)`` (recorded at 5) has evicted subjects.

    Subjects: the action ``act(1)`` recorded by ``evt(2)`` (old), the evidence ``evd(3)`` recorded
    by ``evt(3)`` (old), and the claim ``clm(1)`` recorded by ``evt(4)``, which ``clm(2)`` at 12
    corrects when ``claim_superseded``. The repair after the finding: action ``act(9)``
    (``evt(10)``), evidence ``evd(7)`` (``evt(11)``), result ``res(7)`` (``evt(13)``) and a response
    citing ``evd(7)`` (``evt(14)``).
    """

    from builders.policy_cases import claim_record, evd, evidence_record, record, res
    from finishup.domain.events import (
        ActionKind,
        ActionRecordedPayload,
        ClaimKind,
        ClaimRecordedPayload,
        ClaimRecordedPayloadV1_1,
        EvidenceKind,
        EvidenceRecordedPayload,
        ResponseRecordedPayload,
        ResultOutcome,
        ResultRecordedPayload,
    )
    from finishup.domain.findings import ResponseDisposition
    from finishup.domain.values import timestamp_from_string

    observed = timestamp_from_string("2026-01-01T00:00:00.000Z")

    def evidence(number: int, at: int, reference: str) -> object:
        return evidence_record(
            EvidenceRecordedPayload(
                evd(number),
                EvidenceKind.TEST_RESULT,
                EvidenceImmutability.METADATA_ONLY,
                observed,
                reference=reference,
            ),
            at,
        )

    actions = {
        act(1): record(ActionRecordedPayload(act(1), ActionKind.EDIT, "First attempt"), 2),
        act(9): record(ActionRecordedPayload(act(9), ActionKind.EDIT, "Repair"), 10),
    }
    for name, at in (extra_actions or {}).items():
        number = int(name)
        actions[act(number)] = record(
            ActionRecordedPayload(act(number), ActionKind.EDIT, "Other"), at
        )
    claims = {
        clm(1): claim_record(
            ClaimRecordedPayload(clm(1), ClaimKind.COMPLETION, "Done", (evd(3),)),
            4,
            superseded_by_claim_id=clm(2) if claim_superseded else None,
        ),
    }
    if claim_superseded:
        claims[clm(2)] = claim_record(
            ClaimRecordedPayloadV1_1(
                clm(2),
                ClaimKind.COMPLETION,
                "Done, corrected",
                (evd(7),),
                supersedes_claim_refs=(clm(1),),
            ),
            12,
        )
    response = record(
        ResponseRecordedPayload(
            finding_id=fnd(1),
            finding_frontier=Frontier(4, _DIGEST),
            disposition=ResponseDisposition.ACKNOWLEDGED,
            evidence_refs=(evd(7),),
        ),
        14,
    )
    return replace(
        empty_projection_state(),
        frontier=14,
        head_digest=_DIGEST,
        actions=actions,
        evidence={evd(3): evidence(3, 3, "first-log"), evd(7): evidence(7, 11, "repair-log")},
        results={
            res(7): record(
                ResultRecordedPayload(
                    res(7), act(9), ResultOutcome.SUCCESS, 0, evidence_refs=(evd(7),)
                ),
                13,
            )
        },
        claims=claims,
        responses={fnd(1): response},
    )


# What the recheck sent: the finding's row, the old evidence excerpt, the corrected claim and the
# recent history window (the events at 10 to 14) with the records those rows carried.
def _evicted_sent() -> tuple[str, ...]:
    from builders.policy_cases import evd, res

    return (
        fnd(1), evd(3), clm(2), act(9), evd(7), res(7),
        evt(10), evt(11), evt(12), evt(13), evt(14),
    )  # fmt: skip


def _evicted_blockers(
    included: tuple[str, ...],
    *,
    subjects: tuple[object, ...] = (evt(2), evt(3), clm(1)),
    state: ProjectionState | None = None,
) -> tuple[str, ...]:
    from finishup.kernel.finding_resolution import resolution_blockers

    original = replace(
        _semantic_finding(
            "content_unselected", "host_outcome_unavailable", _SCOPE_REDUCED, "unpaired_event"
        ),
        subject_refs=tuple(sorted(subjects, key=lambda ref: str(ref).encode())),
    )
    check = _review_check(*_LONG_SESSION_REVIEW_GAPS, tested=14, included=included)
    return resolution_blockers(
        original, 5, check, frozenset(), proof_state=_evicted_state() if state is None else state
    )


_OUTSIDE_SCOPE = ("finding_material_outside_reduced_review_scope", "coverage:" + _SCOPE_REDUCED)


def test_a_repair_that_evicted_and_superseded_the_subjects_resolves_under_a_reduced_scope() -> None:
    """Issue #947: the goreleaser shape. No subject was re-sent, yet each one is accounted."""

    assert _evicted_blockers(_evicted_sent()) == ()


def test_the_finding_row_must_have_been_sent() -> None:
    sent = tuple(ref for ref in _evicted_sent() if ref != fnd(1))
    assert _evicted_blockers(sent) == _OUTSIDE_SCOPE


def test_an_evicted_subject_still_needs_the_linked_repair_in_the_packet() -> None:
    """PR930-F1 holds: the evicted-subject rule never excuses an omitted repair."""

    from builders.policy_cases import evd

    sent = tuple(ref for ref in _evicted_sent() if ref not in {evd(7), evt(11)})
    assert _evicted_blockers(sent) == _OUTSIDE_SCOPE


def test_a_post_finding_change_must_still_be_in_the_packet() -> None:
    """An evicted subject is excused only beside a change made after the finding (PR930-F1)."""

    from builders.policy_cases import evd

    unanswered = replace(_evicted_state(), responses={})
    # The packet carried the row and only material from before the finding.
    before = (fnd(1), evd(3), evt(3))
    assert _evicted_blockers(before, subjects=(evt(2),), state=unanswered) == _OUTSIDE_SCOPE
    assert _evicted_blockers((*before, evt(10)), subjects=(evt(2),), state=unanswered) == ()


def test_a_subject_neither_sent_superseded_nor_evicted_blocks() -> None:
    """An effective claim the packet left out is not accounted, however old."""

    state = _evicted_state(claim_superseded=False)
    sent = tuple(ref for ref in _evicted_sent() if ref not in {clm(2), evt(12)})
    assert _evicted_blockers(sent, state=state) == _OUTSIDE_SCOPE
    # With the claim itself sent, it is accounted.
    assert _evicted_blockers((*sent, clm(1)), state=state) == ()


def test_an_old_subject_inside_the_carried_window_is_not_excused() -> None:
    """A history row older than the subject was carried: the subject was left out, not evicted."""

    state = _evicted_state(extra_actions={"5": 1})
    assert _evicted_blockers((*_evicted_sent(), evt(1)), state=state) == _OUTSIDE_SCOPE
    # The same packet without that older row: the subject is older than every carried row.
    assert _evicted_blockers(_evicted_sent(), state=state) == ()


def test_an_evicted_subject_must_be_listed_by_the_sent_row() -> None:
    """The row lists at most eight subjects; one past that bound was never named to the reviewer."""

    # Subjects are ``evt_``, ``obl_`` or ``clm_`` refs, listed in ASCII order: ``clm_`` before
    # ``evt_``. Sent effective claims pad the list ahead of the evicted event.
    padding = tuple(clm(100 + number) for number in range(_LISTED))
    listed = (evt(2), *padding[: _LISTED - 1])
    sent = (*_evicted_sent(), *padding)
    assert _evicted_blockers(sent, subjects=listed) == ()
    unlisted = (*padding, evt(2))
    assert _evicted_blockers(sent, subjects=unlisted) == _OUTSIDE_SCOPE


def test_a_carried_record_credits_the_event_that_recorded_it() -> None:
    """Record-to-event aliasing: a carried ``evd_`` excerpt counts for its recording ``evt_``.

    Finding subjects are ``evt_``, ``obl_`` or ``clm_`` refs, so this is the direction a reviewer's
    citation needs; the reverse (a history row crediting its record) is recorded at check time.
    """

    from builders.policy_cases import evd

    # evt(3) is accounted only through its carried evidence record evd(3).
    without_excerpt = tuple(ref for ref in _evicted_sent() if ref != evd(3))
    # Without the excerpt, evt(3) at 3 is older than every carried history row.
    assert _evicted_blockers(without_excerpt, subjects=(evt(3),)) == ()
    # Carrying the old event's row puts it inside the window; it counts only if sent itself.
    assert _evicted_blockers((*without_excerpt, evt(2)), subjects=(evt(3),)) == _OUTSIDE_SCOPE
    assert _evicted_blockers((*without_excerpt, evt(2), evd(3)), subjects=(evt(3),)) == ()


def test_the_explanation_reads_the_newest_check_that_could_resolve_the_finding() -> None:
    """Issue #947: a later scoped check must not hide the blockers of the review that mattered."""

    from types import SimpleNamespace

    from finishup.domain.events import LedgerRecord
    from finishup.kernel.finding_resolution import finding_resolution_explanation

    finding = _finding()
    state = replace(
        empty_projection_state(),
        frontier=20,
        head_digest=_DIGEST,
        findings={fnd(1): finding_record(finding, 4)},
    )

    def row(sequence: int, check: CheckRecordedPayload) -> object:
        return SimpleNamespace(
            event_id=evt(sequence),
            schema=SimpleNamespace(name="check_recorded"),
            ledger=SimpleNamespace(ingestion_sequence=sequence),
            payload=check,
        )

    whole = _check(tested=6, coverage=_coverage(gaps=("truncated_payload",)))
    scoped = _check(tested=8, scope=CheckScopeModel(claim_ids=(), obligation_ids=(obl(2),)))
    records = cast(tuple[LedgerRecord, ...], (row(6, whole), row(8, scoped)))
    explanation = finding_resolution_explanation(state, fnd(1), records)
    assert f"in check {evt(6)} of subject frontier 6" in explanation
    assert "coverage:truncated_payload" in explanation
    assert "subject_outside_checked_scope" not in explanation
    assert f"Later check {evt(8)} did not run a completed matching review" in explanation

    # With no check able to resolve it, the newest check is explained as before.
    only_scoped = cast(tuple[LedgerRecord, ...], (row(8, scoped),))
    explanation = finding_resolution_explanation(state, fnd(1), only_scoped)
    assert f"in check {evt(8)}" in explanation
    assert "subject_outside_checked_scope" in explanation
    assert "Later check" not in explanation


_WORK_CURRENT = ("work-integrity", "0.3.0")
_RESEARCH_CURRENT = ("research-evidence", "0.2.0")


def _current_check(**overrides: object) -> CheckRecordedPayload:
    """A check the upgraded build records: every execution at the current pack versions."""

    check = _check(**overrides)  # type: ignore[arg-type]
    return replace(
        check,
        policies=(PolicyVersion(*_RESEARCH_CURRENT), PolicyVersion(*_WORK_CURRENT)),
        policy_executions=tuple(
            _execution(
                (
                    execution.policy_id,
                    _WORK_CURRENT[1]
                    if execution.policy_id == _WORK_CURRENT[0]
                    else _RESEARCH_CURRENT[1],
                ),
                execution.outcome,
                execution.reason,
            )
            for execution in check.policy_executions
        ),
    )


def test_a_finding_recorded_before_the_pack_upgrade_stays_resolvable() -> None:
    """A 0.1.0 finding is resolved by a later check that ran the same pack at 0.2.0."""

    assert _resolves(_finding(), _current_check()) is True


def test_a_newer_finding_is_never_resolved_by_an_older_pack_version() -> None:
    newer = replace(_finding(), policy_version="0.2.0")
    assert _resolves(newer, _check()) is False
    assert _resolves(newer, _current_check()) is True


def test_an_issue_re_raised_by_the_upgraded_pack_is_the_same_issue() -> None:
    """The issue key names the pack lineage, so a 0.2.0 re-raise refires the 0.1.0 row."""

    legacy = _finding()
    successor = replace(_finding(2), policy_version="0.2.0")
    assert issue_key(successor) == issue_key(legacy)
    keys = frozenset({issue_key(successor)})
    check = _current_check(returned=(fnd(2),))
    assert qualifying_check_resolves(legacy, 4, check, keys) is False


def test_a_check_mixing_pack_generations_is_not_a_recorded_selection() -> None:
    with pytest.raises(ValueError):
        replace(
            _check(),
            policies=(PolicyVersion(*_RESEARCH), PolicyVersion(*_WORK_CURRENT)),
            policy_executions=(
                _execution(_RESEARCH, "run", "completed"),
                _execution(_WORK_CURRENT, "run", "completed"),
            ),
        )


def test_an_unknown_pack_version_is_not_decodable() -> None:
    with pytest.raises(ValueError):
        PolicyVersion("work-integrity", "0.9.0")
    with pytest.raises(ValueError):
        PolicyVersion("coordination", "0.2.0")
    with pytest.raises(ValueError):
        replace(_finding(), policy_version="0.9.0")


def test_egress_item_withholding_bounds_only_the_ai_powered_review() -> None:
    """Issue #982 (owner decision B2, regression from 860811ed).

    Withholding one packet item from the external reviewer used to stamp ``content_redacted`` on
    the whole check, which made every local finding on the task unresolvable. The review-scoped
    code never vetoes local proof, and for AI-powered proof it is a recorded baseline only.
    """

    from finishup.domain.receipts import SEMANTIC_REVIEW_ITEM_WITHHELD_GAP

    later = _review_check(SEMANTIC_REVIEW_ITEM_WITHHELD_GAP)
    assert _blockers(_finding(), later) == ()
    assert _blockers(_semantic_finding(), later) == (
        "coverage:" + SEMANTIC_REVIEW_ITEM_WITHHELD_GAP,
    )
    assert _blockers(_semantic_finding(SEMANTIC_REVIEW_ITEM_WITHHELD_GAP), later) == ()


def test_a_retired_capture_handoff_never_vetoes_deterministic_proof() -> None:
    """#1019 (tb4n2 N-4): the retirement disclosure stays on the check, the repair still proves.

    For AI-powered findings it is a capture baseline like the other host-capture gaps: tolerated
    only when the raising review ran under it too.
    """

    from finishup.kernel.closure_readiness import GAP_CLASSIFICATION, GapClass
    from finishup.kernel.deterministic_scope import CLEAN_COMPATIBLE_GAPS
    from finishup.kernel.finding_resolution import (
        DETERMINISTIC_PROOF_TOLERATED_GAPS,
        SEMANTIC_FINDING_CAPTURE_BASELINE_GAPS,
    )

    gap = "capture_handoff_retired"
    assert GAP_CLASSIFICATION[gap] is GapClass.STANDING_LIMITATION
    assert gap in DETERMINISTIC_PROOF_TOLERATED_GAPS
    assert gap in CLEAN_COMPATIBLE_GAPS
    assert gap in SEMANTIC_FINDING_CAPTURE_BASELINE_GAPS
    coverage = _coverage(gaps=(gap, "semantic_review_not_requested"))
    assert _resolves(_finding(), _check(coverage=coverage)) is True
    research_finding = _finding(
        kind=FindingKind.MATERIAL_LIMITATION_OMITTED,
        subject_refs=(clm(1),),
        policy_id="research-evidence",
    )
    assert _resolves(research_finding, _check(coverage=coverage)) is True


def test_an_unresolved_verification_limit_never_vetoes_deterministic_proof() -> None:
    """#1079 F2 (ADR-033): the derived limit bounds the receipt, never a repaired local finding.

    A resolved obligation with only the agent's own evidence carries it on every later check. A
    repaired local finding must still prove absent there, or the limit would reopen the finding
    and reblock Stop; the receipt stays bounded by the same code.
    """

    from finishup.domain.receipts import UNRESOLVED_VERIFICATION_GAP
    from finishup.kernel.deterministic_scope import CLEAN_COMPATIBLE_GAPS
    from finishup.kernel.finding_resolution import DETERMINISTIC_PROOF_TOLERATED_GAPS
    from finishup.kernel.gap_effect import gap_effect

    gap = UNRESOLVED_VERIFICATION_GAP
    assert gap in DETERMINISTIC_PROOF_TOLERATED_GAPS
    assert gap not in CLEAN_COMPATIBLE_GAPS
    assert gap_effect(gap).kind.bounds
    coverage = _coverage(gaps=(gap, "semantic_review_not_requested"))
    assert _blockers(_finding(), _check(coverage=coverage)) == ()
    assert _resolves(_finding(), _check(coverage=coverage)) is True


def test_an_unresolved_verification_limit_never_vetoes_a_repaired_ai_powered_finding() -> None:
    """#1079 F2 (ADR-033): a later review that no longer returns the finding resolves it.

    The limit says nothing about what the reviewer was shown, whether or not the finding was raised
    under it; the receipt stays bounded by the same code.
    """

    from finishup.domain.receipts import UNRESOLVED_VERIFICATION_GAP
    from finishup.kernel.deterministic_scope import CLEAN_COMPATIBLE_GAPS

    gap = UNRESOLVED_VERIFICATION_GAP
    assert gap not in CLEAN_COMPATIBLE_GAPS
    finding = _finding(origin=FindingOrigin.SEMANTIC_MODEL_DERIVED)
    later = _check(semantic=_SEMANTIC_OK, coverage=_coverage(gaps=(gap,), semantic=True))
    assert _blockers(finding, later) == ()
    assert _resolves(finding, later) is True
    raised_under = replace(finding, coverage=_coverage(gaps=(gap,), semantic=True))
    assert _blockers(raised_under, later) == ()
    assert _resolves(raised_under, later) is True
