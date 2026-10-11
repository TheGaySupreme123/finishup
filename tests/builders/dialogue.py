"""Builders for the tb4n3 finding-dialogue tests (issues #1024 and #1030).

Small, explicit constructors for the shapes the recorded tb4n3 runs produced: a reviewer finding
with its challenge, the agent's reasoned answers, a ``yoetz-verification-limit`` decision and a
projection holding them. Nothing here reads a ledger; the reducer-level tests build real ones with
``builders.observed_runs.ObservedLedger``.
"""

from __future__ import annotations

from dataclasses import replace
from types import MappingProxyType

from builders.policy_cases import (
    BASE_COVERAGE,
    FRONTIER,
    claim_record,
    evt,
    finding_record,
    fnd,
    obl,
    obligation_record,
    record,
)
from yoetz.domain.events import (
    CheckMode,
    CheckRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    DecisionRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PolicyVersion,
    ResponseRecordedPayload,
    encode_payload,
)
from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    CheckVerdict,
    Finding,
    FindingChallenge,
    FindingKind,
    FindingOrigin,
    PriorFindingVerdictRecord,
    ResponseDisposition,
    SamplingParams,
    SemanticDispatchKind,
    SemanticProvenance,
    finding_policy_identity,
)
from yoetz.domain.values import ClaimId, EventId, FindingId, Frontier, ObligationId, actor_id
from yoetz.kernel.projections import (
    DecisionProjectionRecord,
    FindingProjectionRecord,
    ProjectionRecord,
    ProjectionState,
    empty_projection_state,
)
from yoetz.protocol.canonical import canonical_digest
from yoetz.protocol.coverage import CheckType, LedgerFreshness
from yoetz.protocol.models import (
    CheckPolicyExecutionModel,
    CheckScopeModel,
    SemanticReason,
    SemanticStatus,
)

_DIGEST = "sha256:" + "5" * 64
LIMITATION = "state_unresolved_limitation"


def provenance() -> SemanticProvenance:
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


def reviewer_finding(
    number: int,
    *subjects: str,
    kind: FindingKind = FindingKind.TASK_REQUIREMENT_UNMET,
    next_step: str = "act",
    summary: str = "The required reference comparison is not established",
) -> Finding:
    """An AI-powered finding with its recorded challenge (``requested_next_step``)."""

    policy_id, policy_version = finding_policy_identity(kind)
    coverage = replace(
        BASE_COVERAGE, check_types=(CheckType.DETERMINISTIC, CheckType.SEMANTIC_MODEL_DERIVED)
    )
    return Finding(
        finding_id=fnd(number),
        kind=kind,
        origin=FindingOrigin.SEMANTIC_MODEL_DERIVED,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary=summary,
        detail="Main agent: address the requirement or state the limitation.",
        subject_refs=tuple(sorted(subjects)),  # type: ignore[arg-type]
        policy_id=policy_id,
        policy_version=policy_version,
        subject_frontier=FRONTIER,
        coverage=coverage,
        provenance=provenance(),
        challenge=FindingChallenge(
            discrepancy="The packet shows no comparison against the reference.",
            alternative_interpretation="The reference may be withheld by the task design.",
            requested_next_step=next_step,
            uncertainty="Only the withheld reference would settle it.",
        ),
    )


def answer(
    number: int,
    disposition: ResponseDisposition,
    sequence: int,
    *,
    reason: str | None = "Cannot be verified here: the reference is withheld by the task design.",
    evidence: tuple[object, ...] = (),
) -> ProjectionRecord[ResponseRecordedPayload]:
    needs_reason = disposition in {
        ResponseDisposition.ACKNOWLEDGED_NOT_DONE,
        ResponseDisposition.REJECTED,
        ResponseDisposition.REOPENED,
        ResponseDisposition.SELF_VERIFIED,
    }
    return record(
        ResponseRecordedPayload(
            finding_id=fnd(number),
            finding_frontier=FRONTIER,
            disposition=disposition,
            reason=reason if reason is not None or needs_reason else None,
            evidence_refs=evidence,  # type: ignore[arg-type]
        ),
        sequence,
    )


def limit_decision(
    number: int, obligation: ObligationId, kind: str = "yoetz-verification-limit"
) -> DecisionProjectionRecord:
    payload = DecisionRecordedPayload(
        statement=f"Cannot be verified here.\n{kind}:{obligation}",
        rationale="The reference is withheld by the task design.",
        authority=actor_id("agt_codex"),
    )
    return DecisionProjectionRecord(
        payload=payload,
        payload_digest=canonical_digest(encode_payload(payload)),
        redacted=False,
        source_event_id=evt(number),
        source_frontier=number,
    )


def obligation_row(number: int, sequence: int = 2, *, source: EventId | None = None):
    payload = ObligationPublishedPayload(
        obl(number),
        f"Obligation {number}",
        "criteria",
        ObligationStatus.OPEN,
        source_refs=() if source is None else (source,),
    )
    return obligation_record(payload, sequence)


def claim_row(number: int, sequence: int, *obligations: ObligationId):
    from builders.policy_cases import clm

    payload = ClaimRecordedPayload(
        clm(number), ClaimKind.COMPLETION, "done", (), obligation_refs=tuple(obligations)
    )
    return claim_record(payload, sequence)


def projection(
    findings: dict[FindingId, FindingProjectionRecord] | None = None,
    responses: dict[FindingId, ProjectionRecord[ResponseRecordedPayload]] | None = None,
    *,
    obligations: dict[ObligationId, object] | None = None,
    decisions: dict[EventId, DecisionProjectionRecord] | None = None,
    claims: dict[ClaimId, object] | None = None,
    frontier: int = 40,
) -> ProjectionState:
    return replace(
        empty_projection_state(),
        frontier=frontier,
        head_digest=_DIGEST,
        findings=MappingProxyType(findings or {}),
        responses=MappingProxyType(responses or {}),
        obligations=MappingProxyType(obligations or {}),  # type: ignore[arg-type]
        decisions=MappingProxyType(decisions or {}),
        claims=MappingProxyType(claims or {}),  # type: ignore[arg-type]
        freshness=LedgerFreshness.CURRENT,
    )


def local_finding(
    number: int, *subjects: str, kind: FindingKind = FindingKind.ACTION_WITHOUT_RESULT
) -> Finding:
    """A deterministic (local) finding, as the work-integrity pack raises it."""

    return Finding(
        finding_id=fnd(number),
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=FINDING_KIND_TRAITS[kind][0],
        summary="A recorded action has no linked result.",
        detail="Record the result or state the attempt as unresolved.",
        subject_refs=tuple(sorted(subjects or (str(evt(number)),))),  # type: ignore[arg-type]
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=FRONTIER,
        coverage=BASE_COVERAGE,
        provenance=None,
    )


def ruling_check(
    *,
    tested: int = 8,
    returned: tuple[object, ...] = (),
    rulings: tuple[tuple[int, str], ...] = (),
    cited: dict[int, tuple[str, ...]] | None = None,
    qualifying: bool = False,
) -> CheckRecordedPayload:
    """A recorded check carrying only the fields the resolution and ruling folds read.

    ``qualifying`` leaves nothing suppressed, so ``apply_check_resolution`` may prove findings
    absent; otherwise one suppressed finding keeps it from proving anything.
    """

    payload = object.__new__(CheckRecordedPayload)
    for name, value in (
        ("mode", CheckMode.DETERMINISTIC_ONLY),
        ("policies", (PolicyVersion("work-integrity", "0.1.0"),)),
        ("scope", CheckScopeModel(claim_ids=(), obligation_ids=())),
        (
            "policy_executions",
            (
                CheckPolicyExecutionModel(
                    policy_id="work-integrity",
                    policy_version="0.1.0",
                    outcome="run",
                    reason="completed",
                ),
            ),
        ),
        ("subject_frontier", Frontier(tested, _DIGEST)),
        ("verdict", CheckVerdict.ACTION_REQUIRED if returned else CheckVerdict.NO_ISSUE_DETECTED),
        ("returned_finding_ids", returned),
        ("suppressed_count", 0 if qualifying else 1),
        ("coverage", BASE_COVERAGE),
        ("semantic_status", SemanticStatus.NOT_REQUESTED),
        ("semantic_reason", SemanticReason.DETERMINISTIC_MODE),
        ("engine_version", "0.1.0"),
        ("projection_version", "yoetz/0.1.0"),
        ("semantic_provenance", None),
        ("semantic_conclusion", None),
        (
            "prior_finding_verdicts",
            tuple(
                PriorFindingVerdictRecord(
                    fnd(number),
                    verdict,
                    tuple(sorted((cited or {}).get(number, ()), key=str.encode)),
                )
                for number, verdict in rulings
            ),
        ),
    ):
        object.__setattr__(payload, name, value)
    return payload


__all__ = [
    "LIMITATION",
    "answer",
    "local_finding",
    "ruling_check",
    "claim_row",
    "finding_record",
    "limit_decision",
    "obligation_row",
    "projection",
    "provenance",
    "reviewer_finding",
]
