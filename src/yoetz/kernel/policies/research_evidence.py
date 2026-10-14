"""Local research-evidence policy pack."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final, cast

from yoetz.domain.events import (
    ClaimKind,
    ObligationChangeKind,
    ObligationStatus,
    ResponseDisposition,
    ResultOutcome,
)
from yoetz.domain.findings import FindingKind, FindingOrigin
from yoetz.domain.values import (
    EvidenceId,
    ObligationId,
    ResultId,
    SubjectStateRef,
    SubjectStateRelation,
    subject_state_relation,
)
from yoetz.kernel.claims import (
    claim_discloses_result,
    effective_claim_items,
    result_is_relevant_to_claim,
)
from yoetz.kernel.deterministic_checks import (
    DeterministicAssessment,
    DeterministicCase,
    FindingBasisRef,
    FindingFact,
    FrozenSourceAvailability,
    PolicyPack,
    build_policy_assessment,
    policy_public_root,
    policy_source_availability,
)
from yoetz.kernel.observed_failures import (
    ObservedFailureState,
    observed_action_is_exploratory,
    observed_event_ids_from_coverage,
    observed_failure_states,
)
from yoetz.kernel.outcome_corrections import superseded_unknown_results
from yoetz.kernel.policies.response_support import (
    BASE_RESPONSE_INADMISSIBLE_GAPS,
    RESEARCH_REJECTION_PRESENT_FACT,
    response_support_admissible,
)
from yoetz.kernel.projections import ClaimProjectionRecord
from yoetz.protocol.coverage import PublicationChannel
from yoetz.protocol.policy_packs import (
    RESEARCH_EVIDENCE_POLICY_ID,
    RESEARCH_EVIDENCE_POLICY_VERSION,
)

__all__ = [
    "RESEARCH_EVIDENCE_FACT_CODES",
    "RESEARCH_EVIDENCE_POLICY_ID",
    "RESEARCH_EVIDENCE_POLICY_PACK",
    "RESEARCH_EVIDENCE_POLICY_VERSION",
    "research_evidence_findings",
]

RESEARCH_EVIDENCE_POLICY_PACK: Final = PolicyPack(
    RESEARCH_EVIDENCE_POLICY_ID,
    RESEARCH_EVIDENCE_POLICY_VERSION,
)
RESEARCH_EVIDENCE_FACT_CODES: Final = frozenset(
    {
        "claim_support_present",
        "claim_support_mismatch",
        "captured_state_present",
        "account_state_mismatch",
        "material_limitation_present",
        "limitation_disclosure_absent",
        "finding_rejection_present",
        "rejection_basis_insufficient",
    }
)

_RULE_ORDER: Final = (
    FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
    FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT,
    FindingKind.MATERIAL_LIMITATION_OMITTED,
    FindingKind.QUESTIONABLE_FINDING_REJECTION,
)
_MATERIAL_GAPS: Final = BASE_RESPONSE_INADMISSIBLE_GAPS
_HOST_OUTCOME_UNAVAILABLE_GAP: Final = "host_outcome_unavailable"


def _ascii(value: str) -> bytes:
    return value.encode("ascii", errors="strict")


def _refs(values: Iterable[FindingBasisRef]) -> tuple[FindingBasisRef, ...]:
    return tuple(sorted(set(values), key=_ascii))


def _fact(code: str, *refs: FindingBasisRef) -> FindingFact:
    return FindingFact(code, _refs(refs))


def _support_state(case: DeterministicCase, ref: FindingBasisRef) -> SubjectStateRef | None:
    if ref.startswith("evd_"):
        record = case.projection.evidence.get(EvidenceId(ref))
        return None if record is None or record.payload is None else record.payload.subject_state
    if ref.startswith("res_"):
        record = case.projection.results.get(ResultId(ref))
        return None if record is None or record.payload is None else record.payload.subject_state
    return None


def _typed_support_mismatch(
    case: DeterministicCase,
    claim_kind: ClaimKind,
    claim_state: SubjectStateRef | None,
    ref: FindingBasisRef,
) -> tuple[bool, SubjectStateRelation]:
    if ref not in case.allowed_ids:
        return False, SubjectStateRelation.UNKNOWN
    relation = subject_state_relation(_support_state(case, ref), claim_state)
    if relation is SubjectStateRelation.DIFFERENT:
        return True, relation
    # A failure/partial result cited on supporting_refs is limitation disclosure, not a
    # support mismatch (#429). Outcome-less UNKNOWN remains a mismatch: exempting the
    # finding storm never upgrades that record into completion support (#350).
    if ref.startswith("res_"):
        record = case.projection.results.get(ResultId(ref))
        if (
            record is not None
            and record.payload is not None
            and claim_kind is ClaimKind.COMPLETION
            and record.payload.outcome is ResultOutcome.UNKNOWN
        ):
            return True, relation
    if ref.startswith("obl_"):
        record = case.projection.obligations.get(ObligationId(ref))
        if (
            record is not None
            and record.payload is not None
            and claim_kind is ClaimKind.COMPLETION
            # acknowledged_not_done (#1002) is not resolved: treated like open here.
            and record.payload.status is not ObligationStatus.RESOLVED
            and record.plan_change is not ObligationChangeKind.WAIVED
        ):
            return True, relation
    return False, relation


def _exact_state_mismatch(
    left: SubjectStateRef | None,
    right: SubjectStateRef | None,
) -> bool:
    if left is None or right is None:
        return False
    if left.tree_digest is not None and right.tree_digest is not None:
        return left.tree_digest != right.tree_digest
    if left.diff_digest is not None and right.diff_digest is not None:
        return left.diff_digest != right.diff_digest
    return False


def _response_support_admissible(
    case: DeterministicCase,
    refs: tuple[EvidenceId | ResultId, ...],
) -> bool:
    return response_support_admissible(
        case,
        refs,
        inadmissible_gaps=_MATERIAL_GAPS,
    )


def _support_mismatch_findings(case: DeterministicCase) -> list[DeterministicAssessment]:
    output: list[DeterministicAssessment] = []
    for claim_id, record in effective_claim_items(case.projection):
        claim = record.payload
        if claim is None:
            continue
        for raw_ref in claim.supporting_refs:
            ref = cast(FindingBasisRef, raw_ref)
            mismatch, relation = _typed_support_mismatch(
                case,
                claim.claim_kind,
                claim.subject_state,
                ref,
            )
            if not mismatch:
                continue
            fact_refs = _refs((claim_id, ref))
            output.append(
                build_policy_assessment(
                    case,
                    RESEARCH_EVIDENCE_POLICY_PACK,
                    FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
                    _refs((claim_id, policy_public_root(case, ref))),
                    (FindingFact("claim_support_present", fact_refs),),
                    (FindingFact("claim_support_mismatch", fact_refs),),
                    subject_state_relation=relation,
                    source_availability=policy_source_availability(case, fact_refs),
                )
            )
    return output


def _diff_mismatch_findings(case: DeterministicCase) -> list[DeterministicAssessment]:
    output: list[DeterministicAssessment] = []
    for claim_id, record in effective_claim_items(case.projection):
        claim = record.payload
        if claim is None or claim.subject_state is None:
            continue
        for raw_ref in claim.supporting_refs:
            ref = cast(FindingBasisRef, raw_ref)
            state = _support_state(case, ref)
            if not _exact_state_mismatch(state, claim.subject_state):
                continue
            fact_refs = _refs((claim_id, ref))
            output.append(
                build_policy_assessment(
                    case,
                    RESEARCH_EVIDENCE_POLICY_PACK,
                    FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT,
                    _refs((claim_id, policy_public_root(case, ref))),
                    (
                        FindingFact("captured_state_present", fact_refs),
                        FindingFact("account_state_mismatch", fact_refs),
                    ),
                    subject_state_relation=SubjectStateRelation.DIFFERENT,
                    source_availability=policy_source_availability(case, fact_refs),
                )
            )
    return output


def _observation_outcome_unavailable(case: DeterministicCase, ref: FindingBasisRef) -> bool:
    """One host capability limitation, not one omission per observed call (#350).

    The narrowing is provenance- and cause-aware: it applies only to results the
    service itself materialized from harness observation — their source-event
    coverage carries the ``hook_observed`` publication channel, which ADR-022
    decision 2 keeps service-derived and unselectable by cooperative requests —
    and only when the host stated no outcome at all (``UNKNOWN`` with no exit
    status). Such records name the standing ``host_outcome_unavailable``
    coverage condition that check coverage and the receipt already carry, so
    excluding them here bounds the finding set without hiding the limitation.
    A cooperative result with an ``UNKNOWN`` outcome remains individually
    limiting, and explicit ``FAILURE``/``PARTIAL`` observations are unaffected.
    """

    record = case.projection.results.get(ResultId(ref))
    if record is None or record.payload is None:
        return False
    if record.payload.outcome is not ResultOutcome.UNKNOWN:
        return False
    if record.payload.exit_status is not None:
        return False
    coverage = case.coverage_by_ref.get(ref)
    # Only newly materialized rows carry the explicit capability gap. Historical
    # rows have the same outcome/channel shape but no durable cause marker, so
    # retaining the old limiting finding is the only honest compatibility path.
    return (
        coverage is not None
        and _HOST_OUTCOME_UNAVAILABLE_GAP in coverage.known_gaps
        and PublicationChannel.HOOK_OBSERVED in set(coverage.publication_channels)
    )


def _limiting_refs(
    case: DeterministicCase,
    claim_record: ClaimProjectionRecord,
) -> tuple[FindingBasisRef, ...]:
    if claim_record.payload is None:
        return ()
    limitations: set[FindingBasisRef] = set()
    observed = observed_event_ids_from_coverage(case.coverage_by_ref)
    # The same reading work integrity applies (#909): an observed failure that a later passing run
    # of its command superseded no longer limits this claim. A completed edit alone does not prove
    # a covering rerun, so the failed result remains a limitation until it is rerun or disclosed.
    observed_states = observed_failure_states(
        case.projection,
        observed,
        through=claim_record.source_frontier,
    )
    # An unknown hook result whose outcome the host's stream later recorded for the same action
    # is not a separate limitation: the corrected result stands for the call (#1001).
    superseded = superseded_unknown_results(case.projection.results, include=observed.__contains__)
    for result_id, record in case.projection.results.items():
        if result_id in superseded:
            continue
        action = (
            None
            if record.payload is None
            else case.projection.actions.get(record.payload.action_id)
        )
        if (
            action is not None
            and action.payload is not None
            and action.source_event_id in observed
            and observed_action_is_exploratory(action.payload)
        ):
            continue
        if (
            record.payload is not None
            and record.payload.outcome
            in {
                ResultOutcome.FAILURE,
                ResultOutcome.PARTIAL,
                ResultOutcome.UNKNOWN,
            }
            and not _observation_outcome_unavailable(case, result_id)
            and observed_states.get(result_id, ObservedFailureState.LIVE)
            is ObservedFailureState.LIVE
            and result_is_relevant_to_claim(case.projection, claim_record, result_id)
        ):
            limitations.add(result_id)
    # A material coverage gap on an obligation, result, or evidence record is a task-level
    # honesty fact about the recorded account, not a claim-scoped result relevance question.
    # ADR-025 bounds which *results* a claim must disclose; it does not bound this scan, and
    # restricting it to refs the claim already links made uncited evidence with a material gap
    # (for example a redacted object) stop producing MATERIAL_LIMITATION_OMITTED entirely.
    for ref, coverage in case.coverage_by_ref.items():
        if ref.startswith(("obl_", "res_", "evd_")) and _MATERIAL_GAPS & set(coverage.known_gaps):
            limitations.add(ref)
    return _refs(limitations)


def _limitation_findings(case: DeterministicCase) -> list[DeterministicAssessment]:
    output: list[DeterministicAssessment] = []
    rootless_material_gap = any(
        not gap.subject_refs and gap.code in _MATERIAL_GAPS for gap in case.gaps
    )
    for claim_id, record in effective_claim_items(case.projection):
        claim = record.payload
        if claim is None or claim.claim_kind is not ClaimKind.COMPLETION:
            continue
        limiting = _limiting_refs(case, record)
        for limiting_ref in limiting:
            if limiting_ref.startswith("res_") and claim_discloses_result(
                claim, ResultId(limiting_ref)
            ):
                continue
            if not limiting_ref.startswith("res_") and limiting_ref in claim.supporting_refs:
                continue
            fact_refs = _refs((claim_id, limiting_ref))
            output.append(
                build_policy_assessment(
                    case,
                    RESEARCH_EVIDENCE_POLICY_PACK,
                    FindingKind.MATERIAL_LIMITATION_OMITTED,
                    _refs((claim_id, policy_public_root(case, limiting_ref))),
                    (FindingFact("material_limitation_present", fact_refs),),
                    (FindingFact("limitation_disclosure_absent", fact_refs),),
                    source_availability=policy_source_availability(case, (limiting_ref,)),
                )
            )
        if rootless_material_gap:
            output.append(
                build_policy_assessment(
                    case,
                    RESEARCH_EVIDENCE_POLICY_PACK,
                    FindingKind.MATERIAL_LIMITATION_OMITTED,
                    (claim_id,),
                    (_fact("material_limitation_present", claim_id),),
                    (_fact("limitation_disclosure_absent", claim_id),),
                    source_availability=FrozenSourceAvailability.NOT_RECORDED,
                )
            )
    return output


def _rejection_findings(case: DeterministicCase) -> list[DeterministicAssessment]:
    output: list[DeterministicAssessment] = []
    for finding_id, response_record in case.projection.responses.items():
        response = response_record.payload
        finding_record = case.projection.findings.get(finding_id)
        if (
            response is None
            # A provenance dispute contests the finding's authorship/premise. It is not an
            # evidence-free rejection of the finding's conclusion and is not scored here.
            or response.disposition
            not in {ResponseDisposition.REJECTED, ResponseDisposition.WAIVED}
            or finding_record is None
            or finding_record.payload is None
            or finding_record.payload.origin is not FindingOrigin.DETERMINISTIC
            or _response_support_admissible(case, response.evidence_refs)
        ):
            continue
        finding = finding_record.payload
        # The response must answer the finding at or after the subject the check tested; a response
        # aimed at an older state is a different, weaker claim that work integrity reports instead.
        if response.finding_frontier.sequence < finding.subject_frontier.sequence or any(
            ref not in case.allowed_ids for ref in finding.subject_refs
        ):
            continue
        response_event = response_record.source_event_id
        evidence_refs = tuple(ref for ref in response.evidence_refs if ref in case.allowed_ids)
        present_refs = _refs((finding_id, response_event, *evidence_refs))
        compared = _refs(evidence_refs)
        output.append(
            build_policy_assessment(
                case,
                RESEARCH_EVIDENCE_POLICY_PACK,
                FindingKind.QUESTIONABLE_FINDING_REJECTION,
                finding.subject_refs,
                (FindingFact(RESEARCH_REJECTION_PRESENT_FACT, present_refs),),
                (_fact("rejection_basis_insufficient", finding_id, response_event),),
                source_availability=(
                    policy_source_availability(case, compared)
                    if compared
                    else FrozenSourceAvailability.AVAILABLE
                ),
            )
        )
    return output


def research_evidence_findings(
    case: DeterministicCase,
) -> tuple[DeterministicAssessment, ...]:
    """Evaluate the closed research-evidence rule table without I/O."""

    if type(case) is not DeterministicCase:
        raise ValueError("policy_wiring_invalid")
    by_rule = (
        _support_mismatch_findings(case),
        _diff_mismatch_findings(case),
        _limitation_findings(case),
        _rejection_findings(case),
    )
    if len(by_rule) != len(_RULE_ORDER):
        raise ValueError("policy_wiring_invalid")
    output: list[DeterministicAssessment] = []
    for kind, assessments in zip(_RULE_ORDER, by_rule, strict=True):
        deduped: dict[tuple[str, ...], DeterministicAssessment] = {}
        for assessment in assessments:
            if assessment.candidate.kind is not kind:
                raise ValueError("policy_wiring_invalid")
            key = tuple(assessment.candidate.subject_refs)
            if key in deduped:
                if deduped[key] != assessment:
                    raise ValueError("policy_wiring_invalid")
                continue
            deduped[key] = assessment
        output.extend(
            deduped[key]
            for key in sorted(deduped, key=lambda refs: tuple(_ascii(ref) for ref in refs))
        )
    return tuple(output)
