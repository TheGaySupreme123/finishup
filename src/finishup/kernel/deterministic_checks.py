"""Pure local case construction and versioned policy dispatch."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import Enum
from types import MappingProxyType
from typing import Final, Literal, cast

from finishup.domain.events import (
    MAX_REF_LIST,
    AcceptedEvent,
    ClaimKind,
    ClaimRecordedPayloadV1_1,
    EventSchema,
    EvidenceContentAvailability,
    LedgerRecord,
    RedactionState,
    UnknownEvent,
    decode_payload,
    encode_payload,
    is_observation_authored,
)
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    CandidateFinding,
    FindingKind,
    FindingOrigin,
)
from finishup.domain.receipts import (
    COMPLETION_SCOPE_DECLARED_NONE_GAP,
    COMPLETION_SCOPE_UNDECLARED_GAP,
)
from finishup.domain.task_statement import (
    NO_MATERIAL_WORK_MARKER,
    TASK_STATEMENT_SCOPE_EMPTY_SUMMARY,
    TASK_STATEMENT_UNMAPPED_SUMMARY,
    RecordedTaskStatement,
    current_task_statement,
    recorded_task_title,
)
from finishup.domain.values import (
    ActionId,
    ClaimId,
    EventId,
    EvidenceId,
    FindingId,
    Frontier,
    ObjectId,
    ObligationId,
    ResultId,
    SubjectStateRelation,
    action_id,
    claim_id,
    event_id,
    evidence_id,
    finding_id,
    freeze_json,
    frontier_from_json,
    object_id,
    obligation_id,
    occurred_at_consistency,
    result_id,
    timestamp_from_string,
    validate_sha256_digest,
)
from finishup.kernel.claims import effective_claim_items
from finishup.kernel.completion_scope import completion_scope_codes
from finishup.kernel.outcome_corrections import (
    HOST_OUTCOME_UNAVAILABLE_GAP,
    superseded_unknown_results,
)
from finishup.kernel.plan_drift import plan_drift_signals
from finishup.kernel.plan_scope import current_plan_scope
from finishup.kernel.projections import (
    ProjectionRecord,
    ProjectionState,
    projection_from_snapshot,
    projection_snapshot,
)
from finishup.kernel.reducers import (
    ReplayIndex,
    build_replay_index,
    replay,
    validate_replay_index,
)
from finishup.kernel.verification_freshness import VerificationFreshness
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.coverage import (
    EVIDENCE_IMMUTABILITY_ORDER,
    LEDGER_FRESHNESS_ORDER,
    ArtifactObservation,
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
from finishup.protocol.policy_packs import (
    RESEARCH_EVIDENCE_POLICY_ID,
    RESEARCH_EVIDENCE_POLICY_VERSION,
    WORK_INTEGRITY_POLICY_ID,
    WORK_INTEGRITY_POLICY_VERSION,
)

__all__ = [
    "CALLER_DIGEST_PROVENANCE_GAPS",
    "DETERMINISTIC_FINDING_TEMPLATES",
    "DETERMINISTIC_TEXT_CONTRACT_DIGEST",
    "EVIDENCE_PROVENANCE_GAPS",
    "CaseAvailabilityFacts",
    "CaseGap",
    "DeterministicAssessment",
    "DeterministicCase",
    "DeterministicFindingTemplate",
    "DeterministicPolicyResult",
    "FindingBasis",
    "FindingBasisRef",
    "FindingFact",
    "FrozenHistoryEvent",
    "FrozenSourceAvailability",
    "MAX_FROZEN_HISTORY_BYTES",
    "MAX_FROZEN_HISTORY_EVENTS",
    "OBSERVED_FAILURE_LIVE_FACT",
    "OBSERVED_VERIFICATION_ABSENT_FACT",
    "REQUESTED_OUTPUT_ABSENT_FACT",
    "OBSERVED_VERIFICATION_UNCITED_FACT",
    "PREEXISTING_TEST_EDIT_UNJUSTIFIED_FACT",
    "STATEMENT_SOURCED_OBLIGATION_ABSENT_FACT",
    "TASK_STATEMENT_RECORDED_FACT",
    "TASK_STATEMENT_SCOPE_EMPTY_FACT",
    "TASK_STATEMENT_UNMAPPED_FACT",
    "PolicyPack",
    "UnavailableCapturedObject",
    "build_deterministic_case",
    "build_task_statement_unmapped_assessment",
    "build_test_edit_integrity_assessment",
    "case_coverage",
    "healthy_storage_availability",
    "deterministic_case_from_json",
    "deterministic_case_to_json",
    "finding_basis_from_json",
    "finding_basis_to_json",
    "finding_basis_to_status_json",
    "render_deterministic_finding_text",
    "run_deterministic_policies",
]

type FindingBasisRef = (
    EventId | ObligationId | ClaimId | ActionId | ResultId | EvidenceId | FindingId
)
type PublicSubjectRef = EventId | ObligationId | ClaimId

_MAX_SAFE_INTEGER: Final = 2**53 - 1
# Work-integrity fact naming a hook-observed failure that is still live at the claim: the latest
# observed run of its command identity failed and no covering rerun or acknowledgement followed
# it (#909).
OBSERVED_FAILURE_LIVE_FACT: Final = "observed_failure_live"
# The recorded task statement has no effective obligation citing it in source_refs (TB4 pilot).
TASK_STATEMENT_UNMAPPED_FACT: Final = "task_statement_unmapped"
STATEMENT_SOURCED_OBLIGATION_ABSENT_FACT: Final = "statement_sourced_obligation_absent"
# A completion claim stands on no plan or an explicit empty scope while a task statement is
# recorded and no no-material-work decision answers it (TB4 pilot).
TASK_STATEMENT_SCOPE_EMPTY_FACT: Final = "task_statement_scope_empty"
# The unjustified pre-existing test edit (ADR-032), and the statement event its repair must cite.
PREEXISTING_TEST_EDIT_UNJUSTIFIED_FACT: Final = "preexisting_test_edit_unjustified"
TASK_STATEMENT_RECORDED_FACT: Final = "task_statement_recorded"
# A completion claim cites no verification (observed or self-published) made after the latest observed edit.
OBSERVED_VERIFICATION_UNCITED_FACT: Final = "observed_verification_uncited"
OBSERVED_VERIFICATION_ABSENT_FACT: Final = "observed_verification_absent"
REQUESTED_OUTPUT_ABSENT_SUMMARY: Final = (
    "A requested output file does not exist in the workspace at check time."
)
# A requested file the check-time workspace read found absent, and not a tracked file the change
# deletes (#977). Its repair is the deliverable itself, never a revised obligation, with one
# exception (tb4n5 react-lead-form, ADR-033 amendment): a file the request asks for only under a
# condition the final state does not meet is runtime behavior, not a file delivered now, so the
# repair is a plan correction that models it as a ``change`` item, never a placeholder file.
REQUESTED_OUTPUT_ABSENT_FACT: Final = "requested_output_absent"
_CODE_PATTERN: Final = re.compile(r"^[a-z][a-z0-9_]{0,127}$", re.ASCII)
_POLICY_PATTERN: Final = re.compile(r"^[a-z][a-z0-9-]{0,127}$", re.ASCII)
_VERSION_PATTERN: Final = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$",
    re.ASCII,
)
MAX_FROZEN_HISTORY_EVENTS: Final = 64
MAX_FROZEN_HISTORY_BYTES: Final = 512 * 1024
_SEMANTIC_HISTORY_FAMILIES: Final = frozenset(
    {
        "action_recorded",
        "check_recorded",
        "claim_recorded",
        "decision_recorded",
        "evidence_recorded",
        "finding_recorded",
        "obligation_published",
        "plan_published",
        "plan_revised",
        "response_recorded",
        "result_recorded",
    }
)


def _invalid_case() -> ValueError:
    return ValueError("deterministic_case_invalid")


def _invalid_basis() -> ValueError:
    return ValueError("finding_basis_invalid")


def _invalid_policy() -> ValueError:
    return ValueError("policy_wiring_invalid")


def _ascii_key(value: str) -> bytes:
    try:
        return value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise _invalid_case() from exc


def _sorted_unique[T: str](values: Iterable[T]) -> tuple[T, ...]:
    return tuple(sorted(set(values), key=_ascii_key))


def _basis_ref(value: object) -> FindingBasisRef:
    if type(value) is not str:
        raise _invalid_basis()
    try:
        if value.startswith("evt_"):
            return event_id(value)
        if value.startswith("obl_"):
            return obligation_id(value)
        if value.startswith("clm_"):
            return claim_id(value)
        if value.startswith("act_"):
            return action_id(value)
        if value.startswith("res_"):
            return result_id(value)
        if value.startswith("evd_"):
            return evidence_id(value)
        if value.startswith("fnd_"):
            return finding_id(value)
    except ValueError as exc:
        raise _invalid_basis() from exc
    raise _invalid_basis()


def _public_ref(value: object) -> PublicSubjectRef:
    ref = _basis_ref(value)
    if ref.startswith("evt_"):
        return event_id(ref)
    if ref.startswith("obl_"):
        return obligation_id(ref)
    if ref.startswith("clm_"):
        return claim_id(ref)
    raise _invalid_basis()


def _validated_ref_tuple(
    value: object,
    *,
    public_only: bool = False,
    allow_empty: bool = False,
) -> tuple[FindingBasisRef, ...] | tuple[PublicSubjectRef, ...]:
    if type(value) is not tuple:
        raise _invalid_basis()
    raw = cast(tuple[object, ...], value)
    if not (0 if allow_empty else 1) <= len(raw) <= MAX_REF_LIST:
        raise _invalid_basis()
    refs = tuple((_public_ref(item) if public_only else _basis_ref(item)) for item in raw)
    if refs != _sorted_unique(refs):
        raise _invalid_basis()
    return refs


@dataclass(frozen=True, slots=True)
class PolicyPack:
    policy_id: str
    policy_version: str

    def __post_init__(self) -> None:
        if (
            type(self.policy_id) is not str
            or _POLICY_PATTERN.fullmatch(self.policy_id) is None
            or type(self.policy_version) is not str
            or _VERSION_PATTERN.fullmatch(self.policy_version) is None
        ):
            raise _invalid_policy()


@dataclass(frozen=True, slots=True)
class UnavailableCapturedObject:
    source_event_id: EventId
    object_id: ObjectId

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "source_event_id", event_id(self.source_event_id))
            object.__setattr__(self, "object_id", object_id(self.object_id))
        except ValueError as exc:
            raise _invalid_case() from exc


@dataclass(frozen=True, slots=True)
class CaseAvailabilityFacts:
    unavailable_event_ids: tuple[EventId, ...] = ()
    unavailable_captured_objects: tuple[UnavailableCapturedObject, ...] = ()

    def __post_init__(self) -> None:
        if type(self.unavailable_event_ids) is not tuple:
            raise _invalid_case()
        try:
            event_ids = tuple(event_id(value) for value in self.unavailable_event_ids)
        except ValueError as exc:
            raise _invalid_case() from exc
        if event_ids != _sorted_unique(event_ids):
            raise _invalid_case()
        if type(self.unavailable_captured_objects) is not tuple or any(
            type(item) is not UnavailableCapturedObject
            for item in self.unavailable_captured_objects
        ):
            raise _invalid_case()
        objects = self.unavailable_captured_objects
        ordered = tuple(
            sorted(
                set(objects),
                key=lambda item: (_ascii_key(item.source_event_id), _ascii_key(item.object_id)),
            )
        )
        if objects != ordered:
            raise _invalid_case()
        object.__setattr__(self, "unavailable_event_ids", event_ids)


class FrozenSourceAvailability(str, Enum):  # noqa: UP042 - exact wire enum base
    AVAILABLE = "available"
    NOT_RECORDED = "not_recorded"
    UNAVAILABLE_AT_FREEZE = "unavailable_at_freeze"
    REDACTED_AT_SOURCE = "redacted_at_source"


@dataclass(frozen=True, slots=True)
class FindingFact:
    fact_code: str
    subject_refs: tuple[FindingBasisRef, ...]

    def __post_init__(self) -> None:
        if type(self.fact_code) is not str or _CODE_PATTERN.fullmatch(self.fact_code) is None:
            raise _invalid_basis()
        refs = _validated_ref_tuple(self.subject_refs)
        object.__setattr__(self, "subject_refs", cast(tuple[FindingBasisRef, ...], refs))


def _fact_key(fact: FindingFact) -> tuple[bytes, tuple[bytes, ...]]:
    return (_ascii_key(fact.fact_code), tuple(_ascii_key(ref) for ref in fact.subject_refs))


def _validate_fact_tuple(value: object, *, minimum: int) -> tuple[FindingFact, ...]:
    if type(value) is not tuple:
        raise _invalid_basis()
    facts = cast(tuple[object, ...], value)
    if not minimum <= len(facts) <= 33 or any(type(fact) is not FindingFact for fact in facts):
        raise _invalid_basis()
    typed = cast(tuple[FindingFact, ...], facts)
    if typed != tuple(sorted(typed, key=_fact_key)) or len(
        {fact.fact_code for fact in typed}
    ) != len(typed):
        raise _invalid_basis()
    return typed


@dataclass(frozen=True, slots=True)
class FindingBasis:
    rule_id: str
    observed_facts: tuple[FindingFact, ...]
    required_but_missing_facts: tuple[FindingFact, ...]
    subject_state_relation: SubjectStateRelation
    source_availability: FrozenSourceAvailability
    coverage_gaps: tuple[str, ...]
    supporting_refs: tuple[FindingBasisRef, ...]

    def __post_init__(self) -> None:
        if type(self.rule_id) is not str or len(self.rule_id) > 256 or self.rule_id.count("/") != 1:
            raise _invalid_basis()
        policy, rule = self.rule_id.split("/", 1)
        if _POLICY_PATTERN.fullmatch(policy) is None or _CODE_PATTERN.fullmatch(rule) is None:
            raise _invalid_basis()
        observed = _validate_fact_tuple(self.observed_facts, minimum=1)
        missing = _validate_fact_tuple(self.required_but_missing_facts, minimum=0)
        object.__setattr__(self, "observed_facts", observed)
        object.__setattr__(self, "required_but_missing_facts", missing)
        if type(self.subject_state_relation) is not SubjectStateRelation:
            raise _invalid_basis()
        if type(self.source_availability) is not FrozenSourceAvailability:
            raise _invalid_basis()
        if (
            type(self.coverage_gaps) is not tuple
            or not 0 <= len(self.coverage_gaps) <= MAX_REF_LIST
        ):
            raise _invalid_basis()
        for gap in self.coverage_gaps:
            if type(gap) is not str or _CODE_PATTERN.fullmatch(gap) is None:
                raise _invalid_basis()
        if self.coverage_gaps != _sorted_unique(self.coverage_gaps):
            raise _invalid_basis()
        refs = cast(
            tuple[FindingBasisRef, ...],
            _validated_ref_tuple(self.supporting_refs),
        )
        expected = _sorted_unique(ref for fact in self.observed_facts for ref in fact.subject_refs)
        if refs != expected:
            raise _invalid_basis()
        object.__setattr__(self, "supporting_refs", refs)


@dataclass(frozen=True, slots=True)
class DeterministicFindingTemplate:
    summary: str
    next_action: str

    def __post_init__(self) -> None:
        if (
            type(self.summary) is not str
            or not self.summary
            or type(self.next_action) is not str
            or not self.next_action
        ):
            raise _invalid_policy()


def _test_edit_repair(statement_refs: str) -> str:
    """The complete working repair for an unjustified pre-existing test edit (ADR-032).

    Every step is needed: ``source_refs`` cannot change on an existing obligation, the requested
    file needs an attributable attempt, and the claim must name the new obligation.
    """

    return (
        "If the user's request asks for this test change, do all of these, then check again:"
        " (1) publish a NEW obligation_published (source_refs cannot change on an existing"
        f" obligation) whose source_refs cite {statement_refs} and whose requested_items list"
        " the test file's repository-relative path with item_kind file; (2) add it to the plan"
        " with plan_revised, change=carried for it and for every obligation you keep; (3) record"
        " an action_recorded (action_kind edit) whose attempted_items list that same path, with"
        " its result_recorded;"
        " (4) after step 3, rerun your verification (evidence from before step 3 is stale) and"
        " republish the new obligation with status resolved and resolution_evidence_refs naming"
        " that fresh observed verification result; (5) replace the"
        " completion claim with claim_recorded/1.1.0 supersedes_claim_refs naming the old claim"
        " and obligation_refs including the new obligation. Otherwise revert the test change and"
        " check again."
    )


DETERMINISTIC_FINDING_TEMPLATES: Final[
    MappingProxyType[FindingKind, DeterministicFindingTemplate]
] = MappingProxyType(
    {
        FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS: DeterministicFindingTemplate(
            "A completion claim covers an obligation that remains open.",
            "Resolve the obligation or revise the completion claim. An obligation you acknowledged"
            " as not done is not completed: omit it from the completion claim (replace the claim"
            " with claim_recorded/1.1.0 supersedes_claim_refs); the receipt discloses it as not"
            " done, and omitting it is not a plan-scope gap.",
        ),
        FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED: DeterministicFindingTemplate(
            "A requested item has no recorded attempt.",
            "Attempt the requested item and record the action naming it in attempted_items."
            " Revise the obligation only if the user's request itself changed. If you did the"
            " work and FinishUP cannot show it (a FinishUP limit), verify it yourself and respond"
            " self_verified with your evidence; a FinishUP limit is never a blocker. An inherent"
            " verification limit (a hidden verifier, a private trace) or a best-effort choice is"
            " not a blocker either: finish the work and disclose it with a decision line"
            " finishup-assumption:<obligation id> or finishup-verification-limit:<obligation id>. If you"
            " truly will not do it, after repair, republish the obligation with status"
            " acknowledged_not_done and an acknowledged_not_done_reason: the honest last resort. Only when"
            " something genuinely outside your control (authority, consent, a credential, a"
            " dependency you cannot obtain) prevents this open obligation, and the task does not"
            " say the outcome is recoverable, record a decision_recorded naming it in"
            " affected_obligation_ids with the statement line finishup-blocker:<authority|consent|"
            "credential|dependency_unavailable>; the publish result then challenges it.",
        ),
        FindingKind.FAILED_WORK_OMITTED: DeterministicFindingTemplate(
            "Recorded failed work is omitted from the published account.",
            "Replace the claim with claim_recorded/1.1.0 and name the result in limitation_refs.",
        ),
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE: DeterministicFindingTemplate(
            "A recorded claim has no admissible supporting evidence.",
            "Provide admissible support or revise the claim.",
        ),
        FindingKind.RESULT_WITHOUT_ACTION: DeterministicFindingTemplate(
            "A recorded result has no linked action.",
            "Publish the linked action or correct the result record.",
        ),
        FindingKind.ACTION_WITHOUT_RESULT: DeterministicFindingTemplate(
            "A recorded action has no linked result.",
            "Record the result or state the attempt as unresolved.",
        ),
        FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE: DeterministicFindingTemplate(
            "The cited evidence predates a materially changed subject state.",
            "Run a check against the current state.",
        ),
        FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED: DeterministicFindingTemplate(
            "Explicitly disputed claims remain structurally unresolved.",
            "Replace the effective claim with claim_recorded/1.1.0 supersedes_claim_refs.",
        ),
        FindingKind.LEDGER_STALE_OR_INCOMPLETE: DeterministicFindingTemplate(
            "The ledger is too incomplete for a current conclusion.",
            "Treat the conclusion as coverage-limited.",
        ),
        FindingKind.WEAK_OR_STALE_RESPONSE: DeterministicFindingTemplate(
            "A finding response lacks current admissible support.",
            "Provide current admissible response evidence.",
        ),
        FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM: DeterministicFindingTemplate(
            "The cited evidence does not support the recorded claim.",
            "Publish supported evidence or replace the claim with claim_recorded/1.1.0.",
        ),
        FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT: DeterministicFindingTemplate(
            "Recorded subject-state digests contradict the published account.",
            "Revise the account or publish matching state evidence.",
        ),
        FindingKind.MATERIAL_LIMITATION_OMITTED: DeterministicFindingTemplate(
            "A material recorded limitation is omitted from the published account.",
            "Replace or narrow the claim with exact accepted support or limitation references.",
        ),
        FindingKind.QUESTIONABLE_FINDING_REJECTION: DeterministicFindingTemplate(
            "A local finding was rejected without admissible support.",
            "Provide current evidence for the rejection.",
        ),
        FindingKind.COORDINATION_OVERLAP: DeterministicFindingTemplate(
            "Accepted work overlaps another live task in the coordination scope.",
            "Record a coordination disposition, then run a qualifying check to resolve the overlap.",
        ),
        FindingKind.CODE_DEFECT: DeterministicFindingTemplate(
            "A code defect was recorded without a qualifying repair that local checks confirm.",
            "Record the repair evidence or revise the code-defect finding.",
        ),
        FindingKind.TASK_REQUIREMENT_UNMET: DeterministicFindingTemplate(
            "An existing test file was edited without a recorded justification.",
            _test_edit_repair(
                "the task-statement event (the newest event that carried task_statement:"
                " session_opened, session_resumed, plan_published or plan_revised)"
            ),
        ),
        # Issue #1043: raised only by the AI-powered review (or routed to it by the check); no
        # local pack emits it. The template exists because every kind needs one.
        FindingKind.AGENT_CRITERION_UNMET: DeterministicFindingTemplate(
            "A criterion the agent set for itself beyond the task's stated scope is not met.",
            "Fix the work, or narrow the criterion by responding acknowledged with the reason.",
        ),
        FindingKind.DECISION_NEEDED: DeterministicFindingTemplate(
            "The reviewer identified a choice between defensible interpretations.",
            "You decide; record the choice and reason with respond acknowledged or rejected.",
        ),
    }
)
if frozenset(DETERMINISTIC_FINDING_TEMPLATES) != frozenset(FindingKind):
    raise _invalid_policy()


EVIDENCE_PROVENANCE_GAPS: Final[frozenset[str]] = frozenset(
    {
        "evidence_content_digest_only",
        "evidence_content_withheld",
        "evidence_digest_subject_legacy_unknown",
    }
)
# Caller digests whose bytes FinishUP neither retained nor verified (issue #912). Every service
# producer (approved check, trusted-import report, observation capture) records ``captured``
# availability, so a cited ``digest_only`` or ``withheld`` binding comes from ordinary publication
# and is ``caller_asserted``. Nothing an agent can publish changes that recorded provenance, so
# these codes stay exact coverage limitations that the receipt discloses once, with a count, and
# never become a ledger finding whose remedy the agent cannot perform. A legacy digest without a
# binding keeps its finding: its subject is unknown, not merely unverified.
CALLER_DIGEST_PROVENANCE_GAPS: Final[frozenset[str]] = frozenset(
    {
        "evidence_content_digest_only",
        "evidence_content_withheld",
    }
)


def render_deterministic_finding_text(
    kind: FindingKind,
    subject_refs: tuple[PublicSubjectRef, ...],
    gap_codes: tuple[str, ...] = (),
    observed_facts: tuple[FindingFact, ...] = (),
) -> tuple[str, str]:
    if (
        type(kind) is not FindingKind
        or type(gap_codes) is not tuple
        or type(observed_facts) is not tuple
        or any(type(fact) is not FindingFact for fact in observed_facts)
    ):
        raise _invalid_policy()
    refs = cast(
        tuple[PublicSubjectRef, ...],
        _validated_ref_tuple(subject_refs, public_only=True),
    )
    template = DETERMINISTIC_FINDING_TEMPLATES[kind]
    if any(fact.fact_code == "verification_freshness_question" for fact in observed_facts):
        return (
            "Is a verification rerun needed after the recorded changes?",
            f"Subjects: {', '.join(refs)}. Review the verification and later changes. Rerun it"
            " or respond acknowledged with a reasoned explanation that a rerun is not needed."
            " This question does not block closure: unknown inputs never demand a rerun, and on"
            " AI review a known input change is asked about rather than blocked.",
        )
    detail = f"Subjects: {', '.join(refs)}. Main agent: {template.next_action}"
    if kind is FindingKind.LEDGER_STALE_OR_INCOMPLETE and gap_codes:
        detail = (
            f"Subjects: {', '.join(refs)}. Gaps: {', '.join(gap_codes)}."
            f" Main agent: {template.next_action}"
        )
        if EVIDENCE_PROVENANCE_GAPS & set(gap_codes):
            # Name only actions an agent can take (issue #912): ordinary publication cannot
            # record captured content, so the old "record content-bearing evidence" remedy sent
            # agents into publishing more digest-only items. Provenance is the whole finding only
            # when every listed gap code is a provenance code, every subject is an event root
            # (case construction weakens each event root with its own gap code), and no fact
            # names an unknown or redacted event. Anything else (another gap code, an unknown or
            # redaction fact, or an obligation or claim subject such as a command-attempt gap)
            # keeps the finding current after any acknowledgement, so it gets the mixed wording.
            support = (
                " Where a claim needs stronger support, cite an existing captured evidence id"
                " (status view=evidence, filter.strength immutable_snapshot) or new evidence with a"
                " typed digest_binding in a replacement claim."
            )
            if (
                set(gap_codes) <= EVIDENCE_PROVENANCE_GAPS
                and all(ref.startswith("evt_") for ref in refs)
                and all(fact.fact_code == "freshness_gap_present" for fact in observed_facts)
            ):
                detail = (
                    f"{detail} Evidence provenance is recorded history: no finding response,"
                    " recheck, or further digest-only publication changes it, and the receipt"
                    " discloses it, so it needs no repair or recheck; one acknowledged response"
                    f" answers it.{support}"
                )
            else:
                detail = (
                    f"{detail} Its evidence-provenance gaps are recorded history: no finding"
                    " response, recheck, or further digest-only publication changes them, and"
                    " the receipt discloses them. The other gaps and subjects named here are not"
                    " covered by that: an acknowledgement answers this finding but does not"
                    " resolve it, and it stays current until a qualifying check proves those"
                    f" other gaps absent.{support}"
                )
    if kind is FindingKind.ACTION_WITHOUT_RESULT:
        # tb4n3 N3-5: the subject is the event that recorded the action, but a result links by the
        # action's own act_ id. cargo D could not find it and tried a causal parent instead.
        action_ids = tuple(
            dict.fromkeys(
                ref
                for fact in observed_facts
                if fact.fact_code == "action_present"
                for ref in fact.subject_refs
                if ref.startswith("act_")
            )
        )
        if action_ids:
            named = ", ".join(action_ids[:3]) + (
                f" and {len(action_ids) - 3} more" if len(action_ids) > 3 else ""
            )
            return (
                template.summary,
                f"Subjects: {', '.join(refs)}. Main agent: {template.next_action} The action to"
                f" link is {named} (the subject above is the event that recorded it). Link a"
                " result by publishing a result_recorded whose payload action_id is that act_ id,"
                " with outcome success, failure, partial or unknown and a summary; a causal"
                " parent alone names the event but does not link the result. If the attempt was"
                " abandoned, record its result with outcome unknown and say so in the summary.",
            )
    if kind is FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED and any(
        fact.fact_code == REQUESTED_OUTPUT_ABSENT_FACT for fact in observed_facts
    ):
        return (
            REQUESTED_OUTPUT_ABSENT_SUMMARY,
            f"Subjects: {', '.join(refs)}. Main agent: Write each requested file the obligation"
            " names (status view=obligations lists them) at its requested path, then check again."
            " If an input looks inconsistent, still write a best-effort artifact in the requested"
            " format and disclose the assumption; an input problem is not a reason to omit a"
            " requested output, and publishing an action that names the file does not create it."
            " If the request asks for this file only under a condition your final state does not"
            " meet (a quarantine log written only for a malformed input, a report written only"
            " for a failing case), it is runtime behavior, not a file delivered now: correct the"
            " plan, not the deliverable. Publish a new obligation with the same acceptance"
            " criteria where this file has a `change` item of its own that spells its declared"
            " path and states its condition (when, if or unless), and whose `file` items (role"
            " `output`) name the source files that implement it; supersede this"
            " obligation with plan_revised (change superseded, a reason, and"
            " replacement_obligation_ids naming the new one); record the work with each new item"
            " value in attempted_items, resolve the new obligation with its evidence, replace the"
            " completion claim with one naming it, then check again. Never write an empty or"
            " placeholder file, and never change when the deliverable writes the file, to satisfy"
            " the declaration. A file the request asks for unconditionally stays required: a file"
            " the replacement neither re-declares as a `file` item (not role `input`) nor names"
            " alone, with its condition, in a `change` item stays requested on the superseded"
            " obligation."
            " If the requested item is not the path the request asks for, correct the item."
            " Do not git-ignore, exclude, stash or delete a requested output to keep it out of"
            " review: FinishUP redacts what it sends.",
        )
    if kind is FindingKind.TASK_REQUIREMENT_UNMET and any(
        fact.fact_code == TASK_STATEMENT_UNMAPPED_FACT for fact in observed_facts
    ):
        statement_refs = ", ".join(ref for ref in refs if ref.startswith("evt_"))
        return (
            TASK_STATEMENT_UNMAPPED_SUMMARY,
            f"Subjects: {', '.join(refs)}. Main agent: Decompose the user's request into"
            " obligations, one per stated requirement, symptom, constraint, or deliverable."
            " Publish each as a NEW obligation_published (source_refs cannot change on an"
            f" existing obligation) with source_refs [{statement_refs}], observable"
            " acceptance_criteria, and requested_items for every file or output the request"
            " names. Add them with plan_revised (change=carried for them and for every"
            " obligation you keep), resolve each with its own evidence, and replace the"
            " completion claim with claim_recorded/1.1.0 supersedes_claim_refs naming them in"
            " obligation_refs. A check rerun without that plan change returns this finding"
            " again. If the request asks for no material work, revise the plan to an explicit"
            " empty scope and record a decision_recorded whose statement holds the exact line"
            f" {NO_MATERIAL_WORK_MARKER}:{statement_refs} and whose rationale says why; that"
            " decision counts only while the task records no edit and the check-time change"
            " shows no changed file.",
        )
    if kind is FindingKind.TASK_REQUIREMENT_UNMET and any(
        fact.fact_code == TASK_STATEMENT_SCOPE_EMPTY_FACT for fact in observed_facts
    ):
        statement_refs = ", ".join(ref for ref in refs if ref.startswith("evt_"))
        return (
            TASK_STATEMENT_SCOPE_EMPTY_SUMMARY,
            f"Subjects: {', '.join(refs)}. Main agent: The completion claim stands on no plan or"
            " an explicit empty scope, so the user's request was never decomposed. Either"
            " publish one obligation per stated requirement, symptom, constraint, or deliverable"
            f" with source_refs [{statement_refs}], add them with plan_published (or plan_revised"
            " from the empty-scope plan, change=carried), resolve each with its own evidence,"
            " and replace the completion claim with claim_recorded/1.1.0 supersedes_claim_refs"
            " naming them in obligation_refs; or, if the request asks for no material work,"
            " record a decision_recorded whose statement holds the exact line"
            f" {NO_MATERIAL_WORK_MARKER}:{statement_refs} and whose rationale says why. That"
            " decision counts only while the task records no edit and the check-time change"
            " shows no changed file (shell writes count). Then check again; a rerun without one"
            " of these returns this finding again.",
        )
    if kind is FindingKind.TASK_REQUIREMENT_UNMET and any(
        fact.fact_code == TASK_STATEMENT_RECORDED_FACT for fact in observed_facts
    ):
        statement_refs = ", ".join(
            ref
            for fact in observed_facts
            if fact.fact_code == TASK_STATEMENT_RECORDED_FACT
            for ref in fact.subject_refs
        )
        return (
            template.summary,
            f"Subjects: {', '.join(refs)}. Main agent: " + _test_edit_repair(f"[{statement_refs}]"),
        )
    if kind is FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE and any(
        fact.fact_code == OBSERVED_VERIFICATION_UNCITED_FACT for fact in observed_facts
    ):
        claim_refs = ", ".join(ref for ref in refs if ref.startswith("clm_"))
        return (
            "A completion claim cites no verification made after the latest observed edit.",
            f"Subjects: {', '.join(refs)}. Main agent: Every verification the claim cites"
            " predates your latest edit, or it cites none. Run the verification the request"
            " needs after your last edit and replace the claim with claim_recorded/1.1.0"
            f" supersedes_claim_refs [{claim_refs}], citing that run in supporting_refs (or in"
            " limitation_refs when it failed): the observed res_ id from status view=results"
            " (tool, occurrence, exit status), or your own command result or test_result"
            " evidence published after the edit; self-generated evidence is admissible."
            " A check rerun alone returns this finding again; if no verification is possible,"
            " narrow the claim or answer with respond.",
        )
    if kind is FindingKind.MATERIAL_LIMITATION_OMITTED:
        limitation_refs = tuple(
            ref
            for fact in observed_facts
            if fact.fact_code == "material_limitation_present"
            for ref in fact.subject_refs
            if not ref.startswith("clm_")
        )
        if limitation_refs:
            # A res_ ref reaches this fact through either a non-success outcome
            # or a material coverage gap on its source event, and the basis does
            # not record which route; the label must stay truthful for both.
            limiting_records = "; ".join(
                (
                    f"limiting result {ref}"
                    if ref.startswith("res_")
                    else f"material coverage-gap record {ref}"
                )
                for ref in limitation_refs
            )
            claim_records = ", ".join(ref for ref in refs if ref.startswith("clm_"))
            result_records = ", ".join(ref for ref in limitation_refs if ref.startswith("res_"))
            support_records = ", ".join(
                ref for ref in limitation_refs if not ref.startswith("res_")
            )
            accepted_links: list[str] = []
            if result_records:
                accepted_links.append(f"limitation_refs [{result_records}]")
            if support_records:
                accepted_links.append(f"supporting_refs [{support_records}]")
            detail = (
                f"{detail} Omitted limitation basis: {limiting_records}. Accepted disclosure "
                f"link: {' and '.join(accepted_links)}. For replacement, claim_recorded/1.1.0 "
                f"supersedes_claim_refs names [{claim_records}]."
            )
        else:
            detail = (
                f"{detail} Omitted limitation basis: task-level material coverage gap; "
                "no individual limitation record was available."
            )
    if kind is FindingKind.FAILED_WORK_OMITTED:
        failed_refs = tuple(
            ref
            for fact in observed_facts
            if fact.fact_code == "failed_result_present"
            for ref in fact.subject_refs
            if ref.startswith("res_")
        )
        claim_refs = tuple(ref for ref in refs if ref.startswith("clm_"))
        if failed_refs and claim_refs:
            detail = (
                f"{detail} Canonical repair: publish claim_recorded/1.1.0 with "
                f"supersedes_claim_refs [{', '.join(claim_refs)}] and limitation_refs "
                f"[{', '.join(failed_refs)}]; keep admissible support in supporting_refs."
            )
        live_runs = tuple(
            fact.subject_refs
            for fact in observed_facts
            if fact.fact_code == OBSERVED_FAILURE_LIVE_FACT
        )
        for run in live_runs:
            run_results = ", ".join(ref for ref in run if ref.startswith("res_"))
            run_actions = ", ".join(ref for ref in run if ref.startswith("act_"))
            named = f"result {run_results}" + (f" of action {run_actions}" if run_actions else "")
            detail = (
                f"{detail} Observed run: {named} failed, and before the claim no later "
                "hook-observed run of the same command identity followed it (alone, or as a "
                "segment run as is inside a passing && chain). status view=results lists its "
                "tool, occurrence, command commitment (when recorded) and exit status; command "
                "text is never recorded. Either disclose it as above, or fix it and publish a "
                "replacement claim once a later observed run of the same command passes. A run "
                "without a command commitment keeps its disclosure duty until a completion claim "
                "names it in limitation_refs."
            )
    if kind is FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED:
        claim_refs = tuple(ref for ref in refs if ref.startswith("clm_"))
        if claim_refs:
            detail = (
                f"{detail} The accepted supersession reference kind is a claim id in "
                f"claim_recorded/1.1.0 supersedes_claim_refs; candidate claim ids: "
                f"{', '.join(claim_refs)}. disputes_refs and decision supersedes_event_id do "
                "not supersede claims."
            )
    if kind is FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM:
        claim_refs = tuple(ref for ref in refs if ref.startswith("clm_"))
        evidence_refs = tuple(ref for ref in refs if not ref.startswith("clm_"))
        if claim_refs and evidence_refs:
            detail = (
                f"{detail} To replace the claim, name {', '.join(claim_refs)} in "
                "claim_recorded/1.1.0 supersedes_claim_refs and do not cite the mismatched "
                f"reference as support: {', '.join(evidence_refs)}."
            )
    return template.summary, detail


def _text_contract_corpus() -> tuple[JsonValue, ...]:
    """Render every finding-text wording branch once, on fixed synthetic inputs.

    The corpus must cover each branch of ``render_deterministic_finding_text`` that can produce
    distinct wording: every template, the ledger-stale gap listing, both evidence-provenance
    addenda (provenance-only and mixed), and each omitted-limitation basis label. A new wording branch must add a corpus
    entry here, or checkpoints written before that branch changes will replay as corrupt instead
    of superseded.
    """

    subject = (event_id("evt_00000000-0000-4000-8000-000000000000"),)
    limitation_result = FindingFact(
        "material_limitation_present",
        (result_id("res_00000000-0000-4000-8000-000000000000"),),
    )
    limitation_record = FindingFact(
        "material_limitation_present",
        (event_id("evt_00000000-0000-4000-8000-000000000001"),),
    )
    failed_claim = claim_id("clm_00000000-0000-4000-8000-000000000000")
    failed_result = result_id("res_00000000-0000-4000-8000-000000000000")
    failed_facts = (
        FindingFact("failed_result_present", (failed_result,)),
        FindingFact(
            OBSERVED_FAILURE_LIVE_FACT,
            (action_id("act_00000000-0000-4000-8000-000000000000"), failed_result),
        ),
    )
    branches: tuple[tuple[str, FindingKind, tuple[str, ...], tuple[FindingFact, ...]], ...] = (
        *(("template", kind, (), ()) for kind in FindingKind),
        ("stale_gap_listing", FindingKind.LEDGER_STALE_OR_INCOMPLETE, ("missing_ref",), ()),
        (
            "stale_provenance_addendum",
            FindingKind.LEDGER_STALE_OR_INCOMPLETE,
            ("evidence_digest_subject_legacy_unknown",),
            (),
        ),
        (
            "stale_mixed_provenance_addendum",
            FindingKind.LEDGER_STALE_OR_INCOMPLETE,
            ("evidence_digest_subject_legacy_unknown", "unknown_event"),
            (),
        ),
        (
            # tb4n3 N3-5: the action finding names the act_ id a result must link to.
            "action_without_result_link",
            FindingKind.ACTION_WITHOUT_RESULT,
            (),
            (
                FindingFact(
                    "action_present",
                    (action_id("act_00000000-0000-4000-8000-000000000000"),),
                ),
            ),
        ),
        ("limitation_result", FindingKind.MATERIAL_LIMITATION_OMITTED, (), (limitation_result,)),
        ("limitation_record", FindingKind.MATERIAL_LIMITATION_OMITTED, (), (limitation_record,)),
        (
            "task_statement_unmapped",
            FindingKind.TASK_REQUIREMENT_UNMET,
            (),
            (FindingFact(TASK_STATEMENT_UNMAPPED_FACT, subject),),
        ),
        (
            "task_statement_scope_empty",
            FindingKind.TASK_REQUIREMENT_UNMET,
            (),
            (FindingFact(TASK_STATEMENT_SCOPE_EMPTY_FACT, subject),),
        ),
        (
            "test_edit_with_statement",
            FindingKind.TASK_REQUIREMENT_UNMET,
            (),
            (
                FindingFact(PREEXISTING_TEST_EDIT_UNJUSTIFIED_FACT, subject),
                FindingFact(
                    TASK_STATEMENT_RECORDED_FACT,
                    (event_id("evt_00000000-0000-4000-8000-000000000001"),),
                ),
            ),
        ),
    )
    failed_subjects = (failed_claim, *subject)
    return (
        *(
            [label, kind.value, *render_deterministic_finding_text(kind, subject, gaps, facts)]
            for label, kind, gaps, facts in branches
        ),
        [
            "observed_verification_uncited",
            FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE.value,
            *render_deterministic_finding_text(
                FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
                (failed_claim,),
                (),
                (FindingFact(OBSERVED_VERIFICATION_UNCITED_FACT, (failed_claim,)),),
            ),
        ],
        [
            "failed_observed_run",
            FindingKind.FAILED_WORK_OMITTED.value,
            *render_deterministic_finding_text(
                FindingKind.FAILED_WORK_OMITTED, failed_subjects, (), failed_facts
            ),
        ],
    )


# The exact rendered-text contract of local findings. A persisted DETERMINISTIC_RESULT
# checkpoint stamps this digest; on replay, a stamp from different wording marks the checkpoint
# superseded (recompute from the frozen case) instead of corrupt (issue #340).
DETERMINISTIC_TEXT_CONTRACT_DIGEST: Final[str] = canonical_digest(_text_contract_corpus())


@dataclass(frozen=True, slots=True)
class DeterministicAssessment:
    candidate: CandidateFinding
    basis: FindingBasis

    def __post_init__(self) -> None:
        if type(self.candidate) is not CandidateFinding or type(self.basis) is not FindingBasis:
            raise _invalid_policy()
        candidate = self.candidate
        if (
            candidate.origin is not FindingOrigin.DETERMINISTIC
            or candidate.provenance is not None
            or self.basis.rule_id != f"{candidate.policy_id}/{candidate.kind.value}"
        ):
            raise _invalid_policy()
        summary, detail = render_deterministic_finding_text(
            candidate.kind,
            candidate.subject_refs,
            self.basis.coverage_gaps,
            self.basis.observed_facts,
        )
        if candidate.summary != summary or candidate.detail != detail:
            raise _invalid_policy()


@dataclass(frozen=True, slots=True)
class DeterministicPolicyResult:
    assessments: tuple[DeterministicAssessment, ...]

    def __post_init__(self) -> None:
        if type(self.assessments) is not tuple or any(
            type(item) is not DeterministicAssessment for item in self.assessments
        ):
            raise _invalid_policy()
        keys = tuple(
            (
                item.candidate.policy_id,
                item.basis.rule_id,
                item.candidate.subject_refs,
            )
            for item in self.assessments
        )
        if len(keys) != len(set(keys)):
            raise _invalid_policy()


def finding_basis_to_status_json(
    assessment: DeterministicAssessment,
) -> dict[str, object]:
    if type(assessment) is not DeterministicAssessment:
        raise _invalid_basis()
    candidate = assessment.candidate
    basis = assessment.basis
    if basis.rule_id != f"{candidate.policy_id}/{candidate.kind.value}":
        raise _invalid_basis()
    observed_codes = _sorted_unique(fact.fact_code for fact in basis.observed_facts)
    observed_refs = _sorted_unique(
        ref for fact in basis.observed_facts for ref in fact.subject_refs
    )
    missing_codes = _sorted_unique(fact.fact_code for fact in basis.required_but_missing_facts)
    availability = {
        FrozenSourceAvailability.AVAILABLE: "available",
        FrozenSourceAvailability.NOT_RECORDED: "not_recorded",
        FrozenSourceAvailability.UNAVAILABLE_AT_FREEZE: "unavailable",
        FrozenSourceAvailability.REDACTED_AT_SOURCE: "redacted",
    }[basis.source_availability]
    evidence_refs = tuple(ref for ref in basis.supporting_refs if ref.startswith(("evd_", "res_")))
    return {
        "rule_id": candidate.kind.value,
        "observed_fact_codes": list(observed_codes),
        "observed_refs": list(observed_refs),
        "required_missing_fact_codes": list(missing_codes),
        "subject_state_relation": basis.subject_state_relation.value,
        "frozen_source_availability": availability,
        "coverage_gaps": list(basis.coverage_gaps),
        "evidence_refs": list(evidence_refs),
    }


@dataclass(frozen=True, slots=True)
class CaseGap:
    marker: str
    code: str
    subject_refs: tuple[PublicSubjectRef, ...]

    def __post_init__(self) -> None:
        if (
            type(self.marker) is not str
            or not self.marker
            or len(self.marker.encode("utf-8")) > 8_192
            or type(self.code) is not str
            or _CODE_PATTERN.fullmatch(self.code) is None
        ):
            raise _invalid_case()
        refs = cast(
            tuple[PublicSubjectRef, ...],
            _validated_ref_tuple(self.subject_refs, public_only=True, allow_empty=True),
        )
        object.__setattr__(self, "subject_refs", refs)


@dataclass(frozen=True, slots=True)
class FrozenHistoryEvent:
    """One material accepted event retained in the bounded frozen history slice."""

    event_id: EventId
    schema_name: str
    schema_version: str
    ingestion_sequence: int
    occurred_at: str
    accepted_at: str | None
    occurred_at_consistency: (
        Literal[
            "within_forward_skew_allowance",
            "ahead_of_forward_skew_allowance",
        ]
        | None
    )
    payload_digest: str
    content_visibility: Literal["available", "not_recorded", "not_selected", "redacted_never_send"]
    payload: JsonValue | None
    # Issue #1084 (review R7): ``service_clock`` when the publish that appended this event omitted
    # ``occurred_at`` and the service recorded its own clock; ``None`` means caller-asserted (or a
    # case frozen before the label existed). Derived from the appending operation's durable record.
    occurred_at_source: Literal["service_clock"] | None = None

    def __post_init__(self) -> None:
        if self.occurred_at_source not in {None, "service_clock"}:
            raise _invalid_case()
        try:
            object.__setattr__(self, "event_id", event_id(self.event_id))
            schema = EventSchema(self.schema_name, self.schema_version)
            validate_sha256_digest(self.payload_digest)
            occurred = timestamp_from_string(self.occurred_at)
            accepted = None if self.accepted_at is None else timestamp_from_string(self.accepted_at)
        except (TypeError, ValueError) as exc:
            raise _invalid_case() from exc
        if (
            schema.name not in _SEMANTIC_HISTORY_FAMILIES
            or type(self.ingestion_sequence) is not int
            or not 1 <= self.ingestion_sequence <= _MAX_SAFE_INTEGER
            or self.content_visibility
            not in {"available", "not_recorded", "not_selected", "redacted_never_send"}
        ):
            raise _invalid_case()
        if (accepted is None) is not (self.occurred_at_consistency is None):
            raise _invalid_case()
        if accepted is not None and self.occurred_at_consistency != occurred_at_consistency(
            occurred, accepted
        ):
            raise _invalid_case()
        if self.content_visibility == "available":
            if self.payload is None:
                raise _invalid_case()
            try:
                payload = freeze_json(self.payload)
                decoded = decode_payload(schema, payload)
            except (TypeError, ValueError) as exc:
                raise _invalid_case() from exc
            if canonical_digest(encode_payload(decoded)) != self.payload_digest:
                raise _invalid_case()
            object.__setattr__(self, "payload", payload)
        elif self.payload is not None:
            raise _invalid_case()


@dataclass(frozen=True, slots=True)
class DeterministicCase:
    projection: ProjectionState
    frontier: Frontier
    availability: CaseAvailabilityFacts
    allowed_ids: frozenset[FindingBasisRef]
    coverage_by_ref: Mapping[FindingBasisRef, Coverage]
    gaps: tuple[CaseGap, ...]
    history: tuple[FrozenHistoryEvent, ...] = ()
    history_availability: Literal["available", "not_recorded"] = "not_recorded"
    history_omitted_before_count: int = 0
    # Service-stamped observation-authored events recorded after the pending missing-item request
    # (issue #907). Authorship is an envelope fact the projection does not keep; the next review
    # needs it to tell the agent answering a request from hook capture recording each tool call.
    observation_event_ids: frozenset[EventId] = frozenset()
    # The task's current statement and title at this frontier (issue #908). Local facts only:
    # whether either may leave the machine is the review selection's decision, never the case's.
    task_statement: RecordedTaskStatement | None = None
    task_title: str | None = None
    # Agent-published action events that one ``publish_work`` batch recorded together (tb4n5
    # follow-up, owner decision 2026-10-13): each group holds two or more ``action_recorded``
    # events of one cooperative operation, sorted, and no event is in two groups. Batch membership
    # is an envelope fact (the operation id) the projection does not keep; the action/result rule
    # needs it so a sibling action in the same batch is never "subsequent unrelated work".
    action_batches: tuple[tuple[EventId, ...], ...] = ()
    workspace_verification_edit_frontier: int = 0
    # Trusted, prefix-derived no-op shell writes. Persist with the frozen case so the local
    # claim rule and task-fact freshness use the same decision after recovery (#1143).
    verification_unchanged_action_ids: tuple[ActionId, ...] = ()
    verification_freshness: tuple[VerificationFreshness, ...] | None = None
    verification_advisory: bool = False

    def __post_init__(self) -> None:
        if type(self.verification_advisory) is not bool:
            raise _invalid_case()
        if self.verification_freshness is not None and (
            type(self.verification_freshness) is not tuple
            or any(
                type(row) is not VerificationFreshness
                or row.run_ref not in self.projection.results
                or row.state not in {"current", "stale", "unknown"}
                or any(ref not in self.allowed_ids for ref in row.change_refs)
                for row in self.verification_freshness
            )
        ):
            raise _invalid_case()
        if type(self.verification_unchanged_action_ids) is not tuple:
            raise _invalid_case()
        unchanged = tuple(action_id(value) for value in self.verification_unchanged_action_ids)
        if unchanged != tuple(sorted(set(unchanged), key=str.encode)) or any(
            action not in self.projection.actions for action in unchanged
        ):
            raise _invalid_case()
        if (
            type(self.workspace_verification_edit_frontier) is not int
            or not 0 <= self.workspace_verification_edit_frontier <= self.projection.frontier
        ):
            raise _invalid_case()
        if type(self.action_batches) is not tuple or any(
            type(group) is not tuple for group in self.action_batches
        ):
            raise _invalid_case()
        try:
            batches = tuple(
                tuple(event_id(value) for value in group) for group in self.action_batches
            )
        except (TypeError, ValueError) as exc:
            raise _invalid_case() from exc
        batch_members = [member for group in batches for member in group]
        if (
            any(
                len(group) < 2 or group != tuple(sorted(set(group), key=_ascii_key))
                for group in batches
            )
            or batches != tuple(sorted(batches, key=lambda group: _ascii_key(group[0])))
            or len(set(batch_members)) != len(batch_members)
        ):
            raise _invalid_case()
        object.__setattr__(self, "action_batches", batches)
        if type(self.observation_event_ids) is not frozenset:
            raise _invalid_case()
        try:
            object.__setattr__(
                self,
                "observation_event_ids",
                frozenset(event_id(value) for value in self.observation_event_ids),
            )
        except (TypeError, ValueError) as exc:
            raise _invalid_case() from exc
        if (
            type(self.projection) is not ProjectionState
            or type(self.frontier) is not Frontier
            or self.frontier.sequence != self.projection.frontier
            or self.frontier.head_digest != self.projection.head_digest
            or type(self.availability) is not CaseAvailabilityFacts
            or type(self.allowed_ids) is not frozenset
        ):
            raise _invalid_case()
        try:
            allowed = frozenset(_basis_ref(value) for value in self.allowed_ids)
        except ValueError as exc:
            raise _invalid_case() from exc
        if not isinstance(cast(object, self.coverage_by_ref), Mapping):
            raise _invalid_case()
        coverage: dict[FindingBasisRef, Coverage] = {}
        try:
            for raw_ref, value in self.coverage_by_ref.items():
                ref = _basis_ref(raw_ref)
                if type(value) is not Coverage:
                    raise _invalid_case()
                coverage[ref] = value
        except ValueError as exc:
            raise _invalid_case() from exc
        if frozenset(coverage) != allowed:
            raise _invalid_case()
        if type(self.gaps) is not tuple or any(type(gap) is not CaseGap for gap in self.gaps):
            raise _invalid_case()
        ordered_gaps = tuple(
            sorted(
                self.gaps,
                key=lambda gap: (
                    _ascii_key(gap.marker),
                    tuple(_ascii_key(ref) for ref in gap.subject_refs),
                ),
            )
        )
        if self.gaps != ordered_gaps or len({gap.marker for gap in self.gaps}) != len(self.gaps):
            raise _invalid_case()
        if (
            type(self.history) is not tuple
            or len(self.history) > MAX_FROZEN_HISTORY_EVENTS
            or any(type(item) is not FrozenHistoryEvent for item in self.history)
            or self.history_availability not in {"available", "not_recorded"}
            or type(self.history_omitted_before_count) is not int
            or not 0 <= self.history_omitted_before_count <= _MAX_SAFE_INTEGER
            or (
                self.history_availability == "not_recorded"
                and (self.history or self.history_omitted_before_count)
            )
        ):
            raise _invalid_case()
        history_keys = tuple(
            (item.ingestion_sequence, _ascii_key(item.event_id)) for item in self.history
        )
        history_bytes = sum(
            len(canonical_encode(item.payload)) for item in self.history if item.payload is not None
        )
        if (
            history_keys != tuple(sorted(history_keys))
            or len({item.event_id for item in self.history}) != len(self.history)
            or any(item.ingestion_sequence > self.frontier.sequence for item in self.history)
            or any(item.event_id not in allowed for item in self.history)
            or history_bytes > MAX_FROZEN_HISTORY_BYTES
        ):
            raise _invalid_case()
        if self.task_statement is not None and (
            type(self.task_statement) is not RecordedTaskStatement
            or self.task_statement.ingestion_sequence > self.frontier.sequence
            or self.task_statement.source_event_id not in allowed
        ):
            raise _invalid_case()
        if self.task_title is not None and (
            type(self.task_title) is not str or not self.task_title
        ):
            raise _invalid_case()
        if any(member not in allowed for group in self.action_batches for member in group):
            raise _invalid_case()
        object.__setattr__(self, "allowed_ids", allowed)
        object.__setattr__(self, "coverage_by_ref", MappingProxyType(coverage))


_LEGACY_CASE_JSON_KEYS: Final = frozenset(
    {"projection", "frontier", "availability", "allowed_ids", "coverage_by_ref", "gaps"}
)
_CASE_JSON_KEYS: Final = _LEGACY_CASE_JSON_KEYS | frozenset(
    {"history", "history_availability", "history_omitted_before_count"}
)
# Emitted only when non-empty, so a case without a pending request keeps its exact bytes.
_OBSERVATION_CASE_JSON_KEYS: Final = _CASE_JSON_KEYS | frozenset({"observation_event_ids"})

# Emitted only when the prefix records a title or statement, so every case frozen before issue
# #908 keeps its exact bytes.
_TASK_CONTEXT_CASE_JSON_KEYS: Final = _CASE_JSON_KEYS | frozenset({"task_context"})
# Both optional additions at once: a pending missing-item request and a recorded task context.
_OBSERVATION_TASK_CONTEXT_CASE_JSON_KEYS: Final = _OBSERVATION_CASE_JSON_KEYS | frozenset(
    {"task_context"}
)
# Emitted only when one cooperative batch recorded two or more actions (tb4n5 follow-up), so every
# case without such a batch keeps its exact bytes. It may join any of the non-legacy key sets.
_ACTION_BATCHES_CASE_JSON_KEY: Final = "action_batches"


def _task_statement_to_json(statement: RecordedTaskStatement) -> dict[str, JsonValue]:
    value: dict[str, JsonValue] = {
        "ingestion_sequence": statement.ingestion_sequence,
        "source_event_id": statement.source_event_id,
        "source_family": statement.source_family,
        "text": statement.text,
    }
    if statement.equivalent_event_ids != (statement.source_event_id,):
        # Emitted only when an unchanged statement was recorded more than once, so every case
        # frozen with a single statement event keeps its exact bytes.
        value["equivalent_event_ids"] = list(statement.equivalent_event_ids)
    return value


def _task_context_to_json(case: DeterministicCase) -> dict[str, JsonValue]:
    statement = case.task_statement
    return {
        "task_statement": None if statement is None else _task_statement_to_json(statement),
        "task_title": case.task_title,
    }


def _task_context_from_json(value: JsonValue) -> tuple[RecordedTaskStatement | None, str | None]:
    source = _case_json_object(value, required=frozenset({"task_statement", "task_title"}))
    title = source["task_title"]
    if title is not None and type(title) is not str:
        raise _invalid_case()
    raw_statement = source["task_statement"]
    if raw_statement is None:
        return None, title
    base_keys = frozenset({"ingestion_sequence", "source_event_id", "source_family", "text"})
    statement = _case_json_object(raw_statement)
    keys = frozenset(statement)
    if keys not in {base_keys, base_keys | {"equivalent_event_ids"}}:
        raise _invalid_case()
    equivalent: tuple[EventId, ...] = ()
    if "equivalent_event_ids" in keys:
        raw_equivalent = _case_json_array(statement["equivalent_event_ids"])
        if len(raw_equivalent) < 2 or any(type(item) is not str for item in raw_equivalent):
            raise _invalid_case()
        equivalent = tuple(cast(EventId, item) for item in raw_equivalent)
    parsed = RecordedTaskStatement(
        text=cast(str, statement["text"]),
        source_event_id=cast(EventId, statement["source_event_id"]),
        source_family=cast(str, statement["source_family"]),
        ingestion_sequence=cast(int, statement["ingestion_sequence"]),
        equivalent_event_ids=equivalent,
    )
    if equivalent and parsed.equivalent_event_ids != equivalent:
        raise _invalid_case()
    return parsed, title


def _case_json_object(
    value: object,
    *,
    required: frozenset[str] | None = None,
) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise _invalid_case()
    source = cast(Mapping[object, object], value)
    keys = tuple(source)
    if any(type(key) is not str for key in keys):
        raise _invalid_case()
    typed = cast(Mapping[str, JsonValue], source)
    if required is not None and frozenset(cast(tuple[str, ...], keys)) != required:
        raise _invalid_case()
    return typed


def _case_json_array(value: object) -> tuple[JsonValue, ...]:
    if type(value) is not tuple:
        raise _invalid_case()
    return cast(tuple[JsonValue, ...], value)


def _basis_json_object(
    value: object,
    *,
    required: frozenset[str],
) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise _invalid_basis()
    source = cast(Mapping[object, object], value)
    keys = tuple(source)
    if any(type(key) is not str for key in keys):
        raise _invalid_basis()
    if frozenset(cast(tuple[str, ...], keys)) != required:
        raise _invalid_basis()
    return cast(Mapping[str, JsonValue], source)


def _basis_json_array(value: object) -> tuple[JsonValue, ...]:
    if type(value) is not tuple:
        raise _invalid_basis()
    return cast(tuple[JsonValue, ...], value)


def finding_basis_to_json(basis: FindingBasis) -> dict[str, JsonValue]:
    """Encode one complete finding basis without the lossy status projection."""

    if type(basis) is not FindingBasis:
        raise _invalid_basis()

    def encode_facts(facts: tuple[FindingFact, ...]) -> list[JsonValue]:
        return [
            {
                "fact_code": fact.fact_code,
                "subject_refs": list(fact.subject_refs),
            }
            for fact in facts
        ]

    return {
        "rule_id": basis.rule_id,
        "observed_facts": encode_facts(basis.observed_facts),
        "required_but_missing_facts": encode_facts(basis.required_but_missing_facts),
        "subject_state_relation": basis.subject_state_relation.value,
        "source_availability": basis.source_availability.value,
        "coverage_gaps": list(basis.coverage_gaps),
        "supporting_refs": list(basis.supporting_refs),
    }


def finding_basis_from_json(value: JsonValue) -> FindingBasis:
    """Decode and revalidate one complete, closed finding-basis JSON tree."""

    try:
        frozen = freeze_json(value)
        source = _basis_json_object(
            frozen,
            required=frozenset(
                {
                    "rule_id",
                    "observed_facts",
                    "required_but_missing_facts",
                    "subject_state_relation",
                    "source_availability",
                    "coverage_gaps",
                    "supporting_refs",
                }
            ),
        )

        def decode_facts(raw_facts: JsonValue) -> tuple[FindingFact, ...]:
            facts: list[FindingFact] = []
            for raw_fact in _basis_json_array(raw_facts):
                fact_source = _basis_json_object(
                    raw_fact,
                    required=frozenset({"fact_code", "subject_refs"}),
                )
                facts.append(
                    FindingFact(
                        fact_code=cast(str, fact_source["fact_code"]),
                        subject_refs=cast(
                            tuple[FindingBasisRef, ...],
                            _basis_json_array(fact_source["subject_refs"]),
                        ),
                    )
                )
            return tuple(facts)

        return FindingBasis(
            rule_id=cast(str, source["rule_id"]),
            observed_facts=decode_facts(source["observed_facts"]),
            required_but_missing_facts=decode_facts(source["required_but_missing_facts"]),
            subject_state_relation=SubjectStateRelation(
                cast(str, source["subject_state_relation"])
            ),
            source_availability=FrozenSourceAvailability(cast(str, source["source_availability"])),
            coverage_gaps=cast(
                tuple[str, ...],
                _basis_json_array(source["coverage_gaps"]),
            ),
            supporting_refs=cast(
                tuple[FindingBasisRef, ...],
                _basis_json_array(source["supporting_refs"]),
            ),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise _invalid_basis() from exc


def deterministic_case_to_json(case: DeterministicCase) -> dict[str, JsonValue]:
    """Encode one frozen local case as its exact canonical JSON tree."""

    if type(case) is not DeterministicCase:
        raise _invalid_case()
    coverage: dict[str, JsonValue] = {
        str(ref): coverage_to_json(case.coverage_by_ref[ref])
        for ref in sorted(case.coverage_by_ref, key=_ascii_key)
    }
    return {
        "projection": projection_snapshot(case.projection),
        "frontier": case.frontier.as_wire(),
        "availability": {
            "unavailable_event_ids": list(case.availability.unavailable_event_ids),
            "unavailable_captured_objects": [
                {
                    "source_event_id": item.source_event_id,
                    "object_id": item.object_id,
                }
                for item in case.availability.unavailable_captured_objects
            ],
        },
        "allowed_ids": list(sorted(case.allowed_ids, key=_ascii_key)),
        "coverage_by_ref": coverage,
        "gaps": [
            {
                "marker": gap.marker,
                "code": gap.code,
                "subject_refs": list(gap.subject_refs),
            }
            for gap in case.gaps
        ],
        "history": [
            {
                "event_id": item.event_id,
                "schema_name": item.schema_name,
                "schema_version": item.schema_version,
                "ingestion_sequence": item.ingestion_sequence,
                "occurred_at": item.occurred_at,
                "payload_digest": item.payload_digest,
                "content_visibility": item.content_visibility,
                "payload": item.payload,
                **(
                    {}
                    if item.accepted_at is None
                    else {
                        "accepted_at": item.accepted_at,
                        "occurred_at_consistency": item.occurred_at_consistency,
                    }
                ),
                **(
                    {}
                    if item.occurred_at_source is None
                    else {"occurred_at_source": item.occurred_at_source}
                ),
            }
            for item in case.history
        ],
        "history_availability": case.history_availability,
        "history_omitted_before_count": case.history_omitted_before_count,
        **(
            {}
            if not case.observation_event_ids
            else {
                "observation_event_ids": [
                    str(item) for item in sorted(case.observation_event_ids, key=_ascii_key)
                ]
            }
        ),
        **(
            {"task_context": cast(JsonValue, _task_context_to_json(case))}
            if case.task_statement is not None or case.task_title is not None
            else {}
        ),
        **({"verification_advisory": True} if case.verification_advisory else {}),
        **(
            {
                "verification_freshness": cast(
                    JsonValue, [row.to_json() for row in case.verification_freshness]
                )
            }
            if case.verification_freshness is not None
            else {}
        ),
        **(
            {"workspace_verification_edit_frontier": case.workspace_verification_edit_frontier}
            if case.workspace_verification_edit_frontier
            else {}
        ),
        **(
            {"verification_unchanged_action_ids": list(case.verification_unchanged_action_ids)}
            if case.verification_unchanged_action_ids
            else {}
        ),
        **(
            {
                _ACTION_BATCHES_CASE_JSON_KEY: [
                    [str(member) for member in group] for group in case.action_batches
                ]
            }
            if case.action_batches
            else {}
        ),
    }


def deterministic_case_from_json(value: JsonValue) -> DeterministicCase:
    """Decode and revalidate one exact local-case JSON tree."""

    try:
        frozen = freeze_json(value)
        source = _case_json_object(frozen)
        source_keys = frozenset(source)
        advisory = source.get("verification_advisory", False)
        source_keys -= {"verification_advisory"}
        freshness = None
        if "verification_freshness" in source:
            freshness_rows: list[VerificationFreshness] = []
            for raw in _case_json_array(source["verification_freshness"]):
                row = _case_json_array(raw)
                if (
                    len(row) != 6
                    or type(row[0]) is not str
                    or type(row[1]) is not str
                    or type(row[4]) is not str
                    or (row[5] is not None and type(row[5]) is not str)
                ):
                    raise _invalid_case()
                texts = _case_json_array(row[2])
                if any(type(text) is not str for text in texts):
                    raise _invalid_case()
                freshness_rows.append(
                    VerificationFreshness(
                        result_id(row[0]),
                        row[1],
                        cast(tuple[str, ...], tuple(texts)),
                        tuple(event_id(cast(str, ref)) for ref in _case_json_array(row[3])),
                        row[4],
                        row[5],
                    )
                )
            freshness = tuple(freshness_rows)
            source_keys -= {"verification_freshness"}
        workspace_edit = source.get("workspace_verification_edit_frontier", 0)
        source_keys -= {"workspace_verification_edit_frontier"}
        unchanged_actions = tuple(
            action_id(cast(str, value))
            for value in _case_json_array(source.get("verification_unchanged_action_ids", ()))
        )
        source_keys -= {"verification_unchanged_action_ids"}
        action_batches: tuple[tuple[EventId, ...], ...] = ()
        if _ACTION_BATCHES_CASE_JSON_KEY in source_keys:
            source_keys = source_keys - {_ACTION_BATCHES_CASE_JSON_KEY}
            if source_keys == _LEGACY_CASE_JSON_KEYS:
                raise _invalid_case()
            raw_batches = _case_json_array(source[_ACTION_BATCHES_CASE_JSON_KEY])
            if not raw_batches:
                raise _invalid_case()
            action_batches = tuple(
                tuple(event_id(cast(str, member)) for member in _case_json_array(group))
                for group in raw_batches
            )
        if source_keys not in {
            _CASE_JSON_KEYS,
            _LEGACY_CASE_JSON_KEYS,
            _OBSERVATION_CASE_JSON_KEYS,
            _TASK_CONTEXT_CASE_JSON_KEYS,
            _OBSERVATION_TASK_CONTEXT_CASE_JSON_KEYS,
        }:
            raise _invalid_case()
        availability_source = _case_json_object(
            source["availability"],
            required=frozenset({"unavailable_event_ids", "unavailable_captured_objects"}),
        )
        unavailable_objects: list[UnavailableCapturedObject] = []
        for raw_object in _case_json_array(availability_source["unavailable_captured_objects"]):
            object_source = _case_json_object(
                raw_object,
                required=frozenset({"source_event_id", "object_id"}),
            )
            unavailable_objects.append(
                UnavailableCapturedObject(
                    source_event_id=cast(EventId, object_source["source_event_id"]),
                    object_id=cast(ObjectId, object_source["object_id"]),
                )
            )
        availability = CaseAvailabilityFacts(
            unavailable_event_ids=cast(
                tuple[EventId, ...],
                _case_json_array(availability_source["unavailable_event_ids"]),
            ),
            unavailable_captured_objects=tuple(unavailable_objects),
        )
        coverage_source = _case_json_object(source["coverage_by_ref"])
        coverage = {
            _basis_ref(raw_ref): coverage_from_json(raw_coverage)
            for raw_ref, raw_coverage in coverage_source.items()
        }
        allowed_refs = tuple(_basis_ref(item) for item in _case_json_array(source["allowed_ids"]))
        if allowed_refs != _sorted_unique(allowed_refs):
            raise _invalid_case()
        gaps: list[CaseGap] = []
        for raw_gap in _case_json_array(source["gaps"]):
            gap_source = _case_json_object(
                raw_gap,
                required=frozenset({"marker", "code", "subject_refs"}),
            )
            gaps.append(
                CaseGap(
                    marker=cast(str, gap_source["marker"]),
                    code=cast(str, gap_source["code"]),
                    subject_refs=cast(
                        tuple[PublicSubjectRef, ...],
                        _case_json_array(gap_source["subject_refs"]),
                    ),
                )
            )
        history: list[FrozenHistoryEvent] = []
        history_availability: Literal["available", "not_recorded"] = "not_recorded"
        history_omitted_before_count = 0
        task_statement: RecordedTaskStatement | None = None
        task_title: str | None = None
        if "task_context" in source_keys:
            task_statement, task_title = _task_context_from_json(source["task_context"])
        if source_keys != _LEGACY_CASE_JSON_KEYS:
            for raw_item in _case_json_array(source["history"]):
                item = _case_json_object(raw_item)
                legacy_history_keys = frozenset(
                    {
                        "event_id",
                        "schema_name",
                        "schema_version",
                        "ingestion_sequence",
                        "occurred_at",
                        "payload_digest",
                        "content_visibility",
                        "payload",
                    }
                )
                current_history_keys = legacy_history_keys | frozenset(
                    {"accepted_at", "occurred_at_consistency"}
                )
                # Issue #1084 (review R7): a service-recorded event time is labelled.
                labelled_history_keys = current_history_keys | frozenset({"occurred_at_source"})
                if frozenset(item) not in {
                    legacy_history_keys,
                    current_history_keys,
                    labelled_history_keys,
                }:
                    raise _invalid_case()
                source_label = item.get("occurred_at_source")
                if source_label is not None and source_label != "service_clock":
                    raise _invalid_case()
                accepted_at = cast(str, item["accepted_at"]) if "accepted_at" in item else None
                consistency = (
                    cast(
                        Literal[
                            "within_forward_skew_allowance",
                            "ahead_of_forward_skew_allowance",
                        ],
                        item["occurred_at_consistency"],
                    )
                    if "occurred_at_consistency" in item
                    else None
                )
                history.append(
                    FrozenHistoryEvent(
                        event_id=cast(EventId, item["event_id"]),
                        schema_name=cast(str, item["schema_name"]),
                        schema_version=cast(str, item["schema_version"]),
                        ingestion_sequence=cast(int, item["ingestion_sequence"]),
                        occurred_at=cast(str, item["occurred_at"]),
                        accepted_at=accepted_at,
                        occurred_at_consistency=consistency,
                        payload_digest=cast(str, item["payload_digest"]),
                        content_visibility=cast(
                            Literal[
                                "available",
                                "not_recorded",
                                "not_selected",
                                "redacted_never_send",
                            ],
                            item["content_visibility"],
                        ),
                        payload=item["payload"],
                        occurred_at_source=(
                            "service_clock" if source_label == "service_clock" else None
                        ),
                    )
                )
            history_availability = cast(
                Literal["available", "not_recorded"], source["history_availability"]
            )
            history_omitted_before_count = cast(int, source["history_omitted_before_count"])
        return DeterministicCase(
            projection=projection_from_snapshot(source["projection"]),
            frontier=frontier_from_json(source["frontier"]),
            availability=availability,
            allowed_ids=frozenset(allowed_refs),
            coverage_by_ref=coverage,
            gaps=tuple(gaps),
            history=tuple(history),
            history_availability=history_availability,
            history_omitted_before_count=history_omitted_before_count,
            observation_event_ids=frozenset(
                event_id(cast(str, value))
                for value in _case_json_array(source.get("observation_event_ids", ()))
            ),
            task_statement=task_statement,
            task_title=task_title,
            action_batches=action_batches,
            workspace_verification_edit_frontier=cast(int, workspace_edit),
            verification_unchanged_action_ids=unchanged_actions,
            verification_freshness=freshness,
            verification_advisory=cast(bool, advisory),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise _invalid_case() from exc


def _projection_records(
    projection: ProjectionState,
) -> tuple[ProjectionRecord[object], ...]:
    records: list[ProjectionRecord[object]] = []
    for collection in (
        projection.plans,
        projection.obligations,
        projection.decisions,
        projection.assignments,
        projection.actions,
        projection.results,
        projection.evidence,
        projection.claims,
        projection.findings,
        projection.responses,
        projection.coordination_contexts,
        projection.coordination_declarations,
        projection.coordination_dispositions,
    ):
        records.extend(cast(Iterable[ProjectionRecord[object]], collection.values()))
    return tuple(records)


def _logical_sources(projection: ProjectionState) -> dict[FindingBasisRef, EventId]:
    sources: dict[FindingBasisRef, EventId] = {}
    for logical, record in projection.obligations.items():
        sources[logical] = record.source_event_id
    for logical, record in projection.actions.items():
        sources[logical] = record.source_event_id
    for logical, record in projection.results.items():
        sources[logical] = record.source_event_id
    for logical, record in projection.evidence.items():
        sources[logical] = record.source_event_id
    for logical, record in projection.claims.items():
        sources[logical] = record.source_event_id
    for logical, record in projection.findings.items():
        sources[logical] = record.source_event_id
    for logical, record in projection.coordination_contexts.items():
        sources[logical] = record.source_event_id
    for logical, record in projection.coordination_declarations.items():
        sources[logical] = record.source_event_id
    for logical, record in projection.coordination_dispositions.items():
        sources[logical] = record.source_event_id
    return sources


def _cap[T: Enum](value: T, limit: T, order: Mapping[T, int]) -> T:
    return value if order[value] <= order[limit] else limit


def _weaken_ref_coverage(
    base: Coverage,
    *,
    redacted_event: bool,
    unavailable_event: bool,
    redacted_object: bool,
    unavailable_object: bool,
    missing_ref: bool,
    unknown_event: bool,
    evidence_provenance_gaps: frozenset[str] = frozenset(),
) -> Coverage:
    observation = base.artifact_observation
    immutability = base.evidence_immutability
    freshness = base.ledger_freshness
    gaps = set(base.known_gaps)

    if redacted_event:
        observation = ArtifactObservation.PUBLISHED_ONLY
        immutability = _cap(
            immutability,
            EvidenceImmutability.METADATA_ONLY,
            EVIDENCE_IMMUTABILITY_ORDER,
        )
        freshness = _cap(
            freshness,
            LedgerFreshness.REDACTED_GAP,
            LEDGER_FRESHNESS_ORDER,
        )
        gaps.add("redacted_event")
    if unavailable_event:
        observation = ArtifactObservation.PUBLISHED_ONLY
        immutability = _cap(
            immutability,
            EvidenceImmutability.METADATA_ONLY,
            EVIDENCE_IMMUTABILITY_ORDER,
        )
        freshness = _cap(
            freshness,
            LedgerFreshness.REDACTED_GAP,
            LEDGER_FRESHNESS_ORDER,
        )
        gaps.add("event_payload_unavailable")
    if redacted_object:
        observation = ArtifactObservation.PUBLISHED_ONLY
        immutability = _cap(
            immutability,
            EvidenceImmutability.CONTENT_DIGEST,
            EVIDENCE_IMMUTABILITY_ORDER,
        )
        freshness = _cap(
            freshness,
            LedgerFreshness.REDACTED_GAP,
            LEDGER_FRESHNESS_ORDER,
        )
        gaps.add("redacted_object")
    if unavailable_object:
        observation = ArtifactObservation.PUBLISHED_ONLY
        immutability = _cap(
            immutability,
            EvidenceImmutability.CONTENT_DIGEST,
            EVIDENCE_IMMUTABILITY_ORDER,
        )
        freshness = _cap(
            freshness,
            LedgerFreshness.REDACTED_GAP,
            LEDGER_FRESHNESS_ORDER,
        )
        gaps.add("captured_object_unavailable")
    if missing_ref:
        freshness = _cap(
            freshness,
            LedgerFreshness.PARTIAL,
            LEDGER_FRESHNESS_ORDER,
        )
        gaps.add("missing_ref")
    if unknown_event:
        freshness = _cap(
            freshness,
            LedgerFreshness.PARTIAL,
            LEDGER_FRESHNESS_ORDER,
        )
        gaps.add("unknown_event")
    gaps.update(evidence_provenance_gaps)
    if len(gaps) > MAX_REF_LIST:
        raise _invalid_case()

    return Coverage(
        publication_channels=base.publication_channels,
        authorship_assurance=base.authorship_assurance,
        artifact_observation=observation,
        evidence_immutability=immutability,
        ledger_freshness=freshness,
        check_types=base.check_types,
        known_gaps=_sorted_unique(gaps),
    )


def _add_gap(
    gaps: dict[str, CaseGap],
    marker: str,
    code: str,
    refs: tuple[PublicSubjectRef, ...],
) -> None:
    gap = CaseGap(marker, code, refs)
    previous = gaps.get(marker)
    if previous is not None and previous != gap:
        raise _invalid_case()
    gaps[marker] = gap


def _projection_gap(
    marker: str,
    index: ReplayIndex,
) -> CaseGap:
    if marker.startswith("unknown_event:"):
        parts = marker.split(":", 2)
        if len(parts) != 3:
            raise _invalid_case()
        return CaseGap(marker, "unknown_event", (event_id(parts[1]),))
    if marker.startswith("redacted_event:"):
        target = event_id(marker.removeprefix("redacted_event:"))
        return CaseGap(marker, "redacted_event", (target,))
    if marker.startswith("redacted_object:"):
        target = object_id(marker.removeprefix("redacted_object:"))
        root = index.redaction_root_by_object.get(target)
        if root is None:
            raise _invalid_case()
        return CaseGap(marker, "redacted_object", (root,))
    if marker.startswith("missing_ref:"):
        parts = marker.split(":", 2)
        if len(parts) != 3:
            raise _invalid_case()
        return CaseGap(marker, "missing_ref", (event_id(parts[1]),))
    raise _invalid_case()


def _build_replay_index(records: tuple[LedgerRecord, ...]) -> ReplayIndex:
    return build_replay_index(records)


def _expected_unavailable_events(
    projection: ProjectionState,
    records_by_event: Mapping[EventId, LedgerRecord],
    redacted_events: frozenset[EventId],
) -> tuple[EventId, ...]:
    """Return the exact source events a readable case must declare unavailable."""

    expected_unavailable: set[EventId] = set()
    for record in _projection_records(projection):
        if record.payload is not None:
            continue
        envelope = records_by_event.get(record.source_event_id)
        if type(envelope) is not AcceptedEvent:
            raise _invalid_case()
        accepted = envelope
        recorded_redaction = record.source_event_id in redacted_events or accepted.redaction in {
            RedactionState.LOGICALLY_REDACTED,
            RedactionState.ERASED_CLAIMED,
        }
        if recorded_redaction:
            continue
        if accepted.redaction not in {RedactionState.PRESENT, RedactionState.KEY_UNAVAILABLE}:
            raise _invalid_case()
        expected_unavailable.add(record.source_event_id)
    return _sorted_unique(expected_unavailable)


def _validate_availability(
    projection: ProjectionState,
    records_by_event: Mapping[EventId, LedgerRecord],
    index: ReplayIndex,
    redacted_events: frozenset[EventId],
    redacted_objects: frozenset[ObjectId],
    availability: CaseAvailabilityFacts,
) -> None:
    if availability.unavailable_event_ids != _expected_unavailable_events(
        projection, records_by_event, redacted_events
    ):
        raise _invalid_case()

    for unavailable in availability.unavailable_captured_objects:
        if (
            unavailable.object_id in redacted_objects
            or unavailable.object_id in index.redaction_root_by_object
        ):
            raise _invalid_case()
        associations = index.evidence_sources_by_object.get(unavailable.object_id, ())
        matched = tuple(
            item for item in associations if item.source_event_id == unavailable.source_event_id
        )
        if len(matched) != 1:
            raise _invalid_case()
        association = matched[0]
        current = projection.evidence.get(association.evidence_id)
        if (
            current is None
            or current.source_event_id != unavailable.source_event_id
            or current.payload is None
            or current.payload.captured_object_id != unavailable.object_id
            or not current.object_available
            or current.redacted_object_id is not None
        ):
            raise _invalid_case()


def completion_scope_gap(projection: ProjectionState) -> CaseGap | None:
    """Return the one plan-bound completion-scope gap for a readable case, if applicable."""

    completion_claim_present = any(
        record.payload is not None and record.payload.claim_kind is ClaimKind.COMPLETION
        for _, record in effective_claim_items(projection)
    )
    plan_scope = current_plan_scope(projection.plans, projection.coverage_gaps)
    if not (
        completion_claim_present
        and plan_scope.has_plan
        and plan_scope.readable
        and plan_scope.declared_obligation_count == 0
    ):
        return None
    code = (
        COMPLETION_SCOPE_UNDECLARED_GAP
        if plan_scope.no_obligations_reason is None
        else COMPLETION_SCOPE_DECLARED_NONE_GAP
    )
    source_event = plan_scope.current_plan_event_id
    if source_event is None:  # pragma: no cover - readable plan state owns its source event
        raise _invalid_case()
    # Keep the marker bound to the declaration event for deterministic identity, but do not make
    # the plan event a finding subject. This is a coverage limitation, not ledger-staleness and
    # deliberately does not create a FindingKind.
    return CaseGap(f"{code}:{source_event}", code, ())


def build_deterministic_case(
    projection: ProjectionState,
    records: Iterable[LedgerRecord],
    availability: CaseAvailabilityFacts,
    *,
    _projection_validated: bool = False,
    _replay_index: ReplayIndex | None = None,
    service_clock_events: frozenset[str] = frozenset(),
) -> DeterministicCase:
    """Freeze one exact accepted prefix into the pure local-policy input.

    ``service_clock_events`` names the events whose ``occurred_at`` the service recorded because
    their publish omitted it (issue #1084, review R7); their frozen history rows say so.

    ``_projection_validated`` and ``_replay_index`` are internal trusted-snapshot seams. The
    SQLite/memory append path and exact-frontier application snapshot loader already validate the
    immutable prefix and pass its projection (and, when available, reverse index),
    so the case builder does not replay or rebuild it a second
    time. Public callers keep the default genesis replay and therefore retain the full standalone
    validation contract.
    """

    if type(projection) is not ProjectionState or type(availability) is not CaseAvailabilityFacts:
        raise _invalid_case()
    accepted_prefix = tuple(records)
    if any(type(record) not in {AcceptedEvent, UnknownEvent} for record in accepted_prefix):
        raise _invalid_case()
    if _replay_index is not None and not _projection_validated:
        raise _invalid_case()
    if not _projection_validated:
        rebuilt = replay(accepted_prefix)
        if rebuilt != projection:
            raise _invalid_case()
    if _replay_index is None:
        index = _build_replay_index(accepted_prefix)
    else:
        try:
            validate_replay_index(_replay_index, accepted_prefix)
        except ValueError as exc:
            raise _invalid_case() from exc
        index = _replay_index
    if index.frontier != projection.frontier or index.head_digest != projection.head_digest:
        raise _invalid_case()
    records_by_event = {record.event_id: record for record in accepted_prefix}
    if len(records_by_event) != len(accepted_prefix):
        raise _invalid_case()
    pending_missing = projection.pending_missing_for_assessment

    projection_redacted_events: set[EventId] = set()
    redacted_objects: set[ObjectId] = set()
    missing_sources: set[EventId] = set()
    unknown_events: set[EventId] = set()
    gaps: dict[str, CaseGap] = {}
    from finishup.kernel.claim_verification import (
        UNRESOLVED_VERIFICATION_GAP,
        unresolved_verification_obligations,
    )
    from finishup.kernel.command_attempts import closure_command_gaps

    for obligation_ref in unresolved_verification_obligations(projection, accepted_prefix):
        _add_gap(
            gaps,
            f"{UNRESOLVED_VERIFICATION_GAP}:{obligation_ref}",
            UNRESOLVED_VERIFICATION_GAP,
            (obligation_ref,),
        )
    for obligation_ref, code in closure_command_gaps(projection, accepted_prefix):
        _add_gap(gaps, f"{code}:{obligation_ref}", code, (obligation_ref,))
    for marker in projection.coverage_gaps:
        gap = _projection_gap(marker, index)
        _add_gap(gaps, gap.marker, gap.code, gap.subject_refs)
        if gap.code == "redacted_event":
            projection_redacted_events.add(event_id(gap.subject_refs[0]))
        elif gap.code == "redacted_object":
            redacted_objects.add(object_id(marker.removeprefix("redacted_object:")))
        elif gap.code == "missing_ref":
            missing_sources.add(event_id(gap.subject_refs[0]))
        elif gap.code == "unknown_event":
            unknown_events.add(event_id(gap.subject_refs[0]))

    # Two bounded relation codes, independent of the number of claims/obligations.
    # No subjects here: this is completion coverage, not a ledger-staleness finding.
    for code in completion_scope_codes(projection):
        _add_gap(gaps, code, code, ())

    scope_gap = completion_scope_gap(projection)
    if scope_gap is not None:
        _add_gap(
            gaps,
            scope_gap.marker,
            scope_gap.code,
            scope_gap.subject_refs,
        )

    # Plan drift is a bounded advisory derived from the same accepted prefix.  Keep it in the
    # frozen case so a resumed check and a receipt replay disclose the same signal, while the
    # check/receipt conclusion paths explicitly treat these codes as non-blocking diagnostics.
    for code in plan_drift_signals(projection, accepted_prefix).codes:
        _add_gap(gaps, code, code, ())

    # Task facts (#977): what hook observations and the ledger establish about the task's own
    # work. Frozen with the case so a resumed check and a receipt replay disclose the same facts.
    from finishup.kernel.task_facts import (
        observed_event_ids_from_records,
        task_fact_signals,
        verification_unchanged_actions,
        workspace_verification_edits,
    )
    from finishup.kernel.verification_freshness import verification_freshness

    freshness = verification_freshness(projection, accepted_prefix)
    for code, obligation in task_fact_signals(projection, accepted_prefix).markers:
        if obligation is None:
            _add_gap(gaps, code, code, ())
        else:
            _add_gap(gaps, f"{code}:{obligation}", code, (obligation,))

    relevant_evidence: set[EvidenceId] = set()
    relevant_results: set[ResultId] = set()
    for _, record in effective_claim_items(projection):
        if record.payload is not None:
            relevant_evidence.update(
                evidence_id(ref) for ref in record.payload.supporting_refs if ref.startswith("evd_")
            )
            relevant_results.update(
                result_id(ref) for ref in record.payload.supporting_refs if ref.startswith("res_")
            )
            if type(record.payload) is ClaimRecordedPayloadV1_1:
                relevant_results.update(record.payload.limitation_refs)
    for record in projection.obligations.values():
        if record.payload is not None:
            relevant_evidence.update(
                evidence_id(ref)
                for ref in record.payload.resolution_evidence_refs
                if ref.startswith("evd_")
            )
            relevant_results.update(
                result_id(ref)
                for ref in record.payload.resolution_evidence_refs
                if ref.startswith("res_")
            )
    for record in projection.responses.values():
        if record.payload is not None:
            relevant_evidence.update(
                evidence_id(ref) for ref in record.payload.evidence_refs if ref.startswith("evd_")
            )
            relevant_results.update(
                result_id(ref) for ref in record.payload.evidence_refs if ref.startswith("res_")
            )
    for result_ref in relevant_results:
        result_record = projection.results.get(result_ref)
        if result_record is not None and result_record.payload is not None:
            relevant_evidence.update(result_record.payload.evidence_refs)
    for evidence_ref in sorted(relevant_evidence, key=lambda value: str(value).encode("ascii")):
        record = projection.evidence.get(evidence_ref)
        if record is None or record.payload is None:
            continue
        payload = record.payload
        if payload.content_digest is None:
            continue
        if payload.digest_binding is None:
            code = "evidence_digest_subject_legacy_unknown"
        elif payload.digest_binding.content_availability is EvidenceContentAvailability.DIGEST_ONLY:
            code = "evidence_content_digest_only"
        elif payload.digest_binding.content_availability is EvidenceContentAvailability.WITHHELD:
            code = "evidence_content_withheld"
        else:
            continue
        marker = f"{code}:{record.source_event_id}"
        _add_gap(gaps, marker, code, (record.source_event_id,))

    current_sources = {record.source_event_id for record in _projection_records(projection)}
    envelope_redacted_events: set[EventId] = set()
    for source_event in current_sources:
        envelope = records_by_event.get(source_event)
        if type(envelope) is not AcceptedEvent:
            raise _invalid_case()
        accepted = envelope
        if accepted.redaction in {
            RedactionState.LOGICALLY_REDACTED,
            RedactionState.ERASED_CLAIMED,
        }:
            envelope_redacted_events.add(source_event)
            marker = f"redacted_event:{source_event}"
            _add_gap(gaps, marker, "redacted_event", (source_event,))
    redacted_events = frozenset(projection_redacted_events | envelope_redacted_events)

    _validate_availability(
        projection,
        records_by_event,
        index,
        redacted_events,
        frozenset(redacted_objects),
        availability,
    )
    unavailable_events = frozenset(availability.unavailable_event_ids)
    unavailable_objects = {
        (item.source_event_id, item.object_id) for item in availability.unavailable_captured_objects
    }
    for source_event in availability.unavailable_event_ids:
        _add_gap(
            gaps,
            f"unavailable_event:{source_event}",
            "event_payload_unavailable",
            (source_event,),
        )
    for item in availability.unavailable_captured_objects:
        _add_gap(
            gaps,
            f"unavailable_captured_object:{item.source_event_id}:{item.object_id}",
            "captured_object_unavailable",
            (item.source_event_id,),
        )

    # A hook result whose unknown outcome the host's stream later supplied for the same action
    # no longer leaves `host_outcome_unavailable` in the case: the outcome is recorded (#1001).
    # Only service-derived hook observations take part on either side (ADR-022 decision 2 keeps
    # `hook_observed` unselectable by cooperative requests), so an agent-published result can
    # neither be superseded nor supersede.
    def _hook_observed(source_event: EventId) -> bool:
        record = records_by_event.get(source_event)
        return record is not None and PublicationChannel.HOOK_OBSERVED in set(
            record.coverage.publication_channels
        )

    superseded_sources = {
        projection.results[result].source_event_id
        for result in superseded_unknown_results(projection.results, include=_hook_observed)
    }
    for record in accepted_prefix:
        for known_gap in record.coverage.known_gaps:
            if known_gap == HOST_OUTCOME_UNAVAILABLE_GAP and record.event_id in superseded_sources:
                continue
            if known_gap not in gaps:
                _add_gap(gaps, known_gap, known_gap, ())

    material_records = tuple(
        record
        for record in accepted_prefix
        if type(record) is AcceptedEvent and record.schema.name in _SEMANTIC_HISTORY_FAMILIES
    )
    history_omitted_before_count = max(0, len(material_records) - MAX_FROZEN_HISTORY_EVENTS)
    retained_records = material_records[history_omitted_before_count:]
    history_bytes_remaining = MAX_FROZEN_HISTORY_BYTES
    newest_first: list[FrozenHistoryEvent] = []
    for record in reversed(retained_records):
        history_payload: JsonValue | None = None
        if record.redaction is not RedactionState.PRESENT:
            visibility: Literal[
                "available", "not_recorded", "not_selected", "redacted_never_send"
            ] = "redacted_never_send"
        elif record.event_id in unavailable_events or record.payload is None:
            visibility = "not_recorded"
        else:
            encoded_payload = encode_payload(record.payload)
            payload_bytes = len(canonical_encode(encoded_payload))
            if payload_bytes > history_bytes_remaining:
                visibility = "not_selected"
            else:
                visibility = "available"
                history_payload = encoded_payload
                history_bytes_remaining -= payload_bytes
        newest_first.append(
            FrozenHistoryEvent(
                event_id=record.event_id,
                schema_name=record.schema.name,
                schema_version=record.schema.version,
                ingestion_sequence=record.ledger.ingestion_sequence,
                occurred_at=record.occurred_at.wire,
                accepted_at=record.ledger.accepted_at.wire,
                occurred_at_consistency=occurred_at_consistency(
                    record.occurred_at, record.ledger.accepted_at
                ),
                payload_digest=record.projection_locator.canonical_payload_digest,
                content_visibility=visibility,
                payload=history_payload,
                occurred_at_source=(
                    "service_clock" if str(record.event_id) in service_clock_events else None
                ),
            )
        )
    history = tuple(reversed(newest_first))

    source_by_ref = _logical_sources(projection)
    cited_event_absent = False

    def add_event_ref(ref: EventId) -> None:
        if ref not in records_by_event:
            raise _invalid_case()
        source_by_ref[ref] = ref

    def add_optional_event_ref(ref: EventId) -> None:
        """Bind a cited event when it is in the prefix; otherwise note a bounded gap.

        Projection source events and the selected history window remain required. Finding
        and contradiction citations can name an event that was never appended — observation
        advice historically computed those IDs from envelopes. Receipts admit at most 64
        gaps, so many dangling citations collapse to one task-global missing_ref rather
        than one marker per finding.
        """

        nonlocal cited_event_absent
        if ref in records_by_event:
            source_by_ref[ref] = ref
            return
        cited_event_absent = True

    for record in _projection_records(projection):
        add_event_ref(record.source_event_id)
    for item in history:
        add_event_ref(item.event_id)
    # The event that recorded the current task statement is a citable source, so a reviewer can
    # name the stated requirement a plan or diff omits (issue #908).
    task_statement = current_task_statement(accepted_prefix)
    if task_statement is not None:
        add_event_ref(task_statement.source_event_id)
    if projection.latest_tested_state is not None:
        add_event_ref(projection.latest_tested_state.source_check_event_id)
    for contradiction in projection.contradictions.values():
        if contradiction.disputed_ref.startswith("evt_"):
            add_optional_event_ref(event_id(contradiction.disputed_ref))
    for record in projection.findings.values():
        if record.payload is not None:
            for ref in record.payload.subject_refs:
                if ref.startswith("evt_"):
                    add_optional_event_ref(event_id(ref))
    for gap in gaps.values():
        for ref in gap.subject_refs:
            if not ref.startswith("evt_"):
                continue
            cited = event_id(ref)
            if cited in records_by_event:
                source_by_ref[cited] = cited
    if cited_event_absent and not any(gap.code == "missing_ref" for gap in gaps.values()):
        _add_gap(gaps, "missing_ref:cited_event_absent", "missing_ref", ())

    redacted_object_by_evidence: dict[EvidenceId, set[ObjectId]] = {}
    for target in redacted_objects:
        for association in index.evidence_sources_by_object.get(target, ()):
            current = projection.evidence.get(association.evidence_id)
            if current is not None and current.source_event_id == association.source_event_id:
                redacted_object_by_evidence.setdefault(association.evidence_id, set()).add(target)
    unavailable_object_by_evidence: dict[EvidenceId, set[ObjectId]] = {}
    for source_event, target in unavailable_objects:
        for association in index.evidence_sources_by_object.get(target, ()):
            if association.source_event_id == source_event:
                unavailable_object_by_evidence.setdefault(association.evidence_id, set()).add(
                    target
                )

    gap_codes_by_root: dict[EventId, set[str]] = {}
    for gap in gaps.values():
        for root in gap.subject_refs:
            if root.startswith("evt_"):
                gap_codes_by_root.setdefault(event_id(root), set()).add(gap.code)

    coverage_by_ref: dict[FindingBasisRef, Coverage] = {}
    for ref, source_event in source_by_ref.items():
        source = records_by_event.get(source_event)
        if source is None:
            raise _invalid_case()
        coverage_by_ref[ref] = _weaken_ref_coverage(
            source.coverage,
            redacted_event=source_event in redacted_events,
            unavailable_event=source_event in unavailable_events,
            redacted_object=(
                (ref.startswith("evd_") and evidence_id(ref) in redacted_object_by_evidence)
                or "redacted_object" in gap_codes_by_root.get(source_event, set())
            ),
            unavailable_object=(
                (ref.startswith("evd_") and evidence_id(ref) in unavailable_object_by_evidence)
                or "captured_object_unavailable" in gap_codes_by_root.get(source_event, set())
            ),
            missing_ref=source_event in missing_sources,
            unknown_event=(
                ref.startswith("evt_")
                and event_id(ref) in unknown_events
                and type(source) is UnknownEvent
            ),
            evidence_provenance_gaps=frozenset(
                gap_codes_by_root.get(source_event, set())
                & {
                    "evidence_content_digest_only",
                    "evidence_content_withheld",
                    "evidence_digest_subject_legacy_unknown",
                }
            ),
        )

    if superseded_sources:
        for ref, source_event in source_by_ref.items():
            coverage = coverage_by_ref.get(ref)
            if (
                source_event in superseded_sources
                and coverage is not None
                and HOST_OUTCOME_UNAVAILABLE_GAP in coverage.known_gaps
            ):
                coverage_by_ref[ref] = replace(
                    coverage,
                    known_gaps=tuple(
                        gap for gap in coverage.known_gaps if gap != HOST_OUTCOME_UNAVAILABLE_GAP
                    ),
                )

    return DeterministicCase(
        projection=projection,
        frontier=Frontier(projection.frontier, projection.head_digest),
        availability=availability,
        allowed_ids=frozenset(source_by_ref),
        coverage_by_ref=coverage_by_ref,
        gaps=tuple(
            sorted(
                gaps.values(),
                key=lambda gap: (
                    _ascii_key(gap.marker),
                    tuple(_ascii_key(ref) for ref in gap.subject_refs),
                ),
            )
        ),
        history=history,
        history_availability="available",
        history_omitted_before_count=history_omitted_before_count,
        observation_event_ids=frozenset(
            record.event_id
            for record in accepted_prefix
            if pending_missing is not None
            and record.ledger.ingestion_sequence > pending_missing.source_frontier
            and is_observation_authored(record)
        ),
        task_statement=task_statement,
        task_title=recorded_task_title(accepted_prefix),
        action_batches=_cooperative_action_batches(projection, accepted_prefix),
        workspace_verification_edit_frontier=max(
            (
                position
                for position, _ in workspace_verification_edits(
                    projection, observed_event_ids_from_records(accepted_prefix), accepted_prefix
                )
            ),
            default=0,
        ),
        verification_unchanged_action_ids=tuple(
            sorted(verification_unchanged_actions(projection, accepted_prefix), key=str.encode)
        ),
        verification_freshness=freshness,
    )


# The cooperative publication channels a ``publish_work`` batch arrives on. Import and hook
# operations can carry many unrelated actions under one operation id, so they never form a batch.
_COOPERATIVE_BATCH_CHANNELS: Final = frozenset(
    {PublicationChannel.COOPERATIVE_MCP, PublicationChannel.LOCAL_CLI}
)


def _cooperative_action_batches(
    projection: ProjectionState, records: tuple[LedgerRecord, ...]
) -> tuple[tuple[EventId, ...], ...]:
    """Group the agent-published actions each cooperative ``publish_work`` batch recorded.

    One batch is one operation id. Only the event behind a projected action row counts, and only
    when the agent published it on a cooperative channel (never a service-stamped observation, an
    import or an engine row); only groups of two or more are kept: a lone action has no sibling.
    """

    action_events = {row.source_event_id for row in projection.actions.values()}
    grouped: dict[str, list[EventId]] = {}
    for record in records:
        if (
            type(record) is AcceptedEvent
            and record.event_id in action_events
            and record.schema.name == "action_recorded"
            and record.publication_channel in _COOPERATIVE_BATCH_CHANNELS
            and not is_observation_authored(record)
        ):
            grouped.setdefault(str(record.operation_id), []).append(record.event_id)
    batches = tuple(
        tuple(sorted(set(members), key=_ascii_key))
        for members in grouped.values()
        if len(set(members)) > 1
    )
    return tuple(sorted(batches, key=lambda group: _ascii_key(group[0])))


def healthy_storage_availability(
    projection: ProjectionState,
    records: Iterable[LedgerRecord],
    *,
    _replay_index: ReplayIndex | None = None,
) -> CaseAvailabilityFacts:
    """Return the availability facts this state carries when object storage is healthy.

    ``build_deterministic_case`` requires ``unavailable_event_ids`` to equal the payload rows
    the projection itself already records as unreadable, so an empty fact set is only correct
    for a fully readable state. Callers that must freeze a case without touching the object
    store — append-time receipt-capacity admission in particular — derive the facts here
    instead of asserting emptiness. No captured object is reported missing: a healthy store
    resolves every reference it holds.
    """

    accepted_prefix = tuple(records)
    records_by_event = {record.event_id: record for record in accepted_prefix}
    if _replay_index is None:
        index = _build_replay_index(accepted_prefix)
    else:
        if type(_replay_index) is not ReplayIndex:
            raise _invalid_case()
        index = _replay_index
    redacted: set[EventId] = set()
    for marker in projection.coverage_gaps:
        gap = _projection_gap(marker, index)
        if gap.code == "redacted_event":
            redacted.add(event_id(gap.subject_refs[0]))
    for record in accepted_prefix:
        if type(record) is AcceptedEvent and record.redaction in {
            RedactionState.LOGICALLY_REDACTED,
            RedactionState.ERASED_CLAIMED,
        }:
            redacted.add(record.event_id)
    return CaseAvailabilityFacts(
        _expected_unavailable_events(projection, records_by_event, frozenset(redacted)), ()
    )


def case_coverage(case: DeterministicCase, *, semantic: bool = False) -> Coverage:
    """Fold every frozen material dependency and explicit case gap conservatively."""

    ordered = tuple(case.coverage_by_ref[key] for key in sorted(case.coverage_by_ref, key=str))
    if ordered:
        result = ordered[0]
        for coverage in ordered[1:]:
            result = weakest(result, coverage)
    else:
        result = coverage_for_channel(PublicationChannel.ENGINE_DERIVED)
    gaps = set(result.known_gaps)
    gaps.update(gap.code for gap in case.gaps)
    channels = set(result.publication_channels)
    channels.add(PublicationChannel.ENGINE_DERIVED)
    checks = set(result.check_types)
    checks.discard(CheckType.NONE)
    checks.add(CheckType.DETERMINISTIC)
    if semantic:
        checks.add(CheckType.SEMANTIC_MODEL_DERIVED)
    freshness = result.ledger_freshness
    if gaps and freshness is LedgerFreshness.CURRENT:
        freshness = LedgerFreshness.PARTIAL
    return replace(
        result,
        publication_channels=tuple(sorted(channels, key=lambda value: value.value.encode("ascii"))),
        ledger_freshness=freshness,
        check_types=tuple(sorted(checks, key=lambda value: value.value.encode("ascii"))),
        known_gaps=tuple(sorted(gaps, key=str.encode)),
    )


def _source_event_for_ref(case: DeterministicCase, ref: FindingBasisRef) -> EventId | None:
    if ref not in case.allowed_ids:
        return None
    if ref.startswith("evt_"):
        return event_id(ref)
    # Each logical family already owns an indexed map. Rebuilding all six maps for
    # each policy reference makes repeated lookups quadratic in the task size.
    match ref[:4]:
        case "obl_":
            record = case.projection.obligations.get(cast(ObligationId, ref))
        case "act_":
            record = case.projection.actions.get(cast(ActionId, ref))
        case "res_":
            record = case.projection.results.get(cast(ResultId, ref))
        case "evd_":
            record = case.projection.evidence.get(cast(EvidenceId, ref))
        case "clm_":
            record = case.projection.claims.get(cast(ClaimId, ref))
        case "fnd_":
            record = case.projection.findings.get(cast(FindingId, ref))
        case _:
            return None
    return None if record is None else record.source_event_id


def policy_public_root(
    case: DeterministicCase,
    ref: FindingBasisRef,
) -> PublicSubjectRef:
    validated = _basis_ref(ref)
    if validated not in case.allowed_ids:
        raise _invalid_policy()
    if validated.startswith("evt_"):
        return event_id(validated)
    if validated.startswith("obl_"):
        return obligation_id(validated)
    if validated.startswith("clm_"):
        return claim_id(validated)
    source = _source_event_for_ref(case, validated)
    if source is None:
        raise _invalid_policy()
    return source


def policy_source_availability(
    case: DeterministicCase,
    refs: Iterable[FindingBasisRef],
) -> FrozenSourceAvailability:
    values = tuple(refs)
    if any(ref not in case.allowed_ids for ref in values):
        return FrozenSourceAvailability.NOT_RECORDED
    coverages = tuple(case.coverage_by_ref[ref] for ref in values)
    if any(
        {"redacted_event", "redacted_object"} & set(coverage.known_gaps) for coverage in coverages
    ):
        return FrozenSourceAvailability.REDACTED_AT_SOURCE
    if any(
        {"event_payload_unavailable", "captured_object_unavailable"} & set(coverage.known_gaps)
        for coverage in coverages
    ):
        return FrozenSourceAvailability.UNAVAILABLE_AT_FREEZE
    return FrozenSourceAvailability.AVAILABLE


def _derived_finding_coverage(
    case: DeterministicCase,
    supporting_refs: tuple[FindingBasisRef, ...],
) -> Coverage:
    if not supporting_refs:
        raise _invalid_policy()
    try:
        current = case.coverage_by_ref[supporting_refs[0]]
        for ref in supporting_refs[1:]:
            current = weakest(current, case.coverage_by_ref[ref])
    except KeyError as exc:
        raise _invalid_policy() from exc
    channels = tuple(
        sorted(
            set(current.publication_channels) | {PublicationChannel.ENGINE_DERIVED},
            key=lambda item: _ascii_key(item.value),
        )
    )
    check_types = set(current.check_types) | {CheckType.DETERMINISTIC}
    check_types.discard(CheckType.NONE)
    return Coverage(
        publication_channels=channels,
        authorship_assurance=current.authorship_assurance,
        artifact_observation=current.artifact_observation,
        evidence_immutability=current.evidence_immutability,
        ledger_freshness=current.ledger_freshness,
        check_types=tuple(sorted(check_types, key=lambda item: _ascii_key(item.value))),
        known_gaps=current.known_gaps,
    )


def build_policy_assessment(
    case: DeterministicCase,
    policy: PolicyPack,
    kind: FindingKind,
    subject_refs: tuple[FindingBasisRef, ...],
    observed_facts: tuple[FindingFact, ...],
    required_but_missing_facts: tuple[FindingFact, ...] = (),
    *,
    subject_state_relation: SubjectStateRelation = SubjectStateRelation.UNKNOWN,
    source_availability: FrozenSourceAvailability = FrozenSourceAvailability.AVAILABLE,
) -> DeterministicAssessment:
    public_refs = cast(
        tuple[PublicSubjectRef, ...],
        _validated_ref_tuple(subject_refs, public_only=True),
    )
    if any(ref not in case.allowed_ids for ref in public_refs):
        raise _invalid_policy()
    ordered_observed = tuple(sorted(observed_facts, key=_fact_key))
    ordered_missing = tuple(sorted(required_but_missing_facts, key=_fact_key))
    supporting_refs = _sorted_unique(ref for fact in ordered_observed for ref in fact.subject_refs)
    coverage = _derived_finding_coverage(case, supporting_refs)
    basis = FindingBasis(
        rule_id=f"{policy.policy_id}/{kind.value}",
        observed_facts=ordered_observed,
        required_but_missing_facts=ordered_missing,
        subject_state_relation=subject_state_relation,
        source_availability=source_availability,
        coverage_gaps=coverage.known_gaps,
        supporting_refs=supporting_refs,
    )
    summary, detail = render_deterministic_finding_text(
        kind,
        public_refs,
        basis.coverage_gaps,
        basis.observed_facts,
    )
    priority, _ = FINDING_KIND_TRAITS[kind]
    candidate = CandidateFinding(
        kind=kind,
        origin=FindingOrigin.DETERMINISTIC,
        priority=priority,
        summary=summary,
        detail=detail,
        subject_refs=public_refs,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        subject_frontier=case.frontier,
        coverage=coverage,
        provenance=None,
    )
    return DeterministicAssessment(candidate, basis)


def build_test_edit_integrity_assessment(
    case: DeterministicCase,
    source_event_refs: tuple[EventId, ...],
    support_refs: tuple[EventId, ...],
) -> DeterministicAssessment:
    """Build the local finding for an unjustified pre-existing test edit.

    The public subjects are action source events; the same safe event identities stay in the basis
    as exact structural support. Neither side contains a captured path.
    """

    if not source_event_refs or not support_refs:
        raise _invalid_policy()
    facts = [FindingFact(PREEXISTING_TEST_EDIT_UNJUSTIFIED_FACT, support_refs)]
    statement = case.task_statement
    if statement is not None and statement.source_event_id in case.allowed_ids:
        # Name the statement event the repair obligation must cite, so the finding text spells
        # out the whole working sequence instead of sending the agent to look it up.
        facts.append(FindingFact(TASK_STATEMENT_RECORDED_FACT, (statement.source_event_id,)))
    return build_policy_assessment(
        case,
        PolicyPack(RESEARCH_EVIDENCE_POLICY_ID, RESEARCH_EVIDENCE_POLICY_VERSION),
        FindingKind.TASK_REQUIREMENT_UNMET,
        source_event_refs,
        tuple(facts),
    )


def build_task_statement_unmapped_assessment(
    case: DeterministicCase,
    *,
    workspace_changed: bool | None = None,
) -> DeterministicAssessment | None:
    """Raise the local finding for a task statement the plan does not decompose (TB4 pilot).

    The rule reads exact relations only, never statement, plan or obligation prose:

    * the effective plan declares obligations, none of which names an event that recorded the
      current statement content in ``source_refs`` (``task_statement_unmapped``); or
    * a completion claim stands on no plan or an explicit empty scope and no recorded
      no-material-work decision answers it (``task_statement_scope_empty``). Mid-task checks
      before any completion claim never raise this form. The decision answers it only when
      ``workspace_changed`` is ``False``: the caller's check-time change capture showed no changed
      path. A changed path or an unavailable capture (the default ``None``) fails closed.

    No statement and an unreadable plan raise nothing. The single public subject is the current
    statement event, so both forms share one issue identity across plan revisions until the
    request is mapped (or, for the empty form, answered by the decision).
    """

    from finishup.kernel.plan_drift import (
        task_statement_scope_empty_at_completion,
        task_statement_unmapped,
    )

    statement = case.task_statement
    if statement is None or statement.source_event_id not in case.allowed_ids:
        return None
    if task_statement_unmapped(case.projection, statement):
        fact = TASK_STATEMENT_UNMAPPED_FACT
    elif task_statement_scope_empty_at_completion(
        case.projection, statement, workspace_changed=workspace_changed
    ):
        fact = TASK_STATEMENT_SCOPE_EMPTY_FACT
    else:
        return None
    subject = (statement.source_event_id,)
    return build_policy_assessment(
        case,
        PolicyPack(RESEARCH_EVIDENCE_POLICY_ID, RESEARCH_EVIDENCE_POLICY_VERSION),
        FindingKind.TASK_REQUIREMENT_UNMET,
        subject,
        (FindingFact(fact, subject),),
        (FindingFact(STATEMENT_SOURCED_OBLIGATION_ABSENT_FACT, subject),),
    )


def run_deterministic_policies(
    case: DeterministicCase,
    policy: PolicyPack,
) -> DeterministicPolicyResult:
    """Run one closed built-in policy pack over an immutable local case."""

    if type(case) is not DeterministicCase or type(policy) is not PolicyPack:
        raise _invalid_policy()
    if (policy.policy_id, policy.policy_version) == (
        WORK_INTEGRITY_POLICY_ID,
        WORK_INTEGRITY_POLICY_VERSION,
    ):
        from finishup.kernel.policies.work_integrity import (
            WORK_INTEGRITY_FACT_CODES,
            WORK_INTEGRITY_POLICY_PACK,
            work_integrity_findings,
        )

        if (
            WORK_INTEGRITY_POLICY_ID != policy.policy_id
            or WORK_INTEGRITY_POLICY_VERSION != policy.policy_version
            or WORK_INTEGRITY_POLICY_PACK != policy
        ):
            raise _invalid_policy()
        facts = WORK_INTEGRITY_FACT_CODES
        rule_order: tuple[FindingKind, ...] = (
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
        )
        assessments = work_integrity_findings(case)
    elif (policy.policy_id, policy.policy_version) == (
        RESEARCH_EVIDENCE_POLICY_ID,
        RESEARCH_EVIDENCE_POLICY_VERSION,
    ):
        from finishup.kernel.policies.research_evidence import (
            RESEARCH_EVIDENCE_FACT_CODES,
            RESEARCH_EVIDENCE_POLICY_PACK,
            research_evidence_findings,
        )

        if (
            RESEARCH_EVIDENCE_POLICY_ID != policy.policy_id
            or RESEARCH_EVIDENCE_POLICY_VERSION != policy.policy_version
            or RESEARCH_EVIDENCE_POLICY_PACK != policy
        ):
            raise _invalid_policy()
        facts = RESEARCH_EVIDENCE_FACT_CODES
        rule_order = (
            FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
            FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT,
            FindingKind.MATERIAL_LIMITATION_OMITTED,
            FindingKind.QUESTIONABLE_FINDING_REJECTION,
        )
        assessments = research_evidence_findings(case)
    else:
        raise _invalid_policy()

    if type(assessments) is not tuple:
        raise _invalid_policy()
    ordinal = {kind: index for index, kind in enumerate(rule_order)}
    validated: list[DeterministicAssessment] = []
    seen: set[tuple[str, str, tuple[PublicSubjectRef, ...]]] = set()
    for assessment in assessments:
        if type(assessment) is not DeterministicAssessment:
            raise _invalid_policy()
        candidate = assessment.candidate
        basis = assessment.basis
        if (
            candidate.policy_id != policy.policy_id
            or candidate.policy_version != policy.policy_version
            or candidate.kind not in ordinal
            or any(
                fact.fact_code not in facts
                for fact in (*basis.observed_facts, *basis.required_but_missing_facts)
            )
            or any(ref not in case.allowed_ids for ref in basis.supporting_refs)
            or any(ref not in case.allowed_ids for ref in candidate.subject_refs)
            or candidate.coverage != _derived_finding_coverage(case, basis.supporting_refs)
        ):
            raise _invalid_policy()
        key = (candidate.policy_id, basis.rule_id, candidate.subject_refs)
        if key in seen:
            raise _invalid_policy()
        seen.add(key)
        validated.append(assessment)
    ordered = tuple(
        sorted(
            validated,
            key=lambda item: (
                ordinal[item.candidate.kind],
                tuple(_ascii_key(ref) for ref in item.candidate.subject_refs),
            ),
        )
    )
    return DeterministicPolicyResult(ordered)
