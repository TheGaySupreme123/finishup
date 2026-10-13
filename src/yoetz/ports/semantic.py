"""Bounded AI-powered review values and the optional evaluator port."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Final, Literal, Protocol, cast

from yoetz.domain.events import (
    EvidenceContentAvailability,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceKind,
)
from yoetz.domain.findings import (
    FINDING_KIND_TRAITS,
    CostFields,
    FindingKind,
    FindingOrigin,
    RuntimeAttemptEvidence,
    SamplingParams,
    SemanticFailureClass,
    SemanticProvenance,
    TokenUsage,
)
from yoetz.domain.values import (
    FindingId,
    Frontier,
    SubjectStateRelation,
    finding_id,
    validate_commitment,
    validate_sha256_digest,
)
from yoetz.kernel.deterministic_checks import (
    DeterministicAssessment,
    FindingFact,
    FrozenSourceAvailability,
)
from yoetz.kernel.policies.research_evidence import RESEARCH_EVIDENCE_FACT_CODES
from yoetz.kernel.policies.work_integrity import WORK_INTEGRITY_FACT_CODES
from yoetz.protocol.coverage import Coverage, EvidenceImmutability
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.ids import IdKind, validate_id
from yoetz.protocol.models import (
    MAX_MISSING_FOR_ASSESSMENT,
    MAX_MISSING_REASON_BYTES,
    MAX_MISSING_TARGET_REFS,
    MAX_REVIEW_ASSESSMENTS,
    MAX_REVIEW_CHALLENGES,
    MAX_REVIEW_CHANGE_OBSERVATIONS,
    MAX_REVIEW_EXCERPTS,
    MAX_REVIEW_FOLLOW_UP_ROUNDS,
    MAX_REVIEW_OMISSION_TOTAL,
    MAX_REVIEW_OMISSIONS,
    MAX_REVIEW_TEXT_BYTES,
    MAX_REVIEW_TIMELINE_ITEMS,
    MAX_SEMANTIC_CASE_BYTES,
    MAX_SEMANTIC_ITEM_BYTES,
    MISSING_FOR_ASSESSMENT_KINDS,
    VALID_SEMANTIC_REASONS,
    DataCategory,
    SemanticReason,
    SemanticStatus,
    validate_semantic_outcome,
)

if TYPE_CHECKING:
    from yoetz.domain.privacy import (  # pyright: ignore[reportMissingImports, reportUnknownVariableType]
        ApprovedProviderCase,  # pyright: ignore[reportUnknownVariableType]
        ReviewContextProfile,  # pyright: ignore[reportUnknownVariableType]
        ReviewSelectionPolicy,  # pyright: ignore[reportUnknownVariableType]
    )

__all__ = [
    "MAX_PRIOR_FINDING_ITEMS",
    "MAX_PRIOR_FINDING_REFS",
    "MAX_REVIEW_INPUT_SECTION_ITEMS",
    "MAX_SEMANTIC_CASE_ITEMS",
    "MAX_SEMANTIC_ITEM_SUBJECT_REFS",
    "PRIOR_FINDING_VERDICT_KINDS",
    "PriorFindingVerdict",
    "PriorFindingVerdictKind",
    "ChangeObservation",
    "Deadline",
    "ExcerptDigestProvenance",
    "ProviderAttemptProvenance",
    "ExternalRuntimeAuthority",
    "MissingForAssessment",
    "RuntimeAttemptEvidence",
    "ReviewAssessment",
    "ReviewAssessmentSkipped",
    "ReviewInputManifest",
    "ReviewInputMissing",
    "ReviewInputSection",
    "ReviewOmission",
    "ReviewPacket",
    "ReviewerChallenge",
    "VerifiedReviewItem",
    "VerifiedReviewVerdict",
    "SemanticCase",
    "SemanticCaseItem",
    "SemanticEvaluatorPort",
    "SemanticJudgment",
    "SemanticProvenance",
    "SemanticReason",
    "SemanticResult",
    "SemanticResultInvalid",
    "SemanticResultLate",
    "SemanticResultRefused",
    "SemanticResultSuccess",
    "SemanticResultTimeout",
    "SemanticResultUnavailable",
    "SemanticStatus",
    "TargetedExcerptRef",
    "project_review_assessment",
]

type SemanticCaseSection = Literal[
    "task_statement",
    "goal",
    "obligation",
    "claim",
    "decision",
    "prior_finding",
    "timeline",
    "deterministic_summary",
    "deterministic_detail",
    "excerpt",
]
type SemanticSourceKind = Literal[
    "task",
    "obligation",
    "claim",
    "decision",
    "action",
    "result",
    "evidence",
    "finding",
    "test",
    "failure",
    "diff",
    "command",
    "repository",
]
type ExcerptSourceKind = Literal["evidence", "test", "failure", "diff", "command", "repository"]
type ExcerptLatestFor = Literal["path", "command"]
type ContentVisibility = Literal[
    "available",
    "not_recorded",
    "not_selected",
    "withheld_by_policy",
    "redacted_never_send",
]
type ReviewOmissionReason = Literal[
    "not_recorded",
    "not_selected",
    "withheld_by_policy",
    "redacted_never_send",
    "never_send_heuristic",
]
type AssessmentLimitField = Literal[
    "subject_refs",
    "observed_fact_subject_refs",
    "required_missing_fact_subject_refs",
    "supporting_refs",
]
type SemanticConclusion = Literal[
    "no_material_discrepancy", "challenges_returned", "insufficient_packet"
]
type MissingForAssessmentKind = Literal[
    "command_identity",
    "current_diff_for_path",
    "other",
    "plan_or_claim_text",
    "prior_finding_context",
    "task_statement",
    "verification_output",
]
# Item-id prefix of the non-rulable rows that carry the agent's answer to a local finding.
LOCAL_FINDING_ANSWER_ITEM_PREFIX: Final = "local-finding-answer-"
# Item-id prefix of the non-rulable rows that carry a finding the agent settled
# (``acknowledged_not_done`` or ``self_verified``): the reviewer may name it in ``restates``
# (issue #980). Structural row ``settled-finding-<ref>``; prose rows
# ``settled-finding-summary-<ref>`` and ``settled-finding-response-<ref>``.
SETTLED_FINDING_ITEM_PREFIX: Final = "settled-finding-"
SETTLED_FINDING_ITEM_SUFFIXES: Final = ("", "summary-", "response-")
type ReviewerNextStep = Literal[
    "act",
    "provide_evidence",
    "revise_claim",
    "dispute_with_evidence",
    "state_unresolved_limitation",
    "answer_question",
]
type ReviewInputSectionName = Literal[
    "specification",
    "current_diff",
    "caller_evidence",
    "latest_verification",
    "prior_finding_context",
]
type ReviewInputSectionStatus = Literal[
    "complete",
    "partial",
    "title_only",
    "missing",
    "withheld",
    "not_selected",
]
type ReviewInputMissingStatus = Literal[
    "pending",
    "supplied",
    "unavailable",
    "repeated",
]
_REVIEW_INPUT_OMISSION_REASONS: Final = frozenset(
    {
        "capture_unavailable",
        "content_unselected",
        "not_recorded",
        "not_selected",
        "redacted_never_send",
        "task_statement_not_authorized",
        "task_statement_not_supplied",
        "task_statement_unavailable",
        "truncated_payload",
        "withheld_by_policy",
    }
)

_MAX_SAFE_INTEGER: Final = 2**53 - 1
_MAX_SUBJECT_REFS: Final = 16
# Public name for the per-item / per-assessment outbound reference bound. A local finding may
# cite up to 64 subjects; a case item or projected assessment carries at most this many, so
# the case builder must decide explicitly what to do with a wider finding (issue #858).
MAX_SEMANTIC_ITEM_SUBJECT_REFS: Final = _MAX_SUBJECT_REFS
_MAX_INTERNAL_SUBJECT_REFS: Final = 64
# Raised with ``MAX_REVIEW_EXCERPTS`` (issue #907 Phase 1b) so the other sections keep the room
# they had when a packet carried at most 16 excerpts.
_MAX_CASE_ITEMS: Final = 256 + MAX_REVIEW_EXCERPTS - 16
MAX_SEMANTIC_CASE_ITEMS: Final = _MAX_CASE_ITEMS
# The prior-findings section (issue #905): at most sixteen earlier AI-powered findings (issue
# #976), each one structural row plus up to six prose rows (summary, message, three challenge
# fields, response).
MAX_PRIOR_FINDING_ITEMS: Final = 112
# The rulable list: one entry per carried earlier finding, never one per row (issue #905).
MAX_PRIOR_FINDING_REFS: Final = 16
# Item ids one review-input manifest section lists: the prior-findings section's rows, its local
# answers and the pending missing-for-assessment row, rounded up (issue #976).
MAX_REVIEW_INPUT_SECTION_ITEMS: Final = 128
_OPAQUE_REF_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
_IDENTITY_PATTERN: Final = re.compile(r"^[a-z0-9][a-z0-9._-]*$", re.ASCII)
_MODEL_IDENTITY_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$", re.ASCII)
_VERSION_IDENTITY_PATTERN: Final = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]*$", re.ASCII)
_PROVIDER_REQUEST_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$", re.ASCII)
_SEMANTIC_VERSION_PATTERN: Final = re.compile(
    r"^(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$",
    re.ASCII,
)
_GAP_CODE_PATTERN: Final = re.compile(r"^[a-z][a-z0-9_]{0,127}$", re.ASCII)

_SECTIONS: Final = frozenset(
    {
        "task_statement",
        "goal",
        "obligation",
        "claim",
        "decision",
        "prior_finding",
        "timeline",
        "deterministic_summary",
        "deterministic_detail",
        "excerpt",
    }
)
_SECTION_ORDINAL: Final = {
    section: ordinal
    for ordinal, section in enumerate(
        (
            # The specification leads the case: the reviewer reads what the user asked for
            # before the agent's own plan, and envelope bounding drops it last (issue #908).
            "task_statement",
            "goal",
            "obligation",
            "claim",
            "decision",
            # Ahead of the timeline: envelope bounding drops catalog rows from the tail, and the
            # dialogue record must never be crowded out by hook rows (issue #905).
            "prior_finding",
            "timeline",
            "deterministic_summary",
            "deterministic_detail",
            "excerpt",
        )
    )
}
_SOURCE_KINDS: Final = frozenset(
    {
        "task",
        "obligation",
        "claim",
        "decision",
        "action",
        "result",
        "evidence",
        "finding",
        "test",
        "failure",
        "diff",
        "command",
        "repository",
    }
)
_EXCERPT_SOURCE_KINDS: Final = frozenset(
    {"evidence", "test", "failure", "diff", "command", "repository"}
)
_EXCERPT_LATEST_FOR: Final = frozenset({"path", "command"})
_CONTENT_VISIBILITIES: Final = frozenset(
    {
        "available",
        "not_recorded",
        "not_selected",
        "withheld_by_policy",
        "redacted_never_send",
    }
)
_OMISSION_REASONS: Final = frozenset(
    {
        "not_recorded",
        "not_selected",
        "withheld_by_policy",
        "redacted_never_send",
        "never_send_heuristic",
    }
)
_CONCLUSIONS: Final = frozenset(
    {"no_material_discrepancy", "challenges_returned", "insufficient_packet"}
)
_NEXT_STEPS: Final = frozenset(
    {
        "act",
        "provide_evidence",
        "revise_claim",
        "dispute_with_evidence",
        "state_unresolved_limitation",
        "answer_question",
    }
)
_FACT_CODES: Final = WORK_INTEGRITY_FACT_CODES | RESEARCH_EVIDENCE_FACT_CODES
_ASSESSMENT_KIND_ORDER: Final = {
    kind: ordinal
    for ordinal, kind in enumerate(
        (
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
            FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
            FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT,
            FindingKind.MATERIAL_LIMITATION_OMITTED,
            FindingKind.QUESTIONABLE_FINDING_REJECTION,
        )
    )
}

if frozenset(VALID_SEMANTIC_REASONS) != frozenset(SemanticStatus):
    raise RuntimeError("semantic_status_registry_incomplete")


def _invalid_case() -> ValueError:
    return ValueError("semantic_case_invalid")


def _invalid_assessment() -> ValueError:
    return ValueError("review_assessment_invalid")


def _invalid_judgment() -> ValueError:
    return ValueError("semantic_judgment_invalid")


def _ascii(value: str) -> bytes:
    try:
        return value.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise _invalid_case() from exc


def _snapshot_text(value: object, *, maximum_bytes: int, error: ValueError) -> str:
    if type(value) is not str:
        raise error
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise error from exc
    if not 1 <= len(encoded) <= maximum_bytes:
        raise error
    return str.__getitem__(value, slice(None))


def _snapshot_opaque_ref(value: object, *, error: ValueError) -> str:
    if type(value) is not str or _OPAQUE_REF_PATTERN.fullmatch(value) is None:
        raise error
    return str.__getitem__(value, slice(None))


def _snapshot_digest(value: object, *, error: ValueError) -> str:
    try:
        return str.__getitem__(validate_sha256_digest(cast(str, value)), slice(None))
    except (ProtocolValueError, TypeError) as exc:
        raise error from exc


def _snapshot_finding_id(value: object, *, error: ValueError) -> FindingId:
    try:
        return finding_id(value)
    except ProtocolValueError as exc:
        raise error from exc


def _snapshot_subject_ref(value: object, *, public_only: bool, error: ValueError) -> str:
    if type(value) is not str:
        raise error
    prefix = value[:4]
    kind = {
        "evt_": IdKind.EVENT,
        "obl_": IdKind.OBLIGATION,
        "clm_": IdKind.CLAIM,
        "act_": IdKind.ACTION,
        "res_": IdKind.RESULT,
        "evd_": IdKind.EVIDENCE,
        "fnd_": IdKind.FINDING,
    }.get(prefix)
    if kind is None or (
        public_only and kind not in {IdKind.EVENT, IdKind.OBLIGATION, IdKind.CLAIM}
    ):
        raise error
    try:
        validated = validate_id(kind, value)
    except ProtocolValueError as exc:
        raise error from exc
    return str.__getitem__(validated, slice(None))


def _validated_ref_tuple(
    value: object,
    *,
    minimum: int,
    maximum: int,
    public_only: bool,
    error: ValueError,
    canonicalize: bool = False,
) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise error
    raw = cast(tuple[object, ...], value)
    if not minimum <= len(raw) <= maximum:
        raise error
    refs = tuple(_snapshot_subject_ref(item, public_only=public_only, error=error) for item in raw)
    canonical = tuple(sorted(set(refs), key=_ascii))
    if canonicalize:
        # Reference order has no semantic meaning for provider challenges: accept any order,
        # reject only duplicates / invalid IDs, then store ASCII-canonical form.
        if len(refs) != len(canonical):
            raise error
        return canonical
    if refs != canonical:
        raise error
    return refs


def _validated_item_ids(value: object, *, maximum: int) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise _invalid_case()
    raw = cast(tuple[object, ...], value)
    if len(raw) > maximum:
        raise _invalid_case()
    ids = tuple(_snapshot_opaque_ref(item, error=_invalid_case()) for item in raw)
    if len(ids) != len(set(ids)):
        raise _invalid_case()
    return ids


def _validate_fact_tuple(
    value: object,
    *,
    minimum: int,
    maximum_refs: int,
) -> tuple[FindingFact, ...]:
    if type(value) is not tuple:
        raise _invalid_assessment()
    facts = cast(tuple[object, ...], value)
    if not minimum <= len(facts) <= 33 or any(type(fact) is not FindingFact for fact in facts):
        raise _invalid_assessment()
    typed = cast(tuple[FindingFact, ...], facts)
    previous: tuple[bytes, tuple[bytes, ...]] | None = None
    seen_codes: set[str] = set()
    for fact in typed:
        if fact.fact_code not in _FACT_CODES or not 1 <= len(fact.subject_refs) <= maximum_refs:
            raise _invalid_assessment()
        refs = _validated_ref_tuple(
            fact.subject_refs,
            minimum=1,
            maximum=maximum_refs,
            public_only=False,
            error=_invalid_assessment(),
        )
        key = (_ascii(fact.fact_code), tuple(_ascii(ref) for ref in refs))
        if fact.fact_code in seen_codes or (previous is not None and key <= previous):
            raise _invalid_assessment()
        seen_codes.add(fact.fact_code)
        previous = key
    return typed


@dataclass(frozen=True, slots=True)
class Deadline:
    """A process-local monotonic budget plus a diagnostic UTC instant."""

    expires_at_utc: datetime
    monotonic_deadline: float

    def __post_init__(self) -> None:
        if type(self.expires_at_utc) is not datetime or self.expires_at_utc.tzinfo is None:
            raise ValueError("deadline_invalid")
        try:
            offset = self.expires_at_utc.utcoffset()
        except Exception as exc:
            raise ValueError("deadline_invalid") from exc
        if offset != timedelta(0) or not _valid_monotonic(self.monotonic_deadline):
            raise ValueError("deadline_invalid")

    def remaining_seconds(self, now_monotonic: float, /) -> float:
        if not _valid_monotonic(now_monotonic):
            raise ValueError("deadline_sample_invalid")
        return max(0.0, self.monotonic_deadline - now_monotonic)

    def expired(self, now_monotonic: float, /) -> bool:
        if not _valid_monotonic(now_monotonic):
            raise ValueError("deadline_sample_invalid")
        return now_monotonic >= self.monotonic_deadline


def _valid_monotonic(value: object) -> bool:
    return type(value) is float and math.isfinite(value) and value >= 0.0


@dataclass(frozen=True, slots=True)
class SemanticCaseItem:
    item_id: str
    section: SemanticCaseSection
    category: DataCategory
    source_kind: SemanticSourceKind
    source_ref: str
    linked_subject_refs: tuple[str, ...]
    occurred_order: int
    content: bytes
    content_bytes: int
    content_digest: str
    # Freshness marks on an excerpt (issue #907). ``latest_for`` says this excerpt is the newest
    # recorded edit of its changed path(s) or the newest output of its verification command;
    # ``superseded_by`` names the newer source refs of the same path or command. Both describe
    # recording order only; neither claims what the working tree contains now.
    latest_for: ExcerptLatestFor | None = None
    superseded_by: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "item_id", _snapshot_opaque_ref(self.item_id, error=_invalid_case())
        )
        if type(self.section) is not str or self.section not in _SECTIONS:
            raise _invalid_case()
        if self.latest_for is not None and (
            type(self.latest_for) is not str or self.latest_for not in _EXCERPT_LATEST_FOR
        ):
            raise _invalid_case()
        if type(self.superseded_by) is not tuple or len(self.superseded_by) > _MAX_SUBJECT_REFS:
            raise _invalid_case()
        superseded = tuple(
            _snapshot_opaque_ref(ref, error=_invalid_case()) for ref in self.superseded_by
        )
        if superseded != tuple(sorted(set(superseded), key=_ascii)):
            raise _invalid_case()
        object.__setattr__(self, "superseded_by", superseded)
        if (self.latest_for is not None or superseded) and self.section != "excerpt":
            raise _invalid_case()
        if self.latest_for is not None and superseded:
            raise _invalid_case()
        if type(self.category) is not DataCategory:
            raise _invalid_case()
        if type(self.source_kind) is not str or self.source_kind not in _SOURCE_KINDS:
            raise _invalid_case()
        object.__setattr__(
            self, "source_ref", _snapshot_opaque_ref(self.source_ref, error=_invalid_case())
        )
        object.__setattr__(
            self,
            "linked_subject_refs",
            _validated_ref_tuple(
                self.linked_subject_refs,
                minimum=0,
                maximum=_MAX_SUBJECT_REFS,
                public_only=False,
                error=_invalid_case(),
            ),
        )
        if (
            type(self.occurred_order) is not int
            or not 0 <= self.occurred_order <= _MAX_SAFE_INTEGER
        ):
            raise _invalid_case()
        if type(self.content) is not bytes or not 1 <= len(self.content) <= MAX_SEMANTIC_ITEM_BYTES:
            raise _invalid_case()
        try:
            self.content.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise _invalid_case() from exc
        if type(self.content_bytes) is not int or self.content_bytes != len(self.content):
            raise _invalid_case()
        digest = _snapshot_digest(self.content_digest, error=_invalid_case())
        actual_digest = "sha256:" + hashlib.sha256(self.content).hexdigest()
        if digest != actual_digest:
            raise _invalid_case()
        object.__setattr__(self, "content_digest", digest)


@dataclass(frozen=True, slots=True)
class ReviewAssessment:
    finding_ref: FindingId
    finding_kind: FindingKind
    priority: int
    subject_refs: tuple[str, ...]
    rule_id: str
    observed_facts: tuple[FindingFact, ...]
    required_but_missing_facts: tuple[FindingFact, ...]
    subject_state_relation: SubjectStateRelation
    source_availability: FrozenSourceAvailability
    coverage_gaps: tuple[str, ...]
    supporting_refs: tuple[str, ...]
    summary_item_id: str | None = None
    detail_item_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "finding_ref", _snapshot_finding_id(self.finding_ref, error=_invalid_assessment())
        )
        if type(self.finding_kind) is not FindingKind:
            raise _invalid_assessment()
        required_priority, _ = FINDING_KIND_TRAITS[self.finding_kind]
        if type(self.priority) is not int or self.priority != required_priority:
            raise _invalid_assessment()
        object.__setattr__(
            self,
            "subject_refs",
            _validated_ref_tuple(
                self.subject_refs,
                minimum=1,
                maximum=_MAX_SUBJECT_REFS,
                public_only=True,
                error=_invalid_assessment(),
            ),
        )
        if type(self.rule_id) is not str or self.rule_id != self.finding_kind.value:
            raise _invalid_assessment()
        object.__setattr__(
            self,
            "observed_facts",
            _validate_fact_tuple(self.observed_facts, minimum=1, maximum_refs=_MAX_SUBJECT_REFS),
        )
        object.__setattr__(
            self,
            "required_but_missing_facts",
            _validate_fact_tuple(
                self.required_but_missing_facts,
                minimum=0,
                maximum_refs=_MAX_SUBJECT_REFS,
            ),
        )
        if type(self.subject_state_relation) is not SubjectStateRelation:
            raise _invalid_assessment()
        if type(self.source_availability) is not FrozenSourceAvailability:
            raise _invalid_assessment()
        if type(self.coverage_gaps) is not tuple or len(self.coverage_gaps) > 64:
            raise _invalid_assessment()
        gaps = cast(tuple[object, ...], self.coverage_gaps)
        if any(type(gap) is not str or _GAP_CODE_PATTERN.fullmatch(gap) is None for gap in gaps):
            raise _invalid_assessment()
        typed_gaps = cast(tuple[str, ...], gaps)
        if typed_gaps != tuple(sorted(set(typed_gaps), key=_ascii)):
            raise _invalid_assessment()
        object.__setattr__(self, "coverage_gaps", typed_gaps)
        supporting_refs = _validated_ref_tuple(
            self.supporting_refs,
            minimum=0,
            maximum=_MAX_SUBJECT_REFS,
            public_only=False,
            error=_invalid_assessment(),
        )
        expected_supporting_refs = tuple(
            sorted(
                {ref for fact in self.observed_facts for ref in fact.subject_refs},
                key=_ascii,
            )
        )
        if supporting_refs != expected_supporting_refs:
            raise _invalid_assessment()
        object.__setattr__(self, "supporting_refs", supporting_refs)
        if (self.summary_item_id is None) is not (self.detail_item_id is None):
            raise _invalid_assessment()
        if self.summary_item_id is not None and self.detail_item_id is not None:
            object.__setattr__(
                self,
                "summary_item_id",
                _snapshot_opaque_ref(self.summary_item_id, error=_invalid_assessment()),
            )
            object.__setattr__(
                self,
                "detail_item_id",
                _snapshot_opaque_ref(self.detail_item_id, error=_invalid_assessment()),
            )
            if self.summary_item_id == self.detail_item_id:
                raise _invalid_assessment()


@dataclass(frozen=True, slots=True)
class ReviewOmission:
    subject_ref: str
    category: DataCategory
    source_kind: SemanticSourceKind
    reason: ReviewOmissionReason

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "subject_ref",
            _snapshot_subject_ref(self.subject_ref, public_only=False, error=_invalid_case()),
        )
        if type(self.category) is not DataCategory:
            raise _invalid_case()
        if type(self.source_kind) is not str or self.source_kind not in _SOURCE_KINDS:
            raise _invalid_case()
        if type(self.reason) is not str or self.reason not in _OMISSION_REASONS:
            raise _invalid_case()


@dataclass(frozen=True, slots=True)
class ReviewAssessmentSkipped:
    finding_ref: FindingId
    limit_field: AssessmentLimitField
    actual_count: int
    omission: ReviewOmission

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "finding_ref", _snapshot_finding_id(self.finding_ref, error=_invalid_assessment())
        )
        if self.limit_field not in {
            "subject_refs",
            "observed_fact_subject_refs",
            "required_missing_fact_subject_refs",
            "supporting_refs",
        }:
            raise _invalid_assessment()
        if type(self.actual_count) is not int or not 17 <= self.actual_count <= 64:
            raise _invalid_assessment()
        if type(self.omission) is not ReviewOmission:
            raise _invalid_assessment()
        if (
            self.omission.subject_ref != self.finding_ref
            or self.omission.category is not DataCategory.BOUNDED_STRUCTURAL_METADATA
            or self.omission.source_kind != "finding"
            or self.omission.reason != "not_selected"
        ):
            raise _invalid_assessment()


def project_review_assessment(
    assessment: DeterministicAssessment,
    finding_ref: str,
    summary_item_id: str | None = None,
    detail_item_id: str | None = None,
) -> ReviewAssessment | ReviewAssessmentSkipped:
    """Project one complete local basis without truncating narrower outbound refs."""

    if type(assessment) is not DeterministicAssessment:
        raise _invalid_assessment()
    pinned_ref = _snapshot_finding_id(finding_ref, error=_invalid_assessment())
    if (summary_item_id is None) is not (detail_item_id is None):
        raise _invalid_assessment()
    if summary_item_id is not None and detail_item_id is not None:
        summary_item_id = _snapshot_opaque_ref(summary_item_id, error=_invalid_assessment())
        detail_item_id = _snapshot_opaque_ref(detail_item_id, error=_invalid_assessment())
        if summary_item_id == detail_item_id:
            raise _invalid_assessment()

    candidate = assessment.candidate
    basis = assessment.basis
    if (
        candidate.origin is not FindingOrigin.DETERMINISTIC
        or candidate.provenance is not None
        or basis.rule_id != f"{candidate.policy_id}/{candidate.kind.value}"
    ):
        raise _invalid_assessment()
    _validated_ref_tuple(
        candidate.subject_refs,
        minimum=1,
        maximum=_MAX_INTERNAL_SUBJECT_REFS,
        public_only=True,
        error=_invalid_assessment(),
    )
    observed = _validate_fact_tuple(
        basis.observed_facts,
        minimum=1,
        maximum_refs=_MAX_INTERNAL_SUBJECT_REFS,
    )
    missing = _validate_fact_tuple(
        basis.required_but_missing_facts,
        minimum=0,
        maximum_refs=_MAX_INTERNAL_SUBJECT_REFS,
    )
    _validated_ref_tuple(
        basis.supporting_refs,
        minimum=0,
        maximum=_MAX_INTERNAL_SUBJECT_REFS,
        public_only=False,
        error=_invalid_assessment(),
    )

    def skipped(field: AssessmentLimitField, count: int) -> ReviewAssessmentSkipped:
        omission = ReviewOmission(
            subject_ref=pinned_ref,
            category=DataCategory.BOUNDED_STRUCTURAL_METADATA,
            source_kind="finding",
            reason="not_selected",
        )
        return ReviewAssessmentSkipped(pinned_ref, field, count, omission)

    if len(candidate.subject_refs) > _MAX_SUBJECT_REFS:
        return skipped("subject_refs", len(candidate.subject_refs))
    for fact in observed:
        if len(fact.subject_refs) > _MAX_SUBJECT_REFS:
            return skipped("observed_fact_subject_refs", len(fact.subject_refs))
    for fact in missing:
        if len(fact.subject_refs) > _MAX_SUBJECT_REFS:
            return skipped("required_missing_fact_subject_refs", len(fact.subject_refs))
    if len(basis.supporting_refs) > _MAX_SUBJECT_REFS:
        return skipped("supporting_refs", len(basis.supporting_refs))

    return ReviewAssessment(
        finding_ref=pinned_ref,
        finding_kind=candidate.kind,
        priority=candidate.priority,
        subject_refs=cast(tuple[str, ...], candidate.subject_refs),
        rule_id=candidate.kind.value,
        observed_facts=observed,
        required_but_missing_facts=missing,
        subject_state_relation=basis.subject_state_relation,
        source_availability=basis.source_availability,
        coverage_gaps=basis.coverage_gaps,
        supporting_refs=cast(tuple[str, ...], basis.supporting_refs),
        summary_item_id=summary_item_id,
        detail_item_id=detail_item_id,
    )


@dataclass(frozen=True, slots=True)
class ExcerptDigestProvenance:
    """Digest-identity facts for an excerpt whose source evidence carries a typed binding."""

    evidence_kind: EvidenceKind
    strength: EvidenceImmutability
    content_digest: str
    digest_subject: EvidenceDigestSubject
    content_availability: EvidenceContentAvailability
    byte_count: int
    provenance: EvidenceDigestProvenance
    approval_commitment: str | None = None
    approved_check_result_digest: str | None = None

    def __post_init__(self) -> None:
        if type(self.evidence_kind) is not EvidenceKind:
            raise _invalid_case()
        if type(self.strength) is not EvidenceImmutability:
            raise _invalid_case()
        object.__setattr__(
            self, "content_digest", _snapshot_digest(self.content_digest, error=_invalid_case())
        )
        if type(self.digest_subject) is not EvidenceDigestSubject:
            raise _invalid_case()
        if type(self.content_availability) is not EvidenceContentAvailability:
            raise _invalid_case()
        if type(self.byte_count) is not int or not 0 <= self.byte_count <= _MAX_SAFE_INTEGER:
            raise _invalid_case()
        if type(self.provenance) is not EvidenceDigestProvenance:
            raise _invalid_case()
        if self.approval_commitment is not None:
            object.__setattr__(
                self,
                "approval_commitment",
                _snapshot_digest(self.approval_commitment, error=_invalid_case()),
            )
        if self.approved_check_result_digest is not None:
            object.__setattr__(
                self,
                "approved_check_result_digest",
                _snapshot_digest(self.approved_check_result_digest, error=_invalid_case()),
            )
        approved = self.provenance is EvidenceDigestProvenance.APPROVED_CHECK
        if approved is not (
            self.approval_commitment is not None and self.approved_check_result_digest is not None
        ):
            raise _invalid_case()
        if (
            self.digest_subject is EvidenceDigestSubject.APPROVED_CHECK_RECEIPT
            and self.provenance is not EvidenceDigestProvenance.APPROVED_CHECK
        ):
            raise _invalid_case()
        if (
            self.digest_subject is EvidenceDigestSubject.IMPORT_REPORT
            and self.provenance is not EvidenceDigestProvenance.IMPORT_OBSERVED
        ):
            raise _invalid_case()


@dataclass(frozen=True, slots=True)
class TargetedExcerptRef:
    excerpt_item_id: str
    source_kind: ExcerptSourceKind
    linked_subject_refs: tuple[str, ...]
    subject_state_relation: SubjectStateRelation
    content_visibility: ContentVisibility
    content_digest: str
    content_bytes: int
    digest_provenance: ExcerptDigestProvenance | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "excerpt_item_id",
            _snapshot_opaque_ref(self.excerpt_item_id, error=_invalid_case()),
        )
        if type(self.source_kind) is not str or self.source_kind not in _EXCERPT_SOURCE_KINDS:
            raise _invalid_case()
        object.__setattr__(
            self,
            "linked_subject_refs",
            _validated_ref_tuple(
                self.linked_subject_refs,
                minimum=1,
                maximum=_MAX_SUBJECT_REFS,
                public_only=False,
                error=_invalid_case(),
            ),
        )
        if type(self.subject_state_relation) is not SubjectStateRelation:
            raise _invalid_case()
        if (
            type(self.content_visibility) is not str
            or self.content_visibility not in _CONTENT_VISIBILITIES
        ):
            raise _invalid_case()
        object.__setattr__(
            self, "content_digest", _snapshot_digest(self.content_digest, error=_invalid_case())
        )
        if (
            type(self.content_bytes) is not int
            or not 1 <= self.content_bytes <= MAX_SEMANTIC_ITEM_BYTES
        ):
            raise _invalid_case()
        if self.digest_provenance is not None and (
            type(self.digest_provenance) is not ExcerptDigestProvenance
        ):
            raise _invalid_case()


@dataclass(frozen=True, slots=True)
class ReviewInputSection:
    """Bounded structural accounting for one review input family.

    This manifest is deliberately metadata-only. It names the source and revision that the
    frozen case considered, the item ids and refs that survived selection, and bounded omission
    counts. It never copies statement, diff, test, or finding prose into a status or diagnostic
    surface (issue #951 / residual #907).
    """

    name: ReviewInputSectionName
    status: ReviewInputSectionStatus
    source_refs: tuple[str, ...] = ()
    selected_item_ids: tuple[str, ...] = ()
    omitted_refs: tuple[str, ...] = ()
    omission_reasons: tuple[str, ...] = ()
    revision: int | None = None
    content_digest: str | None = None
    content_bytes: int = 0

    def __post_init__(self) -> None:
        if self.name not in {
            "specification",
            "current_diff",
            "caller_evidence",
            "latest_verification",
            "prior_finding_context",
        }:
            raise _invalid_case()
        if self.status not in {
            "complete",
            "partial",
            "title_only",
            "missing",
            "withheld",
            "not_selected",
        }:
            raise _invalid_case()

        def opaque_refs(value: object, *, maximum: int) -> tuple[str, ...]:
            if type(value) is not tuple:
                raise _invalid_case()
            raw = cast(tuple[object, ...], value)
            if len(raw) > maximum:
                raise _invalid_case()
            values = tuple(_snapshot_opaque_ref(item, error=_invalid_case()) for item in raw)
            if values != tuple(sorted(set(values), key=_ascii)):
                raise _invalid_case()
            return values

        object.__setattr__(self, "source_refs", opaque_refs(self.source_refs, maximum=16))
        object.__setattr__(
            self,
            "selected_item_ids",
            opaque_refs(self.selected_item_ids, maximum=MAX_REVIEW_INPUT_SECTION_ITEMS),
        )
        object.__setattr__(self, "omitted_refs", opaque_refs(self.omitted_refs, maximum=16))
        if type(self.omission_reasons) is not tuple or len(self.omission_reasons) > 8:
            raise _invalid_case()
        reasons = tuple(cast(tuple[object, ...], self.omission_reasons))
        if any(
            type(item) is not str or item not in _REVIEW_INPUT_OMISSION_REASONS for item in reasons
        ):
            raise _invalid_case()
        reasons = cast(tuple[str, ...], reasons)
        if reasons != tuple(sorted(set(reasons), key=_ascii)):
            raise _invalid_case()
        object.__setattr__(self, "omission_reasons", reasons)
        if self.revision is not None and (
            type(self.revision) is not int or not 0 <= self.revision <= _MAX_SAFE_INTEGER
        ):
            raise _invalid_case()
        if self.content_digest is not None:
            object.__setattr__(
                self,
                "content_digest",
                _snapshot_digest(self.content_digest, error=_invalid_case()),
            )
        if (
            type(self.content_bytes) is not int
            or not 0 <= self.content_bytes <= MAX_SEMANTIC_CASE_BYTES
        ):
            raise _invalid_case()
        if (
            self.status in {"missing", "withheld", "not_selected"}
            and self.content_digest is not None
        ):
            raise _invalid_case()


@dataclass(frozen=True, slots=True)
class ReviewInputMissing:
    """One bounded missing-input request carried by the per-check manifest."""

    kind: MissingForAssessmentKind
    target_refs: tuple[str, ...] = ()
    supplied_refs: tuple[str, ...] = ()
    status: ReviewInputMissingStatus = "pending"

    def __post_init__(self) -> None:
        if self.kind not in {
            "command_identity",
            "current_diff_for_path",
            "other",
            "plan_or_claim_text",
            "prior_finding_context",
            "task_statement",
            "verification_output",
        }:
            raise _invalid_case()
        for field_name, value in (
            ("target_refs", self.target_refs),
            ("supplied_refs", self.supplied_refs),
        ):
            if type(value) is not tuple or len(value) > MAX_MISSING_TARGET_REFS:
                raise _invalid_case()
            refs = tuple(
                _snapshot_subject_ref(item, public_only=False, error=_invalid_case())
                for item in cast(tuple[object, ...], value)
            )
            if refs != tuple(sorted(set(refs), key=_ascii)):
                raise _invalid_case()
            object.__setattr__(self, field_name, refs)
        if self.status not in {"pending", "supplied", "unavailable", "repeated"}:
            raise _invalid_case()


@dataclass(frozen=True, slots=True)
class ReviewInputManifest:
    """The exact bounded input coverage summary for one semantic check.

    The manifest is part of the frozen review packet and therefore its digest. It is safe to
    project into check/status surfaces because it contains only ids, digests, byte counts and
    closed status tokens. Content itself remains in the ordinary privacy-selected packet items.
    """

    schema: Literal["yoetz.review-input-manifest/1"]
    specification: ReviewInputSection
    current_diff: ReviewInputSection
    caller_evidence: ReviewInputSection
    latest_verification: ReviewInputSection
    prior_finding_context: ReviewInputSection
    phase: Literal["composed", "provider_bound"] = "composed"
    missing_inputs: tuple[ReviewInputMissing, ...] = ()
    selected_item_count: int = 0
    selected_excerpt_bytes: int = 0
    # The omission rows the packet lists, capped at ``MAX_REVIEW_OMISSIONS``.
    omitted_item_count: int = 0
    # Issue #976: the review phase the packet's question set named; ``None`` on older manifests.
    review_phase: Literal["routine", "final"] | None = None
    # Every distinct omission before that cap (issue #976, tb4n1 D11); ``None`` on older
    # manifests, which reported only the capped count.
    omitted_item_total: int | None = None
    # Issue #1047: the in-check follow-up round this packet is (1 to
    # ``MAX_REVIEW_FOLLOW_UP_ROUNDS``); ``None`` for the check's own first packet. A follow-up
    # manifest's ``missing_inputs`` lists the reviewer's request Yoetz answered from its records.
    follow_up_round: int | None = None

    def __post_init__(self) -> None:
        if self.schema != "yoetz.review-input-manifest/1":
            raise _invalid_case()
        if self.review_phase not in {None, "routine", "final"}:
            raise _invalid_case()
        if self.follow_up_round is not None and (
            type(self.follow_up_round) is not int
            or not 1 <= self.follow_up_round <= MAX_REVIEW_FOLLOW_UP_ROUNDS
        ):
            raise _invalid_case()
        if self.phase not in {"composed", "provider_bound"}:
            raise _invalid_case()
        sections = (
            self.specification,
            self.current_diff,
            self.caller_evidence,
            self.latest_verification,
            self.prior_finding_context,
        )
        if any(type(item) is not ReviewInputSection for item in sections):
            raise _invalid_case()
        if tuple(item.name for item in sections) != (
            "specification",
            "current_diff",
            "caller_evidence",
            "latest_verification",
            "prior_finding_context",
        ):
            raise _invalid_case()
        if (
            type(self.missing_inputs) is not tuple
            or len(self.missing_inputs) > MAX_MISSING_FOR_ASSESSMENT
            or any(type(item) is not ReviewInputMissing for item in self.missing_inputs)
        ):
            raise _invalid_case()
        if (
            type(self.selected_item_count) is not int
            or not 0 <= self.selected_item_count <= MAX_SEMANTIC_CASE_ITEMS
        ):
            raise _invalid_case()
        if (
            type(self.selected_excerpt_bytes) is not int
            or not 0 <= self.selected_excerpt_bytes <= MAX_SEMANTIC_CASE_BYTES
        ):
            raise _invalid_case()
        if (
            type(self.omitted_item_count) is not int
            or not 0 <= self.omitted_item_count <= MAX_REVIEW_OMISSIONS
        ):
            raise _invalid_case()
        if self.omitted_item_total is not None and (
            type(self.omitted_item_total) is not int
            or not self.omitted_item_count <= self.omitted_item_total <= MAX_REVIEW_OMISSION_TOTAL
        ):
            raise _invalid_case()


@dataclass(frozen=True, slots=True)
class ChangeObservation:
    subject_refs: tuple[str, ...]
    claimed_change: bool
    subject_state_relation: SubjectStateRelation
    content_visibility: ContentVisibility
    before_state_digest: str | None = None
    after_state_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "subject_refs",
            _validated_ref_tuple(
                self.subject_refs,
                minimum=1,
                maximum=_MAX_SUBJECT_REFS,
                public_only=True,
                error=_invalid_case(),
            ),
        )
        if type(self.claimed_change) is not bool:
            raise _invalid_case()
        if type(self.subject_state_relation) is not SubjectStateRelation:
            raise _invalid_case()
        if (
            type(self.content_visibility) is not str
            or self.content_visibility not in _CONTENT_VISIBILITIES
        ):
            raise _invalid_case()
        if (self.before_state_digest is None) is not (self.after_state_digest is None):
            raise _invalid_case()
        if self.before_state_digest is None:
            if self.subject_state_relation is not SubjectStateRelation.UNKNOWN:
                raise _invalid_case()
            return
        before = _snapshot_digest(self.before_state_digest, error=_invalid_case())
        after = _snapshot_digest(self.after_state_digest, error=_invalid_case())
        object.__setattr__(self, "before_state_digest", before)
        object.__setattr__(self, "after_state_digest", after)
        expected = SubjectStateRelation.SAME if before == after else SubjectStateRelation.DIFFERENT
        if self.subject_state_relation is not expected:
            raise _invalid_case()


@dataclass(frozen=True, slots=True)
class ReviewPacket:
    goal_item_ids: tuple[str, ...]
    obligation_item_ids: tuple[str, ...]
    claim_item_ids: tuple[str, ...]
    decision_item_ids: tuple[str, ...]
    timeline_item_ids: tuple[str, ...]
    deterministic_assessments: tuple[ReviewAssessment, ...]
    change_observations: tuple[ChangeObservation, ...]
    coverage: Coverage
    targeted_excerpts: tuple[TargetedExcerptRef, ...]
    omissions: tuple[ReviewOmission, ...]
    # Earlier AI-powered findings with the agent's answers, outside the timeline (issue #905).
    prior_finding_item_ids: tuple[str, ...] = ()
    # The rulable list: each carried earlier finding once, newest first. A finding contributes a
    # structural row and, under a prose profile, several prose rows; the reviewer rules once per
    # entry here, never once per row, so the sixteen-ruling cap always covers every finding.
    prior_finding_refs: tuple[str, ...] = ()
    # At most one statement item: the task's current statement, never a plan (issue #908).
    task_statement_item_ids: tuple[str, ...] = ()
    # Metadata-only coverage for the exact input families considered by this check (#951).
    input_manifest: ReviewInputManifest | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "task_statement_item_ids",
            _validated_item_ids(self.task_statement_item_ids, maximum=1),
        )
        if self.input_manifest is not None and type(self.input_manifest) is not ReviewInputManifest:
            raise _invalid_case()
        object.__setattr__(
            self, "goal_item_ids", _validated_item_ids(self.goal_item_ids, maximum=4)
        )
        object.__setattr__(
            self,
            "prior_finding_item_ids",
            _validated_item_ids(self.prior_finding_item_ids, maximum=MAX_PRIOR_FINDING_ITEMS),
        )
        refs = self.prior_finding_refs
        if type(refs) is not tuple or len(refs) > MAX_PRIOR_FINDING_REFS:
            raise _invalid_case()
        canonical_refs = tuple(
            str(_snapshot_finding_id(item, error=_invalid_case()))
            for item in cast(tuple[object, ...], refs)
        )
        if len(canonical_refs) != len(set(canonical_refs)):
            raise _invalid_case()
        object.__setattr__(self, "prior_finding_refs", canonical_refs)
        object.__setattr__(
            self,
            "obligation_item_ids",
            _validated_item_ids(self.obligation_item_ids, maximum=32),
        )
        object.__setattr__(
            self, "claim_item_ids", _validated_item_ids(self.claim_item_ids, maximum=32)
        )
        object.__setattr__(
            self, "decision_item_ids", _validated_item_ids(self.decision_item_ids, maximum=16)
        )
        object.__setattr__(
            self,
            "timeline_item_ids",
            _validated_item_ids(self.timeline_item_ids, maximum=MAX_REVIEW_TIMELINE_ITEMS),
        )
        if (
            type(self.deterministic_assessments) is not tuple
            or not 0 <= len(self.deterministic_assessments) <= MAX_REVIEW_ASSESSMENTS
        ):
            raise _invalid_case()
        if any(type(item) is not ReviewAssessment for item in self.deterministic_assessments):
            raise _invalid_case()
        assessment_keys = tuple(
            (
                _ASSESSMENT_KIND_ORDER[item.finding_kind],
                tuple(_ascii(ref) for ref in item.subject_refs),
            )
            for item in self.deterministic_assessments
        )
        if assessment_keys != tuple(sorted(assessment_keys)) or len(assessment_keys) != len(
            set(assessment_keys)
        ):
            raise _invalid_case()
        if (
            type(self.change_observations) is not tuple
            or not 0 <= len(self.change_observations) <= MAX_REVIEW_CHANGE_OBSERVATIONS
        ):
            raise _invalid_case()
        if any(type(item) is not ChangeObservation for item in self.change_observations):
            raise _invalid_case()
        change_keys = tuple(
            tuple(_ascii(ref) for ref in item.subject_refs) for item in self.change_observations
        )
        if change_keys != tuple(sorted(change_keys)) or len(change_keys) != len(set(change_keys)):
            raise _invalid_case()
        if type(self.coverage) is not Coverage:
            raise _invalid_case()
        if (
            type(self.targeted_excerpts) is not tuple
            or not 0 <= len(self.targeted_excerpts) <= MAX_REVIEW_EXCERPTS
        ):
            raise _invalid_case()
        if any(type(item) is not TargetedExcerptRef for item in self.targeted_excerpts):
            raise _invalid_case()
        if (
            type(self.omissions) is not tuple
            or not 0 <= len(self.omissions) <= MAX_REVIEW_OMISSIONS
        ):
            raise _invalid_case()
        if any(type(item) is not ReviewOmission for item in self.omissions):
            raise _invalid_case()
        omission_keys = tuple(
            (_ascii(item.subject_ref), _ascii(item.category.value), _ascii(item.reason))
            for item in self.omissions
        )
        if omission_keys != tuple(sorted(omission_keys)) or len(self.omissions) != len(
            set(self.omissions)
        ):
            raise _invalid_case()

        referenced_ids = [
            *self.task_statement_item_ids,
            *self.goal_item_ids,
            *self.obligation_item_ids,
            *self.claim_item_ids,
            *self.decision_item_ids,
            *self.prior_finding_item_ids,
            *self.timeline_item_ids,
        ]
        for assessment in self.deterministic_assessments:
            if assessment.summary_item_id is not None and assessment.detail_item_id is not None:
                referenced_ids.extend((assessment.summary_item_id, assessment.detail_item_id))
        referenced_ids.extend(item.excerpt_item_id for item in self.targeted_excerpts)
        if len(referenced_ids) != len(set(referenced_ids)):
            raise _invalid_case()


@dataclass(frozen=True, slots=True)
class SemanticCase:
    case_id: str
    subject_frontier: Frontier
    dependency_digest: str
    frontier_refs: frozenset[str]
    local_check_refs: frozenset[str]
    review_context_profile: ReviewContextProfile
    review_selection: ReviewSelectionPolicy
    policy_id: str
    policy_version: str
    packet: ReviewPacket
    items: tuple[SemanticCaseItem, ...]
    question_set: tuple[str, ...]
    case_digest: str
    omitted_reference_count: int = 0
    # Local composition fact, not wire or digest material: how many selected excerpts the builder
    # dropped to fit MAX_SEMANTIC_CASE_BYTES (issue #907 Phase 1b). Diagnostics report it.
    excerpts_cut_for_case_bound: int = field(default=0, compare=False)
    # Local composition fact, not wire or digest material (tb4n5, issue #1047 follow-up): each
    # excerpt item's place in its source text as ``(item_id, span_key)``, so an in-check
    # follow-up can tell which parts of a partly shown source a sent packet carried.
    excerpt_parts: tuple[tuple[str, str], ...] = field(default=(), compare=False)

    def __post_init__(self) -> None:
        if (
            type(self.omitted_reference_count) is not int
            or not 0 <= self.omitted_reference_count <= _MAX_SAFE_INTEGER
        ):
            raise _invalid_case()
        if (
            type(self.excerpt_parts) is not tuple
            or len(self.excerpt_parts) > _MAX_CASE_ITEMS
            or any(
                type(pair) is not tuple
                or len(pair) != 2
                or any(type(value) is not str for value in pair)
                for pair in self.excerpt_parts
            )
        ):
            raise _invalid_case()
        if (
            type(self.excerpts_cut_for_case_bound) is not int
            or not 0 <= self.excerpts_cut_for_case_bound <= MAX_REVIEW_EXCERPTS
        ):
            raise _invalid_case()
        try:
            case_id = validate_id(IdKind.OUTBOUND_CASE, self.case_id)
        except ProtocolValueError as exc:
            raise _invalid_case() from exc
        object.__setattr__(self, "case_id", str.__getitem__(case_id, slice(None)))
        if type(self.subject_frontier) is not Frontier:
            raise _invalid_case()
        object.__setattr__(
            self,
            "dependency_digest",
            _snapshot_digest(self.dependency_digest, error=_invalid_case()),
        )
        if (
            type(self.frontier_refs) is not frozenset
            or type(self.local_check_refs) is not frozenset
        ):
            raise _invalid_case()
        frontier_refs = frozenset(
            _snapshot_subject_ref(ref, public_only=False, error=_invalid_case())
            for ref in self.frontier_refs
        )
        local_refs = frozenset(
            _snapshot_finding_id(ref, error=_invalid_case()) for ref in self.local_check_refs
        )
        if (
            len(frontier_refs) != len(self.frontier_refs)
            or len(local_refs) != len(self.local_check_refs)
            or frontier_refs & local_refs
        ):
            raise _invalid_case()
        object.__setattr__(self, "frontier_refs", frontier_refs)
        object.__setattr__(self, "local_check_refs", local_refs)
        if type(self.policy_id) is not str or not self.policy_id:
            raise _invalid_case()
        if type(self.policy_version) is not str or not self.policy_version:
            raise _invalid_case()
        if type(self.packet) is not ReviewPacket:
            raise _invalid_case()
        if type(self.items) is not tuple or not 1 <= len(self.items) <= _MAX_CASE_ITEMS:
            raise _invalid_case()
        if any(type(item) is not SemanticCaseItem for item in self.items):
            raise _invalid_case()
        item_keys = tuple(
            (
                _SECTION_ORDINAL[item.section],
                item.occurred_order,
                _ascii(item.source_ref),
                _ascii(item.item_id),
            )
            for item in self.items
        )
        if item_keys != tuple(sorted(item_keys)):
            raise _invalid_case()
        item_by_id = {item.item_id: item for item in self.items}
        if len(item_by_id) != len(self.items):
            raise _invalid_case()
        allowed_refs = frontier_refs | local_refs
        if any(not set(item.linked_subject_refs) <= allowed_refs for item in self.items):
            raise _invalid_case()
        if sum(item.content_bytes for item in self.items) > MAX_SEMANTIC_CASE_BYTES:
            raise _invalid_case()

        packet = self.packet
        expected_sections = (
            (packet.task_statement_item_ids, "task_statement"),
            (packet.goal_item_ids, "goal"),
            (packet.obligation_item_ids, "obligation"),
            (packet.claim_item_ids, "claim"),
            (packet.decision_item_ids, "decision"),
            (packet.prior_finding_item_ids, "prior_finding"),
            (packet.timeline_item_ids, "timeline"),
        )
        for ids, section in expected_sections:
            for item_id in ids:
                item = item_by_id.get(item_id)
                if item is None or item.section != section:
                    raise _invalid_case()
        # Each rulable earlier finding is exactly one carried finding, in section order, and its
        # structural row is the one the ref names; every prior-finding row belongs to one of them.
        structural = tuple(
            item.source_ref
            for item_id in packet.prior_finding_item_ids
            if (item := item_by_id[item_id]).item_id == f"prior-finding-{item.source_ref}"
        )
        # Rows answering a local finding (issue #976) and rows carrying a finding the agent settled
        # (issue #980) are non-rulable context of their own.
        if packet.prior_finding_refs != structural or any(
            item_by_id[item_id].source_ref not in structural
            and item_id
            not in {
                LOCAL_FINDING_ANSWER_ITEM_PREFIX + item_by_id[item_id].source_ref,
                LOCAL_FINDING_ANSWER_ITEM_PREFIX + "text-" + item_by_id[item_id].source_ref,
                *(
                    SETTLED_FINDING_ITEM_PREFIX + infix + item_by_id[item_id].source_ref
                    for infix in SETTLED_FINDING_ITEM_SUFFIXES
                ),
            }
            for item_id in packet.prior_finding_item_ids
        ):
            raise _invalid_case()
        for assessment in packet.deterministic_assessments:
            if (
                assessment.finding_ref not in local_refs
                or not set(assessment.subject_refs) <= frontier_refs
                or any(
                    not set(fact.subject_refs) <= allowed_refs
                    for fact in (*assessment.observed_facts, *assessment.required_but_missing_facts)
                )
                or not set(assessment.supporting_refs) <= allowed_refs
            ):
                raise _invalid_case()
            if assessment.summary_item_id is not None and assessment.detail_item_id is not None:
                summary = item_by_id.get(assessment.summary_item_id)
                detail = item_by_id.get(assessment.detail_item_id)
                if (
                    summary is None
                    or detail is None
                    or summary.section != "deterministic_summary"
                    or detail.section != "deterministic_detail"
                    or summary.source_kind != "finding"
                    or detail.source_kind != "finding"
                    or summary.category is not DataCategory.FINDING_SUMMARY
                    or detail.category is not DataCategory.FINDING_SUMMARY
                    or summary.source_ref != assessment.finding_ref
                    or detail.source_ref != assessment.finding_ref
                    or summary.linked_subject_refs != assessment.subject_refs
                    or detail.linked_subject_refs != assessment.subject_refs
                ):
                    raise _invalid_case()
        if any(not set(item.subject_refs) <= frontier_refs for item in packet.change_observations):
            raise _invalid_case()
        for excerpt in packet.targeted_excerpts:
            item = item_by_id.get(excerpt.excerpt_item_id)
            if (
                item is None
                or item.section != "excerpt"
                or item.source_kind != excerpt.source_kind
                or item.linked_subject_refs != excerpt.linked_subject_refs
                or item.content_digest != excerpt.content_digest
                or item.content_bytes != excerpt.content_bytes
            ):
                raise _invalid_case()
        if any(item.subject_ref not in allowed_refs for item in packet.omissions):
            raise _invalid_case()

        referenced_ids = {
            *packet.task_statement_item_ids,
            *packet.goal_item_ids,
            *packet.obligation_item_ids,
            *packet.claim_item_ids,
            *packet.decision_item_ids,
            *packet.prior_finding_item_ids,
            *packet.timeline_item_ids,
            *(item.excerpt_item_id for item in packet.targeted_excerpts),
        }
        for assessment in packet.deterministic_assessments:
            if assessment.summary_item_id is not None and assessment.detail_item_id is not None:
                referenced_ids.update((assessment.summary_item_id, assessment.detail_item_id))
        if referenced_ids != set(item_by_id):
            raise _invalid_case()

        if type(self.question_set) is not tuple:
            raise _invalid_case()
        questions = tuple(
            _snapshot_text(question, maximum_bytes=MAX_REVIEW_TEXT_BYTES, error=_invalid_case())
            for question in self.question_set
        )
        if len(questions) != len(set(questions)):
            raise _invalid_case()
        object.__setattr__(self, "question_set", questions)
        object.__setattr__(
            self, "case_digest", _snapshot_digest(self.case_digest, error=_invalid_case())
        )


@dataclass(frozen=True, slots=True)
class ReviewerChallenge:
    finding_kind: FindingKind
    summary: str
    cited_refs: tuple[str, ...]
    discrepancy: str
    alternative_interpretation: str
    message_to_main_agent: str
    requested_next_step: ReviewerNextStep
    uncertainty: str
    # Exact supporting quote from the packet. The provider contract requires this; the domain
    # keeps it separate from the structural challenge fields so older persisted findings can
    # still decode without one.
    snippet: str | None = None
    # The earlier finding this challenge restates (issue #980): one ``fnd_`` id from the packet's
    # prior findings. The check fences it like any citation; when it holds, the challenge is
    # recorded on that finding instead of minting an unrelated new one.
    restates: str | None = None

    def __post_init__(self) -> None:
        if type(self.finding_kind) is not FindingKind:
            raise _invalid_judgment()
        if self.restates is not None:
            if type(self.restates) is not str or not self.restates.startswith("fnd_"):
                raise _invalid_judgment()
            try:
                validate_id(IdKind.FINDING, self.restates)
            except ValueError as exc:
                raise _invalid_judgment() from exc
        for field_name in (
            "summary",
            "discrepancy",
            "alternative_interpretation",
            "message_to_main_agent",
            "uncertainty",
        ):
            object.__setattr__(
                self,
                field_name,
                _snapshot_text(
                    getattr(self, field_name),
                    maximum_bytes=MAX_REVIEW_TEXT_BYTES,
                    error=_invalid_judgment(),
                ),
            )
        object.__setattr__(
            self,
            "cited_refs",
            _validated_ref_tuple(
                self.cited_refs,
                minimum=1,
                maximum=_MAX_SUBJECT_REFS,
                public_only=False,
                error=_invalid_judgment(),
                canonicalize=True,
            ),
        )
        if type(self.requested_next_step) is not str or self.requested_next_step not in _NEXT_STEPS:
            raise _invalid_judgment()
        if self.snippet is not None:
            object.__setattr__(
                self,
                "snippet",
                _snapshot_text(
                    self.snippet, maximum_bytes=MAX_REVIEW_TEXT_BYTES, error=_invalid_judgment()
                ),
            )


type VerifiedReviewVerdict = Literal["supported", "not_supported", "not_assessable"]


@dataclass(frozen=True, slots=True)
class VerifiedReviewItem:
    """One per-requirement or per-claim reviewer judgement (issue #906 Part 2)."""

    requirement_or_claim: str
    verdict: VerifiedReviewVerdict
    cited_refs: tuple[str, ...]
    snippet: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "requirement_or_claim",
            _snapshot_text(
                self.requirement_or_claim,
                maximum_bytes=MAX_REVIEW_TEXT_BYTES,
                error=_invalid_judgment(),
            ),
        )
        if self.verdict not in {"supported", "not_supported", "not_assessable"}:
            raise _invalid_judgment()
        object.__setattr__(
            self,
            "cited_refs",
            _validated_ref_tuple(
                self.cited_refs,
                minimum=1,
                maximum=_MAX_SUBJECT_REFS,
                public_only=False,
                error=_invalid_judgment(),
                canonicalize=True,
            ),
        )
        if self.verdict == "not_assessable" and self.snippet is not None:
            raise _invalid_judgment()
        if self.verdict != "not_assessable" and self.snippet is None:
            raise _invalid_judgment()
        if self.snippet is not None:
            object.__setattr__(
                self,
                "snippet",
                _snapshot_text(
                    self.snippet, maximum_bytes=MAX_REVIEW_TEXT_BYTES, error=_invalid_judgment()
                ),
            )


type PriorFindingVerdictKind = Literal[
    "fixed", "still_present", "answered_not_fixed", "unassessable", "withdrawn"
]
PRIOR_FINDING_VERDICT_KINDS: Final = frozenset(
    {"fixed", "still_present", "answered_not_fixed", "unassessable", "withdrawn"}
)
_MAX_PRIOR_FINDING_VERDICTS: Final = MAX_PRIOR_FINDING_REFS


@dataclass(frozen=True, slots=True)
class PriorFindingVerdict:
    """The reviewer's ruling on one earlier finding (issue #905), before post-validation.

    The reviewer's free-text note is advisory reasoning for this turn only; it is never recorded.
    """

    finding_id: str
    verdict: PriorFindingVerdictKind
    cited_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "finding_id", _snapshot_finding_id(self.finding_id, error=_invalid_judgment())
        )
        if type(self.verdict) is not str or self.verdict not in PRIOR_FINDING_VERDICT_KINDS:
            raise _invalid_judgment()
        object.__setattr__(
            self,
            "cited_refs",
            _validated_ref_tuple(
                self.cited_refs,
                minimum=0,
                maximum=_MAX_SUBJECT_REFS,
                public_only=False,
                error=_invalid_judgment(),
                canonicalize=True,
            ),
        )


@dataclass(frozen=True, slots=True)
class MissingForAssessment:
    """One item an ``insufficient_packet`` reviewer said it needed (issue #907).

    ``target_refs`` are refs the reviewer cited from the packet; the check fence drops any that
    the frozen case does not contain. ``reason`` is bounded reviewer prose: it stays in the
    durable semantic response object and never enters a structural record or summary.
    """

    kind: MissingForAssessmentKind
    target_refs: tuple[str, ...]
    reason: str

    def __post_init__(self) -> None:
        if type(self.kind) is not str or self.kind not in MISSING_FOR_ASSESSMENT_KINDS:
            raise _invalid_judgment()
        object.__setattr__(
            self,
            "target_refs",
            _validated_ref_tuple(
                self.target_refs,
                minimum=0,
                maximum=MAX_MISSING_TARGET_REFS,
                public_only=False,
                error=_invalid_judgment(),
                canonicalize=True,
            ),
        )
        object.__setattr__(
            self,
            "reason",
            _snapshot_text(
                self.reason, maximum_bytes=MAX_MISSING_REASON_BYTES, error=_invalid_judgment()
            ),
        )


@dataclass(frozen=True, slots=True)
class SemanticJudgment:
    conclusion: SemanticConclusion
    challenges: tuple[ReviewerChallenge, ...]
    prior_finding_verdicts: tuple[PriorFindingVerdict, ...] = ()
    # Rulings the reviewer returned that were malformed or over the cap and so were never read.
    prior_finding_verdicts_dropped: int = 0
    # Named by every provider-judgment 1.1.0 ``insufficient_packet``. A durable semantic response
    # recorded before issue #907 decodes with none, so the domain value admits an empty tuple;
    # the provider schema is what requires at least one.
    missing_for_assessment: tuple[MissingForAssessment, ...] = ()
    # Part 2 is additive for old evaluator doubles and imported ledgers. New provider responses
    # must supply this field; legacy local scripts retain the explicit bounded fallback text.
    review_summary: str = "No review summary recorded."
    verified: tuple[VerifiedReviewItem, ...] = ()
    # Verified rows the normalizer dropped because their quote did not match their verdict
    # (supported/not_supported without a quote). Disclosed through the snippet gap.
    verified_dropped: int = 0

    def __post_init__(self) -> None:
        if type(self.conclusion) is not str or self.conclusion not in _CONCLUSIONS:
            raise _invalid_judgment()
        object.__setattr__(
            self,
            "review_summary",
            _snapshot_text(
                self.review_summary,
                maximum_bytes=MAX_REVIEW_TEXT_BYTES,
                error=_invalid_judgment(),
            ),
        )
        if (
            type(self.verified) is not tuple
            or len(self.verified) > MAX_REVIEW_ASSESSMENTS
            or any(type(item) is not VerifiedReviewItem for item in self.verified)
        ):
            raise _invalid_judgment()
        if type(self.challenges) is not tuple or len(self.challenges) > MAX_REVIEW_CHALLENGES:
            raise _invalid_judgment()
        if any(type(item) is not ReviewerChallenge for item in self.challenges):
            raise _invalid_judgment()
        if self.conclusion == "challenges_returned":
            if not self.challenges:
                raise _invalid_judgment()
        elif self.challenges:
            raise _invalid_judgment()
        if (
            type(self.missing_for_assessment) is not tuple
            or len(self.missing_for_assessment) > MAX_MISSING_FOR_ASSESSMENT
            or any(type(item) is not MissingForAssessment for item in self.missing_for_assessment)
        ):
            raise _invalid_judgment()
        if self.missing_for_assessment and self.conclusion != "insufficient_packet":
            raise _invalid_judgment()
        verdicts = self.prior_finding_verdicts
        if (
            type(verdicts) is not tuple
            or len(verdicts) > _MAX_PRIOR_FINDING_VERDICTS
            or any(type(item) is not PriorFindingVerdict for item in verdicts)
        ):
            raise _invalid_judgment()
        dropped = self.prior_finding_verdicts_dropped
        if type(dropped) is not int or not 0 <= dropped <= _MAX_SAFE_INTEGER:
            raise _invalid_judgment()
        verified_dropped = self.verified_dropped
        if type(verified_dropped) is not int or not 0 <= verified_dropped <= _MAX_SAFE_INTEGER:
            raise _invalid_judgment()


def _valid_pattern(
    value: object, pattern: re.Pattern[str], maximum: int, *, minimum: int = 1
) -> bool:
    return (
        type(value) is str
        and minimum <= len(value) <= maximum
        and pattern.fullmatch(value) is not None
    )


@dataclass(frozen=True, slots=True)
class ExternalRuntimeAuthority:
    """Secret-free one-attempt authority for a vendor-owned OAuth runtime."""

    dispatch_id: str
    request_body_digest: str
    request_commitment: str
    service_generation: int
    monotonic_deadline: float

    def __post_init__(self) -> None:
        validate_id(IdKind.EGRESS_DISPATCH, self.dispatch_id)
        validate_sha256_digest(self.request_body_digest)
        validate_commitment(self.request_commitment)
        if type(self.service_generation) is not int or self.service_generation < 1:
            raise ProtocolValueError("invalid_external_runtime_authority")
        if (
            type(self.monotonic_deadline) is not float
            or not math.isfinite(self.monotonic_deadline)
            or self.monotonic_deadline < 0.0
        ):
            raise ProtocolValueError("invalid_external_runtime_authority")


@dataclass(frozen=True, slots=True)
class ProviderAttemptProvenance:
    provider: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    model: str
    sdk_version: str
    prompt_digest: str
    schema_digest: str
    policy_digest: str
    privacy_policy_digest: str
    sampling_params: SamplingParams
    latency_ms: int
    status: SemanticStatus
    provider_request_id: str | None = None
    token_usage: TokenUsage | None = None
    cost_fields: CostFields | None = None
    failure_class: SemanticFailureClass | None = None
    request_commitment: str | None = None
    runtime_evidence: RuntimeAttemptEvidence | None = None

    def __post_init__(self) -> None:
        if not _valid_pattern(self.provider, _IDENTITY_PATTERN, 128):
            raise ProtocolValueError("invalid_semantic_provenance")
        if not _valid_pattern(self.endpoint_profile_id, _IDENTITY_PATTERN, 128):
            raise ProtocolValueError("invalid_semantic_provenance")
        if not _valid_pattern(
            self.endpoint_profile_version, _SEMANTIC_VERSION_PATTERN, 128, minimum=5
        ):
            raise ProtocolValueError("invalid_semantic_provenance")
        if not _valid_pattern(self.model, _MODEL_IDENTITY_PATTERN, 256):
            raise ProtocolValueError("invalid_semantic_provenance")
        if not _valid_pattern(self.sdk_version, _VERSION_IDENTITY_PATTERN, 128):
            raise ProtocolValueError("invalid_semantic_provenance")
        validate_sha256_digest(self.prompt_digest)
        validate_sha256_digest(self.schema_digest)
        validate_sha256_digest(self.policy_digest)
        validate_sha256_digest(self.privacy_policy_digest)
        if type(self.sampling_params) is not SamplingParams:
            raise ProtocolValueError("invalid_semantic_provenance")
        if type(self.latency_ms) is not int or not 0 <= self.latency_ms <= _MAX_SAFE_INTEGER:
            raise ProtocolValueError("invalid_semantic_provenance")
        if type(self.status) is not SemanticStatus or self.status not in {
            SemanticStatus.SUCCEEDED,
            SemanticStatus.REFUSED,
            SemanticStatus.TIMEOUT,
            SemanticStatus.INVALID,
            SemanticStatus.UNAVAILABLE,
            SemanticStatus.LATE,
        }:
            raise ProtocolValueError("invalid_semantic_provenance")
        if self.provider_request_id is not None and not _valid_pattern(
            self.provider_request_id, _PROVIDER_REQUEST_ID_PATTERN, 256
        ):
            raise ProtocolValueError("invalid_semantic_provenance")
        if self.token_usage is not None and type(self.token_usage) is not TokenUsage:
            raise ProtocolValueError("invalid_semantic_provenance")
        if self.cost_fields is not None and type(self.cost_fields) is not CostFields:
            raise ProtocolValueError("invalid_semantic_provenance")
        if self.failure_class is not None and type(self.failure_class) is not SemanticFailureClass:
            raise ProtocolValueError("invalid_semantic_failure_class")
        if self.request_commitment is not None:
            validate_commitment(self.request_commitment)
        if (
            self.runtime_evidence is not None
            and type(self.runtime_evidence) is not RuntimeAttemptEvidence
        ):
            raise ProtocolValueError("invalid_runtime_attempt_evidence")


def _validate_result_provenance(
    provenance: object,
    expected_status: SemanticStatus,
    representative_reason: SemanticReason,
) -> ProviderAttemptProvenance:
    validate_semantic_outcome(expected_status, representative_reason)
    if representative_reason not in VALID_SEMANTIC_REASONS[expected_status]:
        raise RuntimeError("semantic_status_registry_incomplete")
    if (
        type(provenance) is not ProviderAttemptProvenance
        or provenance.status is not expected_status
    ):
        raise ProtocolValueError("invalid_semantic_provenance")
    return provenance


@dataclass(frozen=True, slots=True)
class SemanticResultSuccess:
    judgment: SemanticJudgment
    provenance: ProviderAttemptProvenance

    def __post_init__(self) -> None:
        if type(self.judgment) is not SemanticJudgment:
            raise _invalid_judgment()
        _validate_result_provenance(
            self.provenance, SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED
        )


@dataclass(frozen=True, slots=True)
class SemanticResultRefused:
    provenance: ProviderAttemptProvenance

    def __post_init__(self) -> None:
        _validate_result_provenance(
            self.provenance, SemanticStatus.REFUSED, SemanticReason.PROVIDER_REFUSED
        )


@dataclass(frozen=True, slots=True)
class SemanticResultTimeout:
    provenance: ProviderAttemptProvenance

    def __post_init__(self) -> None:
        _validate_result_provenance(
            self.provenance, SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT
        )


@dataclass(frozen=True, slots=True)
class SemanticResultInvalid:
    provenance: ProviderAttemptProvenance
    raw_size: int

    def __post_init__(self) -> None:
        _validate_result_provenance(
            self.provenance, SemanticStatus.INVALID, SemanticReason.RESPONSE_SCHEMA_INVALID
        )
        if type(self.raw_size) is not int or not 0 <= self.raw_size <= _MAX_SAFE_INTEGER:
            raise ProtocolValueError("invalid_semantic_provenance")


@dataclass(frozen=True, slots=True)
class SemanticResultLate:
    provenance: ProviderAttemptProvenance

    def __post_init__(self) -> None:
        _validate_result_provenance(
            self.provenance, SemanticStatus.LATE, SemanticReason.DEADLINE_AUTHORITY_LOST
        )


@dataclass(frozen=True, slots=True)
class SemanticResultUnavailable:
    provenance: ProviderAttemptProvenance

    def __post_init__(self) -> None:
        _validate_result_provenance(
            self.provenance, SemanticStatus.UNAVAILABLE, SemanticReason.TRANSPORT_UNAVAILABLE
        )


type SemanticResult = (
    SemanticResultSuccess
    | SemanticResultRefused
    | SemanticResultTimeout
    | SemanticResultInvalid
    | SemanticResultLate
    | SemanticResultUnavailable
)


class SemanticEvaluatorPort(Protocol):
    """Provider plug-in callable only by the policy-enforcing outbound gateway."""

    async def evaluate(
        self,
        case: ApprovedProviderCase,  # pyright: ignore[reportUnknownParameterType]
        deadline: Deadline,
    ) -> SemanticResult: ...
