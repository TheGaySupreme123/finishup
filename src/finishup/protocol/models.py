"""Shared protocol constants, strict boundary models, and public envelopes."""

from __future__ import annotations

import re
import types
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from functools import lru_cache
from types import MappingProxyType
from typing import (
    Annotated,
    ClassVar,
    Final,
    Literal,
    Union,
    cast,
    get_args,
    get_origin,
)

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Discriminator,
    Field,
    RootModel,
    Tag,
    field_validator,
    model_validator,
)

from finishup.domain.coordination import (
    GrantState,
    LineageAcceptance,
    LineageOrigin,
    MemberKind,
    ProjectKind,
    SessionHealth,
    WorkState,
)
from finishup.legacy_names import LAUNCHER_NAMES
from finishup.protocol.canonical import JsonValue, parse_canonical_integer_string
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from finishup.protocol.errors import ProtocolValueError, PublicErrorCode
from finishup.protocol.guidance_uris import (
    REGISTERED_GUIDANCE_URIS as _REGISTERED_GUIDANCE_URIS,
)
from finishup.protocol.guidance_uris import (
    canonical_guidance_uri as _canonical_guidance_uri,
)
from finishup.protocol.ids import IdKind, validate_actor_id, validate_id
from finishup.protocol.redacted_values import (
    MAX_SEMANTIC_REDACTED_VALUE_ITEMS,
    MAX_SEMANTIC_REDACTED_VALUE_LINE,
    MAX_SEMANTIC_REDACTED_VALUE_LINES,
)

__all__ = [
    "GENESIS_PREDECESSOR_DIGEST",
    "MAX_CANONICAL_REQUEST_BYTES",
    "MAX_EVENTS_PER_BATCH",
    "MAX_FINDINGS_DEFAULT",
    "MAX_FINDINGS_LIMIT",
    "MAX_INTERNAL_PROJECTABLE_RESULT_BYTES",
    "MAX_MISSING_FOR_ASSESSMENT",
    "MAX_MISSING_REASON_BYTES",
    "MAX_MISSING_TARGET_REFS",
    "MAX_OBJECT_PLAINTEXT_BYTES",
    "MAX_REVIEW_ASSESSMENTS",
    "MAX_REVIEW_CHALLENGES",
    "MAX_REVIEW_CHANGE_OBSERVATIONS",
    "MAX_REVIEW_EXCERPTS",
    "MAX_REVIEW_FOLLOW_UP_ROUNDS",
    "MAX_REVIEW_OMISSIONS",
    "MAX_REVIEW_OMISSION_TOTAL",
    "MAX_REVIEW_TEXT_BYTES",
    "MAX_TASK_STATEMENT_BYTES",
    "MAX_REVIEW_TIMELINE_ITEMS",
    "MAX_SEMANTIC_CASE_BYTES",
    "MAX_SEMANTIC_ITEM_BYTES",
    "MAX_PROJECTED_RESULT_BYTES",
    "MAX_PROJECTION_CONTENT_LEAVES",
    "MAX_PROJECTION_POINTER_BYTES",
    "MAX_REASON_BYTES",
    "MISSING_FOR_ASSESSMENT_KINDS",
    "MISSING_ITEM_AVAILABILITIES",
    "PROTOCOL_VERSION",
    "ActorAssertionModel",
    "ActorType",
    "CheckRequest",
    "CheckRequestModel",
    "CheckResult",
    "CheckResultModel",
    "CheckScopeModel",
    "ClosurePrepareRequest",
    "ClosurePrepareRequestModel",
    "ClosurePrepareResult",
    "ClosurePrepareResultModel",
    "ClosureSelectionModel",
    "ClientInfoModel",
    "ClientKind",
    "CoverageModel",
    "DataCategory",
    "FrontierModel",
    "IntegrationKind",
    "JsonValue",
    "OmittedContentModel",
    "OperationFailureModel",
    "PrivacyProjectionModel",
    "PublicEnvelopeModel",
    "PublicErrorModel",
    "PublicRequestModel",
    "PublicResultModel",
    "PublicationChannel",
    "PublishWorkAcceptedMinimalEventModel",
    "PublishWorkAcceptedProjectionUnavailableModel",
    "PublishWorkRequest",
    "PublishWorkRequestModel",
    "PublishWorkResult",
    "PublishWorkResultModel",
    "ReceiptFormat",
    "ReceiptInclude",
    "ReceiptRedactionProfile",
    "ReceiptRequest",
    "ReceiptRequestModel",
    "ReceiptResult",
    "ReceiptResultModel",
    "WorkState",
    "SessionHealth",
    "LineageOrigin",
    "LineageAcceptance",
    "ProjectKind",
    "MembershipKind",
    "GrantState",
    "LineageRollupState",
    "LineageReadGapReason",
    "LineageProvenanceRestriction",
    "AttachHandleModel",
    "ChildFindingSnapshotModel",
    "ChildDependencySnapshotModel",
    "ChildDependenciesModel",
    "CheckChildPreviewItemModel",
    "CheckChildrenPreviewModel",
    "CheckAdvisoryNoteModel",
    "CheckFindingChallengeModel",
    "CheckVerifiedItemModel",
    "CheckMissingItemModel",
    "SemanticWithheldItemModel",
    "StatusLineageChildModel",
    "StatusLineageAnnotationModel",
    "StatusLineagePageModel",
    "ProjectTextRefModel",
    "StatusProjectMemberModel",
    "StatusProjectCoverageModel",
    "StatusProjectDetectionModel",
    "StatusProjectReceiptModel",
    "StatusProjectPageModel",
    "ReceiptChildOutcomeModel",
    "ReceiptChildrenModel",
    "REGISTERED_GUIDANCE_URIS",
    "ReadGuidanceRequest",
    "ReadGuidanceRequestModel",
    "ReadGuidanceResult",
    "ReadGuidanceResultModel",
    "ReadGuidanceContinuationModel",
    "ReadGuidanceSectionModel",
    "RespondRequest",
    "RespondRequestModel",
    "RespondResult",
    "RespondResultModel",
    "MAX_PRIOR_FINDING_VERDICTS",
    "PriorFindingVerdictWire",
    "ProviderChallengeModel",
    "ProviderVerifiedItemModel",
    "ProviderJudgmentChallengesModel",
    "ProviderJudgmentEnvelopeModel",
    "ProviderJudgmentInsufficientModel",
    "ProviderMissingItemModel",
    "ProviderJudgmentModel",
    "ProviderJudgmentNoDiscrepancyModel",
    "ProviderPriorFindingVerdictModel",
    "SEMANTIC_PROGRESS_PHASE_RANK",
    "SemanticProgressPhase",
    "SemanticReason",
    "SemanticStatus",
    "StatusSemanticProgressModel",
    "StartRequest",
    "StartRequestModel",
    "StartResult",
    "StartResultModel",
    "StatusRequest",
    "StatusRequestModel",
    "StatusResult",
    "StatusResultModel",
    "SubjectStateRefModel",
    "VALID_SEMANTIC_REASONS",
    "classify_result_leaf",
    "public_model_to_wire",
    "validate_semantic_outcome",
    "validate_semantic_provenance_binding",
]

PROTOCOL_VERSION: Final = "0.1"
MAX_EVENTS_PER_BATCH: Final = 100
MAX_CANONICAL_REQUEST_BYTES: Final = 1_048_576
MAX_FINDINGS_DEFAULT: Final = 3
MAX_FINDINGS_LIMIT: Final = 10
MAX_REASON_BYTES: Final = 4_096
MAX_OBJECT_PLAINTEXT_BYTES: Final = 4_194_304
MAX_SEMANTIC_ITEM_BYTES: Final = 16_384
MAX_SEMANTIC_CASE_BYTES: Final = 262_144
MAX_REVIEW_TEXT_BYTES: Final = 4_096
# The agent-transcribed task statement (issue #908), bounded by UTF-8 bytes. It is recorded whole
# far above what one review item carries (16 KiB): the packet keeps its head and tail and marks
# the elision, so the ledger never has to shorten the user's words to fit the reviewer.
MAX_TASK_STATEMENT_BYTES: Final = 65_536
MAX_REVIEW_TIMELINE_ITEMS: Final = 64
MAX_REVIEW_ASSESSMENTS: Final = 64
MAX_REVIEW_CHANGE_OBSERVATIONS: Final = 32
# The protocol maximum on targeted excerpts in one review packet. It exists only to bound work:
# the owner-approved byte budget (``max_total_excerpt_bytes``) is meant to bind first. Privacy
# policy 1.2.0 lets the Expanded preset use it; wire 1.0.0/1.1.0 still cap a policy at 16
# (issue #907 Phase 1b).
MAX_REVIEW_EXCERPTS: Final = 64
MAX_REVIEW_OMISSIONS: Final = 64
# The true count of distinct omissions behind a review input manifest's capped listed count
# (issue #976): far above anything a bounded ledger case produces, so it never saturates.
MAX_REVIEW_OMISSION_TOTAL: Final = 1_048_576
MAX_REVIEW_CHALLENGES: Final = 3
# JSON Schema ``maxLength`` counts Unicode code points, while the durable AI-powered review contract
# bounds review prose by UTF-8 bytes. Four bytes is the largest UTF-8 encoding of one valid
# Unicode scalar value, so this conservative provider-facing limit guarantees that every string
# admitted by the machine-enforced schema also fits the 4 KiB domain boundary.
MAX_PROVIDER_REVIEW_TEXT_CHARS: Final = MAX_REVIEW_TEXT_BYTES // 4
# ``insufficient_packet`` names what the reviewer needed (issue #907). Targets are refs already in
# the packet; the short reason stays in the durable semantic response, never in structural records.
MAX_MISSING_FOR_ASSESSMENT: Final = 8
MAX_MISSING_TARGET_REFS: Final = 4
# Issue #1047: inside one check FinishUP may answer the reviewer's own request from its records and
# ask again at most this many times (the review input manifest's ``follow_up_round``).
MAX_REVIEW_FOLLOW_UP_ROUNDS: Final = 3
MAX_MISSING_REASON_BYTES: Final = 1_024
MAX_PROVIDER_MISSING_REASON_CHARS: Final = MAX_MISSING_REASON_BYTES // 4
MISSING_FOR_ASSESSMENT_KINDS: Final = frozenset(
    {
        "command_identity",
        "current_diff_for_path",
        "other",
        "plan_or_claim_text",
        "prior_finding_context",
        "task_statement",
        "verification_output",
    }
)
# Frozen legacy identifier (ADR-048): the ``yoetz_limit_*`` availability values are released.
MISSING_ITEM_AVAILABILITIES: Final = frozenset(
    {
        "agent_suppliable",
        "structurally_unavailable_on_this_host",
        "yoetz_limit_packet_room",
        "yoetz_limit_unsupported_data_type",
    }
)
GENESIS_PREDECESSOR_DIGEST: Final = "genesis"
MAX_PROJECTION_CONTENT_LEAVES: Final = 512
MAX_PROJECTION_POINTER_BYTES: Final = 256
MAX_INTERNAL_PROJECTABLE_RESULT_BYTES: Final = 524_288
MAX_PROJECTED_RESULT_BYTES: Final = 1_048_576


class ActorType(str, Enum):  # noqa: UP042 - exact public wire enum base
    HUMAN = "human"
    HARNESS = "harness"
    LOGICAL_AGENT = "logical_agent"
    MODEL_BACKED_WORKER = "model_backed_worker"
    DELEGATED_SUBAGENT = "delegated_subagent"
    # Frozen legacy identifier (ADR-048): the released actor-type wire value.
    FINISHUP_ENGINE = "yoetz_engine"
    IMPORTER = "importer"


class DataCategory(str, Enum):  # noqa: UP042 - exact public wire enum base
    BOUNDED_STRUCTURAL_METADATA = "bounded_structural_metadata"
    DECLARED_FILE_TYPE = "declared_file_type"
    TASK_DESCRIPTION = "task_description"
    CLAIM_TEXT = "claim_text"
    OBLIGATION_TEXT = "obligation_text"
    DECISION_EXCERPT = "decision_excerpt"
    EVIDENCE_EXCERPT = "evidence_excerpt"
    FINDING_SUMMARY = "finding_summary"
    COMMAND_METADATA = "command_metadata"
    DIFF_METADATA = "diff_metadata"
    REPOSITORY_EXCERPT = "repository_excerpt"
    TRANSCRIPT_EXCERPT = "transcript_excerpt"
    DIAGNOSTIC_METADATA = "diagnostic_metadata"


class ClientKind(str, Enum):  # noqa: UP042 - exact public wire enum base
    CODEX_CLI = "codex_cli"
    COOPERATIVE_AGENT = "cooperative_agent"
    # Frozen legacy identifier (ADR-048): the released client-kind wire value.
    FINISHUP_CLI = "yoetz_cli"
    TEST_CLIENT = "test_client"
    IMPORTER = "importer"


class IntegrationKind(str, Enum):  # noqa: UP042 - exact public wire enum base
    COOPERATIVE_MCP = "cooperative_mcp"
    LOCAL_CLI = "local_cli"
    CODEX_JSONL_IMPORT = "codex_jsonl_import"


MembershipKind = MemberKind


class LineageRollupState(str, Enum):  # noqa: UP042 - exact wire enum base
    CLEAN = "clean"
    ANNOTATION = "annotation"
    BLOCKED = "blocked"
    OPEN_GAP = "open_gap"
    INCOMPLETE = "incomplete"
    UNAVAILABLE = "unavailable"


class LineageReadGapReason(str, Enum):  # noqa: UP042 - exact wire enum base
    MISSING = "missing"
    UNREADABLE = "unreadable"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"
    NOT_AUTHORIZED = "not_authorized"
    UNKNOWN = "unknown"


class LineageProvenanceRestriction(str, Enum):  # noqa: UP042 - exact wire enum base
    CATEGORY_RESTRICTED = "category_restricted"
    NEVER_SEND = "never_send"
    TASK_SCOPE = "task_scope"
    MINIMIZATION = "minimization"
    AUTHORIZATION_MISSING = "authorization_missing"


class ReceiptFormat(str, Enum):  # noqa: UP042 - exact public wire enum base
    JSON = "json"
    MARKDOWN = "markdown"
    TEXT = "text"


class ReceiptInclude(str, Enum):  # noqa: UP042 - exact public wire enum base
    SUMMARY = "summary"
    STANDARD = "standard"
    FULL = "full"


class ReceiptRedactionProfile(str, Enum):  # noqa: UP042 - exact public wire enum base
    FULL_LOCAL = "full_local"
    DEFAULT_LOCAL_EXPORT = "default_local_export"
    REDACTED_SHARE = "redacted_share"


class SemanticStatus(str, Enum):  # noqa: UP042 - exact public wire enum base
    NOT_REQUESTED = "not_requested"
    NOT_CONFIGURED = "not_configured"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    BLOCKED_FORBIDDEN_DATA = "blocked_forbidden_data"
    CLASSIFICATION_UNCERTAIN = "classification_uncertain"
    AWAITING_HUMAN = "awaiting_human"
    HUMAN_DENIED = "human_denied"
    APPROVAL_EXPIRED = "approval_expired"
    SUCCEEDED = "succeeded"
    REFUSED = "refused"
    TIMEOUT = "timeout"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"
    LATE = "late"
    STALE = "stale"
    FAILED = "failed"


class SemanticReason(str, Enum):  # noqa: UP042 - exact public wire enum base
    DETERMINISTIC_MODE = "deterministic_mode"
    # Pre-edit deferral (#1046). Distinct from DETERMINISTIC_MODE so a reader does not
    # treat an AI-powered setting as ignored. Admitted on check-result / check-recorded 1.5.0.
    DEFERRED_BEFORE_FIRST_EDIT = "deferred_before_first_edit"
    NO_MATERIAL_SEMANTIC_CASE = "no_material_semantic_case"
    PROVIDER_NOT_CONFIGURED = "provider_not_configured"
    LOCAL_MODEL_NOT_CONFIGURED = "local_model_not_configured"
    NETWORK_EGRESS_DENIED = "network_egress_denied"
    ROUTE_SEMANTIC_CEILING = "route_semantic_ceiling"
    CHANNEL_DISABLED = "channel_disabled"
    PROVIDER_BINDING_NOT_AUTHORIZED = "provider_binding_not_authorized"
    SCOPE_NOT_AUTHORIZED = "scope_not_authorized"
    CONTENT_CATEGORY_NOT_AUTHORIZED = "content_category_not_authorized"
    POLICY_GENERATION_REVOKED = "policy_generation_revoked"
    NEVER_SEND_DETECTED = "never_send_detected"
    SECRET_DETECTED = "secret_detected"
    CLASSIFICATION_UNCERTAIN = "classification_uncertain"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"
    HUMAN_DENIED = "human_denied"
    HUMAN_APPROVAL_EXPIRED = "human_approval_expired"
    SEMANTIC_COMPLETED = "semantic_completed"
    PROVIDER_REFUSED = "provider_refused"
    PROVIDER_TIMEOUT = "provider_timeout"
    RESPONSE_SCHEMA_INVALID = "response_schema_invalid"
    RESPONSE_CONTENT_INVALID = "response_content_invalid"
    SEMANTIC_JUDGMENT_REJECTED = "semantic_judgment_rejected"
    CREDENTIAL_UNAVAILABLE = "credential_unavailable"
    ENDPOINT_PROFILE_UNAVAILABLE = "endpoint_profile_unavailable"
    TRANSPORT_UNAVAILABLE = "transport_unavailable"
    PROVIDER_RATE_LIMITED = "provider_rate_limited"
    PROVIDER_QUOTA_EXHAUSTED = "provider_quota_exhausted"
    RETRY_BUDGET_EXHAUSTED = "retry_budget_exhausted"
    AUDIT_RESERVATION_UNAVAILABLE = "audit_reservation_unavailable"
    RECEIPT_PERSISTENCE_UNKNOWN = "receipt_persistence_unknown"
    OUTCOME_UNKNOWN = "outcome_unknown"
    DEADLINE_AUTHORITY_LOST = "deadline_authority_lost"
    LEASE_AUTHORITY_LOST = "lease_authority_lost"
    FRONTIER_CHANGED = "frontier_changed"
    DEPENDENCY_CHANGED = "dependency_changed"
    CASE_CAPACITY_EXCEEDED = "case_capacity_exceeded"
    COORDINATOR_FAILURE = "coordinator_failure"


class SemanticProgressPhase(str, Enum):  # noqa: UP042 - exact public wire enum base
    """Structural phase of one durable AI-powered review job (issue #571 item A2).

    Declaration order is execution order. A job's recorded phase only moves forward: within one
    physical attempt by this order, and across attempts by attempt ordinal. ``terminal`` is
    derived from the terminal job row, so there is exactly one terminal state per job.
    """

    QUEUED = "queued"
    CASE_ADMITTED = "case_admitted"
    RUNTIME_STARTING = "runtime_starting"
    ACCOUNT_MODEL_VALIDATION = "account_model_validation"
    PROVIDER_SAMPLING = "provider_sampling"
    RESPONSE_VALIDATION = "response_validation"
    CLEANUP = "cleanup"
    TERMINAL = "terminal"


SEMANTIC_PROGRESS_PHASE_RANK: Final[Mapping[SemanticProgressPhase, int]] = MappingProxyType(
    {phase: index for index, phase in enumerate(SemanticProgressPhase, start=1)}
)


VALID_SEMANTIC_REASONS: Final[Mapping[SemanticStatus, frozenset[SemanticReason]]] = (
    MappingProxyType(
        {
            SemanticStatus.NOT_REQUESTED: frozenset(
                {
                    SemanticReason.DETERMINISTIC_MODE,
                    SemanticReason.DEFERRED_BEFORE_FIRST_EDIT,
                    SemanticReason.NO_MATERIAL_SEMANTIC_CASE,
                }
            ),
            SemanticStatus.NOT_CONFIGURED: frozenset(
                {SemanticReason.PROVIDER_NOT_CONFIGURED, SemanticReason.LOCAL_MODEL_NOT_CONFIGURED}
            ),
            SemanticStatus.BLOCKED_BY_POLICY: frozenset(
                {
                    SemanticReason.NETWORK_EGRESS_DENIED,
                    SemanticReason.ROUTE_SEMANTIC_CEILING,
                    SemanticReason.CHANNEL_DISABLED,
                    SemanticReason.PROVIDER_BINDING_NOT_AUTHORIZED,
                    SemanticReason.SCOPE_NOT_AUTHORIZED,
                    SemanticReason.CONTENT_CATEGORY_NOT_AUTHORIZED,
                    SemanticReason.POLICY_GENERATION_REVOKED,
                }
            ),
            SemanticStatus.BLOCKED_FORBIDDEN_DATA: frozenset(
                {SemanticReason.NEVER_SEND_DETECTED, SemanticReason.SECRET_DETECTED}
            ),
            SemanticStatus.CLASSIFICATION_UNCERTAIN: frozenset(
                {SemanticReason.CLASSIFICATION_UNCERTAIN}
            ),
            SemanticStatus.AWAITING_HUMAN: frozenset({SemanticReason.HUMAN_APPROVAL_REQUIRED}),
            SemanticStatus.HUMAN_DENIED: frozenset({SemanticReason.HUMAN_DENIED}),
            SemanticStatus.APPROVAL_EXPIRED: frozenset({SemanticReason.HUMAN_APPROVAL_EXPIRED}),
            SemanticStatus.SUCCEEDED: frozenset({SemanticReason.SEMANTIC_COMPLETED}),
            SemanticStatus.REFUSED: frozenset({SemanticReason.PROVIDER_REFUSED}),
            SemanticStatus.TIMEOUT: frozenset({SemanticReason.PROVIDER_TIMEOUT}),
            SemanticStatus.INVALID: frozenset(
                {
                    SemanticReason.RESPONSE_SCHEMA_INVALID,
                    SemanticReason.RESPONSE_CONTENT_INVALID,
                    SemanticReason.SEMANTIC_JUDGMENT_REJECTED,
                }
            ),
            SemanticStatus.UNAVAILABLE: frozenset(
                {
                    SemanticReason.CREDENTIAL_UNAVAILABLE,
                    SemanticReason.ENDPOINT_PROFILE_UNAVAILABLE,
                    SemanticReason.TRANSPORT_UNAVAILABLE,
                    SemanticReason.PROVIDER_RATE_LIMITED,
                    SemanticReason.PROVIDER_QUOTA_EXHAUSTED,
                    SemanticReason.RETRY_BUDGET_EXHAUSTED,
                    SemanticReason.AUDIT_RESERVATION_UNAVAILABLE,
                    SemanticReason.RECEIPT_PERSISTENCE_UNKNOWN,
                    SemanticReason.OUTCOME_UNKNOWN,
                }
            ),
            SemanticStatus.LATE: frozenset(
                {SemanticReason.DEADLINE_AUTHORITY_LOST, SemanticReason.LEASE_AUTHORITY_LOST}
            ),
            SemanticStatus.STALE: frozenset(
                {SemanticReason.FRONTIER_CHANGED, SemanticReason.DEPENDENCY_CHANGED}
            ),
            SemanticStatus.FAILED: frozenset(
                {SemanticReason.COORDINATOR_FAILURE, SemanticReason.CASE_CAPACITY_EXCEEDED}
            ),
        }
    )
)


_PREDISPATCH_SEMANTIC_STATUSES: Final[frozenset[SemanticStatus]] = frozenset(
    {
        SemanticStatus.NOT_REQUESTED,
        SemanticStatus.NOT_CONFIGURED,
        SemanticStatus.BLOCKED_BY_POLICY,
        SemanticStatus.BLOCKED_FORBIDDEN_DATA,
        SemanticStatus.CLASSIFICATION_UNCERTAIN,
        SemanticStatus.AWAITING_HUMAN,
        SemanticStatus.HUMAN_DENIED,
        SemanticStatus.APPROVAL_EXPIRED,
    }
)
_REQUIRED_SEMANTIC_PROVENANCE_STATUSES: Final[frozenset[SemanticStatus]] = frozenset(
    {
        SemanticStatus.SUCCEEDED,
        SemanticStatus.REFUSED,
        SemanticStatus.TIMEOUT,
        SemanticStatus.INVALID,
        SemanticStatus.LATE,
        SemanticStatus.STALE,
    }
)
_REQUIRED_UNAVAILABLE_PROVENANCE_REASONS: Final[frozenset[SemanticReason]] = frozenset(
    {
        SemanticReason.TRANSPORT_UNAVAILABLE,
        SemanticReason.PROVIDER_RATE_LIMITED,
        SemanticReason.PROVIDER_QUOTA_EXHAUSTED,
        SemanticReason.OUTCOME_UNKNOWN,
    }
)
_FORBIDDEN_UNAVAILABLE_PROVENANCE_REASONS: Final[frozenset[SemanticReason]] = frozenset(
    {
        SemanticReason.CREDENTIAL_UNAVAILABLE,
        SemanticReason.ENDPOINT_PROFILE_UNAVAILABLE,
        SemanticReason.RETRY_BUDGET_EXHAUSTED,
        SemanticReason.AUDIT_RESERVATION_UNAVAILABLE,
        SemanticReason.RECEIPT_PERSISTENCE_UNKNOWN,
    }
)


def validate_semantic_outcome(status: SemanticStatus, reason: SemanticReason) -> None:
    """Validate one exact AI-powered review status/reason pair without coercion."""

    if type(status) is not SemanticStatus or type(reason) is not SemanticReason:
        raise ProtocolValueError("invalid_semantic_outcome_type")
    if reason not in VALID_SEMANTIC_REASONS[status]:
        raise ProtocolValueError("invalid_semantic_status_reason_pair")


def validate_semantic_provenance_binding(
    status: SemanticStatus,
    reason: SemanticReason,
    provenance_status: SemanticStatus | None,
    provenance_reason: SemanticReason | None,
) -> None:
    """Validate the closed provenance-presence and final-attempt identity partition."""

    validate_semantic_outcome(status, reason)

    if provenance_status is None and provenance_reason is None:
        provenance_present = False
    elif type(provenance_status) is SemanticStatus and type(provenance_reason) is SemanticReason:
        provenance_present = True
    else:
        raise ProtocolValueError("invalid_semantic_provenance")

    if provenance_present and (provenance_status is not status or provenance_reason is not reason):
        raise ProtocolValueError("invalid_semantic_provenance")

    if status in _PREDISPATCH_SEMANTIC_STATUSES or reason is SemanticReason.CASE_CAPACITY_EXCEEDED:
        provenance_required = False
    elif status in _REQUIRED_SEMANTIC_PROVENANCE_STATUSES:
        provenance_required = True
    elif status is SemanticStatus.UNAVAILABLE:
        if reason in _REQUIRED_UNAVAILABLE_PROVENANCE_REASONS:
            provenance_required = True
        elif reason in _FORBIDDEN_UNAVAILABLE_PROVENANCE_REASONS:
            provenance_required = False
        else:  # pragma: no cover - guarded by validate_semantic_outcome
            raise ProtocolValueError("invalid_semantic_provenance")
    elif status is SemanticStatus.FAILED:
        return
    else:  # pragma: no cover - the enum and status/reason registry are closed
        raise ProtocolValueError("invalid_semantic_provenance")

    if provenance_present is not provenance_required:
        raise ProtocolValueError("invalid_semantic_provenance")


_ORDINARY_CONFIG: Final = ConfigDict(
    extra="forbid", frozen=True, strict=True, validate_default=True
)
_ROOT_CONFIG: Final = ConfigDict(frozen=True, strict=True, validate_default=True)
_DIGEST_PATTERN: Final = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_COMMITMENT_PATTERN: Final = re.compile(r"^hmac-sha256:[0-9a-f]{64}$", re.ASCII)
_TIMESTAMP_PATTERN: Final = re.compile(
    r"^(?:[0-9]{4})-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$",
    re.ASCII,
)
_JSON_POINTER_PATTERN: Final = re.compile(r"^(?:/(?:[^~/\x00-\x1f\x7f]|~[01])*)+$")
_CANONICAL_PAGE_LIMITS: Final = frozenset(str(value) for value in range(1, 101))
_MAX_FINDING_LITERALS: Final = frozenset(str(value) for value in range(1, 11))


def _enum_from_wire[T: Enum](value: object, enum_type: type[T]) -> T:
    if type(value) is not str:
        raise ValueError("wire_enum_wrong_type")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ValueError("wire_enum_invalid") from exc


def _actor_type_from_wire(value: object) -> ActorType:
    return _enum_from_wire(value, ActorType)


def _client_kind_from_wire(value: object) -> ClientKind:
    return _enum_from_wire(value, ClientKind)


def _integration_kind_from_wire(value: object) -> IntegrationKind:
    return _enum_from_wire(value, IntegrationKind)


def _public_error_code_from_wire(value: object) -> PublicErrorCode:
    return _enum_from_wire(value, PublicErrorCode)


def _publication_channel_from_wire(value: object) -> PublicationChannel:
    return _enum_from_wire(value, PublicationChannel)


def _authorship_assurance_from_wire(value: object) -> AuthorshipAssurance:
    return _enum_from_wire(value, AuthorshipAssurance)


def _artifact_observation_from_wire(value: object) -> ArtifactObservation:
    return _enum_from_wire(value, ArtifactObservation)


def _evidence_immutability_from_wire(value: object) -> EvidenceImmutability:
    return _enum_from_wire(value, EvidenceImmutability)


def _ledger_freshness_from_wire(value: object) -> LedgerFreshness:
    return _enum_from_wire(value, LedgerFreshness)


def _check_type_from_wire(value: object) -> CheckType:
    return _enum_from_wire(value, CheckType)


def _data_category_from_wire(value: object) -> DataCategory:
    return _enum_from_wire(value, DataCategory)


def _work_state_from_wire(value: object) -> WorkState:
    return _enum_from_wire(value, WorkState)


def _session_health_from_wire(value: object) -> SessionHealth:
    return _enum_from_wire(value, SessionHealth)


def _lineage_origin_from_wire(value: object) -> LineageOrigin:
    return _enum_from_wire(value, LineageOrigin)


def _lineage_acceptance_from_wire(value: object) -> LineageAcceptance:
    return _enum_from_wire(value, LineageAcceptance)


def _project_kind_from_wire(value: object) -> ProjectKind:
    return _enum_from_wire(value, ProjectKind)


def _membership_kind_from_wire(value: object) -> MembershipKind:
    return _enum_from_wire(value, MembershipKind)


def _grant_state_from_wire(value: object) -> GrantState:
    return _enum_from_wire(value, GrantState)


def _lineage_rollup_state_from_wire(value: object) -> LineageRollupState:
    return _enum_from_wire(value, LineageRollupState)


def _lineage_read_gap_reason_from_wire(value: object) -> LineageReadGapReason:
    return _enum_from_wire(value, LineageReadGapReason)


def _lineage_provenance_restriction_from_wire(value: object) -> LineageProvenanceRestriction:
    return _enum_from_wire(value, LineageProvenanceRestriction)


def _receipt_format_from_wire(value: object) -> ReceiptFormat:
    return _enum_from_wire(value, ReceiptFormat)


def _receipt_include_from_wire(value: object) -> ReceiptInclude:
    return _enum_from_wire(value, ReceiptInclude)


def _receipt_redaction_profile_from_wire(value: object) -> ReceiptRedactionProfile:
    return _enum_from_wire(value, ReceiptRedactionProfile)


def _semantic_status_from_wire(value: object) -> SemanticStatus:
    return _enum_from_wire(value, SemanticStatus)


def _semantic_reason_from_wire(value: object) -> SemanticReason:
    return _enum_from_wire(value, SemanticReason)


def _semantic_progress_phase_from_wire(value: object) -> SemanticProgressPhase:
    return _enum_from_wire(value, SemanticProgressPhase)


def _validate_id_wire(kind: IdKind, value: object) -> str:
    return validate_id(kind, value)


def _request_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.REQUEST, value)


def _session_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.SESSION, value)


def _writer_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.WRITER, value)


def _claim_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.CLAIM, value)


def _obligation_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.OBLIGATION, value)


def _task_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.TASK, value)


def _project_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.PROJECT, value)


def _finding_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.FINDING, value)


def _evidence_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.EVIDENCE, value)


def _result_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.RESULT, value)


def _event_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.EVENT, value)


def _object_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.OBJECT, value)


def _receipt_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.RECEIPT, value)


def _evidence_or_result_id_wire(value: object) -> str:
    try:
        return _evidence_id_wire(value)
    except ProtocolValueError:
        return _result_id_wire(value)


def _correlation_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.CORRELATION, value)


def _privacy_policy_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.PRIVACY_POLICY, value)


def _privacy_proposal_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.PRIVACY_PROPOSAL, value)


def _egress_receipt_id_wire(value: object) -> str:
    return _validate_id_wire(IdKind.EGRESS_RECEIPT, value)


def _actor_assertion_id_wire(value: object) -> str:
    return validate_actor_id(value)


def _canonical_uint_wire(value: object) -> str:
    if type(value) is not str:
        raise ProtocolValueError("noncanonical_integer_string")
    parse_canonical_integer_string(value)
    return value


def _canonical_positive_uint_wire(value: object) -> str:
    validated = _canonical_uint_wire(value)
    if validated == "0":
        raise ProtocolValueError("noncanonical_integer_string")
    return validated


def _canonical_page_limit_wire(value: object) -> str:
    # tb4n4 (#1049): four status calls sent ``limit`` as a JSON integer. A page size has one
    # meaning in either spelling, so an integer from 1 to 100 is read as its canonical decimal
    # string here, before the schema check, routing or any hash sees the request. ``bool`` is
    # not admitted (``type(True) is bool``), and every other value keeps the refusal.
    if type(value) is int and 1 <= value <= 100:
        value = str(value)
    if type(value) is not str or value not in _CANONICAL_PAGE_LIMITS:
        raise ProtocolValueError("noncanonical_integer_string")
    return value


def _digest_wire(value: object) -> str:
    if type(value) is not str or _DIGEST_PATTERN.fullmatch(value) is None:
        raise ProtocolValueError("invalid_digest")
    return value


def _genesis_or_digest_wire(value: object) -> str:
    if value == GENESIS_PREDECESSOR_DIGEST and type(value) is str:
        return value
    return _digest_wire(value)


def _commitment_wire(value: object) -> str:
    if type(value) is not str or _COMMITMENT_PATTERN.fullmatch(value) is None:
        raise ProtocolValueError("invalid_commitment")
    return value


def _timestamp_wire(value: object) -> str:
    if type(value) is not str or _TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise ProtocolValueError("invalid_timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise ProtocolValueError("invalid_timestamp") from exc
    return value


def _json_pointer_wire(value: object) -> str:
    if type(value) is not str:
        raise ProtocolValueError("invalid_json_pointer")
    if unicodedata.normalize("NFC", value) != value:
        raise ProtocolValueError("invalid_json_pointer")
    try:
        pointer_size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ProtocolValueError("invalid_json_pointer") from exc
    if pointer_size > MAX_PROJECTION_POINTER_BYTES:
        raise ProtocolValueError("invalid_json_pointer")
    if _JSON_POINTER_PATTERN.fullmatch(value) is None:
        raise ProtocolValueError("invalid_json_pointer")
    return value


ActorTypeWire = Annotated[ActorType, BeforeValidator(_actor_type_from_wire)]
ClientKindWire = Annotated[ClientKind, BeforeValidator(_client_kind_from_wire)]
IntegrationKindWire = Annotated[IntegrationKind, BeforeValidator(_integration_kind_from_wire)]
PublicErrorCodeWire = Annotated[PublicErrorCode, BeforeValidator(_public_error_code_from_wire)]
PublicationChannelWire = Annotated[
    PublicationChannel, BeforeValidator(_publication_channel_from_wire)
]
AuthorshipAssuranceWire = Annotated[
    AuthorshipAssurance, BeforeValidator(_authorship_assurance_from_wire)
]
ArtifactObservationWire = Annotated[
    ArtifactObservation, BeforeValidator(_artifact_observation_from_wire)
]
EvidenceImmutabilityWire = Annotated[
    EvidenceImmutability, BeforeValidator(_evidence_immutability_from_wire)
]
LedgerFreshnessWire = Annotated[LedgerFreshness, BeforeValidator(_ledger_freshness_from_wire)]
CheckTypeWire = Annotated[CheckType, BeforeValidator(_check_type_from_wire)]
# Built-in policy-pack identities (``finishup.protocol.policy_packs``). Requests select only current
# packs; results and recorded rows also admit the earlier identities a ledger or an older 0.3
# service may still carry.
RecordedPolicyVersionWire = Literal["0.1.0", "0.2.0", "0.3.0"]
CurrentPolicyPackWire = Literal[
    "coordination/0.1.0", "research-evidence/0.2.0", "work-integrity/0.3.0"
]
RecordedPolicyPackWire = Literal[
    "coordination/0.1.0",
    "research-evidence/0.1.0",
    "research-evidence/0.2.0",
    "work-integrity/0.1.0",
    "work-integrity/0.2.0",
    "work-integrity/0.3.0",
]
RecordedVersionSlicePackWire = Literal[
    "research-evidence/0.1.0",
    "research-evidence/0.2.0",
    "work-integrity/0.1.0",
    "work-integrity/0.2.0",
    "work-integrity/0.3.0",
]
DataCategoryWire = Annotated[DataCategory, BeforeValidator(_data_category_from_wire)]
WorkStateWire = Annotated[WorkState, BeforeValidator(_work_state_from_wire)]
SessionHealthWire = Annotated[SessionHealth, BeforeValidator(_session_health_from_wire)]
LineageOriginWire = Annotated[LineageOrigin, BeforeValidator(_lineage_origin_from_wire)]
LineageAcceptanceWire = Annotated[LineageAcceptance, BeforeValidator(_lineage_acceptance_from_wire)]
ProjectKindWire = Annotated[ProjectKind, BeforeValidator(_project_kind_from_wire)]
MembershipKindWire = Annotated[MembershipKind, BeforeValidator(_membership_kind_from_wire)]
GrantStateWire = Annotated[GrantState, BeforeValidator(_grant_state_from_wire)]
LineageRollupStateWire = Annotated[
    LineageRollupState, BeforeValidator(_lineage_rollup_state_from_wire)
]
LineageReadGapReasonWire = Annotated[
    LineageReadGapReason,
    BeforeValidator(_lineage_read_gap_reason_from_wire),
]
LineageProvenanceRestrictionWire = Annotated[
    LineageProvenanceRestriction,
    BeforeValidator(_lineage_provenance_restriction_from_wire),
]
ReceiptFormatWire = Annotated[ReceiptFormat, BeforeValidator(_receipt_format_from_wire)]
ReceiptIncludeWire = Annotated[ReceiptInclude, BeforeValidator(_receipt_include_from_wire)]
ReceiptRedactionProfileWire = Annotated[
    ReceiptRedactionProfile, BeforeValidator(_receipt_redaction_profile_from_wire)
]
SemanticStatusWire = Annotated[SemanticStatus, BeforeValidator(_semantic_status_from_wire)]
SemanticReasonWire = Annotated[SemanticReason, BeforeValidator(_semantic_reason_from_wire)]
SemanticProgressPhaseWire = Annotated[
    SemanticProgressPhase, BeforeValidator(_semantic_progress_phase_from_wire)
]

ActorAssertionIdWire = Annotated[str, BeforeValidator(_actor_assertion_id_wire)]
RequestIdWire = Annotated[str, BeforeValidator(_request_id_wire)]
SessionIdWire = Annotated[str, BeforeValidator(_session_id_wire)]
WriterIdWire = Annotated[str, BeforeValidator(_writer_id_wire)]
ClaimIdWire = Annotated[str, BeforeValidator(_claim_id_wire)]
ObligationIdWire = Annotated[str, BeforeValidator(_obligation_id_wire)]
TaskIdWire = Annotated[str, BeforeValidator(_task_id_wire)]
ProjectIdWire = Annotated[str, BeforeValidator(_project_id_wire)]
FindingIdWire = Annotated[str, BeforeValidator(_finding_id_wire)]
EvidenceIdWire = Annotated[str, BeforeValidator(_evidence_id_wire)]
ResultIdWire = Annotated[str, BeforeValidator(_result_id_wire)]
ActionIdWire = Annotated[
    str,
    Field(pattern=r"^act_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
]
EventIdWire = Annotated[str, BeforeValidator(_event_id_wire)]
ObjectIdWire = Annotated[str, BeforeValidator(_object_id_wire)]
ReceiptIdWire = Annotated[str, BeforeValidator(_receipt_id_wire)]
EvidenceOrResultIdWire = Annotated[str, BeforeValidator(_evidence_or_result_id_wire)]
CorrelationIdWire = Annotated[str, BeforeValidator(_correlation_id_wire)]
PrivacyPolicyIdWire = Annotated[str, BeforeValidator(_privacy_policy_id_wire)]
PrivacyProposalIdWire = Annotated[str, BeforeValidator(_privacy_proposal_id_wire)]
EgressReceiptIdWire = Annotated[str, BeforeValidator(_egress_receipt_id_wire)]
CanonicalUInt64Wire = Annotated[str, BeforeValidator(_canonical_uint_wire)]
CanonicalPositiveUInt64Wire = Annotated[str, BeforeValidator(_canonical_positive_uint_wire)]
CanonicalPageLimitWire = Annotated[str, BeforeValidator(_canonical_page_limit_wire)]
Sha256Digest = Annotated[str, BeforeValidator(_digest_wire)]
GenesisOrSha256Digest = Annotated[str, BeforeValidator(_genesis_or_digest_wire)]
HmacSha256Commitment = Annotated[str, BeforeValidator(_commitment_wire)]
TimestampWire = Annotated[str, BeforeValidator(_timestamp_wire)]
JsonPointer = Annotated[str, BeforeValidator(_json_pointer_wire)]
String1To256 = Annotated[str, Field(min_length=1, max_length=256)]
OpaqueItemId = Annotated[
    str,
    Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    ),
]
String1To4096 = Annotated[str, Field(min_length=1, max_length=4096)]
String1To8192 = Annotated[str, Field(min_length=1, max_length=8192)]
String0To1024 = Annotated[str, Field(max_length=1024)]
String1To32768 = Annotated[str, Field(min_length=1, max_length=32768)]
TaskStatementWire = Annotated[str, Field(min_length=1, max_length=MAX_TASK_STATEMENT_BYTES)]
CursorWire = Annotated[str, Field(min_length=1, max_length=4096, pattern=r"^[A-Za-z0-9_-]+$")]
SchemaNameWire = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]
SubjectIdWire = Annotated[
    str,
    Field(
        pattern=r"^(act|clm|evd|evt|fnd|obl|res)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    ),
]
CodeWire = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,127}$", max_length=128)]
# A host tool name as materialization records it (a closed token; never a path or command text).
ObservedToolWire = Annotated[
    str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$", max_length=128)
]
# One closure-readiness checklist entry: a condition token, an actionable gap code, or the
# conservative ``unclassified_gap:<code>`` form for a code the running build does not know.
ReadinessItemWire = Annotated[
    str,
    Field(pattern=r"^(?:unclassified_gap:)?[a-z][a-z0-9_]{0,127}$", max_length=145),
]
# The 0-based index of a requested item inside its obligation (at most 64 items).
RequestedItemIndexWire = Annotated[str, Field(pattern=r"^(?:[0-9]|[1-5][0-9]|6[0-3])$")]
# An obligation or a finding the agent recorded as acknowledged, not done.
AcknowledgedItemIdWire = Annotated[
    str,
    Field(
        pattern=r"^(fnd|obl)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    ),
]
HostCorrelationWire = Annotated[
    str,
    Field(
        min_length=1,
        max_length=256,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]*$",
    ),
]
VersionWire = Annotated[
    str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,63}$")
]
ReceiptVersionIdentityWire = Annotated[
    str,
    Field(min_length=1, max_length=256, pattern=r"^[0-9A-Za-z][0-9A-Za-z._/+:-]*$"),
]
ReceiptSchemaCounterVersionWire = Annotated[
    str, Field(min_length=1, max_length=19, pattern=r"^[1-9][0-9]*$")
]
ReceiptPolicyIdWire = Annotated[
    str,
    Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$",
    ),
]
ReceiptSchemaIdWire = Annotated[
    str,
    Field(
        min_length=1,
        max_length=256,
        pattern=r"^[a-z][a-z0-9]*(?:[-_/][a-z0-9.]+)*$",
    ),
]
SemverWire = Annotated[
    str,
    Field(
        max_length=32,
        pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$",
    ),
]
ProfileIdWire = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._/-]{0,127}$"),
]
AsciiString1To160 = Annotated[str, Field(min_length=1, max_length=160, pattern=r"^[ -~]+$")]

type FreshnessWire = Literal[
    "current", "partial", "redacted_gap", "stale_after_material_change", "unknown"
]
# Public finding projections include local coordination findings. Provider judgment uses the
# separate historical alias below because D7 keeps the frozen external semantic wire at fourteen
# kinds. The provider adapter preserves the historical schema definition key.
type FindingKindWire = Literal[
    "action_without_result",
    "claim_without_admissible_evidence",
    "coordination_overlap",
    "completion_with_open_obligations",
    "contradictory_claims_unresolved",
    "diff_does_not_match_account",
    "evidence_does_not_support_claim",
    "failed_work_omitted",
    "ledger_stale_or_incomplete",
    "material_limitation_omitted",
    "questionable_finding_rejection",
    "requested_item_never_attempted",
    "result_without_action",
    "stale_evidence_for_changed_state",
    "weak_or_stale_response",
    "code_defect",
    "task_requirement_unmet",
    "agent_criterion_unmet",
]

type ProviderFindingKindWire = Literal[
    "action_without_result",
    "claim_without_admissible_evidence",
    "completion_with_open_obligations",
    "contradictory_claims_unresolved",
    "diff_does_not_match_account",
    "evidence_does_not_support_claim",
    "failed_work_omitted",
    "ledger_stale_or_incomplete",
    "material_limitation_omitted",
    "questionable_finding_rejection",
    "requested_item_never_attempted",
    "result_without_action",
    "stale_evidence_for_changed_state",
    "weak_or_stale_response",
    "code_defect",
    "task_requirement_unmet",
    "agent_criterion_unmet",
]

type SafeDetailPrimitive = (
    bool
    | Annotated[int, Field(ge=-(2**53 - 1), le=2**53 - 1)]
    | Annotated[str, Field(max_length=4096)]
)
type SafeDetailArray = Annotated[
    tuple[SafeDetailPrimitive, ...], Field(min_length=0, max_length=32)
]
type SafeDetailValueModel = SafeDetailPrimitive | SafeDetailArray
type SafeDetailObject = Annotated[
    dict[
        Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$", max_length=64)],
        SafeDetailValueModel,
    ],
    Field(min_length=0, max_length=32),
]
type SafeDetailValues = Annotated[
    tuple[SafeDetailValueModel, ...], Field(min_length=0, max_length=32)
]


def _normalize_safe_detail_item(value: object) -> object:
    if type(value) is list:
        return tuple(cast(list[object], value))
    return value


def _normalize_safe_details_wire(value: object) -> object:
    if type(value) is list:
        return tuple(_normalize_safe_detail_item(item) for item in cast(list[object], value))
    if type(value) is dict:
        source = cast(dict[object, object], value)
        return {key: _normalize_safe_detail_item(item) for key, item in source.items()}
    return value


type SafeDetails = Annotated[
    SafeDetailObject | SafeDetailValues,
    BeforeValidator(_normalize_safe_details_wire),
]


def _annotation_accepts_tuple(annotation: object) -> bool:
    origin = get_origin(annotation)
    if origin is tuple:
        return True
    if origin is Annotated:
        return _annotation_accepts_tuple(get_args(annotation)[0])
    if origin is types.UnionType or origin is Union:
        return any(_annotation_accepts_tuple(argument) for argument in get_args(annotation))
    return False


class _ClosedModel(BaseModel):
    model_config = _ORDINARY_CONFIG

    optional_non_null_fields: ClassVar[frozenset[str]] = frozenset()

    @model_validator(mode="before")
    @classmethod
    def _adapt_json_arrays_and_reject_forbidden_nulls(cls, value: object) -> object:
        if isinstance(value, Mapping):
            source = cast(Mapping[object, object], value)
            for field_name in cls.optional_non_null_fields:
                if field_name in source and source[field_name] is None:
                    raise ValueError("optional_field_must_not_be_null")
            adapted: dict[object, object] | None = None
            for field_name, field in cls.model_fields.items():
                raw = source.get(field_name)
                if type(raw) is list and _annotation_accepts_tuple(field.annotation):
                    if adapted is None:
                        adapted = dict(source)
                    adapted[field_name] = tuple(cast(list[object], raw))
            if adapted is not None:
                return adapted
        return cast(object, value)


def _strip_optional_non_null_fields(
    model: BaseModel, dumped: Mapping[str, JsonValue]
) -> dict[str, JsonValue]:
    """Omit unset optional non-null fields recursively from one public model tree."""

    root: object = getattr(model, "root", None)
    if isinstance(root, BaseModel):
        return _strip_optional_non_null_fields(root, dumped)
    declared: object = getattr(type(model), "optional_non_null_fields", None)
    optional: frozenset[str] = (
        cast(frozenset[str], declared) if isinstance(declared, frozenset) else frozenset()
    )
    field_names_by_dump_key = {
        (field.serialization_alias or field.alias or field_name): field_name
        for field_name, field in type(model).model_fields.items()
    }
    result: dict[str, JsonValue] = {}
    for key, value in dumped.items():
        field_name = field_names_by_dump_key.get(key, key)
        if field_name in optional and value is None:
            continue
        attribute: object = getattr(model, field_name)
        if isinstance(attribute, BaseModel) and isinstance(value, Mapping):
            result[key] = _strip_optional_non_null_fields(attribute, value)
        elif (
            isinstance(attribute, Sequence)
            and not isinstance(attribute, str | bytes)
            and isinstance(value, list)
        ):
            children: list[JsonValue] = []
            for child, child_dump in zip(cast(Sequence[object], attribute), value, strict=True):
                if isinstance(child, BaseModel) and isinstance(child_dump, Mapping):
                    children.append(_strip_optional_non_null_fields(child, child_dump))
                else:
                    children.append(child_dump)
            result[key] = children
        else:
            result[key] = value
    return result


class PublicEnvelopeModel(_ClosedModel):
    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]


class ActorAssertionModel(_ClosedModel):
    optional_non_null_fields = frozenset({"asserted_by", "display_name"})

    actor_id: ActorAssertionIdWire
    actor_type: ActorTypeWire
    asserted_by: String1To256 | None = None
    display_name: String1To256 | None = None


class ClientInfoModel(_ClosedModel):
    kind: ClientKindWire
    version: String1To256
    integration: IntegrationKindWire


class PublicRequestModel(PublicEnvelopeModel):
    request_id: RequestIdWire
    actor: ActorAssertionModel
    client: ClientInfoModel


class PublicResultModel[T](RootModel[T]):
    model_config = _ROOT_CONFIG

    @model_validator(mode="before")
    @classmethod
    def _require_exact_boolean_discriminator(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            raise ValueError("result_root_not_mapping")
        source = cast(Mapping[object, object], value)
        if type(source.get("ok")) is not bool:
            raise ValueError("result_ok_wrong_type")
        return cast(object, value)


class FrontierModel(_ClosedModel):
    sequence: CanonicalUInt64Wire
    head_digest: GenesisOrSha256Digest

    @model_validator(mode="after")
    def _validate_genesis_identity(self) -> FrontierModel:
        if (self.sequence == "0") is not (self.head_digest == GENESIS_PREDECESSOR_DIGEST):
            raise ProtocolValueError("invalid_frontier")
        return self


class CoverageModel(_ClosedModel):
    publication_channels: tuple[PublicationChannelWire, ...]
    authorship_assurance: AuthorshipAssuranceWire
    artifact_observation: ArtifactObservationWire
    evidence_immutability: EvidenceImmutabilityWire
    ledger_freshness: LedgerFreshnessWire
    check_types: tuple[CheckTypeWire, ...]
    known_gaps: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...]

    @model_validator(mode="after")
    def _validate_coverage_lattice(self) -> CoverageModel:
        Coverage(
            publication_channels=self.publication_channels,
            authorship_assurance=self.authorship_assurance,
            artifact_observation=self.artifact_observation,
            evidence_immutability=self.evidence_immutability,
            ledger_freshness=self.ledger_freshness,
            check_types=self.check_types,
            known_gaps=self.known_gaps,
        )
        return self


class AttachHandleModel(_ClosedModel):
    """A service-minted, single-use child attachment capability.

    The opaque handle is deliberately bounded and structurally opaque.  Its meaning is held by
    the service; callers receive the child identity and expiry so they can route a subagent, but
    no secret or transcript content is exposed in this contract.
    """

    handle: Annotated[
        str, Field(min_length=32, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]*$")
    ]
    child_task_id: TaskIdWire
    expires_at: TimestampWire

    @property
    def token(self) -> str:
        """Compatibility spelling used by host adapters when forwarding the capability."""

        return self.handle


_CHILD_FINDING_TRAITS: Final[Mapping[str, tuple[int, bool]]] = MappingProxyType(
    {
        "completion_with_open_obligations": (1, True),
        "requested_item_never_attempted": (2, True),
        "failed_work_omitted": (1, True),
        "claim_without_admissible_evidence": (1, True),
        "result_without_action": (2, True),
        "action_without_result": (3, True),
        "stale_evidence_for_changed_state": (2, True),
        "contradictory_claims_unresolved": (1, True),
        "ledger_stale_or_incomplete": (3, False),
        "weak_or_stale_response": (2, True),
        "evidence_does_not_support_claim": (1, True),
        "diff_does_not_match_account": (1, True),
        "material_limitation_omitted": (1, True),
        "questionable_finding_rejection": (2, True),
        "coordination_overlap": (2, True),
        "code_defect": (1, True),
        "task_requirement_unmet": (1, True),
        "agent_criterion_unmet": (2, True),
    }
)


class ChildFindingSnapshotModel(_ClosedModel):
    optional_non_null_fields = frozenset({"resolution_event_id", "self_verified"})

    finding_id: FindingIdWire
    kind: Literal[
        "action_without_result",
        "claim_without_admissible_evidence",
        "coordination_overlap",
        "completion_with_open_obligations",
        "contradictory_claims_unresolved",
        "diff_does_not_match_account",
        "evidence_does_not_support_claim",
        "failed_work_omitted",
        "ledger_stale_or_incomplete",
        "material_limitation_omitted",
        "questionable_finding_rejection",
        "requested_item_never_attempted",
        "result_without_action",
        "stale_evidence_for_changed_state",
        "weak_or_stale_response",
        "code_defect",
        "task_requirement_unmet",
        "agent_criterion_unmet",
    ]
    origin: Literal["deterministic", "semantic_model_derived"]
    priority: Annotated[int, Field(ge=1, le=3)]
    actionable: bool
    resolved: bool
    resolution_event_id: EventIdWire | None = None
    # Issue #984: present (and true) only for a repair the child agent self-verified.
    self_verified: Literal[True] | None = None

    @model_validator(mode="after")
    def _validate_child_finding_snapshot(self) -> ChildFindingSnapshotModel:
        expected_priority, expected_actionable = _CHILD_FINDING_TRAITS[self.kind]
        if self.priority != expected_priority:
            raise ValueError("child_finding_priority_mismatch")
        if self.actionable != expected_actionable:
            raise ValueError("child_finding_actionable_mismatch")
        if self.resolved != (self.resolution_event_id is not None):
            raise ValueError("child_finding_resolution_mismatch")
        if self.self_verified and (self.resolved or not self.actionable):
            raise ValueError("child_finding_resolution_mismatch")
        return self


class ChildDependencySnapshotModel(_ClosedModel):
    optional_non_null_fields = frozenset(
        {
            "child_frontier",
            "child_check_id",
            "child_receipt_id",
            "membership_generation",
        }
    )

    child_task_id: TaskIdWire
    origin: LineageOriginWire
    acceptance: LineageAcceptanceWire
    work_state: WorkStateWire
    session_health: SessionHealthWire
    child_frontier: FrontierModel | None = None
    child_check_id: EventIdWire | None = None
    child_check_subject_frontier: FrontierModel | None = None
    child_receipt_id: ReceiptIdWire | None = None
    coverage: CoverageModel
    findings: tuple[ChildFindingSnapshotModel, ...]
    lineage_authority_revision: CanonicalPositiveUInt64Wire
    membership_generation: CanonicalPositiveUInt64Wire | None = None
    read_gap_reasons: tuple[LineageReadGapReasonWire, ...] = ()
    provenance_restrictions: tuple[LineageProvenanceRestrictionWire, ...] = ()

    @model_validator(mode="after")
    def _validate_child_dependency_snapshot(self) -> ChildDependencySnapshotModel:
        if len(self.findings) > 100:
            raise ValueError("child_finding_count_invalid")
        _require_unique(tuple(item.finding_id for item in self.findings), limit=100)
        _require_unique(self.read_gap_reasons, limit=len(LineageReadGapReason))
        _require_unique(self.provenance_restrictions, limit=len(LineageProvenanceRestriction))
        if self.read_gap_reasons and self.child_frontier is not None:
            raise ValueError("child_gap_frontier_mismatch")
        if not self.read_gap_reasons and self.child_frontier is None:
            raise ValueError("child_frontier_missing")
        if self.child_check_id is None and self.child_check_subject_frontier is not None:
            raise ValueError("child_check_frontier_without_check")
        if self.child_check_id is not None and self.child_check_subject_frontier is None:
            raise ValueError("child_check_frontier_missing")
        return self

    @property
    def tested_frontier(self) -> FrontierModel | None:
        """The frontier actually covered by the child's check, when one was recorded."""

        return self.child_check_subject_frontier


class ChildDependenciesModel(_ClosedModel):
    children: tuple[ChildDependencySnapshotModel, ...]

    @model_validator(mode="after")
    def _validate_child_dependencies(self) -> ChildDependenciesModel:
        ids = tuple(item.child_task_id for item in self.children)
        _require_unique(ids, limit=100)
        if ids != tuple(sorted(ids, key=str.encode)):
            raise ValueError("child_dependencies_not_canonical")
        return self


class SubjectStateRefModel(_ClosedModel):
    optional_non_null_fields = frozenset({"tree_digest", "diff_digest", "described_state"})

    tree_digest: Sha256Digest | None = None
    diff_digest: Sha256Digest | None = None
    described_state: String1To256 | None = None

    @model_validator(mode="after")
    def _require_one_state_member(self) -> SubjectStateRefModel:
        if self.tree_digest is None and self.diff_digest is None and self.described_state is None:
            raise ProtocolValueError("empty_subject_state")
        return self


class PublicErrorModel(_ClosedModel):
    optional_non_null_fields = frozenset({"safe_details"})

    code: PublicErrorCodeWire
    message: String1To4096
    retryable: bool
    correlation_id: CorrelationIdWire
    safe_details: SafeDetails | None = None


class OmittedContentModel(_ClosedModel):
    omitted: Literal[True]
    category: DataCategoryWire
    reason: Literal["local_disclosure_not_authorized", "never_send_redacted"]


class PrivacyProjectionModel(_ClosedModel):
    sink: Literal["agent_context", "local_human_view"]
    local_disclosure_receipt_id: EgressReceiptIdWire
    policy_id: PrivacyPolicyIdWire
    policy_version: CanonicalPositiveUInt64Wire
    policy_digest: Sha256Digest
    included_categories: tuple[DataCategoryWire, ...]
    blocked_categories: tuple[DataCategoryWire, ...]
    omitted_pointers: tuple[JsonPointer, ...]
    projection_commitment: HmacSha256Commitment

    @model_validator(mode="after")
    def _validate_sorted_unique_projection_sets(self) -> PrivacyProjectionModel:
        for values in (self.included_categories, self.blocked_categories):
            if len(values) > len(DataCategory):
                raise ValueError("projection_category_limit")
            encoded = tuple(value.value.encode("ascii") for value in values)
            if encoded != tuple(sorted(set(encoded))):
                raise ValueError("projection_categories_not_canonical")
        if len(self.omitted_pointers) > MAX_PROJECTION_CONTENT_LEAVES:
            raise ValueError("projection_pointer_limit")
        encoded_pointers = tuple(pointer.encode("utf-8") for pointer in self.omitted_pointers)
        if encoded_pointers != tuple(sorted(set(encoded_pointers))):
            raise ValueError("projection_pointers_not_canonical")
        return self


class OperationFailureModel(PublicEnvelopeModel):
    ok: Literal[False]
    error: PublicErrorModel
    request_id: RequestIdWire | None = None


class CheckScopeModel(_ClosedModel):
    claim_ids: tuple[ClaimIdWire, ...]
    obligation_ids: tuple[ObligationIdWire, ...]

    @model_validator(mode="after")
    def _validate_scope_sets(self) -> CheckScopeModel:
        if len(self.claim_ids) > 64 or len(set(self.claim_ids)) != len(self.claim_ids):
            raise ValueError("invalid_claim_ids")
        if len(self.obligation_ids) > 64 or len(set(self.obligation_ids)) != len(
            self.obligation_ids
        ):
            raise ValueError("invalid_obligation_ids")
        return self


def _validate_model_against_schema(model: BaseModel, schema_name: str) -> None:
    from pydantic import ValidationError as PydanticValidationError

    from finishup.protocol.schemas import (
        SchemaInstanceInvalid,
        load_schema_catalog,
        request_result_schema_versions,
        validate_schema_instance,
    )

    raw_dump = model.model_dump(
        mode="json",
        by_alias=True,
        exclude_unset=True,
        exclude_none=False,
    )
    dumped = _strip_optional_non_null_fields(model, cast(Mapping[str, JsonValue], raw_dump))
    try:
        schema_version = request_result_schema_versions(load_schema_catalog())[schema_name]
        validate_schema_instance(schema_name, schema_version, cast(JsonValue, dumped))
    except SchemaInstanceInvalid as exc:
        # Re-raise with JSON Schema path(s) so MCP safe_details can name corrective fields.
        # Root-level object rules (dependentRequired, if/then) arrive as location_reasons with
        # closed reason tokens; nested field failures use absolute_path.
        if exc.location_reasons:
            raise PydanticValidationError.from_exception_data(
                type(model).__name__,
                [
                    {
                        "type": "value_error",
                        "loc": tuple(path),
                        "input": None,
                        "ctx": {
                            "error": ValueError(reason),
                            "schema_name": exc.family,
                            "schema_version": exc.family_version,
                            "condition_field": exc.condition_field,
                            "condition_value": exc.condition_value,
                        },
                    }
                    for path, reason in exc.location_reasons
                ],
            ) from None
        if exc.absolute_path:
            # The reason token is drawn from a closed set inside the validator, and the family,
            # its schema version, and the count beside it are frozen schema content, so MCP can
            # name the class of the mistake rather than collapsing every nested failure to one
            # generic token (issue #240). The version rides along because a family may have
            # several admitted versions, and naming the wrong one hands back the wrong contract
            # (issue #239).
            raise PydanticValidationError.from_exception_data(
                type(model).__name__,
                [
                    {
                        "type": "value_error",
                        "loc": tuple(exc.absolute_path),
                        "input": None,
                        "ctx": {
                            "error": ValueError(exc.reason or "schema_instance_invalid"),
                            "schema_name": exc.family,
                            "schema_version": exc.family_version,
                            "count": exc.unknown_count or None,
                            # Frozen schema vocabulary, never a caller-invented key: the validator
                            # admits it only when it byte-equals a catalogued payload property
                            # name, so MCP can name the field's one legal owner (issue #266).
                            "misplaced_field": exc.misplaced_field,
                            # Schema-listed required names the instance lacks (frozen schema
                            # vocabulary), so the hint names the absent key, not the whole list.
                            "missing_fields": exc.missing_fields or None,
                            # tb4n5 (#1049): the frozen const of the sibling that narrowed this
                            # value (``evidence_kind`` for ``digest_binding/subject``).
                            "condition_field": exc.condition_field,
                            "condition_value": exc.condition_value,
                        },
                    }
                ],
            ) from None
        raise ValueError("schema_instance_invalid") from None


class StartRequestModel(PublicRequestModel):
    optional_non_null_fields = frozenset(
        {
            "session_id",
            "external_ref",
            "workspace_ref",
            "parent_session_id",
            "attach_handle",
            "subagent_id",
            "parent_tool_call_id",
            "correlation_id",
            "task_statement",
        }
    )

    mode: Literal["attach", "create", "create_or_attach", "delegate"]
    task_title: String1To8192
    requested_view: Literal["compact"]
    # The user's request, verbatim, as the agent transcribed it (issue #908). Recorded in the task
    # ledger; the AI-powered review sends it only under a policy that names the section.
    task_statement: TaskStatementWire | None = None
    session_id: SessionIdWire | None = None
    external_ref: String1To8192 | None = None
    workspace_ref: String1To8192 | None = None
    parent_session_id: SessionIdWire | None = None
    attach_handle: AttachHandleModel | None = None
    subagent_id: HostCorrelationWire | None = None
    parent_tool_call_id: HostCorrelationWire | None = None
    correlation_id: HostCorrelationWire | None = None

    @model_validator(mode="after")
    def _validate_start_request(self) -> StartRequestModel:
        if self.mode == "delegate":
            if self.session_id is None:
                raise ValueError("delegate_parent_session_required")
            if self.parent_session_id is not None or self.attach_handle is not None:
                raise ValueError("selector_conflict")
        if self.attach_handle is not None and self.mode != "attach":
            raise ValueError("selector_conflict")
        if self.parent_session_id is not None and self.mode not in {"create", "create_or_attach"}:
            raise ValueError("selector_conflict")
        if (
            self.task_statement is not None
            and len(self.task_statement.encode("utf-8")) > MAX_TASK_STATEMENT_BYTES
        ):
            raise ValueError("task_statement_too_large")
        _validate_model_against_schema(self, "start-request")
        return self


_IGNORED_DECISION_ID_KEY: Final = "decision_id"


def _drop_ignored_decision_ids(drafts: object) -> object:
    """Drop ``decision_id`` from every ``decision_recorded`` draft payload (tb4n4, #1049).

    ``decision_recorded`` is the one ordinary family without an id of its own (a decision is
    addressed by its ``event_id``), and ten tb4n4 attempts sent a ``decision_id`` by analogy with
    ``action_id``, ``claim_id`` and the rest. The key has no meaning in any spelling, so it is
    accepted and ignored: dropped here, before the schema check and before anything prepares,
    commits or hashes the drafts. A retry with or without it is therefore the same request (one
    request digest), and the recorded event never holds it. Every other unknown key, in this and
    every other family, keeps its ``extra_forbidden`` refusal.
    """

    if not isinstance(drafts, list | tuple):
        return drafts
    sequence = cast(Sequence[object], drafts)
    adapted: list[object] = []
    changed = False
    for draft in sequence:
        replacement: object = draft
        if isinstance(draft, Mapping):
            source = cast(Mapping[object, object], draft)
            schema: object = source.get("schema")
            payload: object = source.get("payload")
            if (
                isinstance(schema, Mapping)
                and cast(Mapping[object, object], schema).get("name") == "decision_recorded"
                and isinstance(payload, Mapping)
                and _IGNORED_DECISION_ID_KEY in cast(Mapping[object, object], payload)
            ):
                kept: dict[object, object] = {
                    key: value
                    for key, value in cast(Mapping[object, object], payload).items()
                    if key != _IGNORED_DECISION_ID_KEY
                }
                rebuilt: dict[object, object] = dict(source)
                rebuilt["payload"] = kept
                replacement = rebuilt
                changed = True
        adapted.append(replacement)
    if not changed:
        return sequence
    return adapted if isinstance(sequence, list) else tuple(adapted)


class PublishWorkRequestModel(PublicRequestModel):
    optional_non_null_fields = frozenset({"dry_run"})

    session_id: SessionIdWire
    writer_id: WriterIdWire
    expected_frontier: FrontierModel | None
    event_drafts: tuple[JsonValue, ...]
    # When true, validate the batch and return a non-evidential preview without appending.
    dry_run: bool | None = None

    @model_validator(mode="before")
    @classmethod
    def _ignore_decision_ids(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        source = cast(Mapping[object, object], value)
        drafts = source.get("event_drafts")
        adapted = _drop_ignored_decision_ids(drafts)
        if adapted is drafts:
            return cast(object, value)
        return {**source, "event_drafts": adapted}

    @model_validator(mode="after")
    def _validate_publish_work_request(self) -> PublishWorkRequestModel:
        _validate_model_against_schema(self, "publish-work-request")
        return self


class CheckRequestModel(PublicRequestModel):
    optional_non_null_fields = frozenset(
        {"mode", "scope", "max_findings", "policy_packs", "final_review", "await_observations"}
    )

    session_id: SessionIdWire
    writer_id: WriterIdWire
    expected_frontier: FrontierModel
    # Omitted mode resolves via VerificationPolicy.default_check_mode in the application facade.
    # ``inspect`` (issue #1048, ADR-047) reads what is left to close instead of checking: it
    # records nothing, mints no findings and calls no reviewer; the schema refuses the finding,
    # pack, closing-review and scope options beside it.
    mode: (
        Literal["deterministic_only", "inspect", "semantic_if_configured", "semantic_required"]
        | None
    ) = None
    scope: CheckScopeModel | None = None
    max_findings: Literal["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"] | None = None
    policy_packs: tuple[CurrentPolicyPackWire, ...] | None = None
    # Issue #976: the closing review. True runs the final review phase with or without a
    # completion claim; omitted keeps the claim-driven selection.
    final_review: bool | None = None
    # Issue #1012: wait, bounded, for this task's pending hook rows before the case freezes.
    # Omitted keeps today's behaviour and request bytes.
    await_observations: bool | None = None

    @model_validator(mode="after")
    def _validate_check_request(self) -> CheckRequestModel:
        _validate_model_against_schema(self, "check-request")
        if self.mode == "inspect":
            # ADR-047: an inspection mints nothing, so the options of a minting check are refused
            # beside it, each at its own field. Kept here rather than as a schema conditional,
            # which observed hosts lower to an unauthorable ``unknown`` check input.
            present = tuple(
                name
                for name in ("final_review", "max_findings", "policy_packs", "scope")
                if getattr(self, name) is not None
            )
            if present:
                from pydantic import ValidationError as PydanticValidationError

                raise PydanticValidationError.from_exception_data(
                    type(self).__name__,
                    [
                        {
                            "type": "value_error",
                            "loc": (name,),
                            "input": None,
                            "ctx": {"error": ValueError("extra_forbidden")},
                        }
                        for name in present
                    ],
                )
        return self


class RespondRequestModel(PublicRequestModel):
    optional_non_null_fields = frozenset(
        {"reason", "waiver_scope", "waiver_expiry", "evidence_refs", "duplicate_of_finding_id"}
    )

    session_id: SessionIdWire
    writer_id: WriterIdWire
    expected_frontier: FrontierModel
    finding_id: FindingIdWire
    finding_frontier: FrontierModel
    disposition: Literal[
        "acknowledged",
        "acknowledged_not_done",
        "duplicate_of",
        "provenance_disputed",
        "rejected",
        "reopened",
        "self_verified",
        "waived",
    ]
    reason: String1To4096 | None = None
    waiver_scope: Literal["finding_only"] | None = None
    waiver_expiry: TimestampWire | None = None
    evidence_refs: tuple[EvidenceOrResultIdWire, ...] | None = None
    # Issue #996: the earlier finding a ``duplicate_of`` answer links to; only with it.
    duplicate_of_finding_id: FindingIdWire | None = None

    @model_validator(mode="after")
    def _validate_respond_request(self) -> RespondRequestModel:
        _validate_model_against_schema(self, "respond-request")
        return self


class StatusAssignmentFilterModel(_ClosedModel):
    optional_non_null_fields = frozenset({"actor_id", "include_resolved"})

    actor_id: ActorAssertionIdWire | None = None
    include_resolved: bool | None = None


class StatusCandidateFindingsFilterModel(_ClosedModel):
    optional_non_null_fields = frozenset({"priority"})

    priority: Annotated[int, Field(ge=1, le=3)] | None = None


class StatusEvidenceFilterModel(_ClosedModel):
    optional_non_null_fields = frozenset({"author", "freshness", "include_unavailable", "strength"})

    # ``mine`` keeps only rows whose source event this writer published in this session, decided
    # by the service from ledger authorship; the caller cannot assert it for any other row.
    author: Literal["mine"] | None = None
    freshness: (
        Literal["current", "partial", "redacted_gap", "stale_after_material_change", "unknown"]
        | None
    ) = None
    include_unavailable: bool | None = None
    strength: (
        Literal[
            "content_digest",
            "immutable_snapshot",
            "independently_reproduced",
            "metadata_only",
            "mutable_reference",
        ]
        | None
    ) = None


class StatusFindingsFilterModel(_ClosedModel):
    optional_non_null_fields = frozenset({"disposition", "include_resolved", "origin", "priority"})

    disposition: (
        Literal[
            "acknowledged",
            "acknowledged_not_done",
            "duplicate_of",
            "none",
            "provenance_disputed",
            "rejected",
            "reopened",
            "self_verified",
            "waived",
        ]
        | None
    ) = None
    include_resolved: bool | None = None
    origin: Literal["deterministic", "semantic_model_derived"] | None = None
    priority: Annotated[int, Field(ge=1, le=3)] | None = None


class StatusHistoryFilterModel(_ClosedModel):
    optional_non_null_fields = frozenset({"actor_id", "after_sequence", "schema_name"})

    actor_id: ActorAssertionIdWire | None = None
    after_sequence: CanonicalUInt64Wire | None = None
    schema_name: SchemaNameWire | None = None


class StatusObligationsFilterModel(_ClosedModel):
    optional_non_null_fields = frozenset({"actor_id", "include_resolved", "status"})

    actor_id: ActorAssertionIdWire | None = None
    include_resolved: bool | None = None
    status: Literal["open", "resolved"] | None = None


class StatusOperationFilterModel(_ClosedModel):
    """Keys a status read at one prior operation identity within the authenticated task."""

    operation_request_id: RequestIdWire


type StatusFilter = (
    StatusAssignmentFilterModel
    | StatusCandidateFindingsFilterModel
    | StatusEvidenceFilterModel
    | StatusFindingsFilterModel
    | StatusHistoryFilterModel
    | StatusObligationsFilterModel
    | StatusOperationFilterModel
)

_STATUS_FILTER_BY_VIEW: Final[Mapping[str, type[_ClosedModel]]] = MappingProxyType(
    {
        "assignment": StatusAssignmentFilterModel,
        "candidate_findings": StatusCandidateFindingsFilterModel,
        "evidence": StatusEvidenceFilterModel,
        "findings": StatusFindingsFilterModel,
        "history": StatusHistoryFilterModel,
        "obligations": StatusObligationsFilterModel,
        "operation": StatusOperationFilterModel,
    }
)


class StatusRequestModel(PublicRequestModel):
    optional_non_null_fields = frozenset({"filter", "project_id", "task_id", "correlation_id"})

    session_id: SessionIdWire
    writer_id: WriterIdWire
    view: Literal[
        "advice",
        "assignment",
        "candidate_findings",
        "compact",
        "evidence",
        "findings",
        "history",
        "obligations",
        "operation",
        "lineage",
        "project",
        "results",
        "versions",
    ]
    limit: CanonicalPageLimitWire
    filter: StatusFilter | None = None
    project_id: ProjectIdWire | None = None
    task_id: TaskIdWire | None = None
    correlation_id: HostCorrelationWire | None = None
    at_frontier: CanonicalUInt64Wire | None = None
    cursor: CursorWire | None = None

    @model_validator(mode="before")
    @classmethod
    def _route_status_filter(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        source = cast(Mapping[object, object], value)
        raw_filter = source.get("filter")
        raw_view = source.get("view")
        if raw_filter is None or type(raw_view) is not str:
            return cast(object, value)
        filter_type = _STATUS_FILTER_BY_VIEW.get(raw_view)
        if filter_type is None:
            return cast(object, value)
        routed = dict(source)
        routed["filter"] = filter_type.model_validate(raw_filter)
        return routed

    @model_validator(mode="after")
    def _validate_status_request(self) -> StatusRequestModel:
        selectors = tuple(
            value
            for value in (self.project_id, self.task_id, self.correlation_id)
            if value is not None
        )
        if len(selectors) > 1:
            raise ValueError("selector_conflict")
        # A filter beside a view that admits none (lineage, project, results, ...) is refused by
        # the schema's own ``not required`` rule below, which names /filter for the caller.
        if self.project_id is not None and self.view != "project":
            raise ValueError("selector_conflict")
        if self.correlation_id is not None and self.view != "lineage":
            raise ValueError("selector_conflict")
        _validate_model_against_schema(self, "status-request")
        return self


class ReceiptRequestModel(PublicRequestModel):
    task_id: TaskIdWire
    session_id: SessionIdWire
    writer_id: WriterIdWire
    expected_frontier: FrontierModel
    format: ReceiptFormatWire
    include: ReceiptIncludeWire
    redaction_profile: ReceiptRedactionProfileWire

    @model_validator(mode="after")
    def _validate_receipt_request(self) -> ReceiptRequestModel:
        _validate_model_against_schema(self, "receipt-request")
        return self


REGISTERED_GUIDANCE_URIS: Final[tuple[str, ...]] = _REGISTERED_GUIDANCE_URIS


def _guidance_resource_uri(value: object) -> str:
    """Admit only catalogued full-document or bounded-section guidance URIs.

    The exact legacy ``yoetz://`` spelling of a catalogued entry is admitted unchanged, so a
    caller reading pre-rename guidance is answered in the scheme it used (ADR-048).
    """

    if type(value) is not str or _canonical_guidance_uri(value) is None:
        raise ValueError("guidance_resource_uri_unregistered")
    return value


GuidanceResourceUri = Annotated[str, BeforeValidator(_guidance_resource_uri)]
_MAX_GUIDANCE_DOCUMENT_CHARS: Final = 65_536
_MAX_GUIDANCE_DOCUMENT_BYTES: Final = 1_048_576
_MIN_GUIDANCE_PAGE_SIZE: Final = 4
_MAX_GUIDANCE_PAGE_SIZE: Final = 16_384
_MAX_GUIDANCE_PAGE_COUNT: Final = 16_384
_MAX_GUIDANCE_SECTIONS: Final = 128


def _guidance_page_size(value: object) -> str:
    """Validate a canonical page-size token without widening the generic integer aliases."""

    validated = _canonical_uint_wire(value)
    parsed = int(validated)
    if not _MIN_GUIDANCE_PAGE_SIZE <= parsed <= _MAX_GUIDANCE_PAGE_SIZE:
        raise ValueError("guidance_page_size_invalid")
    return validated


GuidancePageSizeWire = Annotated[str, BeforeValidator(_guidance_page_size)]


class ReadGuidanceContinuationModel(_ClosedModel):
    """Exact next-page request material returned for an incomplete guidance read."""

    uri: GuidanceResourceUri
    page: CanonicalUInt64Wire
    page_size: GuidancePageSizeWire
    revision: Sha256Digest
    digest: Sha256Digest

    @model_validator(mode="after")
    def _validate_guidance_continuation(self) -> ReadGuidanceContinuationModel:
        if int(self.page) > _MAX_GUIDANCE_PAGE_COUNT:
            raise ValueError("guidance_page_invalid")
        if self.revision != self.digest:
            raise ValueError("guidance_revision_digest_mismatch")
        return self


class ReadGuidanceSectionModel(_ClosedModel):
    """One catalogued section a paged guidance read names on page zero (tb4n5)."""

    uri: GuidanceResourceUri
    byte_count: Annotated[int, Field(ge=0, le=_MAX_GUIDANCE_DOCUMENT_BYTES)]


class ReadGuidanceRequestModel(_ClosedModel):
    """Request to read one registered FinishUP guidance document as tool text."""

    optional_non_null_fields = frozenset({"page", "page_size", "revision", "digest"})

    uri: GuidanceResourceUri = Field(
        description="One registered URI such as finishup://guidance/workflow.md."
    )
    # Omitting all four optional fields preserves the legacy full-document route. Supplying any
    # page field opts into the bounded route; ``page`` defaults to zero and ``page_size`` to the
    # service's bounded default at the MCP edge.
    page: CanonicalUInt64Wire | None = None
    page_size: GuidancePageSizeWire | None = Field(
        default=None,
        description=(
            "Canonical UTF-8 byte budget for one page; use 4096 by default, with a permitted "
            "range of 4 through 16384 inclusive."
        ),
    )
    revision: Sha256Digest | None = None
    digest: Sha256Digest | None = None

    @model_validator(mode="after")
    def _validate_read_guidance_request(self) -> ReadGuidanceRequestModel:
        if self.page is not None and int(self.page) > _MAX_GUIDANCE_PAGE_COUNT:
            raise ValueError("guidance_page_invalid")
        if self.revision is not None and self.digest is not None and self.revision != self.digest:
            raise ValueError("guidance_revision_digest_mismatch")
        _validate_model_against_schema(self, "read-guidance-request")
        return self


class ReadGuidanceSuccessModel(_ClosedModel):
    """Registered guidance document returned as tool text."""

    optional_non_null_fields = frozenset(
        {
            "document_id",
            "revision",
            "digest",
            "total_byte_count",
            "page",
            "page_size",
            "page_offset",
            "page_byte_count",
            "page_count",
            "complete",
            "continuation",
            "sections",
        }
    )

    ok: Literal[True]
    uri: GuidanceResourceUri
    media_type: Literal["text/markdown"]
    byte_count: Annotated[int, Field(ge=0, le=_MAX_GUIDANCE_DOCUMENT_CHARS)]
    text: Annotated[str, Field(min_length=0, max_length=_MAX_GUIDANCE_DOCUMENT_CHARS)]
    document_id: GuidanceResourceUri | None = None
    revision: Sha256Digest | None = None
    digest: Sha256Digest | None = None
    total_byte_count: Annotated[int, Field(ge=0, le=_MAX_GUIDANCE_DOCUMENT_BYTES)] | None = None
    page: CanonicalUInt64Wire | None = None
    page_size: GuidancePageSizeWire | None = None
    page_offset: Annotated[int, Field(ge=0, le=_MAX_GUIDANCE_DOCUMENT_BYTES)] | None = None
    page_byte_count: Annotated[int, Field(ge=0, le=_MAX_GUIDANCE_DOCUMENT_CHARS)] | None = None
    page_count: CanonicalPositiveUInt64Wire | None = None
    complete: bool | None = None
    continuation: ReadGuidanceContinuationModel | None = None
    # Page zero of a paged read names the catalogued sections inside the resource (tb4n5), so a
    # caller reads one section instead of paging the document.
    sections: (
        Annotated[
            tuple[ReadGuidanceSectionModel, ...],
            Field(min_length=1, max_length=_MAX_GUIDANCE_SECTIONS),
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def _validate_read_guidance_success(self) -> ReadGuidanceSuccessModel:
        encoded = self.text.encode("utf-8")
        if len(encoded) != self.byte_count:
            raise ValueError("guidance_byte_count_mismatch")
        page_fields = (
            self.document_id,
            self.revision,
            self.digest,
            self.total_byte_count,
            self.page,
            self.page_size,
            self.page_offset,
            self.page_byte_count,
            self.page_count,
            self.complete,
        )
        if not any(value is not None for value in page_fields):
            if self.continuation is not None or self.sections is not None:
                raise ValueError("guidance_page_metadata_incomplete")
        else:
            if any(value is None for value in page_fields):
                raise ValueError("guidance_page_metadata_incomplete")
            assert self.document_id is not None
            assert self.revision is not None
            assert self.digest is not None
            assert self.total_byte_count is not None
            assert self.page is not None
            assert self.page_size is not None
            assert self.page_offset is not None
            assert self.page_byte_count is not None
            assert self.page_count is not None
            assert self.complete is not None
            if self.revision != self.digest:
                raise ValueError("guidance_revision_digest_mismatch")
            page = int(self.page)
            page_size = int(self.page_size)
            page_count = int(self.page_count)
            if page_count < 1 or page_count > _MAX_GUIDANCE_PAGE_COUNT or page >= page_count:
                raise ValueError("guidance_page_invalid")
            minimum_page_count = max(1, (self.total_byte_count + page_size - 1) // page_size)
            if page_count < minimum_page_count:
                raise ValueError("guidance_page_count_invalid")
            if self.page_byte_count != self.byte_count:
                raise ValueError("guidance_page_byte_count_mismatch")
            if self.page_offset + self.page_byte_count > self.total_byte_count:
                raise ValueError("guidance_page_offset_invalid")
            expected_complete = page + 1 == page_count
            if self.complete != expected_complete:
                raise ValueError("guidance_completion_mismatch")
            if self.complete and self.continuation is not None:
                raise ValueError("guidance_completion_continuation_invalid")
            if not self.complete and self.continuation is None:
                raise ValueError("guidance_continuation_missing")
            if self.continuation is not None:
                if self.continuation.uri != self.uri:
                    raise ValueError("guidance_continuation_uri_mismatch")
                if int(self.continuation.page) != page + 1:
                    raise ValueError("guidance_continuation_page_mismatch")
                if self.continuation.page_size != self.page_size:
                    raise ValueError("guidance_continuation_page_size_mismatch")
                if self.continuation.revision != self.revision:
                    raise ValueError("guidance_continuation_revision_mismatch")
            if self.sections is not None:
                if page != 0:
                    raise ValueError("guidance_sections_page_invalid")
                document = self.uri.partition("#")[0]
                if any(
                    section.uri == self.uri or section.uri.partition("#")[0] != document
                    for section in self.sections
                ):
                    raise ValueError("guidance_sections_document_mismatch")
        _validate_model_against_schema(self, "read-guidance-result")
        return self


type ReadGuidanceResultBranch = Annotated[
    ReadGuidanceSuccessModel | OperationFailureModel, Field(discriminator="ok")
]


class ReadGuidanceResultModel(PublicResultModel[ReadGuidanceResultBranch]):
    pass


class ClosureSelectionModel(_ClosedModel):
    """Explicit caller choices for the read-only closure preparation helper."""

    phase: Literal["inventory", "attempt", "respond", "resolve", "claim", "receipt"] = "inventory"
    obligation_ids: Annotated[tuple[ObligationIdWire, ...], Field(max_length=64)] = ()
    requested_item_indexes: Annotated[
        tuple[Annotated[int, Field(ge=0, le=63)], ...], Field(max_length=64)
    ] = ()
    description: String1To8192 | None = None
    command: String1To8192 | None = None
    action_kind: Literal["command", "edit", "research", "review", "other"] = "other"
    observed_event_ids: Annotated[tuple[EventIdWire, ...], Field(max_length=64)] = ()
    evidence_refs: Annotated[tuple[EvidenceOrResultIdWire, ...], Field(max_length=64)] = ()
    result_ids: Annotated[tuple[ResultIdWire, ...], Field(max_length=64)] = ()
    finding_id: FindingIdWire | None = None
    disposition: (
        Literal[
            "acknowledged",
            "acknowledged_not_done",
            "duplicate_of",
            "provenance_disputed",
            "rejected",
            "reopened",
            "self_verified",
            "waived",
        ]
        | None
    ) = None
    reason: String1To4096 | None = None
    supersedes_claim_refs: Annotated[tuple[ClaimIdWire, ...], Field(max_length=64)] = ()
    format: Literal["markdown", "text", "json"] = "markdown"

    @model_validator(mode="after")
    def _validate_closure_selection(self) -> ClosureSelectionModel:
        for values in (
            self.obligation_ids,
            self.observed_event_ids,
            self.evidence_refs,
            self.result_ids,
            self.supersedes_claim_refs,
        ):
            _require_unique(values, limit=64)
        if len(self.requested_item_indexes) > 64 or len(set(self.requested_item_indexes)) != len(
            self.requested_item_indexes
        ):
            raise ValueError("closure_selection_indexes_not_unique")
        return self


class ClosurePrepareRequestModel(_ClosedModel):
    """MCP input for the read-only closure preparation helper."""

    session_id: SessionIdWire
    writer_id: WriterIdWire
    selection: ClosureSelectionModel

    @model_validator(mode="after")
    def _validate_closure_prepare_request(self) -> ClosurePrepareRequestModel:
        _validate_model_against_schema(self, "closure-prepare-request")
        return self


class ClosurePrepareSuccessModel(_ClosedModel):
    """MCP result carrying a CLI-equivalent closure inventory or one explicit draft."""

    ok: Literal[True]
    preparatory_only: Literal[True]
    frontier: FrontierModel
    closure_readiness: dict[str, JsonValue]
    inventory: dict[str, JsonValue]
    request: dict[str, JsonValue] | None = None
    notes: tuple[String1To8192, ...]
    operation: Literal["publish_work", "respond", "receipt"] | None = None
    recovery_request: dict[str, JsonValue] | None = None
    recovery: String1To4096 | None = None

    @model_validator(mode="after")
    def _validate_closure_prepare_success(self) -> ClosurePrepareSuccessModel:
        return self


type ClosurePrepareResultBranch = Annotated[
    ClosurePrepareSuccessModel | OperationFailureModel, Field(discriminator="ok")
]


class ClosurePrepareResultModel(PublicResultModel[ClosurePrepareResultBranch]):
    pass


def _require_unique(values: tuple[object, ...], *, limit: int) -> None:
    if len(values) > limit or len(set(values)) != len(values):
        raise ValueError("array_not_unique_or_bounded")


def _require_review_text_utf8_bytes(value: str) -> str:
    """Bound review prose by UTF-8 byte length (matches domain ReviewerChallenge)."""

    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("provider_review_text_invalid") from exc
    if not 1 <= len(encoded) <= MAX_REVIEW_TEXT_BYTES:
        raise ValueError("provider_review_text_invalid")
    return value


type ReviewerNextStepWire = Literal[
    "act",
    "provide_evidence",
    "revise_claim",
    "dispute_with_evidence",
    "state_unresolved_limitation",
    "answer_question",
]
type VerifiedVerdictWire = Literal["supported", "not_supported", "not_assessable"]
type MissingForAssessmentKindWire = Literal[
    "command_identity",
    "current_diff_for_path",
    "other",
    "plan_or_claim_text",
    "prior_finding_context",
    "task_statement",
    "verification_output",
]
# Frozen legacy identifier (ADR-048): the ``yoetz_limit_*`` availability values are released.
type MissingItemAvailabilityWire = Literal[
    "agent_suppliable",
    "structurally_unavailable_on_this_host",
    "yoetz_limit_packet_room",
    "yoetz_limit_unsupported_data_type",
]

ProviderReviewTextWire = Annotated[
    str,
    Field(min_length=1, max_length=MAX_PROVIDER_REVIEW_TEXT_CHARS),
]


class ProviderChallengeModel(_ClosedModel):
    """One provider-facing reviewer challenge; owns the constrained-output shape."""

    finding_kind: ProviderFindingKindWire
    summary: ProviderReviewTextWire
    cited_refs: Annotated[
        tuple[SubjectIdWire, ...],
        Field(min_length=1, max_length=16, json_schema_extra={"uniqueItems": True}),
    ]
    discrepancy: ProviderReviewTextWire
    alternative_interpretation: ProviderReviewTextWire
    message_to_main_agent: ProviderReviewTextWire
    requested_next_step: ReviewerNextStepWire
    uncertainty: ProviderReviewTextWire
    # One verbatim quote supporting the challenge. The check fence validates that it is an
    # exact substring of a packet item linked to one of cited_refs (issue #906 Part 2).
    snippet: ProviderReviewTextWire | None = None
    # The earlier finding this challenge restates (issue #980), from prior_finding_refs.
    restates: ProviderFindingIdWire | None = None

    @model_validator(mode="after")
    def _validate_challenge_invariants(self) -> ProviderChallengeModel:
        _require_unique(self.cited_refs, limit=16)
        for field_name in (
            "summary",
            "discrepancy",
            "alternative_interpretation",
            "message_to_main_agent",
            "uncertainty",
        ):
            _require_review_text_utf8_bytes(getattr(self, field_name))
        return self


class ProviderVerifiedItemModel(_ClosedModel):
    """One requirement/claim judgement returned by the verifying reviewer (issue #906)."""

    requirement_or_claim: ProviderReviewTextWire
    verdict: VerifiedVerdictWire
    cited_refs: Annotated[
        tuple[SubjectIdWire, ...],
        Field(min_length=1, max_length=16, json_schema_extra={"uniqueItems": True}),
    ]
    # A supported/not-supported judgement must quote what the reviewer saw. A not-assessable
    # row may omit the quote because its purpose is to name the missing coverage honestly.
    snippet: ProviderReviewTextWire | None = None

    @model_validator(mode="after")
    def _validate_verified_item(self) -> ProviderVerifiedItemModel:
        _require_unique(self.cited_refs, limit=16)
        if self.verdict == "not_assessable" and self.snippet is not None:
            raise ValueError("verified_snippet_invalid")
        if self.verdict != "not_assessable" and self.snippet is None:
            raise ValueError("verified_snippet_required")
        if self.snippet is not None:
            _require_review_text_utf8_bytes(self.snippet)
        return self


# Issue #905: one ruling per earlier AI-powered finding the packet's prior-findings section
# carries. ``withdrawn`` accepts the main agent's rejection; ``unassessable`` speaks only for its
# own finding. The section carries at most sixteen findings (issue #976).
type PriorFindingVerdictWire = Literal[
    "fixed",
    "still_present",
    "answered_not_fixed",
    "unassessable",
    "withdrawn",
]
MAX_PRIOR_FINDING_VERDICTS: Final = 16
ProviderFindingIdWire = Annotated[
    str,
    Field(pattern=r"^fnd_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
]


class ProviderPriorFindingVerdictModel(_ClosedModel):
    """The reviewer's ruling on one earlier finding, independent of the packet conclusion."""

    finding_id: ProviderFindingIdWire
    verdict: PriorFindingVerdictWire
    cited_refs: Annotated[
        tuple[SubjectIdWire, ...],
        Field(min_length=0, max_length=16, json_schema_extra={"uniqueItems": True}),
    ]
    note: ProviderReviewTextWire

    @model_validator(mode="after")
    def _validate_verdict_invariants(self) -> ProviderPriorFindingVerdictModel:
        _require_unique(self.cited_refs, limit=16)
        _require_review_text_utf8_bytes(self.note)
        return self


PriorFindingVerdictsWire = Annotated[
    tuple[ProviderPriorFindingVerdictModel, ...],
    Field(min_length=0, max_length=MAX_PRIOR_FINDING_VERDICTS),
]


class ProviderJudgmentNoDiscrepancyModel(_ClosedModel):
    conclusion: Literal["no_material_discrepancy"]
    review_summary: ProviderReviewTextWire = "No review summary recorded."
    verified: Annotated[tuple[ProviderVerifiedItemModel, ...], Field(max_length=64)] = ()
    reviewer_challenges: Annotated[
        tuple[ProviderChallengeModel, ...], Field(min_length=0, max_length=0)
    ]
    prior_finding_verdicts: PriorFindingVerdictsWire


class ProviderJudgmentChallengesModel(_ClosedModel):
    conclusion: Literal["challenges_returned"]
    review_summary: ProviderReviewTextWire = "No review summary recorded."
    verified: Annotated[tuple[ProviderVerifiedItemModel, ...], Field(max_length=64)] = ()
    reviewer_challenges: Annotated[
        tuple[ProviderChallengeModel, ...],
        Field(min_length=1, max_length=MAX_REVIEW_CHALLENGES),
    ]
    prior_finding_verdicts: PriorFindingVerdictsWire


class ProviderMissingItemModel(_ClosedModel):
    """One item the reviewer needed and the packet did not carry (issue #907)."""

    kind: MissingForAssessmentKindWire
    target_refs: Annotated[
        tuple[SubjectIdWire, ...],
        Field(
            min_length=0,
            max_length=MAX_MISSING_TARGET_REFS,
            json_schema_extra={"uniqueItems": True},
        ),
    ]
    reason: Annotated[str, Field(min_length=1, max_length=MAX_PROVIDER_MISSING_REASON_CHARS)]

    @model_validator(mode="after")
    def _validate_missing_item(self) -> ProviderMissingItemModel:
        _require_unique(self.target_refs, limit=MAX_MISSING_TARGET_REFS)
        encoded = self.reason.encode("utf-8", errors="strict")
        if not 1 <= len(encoded) <= MAX_MISSING_REASON_BYTES:
            raise ValueError("provider_review_text_invalid")
        return self


class ProviderJudgmentInsufficientModel(_ClosedModel):
    conclusion: Literal["insufficient_packet"]
    review_summary: ProviderReviewTextWire = "No review summary recorded."
    verified: Annotated[tuple[ProviderVerifiedItemModel, ...], Field(max_length=64)] = ()
    reviewer_challenges: Annotated[
        tuple[ProviderChallengeModel, ...], Field(min_length=0, max_length=0)
    ]
    # A whole-packet ``insufficient_packet`` may still rule on individual earlier findings the
    # reviewer could judge (issue #905); it vetoes only those it leaves without a verdict.
    prior_finding_verdicts: PriorFindingVerdictsWire
    # Required from provider-judgment 1.1.0: an unassessable packet must say what was missing,
    # or the agent can only add excerpts blind and recheck (issue #907).
    missing_for_assessment: Annotated[
        tuple[ProviderMissingItemModel, ...],
        Field(min_length=1, max_length=MAX_MISSING_FOR_ASSESSMENT),
    ]


type ProviderJudgmentModel = (
    ProviderJudgmentNoDiscrepancyModel
    | ProviderJudgmentChallengesModel
    | ProviderJudgmentInsufficientModel
)


class ProviderJudgmentEnvelopeModel(_ClosedModel):
    """Root wrapper that carries the judgment union one level below the schema root.

    Constrained-output (``strict: true``) schemas must have an object at the root; a root-level
    ``anyOf`` is rejected by the provider before generation starts. Nesting the union under a
    single required property keeps one owning contract for generation and consumption while
    still expressing the conclusion/challenge coupling through explicit union branches.
    """

    judgment: ProviderJudgmentModel


class StartCompactViewModel(_ClosedModel):
    # Start reuses the same compact projection as status. A redacted/unreadable current plan
    # cannot honestly produce a numeric count, so attach preserves null instead of inventing zero.
    open_obligation_count: CanonicalUInt64Wire | None
    unanswered_finding_count: CanonicalUInt64Wire
    receipt_blocking_finding_count: CanonicalUInt64Wire | None
    ledger_freshness: Literal[
        "current", "partial", "redacted_gap", "stale_after_material_change", "unknown"
    ]
    coverage: CoverageModel
    gaps: tuple[CodeWire, ...]
    current_plan_event_id: EventIdWire | None = None

    @model_validator(mode="after")
    def _validate_start_compact_sets(self) -> StartCompactViewModel:
        _require_unique(self.gaps, limit=64)
        legacy_unknown = "legacy_receipt_blocking_count_unknown" in self.gaps
        if (self.receipt_blocking_finding_count is None) != legacy_unknown:
            raise ValueError("start_compact_receipt_blocking_count_mismatch")
        return self


class StartVersionSliceModel(_ClosedModel):
    protocol_version: Literal["0.1"]
    engine_version: VersionWire
    projection_version: VersionWire
    policy_packs: tuple[RecordedVersionSlicePackWire, ...]

    @model_validator(mode="after")
    def _validate_start_version_packs(self) -> StartVersionSliceModel:
        _require_unique(self.policy_packs, limit=2)
        return self


class StartNextRequestActorTemplateModel(_ClosedModel):
    """Caller-owned actor fields that must be filled before publication."""

    actor_id: Literal[""]
    actor_type: Literal[""]


class StartNextRequestClientTemplateModel(_ClosedModel):
    """Caller-owned client fields that must be filled before publication."""

    kind: Literal[""]
    version: Literal[""]
    integration: Literal[""]


class StartNextRequestEventSchemaTemplateModel(_ClosedModel):
    name: Literal["plan_published", "obligation_published"]
    version: Literal["1.0.0"]


class StartNextRequestPlanPayloadTemplateModel(_ClosedModel):
    plan_version: Literal[1]
    summary: Literal[""]
    obligation_refs: tuple[Literal[""], ...]

    @model_validator(mode="after")
    def _validate_plan_template(self) -> StartNextRequestPlanPayloadTemplateModel:
        if self.obligation_refs != ("",):
            raise ValueError("invalid_start_next_request_template")
        return self


class StartNextRequestObligationPayloadTemplateModel(_ClosedModel):
    obligation_id: Literal[""]
    description: Literal[""]
    acceptance_criteria: Literal[""]
    evidence_expectation: Literal[""]
    status: Literal["open"]


class StartNextRequestEventDraftTemplateModel(_ClosedModel):
    event_id: Literal[""]
    event_schema: StartNextRequestEventSchemaTemplateModel = Field(alias="schema")
    occurred_at: Literal[""]
    causal_parents: tuple[Literal[""], ...]
    payload: (
        StartNextRequestPlanPayloadTemplateModel | StartNextRequestObligationPayloadTemplateModel
    )
    artifact_refs: tuple[Literal[""], ...]
    evidence_refs: tuple[Literal[""], ...]

    @model_validator(mode="after")
    def _validate_event_template(self) -> StartNextRequestEventDraftTemplateModel:
        if self.causal_parents or self.artifact_refs or self.evidence_refs:
            raise ValueError("invalid_start_next_request_template")
        expected_name = (
            "plan_published"
            if type(self.payload) is StartNextRequestPlanPayloadTemplateModel
            else "obligation_published"
        )
        if self.event_schema.name != expected_name:
            raise ValueError("invalid_start_next_request_template")
        return self


class StartPublishWorkRequestTemplateModel(_ClosedModel):
    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: Literal[""]
    actor: StartNextRequestActorTemplateModel
    client: StartNextRequestClientTemplateModel
    session_id: SessionIdWire
    writer_id: WriterIdWire
    expected_frontier: FrontierModel
    event_drafts: tuple[StartNextRequestEventDraftTemplateModel, ...]

    @model_validator(mode="after")
    def _validate_event_pair(self) -> StartPublishWorkRequestTemplateModel:
        if (
            len(self.event_drafts) != 2
            or self.event_drafts[0].event_schema.name != "plan_published"
            or self.event_drafts[1].event_schema.name != "obligation_published"
        ):
            raise ValueError("invalid_start_next_request_template")
        return self


class StartNextRequestTemplateModel(_ClosedModel):
    """Non-evidential, projection-only authoring scaffold for the first publication."""

    evidential: Literal[False]
    operation: Literal["publish_work"]
    arguments: StartPublishWorkRequestTemplateModel


class StartSuccessModel(_ClosedModel):
    optional_non_null_fields = frozenset(
        {"attach_handle", "parent_task_id", "depth", "origin", "acceptance"}
    )

    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: RequestIdWire
    ok: Literal[True]
    outcome: Literal["attached", "created", "replayed", "delegated"]
    task_id: TaskIdWire
    session_id: SessionIdWire
    writer_id: WriterIdWire
    frontier: FrontierModel
    compact: StartCompactViewModel
    versions: StartVersionSliceModel
    next_request_template: StartNextRequestTemplateModel
    privacy_projection: PrivacyProjectionModel
    attach_handle: AttachHandleModel | None = None
    parent_task_id: TaskIdWire | None = None
    depth: CanonicalPositiveUInt64Wire | None = None
    origin: LineageOriginWire | None = None
    acceptance: LineageAcceptanceWire | None = None

    @model_validator(mode="after")
    def _validate_start_success(self) -> StartSuccessModel:
        lineage_values = (self.parent_task_id, self.depth, self.origin, self.acceptance)
        if any(value is not None for value in lineage_values) and not all(
            value is not None for value in lineage_values
        ):
            raise ValueError("start_lineage_fields_incomplete")
        if self.attach_handle is not None:
            if self.outcome != "delegated" or self.attach_handle.child_task_id != self.task_id:
                raise ValueError("start_attach_handle_mismatch")
        if self.outcome == "delegated":
            if self.attach_handle is None or self.parent_task_id is None or self.depth is None:
                raise ValueError("start_delegation_fields_missing")
            if (
                self.origin is not LineageOrigin.PARENT_MINTED
                or self.acceptance is not LineageAcceptance.ACCEPTED
            ):
                raise ValueError("start_delegation_identity_invalid")
        elif self.attach_handle is not None:
            raise ValueError("start_attach_handle_mismatch")
        request = self.next_request_template.arguments
        if (
            request.protocol_version != self.protocol_version
            or request.schema_version != self.schema_version
            or request.session_id != self.session_id
            or request.writer_id != self.writer_id
            or request.expected_frontier != self.frontier
        ):
            raise ValueError("start_next_request_binding_mismatch")
        _validate_model_against_schema(self, "start-result")
        return self


type StartResultBranch = Annotated[
    StartSuccessModel | OperationFailureModel, Field(discriminator="ok")
]


class StartResultModel(PublicResultModel[StartResultBranch]):
    pass


_PUBLISH_SUMMARY_CATEGORY: Final[Mapping[tuple[str, str], DataCategory]] = MappingProxyType(
    {
        ("plan_published", "1.0.0"): DataCategory.TASK_DESCRIPTION,
        ("plan_revised", "1.0.0"): DataCategory.TASK_DESCRIPTION,
        ("obligation_published", "1.0.0"): DataCategory.TASK_DESCRIPTION,
        ("decision_recorded", "1.0.0"): DataCategory.DECISION_EXCERPT,
        ("action_recorded", "1.0.0"): DataCategory.COMMAND_METADATA,
        ("result_recorded", "1.0.0"): DataCategory.COMMAND_METADATA,
        ("evidence_recorded", "1.0.0"): DataCategory.EVIDENCE_EXCERPT,
        ("claim_recorded", "1.0.0"): DataCategory.FINDING_SUMMARY,
        ("response_recorded", "1.0.0"): DataCategory.FINDING_SUMMARY,
        ("finding_recorded", "1.0.0"): DataCategory.FINDING_SUMMARY,
        ("finding_recorded", "1.1.0"): DataCategory.FINDING_SUMMARY,
        ("finding_recorded", "1.2.0"): DataCategory.FINDING_SUMMARY,
        ("finding_recorded", "1.3.0"): DataCategory.FINDING_SUMMARY,
        ("finding_recorded", "1.4.0"): DataCategory.FINDING_SUMMARY,
    }
)
_PUBLISH_FIXED_SUMMARY: Final[Mapping[tuple[str, str], str]] = MappingProxyType(
    {
        ("session_opened", "1.0.0"): "session_opened",
        ("session_resumed", "1.0.0"): "session_resumed",
        ("assignment_recorded", "1.0.0"): "assignment_recorded",
        ("redaction_recorded", "1.0.0"): "redaction_recorded",
        ("check_recorded", "1.0.0"): "check_recorded",
        ("check_recorded", "1.1.0"): "check_recorded",
        ("check_recorded", "1.2.0"): "check_recorded",
        ("check_recorded", "1.3.0"): "check_recorded",
        ("check_recorded", "1.4.0"): "check_recorded",
        ("check_recorded", "1.5.0"): "check_recorded",
        ("receipt_recorded", "1.0.0"): "receipt_recorded",
        ("coordination_context_recorded", "1.0.0"): "coordination_context_recorded",
        ("coordination_obligation_declared", "1.0.0"): "coordination_obligation_declared",
        ("coordination_disposition_recorded", "1.0.0"): "coordination_disposition_recorded",
    }
)


class PublishWorkAcceptedEventModel(_ClosedModel):
    optional_non_null_fields = frozenset({"summary"})

    event_id: EventIdWire
    schema_name: SchemaNameWire
    schema_version: SemverWire
    writer_sequence: CanonicalUInt64Wire
    ingestion_sequence: CanonicalUInt64Wire
    accepted_at: TimestampWire
    predecessor_digest: GenesisOrSha256Digest
    entry_digest: Sha256Digest
    projection_status: Literal["projected", "unknown_unprojected"]
    summary: String1To8192 | OmittedContentModel | None = None

    @model_validator(mode="after")
    def _validate_summary_identity(self) -> PublishWorkAcceptedEventModel:
        if self.summary is None:
            return self
        identity = (self.schema_name, self.schema_version)
        category = _PUBLISH_SUMMARY_CATEGORY.get(identity)
        if category is not None:
            if (
                isinstance(self.summary, OmittedContentModel)
                and self.summary.category is not category
            ):
                raise ValueError("publish_summary_category_mismatch")
            return self
        fixed = _PUBLISH_FIXED_SUMMARY.get(identity)
        if fixed is not None:
            if type(self.summary) is not str or self.summary != fixed:
                raise ValueError("publish_fixed_summary_mismatch")
            return self
        if type(self.summary) is not str or self.summary != "opaque_unknown":
            raise ValueError("publish_opaque_summary_mismatch")
        return self


class PublishWorkVersionSliceModel(_ClosedModel):
    protocol_version: Literal["0.1"]
    engine_version: VersionWire
    projection_version: VersionWire
    policy_packs: tuple[RecordedVersionSlicePackWire, ...]

    @model_validator(mode="after")
    def _validate_publish_version_packs(self) -> PublishWorkVersionSliceModel:
        _require_unique(self.policy_packs, limit=2)
        return self


# Issue #985 (C2b/C3): fixed, closed publish-time texts for a ``finishup-blocker`` line, selected by
# the notice code. They carry no caller value; the obligation id and kind ride beside them.
PUBLISH_BLOCKER_NOTICE_TEXTS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "blocker_claimed": (
            "FinishUP challenges this finishup-blocker before it counts. Repair the obligation first if"
            " any route remains. A FinishUP limit (something FinishUP cannot show or prove) is never a"
            " blocker: verify that work yourself and respond self_verified on the finding. Data"
            " or an outcome the task says is recoverable or achievable is not a blocker, and"
            " neither is an inherent verification limit (a hidden verifier, a private trace) or"
            " a best-effort choice: finish the work and disclose it with a decision line"
            " finishup-assumption:<obligation id> or finishup-verification-limit:<obligation id>. Keep a"
            " blocker only for an open obligation genuinely blocked outside your control"
            " (authority, consent, a credential, a dependency you cannot obtain). Until then the"
            " obligation stays your work (obligation_blocker_unconfirmed). If it is still genuine"
            " after you re-read the task and tried the obvious prerequisite, confirm it: publish"
            " the same finishup-blocker line for it again in a later publish_work call."
        ),
        "blocker_confirmed": (
            "This finishup-blocker is confirmed: the obligation is disclosed as blocked outside your"
            " control (obligation_blocked_outside_agent_control), not done. FinishUP did not verify"
            " the claim; say so in your final answer, and supersede the decision if the"
            " obligation becomes doable."
        ),
        "blocker_without_effect": (
            "This finishup-blocker has no effect: the obligation it names is not open, and a blocker"
            " only applies to open obligations. If a finding stays unresolved because FinishUP cannot"
            " prove your repair (a FinishUP limit), verify it yourself and respond self_verified;"
            " respond acknowledged_not_done only as a last resort, for work you will not do."
        ),
    }
)


class PublishWorkBlockerNoticeModel(_ClosedModel):
    """One publish-time notice for a ``finishup-blocker`` line (#985): closed code and fixed text."""

    obligation_id: ObligationIdWire
    blocker_kind: Literal["authority", "consent", "credential", "dependency_unavailable"]
    notice: Literal["blocker_claimed", "blocker_confirmed", "blocker_without_effect"]
    text: str

    @model_validator(mode="after")
    def _validate_fixed_text(self) -> PublishWorkBlockerNoticeModel:
        if self.text != PUBLISH_BLOCKER_NOTICE_TEXTS[self.notice]:
            raise ValueError("publish_blocker_notice_text_mismatch")
        return self


# tb4n5 follow-up (owner decision 2026-10-13): the fixed publish-time text for an action the batch
# recorded that no ``result_recorded`` names yet. It carries no caller value; the act_ id rides
# beside it. 15 of 15 tb4n5 ``action_without_result`` findings were agent-published actions whose
# result followed only after the check asked for it.
PUBLISH_ACTION_NOTICE_TEXTS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "result_not_linked": (
            "No result names this action yet. Record its outcome as a result_recorded whose"
            " payload action_id is this act_ id (outcome success, failure, partial or unknown,"
            " with a summary), normally in the same publish_work batch as the action; evidence,"
            " decisions and causal parents do not link it. If the work is still running, publish"
            " the result when it ends; if it was abandoned, record outcome unknown and say so."
            " Until a result names it, unrelated work in a later batch raises"
            " action_without_result."
        ),
    }
)


class PublishWorkActionNoticeModel(_ClosedModel):
    """One publish-time notice for an action no result names yet: closed code and fixed text."""

    action_id: ActionIdWire
    notice: Literal["result_not_linked"]
    text: str

    @model_validator(mode="after")
    def _validate_fixed_text(self) -> PublishWorkActionNoticeModel:
        if self.text != PUBLISH_ACTION_NOTICE_TEXTS[self.notice]:
            raise ValueError("publish_action_notice_text_mismatch")
        return self


class PublishWorkSuccessModel(_ClosedModel):
    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: RequestIdWire
    ok: Literal[True]
    outcome: Literal["accepted", "replayed"]
    task_id: TaskIdWire
    session_id: SessionIdWire
    writer_id: WriterIdWire
    subject_frontier: FrontierModel
    result_frontier: FrontierModel
    accepted_events: tuple[PublishWorkAcceptedEventModel, ...]
    warning_codes: tuple[Literal["unknown_event_schema_preserved"], ...]
    coverage: CoverageModel
    gaps: tuple[CodeWire, ...]
    versions: PublishWorkVersionSliceModel
    privacy_projection: PrivacyProjectionModel
    # Issue #985: present only when the batch carried a finishup-blocker line FinishUP has a notice for.
    blocker_notices: tuple[PublishWorkBlockerNoticeModel, ...] | None = None
    # tb4n5 follow-up: present only when the batch recorded an action no result names yet.
    action_notices: tuple[PublishWorkActionNoticeModel, ...] | None = None

    optional_non_null_fields = frozenset({"blocker_notices", "action_notices"})

    @model_validator(mode="after")
    def _validate_publish_success(self) -> PublishWorkSuccessModel:
        if not 1 <= len(self.accepted_events) <= MAX_EVENTS_PER_BATCH:
            raise ValueError("accepted_event_count_invalid")
        _require_unique(self.warning_codes, limit=1)
        _require_unique(self.gaps, limit=64)
        _validate_blocker_notices(self.blocker_notices)
        _validate_action_notices(self.action_notices)
        _validate_model_against_schema(self, "publish-work-result")
        return self


class PublishWorkAcceptedMinimalEventModel(_ClosedModel):
    """Structural acceptance facts available from the ledger append result alone."""

    event_id: EventIdWire
    entry_digest: Sha256Digest
    ingestion_sequence: CanonicalUInt64Wire


class PublishWorkAcceptedProjectionUnavailableModel(_ClosedModel):
    """Total acceptance when privacy projection cannot shape the full success body.

    Built only from committed ledger facts plus a correlation id for operator diagnostics. It is a
    true success (`ok: true`), not an error bent into one: the write is durable and the caller does
    not need a second `status` call or same-`request_id` replay to learn what landed.
    """

    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: RequestIdWire
    ok: Literal[True]
    response_completeness: Literal["accepted_projection_unavailable"]
    reason_code: Literal["response_projection_failed"]
    correlation_id: CorrelationIdWire
    outcome: Literal["accepted", "replayed"]
    task_id: TaskIdWire
    session_id: SessionIdWire
    writer_id: WriterIdWire
    subject_frontier: FrontierModel
    result_frontier: FrontierModel
    accepted_events: tuple[PublishWorkAcceptedMinimalEventModel, ...]

    @model_validator(mode="after")
    def _validate_publish_accepted_projection_unavailable(
        self,
    ) -> PublishWorkAcceptedProjectionUnavailableModel:
        if not 1 <= len(self.accepted_events) <= MAX_EVENTS_PER_BATCH:
            raise ValueError("accepted_event_count_invalid")
        _validate_model_against_schema(self, "publish-work-result")
        return self


class PublishWorkDryRunPreviewEventModel(_ClosedModel):
    """Structural preview of one draft that would be accepted on a real publish."""

    event_id: EventIdWire
    schema_name: SchemaNameWire
    schema_version: SemverWire
    causal_parents: tuple[EventIdWire, ...]
    artifact_refs: tuple[ObjectIdWire, ...]
    evidence_refs: tuple[EvidenceOrResultIdWire, ...]

    @model_validator(mode="after")
    def _validate_preview_refs(self) -> PublishWorkDryRunPreviewEventModel:
        _require_unique(self.causal_parents, limit=32)
        _require_unique(self.artifact_refs, limit=64)
        _require_unique(self.evidence_refs, limit=64)
        return self


class PublishWorkDryRunModel(_ClosedModel):
    """Non-evidential validation preview: nothing was appended and nothing is citable.

    Same discipline as ``status view=candidate_findings``: the body is advisory. It is not a
    check, publication, coverage source, or receipt input. ``evidential`` is always false.
    """

    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: RequestIdWire
    ok: Literal[True]
    outcome: Literal["dry_run"]
    evidential: Literal[False]
    task_id: TaskIdWire
    session_id: SessionIdWire
    writer_id: WriterIdWire
    subject_frontier: FrontierModel
    result_frontier: FrontierModel
    would_accept: tuple[PublishWorkDryRunPreviewEventModel, ...]
    coverage: CoverageModel
    gaps: tuple[CodeWire, ...]
    # Issue #985: the same publish-time blocker notices a real publish would return.
    blocker_notices: tuple[PublishWorkBlockerNoticeModel, ...] | None = None
    # tb4n5 follow-up: the same unlinked-action notices a real publish would return.
    action_notices: tuple[PublishWorkActionNoticeModel, ...] | None = None

    optional_non_null_fields = frozenset({"blocker_notices", "action_notices"})

    @model_validator(mode="after")
    def _validate_publish_dry_run(self) -> PublishWorkDryRunModel:
        if not 1 <= len(self.would_accept) <= MAX_EVENTS_PER_BATCH:
            raise ValueError("dry_run_preview_count_invalid")
        if self.subject_frontier != self.result_frontier:
            raise ValueError("dry_run_frontier_moved")
        _require_unique(self.gaps, limit=64)
        _validate_blocker_notices(self.blocker_notices)
        _validate_action_notices(self.action_notices)
        _validate_model_against_schema(self, "publish-work-result")
        return self


def _validate_blocker_notices(notices: tuple[PublishWorkBlockerNoticeModel, ...] | None) -> None:
    if notices is None:
        return
    if not 1 <= len(notices) <= 64:
        raise ValueError("publish_blocker_notice_count_invalid")
    _require_unique(tuple((item.obligation_id, item.blocker_kind) for item in notices), limit=64)


def _validate_action_notices(notices: tuple[PublishWorkActionNoticeModel, ...] | None) -> None:
    # One row per unpaired action, so the bound is the batch bound: a full batch is never cut.
    if notices is None:
        return
    if not 1 <= len(notices) <= MAX_EVENTS_PER_BATCH:
        raise ValueError("publish_action_notice_count_invalid")
    _require_unique(tuple(item.action_id for item in notices), limit=MAX_EVENTS_PER_BATCH)


def _publish_work_result_kind(value: object) -> str:
    """Discriminate the publish result shapes without overloading ``ok`` alone."""

    if isinstance(value, Mapping):
        source = cast(Mapping[object, object], value)
        if source.get("ok") is False:
            return "failure"
        if source.get("response_completeness") == "accepted_projection_unavailable":
            return "accepted_projection_unavailable"
        if source.get("outcome") == "dry_run":
            return "dry_run"
        return "success"
    if getattr(value, "ok", None) is False:
        return "failure"
    if getattr(value, "response_completeness", None) == "accepted_projection_unavailable":
        return "accepted_projection_unavailable"
    if getattr(value, "outcome", None) == "dry_run":
        return "dry_run"
    return "success"


type PublishWorkResultBranch = Annotated[
    Annotated[PublishWorkSuccessModel, Tag("success")]
    | Annotated[
        PublishWorkAcceptedProjectionUnavailableModel,
        Tag("accepted_projection_unavailable"),
    ]
    | Annotated[PublishWorkDryRunModel, Tag("dry_run")]
    | Annotated[OperationFailureModel, Tag("failure")],
    Discriminator(_publish_work_result_kind),
]


class PublishWorkResultModel(PublicResultModel[PublishWorkResultBranch]):
    """RootModel wrapper with typed success-field accessors for static checkers.

    Pydantic RootModel delegates attributes to ``root`` at runtime, but pyright does not
    synthesize those members. After the publish result discriminator, call sites that
    hold ``PublishWorkInternalResult | PublishWorkResult`` need these fields to exist on both
    arms. Failure roots raise ``AttributeError`` for success-only names (callers check ``ok``).
    """

    @property
    def ok(self) -> bool:
        return self.root.ok

    @property
    def outcome(self) -> Literal["accepted", "replayed", "dry_run"]:
        root = self.root
        if type(root) is PublishWorkSuccessModel:
            return root.outcome
        if type(root) is PublishWorkAcceptedProjectionUnavailableModel:
            return root.outcome
        if type(root) is PublishWorkDryRunModel:
            return root.outcome
        raise AttributeError("outcome")

    @property
    def subject_frontier(self) -> FrontierModel:
        root = self.root
        if type(root) is PublishWorkSuccessModel:
            return root.subject_frontier
        if type(root) is PublishWorkAcceptedProjectionUnavailableModel:
            return root.subject_frontier
        if type(root) is PublishWorkDryRunModel:
            return root.subject_frontier
        raise AttributeError("subject_frontier")

    @property
    def result_frontier(self) -> FrontierModel:
        root = self.root
        if type(root) is PublishWorkSuccessModel:
            return root.result_frontier
        if type(root) is PublishWorkAcceptedProjectionUnavailableModel:
            return root.result_frontier
        if type(root) is PublishWorkDryRunModel:
            return root.result_frontier
        raise AttributeError("result_frontier")

    @property
    def accepted_events(
        self,
    ) -> (
        tuple[PublishWorkAcceptedEventModel, ...] | tuple[PublishWorkAcceptedMinimalEventModel, ...]
    ):
        root = self.root
        if type(root) is PublishWorkSuccessModel:
            return root.accepted_events
        if type(root) is PublishWorkAcceptedProjectionUnavailableModel:
            return root.accepted_events
        raise AttributeError("accepted_events")


class CheckPolicyExecutionModel(_ClosedModel):
    policy_id: Literal["coordination", "research-evidence", "work-integrity"]
    policy_version: RecordedPolicyVersionWire
    outcome: Literal["failed", "run", "skipped"]
    reason: Literal[
        "completed",
        "material_unavailable",
        "not_applicable",
        "policy_failure",
        "scope_excluded",
    ]

    @model_validator(mode="after")
    def _validate_policy_execution_pair(self) -> CheckPolicyExecutionModel:
        allowed: Mapping[str, frozenset[str]] = {
            "run": frozenset({"completed"}),
            "skipped": frozenset({"material_unavailable", "not_applicable", "scope_excluded"}),
            "failed": frozenset({"policy_failure"}),
        }
        if self.reason not in allowed[self.outcome]:
            raise ValueError("policy_execution_pair_invalid")
        return self


class CheckFindingChallengeModel(_ClosedModel):
    """Privacy-projectable dialogue retained with an AI-powered finding."""

    discrepancy: String1To8192 | OmittedContentModel
    alternative_interpretation: String1To8192 | OmittedContentModel
    requested_next_step: ReviewerNextStepWire
    uncertainty: String1To8192 | OmittedContentModel
    snippet: String1To8192 | OmittedContentModel | None = None

    @model_validator(mode="after")
    def _validate_challenge_content(self) -> CheckFindingChallengeModel:
        for value in (
            self.discrepancy,
            self.alternative_interpretation,
            self.uncertainty,
            self.snippet,
        ):
            if (
                isinstance(value, OmittedContentModel)
                and value.category is not DataCategory.FINDING_SUMMARY
            ):
                raise ValueError("challenge_omission_category_invalid")
        return self


class CheckProjectedFindingModel(_ClosedModel):
    optional_non_null_fields = frozenset({"challenge"})

    finding_id: FindingIdWire
    kind: Literal[
        "action_without_result",
        "claim_without_admissible_evidence",
        "coordination_overlap",
        "completion_with_open_obligations",
        "contradictory_claims_unresolved",
        "diff_does_not_match_account",
        "evidence_does_not_support_claim",
        "failed_work_omitted",
        "ledger_stale_or_incomplete",
        "material_limitation_omitted",
        "questionable_finding_rejection",
        "requested_item_never_attempted",
        "result_without_action",
        "stale_evidence_for_changed_state",
        "weak_or_stale_response",
        "code_defect",
        "task_requirement_unmet",
        "agent_criterion_unmet",
    ]
    origin: Literal["deterministic", "semantic_model_derived"]
    priority: Annotated[int, Field(ge=1, le=3)]
    summary: String1To8192 | OmittedContentModel
    detail: String1To8192 | OmittedContentModel
    subject_refs: tuple[SubjectIdWire, ...]
    policy_id: Literal["coordination", "research-evidence", "work-integrity"]
    policy_version: RecordedPolicyVersionWire
    subject_frontier: FrontierModel
    coverage: CoverageModel
    provenance: JsonValue | None
    challenge: CheckFindingChallengeModel | None = None

    @model_validator(mode="after")
    def _validate_projected_finding(self) -> CheckProjectedFindingModel:
        if not 1 <= len(self.subject_refs) <= 64 or len(set(self.subject_refs)) != len(
            self.subject_refs
        ):
            raise ValueError("finding_subject_refs_invalid")
        for value in (self.summary, self.detail):
            if (
                isinstance(value, OmittedContentModel)
                and value.category is not DataCategory.FINDING_SUMMARY
            ):
                raise ValueError("finding_omission_category_invalid")
        if self.origin == "deterministic" and self.provenance is not None:
            raise ValueError("deterministic_finding_provenance_invalid")
        if self.origin == "semantic_model_derived" and self.provenance is None:
            raise ValueError("semantic_finding_provenance_missing")
        return self


class CheckVerifiedItemModel(_ClosedModel):
    """One privacy-projectable requirement or claim judgement from the reviewer."""

    optional_non_null_fields = frozenset({"requirement_or_claim", "snippet"})

    requirement_or_claim: String1To8192 | OmittedContentModel
    verdict: Literal["supported", "not_supported", "not_assessable"]
    cited_refs: tuple[SubjectIdWire, ...]
    snippet: String1To8192 | OmittedContentModel | None = None

    @model_validator(mode="after")
    def _validate_verified_item(self) -> CheckVerifiedItemModel:
        if len(self.cited_refs) < 1 or len(self.cited_refs) > 16:
            raise ValueError("verified_cited_refs_invalid")
        _require_unique(self.cited_refs, limit=16)
        for value in (self.requirement_or_claim, self.snippet):
            if (
                isinstance(value, OmittedContentModel)
                and value.category is not DataCategory.FINDING_SUMMARY
            ):
                raise ValueError("verified_content_omission_category_invalid")
        if self.verdict == "not_assessable" and self.snippet is not None:
            raise ValueError("verified_snippet_invalid")
        if self.verdict != "not_assessable" and self.snippet is None:
            raise ValueError("verified_snippet_missing")
        return self


class CheckChildPreviewItemModel(_ClosedModel):
    child_task_id: TaskIdWire
    origin: LineageOriginWire
    acceptance: LineageAcceptanceWire
    work_state: WorkStateWire
    session_health: SessionHealthWire
    rollup_state: LineageRollupStateWire
    blocking_conditions: tuple[CodeWire, ...]

    @model_validator(mode="after")
    def _validate_child_preview_item(self) -> CheckChildPreviewItemModel:
        _require_unique(self.blocking_conditions, limit=64)
        return self


class CheckChildrenPreviewModel(_ClosedModel):
    label: Literal["recorded", "preview"]
    items: tuple[CheckChildPreviewItemModel, ...]
    tested_manifest_frontier: FrontierModel | None = None

    @model_validator(mode="after")
    def _validate_child_preview(self) -> CheckChildrenPreviewModel:
        _require_unique(tuple(item.child_task_id for item in self.items), limit=64)
        if len(self.items) > 64:
            raise ValueError("child_preview_count_invalid")
        return self


class CheckAdvisoryNoteModel(_ClosedModel):
    """A coordination hint, deliberately disjoint from CheckProjectedFindingModel."""

    kind: Literal["live_member_present", "duplicate_finding"]
    project_id: ProjectIdWire
    task_ids: tuple[TaskIdWire, ...]
    count: CanonicalPositiveUInt64Wire

    @model_validator(mode="after")
    def _validate_advisory_note(self) -> CheckAdvisoryNoteModel:
        _require_unique(self.task_ids, limit=64)
        if self.kind == "duplicate_finding" and len(self.task_ids) < 2:
            raise ValueError("advisory_note_task_count_invalid")
        return self


class CheckMissingItemModel(_ClosedModel):
    """One item an ``insufficient_packet`` review named, as the check recorded it (issue #907).

    A check limitation, never a finding: its closed kind, the case refs it concerns, and whether
    the agent can supply it. The reviewer's own reason is not part of the check result.
    """

    kind: MissingForAssessmentKindWire
    target_refs: tuple[SubjectIdWire, ...]
    availability: MissingItemAvailabilityWire

    @model_validator(mode="after")
    def _validate_check_missing_item(self) -> CheckMissingItemModel:
        _require_unique(self.target_refs, limit=MAX_MISSING_TARGET_REFS)
        return self


class SemanticWithheldItemModel(_ClosedModel):
    """One safe opaque case item omitted by the never-send heuristic."""

    item_id: OpaqueItemId
    reason: Literal["never_send_heuristic"]


class SemanticRedactedValueModel(_ClosedModel):
    """PL2-1 (issue #982): one case item whose external-review copy lost credential-like values.

    Structural only: the opaque item id, its catalogued ledger ref when that ref is itself an
    opaque token, the disposition, and 1-based line numbers in the item's own text. Never values.
    """

    optional_non_null_fields = frozenset({"source_ref"})

    item_id: OpaqueItemId
    disposition: Literal["item_withheld", "value_replaced"]
    lines: tuple[Annotated[int, Field(strict=True, ge=1, le=MAX_SEMANTIC_REDACTED_VALUE_LINE)], ...]
    source_ref: OpaqueItemId | None = None

    @model_validator(mode="after")
    def _validate_lines(self) -> SemanticRedactedValueModel:
        if len(self.lines) > MAX_SEMANTIC_REDACTED_VALUE_LINES or self.lines != tuple(
            sorted(set(self.lines))
        ):
            raise ValueError("semantic_redacted_value_lines_invalid")
        return self


def _validate_semantic_redacted_value_models(
    values: tuple[SemanticRedactedValueModel, ...] | None,
) -> None:
    if values is None:
        return
    item_ids = tuple(item.item_id for item in values)
    if len(values) > MAX_SEMANTIC_REDACTED_VALUE_ITEMS or item_ids != tuple(
        sorted(set(item_ids), key=str.encode)
    ):
        raise ValueError("semantic_redacted_values_invalid")


class CheckVersionSliceModel(_ClosedModel):
    protocol_version: Literal["0.1"]
    engine_version: VersionWire
    projection_version: VersionWire
    policy_packs: tuple[RecordedPolicyPackWire, ...]

    @model_validator(mode="after")
    def _validate_check_version_packs(self) -> CheckVersionSliceModel:
        if not 1 <= len(self.policy_packs) <= 3:
            raise ValueError("policy_pack_count_invalid")
        _require_unique(self.policy_packs, limit=3)
        return self


def _semantic_provenance_identity(
    value: object,
) -> tuple[SemanticStatus, SemanticReason]:
    """Extract identity fields without invoking methods on caller-owned mappings."""

    if type(value) is not dict:
        raise ProtocolValueError("invalid_semantic_provenance")

    missing = object()
    status_token: object = missing
    reason_token: object = missing
    source = cast(dict[object, object], value)
    for key, item in source.items():
        if type(key) is not str:
            continue
        if key == "status":
            status_token = item
        elif key == "reason":
            reason_token = item

    if type(status_token) is not str or type(reason_token) is not str:
        raise ProtocolValueError("invalid_semantic_provenance")
    try:
        status = SemanticStatus(status_token)
        reason = SemanticReason(reason_token)
    except ValueError as exc:
        raise ProtocolValueError("invalid_semantic_provenance") from exc
    return status, reason


class CheckContinuationModel(_ClosedModel):
    """What the caller must do to resume one suspended check.

    The command is fixed by the service rather than assembled by the caller: an agent told only
    that a human must approve has no supported way to learn *what* to approve, which is what
    drives it to read the catalog database or product source instead.
    """

    optional_non_null_fields = frozenset({"pending_id", "expires_at"})

    kind: Literal[
        "privacy_disclosure_decision",
        "repository_privacy_setup",
        "review_input_required",
    ]
    pending_id: PrivacyProposalIdWire | None = None
    expires_at: TimestampWire | None = None
    command: tuple[String1To256, ...]
    replay_request_id: RequestIdWire
    instruction: String1To4096

    @model_validator(mode="after")
    def _validate_continuation(self) -> CheckContinuationModel:
        # The service names the current launcher. A pre-rename service named the legacy one, so
        # either head is admitted; every rendering names the current launcher (ADR-048).
        launcher = self.command[0] if self.command else None
        arguments = tuple(self.command[1:]) if launcher in LAUNCHER_NAMES else None
        if self.kind == "privacy_disclosure_decision":
            if self.pending_id is None or self.expires_at is None or len(self.command) != 4:
                raise ValueError("check_continuation_disclosure_invalid")
            if arguments != ("privacy", "decide-disclosure", self.pending_id):
                raise ValueError("check_continuation_command_invalid")
        elif self.kind == "review_input_required" and (
            self.pending_id is not None
            or self.expires_at is not None
            or arguments != ("publish-work", "--input", "PATH")
        ):
            raise ValueError("check_continuation_review_input_invalid")
        elif self.kind == "repository_privacy_setup" and (
            self.pending_id is not None
            or self.expires_at is not None
            or arguments != ("--privacy",)
        ):
            raise ValueError("check_continuation_repository_setup_invalid")
        return self


class SpecificationPreflightModel(_ClosedModel):
    """Metadata-only specification admission result before semantic dispatch."""

    status: Literal["complete", "title_only", "missing", "withheld"]
    source: Literal["agent_transcribed", "host_captured_user_prompt", "task_title_only"] | None
    content_digest: Sha256Digest | None
    # The check-result schema types these as JSON integers (unlike counters elsewhere on the wire).
    content_bytes: int = Field(ge=0, le=2**53 - 1, strict=True)
    revision: int | None = Field(ge=0, le=2**53 - 1, strict=True)
    required: bool
    actionable: bool
    gap: Literal["task_statement_not_authorized", "task_statement_not_supplied"] | None = None


class ReviewInputSectionModel(_ClosedModel):
    """Metadata-only coverage for one bounded review-input family."""

    status: Literal[
        "complete",
        "partial",
        "title_only",
        "missing",
        "withheld",
        "not_selected",
    ]
    source_refs: tuple[String1To256, ...] = Field(max_length=16)
    # The prior-findings section lists up to sixteen findings' rows (issue #976).
    item_ids: tuple[String1To256, ...] = Field(max_length=128)
    omitted_refs: tuple[String1To256, ...] = Field(max_length=16)
    omission_reasons: tuple[
        Literal[
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
        ],
        ...,
    ] = Field(max_length=8)
    revision: int | None = Field(default=None, ge=0, le=2**53 - 1)
    content_digest: Sha256Digest | None = None
    content_bytes: int = Field(ge=0, le=MAX_SEMANTIC_CASE_BYTES)


class ReviewInputMissingModel(_ClosedModel):
    kind: Literal[
        "command_identity",
        "current_diff_for_path",
        "other",
        "plan_or_claim_text",
        "prior_finding_context",
        "task_statement",
        "verification_output",
    ]
    target_refs: tuple[String1To256, ...] = Field(max_length=4)
    supplied_refs: tuple[String1To256, ...] = Field(max_length=4)
    status: Literal["pending", "supplied", "unavailable", "repeated"]


class ReviewInputManifestModel(_ClosedModel):
    optional_non_null_fields = frozenset({"review_phase", "omitted_item_total", "follow_up_round"})

    # Frozen legacy identifier (ADR-048): the recorded review-input manifest tag.
    schema_: Literal["yoetz.review-input-manifest/1"] = Field(alias="schema")
    specification: ReviewInputSectionModel
    current_diff: ReviewInputSectionModel
    caller_evidence: ReviewInputSectionModel
    latest_verification: ReviewInputSectionModel
    prior_finding_context: ReviewInputSectionModel
    phase: Literal["composed", "provider_bound"]
    missing_inputs: tuple[ReviewInputMissingModel, ...] = Field(max_length=8)
    selected_item_count: int = Field(ge=0, le=304)
    selected_excerpt_bytes: int = Field(ge=0, le=MAX_SEMANTIC_CASE_BYTES)
    # Omission rows the manifest's packet lists, capped at MAX_REVIEW_OMISSIONS.
    omitted_item_count: int = Field(ge=0, le=MAX_REVIEW_OMISSIONS)
    # Issue #976 (tb4n1 D11), optional in place: every distinct omission before that cap.
    omitted_item_total: int | None = Field(default=None, ge=0, le=MAX_REVIEW_OMISSION_TOTAL)
    # Issue #976: the review phase the packet's question set named (closing review = final).
    review_phase: Literal["routine", "final"] | None = None
    # Issue #1047, optional in place: this packet is the Nth in-check follow-up, sent after FinishUP
    # added recorded excerpts the reviewer asked for; ``missing_inputs`` then lists that request.
    follow_up_round: int | None = Field(default=None, ge=1, le=MAX_REVIEW_FOLLOW_UP_ROUNDS)


class CheckAwaitingHumanModel(_ClosedModel):
    """The nonterminal CHECK branch: suspended on a local disclosure decision.

    Carries no verdict, findings, coverage, or AI-powered review provenance. A completion-grade shape here
    would let a caller conclude from a check that never ran.
    """

    optional_non_null_fields = frozenset({"specification_preflight"})

    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: RequestIdWire
    ok: Literal[True]
    state: Literal["awaiting_human", "awaiting_input"]
    task_id: TaskIdWire
    session_id: SessionIdWire
    writer_id: WriterIdWire
    subject_frontier: FrontierModel
    result_frontier: FrontierModel
    semantic_status: Literal["awaiting_human", "awaiting_input"]
    semantic_reason: Literal["human_approval_required", "review_input_required"]
    continuation: CheckContinuationModel
    versions: CheckVersionSliceModel
    specification_preflight: SpecificationPreflightModel | None = None
    # Every projected success body carries its disclosure projection; the nonterminal branch is
    # projected through the same path and must not be an exception to that invariant.
    privacy_projection: PrivacyProjectionModel

    @model_validator(mode="after")
    def _validate_awaiting_human(self) -> CheckAwaitingHumanModel:
        if self.continuation.replay_request_id != self.request_id:
            raise ValueError("check_continuation_request_mismatch")
        if self.state == "awaiting_input":
            if (
                self.continuation.kind != "review_input_required"
                or self.semantic_status != "awaiting_input"
                or self.semantic_reason != "review_input_required"
            ):
                raise ValueError("check_awaiting_input_shape_invalid")
        elif (
            self.continuation.kind == "review_input_required"
            or self.semantic_status != "awaiting_human"
            or self.semantic_reason != "human_approval_required"
        ):
            raise ValueError("check_awaiting_human_shape_invalid")
        _validate_model_against_schema(self, "check-result")
        return self


# tb4n3 RC-3 (issue #1026, ADR-046): the one closure verdict. Closed vocabularies mirror
# ``kernel.closure_class`` and ``kernel.receipt_prediction``; a conformance test asserts equality.
FindingClosureClassLiteral = Literal[
    "agent_work", "awaiting_ruling", "settled_unmet", "settled_disclosed", "resolved"
]
ObligationClosureClassLiteral = Literal[
    "agent_work", "settled_unmet", "settled_disclosed", "resolved"
]
FindingClosureBasisLiteral = Literal[
    "open_unanswered",
    "open_answered",
    "reopened",
    "limitation_requested",
    "rejected_awaiting_ruling",
    "rejected_review_unavailable",
    "acknowledged_not_done_requirement",
    "acknowledged_not_done_bookkeeping",
    "self_verified",
    "disputed_after_rebuttal",
    "rejection_accepted",
    "limitation_disclosed",
    "limitation_acknowledged_not_done",
    "absence_proved",
    "absence_proved_after_acknowledged_not_done",
    "absence_proved_after_self_verified",
]
ObligationClosureBasisLiteral = Literal[
    "open",
    "blocker_claimed",
    "resolved_deliverable_emptied",
    "acknowledged_not_done",
    "blocker_confirmed",
    "externally_evaluated",
    "resolved",
]
FindingNextActionLiteral = Literal[
    "repair",
    "recheck",
    "reject",
    "acknowledge",
    "acknowledge_not_done",
    "self_verify",
    "reopen",
    "none",
]
ReceiptConclusionLiteral = Literal[
    "unresolved_findings_remain",
    "insufficient_coverage",
    "no_unresolved_deterministic_findings",
]
PredictionReasonCodeLiteral = Literal[
    "completion_scope_gap",
    "findings_to_do",
    "findings_awaiting_ruling",
    "findings_unmet",
    "child_findings_actionable",
    "limitations_to_disclose",
    "findings_disclosed",
    "obligations_open",
    "obligations_acknowledged",
    "obligations_disclosed",
    "lineage_blocks",
    "no_applicable_check",
    "check_suppressed_findings",
    "check_verdict_insufficient",
    "policy_execution_incomplete",
    "live_gap_bounds",
]
# A prediction reason cites at most three findings, obligations or gap codes.
PredictionRefWire = Annotated[
    str,
    Field(
        max_length=128,
        pattern=(
            r"^(?:(?:fnd|obl)_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
            r"|[a-z][a-z0-9_]{0,127})$"
        ),
    ),
]
RecheckKeyWire = Annotated[
    str, Field(max_length=160, pattern=r"^(?:accept|ack|blocker|premise):[A-Za-z0-9_.:?-]{1,140}$")
]


class CheckChecklistItemModel(_ClosedModel):
    # ADR-046: who owes the next move and why. Optional on the unreleased 1.4.0 wire.
    optional_non_null_fields = frozenset({"closure_class", "closure_basis"})

    finding_id: FindingIdWire
    todo_state: FindingTodoStateLiteral
    review_rounds: CanonicalUInt64Wire
    closure_class: FindingClosureClassLiteral | None = None
    closure_basis: FindingClosureBasisLiteral | None = None

    @model_validator(mode="after")
    def _validate_item_closure(self) -> CheckChecklistItemModel:
        if (self.closure_class is None) != (self.closure_basis is None):
            raise ValueError("checklist_item_closure_partial")
        return self


class CheckChecklistCountsModel(_ClosedModel):
    # Issue #1020: present only when non-zero. ADR-046: the five closure counters are present
    # together or not at all (an earlier build omits them); ``to_do`` includes ``awaiting_ruling``.
    optional_non_null_fields = frozenset(
        {
            "disputed_after_rebuttal",
            "to_do",
            "awaiting_ruling",
            "unmet",
            "disclosed",
            "to_disclose",
        }
    )

    acknowledged_not_done: CanonicalUInt64Wire
    awaiting_ruling: CanonicalUInt64Wire | None = None
    disclosed: CanonicalUInt64Wire | None = None
    disputed_after_rebuttal: CanonicalUInt64Wire | None = None
    to_disclose: CanonicalUInt64Wire | None = None
    to_do: CanonicalUInt64Wire | None = None
    unmet: CanonicalUInt64Wire | None = None
    open: CanonicalUInt64Wire
    open_at_budget: CanonicalUInt64Wire
    rejection_accepted: CanonicalUInt64Wire
    self_verified: CanonicalUInt64Wire
    verified_resolved: CanonicalUInt64Wire

    @model_validator(mode="after")
    def _validate_closure_counts(self) -> CheckChecklistCountsModel:
        group = (self.to_do, self.awaiting_ruling, self.unmet, self.disclosed, self.to_disclose)
        if any(value is None for value in group) and any(value is not None for value in group):
            raise ValueError("checklist_closure_counts_partial")
        if self.to_do is not None and int(cast(str, self.awaiting_ruling)) > int(self.to_do):
            raise ValueError("checklist_closure_counts_invalid")
        return self


class CheckFindingChecklistModel(_ClosedModel):
    """The task's findings as a to-do list after this check (issue #905). Structural only."""

    attempt_budget: CanonicalPositiveUInt64Wire
    counts: CheckChecklistCountsModel
    items: tuple[CheckChecklistItemModel, ...]
    next: Literal[
        "decide_at_budget",
        "disclose_limitations",
        "request_receipt",
        "request_ruling",
        "work_open_findings",
    ]

    @model_validator(mode="after")
    def _validate_checklist(self) -> CheckFindingChecklistModel:
        _require_unique(tuple(item.finding_id for item in self.items), limit=100)
        if not 1 <= int(self.attempt_budget) <= 50:
            raise ValueError("checklist_attempt_budget_invalid")
        return self


class CheckOverallNextModel(_ClosedModel):
    """Task-level continuation beside the finding-only checklist (issue #963)."""

    status: Literal["action_required", "ready_with_limitations", "ready"]
    action: Literal[
        "supply_missing_input",
        "work_open_findings",
        "disclose_limitations",
        "request_ruling",
        "review_recorded_work",
        "request_receipt",
    ]
    target_refs: tuple[SubjectIdWire, ...] = Field(max_length=64)
    acknowledged_incomplete_endpoint: Literal["receipt"] | None = None
    # ADR-046: the receipt conclusion a request now would carry, from the receipt's own function.
    predicted_conclusion: ReceiptConclusionLiteral | None = None

    optional_non_null_fields = frozenset({"predicted_conclusion"})

    @model_validator(mode="after")
    def _validate_overall_next(self) -> CheckOverallNextModel:
        _require_unique(self.target_refs, limit=64)
        if self.action in {
            "supply_missing_input",
            "work_open_findings",
            "disclose_limitations",
            "request_ruling",
            "review_recorded_work",
        }:
            if self.status != "action_required":
                raise ValueError("check_overall_next_action_invalid")
            if (
                self.action
                in {
                    "work_open_findings",
                    "disclose_limitations",
                    "request_ruling",
                    "review_recorded_work",
                }
                and not self.target_refs
            ):
                raise ValueError("check_overall_next_targets_invalid")
        elif self.target_refs:
            raise ValueError("check_overall_next_targets_invalid")
        if self.acknowledged_incomplete_endpoint is not None and (
            self.action != "request_receipt" or self.status != "ready_with_limitations"
        ):
            raise ValueError("check_overall_next_endpoint_invalid")
        return self


class CheckObligationTotalsModel(_ClosedModel):
    declared: CanonicalUInt64Wire
    resolved: CanonicalUInt64Wire
    open: CanonicalUInt64Wire
    unreadable: CanonicalUInt64Wire
    with_evidence: CanonicalUInt64Wire
    scope_known: Literal["0", "1"]


class CheckRequestedItemTotalsModel(_ClosedModel):
    attempted: CanonicalUInt64Wire
    unattempted: CanonicalUInt64Wire


class CheckCommandTotalsModel(_ClosedModel):
    observed: CanonicalUInt64Wire
    failed: CanonicalUInt64Wire
    unknown: CanonicalUInt64Wire
    live_failed: CanonicalUInt64Wire
    retired_by_rerun: CanonicalUInt64Wire
    disclosed_not_rerun_green: CanonicalUInt64Wire


class CheckEvidenceTotalsModel(_ClosedModel):
    mutable_reference: CanonicalUInt64Wire
    metadata_only: CanonicalUInt64Wire
    content_digest: CanonicalUInt64Wire
    immutable_snapshot: CanonicalUInt64Wire
    independently_reproduced: CanonicalUInt64Wire


class CheckFindingTotalsModel(_ClosedModel):
    returned: CanonicalUInt64Wire
    actionable_returned: CanonicalUInt64Wire
    coverage_only_returned: CanonicalUInt64Wire
    suppressed: CanonicalUInt64Wire


class CheckTestEditTotalsModel(_ClosedModel):
    examined: Literal["0", "1"]
    baseline_known: Literal["0", "1"]
    modified: CanonicalUInt64Wire
    renamed: CanonicalUInt64Wire
    deleted: CanonicalUInt64Wire
    skipped: CanonicalUInt64Wire
    unjustified: CanonicalUInt64Wire
    unknown: CanonicalUInt64Wire


class CheckTotalsModel(_ClosedModel):
    obligations: CheckObligationTotalsModel
    requested_items: CheckRequestedItemTotalsModel
    commands: CheckCommandTotalsModel
    evidence: CheckEvidenceTotalsModel
    findings: CheckFindingTotalsModel
    test_edits: CheckTestEditTotalsModel


class FactLineageModel(_ClosedModel):
    """Where one derived fact came from (ADR-045): rule, subject, observing check, prior state.

    Closed tokens, counts and service-minted ids only: never a path, command text or prose. The
    obligation item is named by id and index (``status view=obligations`` resolves it). Counts are
    canonical decimal strings like every other count on the wire. A reader renders the same
    sentence from it on every surface (``kernel.fact_lineage.lineage_text``). The literals below
    repeat ``kernel.fact_lineage``'s closed sets; a test pins them equal.
    """

    optional_non_null_fields = frozenset(
        {
            "obligation_id",
            "item_index",
            "check_event_id",
            "frontier",
            "prior_event_id",
            "prior_frontier",
            "prior_size_bytes",
            "prior_lines",
            "now_size_bytes",
            "now_lines",
            "proof",
            "basis",
            "accepted_by",
        }
    )

    code: CodeWire
    rule: Literal[
        "deliverable_path_history",
        "deliverable_read",
        "planned_command_match",
        "planned_command_unmatched",
        "edit_after_verification_run",
    ]
    state: Literal[
        "emptied",
        "truncated",
        "removed",
        "accepted",
        "unreviewable",
        "matched_exact",
        "matched_normalized",
        "matched_prefix",
        "matched_flags",
        "matched_agent_link",
        "unmatched",
        "failed",
        "stale",
        "edited_after",
    ]
    obligation_id: ObligationIdWire | None = None
    item_index: Annotated[str, Field(pattern=r"^(?:[0-9]|[1-5][0-9]|6[0-3])$")] | None = None
    check_event_id: EventIdWire | None = None
    frontier: CanonicalUInt64Wire | None = None
    prior_event_id: EventIdWire | None = None
    prior_frontier: CanonicalUInt64Wire | None = None
    prior_size_bytes: CanonicalUInt64Wire | None = None
    prior_lines: CanonicalUInt64Wire | None = None
    now_size_bytes: CanonicalUInt64Wire | None = None
    now_lines: CanonicalUInt64Wire | None = None
    proof: Literal["task_base", "earlier_check", "observed_run"] | None = None
    basis: Literal["delivered", "verified", "present"] | None = None
    source_event_ids: tuple[EventIdWire, ...] = ()
    accepted_by: EventIdWire | None = None

    @model_validator(mode="after")
    def _validate_fact_lineage(self) -> FactLineageModel:
        _require_unique(self.source_event_ids, limit=8)
        if (self.item_index is None) != (
            self.obligation_id is None
        ) and self.item_index is not None:
            raise ValueError("fact_lineage_subject_mismatch")
        return self


def _validate_fact_lineage_models(values: tuple[FactLineageModel, ...] | None) -> None:
    if values is None:
        return
    if len(values) > 64:
        raise ValueError("fact_lineage_count_invalid")
    _require_unique(
        tuple((item.code, item.rule, item.obligation_id, item.item_index) for item in values),
        limit=64,
    )


class CheckReviewModeModel(_ClosedModel):
    """ADR-049: the conversation review mode one check ran in and why. Closed tokens only."""

    optional_non_null_fields = frozenset({"local_reason", "switch_event_id"})

    mode: Literal["ai_powered", "local"]
    source: Literal["check_request", "conversation_default", "conversation_switch"]
    local_reason: (
        Literal["ai_review_not_set_up", "owner_local_only", "review_disabled", "route_local_only"]
        | None
    ) = None
    switch_event_id: EventIdWire | None = None

    @model_validator(mode="after")
    def _validate_review_mode(self) -> CheckReviewModeModel:
        if (self.switch_event_id is not None) != (self.source == "conversation_switch"):
            raise ValueError("check_review_mode_invalid")
        if self.local_reason is not None and self.mode != "local":
            raise ValueError("check_review_mode_invalid")
        return self


class CheckObservationsAwaitedModel(_ClosedModel):
    """Outcome of the optional pre-check wait for this task's hook rows (issue #1012)."""

    state: Literal["bounded_timeout", "complete", "unavailable"]
    pending_count: CanonicalUInt64Wire


class CheckInspectionMissingModel(_ClosedModel):
    """One thing an open obligation still lacks, and whose move it is (issue #1048)."""

    optional_non_null_fields = frozenset({"item_indexes"})

    kind: Literal[
        "blocker_unconfirmed",
        "command_attempt_mismatch",
        "command_run_not_observed",
        "requested_item_not_attempted",
        "resolution_evidence_not_cited",
    ]
    # Frozen legacy identifier (ADR-048): the released ``owner`` wire value.
    owner: Literal["agent", "yoetz"]
    item_indexes: tuple[RequestedItemIndexWire, ...] | None = None

    @model_validator(mode="after")
    def _validate_inspection_missing(self) -> CheckInspectionMissingModel:
        if self.item_indexes is not None:
            _require_unique(self.item_indexes, limit=64)
        return self


class CheckInspectionObligationModel(_ClosedModel):
    obligation_id: ObligationIdWire
    closure_class: Literal["agent_work", "settled_disclosed", "settled_unmet"]
    closure_basis: Literal[
        "acknowledged_not_done",
        "blocker_claimed",
        "blocker_confirmed",
        "externally_evaluated",
        "open",
        "resolved",
        "resolved_deliverable_emptied",
    ]
    missing: Annotated[tuple[CheckInspectionMissingModel, ...], Field(max_length=8)]


class CheckInspectionFindingModel(_ClosedModel):
    finding_id: FindingIdWire
    closure_class: Literal["agent_work", "awaiting_ruling", "settled_disclosed", "settled_unmet"]
    closure_basis: Literal[
        "absence_proved",
        "absence_proved_after_acknowledged_not_done",
        "absence_proved_after_self_verified",
        "acknowledged_not_done_bookkeeping",
        "acknowledged_not_done_requirement",
        "disputed_after_rebuttal",
        "limitation_acknowledged_not_done",
        "limitation_disclosed",
        "limitation_requested",
        "open_answered",
        "open_unanswered",
        "rejected_awaiting_ruling",
        "rejected_review_unavailable",
        "rejection_accepted",
        "reopened",
        "self_verified",
    ]


class CheckInspectionRemainingModel(_ClosedModel):
    """What is left to close and why: the closure verdict status prints (ADR-046)."""

    optional_non_null_fields = frozenset({"predicted_conclusion"})

    readiness: Literal["action_required", "ready", "ready_with_limitations", "unknown"]
    predicted_conclusion: (
        Literal[
            "insufficient_coverage",
            "no_unresolved_deterministic_findings",
            "unresolved_findings_remain",
        ]
        | None
    ) = None
    agent_actionable: Annotated[tuple[ReadinessItemWire, ...], Field(max_length=128)]
    standing_limitations: Annotated[tuple[ReadinessItemWire, ...], Field(max_length=128)]
    obligations: Annotated[tuple[CheckInspectionObligationModel, ...], Field(max_length=64)]
    obligation_count: CanonicalUInt64Wire
    findings: Annotated[tuple[CheckInspectionFindingModel, ...], Field(max_length=64)]
    finding_count: CanonicalUInt64Wire

    @model_validator(mode="after")
    def _validate_inspection_remaining(self) -> CheckInspectionRemainingModel:
        _require_unique(self.agent_actionable, limit=128)
        _require_unique(self.standing_limitations, limit=128)
        return self


class CheckInspectionObservedActionModel(_ClosedModel):
    """One hook-observed action after the last check; structural facts only, never text."""

    optional_non_null_fields = frozenset(
        {"tool_name", "write_scope", "outcome", "exit_status", "command_commitment"}
    )

    event_id: EventIdWire
    ledger_sequence: CanonicalUInt64Wire
    action_kind: Literal["command", "edit", "other", "research", "review"]
    material_class: Literal["edit_or_write", "exploration", "non_counting_write", "other"]
    tool_name: ObservedToolWire | None = None
    # Frozen legacy identifier (ADR-048): ``yoetz_owned`` is a released write-scope value.
    write_scope: (
        Literal["notes", "outside_workspace", "scratch", "workspace", "yoetz_owned"] | None
    ) = None
    outcome: Literal["failure", "partial", "success", "unknown"] | None = None
    exit_status: Annotated[int, Field(ge=-(2**31), le=2**31 - 1)] | None = None
    command_commitment: HmacSha256Commitment | None = None


class CheckInspectionObservedModel(_ClosedModel):
    optional_non_null_fields = frozenset({"last_check_frontier"})

    last_check_frontier: CanonicalUInt64Wire | None = None
    actions: Annotated[tuple[CheckInspectionObservedActionModel, ...], Field(max_length=64)]
    action_count: CanonicalUInt64Wire


class CheckInspectionDeclaredItemModel(_ClosedModel):
    index: RequestedItemIndexWire
    item_kind: Literal["command", "directory", "file"]


class CheckInspectionEvidenceSourceModel(_ClosedModel):
    optional_non_null_fields = frozenset({"command_commitment", "outcome"})

    ref: EvidenceOrResultIdWire
    origin: Literal["asserted", "observed", "unattributed"]
    command_commitment: HmacSha256Commitment | None = None
    outcome: Literal["failure", "partial", "success", "unknown"] | None = None
    named_item_indexes: tuple[RequestedItemIndexWire, ...]

    @model_validator(mode="after")
    def _validate_inspection_source(self) -> CheckInspectionEvidenceSourceModel:
        _require_unique(self.named_item_indexes, limit=64)
        return self


class CheckInspectionAlignmentObligationModel(_ClosedModel):
    obligation_id: ObligationIdWire
    alignment: Literal[
        "evidence_names_declared_item",
        "evidence_off_declared_items",
        "evidence_unattributed",
        "no_declared_items",
    ]
    declared_items: Annotated[tuple[CheckInspectionDeclaredItemModel, ...], Field(max_length=64)]
    sources: Annotated[tuple[CheckInspectionEvidenceSourceModel, ...], Field(max_length=64)]


class CheckInspectionAlignmentModel(_ClosedModel):
    """Where each obligation's resolution evidence came from, beside what it declared.

    ``obligations`` lists flagged rows first; both counts cover every row, listed or not.
    """

    basis: Literal["recorded_links"]
    obligations: Annotated[
        tuple[CheckInspectionAlignmentObligationModel, ...], Field(max_length=64)
    ]
    obligation_count: CanonicalUInt64Wire
    off_declared_count: CanonicalUInt64Wire


class CheckInspectionModel(_ClosedModel):
    """The read-only ``mode: inspect`` branch (issue #1048, ADR-047).

    Carries no verdict, findings, coverage vector or review provenance: an inspection records
    nothing and mints nothing, so a completion-grade shape here would let a caller conclude from
    a check that never ran. ``subject_frontier`` is the ledger state it read.
    """

    optional_non_null_fields = frozenset({"observations_awaited"})

    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: RequestIdWire
    ok: Literal[True]
    state: Literal["inspected"]
    task_id: TaskIdWire
    session_id: SessionIdWire
    writer_id: WriterIdWire
    subject_frontier: FrontierModel
    remaining: CheckInspectionRemainingModel
    observed_since_check: CheckInspectionObservedModel
    evidence_alignment: CheckInspectionAlignmentModel
    observations_awaited: CheckObservationsAwaitedModel | None = None
    privacy_projection: PrivacyProjectionModel

    @model_validator(mode="after")
    def _validate_check_inspection(self) -> CheckInspectionModel:
        _validate_model_against_schema(self, "check-result")
        return self


class CheckSuccessModel(_ClosedModel):
    optional_non_null_fields = frozenset(
        {
            "observations_awaited",
            "children",
            "advisory_notes",
            "missing_for_assessment",
            "finding_checklist",
            "overall_next",
            "semantic_withheld_items",
            "semantic_redacted_values",
            "semantic_route_required",
            "review_mode",
            "fact_lineage",
            "review_input_manifest",
            "semantic_conclusion",
            "review_summary",
            "verified",
            "totals",
        }
    )

    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: RequestIdWire
    ok: Literal[True]
    state: Literal["complete"]
    task_id: TaskIdWire
    session_id: SessionIdWire
    writer_id: WriterIdWire
    subject_frontier: FrontierModel
    result_frontier: FrontierModel
    verdict: Literal[
        "action_required", "incomplete_check", "insufficient_coverage", "no_issue_detected"
    ]
    findings: tuple[CheckProjectedFindingModel, ...]
    suppressed_count: CanonicalUInt64Wire
    policy_executions: tuple[CheckPolicyExecutionModel, ...]
    semantic_status: SemanticStatusWire
    semantic_reason: SemanticReasonWire
    semantic_provenance: JsonValue | None = None
    # The provider's closed conclusion and Part 2 verification output are present on successful
    # AI-powered reviews. They remain optional on legacy/local-only results so old ledgers retain
    # their readable fallback behavior.
    semantic_conclusion: (
        Literal["no_material_discrepancy", "challenges_returned", "insufficient_packet"] | None
    ) = None
    review_summary: String1To8192 | OmittedContentModel | None = None
    verified: tuple[CheckVerifiedItemModel, ...] = ()
    children: CheckChildrenPreviewModel | None = None
    advisory_notes: tuple[CheckAdvisoryNoteModel, ...] = ()
    missing_for_assessment: tuple[CheckMissingItemModel, ...] = ()
    finding_checklist: CheckFindingChecklistModel | None = None
    overall_next: CheckOverallNextModel | None = None
    semantic_withheld_items: tuple[SemanticWithheldItemModel, ...] = ()
    # PL2-1: item refs and line numbers of values the external reviewer did not see.
    semantic_redacted_values: tuple[SemanticRedactedValueModel, ...] = ()
    review_input_manifest: ReviewInputManifestModel | None = None
    totals: CheckTotalsModel | None = None
    observations_awaited: CheckObservationsAwaitedModel | None = None
    # Issue #986: ``false`` only when the check's route did not require AI-powered review; absent
    # when it did or on results from older builds (the missing review then still blocks).
    semantic_route_required: bool | None = None
    # ADR-049: the conversation review mode this check ran in (local or AI-powered) and why.
    review_mode: CheckReviewModeModel | None = None
    # ADR-045: where each derived task fact this check carries came from (rule, obligation item,
    # observing check frontier, prior state). Absent when the check carries no such fact.
    fact_lineage: tuple[FactLineageModel, ...] = ()
    coverage: CoverageModel
    versions: CheckVersionSliceModel
    privacy_projection: PrivacyProjectionModel

    @field_validator("semantic_provenance", mode="before")
    @classmethod
    def _require_safe_semantic_provenance_identity(cls, value: object) -> object:
        if value is not None:
            _semantic_provenance_identity(value)
        return value

    @model_validator(mode="after")
    def _validate_check_success(self) -> CheckSuccessModel:
        if len(self.findings) > MAX_FINDINGS_LIMIT:
            raise ValueError("finding_count_invalid")
        if len(self.advisory_notes) > 64:
            raise ValueError("advisory_note_count_invalid")
        _require_unique(
            tuple((note.kind, note.project_id, note.task_ids) for note in self.advisory_notes),
            limit=64,
        )
        _require_unique(
            tuple((item.kind, item.target_refs) for item in self.missing_for_assessment),
            limit=MAX_MISSING_FOR_ASSESSMENT,
        )
        if len(self.semantic_withheld_items) > 64:
            raise ValueError("semantic_withheld_item_count_invalid")
        _require_unique(
            tuple(item.item_id for item in self.semantic_withheld_items),
            limit=64,
        )
        _validate_semantic_redacted_value_models(self.semantic_redacted_values)
        _validate_fact_lineage_models(self.fact_lineage)
        if not 1 <= len(self.policy_executions) <= 3 or len(set(self.policy_executions)) != len(
            self.policy_executions
        ):
            raise ValueError("policy_execution_count_invalid")
        validate_semantic_outcome(self.semantic_status, self.semantic_reason)
        provenance_status: SemanticStatus | None = None
        provenance_reason: SemanticReason | None = None
        if self.semantic_provenance is not None:
            provenance_status, provenance_reason = _semantic_provenance_identity(
                self.semantic_provenance
            )
        validate_semantic_provenance_binding(
            self.semantic_status,
            self.semantic_reason,
            provenance_status,
            provenance_reason,
        )
        if isinstance(self.review_summary, OmittedContentModel):
            if self.review_summary.category is not DataCategory.FINDING_SUMMARY:
                raise ValueError("review_summary_omission_category_invalid")
        if len(self.verified) > 64:
            raise ValueError("verified_item_count_invalid")
        _validate_model_against_schema(self, "check-result")
        return self


type CheckSuccessBranch = Annotated[
    CheckSuccessModel | CheckAwaitingHumanModel | CheckInspectionModel,
    Field(discriminator="state"),
]
type CheckResultBranch = Annotated[
    CheckSuccessBranch | OperationFailureModel, Field(discriminator="ok")
]


class CheckResultModel(PublicResultModel[CheckResultBranch]):
    pass


class RespondAcceptedEventModel(_ClosedModel):
    event_id: EventIdWire
    writer_sequence: CanonicalUInt64Wire
    ingestion_sequence: CanonicalUInt64Wire
    accepted_at: TimestampWire
    entry_digest: Sha256Digest


class RespondEvidenceSummaryModel(_ClosedModel):
    optional_non_null_fields = frozenset({"description"})

    reference_id: EvidenceOrResultIdWire
    description: String1To8192 | OmittedContentModel | None = None

    @model_validator(mode="after")
    def _validate_evidence_omission(self) -> RespondEvidenceSummaryModel:
        if (
            isinstance(self.description, OmittedContentModel)
            and self.description.category is not DataCategory.EVIDENCE_EXCERPT
        ):
            raise ValueError("evidence_omission_category_invalid")
        return self


class RespondResponseModel(_ClosedModel):
    optional_non_null_fields = frozenset(
        {"reason", "waiver_scope", "waiver_expiry", "duplicate_of_finding_id"}
    )

    response_event_id: EventIdWire
    finding_id: FindingIdWire
    finding_frontier: FrontierModel
    disposition: Literal[
        "acknowledged",
        "acknowledged_not_done",
        "duplicate_of",
        "provenance_disputed",
        "rejected",
        "reopened",
        "self_verified",
        "waived",
    ]
    evidence: tuple[RespondEvidenceSummaryModel, ...]
    reason: String1To4096 | OmittedContentModel | None = None
    waiver_scope: Literal["finding_only"] | None = None
    waiver_expiry: TimestampWire | None = None
    duplicate_of_finding_id: FindingIdWire | None = None

    @model_validator(mode="after")
    def _validate_response_fields(self) -> RespondResponseModel:
        if len(self.evidence) > 64:
            raise ValueError("response_evidence_limit")
        # Issue #996: the link target is present exactly on a ``duplicate_of`` answer.
        if (self.disposition == "duplicate_of") != (
            self.duplicate_of_finding_id is not None
        ) or self.duplicate_of_finding_id == self.finding_id:
            raise ValueError("response_fields_invalid")
        if (
            isinstance(self.reason, OmittedContentModel)
            and self.reason.category is not DataCategory.FINDING_SUMMARY
        ):
            raise ValueError("reason_omission_category_invalid")
        if self.disposition in {"acknowledged", "duplicate_of"}:
            if self.waiver_scope is not None or self.waiver_expiry is not None:
                raise ValueError("response_fields_invalid")
        elif self.disposition in {
            "acknowledged_not_done",
            "provenance_disputed",
            "rejected",
            "reopened",
            "self_verified",
        }:
            if (
                self.reason is None
                or self.waiver_scope is not None
                or self.waiver_expiry is not None
                or (self.disposition == "self_verified" and not self.evidence)
            ):
                raise ValueError("response_fields_invalid")
        elif self.reason is None or self.waiver_scope != "finding_only":
            raise ValueError("response_fields_invalid")
        return self


class RespondVersionSliceModel(_ClosedModel):
    protocol_version: Literal["0.1"]
    engine_version: VersionWire
    projection_version: VersionWire
    policy_packs: tuple[RecordedVersionSlicePackWire, ...]

    @model_validator(mode="after")
    def _validate_respond_version_packs(self) -> RespondVersionSliceModel:
        _require_unique(self.policy_packs, limit=2)
        return self


class RespondClosureAfterModel(_ClosedModel):
    """Where the finding stands once this answer is recorded (tb4n3 RC-7, issue #1030).

    ``todo_state`` is the finding's shared to-do state after the answer; ``limitation`` is set
    only for a reviewer's limitation request (owner decision Q4): ``limitation_requested`` until
    the agent answers it, ``limitation_disclosed`` once a reasoned acknowledgement did (the
    requirement may be met but cannot be verified here), ``limitation_acknowledged_not_done`` once
    it answered ``acknowledged_not_done`` (the requirement is NOT met; owner decision 2026-10-12).
    """

    optional_non_null_fields = frozenset({"limitation"})

    todo_state: Literal[
        "acknowledged_not_done",
        "disputed_after_rebuttal",
        "open",
        "rejection_accepted",
        "self_verified",
        "verified_resolved",
    ]
    limitation: (
        Literal["limitation_requested", "limitation_disclosed", "limitation_acknowledged_not_done"]
        | None
    ) = None


class RespondSuccessModel(_ClosedModel):
    optional_non_null_fields = frozenset({"closure_after"})

    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: RequestIdWire
    ok: Literal[True]
    task_id: TaskIdWire
    session_id: SessionIdWire
    writer_id: WriterIdWire
    subject_frontier: FrontierModel
    result_frontier: FrontierModel
    accepted_event: RespondAcceptedEventModel
    response: RespondResponseModel
    coverage: CoverageModel
    warning_codes: tuple[Literal["waiver_expired_at_recording"], ...]
    versions: RespondVersionSliceModel
    privacy_projection: PrivacyProjectionModel
    closure_after: RespondClosureAfterModel | None = None

    @model_validator(mode="after")
    def _validate_respond_success(self) -> RespondSuccessModel:
        _require_unique(self.warning_codes, limit=1)
        _validate_model_against_schema(self, "respond-result")
        return self


type RespondResultBranch = Annotated[
    RespondSuccessModel | OperationFailureModel, Field(discriminator="ok")
]


class RespondResultModel(PublicResultModel[RespondResultBranch]):
    pass


class StatusAssignmentItemModel(_ClosedModel):
    assignment_event_id: EventIdWire
    actor_id: ActorAssertionIdWire
    obligation_ids: tuple[ObligationIdWire, ...]
    scope_refs: tuple[SubjectIdWire, ...]
    resolved: bool

    @model_validator(mode="after")
    def _validate_assignment_sets(self) -> StatusAssignmentItemModel:
        _require_unique(self.obligation_ids, limit=64)
        _require_unique(self.scope_refs, limit=64)
        return self


class StatusAssignmentPageModel(_ClosedModel):
    items: tuple[StatusAssignmentItemModel, ...]
    next_cursor: CursorWire | None

    @model_validator(mode="after")
    def _validate_assignment_page(self) -> StatusAssignmentPageModel:
        if len(self.items) > 100:
            raise ValueError("status_page_limit")
        return self


class StatusFindingBasisModel(_ClosedModel):
    rule_id: CodeWire
    observed_fact_codes: tuple[CodeWire, ...]
    observed_refs: tuple[SubjectIdWire, ...]
    required_missing_fact_codes: tuple[CodeWire, ...]
    subject_state_relation: Literal["different", "same", "unknown"]
    frozen_source_availability: Literal["available", "not_recorded", "redacted", "unavailable"]
    coverage_gaps: tuple[CodeWire, ...]
    evidence_refs: tuple[EvidenceOrResultIdWire, ...]

    @model_validator(mode="after")
    def _validate_basis_sets(self) -> StatusFindingBasisModel:
        for values in (
            self.observed_fact_codes,
            self.observed_refs,
            self.required_missing_fact_codes,
            self.coverage_gaps,
            self.evidence_refs,
        ):
            _require_unique(values, limit=64)
        return self


class StatusCandidateFindingItemModel(_ClosedModel):
    kind: FindingKindWire
    origin: Literal["deterministic"]
    priority: Annotated[int, Field(ge=1, le=3)]
    summary: String1To8192 | OmittedContentModel
    detail: String1To8192 | OmittedContentModel
    subject_refs: tuple[SubjectIdWire, ...]
    policy_id: Literal["coordination", "research-evidence", "work-integrity"]
    policy_version: RecordedPolicyVersionWire
    subject_frontier: FrontierModel
    coverage: CoverageModel
    basis: StatusFindingBasisModel

    @model_validator(mode="after")
    def _validate_candidate_subjects(self) -> StatusCandidateFindingItemModel:
        if not self.subject_refs:
            raise ValueError("finding_subject_refs_empty")
        _require_unique(self.subject_refs, limit=64)
        for value in (self.summary, self.detail):
            if (
                isinstance(value, OmittedContentModel)
                and value.category is not DataCategory.FINDING_SUMMARY
            ):
                raise ValueError("finding_omission_category_invalid")
        return self


class StatusCandidateFindingsPageModel(_ClosedModel):
    items: tuple[StatusCandidateFindingItemModel, ...]
    next_cursor: CursorWire | None

    @model_validator(mode="after")
    def _validate_candidate_page(self) -> StatusCandidateFindingsPageModel:
        if len(self.items) > 100:
            raise ValueError("status_page_limit")
        return self


class StatusCompactFindingModel(_ClosedModel):
    finding_id: FindingIdWire
    kind: FindingKindWire
    priority: Annotated[int, Field(ge=1, le=3)]
    summary: String1To8192 | OmittedContentModel
    detail: String1To8192 | OmittedContentModel

    @model_validator(mode="after")
    def _validate_compact_finding_omissions(self) -> StatusCompactFindingModel:
        for value in (self.summary, self.detail):
            if (
                isinstance(value, OmittedContentModel)
                and value.category is not DataCategory.FINDING_SUMMARY
            ):
                raise ValueError("finding_omission_category_invalid")
        return self


class StatusLatestCheckTestEditsModel(_ClosedModel):
    """Structural test-edit counters from the latest persisted check."""

    checked_frontier: FrontierModel
    read_availability: Literal["available", "unavailable", "unknown"]
    examined: Literal["0", "1"]
    baseline_known: Literal["0", "1"]
    modified: CanonicalUInt64Wire
    renamed: CanonicalUInt64Wire
    deleted: CanonicalUInt64Wire
    skipped: CanonicalUInt64Wire
    unjustified: CanonicalUInt64Wire
    unknown: CanonicalUInt64Wire

    @model_validator(mode="after")
    def _validate_test_edit_availability(self) -> StatusLatestCheckTestEditsModel:
        expected = (
            "unavailable"
            if self.examined == "0"
            else "unknown"
            if self.baseline_known == "0" or self.unknown != "0"
            else "available"
        )
        if self.read_availability != expected:
            raise ValueError("status_test_edit_availability_mismatch")
        return self


class StatusCompactObligationModel(_ClosedModel):
    optional_non_null_fields = frozenset({"acceptance_criteria"})

    obligation_id: ObligationIdWire
    description: String1To8192 | OmittedContentModel
    evidence_expectation: String1To8192 | OmittedContentModel
    acceptance_criteria: String1To8192 | OmittedContentModel | None = None

    @model_validator(mode="after")
    def _validate_compact_obligation_omissions(self) -> StatusCompactObligationModel:
        for value in (self.description, self.evidence_expectation, self.acceptance_criteria):
            if (
                isinstance(value, OmittedContentModel)
                and value.category is not DataCategory.OBLIGATION_TEXT
            ):
                raise ValueError("obligation_omission_category_invalid")
        return self


class StatusLatestCheckModel(_ClosedModel):
    """The latest recorded check the compact status names, and what it concluded (#1027).

    Read off the recorded ``check_recorded`` event the projection's latest tested state points at:
    the event id, the frontier the check examined and its closed verdict. It is a pointer for an
    agent that lost its context (a post-compaction recap names it); it records nothing, is not a
    readiness claim, and a check recorded later than ``checked_frontier`` is not reflected here.
    """

    check_event_id: EventIdWire
    checked_frontier: FrontierModel
    verdict: Literal[
        "action_required", "incomplete_check", "insufficient_coverage", "no_issue_detected"
    ]


class StatusCompactItemModel(_ClosedModel):
    optional_non_null_fields = frozenset({"latest_check_test_edits", "latest_check"})

    task_id: TaskIdWire
    session_id: SessionIdWire
    task_title: String1To8192 | OmittedContentModel
    current_plan_event_id: EventIdWire | None
    declared_obligation_count: CanonicalUInt64Wire | None
    no_obligations_reason: (
        Literal[
            "no_material_change",
            "single_atomic_change",
            "exploratory_scope_unknown",
        ]
        | None
    )
    open_obligation_count: CanonicalUInt64Wire | None
    unanswered_finding_count: CanonicalUInt64Wire
    receipt_blocking_finding_count: CanonicalUInt64Wire
    open_obligations: tuple[StatusCompactObligationModel, ...]
    unanswered_findings: tuple[StatusCompactFindingModel, ...]
    freshness: FreshnessWire
    coverage: CoverageModel
    gaps: tuple[CodeWire, ...]
    latest_check_test_edits: StatusLatestCheckTestEditsModel | None = None
    latest_check: StatusLatestCheckModel | None = None

    @model_validator(mode="after")
    def _validate_compact_item(self) -> StatusCompactItemModel:
        if (
            isinstance(self.task_title, OmittedContentModel)
            and self.task_title.category is not DataCategory.TASK_DESCRIPTION
        ):
            raise ValueError("task_omission_category_invalid")
        if len(self.open_obligations) > 10 or len(self.unanswered_findings) > 10:
            raise ValueError("compact_item_limit")
        # One item carries two statements of freshness: this scalar, which an agent reads off the
        # summary line, and the coverage vector it stands in for. The scalar may report the
        # weaker fact but never the cleaner one, or the summary line tells the reader the ledger
        # is clean while the coverage beside it records the gaps (issue #307).
        if LedgerFreshness(self.freshness) > self.coverage.ledger_freshness:
            raise ValueError("compact_freshness_above_coverage")
        _require_unique(self.gaps, limit=64)
        unknown = self.declared_obligation_count is None or self.open_obligation_count is None
        if unknown and (
            self.declared_obligation_count is not None
            or self.open_obligation_count is not None
            or self.no_obligations_reason is not None
        ):
            raise ValueError("compact_scope_partial_unknown")
        if self.current_plan_event_id is None and (
            self.declared_obligation_count != "0" or self.no_obligations_reason is not None
        ):
            raise ValueError("compact_no_plan_scope_mismatch")
        if not unknown:
            declared = int(cast(str, self.declared_obligation_count))
            opened = int(cast(str, self.open_obligation_count))
            if opened > declared or len(self.open_obligations) > opened:
                raise ValueError("compact_obligation_count_mismatch")
            if self.no_obligations_reason is not None and declared != 0:
                raise ValueError("compact_no_obligations_reason_mismatch")
        if len(self.unanswered_findings) > int(self.unanswered_finding_count):
            raise ValueError("compact_unanswered_finding_count_mismatch")
        return self


class StatusCompactPageModel(_ClosedModel):
    items: tuple[StatusCompactItemModel, ...]
    next_cursor: None

    @model_validator(mode="after")
    def _validate_compact_page(self) -> StatusCompactPageModel:
        if len(self.items) > 1:
            raise ValueError("status_page_limit")
        return self


class StatusStructuralSubjectStateModel(_ClosedModel):
    optional_non_null_fields = frozenset({"tree_digest", "diff_digest"})

    tree_digest: Sha256Digest | None = None
    diff_digest: Sha256Digest | None = None

    @model_validator(mode="after")
    def _validate_structural_subject_state(self) -> StatusStructuralSubjectStateModel:
        if self.tree_digest is None and self.diff_digest is None:
            raise ProtocolValueError("empty_subject_state")
        return self


class StatusEvidenceItemModel(_ClosedModel):
    optional_non_null_fields = frozenset({"publication_channel"})

    evidence_id: EvidenceIdWire
    # The ledger-recorded channel of the row's source event: a cooperative writer can record only
    # cooperative_mcp or local_cli, while import and observation channels are service-only. The
    # service always fills it; it stays optional so rows from earlier 0.3 builds still parse.
    publication_channel: (
        Literal[
            "codex_jsonl_import",
            "cooperative_mcp",
            "engine_derived",
            "hook_observed",
            "human_import",
            "local_cli",
        ]
        | None
    ) = None
    strength: Literal[
        "content_digest",
        "immutable_snapshot",
        "independently_reproduced",
        "metadata_only",
        "mutable_reference",
    ]
    freshness: FreshnessWire
    available: bool
    description: String1To8192 | OmittedContentModel | None
    reference: String1To8192 | OmittedContentModel | None
    captured_object_id: ObjectIdWire | None
    content_digest: Sha256Digest | None
    subject_state: StatusStructuralSubjectStateModel | None

    @model_validator(mode="after")
    def _validate_evidence_item_omissions(self) -> StatusEvidenceItemModel:
        for value in (self.description, self.reference):
            if (
                isinstance(value, OmittedContentModel)
                and value.category is not DataCategory.EVIDENCE_EXCERPT
            ):
                raise ValueError("evidence_omission_category_invalid")
        return self


class StatusEvidencePageModel(_ClosedModel):
    items: tuple[StatusEvidenceItemModel, ...]
    next_cursor: CursorWire | None

    @model_validator(mode="after")
    def _validate_evidence_page(self) -> StatusEvidencePageModel:
        if len(self.items) > 100:
            raise ValueError("status_page_limit")
        return self


FindingTodoStateLiteral = Literal[
    "acknowledged_not_done",
    "disputed_after_rebuttal",
    "open",
    "rejection_accepted",
    "self_verified",
    "verified_resolved",
]


class StatusFindingItemModel(_ClosedModel):
    # Issue #905 to-do facts: present on every current row, absent only on older recordings.
    optional_non_null_fields = frozenset(
        {
            "challenge",
            "todo_state",
            "review_rounds",
            "finding_frontier",
            "duplicate_of_finding_id",
            "closure_class",
            "closure_basis",
            "next_actions",
        }
    )

    finding_id: FindingIdWire
    kind: FindingKindWire
    origin: Literal["deterministic", "semantic_model_derived"]
    priority: Annotated[int, Field(ge=1, le=3)]
    summary: String1To8192 | OmittedContentModel
    detail: String1To8192 | OmittedContentModel
    subject_refs: tuple[SubjectIdWire, ...]
    policy_id: Literal["coordination", "research-evidence", "work-integrity"]
    policy_version: RecordedPolicyVersionWire
    subject_frontier: FrontierModel
    coverage: CoverageModel
    provenance: JsonValue | None
    disposition: Literal[
        "acknowledged",
        "acknowledged_not_done",
        "duplicate_of",
        "none",
        "provenance_disputed",
        "rejected",
        "reopened",
        "self_verified",
        "waived",
    ]
    resolved: bool
    response_event_id: EventIdWire | None
    reason: String1To8192 | OmittedContentModel | None
    waiver_scope: Literal["finding_only"] | None
    waiver_expiry: TimestampWire | None
    challenge: CheckFindingChallengeModel | None = None
    todo_state: FindingTodoStateLiteral | None = None
    review_rounds: CanonicalUInt64Wire | None = None
    # Issue #917: the frontier of the ledger event that carries this finding's record
    # (sequence plus that event's head digest), for every origin. ``respond`` accepts it
    # as ``finding_frontier`` as-is, so no historical frontier has to be reconstructed.
    finding_frontier: FrontierModel | None = None
    # Issue #996: the earlier finding this one is linked to, present exactly while its
    # ``duplicate_of`` link holds; ``todo_state`` is then derived from that finding. A
    # ``duplicate_of`` row without it is a link a later check broke: it needs its own answer.
    duplicate_of_finding_id: FindingIdWire | None = None
    # tb4n3 RC-3 (ADR-046): who owes the next move on this finding and why, the receipt effect it
    # has, and the closed set of answers that would move it. Absent on non-work kinds and on an
    # earlier 0.3 build. ``todo_state`` keeps its wire values.
    closure_class: FindingClosureClassLiteral | None = None
    closure_basis: FindingClosureBasisLiteral | None = None
    next_actions: tuple[FindingNextActionLiteral, ...] | None = None

    @model_validator(mode="after")
    def _validate_finding_item(self) -> StatusFindingItemModel:
        if (self.closure_class is None) != (self.closure_basis is None) or (
            self.next_actions is not None and self.closure_class is None
        ):
            raise ValueError("finding_closure_partial")
        if self.next_actions is not None:
            _require_unique(self.next_actions, limit=8)
        if not self.subject_refs:
            raise ValueError("finding_subject_refs_empty")
        _require_unique(self.subject_refs, limit=64)
        for value in (self.summary, self.detail, self.reason):
            if (
                isinstance(value, OmittedContentModel)
                and value.category is not DataCategory.FINDING_SUMMARY
            ):
                raise ValueError("finding_omission_category_invalid")
        if self.disposition == "provenance_disputed" and (
            self.reason is None
            or self.resolved
            or self.waiver_scope is not None
            or self.waiver_expiry is not None
        ):
            raise ValueError("provenance_disputed_finding_state_invalid")
        # tb4n3 RC-7 (#1030): ``acknowledged_not_done`` and ``self_verified`` are the agent's last
        # word until a later qualifying check proves the issue absent, so such a row may read
        # ``resolved``; ``reopened`` takes a not-done answer back.
        if self.disposition == "acknowledged_not_done" and (
            self.reason is None or self.waiver_scope is not None or self.waiver_expiry is not None
        ):
            raise ValueError("acknowledged_not_done_finding_state_invalid")
        if self.disposition == "self_verified" and (
            self.reason is None or self.waiver_scope is not None or self.waiver_expiry is not None
        ):
            raise ValueError("self_verified_finding_state_invalid")
        if self.disposition == "reopened" and (
            self.reason is None or self.waiver_scope is not None or self.waiver_expiry is not None
        ):
            raise ValueError("reopened_finding_state_invalid")
        if self.duplicate_of_finding_id is not None and (
            self.disposition != "duplicate_of" or self.duplicate_of_finding_id == self.finding_id
        ):
            raise ValueError("duplicate_of_finding_state_invalid")
        if self.disposition == "duplicate_of" and (
            self.waiver_scope is not None or self.waiver_expiry is not None
        ):
            raise ValueError("duplicate_of_finding_state_invalid")
        return self


class StatusFindingsPageModel(_ClosedModel):
    optional_non_null_fields = frozenset({"attempt_budget"})

    items: tuple[StatusFindingItemModel, ...]
    next_cursor: CursorWire | None
    # The owner's per-item review-round budget, so ``review_rounds`` reads as "2 of 5" (#905).
    attempt_budget: CanonicalPositiveUInt64Wire | None = None

    @model_validator(mode="after")
    def _validate_findings_page(self) -> StatusFindingsPageModel:
        if len(self.items) > 100:
            raise ValueError("status_page_limit")
        return self


class StatusHistoryItemModel(_ClosedModel):
    event_id: EventIdWire
    schema_name: SchemaNameWire
    schema_version: SemverWire
    actor_id: ActorAssertionIdWire
    publication_channel: Literal[
        "codex_jsonl_import",
        "cooperative_mcp",
        "engine_derived",
        "hook_observed",
        "human_import",
        "local_cli",
    ]
    ingestion_sequence: CanonicalUInt64Wire
    # Caller-asserted event time; not service acceptance time.
    occurred_at: TimestampWire
    # Trusted-local service acceptance time bound into the entry digest.
    accepted_at: TimestampWire
    # Exact comparison of the two recorded clocks; this does not verify caller time.
    occurred_at_consistency: Annotated[
        Literal[
            "within_forward_skew_allowance",
            "ahead_of_forward_skew_allowance",
        ],
        Field(
            description=(
                "Exact comparison of caller-asserted occurred_at with service accepted_at. "
                "Caller time through five seconds ahead is within_forward_skew_allowance; "
                "larger forward drift is ahead_of_forward_skew_allowance. This does not verify "
                "caller time or affect ingestion-sequence ordering."
            )
        ),
    ]
    projection_status: Literal["projected", "unknown_unprojected"]
    summary_code: Literal[
        "action_recorded",
        "assignment_recorded",
        "check_recorded",
        "child_accepted",
        "child_dependencies_recorded",
        "child_rejected",
        "child_written_off",
        "claim_recorded",
        "coordination_context_recorded",
        "coordination_disposition_recorded",
        "coordination_obligation_declared",
        "decision_recorded",
        "delegation_cancelled",
        "delegation_declared",
        "evidence_recorded",
        "finding_recorded",
        "obligation_published",
        "opaque_unknown",
        "plan_published",
        "plan_revised",
        "receipt_recorded",
        "redaction_recorded",
        "response_recorded",
        "result_recorded",
        "session_opened",
        "session_resumed",
        "work_abandoned",
        "work_cancelled",
        "work_closed",
        "work_written_off",
    ]


class StatusHistoryItemV14Model(StatusHistoryItemModel):
    """v1.4 history row carrying a completed check's provider-bound input coverage."""

    optional_non_null_fields = frozenset({"review_input_manifest"})
    review_input_manifest: ReviewInputManifestModel | None = None


class StatusHistoryPageModel(_ClosedModel):
    items: tuple[StatusHistoryItemModel | StatusHistoryItemV14Model, ...]
    next_cursor: CursorWire | None

    @model_validator(mode="after")
    def _validate_history_page(self) -> StatusHistoryPageModel:
        if len(self.items) > 100:
            raise ValueError("status_page_limit")
        return self


class StatusImportStatusModel(_ClosedModel):
    pending_count: CanonicalUInt64Wire
    terminal_count: CanonicalUInt64Wire
    phase: (
        Literal[
            "plan_ready",
            "publishing",
            "report_published",
            "report_ready",
            "source_reserved",
            "terminal",
        ]
        | None
    )
    report_evidence_id: EvidenceIdWire | None
    source_identity_digest: Sha256Digest | None


class StatusBlockedObligationModel(_ClosedModel):
    """One open obligation a recorded ``finishup-blocker`` decision names (issues #976, #977).

    Only service-minted ids and the closed blocker kind: the decision's statement and rationale
    stay in the ledger. The Stop-time closure gate names these when it re-asks a blocker once.
    """

    obligation_id: ObligationIdWire
    blocker_kind: Literal["authority", "consent", "credential", "dependency_unavailable"]
    decision_event_id: EventIdWire
    # Issue #985. ``claimed``: only the first decision names it, so it is still agent work
    # (``obligation_blocker_unconfirmed``); ``confirmed``: a later decision repeated the same
    # blocker line (``confirmation_event_id``). Optional on the unreleased 1.4.0 wire: an earlier
    # 0.3 build omits both, and absence never means confirmed.
    confirmation: Literal["claimed", "confirmed"] | None = None
    confirmation_event_id: EventIdWire | None = None

    optional_non_null_fields = frozenset({"confirmation", "confirmation_event_id"})

    @model_validator(mode="after")
    def _validate_blocker_confirmation(self) -> StatusBlockedObligationModel:
        if (self.confirmation == "confirmed") != (self.confirmation_event_id is not None):
            raise ValueError("closure_readiness_blocker_confirmation_mismatch")
        if self.confirmation_event_id == self.decision_event_id:
            raise ValueError("closure_readiness_blocker_confirmation_mismatch")
        return self


class StatusCheckCauseModel(_ClosedModel):
    """Why the latest check is not applicable, or why the earlier-frontier code bounds (RC-6).

    The first record that followed the check and decided it: ``superseded`` names the record that
    revoked the check (an observed deliverable or workspace edit, a cooperative material record,
    an observation finding); ``bounds_conclusion`` names the first observation FinishUP could not
    prove harmless. Service-minted ids, closed tokens and the recorded tool name only: the hook
    records the tool and whether a write left the workspace, never the path (owner lineage rule,
    issue #1029).
    """

    effect: Literal["superseded", "bounds_conclusion"]
    event_id: EventIdWire
    ledger_sequence: CanonicalUInt64Wire
    check_event_id: EventIdWire
    check_subject_frontier: CanonicalUInt64Wire
    family: CodeWire
    # Frozen legacy identifier (ADR-048): ``yoetz_own_call`` is a recorded material class.
    material_class: Literal[
        "yoetz_own_call",
        "response",
        "exploration",
        "no_tool_activity",
        "non_counting_write",
        "edit_or_write",
        "other",
    ]
    rule: CodeWire
    tool: ObservedToolWire | None = None

    optional_non_null_fields = frozenset({"tool"})


class StatusCredentialHeuristicModel(_ClosedModel):
    """The possible-credential filter state for the external AI reviewer (issue #982)."""

    repository: Literal["disabled", "enforced", "unknown"]
    machine_default: Literal["disabled", "enforced", "unknown"]


class StatusReviewModeModel(_ClosedModel):
    """ADR-049: this conversation's review mode, the owner's setting and the latest switch."""

    optional_non_null_fields = frozenset({"local_reason", "switch_event_id", "switch_sequence"})

    mode: Literal["ai_powered", "local"]
    requested: Literal["ai_powered", "local"]
    setting: Literal["ai_powered", "local_agent_opt_in", "local_only", "local_owner_approval"]
    setting_explicit: bool
    ai_review_available: bool
    local_reason: (
        Literal[
            "ai_review_not_set_up",
            "conversation_default",
            "owner_local_only",
            "review_disabled",
            "route_local_only",
            "switched_to_local",
        ]
        | None
    ) = None
    switch_event_id: EventIdWire | None = None
    switch_sequence: CanonicalUInt64Wire | None = None


class StatusPredictedReasonModel(_ClosedModel):
    """One rule that fired in the receipt prediction, with the lineage a reader needs."""

    optional_non_null_fields = frozenset({"since_frontier"})

    code: PredictionReasonCodeLiteral
    rule: Literal["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10"]
    count: CanonicalPositiveUInt64Wire
    refs: tuple[PredictionRefWire, ...]
    since_frontier: CanonicalUInt64Wire | None = None

    @model_validator(mode="after")
    def _validate_reason(self) -> StatusPredictedReasonModel:
        _require_unique(self.refs, limit=3)
        return self


class StatusPredictedReceiptModel(_ClosedModel):
    """The conclusion a receipt requested at this frontier would carry, and why (ADR-046).

    Computed by the receipt's own conclusion function over the receipt's own context, so it is
    the label ``receipt`` returns for the same frontier (``provisional`` while a check is in flight
    or a live dependency fact is not yet recorded).
    """

    conclusion: ReceiptConclusionLiteral
    reasons: tuple[StatusPredictedReasonModel, ...]
    reason_total: CanonicalUInt64Wire
    basis_frontier: CanonicalUInt64Wire
    provisional: bool

    @model_validator(mode="after")
    def _validate_prediction(self) -> StatusPredictedReceiptModel:
        if len(self.reasons) > 8 or len(self.reasons) > int(self.reason_total):
            raise ValueError("predicted_receipt_reasons_invalid")
        if (self.conclusion == "no_unresolved_deterministic_findings") != (
            int(self.reason_total) == 0
        ):
            raise ValueError("predicted_receipt_conclusion_mismatch")
        return self


class StatusFindingCountsModel(_ClosedModel):
    """The finding counters every surface prints (ADR-046); ``to_do`` includes ``awaiting_ruling``."""

    to_do: CanonicalUInt64Wire
    awaiting_ruling: CanonicalUInt64Wire
    unmet: CanonicalUInt64Wire
    disclosed: CanonicalUInt64Wire
    to_disclose: CanonicalUInt64Wire
    self_verify_eligible: CanonicalUInt64Wire

    @model_validator(mode="after")
    def _validate_counts(self) -> StatusFindingCountsModel:
        if int(self.awaiting_ruling) > int(self.to_do) or int(self.self_verify_eligible) > int(
            self.to_do
        ):
            raise ValueError("finding_counts_invalid")
        return self


class StatusObligationCountsModel(_ClosedModel):
    open: CanonicalUInt64Wire
    acknowledged: CanonicalUInt64Wire
    disclosed: CanonicalUInt64Wire


class StatusRecheckModel(_ClosedModel):
    """A once-per-frontier re-read the Stop gate may ask for (RC-8); delivery memory is the gate's."""

    kind: Literal["acceptance", "acknowledgement", "blocker", "premise"]
    key: RecheckKeyWire
    subjects: tuple[SubjectIdWire, ...]
    rule: CodeWire
    since_frontier: CanonicalUInt64Wire

    @model_validator(mode="after")
    def _validate_recheck(self) -> StatusRecheckModel:
        _require_unique(self.subjects, limit=8)
        return self


class StatusAwaitingRulingFindingModel(_ClosedModel):
    """A finding the agent rejected with a reason that no reviewer ruling has answered yet."""

    finding_id: FindingIdWire
    # The frontier of the agent's standing rejection: the answer the ruling is owed to.
    since_frontier: CanonicalUInt64Wire


UndeclaredReferencePathWire = Annotated[
    str,
    Field(
        min_length=1,
        max_length=256,
        pattern=r"^[^\u0000-\u001f\u007f/][^\u0000-\u001f\u007f]*$",
    ),
]


class StatusUndeclaredReferenceModel(_ClosedModel):
    """A delivered file naming files the change created that no item declares (tb4n4, #1044).

    The declared item that names them, the root-relative files it names (repository-excerpt
    content: a privacy policy may withhold each one) and how many it names in all, from the
    applicable check's recorded deliverable state. The Stop gate and the receipt name them.
    A name the requesting writer itself published in this session returns to it under the
    ordinary ``self_authored`` rule (tb4n5); a withheld one is listed with the agent's own shell.
    """

    obligation_id: ObligationIdWire
    item_index: Annotated[str, Field(pattern=r"^(?:[0-9]|[1-5][0-9]|6[0-3])$")]
    paths: tuple[UndeclaredReferencePathWire | OmittedContentModel, ...] = Field(max_length=8)
    total: CanonicalPositiveUInt64Wire

    @model_validator(mode="after")
    def _validate_undeclared_reference(self) -> StatusUndeclaredReferenceModel:
        if int(self.total) < len(self.paths):
            raise ValueError("undeclared_reference_total_invalid")
        for value in self.paths:
            if (
                isinstance(value, OmittedContentModel)
                and value.category is not DataCategory.REPOSITORY_EXCERPT
            ):
                raise ValueError("undeclared_reference_omission_category_invalid")
        return self


class StatusClosureReadinessModel(_ClosedModel):
    """What currently bounds a completion conclusion, before a check or receipt is spent.

    Advisory and derived: reading it records nothing, creates no verdict, and never strengthens
    coverage. It exists so an agent can see that a check would come back coverage-bounded instead
    of discovering it afterwards from the receipt.

    ``blocking_conditions`` keeps naming everything that bounds the conclusion. The checklist
    fields split that into what the agent can still do (``agent_actionable``), what this host,
    profile or privacy policy always limits (``standing_limitations``, classified by the closed
    table ``gap_classification_version`` names), and what the agent recorded as not done
    (``acknowledged_not_done``). ``state`` is ``ready_with_limitations`` exactly when nothing is
    left to do but the receipt will disclose limitations or acknowledged items (ADR-032).
    """

    declared_obligation_count: CanonicalUInt64Wire | None
    no_obligations_reason: (
        Literal[
            "no_material_change",
            "single_atomic_change",
            "exploratory_scope_unknown",
        ]
        | None
    )
    open_obligation_count: CanonicalUInt64Wire | None
    unanswered_finding_count: CanonicalUInt64Wire | None
    receipt_blocking_finding_count: CanonicalUInt64Wire | None
    blocking_conditions: tuple[
        Literal[
            "obligations_open",
            "findings_unanswered",
            "receipt_findings_unresolved",
            "no_plan_published",
            "no_obligations_declared",
            "projection_stale",
            "coverage_gaps_declared",
            "readiness_unknown",
        ],
        ...,
    ]
    # The checklist (issue #913) is emitted on every status success by this build. It is optional
    # on the unreleased 1.4.0 wire so a result shaped by an earlier 0.3 build still validates; it
    # is then absent as a whole, never partially present and never null.
    state: Literal["action_required", "ready", "ready_with_limitations", "unknown"] | None = None
    gap_classification_version: Literal["1", "2", "3", "4", "5", "6", "7", "8"] | None = None
    agent_actionable: tuple[ReadinessItemWire, ...] | None = None
    standing_limitations: tuple[CodeWire, ...] | None = None
    acknowledged_not_done: tuple[AcknowledgedItemIdWire, ...] | None = None
    acknowledged_not_done_count: CanonicalUInt64Wire | None = None
    # Open obligations a recorded blocker decision names (#977). Optional on the unreleased 1.4.0
    # wire: an earlier 0.3 build omits it, and absence never means "nothing is blocked".
    blocked_obligations: tuple[StatusBlockedObligationModel, ...] | None = None
    # F3: result ids a whole-task completion claim recorded now must name in ``limitation_refs``
    # (the reducer's rule; sorted, first 64) and their full count. Optional on the unreleased
    # 1.4.0 wire, present together; absence never means "nothing is required".
    limitation_refs_required: tuple[ResultIdWire, ...] | None = None
    limitation_refs_required_count: CanonicalUInt64Wire | None = None
    # #997: how many obligations are acknowledged as not done (not truncated, unlike
    # ``acknowledged_not_done``). ``open_obligation_count`` never includes them. Optional on
    # the unreleased 1.4.0 wire; absent from an earlier 0.3 build.
    acknowledged_obligation_count: CanonicalUInt64Wire | None = None
    # tb4n3 RC-6 (owner lineage rule): the record that decided ``check_not_applicable`` (listed as
    # work) or the bounding standing ``check_current_as_of_earlier_frontier``. Optional on the
    # unreleased 1.4.0 wire: absent when neither is listed, and from an earlier 0.3 build.
    check_cause: StatusCheckCauseModel | None = None
    # tb4n3 RC-3 (ADR-046): the receipt conclusion this frontier would carry and why, the finding
    # and obligation counters, and the once-per-frontier re-reads. Optional on the unreleased 1.4.0
    # wire: absent from an earlier 0.3 build and whenever the closure basis could not be read
    # (never guessed); ``receipt_blocking_finding_count`` keeps its wire meaning (to do + unmet).
    predicted_receipt: StatusPredictedReceiptModel | None = None
    finding_counts: StatusFindingCountsModel | None = None
    obligation_counts: StatusObligationCountsModel | None = None
    rechecks: tuple[StatusRecheckModel, ...] | None = None
    # The findings counted in ``finding_counts.awaiting_ruling`` (at most eight, ordered by id),
    # so the Stop gate and the status text name them and the frontier of the rejection.
    awaiting_ruling_findings: tuple[StatusAwaitingRulingFindingModel, ...] | None = None
    # ADR-045: where each derived fact the checklist lists came from (rule, obligation item,
    # observing check and frontier, prior state, observed runs). Optional on the unreleased 1.4.0
    # wire: an earlier 0.3 build omits it, and absence never means the facts have no source.
    fact_lineage: tuple[FactLineageModel, ...] | None = None
    # tb4n4 (#1044): the delivered files that name files the change created and no item declares
    # (``deliverable_references_undeclared_file``), with those files. Optional on the unreleased
    # 1.4.0 wire: absent when the applicable check found none, and from an earlier 0.3 build.
    undeclared_references: tuple[StatusUndeclaredReferenceModel, ...] | None = Field(
        default=None, max_length=16
    )

    optional_non_null_fields = frozenset(
        {
            "check_cause",
            "predicted_receipt",
            "undeclared_references",
            "finding_counts",
            "obligation_counts",
            "rechecks",
            "awaiting_ruling_findings",
            "acknowledged_obligation_count",
            "fact_lineage",
            "state",
            "gap_classification_version",
            "agent_actionable",
            "standing_limitations",
            "acknowledged_not_done",
            "acknowledged_not_done_count",
            "blocked_obligations",
            "limitation_refs_required",
            "limitation_refs_required_count",
        }
    )

    @model_validator(mode="after")
    def _validate_closure_readiness(self) -> StatusClosureReadinessModel:
        _require_unique(self.blocking_conditions, limit=8)
        if (self.limitation_refs_required is None) != (self.limitation_refs_required_count is None):
            raise ValueError("closure_readiness_limitation_refs_partial")
        if self.limitation_refs_required is not None:
            _require_unique(self.limitation_refs_required, limit=64)
            if len(self.limitation_refs_required) != min(
                int(cast(str, self.limitation_refs_required_count)), 64
            ) or self.limitation_refs_required != tuple(
                sorted(self.limitation_refs_required, key=str.encode)
            ):
                raise ValueError("closure_readiness_limitation_refs_mismatch")
        if self.blocked_obligations is not None:
            _require_unique(
                tuple(item.obligation_id for item in self.blocked_obligations), limit=64
            )
        _validate_fact_lineage_models(self.fact_lineage)
        self._validate_checklist()
        # Absent counts mean the compact singleton could not be read (an unreadable task title
        # omits it). Reporting zero there would assert "nothing is open" from missing data, so
        # unknown must be null and must say so rather than look like a clean record.
        counts = (
            self.declared_obligation_count,
            self.open_obligation_count,
            self.unanswered_finding_count,
            self.receipt_blocking_finding_count,
        )
        unknown = any(value is None for value in counts)
        if unknown != ("readiness_unknown" in self.blocking_conditions):
            raise ValueError("closure_readiness_unknown_mismatch")
        if unknown and any(value is not None for value in counts):
            raise ValueError("closure_readiness_partial_unknown")
        if unknown and self.no_obligations_reason is not None:
            raise ValueError("closure_readiness_unknown_reason")
        if unknown and set(self.blocking_conditions) != {"readiness_unknown"}:
            raise ValueError("closure_readiness_unknown_not_exclusive")
        if unknown and any(
            value is not None
            for value in (
                self.predicted_receipt,
                self.finding_counts,
                self.obligation_counts,
                self.rechecks,
                self.awaiting_ruling_findings,
            )
        ):
            raise ValueError("closure_readiness_unknown_verdict")
        if not unknown:
            declared = int(cast(str, self.declared_obligation_count))
            opened = int(cast(str, self.open_obligation_count))
            unanswered = int(cast(str, self.unanswered_finding_count))
            receipt_blocking = int(cast(str, self.receipt_blocking_finding_count))
            if opened > declared:
                raise ValueError("closure_readiness_obligation_count_mismatch")
            if self.no_obligations_reason is not None and declared != 0:
                raise ValueError("closure_readiness_no_obligations_reason_mismatch")
            if (opened > 0) != ("obligations_open" in self.blocking_conditions):
                raise ValueError("closure_readiness_open_blocker_mismatch")
            if (unanswered > 0) != ("findings_unanswered" in self.blocking_conditions):
                raise ValueError("closure_readiness_unanswered_blocker_mismatch")
            if (receipt_blocking > 0) != (
                "receipt_findings_unresolved" in self.blocking_conditions
            ):
                raise ValueError("closure_readiness_receipt_blocker_mismatch")
            no_plan = "no_plan_published" in self.blocking_conditions
            expected_empty_scope_blocker = (
                not no_plan and declared == 0 and self.no_obligations_reason is None
            )
            if (
                "no_obligations_declared" in self.blocking_conditions
            ) != expected_empty_scope_blocker:
                raise ValueError("closure_readiness_empty_scope_blocker_mismatch")
            if no_plan and (declared != 0 or self.no_obligations_reason is not None):
                raise ValueError("closure_readiness_no_plan_blocker_mismatch")
        return self

    def _validate_checklist(self) -> None:
        checklist = (
            self.state,
            self.gap_classification_version,
            self.agent_actionable,
            self.standing_limitations,
            self.acknowledged_not_done,
            self.acknowledged_not_done_count,
        )
        if all(value is None for value in checklist):
            if self.check_cause is not None:
                raise ValueError("closure_readiness_check_cause_mismatch")
            return
        if any(value is None for value in checklist):
            raise ValueError("closure_readiness_checklist_partial")
        state = cast(str, self.state)
        actionable = cast(tuple[str, ...], self.agent_actionable)
        standing = cast(tuple[str, ...], self.standing_limitations)
        acknowledged_ids = cast(tuple[str, ...], self.acknowledged_not_done)
        _require_unique(actionable, limit=128)
        _require_unique(standing, limit=128)
        if self.check_cause is not None:
            # A superseded check is listed as work; a bounding suffix is a standing disclosure.
            listed = (
                "check_not_applicable" in actionable
                if self.check_cause.effect == "superseded"
                else "check_current_as_of_earlier_frontier" in standing
            )
            if not listed:
                raise ValueError("closure_readiness_check_cause_mismatch")
        _require_unique(acknowledged_ids, limit=64)
        acknowledged = int(cast(str, self.acknowledged_not_done_count))
        if len(acknowledged_ids) != min(acknowledged, 64):
            raise ValueError("closure_readiness_acknowledged_count_mismatch")
        if set(actionable) & set(standing):
            raise ValueError("closure_readiness_group_overlap")
        if "readiness_unknown" in self.blocking_conditions:
            if (
                state != "unknown"
                or actionable != ("readiness_unknown",)
                or standing
                or acknowledged
            ):
                raise ValueError("closure_readiness_unknown_checklist_mismatch")
            return
        if state == "unknown" or "readiness_unknown" in actionable:
            raise ValueError("closure_readiness_unknown_checklist_mismatch")
        expected = (
            "action_required"
            if actionable
            else "ready_with_limitations"
            if standing or acknowledged
            else "ready"
        )
        if state != expected:
            raise ValueError("closure_readiness_state_mismatch")
        # Open obligations are the agent's to clear unless every one is named by a recorded
        # blocker outside its control (#977): then readiness discloses them as a standing
        # limitation instead.
        blocked_rows = self.blocked_obligations
        open_count = None if self.open_obligation_count is None else int(self.open_obligation_count)
        if "obligations_open" in self.blocking_conditions and "obligations_open" not in actionable:
            # Replaced by a confirmed blocker (standing) or a claimed one still to confirm (#985),
            # or the open count includes obligations acknowledged as not done (#997).
            # #997: the untruncated count when present; the id list (64, findings sort first)
            # only as a fallback for an earlier 0.3 build.
            acknowledged_obligations = (
                int(self.acknowledged_obligation_count) > 0
                if self.acknowledged_obligation_count is not None
                else any(item.startswith("obl_") for item in acknowledged_ids)
            )
            if (
                "obligation_blocked_outside_agent_control" not in standing
                and "obligation_blocker_unconfirmed" not in actionable
                and "verification_limit_disclosed" not in standing
                and not acknowledged_obligations
            ) or (
                blocked_rows is not None
                and open_count is not None
                and not acknowledged_obligations
                and len(blocked_rows) != min(open_count, 64)
            ):
                raise ValueError("closure_readiness_actionable_condition_mismatch")
        elif ("obligations_open" in self.blocking_conditions) != ("obligations_open" in actionable):
            raise ValueError("closure_readiness_actionable_condition_mismatch")
        if blocked_rows is not None and open_count is not None and len(blocked_rows) > open_count:
            raise ValueError("closure_readiness_blocked_count_mismatch")
        # These conditions are always the agent's to clear; none can be classified away.
        for condition in (
            "findings_unanswered",
            "no_plan_published",
            "no_obligations_declared",
            "projection_stale",
        ):
            if (condition in self.blocking_conditions) != (condition in actionable):
                raise ValueError("closure_readiness_actionable_condition_mismatch")
        receipt_condition = "receipt_findings_unresolved"
        if receipt_condition in actionable:
            if receipt_condition not in self.blocking_conditions:
                raise ValueError("closure_readiness_actionable_condition_mismatch")
        elif (
            receipt_condition in self.blocking_conditions
            and "finding_rejection_awaiting_ruling" not in actionable
            and not any(item.startswith("fnd_") for item in acknowledged_ids)
        ):
            # Only an acknowledgement moves a receipt-blocking finding off the agent's list, or
            # a rejection that now awaits a reviewer ruling (its own token, ADR-046).
            raise ValueError("closure_readiness_receipt_acknowledgement_mismatch")
        if self.finding_counts is not None:
            counts = self.finding_counts
            if self.receipt_blocking_finding_count is not None and int(counts.to_do) + int(
                counts.unmet
            ) != int(self.receipt_blocking_finding_count):
                raise ValueError("closure_readiness_finding_counts_mismatch")
            if (int(counts.awaiting_ruling) > 0) != (
                "finding_rejection_awaiting_ruling" in actionable
            ):
                raise ValueError("closure_readiness_finding_counts_mismatch")
        if self.rechecks is not None:
            _require_unique(tuple(item.key for item in self.rechecks), limit=128)
        if self.awaiting_ruling_findings is not None:
            named = tuple(item.finding_id for item in self.awaiting_ruling_findings)
            _require_unique(named, limit=8)
            if named != tuple(sorted(named, key=str.encode)):
                raise ValueError("closure_readiness_awaiting_ruling_findings_mismatch")
            if self.finding_counts is None or len(named) != min(
                int(self.finding_counts.awaiting_ruling), 8
            ):
                raise ValueError("closure_readiness_awaiting_ruling_findings_mismatch")


class StatusRequestedItemModel(_ClosedModel):
    # ``directory`` and ``role`` come from obligation_published 1.1.0 (#1002) and appear only on
    # status-result 1.4.0; ``role`` is absent, never null, when the obligation declared none.
    optional_non_null_fields = frozenset({"role"})

    item_kind: Literal["url", "file", "command", "change", "source", "directory"]
    value: String0To1024 | OmittedContentModel
    role: Literal["input", "output"] | None = None

    @model_validator(mode="after")
    def _validate_requested_item(self) -> StatusRequestedItemModel:
        if (
            isinstance(self.value, OmittedContentModel)
            and self.value.category is not DataCategory.OBLIGATION_TEXT
        ):
            raise ValueError("requested_item_omission_category_invalid")
        return self


class StatusCommandAttemptModel(_ClosedModel):
    requested_item_index: Annotated[str, Field(pattern=r"^(?:[0-9]|[1-5][0-9]|6[0-3])$")]
    relation: Literal["matching_observed_attempt", "asserted_observed_mismatch", "unknown"]
    asserted_action_ids: tuple[ActionIdWire, ...]
    observed_event_ids: tuple[EventIdWire, ...]

    @model_validator(mode="after")
    def _validate_refs(self) -> StatusCommandAttemptModel:
        _require_unique(self.asserted_action_ids, limit=64)
        _require_unique(self.observed_event_ids, limit=64)
        return self


class StatusObligationItemModel(_ClosedModel):
    optional_non_null_fields = frozenset(
        {
            "acceptance_criteria",
            "acknowledged_not_done_reason",
            "in_current_plan",
            "closure_class",
            "closure_basis",
        }
    )

    obligation_id: ObligationIdWire
    # ``acknowledged_not_done`` (obligation_published 1.1.0, #1002) on status-result 1.4.0 only.
    status: Literal["open", "resolved", "acknowledged_not_done"]
    description: String1To8192 | OmittedContentModel
    evidence_expectation: String1To8192 | OmittedContentModel
    source_refs: tuple[SubjectIdWire, ...]
    assigned_actor_ids: tuple[ActorAssertionIdWire, ...]
    evidence_refs: tuple[EvidenceOrResultIdWire, ...]
    revision_event_id: EventIdWire | None
    requested_items: tuple[StatusRequestedItemModel, ...] = ()
    unattempted_items: tuple[StatusRequestedItemModel, ...] = ()
    command_attempts: tuple[StatusCommandAttemptModel, ...] = ()
    acceptance_criteria: String1To8192 | OmittedContentModel | None = None
    # The agent's own reason for ``acknowledged_not_done`` (#1002/#996), status-result 1.4.0 only,
    # under the same obligation-text category as the description it explains.
    acknowledged_not_done_reason: String1To8192 | OmittedContentModel | None = None
    # Whether the obligation is part of the current plan's effective scope: published, not waived
    # and not superseded by a later plan revision (``task_facts.effective_obligations``). The view
    # lists every obligation ever published; this is how a reader tells the declared ones from the
    # historical ones (#1027, the post-compaction recap's deliverables). Status-result 1.4.0
    # only; absent when the plan scope cannot be read, and never a claim that it is open.
    in_current_plan: bool | None = None
    # tb4n3 RC-3 (ADR-046): the obligation's closure class and why. Absent when the plan scope
    # cannot be read (the obligation is not effective) and on an earlier 0.3 build.
    closure_class: ObligationClosureClassLiteral | None = None
    closure_basis: ObligationClosureBasisLiteral | None = None

    @model_validator(mode="after")
    def _validate_obligation_item(self) -> StatusObligationItemModel:
        if (self.closure_class is None) != (self.closure_basis is None):
            raise ValueError("obligation_closure_partial")
        for values in (self.source_refs, self.assigned_actor_ids, self.evidence_refs):
            _require_unique(values, limit=64)
        if len(self.requested_items) > 64 or len(self.unattempted_items) > 64:
            raise ValueError("obligation_requested_item_limit")
        if len(self.command_attempts) > 64:
            raise ValueError("obligation_command_attempt_limit")
        requested = tuple((item.item_kind, item.value) for item in self.requested_items)
        unattempted = tuple((item.item_kind, item.value) for item in self.unattempted_items)
        if any(item not in requested for item in unattempted):
            raise ValueError("obligation_unattempted_item_mismatch")
        if (self.acknowledged_not_done_reason is None) == (self.status == "acknowledged_not_done"):
            raise ValueError("obligation_acknowledgement_reason_mismatch")
        for value in (
            self.description,
            self.evidence_expectation,
            self.acceptance_criteria,
            self.acknowledged_not_done_reason,
        ):
            if (
                isinstance(value, OmittedContentModel)
                and value.category is not DataCategory.OBLIGATION_TEXT
            ):
                raise ValueError("obligation_omission_category_invalid")
        return self


ObservedToolNameWire = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$")
]


class StatusObservedRunModel(_ClosedModel):
    """Structural facts that let an agent recognize one hook-observed run (issue #909).

    ``occurrence`` is the 1-based position among the task's hook-observed results in ledger
    order; ``command_commitment`` is the installation-keyed identity a later passing run of the
    same command shares. No command text or finer time is exposed. The runner class belongs to
    #910 and is not part of this contract yet.
    """

    optional_non_null_fields = frozenset({"tool_name", "command_commitment", "exit_status"})

    occurrence: CanonicalPositiveUInt64Wire
    tool_name: ObservedToolNameWire | None = None
    command_commitment: HmacSha256Commitment | None = None
    exit_status: Annotated[int, Field(strict=True, ge=-(2**31), le=2**31 - 1)] | None = None


class StatusResultItemModel(_ClosedModel):
    optional_non_null_fields = frozenset({"observed_run"})

    result_id: ResultIdWire
    source_event_id: EventIdWire
    payload_available: bool
    outcome: Literal["success", "failure", "partial", "unknown"] | None
    action_id: ActionIdWire | None
    evidence_refs: tuple[EvidenceIdWire, ...]
    # Present only for a readable, service-stamped hook-observed result.
    observed_run: StatusObservedRunModel | None = None

    @model_validator(mode="after")
    def _validate_result_item(self) -> StatusResultItemModel:
        _require_unique(self.evidence_refs, limit=64)
        structural_payload_available = self.outcome is not None and self.action_id is not None
        if self.payload_available != structural_payload_available:
            raise ValueError("result_payload_availability_mismatch")
        if not self.payload_available and self.evidence_refs:
            raise ValueError("result_unavailable_evidence_refs")
        if not self.payload_available and self.observed_run is not None:
            raise ValueError("result_unavailable_observed_run")
        return self


class StatusResultsPageModel(_ClosedModel):
    items: tuple[StatusResultItemModel, ...]
    next_cursor: CursorWire | None

    @model_validator(mode="after")
    def _validate_results_page(self) -> StatusResultsPageModel:
        if len(self.items) > 100:
            raise ValueError("status_page_limit")
        return self


class StatusObligationsPageModel(_ClosedModel):
    items: tuple[StatusObligationItemModel, ...]
    next_cursor: CursorWire | None

    @model_validator(mode="after")
    def _validate_obligations_page(self) -> StatusObligationsPageModel:
        if len(self.items) > 100:
            raise ValueError("status_page_limit")
        return self


class StatusAdviceItemModel(_ClosedModel):
    optional_non_null_fields = frozenset(
        {
            "coordination_counterpart_task_id",
            "coordination_detection_id",
            "coordination_membership_generation",
            "coordination_project_id",
            "coordination_resource_paths",
        }
    )

    finding_id: FindingIdWire
    rule_code: CodeWire
    priority: Annotated[int, Field(ge=1, le=100)]
    evidence_commitments: tuple[AsciiString1To160, ...]
    coverage: CoverageModel
    freshness_frontier: AsciiString1To160
    verification_state: Literal["current", "stale", "unavailable", "not_required"]
    semantic_state: Literal["ready", "disabled", "unavailable", "failed"]
    recommended_next_action: CodeWire
    coordination_project_id: ProjectIdWire | None = None
    coordination_detection_id: EventIdWire | None = None
    coordination_membership_generation: CanonicalPositiveUInt64Wire | None = None
    coordination_counterpart_task_id: TaskIdWire | None = None
    coordination_resource_paths: tuple[String1To4096, ...] | OmittedContentModel | None = None

    @model_validator(mode="after")
    def _validate_advice_item(self) -> StatusAdviceItemModel:
        _require_unique(self.evidence_commitments, limit=16)
        selector_values = (
            self.coordination_project_id,
            self.coordination_detection_id,
            self.coordination_membership_generation,
            self.coordination_counterpart_task_id,
            self.coordination_resource_paths,
        )
        if any(value is not None for value in selector_values):
            if not all(value is not None for value in selector_values):
                raise ValueError("coordination_advice_selector_incomplete")
        if isinstance(self.coordination_resource_paths, OmittedContentModel):
            if self.coordination_resource_paths.category is not DataCategory.REPOSITORY_EXCERPT:
                raise ValueError("coordination_advice_omission_category_invalid")
        elif self.coordination_resource_paths is not None:
            if len(self.coordination_resource_paths) > 256:
                raise ValueError("coordination_advice_resource_path_limit")
            _require_unique(self.coordination_resource_paths, limit=256)
            if self.coordination_resource_paths != tuple(
                sorted(self.coordination_resource_paths, key=str.encode)
            ):
                raise ValueError("coordination_advice_resource_paths_not_canonical")
        return self


class StatusAdvicePageModel(_ClosedModel):
    # Frozen legacy identifier (ADR-048): the protocol 0.1 tag namespace.
    projection_format: Literal["yoetz.advice-snapshot/1"]
    items: tuple[StatusAdviceItemModel, ...]
    next_cursor: None

    @model_validator(mode="after")
    def _validate_advice_page(self) -> StatusAdvicePageModel:
        if len(self.items) > 64:
            raise ValueError("status_page_limit")
        return self


class StatusLineageChildModel(_ClosedModel):
    """One direct child in the bounded lineage projection."""

    optional_non_null_fields = frozenset({"self_verified_finding_count"})

    task_id: TaskIdWire
    parent_task_id: TaskIdWire
    origin: LineageOriginWire
    acceptance: LineageAcceptanceWire
    work_state: WorkStateWire
    session_health: SessionHealthWire
    depth: CanonicalPositiveUInt64Wire
    rollup_state: LineageRollupStateWire
    blocking_conditions: tuple[CodeWire, ...]
    # Issue #984 (S2): how many of an accepted child's findings its agent self-verified; present
    # only when positive. The parent receipt is then at best insufficient_coverage.
    self_verified_finding_count: CanonicalPositiveUInt64Wire | None = None

    @model_validator(mode="after")
    def _validate_lineage_child(self) -> StatusLineageChildModel:
        _require_unique(self.blocking_conditions, limit=64)
        return self


class StatusLineageAnnotationModel(_ClosedModel):
    """A host-observed child signal before a real child task is bound.

    An annotation intentionally carries no task or bundle identity.  Binding it to a task is a
    service-side operation and must never be inferred by a status renderer.
    """

    correlation_id: HostCorrelationWire
    subagent_id: HostCorrelationWire | None = None
    parent_tool_call_id: HostCorrelationWire | None = None
    origin: Literal["host_observed"]
    acceptance: Literal["pending"]

    @model_validator(mode="after")
    def _validate_annotation_identity(self) -> StatusLineageAnnotationModel:
        if self.subagent_id is None and self.parent_tool_call_id is None:
            raise ValueError("lineage_annotation_identity_missing")
        return self


class StatusLineagePageModel(_ClosedModel):
    """Direct-child lineage view, with provisional host annotations kept separate."""

    parent_task_id: TaskIdWire | None = None
    children: tuple[StatusLineageChildModel, ...]
    annotations: tuple[StatusLineageAnnotationModel, ...]
    next_cursor: CursorWire | None

    @model_validator(mode="after")
    def _validate_lineage_page(self) -> StatusLineagePageModel:
        _require_unique(tuple(item.task_id for item in self.children), limit=100)
        _require_unique(tuple(item.correlation_id for item in self.annotations), limit=100)
        if len(self.children) > 100 or len(self.annotations) > 100:
            raise ValueError("status_page_limit")
        return self


class StatusProjectMemberModel(_ClosedModel):
    task_id: TaskIdWire
    actor_id: ActorAssertionIdWire | None
    work_state: WorkStateWire
    session_health: SessionHealthWire
    parent_task_id: TaskIdWire | None = None


class ProjectTextRefModel(_ClosedModel):
    """Reference to encrypted project text; plaintext is never a structural field."""

    optional_non_null_fields = frozenset({"envelope_digest"})

    object_id: ObjectIdWire
    content_digest: Sha256Digest
    plaintext_size: Annotated[int, Field(ge=0, le=MAX_OBJECT_PLAINTEXT_BYTES)]
    owner_task_id: TaskIdWire
    route_generation: CanonicalPositiveUInt64Wire
    envelope_digest: Sha256Digest | None = None


class StatusProjectDetectionModel(_ClosedModel):
    optional_non_null_fields = frozenset({"resource_paths"})

    detection_id: EventIdWire
    task_ids: tuple[TaskIdWire, ...]
    resource_count: CanonicalUInt64Wire
    open: bool
    resource_paths: tuple[String1To4096, ...] | OmittedContentModel | None = None

    @model_validator(mode="after")
    def _validate_project_detection(self) -> StatusProjectDetectionModel:
        if len(self.task_ids) < 2:
            raise ValueError("project_detection_task_count_invalid")
        _require_unique(self.task_ids, limit=64)
        if self.task_ids != tuple(sorted(self.task_ids, key=str.encode)):
            raise ValueError("project_detection_tasks_not_canonical")
        if isinstance(self.resource_paths, OmittedContentModel):
            if self.resource_paths.category is not DataCategory.REPOSITORY_EXCERPT:
                raise ValueError("project_resource_omission_category_invalid")
        elif self.resource_paths is not None:
            if len(self.resource_paths) > 256:
                raise ValueError("project_resource_path_limit")
            _require_unique(self.resource_paths, limit=256)
            if self.resource_paths != tuple(sorted(self.resource_paths, key=str.encode)):
                raise ValueError("project_resource_paths_not_canonical")
        return self


class StatusProjectCoverageModel(_ClosedModel):
    coverage_id: EventIdWire
    project_id: ProjectIdWire
    task_id: TaskIdWire
    membership_generation: CanonicalPositiveUInt64Wire
    coverage: Literal["unobservable"]
    gap_code: Literal["not_observable"]


class StatusProjectReceiptModel(_ClosedModel):
    task_id: TaskIdWire
    receipt_id: ReceiptIdWire
    frontier: FrontierModel
    conclusion: Literal[
        "insufficient_coverage",
        "no_unresolved_deterministic_findings",
        "unresolved_findings_remain",
    ]


class StatusProjectPageModel(_ClosedModel):
    optional_non_null_fields = frozenset({"title", "description", "title_ref", "description_ref"})

    project_id: ProjectIdWire
    kind: ProjectKindWire
    membership_generation: CanonicalPositiveUInt64Wire
    grant_state: GrantStateWire | None
    title: String1To8192 | OmittedContentModel | None = None
    description: String1To8192 | OmittedContentModel | None = None
    title_ref: ProjectTextRefModel | None = None
    description_ref: ProjectTextRefModel | None = None
    members: tuple[StatusProjectMemberModel, ...]
    lineage: StatusLineagePageModel
    detections: tuple[StatusProjectDetectionModel, ...]
    receipts: tuple[StatusProjectReceiptModel, ...]
    coverage: tuple[StatusProjectCoverageModel, ...] = ()
    next_cursor: CursorWire | None

    @model_validator(mode="after")
    def _validate_project_page(self) -> StatusProjectPageModel:
        for value in (self.title, self.description):
            if (
                isinstance(value, OmittedContentModel)
                and value.category is not DataCategory.TASK_DESCRIPTION
            ):
                raise ValueError("project_text_omission_category_invalid")
        _require_unique(tuple(item.task_id for item in self.members), limit=100)
        _require_unique(tuple(item.detection_id for item in self.detections), limit=100)
        _require_unique(tuple(item.receipt_id for item in self.receipts), limit=100)
        _require_unique(tuple(item.coverage_id for item in self.coverage), limit=100)
        if (
            len(self.members) > 100
            or len(self.detections) > 100
            or len(self.receipts) > 100
            or len(self.coverage) > 100
        ):
            raise ValueError("status_page_limit")
        return self


class StatusVersionSliceModel(_ClosedModel):
    optional_non_null_fields = frozenset({"route_profile"})

    protocol_version: Literal["0.1"]
    engine_version: VersionWire
    projection_version: VersionWire
    # Frozen legacy identifier (ADR-048): the stored object format.
    object_format: Literal["yoetz-object/1"]
    storage_schema: CanonicalUInt64Wire
    python_version: VersionWire
    apsw_version: VersionWire
    sqlite_version: VersionWire
    sqlite_source_id: AsciiString1To160
    policy_packs: tuple[RecordedVersionSlicePackWire, ...]
    provider_profiles: tuple[ProfileIdWire, ...]
    route_profile: Literal["policy", "strict"] | None = None

    @model_validator(mode="after")
    def _validate_status_version_sets(self) -> StatusVersionSliceModel:
        _require_unique(self.policy_packs, limit=2)
        _require_unique(self.provider_profiles, limit=16)
        return self


class StatusVersionsPageModel(_ClosedModel):
    items: tuple[StatusVersionSliceModel, ...]
    next_cursor: None

    @model_validator(mode="after")
    def _validate_versions_page(self) -> StatusVersionsPageModel:
        if len(self.items) > 1:
            raise ValueError("status_page_limit")
        return self


class StatusOperationAcceptedEventModel(_ClosedModel):
    event_id: EventIdWire
    entry_digest: Sha256Digest
    ingestion_sequence: CanonicalUInt64Wire
    writer_sequence: CanonicalUInt64Wire
    projection_status: Literal["projected", "unknown_unprojected"]


class StatusSemanticProgressModel(_ClosedModel):
    """Bounded structural progress of the AI-powered review job behind one check operation.

    Every field is service-authored structure: a closed phase, an attempt ordinal, service
    timestamps, derived durations, and the closed terminal outcome and reason of the durable job.
    It never carries tokens, reasoning, prompt or response text, credentials, or account identity.
    ``elapsed_ms`` and ``remaining_ms`` are computed by the service at ``observed_at``.
    """

    optional_non_null_fields = frozenset({"remaining_ms", "terminal_outcome", "terminal_reason"})

    phase: SemanticProgressPhaseWire
    attempt_ordinal: CanonicalUInt64Wire
    queued_at: TimestampWire
    phase_entered_at: TimestampWire
    deadline_at: TimestampWire
    observed_at: TimestampWire
    elapsed_ms: CanonicalUInt64Wire
    remaining_ms: CanonicalUInt64Wire | None = None
    condition: Literal["active", "overdue", "terminal"]
    terminal_outcome: Literal["succeeded", "failed", "quarantined"] | None = None
    terminal_reason: SemanticReasonWire | None = None

    @model_validator(mode="after")
    def _validate_semantic_progress(self) -> StatusSemanticProgressModel:
        terminal = self.phase is SemanticProgressPhase.TERMINAL
        if terminal != (self.condition == "terminal"):
            raise ValueError("status_semantic_progress_invalid")
        if terminal:
            if (
                self.terminal_outcome is None
                or self.terminal_reason is None
                or self.remaining_ms is not None
            ):
                raise ValueError("status_semantic_progress_invalid")
        else:
            if (
                self.terminal_outcome is not None
                or self.terminal_reason is not None
                or self.remaining_ms is None
                or (self.condition == "active") != (int(self.remaining_ms) > 0)
            ):
                raise ValueError("status_semantic_progress_invalid")
            if int(self.attempt_ordinal) == 0 and self.phase is not SemanticProgressPhase.QUEUED:
                raise ValueError("status_semantic_progress_invalid")
        return self


class StatusCheckAdmissionModel(_ClosedModel):
    """Why a check request id has no operation record yet (issue #838).

    Present only on an ``absent`` page, and only while this service holds a live acquisition
    reservation or a recent pre-admission refusal for the exact (writer, request) key. Every
    field is a closed token, a count, or a service timestamp; ``elapsed_ms`` runs from
    ``first_observed_at`` to ``observed_at``. Nothing was recorded under the request id, so the
    exact replay after ``retry_after_ms`` is the recovery.
    """

    stage: Literal[
        "acquiring", "capture_handoff_pending", "acquisition_contended", "import_pending"
    ]
    refusal_count: CanonicalUInt64Wire
    first_observed_at: TimestampWire
    last_observed_at: TimestampWire
    observed_at: TimestampWire
    elapsed_ms: CanonicalUInt64Wire
    retry_after_ms: CanonicalUInt64Wire

    @model_validator(mode="after")
    def _validate_check_admission(self) -> StatusCheckAdmissionModel:
        if int(self.refusal_count) == 0 and self.stage != "acquiring":
            raise ValueError("status_check_admission_invalid")
        return self


class StatusOperationPageModel(_ClosedModel):
    """One request-id-keyed operation recovery page within the authenticated task."""

    optional_non_null_fields = frozenset(
        {"semantic_progress", "admission", "semantic_withheld_items", "semantic_redacted_values"}
    )

    operation_request_id: RequestIdWire
    found: bool
    state: Literal["absent", "pending", "complete", "quarantined"]
    operation_kind: Literal["start", "publish_work", "check", "respond", "receipt"] | None = None
    outcome: Literal["accepted", "replayed"] | None = None
    subject_frontier: FrontierModel | None = None
    result_frontier: FrontierModel | None = None
    accepted_events: tuple[StatusOperationAcceptedEventModel, ...] = ()
    # Recovery after lost output or compaction: a pending check suspended on a local disclosure
    # decision returns the same continuation its check result carried. Every other operation
    # state returns null, so its presence is never ambiguous.
    continuation: CheckContinuationModel | None = None
    # Issue #571 A2: structural progress of the AI-powered review job behind a check. Omitted when
    # the operation is not a check or no durable progress was recorded for it.
    semantic_progress: StatusSemanticProgressModel | None = None
    # A completed check may disclose the bounded opaque identities omitted by the never-send
    # heuristic. Old operation rows omit this field entirely.
    semantic_withheld_items: tuple[SemanticWithheldItemModel, ...] | None = None
    # PL2-1: a completed check's item refs and line numbers of values the external reviewer did
    # not see. Omitted when the check recorded none.
    semantic_redacted_values: tuple[SemanticRedactedValueModel, ...] | None = None
    # Issue #838: pre-admission stage of a check request that has no operation record yet.
    # Omitted whenever the service knows of no reservation or refusal for the exact key.
    admission: StatusCheckAdmissionModel | None = None
    next_cursor: None = None

    @model_validator(mode="after")
    def _validate_operation_page(self) -> StatusOperationPageModel:
        if self.admission is not None and (self.state != "absent" or self.found):
            raise ValueError("status_operation_page_invalid")
        if self.semantic_progress is not None and not (
            self.operation_kind == "check" and self.state in {"pending", "complete"}
        ):
            raise ValueError("status_operation_page_invalid")
        if self.semantic_withheld_items is not None:
            if not (self.operation_kind == "check" and self.state == "complete"):
                raise ValueError("status_operation_page_invalid")
            _require_unique(
                tuple(item.item_id for item in self.semantic_withheld_items),
                limit=64,
            )
        if self.semantic_redacted_values is not None:
            if not (self.operation_kind == "check" and self.state == "complete"):
                raise ValueError("status_operation_page_invalid")
            _validate_semantic_redacted_value_models(self.semantic_redacted_values)
        if (
            self.continuation is not None
            and self.continuation.replay_request_id != self.operation_request_id
        ):
            raise ValueError("status_operation_continuation_request_mismatch")
        if self.continuation is not None and not (
            self.state == "pending" and self.operation_kind == "check"
        ):
            raise ValueError("status_operation_page_invalid")
        if self.state == "absent":
            if (
                self.found
                or self.operation_kind is not None
                or self.outcome is not None
                or self.subject_frontier is not None
                or self.result_frontier is not None
                or self.accepted_events
            ):
                raise ValueError("status_operation_page_invalid")
            return self
        if not self.found or self.operation_kind is None:
            raise ValueError("status_operation_page_invalid")
        if self.state == "complete" and self.operation_kind == "publish_work":
            if (
                self.outcome is None
                or self.subject_frontier is None
                or self.result_frontier is None
                or not self.accepted_events
            ):
                raise ValueError("status_operation_page_invalid")
            if len(self.accepted_events) > MAX_EVENTS_PER_BATCH:
                raise ValueError("status_page_limit")
            return self
        if self.state == "complete":
            # Non-publish completions are reported without append-shaped event detail.
            if (
                self.outcome is not None
                or self.subject_frontier is not None
                or self.result_frontier is not None
                or self.accepted_events
            ):
                raise ValueError("status_operation_page_invalid")
            return self
        if (
            self.outcome is not None
            or self.subject_frontier is not None
            or self.result_frontier is not None
            or self.accepted_events
        ):
            raise ValueError("status_operation_page_invalid")
        return self


type StatusPage = (
    StatusAdvicePageModel
    | StatusAssignmentPageModel
    | StatusCandidateFindingsPageModel
    | StatusCompactPageModel
    | StatusEvidencePageModel
    | StatusFindingsPageModel
    | StatusHistoryPageModel
    | StatusObligationsPageModel
    | StatusOperationPageModel
    | StatusResultsPageModel
    | StatusLineagePageModel
    | StatusProjectPageModel
    | StatusVersionsPageModel
)

_STATUS_PAGE_BY_VIEW: Final[Mapping[str, type[_ClosedModel]]] = MappingProxyType(
    {
        "advice": StatusAdvicePageModel,
        "assignment": StatusAssignmentPageModel,
        "candidate_findings": StatusCandidateFindingsPageModel,
        "compact": StatusCompactPageModel,
        "evidence": StatusEvidencePageModel,
        "findings": StatusFindingsPageModel,
        "history": StatusHistoryPageModel,
        "obligations": StatusObligationsPageModel,
        "operation": StatusOperationPageModel,
        "lineage": StatusLineagePageModel,
        "project": StatusProjectPageModel,
        "results": StatusResultsPageModel,
        "versions": StatusVersionsPageModel,
    }
)


class StatusSuccessModel(_ClosedModel):
    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: RequestIdWire
    ok: Literal[True]
    task_id: TaskIdWire
    session_id: SessionIdWire
    writer_id: WriterIdWire
    view: Literal[
        "advice",
        "assignment",
        "candidate_findings",
        "compact",
        "evidence",
        "findings",
        "history",
        "obligations",
        "operation",
        "lineage",
        "project",
        "results",
        "versions",
    ]
    requested_frontier: FrontierModel
    head_frontier: FrontierModel
    subject_frontier: FrontierModel
    result_frontier: FrontierModel
    projection_lag: CanonicalUInt64Wire
    projection_version: VersionWire
    rebuild_state: Literal["current", "rebuild_required", "rebuilding"]
    page: StatusPage
    coverage: CoverageModel
    gaps: tuple[CodeWire, ...]
    import_status: StatusImportStatusModel
    closure_readiness: StatusClosureReadinessModel
    privacy_projection: PrivacyProjectionModel
    # Owner opt-out state, visible before any check runs (issue #982). Absent when the service
    # did not compose it (for example a direct in-process application without privacy support).
    credential_heuristic: StatusCredentialHeuristicModel | None = None
    # ADR-049: the conversation's review mode and the owner's setting, when composed.
    review_mode: StatusReviewModeModel | None = None

    @model_validator(mode="before")
    @classmethod
    def _route_status_page(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        source = cast(Mapping[object, object], value)
        raw_page = source.get("page")
        raw_view = source.get("view")
        if raw_page is None or type(raw_view) is not str:
            return cast(object, value)
        page_type = _STATUS_PAGE_BY_VIEW.get(raw_view)
        if page_type is None:
            return cast(object, value)
        routed = dict(source)
        routed["page"] = page_type.model_validate(raw_page)
        return routed

    @model_validator(mode="after")
    def _validate_status_success(self) -> StatusSuccessModel:
        expected_type = _STATUS_PAGE_BY_VIEW[self.view]
        if type(self.page) is not expected_type:
            raise ValueError("status_view_page_mismatch")
        _require_unique(self.gaps, limit=64)
        _validate_model_against_schema(self, "status-result")
        return self


type StatusResultBranch = Annotated[
    StatusSuccessModel | OperationFailureModel, Field(discriminator="ok")
]


class StatusResultModel(PublicResultModel[StatusResultBranch]):
    pass


class ReceiptPolicyVersionEntryModel(_ClosedModel):
    policy_id: ReceiptPolicyIdWire
    policy_version: ReceiptVersionIdentityWire


class ReceiptSchemaVersionEntryModel(_ClosedModel):
    schema_id: ReceiptSchemaIdWire
    schema_version: ReceiptVersionIdentityWire


class ReceiptVersionSliceModel(_ClosedModel):
    # A receipt issued before the rename names the ``yoetz`` distribution; new receipts name
    # ``finishup`` (ADR-048).
    package_name: Literal["finishup", "yoetz"]
    package_version: ReceiptVersionIdentityWire
    protocol_version: ReceiptVersionIdentityWire
    engine_version: ReceiptVersionIdentityWire
    projection_version: ReceiptVersionIdentityWire
    object_format_version: ReceiptVersionIdentityWire
    catalog_schema_version: ReceiptSchemaCounterVersionWire
    bundle_schema_version: ReceiptSchemaCounterVersionWire
    policy_versions: Annotated[
        tuple[ReceiptPolicyVersionEntryModel, ...], Field(min_length=1, max_length=16)
    ]
    schema_versions: Annotated[
        tuple[ReceiptSchemaVersionEntryModel, ...], Field(min_length=1, max_length=64)
    ]
    resource_manifest_digest: Sha256Digest

    @model_validator(mode="after")
    def _validate_receipt_version_entries(self) -> ReceiptVersionSliceModel:
        policy_keys = tuple(
            f"{entry.policy_id}\x00{entry.policy_version}".encode("ascii")
            for entry in self.policy_versions
        )
        schema_keys = tuple(
            f"{entry.schema_id}\x00{entry.schema_version}".encode("ascii")
            for entry in self.schema_versions
        )
        if policy_keys != tuple(sorted(set(policy_keys))):
            raise ValueError("receipt_policy_versions_not_canonical")
        if schema_keys != tuple(sorted(set(schema_keys))):
            raise ValueError("receipt_schema_versions_not_canonical")
        return self


class ReceiptChildOutcomeModel(_ClosedModel):
    """One direct child contribution in a receipt document."""

    child_task_id: TaskIdWire
    outcome: Literal["clean", "annotated", "open_gap", "incomplete", "unavailable"]
    tested_manifest_ref: EventIdWire | None
    later_manifest_ref: EventIdWire | None = None
    freshness: Literal["known", "unknown"]
    findings: tuple[ChildFindingSnapshotModel, ...]

    @model_validator(mode="after")
    def _validate_receipt_child(self) -> ReceiptChildOutcomeModel:
        _require_unique(tuple(item.finding_id for item in self.findings), limit=64)
        if self.outcome == "unavailable" and self.tested_manifest_ref is not None:
            raise ValueError("receipt_child_manifest_mismatch")
        return self


class ReceiptChildrenModel(_ClosedModel):
    children: tuple[ReceiptChildOutcomeModel, ...]

    @model_validator(mode="after")
    def _validate_receipt_children(self) -> ReceiptChildrenModel:
        ids = tuple(item.child_task_id for item in self.children)
        _require_unique(ids, limit=64)
        if ids != tuple(sorted(ids, key=str.encode)):
            raise ValueError("receipt_children_not_canonical")
        return self


class ReceiptSuccessModel(_ClosedModel):
    protocol_version: Literal["0.1"]
    schema_version: Literal["1.0.0"]
    request_id: RequestIdWire
    ok: Literal[True]
    receipt_id: ReceiptIdWire
    task_id: TaskIdWire
    session_id: SessionIdWire
    subject_frontier: FrontierModel
    result_frontier: FrontierModel
    receipt_object_id: ObjectIdWire
    receipt_digest: Sha256Digest
    conclusion: Literal[
        "insufficient_coverage",
        "no_unresolved_deterministic_findings",
        "unresolved_findings_remain",
    ]
    redaction_profile: ReceiptRedactionProfileWire
    format: ReceiptFormatWire
    include: ReceiptIncludeWire
    document: JsonValue | None
    human_text: String1To32768 | OmittedContentModel | None
    coverage: CoverageModel
    suppressed_finding_count: Annotated[int, Field(ge=0, le=2**53 - 1)]
    versions: ReceiptVersionSliceModel
    privacy_projection: PrivacyProjectionModel

    @model_validator(mode="after")
    def _validate_receipt_success(self) -> ReceiptSuccessModel:
        if (
            isinstance(self.human_text, OmittedContentModel)
            and self.human_text.category is not DataCategory.FINDING_SUMMARY
        ):
            raise ValueError("finding_omission_category_invalid")
        if self.format is ReceiptFormat.JSON:
            if self.document is None or self.human_text is not None:
                raise ValueError("receipt_format_body_mismatch")
        elif self.document is not None or self.human_text is None:
            raise ValueError("receipt_format_body_mismatch")
        _validate_model_against_schema(self, "receipt-result")
        return self


type ReceiptResultBranch = Annotated[
    ReceiptSuccessModel | OperationFailureModel, Field(discriminator="ok")
]


class ReceiptResultModel(PublicResultModel[ReceiptResultBranch]):
    pass


StartRequest = StartRequestModel
StartResult = StartResultModel
PublishWorkRequest = PublishWorkRequestModel
PublishWorkResult = PublishWorkResultModel
CheckRequest = CheckRequestModel
CheckResult = CheckResultModel
RespondRequest = RespondRequestModel
RespondResult = RespondResultModel
StatusRequest = StatusRequestModel
StatusResult = StatusResultModel
ReceiptRequest = ReceiptRequestModel
ReceiptResult = ReceiptResultModel
ReadGuidanceRequest = ReadGuidanceRequestModel
ReadGuidanceResult = ReadGuidanceResultModel
ClosurePrepareRequest = ClosurePrepareRequestModel
ClosurePrepareResult = ClosurePrepareResultModel

_PUBLIC_MODEL_SCHEMA: Final[Mapping[type[object], str]] = MappingProxyType(
    {
        StartRequestModel: "start-request",
        StartResultModel: "start-result",
        PublishWorkRequestModel: "publish-work-request",
        PublishWorkResultModel: "publish-work-result",
        CheckRequestModel: "check-request",
        CheckResultModel: "check-result",
        RespondRequestModel: "respond-request",
        RespondResultModel: "respond-result",
        StatusRequestModel: "status-request",
        StatusResultModel: "status-result",
        ReceiptRequestModel: "receipt-request",
        ReceiptResultModel: "receipt-result",
        ReadGuidanceRequestModel: "read-guidance-request",
        ReadGuidanceResultModel: "read-guidance-result",
        ClosurePrepareRequestModel: "closure-prepare-request",
        ClosurePrepareResultModel: "closure-prepare-result",
    }
)


def public_model_to_wire(model: object) -> dict[str, JsonValue]:
    """Dump one exact public model type and validate it against the local schema catalog."""

    schema_name = _PUBLIC_MODEL_SCHEMA.get(type(model))
    if schema_name is None:
        raise TypeError("public_model_wrong_type")
    public_model = cast(BaseModel, model)
    raw_dump = public_model.model_dump(
        mode="json",
        by_alias=True,
        exclude_unset=True,
        exclude_none=False,
    )
    dumped = _strip_optional_non_null_fields(public_model, raw_dump)
    if type(dumped) is not dict:
        raise TypeError("public_model_wrong_type")
    from finishup.protocol.schemas import (
        load_schema_catalog,
        request_result_schema_versions,
        validate_schema_instance,
    )

    schema_version = request_result_schema_versions(load_schema_catalog())[schema_name]
    validate_schema_instance(schema_name, schema_version, cast(JsonValue, dumped))
    return dict(dumped)


type _LeafClassification = Literal["public_structural"] | DataCategory
type _EventSelector = tuple[str, str] | Literal["<opaque>"]


@dataclass(frozen=True, slots=True)
class _ResultLeafRule:
    method: str
    status_view: str | None
    event_selector: _EventSelector | None
    segments: tuple[str, ...]
    classification: _LeafClassification


_RESULT_METHODS: Final[frozenset[str]] = frozenset(
    {"check", "publish_work", "receipt", "respond", "start", "status"}
)
_STATUS_VIEWS: Final[frozenset[str]] = frozenset(_STATUS_PAGE_BY_VIEW)
_KNOWN_PUBLISH_EVENT_SELECTORS: Final[frozenset[tuple[str, str]]] = frozenset(
    set(_PUBLISH_SUMMARY_CATEGORY) | set(_PUBLISH_FIXED_SUMMARY)
)


def _prefix_leaf_patterns(prefix: str, suffixes: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(f"{prefix}/{suffix}" for suffix in suffixes)


_COMMON_SUCCESS_LEAVES: Final = (
    "/ok",
    "/protocol_version",
    "/request_id",
    "/schema_version",
    "/session_id",
    "/task_id",
)
FRONTIER_LEAVES: Final = ("head_digest", "sequence")
_COVERAGE_LEAVES: Final = (
    "artifact_observation",
    "authorship_assurance",
    "check_types/*",
    "evidence_immutability",
    "known_gaps/*",
    "ledger_freshness",
    "publication_channels/*",
)
_PRIVACY_PROJECTION_LEAVES: Final = (
    "blocked_categories/*",
    "included_categories/*",
    "local_disclosure_receipt_id",
    "omitted_pointers/*",
    "policy_digest",
    "policy_id",
    "policy_version",
    "projection_commitment",
    "sink",
)
_OMITTED_CONTENT_LEAVES: Final = ("category", "omitted", "reason")
_REVIEW_INPUT_MANIFEST_LEAVES: Final = (
    "caller_evidence/content_bytes",
    "caller_evidence/content_digest",
    "caller_evidence/item_ids/*",
    "caller_evidence/omission_reasons/*",
    "caller_evidence/omitted_refs/*",
    "caller_evidence/revision",
    "caller_evidence/source_refs/*",
    "caller_evidence/status",
    "current_diff/content_bytes",
    "current_diff/content_digest",
    "current_diff/item_ids/*",
    "current_diff/omission_reasons/*",
    "current_diff/omitted_refs/*",
    "current_diff/revision",
    "current_diff/source_refs/*",
    "current_diff/status",
    "follow_up_round",
    "latest_verification/content_bytes",
    "latest_verification/content_digest",
    "latest_verification/item_ids/*",
    "latest_verification/omission_reasons/*",
    "latest_verification/omitted_refs/*",
    "latest_verification/revision",
    "latest_verification/source_refs/*",
    "latest_verification/status",
    "missing_inputs/*/kind",
    "missing_inputs/*/status",
    "missing_inputs/*/supplied_refs/*",
    "missing_inputs/*/target_refs/*",
    "omitted_item_count",
    "omitted_item_total",
    "phase",
    "prior_finding_context/content_bytes",
    "prior_finding_context/content_digest",
    "prior_finding_context/item_ids/*",
    "prior_finding_context/omission_reasons/*",
    "prior_finding_context/omitted_refs/*",
    "prior_finding_context/revision",
    "prior_finding_context/source_refs/*",
    "prior_finding_context/status",
    "review_phase",
    "schema",
    "selected_excerpt_bytes",
    "selected_item_count",
    "specification/content_bytes",
    "specification/content_digest",
    "specification/item_ids/*",
    "specification/omission_reasons/*",
    "specification/omitted_refs/*",
    "specification/revision",
    "specification/source_refs/*",
    "specification/status",
)
_BASIC_VERSION_LEAVES: Final = (
    "engine_version",
    "policy_packs/*",
    "projection_version",
    "protocol_version",
)
_SEMANTIC_PROVENANCE_LEAVES: Final = (
    "cost_fields/currency",
    "cost_fields/input_microunits",
    "cost_fields/output_microunits",
    "cost_fields/total_microunits",
    "dispatch_kind",
    "egress_authorization_id",
    "endpoint_profile_id",
    "endpoint_profile_version",
    "failure_class",
    "fallback_from/attempted_count",
    "fallback_from/endpoint_profile_id",
    "fallback_from/endpoint_profile_version",
    "fallback_from/model",
    "fallback_from/provider",
    "fallback_from/reason",
    "latency_ms",
    "local_disclosure_reservation_id",
    "model",
    "policy_digest",
    "privacy_policy_digest",
    "privacy_receipt_id",
    "prompt_digest",
    "provider",
    "provider_request_id",
    "reason",
    "request_commitment",
    "runtime_evidence/app_server_schema_sha256",
    "runtime_evidence/auth_mode",
    "runtime_evidence/capability_cell_sha256",
    "runtime_evidence/capability_evidence_expires_at",
    "runtime_evidence/capability_profile",
    "runtime_evidence/case_disclosed",
    "runtime_evidence/credential_authority",
    "runtime_evidence/disclosed_case_sha256",
    "runtime_evidence/executable_sha256",
    "runtime_evidence/failure_stage",
    "runtime_evidence/final_output_sha256",
    "runtime_evidence/instruction_sha256",
    "runtime_evidence/isolated_config_sha256",
    "runtime_evidence/launcher_sha256",
    "runtime_evidence/output_schema_sha256",
    "runtime_evidence/plan_type",
    "runtime_evidence/process_cleanup",
    "runtime_evidence/reasoning_effort",
    "runtime_evidence/runtime_source_identity",
    "runtime_evidence/runtime_version",
    "runtime_evidence/selection_sha256",
    "runtime_evidence/thread_id",
    "runtime_evidence/turn_acknowledged",
    "runtime_evidence/turn_id",
    "runtime_evidence/upstream_body_observability",
    "runtime_evidence/token_usage/cached_input_tokens",
    "runtime_evidence/token_usage/cache_write_input_tokens",
    "runtime_evidence/token_usage/input_tokens",
    "runtime_evidence/token_usage/output_tokens",
    "runtime_evidence/token_usage/reasoning_output_tokens",
    "runtime_evidence/token_usage/total_tokens",
    "sampling_params/max_output_tokens",
    "sampling_params/seed",
    "sampling_params/temperature",
    "sampling_params/top_p",
    "schema_digest",
    "sdk_version",
    "semantic_attempt_id",
    "status",
    "token_usage/input_tokens",
    "token_usage/output_tokens",
    "token_usage/total_tokens",
)
_RECEIPT_VERSION_LEAVES: Final = (
    "bundle_schema_version",
    "catalog_schema_version",
    "engine_version",
    "object_format_version",
    "package_name",
    "package_version",
    "policy_versions/*/policy_id",
    "policy_versions/*/policy_version",
    "projection_version",
    "protocol_version",
    "resource_manifest_digest",
    "schema_versions/*/schema_id",
    "schema_versions/*/schema_version",
)
_RECEIPT_DOCUMENT_VERSION_LEAVES: Final = (
    "bundle_schema_version",
    "catalog_schema_version",
    "engine_version",
    "object_format_version",
    "package_name",
    "package_version",
    "policy_versions/*/policy_id",
    "policy_versions/*/policy_version",
    "projection_version",
    "protocol_version",
    "resource_manifest_digest",
    "schema_versions/*/schema_id",
    "schema_versions/*/schema_version",
)

_START_STRUCTURAL_POINTERS: Final = (
    _COMMON_SUCCESS_LEAVES
    + ("/outcome", "/writer_id")
    + (
        "/acceptance",
        "/attach_handle/child_task_id",
        "/attach_handle/expires_at",
        "/attach_handle/handle",
        "/depth",
        "/origin",
        "/parent_task_id",
    )
    + _prefix_leaf_patterns("/frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/compact/coverage", _COVERAGE_LEAVES)
    + (
        "/compact/current_plan_event_id",
        "/compact/gaps/*",
        "/compact/ledger_freshness",
        "/compact/open_obligation_count",
        "/compact/unanswered_finding_count",
        "/compact/receipt_blocking_finding_count",
    )
    + _prefix_leaf_patterns("/privacy_projection", _PRIVACY_PROJECTION_LEAVES)
    + _prefix_leaf_patterns("/versions", _BASIC_VERSION_LEAVES)
    + (
        "/next_request_template/evidential",
        "/next_request_template/operation",
        "/next_request_template/arguments/protocol_version",
        "/next_request_template/arguments/schema_version",
        "/next_request_template/arguments/request_id",
        "/next_request_template/arguments/actor/actor_id",
        "/next_request_template/arguments/actor/actor_type",
        "/next_request_template/arguments/client/kind",
        "/next_request_template/arguments/client/version",
        "/next_request_template/arguments/client/integration",
        "/next_request_template/arguments/session_id",
        "/next_request_template/arguments/writer_id",
        "/next_request_template/arguments/expected_frontier/sequence",
        "/next_request_template/arguments/expected_frontier/head_digest",
        "/next_request_template/arguments/event_drafts/*/event_id",
        "/next_request_template/arguments/event_drafts/*/schema/name",
        "/next_request_template/arguments/event_drafts/*/schema/version",
        "/next_request_template/arguments/event_drafts/*/occurred_at",
        "/next_request_template/arguments/event_drafts/*/causal_parents/*",
        "/next_request_template/arguments/event_drafts/*/payload/plan_version",
        "/next_request_template/arguments/event_drafts/*/payload/summary",
        "/next_request_template/arguments/event_drafts/*/payload/obligation_refs/*",
        "/next_request_template/arguments/event_drafts/*/payload/obligation_id",
        "/next_request_template/arguments/event_drafts/*/payload/description",
        "/next_request_template/arguments/event_drafts/*/payload/acceptance_criteria",
        "/next_request_template/arguments/event_drafts/*/payload/evidence_expectation",
        "/next_request_template/arguments/event_drafts/*/payload/status",
        "/next_request_template/arguments/event_drafts/*/artifact_refs/*",
        "/next_request_template/arguments/event_drafts/*/evidence_refs/*",
    )
)

_PUBLISH_STRUCTURAL_POINTERS: Final = (
    _COMMON_SUCCESS_LEAVES
    + (
        "/correlation_id",
        "/evidential",
        "/gaps/*",
        "/outcome",
        "/reason_code",
        "/response_completeness",
        "/warning_codes/*",
        "/writer_id",
    )
    + _prefix_leaf_patterns("/subject_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/result_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/coverage", _COVERAGE_LEAVES)
    + _prefix_leaf_patterns("/privacy_projection", _PRIVACY_PROJECTION_LEAVES)
    + _prefix_leaf_patterns("/versions", _BASIC_VERSION_LEAVES)
    + _prefix_leaf_patterns(
        "/accepted_events/*",
        (
            "accepted_at",
            "entry_digest",
            "event_id",
            "ingestion_sequence",
            "predecessor_digest",
            "projection_status",
            "schema_name",
            "schema_version",
            "writer_sequence",
        ),
    )
    + _prefix_leaf_patterns(
        "/accepted_events/*/summary",
        _OMITTED_CONTENT_LEAVES,
    )
    + _prefix_leaf_patterns(
        "/would_accept/*",
        (
            "artifact_refs/*",
            "causal_parents/*",
            "event_id",
            "evidence_refs/*",
            "schema_name",
            "schema_version",
        ),
    )
    # #985: service-minted ids, closed codes and fixed repository text only.
    + _prefix_leaf_patterns(
        "/blocker_notices/*",
        ("blocker_kind", "notice", "obligation_id", "text"),
    )
    # tb4n5 follow-up: the agent's own act_ id, a closed code and fixed repository text only.
    + _prefix_leaf_patterns(
        "/action_notices/*",
        ("action_id", "notice", "text"),
    )
)

# ADR-045: closed tokens, counts and service-minted ids only (no path, command text or prose).
_FACT_LINEAGE_LEAVES: Final = (
    "accepted_by",
    "basis",
    "check_event_id",
    "code",
    "frontier",
    "item_index",
    "now_lines",
    "now_size_bytes",
    "obligation_id",
    "prior_event_id",
    "prior_frontier",
    "prior_lines",
    "prior_size_bytes",
    "proof",
    "rule",
    "source_event_ids/*",
    "state",
)

_CHECK_STRUCTURAL_POINTERS: Final = (
    _COMMON_SUCCESS_LEAVES
    + (
        "/semantic_conclusion",
        "/semantic_provenance",
        "/semantic_reason",
        # Issue #986: a closed boolean the service writes from the route, never case content.
        "/semantic_route_required",
        "/semantic_status",
        # Every continuation leaf is service-authored: an opaque proposal id, its expiry, the
        # fixed argv, the request id to replay, and fixed instruction prose. None of it carries
        # case content, so all of it is structural.
        "/state",
        "/continuation/expires_at",
        "/continuation/instruction",
        "/continuation/kind",
        "/continuation/pending_id",
        "/continuation/replay_request_id",
        "/continuation/command/*",
        "/suppressed_count",
        "/verdict",
        "/writer_id",
    )
    + _prefix_leaf_patterns("/subject_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/result_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/coverage", _COVERAGE_LEAVES)
    + _prefix_leaf_patterns("/privacy_projection", _PRIVACY_PROJECTION_LEAVES)
    + _prefix_leaf_patterns("/versions", _BASIC_VERSION_LEAVES)
    + _prefix_leaf_patterns("/semantic_provenance", _SEMANTIC_PROVENANCE_LEAVES)
    + _prefix_leaf_patterns(
        "/semantic_withheld_items/*",
        ("item_id", "reason"),
    )
    + _prefix_leaf_patterns(
        "/semantic_redacted_values/*",
        ("disposition", "item_id", "lines/*", "source_ref"),
    )
    + _prefix_leaf_patterns("/review_input_manifest", _REVIEW_INPUT_MANIFEST_LEAVES)
    + _prefix_leaf_patterns("/fact_lineage/*", _FACT_LINEAGE_LEAVES)
    + _prefix_leaf_patterns(
        "/specification_preflight",
        (
            "actionable",
            "content_bytes",
            "content_digest",
            "gap",
            "required",
            "revision",
            "source",
            "status",
        ),
    )
    + (
        "/finding_checklist/attempt_budget",
        "/finding_checklist/counts/acknowledged_not_done",
        "/finding_checklist/counts/disputed_after_rebuttal",
        "/finding_checklist/counts/open",
        "/finding_checklist/counts/open_at_budget",
        "/finding_checklist/counts/rejection_accepted",
        "/finding_checklist/counts/self_verified",
        "/finding_checklist/counts/verified_resolved",
        # ADR-046: the five closure counters travel together.
        "/finding_checklist/counts/to_do",
        "/finding_checklist/counts/awaiting_ruling",
        "/finding_checklist/counts/unmet",
        "/finding_checklist/counts/disclosed",
        "/finding_checklist/counts/to_disclose",
        "/finding_checklist/items/*/finding_id",
        "/finding_checklist/items/*/review_rounds",
        "/finding_checklist/items/*/todo_state",
        "/finding_checklist/items/*/closure_class",
        "/finding_checklist/items/*/closure_basis",
        "/finding_checklist/next",
    )
    + (
        "/overall_next/action",
        "/overall_next/acknowledged_incomplete_endpoint",
        "/overall_next/predicted_conclusion",
        "/overall_next/status",
        "/overall_next/target_refs/*",
    )
    + (
        "/children",
        "/children/label",
        "/children/tested_manifest_frontier",
        "/children/tested_manifest_frontier/head_digest",
        "/children/tested_manifest_frontier/sequence",
    )
    + _prefix_leaf_patterns(
        "/children/items/*",
        (
            "acceptance",
            "blocking_conditions/*",
            "child_task_id",
            "origin",
            "rollup_state",
            "session_health",
            "work_state",
        ),
    )
    + _prefix_leaf_patterns(
        "/advisory_notes/*",
        ("count", "kind", "project_id", "task_ids/*"),
    )
    # Issue #907: closed kind, case refs and FinishUP's availability class; no reviewer prose.
    + _prefix_leaf_patterns(
        "/missing_for_assessment/*",
        ("availability", "kind", "target_refs/*"),
    )
    + _prefix_leaf_patterns(
        "/policy_executions/*",
        ("outcome", "policy_id", "policy_version", "reason"),
    )
    + _prefix_leaf_patterns(
        "/findings/*",
        (
            "finding_id",
            "kind",
            "origin",
            "policy_id",
            "policy_version",
            "priority",
            "provenance",
            "subject_refs/*",
        ),
    )
    + _prefix_leaf_patterns("/findings/*/subject_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/findings/*/coverage", _COVERAGE_LEAVES)
    + _prefix_leaf_patterns("/findings/*/provenance", _SEMANTIC_PROVENANCE_LEAVES)
    + _prefix_leaf_patterns("/findings/*/challenge", ("requested_next_step",))
    + _prefix_leaf_patterns(
        "/findings/*/challenge/alternative_interpretation", _OMITTED_CONTENT_LEAVES
    )
    + _prefix_leaf_patterns("/findings/*/challenge/discrepancy", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/findings/*/challenge/snippet", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/findings/*/challenge/uncertainty", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/findings/*/summary", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/findings/*/detail", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/review_summary", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/verified/*", ("cited_refs/*", "verdict"))
    + _prefix_leaf_patterns("/verified/*/requirement_or_claim", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/verified/*/snippet", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns(
        "/totals",
        (
            "obligations/declared",
            "obligations/resolved",
            "obligations/open",
            "obligations/unreadable",
            "obligations/with_evidence",
            "obligations/scope_known",
            "requested_items/attempted",
            "requested_items/unattempted",
            "commands/observed",
            "commands/failed",
            "commands/unknown",
            "commands/live_failed",
            "commands/retired_by_rerun",
            "commands/disclosed_not_rerun_green",
            "evidence/mutable_reference",
            "evidence/metadata_only",
            "evidence/content_digest",
            "evidence/immutable_snapshot",
            "evidence/independently_reproduced",
            "findings/returned",
            "findings/actionable_returned",
            "findings/coverage_only_returned",
            "findings/suppressed",
            "test_edits/examined",
            "test_edits/baseline_known",
            "test_edits/modified",
            "test_edits/renamed",
            "test_edits/deleted",
            "test_edits/skipped",
            "test_edits/unjustified",
            "test_edits/unknown",
        ),
    )
    # Issue #1012: closed state and count of the optional pre-check hook-row wait.
    + _prefix_leaf_patterns("/observations_awaited", ("pending_count", "state"))
    # ADR-049: the review mode this check ran in. Closed tokens and one event id.
    + _prefix_leaf_patterns("/review_mode", ("local_reason", "mode", "source", "switch_event_id"))
    # Issue #1048 (ADR-047): the read-only inspection branch. Every leaf is an id, a closed
    # token, a count, a requested-item index or a keyed command commitment; never text or paths.
    + _prefix_leaf_patterns(
        "/remaining",
        (
            "agent_actionable/*",
            "finding_count",
            "obligation_count",
            "predicted_conclusion",
            "readiness",
            "standing_limitations/*",
        ),
    )
    + _prefix_leaf_patterns(
        "/remaining/obligations/*",
        (
            "closure_basis",
            "closure_class",
            "missing/*/item_indexes/*",
            "missing/*/kind",
            "missing/*/owner",
            "obligation_id",
        ),
    )
    + _prefix_leaf_patterns(
        "/remaining/findings/*", ("closure_basis", "closure_class", "finding_id")
    )
    + _prefix_leaf_patterns("/observed_since_check", ("action_count", "last_check_frontier"))
    + _prefix_leaf_patterns(
        "/observed_since_check/actions/*",
        (
            "action_kind",
            "command_commitment",
            "event_id",
            "exit_status",
            "ledger_sequence",
            "material_class",
            "outcome",
            "tool_name",
            "write_scope",
        ),
    )
    + _prefix_leaf_patterns(
        "/evidence_alignment", ("basis", "obligation_count", "off_declared_count")
    )
    + _prefix_leaf_patterns(
        "/evidence_alignment/obligations/*",
        (
            "alignment",
            "declared_items/*/index",
            "declared_items/*/item_kind",
            "obligation_id",
            "sources/*/command_commitment",
            "sources/*/named_item_indexes/*",
            "sources/*/origin",
            "sources/*/outcome",
            "sources/*/ref",
        ),
    )
)

_RESPOND_STRUCTURAL_POINTERS: Final = (
    _COMMON_SUCCESS_LEAVES
    + ("/warning_codes/*", "/writer_id")
    + _prefix_leaf_patterns("/subject_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/result_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/coverage", _COVERAGE_LEAVES)
    + _prefix_leaf_patterns("/privacy_projection", _PRIVACY_PROJECTION_LEAVES)
    + _prefix_leaf_patterns("/versions", _BASIC_VERSION_LEAVES)
    + _prefix_leaf_patterns(
        "/accepted_event",
        ("accepted_at", "entry_digest", "event_id", "ingestion_sequence", "writer_sequence"),
    )
    + _prefix_leaf_patterns(
        "/response",
        (
            "disposition",
            "duplicate_of_finding_id",
            "finding_id",
            "response_event_id",
            "waiver_expiry",
            "waiver_scope",
        ),
    )
    + _prefix_leaf_patterns("/response/finding_frontier", FRONTIER_LEAVES)
    # tb4n3 RC-7 (#1030): the finding's to-do state and limitation state after the answer.
    + _prefix_leaf_patterns("/closure_after", ("limitation", "todo_state"))
    + _prefix_leaf_patterns("/response/evidence/*", ("reference_id",))
    + _prefix_leaf_patterns("/response/reason", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns(
        "/response/evidence/*/description",
        _OMITTED_CONTENT_LEAVES,
    )
)

_STATUS_COMMON_STRUCTURAL_POINTERS: Final = (
    _COMMON_SUCCESS_LEAVES
    + (
        "/gaps/*",
        "/projection_lag",
        "/projection_version",
        "/rebuild_state",
        "/view",
        "/writer_id",
    )
    + _prefix_leaf_patterns("/requested_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/head_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/subject_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/result_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/coverage", _COVERAGE_LEAVES)
    + _prefix_leaf_patterns("/privacy_projection", _PRIVACY_PROJECTION_LEAVES)
    + _prefix_leaf_patterns(
        "/import_status",
        (
            "pending_count",
            "phase",
            "report_evidence_id",
            "source_identity_digest",
            "terminal_count",
        ),
    )
    + _prefix_leaf_patterns(
        "/closure_readiness",
        (
            "blocking_conditions/*",
            "declared_obligation_count",
            "no_obligations_reason",
            "open_obligation_count",
            "unanswered_finding_count",
            "receipt_blocking_finding_count",
            # The checklist carries only closed tokens, counts and service-minted ids (#913).
            "state",
            "gap_classification_version",
            "agent_actionable/*",
            "standing_limitations/*",
            "acknowledged_not_done/*",
            "acknowledged_not_done_count",
            # Service-minted ids and the closed blocker kind only (#977).
            "blocked_obligations/*/obligation_id",
            "blocked_obligations/*/blocker_kind",
            "blocked_obligations/*/decision_event_id",
            "blocked_obligations/*/confirmation",
            "blocked_obligations/*/confirmation_event_id",
            # F3: service-minted result ids and their count only.
            "limitation_refs_required/*",
            "limitation_refs_required_count",
            # #997: a count only.
            "acknowledged_obligation_count",
            # tb4n3 RC-6: service-minted ids, counters and closed tokens only (the recorded tool
            # name is a closed token, never a path or command text).
            "check_cause/effect",
            "check_cause/event_id",
            "check_cause/ledger_sequence",
            "check_cause/check_event_id",
            "check_cause/check_subject_frontier",
            "check_cause/family",
            "check_cause/material_class",
            "check_cause/rule",
            "check_cause/tool",
            # ADR-046: closed tokens and counters only (the one closure verdict).
            "finding_counts/to_do",
            "finding_counts/awaiting_ruling",
            "finding_counts/unmet",
            "finding_counts/disclosed",
            "finding_counts/to_disclose",
            "finding_counts/self_verify_eligible",
            "obligation_counts/open",
            "obligation_counts/acknowledged",
            "obligation_counts/disclosed",
            "predicted_receipt/conclusion",
            "predicted_receipt/reason_total",
            "predicted_receipt/basis_frontier",
            "predicted_receipt/provisional",
            "predicted_receipt/reasons/*/code",
            "predicted_receipt/reasons/*/rule",
            "predicted_receipt/reasons/*/count",
            "predicted_receipt/reasons/*/refs/*",
            "predicted_receipt/reasons/*/since_frontier",
            "rechecks/*/kind",
            "rechecks/*/key",
            "rechecks/*/subjects/*",
            "rechecks/*/rule",
            "rechecks/*/since_frontier",
            "awaiting_ruling_findings/*/finding_id",
            "awaiting_ruling_findings/*/since_frontier",
            # ADR-045: closed tokens, counts and service-minted ids only.
            *(f"fact_lineage/*/{leaf}" for leaf in _FACT_LINEAGE_LEAVES),
            # tb4n4 (#1044): service-minted ids and counts; each path is repository-excerpt
            # content (``_STATUS_COMMON_CONTENT_RULES``) and a withheld one is the omission marker.
            "undeclared_references/*/obligation_id",
            "undeclared_references/*/item_index",
            "undeclared_references/*/total",
            *(f"undeclared_references/*/paths/*/{leaf}" for leaf in _OMITTED_CONTENT_LEAVES),
        ),
    )
    # Closed state tokens only (issue #982).
    + _prefix_leaf_patterns("/credential_heuristic", ("machine_default", "repository"))
    # ADR-049: closed tokens, a boolean, one event id and one sequence.
    + _prefix_leaf_patterns(
        "/review_mode",
        (
            "ai_review_available",
            "local_reason",
            "mode",
            "requested",
            "setting",
            "setting_explicit",
            "switch_event_id",
            "switch_sequence",
        ),
    )
)

_STATUS_ADVICE_STRUCTURAL_POINTERS: Final = (
    (
        "/page/next_cursor",
        "/page/projection_format",
    )
    + _prefix_leaf_patterns(
        "/page/items/*",
        (
            "evidence_commitments/*",
            "finding_id",
            "freshness_frontier",
            "coordination_counterpart_task_id",
            "coordination_detection_id",
            "coordination_membership_generation",
            "coordination_project_id",
            "priority",
            "recommended_next_action",
            "rule_code",
            "semantic_state",
            "verification_state",
        ),
    )
    + (
        "/page/items/*/coordination_resource_paths/category",
        "/page/items/*/coordination_resource_paths/omitted",
        "/page/items/*/coordination_resource_paths/reason",
    )
    + _prefix_leaf_patterns("/page/items/*/coverage", _COVERAGE_LEAVES)
)

_STATUS_ASSIGNMENT_STRUCTURAL_POINTERS: Final = ("/page/next_cursor",) + _prefix_leaf_patterns(
    "/page/items/*",
    ("actor_id", "assignment_event_id", "obligation_ids/*", "resolved", "scope_refs/*"),
)

_STATUS_CANDIDATE_FINDINGS_STRUCTURAL_POINTERS: Final = (
    ("/page/next_cursor",)
    + _prefix_leaf_patterns(
        "/page/items/*",
        ("kind", "origin", "policy_id", "policy_version", "priority", "subject_refs/*"),
    )
    + _prefix_leaf_patterns(
        "/page/items/*/basis",
        (
            "coverage_gaps/*",
            "evidence_refs/*",
            "frozen_source_availability",
            "observed_fact_codes/*",
            "observed_refs/*",
            "required_missing_fact_codes/*",
            "rule_id",
            "subject_state_relation",
        ),
    )
    + _prefix_leaf_patterns("/page/items/*/coverage", _COVERAGE_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/subject_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/detail", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/summary", _OMITTED_CONTENT_LEAVES)
)

_STATUS_COMPACT_STRUCTURAL_POINTERS: Final = (
    ("/page/next_cursor",)
    + _prefix_leaf_patterns(
        "/page/items/*",
        (
            "current_plan_event_id",
            "declared_obligation_count",
            "freshness",
            "gaps/*",
            "no_obligations_reason",
            "open_obligation_count",
            "receipt_blocking_finding_count",
            "session_id",
            "task_id",
            "unanswered_finding_count",
        ),
    )
    + _prefix_leaf_patterns("/page/items/*/coverage", _COVERAGE_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/task_title", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/open_obligations/*", ("obligation_id",))
    + _prefix_leaf_patterns(
        "/page/items/*/open_obligations/*/acceptance_criteria",
        _OMITTED_CONTENT_LEAVES,
    )
    + _prefix_leaf_patterns(
        "/page/items/*/open_obligations/*/description",
        _OMITTED_CONTENT_LEAVES,
    )
    + _prefix_leaf_patterns(
        "/page/items/*/open_obligations/*/evidence_expectation",
        _OMITTED_CONTENT_LEAVES,
    )
    + _prefix_leaf_patterns(
        "/page/items/*/unanswered_findings/*",
        ("finding_id", "kind", "priority"),
    )
    + _prefix_leaf_patterns(
        "/page/items/*/unanswered_findings/*/detail",
        _OMITTED_CONTENT_LEAVES,
    )
    + _prefix_leaf_patterns(
        "/page/items/*/unanswered_findings/*/summary",
        _OMITTED_CONTENT_LEAVES,
    )
    + _prefix_leaf_patterns(
        "/page/items/*/latest_check_test_edits",
        (
            "baseline_known",
            "deleted",
            "examined",
            "modified",
            "read_availability",
            "renamed",
            "skipped",
            "unjustified",
            "unknown",
        ),
    )
    + _prefix_leaf_patterns(
        "/page/items/*/latest_check_test_edits/checked_frontier",
        FRONTIER_LEAVES,
    )
    + _prefix_leaf_patterns(
        "/page/items/*/latest_check",
        ("check_event_id", "verdict"),
    )
    + _prefix_leaf_patterns(
        "/page/items/*/latest_check/checked_frontier",
        FRONTIER_LEAVES,
    )
)

_STATUS_EVIDENCE_STRUCTURAL_POINTERS: Final = (
    ("/page/next_cursor",)
    + _prefix_leaf_patterns(
        "/page/items/*",
        (
            "available",
            "captured_object_id",
            "content_digest",
            "evidence_id",
            "freshness",
            "publication_channel",
            "strength",
            "subject_state",
        ),
    )
    + _prefix_leaf_patterns("/page/items/*/description", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/reference", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns(
        "/page/items/*/subject_state",
        ("diff_digest", "tree_digest"),
    )
)

_STATUS_FINDINGS_STRUCTURAL_POINTERS: Final = (
    ("/page/attempt_budget", "/page/next_cursor")
    + _prefix_leaf_patterns(
        "/page/items/*",
        (
            "disposition",
            "duplicate_of_finding_id",
            "finding_id",
            "kind",
            "origin",
            "policy_id",
            "policy_version",
            "priority",
            "provenance",
            "resolved",
            "response_event_id",
            "review_rounds",
            "subject_refs/*",
            "todo_state",
            "waiver_expiry",
            "waiver_scope",
            # ADR-046: closed tokens only (who owes the next move, why, and the answers offered).
            "closure_class",
            "closure_basis",
            "next_actions/*",
        ),
    )
    + _prefix_leaf_patterns("/page/items/*/coverage", _COVERAGE_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/subject_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/finding_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/provenance", _SEMANTIC_PROVENANCE_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/challenge", ("requested_next_step",))
    + _prefix_leaf_patterns(
        "/page/items/*/challenge/alternative_interpretation", _OMITTED_CONTENT_LEAVES
    )
    + _prefix_leaf_patterns("/page/items/*/challenge/discrepancy", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/challenge/snippet", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/challenge/uncertainty", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/detail", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/reason", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/summary", _OMITTED_CONTENT_LEAVES)
)

_STATUS_HISTORY_STRUCTURAL_POINTERS: Final = (
    ("/page/next_cursor",)
    + _prefix_leaf_patterns(
        "/page/items/*",
        (
            "accepted_at",
            "actor_id",
            "event_id",
            "ingestion_sequence",
            "occurred_at",
            "occurred_at_consistency",
            "projection_status",
            "publication_channel",
            "schema_name",
            "schema_version",
            "summary_code",
        ),
    )
    + _prefix_leaf_patterns("/page/items/*/review_input_manifest", _REVIEW_INPUT_MANIFEST_LEAVES)
)

_STATUS_OBLIGATIONS_STRUCTURAL_POINTERS: Final = (
    ("/page/next_cursor",)
    + _prefix_leaf_patterns(
        "/page/items/*",
        (
            "assigned_actor_ids/*",
            "evidence_refs/*",
            "obligation_id",
            "revision_event_id",
            "requested_items/*/item_kind",
            "requested_items/*/role",
            "source_refs/*",
            "in_current_plan",
            "closure_class",
            "closure_basis",
            "status",
            "unattempted_items/*/item_kind",
            "unattempted_items/*/role",
            "command_attempts/*/requested_item_index",
            "command_attempts/*/relation",
            "command_attempts/*/asserted_action_ids/*",
            "command_attempts/*/observed_event_ids/*",
        ),
    )
    + _prefix_leaf_patterns("/page/items/*/acceptance_criteria", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/acknowledged_not_done_reason", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/description", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/evidence_expectation", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/requested_items/*/value", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns("/page/items/*/unattempted_items/*/value", _OMITTED_CONTENT_LEAVES)
)

_STATUS_RESULTS_STRUCTURAL_POINTERS: Final = ("/page/next_cursor",) + _prefix_leaf_patterns(
    "/page/items/*",
    (
        "action_id",
        "evidence_refs/*",
        "observed_run/command_commitment",
        "observed_run/exit_status",
        "observed_run/occurrence",
        "observed_run/tool_name",
        "outcome",
        "payload_available",
        "result_id",
        "source_event_id",
    ),
)

_STATUS_OPERATION_STRUCTURAL_POINTERS: Final = (
    (
        "/page/accepted_events/*/entry_digest",
        "/page/accepted_events/*/event_id",
        "/page/accepted_events/*/ingestion_sequence",
        "/page/accepted_events/*/projection_status",
        "/page/accepted_events/*/writer_sequence",
        # Issue #838: service-derived pre-admission stage; closed tokens, counts, and timestamps.
        "/page/admission/elapsed_ms",
        "/page/admission/first_observed_at",
        "/page/admission/last_observed_at",
        "/page/admission/observed_at",
        "/page/admission/refusal_count",
        "/page/admission/retry_after_ms",
        "/page/admission/stage",
        # Nullable continuation object: a leaf when null, expands when a check is suspended.
        # Every field is service-authored, so all of it is structural.
        "/page/continuation",
        "/page/continuation/command/*",
        "/page/continuation/expires_at",
        "/page/continuation/instruction",
        "/page/continuation/kind",
        "/page/continuation/pending_id",
        "/page/continuation/replay_request_id",
        "/page/found",
        "/page/next_cursor",
        "/page/operation_kind",
        "/page/operation_request_id",
        "/page/outcome",
        # Nullable frontier objects are leaves when null and expand when present.
        "/page/result_frontier",
        # Issue #571 A2: service-derived structural progress; no provider or user content.
        "/page/semantic_progress/attempt_ordinal",
        "/page/semantic_progress/condition",
        "/page/semantic_progress/deadline_at",
        "/page/semantic_progress/elapsed_ms",
        "/page/semantic_progress/observed_at",
        "/page/semantic_progress/phase",
        "/page/semantic_progress/phase_entered_at",
        "/page/semantic_progress/queued_at",
        "/page/semantic_progress/remaining_ms",
        "/page/semantic_progress/terminal_outcome",
        "/page/semantic_progress/terminal_reason",
        "/page/semantic_withheld_items/*/item_id",
        "/page/semantic_withheld_items/*/reason",
        "/page/semantic_redacted_values/*/disposition",
        "/page/semantic_redacted_values/*/item_id",
        "/page/semantic_redacted_values/*/lines/*",
        "/page/semantic_redacted_values/*/source_ref",
        "/page/state",
        "/page/subject_frontier",
    )
    + _prefix_leaf_patterns("/page/subject_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/page/result_frontier", FRONTIER_LEAVES)
)

_STATUS_VERSIONS_STRUCTURAL_POINTERS: Final = ("/page/next_cursor",) + _prefix_leaf_patterns(
    "/page/items/*",
    (
        "apsw_version",
        "engine_version",
        "object_format",
        "policy_packs/*",
        "projection_version",
        "protocol_version",
        "provider_profiles/*",
        "python_version",
        "route_profile",
        "sqlite_source_id",
        "sqlite_version",
        "storage_schema",
    ),
)

_STATUS_LINEAGE_STRUCTURAL_POINTERS: Final = (
    "/page/next_cursor",
    "/page/parent_task_id",
    "/page/children/*/acceptance",
    "/page/children/*/blocking_conditions/*",
    "/page/children/*/depth",
    "/page/children/*/origin",
    "/page/children/*/parent_task_id",
    "/page/children/*/rollup_state",
    "/page/children/*/self_verified_finding_count",
    "/page/children/*/session_health",
    "/page/children/*/task_id",
    "/page/children/*/work_state",
    "/page/annotations/*/acceptance",
    "/page/annotations/*/correlation_id",
    "/page/annotations/*/origin",
    "/page/annotations/*/parent_tool_call_id",
    "/page/annotations/*/subagent_id",
)

_STATUS_PROJECT_STRUCTURAL_POINTERS: Final = (
    "/page/next_cursor",
    "/page/project_id",
    "/page/kind",
    "/page/membership_generation",
    "/page/grant_state",
    "/page/title/category",
    "/page/title/omitted",
    "/page/title/reason",
    "/page/title_ref/object_id",
    "/page/title_ref/content_digest",
    "/page/title_ref/plaintext_size",
    "/page/title_ref/owner_task_id",
    "/page/title_ref/route_generation",
    "/page/title_ref/envelope_digest",
    "/page/title_ref",
    "/page/description_ref/object_id",
    "/page/description_ref/content_digest",
    "/page/description_ref/plaintext_size",
    "/page/description_ref/owner_task_id",
    "/page/description_ref/route_generation",
    "/page/description_ref/envelope_digest",
    "/page/description_ref",
    "/page/description/category",
    "/page/description/omitted",
    "/page/description/reason",
    "/page/members/*/task_id",
    "/page/members/*/actor_id",
    "/page/members/*/work_state",
    "/page/members/*/session_health",
    "/page/members/*/parent_task_id",
    "/page/detections/*/detection_id",
    "/page/detections/*/task_ids/*",
    "/page/detections/*/resource_count",
    "/page/detections/*/open",
    "/page/detections/*/resource_paths/category",
    "/page/detections/*/resource_paths/omitted",
    "/page/detections/*/resource_paths/reason",
    "/page/coverage/*/coverage_id",
    "/page/coverage/*/project_id",
    "/page/coverage/*/task_id",
    "/page/coverage/*/membership_generation",
    "/page/coverage/*/coverage",
    "/page/coverage/*/gap_code",
    "/page/receipts/*/task_id",
    "/page/receipts/*/receipt_id",
    "/page/receipts/*/frontier/head_digest",
    "/page/receipts/*/frontier/sequence",
    "/page/receipts/*/conclusion",
    "/page/lineage/next_cursor",
    "/page/lineage/parent_task_id",
    "/page/lineage/children/*/acceptance",
    "/page/lineage/children/*/blocking_conditions/*",
    "/page/lineage/children/*/depth",
    "/page/lineage/children/*/origin",
    "/page/lineage/children/*/parent_task_id",
    "/page/lineage/children/*/rollup_state",
    "/page/lineage/children/*/self_verified_finding_count",
    "/page/lineage/children/*/session_health",
    "/page/lineage/children/*/task_id",
    "/page/lineage/children/*/work_state",
    "/page/lineage/annotations/*/acceptance",
    "/page/lineage/annotations/*/correlation_id",
    "/page/lineage/annotations/*/origin",
    "/page/lineage/annotations/*/parent_tool_call_id",
    "/page/lineage/annotations/*/subagent_id",
)

_RECEIPT_STRUCTURAL_POINTERS: Final = (
    _COMMON_SUCCESS_LEAVES
    + (
        "/conclusion",
        "/document",
        "/format",
        "/include",
        "/receipt_digest",
        "/receipt_id",
        "/receipt_object_id",
        "/redaction_profile",
        "/suppressed_finding_count",
    )
    + _prefix_leaf_patterns("/subject_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/result_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/coverage", _COVERAGE_LEAVES)
    + _prefix_leaf_patterns("/privacy_projection", _PRIVACY_PROJECTION_LEAVES)
    + _prefix_leaf_patterns("/versions", _RECEIPT_VERSION_LEAVES)
    + _prefix_leaf_patterns("/human_text", _OMITTED_CONTENT_LEAVES)
    + _prefix_leaf_patterns(
        "/document",
        (
            "acknowledged_not_done_finding_ids/*",
            "acknowledged_not_done_obligation_ids/*",
            "claim_refs/*",
            "premise_disputed_finding_ids/*",
            "conclusion",
            "disclosed_assumptions/*/decision_event_id",
            "disclosed_assumptions/*/kind",
            "disclosed_assumptions/*/obligation_id",
            "duplicate_finding_links/*/duplicate_of_finding_id",
            "duplicate_finding_links/*/finding_id",
            "evidence_refs/*",
            "generated_at",
            "receipt_id",
            "rejection_accepted_finding_ids/*",
            "schema_version",
            "self_verified_finding_ids/*",
            "disputed_after_rebuttal_finding_ids/*",
            # ADR-046: ids, closed codes and counters only.
            "limitation_disclosed_finding_ids/*",
            "conclusion_basis/reason_total",
            "conclusion_basis/reasons/*/code",
            "conclusion_basis/reasons/*/rule",
            "conclusion_basis/reasons/*/count",
            "conclusion_basis/reasons/*/refs/*",
            "conclusion_basis/reasons/*/since_frontier",
            "session_id",
            "suppressed_finding_count",
            "task_id",
        ),
    )
    + _prefix_leaf_patterns("/document/coverage", _COVERAGE_LEAVES)
    + _prefix_leaf_patterns("/document/subject_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/document/versions", _RECEIPT_DOCUMENT_VERSION_LEAVES)
    + _prefix_leaf_patterns(
        "/document/findings/*",
        (
            "finding_id",
            "kind",
            "origin",
            "policy_id",
            "policy_version",
            "priority",
            "subject_refs/*",
        ),
    )
    + _prefix_leaf_patterns("/document/findings/*/coverage", _COVERAGE_LEAVES)
    + _prefix_leaf_patterns("/document/findings/*/subject_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns(
        "/document/findings/*/provenance",
        _SEMANTIC_PROVENANCE_LEAVES,
    )
    + _prefix_leaf_patterns("/document/semantic_provenance", _SEMANTIC_PROVENANCE_LEAVES)
    + _prefix_leaf_patterns(
        "/document/semantic_withheld_items/*",
        ("item_id", "reason"),
    )
    + _prefix_leaf_patterns(
        "/document/semantic_redacted_values/*",
        ("disposition", "item_id", "lines/*", "source_ref"),
    )
    + _prefix_leaf_patterns(
        "/document/obligations/*",
        ("obligation_id", "source_refs/*", "status"),
    )
    + _prefix_leaf_patterns(
        "/document/responses/*",
        ("disposition", "evidence_refs/*", "finding_id", "waiver_expiry", "waiver_scope"),
    )
    + _prefix_leaf_patterns("/document/responses/*/finding_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/document/gaps/*", ("code", "effect", "status", "subject_refs/*"))
    # Issue #1017: the frontier a later check cleared a historical gap at.
    + _prefix_leaf_patterns("/document/gaps/*/cleared_at_frontier", FRONTIER_LEAVES)
    + _prefix_leaf_patterns("/document/redactions/*", ("category", "count", "reason"))
    + _prefix_leaf_patterns("/document/sections/*", ("key",))
    + (
        "/document/children/children/*/child_task_id",
        "/document/children/children/*/outcome",
        "/document/children/children/*/tested_manifest_ref",
        "/document/children/children/*/later_manifest_ref",
        "/document/children/children/*/freshness",
    )
    + _prefix_leaf_patterns(
        "/document/children/children/*/findings/*",
        (
            "finding_id",
            "kind",
            "origin",
            "priority",
            "actionable",
            "resolved",
            "resolution_event_id",
            "self_verified",
        ),
    )
)

_CHECK_CONTENT_RULES: Final[tuple[tuple[str, DataCategory], ...]] = (
    ("/findings/*/detail", DataCategory.FINDING_SUMMARY),
    ("/findings/*/summary", DataCategory.FINDING_SUMMARY),
    ("/findings/*/challenge/alternative_interpretation", DataCategory.FINDING_SUMMARY),
    ("/findings/*/challenge/discrepancy", DataCategory.FINDING_SUMMARY),
    ("/findings/*/challenge/snippet", DataCategory.FINDING_SUMMARY),
    ("/findings/*/challenge/uncertainty", DataCategory.FINDING_SUMMARY),
    ("/review_summary", DataCategory.FINDING_SUMMARY),
    ("/verified/*/requirement_or_claim", DataCategory.FINDING_SUMMARY),
    ("/verified/*/snippet", DataCategory.FINDING_SUMMARY),
)
_RESPOND_CONTENT_RULES: Final[tuple[tuple[str, DataCategory], ...]] = (
    ("/response/evidence/*/description", DataCategory.EVIDENCE_EXCERPT),
    ("/response/reason", DataCategory.FINDING_SUMMARY),
)
_STATUS_CONTENT_RULES: Final[tuple[tuple[str, str, DataCategory], ...]] = (
    ("candidate_findings", "/page/items/*/detail", DataCategory.FINDING_SUMMARY),
    ("candidate_findings", "/page/items/*/summary", DataCategory.FINDING_SUMMARY),
    (
        "compact",
        "/page/items/*/open_obligations/*/acceptance_criteria",
        DataCategory.OBLIGATION_TEXT,
    ),
    (
        "compact",
        "/page/items/*/open_obligations/*/description",
        DataCategory.OBLIGATION_TEXT,
    ),
    (
        "compact",
        "/page/items/*/open_obligations/*/evidence_expectation",
        DataCategory.OBLIGATION_TEXT,
    ),
    ("compact", "/page/items/*/task_title", DataCategory.TASK_DESCRIPTION),
    (
        "compact",
        "/page/items/*/unanswered_findings/*/detail",
        DataCategory.FINDING_SUMMARY,
    ),
    (
        "compact",
        "/page/items/*/unanswered_findings/*/summary",
        DataCategory.FINDING_SUMMARY,
    ),
    ("evidence", "/page/items/*/description", DataCategory.EVIDENCE_EXCERPT),
    ("evidence", "/page/items/*/reference", DataCategory.EVIDENCE_EXCERPT),
    ("findings", "/page/items/*/detail", DataCategory.FINDING_SUMMARY),
    ("findings", "/page/items/*/reason", DataCategory.FINDING_SUMMARY),
    ("findings", "/page/items/*/summary", DataCategory.FINDING_SUMMARY),
    (
        "findings",
        "/page/items/*/challenge/alternative_interpretation",
        DataCategory.FINDING_SUMMARY,
    ),
    ("findings", "/page/items/*/challenge/discrepancy", DataCategory.FINDING_SUMMARY),
    ("findings", "/page/items/*/challenge/snippet", DataCategory.FINDING_SUMMARY),
    ("findings", "/page/items/*/challenge/uncertainty", DataCategory.FINDING_SUMMARY),
    ("obligations", "/page/items/*/acceptance_criteria", DataCategory.OBLIGATION_TEXT),
    ("obligations", "/page/items/*/acknowledged_not_done_reason", DataCategory.OBLIGATION_TEXT),
    ("obligations", "/page/items/*/description", DataCategory.OBLIGATION_TEXT),
    ("obligations", "/page/items/*/evidence_expectation", DataCategory.OBLIGATION_TEXT),
    ("obligations", "/page/items/*/requested_items/*/value", DataCategory.OBLIGATION_TEXT),
    ("obligations", "/page/items/*/unattempted_items/*/value", DataCategory.OBLIGATION_TEXT),
    ("project", "/page/title", DataCategory.TASK_DESCRIPTION),
    ("project", "/page/description", DataCategory.TASK_DESCRIPTION),
    (
        "project",
        "/page/detections/*/resource_paths/*",
        DataCategory.REPOSITORY_EXCERPT,
    ),
    (
        "advice",
        "/page/items/*/coordination_resource_paths/*",
        DataCategory.REPOSITORY_EXCERPT,
    ),
)
# Content leaves every status view carries (the closure readiness is on each of them).
_STATUS_COMMON_CONTENT_RULES: Final[tuple[tuple[str, DataCategory], ...]] = (
    (
        "/closure_readiness/undeclared_references/*/paths/*",
        DataCategory.REPOSITORY_EXCERPT,
    ),
)
_RECEIPT_CONTENT_RULES: Final[tuple[tuple[str, DataCategory], ...]] = (
    ("/document/gaps/*/detail", DataCategory.FINDING_SUMMARY),
    ("/document/findings/*/detail", DataCategory.FINDING_SUMMARY),
    ("/document/findings/*/summary", DataCategory.FINDING_SUMMARY),
    ("/document/obligations/*/summary", DataCategory.OBLIGATION_TEXT),
    ("/document/responses/*/reason", DataCategory.FINDING_SUMMARY),
    ("/document/sections/*/body", DataCategory.FINDING_SUMMARY),
    ("/document/sections/*/coverage_note", DataCategory.FINDING_SUMMARY),
    ("/document/sections/*/items/*", DataCategory.FINDING_SUMMARY),
    ("/document/sections/*/title", DataCategory.FINDING_SUMMARY),
    ("/human_text", DataCategory.FINDING_SUMMARY),
)


def _leaf_rule(
    method: str,
    pointer_pattern: str,
    classification: _LeafClassification,
    *,
    status_view: str | None = None,
    event_selector: _EventSelector | None = None,
) -> _ResultLeafRule:
    return _ResultLeafRule(
        method=method,
        status_view=status_view,
        event_selector=event_selector,
        segments=tuple(pointer_pattern.removeprefix("/").split("/")) if pointer_pattern else (),
        classification=classification,
    )


def _build_result_leaf_rules() -> tuple[_ResultLeafRule, ...]:
    rules: list[_ResultLeafRule] = []

    def add_structural(
        method: str,
        pointers: tuple[str, ...],
        *,
        status_view: str | None = None,
    ) -> None:
        rules.extend(
            _leaf_rule(method, pointer, "public_structural", status_view=status_view)
            for pointer in pointers
        )

    add_structural("start", _START_STRUCTURAL_POINTERS)
    add_structural("publish_work", _PUBLISH_STRUCTURAL_POINTERS)
    add_structural("check", _CHECK_STRUCTURAL_POINTERS)
    add_structural("respond", _RESPOND_STRUCTURAL_POINTERS)
    add_structural("status", _STATUS_COMMON_STRUCTURAL_POINTERS)
    add_structural("status", _STATUS_ADVICE_STRUCTURAL_POINTERS, status_view="advice")
    add_structural(
        "status",
        _STATUS_ASSIGNMENT_STRUCTURAL_POINTERS,
        status_view="assignment",
    )
    add_structural(
        "status",
        _STATUS_CANDIDATE_FINDINGS_STRUCTURAL_POINTERS,
        status_view="candidate_findings",
    )
    add_structural("status", _STATUS_COMPACT_STRUCTURAL_POINTERS, status_view="compact")
    add_structural("status", _STATUS_EVIDENCE_STRUCTURAL_POINTERS, status_view="evidence")
    add_structural("status", _STATUS_FINDINGS_STRUCTURAL_POINTERS, status_view="findings")
    add_structural("status", _STATUS_HISTORY_STRUCTURAL_POINTERS, status_view="history")
    add_structural(
        "status",
        _STATUS_OBLIGATIONS_STRUCTURAL_POINTERS,
        status_view="obligations",
    )
    add_structural(
        "status",
        _STATUS_OPERATION_STRUCTURAL_POINTERS,
        status_view="operation",
    )
    add_structural("status", _STATUS_RESULTS_STRUCTURAL_POINTERS, status_view="results")
    add_structural("status", _STATUS_LINEAGE_STRUCTURAL_POINTERS, status_view="lineage")
    add_structural("status", _STATUS_PROJECT_STRUCTURAL_POINTERS, status_view="project")
    add_structural("status", _STATUS_VERSIONS_STRUCTURAL_POINTERS, status_view="versions")
    add_structural("receipt", _RECEIPT_STRUCTURAL_POINTERS)

    summary_pattern = "/accepted_events/*/summary"
    for selector, category in _PUBLISH_SUMMARY_CATEGORY.items():
        rules.append(
            _leaf_rule(
                "publish_work",
                summary_pattern,
                category,
                event_selector=selector,
            )
        )
    for selector in _PUBLISH_FIXED_SUMMARY:
        rules.append(
            _leaf_rule(
                "publish_work",
                summary_pattern,
                "public_structural",
                event_selector=selector,
            )
        )
    rules.append(
        _leaf_rule(
            "publish_work",
            summary_pattern,
            "public_structural",
            event_selector="<opaque>",
        )
    )

    for pointer, category in _CHECK_CONTENT_RULES:
        rules.append(_leaf_rule("check", pointer, category))
    for pointer, category in _RESPOND_CONTENT_RULES:
        rules.append(_leaf_rule("respond", pointer, category))
    for view, pointer, category in _STATUS_CONTENT_RULES:
        rules.append(_leaf_rule("status", pointer, category, status_view=view))
    for pointer, category in _STATUS_COMMON_CONTENT_RULES:
        rules.append(_leaf_rule("status", pointer, category))
    for pointer, category in _RECEIPT_CONTENT_RULES:
        rules.append(_leaf_rule("receipt", pointer, category))

    def sort_key(rule: _ResultLeafRule) -> tuple[bytes, bytes, bytes, tuple[bytes, ...]]:
        if isinstance(rule.event_selector, tuple):
            selector = f"{rule.event_selector[0]}@{rule.event_selector[1]}"
        else:
            selector = rule.event_selector or ""
        return (
            rule.method.encode("utf-8"),
            (rule.status_view or "").encode("utf-8"),
            selector.encode("utf-8"),
            tuple(segment.encode("utf-8") for segment in rule.segments),
        )

    result = tuple(sorted(rules, key=sort_key))
    keys: set[tuple[str, str | None, _EventSelector | None, tuple[str, ...]]] = set()
    for rule in result:
        key = (rule.method, rule.status_view, rule.event_selector, rule.segments)
        if key in keys:
            raise RuntimeError("duplicate_result_leaf_rule")
        keys.add(key)
        if rule.method not in _RESULT_METHODS:
            raise RuntimeError("invalid_result_leaf_method")
        if not rule.segments:
            raise RuntimeError("invalid_result_leaf_pattern")
        if rule.status_view is not None and (
            rule.method != "status" or rule.status_view not in _STATUS_VIEWS
        ):
            raise RuntimeError("invalid_result_leaf_view")
        if rule.event_selector is not None and (
            rule.method != "publish_work" or rule.segments != ("accepted_events", "*", "summary")
        ):
            raise RuntimeError("invalid_result_leaf_event_selector")
        if rule.status_view is not None and rule.event_selector is not None:
            raise RuntimeError("invalid_result_leaf_context")
        if any(segment == "**" or ("*" in segment and segment != "*") for segment in rule.segments):
            raise RuntimeError("invalid_result_leaf_pattern")
        if any(segment.isascii() and segment.isdecimal() for segment in rule.segments):
            # An array position is matched by ``*`` alone; ``_classify_leaf_shape`` relies on it.
            raise RuntimeError("invalid_result_leaf_pattern")
        if (
            rule.classification != "public_structural"
            and type(rule.classification) is not DataCategory
        ):
            raise RuntimeError("invalid_result_leaf_classification")
    if (
        len(result) != 1627
    ):  # ... #1017 +3, #1027 +5, tb4n3 LO +9, W2-A +46, LF +34 (fact_lineage), W2-B +2,
        # tb4n4 #1044 +7 (closure_readiness.undeclared_references), #1048 +38 (inspection),
        # #1047 +2 (follow_up_round), tb4n5 +3 (publish action_notices),
        # ADR-049 +4 check / +8 status (review_mode), n6 item 4 +1 check_recorded 1.5.0
        raise RuntimeError("incomplete_result_leaf_registry")
    return result


_RESULT_LEAF_RULES: Final[tuple[_ResultLeafRule, ...]] = _build_result_leaf_rules()


def _decode_pointer(pointer: object) -> tuple[str, ...]:
    if type(pointer) is not str or unicodedata.normalize("NFC", pointer) != pointer:
        raise ProtocolValueError("invalid_json_pointer")
    try:
        pointer_size = len(pointer.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ProtocolValueError("invalid_json_pointer") from exc
    if not pointer.startswith("/") or pointer_size > MAX_PROJECTION_POINTER_BYTES:
        raise ProtocolValueError("invalid_json_pointer")
    raw_segments = pointer[1:].split("/")
    decoded: list[str] = []
    for raw in raw_segments:
        index = 0
        while index < len(raw):
            if raw[index] == "~":
                if index + 1 >= len(raw) or raw[index + 1] not in {"0", "1"}:
                    raise ProtocolValueError("invalid_json_pointer")
                index += 2
            else:
                index += 1
        segment = raw.replace("~1", "/").replace("~0", "~")
        canonical = segment.replace("~", "~0").replace("/", "~1")
        if canonical != raw or unicodedata.normalize("NFC", segment) != segment:
            raise ProtocolValueError("invalid_json_pointer")
        decoded.append(segment)
    return tuple(decoded)


def _traverse_result_leaf(
    result: Mapping[str, JsonValue], segments: tuple[str, ...]
) -> tuple[JsonValue, tuple[bool, ...]]:
    current: JsonValue = result
    array_segments: list[bool] = []
    for segment in segments:
        if isinstance(current, Mapping):
            if segment not in current:
                raise ProtocolValueError("invalid_json_pointer")
            current = current[segment]
            array_segments.append(False)
        elif type(current) is list or type(current) is tuple:
            if not segment.isascii() or not segment.isdecimal():
                raise ProtocolValueError("invalid_json_pointer")
            if segment != "0" and segment.startswith("0"):
                raise ProtocolValueError("invalid_json_pointer")
            index = int(segment)
            sequence = cast(list[JsonValue] | tuple[JsonValue, ...], current)
            if index >= len(sequence):
                raise ProtocolValueError("invalid_json_pointer")
            current = sequence[index]
            array_segments.append(True)
        else:
            raise ProtocolValueError("invalid_json_pointer")
    if type(current) not in {type(None), bool, int, str}:
        raise ProtocolValueError("invalid_json_pointer")
    return current, tuple(array_segments)


def _shape_matches(rule: _ResultLeafRule, shape: tuple[str | None, ...]) -> bool:
    if len(rule.segments) != len(shape):
        return False
    for expected, actual in zip(rule.segments, shape, strict=True):
        if expected == "*":
            if actual is not None:
                return False
        elif expected != actual:
            return False
    return True


@lru_cache(maxsize=4096)
def _classify_leaf_shape(
    method: str,
    status_view: str | None,
    event_selector: _EventSelector | None,
    shape: tuple[str | None, ...],
) -> _LeafClassification | None:
    """The single rule for one leaf shape, or ``None`` when no single rule applies.

    ``shape`` is the leaf's decoded pointer with every array index replaced by ``None``. No rule
    names an array index literally (``_build_result_leaf_rules`` refuses one), so which rule
    matches depends only on this shape: every row of a page shares one decision instead of
    scanning all rules per leaf (issue #916).
    """

    contextual = tuple(
        rule
        for rule in _RESULT_LEAF_RULES
        if rule.method == method
        and (rule.status_view is None or rule.status_view == status_view)
        and (rule.event_selector is None or rule.event_selector == event_selector)
    )
    exact = tuple(
        rule for rule in contextual if "*" not in rule.segments and _shape_matches(rule, shape)
    )
    if len(exact) > 1:
        return None
    if exact:
        return exact[0].classification
    wildcard = tuple(
        rule for rule in contextual if "*" in rule.segments and _shape_matches(rule, shape)
    )
    if len(wildcard) != 1:
        return None
    return wildcard[0].classification


def _publish_event_selector(
    result: Mapping[str, JsonValue], segments: tuple[str, ...]
) -> _EventSelector | None:
    if len(segments) != 3 or segments[0] != "accepted_events" or segments[2] != "summary":
        return None
    try:
        index = int(segments[1])
        raw_events = result["accepted_events"]
        if type(raw_events) is not list and type(raw_events) is not tuple:
            raise ProtocolValueError("invalid_json_pointer")
        event = cast(list[JsonValue] | tuple[JsonValue, ...], raw_events)[index]
        if not isinstance(event, Mapping):
            raise ProtocolValueError("invalid_json_pointer")
        event_map = cast(Mapping[str, JsonValue], event)
        schema_name = event_map.get("schema_name")
        schema_version = event_map.get("schema_version")
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise ProtocolValueError("invalid_json_pointer") from exc
    if type(schema_name) is not str or type(schema_version) is not str:
        raise ProtocolValueError("invalid_json_pointer")
    selector = (schema_name, schema_version)
    if selector in _KNOWN_PUBLISH_EVENT_SELECTORS:
        return selector
    if event_map.get("summary") != "opaque_unknown":
        raise ProtocolValueError("invalid_json_pointer")
    return "<opaque>"


def classify_result_leaf(
    method: str,
    validated_result: Mapping[str, JsonValue],
    pointer: str,
) -> Literal["public_structural"] | DataCategory:
    """Classify one leaf of an exact locally validated public success result."""

    if type(method) is not str or method not in _RESULT_METHODS:
        raise ProtocolValueError("invalid_json_pointer")
    if not isinstance(validated_result, Mapping):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ProtocolValueError("invalid_json_pointer")
    result = validated_result
    if result.get("ok") is not True:
        raise ProtocolValueError("invalid_json_pointer")

    segments = _decode_pointer(pointer)
    leaf_value, array_segments = _traverse_result_leaf(result, segments)
    if method == "receipt" and segments == ("human_text",):
        receipt_format = result.get("format")
        if leaf_value is None:
            if receipt_format != "json":
                raise ProtocolValueError("invalid_json_pointer")
            return "public_structural"
        if type(leaf_value) is not str or receipt_format not in {"markdown", "text"}:
            raise ProtocolValueError("invalid_json_pointer")
    status_view: str | None = None
    if method == "status":
        candidate = result.get("view")
        if type(candidate) is not str or candidate not in _STATUS_VIEWS:
            raise ProtocolValueError("invalid_json_pointer")
        status_view = candidate
    event_selector = _publish_event_selector(result, segments) if method == "publish_work" else None

    shape = tuple(
        None if is_array else segment
        for segment, is_array in zip(segments, array_segments, strict=True)
    )
    classification = _classify_leaf_shape(method, status_view, event_selector, shape)
    if classification is None:
        raise ProtocolValueError("invalid_json_pointer")
    return classification
