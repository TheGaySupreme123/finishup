"""Typed event payloads, draft values, and accepted ledger records."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Annotated, Final, Literal, cast

from pydantic import Field, ValidationError

from finishup.domain.coordination import (
    CoordinationDisposition,
    CoordinationGapCode,
    LineageAcceptance,
    LineageOrigin,
    OverlapKind,
    ProjectTextRef,
    SessionHealth,
    WorkState,
    project_id,
)
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    MAX_RECORDED_VERDICTS,
    RESPONSE_V1_1_DISPOSITIONS,
    CheckVerdict,
    Finding,
    FindingKind,
    FindingOrigin,
    PriorFindingVerdictRecord,
    ResponseDisposition,
    SemanticDispatchKind,
    SemanticProvenance,
    WaiverScope,
    finding_event_from_json,
    finding_event_to_json,
    finding_has_dialogue_fields,
    semantic_provenance_from_json,
    semantic_provenance_to_json,
)
from finishup.domain.receipts import SEMANTIC_REVIEW_ITEM_WITHHELD_GAP, ReceiptConclusion
from finishup.domain.values import (
    ActionId,
    Actor,
    ActorId,
    ActorType,
    ClaimId,
    EventId,
    EvidenceId,
    FindingId,
    Frontier,
    JsonObject,
    JsonValue,
    ObjectId,
    ObligationId,
    ReceiptId,
    RequestId,
    ResultId,
    SessionId,
    SubjectStateRef,
    TaskId,
    Timestamp,
    WriterId,
    action_id,
    actor_id,
    claim_id,
    event_id,
    evidence_id,
    finding_id,
    freeze_json,
    frontier_from_json,
    object_id,
    obligation_id,
    parse_wire_sequence,
    receipt_id,
    render_wire_sequence,
    request_id,
    result_id,
    session_id,
    task_id,
    timestamp_from_string,
    validate_commitment,
    validate_sha256_digest,
    writer_id,
)
from finishup.protocol.canonical import JsonValue as CanonicalJsonValue
from finishup.protocol.canonical import canonical_digest, ensure_canonical_set
from finishup.protocol.canonical import entry_digest as compute_entry_digest
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    Coverage,
    EvidenceImmutability,
    PublicationChannel,
    coverage_from_json,
    coverage_to_json,
)
from finishup.protocol.errors import (
    ADMITTED_CLAIM_REVISION_INVARIANTS,
    ProtocolValueError,
    PublicErrorCode,
    PublicOperationError,
)
from finishup.protocol.ids import validate_opaque_item_id
from finishup.protocol.models import (
    MAX_MISSING_FOR_ASSESSMENT,
    MAX_MISSING_TARGET_REFS,
    MAX_REVIEW_FOLLOW_UP_ROUNDS,
    MAX_TASK_STATEMENT_BYTES,
    MISSING_FOR_ASSESSMENT_KINDS,
    MISSING_ITEM_AVAILABILITIES,
    CheckPolicyExecutionModel,
    CheckScopeModel,
    ClientKind,
    IntegrationKind,
    LineageProvenanceRestriction,
    LineageReadGapReason,
    ReceiptRedactionProfile,
    SemanticReason,
    SemanticStatus,
    validate_semantic_provenance_binding,
)
from finishup.protocol.policy_packs import (
    COORDINATION_POLICY_ID,
    POLICY_PACK_GENERATIONS,
    RESEARCH_EVIDENCE_POLICY_ID,
    WORK_INTEGRITY_POLICY_ID,
    is_recorded_policy_identity,
)
from finishup.protocol.recovery import correction_for_invariant
from finishup.protocol.redacted_values import (
    SemanticRedactedValue,
    semantic_redacted_values_from_wire,
    validate_semantic_redacted_values,
)

__all__ = [
    "EVENT_FAMILIES",
    "MAX_ALTERNATIVES",
    "MAX_CAUSAL_PARENTS",
    "MAX_LABEL_BYTES",
    "MAX_REASON_BYTES",
    "MAX_REF_LIST",
    "MAX_REQUESTED_ITEMS",
    "MAX_TASK_STATEMENT_BYTES",
    "MAX_SEMANTIC_INCLUDED_REFS",
    "MAX_TEXT_BYTES",
    "OBSERVATION_COORDINATOR_ACTOR_ID",
    "PAYLOAD_TYPES",
    "CLAIM_SCHEMA_VERSION",
    "COORDINATION_EVENT_SCHEMA_VERSION",
    "SCHEMA_VERSION",
    "SEMANTIC_INCLUDED_REFS_NOT_RECORDED_GAP",
    "SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP",
    "EVIDENCE_SCHEMA_VERSION",
    "EVIDENCE_SCHEMA_VERSIONS",
    "EVIDENCE_TYPED_SCHEMA_VERSION",
    "LINEAGE_EVENT_SCHEMA_VERSION",
    "LINEAGE_SESSION_EVENT_SCHEMA_VERSION",
    "LINEAGE_SERVICE_STAMPED_FAMILIES",
    "AcceptedEvent",
    "ActionKind",
    "ActionRecordedPayload",
    "AssignmentRecordedPayload",
    "CheckMode",
    "MissingForAssessmentItem",
    "CheckChangePartialFile",
    "CheckChangeShownFiles",
    "CheckRecordedPayload",
    "MAX_CHECK_CHANGE_RAISED_FILES",
    "MAX_CHECK_CHANGE_SHOWN_BYTES",
    "MAX_CHECK_CHANGE_SHOWN_FILES",
    "check_change_files_from_json",
    "check_change_files_to_json",
    "ClaimKind",
    "ClaimRecordedPayload",
    "ClaimRecordedPayloadV1_1",
    "ChildDependenciesRecordedPayload",
    "ChildDependencySnapshot",
    "ChildFindingSnapshot",
    "CoordinationContextRecordedPayload",
    "CoordinationObligationDeclaredPayload",
    "CoordinationDisposition",
    "CoordinationDispositionRecordedPayload",
    "CoordinationGapCode",
    "ClaimRevisionMismatch",
    "ClientKind",
    "CHECK_REVIEW_MODE_LOCAL_REASONS",
    "CHECK_REVIEW_MODE_SOURCES",
    "CheckReviewMode",
    "DECISION_REVIEW_MODE_SCHEMA_VERSION",
    "DecisionRecordedPayload",
    "DelegationCancelledPayload",
    "DelegationDeclaredPayload",
    "EventDraft",
    "EventPayload",
    "EventSchema",
    "OCCURRED_AT_DRAFT_DESCRIPTION",
    "EvidenceKind",
    "EvidenceContentAvailability",
    "EvidenceDigestBinding",
    "EvidenceDigestProvenance",
    "EvidenceDigestSubject",
    "EvidenceRecordedPayload",
    "FindingRecordedPayload",
    "FINDING_EVENT_SCHEMA_VERSION",
    "FINDING_SNIPPET_EVENT_SCHEMA_VERSION",
    "IntegrationKind",
    "LedgerChain",
    "LedgerRecord",
    "is_observation_authored",
    "is_observation_authorship",
    "is_lineage_service_stamped",
    "ObligationChange",
    "ObligationChangeKind",
    "NoObligationsReason",
    "NoObligationsReasonMismatch",
    "ObligationPublishedPayload",
    "ObligationResolutionMismatch",
    "ObligationStatus",
    "ReviewMode",
    "obligation_meaning_field_diffs",
    "public_error_for_obligation_resolution_mismatch",
    "public_error_for_no_obligations_reason_mismatch",
    "public_error_for_claim_revision_mismatch",
    "PayloadRef",
    "PlanPublishedPayload",
    "PlanRevisedPayload",
    "PolicyVersion",
    "ProjectionLocator",
    "ReceiptRecordedPayload",
    "RedactionMethod",
    "RedactionReasonCategory",
    "RedactionRecordedPayload",
    "RedactionState",
    "RequestedItem",
    "RequestedItemKind",
    "RequestedItemRole",
    "ResponseRecordedPayload",
    "ResultOutcome",
    "ResultRecordedPayload",
    "RuntimeProfile",
    "RESPONSE_EVENT_SCHEMA_VERSION",
    "OBLIGATION_BASE_SCHEMA_VERSION",
    "OBLIGATION_SCHEMA_VERSION",
    "SESSION_EVENT_SCHEMA_VERSION",
    "TASK_STATEMENT_EVENT_SCHEMAS",
    "TASK_STATEMENT_PLAN_SCHEMA_VERSION",
    "TASK_STATEMENT_SESSION_OPENED_SCHEMA_VERSION",
    "TASK_STATEMENT_SESSION_RESUMED_SCHEMA_VERSION",
    "SessionOpenedPayload",
    "SessionResumedPayload",
    "ChildAcceptedPayload",
    "ChildRejectedPayload",
    "ChildWrittenOffPayload",
    "WorkAbandonedPayload",
    "WorkCancelledPayload",
    "WorkClosedPayload",
    "WorkWrittenOffPayload",
    "UnknownEvent",
    "WritePolicy",
    "WriterChain",
    "accepted_record_digest_preimage",
    "accepted_record_to_json",
    "decode_payload",
    "encode_payload",
    "media_type_for",
    "normalize_payload_json",
    "obligation_schema_admits",
    "obligation_schema_version",
]

OBSERVATION_COORDINATOR_ACTOR_ID: Final = "yoetz:observation-coordinator"

SCHEMA_VERSION: Final = "1.0.0"
EVIDENCE_SCHEMA_VERSION: Final = "1.2.0"
EVIDENCE_TYPED_SCHEMA_VERSION: Final = "1.1.0"
EVIDENCE_SCHEMA_VERSIONS: Final = (
    SCHEMA_VERSION,
    EVIDENCE_TYPED_SCHEMA_VERSION,
    EVIDENCE_SCHEMA_VERSION,
)
CLAIM_SCHEMA_VERSION: Final = "1.1.0"
# ``obligation_published`` 1.0.0 is released and frozen. 1.1.0 (issue #1002) admits the
# ``directory`` requested-item kind, the optional per-item ``role`` (``input``/``output``, on ``file``
# and ``directory`` items only) and the ``acknowledged_not_done`` status with its required reason.
# 1.0.0 refuses those; 1.1.0 is a superset and also admits a payload without them (tb4n2 R3,
# issue #1023: agents copied the 1.1.0 template onto plain obligations and 24/28 attempts were
# refused). ``obligation_schema_admits`` is that single rule and ``obligation_schema_version`` the
# single writer choice (1.1.0 iff one of those is present), so every FinishUP-drafted obligation
# without them keeps its exact 1.0.0 bytes and old ledgers replay unchanged.
OBLIGATION_SCHEMA_VERSION: Final = "1.1.0"
# ``decision_recorded`` 1.0.0 is released and frozen. 1.1.0 is an additive superset that admits
# one optional ``review_mode`` (ADR-049): the conversation's switch between local checks only
# (``local``) and AI-powered review (``ai_powered``). A decision rides 1.1.0 iff it carries the
# switch, so every other decision keeps its released 1.0.0 bytes and old ledgers replay unchanged.
DECISION_REVIEW_MODE_SCHEMA_VERSION: Final = "1.1.0"
OBLIGATION_BASE_SCHEMA_VERSION: Final = "1.0.0"
# 1.3.0 (unreleased on the 0.3 line) also carries the optional per-finding reviewer rulings of
# issue #905; a check without rulings keeps its earlier 1.3.0 bytes.
CHECK_EVENT_SCHEMA_VERSION: Final = "1.3.0"
# 1.4.0 adds the verifying-reviewer summary and per-requirement judgements. Older check records
# remain byte-identical and decode with these fields absent.
REVIEW_CHECK_EVENT_SCHEMA_VERSION: Final = "1.4.0"
SEMANTIC_EVENT_SCHEMA_VERSION: Final = "1.2.0"
SEMANTIC_EVENT_SCHEMA_VERSIONS: Final = ("1.1.0", SEMANTIC_EVENT_SCHEMA_VERSION)
# 1.3.0 (unreleased on the 0.3 line) also admits the optional review-dialogue fields of issue #905
# (the persisted challenge fields and the ``relates_to`` link) on AI-powered findings; a finding
# without them keeps its earlier 1.3.0 bytes.
FINDING_EVENT_SCHEMA_VERSION: Final = "1.3.0"
FINDING_SNIPPET_EVENT_SCHEMA_VERSION: Final = "1.4.0"
# ``response_recorded`` 1.0.0 is released and frozen. 1.1.0 exists only to admit the terminal
# ``acknowledged_not_done`` (issue #905), ``self_verified`` (issue #984) and ``duplicate_of``
# (issue #996, with its ``duplicate_of_finding_id``) dispositions; every other disposition keeps
# 1.0.0 bytes, so the version is a pure function of the payload and old
# ledgers replay unchanged.
RESPONSE_EVENT_SCHEMA_VERSION: Final = "1.1.0"
COORDINATION_EVENT_SCHEMA_VERSION: Final = "1.0.0"
SESSION_EVENT_SCHEMA_VERSION: Final = "1.1.0"
# Lineage fields are additive to the original event families.  The old session-opened schema
# remains frozen at 1.1.0; the 1.2.0 payload is selected only when a caller supplies the lineage
# metadata.  The lifecycle and manifest families are new 1.0.0 contracts.
LINEAGE_SESSION_EVENT_SCHEMA_VERSION: Final = "1.2.0"
LINEAGE_EVENT_SCHEMA_VERSION: Final = "1.0.0"
# The agent-transcribed task statement (issue #908) is additive to the session and plan families.
# Released schemas stay frozen; a new version is selected only when a statement is present, so a
# ledger that never carries one keeps its exact historical bytes. The unreleased session-opened
# 1.2.0 contract admits the statement as an optional field beside the lineage metadata.
TASK_STATEMENT_SESSION_OPENED_SCHEMA_VERSION: Final = LINEAGE_SESSION_EVENT_SCHEMA_VERSION
TASK_STATEMENT_SESSION_RESUMED_SCHEMA_VERSION: Final = "1.2.0"
TASK_STATEMENT_PLAN_SCHEMA_VERSION: Final = "1.1.0"
LINEAGE_SERVICE_STAMPED_FAMILIES: Final = frozenset(
    {
        "coordination_context_recorded",
        "delegation_declared",
        "child_dependencies_recorded",
        "work_abandoned",
    }
)
MAX_TEXT_BYTES: Final = 8_192
MAX_REASON_BYTES: Final = 4_096
MAX_LABEL_BYTES: Final = 256
MAX_REF_LIST: Final = 64
MAX_CAUSAL_PARENTS: Final = 32
MAX_REQUESTED_ITEMS: Final = 64
MAX_ALTERNATIVES: Final = 16
# The frontier references a reduced AI-powered review packet carried, recorded on its check (issue
# #904): one source per case item (at most 256), the combined parts of captured evidence excerpts
# (at most 64), and the one action, result, evidence, claim or obligation record each carried
# history event recorded (at most one per item). A valid sent set therefore never exceeds 576. The
# event that recorded a carried record is credited when a finding is resolved, never recorded here,
# so that aliasing cannot push a valid set past this bound (issue #947). A check whose set cannot
# be recorded carries SEMANTIC_INCLUDED_REFS_NOT_RECORDED_GAP instead, and its reduced scope keeps
# blocking resolution.
MAX_SEMANTIC_INCLUDED_REFS: Final = 576
# How many of a finding's subject refs its prior-finding row lists to a later reviewer, in the
# finding's own canonical order (issues #905, #947). Shared by the case builder that writes the row
# and the kernel rule that credits a subject the row listed.
MAX_PRIOR_FINDING_LISTED_REFS: Final = 8
SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP: Final = "semantic_reference_scope_reduced"
SEMANTIC_INCLUDED_REFS_NOT_RECORDED_GAP: Final = "semantic_included_refs_not_recorded"

_MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991
_MAX_SQLITE_INTEGER: Final = 9_223_372_036_854_775_807
_MAX_OBJECT_PLAINTEXT_BYTES: Final = 4_194_304
_MAX_FINDINGS_LIMIT: Final = 10
_SCHEMA_NAME_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)
_SEMVER_RE: Final = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$",
    re.ASCII,
)
# Frozen legacy identifier (ADR-048): recorded payload media types keep the protocol 0.1
# ``vnd.yoetz`` namespace, which sits inside every entry digest.
_MEDIA_TYPE_RE: Final = re.compile(
    r"^application/vnd\.yoetz\.[a-z][a-z0-9_]{0,63}\+json$",
    re.ASCII,
)

EVENT_FAMILIES: Final = (
    "session_opened",
    "session_resumed",
    "plan_published",
    "obligation_published",
    "assignment_recorded",
    "decision_recorded",
    "action_recorded",
    "result_recorded",
    "evidence_recorded",
    "claim_recorded",
    "plan_revised",
    "finding_recorded",
    "response_recorded",
    "redaction_recorded",
    "check_recorded",
    "receipt_recorded",
    "delegation_declared",
    "delegation_cancelled",
    "child_accepted",
    "child_rejected",
    "child_written_off",
    "child_dependencies_recorded",
    "coordination_context_recorded",
    "coordination_obligation_declared",
    "coordination_disposition_recorded",
    "work_closed",
    "work_abandoned",
    "work_cancelled",
    "work_written_off",
)


class RuntimeProfile(str, Enum):  # noqa: UP042 - exact wire enum base
    STRICT_LOCAL = "strict-local"
    LOCAL_OPENAI = "local-openai"
    CODEX_SUBSCRIPTION = "codex-subscription"
    TEST_FAKE = "test-fake"
    RELEASE_PROBE = "release-probe"


class RequestedItemKind(str, Enum):  # noqa: UP042 - exact wire enum base
    URL = "url"
    FILE = "file"
    COMMAND = "command"
    CHANGE = "change"
    SOURCE = "source"
    # obligation_published 1.1.0 only (issue #1002): a directory the request names.
    DIRECTORY = "directory"


class RequestedItemRole(str, Enum):  # noqa: UP042 - exact wire enum base
    """Whether a requested file or directory is read by the task or delivered by it (#1002)."""

    INPUT = "input"
    OUTPUT = "output"


class ObligationStatus(str, Enum):  # noqa: UP042 - exact wire enum base
    OPEN = "open"
    RESOLVED = "resolved"
    # ``obligation_published`` 1.1.0 only (issue #997, ADR-032 slice C): the agent will not do
    # this obligation and says why. Not open, not resolved; disclosed as not done.
    ACKNOWLEDGED_NOT_DONE = "acknowledged_not_done"


class ReviewMode(str, Enum):  # noqa: UP042 - exact wire enum base
    """A conversation's review mode, switched by ``decision_recorded`` 1.1.0 (ADR-049).

    ``local`` is FinishUP's local checks only; ``ai_powered`` asks for AI-powered review under the
    owner's standing privacy policy. The switch is a request: it never grants disclosure.
    """

    LOCAL = "local"
    AI_POWERED = "ai_powered"


class NoObligationsReason(str, Enum):  # noqa: UP042 - exact wire enum base
    NO_MATERIAL_CHANGE = "no_material_change"
    SINGLE_ATOMIC_CHANGE = "single_atomic_change"
    EXPLORATORY_SCOPE_UNKNOWN = "exploratory_scope_unknown"


class WritePolicy(str, Enum):  # noqa: UP042 - exact wire enum base
    READ_ONLY = "read_only"
    WRITES_ALLOWED = "writes_allowed"


class ActionKind(str, Enum):  # noqa: UP042 - exact wire enum base
    COMMAND = "command"
    EDIT = "edit"
    RESEARCH = "research"
    REVIEW = "review"
    OTHER = "other"


class ResultOutcome(str, Enum):  # noqa: UP042 - exact wire enum base
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class EvidenceKind(str, Enum):  # noqa: UP042 - exact wire enum base
    ARTIFACT = "artifact"
    COMMAND_OUTPUT = "command_output"
    TEST_RESULT = "test_result"
    RESEARCH_SOURCE = "research_source"
    IMPORT_REPORT = "import_report"
    OTHER = "other"


class EvidenceDigestSubject(str, Enum):  # noqa: UP042 - exact wire enum base
    APPROVED_CHECK_RECEIPT = "approved_check_receipt"
    ARTIFACT_BYTES = "artifact_bytes"
    BOUNDED_EXCERPT = "bounded_excerpt"
    COMMAND_STDOUT = "command_stdout"
    IMPORT_REPORT = "import_report"
    SOURCE_DIFF = "source_diff"
    STATIC_ANALYSIS_REPORT = "static_analysis_report"
    TEST_REPORT = "test_report"
    TEST_STDOUT = "test_stdout"


class EvidenceContentAvailability(str, Enum):  # noqa: UP042 - exact wire enum base
    CAPTURED = "captured"
    DIGEST_ONLY = "digest_only"
    WITHHELD = "withheld"


class EvidenceDigestProvenance(str, Enum):  # noqa: UP042 - exact wire enum base
    APPROVED_CHECK = "approved_check"
    CALLER_ASSERTED = "caller_asserted"
    IMPORT_OBSERVED = "import_observed"
    OBSERVATION_CAPTURED = "observation_captured"


class ClaimKind(str, Enum):  # noqa: UP042 - exact wire enum base
    COMPLETION = "completion"
    MATERIAL = "material"


class ObligationChangeKind(str, Enum):  # noqa: UP042 - exact wire enum base
    SUPERSEDED = "superseded"
    WAIVED = "waived"
    CARRIED = "carried"


class RedactionMethod(str, Enum):  # noqa: UP042 - exact wire enum base
    LOGICAL_REDACTION = "logical_redaction"
    OBJECT_DELETION = "object_deletion"


class RedactionReasonCategory(str, Enum):  # noqa: UP042 - exact wire enum base
    SECRET = "secret"
    PRIVACY = "privacy"
    RETENTION = "retention"
    LEGAL = "legal"
    OTHER = "other"


class CheckMode(str, Enum):  # noqa: UP042 - exact wire enum base
    DETERMINISTIC_ONLY = "deterministic_only"
    SEMANTIC_IF_CONFIGURED = "semantic_if_configured"
    SEMANTIC_REQUIRED = "semantic_required"


class RedactionState(str, Enum):  # noqa: UP042 - exact wire enum base
    PRESENT = "present"
    LOGICALLY_REDACTED = "logically_redacted"
    KEY_UNAVAILABLE = "key_unavailable"
    ERASED_CLAIMED = "erased_claimed"


def _bounded_text(value: object, maximum: int, *, minimum: int = 0) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        raise ProtocolValueError("event_text_out_of_bounds")
    freeze_json(value)
    return str.__getitem__(value, slice(None))


def _task_statement(value: object) -> str:
    """Bound one recorded task statement by UTF-8 bytes, never by characters."""

    text = _bounded_text(value, MAX_TASK_STATEMENT_BYTES, minimum=1)
    if len(text.encode("utf-8")) > MAX_TASK_STATEMENT_BYTES:
        raise ProtocolValueError("event_text_out_of_bounds")
    return text


def _exact_enum[T: Enum](value: object, enum_type: type[T]) -> T:
    if type(value) is not enum_type:
        raise ProtocolValueError("invalid_event_enum")
    return cast(T, value)


def _enum_from_json[T: Enum](value: object, enum_type: type[T]) -> T:
    if type(value) is not str:
        raise ProtocolValueError("invalid_event_enum")
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ProtocolValueError("invalid_event_enum") from exc


def _bounded_integer(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProtocolValueError("event_integer_out_of_range")
    return value


def _tuple(value: object, minimum: int, maximum: int) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise ProtocolValueError("invalid_event_value_type")
    items = cast(tuple[object, ...], value)
    if not minimum <= len(items) <= maximum:
        raise ProtocolValueError("invalid_event_value_type")
    return items


def _validate_ascii_sorted_unique(values: tuple[str, ...], *, field: str | None = None) -> None:
    """Enforce the canonical set form, naming the owning field so a rejection is actionable.

    ``field`` is a frozen payload field name from this module, never caller data. A non-ASCII
    member is its own reason: reporting it as unsorted sent agents hunting for an ordering bug
    that was not there.
    """

    previous: bytes | None = None
    for value in values:
        try:
            encoded = value.encode("ascii", errors="strict")
        except UnicodeEncodeError as exc:
            raise ProtocolValueError("set_member_not_ascii", field=field) from exc
        if previous is not None:
            if encoded == previous:
                raise ProtocolValueError("duplicate_set_member", field=field)
            if encoded < previous:
                raise ProtocolValueError("unsorted_set_field", field=field)
        previous = encoded


def _id_tuple[T](
    value: object,
    constructor: Callable[[object], T],
    *,
    minimum: int = 0,
    maximum: int = MAX_REF_LIST,
    field: str | None = None,
) -> tuple[T, ...]:
    raw = _tuple(value, minimum, maximum)
    validated = tuple(constructor(item) for item in raw)
    _validate_ascii_sorted_unique(cast(tuple[str, ...], validated), field=field)
    return validated


def _text_tuple(
    value: object,
    maximum_items: int,
    maximum_text: int,
    *,
    unique: bool = False,
) -> tuple[str, ...]:
    raw = _tuple(value, 0, maximum_items)
    result = tuple(_bounded_text(item, maximum_text) for item in raw)
    if unique and len(result) != len(set(result)):
        raise ProtocolValueError("duplicate_set_member")
    return result


_INCLUDED_REF_CONSTRUCTORS: Final[Mapping[str, Callable[[object], str]]] = MappingProxyType(
    {
        "act_": action_id,
        "clm_": claim_id,
        "evd_": evidence_id,
        "evt_": event_id,
        "fnd_": finding_id,
        "obl_": obligation_id,
        "res_": result_id,
    }
)


def _included_ref(value: object) -> str:
    """One typed ledger reference a review packet can carry; never free text."""

    if type(value) is not str:
        raise ProtocolValueError("invalid_event_value_type")
    constructor = _INCLUDED_REF_CONSTRUCTORS.get(value[:4])
    if constructor is None:
        raise ProtocolValueError("invalid_event_value_type")
    return constructor(value)


def _valid_opaque_item_id(value: object) -> bool:
    try:
        validate_opaque_item_id(value)
    except ProtocolValueError:
        return False
    return True


def _evidence_result_ref(value: object) -> EvidenceId | ResultId:
    if type(value) is not str:
        raise ProtocolValueError("invalid_event_value_type")
    if value.startswith("evd_"):
        return evidence_id(value)
    if value.startswith("res_"):
        return result_id(value)
    raise ProtocolValueError("invalid_event_value_type")


def _evidence_result_tuple(
    value: object,
    *,
    minimum: int = 0,
    maximum: int = MAX_REF_LIST,
    field: str | None = None,
) -> tuple[EvidenceId | ResultId, ...]:
    raw = _tuple(value, minimum, maximum)
    result = tuple(_evidence_result_ref(item) for item in raw)
    _validate_ascii_sorted_unique(cast(tuple[str, ...], result), field=field)
    return result


def _claim_supporting_ref(value: object) -> EvidenceId | ResultId | ObligationId:
    if type(value) is not str:
        raise ProtocolValueError("invalid_event_value_type")
    if value.startswith("evd_"):
        return evidence_id(value)
    if value.startswith("res_"):
        return result_id(value)
    if value.startswith("obl_"):
        return obligation_id(value)
    raise ProtocolValueError("invalid_event_value_type")


def _claim_dispute_ref(value: object) -> ClaimId | EventId:
    if type(value) is not str:
        raise ProtocolValueError("invalid_event_value_type")
    if value.startswith("clm_"):
        return claim_id(value)
    if value.startswith("evt_"):
        return event_id(value)
    raise ProtocolValueError("invalid_event_value_type")


def _subject_state(value: object) -> SubjectStateRef:
    if type(value) is not SubjectStateRef:
        raise ProtocolValueError("invalid_event_value_type")
    return value


def _frontier(value: object) -> Frontier:
    if type(value) is not Frontier:
        raise ProtocolValueError("invalid_frontier")
    return value


def _timestamp(value: object) -> Timestamp:
    if type(value) is not Timestamp:
        raise ProtocolValueError("invalid_timestamp")
    return value


_LINEAGE_REVISION_MAX: Final = _MAX_SAFE_INTEGER
_LINEAGE_TOKEN_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]{0,255}$", re.ASCII)


def _lineage_revision(value: object) -> int:
    """Validate the service-owned lineage revision as a bounded monotonic counter."""

    if type(value) is int:
        return _bounded_integer(value, 1, _LINEAGE_REVISION_MAX)
    # Wire events use the repository's canonical integer spelling.  Decoding accepts only that
    # spelling and immediately restores the domain integer, so an integer and its wire spelling
    # cannot produce two different manifest identities.
    if type(value) is str:
        try:
            parsed = parse_wire_sequence(value)
        except (TypeError, ValueError, ProtocolValueError) as exc:
            raise ProtocolValueError("invalid_event_value_type") from exc
        return _bounded_integer(parsed, 1, _LINEAGE_REVISION_MAX)
    raise ProtocolValueError("invalid_event_value_type")


def _canonical_uint(value: object) -> int:
    """Decode one canonical nonnegative integer used by current coordination wire fields."""

    if type(value) is int:
        return _bounded_integer(value, 0, _LINEAGE_REVISION_MAX)
    if type(value) is str:
        try:
            parsed = parse_wire_sequence(value)
        except (TypeError, ValueError, ProtocolValueError) as exc:
            raise ProtocolValueError("invalid_event_value_type") from exc
        if str(parsed) != value:
            raise ProtocolValueError("invalid_event_value_type")
        return _bounded_integer(parsed, 0, _LINEAGE_REVISION_MAX)
    raise ProtocolValueError("invalid_event_value_type")


def _lineage_token(value: object) -> str:
    if type(value) is not str or _LINEAGE_TOKEN_RE.fullmatch(value) is None:
        raise ProtocolValueError("invalid_event_value_type")
    return value


def _lineage_enum_tuple[T: Enum](
    value: object,
    enum_type: type[T],
    *,
    maximum: int,
    field: str,
) -> tuple[T, ...]:
    raw = _tuple(value, 0, maximum)
    result = tuple(_exact_enum(item, enum_type) for item in raw)
    _validate_ascii_sorted_unique(
        tuple(cast(str, member.value) for member in result),
        field=field,
    )
    return result


@dataclass(frozen=True, slots=True)
class RequestedItem:
    item_kind: RequestedItemKind
    value: str
    # obligation_published 1.1.0 only. ``None`` keeps the 1.0.0 meaning: a ``file`` item may be an
    # input or an output.
    role: RequestedItemRole | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "item_kind", _exact_enum(self.item_kind, RequestedItemKind))
        object.__setattr__(self, "value", _bounded_text(self.value, 1_024))
        if self.role is not None:
            object.__setattr__(self, "role", _exact_enum(self.role, RequestedItemRole))

        if self.role is not None and self.item_kind not in {
            RequestedItemKind.FILE,
            RequestedItemKind.DIRECTORY,
        }:
            # A role says whether a path is read or delivered; no other kind names a path.
            raise ProtocolValueError("invalid_event_value_type")

    @property
    def requires_obligation_v1_1(self) -> bool:
        """Whether only ``obligation_published`` 1.1.0 can carry this item."""

        return self.role is not None or self.item_kind is RequestedItemKind.DIRECTORY


@dataclass(frozen=True, slots=True)
class ObligationChange:
    obligation_id: ObligationId
    change: ObligationChangeKind
    reason: str | None = None
    replacement_obligation_ids: tuple[ObligationId, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "obligation_id", obligation_id(self.obligation_id))
        change = _exact_enum(self.change, ObligationChangeKind)
        object.__setattr__(self, "change", change)
        if self.reason is not None:
            object.__setattr__(
                self, "reason", _bounded_text(self.reason, MAX_REASON_BYTES, minimum=1)
            )
        replacements = _id_tuple(
            self.replacement_obligation_ids,
            obligation_id,
            maximum=8,
            field="replacement_obligation_ids",
        )
        object.__setattr__(self, "replacement_obligation_ids", replacements)
        if change in {ObligationChangeKind.SUPERSEDED, ObligationChangeKind.WAIVED}:
            if self.reason is None:
                raise ProtocolValueError("obligation_change_invalid")
        if change is not ObligationChangeKind.SUPERSEDED and replacements:
            raise ProtocolValueError("obligation_change_invalid")


@dataclass(frozen=True, slots=True)
class PolicyVersion:
    policy_id: str
    policy_version: str

    def __post_init__(self) -> None:
        policy_id_value = _bounded_text(self.policy_id, 128, minimum=1)
        # Earlier pack versions stay decodable: a recorded check keeps the identity it ran.
        if not is_recorded_policy_identity(policy_id_value, self.policy_version):
            raise ProtocolValueError("invalid_event_value_type")
        object.__setattr__(self, "policy_id", policy_id_value)


@dataclass(frozen=True, slots=True)
class EventSchema:
    name: str
    version: str

    def __post_init__(self) -> None:
        name = _bounded_text(self.name, 64, minimum=1)
        version = _bounded_text(self.version, 64, minimum=5)
        if _SCHEMA_NAME_RE.fullmatch(name) is None or _SEMVER_RE.fullmatch(version) is None:
            raise ProtocolValueError("invalid_event_schema")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "version", version)


@dataclass(frozen=True, slots=True)
class WriterChain:
    writer_id: WriterId
    sequence: int
    previous_entry_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "writer_id", writer_id(self.writer_id))
        if type(self.sequence) is not int or not 1 <= self.sequence <= _MAX_SQLITE_INTEGER:
            raise ProtocolValueError("invalid_chain")
        if self.sequence == 1:
            if (
                type(self.previous_entry_digest) is not str
                or self.previous_entry_digest != "genesis"
            ):
                raise ProtocolValueError("invalid_chain")
        else:
            validate_sha256_digest(self.previous_entry_digest)


@dataclass(frozen=True, slots=True)
class LedgerChain:
    ingestion_sequence: int
    previous_entry_digest: str
    accepted_at: Timestamp

    def __post_init__(self) -> None:
        if (
            type(self.ingestion_sequence) is not int
            or not 1 <= self.ingestion_sequence <= _MAX_SQLITE_INTEGER
        ):
            raise ProtocolValueError("invalid_chain")
        if self.ingestion_sequence == 1:
            if (
                type(self.previous_entry_digest) is not str
                or self.previous_entry_digest != "genesis"
            ):
                raise ProtocolValueError("invalid_chain")
        else:
            validate_sha256_digest(self.previous_entry_digest)
        _timestamp(self.accepted_at)


@dataclass(frozen=True, slots=True)
class PayloadRef:
    object_id: ObjectId
    media_type: str
    plaintext_size: int
    commitment: str
    encryption_format: Literal["yoetz-object/1"] = "yoetz-object/1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "object_id", object_id(self.object_id))
        if type(self.media_type) is not str or not 1 <= len(self.media_type) <= 91:
            raise ProtocolValueError("invalid_payload_ref")
        if _MEDIA_TYPE_RE.fullmatch(self.media_type) is None:
            raise ProtocolValueError("invalid_payload_ref")
        if (
            type(self.plaintext_size) is not int
            or not 0 <= self.plaintext_size <= _MAX_OBJECT_PLAINTEXT_BYTES
        ):
            raise ProtocolValueError("invalid_payload_ref")
        validate_commitment(self.commitment)
        if type(self.encryption_format) is not str or self.encryption_format != "yoetz-object/1":
            raise ProtocolValueError("invalid_payload_ref")


def _locator_key_kind(schema: EventSchema) -> str:
    if schema.name not in EVENT_FAMILIES:
        return "none"
    additive = (
        schema == EventSchema("claim_recorded", CLAIM_SCHEMA_VERSION)
        # Role- and directory-bearing obligations project as the same obligation (issue #1002).
        or schema == EventSchema("obligation_published", OBLIGATION_SCHEMA_VERSION)
        # A decision carrying a review-mode switch projects as the same decision (ADR-049).
        or schema == EventSchema("decision_recorded", DECISION_REVIEW_MODE_SCHEMA_VERSION)
        # A plan carrying a revised task statement projects as the same plan (issue #908).
        or schema
        in {
            EventSchema("plan_published", TASK_STATEMENT_PLAN_SCHEMA_VERSION),
            EventSchema("plan_revised", TASK_STATEMENT_PLAN_SCHEMA_VERSION),
        }
        or (schema.name == "evidence_recorded" and schema.version in EVIDENCE_SCHEMA_VERSIONS)
        or (
            schema.name in {"check_recorded", "finding_recorded"}
            and (
                schema.version in SEMANTIC_EVENT_SCHEMA_VERSIONS
                or (
                    schema.name == "check_recorded"
                    and schema.version
                    in {CHECK_EVENT_SCHEMA_VERSION, REVIEW_CHECK_EVENT_SCHEMA_VERSION}
                )
                or (
                    schema.name == "finding_recorded"
                    and schema.version
                    in {FINDING_EVENT_SCHEMA_VERSION, FINDING_SNIPPET_EVENT_SCHEMA_VERSION}
                )
            )
        )
        or schema == EventSchema("response_recorded", RESPONSE_EVENT_SCHEMA_VERSION)
    )
    if schema.version != SCHEMA_VERSION and not additive:
        return "none"
    schema_name = schema.name
    if schema_name in {"plan_published", "plan_revised"}:
        return "plan"
    if schema_name in {"assignment_recorded", "decision_recorded", "check_recorded"}:
        return "event"
    if schema_name == "obligation_published":
        return "obligation"
    if schema_name == "action_recorded":
        return "action"
    if schema_name == "result_recorded":
        return "result"
    if schema_name == "evidence_recorded":
        return "evidence"
    if schema_name == "claim_recorded":
        return "claim"
    if schema_name in {"finding_recorded", "response_recorded"}:
        return "finding"
    return "none"


@dataclass(frozen=True, slots=True)
class ProjectionLocator:
    schema: EventSchema
    logical_key: str | None
    canonical_payload_digest: str
    redaction_target_event_ids: tuple[EventId, ...] = ()
    redaction_target_object_ids: tuple[ObjectId, ...] = ()

    def __post_init__(self) -> None:
        if type(self.schema) is not EventSchema:
            raise ProtocolValueError("invalid_projection_locator")
        validate_sha256_digest(self.canonical_payload_digest)
        try:
            raw_events = _tuple(self.redaction_target_event_ids, 0, MAX_REF_LIST)
            raw_objects = _tuple(self.redaction_target_object_ids, 0, MAX_REF_LIST)
        except ProtocolValueError as exc:
            raise ProtocolValueError("invalid_projection_locator") from exc
        events = tuple(event_id(item) for item in raw_events)
        objects = tuple(object_id(item) for item in raw_objects)
        _validate_ascii_sorted_unique(
            cast(tuple[str, ...], events), field="redaction_target_event_ids"
        )
        _validate_ascii_sorted_unique(
            cast(tuple[str, ...], objects), field="redaction_target_object_ids"
        )
        object.__setattr__(self, "redaction_target_event_ids", events)
        object.__setattr__(self, "redaction_target_object_ids", objects)
        key_kind = _locator_key_kind(self.schema)
        if key_kind == "none":
            if self.logical_key is not None:
                raise ProtocolValueError("invalid_projection_locator")
        else:
            if type(self.logical_key) is not str:
                raise ProtocolValueError("invalid_projection_locator")
            if key_kind == "plan":
                if not self.logical_key.isascii() or not self.logical_key.isdecimal():
                    raise ProtocolValueError("invalid_projection_locator")
                parsed_key = int(self.logical_key)
                if not 1 <= parsed_key <= _MAX_SAFE_INTEGER or str(parsed_key) != self.logical_key:
                    raise ProtocolValueError("invalid_projection_locator")
            else:
                constructors: Mapping[str, Callable[[object], object]] = {
                    "event": event_id,
                    "obligation": obligation_id,
                    "action": action_id,
                    "result": result_id,
                    "evidence": evidence_id,
                    "claim": claim_id,
                    "finding": finding_id,
                }
                constructors[key_kind](self.logical_key)
        if self.schema == EventSchema("redaction_recorded", SCHEMA_VERSION):
            if not events and not objects:
                raise ProtocolValueError("invalid_projection_locator")
        elif events or objects:
            raise ProtocolValueError("invalid_projection_locator")


@dataclass(frozen=True, slots=True)
class SessionOpenedPayload:
    task_title: str
    client_kind: ClientKind
    client_version: str
    integration: IntegrationKind
    profile: RuntimeProfile
    external_ref: str | None = None
    workspace_ref: str | None = None
    parent_task_id: TaskId | None = None
    depth: int | None = None
    origin: LineageOrigin | None = None
    project_id: str | None = None
    membership_generation: int | None = None
    # The user's request as the agent transcribed it on ``start`` (issue #908). Optional and
    # separate from ``task_title``: the title names the task, the statement is the specification.
    task_statement: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "task_title", _bounded_text(self.task_title, MAX_TEXT_BYTES, minimum=1)
        )
        if self.task_statement is not None:
            object.__setattr__(self, "task_statement", _task_statement(self.task_statement))
        object.__setattr__(self, "client_kind", _exact_enum(self.client_kind, ClientKind))
        object.__setattr__(
            self,
            "client_version",
            _bounded_text(self.client_version, MAX_LABEL_BYTES, minimum=1),
        )
        object.__setattr__(self, "integration", _exact_enum(self.integration, IntegrationKind))
        object.__setattr__(self, "profile", _exact_enum(self.profile, RuntimeProfile))
        if self.external_ref is not None:
            object.__setattr__(
                self,
                "external_ref",
                _bounded_text(self.external_ref, MAX_TEXT_BYTES, minimum=1),
            )
        if self.workspace_ref is not None:
            object.__setattr__(
                self,
                "workspace_ref",
                _bounded_text(self.workspace_ref, MAX_TEXT_BYTES, minimum=1),
            )
        parent_task = None if self.parent_task_id is None else task_id(self.parent_task_id)
        object.__setattr__(self, "parent_task_id", parent_task)
        if self.depth is not None:
            object.__setattr__(self, "depth", _bounded_integer(self.depth, 1, 64))
        if self.origin is not None:
            object.__setattr__(self, "origin", _exact_enum(self.origin, LineageOrigin))
        lineage_values_present = (
            parent_task is not None or self.depth is not None or self.origin is not None
        )
        if lineage_values_present and (
            parent_task is None or self.depth is None or self.origin is None
        ):
            raise ProtocolValueError("session_lineage_fields_incomplete")
        project_value = None if self.project_id is None else project_id(self.project_id)
        object.__setattr__(self, "project_id", project_value)
        if self.membership_generation is not None:
            object.__setattr__(
                self,
                "membership_generation",
                _lineage_revision(self.membership_generation),
            )
        project_values_present = project_value is not None or self.membership_generation is not None
        if project_values_present and (project_value is None or self.membership_generation is None):
            raise ProtocolValueError("session_lineage_fields_incomplete")


@dataclass(frozen=True, slots=True)
class SessionResumedPayload:
    client_kind: ClientKind
    client_version: str
    integration: IntegrationKind
    profile: RuntimeProfile
    resumed_frontier: Frontier
    # A statement supplied when ``start`` reattaches revises the task's current statement; the
    # earlier one stays in the ledger history (issue #908).
    task_statement: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "client_kind", _exact_enum(self.client_kind, ClientKind))
        object.__setattr__(
            self,
            "client_version",
            _bounded_text(self.client_version, MAX_LABEL_BYTES, minimum=1),
        )
        object.__setattr__(self, "integration", _exact_enum(self.integration, IntegrationKind))
        object.__setattr__(self, "profile", _exact_enum(self.profile, RuntimeProfile))
        object.__setattr__(self, "resumed_frontier", _frontier(self.resumed_frontier))
        if self.task_statement is not None:
            object.__setattr__(self, "task_statement", _task_statement(self.task_statement))


@dataclass(frozen=True, slots=True)
class ChildFindingSnapshot:
    """Frozen, structural finding facts copied into a parent dependency manifest.

    The finding kind and origin remain in the manifest so a later evaluator can distinguish
    deterministic and semantic findings.  ``actionable`` is service-stamped when present and is
    checked against the canonical kind traits; callers that replay an older producer may omit it,
    in which case the same trait is derived locally.
    """

    finding_id: FindingId
    kind: FindingKind
    origin: FindingOrigin
    priority: int
    resolved: bool
    resolution_event_id: EventId | None = None
    actionable: bool | None = None
    # Issue #984 (ADR-034): the child agent self-verified this repair and FinishUP could not prove
    # it. Recorded only when true, so every other snapshot keeps its bytes.
    self_verified: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "finding_id", finding_id(self.finding_id))
        kind = _exact_enum(self.kind, FindingKind)
        origin = _exact_enum(self.origin, FindingOrigin)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "origin", origin)
        expected_priority, expected_actionable = FINDING_KIND_TRAITS[kind]
        if self.priority != expected_priority:
            raise ProtocolValueError("finding_priority_mismatch")
        if type(self.resolved) is not bool:
            raise ProtocolValueError("invalid_event_value_type")
        resolution = (
            None if self.resolution_event_id is None else event_id(self.resolution_event_id)
        )
        if self.resolved is not (resolution is not None):
            raise ProtocolValueError("finding_resolution_mismatch")
        object.__setattr__(self, "resolution_event_id", resolution)
        actionable = expected_actionable if self.actionable is None else self.actionable
        if type(actionable) is not bool or actionable is not expected_actionable:
            raise ProtocolValueError("finding_actionable_mismatch")
        object.__setattr__(self, "actionable", actionable)
        if type(self.self_verified) is not bool:
            raise ProtocolValueError("invalid_event_value_type")
        if self.self_verified and (self.resolved or not actionable):
            raise ProtocolValueError("finding_resolution_mismatch")


@dataclass(frozen=True, slots=True)
class ChildDependencySnapshot:
    """One complete child snapshot recorded in a parent ledger.

    ``child_frontier`` is the child's observed current frontier.  It is deliberately separate from
    ``child_check_subject_frontier``: a check may have tested an earlier frontier, and its identity
    must not be promoted to the current child state.  A missing current frontier therefore requires
    at least one closed read-gap reason; the service cannot manufacture a frontier.
    """

    child_task_id: TaskId
    origin: LineageOrigin
    acceptance: LineageAcceptance
    work_state: WorkState
    session_health: SessionHealth
    child_frontier: Frontier | None
    child_check_id: EventId | None
    child_check_subject_frontier: Frontier | None
    child_receipt_id: ReceiptId | None
    coverage: Coverage
    findings: tuple[ChildFindingSnapshot, ...]
    lineage_authority_revision: int
    membership_generation: int | None = None
    read_gap_reasons: tuple[LineageReadGapReason, ...] = ()
    provenance_restrictions: tuple[LineageProvenanceRestriction, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "child_task_id", task_id(self.child_task_id))
        object.__setattr__(self, "origin", _exact_enum(self.origin, LineageOrigin))
        object.__setattr__(self, "acceptance", _exact_enum(self.acceptance, LineageAcceptance))
        object.__setattr__(self, "work_state", _exact_enum(self.work_state, WorkState))
        object.__setattr__(self, "session_health", _exact_enum(self.session_health, SessionHealth))
        current = None if self.child_frontier is None else _frontier(self.child_frontier)
        checked = (
            None
            if self.child_check_subject_frontier is None
            else _frontier(self.child_check_subject_frontier)
        )
        object.__setattr__(self, "child_frontier", current)
        object.__setattr__(self, "child_check_subject_frontier", checked)
        check_id = None if self.child_check_id is None else event_id(self.child_check_id)
        receipt_id_value = (
            None if self.child_receipt_id is None else receipt_id(self.child_receipt_id)
        )
        object.__setattr__(self, "child_check_id", check_id)
        object.__setattr__(self, "child_receipt_id", receipt_id_value)
        if check_id is None and checked is not None:
            raise ProtocolValueError("child_check_frontier_without_check")
        if check_id is not None and checked is None:
            raise ProtocolValueError("child_check_frontier_missing")
        if current is not None and checked is not None and checked > current:
            raise ProtocolValueError("child_check_frontier_ahead_of_child")
        coverage = self.coverage
        if type(coverage) is not Coverage:
            raise ProtocolValueError("invalid_coverage_value")
        object.__setattr__(self, "coverage", coverage)
        if type(self.findings) is not tuple or len(self.findings) > 100:
            raise ProtocolValueError("child_finding_count_invalid")
        if any(type(item) is not ChildFindingSnapshot for item in self.findings):
            raise ProtocolValueError("invalid_event_value_type")
        findings = self.findings
        if findings != tuple(
            sorted(findings, key=lambda item: str(item.finding_id).encode("ascii"))
        ):
            raise ProtocolValueError("child_findings_not_canonical")
        if len({item.finding_id for item in findings}) != len(findings):
            raise ProtocolValueError("duplicate_set_member")
        object.__setattr__(self, "findings", findings)
        object.__setattr__(
            self, "lineage_authority_revision", _lineage_revision(self.lineage_authority_revision)
        )
        if self.membership_generation is not None:
            object.__setattr__(
                self,
                "membership_generation",
                _lineage_revision(self.membership_generation),
            )
        object.__setattr__(
            self,
            "read_gap_reasons",
            _lineage_enum_tuple(
                self.read_gap_reasons,
                LineageReadGapReason,
                maximum=len(LineageReadGapReason),
                field="read_gap_reasons",
            ),
        )
        object.__setattr__(
            self,
            "provenance_restrictions",
            _lineage_enum_tuple(
                self.provenance_restrictions,
                LineageProvenanceRestriction,
                maximum=len(LineageProvenanceRestriction),
                field="provenance_restrictions",
            ),
        )
        if self.child_frontier is None and not self.read_gap_reasons:
            raise ProtocolValueError("child_frontier_missing")
        if self.read_gap_reasons and self.child_frontier is not None:
            raise ProtocolValueError("child_gap_frontier_mismatch")

    @property
    def tested_frontier(self) -> Frontier | None:
        """The frontier actually tested by the child's qualifying check, if any."""

        return self.child_check_subject_frontier


@dataclass(frozen=True, slots=True)
class ChildDependenciesRecordedPayload:
    """Service-stamped aggregate of direct child snapshots.

    The aggregate is intentionally closed and canonical.  An empty aggregate is valid when the
    service records that a parent no longer has direct children; each child id may occur once.
    """

    children: tuple[ChildDependencySnapshot, ...]

    def __post_init__(self) -> None:
        if type(self.children) is not tuple or len(self.children) > 64:
            raise ProtocolValueError("child_dependency_count_invalid")
        if any(type(item) is not ChildDependencySnapshot for item in self.children):
            raise ProtocolValueError("invalid_event_value_type")
        if self.children != tuple(
            sorted(self.children, key=lambda item: str(item.child_task_id).encode("ascii"))
        ):
            raise ProtocolValueError("child_dependencies_not_canonical")
        if len({item.child_task_id for item in self.children}) != len(self.children):
            raise ProtocolValueError("duplicate_set_member")


@dataclass(frozen=True, slots=True)
class CoordinationContextRecordedPayload:
    """Service-stamped, structural context for one project-overlap detection.

    Resource identities are commitments; repository-relative path text can only travel through
    the encrypted ``detail_ref`` boundary.  The wire representation renders all counters as
    canonical decimal strings so the same context has one digest identity.
    """

    detection_id: EventId
    project_id: str
    membership_generation: int
    left_task_id: TaskId
    right_task_id: TaskId
    recipient_task_id: TaskId
    counterpart_task_id: TaskId
    source_task_id: TaskId
    overlap_kind: OverlapKind
    resource_identities: tuple[str, ...]
    resource_count: int
    source_repository_commitment: str
    source_workspace_commitment: str
    source_route_generation: int
    source_attributable_paths: bool
    context_digest: str
    detail_ref: ProjectTextRef | None = None
    gap_codes: tuple[CoordinationGapCode, ...] = ()
    recorded_authority_revision: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "detection_id", event_id(self.detection_id))
        object.__setattr__(self, "project_id", project_id(self.project_id))
        object.__setattr__(
            self,
            "membership_generation",
            _lineage_revision(self.membership_generation),
        )
        left = task_id(self.left_task_id)
        right = task_id(self.right_task_id)
        if left >= right:
            raise ProtocolValueError("coordination_tasks_not_canonical")
        object.__setattr__(self, "left_task_id", left)
        object.__setattr__(self, "right_task_id", right)
        recipient = task_id(self.recipient_task_id)
        counterpart = task_id(self.counterpart_task_id)
        source = task_id(self.source_task_id)
        if recipient not in {left, right} or counterpart not in {left, right}:
            raise ProtocolValueError("coordination_task_pair_invalid")
        if source != counterpart or recipient == counterpart:
            raise ProtocolValueError("coordination_task_pair_invalid")
        object.__setattr__(self, "recipient_task_id", recipient)
        object.__setattr__(self, "counterpart_task_id", counterpart)
        object.__setattr__(self, "source_task_id", source)
        object.__setattr__(self, "overlap_kind", _exact_enum(self.overlap_kind, OverlapKind))

        resources = _tuple(self.resource_identities, 0, 64)
        identities = tuple(validate_sha256_digest(cast(str, value)) for value in resources)
        _validate_ascii_sorted_unique(identities, field="resource_identities")
        object.__setattr__(self, "resource_identities", identities)
        resource_count = _canonical_uint(self.resource_count)
        if resource_count < len(identities):
            raise ProtocolValueError("coordination_resource_count_invalid")
        object.__setattr__(self, "resource_count", resource_count)

        object.__setattr__(
            self,
            "source_repository_commitment",
            validate_commitment(self.source_repository_commitment),
        )
        object.__setattr__(
            self,
            "source_workspace_commitment",
            validate_commitment(self.source_workspace_commitment),
        )
        object.__setattr__(
            self,
            "source_route_generation",
            _lineage_revision(self.source_route_generation),
        )
        if type(self.source_attributable_paths) is not bool:
            raise ProtocolValueError("invalid_event_value_type")
        validate_sha256_digest(self.context_digest)
        if self.detail_ref is not None and type(self.detail_ref) is not ProjectTextRef:
            raise ProtocolValueError("invalid_event_value_type")
        object.__setattr__(
            self,
            "gap_codes",
            _lineage_enum_tuple(
                self.gap_codes,
                CoordinationGapCode,
                maximum=len(CoordinationGapCode),
                field="gap_codes",
            ),
        )
        if self.recorded_authority_revision is not None:
            validate_sha256_digest(self.recorded_authority_revision)


@dataclass(frozen=True, slots=True)
class CoordinationObligationDeclaredPayload:
    """Service-stamped binding of one existing obligation to one overlap detection."""

    detection_id: EventId
    project_id: str
    membership_generation: int
    recipient_task_id: TaskId
    obligation_id: ObligationId

    def __post_init__(self) -> None:
        object.__setattr__(self, "detection_id", event_id(self.detection_id))
        object.__setattr__(self, "project_id", project_id(self.project_id))
        object.__setattr__(
            self,
            "membership_generation",
            _lineage_revision(self.membership_generation),
        )
        object.__setattr__(self, "recipient_task_id", task_id(self.recipient_task_id))
        object.__setattr__(self, "obligation_id", obligation_id(self.obligation_id))


@dataclass(frozen=True, slots=True)
class CoordinationDispositionRecordedPayload:
    """Typed evidence that addresses one declared coordination obligation."""

    detection_id: EventId
    project_id: str
    membership_generation: int
    recipient_task_id: TaskId
    obligation_id: ObligationId
    disposition: CoordinationDisposition
    evidence_refs: tuple[EvidenceId | ResultId, ...]
    finding_id: FindingId | None = None
    context_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "detection_id", event_id(self.detection_id))
        object.__setattr__(self, "project_id", project_id(self.project_id))
        object.__setattr__(
            self,
            "membership_generation",
            _lineage_revision(self.membership_generation),
        )
        object.__setattr__(self, "recipient_task_id", task_id(self.recipient_task_id))
        object.__setattr__(self, "obligation_id", obligation_id(self.obligation_id))
        object.__setattr__(
            self,
            "disposition",
            _exact_enum(self.disposition, CoordinationDisposition),
        )
        object.__setattr__(
            self,
            "evidence_refs",
            _evidence_result_tuple(self.evidence_refs, minimum=1, field="evidence_refs"),
        )
        if self.finding_id is not None:
            object.__setattr__(self, "finding_id", finding_id(self.finding_id))
        if self.context_digest is not None:
            validate_sha256_digest(self.context_digest)


@dataclass(frozen=True, slots=True)
class DelegationDeclaredPayload:
    child_task_id: TaskId
    handle_digest: str
    depth: int
    project_id: str | None = None
    membership_generation: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "child_task_id", task_id(self.child_task_id))
        validate_sha256_digest(self.handle_digest)
        object.__setattr__(self, "depth", _bounded_integer(self.depth, 1, 64))
        project_value = None if self.project_id is None else project_id(self.project_id)
        object.__setattr__(self, "project_id", project_value)
        if self.membership_generation is not None:
            object.__setattr__(
                self,
                "membership_generation",
                _lineage_revision(self.membership_generation),
            )
        project_values_present = project_value is not None or self.membership_generation is not None
        if project_values_present and (project_value is None or self.membership_generation is None):
            raise ProtocolValueError("invalid_event_value_type")


@dataclass(frozen=True, slots=True)
class DelegationCancelledPayload:
    child_task_id: TaskId
    reason_code: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "child_task_id", task_id(self.child_task_id))
        if self.reason_code is not None:
            object.__setattr__(self, "reason_code", _lineage_token(self.reason_code))


@dataclass(frozen=True, slots=True)
class ChildAcceptedPayload:
    child_task_id: TaskId

    def __post_init__(self) -> None:
        object.__setattr__(self, "child_task_id", task_id(self.child_task_id))


@dataclass(frozen=True, slots=True)
class ChildRejectedPayload:
    child_task_id: TaskId
    reason_code: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "child_task_id", task_id(self.child_task_id))
        if self.reason_code is not None:
            object.__setattr__(self, "reason_code", _lineage_token(self.reason_code))


@dataclass(frozen=True, slots=True)
class ChildWrittenOffPayload:
    child_task_id: TaskId
    reason_code: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "child_task_id", task_id(self.child_task_id))
        if self.reason_code is not None:
            object.__setattr__(self, "reason_code", _lineage_token(self.reason_code))


@dataclass(frozen=True, slots=True)
class WorkClosedPayload:
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.reason_code is not None:
            object.__setattr__(self, "reason_code", _lineage_token(self.reason_code))


@dataclass(frozen=True, slots=True)
class WorkAbandonedPayload:
    service_stamped: Literal[True] = True
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.service_stamped is not True:
            raise ProtocolValueError("service_stamp_required")
        if self.reason_code is not None:
            object.__setattr__(self, "reason_code", _lineage_token(self.reason_code))


@dataclass(frozen=True, slots=True)
class WorkCancelledPayload:
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.reason_code is not None:
            object.__setattr__(self, "reason_code", _lineage_token(self.reason_code))


@dataclass(frozen=True, slots=True)
class WorkWrittenOffPayload:
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.reason_code is not None:
            object.__setattr__(self, "reason_code", _lineage_token(self.reason_code))


@dataclass(frozen=True, slots=True)
class PlanPublishedPayload:
    plan_version: int
    summary: str
    obligation_refs: tuple[ObligationId, ...]
    scope_exclusions: tuple[str, ...] = ()
    no_obligations_reason: NoObligationsReason | None = None
    # A revised statement of the user's request, kept apart from ``summary`` (the agent's own
    # plan). The AI-powered review never reads it as part of the plan (issue #908).
    task_statement: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "plan_version",
            _bounded_integer(self.plan_version, 1, _MAX_SAFE_INTEGER),
        )
        if self.task_statement is not None:
            object.__setattr__(self, "task_statement", _task_statement(self.task_statement))
        object.__setattr__(self, "summary", _bounded_text(self.summary, MAX_TEXT_BYTES))
        object.__setattr__(
            self,
            "obligation_refs",
            _id_tuple(self.obligation_refs, obligation_id, field="obligation_refs"),
        )
        object.__setattr__(
            self,
            "scope_exclusions",
            _text_tuple(self.scope_exclusions, MAX_ALTERNATIVES, MAX_LABEL_BYTES),
        )
        if self.no_obligations_reason is not None:
            object.__setattr__(
                self,
                "no_obligations_reason",
                _exact_enum(self.no_obligations_reason, NoObligationsReason),
            )


# Schema-owned obligation meaning fields that must repeat byte-for-byte on resolution.
# status and resolution_evidence_refs are intentionally excluded: they are the transition.
_OBLIGATION_MEANING_FIELD_NAMES: Final = (
    "acceptance_criteria",
    "description",
    "evidence_expectation",
    "obligation_id",
    "requested_items",
    "source_refs",
)
_OBLIGATION_RESOLUTION_INVARIANTS: Final = frozenset(
    {
        "meaning_fields_must_repeat",
        "open_to_resolved_only",
    }
)


@dataclass(frozen=True, slots=True)
class ObligationResolutionMismatch(ValueError):
    """Typed rejection when an obligation_published transition is not a valid resolution.

    Carries only allowlisted schema field names and a fixed invariant code — never submitted
    values — so dry-run and durable append can project the same bounded public error.
    """

    differing_fields: tuple[str, ...]
    invariant: str
    event_id: EventId | None = None
    # The ledger status of the obligation the draft tried to republish (``open`` or
    # ``resolved``), a closed token. It lets ``open_to_resolved_only`` say whether the
    # obligation is already resolved, which every tb4n1 occurrence was.
    prior_status: str | None = None

    def __post_init__(self) -> None:
        if type(self.differing_fields) is not tuple:
            raise ProtocolValueError("invalid_event_value_type")
        if self.prior_status is not None and self.prior_status not in {"open", "resolved"}:
            raise ProtocolValueError("invalid_event_value_type")
        ordered = tuple(sorted(self.differing_fields, key=str.encode))
        if len(ordered) != len(set(ordered)):
            raise ProtocolValueError("duplicate_set_member")
        allowed = frozenset((*_OBLIGATION_MEANING_FIELD_NAMES, "status"))
        if any(type(name) is not str or name not in allowed for name in ordered):
            raise ProtocolValueError("invalid_event_value_type")
        if (
            type(self.invariant) is not str
            or self.invariant not in _OBLIGATION_RESOLUTION_INVARIANTS
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if self.event_id is not None:
            object.__setattr__(self, "event_id", event_id(self.event_id))
        object.__setattr__(self, "differing_fields", ordered)
        ValueError.__init__(self, "obligation_resolution_mismatch")

    @property
    def reason_code(self) -> str:
        return "obligation_resolution_mismatch"


_MAX_EVENTS_PER_BATCH_FOR_POINTER: Final = 100


@dataclass(frozen=True, slots=True)
class NoObligationsReasonMismatch(ValueError):
    """Typed rejection for a no-obligations reason on non-empty or unreadable scope.

    The exception carries only the accepted event identity. The caller-supplied summary, revision
    reason, and obligation identifiers never enter the public error, so dry-run and durable append
    can return the same bounded diagnostic without reflecting submitted content.
    """

    event_id: EventId | None = None

    def __post_init__(self) -> None:
        if self.event_id is not None:
            object.__setattr__(self, "event_id", event_id(self.event_id))
        ValueError.__init__(self, "no_obligations_reason_conflict")

    @property
    def reason_code(self) -> str:
        return "no_obligations_reason_conflict"


_CLAIM_REVISION_FIELDS: Final = frozenset(
    {
        "claim_id",
        "claim_kind",
        "disputes_refs",
        "limitation_refs",
        "obligation_refs",
        "supporting_refs",
        "supersedes_claim_refs",
    }
)
# The invariant names are the public wire vocabulary as well as a domain rule, so they are
# allowlisted in the protocol dependency root and reused here rather than restated. A second copy
# is how the MCP projector and this module drifted apart before ADR-030.
_CLAIM_REVISION_INVARIANTS: Final = ADMITTED_CLAIM_REVISION_INVARIANTS


@dataclass(frozen=True, slots=True)
class ClaimRevisionMismatch(ValueError):
    """Typed, content-free rejection for an invalid claim_recorded/1.1 revision."""

    field: str
    invariant: str
    event_id: EventId | None = None
    # Structural result ids a completion claim still owes in ``limitation_refs``. They are ledger
    # identifiers, never caller content, and are carried only for ``limitation_refs_complete`` so
    # the rejection names exactly what to add (hook-observed runs the author never published were
    # otherwise invisible to it).
    missing_refs: tuple[ResultId, ...] = ()
    # Structural result ids the draft listed in ``limitation_refs`` that are not admissible there
    # (unknown, successful, or outside the claim's obligation scope). Carried only for
    # ``limitation_refs_must_be_relevant_non_success_results`` so the rejection names what to drop.
    offending_refs: tuple[ResultId, ...] = ()

    def __post_init__(self) -> None:
        if type(self.field) is not str or self.field not in _CLAIM_REVISION_FIELDS:
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.invariant) is not str or self.invariant not in _CLAIM_REVISION_INVARIANTS:
            raise ProtocolValueError("invalid_event_value_type")
        if self.event_id is not None:
            object.__setattr__(self, "event_id", event_id(self.event_id))
        if type(self.missing_refs) is not tuple:
            raise ProtocolValueError("invalid_event_value_type")
        if self.missing_refs and self.invariant != "limitation_refs_complete":
            raise ProtocolValueError("invalid_event_value_type")
        object.__setattr__(
            self,
            "missing_refs",
            tuple(sorted({result_id(value) for value in self.missing_refs}, key=str.encode)),
        )
        if type(self.offending_refs) is not tuple:
            raise ProtocolValueError("invalid_event_value_type")
        if (
            self.offending_refs
            and self.invariant != "limitation_refs_must_be_relevant_non_success_results"
        ):
            raise ProtocolValueError("invalid_event_value_type")
        object.__setattr__(
            self,
            "offending_refs",
            tuple(sorted({result_id(value) for value in self.offending_refs}, key=str.encode)),
        )
        ValueError.__init__(self, "claim_revision_mismatch")

    @property
    def reason_code(self) -> str:
        return "claim_revision_mismatch"


def public_error_for_no_obligations_reason_mismatch(
    mismatch: NoObligationsReasonMismatch,
    *,
    event_index: int | None = None,
) -> PublicOperationError:
    """Project the typed declaration contradiction identically on every publication path."""

    if type(mismatch) is not NoObligationsReasonMismatch:
        raise TypeError("no_obligations_reason_mismatch_wrong_type")
    details: dict[str, str] = {"reason_code": mismatch.reason_code}
    if type(event_index) is int and 0 <= event_index < _MAX_EVENTS_PER_BATCH_FOR_POINTER:
        details["field"] = f"/event_drafts/{event_index}/payload/no_obligations_reason"
    return PublicOperationError(
        PublicErrorCode.EVENT_INVALID,
        (
            "The event batch is invalid. no_obligations_reason requires a readable effective "
            "current plan with zero obligation_refs. Remove no_obligations_reason or revise the "
            "plan declaration before retrying."
        ),
        False,
        safe_details=details,
    )


def public_error_for_claim_revision_mismatch(
    mismatch: ClaimRevisionMismatch,
    *,
    event_index: int | None = None,
) -> PublicOperationError:
    """Project the same authorable claim-revision error on preview and append paths."""

    if type(mismatch) is not ClaimRevisionMismatch:
        raise TypeError("claim_revision_mismatch_wrong_type")
    # ``invariant`` rides as a typed detail (ADR-030). It was previously legible only inside the
    # message below, which the MCP text projector does not copy, so that projector had to recover
    # it by matching this whole sentence with a regex.
    details: dict[str, str | int] = {
        "invariant": mismatch.invariant,
        "reason_code": mismatch.reason_code,
    }
    if type(event_index) is int and 0 <= event_index < _MAX_EVENTS_PER_BATCH_FOR_POINTER:
        details["field"] = f"/event_drafts/{event_index}/payload/{mismatch.field}"
    if mismatch.invariant == "limitation_refs_complete" and mismatch.missing_refs:
        details["count"] = len(mismatch.missing_refs)
        return PublicOperationError(
            PublicErrorCode.EVENT_INVALID,
            _limitation_refs_complete_message(mismatch.missing_refs),
            False,
            safe_details=details,
        )
    if mismatch.offending_refs:
        details["count"] = len(mismatch.offending_refs)
        named = mismatch.offending_refs[:_MAX_NAMED_MISSING_LIMITATIONS]
        remainder = len(mismatch.offending_refs) - len(named)
        more = f" and {remainder} more" if remainder > 0 else ""
        return PublicOperationError(
            PublicErrorCode.EVENT_INVALID,
            (
                "The event batch is invalid. claim_recorded/1.1.0 requires invariant "
                "limitation_refs_must_be_relevant_non_success_results: limitation_refs may name "
                "only failed, partial, or unknown results in this claim's obligation scope. Not "
                f"admissible here: {', '.join(named)}{more} (each is unknown, successful, or "
                "outside the claim's obligation_refs scope). Remove them from limitation_refs, "
                "keep successful results in supporting_refs, and retry with a new request_id. "
                "Read status view results before retrying."
            ),
            False,
            safe_details=details,
        )
    # One invariant-specific correction first, from the same registry the CLI renders, then the
    # shared revision rules (tb4n1: the rule recital alone did not say which one was broken).
    correction = correction_for_invariant(mismatch.invariant)
    specific = f": {correction}" if correction is not None else ""
    return PublicOperationError(
        PublicErrorCode.EVENT_INVALID,
        (
            "The event batch is invalid. claim_recorded/1.1.0 requires invariant "
            f"{mismatch.invariant} at {mismatch.field}{specific}. Use supersedes_claim_refs only "
            "for exact prior effective claim ids with overlapping obligation scope and a fresh, "
            "materially changed claim. Keep partial or failed result ids in limitation_refs "
            "rather than supporting_refs, and do not combine replacement with disputes_refs. Read "
            "status views candidate_findings, history, and results before retrying."
        ),
        False,
        safe_details=details,
    )


# Bounded so the public message stays far below its 4096-byte ceiling: 32 result ids are 1,344
# bytes. A larger set is named in order across retries, each naming the next 32.
_MAX_NAMED_MISSING_LIMITATIONS: Final = 32


def _limitation_refs_complete_message(missing: tuple[ResultId, ...]) -> str:
    """Name the exact live non-success results a completion claim still has to disclose."""

    named = missing[:_MAX_NAMED_MISSING_LIMITATIONS]
    remainder = len(missing) - len(named)
    more = f" and {remainder} more that the next attempt will name" if remainder > 0 else ""
    return (
        "The event batch is invalid. A claim_recorded/1.1.0 completion claim requires invariant "
        "limitation_refs_complete: limitation_refs must name every failed, partial, or unknown "
        "result that is still live in its "
        "obligation scope, including command runs FinishUP observed through host hooks that you never "
        f"published. Missing {len(missing)}: {', '.join(named)}{more}. Add these ids to "
        "limitation_refs (unique, ascending, beside any already listed; never in supporting_refs), "
        "and retry with a new request_id. A hook-observed "
        "failure stops being required only after a later observed run of the same command passes "
        "before the claim."
    )


def public_error_for_obligation_resolution_mismatch(
    mismatch: ObligationResolutionMismatch,
    *,
    event_index: int | None = None,
) -> PublicOperationError:
    """Project one typed obligation-resolution rejection to the shared public error contract.

    Dry-run, in-memory durable append, and SQLite durable append must use this helper so the
    agent always sees the same reason, pointer, invariant, and allowlisted field names.
    """

    if type(mismatch) is not ObligationResolutionMismatch:
        raise TypeError("obligation_resolution_mismatch_wrong_type")
    fields = ", ".join(mismatch.differing_fields) if mismatch.differing_fields else "status"
    guidance = (
        "See finishup://guidance/publication-policy.md section obligation-resolution and the "
        "publish_work examples entry for obligation_published resolution."
    )
    if mismatch.invariant == "open_to_resolved_only" and mismatch.prior_status == "resolved":
        # tb4n1: all eight occurrences republished an obligation that was already resolved.
        message = (
            "The event batch is invalid. Obligation resolution requires invariant "
            "open_to_resolved_only: this obligation is already resolved in the ledger, and a "
            "resolution is recorded once. Remove this obligation_published draft from the batch "
            "and retry the rest with a new request_id; status view obligations lists which "
            "obligations are still open. If the resolved work no longer holds, republish it "
            "with status open, or acknowledged_not_done with a reason on "
            f"obligation_published/1.1.0, repeating every meaning field. {guidance}"
        )
    elif mismatch.invariant == "open_to_resolved_only":
        message = (
            "The event batch is invalid. Obligation resolution requires invariant "
            "open_to_resolved_only: an open obligation can be republished only with status "
            "resolved and resolution_evidence_refs, repeating every meaning field byte-for-byte. "
            f"Set status to resolved and retry with a new request_id. {guidance}"
        )
    else:
        message = (
            "The event batch is invalid. Obligation resolution requires invariant "
            f"{mismatch.invariant}; mismatched fields: {fields}. Repeat every meaning field "
            "from the open obligation byte-for-byte (status view obligations shows the recorded "
            "values); only status and resolution_evidence_refs may change. "
            f"{guidance} Correct the event payload before retrying."
        )
    details: dict[str, str] = {"reason_code": "obligation_resolution_mismatch"}
    if type(event_index) is int and 0 <= event_index < _MAX_EVENTS_PER_BATCH_FOR_POINTER:
        details["field"] = f"/event_drafts/{event_index}/payload"
    return PublicOperationError(
        PublicErrorCode.EVENT_INVALID,
        message,
        False,
        safe_details=details,
    )


def obligation_meaning_field_diffs(
    previous: ObligationPublishedPayload,
    nxt: ObligationPublishedPayload,
) -> tuple[str, ...]:
    """Return allowlisted meaning-field names that differ between two obligation payloads.

    Comparison normalizes away ``status`` and ``resolution_evidence_refs`` so callers can
    decide whether a candidate is a pure open→resolved transition.
    """

    if (
        type(previous) is not ObligationPublishedPayload
        or type(nxt) is not ObligationPublishedPayload
    ):
        raise ProtocolValueError("invalid_event_value_type")
    diffs: list[str] = []
    if previous.obligation_id != nxt.obligation_id:
        diffs.append("obligation_id")
    if previous.description != nxt.description:
        diffs.append("description")
    if previous.evidence_expectation != nxt.evidence_expectation:
        diffs.append("evidence_expectation")
    if previous.acceptance_criteria != nxt.acceptance_criteria:
        diffs.append("acceptance_criteria")
    if previous.requested_items != nxt.requested_items:
        diffs.append("requested_items")
    if previous.source_refs != nxt.source_refs:
        diffs.append("source_refs")
    return tuple(sorted(diffs, key=str.encode))


@dataclass(frozen=True, slots=True)
class ObligationPublishedPayload:
    obligation_id: ObligationId
    description: str
    evidence_expectation: str
    status: ObligationStatus
    acceptance_criteria: str | None = None
    requested_items: tuple[RequestedItem, ...] = ()
    source_refs: tuple[EventId, ...] = ()
    resolution_evidence_refs: tuple[EvidenceId | ResultId, ...] = ()
    # obligation_published 1.1.0 only: present iff ``status`` is ``acknowledged_not_done``.
    acknowledged_not_done_reason: str | None = None

    @property
    def requires_obligation_v1_1(self) -> bool:
        """Whether only ``obligation_published`` 1.1.0 can carry this payload (issue #1002).

        True iff a ``directory`` item, an item ``role`` or ``acknowledged_not_done`` is present.
        Use ``obligation_schema_admits`` / ``obligation_schema_version`` rather than comparing
        versions against this directly, so the rule lives in one place (issue #1023).
        """

        return self.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE or any(
            item.requires_obligation_v1_1 for item in self.requested_items
        )

    def __post_init__(self) -> None:
        object.__setattr__(self, "obligation_id", obligation_id(self.obligation_id))
        object.__setattr__(self, "description", _bounded_text(self.description, MAX_TEXT_BYTES))
        object.__setattr__(
            self,
            "evidence_expectation",
            _bounded_text(self.evidence_expectation, MAX_TEXT_BYTES),
        )
        status = _exact_enum(self.status, ObligationStatus)
        object.__setattr__(self, "status", status)
        if self.acceptance_criteria is not None:
            object.__setattr__(
                self,
                "acceptance_criteria",
                _bounded_text(self.acceptance_criteria, MAX_TEXT_BYTES),
            )
        requested = _tuple(self.requested_items, 0, MAX_REQUESTED_ITEMS)
        if any(type(item) is not RequestedItem for item in requested):
            raise ProtocolValueError("invalid_event_value_type")
        object.__setattr__(self, "requested_items", cast(tuple[RequestedItem, ...], requested))
        object.__setattr__(
            self,
            "source_refs",
            _id_tuple(self.source_refs, event_id, field="source_refs"),
        )
        minimum = 1 if status is ObligationStatus.RESOLVED else 0
        resolution_refs = _evidence_result_tuple(
            self.resolution_evidence_refs,
            minimum=minimum,
            field="resolution_evidence_refs",
        )
        object.__setattr__(self, "resolution_evidence_refs", resolution_refs)
        if status is not ObligationStatus.RESOLVED and resolution_refs:
            raise ProtocolValueError("obligation_resolution_invalid")
        reason = self.acknowledged_not_done_reason
        if (status is ObligationStatus.ACKNOWLEDGED_NOT_DONE) != (reason is not None):
            raise ProtocolValueError("obligation_resolution_invalid")
        if reason is not None:
            reason = _bounded_text(reason, MAX_REASON_BYTES, minimum=1)
            # 1..4096 UTF-8 bytes, not characters, and never blank.
            if len(reason.encode("utf-8")) > MAX_REASON_BYTES or not reason.strip():
                raise ProtocolValueError("obligation_resolution_invalid")
            object.__setattr__(self, "acknowledged_not_done_reason", reason)


def obligation_schema_admits(payload: ObligationPublishedPayload, version: str) -> bool:
    """The one ``obligation_published`` version rule (tb4n2 R3, issue #1023).

    1.1.0 admits every payload; 1.0.0 admits a payload without a ``directory`` item, an item
    ``role`` or ``acknowledged_not_done``. Any other version admits nothing. The ingest validator,
    closure preparation and every corrective hint read this rule.
    """

    if version == OBLIGATION_SCHEMA_VERSION:
        return True
    return version == OBLIGATION_BASE_SCHEMA_VERSION and not payload.requires_obligation_v1_1


def obligation_schema_version(payload: ObligationPublishedPayload) -> str:
    """The version FinishUP drafts for *payload*: 1.1.0 iff it needs a 1.1.0 feature, else 1.0.0.

    Choosing the lowest admitting version keeps a plain obligation's released 1.0.0 bytes.
    """

    return (
        OBLIGATION_SCHEMA_VERSION
        if payload.requires_obligation_v1_1
        else OBLIGATION_BASE_SCHEMA_VERSION
    )


@dataclass(frozen=True, slots=True)
class AssignmentRecordedPayload:
    assignee_actor_id: ActorId
    obligation_ids: tuple[ObligationId, ...]
    scope_description: str
    write_policy: WritePolicy | None = None
    handoff_of: EventId | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "assignee_actor_id", actor_id(self.assignee_actor_id))
        object.__setattr__(
            self,
            "obligation_ids",
            _id_tuple(
                self.obligation_ids,
                obligation_id,
                minimum=1,
                field="obligation_ids",
            ),
        )
        object.__setattr__(
            self,
            "scope_description",
            _bounded_text(self.scope_description, MAX_TEXT_BYTES),
        )
        if self.write_policy is not None:
            object.__setattr__(
                self,
                "write_policy",
                _exact_enum(self.write_policy, WritePolicy),
            )
        if self.handoff_of is not None:
            object.__setattr__(self, "handoff_of", event_id(self.handoff_of))


@dataclass(frozen=True, slots=True)
class DecisionRecordedPayload:
    statement: str
    rationale: str
    authority: ActorId
    alternatives: tuple[str, ...] = ()
    affected_obligation_ids: tuple[ObligationId, ...] = ()
    supersedes_event_id: EventId | None = None
    # ``decision_recorded`` 1.1.0 only (ADR-049): this conversation's review-mode switch.
    review_mode: ReviewMode | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "statement", _bounded_text(self.statement, MAX_TEXT_BYTES))
        object.__setattr__(
            self,
            "rationale",
            _bounded_text(self.rationale, MAX_TEXT_BYTES, minimum=1),
        )
        object.__setattr__(self, "authority", actor_id(self.authority))
        object.__setattr__(
            self,
            "alternatives",
            _text_tuple(self.alternatives, MAX_ALTERNATIVES, MAX_TEXT_BYTES),
        )
        object.__setattr__(
            self,
            "affected_obligation_ids",
            _id_tuple(self.affected_obligation_ids, obligation_id, field="affected_obligation_ids"),
        )
        if self.supersedes_event_id is not None:
            object.__setattr__(
                self,
                "supersedes_event_id",
                event_id(self.supersedes_event_id),
            )
        if self.review_mode is not None:
            object.__setattr__(self, "review_mode", _exact_enum(self.review_mode, ReviewMode))


@dataclass(frozen=True, slots=True)
class ActionRecordedPayload:
    action_id: ActionId
    action_kind: ActionKind
    description: str
    command: str | None = None
    subject_state: SubjectStateRef | None = None
    obligation_refs: tuple[ObligationId, ...] = ()
    attempted_items: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "action_id", action_id(self.action_id))
        kind = _exact_enum(self.action_kind, ActionKind)
        object.__setattr__(self, "action_kind", kind)
        object.__setattr__(self, "description", _bounded_text(self.description, MAX_TEXT_BYTES))
        if self.command is not None:
            object.__setattr__(self, "command", _bounded_text(self.command, MAX_TEXT_BYTES))
        if kind is ActionKind.COMMAND and self.command is None:
            raise ProtocolValueError("invalid_event_value_type")
        if self.subject_state is not None:
            object.__setattr__(self, "subject_state", _subject_state(self.subject_state))
        object.__setattr__(
            self,
            "obligation_refs",
            _id_tuple(self.obligation_refs, obligation_id, field="obligation_refs"),
        )
        object.__setattr__(
            self,
            "attempted_items",
            _text_tuple(
                self.attempted_items,
                MAX_REQUESTED_ITEMS,
                1_024,
                unique=True,
            ),
        )


@dataclass(frozen=True, slots=True)
class ResultRecordedPayload:
    result_id: ResultId
    action_id: ActionId
    outcome: ResultOutcome
    exit_status: int | None = None
    summary: str | None = None
    subject_state: SubjectStateRef | None = None
    evidence_refs: tuple[EvidenceId, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "result_id", result_id(self.result_id))
        object.__setattr__(self, "action_id", action_id(self.action_id))
        object.__setattr__(self, "outcome", _exact_enum(self.outcome, ResultOutcome))
        if self.exit_status is not None:
            object.__setattr__(
                self,
                "exit_status",
                _bounded_integer(self.exit_status, -(2**31), 2**31 - 1),
            )
        if self.summary is not None:
            object.__setattr__(self, "summary", _bounded_text(self.summary, MAX_TEXT_BYTES))
        if self.subject_state is not None:
            object.__setattr__(self, "subject_state", _subject_state(self.subject_state))
        object.__setattr__(
            self,
            "evidence_refs",
            _id_tuple(self.evidence_refs, evidence_id, field="evidence_refs"),
        )


@dataclass(frozen=True, slots=True)
class EvidenceDigestBinding:
    subject: EvidenceDigestSubject
    content_availability: EvidenceContentAvailability
    byte_count: int
    provenance: EvidenceDigestProvenance
    approval_commitment: str | None = None
    approved_check_result_digest: str | None = None

    def __post_init__(self) -> None:
        subject = _exact_enum(self.subject, EvidenceDigestSubject)
        availability = _exact_enum(self.content_availability, EvidenceContentAvailability)
        provenance = _exact_enum(self.provenance, EvidenceDigestProvenance)
        object.__setattr__(self, "subject", subject)
        object.__setattr__(self, "content_availability", availability)
        object.__setattr__(self, "provenance", provenance)
        object.__setattr__(
            self, "byte_count", _bounded_integer(self.byte_count, 0, _MAX_SAFE_INTEGER)
        )
        if self.approval_commitment is not None:
            validate_sha256_digest(self.approval_commitment)
        if self.approved_check_result_digest is not None:
            validate_sha256_digest(self.approved_check_result_digest)
        approved = provenance is EvidenceDigestProvenance.APPROVED_CHECK
        if approved is not (
            self.approval_commitment is not None and self.approved_check_result_digest is not None
        ):
            raise ProtocolValueError("evidence_digest_provenance_invalid")
        if (
            subject is EvidenceDigestSubject.APPROVED_CHECK_RECEIPT
            and provenance is not EvidenceDigestProvenance.APPROVED_CHECK
        ):
            raise ProtocolValueError("evidence_digest_provenance_invalid")
        if (
            subject is EvidenceDigestSubject.IMPORT_REPORT
            and provenance is not EvidenceDigestProvenance.IMPORT_OBSERVED
        ):
            raise ProtocolValueError("evidence_digest_provenance_invalid")


_EVIDENCE_SUBJECTS_BY_KIND: Final[Mapping[EvidenceKind, frozenset[EvidenceDigestSubject]]] = (
    MappingProxyType(
        {
            EvidenceKind.ARTIFACT: frozenset(
                {
                    EvidenceDigestSubject.ARTIFACT_BYTES,
                    EvidenceDigestSubject.BOUNDED_EXCERPT,
                    EvidenceDigestSubject.SOURCE_DIFF,
                }
            ),
            EvidenceKind.COMMAND_OUTPUT: frozenset(
                {
                    EvidenceDigestSubject.APPROVED_CHECK_RECEIPT,
                    EvidenceDigestSubject.COMMAND_STDOUT,
                    EvidenceDigestSubject.STATIC_ANALYSIS_REPORT,
                    EvidenceDigestSubject.TEST_REPORT,
                    EvidenceDigestSubject.TEST_STDOUT,
                }
            ),
            EvidenceKind.TEST_RESULT: frozenset(
                {
                    EvidenceDigestSubject.APPROVED_CHECK_RECEIPT,
                    EvidenceDigestSubject.STATIC_ANALYSIS_REPORT,
                    EvidenceDigestSubject.TEST_REPORT,
                    EvidenceDigestSubject.TEST_STDOUT,
                }
            ),
            EvidenceKind.RESEARCH_SOURCE: frozenset(
                {
                    EvidenceDigestSubject.ARTIFACT_BYTES,
                    EvidenceDigestSubject.BOUNDED_EXCERPT,
                }
            ),
            EvidenceKind.IMPORT_REPORT: frozenset({EvidenceDigestSubject.IMPORT_REPORT}),
            EvidenceKind.OTHER: frozenset({EvidenceDigestSubject.BOUNDED_EXCERPT}),
        }
    )
)


@dataclass(frozen=True, slots=True)
class EvidenceRecordedPayload:
    evidence_id: EvidenceId
    evidence_kind: EvidenceKind
    strength: EvidenceImmutability
    observed_at: Timestamp
    reference: str | None = None
    captured_object_id: ObjectId | None = None
    content_digest: str | None = None
    description: str | None = None
    subject_state: SubjectStateRef | None = None
    digest_binding: EvidenceDigestBinding | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_id", evidence_id(self.evidence_id))
        kind = _exact_enum(self.evidence_kind, EvidenceKind)
        strength = _exact_enum(self.strength, EvidenceImmutability)
        object.__setattr__(self, "evidence_kind", kind)
        object.__setattr__(self, "strength", strength)
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at))
        if self.reference is not None:
            object.__setattr__(self, "reference", _bounded_text(self.reference, 2_048))
        if self.captured_object_id is not None:
            object.__setattr__(
                self,
                "captured_object_id",
                object_id(self.captured_object_id),
            )
        if self.content_digest is not None:
            validate_sha256_digest(self.content_digest)
        if self.description is not None:
            object.__setattr__(
                self,
                "description",
                _bounded_text(self.description, MAX_TEXT_BYTES),
            )
        if self.subject_state is not None:
            object.__setattr__(self, "subject_state", _subject_state(self.subject_state))
        if self.digest_binding is not None:
            if type(self.digest_binding) is not EvidenceDigestBinding:
                raise ProtocolValueError("invalid_event_value_type")
            if self.content_digest is None:
                raise ProtocolValueError("evidence_digest_binding_invalid")
            if self.digest_binding.subject not in _EVIDENCE_SUBJECTS_BY_KIND[kind]:
                raise ProtocolValueError("evidence_digest_subject_incompatible")
            captured = (
                self.digest_binding.content_availability is EvidenceContentAvailability.CAPTURED
            )
            if captured is not (self.captured_object_id is not None):
                raise ProtocolValueError("evidence_digest_availability_invalid")

        supported = True
        if strength is EvidenceImmutability.MUTABLE_REFERENCE:
            supported = self.reference is not None
        elif strength is EvidenceImmutability.METADATA_ONLY:
            supported = self.description is not None or self.reference is not None
        elif strength is EvidenceImmutability.CONTENT_DIGEST:
            supported = self.content_digest is not None
        elif strength is EvidenceImmutability.IMMUTABLE_SNAPSHOT:
            supported = self.captured_object_id is not None and self.content_digest is not None
        elif strength is EvidenceImmutability.INDEPENDENTLY_REPRODUCED:
            supported = (
                self.captured_object_id is not None
                and self.content_digest is not None
                and self.subject_state is not None
            )
        if not supported:
            raise ProtocolValueError("evidence_strength_unsupported")
        if kind is EvidenceKind.IMPORT_REPORT and (
            strength is not EvidenceImmutability.IMMUTABLE_SNAPSHOT
            or self.captured_object_id is None
            or self.content_digest is None
        ):
            raise ProtocolValueError("import_report_invalid")


@dataclass(frozen=True, slots=True)
class ClaimRecordedPayload:
    claim_id: ClaimId
    claim_kind: ClaimKind
    statement: str
    supporting_refs: tuple[EvidenceId | ResultId | ObligationId, ...]
    subject_state: SubjectStateRef | None = None
    obligation_refs: tuple[ObligationId, ...] = ()
    disputes_refs: tuple[ClaimId | EventId, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_id", claim_id(self.claim_id))
        object.__setattr__(self, "claim_kind", _exact_enum(self.claim_kind, ClaimKind))
        object.__setattr__(self, "statement", _bounded_text(self.statement, MAX_TEXT_BYTES))
        supporting_raw = _tuple(self.supporting_refs, 0, MAX_REF_LIST)
        supporting = tuple(_claim_supporting_ref(item) for item in supporting_raw)
        _validate_ascii_sorted_unique(cast(tuple[str, ...], supporting), field="supporting_refs")
        object.__setattr__(self, "supporting_refs", supporting)
        if self.subject_state is not None:
            object.__setattr__(self, "subject_state", _subject_state(self.subject_state))
        object.__setattr__(
            self,
            "obligation_refs",
            _id_tuple(self.obligation_refs, obligation_id, field="obligation_refs"),
        )
        disputes_raw = _tuple(self.disputes_refs, 0, MAX_ALTERNATIVES)
        disputes = tuple(_claim_dispute_ref(item) for item in disputes_raw)
        _validate_ascii_sorted_unique(cast(tuple[str, ...], disputes), field="disputes_refs")
        object.__setattr__(self, "disputes_refs", disputes)


@dataclass(frozen=True, slots=True)
class ClaimRecordedPayloadV1_1(ClaimRecordedPayload):
    """Append-only claim correction with support and limitations kept distinct."""

    limitation_refs: tuple[ResultId, ...] = ()
    supersedes_claim_refs: tuple[ClaimId, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        limitations = _id_tuple(self.limitation_refs, result_id, field="limitation_refs")
        superseded = _id_tuple(
            self.supersedes_claim_refs,
            claim_id,
            maximum=MAX_ALTERNATIVES,
            field="supersedes_claim_refs",
        )
        if set(limitations) & set(self.supporting_refs):
            raise ProtocolValueError("claim_revision_invalid", field="limitation_refs")
        if self.claim_id in superseded:
            raise ProtocolValueError("claim_revision_invalid", field="supersedes_claim_refs")
        object.__setattr__(self, "limitation_refs", limitations)
        object.__setattr__(self, "supersedes_claim_refs", superseded)


@dataclass(frozen=True, slots=True)
class PlanRevisedPayload:
    plan_version: int
    supersedes_plan_version: int
    reason: str
    summary: str
    obligation_changes: tuple[ObligationChange, ...]
    no_obligations_reason: NoObligationsReason | None = None
    task_statement: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "plan_version",
            _bounded_integer(self.plan_version, 2, _MAX_SAFE_INTEGER),
        )
        if self.task_statement is not None:
            object.__setattr__(self, "task_statement", _task_statement(self.task_statement))
        object.__setattr__(
            self,
            "supersedes_plan_version",
            _bounded_integer(self.supersedes_plan_version, 1, _MAX_SAFE_INTEGER),
        )
        object.__setattr__(self, "reason", _bounded_text(self.reason, MAX_REASON_BYTES))
        object.__setattr__(self, "summary", _bounded_text(self.summary, MAX_TEXT_BYTES))
        changes = _tuple(self.obligation_changes, 0, MAX_REF_LIST)
        if any(type(change) is not ObligationChange for change in changes):
            raise ProtocolValueError("invalid_event_value_type")
        typed_changes = cast(tuple[ObligationChange, ...], changes)
        if len(typed_changes) != len(set(typed_changes)):
            raise ProtocolValueError("duplicate_set_member")
        object.__setattr__(self, "obligation_changes", typed_changes)
        if self.no_obligations_reason is not None:
            object.__setattr__(
                self,
                "no_obligations_reason",
                _exact_enum(self.no_obligations_reason, NoObligationsReason),
            )


FindingRecordedPayload = Finding


@dataclass(frozen=True, slots=True)
class ResponseRecordedPayload:
    finding_id: FindingId
    finding_frontier: Frontier
    disposition: ResponseDisposition
    reason: str | None = None
    waiver_scope: WaiverScope | None = None
    waiver_expiry: Timestamp | None = None
    evidence_refs: tuple[EvidenceId | ResultId, ...] = ()
    # Issue #996: the earlier finding a ``duplicate_of`` response links to; set only for it.
    duplicate_of_finding_id: FindingId | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "finding_id", finding_id(self.finding_id))
        object.__setattr__(self, "finding_frontier", _frontier(self.finding_frontier))
        disposition = _exact_enum(self.disposition, ResponseDisposition)
        if self.duplicate_of_finding_id is not None:
            object.__setattr__(
                self, "duplicate_of_finding_id", finding_id(self.duplicate_of_finding_id)
            )
        if (disposition is ResponseDisposition.DUPLICATE_OF) != (
            self.duplicate_of_finding_id is not None
        ) or self.duplicate_of_finding_id == self.finding_id:
            raise ProtocolValueError("response_fields_invalid")
        object.__setattr__(self, "disposition", disposition)
        if self.reason is not None:
            object.__setattr__(
                self,
                "reason",
                _bounded_text(self.reason, MAX_REASON_BYTES, minimum=1),
            )
        if self.waiver_scope is not None:
            object.__setattr__(
                self,
                "waiver_scope",
                _exact_enum(self.waiver_scope, WaiverScope),
            )
        if self.waiver_expiry is not None:
            object.__setattr__(self, "waiver_expiry", _timestamp(self.waiver_expiry))
        object.__setattr__(
            self,
            "evidence_refs",
            _evidence_result_tuple(self.evidence_refs, field="evidence_refs"),
        )
        if disposition in {
            ResponseDisposition.ACKNOWLEDGED_NOT_DONE,
            ResponseDisposition.PROVENANCE_DISPUTED,
            ResponseDisposition.REJECTED,
            ResponseDisposition.REOPENED,
            ResponseDisposition.SELF_VERIFIED,
            ResponseDisposition.WAIVED,
        }:
            if self.reason is None:
                raise ProtocolValueError("response_fields_invalid")
        # Issue #984: a self-verification names the agent's own recorded evidence.
        if disposition is ResponseDisposition.SELF_VERIFIED and not self.evidence_refs:
            raise ProtocolValueError("response_fields_invalid")
        if disposition is ResponseDisposition.WAIVED:
            if self.waiver_scope is None:
                raise ProtocolValueError("response_fields_invalid")
        elif self.waiver_scope is not None or self.waiver_expiry is not None:
            raise ProtocolValueError("response_fields_invalid")


@dataclass(frozen=True, slots=True)
class RedactionRecordedPayload:
    target_event_ids: tuple[EventId, ...]
    target_object_ids: tuple[ObjectId, ...]
    method: RedactionMethod
    reason_category: RedactionReasonCategory
    authority: ActorId
    remaining_gap: str

    def __post_init__(self) -> None:
        events = _id_tuple(self.target_event_ids, event_id, field="target_event_ids")
        objects = _id_tuple(self.target_object_ids, object_id, field="target_object_ids")
        if not events and not objects:
            raise ProtocolValueError("redaction_target_required")
        object.__setattr__(self, "target_event_ids", events)
        object.__setattr__(self, "target_object_ids", objects)
        object.__setattr__(self, "method", _exact_enum(self.method, RedactionMethod))
        object.__setattr__(
            self,
            "reason_category",
            _exact_enum(self.reason_category, RedactionReasonCategory),
        )
        object.__setattr__(self, "authority", actor_id(self.authority))
        object.__setattr__(
            self,
            "remaining_gap",
            _bounded_text(self.remaining_gap, MAX_REASON_BYTES),
        )


_POLICY_SELECTION_ORDER: Final = (
    COORDINATION_POLICY_ID,
    RESEARCH_EVIDENCE_POLICY_ID,
    WORK_INTEGRITY_POLICY_ID,
)
# A check records a non-empty, ordered selection from one generation of the built-in packs.
_VALID_POLICY_SELECTIONS: Final = frozenset(
    tuple(
        PolicyVersion(policy_id, generation[policy_id])
        for index, policy_id in enumerate(_POLICY_SELECTION_ORDER)
        if mask & (1 << index)
    )
    for generation in POLICY_PACK_GENERATIONS
    for mask in range(1, 1 << len(_POLICY_SELECTION_ORDER))
)


_MISSING_TARGET_PREFIXES: Final[Mapping[str, Callable[[object], str]]] = MappingProxyType(
    {
        "act_": action_id,
        "clm_": claim_id,
        "evd_": evidence_id,
        "evt_": event_id,
        "fnd_": finding_id,
        "obl_": obligation_id,
        "res_": result_id,
    }
)


def _missing_target_ref(value: object) -> str:
    if type(value) is not str:
        raise ProtocolValueError("invalid_event_value_type")
    constructor = _MISSING_TARGET_PREFIXES.get(value[:4])
    if constructor is None:
        raise ProtocolValueError("invalid_event_value_type")
    return str(constructor(value))


@dataclass(frozen=True, slots=True)
class MissingForAssessmentItem:
    """One item an ``insufficient_packet`` review named as missing, as the check recorded it.

    Structural only (issue #907): a closed kind, refs the frozen case contained, and FinishUP's own
    availability classification. The reviewer's reason is not part of the check record.
    """

    kind: str
    target_refs: tuple[str, ...]
    availability: str

    def __post_init__(self) -> None:
        if type(self.kind) is not str or self.kind not in MISSING_FOR_ASSESSMENT_KINDS:
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.availability) is not str or self.availability not in (
            MISSING_ITEM_AVAILABILITIES
        ):
            raise ProtocolValueError("invalid_event_value_type")
        object.__setattr__(
            self,
            "target_refs",
            _id_tuple(
                self.target_refs,
                _missing_target_ref,
                maximum=MAX_MISSING_TARGET_REFS,
                field="target_refs",
            ),
        )


# At most this many changed files a check-time change showed are recorded on one check (ADR-031).
MAX_CHECK_CHANGE_SHOWN_FILES: Final = 128
# The requirement merged from every raising review lives only on the finding's projection row and
# may hold more files than one event row; past this it is unknown.
MAX_CHECK_CHANGE_RAISED_FILES: Final = 1024
# A shown length never exceeds the stored change's own bound.
MAX_CHECK_CHANGE_SHOWN_BYTES: Final = 262_144


@dataclass(frozen=True, slots=True)
class CheckChangePartialFile:
    """One changed file a review saw only in part: its commitment and how much it saw.

    ``shown_bytes`` counts the bytes of the file's diff section that reached the packet,
    redaction markers included; ``redactions`` counts the ``[REDACTED]`` markers inside them;
    ``clean_bytes`` is where the first of those markers starts (``shown_bytes`` without one);
    ``section_admitted`` says the whole section reached the packet (it is partial only because
    of a redaction). ``view_commitment`` is a keyed commitment (the task bundle's object
    commitment key, never content) over the view's structure: its shown length, whether the
    whole section was admitted, the position of every redaction marker, and the position and
    header of every hunk it showed (ADR-031 decision 9). ``None`` only on a record written before
    view commitments existed. All are counts, flags or commitments, never content.
    """

    commitment: str
    shown_bytes: int
    redactions: int
    section_admitted: bool
    clean_bytes: int
    view_commitment: str | None = None

    def __post_init__(self) -> None:
        validate_commitment(self.commitment)
        if self.view_commitment is not None:
            validate_commitment(self.view_commitment)
        for name in ("shown_bytes", "redactions", "clean_bytes"):
            object.__setattr__(
                self,
                name,
                _bounded_integer(getattr(self, name), 0, MAX_CHECK_CHANGE_SHOWN_BYTES),
            )
        if type(self.section_admitted) is not bool or self.clean_bytes > self.shown_bytes:
            raise ProtocolValueError("invalid_event_value_type")

    def covers(self, raised: CheckChangePartialFile) -> bool:
        """Whether this (repair) view shows at least what a raising partial view did.

        A raising view with a view commitment is covered only by a repair view with the same
        commitment: the same shown length, the same redaction markers at the same positions and
        the same hunks at the same positions. A redaction or a packet-edge hunk that moved is
        therefore not covered, even with equal counts (R945-02). A raising view recorded before
        view commitments falls back to the length and count comparison, which callers disclose
        (``CheckChangeShownFiles.has_unverified_views``): it showed at least n bytes or its whole
        current section, and hid no more spans or its first n bytes were clean.
        """

        if raised.view_commitment is not None:
            return self.view_commitment == raised.view_commitment
        return (self.shown_bytes >= raised.shown_bytes or self.section_admitted) and (
            self.redactions <= raised.redactions or self.clean_bytes >= raised.shown_bytes
        )


@dataclass(frozen=True, slots=True)
class CheckChangeShownFiles:
    """Which changed files of the ADR-031 check-time change reached this check's review packet.

    Each entry is a keyed commitment to one changed file under the change's base, never a path.
    ``fully_shown`` files reached the packet whole, unredacted and untruncated;
    ``partially_shown`` files reached it only in part, each with the clean prefix length it
    carried. At most ``MAX_CHECK_CHANGE_SHOWN_FILES`` files are recorded; when the packet showed
    more, ``complete`` is false and the record holds a subset. Every entry is still true, so an
    incomplete record may prove what a repair review saw, but never everything a review saw.
    """

    fully_shown: tuple[str, ...]
    partially_shown: tuple[CheckChangePartialFile, ...]
    complete: bool

    def __post_init__(self) -> None:
        if type(self.complete) is not bool:
            raise ProtocolValueError("invalid_event_value_type")
        full = tuple(validate_commitment(cast(str, item)) for item in _array(self.fully_shown))
        if full != tuple(sorted(set(full), key=str.encode)):
            raise ProtocolValueError("duplicate_set_member")
        partial = _array(self.partially_shown)
        if any(type(item) is not CheckChangePartialFile for item in partial):
            raise ProtocolValueError("invalid_event_value_type")
        partial_files = cast(tuple[CheckChangePartialFile, ...], partial)
        keys = tuple(item.commitment for item in partial_files)
        if keys != tuple(sorted(set(keys), key=str.encode)) or set(keys) & set(full):
            raise ProtocolValueError("duplicate_set_member")
        if len(full) + len(keys) > MAX_CHECK_CHANGE_RAISED_FILES:
            raise ProtocolValueError("invalid_event_value_type")
        object.__setattr__(self, "fully_shown", full)
        object.__setattr__(self, "partially_shown", partial_files)

    def partial_files(self) -> Mapping[str, CheckChangePartialFile]:
        return {item.commitment: item for item in self.partially_shown}

    def has_unverified_views(self) -> bool:
        """Whether any file this record saw in part has no view commitment (a legacy record)."""

        return any(item.view_commitment is None for item in self.partially_shown)

    def covers(self, raised: CheckChangeShownFiles) -> bool:
        """Whether this (repair) record proves it saw at least what *raised* saw (ADR-031).

        Every file *raised* saw whole is whole here. Every file it saw in part (n bytes with k
        redacted spans) is whole here, or seen in part with at least n bytes and at most k
        redacted spans. *raised* must be complete; this record may be incomplete, because each
        entry it holds is still true.
        """

        if not raised.complete:
            return False
        full = frozenset(self.fully_shown)
        if not frozenset(raised.fully_shown) <= full:
            return False
        partial = self.partial_files()
        for item in raised.partially_shown:
            if item.commitment in full:
                continue
            seen = partial.get(item.commitment)
            if seen is None or not seen.covers(item):
                return False
        return True

    def merged(self, other: CheckChangeShownFiles) -> CheckChangeShownFiles | None:
        """The requirement of two reviews that both raised an issue: what each of them saw.

        Whole files are united; a file either saw whole needs to be seen whole. A file both saw
        in part through the same view commitment keeps that view. Two different views of one file
        (or one committed and one legacy) cannot both be matched by one repair view, so that file
        must be seen whole. Two legacy views keep the larger length and the fewer redacted spans.
        ``None`` (unknown) when either record is incomplete or the union outgrows
        ``MAX_CHECK_CHANGE_RAISED_FILES``.
        """

        if not self.complete or not other.complete:
            return None
        full = set(self.fully_shown) | set(other.fully_shown)
        partial: dict[str, CheckChangePartialFile] = {}
        for item in (*self.partially_shown, *other.partially_shown):
            if item.commitment in full:
                continue
            prior = partial.get(item.commitment)
            if prior is None:
                partial[item.commitment] = item
            elif prior.view_commitment is None and item.view_commitment is None:
                partial[item.commitment] = CheckChangePartialFile(
                    item.commitment,
                    max(prior.shown_bytes, item.shown_bytes),
                    min(prior.redactions, item.redactions),
                    prior.section_admitted and item.section_admitted,
                    min(prior.clean_bytes, item.clean_bytes),
                )
            elif prior.view_commitment != item.view_commitment:
                del partial[item.commitment]
                full.add(item.commitment)
        if len(full) + len(partial) > MAX_CHECK_CHANGE_RAISED_FILES:
            return None
        return CheckChangeShownFiles(
            tuple(sorted(full, key=str.encode)),
            tuple(partial[key] for key in sorted(partial, key=str.encode)),
            complete=True,
        )


def check_change_files_to_json(value: CheckChangeShownFiles) -> dict[str, object]:
    if type(value) is not CheckChangeShownFiles:
        raise ProtocolValueError("invalid_event_value_type")
    return {
        "complete": value.complete,
        "fully_shown": value.fully_shown,
        "partially_shown": tuple(
            {
                "clean_bytes": item.clean_bytes,
                "commitment": item.commitment,
                "redactions": item.redactions,
                "section_admitted": item.section_admitted,
                "shown_bytes": item.shown_bytes,
                # Emitted only when present, so a legacy record keeps its bytes.
                **(
                    {}
                    if item.view_commitment is None
                    else {"view_commitment": item.view_commitment}
                ),
            }
            for item in value.partially_shown
        ),
    }


def check_change_files_from_json(value: object) -> CheckChangeShownFiles:
    source = _closed_object(
        value, required=frozenset({"complete", "fully_shown", "partially_shown"})
    )
    partial: list[CheckChangePartialFile] = []
    for raw in _array(_field(source, "partially_shown")):
        item = _closed_object(
            raw,
            required=frozenset(
                {"clean_bytes", "commitment", "redactions", "section_admitted", "shown_bytes"}
            ),
            optional=frozenset({"view_commitment"}),
        )
        commitment = _field(item, "commitment")
        shown_bytes = _field(item, "shown_bytes")
        redactions = _field(item, "redactions")
        section_admitted = _field(item, "section_admitted")
        clean_bytes = _field(item, "clean_bytes")
        view_commitment = item.get("view_commitment")
        if (
            (view_commitment is not None and type(view_commitment) is not str)
            or type(commitment) is not str
            or type(shown_bytes) is not int
            or type(redactions) is not int
            or type(section_admitted) is not bool
            or type(clean_bytes) is not int
        ):
            raise ProtocolValueError("invalid_event_value_type")
        partial.append(
            CheckChangePartialFile(
                commitment,
                shown_bytes,
                redactions,
                section_admitted,
                clean_bytes,
                view_commitment,
            )
        )
    complete = _field(source, "complete")
    if type(complete) is not bool:
        raise ProtocolValueError("invalid_event_value_type")
    return CheckChangeShownFiles(
        fully_shown=cast(tuple[str, ...], _array(_field(source, "fully_shown"))),
        partially_shown=tuple(partial),
        complete=complete,
    )


# ADR-045: what one check read of a declared output file, and what the check concluded from it
# and from the earlier checks of the same path. Closed tokens, counts and ids only; the path is a
# keyed commitment, never text. The one exception (tb4n4, issue #1044, ADR-035 amendment) is
# ``undeclared_references``: the root-relative paths of files the change created that a source
# deliverable names and no requested item declares, so the receipt and the Stop gate can name the
# file the agent must embed, rebuild or declare.
DELIVERABLE_CHANGES: Final = ("emptied", "truncated", "removed", "unchanged")
DELIVERABLE_PROOFS: Final = ("task_base", "earlier_check")
DELIVERABLE_BASES: Final = ("delivered", "verified", "present")
MAX_DELIVERABLE_STATES: Final = 64
MAX_UNDECLARED_REFERENCES: Final = 8
MAX_UNDECLARED_REFERENCE_CHARS: Final = 256


def undeclared_reference_path_valid(value: object) -> bool:
    """Whether *value* may be recorded as an undeclared reference (tb4n4, #1044).

    A plain root-relative path of 1-256 characters: valid UTF-8, no control character, no leading
    ``/`` and no empty, ``.`` or ``..`` segment. Anything else is counted but never named.
    """

    if type(value) is not str or not 1 <= len(value) <= MAX_UNDECLARED_REFERENCE_CHARS:
        return False
    if value.startswith("/") or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return False
    if any(part in {"", ".", ".."} for part in value.split("/")):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _undeclared_references(value: object) -> tuple[str, ...]:
    raw = _tuple(value, 0, MAX_UNDECLARED_REFERENCES)
    if any(not undeclared_reference_path_valid(item) for item in raw):
        raise ProtocolValueError("invalid_event_value_type")
    paths = cast(tuple[str, ...], raw)
    keys = tuple(path.encode("utf-8") for path in paths)
    if keys != tuple(sorted(set(keys))):
        raise ProtocolValueError("duplicate_set_member")
    return paths


@dataclass(frozen=True, slots=True)
class DeliverableState:
    """One declared output file as a check read it (ADR-045, ``check_recorded`` 1.4.0).

    ``path_key`` is a keyed commitment to the root-relative path (``None`` when the installation
    key was not available, which only costs history, never correctness): the key is the path, not
    the obligation, so republishing an obligation or declaring a second one on the same path does
    not start a new history. ``size_bytes`` and ``lines`` are what the check read (``None`` when
    unknown); ``base_lines`` the line count of the tracked file at the task base. ``basis`` says
    why this state counts as a delivery: ``delivered`` (an obligation declaring the path was
    resolved or claimed complete at this check), ``verified`` (a passing verification run was
    observed while the file had content) or ``present`` (neither). ``change`` is the check's
    conclusion against the history (``emptied``, ``truncated``, ``removed``, ``unchanged``), with
    ``proof`` saying how earlier content is known and ``prior_*`` the last state that held
    content: its size, line count, check event and subject frontier. ``accepted_by`` is the
    ``finishup-assumption`` decision that names this path, which stops the fact from firing while the
    state itself stays on the record.
    """

    obligation_id: ObligationId
    item_index: int
    path_key: str | None = None
    size_bytes: int | None = None
    lines: int | None = None
    base_lines: int | None = None
    basis: str = "present"
    change: str | None = None
    proof: str | None = None
    prior_size_bytes: int | None = None
    prior_lines: int | None = None
    prior_event_id: EventId | None = None
    prior_frontier: int | None = None
    accepted_by: EventId | None = None
    # The file is a type the review packet never carries (binary by Git's NUL sniff, or an
    # unlisted file with a binary suffix) and a review ran: the deliverable was not reviewed.
    unreviewable: bool = False
    # tb4n4 (#1044): the files the change created that this source deliverable names and no item
    # declares (``deliverable_references_undeclared_file``), root-relative and sorted, at most
    # ``MAX_UNDECLARED_REFERENCES``; ``undeclared_reference_count`` is present only when more
    # were found than are named here (a longer list, or a path that cannot be named).
    undeclared_references: tuple[str, ...] = ()
    undeclared_reference_count: int | None = None
    # tb4n5 (ADR-035 amendment): how many created, undeclared files this deliverable names only by
    # an ambiguous file name (a declared file shares it, or nothing ties it to the file's
    # directory), so the check did not treat them as dependencies. A count, never a name.
    undeclared_reference_ambiguous: int | None = None
    # Read-compatibility only: intermediate tb4n5 builds (857a712de) recorded this flag, true
    # beside the references it qualified, before the created-in-task provenance was withdrawn
    # (38ecb467d). Such payloads still decode and re-encode byte-identically; nothing produces the
    # flag any more and nothing consults it, so it grants no disclosure.
    undeclared_references_created_in_task: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "obligation_id", obligation_id(self.obligation_id))
        object.__setattr__(self, "item_index", _bounded_integer(self.item_index, 0, 63))
        if type(self.unreviewable) is not bool:
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.undeclared_references_created_in_task) is not bool or (
            self.undeclared_references_created_in_task
            and not self.undeclared_references
            and self.undeclared_reference_count is None
        ):
            # As recorded: present only beside the references it qualified.
            raise ProtocolValueError("invalid_event_value_type")
        if self.undeclared_reference_ambiguous is not None:
            object.__setattr__(
                self,
                "undeclared_reference_ambiguous",
                _bounded_integer(self.undeclared_reference_ambiguous, 1, _MAX_SAFE_INTEGER),
            )
        object.__setattr__(
            self, "undeclared_references", _undeclared_references(self.undeclared_references)
        )
        if self.undeclared_reference_count is not None:
            count = _bounded_integer(self.undeclared_reference_count, 1, _MAX_SAFE_INTEGER)
            if count <= len(self.undeclared_references):
                # Present only when it says more than the named list does.
                raise ProtocolValueError("invalid_event_value_type")
            object.__setattr__(self, "undeclared_reference_count", count)
        if self.path_key is not None:
            validate_commitment(self.path_key)
        for name in ("size_bytes", "lines", "base_lines", "prior_size_bytes", "prior_lines"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _bounded_integer(value, 0, _MAX_SAFE_INTEGER))
        if self.prior_frontier is not None:
            object.__setattr__(
                self, "prior_frontier", _bounded_integer(self.prior_frontier, 0, _MAX_SAFE_INTEGER)
            )
        for name in ("prior_event_id", "accepted_by"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, event_id(value))
        if type(self.basis) is not str or self.basis not in DELIVERABLE_BASES:
            raise ProtocolValueError("invalid_event_value_type")
        if self.change is not None and (
            type(self.change) is not str or self.change not in DELIVERABLE_CHANGES
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if self.proof is not None and (
            type(self.proof) is not str or self.proof not in DELIVERABLE_PROOFS
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if self.change in {"emptied", "truncated"} and self.proof is None:
            # The fact fires only with proof of earlier content; a record cannot say otherwise.
            raise ProtocolValueError("invalid_event_value_type")
        if (self.prior_event_id is None) != (self.prior_frontier is None):
            raise ProtocolValueError("invalid_event_value_type")

    def as_wire(self) -> dict[str, JsonValue]:
        wire: dict[str, JsonValue] = {
            "basis": self.basis,
            "item_index": self.item_index,
            "obligation_id": self.obligation_id,
        }
        if self.unreviewable:
            wire["unreviewable"] = True
        if self.undeclared_references:
            wire["undeclared_references"] = self.undeclared_references
        if self.undeclared_references_created_in_task:
            wire["undeclared_references_created_in_task"] = True
        for name in (
            "undeclared_reference_count",
            "undeclared_reference_ambiguous",
            "path_key",
            "size_bytes",
            "lines",
            "base_lines",
            "change",
            "proof",
            "prior_size_bytes",
            "prior_lines",
            "prior_event_id",
            "prior_frontier",
            "accepted_by",
        ):
            value = getattr(self, name)
            if value is not None:
                wire[name] = value
        return wire

    @classmethod
    def from_wire(cls, value: object) -> DeliverableState:
        source = _closed_object(
            value,
            required=frozenset({"basis", "item_index", "obligation_id"}),
            optional=frozenset(
                {
                    "path_key",
                    "size_bytes",
                    "lines",
                    "base_lines",
                    "change",
                    "proof",
                    "prior_size_bytes",
                    "prior_lines",
                    "prior_event_id",
                    "prior_frontier",
                    "accepted_by",
                    "unreviewable",
                    "undeclared_references",
                    "undeclared_reference_count",
                    "undeclared_reference_ambiguous",
                    "undeclared_references_created_in_task",
                }
            ),
        )

        def integer(name: str) -> int | None:
            value = source.get(name)
            if value is None:
                return None
            if type(value) is not int:
                raise ProtocolValueError("invalid_event_value_type")
            return value

        def text(name: str) -> str | None:
            value = source.get(name)
            if value is None:
                return None
            if type(value) is not str:
                raise ProtocolValueError("invalid_event_value_type")
            return value

        item_index = _field(source, "item_index")
        basis = _field(source, "basis")
        obligation = _field(source, "obligation_id")
        unreviewable = source.get("unreviewable", False)
        created_in_task = source.get("undeclared_references_created_in_task", False)
        if (
            type(item_index) is not int
            or type(basis) is not str
            or type(obligation) is not str
            or type(unreviewable) is not bool
            or type(created_in_task) is not bool
            # The wire carried the flag only when it was true (``const: true``).
            or ("undeclared_references_created_in_task" in source and not created_in_task)
        ):
            raise ProtocolValueError("invalid_event_value_type")
        prior_event = text("prior_event_id")
        accepted = text("accepted_by")
        references = cast(object, source.get("undeclared_references", ()))
        if not isinstance(references, (list, tuple)):
            raise ProtocolValueError("invalid_event_value_type")
        return cls(
            obligation_id=obligation_id(obligation),
            item_index=item_index,
            path_key=text("path_key"),
            size_bytes=integer("size_bytes"),
            lines=integer("lines"),
            base_lines=integer("base_lines"),
            basis=basis,
            change=text("change"),
            proof=text("proof"),
            prior_size_bytes=integer("prior_size_bytes"),
            prior_lines=integer("prior_lines"),
            prior_event_id=None if prior_event is None else event_id(prior_event),
            prior_frontier=integer("prior_frontier"),
            accepted_by=None if accepted is None else event_id(accepted),
            unreviewable=unreviewable,
            undeclared_references=cast(
                tuple[str, ...], tuple(cast(list[object] | tuple[object, ...], references))
            ),
            undeclared_reference_count=integer("undeclared_reference_count"),
            undeclared_reference_ambiguous=integer("undeclared_reference_ambiguous"),
            undeclared_references_created_in_task=created_in_task,
        )


def validate_deliverable_states(value: object) -> tuple[DeliverableState, ...]:
    """The bounded, ordered, duplicate-free deliverable states of one check."""

    raw = _tuple(value, 0, MAX_DELIVERABLE_STATES)
    if any(type(item) is not DeliverableState for item in raw):
        raise ProtocolValueError("invalid_event_value_type")
    states = cast(tuple[DeliverableState, ...], raw)
    keys = tuple((str(item.obligation_id).encode(), item.item_index) for item in states)
    if keys != tuple(sorted(set(keys))):
        raise ProtocolValueError("duplicate_set_member")
    return states


CHECK_REVIEW_MODE_SOURCES: Final = frozenset(
    {"conversation_default", "conversation_switch", "check_request"}
)
CHECK_REVIEW_MODE_LOCAL_REASONS: Final = frozenset(
    {"owner_local_only", "route_local_only", "review_disabled", "ai_review_not_set_up"}
)


@dataclass(frozen=True, slots=True)
class CheckReviewMode:
    """Which review mode one check ran in and why (ADR-049, check_recorded 1.4.0 only).

    ``mode`` is ``local`` (FinishUP's local checks only) or ``ai_powered``. ``source`` says what
    chose it: the conversation's default from the owner's setting, the conversation's latest
    ``decision_recorded`` switch (``switch_event_id``), or the check's own explicit mode.
    ``local_reason`` is present only when AI-powered review was asked for and the check still ran
    local: the owner set the repository to local only, the host connection is registered on the
    strict route, or AI-powered review is not set up.
    Closed tokens and an event id only; never prose.
    """

    mode: ReviewMode
    source: str
    local_reason: str | None = None
    switch_event_id: EventId | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", _exact_enum(self.mode, ReviewMode))
        if self.source not in CHECK_REVIEW_MODE_SOURCES:
            raise ProtocolValueError("invalid_event_value_type")
        if self.local_reason is not None and (
            self.local_reason not in CHECK_REVIEW_MODE_LOCAL_REASONS
            or self.mode is not ReviewMode.LOCAL
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if self.switch_event_id is not None:
            object.__setattr__(self, "switch_event_id", event_id(self.switch_event_id))
        if (self.switch_event_id is not None) != (self.source == "conversation_switch"):
            raise ProtocolValueError("invalid_event_value_type")

    def as_wire(self) -> dict[str, JsonValue]:
        wire: dict[str, JsonValue] = {"mode": self.mode.value, "source": self.source}
        if self.local_reason is not None:
            wire["local_reason"] = self.local_reason
        if self.switch_event_id is not None:
            wire["switch_event_id"] = self.switch_event_id
        return wire

    @classmethod
    def from_wire(cls, value: object) -> CheckReviewMode:
        source = _closed_object(
            freeze_json(cast(JsonValue, value)),
            required=frozenset({"mode", "source"}),
            optional=frozenset({"local_reason", "switch_event_id"}),
        )
        local_reason = _optional(source, "local_reason")
        switch = _optional(source, "switch_event_id")
        return cls(
            _enum_from_json(_field(source, "mode"), ReviewMode),
            cast(str, _field(source, "source")),
            None if local_reason is None else cast(str, local_reason),
            None if switch is None else event_id(switch),
        )


@dataclass(frozen=True, slots=True)
class CheckRecordedPayload:
    mode: CheckMode
    policies: tuple[PolicyVersion, ...]
    scope: CheckScopeModel
    policy_executions: tuple[CheckPolicyExecutionModel, ...]
    subject_frontier: Frontier
    verdict: CheckVerdict
    returned_finding_ids: tuple[FindingId, ...]
    suppressed_count: int
    coverage: Coverage
    semantic_status: SemanticStatus
    semantic_reason: SemanticReason
    engine_version: str
    projection_version: str
    semantic_provenance: SemanticProvenance | None = None
    semantic_conclusion: str | None = None
    # Part 2 reviewer output. Prose and cited refs are bounded by the provider/check fence before
    # publication; JsonObject keeps the event module independent from the provider adapter.
    review_summary: str | None = None
    verified: tuple[JsonObject, ...] = ()
    # Admitted reviewer rulings on earlier AI-powered findings, ASCII-ascending by finding id.
    prior_finding_verdicts: tuple[PriorFindingVerdictRecord, ...] = ()
    # What an ``insufficient_packet`` review named as missing, classified by FinishUP (issue #907).
    missing_for_assessment: tuple[MissingForAssessmentItem, ...] = ()
    # ADR-031: set only on a completed review (``check_recorded`` 1.3.0) whose packet carried a
    # check-time change. AI-powered finding resolution compares these sets across checks.
    check_change_files: CheckChangeShownFiles | None = None
    # The frontier references whose own content item a reduced AI-powered review packet actually
    # sent (after envelope bounding and privacy minimization, issue #904). Present only on a
    # completed review whose coverage records the reduced scope; resolution tests a finding's
    # relevant material against it.
    semantic_included_refs: tuple[str, ...] | None = None
    # Opaque item identities omitted by the low-confidence never-send heuristic. A companion
    # coverage gap is required whenever this field is present: ``semantic_review_item_withheld``
    # (review-scoped, issue #982) on current checks, or ``content_redacted`` on checks recorded
    # before that change, which stay valid on replay.
    semantic_withheld_item_ids: tuple[str, ...] = ()
    # Metadata-only input coverage for the exact check packet (issue #951).
    review_input_manifest: JsonObject | None = None
    # Frozen-frontier structural totals; absent only on legacy check events.
    totals: JsonObject | None = None
    # PL2-1 (issue #982, 1.4.0 only): per case item, its catalogued ref and the 1-based lines whose
    # credential-like values the external reviewer's copy did not carry. Never values.
    semantic_redacted_values: tuple[SemanticRedactedValue, ...] = ()
    # Issue #986 (owner decision "record route; don't block", 1.4.0 only): whether the check's
    # route required AI-powered review. Writers record only ``False`` (the route did not require
    # it); a route that required review omits it, so those checks and every older check keep
    # their bytes. Absent or ``True`` keeps ``semantic_review_not_requested`` blocking.
    semantic_route_required: bool | None = None
    # ADR-045 (tb4n3 RC-5, 1.4.0 only): how each declared output file read at this check stood and
    # what the check concluded from it and from the earlier checks of the same path. Empty when
    # the check read no declared output file, so those checks keep their bytes.
    deliverable_states: tuple[DeliverableState, ...] = ()
    # ADR-049 (1.4.0 only): the conversation review mode this check ran in and why. Absent on
    # checks that predate it and where the owner's conversation setting could not be read.
    review_mode: CheckReviewMode | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", _exact_enum(self.mode, CheckMode))
        policies_raw = _tuple(self.policies, 1, 3)
        if any(type(policy) is not PolicyVersion for policy in policies_raw):
            raise ProtocolValueError("invalid_event_value_type")
        policies = cast(tuple[PolicyVersion, ...], policies_raw)
        if policies not in _VALID_POLICY_SELECTIONS:
            raise ProtocolValueError("invalid_event_value_type")
        object.__setattr__(self, "policies", policies)
        if type(self.scope) is not CheckScopeModel:
            raise ProtocolValueError("invalid_event_value_type")
        _id_tuple(self.scope.claim_ids, claim_id, field="scope")
        _id_tuple(self.scope.obligation_ids, obligation_id, field="scope")
        executions_raw = _tuple(self.policy_executions, 1, 3)
        if any(type(execution) is not CheckPolicyExecutionModel for execution in executions_raw):
            raise ProtocolValueError("invalid_event_value_type")
        executions = cast(tuple[CheckPolicyExecutionModel, ...], executions_raw)
        if len(executions) != len(set(executions)):
            raise ProtocolValueError("duplicate_set_member")
        execution_identities = tuple(
            (execution.policy_id, execution.policy_version) for execution in executions
        )
        policy_identities = tuple((policy.policy_id, policy.policy_version) for policy in policies)
        if execution_identities != policy_identities:
            raise ProtocolValueError("invalid_event_value_type")
        object.__setattr__(self, "policy_executions", executions)
        object.__setattr__(self, "subject_frontier", _frontier(self.subject_frontier))
        object.__setattr__(self, "verdict", _exact_enum(self.verdict, CheckVerdict))
        object.__setattr__(
            self,
            "returned_finding_ids",
            _id_tuple(
                self.returned_finding_ids,
                finding_id,
                maximum=_MAX_FINDINGS_LIMIT,
                field="returned_finding_ids",
            ),
        )
        object.__setattr__(
            self,
            "suppressed_count",
            _bounded_integer(self.suppressed_count, 0, _MAX_SAFE_INTEGER),
        )
        if type(self.coverage) is not Coverage:
            raise ProtocolValueError("invalid_coverage_value")
        status = _exact_enum(self.semantic_status, SemanticStatus)
        reason = _exact_enum(self.semantic_reason, SemanticReason)
        object.__setattr__(self, "semantic_status", status)
        object.__setattr__(self, "semantic_reason", reason)
        provenance_status: SemanticStatus | None = None
        provenance_reason: SemanticReason | None = None
        if self.semantic_provenance is not None:
            if type(self.semantic_provenance) is not SemanticProvenance:
                raise ProtocolValueError("invalid_semantic_provenance")
            provenance_status = self.semantic_provenance.status
            provenance_reason = self.semantic_provenance.reason
        validate_semantic_provenance_binding(
            status,
            reason,
            provenance_status,
            provenance_reason,
        )
        if self.semantic_conclusion is not None and (
            type(self.semantic_conclusion) is not str
            or self.semantic_conclusion
            not in {"no_material_discrepancy", "challenges_returned", "insufficient_packet"}
            or status is not SemanticStatus.SUCCEEDED
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if self.review_summary is not None:
            object.__setattr__(
                self,
                "review_summary",
                _bounded_text(self.review_summary, MAX_TEXT_BYTES, minimum=1),
            )
        if type(self.verified) is not tuple or len(self.verified) > 64:
            raise ProtocolValueError("invalid_event_value_type")
        if any(type(item) is not JsonObject for item in self.verified):
            raise ProtocolValueError("invalid_event_value_type")
        object.__setattr__(self, "verified", tuple(freeze_json(item) for item in self.verified))
        missing = _tuple(self.missing_for_assessment, 0, MAX_MISSING_FOR_ASSESSMENT)
        if any(type(item) is not MissingForAssessmentItem for item in missing):
            raise ProtocolValueError("invalid_event_value_type")
        missing_items = cast(tuple[MissingForAssessmentItem, ...], missing)
        if missing_items and self.semantic_conclusion != "insufficient_packet":
            raise ProtocolValueError("invalid_event_value_type")
        keys = tuple(
            (item.kind.encode("ascii"), tuple(ref.encode("ascii") for ref in item.target_refs))
            for item in missing_items
        )
        if keys != tuple(sorted(set(keys))):
            raise ProtocolValueError("duplicate_set_member")
        object.__setattr__(self, "missing_for_assessment", missing_items)
        if self.check_change_files is not None and (
            type(self.check_change_files) is not CheckChangeShownFiles
            or self.semantic_conclusion is None
            or len(self.check_change_files.fully_shown)
            + len(self.check_change_files.partially_shown)
            > MAX_CHECK_CHANGE_SHOWN_FILES
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if self.semantic_included_refs is not None:
            if (
                self.semantic_conclusion is None
                or SEMANTIC_REFERENCE_SCOPE_REDUCED_GAP not in self.coverage.known_gaps
            ):
                raise ProtocolValueError("invalid_event_value_type")
            object.__setattr__(
                self,
                "semantic_included_refs",
                _id_tuple(
                    self.semantic_included_refs,
                    _included_ref,
                    minimum=1,
                    maximum=MAX_SEMANTIC_INCLUDED_REFS,
                    field="semantic_included_refs",
                ),
            )
        if (
            type(self.semantic_withheld_item_ids) is not tuple
            or len(self.semantic_withheld_item_ids) > 64
            or any(
                not _valid_opaque_item_id(item_id) for item_id in self.semantic_withheld_item_ids
            )
            or self.semantic_withheld_item_ids
            != tuple(sorted(set(self.semantic_withheld_item_ids), key=str.encode))
            or (
                self.semantic_withheld_item_ids
                and "content_redacted" not in self.coverage.known_gaps
                and SEMANTIC_REVIEW_ITEM_WITHHELD_GAP not in self.coverage.known_gaps
            )
        ):
            raise ProtocolValueError("invalid_event_value_type")
        try:
            validate_semantic_redacted_values(self.semantic_redacted_values)
        except ValueError as exc:
            raise ProtocolValueError("invalid_event_value_type") from exc
        if any(
            item.disposition == "item_withheld"
            and item.item_id not in self.semantic_withheld_item_ids
            for item in self.semantic_redacted_values
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if (
            self.review_input_manifest is not None
            and type(self.review_input_manifest) is not JsonObject
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if (
            self.semantic_route_required is not None
            and type(self.semantic_route_required) is not bool
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if self.review_mode is not None and type(self.review_mode) is not CheckReviewMode:
            raise ProtocolValueError("invalid_event_value_type")
        object.__setattr__(
            self, "deliverable_states", validate_deliverable_states(self.deliverable_states)
        )
        if type(self.engine_version) is not str or self.engine_version != "0.1.0":
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.projection_version) is not str or self.projection_version != "yoetz/0.1.0":
            raise ProtocolValueError("invalid_event_value_type")
        if self.totals is not None:
            from finishup.domain.check_totals import validate_check_totals

            object.__setattr__(self, "totals", validate_check_totals(self.totals))
        verdicts = self.prior_finding_verdicts
        if (
            type(verdicts) is not tuple
            or len(verdicts) > MAX_RECORDED_VERDICTS
            or any(type(item) is not PriorFindingVerdictRecord for item in verdicts)
            or (verdicts and self.semantic_conclusion is None)
        ):
            raise ProtocolValueError("invalid_event_value_type")
        ensure_canonical_set(tuple(str(item.finding_id) for item in verdicts))


@dataclass(frozen=True, slots=True)
class ReceiptRecordedPayload:
    receipt_id: ReceiptId
    subject_frontier: Frontier
    receipt_digest: str
    receipt_object_id: ObjectId
    conclusion_code: ReceiptConclusion
    redaction_profile: ReceiptRedactionProfile

    def __post_init__(self) -> None:
        object.__setattr__(self, "receipt_id", receipt_id(self.receipt_id))
        object.__setattr__(self, "subject_frontier", _frontier(self.subject_frontier))
        validate_sha256_digest(self.receipt_digest)
        object.__setattr__(self, "receipt_object_id", object_id(self.receipt_object_id))
        object.__setattr__(
            self,
            "conclusion_code",
            _exact_enum(self.conclusion_code, ReceiptConclusion),
        )
        object.__setattr__(
            self,
            "redaction_profile",
            _exact_enum(self.redaction_profile, ReceiptRedactionProfile),
        )


type EventPayload = (
    SessionOpenedPayload
    | SessionResumedPayload
    | ChildDependenciesRecordedPayload
    | CoordinationContextRecordedPayload
    | CoordinationObligationDeclaredPayload
    | CoordinationDispositionRecordedPayload
    | DelegationDeclaredPayload
    | DelegationCancelledPayload
    | ChildAcceptedPayload
    | ChildRejectedPayload
    | ChildWrittenOffPayload
    | WorkClosedPayload
    | WorkAbandonedPayload
    | WorkCancelledPayload
    | WorkWrittenOffPayload
    | PlanPublishedPayload
    | ObligationPublishedPayload
    | AssignmentRecordedPayload
    | DecisionRecordedPayload
    | ActionRecordedPayload
    | ResultRecordedPayload
    | EvidenceRecordedPayload
    | ClaimRecordedPayload
    | ClaimRecordedPayloadV1_1
    | PlanRevisedPayload
    | Finding
    | ResponseRecordedPayload
    | RedactionRecordedPayload
    | CheckRecordedPayload
    | ReceiptRecordedPayload
)


PAYLOAD_TYPES: Final[Mapping[EventSchema, type[EventPayload]]] = MappingProxyType(
    {
        EventSchema("session_opened", SCHEMA_VERSION): SessionOpenedPayload,
        EventSchema("session_opened", SESSION_EVENT_SCHEMA_VERSION): SessionOpenedPayload,
        EventSchema("session_opened", LINEAGE_SESSION_EVENT_SCHEMA_VERSION): SessionOpenedPayload,
        EventSchema("session_resumed", SCHEMA_VERSION): SessionResumedPayload,
        EventSchema("session_resumed", SESSION_EVENT_SCHEMA_VERSION): SessionResumedPayload,
        EventSchema(
            "session_resumed", TASK_STATEMENT_SESSION_RESUMED_SCHEMA_VERSION
        ): SessionResumedPayload,
        EventSchema("plan_published", SCHEMA_VERSION): PlanPublishedPayload,
        EventSchema("plan_published", TASK_STATEMENT_PLAN_SCHEMA_VERSION): PlanPublishedPayload,
        EventSchema("obligation_published", SCHEMA_VERSION): ObligationPublishedPayload,
        EventSchema("obligation_published", OBLIGATION_SCHEMA_VERSION): ObligationPublishedPayload,
        EventSchema("assignment_recorded", SCHEMA_VERSION): AssignmentRecordedPayload,
        EventSchema("decision_recorded", SCHEMA_VERSION): DecisionRecordedPayload,
        EventSchema(
            "decision_recorded", DECISION_REVIEW_MODE_SCHEMA_VERSION
        ): DecisionRecordedPayload,
        EventSchema("action_recorded", SCHEMA_VERSION): ActionRecordedPayload,
        EventSchema("result_recorded", SCHEMA_VERSION): ResultRecordedPayload,
        **{
            EventSchema("evidence_recorded", version): EvidenceRecordedPayload
            for version in EVIDENCE_SCHEMA_VERSIONS
        },
        EventSchema("claim_recorded", SCHEMA_VERSION): ClaimRecordedPayload,
        EventSchema("claim_recorded", CLAIM_SCHEMA_VERSION): ClaimRecordedPayloadV1_1,
        EventSchema("plan_revised", SCHEMA_VERSION): PlanRevisedPayload,
        EventSchema("plan_revised", TASK_STATEMENT_PLAN_SCHEMA_VERSION): PlanRevisedPayload,
        EventSchema("finding_recorded", SCHEMA_VERSION): Finding,
        EventSchema("finding_recorded", FINDING_EVENT_SCHEMA_VERSION): Finding,
        EventSchema("finding_recorded", FINDING_SNIPPET_EVENT_SCHEMA_VERSION): Finding,
        **{
            EventSchema("finding_recorded", version): Finding
            for version in SEMANTIC_EVENT_SCHEMA_VERSIONS
        },
        EventSchema("response_recorded", SCHEMA_VERSION): ResponseRecordedPayload,
        EventSchema("response_recorded", RESPONSE_EVENT_SCHEMA_VERSION): ResponseRecordedPayload,
        EventSchema("redaction_recorded", SCHEMA_VERSION): RedactionRecordedPayload,
        EventSchema("check_recorded", SCHEMA_VERSION): CheckRecordedPayload,
        EventSchema("check_recorded", CHECK_EVENT_SCHEMA_VERSION): CheckRecordedPayload,
        EventSchema("check_recorded", REVIEW_CHECK_EVENT_SCHEMA_VERSION): CheckRecordedPayload,
        **{
            EventSchema("check_recorded", version): CheckRecordedPayload
            for version in SEMANTIC_EVENT_SCHEMA_VERSIONS
        },
        EventSchema("receipt_recorded", SCHEMA_VERSION): ReceiptRecordedPayload,
        EventSchema("delegation_declared", LINEAGE_EVENT_SCHEMA_VERSION): DelegationDeclaredPayload,
        EventSchema(
            "delegation_cancelled", LINEAGE_EVENT_SCHEMA_VERSION
        ): DelegationCancelledPayload,
        EventSchema("child_accepted", LINEAGE_EVENT_SCHEMA_VERSION): ChildAcceptedPayload,
        EventSchema("child_rejected", LINEAGE_EVENT_SCHEMA_VERSION): ChildRejectedPayload,
        EventSchema("child_written_off", LINEAGE_EVENT_SCHEMA_VERSION): ChildWrittenOffPayload,
        EventSchema(
            "child_dependencies_recorded", LINEAGE_EVENT_SCHEMA_VERSION
        ): ChildDependenciesRecordedPayload,
        EventSchema(
            "coordination_context_recorded", COORDINATION_EVENT_SCHEMA_VERSION
        ): CoordinationContextRecordedPayload,
        EventSchema(
            "coordination_obligation_declared", COORDINATION_EVENT_SCHEMA_VERSION
        ): CoordinationObligationDeclaredPayload,
        EventSchema(
            "coordination_disposition_recorded", COORDINATION_EVENT_SCHEMA_VERSION
        ): CoordinationDispositionRecordedPayload,
        EventSchema("work_closed", LINEAGE_EVENT_SCHEMA_VERSION): WorkClosedPayload,
        EventSchema("work_abandoned", LINEAGE_EVENT_SCHEMA_VERSION): WorkAbandonedPayload,
        EventSchema("work_cancelled", LINEAGE_EVENT_SCHEMA_VERSION): WorkCancelledPayload,
        EventSchema("work_written_off", LINEAGE_EVENT_SCHEMA_VERSION): WorkWrittenOffPayload,
    }
)

# The one schema per family that may carry a task statement (issue #908).
TASK_STATEMENT_EVENT_SCHEMAS: Final = frozenset(
    {
        EventSchema("session_opened", TASK_STATEMENT_SESSION_OPENED_SCHEMA_VERSION),
        EventSchema("session_resumed", TASK_STATEMENT_SESSION_RESUMED_SCHEMA_VERSION),
        EventSchema("plan_published", TASK_STATEMENT_PLAN_SCHEMA_VERSION),
        EventSchema("plan_revised", TASK_STATEMENT_PLAN_SCHEMA_VERSION),
    }
)
# The versions minted only for the statement are never chosen without one; session-opened 1.2.0
# also carries lineage alone, so its statement stays optional.
_TASK_STATEMENT_REQUIRED_SCHEMAS: Final = TASK_STATEMENT_EVENT_SCHEMAS - {
    EventSchema("session_opened", TASK_STATEMENT_SESSION_OPENED_SCHEMA_VERSION)
}


def _closed_object(
    value: object,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise ProtocolValueError("invalid_event_value_type")
    source = cast(Mapping[object, object], value)
    try:
        keys = tuple(source)
    except Exception as exc:
        raise ProtocolValueError("invalid_event_value_type") from exc
    if any(type(key) is not str for key in keys):
        raise ProtocolValueError("invalid_event_value_type")
    string_keys = cast(tuple[str, ...], keys)
    present = frozenset(string_keys)
    if missing := required - present:
        _ = missing
        raise ProtocolValueError("missing_payload_field")
    if present - required - optional:
        raise ProtocolValueError("unknown_payload_field")
    try:
        return cast(Mapping[str, JsonValue], {key: source[key] for key in string_keys})
    except Exception as exc:
        raise ProtocolValueError("invalid_event_value_type") from exc


def _field(source: Mapping[str, JsonValue], key: str) -> JsonValue:
    try:
        return source[key]
    except Exception as exc:
        raise ProtocolValueError("missing_payload_field") from exc


def _optional(source: Mapping[str, JsonValue], key: str) -> JsonValue | None:
    if key not in source:
        return None
    value = _field(source, key)
    if value is None:
        raise ProtocolValueError("invalid_event_value_type")
    return value


def _decode_check_change_files(value: object | None) -> CheckChangeShownFiles | None:
    return None if value is None else check_change_files_from_json(value)


def _array(value: object) -> tuple[object, ...]:
    if type(value) is tuple:
        return cast(tuple[object, ...], value)
    if type(value) is list:
        return tuple(cast(list[object], value))
    raise ProtocolValueError("invalid_event_value_type")


def _missing_items_from_json(value: JsonValue | None) -> tuple[MissingForAssessmentItem, ...]:
    if value is None:
        return ()
    items: list[MissingForAssessmentItem] = []
    for raw in _array(value):
        source = _closed_object(
            raw,
            required=frozenset({"availability", "kind", "target_refs"}),
            optional=frozenset(),
        )
        items.append(
            MissingForAssessmentItem(
                kind=cast(str, _field(source, "kind")),
                target_refs=cast(tuple[str, ...], _array(_field(source, "target_refs"))),
                availability=cast(str, _field(source, "availability")),
            )
        )
    if not items:
        # An emitted list is never empty; absence is how a check without items is recorded.
        raise ProtocolValueError("invalid_event_value_type")
    return tuple(items)


_REVIEW_INPUT_SECTION_NAMES: Final = frozenset(
    {
        "specification",
        "current_diff",
        "caller_evidence",
        "latest_verification",
        "prior_finding_context",
    }
)
_REVIEW_INPUT_SECTION_STATUSES: Final = frozenset(
    {"complete", "partial", "title_only", "missing", "withheld", "not_selected"}
)
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


def _review_input_manifest_from_json(value: JsonValue | None) -> JsonObject | None:
    """Validate and freeze the metadata-only per-check input manifest."""

    if value is None:
        return None
    source = _closed_object(
        value,
        required=frozenset(
            {
                "schema",
                "specification",
                "current_diff",
                "caller_evidence",
                "latest_verification",
                "prior_finding_context",
                "phase",
                "missing_inputs",
                "selected_item_count",
                "selected_excerpt_bytes",
                "omitted_item_count",
            }
        ),
        optional=frozenset({"review_phase", "omitted_item_total", "follow_up_round"}),
    )
    if _field(source, "schema") != "yoetz.review-input-manifest/1":
        raise ProtocolValueError("invalid_event_value_type")
    if "review_phase" in source and source["review_phase"] not in {"routine", "final"}:
        raise ProtocolValueError("invalid_event_value_type")
    if "follow_up_round" in source:
        # Issue #1047: the in-check follow-up round the recorded packet was.
        follow_up_round = source["follow_up_round"]
        if (
            type(follow_up_round) is not int
            or not 1 <= follow_up_round <= MAX_REVIEW_FOLLOW_UP_ROUNDS
        ):
            raise ProtocolValueError("invalid_event_value_type")
    if _field(source, "phase") not in {"composed", "provider_bound"}:
        raise ProtocolValueError("invalid_event_value_type")
    for key in _REVIEW_INPUT_SECTION_NAMES:
        section = _closed_object(
            _field(source, key),
            required=frozenset(
                {
                    "status",
                    "source_refs",
                    "item_ids",
                    "omitted_refs",
                    "omission_reasons",
                    "revision",
                    "content_digest",
                    "content_bytes",
                }
            ),
        )
        status = _field(section, "status")
        if status not in _REVIEW_INPUT_SECTION_STATUSES:
            raise ProtocolValueError("invalid_event_value_type")
        for field_name, maximum in (
            ("source_refs", 16),
            ("item_ids", 128),
            ("omitted_refs", 16),
            ("omission_reasons", 8),
        ):
            values = _array(_field(section, field_name))
            if len(values) > maximum or any(type(item) is not str for item in values):
                raise ProtocolValueError("invalid_event_value_type")
        if any(
            cast(str, item) not in _REVIEW_INPUT_OMISSION_REASONS
            for item in _array(_field(section, "omission_reasons"))
        ):
            raise ProtocolValueError("invalid_event_value_type")
        revision = _field(section, "revision")
        if revision is not None and (type(revision) is not int or revision < 0):
            raise ProtocolValueError("invalid_event_value_type")
        digest = _field(section, "content_digest")
        if digest is not None:
            validate_sha256_digest(cast(str, digest))
        content_bytes = _field(section, "content_bytes")
        if type(content_bytes) is not int or not 0 <= content_bytes <= 524288:
            raise ProtocolValueError("invalid_event_value_type")
    for field_name in ("selected_item_count", "selected_excerpt_bytes", "omitted_item_count"):
        value_int = _field(source, field_name)
        if type(value_int) is not int or value_int < 0:
            raise ProtocolValueError("invalid_event_value_type")
    if "omitted_item_total" in source:
        # Issue #976: the true omission total beside the capped listed count.
        total = source["omitted_item_total"]
        if type(total) is not int or not cast(int, _field(source, "omitted_item_count")) <= total:
            raise ProtocolValueError("invalid_event_value_type")
    missing = _array(_field(source, "missing_inputs"))
    if len(missing) > 8:
        raise ProtocolValueError("invalid_event_value_type")
    for raw in missing:
        item = _closed_object(
            raw,
            required=frozenset({"kind", "target_refs", "supplied_refs", "status"}),
        )
        if _field(item, "kind") not in MISSING_FOR_ASSESSMENT_KINDS:
            raise ProtocolValueError("invalid_event_value_type")
        if _field(item, "status") not in {"pending", "supplied", "unavailable", "repeated"}:
            raise ProtocolValueError("invalid_event_value_type")
        for ref_field in ("target_refs", "supplied_refs"):
            refs = _array(_field(item, ref_field))
            if len(refs) > MAX_MISSING_TARGET_REFS or any(type(ref) is not str for ref in refs):
                raise ProtocolValueError("invalid_event_value_type")
    frozen = freeze_json(value)
    if type(frozen) is not JsonObject:
        raise ProtocolValueError("invalid_event_value_type")
    return frozen


def _decode_subject_state(value: object) -> SubjectStateRef:
    source = _closed_object(
        value,
        required=frozenset(),
        optional=frozenset({"tree_digest", "diff_digest", "described_state"}),
    )
    tree_digest = _optional(source, "tree_digest")
    diff_digest = _optional(source, "diff_digest")
    described_state = _optional(source, "described_state")
    return SubjectStateRef(
        tree_digest=cast(str | None, tree_digest),
        diff_digest=cast(str | None, diff_digest),
        described_state=cast(str | None, described_state),
    )


def _encode_subject_state(value: SubjectStateRef) -> JsonObject:
    if type(value) is not SubjectStateRef:
        raise ProtocolValueError("invalid_event_value_type")
    result: dict[str, object] = {}
    if value.tree_digest is not None:
        result["tree_digest"] = value.tree_digest
    if value.diff_digest is not None:
        result["diff_digest"] = value.diff_digest
    if value.described_state is not None:
        result["described_state"] = value.described_state
    return JsonObject(result)


def _decode_digest_binding(value: object) -> EvidenceDigestBinding:
    source = _closed_object(
        value,
        required=frozenset({"subject", "content_availability", "byte_count", "provenance"}),
        optional=frozenset({"approval_commitment", "approved_check_result_digest"}),
    )
    return EvidenceDigestBinding(
        subject=_enum_from_json(_field(source, "subject"), EvidenceDigestSubject),
        content_availability=_enum_from_json(
            _field(source, "content_availability"), EvidenceContentAvailability
        ),
        byte_count=cast(int, _field(source, "byte_count")),
        provenance=_enum_from_json(_field(source, "provenance"), EvidenceDigestProvenance),
        approval_commitment=cast(str | None, _optional(source, "approval_commitment")),
        approved_check_result_digest=cast(
            str | None, _optional(source, "approved_check_result_digest")
        ),
    )


def _encode_digest_binding(value: EvidenceDigestBinding) -> JsonObject:
    if type(value) is not EvidenceDigestBinding:
        raise ProtocolValueError("invalid_event_value_type")
    result: dict[str, object] = {
        "subject": value.subject.value,
        "content_availability": value.content_availability.value,
        "byte_count": value.byte_count,
        "provenance": value.provenance.value,
    }
    _optional_value(result, "approval_commitment", value.approval_commitment)
    _optional_value(result, "approved_check_result_digest", value.approved_check_result_digest)
    return JsonObject(result)


def _decode_requested_item(value: object) -> RequestedItem:
    source = _closed_object(
        value,
        required=frozenset({"item_kind", "value"}),
        optional=frozenset({"role"}),
    )
    role = _optional(source, "role")
    return RequestedItem(
        item_kind=_enum_from_json(_field(source, "item_kind"), RequestedItemKind),
        value=cast(str, _field(source, "value")),
        role=None if role is None else _enum_from_json(role, RequestedItemRole),
    )


def _decode_obligation_change(value: object) -> ObligationChange:
    source = _closed_object(
        value,
        required=frozenset({"obligation_id", "change"}),
        optional=frozenset({"reason", "replacement_obligation_ids"}),
    )
    change = _enum_from_json(_field(source, "change"), ObligationChangeKind)
    replacement_value = _optional(source, "replacement_obligation_ids")
    if change is not ObligationChangeKind.SUPERSEDED and "replacement_obligation_ids" in source:
        raise ProtocolValueError("obligation_change_invalid")
    return ObligationChange(
        obligation_id=obligation_id(_field(source, "obligation_id")),
        change=change,
        reason=cast(str | None, _optional(source, "reason")),
        replacement_obligation_ids=(
            ()
            if replacement_value is None
            else cast(
                tuple[ObligationId, ...],
                tuple(_array(replacement_value)),
            )
        ),
    )


def _decode_policy_version(value: object) -> PolicyVersion:
    source = _closed_object(
        value,
        required=frozenset({"policy_id", "policy_version"}),
    )
    return PolicyVersion(
        policy_id=cast(str, _field(source, "policy_id")),
        policy_version=cast(str, _field(source, "policy_version")),
    )


def _decode_scope(value: object) -> CheckScopeModel:
    source = _closed_object(
        value,
        required=frozenset({"claim_ids", "obligation_ids"}),
    )
    claim_ids = _id_tuple(
        tuple(_array(_field(source, "claim_ids"))),
        claim_id,
        field="scope",
    )
    obligation_ids = _id_tuple(
        tuple(_array(_field(source, "obligation_ids"))),
        obligation_id,
        field="scope",
    )
    try:
        return CheckScopeModel.model_validate(
            {
                "claim_ids": claim_ids,
                "obligation_ids": obligation_ids,
            }
        )
    except ValidationError as exc:
        raise ProtocolValueError("invalid_event_value_type") from exc


def _decode_policy_execution(value: object) -> CheckPolicyExecutionModel:
    source = _closed_object(
        value,
        required=frozenset({"policy_id", "policy_version", "outcome", "reason"}),
    )
    try:
        return CheckPolicyExecutionModel.model_validate(dict(source))
    except ValidationError as exc:
        raise ProtocolValueError("invalid_event_enum") from exc


def _nullable(source: Mapping[str, JsonValue], key: str) -> JsonValue | None:
    """Read a nullable lineage field without treating explicit null as an error."""

    if key not in source:
        return None
    return _field(source, key)


def _decode_child_finding(value: object) -> ChildFindingSnapshot:
    source = _closed_object(
        value,
        required=frozenset({"finding_id", "kind", "origin", "priority", "resolved"}),
        optional=frozenset({"resolution_event_id", "actionable", "self_verified"}),
    )
    actionable = _nullable(source, "actionable")
    # Emitted only when true (issue #984); an explicit false is not a recorded spelling.
    self_verified = _field(source, "self_verified") if "self_verified" in source else False
    if "self_verified" in source and self_verified is not True:
        raise ProtocolValueError("invalid_event_value_type")
    return ChildFindingSnapshot(
        finding_id=finding_id(_field(source, "finding_id")),
        kind=_enum_from_json(_field(source, "kind"), FindingKind),
        origin=_enum_from_json(_field(source, "origin"), FindingOrigin),
        priority=cast(int, _field(source, "priority")),
        resolved=cast(bool, _field(source, "resolved")),
        resolution_event_id=(
            None
            if _nullable(source, "resolution_event_id") is None
            else event_id(_field(source, "resolution_event_id"))
        ),
        actionable=(None if actionable is None else cast(bool, actionable)),
        self_verified=cast(bool, self_verified),
    )


def _decode_child_dependency(value: object) -> ChildDependencySnapshot:
    source = _closed_object(
        value,
        required=frozenset(
            {
                "child_task_id",
                "origin",
                "acceptance",
                "work_state",
                "session_health",
                "coverage",
                "findings",
                "lineage_authority_revision",
            }
        ),
        optional=frozenset(
            {
                "child_frontier",
                "child_check_id",
                "child_check_subject_frontier",
                "child_receipt_id",
                "membership_generation",
                "read_gap_reasons",
                "provenance_restrictions",
            }
        ),
    )
    child_frontier_value = _nullable(source, "child_frontier")
    check_frontier_value = _nullable(source, "child_check_subject_frontier")
    check_id_value = _nullable(source, "child_check_id")
    child_receipt_value = _nullable(source, "child_receipt_id")
    generation_value = _nullable(source, "membership_generation")
    generation = None if generation_value is None else _lineage_revision(generation_value)
    gap_value = _nullable(source, "read_gap_reasons")
    restriction_value = _nullable(source, "provenance_restrictions")
    return ChildDependencySnapshot(
        child_task_id=task_id(_field(source, "child_task_id")),
        origin=_enum_from_json(_field(source, "origin"), LineageOrigin),
        acceptance=_enum_from_json(_field(source, "acceptance"), LineageAcceptance),
        work_state=_enum_from_json(_field(source, "work_state"), WorkState),
        session_health=_enum_from_json(_field(source, "session_health"), SessionHealth),
        child_frontier=(
            None if child_frontier_value is None else frontier_from_json(child_frontier_value)
        ),
        child_check_id=(None if check_id_value is None else event_id(check_id_value)),
        child_check_subject_frontier=(
            None if check_frontier_value is None else frontier_from_json(check_frontier_value)
        ),
        child_receipt_id=(None if child_receipt_value is None else receipt_id(child_receipt_value)),
        coverage=coverage_from_json(cast(CanonicalJsonValue, _field(source, "coverage"))),
        findings=tuple(_decode_child_finding(item) for item in _array(_field(source, "findings"))),
        lineage_authority_revision=_lineage_revision(_field(source, "lineage_authority_revision")),
        membership_generation=generation,
        read_gap_reasons=tuple(
            _enum_from_json(item, LineageReadGapReason)
            for item in (() if gap_value is None else _array(gap_value))
        ),
        provenance_restrictions=tuple(
            _enum_from_json(item, LineageProvenanceRestriction)
            for item in (() if restriction_value is None else _array(restriction_value))
        ),
    )


def _decode_child_dependencies(value: object) -> ChildDependenciesRecordedPayload:
    source = _closed_object(value, required=frozenset({"children"}))
    return ChildDependenciesRecordedPayload(
        children=tuple(
            _decode_child_dependency(item) for item in _array(_field(source, "children"))
        )
    )


def _decode_project_text_ref(value: object) -> ProjectTextRef:
    source = _closed_object(
        value,
        required=frozenset(
            {"object_id", "content_digest", "plaintext_size", "owner_task_id", "route_generation"}
        ),
        optional=frozenset({"envelope_digest"}),
    )
    return ProjectTextRef(
        object_id=cast(str, _field(source, "object_id")),
        content_digest=cast(str, _field(source, "content_digest")),
        plaintext_size=cast(int, _field(source, "plaintext_size")),
        owner_task_id=cast(str, _field(source, "owner_task_id")),
        route_generation=_canonical_uint(_field(source, "route_generation")),
        envelope_digest=cast(str | None, _optional(source, "envelope_digest")),
    )


def _decode_coordination_context(value: object) -> CoordinationContextRecordedPayload:
    source = _closed_object(
        value,
        required=frozenset(
            {
                "detection_id",
                "project_id",
                "membership_generation",
                "left_task_id",
                "right_task_id",
                "recipient_task_id",
                "counterpart_task_id",
                "source_task_id",
                "overlap_kind",
                "resource_identities",
                "resource_count",
                "source_repository_commitment",
                "source_workspace_commitment",
                "source_route_generation",
                "source_attributable_paths",
                "context_digest",
            }
        ),
        optional=frozenset({"detail_ref", "gap_codes", "recorded_authority_revision"}),
    )
    gap_codes = _optional(source, "gap_codes")
    return CoordinationContextRecordedPayload(
        detection_id=event_id(_field(source, "detection_id")),
        project_id=cast(str, _field(source, "project_id")),
        membership_generation=_canonical_uint(_field(source, "membership_generation")),
        left_task_id=task_id(_field(source, "left_task_id")),
        right_task_id=task_id(_field(source, "right_task_id")),
        recipient_task_id=task_id(_field(source, "recipient_task_id")),
        counterpart_task_id=task_id(_field(source, "counterpart_task_id")),
        source_task_id=task_id(_field(source, "source_task_id")),
        overlap_kind=_enum_from_json(_field(source, "overlap_kind"), OverlapKind),
        resource_identities=cast(
            tuple[str, ...], tuple(_array(_field(source, "resource_identities")))
        ),
        resource_count=_canonical_uint(_field(source, "resource_count")),
        source_repository_commitment=cast(str, _field(source, "source_repository_commitment")),
        source_workspace_commitment=cast(str, _field(source, "source_workspace_commitment")),
        source_route_generation=_canonical_uint(_field(source, "source_route_generation")),
        source_attributable_paths=cast(bool, _field(source, "source_attributable_paths")),
        context_digest=cast(str, _field(source, "context_digest")),
        detail_ref=(
            None
            if "detail_ref" not in source
            else _decode_project_text_ref(_field(source, "detail_ref"))
        ),
        gap_codes=(
            ()
            if gap_codes is None
            else tuple(_enum_from_json(item, CoordinationGapCode) for item in _array(gap_codes))
        ),
        recorded_authority_revision=cast(
            str | None,
            _optional(source, "recorded_authority_revision"),
        ),
    )


def _decode_coordination_obligation_declared(
    value: object,
) -> CoordinationObligationDeclaredPayload:
    source = _closed_object(
        value,
        required=frozenset(
            {
                "detection_id",
                "project_id",
                "membership_generation",
                "recipient_task_id",
                "obligation_id",
            }
        ),
    )
    return CoordinationObligationDeclaredPayload(
        detection_id=event_id(_field(source, "detection_id")),
        project_id=cast(str, _field(source, "project_id")),
        membership_generation=_canonical_uint(_field(source, "membership_generation")),
        recipient_task_id=task_id(_field(source, "recipient_task_id")),
        obligation_id=obligation_id(_field(source, "obligation_id")),
    )


def _decode_coordination_disposition(
    value: object,
) -> CoordinationDispositionRecordedPayload:
    source = _closed_object(
        value,
        required=frozenset(
            {
                "detection_id",
                "project_id",
                "membership_generation",
                "recipient_task_id",
                "obligation_id",
                "disposition",
                "evidence_refs",
            }
        ),
        optional=frozenset({"finding_id", "context_digest"}),
    )
    return CoordinationDispositionRecordedPayload(
        detection_id=event_id(_field(source, "detection_id")),
        project_id=cast(str, _field(source, "project_id")),
        membership_generation=_canonical_uint(_field(source, "membership_generation")),
        recipient_task_id=task_id(_field(source, "recipient_task_id")),
        obligation_id=obligation_id(_field(source, "obligation_id")),
        disposition=_enum_from_json(_field(source, "disposition"), CoordinationDisposition),
        evidence_refs=cast(
            tuple[EvidenceId | ResultId, ...], tuple(_array(_field(source, "evidence_refs")))
        ),
        finding_id=(
            None if "finding_id" not in source else finding_id(_field(source, "finding_id"))
        ),
        context_digest=cast(str | None, _optional(source, "context_digest")),
    )


def _decode_session_opened(source: Mapping[str, JsonValue]) -> SessionOpenedPayload:
    return SessionOpenedPayload(
        task_title=cast(str, _field(source, "task_title")),
        client_kind=_enum_from_json(_field(source, "client_kind"), ClientKind),
        client_version=cast(str, _field(source, "client_version")),
        integration=_enum_from_json(_field(source, "integration"), IntegrationKind),
        profile=_enum_from_json(_field(source, "profile"), RuntimeProfile),
        external_ref=cast(str | None, _optional(source, "external_ref")),
        workspace_ref=cast(str | None, _optional(source, "workspace_ref")),
        parent_task_id=cast(TaskId | None, _optional(source, "parent_task_id")),
        depth=cast(int | None, _optional(source, "depth")),
        origin=(
            None
            if _optional(source, "origin") is None
            else _enum_from_json(_field(source, "origin"), LineageOrigin)
        ),
        project_id=cast(str | None, _optional(source, "project_id")),
        membership_generation=(
            None
            if _optional(source, "membership_generation") is None
            else _lineage_revision(_field(source, "membership_generation"))
        ),
        task_statement=cast(str | None, _optional(source, "task_statement")),
    )


def _decode_session_resumed(source: Mapping[str, JsonValue]) -> SessionResumedPayload:
    return SessionResumedPayload(
        client_kind=_enum_from_json(_field(source, "client_kind"), ClientKind),
        client_version=cast(str, _field(source, "client_version")),
        integration=_enum_from_json(_field(source, "integration"), IntegrationKind),
        profile=_enum_from_json(_field(source, "profile"), RuntimeProfile),
        resumed_frontier=frontier_from_json(_field(source, "resumed_frontier")),
        task_statement=cast(str | None, _optional(source, "task_statement")),
    )


_PAYLOAD_SHAPES: Final[Mapping[str, tuple[frozenset[str], frozenset[str]]]] = MappingProxyType(
    {
        "session_opened": (
            frozenset({"task_title", "client_kind", "client_version", "integration", "profile"}),
            frozenset(
                {
                    "external_ref",
                    "workspace_ref",
                    "parent_task_id",
                    "depth",
                    "origin",
                    "project_id",
                    "membership_generation",
                    "task_statement",
                }
            ),
        ),
        "session_resumed": (
            frozenset(
                {"client_kind", "client_version", "integration", "profile", "resumed_frontier"}
            ),
            frozenset({"task_statement"}),
        ),
        "plan_published": (
            frozenset({"plan_version", "summary", "obligation_refs"}),
            frozenset({"scope_exclusions", "no_obligations_reason", "task_statement"}),
        ),
        "obligation_published": (
            frozenset({"obligation_id", "description", "evidence_expectation", "status"}),
            frozenset(
                {
                    "acceptance_criteria",
                    "requested_items",
                    "source_refs",
                    "resolution_evidence_refs",
                    "acknowledged_not_done_reason",
                }
            ),
        ),
        "assignment_recorded": (
            frozenset({"assignee_actor_id", "obligation_ids", "scope_description"}),
            frozenset({"write_policy", "handoff_of"}),
        ),
        "decision_recorded": (
            frozenset({"statement", "rationale", "authority"}),
            frozenset({"alternatives", "affected_obligation_ids", "supersedes_event_id"}),
        ),
        "action_recorded": (
            frozenset({"action_id", "action_kind", "description"}),
            frozenset({"command", "subject_state", "obligation_refs", "attempted_items"}),
        ),
        "result_recorded": (
            frozenset({"result_id", "action_id", "outcome"}),
            frozenset({"exit_status", "summary", "subject_state", "evidence_refs"}),
        ),
        "evidence_recorded": (
            frozenset({"evidence_id", "evidence_kind", "strength", "observed_at"}),
            frozenset(
                {
                    "reference",
                    "captured_object_id",
                    "content_digest",
                    "description",
                    "subject_state",
                }
            ),
        ),
        "claim_recorded": (
            frozenset({"claim_id", "claim_kind", "statement", "supporting_refs"}),
            frozenset({"subject_state", "obligation_refs", "disputes_refs"}),
        ),
        "plan_revised": (
            frozenset(
                {
                    "plan_version",
                    "supersedes_plan_version",
                    "reason",
                    "summary",
                    "obligation_changes",
                }
            ),
            frozenset({"no_obligations_reason", "task_statement"}),
        ),
        "response_recorded": (
            frozenset({"finding_id", "finding_frontier", "disposition"}),
            frozenset(
                {
                    "reason",
                    "waiver_scope",
                    "waiver_expiry",
                    "evidence_refs",
                    "duplicate_of_finding_id",
                }
            ),
        ),
        "redaction_recorded": (
            frozenset(
                {
                    "target_event_ids",
                    "target_object_ids",
                    "method",
                    "reason_category",
                    "authority",
                    "remaining_gap",
                }
            ),
            frozenset(),
        ),
        "check_recorded": (
            frozenset(
                {
                    "mode",
                    "policies",
                    "scope",
                    "policy_executions",
                    "subject_frontier",
                    "verdict",
                    "returned_finding_ids",
                    "suppressed_count",
                    "coverage",
                    "semantic_status",
                    "semantic_reason",
                    "engine_version",
                    "projection_version",
                }
            ),
            frozenset(
                {
                    "semantic_provenance",
                    "semantic_conclusion",
                    "review_summary",
                    "verified",
                    "prior_finding_verdicts",
                    "missing_for_assessment",
                    "check_change_files",
                    "semantic_included_refs",
                    "semantic_withheld_item_ids",
                    "semantic_redacted_values",
                    "semantic_route_required",
                    "deliverable_states",
                    "review_input_manifest",
                    "review_mode",
                    "totals",
                }
            ),
        ),
        "receipt_recorded": (
            frozenset(
                {
                    "receipt_id",
                    "subject_frontier",
                    "receipt_digest",
                    "receipt_object_id",
                    "conclusion_code",
                    "redaction_profile",
                }
            ),
            frozenset(),
        ),
        "child_dependencies_recorded": (
            frozenset({"children"}),
            frozenset(),
        ),
        "coordination_context_recorded": (
            frozenset(
                {
                    "detection_id",
                    "project_id",
                    "membership_generation",
                    "left_task_id",
                    "right_task_id",
                    "recipient_task_id",
                    "counterpart_task_id",
                    "source_task_id",
                    "overlap_kind",
                    "resource_identities",
                    "resource_count",
                    "source_repository_commitment",
                    "source_workspace_commitment",
                    "source_route_generation",
                    "source_attributable_paths",
                    "context_digest",
                }
            ),
            frozenset({"detail_ref", "gap_codes", "recorded_authority_revision"}),
        ),
        "coordination_obligation_declared": (
            frozenset(
                {
                    "detection_id",
                    "project_id",
                    "membership_generation",
                    "recipient_task_id",
                    "obligation_id",
                }
            ),
            frozenset(),
        ),
        "coordination_disposition_recorded": (
            frozenset(
                {
                    "detection_id",
                    "project_id",
                    "membership_generation",
                    "recipient_task_id",
                    "obligation_id",
                    "disposition",
                    "evidence_refs",
                }
            ),
            frozenset({"finding_id", "context_digest"}),
        ),
        "delegation_declared": (
            frozenset({"child_task_id", "handle_digest", "depth"}),
            frozenset({"project_id", "membership_generation"}),
        ),
        "delegation_cancelled": (
            frozenset({"child_task_id"}),
            frozenset({"reason_code"}),
        ),
        "child_accepted": (
            frozenset({"child_task_id"}),
            frozenset(),
        ),
        "child_rejected": (
            frozenset({"child_task_id"}),
            frozenset({"reason_code"}),
        ),
        "child_written_off": (
            frozenset({"child_task_id"}),
            frozenset({"reason_code"}),
        ),
        "work_closed": (
            frozenset(),
            frozenset({"reason_code"}),
        ),
        "work_abandoned": (
            frozenset({"service_stamped"}),
            frozenset({"reason_code"}),
        ),
        "work_cancelled": (
            frozenset(),
            frozenset({"reason_code"}),
        ),
        "work_written_off": (
            frozenset(),
            frozenset({"reason_code"}),
        ),
    }
)


def _decode_prior_verdicts(value: JsonValue | None) -> tuple[PriorFindingVerdictRecord, ...]:
    if value is None:
        return ()
    rows = _array(value)
    if not rows:
        raise ProtocolValueError("invalid_event_value_type")
    verdicts: list[PriorFindingVerdictRecord] = []
    for row in rows:
        source = _closed_object(
            row,
            required=frozenset({"cited_refs", "finding_id", "verdict"}),
            optional=frozenset(),
        )
        verdicts.append(
            PriorFindingVerdictRecord(
                finding_id=finding_id(_field(source, "finding_id")),
                verdict=cast(str, _field(source, "verdict")),
                cited_refs=cast(tuple[str, ...], tuple(_array(_field(source, "cited_refs")))),
            )
        )
    return tuple(verdicts)


def decode_payload(schema: EventSchema, payload: JsonValue) -> EventPayload:
    """Decode one exact known schema pair into its immutable domain payload."""

    if type(schema) is not EventSchema:
        raise ProtocolValueError("invalid_event_schema")
    if schema not in PAYLOAD_TYPES:
        raise ProtocolValueError("unknown_event_schema")
    frozen = freeze_json(payload)
    if schema.name == "finding_recorded":
        finding = finding_event_from_json(frozen)
        _validate_event_schema_payload(schema, finding)
        return finding
    required, optional = _PAYLOAD_SHAPES[schema.name]
    if schema.name == "evidence_recorded" and schema.version != SCHEMA_VERSION:
        optional = frozenset({*optional, "digest_binding"})
    if schema == EventSchema("claim_recorded", CLAIM_SCHEMA_VERSION):
        required = frozenset({*required, "limitation_refs", "supersedes_claim_refs"})
    if schema == EventSchema("decision_recorded", DECISION_REVIEW_MODE_SCHEMA_VERSION):
        required = frozenset({*required, "review_mode"})
    source = _closed_object(frozen, required=required, optional=optional)

    if schema.name == "child_dependencies_recorded":
        return _decode_child_dependencies(source)
    if schema.name == "coordination_context_recorded":
        return _decode_coordination_context(source)
    if schema.name == "coordination_obligation_declared":
        return _decode_coordination_obligation_declared(source)
    if schema.name == "coordination_disposition_recorded":
        return _decode_coordination_disposition(source)
    if schema.name == "delegation_declared":
        return DelegationDeclaredPayload(
            child_task_id=task_id(_field(source, "child_task_id")),
            handle_digest=cast(str, _field(source, "handle_digest")),
            depth=cast(int, _field(source, "depth")),
            project_id=cast(str | None, _optional(source, "project_id")),
            membership_generation=(
                None
                if _optional(source, "membership_generation") is None
                else _lineage_revision(_field(source, "membership_generation"))
            ),
        )
    if schema.name == "delegation_cancelled":
        return DelegationCancelledPayload(
            child_task_id=task_id(_field(source, "child_task_id")),
            reason_code=cast(str | None, _optional(source, "reason_code")),
        )
    if schema.name == "child_accepted":
        return ChildAcceptedPayload(child_task_id=task_id(_field(source, "child_task_id")))
    if schema.name == "child_rejected":
        return ChildRejectedPayload(
            child_task_id=task_id(_field(source, "child_task_id")),
            reason_code=cast(str | None, _optional(source, "reason_code")),
        )
    if schema.name == "child_written_off":
        return ChildWrittenOffPayload(
            child_task_id=task_id(_field(source, "child_task_id")),
            reason_code=cast(str | None, _optional(source, "reason_code")),
        )
    if schema.name == "work_closed":
        return WorkClosedPayload(reason_code=cast(str | None, _optional(source, "reason_code")))
    if schema.name == "work_abandoned":
        return WorkAbandonedPayload(
            service_stamped=cast(Literal[True], _field(source, "service_stamped")),
            reason_code=cast(str | None, _optional(source, "reason_code")),
        )
    if schema.name == "work_cancelled":
        return WorkCancelledPayload(reason_code=cast(str | None, _optional(source, "reason_code")))
    if schema.name == "work_written_off":
        return WorkWrittenOffPayload(reason_code=cast(str | None, _optional(source, "reason_code")))
    if schema.name == "session_opened":
        opened = _decode_session_opened(source)
        _validate_event_schema_payload(schema, opened)
        return opened
    if schema.name == "session_resumed":
        resumed = _decode_session_resumed(source)
        _validate_event_schema_payload(schema, resumed)
        return resumed
    if schema.name == "plan_published":
        exclusions = _optional(source, "scope_exclusions")
        no_obligations_reason = _optional(source, "no_obligations_reason")
        published = PlanPublishedPayload(
            plan_version=cast(int, _field(source, "plan_version")),
            summary=cast(str, _field(source, "summary")),
            obligation_refs=cast(
                tuple[ObligationId, ...], tuple(_array(_field(source, "obligation_refs")))
            ),
            scope_exclusions=(
                () if exclusions is None else cast(tuple[str, ...], tuple(_array(exclusions)))
            ),
            no_obligations_reason=(
                None
                if no_obligations_reason is None
                else _enum_from_json(no_obligations_reason, NoObligationsReason)
            ),
            task_statement=cast(str | None, _optional(source, "task_statement")),
        )
        _validate_event_schema_payload(schema, published)
        return published
    if schema.name == "obligation_published":
        status = _enum_from_json(_field(source, "status"), ObligationStatus)
        resolution_refs = _optional(source, "resolution_evidence_refs")
        if status is not ObligationStatus.RESOLVED and "resolution_evidence_refs" in source:
            raise ProtocolValueError("obligation_resolution_invalid")
        requested = _optional(source, "requested_items")
        source_refs = _optional(source, "source_refs")
        published_obligation = ObligationPublishedPayload(
            obligation_id=obligation_id(_field(source, "obligation_id")),
            description=cast(str, _field(source, "description")),
            evidence_expectation=cast(str, _field(source, "evidence_expectation")),
            status=status,
            acceptance_criteria=cast(str | None, _optional(source, "acceptance_criteria")),
            requested_items=(
                ()
                if requested is None
                else tuple(_decode_requested_item(item) for item in _array(requested))
            ),
            source_refs=(
                () if source_refs is None else cast(tuple[EventId, ...], tuple(_array(source_refs)))
            ),
            resolution_evidence_refs=(
                ()
                if resolution_refs is None
                else cast(
                    tuple[EvidenceId | ResultId, ...],
                    tuple(_array(resolution_refs)),
                )
            ),
            acknowledged_not_done_reason=cast(
                str | None, _optional(source, "acknowledged_not_done_reason")
            ),
        )
        _validate_event_schema_payload(schema, published_obligation)
        return published_obligation
    if schema.name == "assignment_recorded":
        obligations = tuple(_array(_field(source, "obligation_ids")))
        write_policy_value = _optional(source, "write_policy")
        handoff = _optional(source, "handoff_of")
        return AssignmentRecordedPayload(
            assignee_actor_id=actor_id(_field(source, "assignee_actor_id")),
            obligation_ids=cast(tuple[ObligationId, ...], obligations),
            scope_description=cast(str, _field(source, "scope_description")),
            write_policy=(
                None
                if write_policy_value is None
                else _enum_from_json(write_policy_value, WritePolicy)
            ),
            handoff_of=None if handoff is None else event_id(handoff),
        )
    if schema.name == "decision_recorded":
        alternatives = _optional(source, "alternatives")
        affected = _optional(source, "affected_obligation_ids")
        supersedes = _optional(source, "supersedes_event_id")
        review_mode = _optional(source, "review_mode")
        decision = DecisionRecordedPayload(
            statement=cast(str, _field(source, "statement")),
            rationale=cast(str, _field(source, "rationale")),
            authority=actor_id(_field(source, "authority")),
            alternatives=(
                () if alternatives is None else cast(tuple[str, ...], tuple(_array(alternatives)))
            ),
            affected_obligation_ids=(
                () if affected is None else cast(tuple[ObligationId, ...], tuple(_array(affected)))
            ),
            supersedes_event_id=None if supersedes is None else event_id(supersedes),
            review_mode=(None if review_mode is None else _enum_from_json(review_mode, ReviewMode)),
        )
        _validate_event_schema_payload(schema, decision)
        return decision
    if schema.name == "action_recorded":
        command = _optional(source, "command")
        state = _optional(source, "subject_state")
        obligations = _optional(source, "obligation_refs")
        attempted = _optional(source, "attempted_items")
        return ActionRecordedPayload(
            action_id=action_id(_field(source, "action_id")),
            action_kind=_enum_from_json(_field(source, "action_kind"), ActionKind),
            description=cast(str, _field(source, "description")),
            command=cast(str | None, command),
            subject_state=None if state is None else _decode_subject_state(state),
            obligation_refs=(
                ()
                if obligations is None
                else cast(tuple[ObligationId, ...], tuple(_array(obligations)))
            ),
            attempted_items=(
                () if attempted is None else cast(tuple[str, ...], tuple(_array(attempted)))
            ),
        )
    if schema.name == "result_recorded":
        state = _optional(source, "subject_state")
        evidence = _optional(source, "evidence_refs")
        return ResultRecordedPayload(
            result_id=result_id(_field(source, "result_id")),
            action_id=action_id(_field(source, "action_id")),
            outcome=_enum_from_json(_field(source, "outcome"), ResultOutcome),
            exit_status=cast(int | None, _optional(source, "exit_status")),
            summary=cast(str | None, _optional(source, "summary")),
            subject_state=None if state is None else _decode_subject_state(state),
            evidence_refs=(
                () if evidence is None else cast(tuple[EvidenceId, ...], tuple(_array(evidence)))
            ),
        )
    if schema.name == "evidence_recorded":
        state = _optional(source, "subject_state")
        raw_binding = _optional(source, "digest_binding")
        content_digest = cast(str | None, _optional(source, "content_digest"))
        if schema.version == SCHEMA_VERSION and raw_binding is not None:
            raise ProtocolValueError("invalid_event_value_type")
        if schema.version != SCHEMA_VERSION and ((content_digest is None) != (raw_binding is None)):
            raise ProtocolValueError("evidence_digest_binding_required")
        decoded = EvidenceRecordedPayload(
            evidence_id=evidence_id(_field(source, "evidence_id")),
            evidence_kind=_enum_from_json(_field(source, "evidence_kind"), EvidenceKind),
            strength=_enum_from_json(_field(source, "strength"), EvidenceImmutability),
            observed_at=timestamp_from_string(_field(source, "observed_at")),
            reference=cast(str | None, _optional(source, "reference")),
            captured_object_id=(
                None
                if _optional(source, "captured_object_id") is None
                else object_id(_field(source, "captured_object_id"))
            ),
            content_digest=content_digest,
            description=cast(str | None, _optional(source, "description")),
            subject_state=None if state is None else _decode_subject_state(state),
            digest_binding=(None if raw_binding is None else _decode_digest_binding(raw_binding)),
        )
        if (
            schema.version == EVIDENCE_TYPED_SCHEMA_VERSION
            and decoded.digest_binding is not None
            and decoded.digest_binding.provenance is EvidenceDigestProvenance.OBSERVATION_CAPTURED
        ):
            raise ProtocolValueError("evidence_digest_provenance_invalid")
        return decoded
    if schema.name == "claim_recorded":
        state = _optional(source, "subject_state")
        obligations = _optional(source, "obligation_refs")
        disputes = _optional(source, "disputes_refs")
        claim_id_value = claim_id(_field(source, "claim_id"))
        claim_kind_value = _enum_from_json(_field(source, "claim_kind"), ClaimKind)
        statement = cast(str, _field(source, "statement"))
        supporting_refs = cast(
            tuple[EvidenceId | ResultId | ObligationId, ...],
            tuple(_array(_field(source, "supporting_refs"))),
        )
        subject_state = None if state is None else _decode_subject_state(state)
        obligation_refs = (
            ()
            if obligations is None
            else cast(tuple[ObligationId, ...], tuple(_array(obligations)))
        )
        disputes_refs = (
            () if disputes is None else cast(tuple[ClaimId | EventId, ...], tuple(_array(disputes)))
        )
        if schema.version != CLAIM_SCHEMA_VERSION:
            return ClaimRecordedPayload(
                claim_id=claim_id_value,
                claim_kind=claim_kind_value,
                statement=statement,
                supporting_refs=supporting_refs,
                subject_state=subject_state,
                obligation_refs=obligation_refs,
                disputes_refs=disputes_refs,
            )
        limitations = _optional(source, "limitation_refs")
        superseded = _optional(source, "supersedes_claim_refs")
        return ClaimRecordedPayloadV1_1(
            claim_id=claim_id_value,
            claim_kind=claim_kind_value,
            statement=statement,
            supporting_refs=supporting_refs,
            subject_state=subject_state,
            obligation_refs=obligation_refs,
            disputes_refs=disputes_refs,
            limitation_refs=(
                ()
                if limitations is None
                else cast(tuple[ResultId, ...], tuple(_array(limitations)))
            ),
            supersedes_claim_refs=(
                () if superseded is None else cast(tuple[ClaimId, ...], tuple(_array(superseded)))
            ),
        )
    if schema.name == "plan_revised":
        no_obligations_reason = _optional(source, "no_obligations_reason")
        revised = PlanRevisedPayload(
            plan_version=cast(int, _field(source, "plan_version")),
            supersedes_plan_version=cast(int, _field(source, "supersedes_plan_version")),
            reason=cast(str, _field(source, "reason")),
            summary=cast(str, _field(source, "summary")),
            obligation_changes=tuple(
                _decode_obligation_change(item)
                for item in _array(_field(source, "obligation_changes"))
            ),
            no_obligations_reason=(
                None
                if no_obligations_reason is None
                else _enum_from_json(no_obligations_reason, NoObligationsReason)
            ),
            task_statement=cast(str | None, _optional(source, "task_statement")),
        )
        _validate_event_schema_payload(schema, revised)
        return revised
    if schema.name == "response_recorded":
        evidence = _optional(source, "evidence_refs")
        waiver_scope_value = _optional(source, "waiver_scope")
        waiver_expiry_value = _optional(source, "waiver_expiry")
        duplicate_of_value = _optional(source, "duplicate_of_finding_id")
        return ResponseRecordedPayload(
            finding_id=finding_id(_field(source, "finding_id")),
            finding_frontier=frontier_from_json(_field(source, "finding_frontier")),
            disposition=_enum_from_json(_field(source, "disposition"), ResponseDisposition),
            reason=cast(str | None, _optional(source, "reason")),
            waiver_scope=(
                None
                if waiver_scope_value is None
                else _enum_from_json(waiver_scope_value, WaiverScope)
            ),
            waiver_expiry=(
                None if waiver_expiry_value is None else timestamp_from_string(waiver_expiry_value)
            ),
            evidence_refs=(
                ()
                if evidence is None
                else cast(tuple[EvidenceId | ResultId, ...], tuple(_array(evidence)))
            ),
            duplicate_of_finding_id=(
                None if duplicate_of_value is None else finding_id(duplicate_of_value)
            ),
        )
    if schema.name == "redaction_recorded":
        return RedactionRecordedPayload(
            target_event_ids=cast(
                tuple[EventId, ...], tuple(_array(_field(source, "target_event_ids")))
            ),
            target_object_ids=cast(
                tuple[ObjectId, ...], tuple(_array(_field(source, "target_object_ids")))
            ),
            method=_enum_from_json(_field(source, "method"), RedactionMethod),
            reason_category=_enum_from_json(
                _field(source, "reason_category"), RedactionReasonCategory
            ),
            authority=actor_id(_field(source, "authority")),
            remaining_gap=cast(str, _field(source, "remaining_gap")),
        )
    if schema.name == "check_recorded":
        provenance_value = _optional(source, "semantic_provenance")
        verified_value = _optional(source, "verified")
        check = CheckRecordedPayload(
            mode=_enum_from_json(_field(source, "mode"), CheckMode),
            policies=tuple(
                _decode_policy_version(item) for item in _array(_field(source, "policies"))
            ),
            scope=_decode_scope(_field(source, "scope")),
            policy_executions=tuple(
                _decode_policy_execution(item)
                for item in _array(_field(source, "policy_executions"))
            ),
            subject_frontier=frontier_from_json(_field(source, "subject_frontier")),
            verdict=_enum_from_json(_field(source, "verdict"), CheckVerdict),
            returned_finding_ids=cast(
                tuple[FindingId, ...],
                tuple(_array(_field(source, "returned_finding_ids"))),
            ),
            suppressed_count=cast(int, _field(source, "suppressed_count")),
            coverage=coverage_from_json(cast(CanonicalJsonValue, _field(source, "coverage"))),
            semantic_status=_enum_from_json(_field(source, "semantic_status"), SemanticStatus),
            semantic_reason=_enum_from_json(_field(source, "semantic_reason"), SemanticReason),
            engine_version=cast(str, _field(source, "engine_version")),
            projection_version=cast(str, _field(source, "projection_version")),
            semantic_conclusion=cast(str | None, _optional(source, "semantic_conclusion")),
            review_summary=cast(str | None, _optional(source, "review_summary")),
            verified=(
                ()
                if verified_value is None
                else tuple(cast(JsonObject, freeze_json(item)) for item in _array(verified_value))
            ),
            prior_finding_verdicts=_decode_prior_verdicts(
                _optional(source, "prior_finding_verdicts")
            ),
            missing_for_assessment=_missing_items_from_json(
                _optional(source, "missing_for_assessment")
            ),
            check_change_files=_decode_check_change_files(_optional(source, "check_change_files")),
            semantic_included_refs=(
                None
                if (included := _optional(source, "semantic_included_refs")) is None
                else cast(tuple[str, ...], tuple(_array(included)))
            ),
            semantic_withheld_item_ids=cast(
                tuple[str, ...],
                tuple(_array(_optional(source, "semantic_withheld_item_ids")))
                if _optional(source, "semantic_withheld_item_ids") is not None
                else (),
            ),
            semantic_redacted_values=(
                ()
                if (redacted := _optional(source, "semantic_redacted_values")) is None
                else semantic_redacted_values_from_wire(_array(redacted))
            ),
            review_input_manifest=_review_input_manifest_from_json(
                _optional(source, "review_input_manifest")
            ),
            semantic_route_required=cast(bool | None, _optional(source, "semantic_route_required")),
            review_mode=(
                None
                if (recorded_mode := _optional(source, "review_mode")) is None
                else CheckReviewMode.from_wire(recorded_mode)
            ),
            deliverable_states=tuple(
                DeliverableState.from_wire(item)
                for item in _array(_optional(source, "deliverable_states") or ())
            ),
            totals=(
                None
                if _optional(source, "totals") is None
                else cast(JsonObject, freeze_json(_field(source, "totals")))
            ),
            semantic_provenance=(
                None
                if provenance_value is None
                else semantic_provenance_from_json(provenance_value)
            ),
        )
        _validate_event_schema_payload(schema, check)
        return check
    if schema.name == "receipt_recorded":
        return ReceiptRecordedPayload(
            receipt_id=receipt_id(_field(source, "receipt_id")),
            subject_frontier=frontier_from_json(_field(source, "subject_frontier")),
            receipt_digest=cast(str, _field(source, "receipt_digest")),
            receipt_object_id=object_id(_field(source, "receipt_object_id")),
            conclusion_code=_enum_from_json(_field(source, "conclusion_code"), ReceiptConclusion),
            redaction_profile=_enum_from_json(
                _field(source, "redaction_profile"), ReceiptRedactionProfile
            ),
        )
    raise ProtocolValueError("unsupported_payload_type")


def _json_object(fields: Mapping[str, object]) -> JsonObject:
    frozen = freeze_json(fields)
    if type(frozen) is not JsonObject:
        raise ProtocolValueError("unsupported_payload_type")
    return frozen


def _optional_value(result: dict[str, object], key: str, value: object | None) -> None:
    if value is not None:
        result[key] = value


def _optional_tuple(result: dict[str, object], key: str, value: tuple[object, ...]) -> None:
    if value:
        result[key] = value


def _encode_child_finding(value: ChildFindingSnapshot) -> JsonObject:
    if type(value) is not ChildFindingSnapshot:
        raise ProtocolValueError("invalid_event_value_type")
    result: dict[str, object] = {
        "finding_id": value.finding_id,
        "kind": value.kind.value,
        "origin": value.origin.value,
        "priority": value.priority,
        "actionable": value.actionable,
        "resolved": value.resolved,
    }
    _optional_value(result, "resolution_event_id", value.resolution_event_id)
    if value.self_verified:
        result["self_verified"] = True
    return _json_object(result)


def _encode_child_dependency(value: ChildDependencySnapshot) -> JsonObject:
    if type(value) is not ChildDependencySnapshot:
        raise ProtocolValueError("invalid_event_value_type")
    result: dict[str, object] = {
        "child_task_id": value.child_task_id,
        "origin": value.origin.value,
        "acceptance": value.acceptance.value,
        "work_state": value.work_state.value,
        "session_health": value.session_health.value,
        "coverage": coverage_to_json(value.coverage),
        "findings": tuple(_encode_child_finding(item) for item in value.findings),
        "lineage_authority_revision": render_wire_sequence(value.lineage_authority_revision),
    }
    _optional_value(
        result,
        "child_frontier",
        None if value.child_frontier is None else value.child_frontier.as_wire(),
    )
    _optional_value(result, "child_check_id", value.child_check_id)
    _optional_value(
        result,
        "child_check_subject_frontier",
        None
        if value.child_check_subject_frontier is None
        else value.child_check_subject_frontier.as_wire(),
    )
    _optional_value(result, "child_receipt_id", value.child_receipt_id)
    if value.membership_generation is not None:
        result["membership_generation"] = render_wire_sequence(value.membership_generation)
    _optional_tuple(
        result,
        "read_gap_reasons",
        tuple(item.value for item in value.read_gap_reasons),
    )
    _optional_tuple(
        result,
        "provenance_restrictions",
        tuple(item.value for item in value.provenance_restrictions),
    )
    return _json_object(result)


def _encode_project_text_ref(value: ProjectTextRef) -> JsonObject:
    if type(value) is not ProjectTextRef:
        raise ProtocolValueError("invalid_event_value_type")
    result: dict[str, object] = {
        "object_id": value.object_id,
        "content_digest": value.content_digest,
        "plaintext_size": value.plaintext_size,
        "owner_task_id": value.owner_task_id,
        "route_generation": render_wire_sequence(value.route_generation),
    }
    _optional_value(result, "envelope_digest", value.envelope_digest)
    return _json_object(result)


def encode_payload(payload: EventPayload) -> JsonValue:
    """Encode one exact payload type into its normalized closed frozen JSON object."""

    payload_type = type(payload)
    if payload_type is Finding:
        return finding_event_to_json(cast(Finding, payload))
    if payload_type is ChildDependenciesRecordedPayload:
        value = cast(ChildDependenciesRecordedPayload, payload)
        return _json_object(
            {"children": tuple(_encode_child_dependency(item) for item in value.children)}
        )
    if payload_type is CoordinationContextRecordedPayload:
        value = cast(CoordinationContextRecordedPayload, payload)
        result: dict[str, object] = {
            "detection_id": value.detection_id,
            "project_id": value.project_id,
            "membership_generation": render_wire_sequence(value.membership_generation),
            "left_task_id": value.left_task_id,
            "right_task_id": value.right_task_id,
            "recipient_task_id": value.recipient_task_id,
            "counterpart_task_id": value.counterpart_task_id,
            "source_task_id": value.source_task_id,
            "overlap_kind": value.overlap_kind.value,
            "resource_identities": value.resource_identities,
            "resource_count": render_wire_sequence(value.resource_count),
            "source_repository_commitment": value.source_repository_commitment,
            "source_workspace_commitment": value.source_workspace_commitment,
            "source_route_generation": render_wire_sequence(value.source_route_generation),
            "source_attributable_paths": value.source_attributable_paths,
            "context_digest": value.context_digest,
        }
        _optional_value(
            result,
            "detail_ref",
            None if value.detail_ref is None else _encode_project_text_ref(value.detail_ref),
        )
        _optional_tuple(result, "gap_codes", tuple(item.value for item in value.gap_codes))
        _optional_value(result, "recorded_authority_revision", value.recorded_authority_revision)
        return _json_object(result)
    if payload_type is CoordinationObligationDeclaredPayload:
        value = cast(CoordinationObligationDeclaredPayload, payload)
        return _json_object(
            {
                "detection_id": value.detection_id,
                "project_id": value.project_id,
                "membership_generation": render_wire_sequence(value.membership_generation),
                "recipient_task_id": value.recipient_task_id,
                "obligation_id": value.obligation_id,
            }
        )
    if payload_type is CoordinationDispositionRecordedPayload:
        value = cast(CoordinationDispositionRecordedPayload, payload)
        result = {
            "detection_id": value.detection_id,
            "project_id": value.project_id,
            "membership_generation": render_wire_sequence(value.membership_generation),
            "recipient_task_id": value.recipient_task_id,
            "obligation_id": value.obligation_id,
            "disposition": value.disposition.value,
            "evidence_refs": value.evidence_refs,
        }
        _optional_value(result, "finding_id", value.finding_id)
        _optional_value(result, "context_digest", value.context_digest)
        return _json_object(result)
    if payload_type is DelegationDeclaredPayload:
        value = cast(DelegationDeclaredPayload, payload)
        result = {
            "child_task_id": value.child_task_id,
            "handle_digest": value.handle_digest,
            "depth": value.depth,
        }
        _optional_value(result, "project_id", value.project_id)
        if value.membership_generation is not None:
            result["membership_generation"] = render_wire_sequence(value.membership_generation)
        return _json_object(result)
    if payload_type is DelegationCancelledPayload:
        value = cast(DelegationCancelledPayload, payload)
        result = {"child_task_id": value.child_task_id}
        _optional_value(result, "reason_code", value.reason_code)
        return _json_object(result)
    if payload_type is ChildAcceptedPayload:
        value = cast(ChildAcceptedPayload, payload)
        return _json_object({"child_task_id": value.child_task_id})
    if payload_type is ChildRejectedPayload:
        value = cast(ChildRejectedPayload, payload)
        result = {"child_task_id": value.child_task_id}
        _optional_value(result, "reason_code", value.reason_code)
        return _json_object(result)
    if payload_type is ChildWrittenOffPayload:
        value = cast(ChildWrittenOffPayload, payload)
        result = {"child_task_id": value.child_task_id}
        _optional_value(result, "reason_code", value.reason_code)
        return _json_object(result)
    if payload_type is WorkClosedPayload:
        value = cast(WorkClosedPayload, payload)
        result: dict[str, object] = {}
        _optional_value(result, "reason_code", value.reason_code)
        return _json_object(result)
    if payload_type is WorkAbandonedPayload:
        value = cast(WorkAbandonedPayload, payload)
        result = {"service_stamped": value.service_stamped}
        _optional_value(result, "reason_code", value.reason_code)
        return _json_object(result)
    if payload_type is WorkCancelledPayload:
        value = cast(WorkCancelledPayload, payload)
        result = {}
        _optional_value(result, "reason_code", value.reason_code)
        return _json_object(result)
    if payload_type is WorkWrittenOffPayload:
        value = cast(WorkWrittenOffPayload, payload)
        result = {}
        _optional_value(result, "reason_code", value.reason_code)
        return _json_object(result)
    result: dict[str, object]
    if payload_type is SessionOpenedPayload:
        value = cast(SessionOpenedPayload, payload)
        result = {
            "task_title": value.task_title,
            "client_kind": value.client_kind.value,
            "client_version": value.client_version,
            "integration": value.integration.value,
            "profile": value.profile.value,
        }
        _optional_value(result, "external_ref", value.external_ref)
        _optional_value(result, "workspace_ref", value.workspace_ref)
        _optional_value(result, "parent_task_id", value.parent_task_id)
        _optional_value(result, "depth", value.depth)
        _optional_value(
            result,
            "origin",
            None if value.origin is None else value.origin.value,
        )
        _optional_value(result, "project_id", value.project_id)
        if value.membership_generation is not None:
            result["membership_generation"] = render_wire_sequence(value.membership_generation)
        _optional_value(result, "task_statement", value.task_statement)
        return _json_object(result)
    if payload_type is SessionResumedPayload:
        value = cast(SessionResumedPayload, payload)
        result = {
            "client_kind": value.client_kind.value,
            "client_version": value.client_version,
            "integration": value.integration.value,
            "profile": value.profile.value,
            "resumed_frontier": value.resumed_frontier.as_wire(),
        }
        _optional_value(result, "task_statement", value.task_statement)
        return _json_object(result)
    if payload_type is PlanPublishedPayload:
        value = cast(PlanPublishedPayload, payload)
        result = {
            "plan_version": value.plan_version,
            "summary": value.summary,
            "obligation_refs": value.obligation_refs,
        }
        _optional_tuple(
            result, "scope_exclusions", cast(tuple[object, ...], value.scope_exclusions)
        )
        _optional_value(
            result,
            "no_obligations_reason",
            None if value.no_obligations_reason is None else value.no_obligations_reason.value,
        )
        _optional_value(result, "task_statement", value.task_statement)
        return _json_object(result)
    if payload_type is ObligationPublishedPayload:
        value = cast(ObligationPublishedPayload, payload)
        result = {
            "obligation_id": value.obligation_id,
            "description": value.description,
            "evidence_expectation": value.evidence_expectation,
            "status": value.status.value,
        }
        _optional_value(result, "acceptance_criteria", value.acceptance_criteria)
        if value.requested_items:
            result["requested_items"] = tuple(
                {"item_kind": item.item_kind.value, "value": item.value}
                if item.role is None
                else {
                    "item_kind": item.item_kind.value,
                    "value": item.value,
                    "role": item.role.value,
                }
                for item in value.requested_items
            )
        _optional_tuple(result, "source_refs", cast(tuple[object, ...], value.source_refs))
        if value.status is ObligationStatus.RESOLVED:
            result["resolution_evidence_refs"] = value.resolution_evidence_refs
        _optional_value(result, "acknowledged_not_done_reason", value.acknowledged_not_done_reason)
        return _json_object(result)
    if payload_type is AssignmentRecordedPayload:
        value = cast(AssignmentRecordedPayload, payload)
        result = {
            "assignee_actor_id": value.assignee_actor_id,
            "obligation_ids": value.obligation_ids,
            "scope_description": value.scope_description,
        }
        _optional_value(
            result,
            "write_policy",
            None if value.write_policy is None else value.write_policy.value,
        )
        _optional_value(result, "handoff_of", value.handoff_of)
        return _json_object(result)
    if payload_type is DecisionRecordedPayload:
        value = cast(DecisionRecordedPayload, payload)
        result = {
            "statement": value.statement,
            "rationale": value.rationale,
            "authority": value.authority,
        }
        _optional_tuple(result, "alternatives", cast(tuple[object, ...], value.alternatives))
        _optional_tuple(
            result,
            "affected_obligation_ids",
            cast(tuple[object, ...], value.affected_obligation_ids),
        )
        _optional_value(result, "supersedes_event_id", value.supersedes_event_id)
        _optional_value(
            result,
            "review_mode",
            None if value.review_mode is None else value.review_mode.value,
        )
        return _json_object(result)
    if payload_type is ActionRecordedPayload:
        value = cast(ActionRecordedPayload, payload)
        result = {
            "action_id": value.action_id,
            "action_kind": value.action_kind.value,
            "description": value.description,
        }
        _optional_value(result, "command", value.command)
        _optional_value(
            result,
            "subject_state",
            None if value.subject_state is None else _encode_subject_state(value.subject_state),
        )
        _optional_tuple(result, "obligation_refs", cast(tuple[object, ...], value.obligation_refs))
        _optional_tuple(result, "attempted_items", cast(tuple[object, ...], value.attempted_items))
        return _json_object(result)
    if payload_type is ResultRecordedPayload:
        value = cast(ResultRecordedPayload, payload)
        result = {
            "result_id": value.result_id,
            "action_id": value.action_id,
            "outcome": value.outcome.value,
        }
        _optional_value(result, "exit_status", value.exit_status)
        _optional_value(result, "summary", value.summary)
        _optional_value(
            result,
            "subject_state",
            None if value.subject_state is None else _encode_subject_state(value.subject_state),
        )
        _optional_tuple(result, "evidence_refs", cast(tuple[object, ...], value.evidence_refs))
        return _json_object(result)
    if payload_type is EvidenceRecordedPayload:
        value = cast(EvidenceRecordedPayload, payload)
        result = {
            "evidence_id": value.evidence_id,
            "evidence_kind": value.evidence_kind.value,
            "strength": value.strength.value,
            "observed_at": value.observed_at.wire,
        }
        _optional_value(result, "reference", value.reference)
        _optional_value(result, "captured_object_id", value.captured_object_id)
        _optional_value(result, "content_digest", value.content_digest)
        _optional_value(result, "description", value.description)
        _optional_value(
            result,
            "subject_state",
            None if value.subject_state is None else _encode_subject_state(value.subject_state),
        )
        _optional_value(
            result,
            "digest_binding",
            None if value.digest_binding is None else _encode_digest_binding(value.digest_binding),
        )
        return _json_object(result)
    if payload_type in {ClaimRecordedPayload, ClaimRecordedPayloadV1_1}:
        value = cast(ClaimRecordedPayload | ClaimRecordedPayloadV1_1, payload)
        result = {
            "claim_id": value.claim_id,
            "claim_kind": value.claim_kind.value,
            "statement": value.statement,
            "supporting_refs": value.supporting_refs,
        }
        _optional_value(
            result,
            "subject_state",
            None if value.subject_state is None else _encode_subject_state(value.subject_state),
        )
        _optional_tuple(result, "obligation_refs", cast(tuple[object, ...], value.obligation_refs))
        _optional_tuple(result, "disputes_refs", cast(tuple[object, ...], value.disputes_refs))
        if type(value) is ClaimRecordedPayloadV1_1:
            result["limitation_refs"] = cast(tuple[JsonValue, ...], value.limitation_refs)
            result["supersedes_claim_refs"] = cast(
                tuple[JsonValue, ...], value.supersedes_claim_refs
            )
        return _json_object(result)
    if payload_type is PlanRevisedPayload:
        value = cast(PlanRevisedPayload, payload)
        changes: list[object] = []
        for change in value.obligation_changes:
            item: dict[str, object] = {
                "obligation_id": change.obligation_id,
                "change": change.change.value,
            }
            _optional_value(item, "reason", change.reason)
            _optional_tuple(
                item,
                "replacement_obligation_ids",
                cast(tuple[object, ...], change.replacement_obligation_ids),
            )
            changes.append(item)
        result = {
            "plan_version": value.plan_version,
            "supersedes_plan_version": value.supersedes_plan_version,
            "reason": value.reason,
            "summary": value.summary,
            "obligation_changes": tuple(changes),
        }
        _optional_value(
            result,
            "no_obligations_reason",
            None if value.no_obligations_reason is None else value.no_obligations_reason.value,
        )
        _optional_value(result, "task_statement", value.task_statement)
        return _json_object(result)
    if payload_type is ResponseRecordedPayload:
        value = cast(ResponseRecordedPayload, payload)
        result = {
            "finding_id": value.finding_id,
            "finding_frontier": value.finding_frontier.as_wire(),
            "disposition": value.disposition.value,
        }
        _optional_value(result, "reason", value.reason)
        _optional_value(
            result,
            "waiver_scope",
            None if value.waiver_scope is None else value.waiver_scope.value,
        )
        _optional_value(
            result,
            "waiver_expiry",
            None if value.waiver_expiry is None else value.waiver_expiry.wire,
        )
        _optional_tuple(result, "evidence_refs", cast(tuple[object, ...], value.evidence_refs))
        _optional_value(result, "duplicate_of_finding_id", value.duplicate_of_finding_id)
        return _json_object(result)
    if payload_type is RedactionRecordedPayload:
        value = cast(RedactionRecordedPayload, payload)
        return _json_object(
            {
                "target_event_ids": value.target_event_ids,
                "target_object_ids": value.target_object_ids,
                "method": value.method.value,
                "reason_category": value.reason_category.value,
                "authority": value.authority,
                "remaining_gap": value.remaining_gap,
            }
        )
    if payload_type is CheckRecordedPayload:
        value = cast(CheckRecordedPayload, payload)
        result = {
            "mode": value.mode.value,
            "policies": tuple(
                {"policy_id": policy.policy_id, "policy_version": policy.policy_version}
                for policy in value.policies
            ),
            "scope": value.scope.model_dump(mode="json"),
            "policy_executions": tuple(
                execution.model_dump(mode="json") for execution in value.policy_executions
            ),
            "subject_frontier": value.subject_frontier.as_wire(),
            "verdict": value.verdict.value,
            "returned_finding_ids": value.returned_finding_ids,
            "suppressed_count": value.suppressed_count,
            "coverage": coverage_to_json(value.coverage),
            "semantic_status": value.semantic_status.value,
            "semantic_reason": value.semantic_reason.value,
            "engine_version": value.engine_version,
            "projection_version": value.projection_version,
        }
        _optional_value(
            result,
            "semantic_provenance",
            None
            if value.semantic_provenance is None
            else semantic_provenance_to_json(value.semantic_provenance),
        )
        _optional_value(result, "semantic_conclusion", value.semantic_conclusion)
        _optional_value(result, "review_summary", value.review_summary)
        _optional_tuple(result, "verified", cast(tuple[object, ...], value.verified))
        _optional_tuple(
            result,
            "prior_finding_verdicts",
            tuple(
                {
                    "cited_refs": item.cited_refs,
                    "finding_id": item.finding_id,
                    "verdict": item.verdict,
                }
                for item in value.prior_finding_verdicts
            ),
        )
        _optional_tuple(
            result,
            "missing_for_assessment",
            tuple(
                _json_object(
                    {
                        "availability": item.availability,
                        "kind": item.kind,
                        "target_refs": item.target_refs,
                    }
                )
                for item in value.missing_for_assessment
            ),
        )
        if value.check_change_files is not None:
            result["check_change_files"] = check_change_files_to_json(value.check_change_files)
        _optional_value(result, "semantic_included_refs", value.semantic_included_refs)
        _optional_tuple(
            result,
            "semantic_withheld_item_ids",
            cast(tuple[object, ...], value.semantic_withheld_item_ids),
        )
        _optional_tuple(
            result,
            "semantic_redacted_values",
            tuple(item.as_wire() for item in value.semantic_redacted_values),
        )
        _optional_value(result, "review_input_manifest", value.review_input_manifest)
        _optional_value(result, "semantic_route_required", value.semantic_route_required)
        _optional_value(
            result,
            "review_mode",
            None if value.review_mode is None else cast(JsonValue, value.review_mode.as_wire()),
        )
        _optional_tuple(
            result, "deliverable_states", tuple(item.as_wire() for item in value.deliverable_states)
        )
        _optional_value(result, "totals", value.totals)
        return _json_object(result)
    if payload_type is ReceiptRecordedPayload:
        value = cast(ReceiptRecordedPayload, payload)
        return _json_object(
            {
                "receipt_id": value.receipt_id,
                "subject_frontier": value.subject_frontier.as_wire(),
                "receipt_digest": value.receipt_digest,
                "receipt_object_id": value.receipt_object_id,
                "conclusion_code": value.conclusion_code.value,
                "redaction_profile": value.redaction_profile.value,
            }
        )
    raise ProtocolValueError("unsupported_payload_type")


def normalize_payload_json(schema: EventSchema, value: JsonValue) -> JsonValue:
    return encode_payload(decode_payload(schema, value))


def media_type_for(schema_name: str) -> str:
    name = _bounded_text(schema_name, 64, minimum=1)
    if _SCHEMA_NAME_RE.fullmatch(name) is None:
        raise ProtocolValueError("invalid_event_schema")
    return f"application/vnd.yoetz.{name}+json"


def _expected_payload_type(schema: EventSchema) -> type[EventPayload] | None:
    return PAYLOAD_TYPES.get(schema)


def _validate_event_schema_payload(
    schema: EventSchema,
    payload: EventPayload | None,
) -> None:
    if type(payload) is DecisionRecordedPayload:
        # ADR-049: the review-mode switch is 1.1.0-only; 1.0.0 is released and frozen.
        if (payload.review_mode is not None) != (
            schema.version == DECISION_REVIEW_MODE_SCHEMA_VERSION
        ):
            raise ProtocolValueError("invalid_event_schema")
    if type(payload) is SessionOpenedPayload:
        has_lineage = any(
            value is not None for value in (payload.parent_task_id, payload.depth, payload.origin)
        )
        has_project_lineage = any(
            value is not None for value in (payload.project_id, payload.membership_generation)
        )
        if has_lineage and schema != EventSchema(
            "session_opened", LINEAGE_SESSION_EVENT_SCHEMA_VERSION
        ):
            raise ProtocolValueError("invalid_event_schema")
        if has_project_lineage and schema != EventSchema(
            "session_opened", LINEAGE_SESSION_EVENT_SCHEMA_VERSION
        ):
            raise ProtocolValueError("invalid_event_schema")
    if type(payload) in {
        SessionOpenedPayload,
        SessionResumedPayload,
        PlanPublishedPayload,
        PlanRevisedPayload,
    }:
        # One schema per family admits a statement; an older schema never does, and a version
        # minted only for the statement is never chosen without it.
        statement = cast(
            SessionOpenedPayload
            | SessionResumedPayload
            | PlanPublishedPayload
            | PlanRevisedPayload,
            payload,
        ).task_statement
        if statement is not None and schema not in TASK_STATEMENT_EVENT_SCHEMAS:
            raise ProtocolValueError("invalid_event_schema")
        if statement is None and schema in _TASK_STATEMENT_REQUIRED_SCHEMAS:
            raise ProtocolValueError("invalid_event_schema")
    if type(payload) is CheckRecordedPayload:
        has_review_output = (
            payload.review_summary is not None
            or bool(payload.verified)
            or payload.totals is not None
            or bool(payload.semantic_redacted_values)
            or payload.semantic_route_required is not None
            or bool(payload.deliverable_states)
            or payload.review_mode is not None
        )
        if has_review_output:
            if schema.version != REVIEW_CHECK_EVENT_SCHEMA_VERSION:
                raise ProtocolValueError("invalid_event_schema")
        elif payload.semantic_conclusion is not None:
            if schema.version != CHECK_EVENT_SCHEMA_VERSION:
                raise ProtocolValueError("invalid_event_schema")
        elif schema.version in {CHECK_EVENT_SCHEMA_VERSION, REVIEW_CHECK_EVENT_SCHEMA_VERSION}:
            # Plain checks written by older builds legally use the released 1.0.0 shape or the
            # semantic 1.1.0/1.2.0 additions, so every one of those stays replayable after an
            # upgrade. The writer mints 1.2.0 for a new plain check; 1.3.0 and 1.4.0 are reserved
            # for the semantic-conclusion and review-output payloads they introduced.
            raise ProtocolValueError("invalid_event_schema")
    if type(payload) is Finding and schema.name == "finding_recorded":
        has_snippet = payload.challenge is not None and payload.challenge.snippet is not None
        has_new_kind = payload.kind in {
            FindingKind.CODE_DEFECT,
            FindingKind.TASK_REQUIREMENT_UNMET,
            FindingKind.AGENT_CRITERION_UNMET,
        }
        if has_snippet or has_new_kind:
            if schema.version != FINDING_SNIPPET_EVENT_SCHEMA_VERSION:
                raise ProtocolValueError("invalid_event_schema")
        elif finding_has_dialogue_fields(payload):
            if schema.version != FINDING_EVENT_SCHEMA_VERSION:
                raise ProtocolValueError("invalid_event_schema")
        elif schema.version not in {
            SCHEMA_VERSION,
            *SEMANTIC_EVENT_SCHEMA_VERSIONS,
            FINDING_EVENT_SCHEMA_VERSION,
        }:
            # Ordinary findings written by older ledgers legally use the released 1.0.0 shape,
            # semantic 1.1/1.2 additions, or the current dialogue-capable 1.3.0 shape. Keep all
            # of those readable; 1.4.0 is reserved for snippets and the new semantic kinds.
            raise ProtocolValueError("invalid_event_schema")
    if type(payload) is ObligationPublishedPayload and not obligation_schema_admits(
        payload, schema.version
    ):
        # The released 1.0.0 never carries a 1.1.0-only feature (issue #1002); 1.1.0 is a
        # superset that also admits a plain obligation (issue #1023).
        raise ProtocolValueError("invalid_event_schema")
    if type(payload) is ResponseRecordedPayload:
        if (payload.disposition in RESPONSE_V1_1_DISPOSITIONS) != (
            schema.version == RESPONSE_EVENT_SCHEMA_VERSION
        ):
            raise ProtocolValueError("invalid_event_schema")
    if schema.version == SCHEMA_VERSION:
        profile: RuntimeProfile | None = None
        if type(payload) is SessionOpenedPayload:
            profile = payload.profile
        elif type(payload) is SessionResumedPayload:
            profile = payload.profile
        provenance: SemanticProvenance | None = None
        if type(payload) is Finding:
            provenance = payload.provenance
        elif type(payload) is CheckRecordedPayload:
            provenance = payload.semantic_provenance
        if profile is RuntimeProfile.CODEX_SUBSCRIPTION or (
            provenance is not None
            and provenance.dispatch_kind is SemanticDispatchKind.EXTERNAL_RUNTIME_OAUTH
        ):
            raise ProtocolValueError("invalid_event_value_type")
    if type(payload) is not EvidenceRecordedPayload:
        return
    evidence = payload
    if schema == EventSchema("evidence_recorded", SCHEMA_VERSION):
        if evidence.digest_binding is not None:
            raise ProtocolValueError("invalid_event_value_type")
        return
    if (
        schema.name == "evidence_recorded"
        and schema.version != SCHEMA_VERSION
        and ((evidence.content_digest is None) != (evidence.digest_binding is None))
    ):
        raise ProtocolValueError("evidence_digest_binding_required")
    if (
        schema.version == EVIDENCE_TYPED_SCHEMA_VERSION
        and evidence.digest_binding is not None
        and evidence.digest_binding.provenance is EvidenceDigestProvenance.OBSERVATION_CAPTURED
    ):
        raise ProtocolValueError("evidence_digest_provenance_invalid")


def _validate_envelope_ref_mirrors(
    schema: EventSchema,
    payload: EventPayload | None,
    artifact_refs: tuple[ObjectId, ...],
    evidence_refs: tuple[EvidenceId | ResultId, ...],
    locator: ProjectionLocator | None = None,
) -> None:
    # The mismatched envelope field name is the whole repair, and it is a frozen schema name, not
    # a caller-supplied key. Carrying it lets the application layer point at the exact list instead
    # of leaving the caller to re-derive which of the two reference lists broke the mirror.
    if schema.name == "result_recorded":
        if (
            payload is not None
            and evidence_refs != cast(ResultRecordedPayload, payload).evidence_refs
        ):
            raise ProtocolValueError("ref_mirror_mismatch", field="evidence_refs")
    elif schema.name == "response_recorded":
        if (
            payload is not None
            and evidence_refs != cast(ResponseRecordedPayload, payload).evidence_refs
        ):
            raise ProtocolValueError("ref_mirror_mismatch", field="evidence_refs")

    if schema.name == "evidence_recorded":
        if payload is None:
            if len(artifact_refs) > 1:
                raise ProtocolValueError("ref_mirror_mismatch", field="artifact_refs")
        else:
            captured = cast(EvidenceRecordedPayload, payload).captured_object_id
            expected = () if captured is None else (captured,)
            if artifact_refs != expected:
                raise ProtocolValueError("ref_mirror_mismatch", field="artifact_refs")
    elif schema.name == "redaction_recorded":
        if payload is not None:
            expected = cast(RedactionRecordedPayload, payload).target_object_ids
        elif locator is not None:
            expected = locator.redaction_target_object_ids
        else:
            expected = ()
        if artifact_refs != expected:
            raise ProtocolValueError("ref_mirror_mismatch", field="artifact_refs")
    elif schema.name == "receipt_recorded":
        if payload is None:
            if len(artifact_refs) != 1:
                raise ProtocolValueError("ref_mirror_mismatch", field="artifact_refs")
        elif artifact_refs != (cast(ReceiptRecordedPayload, payload).receipt_object_id,):
            raise ProtocolValueError("ref_mirror_mismatch", field="artifact_refs")


# Public draft-schema description for caller-asserted event time. Owned here so schema generation
# and hand-reviewed draft envelopes stay aligned; receipt freshness is frontier-bound, not wall-clock.
OCCURRED_AT_DRAFT_DESCRIPTION: Final = (
    "Caller-asserted event time (RFC 3339 UTC, millisecond precision). Use the best real time "
    "available; do not copy illustrative example timestamps. If the exact time is unknown, use an "
    "honest bounded approximation and treat it as a claim. Ledger order uses ingestion sequence; "
    "receipt freshness is frontier-bound. Service accepted_at is independent acceptance metadata, "
    "not a sort, filter, or freshness key."
)


@dataclass(frozen=True, slots=True)
class EventDraft:
    event_id: EventId
    schema: EventSchema
    occurred_at: Annotated[Timestamp, Field(description=OCCURRED_AT_DRAFT_DESCRIPTION)]
    causal_parents: tuple[EventId, ...]
    payload: EventPayload | JsonValue
    artifact_refs: tuple[ObjectId, ...]
    evidence_refs: tuple[EvidenceId | ResultId, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_id", event_id(self.event_id))
        if type(self.schema) is not EventSchema:
            raise ProtocolValueError("invalid_event_schema")
        object.__setattr__(self, "occurred_at", _timestamp(self.occurred_at))
        object.__setattr__(
            self,
            "causal_parents",
            _id_tuple(
                self.causal_parents,
                event_id,
                maximum=MAX_CAUSAL_PARENTS,
            ),
        )
        object.__setattr__(
            self,
            "artifact_refs",
            _id_tuple(self.artifact_refs, object_id),
        )
        object.__setattr__(
            self,
            "evidence_refs",
            _evidence_result_tuple(self.evidence_refs),
        )

        payload_type = _expected_payload_type(self.schema)
        if payload_type is None:
            object.__setattr__(self, "payload", freeze_json(self.payload))
            return
        if type(self.payload) is not payload_type:
            raise ProtocolValueError("invalid_event_value_type")
        typed_payload = cast(EventPayload, self.payload)
        _validate_event_schema_payload(self.schema, typed_payload)
        _validate_envelope_ref_mirrors(
            self.schema,
            typed_payload,
            self.artifact_refs,
            self.evidence_refs,
        )


def _expected_locator_key(payload: EventPayload, envelope_event_id: EventId) -> str | None:
    payload_type = type(payload)
    if payload_type is PlanPublishedPayload:
        return str(cast(PlanPublishedPayload, payload).plan_version)
    if payload_type is PlanRevisedPayload:
        return str(cast(PlanRevisedPayload, payload).plan_version)
    if payload_type is ObligationPublishedPayload:
        return cast(ObligationPublishedPayload, payload).obligation_id
    if payload_type in {AssignmentRecordedPayload, DecisionRecordedPayload, CheckRecordedPayload}:
        return envelope_event_id
    if payload_type is ActionRecordedPayload:
        return cast(ActionRecordedPayload, payload).action_id
    if payload_type is ResultRecordedPayload:
        return cast(ResultRecordedPayload, payload).result_id
    if payload_type is EvidenceRecordedPayload:
        return cast(EvidenceRecordedPayload, payload).evidence_id
    if payload_type in {ClaimRecordedPayload, ClaimRecordedPayloadV1_1}:
        return cast(ClaimRecordedPayload | ClaimRecordedPayloadV1_1, payload).claim_id
    if payload_type is Finding:
        return cast(Finding, payload).finding_id
    if payload_type is ResponseRecordedPayload:
        return cast(ResponseRecordedPayload, payload).finding_id
    return None


def _expected_locator_targets(
    payload: EventPayload,
) -> tuple[tuple[EventId, ...], tuple[ObjectId, ...]]:
    if type(payload) is RedactionRecordedPayload:
        redaction = payload
        return redaction.target_event_ids, redaction.target_object_ids
    return (), ()


def _validate_projection_locator(
    schema: EventSchema,
    event: EventId,
    payload: EventPayload | None,
    locator: ProjectionLocator,
) -> None:
    if type(locator) is not ProjectionLocator or locator.schema != schema:
        raise ProtocolValueError("invalid_projection_locator")
    if payload is None:
        if schema.name in {"assignment_recorded", "decision_recorded", "check_recorded"} and (
            locator.logical_key != event
        ):
            raise ProtocolValueError("invalid_projection_locator")
        return
    expected_key = _expected_locator_key(payload, event)
    expected_event_targets, expected_object_targets = _expected_locator_targets(payload)
    if (
        locator.logical_key != expected_key
        or locator.redaction_target_event_ids != expected_event_targets
        or locator.redaction_target_object_ids != expected_object_targets
        or locator.canonical_payload_digest != canonical_digest(encode_payload(payload))
    ):
        raise ProtocolValueError("invalid_projection_locator")


def _validate_record_common(record: AcceptedEvent | UnknownEvent) -> None:
    object.__setattr__(record, "event_id", event_id(record.event_id))
    object.__setattr__(record, "task_id", task_id(record.task_id))
    object.__setattr__(record, "session_id", session_id(record.session_id))
    if type(record.schema) is not EventSchema:
        raise ProtocolValueError("accepted_record_shape_invalid")
    if type(record.author) is not Actor:
        raise ProtocolValueError("accepted_record_shape_invalid")
    if type(record.writer) is not WriterChain or type(record.ledger) is not LedgerChain:
        raise ProtocolValueError("accepted_record_shape_invalid")
    object.__setattr__(record, "operation_id", request_id(record.operation_id))
    object.__setattr__(record, "occurred_at", _timestamp(record.occurred_at))
    object.__setattr__(
        record,
        "causal_parents",
        _id_tuple(
            record.causal_parents,
            event_id,
            maximum=MAX_CAUSAL_PARENTS,
        ),
    )
    channel = _exact_enum(record.publication_channel, PublicationChannel)
    object.__setattr__(record, "publication_channel", channel)
    if type(record.coverage) is not Coverage:
        raise ProtocolValueError("invalid_coverage_value")
    if record.coverage.publication_channels != (channel,):
        raise ProtocolValueError("invalid_coverage_value")
    if type(record.payload_ref) is not PayloadRef:
        raise ProtocolValueError("invalid_payload_ref")
    if record.payload_ref.media_type != media_type_for(record.schema.name):
        raise ProtocolValueError("invalid_payload_ref")
    object.__setattr__(record, "redaction", _exact_enum(record.redaction, RedactionState))
    object.__setattr__(
        record,
        "artifact_refs",
        _id_tuple(record.artifact_refs, object_id),
    )
    object.__setattr__(
        record,
        "evidence_refs",
        _evidence_result_tuple(record.evidence_refs),
    )
    validate_sha256_digest(record.entry_digest)
    if type(record.projection_locator) is not ProjectionLocator:
        raise ProtocolValueError("invalid_projection_locator")


@dataclass(frozen=True, slots=True)
class AcceptedEvent:
    protocol: Literal["yoetz.event"] = field(init=False, default="yoetz.event")
    protocol_version: Literal["0.1"] = field(init=False, default="0.1")
    event_id: EventId
    task_id: TaskId
    session_id: SessionId
    schema: EventSchema
    author: Actor
    writer: WriterChain
    ledger: LedgerChain
    operation_id: RequestId
    occurred_at: Timestamp
    causal_parents: tuple[EventId, ...]
    publication_channel: PublicationChannel
    coverage: Coverage
    payload_ref: PayloadRef
    redaction: RedactionState
    artifact_refs: tuple[ObjectId, ...]
    evidence_refs: tuple[EvidenceId | ResultId, ...]
    entry_digest: str
    payload: EventPayload | None
    projection_locator: ProjectionLocator

    def __post_init__(self) -> None:
        _validate_record_common(self)
        payload_type = _expected_payload_type(self.schema)
        if payload_type is None:
            raise ProtocolValueError("invalid_event_schema")
        if self.payload is not None and type(self.payload) is not payload_type:
            raise ProtocolValueError("invalid_event_value_type")
        if self.redaction is not RedactionState.PRESENT and self.payload is not None:
            raise ProtocolValueError("payload_redaction_mismatch")
        typed_payload = self.payload
        _validate_event_schema_payload(self.schema, typed_payload)
        _validate_projection_locator(
            self.schema,
            self.event_id,
            typed_payload,
            self.projection_locator,
        )
        _validate_envelope_ref_mirrors(
            self.schema,
            typed_payload,
            self.artifact_refs,
            self.evidence_refs,
            self.projection_locator,
        )
        if type(typed_payload) is EvidenceRecordedPayload:
            evidence = typed_payload
            if evidence.evidence_kind is EvidenceKind.IMPORT_REPORT and (
                self.author.actor_type is not ActorType.IMPORTER
                or self.publication_channel is not PublicationChannel.CODEX_JSONL_IMPORT
            ):
                raise ProtocolValueError("import_report_invalid")
            binding = evidence.digest_binding
            if binding is not None:
                if binding.provenance is EvidenceDigestProvenance.APPROVED_CHECK and (
                    self.author.actor_type is not ActorType.FINISHUP_ENGINE
                    or self.author.assurance is not AuthorshipAssurance.SERVICE_AUTHENTICATED
                    or self.publication_channel is not PublicationChannel.ENGINE_DERIVED
                ):
                    raise ProtocolValueError("evidence_digest_provenance_invalid")
                if binding.provenance is EvidenceDigestProvenance.IMPORT_OBSERVED and (
                    self.author.actor_type is not ActorType.IMPORTER
                    or self.publication_channel is not PublicationChannel.CODEX_JSONL_IMPORT
                ):
                    raise ProtocolValueError("evidence_digest_provenance_invalid")
                if binding.provenance is EvidenceDigestProvenance.OBSERVATION_CAPTURED:
                    observed_by_service = (
                        self.author.actor_type is ActorType.HARNESS
                        and self.author.assurance is AuthorshipAssurance.HARNESS_OBSERVED
                        and self.publication_channel is PublicationChannel.HOOK_OBSERVED
                    )
                    captured_bytes = (
                        evidence.strength is EvidenceImmutability.IMMUTABLE_SNAPSHOT
                        and binding.content_availability is EvidenceContentAvailability.CAPTURED
                        and self.coverage.artifact_observation
                        is ArtifactObservation.CONTENT_CAPTURED
                        and self.coverage.evidence_immutability
                        is EvidenceImmutability.IMMUTABLE_SNAPSHOT
                    )
                    # An image a host tool returned: the hook hashed the decoded bytes and kept
                    # no pixels, so the row is a digest of artifact bytes with nothing captured
                    # (#1013). It can never pose as captured content.
                    observed_digest_only = (
                        evidence.strength is EvidenceImmutability.CONTENT_DIGEST
                        and binding.content_availability is EvidenceContentAvailability.DIGEST_ONLY
                        and binding.subject is EvidenceDigestSubject.ARTIFACT_BYTES
                        and evidence.captured_object_id is None
                    )
                    if not observed_by_service or not (captured_bytes or observed_digest_only):
                        raise ProtocolValueError("evidence_digest_provenance_invalid")
        if compute_entry_digest(accepted_record_digest_preimage(self)) != self.entry_digest:
            raise ProtocolValueError("entry_digest_mismatch")


@dataclass(frozen=True, slots=True)
class UnknownEvent:
    protocol: Literal["yoetz.event"] = field(init=False, default="yoetz.event")
    protocol_version: Literal["0.1"] = field(init=False, default="0.1")
    event_id: EventId
    task_id: TaskId
    session_id: SessionId
    schema: EventSchema
    author: Actor
    writer: WriterChain
    ledger: LedgerChain
    operation_id: RequestId
    occurred_at: Timestamp
    causal_parents: tuple[EventId, ...]
    publication_channel: PublicationChannel
    coverage: Coverage
    payload_ref: PayloadRef
    redaction: RedactionState
    artifact_refs: tuple[ObjectId, ...]
    evidence_refs: tuple[EvidenceId | ResultId, ...]
    entry_digest: str
    payload: JsonValue | None
    projection_locator: ProjectionLocator
    canonical_payload_digest: str
    projection_status: Literal["unknown_unprojected"] = field(
        init=False,
        default="unknown_unprojected",
    )

    def __post_init__(self) -> None:
        _validate_record_common(self)
        if _expected_payload_type(self.schema) is not None:
            raise ProtocolValueError("invalid_event_schema")
        validate_sha256_digest(self.canonical_payload_digest)
        if (
            self.projection_locator.schema != self.schema
            or self.projection_locator.logical_key is not None
            or self.projection_locator.redaction_target_event_ids
            or self.projection_locator.redaction_target_object_ids
            or self.projection_locator.canonical_payload_digest != self.canonical_payload_digest
        ):
            raise ProtocolValueError("invalid_projection_locator")
        if self.redaction is not RedactionState.PRESENT and self.payload is not None:
            raise ProtocolValueError("payload_redaction_mismatch")
        if self.payload is not None:
            frozen = freeze_json(self.payload)
            object.__setattr__(self, "payload", frozen)
            if canonical_digest(frozen) != self.canonical_payload_digest:
                raise ProtocolValueError("invalid_projection_locator")
        if compute_entry_digest(accepted_record_digest_preimage(self)) != self.entry_digest:
            raise ProtocolValueError("entry_digest_mismatch")


type LedgerRecord = AcceptedEvent | UnknownEvent


def is_observation_authorship(author: Actor, publication_channel: PublicationChannel) -> bool:
    """Recognize only service-stamped observation coordinator authorship.

    Two of these four facts are caller-supplied through ``publish_work`` (``actor_id`` and
    ``actor_type``); ``assurance`` and ``publication_channel`` are service-derived and are what
    make the pair unforgeable. Every caller must test all four, so the predicate lives here once
    rather than being restated per call site.
    """

    return (
        str(author.actor_id) == OBSERVATION_COORDINATOR_ACTOR_ID
        and author.actor_type is ActorType.HARNESS
        and author.assurance is AuthorshipAssurance.HARNESS_OBSERVED
        and publication_channel
        in {PublicationChannel.HOOK_OBSERVED, PublicationChannel.ENGINE_DERIVED}
    )


def is_observation_authored(record: LedgerRecord) -> bool:
    """Recognize only service-stamped observation coordinator records."""

    return is_observation_authorship(record.author, record.publication_channel)


def redaction_targets(
    records: Iterable[LedgerRecord],
) -> tuple[frozenset[EventId], frozenset[ObjectId]]:
    """The event and object targets of every ``redaction_recorded`` among ``records``.

    An object target redacts the event whose payload object it names, exactly as replay resolves
    it, so a caller reading original envelopes excludes a record when its event ID is in the
    first set or its ``payload_ref.object_id`` is in the second. Loaded envelopes keep their
    original ``redaction`` state after a later logical redaction; this is the effective view.
    """

    events: set[EventId] = set()
    objects: set[ObjectId] = set()
    for record in records:
        if record.schema.name != "redaction_recorded":
            continue
        events.update(record.projection_locator.redaction_target_event_ids)
        objects.update(record.projection_locator.redaction_target_object_ids)
    return frozenset(events), frozenset(objects)


def is_lineage_service_stamped(record: LedgerRecord) -> bool:
    """Return whether a service-only lineage event has the observation stamp.

    The event payload itself is closed and cannot prove who authored it.  Publication admission
    must combine this family allowlist with the existing coordinator author/channel predicate;
    keeping the composition here gives every caller one guard instead of a family-specific guess.
    """

    return record.schema.name in LINEAGE_SERVICE_STAMPED_FAMILIES and is_observation_authored(
        record
    )


def accepted_record_to_json(record: LedgerRecord) -> JsonObject:
    """Serialize the exact nineteen-field accepted-event storage/wire record."""

    if type(record) is not AcceptedEvent and type(record) is not UnknownEvent:
        raise ProtocolValueError("accepted_record_shape_invalid")
    return JsonObject(
        {
            "protocol": record.protocol,
            "protocol_version": record.protocol_version,
            "event_id": record.event_id,
            "task_id": record.task_id,
            "session_id": record.session_id,
            "schema": {
                "name": record.schema.name,
                "version": record.schema.version,
            },
            "author": {
                "actor_id": record.author.actor_id,
                "actor_type": record.author.actor_type.value,
                "assurance": record.author.assurance.value,
            },
            "writer": {
                "writer_id": record.writer.writer_id,
                "sequence": str(record.writer.sequence),
                "previous_entry_digest": record.writer.previous_entry_digest,
            },
            "ledger": {
                "ingestion_sequence": str(record.ledger.ingestion_sequence),
                "previous_entry_digest": record.ledger.previous_entry_digest,
                "accepted_at": record.ledger.accepted_at.wire,
            },
            "operation_id": record.operation_id,
            "occurred_at": record.occurred_at.wire,
            "causal_parents": record.causal_parents,
            "publication_channel": record.publication_channel.value,
            "coverage": coverage_to_json(record.coverage),
            "payload_ref": {
                "object_id": record.payload_ref.object_id,
                "media_type": record.payload_ref.media_type,
                "plaintext_size": record.payload_ref.plaintext_size,
                "commitment": record.payload_ref.commitment,
                "encryption_format": record.payload_ref.encryption_format,
            },
            "redaction": record.redaction.value,
            "artifact_refs": record.artifact_refs,
            "evidence_refs": record.evidence_refs,
            "entry_digest": record.entry_digest,
        }
    )


def accepted_record_digest_preimage(record: LedgerRecord) -> JsonObject:
    """Return the exact accepted record with only its top-level digest removed."""

    full = accepted_record_to_json(record)
    return JsonObject(tuple((key, value) for key, value in full.items() if key != "entry_digest"))
