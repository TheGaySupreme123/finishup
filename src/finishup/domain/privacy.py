"""Closed privacy-policy, disclosure-authority, and audit value types."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from typing import Final, Literal, cast

from finishup.domain.reviewer_context import MAX_SIZED_EXCHANGE_BYTES
from finishup.domain.values import (
    Frontier,
    format_rfc3339_millis,
    validate_commitment,
    validate_sha256_digest,
)
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.coverage import PublicationChannel
from finishup.protocol.ids import IdKind, validate_id
from finishup.protocol.models import MAX_REVIEW_EXCERPTS, DataCategory
from finishup.protocol.redacted_values import (
    SemanticRedactedValue,
    validate_semantic_redacted_values,
)

__all__ = [
    "MAX_EGRESS_CASE_BYTES",
    "MAX_EGRESS_ITEM_BYTES",
    "MAX_RECEIPT_FINAL_BYTES",
    "MAX_RECEIPT_FINAL_BYTES_1_0",
    "MAX_RECEIPT_NAME_AUTHORSHIP",
    "MAX_WITHHELD_ITEM_IDS",
    "MAX_PRIVACY_CHANGES",
    "MAX_PRIVACY_CHANGE_LABELS",
    "MAX_PRIVACY_LABEL_BYTES",
    "NEVER_SEND_KINDS",
    "PRIVACY_CHANGE_AREAS",
    "PRIVACY_CHANGE_FIELDS",
    "PRE_1_2_MAX_EXCERPTS",
    "PRIVACY_POLICY_PRESET_VERSIONS",
    "CURRENT_PRIVACY_POLICY_PRESET_VERSION",
    "PrivacyPolicyPresetVersion",
    "review_selection_policy_schema_version",
    "AgentProjectionAuditSubject",
    "ApprovedLocalDisclosureCase",
    "ApprovedLocalItem",
    "ApprovedOutboundCase",
    "ApprovedProviderCase",
    "AuthorizationScope",
    "AuthorizationScopeKind",
    "CandidateContext",
    "CandidateContextItem",
    "ChannelPolicy",
    "ClassifiedContext",
    "ClassifiedContextItem",
    "ConsentSource",
    "ConversationReview",
    "CredentialHeuristic",
    "conversation_review_widens",
    "narrower_conversation_review",
    "policy_field_omitted",
    "MAX_ADMITTED_INPUT_ROOTS",
    "admitted_input_root_valid",
    "validate_admitted_input_roots",
    "external_review_credential_heuristic",
    "DataCategory",
    "DataClass",
    "DisclosureProposal",
    "DisclosureProvenance",
    "EgressAuthorization",
    "EgressChannel",
    "EgressReceipt",
    "ForbiddenDataKind",
    "HumanPrivacyDecision",
    "LocalDisclosureApproved",
    "LocalDisclosureBlocked",
    "LocalDisclosureOmission",
    "LocalDisclosureReceipt",
    "LocalDisclosureSink",
    "LocalDisclosureUnavailable",
    "NonLlmDestination",
    "PolicyOverlay",
    "PreDispatchAuditDecision",
    "PrivacyAuditSubject",
    "PrivacyDecision",
    "PrivacyOutcome",
    "PrivacyPolicy",
    "PrivacyPolicyChange",
    "PrivacyPolicyChangeValue",
    "PrivacyProfile",
    "ProjectionAuditContext",
    "ProjectionItemAuthorship",
    "ProjectionProvenanceContext",
    "PrivacyReason",
    "ProviderBinding",
    "ProviderDataUseProfile",
    "RECEIPT_CAPACITY_SCOPE_UNITS",
    "ReceiptCapacity",
    "ReceiptCounts",
    "ReceiptPolicyBinding",
    "ReceiptSecretScan",
    "ReceiptSecretScanStage",
    "ReceiptTransformations",
    "OBSERVATION_ADVICE_PACKET_ITEM_ID",
    "EgressOriginOperation",
    "REVIEW_PACKET_ITEM_ID",
    "egress_origin_operation",
    "RequestCommitment",
    "ReviewContextProfile",
    "ReviewSelectionPolicy",
    "SourceAuthorship",
    "authorship_provenance",
    "outcome_reason_is_valid",
    "privacy_change_order",
    "sort_privacy_changes",
    "validate_privacy_change_set",
]

# Reserved item id for the structural review-packet envelope. Owned here rather than in the
# application layer because the egress bound below is keyed on it.
REVIEW_PACKET_ITEM_ID: Final = "review-packet"
# Reserved item id for the background observation-advice packet (#619).
OBSERVATION_ADVICE_PACKET_ITEM_ID: Final = "observation-advice-packet"

MAX_EGRESS_ITEM_BYTES: Final = 16 * 1024
# The structural review-packet envelope is one candidate item by transport, but it is not one
# piece of content: it is the catalog and packet spine indexing every other item in the case.
# Budgeting it as a single excerpt is what made a real 44 KiB case unsendable, so it carries its
# own bound. Only the generated envelope may use it — see ``_envelope_item_limit``.
MAX_EGRESS_ENVELOPE_BYTES: Final = 128 * 1024
# Bounds the whole assembled outbound document (envelope spine + every approved content item),
# so it must exceed the parts: MAX_EGRESS_ENVELOPE_BYTES + MAX_SEMANTIC_CASE_BYTES = 384 KiB.
# It previously equalled the content budget alone, which made a maximum-content case impossible
# to dispatch no matter how small its envelope was.
MAX_EGRESS_CASE_BYTES: Final = 512 * 1024
# A receipt's ``counts.final_bytes`` is bounded by the published receipt vocabulary
# (``privacy/egress-receipt-1.1.0`` ``max_524288_decimal``; 1.0.0 kept ``max_262144_decimal``), not
# by the outbound document bound above, though they are now equal. Every disclosure is prepared as
# one ``MinimizedDisclosure`` of at most ``MAX_SIZED_EXCHANGE_BYTES`` (524,288, #1118: a reviewer
# exchange on a route sized to its model's context), so no real receipt exceeds it. The domain once
# admitted more than the wire did, so a receipt between the two bounds was valid in the store and
# invalid on the wire, and failed every page it was listed on (issue #921).
MAX_RECEIPT_FINAL_BYTES: Final = MAX_SIZED_EXCHANGE_BYTES
MAX_RECEIPT_FINAL_BYTES_1_0: Final = 262_144
# The public receipt and semantic-result contracts carry at most 64 opaque item references. Keep
# this bound in the shared privacy domain so proposals, prepared cases, receipts, and in-process
# results reject an overlarge omission set before any object is finalized or encoded.
MAX_WITHHELD_ITEM_IDS: Final = 64
AUDIT_STORE_VERSION: Final = 1
PRIVACY_REQUEST_COMMITMENT_ALGORITHM: Final = "hmac-sha256/yoetz-privacy-egress-request-v1"

_IDENTITY = re.compile(r"^[a-z0-9][a-z0-9._-]*$", re.ASCII)
_MODEL_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]*$", re.ASCII)
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]*$", re.ASCII)
_PURPOSE = re.compile(r"^[a-z][a-z0-9_-]{0,127}$", re.ASCII)
_OPAQUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", re.ASCII)
_POINTER = re.compile(r"^(?:/(?:[^~/]|~0|~1)*)*$")
_MAX_SAFE_INTEGER = 2**53 - 1


def _invalid() -> ValueError:
    return ValueError("invalid_privacy_value")


def _enum(value: object, enum_type: type[Enum]) -> None:
    if type(value) is not enum_type:
        raise _invalid()


def _text(value: object, pattern: re.Pattern[str], *, maximum: int = 128) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise _invalid()
    if pattern.fullmatch(value) is None:
        raise _invalid()
    return value


def _origin_ref(value: object) -> str:
    if type(value) is not str or not value:
        raise _invalid()
    candidate = value
    pattern = _POINTER if candidate.startswith("/") else _OPAQUE
    return _text(candidate, pattern, maximum=256 if pattern is _POINTER else 128)


def _nonnegative(value: object, *, maximum: int = _MAX_SAFE_INTEGER) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise _invalid()
    return value


def _positive(value: object, *, maximum: int = _MAX_SAFE_INTEGER) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise _invalid()
    return value


def _time(value: object) -> datetime:
    if type(value) is not datetime:
        raise _invalid()
    try:
        format_rfc3339_millis(value)
    except ValueError as exc:
        raise _invalid() from exc
    return value


# #1220: categories a receipt may show but no policy names. A reviewer read of an agent-declared
# test file is admitted under the ``repository_excerpt`` grant (ADR-009 amendment) and labelled
# ``declared_test_excerpt`` on the egress receipt of each exchange that carries it. A policy
# category set is read without them (``tuple(DataCategory)`` means every grantable category), so
# every policy keeps its exact wire bytes and digest.
RECEIPT_ONLY_CATEGORIES: Final = frozenset({DataCategory.DECLARED_TEST_EXCERPT})


def _without_receipt_only(values: tuple[DataCategory, ...]) -> tuple[DataCategory, ...]:
    return tuple(value for value in values if value not in RECEIPT_ONLY_CATEGORIES)


def _sorted_enums[TEnum: Enum](values: object, enum_type: type[TEnum]) -> tuple[TEnum, ...]:
    if type(values) not in {tuple, list, set, frozenset}:
        raise _invalid()
    raw = cast(tuple[object, ...] | list[object] | set[object] | frozenset[object], values)
    if any(type(value) is not enum_type for value in raw):
        raise _invalid()
    typed = cast(tuple[TEnum, ...], tuple(raw))
    if len(set(typed)) != len(typed):
        raise _invalid()
    return tuple(sorted(typed, key=lambda value: str(value.value).encode("ascii")))


def _sorted_text(
    values: object, *, pattern: re.Pattern[str] = _OPAQUE, maximum: int = 128
) -> tuple[str, ...]:
    if type(values) not in {tuple, list, set, frozenset}:
        raise _invalid()
    raw = cast(tuple[object, ...] | list[object] | set[object] | frozenset[object], values)
    typed = tuple(_text(value, pattern, maximum=maximum) for value in raw)
    if len(set(typed)) != len(typed):
        raise _invalid()
    return tuple(sorted(typed, key=str.encode))


class PrivacyProfile(str, Enum):  # noqa: UP042 - durable enum
    LOCAL_ONLY = "local_only"
    CONFIRM_EVERY_REQUEST = "confirm_every_request"
    MINIMAL_EXTERNAL = "minimal_external"
    TRUSTED_PROVIDER = "trusted_provider"


class ReviewContextProfile(str, Enum):  # noqa: UP042 - durable enum
    STRUCTURAL = "structural"
    GOAL_AWARE = "goal_aware"
    ASSISTED = "assisted"
    EXPANDED = "expanded"
    CUSTOM = "custom"


class CredentialHeuristic(str, Enum):  # noqa: UP042 - durable enum
    """Whether disclosure applies the low-confidence credential *heuristic* (issue #982).

    ``enforced`` is the default and the only value every policy approved before this field
    existed can mean. ``disabled`` is an owner opt-out, granted only through the trusted policy
    decision, that stops disclosure from replacing or withholding values that only the
    assignment heuristic (``password = ...``, ``*_token = ...``) flags. It never touches the
    high-confidence detectors: known credential shapes, private-key markers, URI passwords,
    canaries and scanner saturation always block or redact.
    """

    ENFORCED = "enforced"
    DISABLED = "disabled"


class ConversationReview(str, Enum):  # noqa: UP042 - durable enum
    """How each conversation starts and who may switch it to AI-powered review (ADR-049).

    A conversation is one task. Every value but ``ai_powered`` starts each conversation with
    local checks only; a conversation switches to AI-powered review through its own
    ``decision_recorded`` 1.1.0 switch. ``local_agent_opt_in`` is the recommended default: the
    owner's choice of it is the standing pre-authorisation for an agent to switch a conversation
    on. Under ``local_owner_approval`` every AI-powered review a switch (or an explicit per-check
    request) asks for waits for the owner's per-request decision. Under ``local_only`` agents may
    not opt in: a switch leaves the conversation local. ``ai_powered`` starts every conversation
    with AI-powered review, the behaviour of every policy written before this field existed. None
    of them grants disclosure: the channel rows still decide what may leave, to whom, and how much.
    """

    LOCAL_ONLY = "local_only"
    LOCAL_OWNER_APPROVAL = "local_owner_approval"
    LOCAL_AGENT_OPT_IN = "local_agent_opt_in"
    AI_POWERED = "ai_powered"


_CONVERSATION_REVIEW_OPENNESS: Final[dict[ConversationReview, int]] = {
    ConversationReview.LOCAL_ONLY: 0,
    ConversationReview.LOCAL_OWNER_APPROVAL: 1,
    ConversationReview.LOCAL_AGENT_OPT_IN: 2,
    ConversationReview.AI_POWERED: 3,
}


# Issue #1082: directories outside the workspace whose files the task names may be read into the
# review packet as read-only task inputs, only beneath a root the owner admitted in the repository
# grant. A root is an absolute, normalized, plain path; never the filesystem root, a hidden
# directory, or a system tree that holds device, process or host configuration state.
MAX_ADMITTED_INPUT_ROOTS: Final = 8
_ADMITTED_INPUT_ROOT: Final = re.compile(r"\A(?:/[A-Za-z0-9_+@-][A-Za-z0-9._+@-]{0,127}){1,16}\Z")
_FORBIDDEN_INPUT_ROOT_PREFIXES: Final = (
    "/boot",
    "/dev",
    "/etc",
    "/private/etc",
    "/private/var/run",
    "/proc",
    "/run",
    "/sys",
    "/var/run",
)


# The same directories, for callers that also compare device and inode (#1220 review).
SYSTEM_DIRECTORY_PREFIXES: Final = _FORBIDDEN_INPUT_ROOT_PREFIXES


def system_directory_path(value: str) -> bool:
    """Whether absolute ``value`` is at or beneath a system directory no review ever reads."""

    return any(
        value == prefix or value.startswith(prefix + "/")
        for prefix in _FORBIDDEN_INPUT_ROOT_PREFIXES
    )


def admitted_input_root_valid(value: object) -> bool:
    """Whether ``value`` may be an admitted outside-workspace input root (issue #1082)."""

    if type(value) is not str or len(value) > 190 or _ADMITTED_INPUT_ROOT.fullmatch(value) is None:
        return False
    if any(part.startswith(".") or part == ".." for part in value.split("/")[1:]):
        return False
    return not any(
        value == prefix or value.startswith(prefix + "/")
        for prefix in _FORBIDDEN_INPUT_ROOT_PREFIXES
    )


def validate_admitted_input_roots(values: object) -> tuple[str, ...]:
    """The roots sorted and unique, or ``privacy_value_invalid``; at most eight."""

    if type(values) is not tuple:
        raise _invalid()
    roots = cast(tuple[object, ...], values)
    if len(roots) > MAX_ADMITTED_INPUT_ROOTS or not all(
        admitted_input_root_valid(root) for root in roots
    ):
        raise _invalid()
    ordered = tuple(sorted(set(cast(tuple[str, ...], roots)), key=str.encode))
    if len(ordered) != len(roots):
        raise _invalid()
    return ordered


def policy_field_omitted(name: str, value: object) -> bool:
    """Whether a policy field is left out of its canonical bytes at this value.

    The credential-heuristic default (issue #982) and an unset conversation setting (ADR-049) are
    never written, so every policy, case and receipt from before those fields existed keeps its
    exact canonical bytes and digest.
    """

    return (
        value is CredentialHeuristic.ENFORCED
        or (name == "conversation_review" and value is None)
        or (name == "admitted_input_roots" and value == ())
    )


def conversation_review_widens(before: ConversationReview, after: ConversationReview) -> bool:
    """Whether moving from *before* to *after* needs less of the owner (a loosening)."""

    return _CONVERSATION_REVIEW_OPENNESS[after] > _CONVERSATION_REVIEW_OPENNESS[before]


def narrower_conversation_review(
    first: ConversationReview, second: ConversationReview
) -> ConversationReview:
    """The setting of the two that needs more of the owner (ADR-049)."""

    return min((first, second), key=lambda item: _CONVERSATION_REVIEW_OPENNESS[item])


class EgressChannel(str, Enum):  # noqa: UP042 - durable enum
    LLM_INFERENCE = "llm_inference"
    PRODUCT_TELEMETRY = "product_telemetry"
    CRASH_DIAGNOSTICS = "crash_diagnostics"
    UPDATE_CHECKS = "update_checks"
    CAPABILITY_TESTING = "capability_testing"


class EgressOriginOperation(str, Enum):  # noqa: UP042 - durable enum
    """The FinishUP operation that asked for one network disclosure (tb4n2 N-5).

    Closed, so a receipt can name which operation minted it without carrying any request content.
    """

    SEMANTIC_CHECK = "semantic_check"
    OBSERVATION_ADVICE = "observation_advice"
    CREDENTIAL_PROBE = "credential_probe"


def egress_origin_operation(purpose: str, item_ids: Iterable[str]) -> EgressOriginOperation | None:
    """Name the operation behind one network disclosure from its purpose and reserved item ids.

    Every producer marks its case with a reserved structural item id, so the origin is derived,
    never asserted by a caller. An unrecognized shape returns ``None`` (the receipt omits it).
    """

    if purpose == "credential-probe":
        return EgressOriginOperation.CREDENTIAL_PROBE
    if purpose != "semantic-review":
        return None
    identities = frozenset(item_ids)
    if OBSERVATION_ADVICE_PACKET_ITEM_ID in identities:
        return EgressOriginOperation.OBSERVATION_ADVICE
    if REVIEW_PACKET_ITEM_ID in identities:
        return EgressOriginOperation.SEMANTIC_CHECK
    return None


class LocalDisclosureSink(str, Enum):  # noqa: UP042 - durable enum
    LOCAL_MODEL = "local_model"
    AGENT_CONTEXT = "agent_context"
    LOCAL_HUMAN_VIEW = "local_human_view"
    TRUSTED_HUMAN_CONTROL = "trusted_human_control"


class DisclosureProvenance(str, Enum):  # noqa: UP042 - durable enum
    SELF_AUTHORED = "self_authored"
    ENGINE_DERIVED_FROM_SELF_AUTHORED = "engine_derived_from_self_authored"
    OTHER_WRITER = "other_writer"
    IMPORTED = "imported"


class DataClass(str, Enum):  # noqa: UP042 - durable enum
    PUBLIC_STRUCTURAL = "public_structural"
    ORDINARY_USER_CONTENT = "ordinary_user_content"
    SENSITIVE_CONFIDENTIAL = "sensitive_confidential"
    SECRET_OR_CRYPTOGRAPHIC = "secret_or_cryptographic"


class ForbiddenDataKind(str, Enum):  # noqa: UP042 - durable enum
    ENCRYPTION_KEY = "encryption_key"
    RECOVERY_OR_UNLOCK_SECRET = "recovery_or_unlock_secret"
    PASSWORD = "password"
    API_CREDENTIAL = "api_credential"
    AUTHENTICATION_TOKEN = "authentication_token"
    COOKIE = "cookie"
    PRIVATE_CERTIFICATE = "private_certificate"
    KEYRING_CONTENT = "keyring_content"
    UNRELATED_ENVIRONMENT = "unrelated_environment"
    CREDENTIAL_FILE = "credential_file"
    HIDDEN_AUTH_CONFIGURATION = "hidden_auth_configuration"
    RAW_DATABASE = "raw_database"
    UNRESTRICTED_LOG = "unrestricted_log"
    RAW_STDERR = "raw_stderr"
    COMPLETE_TRANSCRIPT = "complete_transcript"
    OUT_OF_SCOPE_FILE = "out_of_scope_file"


NEVER_SEND_KINDS: Final = frozenset(ForbiddenDataKind)


class AuthorizationScopeKind(str, Enum):  # noqa: UP042 - durable enum
    MACHINE = "machine"
    WORKSPACE = "workspace"
    TASK = "task"
    REQUEST = "request"


class ConsentSource(str, Enum):  # noqa: UP042 - durable enum
    NONE = "none"
    BASELINE_POLICY = "baseline_policy"
    SCOPED_LOCAL_HUMAN = "scoped_local_human"
    PER_REQUEST_LOCAL_HUMAN = "per_request_local_human"


class PrivacyOutcome(str, Enum):  # noqa: UP042 - durable enum
    BLOCKED_BY_POLICY = "blocked_by_policy"
    BLOCKED_FORBIDDEN_DATA = "blocked_forbidden_data"
    CLASSIFICATION_UNCERTAIN = "classification_uncertain"
    HUMAN_DENIED = "human_denied"
    APPROVAL_EXPIRED = "approval_expired"
    CHANNEL_UNAVAILABLE = "channel_unavailable"
    PROVIDER_REFUSED = "provider_refused"
    TIMEOUT = "timeout"
    INVALID_RESPONSE = "invalid_response"
    TRANSPORT_FAILED = "transport_failed"
    LATE = "late"
    STALE = "stale"
    AUDIT_FAILED = "audit_failed"
    COMPLETED = "completed"


class PrivacyReason(str, Enum):  # noqa: UP042 - durable enum
    POLICY_DENIED = "policy_denied"
    NEVER_SEND_DETECTED = "never_send_detected"
    CLASSIFICATION_UNCERTAIN = "classification_uncertain"
    SCOPE_MISMATCH = "scope_mismatch"
    PURPOSE_NOT_ALLOWED = "purpose_not_allowed"
    DESTINATION_NOT_ALLOWED = "destination_not_allowed"
    CATEGORY_NOT_ALLOWED = "category_not_allowed"
    CHANNEL_UNAVAILABLE = "channel_unavailable"
    HUMAN_DENIED = "human_denied"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    AUTHORIZATION_STALE = "authorization_stale"
    AUTHORIZATION_REUSED = "authorization_reused"
    INSUFFICIENT_APPROVED_CONTEXT = "insufficient_approved_context"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PROVIDER_REFUSED = "provider_refused"
    PROVIDER_TIMEOUT = "provider_timeout"
    PROVIDER_INVALID_RESPONSE = "provider_invalid_response"
    TRANSPORT_FAILED = "transport_failed"
    AUDIT_FAILED = "audit_failed"
    DEADLINE_EXPIRED = "deadline_expired"
    LATE = "late"
    STALE = "stale"
    OUTCOME_UNKNOWN = "outcome_unknown"


_OUTCOME_REASONS: Final[dict[PrivacyOutcome, frozenset[PrivacyReason]]] = {
    PrivacyOutcome.BLOCKED_BY_POLICY: frozenset(
        {
            PrivacyReason.POLICY_DENIED,
            PrivacyReason.SCOPE_MISMATCH,
            PrivacyReason.PURPOSE_NOT_ALLOWED,
            PrivacyReason.DESTINATION_NOT_ALLOWED,
            PrivacyReason.CATEGORY_NOT_ALLOWED,
            PrivacyReason.INSUFFICIENT_APPROVED_CONTEXT,
        }
    ),
    PrivacyOutcome.BLOCKED_FORBIDDEN_DATA: frozenset({PrivacyReason.NEVER_SEND_DETECTED}),
    PrivacyOutcome.CLASSIFICATION_UNCERTAIN: frozenset({PrivacyReason.CLASSIFICATION_UNCERTAIN}),
    PrivacyOutcome.HUMAN_DENIED: frozenset({PrivacyReason.HUMAN_DENIED}),
    PrivacyOutcome.APPROVAL_EXPIRED: frozenset(
        {
            PrivacyReason.AUTHORIZATION_EXPIRED,
            PrivacyReason.AUTHORIZATION_STALE,
            PrivacyReason.AUTHORIZATION_REUSED,
        }
    ),
    PrivacyOutcome.CHANNEL_UNAVAILABLE: frozenset({PrivacyReason.CHANNEL_UNAVAILABLE}),
    PrivacyOutcome.PROVIDER_REFUSED: frozenset({PrivacyReason.PROVIDER_REFUSED}),
    PrivacyOutcome.TIMEOUT: frozenset(
        {PrivacyReason.PROVIDER_TIMEOUT, PrivacyReason.DEADLINE_EXPIRED}
    ),
    PrivacyOutcome.INVALID_RESPONSE: frozenset({PrivacyReason.PROVIDER_INVALID_RESPONSE}),
    PrivacyOutcome.TRANSPORT_FAILED: frozenset(
        {
            PrivacyReason.TRANSPORT_FAILED,
            PrivacyReason.PROVIDER_UNAVAILABLE,
            PrivacyReason.OUTCOME_UNKNOWN,
        }
    ),
    PrivacyOutcome.LATE: frozenset({PrivacyReason.LATE}),
    PrivacyOutcome.STALE: frozenset({PrivacyReason.STALE}),
    PrivacyOutcome.AUDIT_FAILED: frozenset({PrivacyReason.AUDIT_FAILED}),
    PrivacyOutcome.COMPLETED: frozenset(),
}


def outcome_reason_is_valid(outcome: PrivacyOutcome, reason: PrivacyReason | None) -> bool:
    if type(outcome) is not PrivacyOutcome:
        return False
    allowed = _OUTCOME_REASONS[outcome]
    return reason is None if not allowed else type(reason) is PrivacyReason and reason in allowed


@dataclass(frozen=True, slots=True)
class ProviderBinding:
    provider_id: str
    model_id: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    transport: Literal["external", "local_af_unix"]

    def __post_init__(self) -> None:
        _text(self.provider_id, _IDENTITY)
        _text(self.model_id, _MODEL_IDENTITY)
        _text(self.endpoint_profile_id, _IDENTITY)
        _text(self.endpoint_profile_version, _VERSION)
        if self.transport not in {"external", "local_af_unix"}:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class ProviderDataUseProfile:
    data_use_profile_id: str
    data_use_profile_version: str
    customer_content_training: Literal["prohibited", "permitted", "unknown"]
    retention: Literal["none", "bounded", "unbounded", "unknown"]
    retention_days_ceiling: int | None
    provider_human_access: Literal["prohibited", "restricted", "permitted", "unknown"]
    reviewed_at: datetime
    expires_at: datetime
    evidence_digest: str

    def __post_init__(self) -> None:
        _text(self.data_use_profile_id, _IDENTITY)
        _text(self.data_use_profile_version, _VERSION)
        if self.customer_content_training not in {"prohibited", "permitted", "unknown"}:
            raise _invalid()
        if self.retention not in {"none", "bounded", "unbounded", "unknown"}:
            raise _invalid()
        if (self.retention == "bounded") != (self.retention_days_ceiling is not None):
            raise _invalid()
        if self.retention_days_ceiling is not None:
            _nonnegative(self.retention_days_ceiling)
        if self.provider_human_access not in {
            "prohibited",
            "restricted",
            "permitted",
            "unknown",
        }:
            raise _invalid()
        _time(self.reviewed_at)
        _time(self.expires_at)
        if self.reviewed_at >= self.expires_at:
            raise _invalid()
        validate_sha256_digest(self.evidence_digest)

    def recommendation_eligible(self, now: datetime) -> bool:
        _time(now)
        return (
            self.reviewed_at <= now < self.expires_at
            and self.customer_content_training == "prohibited"
            and (
                self.retention == "none"
                or (
                    self.retention == "bounded"
                    and self.retention_days_ceiling is not None
                    and self.retention_days_ceiling <= 30
                )
            )
        )


_SECTIONS: Final = frozenset(
    {
        "goal",
        "obligations",
        "claims",
        "decisions",
        "timeline",
        "deterministic_assessments",
        "change_observations",
        "coverage",
        "targeted_excerpts",
        "omissions",
        # The user's request as transcribed by the agent, or the task title when none was
        # supplied (issue #908). Its own section so no approval given for the agent's plan
        # (``goal``) is ever read as covering it.
        "task_statement",
    }
)
_EXCERPT_KINDS: Final = frozenset({"evidence", "test", "failure", "diff", "command", "repository"})
# Review-selection presets are versioned with the privacy-policy wire schema that introduced them.
# A stored policy keeps the exact preset its owner approved: a newer preset never widens an older
# approval, it only becomes what the next approval ceremony offers. Each later version is a
# superset of the one before, so a newer preset always reads as a widening that needs approval.
type PrivacyPolicyPresetVersion = Literal["1.1.0", "1.2.0"]
PRIVACY_POLICY_PRESET_VERSIONS: Final[tuple[PrivacyPolicyPresetVersion, ...]] = ("1.1.0", "1.2.0")
CURRENT_PRIVACY_POLICY_PRESET_VERSION: Final[PrivacyPolicyPresetVersion] = "1.2.0"
# Sections a wire document can carry only from the named schema version on.
_SECTION_MINIMUM_SCHEMA_VERSION: Final[Mapping[str, PrivacyPolicyPresetVersion]] = {
    "task_statement": "1.2.0",
}
# Wire 1.0.0/1.1.0 bound ``max_excerpts`` to 16. Wire 1.2.0 raises the bound to the protocol
# maximum, and its Expanded preset uses it so the byte budget binds (issue #907 Phase 1b).
PRE_1_2_MAX_EXCERPTS: Final = 16


def review_selection_policy_schema_version(
    selection: ReviewSelectionPolicy,
) -> PrivacyPolicyPresetVersion:
    """The oldest privacy-policy wire schema that can express ``selection`` exactly.

    Encoding a selection at its minimum version keeps every policy approved before a newer
    vocabulary existed byte-identical, digest included.
    """

    if type(selection) is not ReviewSelectionPolicy:
        raise _invalid()
    version: PrivacyPolicyPresetVersion = "1.1.0"
    for section in selection.sections:
        required = _SECTION_MINIMUM_SCHEMA_VERSION.get(section)
        if required is not None and _preset_rank(required) > _preset_rank(version):
            version = required
    if selection.max_excerpts > PRE_1_2_MAX_EXCERPTS:
        version = "1.2.0"
    return version


def _preset_rank(version: PrivacyPolicyPresetVersion) -> int:
    return PRIVACY_POLICY_PRESET_VERSIONS.index(version)


@dataclass(frozen=True, slots=True)
class ReviewSelectionPolicy:
    sections: tuple[str, ...]
    excerpt_kinds: tuple[str, ...]
    relevance: Literal["linked_subjects_only", "linked_then_in_scope"]
    include_finding_prose: bool
    include_exact_command_text: bool
    max_timeline_items: int
    max_assessments: int
    max_change_observations: int
    max_excerpts: int
    max_omissions: int
    max_excerpt_bytes: int
    max_total_excerpt_bytes: int

    def __post_init__(self) -> None:
        sections = _sorted_text(self.sections, pattern=_IDENTITY)
        kinds = _sorted_text(self.excerpt_kinds, pattern=_IDENTITY)
        if not set(sections) <= _SECTIONS or not set(kinds) <= _EXCERPT_KINDS:
            raise _invalid()
        object.__setattr__(self, "sections", sections)
        object.__setattr__(self, "excerpt_kinds", kinds)
        if self.relevance not in {"linked_subjects_only", "linked_then_in_scope"}:
            raise _invalid()
        if (
            type(self.include_finding_prose) is not bool
            or type(self.include_exact_command_text) is not bool
        ):
            raise _invalid()
        _nonnegative(self.max_timeline_items, maximum=64)
        _nonnegative(self.max_assessments, maximum=64)
        _nonnegative(self.max_change_observations, maximum=32)
        _nonnegative(self.max_excerpts, maximum=MAX_REVIEW_EXCERPTS)
        _nonnegative(self.max_omissions, maximum=64)
        _nonnegative(self.max_excerpt_bytes, maximum=16_384)
        _nonnegative(self.max_total_excerpt_bytes, maximum=131_072)
        if self.max_excerpts == 0:
            if self.max_excerpt_bytes != 0 or self.max_total_excerpt_bytes != 0 or kinds:
                raise _invalid()
        elif self.max_excerpt_bytes == 0 or self.max_total_excerpt_bytes == 0:
            raise _invalid()

    @classmethod
    def for_profile(
        cls,
        profile: ReviewContextProfile,
        *,
        preset_version: PrivacyPolicyPresetVersion = CURRENT_PRIVACY_POLICY_PRESET_VERSION,
    ) -> ReviewSelectionPolicy:
        _enum(profile, ReviewContextProfile)
        if profile is ReviewContextProfile.CUSTOM:
            raise _invalid()
        if preset_version not in PRIVACY_POLICY_PRESET_VERSIONS:
            raise _invalid()
        sections = {
            "timeline",
            "deterministic_assessments",
            "change_observations",
            "coverage",
            "omissions",
        }
        finding = False
        kinds: set[str] = set()
        relevance: Literal["linked_subjects_only", "linked_then_in_scope"] = "linked_subjects_only"
        exact_commands = False
        max_excerpts = max_excerpt_bytes = max_total_excerpt_bytes = 0
        if profile is not ReviewContextProfile.STRUCTURAL:
            sections.update({"goal", "obligations", "claims", "decisions"})
            finding = True
            if _preset_rank(preset_version) >= _preset_rank("1.2.0"):
                # Goal-aware, Assisted and Expanded send the task statement from 1.2.0 on;
                # Structural never does (issue #908).
                sections.add("task_statement")
        if profile in {ReviewContextProfile.ASSISTED, ReviewContextProfile.EXPANDED}:
            sections.add("targeted_excerpts")
            kinds = set(_EXCERPT_KINDS)
            max_excerpts = PRE_1_2_MAX_EXCERPTS
            max_excerpt_bytes = 16_384
            max_total_excerpt_bytes = 131_072
        if profile is ReviewContextProfile.EXPANDED:
            relevance = "linked_then_in_scope"
            exact_commands = True
            if _preset_rank(preset_version) >= _preset_rank("1.2.0"):
                # From 1.2.0 the Expanded count is the protocol maximum, so the unchanged byte
                # budget binds instead of a 16-slot constant. Assisted keeps 16 (issue #907).
                max_excerpts = MAX_REVIEW_EXCERPTS
        return cls(
            sections=tuple(sections),
            excerpt_kinds=tuple(kinds),
            relevance=relevance,
            include_finding_prose=finding,
            include_exact_command_text=exact_commands,
            max_timeline_items=64,
            max_assessments=64,
            max_change_observations=32,
            max_excerpts=max_excerpts,
            max_omissions=64,
            max_excerpt_bytes=max_excerpt_bytes,
            max_total_excerpt_bytes=max_total_excerpt_bytes,
        )

    @classmethod
    def is_profile_preset(
        cls, profile: ReviewContextProfile, selection: ReviewSelectionPolicy
    ) -> bool:
        """Whether ``selection`` is exactly one versioned preset of the named profile."""

        _enum(profile, ReviewContextProfile)
        if profile is ReviewContextProfile.CUSTOM or type(selection) is not ReviewSelectionPolicy:
            return False
        return any(
            selection == cls.for_profile(profile, preset_version=version)
            for version in PRIVACY_POLICY_PRESET_VERSIONS
        )

    def required_categories(self) -> frozenset[DataCategory]:
        """Categories the selected sections will actually produce case items in.

        Selection decides what the case is *built* from; a channel's ``allowed_categories``
        decides what may *leave*. The two are configured independently and nothing reconciled
        them, so a profile could select obligations and finding prose while the channel forbade
        ``obligation_text`` and ``finding_summary`` — the reviewer was then asked whether the work
        satisfied its obligations with the obligations withheld, and answered nothing.
        """

        by_section: dict[str, DataCategory] = {
            "task_statement": DataCategory.TASK_DESCRIPTION,
            "goal": DataCategory.TASK_DESCRIPTION,
            "obligations": DataCategory.OBLIGATION_TEXT,
            "claims": DataCategory.CLAIM_TEXT,
            "decisions": DataCategory.DECISION_EXCERPT,
        }
        required = {by_section[section] for section in self.sections if section in by_section}
        # The timeline and the structural spine are always bounded metadata.
        required.add(DataCategory.BOUNDED_STRUCTURAL_METADATA)
        if self.include_finding_prose:
            required.add(DataCategory.FINDING_SUMMARY)
        if self.max_excerpts:
            required.add(DataCategory.EVIDENCE_EXCERPT)
        if self.carries_check_time_change:
            # The check-time change is the service's own repository read (ADR-031), so it leaves
            # only as a repository excerpt; a channel without that category withholds it visibly.
            required.add(DataCategory.REPOSITORY_EXCERPT)
        return frozenset(required)

    @property
    def carries_check_time_change(self) -> bool:
        """Whether a review under this selection carries the ADR-031 check-time change."""

        return (
            "targeted_excerpts" in self.sections
            and self.max_excerpts > 0
            and "diff" in self.excerpt_kinds
        )

    def meet(self, other: ReviewSelectionPolicy) -> ReviewSelectionPolicy:
        if type(other) is not ReviewSelectionPolicy:
            raise _invalid()
        return ReviewSelectionPolicy(
            sections=tuple(set(self.sections) & set(other.sections)),
            excerpt_kinds=tuple(set(self.excerpt_kinds) & set(other.excerpt_kinds)),
            relevance=(
                "linked_subjects_only"
                if "linked_subjects_only" in {self.relevance, other.relevance}
                else "linked_then_in_scope"
            ),
            include_finding_prose=self.include_finding_prose and other.include_finding_prose,
            include_exact_command_text=(
                self.include_exact_command_text and other.include_exact_command_text
            ),
            max_timeline_items=min(self.max_timeline_items, other.max_timeline_items),
            max_assessments=min(self.max_assessments, other.max_assessments),
            max_change_observations=min(
                self.max_change_observations, other.max_change_observations
            ),
            max_excerpts=min(self.max_excerpts, other.max_excerpts),
            max_omissions=min(self.max_omissions, other.max_omissions),
            max_excerpt_bytes=min(self.max_excerpt_bytes, other.max_excerpt_bytes),
            max_total_excerpt_bytes=min(
                self.max_total_excerpt_bytes, other.max_total_excerpt_bytes
            ),
        )


@dataclass(frozen=True, slots=True)
class AuthorizationScope:
    kind: AuthorizationScopeKind
    installation_id: str
    workspace_ref_commitment: str | None = None
    task_id: str | None = None
    request_id: str | None = None

    def __post_init__(self) -> None:
        _enum(self.kind, AuthorizationScopeKind)
        validate_id(IdKind.INSTALLATION, self.installation_id)
        needs_workspace = self.kind is not AuthorizationScopeKind.MACHINE
        needs_task = self.kind in {AuthorizationScopeKind.TASK, AuthorizationScopeKind.REQUEST}
        needs_request = self.kind is AuthorizationScopeKind.REQUEST
        if (self.workspace_ref_commitment is not None) != needs_workspace:
            raise _invalid()
        if self.workspace_ref_commitment is not None:
            validate_commitment(self.workspace_ref_commitment)
        if (self.task_id is not None) != needs_task:
            raise _invalid()
        if self.task_id is not None:
            validate_id(IdKind.TASK, self.task_id)
        if (self.request_id is not None) != needs_request:
            raise _invalid()
        if self.request_id is not None:
            validate_id(IdKind.REQUEST, self.request_id)

    def contains(self, child: AuthorizationScope) -> bool:
        if type(child) is not AuthorizationScope or self.installation_id != child.installation_id:
            return False
        if self.kind is AuthorizationScopeKind.MACHINE:
            return True
        if self.workspace_ref_commitment != child.workspace_ref_commitment:
            return False
        if self.kind is AuthorizationScopeKind.WORKSPACE:
            return True
        if self.task_id != child.task_id:
            return False
        if self.kind is AuthorizationScopeKind.TASK:
            return True
        return self.request_id == child.request_id


@dataclass(frozen=True, slots=True)
class ChannelPolicy:
    channel: EgressChannel
    enabled: bool
    allowed_categories: tuple[DataCategory, ...]
    allowed_data_classes: tuple[DataClass, ...]
    provider_binding: ProviderBinding | None
    allowed_purposes: tuple[str, ...]
    scope_ceiling: AuthorizationScopeKind
    preview_required: bool
    max_bytes: int
    max_tokens: int
    authorization_ttl_seconds: int
    # Second authorized destination for the same channel (issue #582). It is dispatched only
    # after the primary records the closed fallback-licensing failures; approving it is a
    # widening of exactly one more destination, never a wildcard. Trailing default keeps every
    # existing positional constructor and the single-endpoint wire shape unchanged.
    fallback_provider_binding: ProviderBinding | None = None

    def __post_init__(self) -> None:
        _enum(self.channel, EgressChannel)
        if type(self.enabled) is not bool or type(self.preview_required) is not bool:
            raise _invalid()
        object.__setattr__(
            self, "allowed_categories", _sorted_enums(self.allowed_categories, DataCategory)
        )
        object.__setattr__(
            self, "allowed_categories", _without_receipt_only(self.allowed_categories)
        )
        object.__setattr__(
            self, "allowed_data_classes", _sorted_enums(self.allowed_data_classes, DataClass)
        )
        object.__setattr__(
            self, "allowed_purposes", _sorted_text(self.allowed_purposes, pattern=_PURPOSE)
        )
        _enum(self.scope_ceiling, AuthorizationScopeKind)
        _nonnegative(self.max_bytes, maximum=MAX_EGRESS_CASE_BYTES)
        _nonnegative(self.max_tokens)
        _nonnegative(self.authorization_ttl_seconds, maximum=86_400)
        if not self.enabled:
            if (
                self.allowed_categories
                or self.allowed_data_classes
                or self.provider_binding is not None
                or self.fallback_provider_binding is not None
                or self.allowed_purposes
                or self.preview_required
                or self.max_bytes
                or self.max_tokens
                or self.authorization_ttl_seconds
            ):
                raise _invalid()
        if self.provider_binding is not None and type(self.provider_binding) is not ProviderBinding:
            raise _invalid()
        if self.fallback_provider_binding is not None:
            # A fallback is meaningful only behind an external primary it differs from: the same
            # destination twice would be a hidden retry budget, and a local sink cannot stand in
            # for a network channel.
            if (
                type(self.fallback_provider_binding) is not ProviderBinding
                or self.provider_binding is None
                or self.provider_binding.transport != "external"
                or self.fallback_provider_binding.transport != "external"
                or self.fallback_provider_binding == self.provider_binding
            ):
                raise _invalid()
        if self.channel is not EgressChannel.LLM_INFERENCE:
            if self.provider_binding is not None or self.fallback_provider_binding is not None:
                raise _invalid()
            if set(self.allowed_data_classes) - {DataClass.PUBLIC_STRUCTURAL}:
                raise _invalid()

    @property
    def authorized_provider_bindings(self) -> tuple[ProviderBinding, ...]:
        """Every destination this row authorizes, primary first; empty when disabled."""

        if self.provider_binding is None:
            return ()
        if self.fallback_provider_binding is None:
            return (self.provider_binding,)
        return (self.provider_binding, self.fallback_provider_binding)

    def meet(self, other: ChannelPolicy) -> ChannelPolicy:
        """Intersect two channel rows (AND enablement, set meet, min ceilings)."""

        if type(other) is not ChannelPolicy or self.channel is not other.channel:
            raise _invalid()
        if not self.enabled or not other.enabled:
            return ChannelPolicy(
                self.channel,
                False,
                (),
                (),
                None,
                (),
                AuthorizationScopeKind.MACHINE,
                False,
                0,
                0,
                0,
            )
        binding = (
            self.provider_binding
            if self.provider_binding is not None and self.provider_binding == other.provider_binding
            else None
        )
        # Enabled external LLM without an exact shared binding cannot authorize a destination.
        if self.channel is EgressChannel.LLM_INFERENCE and binding is None:
            return ChannelPolicy(
                self.channel,
                False,
                (),
                (),
                None,
                (),
                AuthorizationScopeKind.MACHINE,
                False,
                0,
                0,
                0,
            )
        # The fallback survives only when both scopes name the identical one; disagreement
        # tightens to the primary alone rather than disabling a channel both scopes allow.
        fallback = (
            self.fallback_provider_binding
            if self.fallback_provider_binding is not None
            and self.fallback_provider_binding == other.fallback_provider_binding
            else None
        )
        # A lower rank is a *broader* ceiling (machine is widest, request narrowest), matching
        # ``_scope_rank`` in ``finishup.application.privacy_policy``, where task -> machine is
        # classified as a widening. The meet must therefore keep the higher-ranked ceiling.
        ceiling = (
            self.scope_ceiling
            if _SCOPE_KIND_RANK[self.scope_ceiling] >= _SCOPE_KIND_RANK[other.scope_ceiling]
            else other.scope_ceiling
        )
        return ChannelPolicy(
            self.channel,
            True,
            tuple(set(self.allowed_categories) & set(other.allowed_categories)),
            tuple(set(self.allowed_data_classes) & set(other.allowed_data_classes)),
            binding,
            tuple(set(self.allowed_purposes) & set(other.allowed_purposes)),
            ceiling,
            self.preview_required or other.preview_required,
            min(self.max_bytes, other.max_bytes),
            min(self.max_tokens, other.max_tokens),
            min(self.authorization_ttl_seconds, other.authorization_ttl_seconds),
            fallback,
        )


_SCOPE_KIND_RANK: Final = {
    AuthorizationScopeKind.MACHINE: 0,
    AuthorizationScopeKind.WORKSPACE: 1,
    AuthorizationScopeKind.TASK: 2,
    AuthorizationScopeKind.REQUEST: 3,
}
_PROFILE_OPENNESS: Final = {
    PrivacyProfile.LOCAL_ONLY: 0,
    PrivacyProfile.CONFIRM_EVERY_REQUEST: 1,
    PrivacyProfile.MINIMAL_EXTERNAL: 2,
    PrivacyProfile.TRUSTED_PROVIDER: 3,
}
_REVIEW_CONTEXT_OPENNESS: Final = {
    ReviewContextProfile.STRUCTURAL: 0,
    ReviewContextProfile.GOAL_AWARE: 1,
    ReviewContextProfile.ASSISTED: 2,
    ReviewContextProfile.EXPANDED: 3,
    ReviewContextProfile.CUSTOM: 4,
}


@dataclass(frozen=True, slots=True)
class PrivacyPolicy:
    policy_id: str
    version: int
    policy_digest: str
    profile: PrivacyProfile
    review_context_profile: ReviewContextProfile
    review_selection: ReviewSelectionPolicy
    require_current_provider_data_use_evidence: bool
    network_egress_permitted: bool
    effective_scope: AuthorizationScope
    channel_policies: tuple[ChannelPolicy, ...]
    local_model_enabled: bool
    local_model_binding: ProviderBinding | None
    local_model_categories: tuple[DataCategory, ...]
    local_model_data_classes: tuple[DataClass, ...]
    agent_context_categories: tuple[DataCategory, ...]
    agent_context_data_classes: tuple[DataClass, ...]
    trusted_human_control_categories: tuple[DataCategory, ...]
    trusted_human_control_data_classes: tuple[DataClass, ...]
    created_at: datetime
    supersedes_policy_digest: str | None = None
    # Owner opt-out for the low-confidence credential heuristic (issue #982). Encoded only when
    # ``disabled`` so every policy written before the field existed keeps its bytes and digest.
    credential_heuristic: CredentialHeuristic = CredentialHeuristic.ENFORCED
    # The owner's conversation default and agent opt-in (ADR-049). ``None`` is every policy
    # written before the field existed; it is encoded only when set, so those keep their bytes and
    # digest, and ``effective_conversation_review`` reads it as the released behaviour.
    conversation_review: ConversationReview | None = None
    # Directories outside the workspace the owner admitted for read-only task inputs (issue
    # #1082). Empty is every policy written before the field existed; it is encoded only when
    # set, so those keep their bytes and digest. Adding a root widens disclosure and needs the
    # trusted decision; removing one applies at once.
    admitted_input_roots: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_id(IdKind.PRIVACY_POLICY, self.policy_id)
        _positive(self.version)
        validate_sha256_digest(self.policy_digest)
        _enum(self.profile, PrivacyProfile)
        _enum(self.review_context_profile, ReviewContextProfile)
        if type(self.review_selection) is not ReviewSelectionPolicy:
            raise _invalid()
        if self.review_context_profile is not ReviewContextProfile.CUSTOM:
            # Any versioned preset of the profile is valid: an approval made under an older
            # preset stays exactly what its owner approved (issue #908).
            if not ReviewSelectionPolicy.is_profile_preset(
                self.review_context_profile, self.review_selection
            ):
                raise _invalid()
        if type(self.require_current_provider_data_use_evidence) is not bool:
            raise _invalid()
        if type(self.network_egress_permitted) is not bool:
            raise _invalid()
        if type(self.effective_scope) is not AuthorizationScope:
            raise _invalid()
        if type(self.channel_policies) is not tuple or len(self.channel_policies) != 5:
            raise _invalid()
        if any(type(policy) is not ChannelPolicy for policy in self.channel_policies):
            raise _invalid()
        ordered = tuple(
            sorted(self.channel_policies, key=lambda policy: policy.channel.value.encode())
        )
        if self.channel_policies != ordered or {policy.channel for policy in ordered} != set(
            EgressChannel
        ):
            raise _invalid()
        llm = next(policy for policy in ordered if policy.channel is EgressChannel.LLM_INFERENCE)
        if not self.network_egress_permitted and any(policy.enabled for policy in ordered):
            raise _invalid()
        if self.profile is PrivacyProfile.LOCAL_ONLY:
            if llm.enabled or llm.provider_binding is not None:
                raise _invalid()
        elif (
            not self.network_egress_permitted
            or not llm.enabled
            or llm.provider_binding is None
            or llm.provider_binding.transport != "external"
        ):
            raise _invalid()
        if self.profile is PrivacyProfile.CONFIRM_EVERY_REQUEST and not llm.preview_required:
            raise _invalid()
        if (
            self.profile is PrivacyProfile.MINIMAL_EXTERNAL
            and DataClass.SENSITIVE_CONFIDENTIAL in llm.allowed_data_classes
        ):
            raise _invalid()
        if self.require_current_provider_data_use_evidence and llm.provider_binding is None:
            raise _invalid()
        if type(self.local_model_enabled) is not bool:
            raise _invalid()
        if self.local_model_enabled != (self.local_model_binding is not None):
            raise _invalid()
        if (
            self.local_model_binding is not None
            and self.local_model_binding.transport != "local_af_unix"
        ):
            raise _invalid()
        for name, enum_type in (
            ("local_model_categories", DataCategory),
            ("local_model_data_classes", DataClass),
            ("agent_context_categories", DataCategory),
            ("agent_context_data_classes", DataClass),
            ("trusted_human_control_categories", DataCategory),
            ("trusted_human_control_data_classes", DataClass),
        ):
            object.__setattr__(self, name, _sorted_enums(getattr(self, name), enum_type))
        for name in (
            "local_model_categories",
            "agent_context_categories",
            "trusted_human_control_categories",
        ):
            object.__setattr__(self, name, _without_receipt_only(getattr(self, name)))
        if any(
            DataClass.SECRET_OR_CRYPTOGRAPHIC in values
            for values in (
                self.local_model_data_classes,
                self.agent_context_data_classes,
                self.trusted_human_control_data_classes,
            )
        ):
            raise _invalid()
        _time(self.created_at)
        if self.supersedes_policy_digest is not None:
            validate_sha256_digest(self.supersedes_policy_digest)
        _enum(self.credential_heuristic, CredentialHeuristic)
        if self.conversation_review is not None:
            _enum(self.conversation_review, ConversationReview)
        object.__setattr__(
            self, "admitted_input_roots", validate_admitted_input_roots(self.admitted_input_roots)
        )

    @property
    def credential_heuristic_enforced(self) -> bool:
        return self.credential_heuristic is CredentialHeuristic.ENFORCED

    @property
    def effective_conversation_review(self) -> ConversationReview:
        """The conversation setting this policy means, explicit or released (ADR-049).

        An explicit value is the owner's. A policy written before the field existed keeps the
        released behaviour: AI-powered review in every conversation where its inference channel
        is enabled, and local checks only where nothing may be sent for review.
        """

        if self.conversation_review is not None:
            return self.conversation_review
        llm = next(
            (item for item in self.channel_policies if item.channel is EgressChannel.LLM_INFERENCE),
            None,
        )
        if llm is not None and llm.enabled:
            return ConversationReview.AI_POWERED
        return ConversationReview.LOCAL_ONLY

    def meet(self, other: PrivacyPolicy) -> PrivacyPolicy:
        """Intersect two standing policies (ADR-009 decision 6 / protocol policy resolution).

        Permission fields tighten by meet (AND / set intersection / min ceilings). Identity
        (``policy_id``, ``version``, ``created_at``, ``effective_scope``) is taken from the
        more-specific scope when ranks differ, else from ``self``. The result's
        ``policy_digest`` is recomputed from the meet body so multi-scope composition is not
        confused with a single stored row.
        """

        if type(other) is not PrivacyPolicy:
            raise _invalid()
        if self.effective_scope.installation_id != other.effective_scope.installation_id:
            raise _invalid()

        by_self = {channel.channel: channel for channel in self.channel_policies}
        by_other = {channel.channel: channel for channel in other.channel_policies}
        channels = tuple(
            by_self[channel].meet(by_other[channel])
            for channel in sorted(EgressChannel, key=lambda item: item.value.encode("ascii"))
        )
        network = (
            self.network_egress_permitted
            and other.network_egress_permitted
            and any(channel.enabled for channel in channels)
        )
        if not network:
            channels = tuple(
                ChannelPolicy(
                    channel.channel,
                    False,
                    (),
                    (),
                    None,
                    (),
                    AuthorizationScopeKind.MACHINE,
                    False,
                    0,
                    0,
                    0,
                )
                for channel in channels
            )

        llm = next(
            channel for channel in channels if channel.channel is EgressChannel.LLM_INFERENCE
        )
        profile_rank = min(_PROFILE_OPENNESS[self.profile], _PROFILE_OPENNESS[other.profile])
        if not network or not llm.enabled or llm.provider_binding is None:
            profile = PrivacyProfile.LOCAL_ONLY
        else:
            profile = next(item for item, rank in _PROFILE_OPENNESS.items() if rank == profile_rank)
            if profile is PrivacyProfile.LOCAL_ONLY:
                profile = PrivacyProfile.MINIMAL_EXTERNAL
            if profile is PrivacyProfile.CONFIRM_EVERY_REQUEST and not llm.preview_required:
                # Meet of preview flags should have ORed; keep construction valid.
                llm = replace(llm, preview_required=True)
                channels = tuple(
                    llm if channel.channel is EgressChannel.LLM_INFERENCE else channel
                    for channel in channels
                )
            if (
                profile is PrivacyProfile.MINIMAL_EXTERNAL
                and DataClass.SENSITIVE_CONFIDENTIAL in llm.allowed_data_classes
            ):
                llm = replace(
                    llm,
                    allowed_data_classes=tuple(
                        item
                        for item in llm.allowed_data_classes
                        if item is not DataClass.SENSITIVE_CONFIDENTIAL
                    ),
                )
                channels = tuple(
                    llm if channel.channel is EgressChannel.LLM_INFERENCE else channel
                    for channel in channels
                )

        review_selection = self.review_selection.meet(other.review_selection)
        review_rank = min(
            _REVIEW_CONTEXT_OPENNESS[self.review_context_profile],
            _REVIEW_CONTEXT_OPENNESS[other.review_context_profile],
        )
        review_context = next(
            item for item, rank in _REVIEW_CONTEXT_OPENNESS.items() if rank == review_rank
        )
        if review_context is not ReviewContextProfile.CUSTOM:
            if not ReviewSelectionPolicy.is_profile_preset(review_context, review_selection):
                review_context = ReviewContextProfile.CUSTOM

        local_enabled = self.local_model_enabled and other.local_model_enabled
        local_binding = (
            self.local_model_binding
            if local_enabled
            and self.local_model_binding is not None
            and self.local_model_binding == other.local_model_binding
            else None
        )
        if local_binding is None:
            local_enabled = False

        identity = (
            other
            if _SCOPE_KIND_RANK[other.effective_scope.kind]
            > _SCOPE_KIND_RANK[self.effective_scope.kind]
            else self
        )
        placeholder = PrivacyPolicy(
            identity.policy_id,
            identity.version,
            "sha256:" + "0" * 64,
            profile,
            review_context,
            review_selection,
            self.require_current_provider_data_use_evidence
            or other.require_current_provider_data_use_evidence,
            network,
            identity.effective_scope,
            channels,
            local_enabled,
            local_binding,
            tuple(set(self.local_model_categories) & set(other.local_model_categories)),
            tuple(set(self.local_model_data_classes) & set(other.local_model_data_classes)),
            tuple(set(self.agent_context_categories) & set(other.agent_context_categories)),
            tuple(set(self.agent_context_data_classes) & set(other.agent_context_data_classes)),
            tuple(
                set(self.trusted_human_control_categories)
                & set(other.trusted_human_control_categories)
            ),
            tuple(
                set(self.trusted_human_control_data_classes)
                & set(other.trusted_human_control_data_classes)
            ),
            identity.created_at,
            None,
            _composed_credential_heuristic(self, other),
            _composed_conversation_review(self, other),
            _composed_input_roots(self, other),
        )
        meet_identity: dict[str, JsonValue] = {
            "components": cast(JsonValue, sorted((self.policy_digest, other.policy_digest))),
            "meet": "yoetz.privacy-policy-meet/1",
            "network_egress_permitted": placeholder.network_egress_permitted,
            "profile": placeholder.profile.value,
            "require_current_provider_data_use_evidence": (
                placeholder.require_current_provider_data_use_evidence
            ),
            "review_context_profile": placeholder.review_context_profile.value,
        }
        if not placeholder.credential_heuristic_enforced:
            # Absent when enforced, so every existing composition keeps its digest.
            meet_identity["credential_heuristic"] = placeholder.credential_heuristic.value
        if placeholder.conversation_review is not None:
            # Absent when unset, so every existing composition keeps its digest (ADR-049).
            meet_identity["conversation_review"] = placeholder.conversation_review.value
        if placeholder.admitted_input_roots:
            # Absent when empty, so every existing composition keeps its digest (issue #1082).
            meet_identity["admitted_input_roots"] = cast(
                JsonValue, list(placeholder.admitted_input_roots)
            )
        return replace(
            placeholder,
            policy_digest=canonical_digest(cast(JsonValue, meet_identity)),
        )

    @property
    def unsupported_enabled_channels(self) -> tuple[EgressChannel, ...]:
        """Non-LLM channels that still have no production transport in this release.

        ``update_checks`` ships a bounded structural transport (PyPI package identity only).
        The remaining non-LLM rows stay unavailable: enablement is rejected at proposal time,
        and forced enabled state yields a pre-dispatch ``channel_unavailable`` receipt.
        """

        supported = frozenset({EgressChannel.LLM_INFERENCE, EgressChannel.UPDATE_CHECKS})
        return tuple(
            policy.channel
            for policy in self.channel_policies
            if policy.enabled and policy.channel not in supported
        )

    @property
    def withheld_review_categories(self) -> tuple[DataCategory, ...]:
        """Categories the review selects but the inference channel will not let out.

        Non-empty means the AI-powered reviewer receives a case with holes in exactly the places
        the review profile claimed to fill. That is a legitimate configuration — narrowing egress
        is always allowed — but it must never be silent, because the review still reports
        ``succeeded`` while being unable to answer the question it was asked.
        """

        channel = next(
            (item for item in self.channel_policies if item.channel is EgressChannel.LLM_INFERENCE),
            None,
        )
        if channel is None or not channel.enabled:
            return ()
        permitted = set(channel.allowed_categories)
        return tuple(
            sorted(
                self.review_selection.required_categories() - permitted,
                key=lambda item: item.value.encode("ascii"),
            )
        )


def external_review_credential_heuristic(
    policy: PrivacyPolicy, binding: ProviderBinding | None, *, local_sink: object = None
) -> CredentialHeuristic:
    """The credential-heuristic setting one disclosure applies (owner decision, 2026-10-07).

    The opt-out reaches only the external AI reviewer: an LLM-inference disclosure to an external
    provider binding. Every local output (agent context, local model, local views) keeps the
    heuristic exactly as when it is enabled.
    """

    if type(policy) is not PrivacyPolicy:
        raise _invalid()
    if local_sink is None and binding is not None and binding.transport == "external":
        return policy.credential_heuristic
    return CredentialHeuristic.ENFORCED


def _composed_conversation_review(
    first: PrivacyPolicy, second: PrivacyPolicy
) -> ConversationReview | None:
    """Compose the conversation setting of two scopes (ADR-049).

    Like the credential heuristic, the setting belongs to the repository grant: between the
    installation-wide row and a repository row, the repository row's explicit value decides and
    the installation value is only the default a repository without one inherits. Any other
    composition keeps the setting that needs more of the owner. Unset on both sides stays unset,
    so the released reading applies to the composed policy.
    """

    kinds = {first.effective_scope.kind, second.effective_scope.kind}
    if kinds == {AuthorizationScopeKind.MACHINE, AuthorizationScopeKind.WORKSPACE}:
        repository, machine = (
            (first, second)
            if first.effective_scope.kind is AuthorizationScopeKind.WORKSPACE
            else (second, first)
        )
        if repository.conversation_review is not None:
            return repository.conversation_review
        return machine.conversation_review
    explicit = [
        item.conversation_review for item in (first, second) if item.conversation_review is not None
    ]
    if not explicit:
        return None
    return min(explicit, key=lambda item: _CONVERSATION_REVIEW_OPENNESS[item])


def _composed_input_roots(first: PrivacyPolicy, second: PrivacyPolicy) -> tuple[str, ...]:
    """Compose the admitted outside-workspace input roots of two scopes (issue #1082).

    The roots belong to the repository grant: between the installation-wide row and a repository
    row, the repository row decides, and the installation row cannot admit a root for every
    repository. Any other composition keeps only the roots both sides admit.
    """

    kinds = {first.effective_scope.kind, second.effective_scope.kind}
    if kinds == {AuthorizationScopeKind.MACHINE, AuthorizationScopeKind.WORKSPACE}:
        repository = (
            first if first.effective_scope.kind is AuthorizationScopeKind.WORKSPACE else second
        )
        return repository.admitted_input_roots
    return tuple(
        sorted(set(first.admitted_input_roots) & set(second.admitted_input_roots), key=str.encode)
    )


def _composed_credential_heuristic(
    first: PrivacyPolicy, second: PrivacyPolicy
) -> CredentialHeuristic:
    """Compose the credential-heuristic setting of two scopes (owner decision, 2026-10-07).

    The opt-out belongs to the repository grant: between the installation-wide row and a
    repository row, the repository row decides, so a repository is "off" only where its own grant
    says off. The installation-wide value is only the default a repository without a grant
    inherits. Any other composition (two installation rows, or a task or request row) keeps
    ``enforced`` unless both sides are ``disabled``.
    """

    kinds = {first.effective_scope.kind, second.effective_scope.kind}
    if kinds == {AuthorizationScopeKind.MACHINE, AuthorizationScopeKind.WORKSPACE}:
        repository = (
            first if first.effective_scope.kind is AuthorizationScopeKind.WORKSPACE else second
        )
        return repository.credential_heuristic
    if first.credential_heuristic_enforced or second.credential_heuristic_enforced:
        return CredentialHeuristic.ENFORCED
    return CredentialHeuristic.DISABLED


@dataclass(frozen=True, slots=True)
class PolicyOverlay:
    scope: AuthorizationScope
    review_selection: ReviewSelectionPolicy
    require_current_provider_data_use_evidence: bool
    channel_policies: tuple[ChannelPolicy, ...]
    local_model_categories: tuple[DataCategory, ...]
    local_model_data_classes: tuple[DataClass, ...]
    agent_context_categories: tuple[DataCategory, ...]
    agent_context_data_classes: tuple[DataClass, ...]
    candidate_policy: PrivacyPolicy

    def __post_init__(self) -> None:
        if (
            type(self.scope) is not AuthorizationScope
            or type(self.review_selection) is not ReviewSelectionPolicy
            or type(self.candidate_policy) is not PrivacyPolicy
            or self.candidate_policy.effective_scope != self.scope
        ):
            raise _invalid()
        if type(self.require_current_provider_data_use_evidence) is not bool:
            raise _invalid()
        if type(self.channel_policies) is not tuple or any(
            type(value) is not ChannelPolicy for value in self.channel_policies
        ):
            raise _invalid()
        for name, enum_type in (
            ("local_model_categories", DataCategory),
            ("local_model_data_classes", DataClass),
            ("agent_context_categories", DataCategory),
            ("agent_context_data_classes", DataClass),
        ):
            object.__setattr__(self, name, _sorted_enums(getattr(self, name), enum_type))
        for name in ("local_model_categories", "agent_context_categories"):
            object.__setattr__(self, name, _without_receipt_only(getattr(self, name)))
        if (
            self.candidate_policy.review_selection != self.review_selection
            or self.candidate_policy.require_current_provider_data_use_evidence
            != self.require_current_provider_data_use_evidence
            or self.candidate_policy.channel_policies != self.channel_policies
            or self.candidate_policy.local_model_categories != self.local_model_categories
            or self.candidate_policy.local_model_data_classes != self.local_model_data_classes
            or self.candidate_policy.agent_context_categories != self.agent_context_categories
            or self.candidate_policy.agent_context_data_classes != self.agent_context_data_classes
        ):
            raise _invalid()


PRIVACY_CHANGE_AREAS: Final = frozenset(
    {"global", "review", "channel", "local_model", "agent_context", "human_control"}
)
# Every field token a policy diff may name, keyed by area. The allowlist is the closed
# vocabulary shared by the classifier, the wire preview, and the trusted renderer: a field
# absent here can never reach a human approval screen, and a field present here always has a
# fixed local label. Adding a policy dimension therefore has to add its token in one place.
PRIVACY_CHANGE_FIELDS: Final = {
    "global": frozenset(
        {
            "admitted_input_roots",
            "conversation_review",
            "credential_heuristic",
            "effective_scope",
            "network_egress",
            "provider_data_use_evidence",
        }
    ),
    "review": frozenset(
        {
            "sections",
            "excerpt_kinds",
            "relevance",
            "include_finding_prose",
            "include_exact_command_text",
            "max_timeline_items",
            "max_assessments",
            "max_change_observations",
            "max_excerpts",
            "max_omissions",
            "max_excerpt_bytes",
            "max_total_excerpt_bytes",
        }
    ),
    "channel": frozenset(
        {
            "enabled",
            "categories",
            "data_classes",
            "purposes",
            "provider",
            "fallback_provider",
            "scope_ceiling",
            "preview_required",
            "max_bytes",
            "max_tokens",
            "authorization_ttl_seconds",
        }
    ),
    "local_model": frozenset({"enabled", "binding", "categories", "data_classes"}),
    "agent_context": frozenset({"categories", "data_classes"}),
    "human_control": frozenset({"categories", "data_classes"}),
}
MAX_PRIVACY_CHANGE_LABELS: Final = 64
MAX_PRIVACY_CHANGES: Final = 128
# Derived, not chosen: a label is one fixed prefix plus one policy field, and every policy field
# is independently bounded at 128 bytes by its own validator. The longest prefix in use is
# ``endpoint_version:`` (17), so 192 leaves headroom while staying bounded. A tighter bound would
# reject a legitimate binding, and rejecting one here means a human cannot approve a policy that
# is otherwise entirely valid.
MAX_PRIVACY_LABEL_BYTES: Final = 192
# Terminal-safe: printable ASCII with no space, control byte, or escape introducer, so a value
# that reaches the trusted foreground console cannot move the cursor or repaint the screen.
# ``\A``/``\Z`` rather than ``^``/``$``: the callers use ``fullmatch``, which already refuses a
# trailing newline, but anchoring explicitly means a future ``match`` call cannot quietly admit
# one.
_PRIVACY_LABEL = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,191}\Z", re.ASCII)


@dataclass(frozen=True, slots=True)
class PrivacyPolicyChangeValue:
    """One bounded canonical side of a policy diff.

    ``none`` means the dimension does not apply on that side (a disabled channel has no
    ceiling, an unbound sink has no destination) and is deliberately distinct from ``labels``
    with an empty tuple, which means the dimension applies and permits nothing.
    """

    kind: Literal["none", "flag", "count", "labels"]
    flag: bool | None = None
    count: int | None = None
    labels: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in {"none", "flag", "count", "labels"}:
            raise _invalid()
        if self.kind == "flag":
            if type(self.flag) is not bool:
                raise _invalid()
        elif self.flag is not None:
            raise _invalid()
        if self.kind == "count":
            _nonnegative(self.count)
        elif self.count is not None:
            raise _invalid()
        if self.kind != "labels":
            if self.labels != ():
                raise _invalid()
            return
        labels = _sorted_text(self.labels, pattern=_PRIVACY_LABEL, maximum=MAX_PRIVACY_LABEL_BYTES)
        if len(labels) > MAX_PRIVACY_CHANGE_LABELS:
            raise _invalid()
        object.__setattr__(self, "labels", labels)

    @classmethod
    def absent(cls) -> PrivacyPolicyChangeValue:
        return cls("none")

    @classmethod
    def of_flag(cls, value: bool) -> PrivacyPolicyChangeValue:
        return cls("flag", flag=value)

    @classmethod
    def of_count(cls, value: int) -> PrivacyPolicyChangeValue:
        return cls("count", count=value)

    @classmethod
    def of_labels(cls, values: object) -> PrivacyPolicyChangeValue:
        return cls(
            "labels",
            labels=_sorted_text(values, pattern=_PRIVACY_LABEL, maximum=MAX_PRIVACY_LABEL_BYTES),
        )


@dataclass(frozen=True, slots=True)
class PrivacyPolicyChange:
    """One security-relevant ``before → after`` step between two privacy policies.

    ``widens`` is derived by the service from the same comparison that classifies a proposal,
    never supplied by a client, so a widening cannot describe itself as a tightening.
    """

    area: Literal["global", "review", "channel", "local_model", "agent_context", "human_control"]
    field: str
    subject: str | None
    before: PrivacyPolicyChangeValue
    after: PrivacyPolicyChangeValue
    widens: bool

    def __post_init__(self) -> None:
        if self.area not in PRIVACY_CHANGE_AREAS:
            raise _invalid()
        if type(self.field) is not str or self.field not in PRIVACY_CHANGE_FIELDS[self.area]:
            raise _invalid()
        if self.subject is not None:
            _text(self.subject, _PRIVACY_LABEL, maximum=MAX_PRIVACY_LABEL_BYTES)
        if self.area == "channel":
            if self.subject is None:
                raise _invalid()
        elif self.subject is not None:
            raise _invalid()
        if (
            type(self.before) is not PrivacyPolicyChangeValue
            or type(self.after) is not PrivacyPolicyChangeValue
        ):
            raise _invalid()
        if self.before == self.after:
            raise _invalid()
        if type(self.widens) is not bool:
            raise _invalid()

    @property
    def identity(self) -> tuple[str, str, str]:
        """The tuple a diff may name at most once."""

        return (self.area, self.field, self.subject or "")


# Presentation order, most consequential first. Whether anything may leave the machine at all
# outranks where it goes, which outranks whether a human is asked before each request, which
# outranks what is disclosed, which outranks how much and for how long. Every allowlisted
# (area, field) pair appears exactly once; the tests assert that, so a new dimension cannot be
# added to the vocabulary without being given a place in the human's reading order.
_CHANGE_IMPACT: Final[dict[tuple[str, str], int]] = {
    ("global", "network_egress"): 0,
    ("channel", "enabled"): 1,
    ("channel", "provider"): 2,
    # A second destination reads right after the first: it is the same question ("where does
    # it go") asked once more, and it outranks everything about how much goes.
    ("channel", "fallback_provider"): 3,
    ("local_model", "enabled"): 4,
    ("local_model", "binding"): 5,
    ("channel", "preview_required"): 6,
    # How conversations start and whether an agent's switch to AI-powered review waits for the
    # owner (ADR-049): the same question as per-request confirmation, asked per conversation.
    ("global", "conversation_review"): 7,
    ("global", "provider_data_use_evidence"): 8,
    # Whether possible-credential values are filtered out of what is disclosed: a disclosure
    # dimension, read before which categories and sensitivity classes may leave (issue #982).
    ("global", "credential_heuristic"): 9,
    # Which files outside the workspace may be read as task inputs (issue #1082): also what is
    # disclosed, read with the credential filter before categories and classes.
    ("global", "admitted_input_roots"): 10,
    ("channel", "data_classes"): 11,
    ("channel", "categories"): 12,
    ("channel", "purposes"): 13,
    ("global", "effective_scope"): 14,
    ("channel", "scope_ceiling"): 15,
    ("channel", "authorization_ttl_seconds"): 16,
    ("channel", "max_bytes"): 17,
    ("channel", "max_tokens"): 18,
    ("local_model", "data_classes"): 19,
    ("local_model", "categories"): 20,
    ("agent_context", "data_classes"): 21,
    ("agent_context", "categories"): 22,
    ("human_control", "data_classes"): 23,
    ("human_control", "categories"): 24,
    ("review", "include_exact_command_text"): 25,
    ("review", "include_finding_prose"): 26,
    ("review", "relevance"): 27,
    ("review", "excerpt_kinds"): 28,
    ("review", "sections"): 29,
    ("review", "max_excerpt_bytes"): 30,
    ("review", "max_total_excerpt_bytes"): 31,
    ("review", "max_excerpts"): 32,
    ("review", "max_change_observations"): 33,
    ("review", "max_assessments"): 34,
    ("review", "max_timeline_items"): 35,
    ("review", "max_omissions"): 36,
}


def privacy_change_order(change: PrivacyPolicyChange) -> tuple[int, int, str, str, str]:
    """Total deterministic sort key: widenings first, then impact, then the identity."""

    if type(change) is not PrivacyPolicyChange:
        raise _invalid()
    return (
        0 if change.widens else 1,
        _CHANGE_IMPACT[(change.area, change.field)],
        change.area,
        change.field,
        change.subject or "",
    )


def sort_privacy_changes(
    changes: tuple[PrivacyPolicyChange, ...] | list[PrivacyPolicyChange],
) -> tuple[PrivacyPolicyChange, ...]:
    return tuple(sorted(changes, key=privacy_change_order))


def validate_privacy_change_set(
    changes: tuple[PrivacyPolicyChange, ...], *, require_widening: bool = False
) -> None:
    """Reject a change set that is duplicated, oversized, misordered, or under-reported.

    ``require_widening`` is what closes the finding this type exists for: the trusted approval
    ceremony only ever runs for a widening, so a widening preview whose change set contains no
    widening is incomplete by construction and must never reach a human.
    """

    if type(changes) is not tuple or any(
        type(change) is not PrivacyPolicyChange for change in changes
    ):
        raise _invalid()
    if len(changes) > MAX_PRIVACY_CHANGES:
        raise _invalid()
    identities = [change.identity for change in changes]
    if len(set(identities)) != len(identities):
        raise _invalid()
    if sort_privacy_changes(changes) != changes:
        raise _invalid()
    if require_widening and not any(change.widens for change in changes):
        raise _invalid()


def _envelope_item_limit(item_id: str, category: DataCategory) -> int:
    """Per-item plaintext bound, widened only for the generated structural envelope.

    The exemption is keyed on both the reserved item id and the bounded-structural category, so a
    caller cannot widen the bound for prose by borrowing the id, nor by declaring the category on
    an item the builder did not generate.
    """

    if item_id == REVIEW_PACKET_ITEM_ID and category is DataCategory.BOUNDED_STRUCTURAL_METADATA:
        return MAX_EGRESS_ENVELOPE_BYTES
    return MAX_EGRESS_ITEM_BYTES


@dataclass(frozen=True, slots=True)
class CandidateContextItem:
    item_id: str
    category: DataCategory
    source_scope: AuthorizationScope
    origin_ref: str
    plaintext: bytes
    contributor_refs: tuple[str, ...] = ()
    # Trusted producer restriction, never caller authority. False keeps a source-side denial
    # inside the normal disclosure audit without loading the denied source plaintext.
    source_disclosure_permitted: bool = True
    # #1118 unit 1 (E2E-2): the owner-admitted outside root this item's bytes were read beneath.
    # Trusted producer binding kept in process only; egress refuses the item once the effective
    # policy no longer admits that root, however long ago the bytes were read.
    input_root: str | None = None

    def __post_init__(self) -> None:
        _text(self.item_id, _OPAQUE)
        _enum(self.category, DataCategory)
        if type(self.source_scope) is not AuthorizationScope:
            raise _invalid()
        if self.input_root is not None and not admitted_input_root_valid(self.input_root):
            raise _invalid()
        _origin_ref(self.origin_ref)
        if type(self.plaintext) is not bytes or len(self.plaintext) > _envelope_item_limit(
            self.item_id, self.category
        ):
            raise _invalid()
        object.__setattr__(self, "contributor_refs", _sorted_text(self.contributor_refs))
        if type(self.source_disclosure_permitted) is not bool:
            raise _invalid()


# Channels through which a cooperative writer publishes its own records. Every other channel is a
# service, host-observation, or import stamp and never yields self-authorship.
_SELF_AUTHORING_CHANNELS: Final = frozenset(
    {PublicationChannel.COOPERATIVE_MCP, PublicationChannel.LOCAL_CLI}
)
_IMPORT_CHANNELS: Final = frozenset(
    {PublicationChannel.CODEX_JSONL_IMPORT, PublicationChannel.HUMAN_IMPORT}
)
_MAX_ITEM_AUTHORSHIP: Final = 100
_MAX_ITEM_SOURCES: Final = 64
# At most 16 referencing deliverables of at most 8 named paths each (status-result 1.4.0). A
# receipt attributes each distinct name once, however many prose leaves spell it, under the same
# bound; a name past it is simply never attributed (it stays withheld).
_MAX_LEAF_AUTHORSHIP: Final = 128
MAX_RECEIPT_NAME_AUTHORSHIP: Final = _MAX_LEAF_AUTHORSHIP
_NAME_LEAF_POINTER: Final = re.compile(
    r"(?:/closure_readiness/undeclared_references/(?:0|[1-9][0-9]?)/paths/[0-7]"
    r"|/receipt_repository_names/(?:0|[1-9][0-9]*))",
    re.ASCII,
)


@dataclass(frozen=True, slots=True)
class SourceAuthorship:
    """Ledger-recorded authorship of one accepted event that contributes to a row.

    Every field is read from the accepted event envelope in the ledger, never from the request
    being projected. Writer chain, session and sequence are service-assigned. The publication
    channel is the ledger-recorded channel: a cooperative writer can record only
    ``cooperative_mcp`` or ``local_cli``, while import and observation channels are service-only.
    ``observation_authored`` is the observation coordinator authorship predicate, which a
    cooperative writer cannot assert for itself.
    """

    writer_id: str
    session_id: str
    ingestion_sequence: int
    publication_channel: PublicationChannel
    observation_authored: bool

    def __post_init__(self) -> None:
        validate_id(IdKind.WRITER, self.writer_id)
        validate_id(IdKind.SESSION, self.session_id)
        _positive(self.ingestion_sequence)
        _enum(self.publication_channel, PublicationChannel)
        if type(self.observation_authored) is not bool:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class ProjectionItemAuthorship:
    """The contributing ledger events of one projected row, read at the page's frozen frontier.

    ``item_pointer`` is the JSON pointer of the row inside the unprojected result body (for
    example ``/page/items/3``); a candidate leaf belongs to the row when its origin pointer is a
    child of it.
    """

    item_pointer: str
    sources: tuple[SourceAuthorship, ...]

    def __post_init__(self) -> None:
        _text(self.item_pointer, _POINTER, maximum=256)
        if (
            type(self.sources) is not tuple
            or not 1 <= len(self.sources) <= _MAX_ITEM_SOURCES
            or any(type(source) is not SourceAuthorship for source in self.sources)
        ):
            raise _invalid()


def authorship_provenance(
    sources: tuple[SourceAuthorship, ...],
    *,
    writer_id: str,
    session_id: str,
    frontier_sequence: int,
) -> DisclosureProvenance:
    """Apply the ``DisclosureProvenance`` rule to ledger facts for one requesting writer.

    A row is ``self_authored`` only when every contributing accepted event was written by the
    requesting ``writer_id`` in the requesting session, at or before the frozen frontier, through
    a cooperative publication channel, and without the observation coordinator's stamp. Any
    import-derived contribution makes the row ``imported`` even when the importing writer matches.
    Everything else is ``other_writer``. The result is recomputed for each request and frontier.
    """

    if not sources:
        raise _invalid()
    if any(source.publication_channel in _IMPORT_CHANNELS for source in sources):
        return DisclosureProvenance.IMPORTED
    if all(
        source.writer_id == writer_id
        and source.session_id == session_id
        and source.ingestion_sequence <= frontier_sequence
        and source.publication_channel in _SELF_AUTHORING_CHANNELS
        and not source.observation_authored
        for source in sources
    ):
        return DisclosureProvenance.SELF_AUTHORED
    return DisclosureProvenance.OTHER_WRITER


@dataclass(frozen=True, slots=True)
class ProjectionProvenanceContext:
    """Trusted identity and frozen ledger boundary for agent projection authorship.

    ``item_authorship`` carries the ledger authorship of the projected rows that a production
    resolver can attribute; it is read by the service from the same frozen frontier as the page
    and is never accepted from a caller. An absent row means ambiguous authorship.
    """

    session_id: str
    writer_id: str
    frontier: Frontier
    item_authorship: tuple[ProjectionItemAuthorship, ...] = ()
    # tb4n5 (ADR-035 amendment): exact-leaf authorship of the undeclared-reference names: the
    # ledger authorship of the publication that spelled each path, keyed by the status path leaf
    # or by the receipt's canonical name index (``/receipt_repository_names/<n>``). Service-derived
    # from the ledger, never from a caller, and only ever those two name families; the ordinary
    # authorship rule decides what it grants.
    leaf_authorship: tuple[ProjectionItemAuthorship, ...] = ()

    def __post_init__(self) -> None:
        validate_id(IdKind.SESSION, self.session_id)
        validate_id(IdKind.WRITER, self.writer_id)
        if type(self.frontier) is not Frontier:
            raise _invalid()
        if (
            type(self.item_authorship) is not tuple
            or len(self.item_authorship) > _MAX_ITEM_AUTHORSHIP
            or any(type(item) is not ProjectionItemAuthorship for item in self.item_authorship)
        ):
            raise _invalid()
        pointers = [item.item_pointer for item in self.item_authorship]
        if len(set(pointers)) != len(pointers):
            raise _invalid()
        if (
            type(self.leaf_authorship) is not tuple
            or len(self.leaf_authorship) > _MAX_LEAF_AUTHORSHIP
            or any(
                type(item) is not ProjectionItemAuthorship
                or _NAME_LEAF_POINTER.fullmatch(item.item_pointer) is None
                for item in self.leaf_authorship
            )
            or len({item.item_pointer for item in self.leaf_authorship})
            != len(self.leaf_authorship)
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True, repr=False)
class ProjectionAuditContext:
    """Trusted control binding and canonical source for one client projection."""

    rpc_id: str
    method: str
    service_instance_id: str
    service_generation: int
    original_request_id: str | None
    route_identity_digest: str | None
    control_request_canonical: bytes
    internal_result_canonical: bytes

    def __post_init__(self) -> None:
        validate_id(IdKind.CONTROL_RPC, self.rpc_id)
        _text(self.method, _IDENTITY)
        validate_id(IdKind.SERVICE_INSTANCE, self.service_instance_id)
        _positive(self.service_generation)
        if self.original_request_id is not None:
            validate_id(IdKind.REQUEST, self.original_request_id)
        if self.route_identity_digest is not None:
            validate_sha256_digest(self.route_identity_digest)
        for value in (self.control_request_canonical, self.internal_result_canonical):
            if type(value) is not bytes or not value or len(value) > MAX_EGRESS_CASE_BYTES:
                raise _invalid()
            try:
                if canonical_encode(strict_json_parse(value)) != value:
                    raise _invalid()
            except ValueError as exc:
                raise _invalid() from exc

    def __repr__(self) -> str:
        return "ProjectionAuditContext(<redacted>)"


@dataclass(frozen=True, slots=True)
class CandidateContext:
    request_id: str
    channel: EgressChannel | None
    local_sink: LocalDisclosureSink | None
    purpose: str
    scope: AuthorizationScope
    subject_digest: str | None
    provider_binding: ProviderBinding | None
    items: tuple[CandidateContextItem, ...]
    provenance_context: ProjectionProvenanceContext | None = None
    projection_audit_context: ProjectionAuditContext | None = None

    def __post_init__(self) -> None:
        validate_id(IdKind.REQUEST, self.request_id)
        if (self.channel is None) == (self.local_sink is None):
            raise _invalid()
        if self.channel is not None:
            _enum(self.channel, EgressChannel)
        if self.local_sink is not None:
            _enum(self.local_sink, LocalDisclosureSink)
        _text(self.purpose, _PURPOSE)
        if type(self.scope) is not AuthorizationScope:
            raise _invalid()
        if self.subject_digest is not None:
            validate_sha256_digest(self.subject_digest)
        if self.provider_binding is not None and type(self.provider_binding) is not ProviderBinding:
            raise _invalid()
        if type(self.items) is not tuple or any(
            type(item) is not CandidateContextItem for item in self.items
        ):
            raise _invalid()
        if len({item.item_id for item in self.items}) != len(self.items):
            raise _invalid()
        if (
            self.provenance_context is not None
            and self.local_sink is not LocalDisclosureSink.AGENT_CONTEXT
        ):
            raise _invalid()
        if (
            self.provenance_context is not None
            and type(self.provenance_context) is not ProjectionProvenanceContext
        ):
            raise _invalid()
        projection = self.purpose == "client_result_projection" and self.local_sink in {
            LocalDisclosureSink.AGENT_CONTEXT,
            LocalDisclosureSink.LOCAL_HUMAN_VIEW,
        }
        if (self.projection_audit_context is not None) != projection:
            raise _invalid()
        if self.projection_audit_context is not None:
            if type(self.projection_audit_context) is not ProjectionAuditContext:
                raise _invalid()
            needs_route = self.scope.kind in {
                AuthorizationScopeKind.TASK,
                AuthorizationScopeKind.REQUEST,
            }
            if (self.projection_audit_context.route_identity_digest is not None) != needs_route:
                raise _invalid()


@dataclass(frozen=True, slots=True)
class ClassifiedContextItem:
    candidate: CandidateContextItem
    data_class: DataClass
    forbidden_findings: tuple[ForbiddenDataKind, ...]
    scope_valid: bool
    classifier_ruleset_version: str
    provenance: DisclosureProvenance | None = None
    # Low-confidence secret-like assignments are withheld item-by-item by semantic egress. They
    # remain separate from ``forbidden_findings`` so a concrete credential still blocks the whole
    # case and so local receipts can explain the omission without retaining matched bytes.
    heuristic_findings: tuple[ForbiddenDataKind, ...] = ()

    def __post_init__(self) -> None:
        if type(self.candidate) is not CandidateContextItem:
            raise _invalid()
        _enum(self.data_class, DataClass)
        object.__setattr__(
            self, "forbidden_findings", _sorted_enums(self.forbidden_findings, ForbiddenDataKind)
        )
        object.__setattr__(
            self, "heuristic_findings", _sorted_enums(self.heuristic_findings, ForbiddenDataKind)
        )
        if set(self.forbidden_findings) & set(self.heuristic_findings):
            raise _invalid()
        if type(self.scope_valid) is not bool:
            raise _invalid()
        _text(self.classifier_ruleset_version, _VERSION)
        if self.provenance is not None:
            _enum(self.provenance, DisclosureProvenance)


@dataclass(frozen=True, slots=True)
class ClassifiedContext:
    candidate: CandidateContext
    items: tuple[ClassifiedContextItem, ...]
    # The owner policy's credential-heuristic setting this classification ran under (issue #982).
    # Minimization reads it from here, so the classifier and minimizer cannot disagree about it.
    credential_heuristic: CredentialHeuristic = CredentialHeuristic.ENFORCED

    def __post_init__(self) -> None:
        if type(self.candidate) is not CandidateContext or type(self.items) is not tuple:
            raise _invalid()
        _enum(self.credential_heuristic, CredentialHeuristic)
        if any(type(item) is not ClassifiedContextItem for item in self.items):
            raise _invalid()
        if tuple(item.candidate for item in self.items) != self.candidate.items:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class PrivacyDecision:
    approved_item_ids: tuple[str, ...]
    blocked_categories: tuple[DataCategory, ...]
    outcome: PrivacyOutcome
    reason: PrivacyReason | None
    # Issue #1230: items the policy would release that egress left out so the packet fits the
    # approved excerpt limits or the exchange bound. Never approved; the packet names them
    # ``not_selected`` (room), not withheld by a privacy rule.
    unselected_item_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "approved_item_ids", _sorted_text(self.approved_item_ids))
        object.__setattr__(
            self, "blocked_categories", _sorted_enums(self.blocked_categories, DataCategory)
        )
        object.__setattr__(self, "unselected_item_ids", _sorted_text(self.unselected_item_ids))
        if set(self.unselected_item_ids) & set(self.approved_item_ids):
            raise _invalid()
        if not outcome_reason_is_valid(self.outcome, self.reason):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class PreDispatchAuditDecision:
    privacy_proposal_id: str
    request_id: str
    channel: EgressChannel | None
    local_sink: LocalDisclosureSink | None
    purpose: str
    scope: AuthorizationScope
    policy_id: str
    policy_version: int
    policy_digest: str
    destination_digest: str | None
    categories: tuple[DataCategory, ...]
    candidate_count: int
    blocked_count: int
    forbidden_kind_counts: tuple[tuple[ForbiddenDataKind, int], ...]
    finished_at: datetime
    audit_subject_digest: str
    outcome: PrivacyOutcome
    reason: PrivacyReason

    def __post_init__(self) -> None:
        validate_id(IdKind.PRIVACY_PROPOSAL, self.privacy_proposal_id)
        validate_id(IdKind.REQUEST, self.request_id)
        if (self.channel is None) == (self.local_sink is None):
            raise _invalid()
        _text(self.purpose, _PURPOSE)
        if type(self.scope) is not AuthorizationScope:
            raise _invalid()
        validate_id(IdKind.PRIVACY_POLICY, self.policy_id)
        _positive(self.policy_version)
        validate_sha256_digest(self.policy_digest)
        if self.destination_digest is not None:
            validate_sha256_digest(self.destination_digest)
        object.__setattr__(self, "categories", _sorted_enums(self.categories, DataCategory))
        _nonnegative(self.candidate_count)
        _nonnegative(self.blocked_count)
        if type(self.forbidden_kind_counts) is not tuple:
            raise _invalid()
        expected = tuple(
            sorted(self.forbidden_kind_counts, key=lambda item: item[0].value.encode())
        )
        if self.forbidden_kind_counts != expected or len({kind for kind, _ in expected}) != len(
            expected
        ):
            raise _invalid()
        for kind, count in expected:
            _enum(kind, ForbiddenDataKind)
            _positive(count)
        _time(self.finished_at)
        validate_sha256_digest(self.audit_subject_digest)
        if self.outcome not in {
            PrivacyOutcome.BLOCKED_BY_POLICY,
            PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
            PrivacyOutcome.CLASSIFICATION_UNCERTAIN,
            PrivacyOutcome.CHANNEL_UNAVAILABLE,
        } or not outcome_reason_is_valid(self.outcome, self.reason):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class AgentProjectionAuditSubject:
    privacy_proposal_id: str
    projection_request_id: str
    rpc_id: str
    method: str
    service_instance_id: str
    service_generation: int
    original_request_id: str | None
    scope: AuthorizationScope
    task_id: str | None
    route_identity_digest: str | None
    policy_id: str
    policy_version: int
    policy_digest: str
    sink: LocalDisclosureSink
    provenance: tuple[DisclosureProvenance, ...]
    internal_result_commitment: str
    projection_commitment: str
    field_decisions: tuple[tuple[str, DataCategory, bool, str | None], ...]
    candidate_count: int
    approved_count: int
    omitted_count: int
    finished_at: datetime

    def __post_init__(self) -> None:
        validate_id(IdKind.PRIVACY_PROPOSAL, self.privacy_proposal_id)
        validate_id(IdKind.REQUEST, self.projection_request_id)
        validate_id(IdKind.CONTROL_RPC, self.rpc_id)
        _text(self.method, _IDENTITY)
        validate_id(IdKind.SERVICE_INSTANCE, self.service_instance_id)
        _positive(self.service_generation)
        if self.original_request_id is not None:
            validate_id(IdKind.REQUEST, self.original_request_id)
        if self.sink not in {
            LocalDisclosureSink.AGENT_CONTEXT,
            LocalDisclosureSink.LOCAL_HUMAN_VIEW,
        }:
            raise _invalid()
        needs_task = self.scope.kind in {
            AuthorizationScopeKind.TASK,
            AuthorizationScopeKind.REQUEST,
        }
        if (self.task_id is not None) != needs_task or (
            self.route_identity_digest is not None
        ) != needs_task:
            raise _invalid()
        if self.task_id is not None:
            validate_id(IdKind.TASK, self.task_id)
        if self.route_identity_digest is not None:
            validate_sha256_digest(self.route_identity_digest)
        validate_id(IdKind.PRIVACY_POLICY, self.policy_id)
        _positive(self.policy_version)
        validate_sha256_digest(self.policy_digest)
        object.__setattr__(self, "provenance", _sorted_enums(self.provenance, DisclosureProvenance))
        validate_commitment(self.internal_result_commitment)
        validate_commitment(self.projection_commitment)
        if type(self.field_decisions) is not tuple:
            raise _invalid()
        expected = tuple(sorted(self.field_decisions, key=lambda item: item[0].encode()))
        if expected != self.field_decisions:
            raise _invalid()
        for pointer, category, allowed, reason in expected:
            _text(pointer, _POINTER, maximum=256)
            _enum(category, DataCategory)
            if (
                type(allowed) is not bool
                or (allowed and reason is not None)
                or (not allowed and not reason)
            ):
                raise _invalid()
        _nonnegative(self.candidate_count)
        _nonnegative(self.approved_count)
        _nonnegative(self.omitted_count)
        if self.approved_count + self.omitted_count != self.candidate_count:
            raise _invalid()
        _time(self.finished_at)


@dataclass(frozen=True, slots=True)
class DisclosureProposal:
    privacy_proposal_id: str
    request_id: str
    task_id: str
    source_item_digests: tuple[str, ...]
    prepared_bytes: bytes
    approved_categories: tuple[DataCategory, ...]
    blocked_categories: tuple[DataCategory, ...]
    transformation_summary: tuple[tuple[str, int], ...]
    prepared_case_digest: str
    provider_binding: ProviderBinding | None
    local_sink: LocalDisclosureSink | None
    purpose: str
    scope: AuthorizationScope
    policy_version: int
    policy_digest: str
    max_bytes: int
    max_tokens: int
    expires_at: datetime
    proposal_commitment: str
    # Opaque case item ids omitted by the heuristic scanner. This is persisted with the exact
    # prepared proposal so a restart/replay can report the same coverage loss without reopening
    # or re-scanning the original plaintext.
    withheld_item_ids: tuple[str, ...] = ()
    # Scanner identity is persisted with the proposal so a resume receipt can state the exact
    # scanner that guarded the prepared case, rather than inventing a clean ``resume`` profile.
    # Old proposal rows did not persist scanner identity. ``unknown`` keeps that fact explicit;
    # ``legacy`` would misleadingly name a scanner registry that was never observed.
    scanner_registry_version: str = "unknown"
    scanner_profile_digest: str = "sha256:" + "0" * 64
    # The minimized case identities are retained separately from their content digests.  A digest
    # is evidence about bytes, not an opaque case-item identity, and substituting one for the
    # other during resume loses the exact replacement/withheld-item binding.
    included_item_ids: tuple[str, ...] = ()
    # Proposal admission is route-bound.  Missing identity is an unreadable legacy proposal, not
    # permission to resume it against whichever route happens to be active now.
    route_identity_digest: str | None = None
    # PL2-1 (issue #982): bounded item refs and line numbers of replaced or withheld
    # credential-like values, persisted with the proposal so an approved resume or a replay
    # reports them without reopening plaintext. Never values.
    redacted_values: tuple[SemanticRedactedValue, ...] = ()

    def __post_init__(self) -> None:
        try:
            validate_semantic_redacted_values(self.redacted_values)
        except ValueError as exc:
            raise _invalid() from exc
        validate_id(IdKind.PRIVACY_PROPOSAL, self.privacy_proposal_id)
        validate_id(IdKind.REQUEST, self.request_id)
        validate_id(IdKind.TASK, self.task_id)
        if (self.provider_binding is None) == (self.local_sink is None):
            raise _invalid()
        if (
            type(self.prepared_bytes) is not bytes
            or len(self.prepared_bytes) > MAX_EGRESS_CASE_BYTES
        ):
            raise _invalid()
        for digest in self.source_item_digests:
            validate_sha256_digest(digest)
        if tuple(sorted(set(self.source_item_digests), key=str.encode)) != self.source_item_digests:
            raise _invalid()
        object.__setattr__(
            self, "approved_categories", _sorted_enums(self.approved_categories, DataCategory)
        )
        object.__setattr__(
            self, "blocked_categories", _sorted_enums(self.blocked_categories, DataCategory)
        )
        validate_sha256_digest(self.prepared_case_digest)
        _text(self.purpose, _PURPOSE)
        _positive(self.policy_version)
        validate_sha256_digest(self.policy_digest)
        _nonnegative(self.max_bytes, maximum=MAX_EGRESS_CASE_BYTES)
        _nonnegative(self.max_tokens)
        _time(self.expires_at)
        validate_commitment(self.proposal_commitment)
        if type(self.withheld_item_ids) is not tuple or self.withheld_item_ids != tuple(
            sorted(set(self.withheld_item_ids), key=str.encode)
        ):
            raise _invalid()
        if len(self.withheld_item_ids) > MAX_WITHHELD_ITEM_IDS:
            raise _invalid()
        for item_id in self.withheld_item_ids:
            _text(item_id, _OPAQUE)
        _text(self.scanner_registry_version, _VERSION)
        validate_sha256_digest(self.scanner_profile_digest)
        if type(self.included_item_ids) is not tuple or self.included_item_ids != tuple(
            sorted(set(self.included_item_ids), key=str.encode)
        ):
            raise _invalid()
        if len(self.included_item_ids) > 4096:
            raise _invalid()
        for item_id in self.included_item_ids:
            _text(item_id, _OPAQUE)
        if self.route_identity_digest is not None:
            validate_sha256_digest(self.route_identity_digest)


type PrivacyAuditSubject = (
    PreDispatchAuditDecision | AgentProjectionAuditSubject | DisclosureProposal
)


@dataclass(frozen=True, slots=True)
class HumanPrivacyDecision:
    proposal_commitment: str
    approved: bool
    consent_source: ConsentSource
    decided_at: datetime
    expires_at: datetime | None
    accepted_diff_digest: str
    authority_commitment: str

    def __post_init__(self) -> None:
        validate_commitment(self.proposal_commitment)
        if type(self.approved) is not bool:
            raise _invalid()
        if self.consent_source not in {
            ConsentSource.SCOPED_LOCAL_HUMAN,
            ConsentSource.PER_REQUEST_LOCAL_HUMAN,
        }:
            raise _invalid()
        _time(self.decided_at)
        if self.expires_at is not None and _time(self.expires_at) <= self.decided_at:
            raise _invalid()
        validate_sha256_digest(self.accepted_diff_digest)
        validate_commitment(self.authority_commitment)


@dataclass(frozen=True, slots=True)
class EgressAuthorization:
    authorization_id: str
    privacy_proposal_id: str
    case_digest: str
    channel: EgressChannel
    provider_binding: ProviderBinding
    purpose: str
    scope: AuthorizationScope
    policy_version: int
    policy_digest: str
    max_bytes: int
    max_tokens: int
    consent_source: ConsentSource
    issued_at: datetime
    expires_at: datetime
    service_generation: int

    def __post_init__(self) -> None:
        validate_id(IdKind.EGRESS_AUTHORIZATION, self.authorization_id)
        validate_id(IdKind.PRIVACY_PROPOSAL, self.privacy_proposal_id)
        validate_sha256_digest(self.case_digest)
        _enum(self.channel, EgressChannel)
        if (
            type(self.provider_binding) is not ProviderBinding
            or self.provider_binding.transport != "external"
        ):
            raise _invalid()
        _text(self.purpose, _PURPOSE)
        _positive(self.policy_version)
        validate_sha256_digest(self.policy_digest)
        _nonnegative(self.max_bytes, maximum=MAX_EGRESS_CASE_BYTES)
        _nonnegative(self.max_tokens)
        _enum(self.consent_source, ConsentSource)
        _time(self.issued_at)
        if _time(self.expires_at) <= self.issued_at:
            raise _invalid()
        _positive(self.service_generation)


@dataclass(frozen=True, slots=True)
class ApprovedOutboundCase:
    case_id: str
    request_id: str
    payload: bytes
    media_type: str
    schema_id: str
    included_item_ids: tuple[str, ...]
    approved_categories: tuple[DataCategory, ...]
    blocked_categories: tuple[DataCategory, ...]
    byte_count: int
    token_count: int
    provider_binding: ProviderBinding
    purpose: str
    authorization_id: str
    policy_digest: str
    case_digest: str
    withheld_item_ids: tuple[str, ...] = ()
    redacted_span_count: int = 0
    # The owner policy's credential-heuristic setting the case was prepared under (issue #982);
    # the gateway's final rendered-body scan honours exactly this value.
    credential_heuristic: CredentialHeuristic = CredentialHeuristic.ENFORCED

    # #1118 unit 1 (E2E-2): the outside roots the included items were read beneath; the gateway
    # refuses consume unless its current registry still admits every one.
    input_roots: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_id(IdKind.OUTBOUND_CASE, self.case_id)
        validate_id(IdKind.REQUEST, self.request_id)
        if type(self.payload) is not bytes or len(self.payload) > MAX_EGRESS_CASE_BYTES:
            raise _invalid()
        _text(self.media_type, re.compile(r"^[a-z][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*$", re.ASCII))
        _text(self.schema_id, _OPAQUE)
        object.__setattr__(self, "included_item_ids", _sorted_text(self.included_item_ids))
        object.__setattr__(
            self, "approved_categories", _sorted_enums(self.approved_categories, DataCategory)
        )
        object.__setattr__(
            self, "blocked_categories", _sorted_enums(self.blocked_categories, DataCategory)
        )
        if _nonnegative(self.byte_count, maximum=MAX_EGRESS_CASE_BYTES) != len(self.payload):
            raise _invalid()
        _nonnegative(self.token_count)
        if (
            type(self.provider_binding) is not ProviderBinding
            or self.provider_binding.transport != "external"
        ):
            raise _invalid()
        _text(self.purpose, _PURPOSE)
        validate_id(IdKind.EGRESS_AUTHORIZATION, self.authorization_id)
        validate_sha256_digest(self.policy_digest)
        validate_sha256_digest(self.case_digest)
        object.__setattr__(self, "withheld_item_ids", _sorted_text(self.withheld_item_ids))
        if len(self.withheld_item_ids) > MAX_WITHHELD_ITEM_IDS:
            raise _invalid()
        _nonnegative(self.redacted_span_count)
        _enum(self.credential_heuristic, CredentialHeuristic)
        if validate_admitted_input_roots(self.input_roots) != self.input_roots:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class ApprovedLocalDisclosureCase:
    case_id: str
    request_id: str
    privacy_proposal_id: str
    payload: bytes
    media_type: str
    included_item_ids: tuple[str, ...]
    approved_categories: tuple[DataCategory, ...]
    blocked_categories: tuple[DataCategory, ...]
    byte_count: int
    token_count: int
    sink: LocalDisclosureSink
    binding: ProviderBinding | None
    purpose: str
    policy_digest: str
    case_digest: str
    withheld_item_ids: tuple[str, ...] = ()
    redacted_span_count: int = 0
    # The owner policy's credential-heuristic setting the case was prepared under (issue #982);
    # the gateway's final rendered-body scan honours exactly this value.
    credential_heuristic: CredentialHeuristic = CredentialHeuristic.ENFORCED

    # #1118 unit 1 (E2E-2): the outside roots the included items were read beneath; the gateway
    # refuses consume unless its current registry still admits every one.
    input_roots: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_id(IdKind.OUTBOUND_CASE, self.case_id)
        validate_id(IdKind.REQUEST, self.request_id)
        validate_id(IdKind.PRIVACY_PROPOSAL, self.privacy_proposal_id)
        if type(self.payload) is not bytes or len(self.payload) > MAX_EGRESS_CASE_BYTES:
            raise _invalid()
        _text(self.media_type, re.compile(r"^[a-z][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*$", re.ASCII))
        object.__setattr__(self, "included_item_ids", _sorted_text(self.included_item_ids))
        object.__setattr__(
            self, "approved_categories", _sorted_enums(self.approved_categories, DataCategory)
        )
        object.__setattr__(
            self, "blocked_categories", _sorted_enums(self.blocked_categories, DataCategory)
        )
        if self.byte_count != len(self.payload):
            raise _invalid()
        _nonnegative(self.token_count)
        _enum(self.sink, LocalDisclosureSink)
        if self.sink is LocalDisclosureSink.LOCAL_MODEL:
            if self.binding is None or self.binding.transport != "local_af_unix":
                raise _invalid()
        elif self.binding is not None:
            raise _invalid()
        _text(self.purpose, _PURPOSE)
        validate_sha256_digest(self.policy_digest)
        validate_sha256_digest(self.case_digest)
        object.__setattr__(self, "withheld_item_ids", _sorted_text(self.withheld_item_ids))
        if len(self.withheld_item_ids) > MAX_WITHHELD_ITEM_IDS:
            raise _invalid()
        _nonnegative(self.redacted_span_count)
        _enum(self.credential_heuristic, CredentialHeuristic)
        if validate_admitted_input_roots(self.input_roots) != self.input_roots:
            raise _invalid()


type ApprovedProviderCase = ApprovedOutboundCase | ApprovedLocalDisclosureCase


@dataclass(frozen=True, slots=True)
class RequestCommitment:
    algorithm: Literal["hmac-sha256/yoetz-privacy-egress-request-v1"]
    commitment: str

    def __post_init__(self) -> None:
        if self.algorithm != PRIVACY_REQUEST_COMMITMENT_ALGORITHM:
            raise _invalid()
        validate_commitment(self.commitment)


@dataclass(frozen=True, slots=True)
class NonLlmDestination:
    kind: EgressChannel
    profile_id: str
    profile_version: str

    def __post_init__(self) -> None:
        if self.kind not in {
            EgressChannel.CAPABILITY_TESTING,
            EgressChannel.CRASH_DIAGNOSTICS,
            EgressChannel.PRODUCT_TELEMETRY,
            EgressChannel.UPDATE_CHECKS,
        }:
            raise _invalid()
        _text(self.profile_id, _OPAQUE)
        _text(self.profile_version, _OPAQUE)


@dataclass(frozen=True, slots=True)
class ReceiptPolicyBinding:
    policy_id: str
    version: int
    policy_digest: str
    authorization_scope_digest: str

    def __post_init__(self) -> None:
        validate_id(IdKind.PRIVACY_POLICY, self.policy_id)
        _positive(self.version)
        validate_sha256_digest(self.policy_digest)
        validate_sha256_digest(self.authorization_scope_digest)


@dataclass(frozen=True, slots=True)
class ReceiptCounts:
    candidate_items: int
    included_items: int
    removed_items: int
    approved_items: int
    blocked_items: int
    candidate_bytes: int
    final_bytes: int
    estimated_input_tokens: int | None = None
    request_body_bytes: int | None = None

    def __post_init__(self) -> None:
        for value in (
            self.candidate_items,
            self.included_items,
            self.removed_items,
            self.approved_items,
            self.blocked_items,
            self.candidate_bytes,
        ):
            _nonnegative(value)
        _nonnegative(self.final_bytes, maximum=MAX_RECEIPT_FINAL_BYTES)
        if self.estimated_input_tokens is not None:
            _nonnegative(self.estimated_input_tokens)
        if self.request_body_bytes is not None:
            _nonnegative(self.request_body_bytes)


@dataclass(frozen=True, slots=True)
class ReceiptTransformations:
    minimized_items: int
    redacted_spans: int
    blocked_items: int

    def __post_init__(self) -> None:
        _nonnegative(self.minimized_items)
        _nonnegative(self.redacted_spans)
        _nonnegative(self.blocked_items)


# The approved bound a size refusal exceeded (#1129), with the unit it counts in. The pairs are the
# ones egress measures: the whole rendered disclosure in bytes or estimated model tokens, one
# excerpt's bytes, the excerpt count, or all excerpts' bytes.
RECEIPT_CAPACITY_SCOPE_UNITS: Final = frozenset(
    {
        ("disclosure", "bytes"),
        ("disclosure", "tokens"),
        ("excerpt", "bytes"),
        ("excerpt", "excerpts"),
        ("excerpt_total", "bytes"),
    }
)


@dataclass(frozen=True, slots=True)
class ReceiptCapacity:
    """Why a size refusal was refused: the bound, its unit, and the bounded sizes (#1129).

    A capacity refusal keeps ``blocked_by_policy`` / ``policy_denied`` as its outcome and reason
    (the durable reason vocabulary is unchanged); this typed object says the refusal was for size,
    not for a policy rule, and carries only integers, never content.
    """

    scope: Literal["disclosure", "excerpt", "excerpt_total"]
    unit: Literal["bytes", "tokens", "excerpts"]
    attempted: int
    limit: int

    def __post_init__(self) -> None:
        if (self.scope, self.unit) not in RECEIPT_CAPACITY_SCOPE_UNITS:
            raise _invalid()
        _nonnegative(self.attempted)
        _nonnegative(self.limit)
        if not self.limit < self.attempted:
            raise _invalid()


class ReceiptSecretScanStage(str, Enum):  # noqa: UP042 - durable receipt vocabulary
    CANDIDATE = "candidate"
    PREPARED_CASE = "prepared_case"
    RENDERED_BODY = "rendered_body"
    NOT_RUN = "not_run"
    # Compatibility marker for pre-stage receipts.  Older rows did not say whether a zero-match
    # result came from a prepared scan or from a pre-dispatch refusal; readers preserve that
    # uncertainty instead of presenting it as a clean scan.
    LEGACY_UNKNOWN = "legacy_unknown"


@dataclass(frozen=True, slots=True)
class ReceiptSecretScan:
    registry_version: str
    scanner_profile_digest: str
    match_count: int
    passed: bool
    stage: ReceiptSecretScanStage = ReceiptSecretScanStage.PREPARED_CASE
    not_run_reason: PrivacyReason | None = None
    # ``disabled`` records that the owner policy in force had the low-confidence credential
    # heuristic turned off, so only high-confidence detectors ran (issue #982). Encoded only when
    # disabled; every receipt written before the field existed keeps its exact bytes.
    credential_heuristic: CredentialHeuristic = CredentialHeuristic.ENFORCED

    def __post_init__(self) -> None:
        _text(self.registry_version, _VERSION)
        _enum(self.credential_heuristic, CredentialHeuristic)
        validate_sha256_digest(self.scanner_profile_digest)
        _nonnegative(self.match_count)
        if type(self.passed) is not bool:
            raise _invalid()
        _enum(self.stage, ReceiptSecretScanStage)
        if self.stage is ReceiptSecretScanStage.NOT_RUN:
            if self.match_count != 0 or self.passed or self.not_run_reason is None:
                raise _invalid()
        elif self.stage is ReceiptSecretScanStage.LEGACY_UNKNOWN:
            # Pre-stage receipts carried only ``match_count`` and ``passed``.  Keep their
            # uncertainty for every historical combination, including blocked/unrun rows that
            # stored ``passed=false`` with ``match_count=0``; a reader must not reinterpret that
            # shape as a prepared clean scan.  ``not_run_reason`` is a field introduced with the
            # explicit NOT_RUN stage.
            if self.not_run_reason is not None:
                raise _invalid()
        elif self.not_run_reason is not None or self.passed is not (self.match_count == 0):
            raise _invalid()
        if self.not_run_reason is not None:
            _enum(self.not_run_reason, PrivacyReason)


@dataclass(frozen=True, slots=True)
class EgressReceipt:
    # ``1.0.0`` is retained for durable rows written before the additive receipt extension;
    # newly written receipts use ``1.1.0`` while the active control contract accepts both.
    schema_version: Literal["1.0.0", "1.1.0"]
    receipt_id: str
    request_id: str
    privacy_proposal_id: str
    channel: EgressChannel
    outcome: PrivacyOutcome
    finished_at: datetime
    scope: AuthorizationScope
    purpose: str
    destination: ProviderBinding | NonLlmDestination
    policy: ReceiptPolicyBinding
    consent_source: ConsentSource
    approved_categories: tuple[DataCategory, ...]
    blocked_categories: tuple[DataCategory, ...]
    counts: ReceiptCounts
    transformations: ReceiptTransformations
    secret_scan: ReceiptSecretScan
    safe_failure_reason: PrivacyReason | None
    audit_store_version: Literal[1]
    authorization_id: str | None = None
    dispatch_id: str | None = None
    dispatch_started_at: datetime | None = None
    request_commitment: RequestCommitment | None = None
    withheld_item_ids: tuple[str, ...] = ()
    withheld_item_reason: Literal["never_send_heuristic"] | None = None
    # The closed operation that asked for this disclosure (tb4n2 N-5); 1.1.0 only, optional so
    # every receipt written before it keeps its exact bytes.
    origin_operation: EgressOriginOperation | None = None
    # #1129: a size refusal's typed capacity reason; 1.1.0 only, and only on a pre-dispatch
    # ``blocked_by_policy`` / ``policy_denied`` refusal. Absent on every other receipt, so every
    # receipt written before it keeps its exact bytes.
    capacity_exceeded: ReceiptCapacity | None = None

    def __post_init__(self) -> None:
        if type(self.schema_version) is not str or self.schema_version not in {"1.0.0", "1.1.0"}:
            raise _invalid()
        if self.origin_operation is not None:
            _enum(self.origin_operation, EgressOriginOperation)
            if self.schema_version == "1.0.0":
                raise _invalid()
        if self.capacity_exceeded is not None and (
            type(self.capacity_exceeded) is not ReceiptCapacity
            or self.schema_version == "1.0.0"
            or self.outcome is not PrivacyOutcome.BLOCKED_BY_POLICY
            or self.safe_failure_reason is not PrivacyReason.POLICY_DENIED
        ):
            raise _invalid()
        validate_id(IdKind.EGRESS_RECEIPT, self.receipt_id)
        validate_id(IdKind.REQUEST, self.request_id)
        validate_id(IdKind.PRIVACY_PROPOSAL, self.privacy_proposal_id)
        _enum(self.channel, EgressChannel)
        _enum(self.outcome, PrivacyOutcome)
        _time(self.finished_at)
        if type(self.scope) is not AuthorizationScope:
            raise _invalid()
        _text(self.purpose, _PURPOSE)
        if self.channel is EgressChannel.LLM_INFERENCE:
            if (
                type(self.destination) is not ProviderBinding
                or self.destination.transport != "external"
            ):
                raise _invalid()
        elif (
            type(self.destination) is not NonLlmDestination
            or self.destination.kind is not self.channel
        ):
            raise _invalid()
        if type(self.policy) is not ReceiptPolicyBinding:
            raise _invalid()
        _enum(self.consent_source, ConsentSource)
        object.__setattr__(
            self, "approved_categories", _sorted_enums(self.approved_categories, DataCategory)
        )
        object.__setattr__(
            self, "blocked_categories", _sorted_enums(self.blocked_categories, DataCategory)
        )
        if (
            type(self.counts) is not ReceiptCounts
            or type(self.transformations) is not ReceiptTransformations
            or type(self.secret_scan) is not ReceiptSecretScan
            or not outcome_reason_is_valid(self.outcome, self.safe_failure_reason)
        ):
            raise _invalid()
        attempted = self.dispatch_id is not None
        if self.authorization_id is not None:
            validate_id(IdKind.EGRESS_AUTHORIZATION, self.authorization_id)
        if attempted:
            if (
                self.authorization_id is None
                or self.dispatch_started_at is None
                or self.request_commitment is None
                or self.counts.request_body_bytes is None
            ):
                raise _invalid()
            validate_id(IdKind.EGRESS_DISPATCH, self.dispatch_id)
            if _time(self.dispatch_started_at) > self.finished_at:
                raise _invalid()
            if type(self.request_commitment) is not RequestCommitment:
                raise _invalid()
        elif any(
            value is not None
            for value in (
                self.dispatch_started_at,
                self.request_commitment,
                self.counts.request_body_bytes,
            )
        ):
            raise _invalid()
        if self.outcome in {
            PrivacyOutcome.BLOCKED_BY_POLICY,
            PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
            PrivacyOutcome.CLASSIFICATION_UNCERTAIN,
            PrivacyOutcome.HUMAN_DENIED,
            PrivacyOutcome.CHANNEL_UNAVAILABLE,
        } and (attempted or self.authorization_id is not None):
            raise _invalid()
        if self.outcome is PrivacyOutcome.COMPLETED and not attempted:
            raise _invalid()
        if (
            self.outcome
            in {
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
                PrivacyOutcome.CLASSIFICATION_UNCERTAIN,
                PrivacyOutcome.HUMAN_DENIED,
                PrivacyOutcome.CHANNEL_UNAVAILABLE,
            }
            and self.consent_source is not ConsentSource.NONE
        ):
            raise _invalid()
        if (
            type(self.audit_store_version) is not int
            or self.audit_store_version != AUDIT_STORE_VERSION
        ):
            raise _invalid()
        if (
            type(self.withheld_item_ids) is not tuple
            or len(self.withheld_item_ids) > MAX_WITHHELD_ITEM_IDS
            or self.withheld_item_ids != tuple(sorted(set(self.withheld_item_ids), key=str.encode))
        ):
            raise _invalid()
        for item_id in self.withheld_item_ids:
            _text(item_id, _OPAQUE)
        if self.withheld_item_ids:
            if self.withheld_item_reason is None:
                object.__setattr__(self, "withheld_item_reason", "never_send_heuristic")
            elif self.withheld_item_reason != "never_send_heuristic":
                raise _invalid()
        elif self.withheld_item_reason is not None:
            raise _invalid()
        if self.schema_version == "1.0.0" and (
            self.withheld_item_ids
            or (
                type(self.secret_scan) is ReceiptSecretScan
                and self.secret_scan.credential_heuristic is not CredentialHeuristic.ENFORCED
            )
            # The released 1.0 vocabulary stops at 262,144 final bytes (#1118 widened only 1.1).
            or (
                type(self.counts) is ReceiptCounts
                and self.counts.final_bytes > MAX_RECEIPT_FINAL_BYTES_1_0
            )
        ):
            # The released 1.0 wire contract has no safe place for omission identities or the
            # credential-heuristic opt-out.  Do not let a caller construct a value that a legacy
            # encoder would silently truncate.
            raise _invalid()


@dataclass(frozen=True, slots=True)
class LocalDisclosureReceipt:
    schema_version: Literal["1.0.0", "1.1.0"]
    receipt_id: str
    request_id: str
    privacy_proposal_id: str
    sink: LocalDisclosureSink
    outcome: PrivacyOutcome
    finished_at: datetime
    scope: AuthorizationScope
    purpose: str
    policy: ReceiptPolicyBinding
    consent_source: ConsentSource
    approved_categories: tuple[DataCategory, ...]
    blocked_categories: tuple[DataCategory, ...]
    counts: ReceiptCounts
    transformations: ReceiptTransformations
    secret_scan: ReceiptSecretScan
    safe_failure_reason: PrivacyReason | None
    audit_store_version: Literal[1]
    withheld_item_ids: tuple[str, ...] = ()
    withheld_item_reason: Literal["never_send_heuristic"] | None = None

    def __post_init__(self) -> None:
        if type(self.schema_version) is not str or self.schema_version not in {"1.0.0", "1.1.0"}:
            raise _invalid()
        validate_id(IdKind.EGRESS_RECEIPT, self.receipt_id)
        validate_id(IdKind.REQUEST, self.request_id)
        validate_id(IdKind.PRIVACY_PROPOSAL, self.privacy_proposal_id)
        _enum(self.sink, LocalDisclosureSink)
        _enum(self.outcome, PrivacyOutcome)
        _time(self.finished_at)
        if (
            type(self.scope) is not AuthorizationScope
            or type(self.policy) is not ReceiptPolicyBinding
        ):
            raise _invalid()
        if (
            type(self.withheld_item_ids) is not tuple
            or len(self.withheld_item_ids) > MAX_WITHHELD_ITEM_IDS
            or self.withheld_item_ids != tuple(sorted(set(self.withheld_item_ids), key=str.encode))
        ):
            raise _invalid()
        for item_id in self.withheld_item_ids:
            _text(item_id, _OPAQUE)
        if self.withheld_item_ids:
            if self.withheld_item_reason is None:
                object.__setattr__(self, "withheld_item_reason", "never_send_heuristic")
            elif self.withheld_item_reason != "never_send_heuristic":
                raise _invalid()
        elif self.withheld_item_reason is not None:
            raise _invalid()
        if self.schema_version == "1.0.0" and (
            self.withheld_item_ids
            or (
                type(self.secret_scan) is ReceiptSecretScan
                and self.secret_scan.credential_heuristic is not CredentialHeuristic.ENFORCED
            )
            # The released 1.0 vocabulary stops at 262,144 final bytes (#1118 widened only 1.1).
            or (
                type(self.counts) is ReceiptCounts
                and self.counts.final_bytes > MAX_RECEIPT_FINAL_BYTES_1_0
            )
        ):
            raise _invalid()
        _text(self.purpose, _PURPOSE)
        _enum(self.consent_source, ConsentSource)
        object.__setattr__(
            self, "approved_categories", _sorted_enums(self.approved_categories, DataCategory)
        )
        object.__setattr__(
            self, "blocked_categories", _sorted_enums(self.blocked_categories, DataCategory)
        )
        if (
            type(self.counts) is not ReceiptCounts
            or self.counts.request_body_bytes is not None
            or type(self.transformations) is not ReceiptTransformations
            or type(self.secret_scan) is not ReceiptSecretScan
            or not outcome_reason_is_valid(self.outcome, self.safe_failure_reason)
            or type(self.audit_store_version) is not int
            or self.audit_store_version != 1
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class ApprovedLocalItem:
    json_pointer: str
    category: DataCategory
    bounded_bytes: bytes

    def __post_init__(self) -> None:
        _text(self.json_pointer, _POINTER, maximum=256)
        _enum(self.category, DataCategory)
        if type(self.bounded_bytes) is not bytes or len(self.bounded_bytes) > MAX_EGRESS_ITEM_BYTES:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class LocalDisclosureOmission:
    json_pointer: str
    category: DataCategory
    reason: Literal["local_disclosure_not_authorized", "never_send_redacted"]

    def __post_init__(self) -> None:
        _text(self.json_pointer, _POINTER, maximum=256)
        _enum(self.category, DataCategory)
        if self.reason not in {"local_disclosure_not_authorized", "never_send_redacted"}:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class LocalDisclosureApproved:
    privacy_proposal_id: str
    request_id: str
    sink: LocalDisclosureSink
    purpose: str
    scope: AuthorizationScope
    policy_digest: str
    case_or_projection_commitment: str
    approved_items: tuple[ApprovedLocalItem, ...]
    omissions: tuple[LocalDisclosureOmission, ...]
    receipt: LocalDisclosureReceipt

    def __post_init__(self) -> None:
        _validate_local_disclosure_result(
            privacy_proposal_id=self.privacy_proposal_id,
            request_id=self.request_id,
            sink=self.sink,
            purpose=self.purpose,
            scope=self.scope,
            policy_digest=self.policy_digest,
            case_or_projection_commitment=self.case_or_projection_commitment,
            omissions=self.omissions,
            receipt=self.receipt,
        )
        if type(self.approved_items) is not tuple or any(
            type(item) is not ApprovedLocalItem for item in self.approved_items
        ):
            raise _invalid()
        expected = tuple(sorted(self.approved_items, key=lambda item: item.json_pointer.encode()))
        if self.approved_items != expected or len({item.json_pointer for item in expected}) != len(
            expected
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class LocalDisclosureBlocked:
    privacy_proposal_id: str
    request_id: str
    sink: LocalDisclosureSink
    purpose: str
    scope: AuthorizationScope
    policy_digest: str
    case_or_projection_commitment: str
    omissions: tuple[LocalDisclosureOmission, ...]
    receipt: LocalDisclosureReceipt

    def __post_init__(self) -> None:
        _validate_local_disclosure_result(
            privacy_proposal_id=self.privacy_proposal_id,
            request_id=self.request_id,
            sink=self.sink,
            purpose=self.purpose,
            scope=self.scope,
            policy_digest=self.policy_digest,
            case_or_projection_commitment=self.case_or_projection_commitment,
            omissions=self.omissions,
            receipt=self.receipt,
        )
        if not self.omissions:
            raise _invalid()


@dataclass(frozen=True, slots=True)
class LocalDisclosureUnavailable:
    request_id: str
    sink: LocalDisclosureSink
    reason: Literal["audit_failed"] = "audit_failed"

    def __post_init__(self) -> None:
        validate_id(IdKind.REQUEST, self.request_id)
        _enum(self.sink, LocalDisclosureSink)
        if self.reason != "audit_failed":
            raise _invalid()


def _validate_local_disclosure_result(
    *,
    privacy_proposal_id: str,
    request_id: str,
    sink: LocalDisclosureSink,
    purpose: str,
    scope: AuthorizationScope,
    policy_digest: str,
    case_or_projection_commitment: str,
    omissions: tuple[LocalDisclosureOmission, ...],
    receipt: LocalDisclosureReceipt,
) -> None:
    validate_id(IdKind.PRIVACY_PROPOSAL, privacy_proposal_id)
    validate_id(IdKind.REQUEST, request_id)
    _enum(sink, LocalDisclosureSink)
    _text(purpose, _PURPOSE)
    if type(scope) is not AuthorizationScope:
        raise _invalid()
    validate_sha256_digest(policy_digest)
    if case_or_projection_commitment.startswith("hmac-sha256:"):
        validate_commitment(case_or_projection_commitment)
    else:
        validate_sha256_digest(case_or_projection_commitment)
    if type(omissions) is not tuple or any(
        type(omission) is not LocalDisclosureOmission for omission in omissions
    ):
        raise _invalid()
    expected = tuple(sorted(omissions, key=lambda item: item.json_pointer.encode()))
    if omissions != expected or len({item.json_pointer for item in expected}) != len(expected):
        raise _invalid()
    if (
        type(receipt) is not LocalDisclosureReceipt
        or receipt.privacy_proposal_id != privacy_proposal_id
        or receipt.request_id != request_id
        or receipt.sink is not sink
        or receipt.purpose != purpose
        or receipt.scope != scope
        or receipt.policy.policy_digest != policy_digest
    ):
        raise _invalid()
