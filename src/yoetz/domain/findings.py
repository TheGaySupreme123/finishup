"""Canonical finding values, finalized AI-powered review provenance, and ranking inputs."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Final, Literal, cast

from yoetz.domain.values import (
    ClaimId,
    EventId,
    FindingId,
    Frontier,
    JsonObject,
    JsonValue,
    ObligationId,
    claim_id,
    event_id,
    finding_id,
    frontier_from_json,
    obligation_id,
    parse_wire_sequence,
    render_wire_sequence,
    validate_commitment,
    validate_sha256_digest,
)
from yoetz.protocol.canonical import JsonValue as CanonicalJsonValue
from yoetz.protocol.canonical import ensure_canonical_set, ensure_canonical_value
from yoetz.protocol.coverage import (
    ARTIFACT_OBSERVATION_ORDER,
    AUTHORSHIP_ASSURANCE_ORDER,
    EVIDENCE_IMMUTABILITY_ORDER,
    LEDGER_FRESHNESS_ORDER,
    CheckType,
    Coverage,
    coverage_from_json,
    coverage_to_json,
)
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.ids import IdKind, validate_id
from yoetz.protocol.models import (
    MAX_REVIEW_TEXT_BYTES,
    SemanticReason,
    SemanticStatus,
    validate_semantic_outcome,
)
from yoetz.protocol.policy_packs import (
    COORDINATION_POLICY_ID,
    CURRENT_POLICY_VERSIONS,
    RESEARCH_EVIDENCE_POLICY_ID,
    WORK_INTEGRITY_POLICY_ID,
    is_recorded_policy_identity,
)

__all__ = [
    "EXTERNAL_SEMANTIC_FINDING_KINDS",
    "FALLBACK_ORIGIN_REASONS",
    "FINDING_KIND_TRAITS",
    "MAX_RECORDED_VERDICTS",
    "MAX_RELATED_FINDING_IDS",
    "PRIOR_FINDING_VERDICTS",
    "REVIEWER_NEXT_STEPS",
    "CandidateFinding",
    "CheckVerdict",
    "CostFields",
    "DeterministicFinding",
    "Finding",
    "FindingChallenge",
    "FindingKind",
    "FindingOrigin",
    "PriorFindingVerdictRecord",
    "RankedFindings",
    "ResponseDisposition",
    "RESPONSE_V1_1_DISPOSITIONS",
    "RUNTIME_FAILURE_STAGES",
    "RuntimeAttemptEvidence",
    "SELF_VERIFIED_GUIDANCE",
    "TERMINAL_RESPONSE_DISPOSITIONS",
    "RuntimeTokenUsage",
    "SamplingParams",
    "SemanticDispatchKind",
    "SemanticFailureClass",
    "SemanticFallbackOrigin",
    "SemanticFinding",
    "SemanticProvenance",
    "TokenUsage",
    "WaiverScope",
    "finding_event_from_json",
    "finding_event_to_json",
    "finding_from_json",
    "finding_has_dialogue_fields",
    "finding_policy_identity",
    "finding_to_json",
    "rank_key",
    "semantic_fallback_origin_to_json",
    "semantic_provenance_from_json",
    "semantic_provenance_to_json",
]

_MAX_SAFE_INTEGER: Final = 2**53 - 1
_MAX_FINDING_TEXT_LENGTH: Final = 8_192
_MAX_SUBJECT_REFS: Final = 64

_IDENTITY_PATTERN: Final = re.compile(r"^[a-z0-9][a-z0-9._-]*$", re.ASCII)
_MODEL_IDENTITY_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$", re.ASCII)
_VERSION_IDENTITY_PATTERN: Final = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]*$", re.ASCII)
_PROVIDER_REQUEST_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$", re.ASCII)
_RFC3339_UTC_SECONDS_PATTERN: Final = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", re.ASCII
)
_CURRENCY_PATTERN: Final = re.compile(r"^[A-Z]{3}$", re.ASCII)
_FIXED_DECIMAL_PATTERN: Final = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?$", re.ASCII)
_SEMANTIC_VERSION_PATTERN: Final = re.compile(
    r"^(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$",
    re.ASCII,
)


class FindingKind(str, Enum):  # noqa: UP042 - exact wire enum base
    ACTION_WITHOUT_RESULT = "action_without_result"
    CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE = "claim_without_admissible_evidence"
    COORDINATION_OVERLAP = "coordination_overlap"
    COMPLETION_WITH_OPEN_OBLIGATIONS = "completion_with_open_obligations"
    CONTRADICTORY_CLAIMS_UNRESOLVED = "contradictory_claims_unresolved"
    DIFF_DOES_NOT_MATCH_ACCOUNT = "diff_does_not_match_account"
    EVIDENCE_DOES_NOT_SUPPORT_CLAIM = "evidence_does_not_support_claim"
    FAILED_WORK_OMITTED = "failed_work_omitted"
    LEDGER_STALE_OR_INCOMPLETE = "ledger_stale_or_incomplete"
    MATERIAL_LIMITATION_OMITTED = "material_limitation_omitted"
    QUESTIONABLE_FINDING_REJECTION = "questionable_finding_rejection"
    REQUESTED_ITEM_NEVER_ATTEMPTED = "requested_item_never_attempted"
    RESULT_WITHOUT_ACTION = "result_without_action"
    STALE_EVIDENCE_FOR_CHANGED_STATE = "stale_evidence_for_changed_state"
    WEAK_OR_STALE_RESPONSE = "weak_or_stale_response"
    # AI-powered review findings introduced by the verifying-reviewer contract (issue #906).
    # These are deliberately additive: old ledgers and deterministic policy packs retain their
    # historical kinds, while a provider can name a concrete source defect or a requirement the
    # submitted change failed to satisfy.
    CODE_DEFECT = "code_defect"
    TASK_REQUIREMENT_UNMET = "task_requirement_unmet"


# D7 keeps project coordination local: coordination findings are produced from the admitted
# coordination projection and are never included in an external semantic case. The provider
# judgment 1.0 wire therefore retains this explicit historical allowlist; a future provider
# contract must opt in to a new finding kind through a versioned wire change.
EXTERNAL_SEMANTIC_FINDING_KINDS: Final[tuple[FindingKind, ...]] = (
    FindingKind.ACTION_WITHOUT_RESULT,
    FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
    FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
    FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED,
    FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT,
    FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM,
    FindingKind.FAILED_WORK_OMITTED,
    FindingKind.LEDGER_STALE_OR_INCOMPLETE,
    FindingKind.MATERIAL_LIMITATION_OMITTED,
    FindingKind.QUESTIONABLE_FINDING_REJECTION,
    FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
    FindingKind.RESULT_WITHOUT_ACTION,
    FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE,
    FindingKind.WEAK_OR_STALE_RESPONSE,
    FindingKind.CODE_DEFECT,
    FindingKind.TASK_REQUIREMENT_UNMET,
)


class FindingOrigin(str, Enum):  # noqa: UP042 - exact wire enum base
    DETERMINISTIC = "deterministic"
    SEMANTIC_MODEL_DERIVED = "semantic_model_derived"


class CheckVerdict(str, Enum):  # noqa: UP042 - exact wire enum base
    ACTION_REQUIRED = "action_required"
    NO_ISSUE_DETECTED = "no_issue_detected"
    INSUFFICIENT_COVERAGE = "insufficient_coverage"
    INCOMPLETE_CHECK = "incomplete_check"


class WaiverScope(str, Enum):  # noqa: UP042 - exact wire enum base
    FINDING_ONLY = "finding_only"


class ResponseDisposition(str, Enum):  # noqa: UP042 - exact wire enum base
    ACKNOWLEDGED = "acknowledged"
    # Issue #905: the agent states, with a required reason, that it will not do what the finding
    # asks. Terminal: the item is never re-reviewed, never resolves, and never reads as clean.
    # Recorded only on ``response_recorded`` 1.1.0.
    ACKNOWLEDGED_NOT_DONE = "acknowledged_not_done"
    # Issue #996 (ADR-034 amendment): the agent links this finding to an earlier finding that
    # names the same issue and that it already answered or is answering. Requires
    # ``duplicate_of_finding_id``; reason and evidence are optional, waiver fields are refused.
    # Not terminal: while the link holds the to-do state is derived from the earlier finding, and
    # a later check that raises this finding's issue again breaks the link
    # (``kernel/finding_todo.py``). Recorded only on ``response_recorded`` 1.1.0.
    DUPLICATE_OF = "duplicate_of"
    PROVENANCE_DISPUTED = "provenance_disputed"
    REJECTED = "rejected"
    # Issue #984 (ADR-034): the agent repaired the finding, Yoetz cannot prove the repair because
    # of its own limits (a "Yoetz limit"), and the agent verified it itself. Requires a reason
    # (how it verified) and at least one recorded evidence or result id. Terminal: never resolved,
    # never clean, never re-reviewed, and not agent work. Recorded only on
    # ``response_recorded`` 1.1.0.
    SELF_VERIFIED = "self_verified"
    WAIVED = "waived"


# The dispositions that make a finding's to-do state final when recorded (issues #905, #984).
TERMINAL_RESPONSE_DISPOSITIONS: Final = frozenset(
    {ResponseDisposition.ACKNOWLEDGED_NOT_DONE, ResponseDisposition.SELF_VERIFIED}
)

# The dispositions recorded only on ``response_recorded`` 1.1.0 (issues #905, #984, #996); every
# other disposition keeps the released 1.0.0 bytes.
RESPONSE_V1_1_DISPOSITIONS: Final = TERMINAL_RESPONSE_DISPOSITIONS | frozenset(
    {ResponseDisposition.DUPLICATE_OF}
)

# The one sentence every agent-facing text reuses when it tells the agent what to do with a
# finding Yoetz cannot prove repaired (issue #984, COORD contract wording; tests pin it).
SELF_VERIFIED_GUIDANCE: Final = (
    "If you repaired this and Yoetz cannot prove it (a Yoetz limit), verify it yourself, record "
    "that evidence, and respond `self_verified` with how you verified it and the evidence ids. "
    "Do not reshape your work for Yoetz, and a Yoetz limit is never a `yoetz-blocker`."
)


class SemanticDispatchKind(str, Enum):  # noqa: UP042 - exact wire enum base
    EXTERNAL = "external"
    EXTERNAL_RUNTIME_OAUTH = "external_runtime_oauth"
    LOCAL_MODEL = "local_model"


class SemanticFailureClass(str, Enum):  # noqa: UP042 - exact wire enum base
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    PROVIDER_OUTAGE = "provider_outage"
    QUOTA_EXHAUSTED = "quota_exhausted"
    RATE_LIMITED = "rate_limited"
    RESPONSE_CONTENT = "response_content"
    RESPONSE_SCHEMA = "response_schema"
    TIMEOUT = "timeout"
    TRANSPORT = "transport"
    UNSUPPORTED_PROFILE = "unsupported_profile"


# Closed, nonsecret classification of where one external-runtime attempt stopped. Every token is a
# reviewed literal chosen by the adapter from its own bounded checks; none is derived from provider
# text. ``None`` means the attempt produced an accepted judgment. Stages before ``turn_ack_invalid``
# happen before the case is disclosed; the ``judgment_*`` family is the local validation stage of
# a completed turn's final answer, so an operator can tell malformed JSON from a wrong envelope,
# an invented enum, duplicate refs, or a conclusion/challenge contradiction without any plaintext.
RUNTIME_FAILURE_STAGES: Final[frozenset[str]] = frozenset(
    {
        "capability_evidence_stale",
        "launch_failed",
        "initialize_invalid",
        "login_required",
        "model_unavailable",
        "thread_invalid",
        "predisclosure_event_forbidden",
        "case_invalid",
        "turn_ack_invalid",
        "tool_request_forbidden",
        "event_forbidden",
        "tool_event_forbidden",
        "rate_limits_invalid",
        "token_usage_invalid",
        "runtime_warning",
        "turn_failed",
        "model_rerouted",
        "completion_mismatch",
        "agent_message_count",
        "output_empty",
        "output_oversize",
        "event_limit",
        "output_not_json",
        "judgment_envelope_invalid",
        "judgment_enum_invalid",
        "judgment_refs_duplicate",
        "judgment_refs_invalid",
        "judgment_conclusion_mismatch",
        "judgment_text_bounds",
        "judgment_shape_invalid",
        "judgment_invariant_invalid",
        "request_failed",
        "transport_failed",
        "deadline_expired",
        "cleanup_unconfirmed",
        "unclassified",
    }
)


@dataclass(frozen=True, slots=True)
class RuntimeAttemptEvidence:
    """Bounded nonsecret evidence for one exact external-runtime attempt."""

    credential_authority: Literal["external_runtime_oauth"]
    runtime_version: str
    runtime_source_identity: str
    executable_sha256: str
    app_server_schema_sha256: str
    capability_cell_sha256: str
    capability_profile: str
    capability_evidence_expires_at: str
    launcher_sha256: str
    isolated_config_sha256: str
    disclosed_case_sha256: str
    instruction_sha256: str
    output_schema_sha256: str
    selection_sha256: str
    upstream_body_observability: Literal["unavailable"]
    auth_mode: Literal["chatgpt"] | None
    plan_type: str | None
    reasoning_effort: str
    thread_id: str | None
    turn_id: str | None
    final_output_sha256: str | None
    case_disclosed: bool
    turn_acknowledged: bool
    process_cleanup: Literal["not_started", "terminated", "killed", "failed"]
    failure_stage: str | None = None
    token_usage: RuntimeTokenUsage | None = None

    def __post_init__(self) -> None:
        identity = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$", re.ASCII)
        if self.credential_authority != "external_runtime_oauth":
            raise ProtocolValueError("invalid_runtime_attempt_evidence")
        if not _valid_pattern(self.runtime_version, _VERSION_IDENTITY_PATTERN, 128):
            raise ProtocolValueError("invalid_runtime_attempt_evidence")
        if not _valid_pattern(self.runtime_source_identity, identity, 256):
            raise ProtocolValueError("invalid_runtime_attempt_evidence")
        if not _valid_pattern(self.capability_profile, identity, 256):
            raise ProtocolValueError("invalid_runtime_attempt_evidence")
        for value in (
            self.executable_sha256,
            self.app_server_schema_sha256,
            self.capability_cell_sha256,
            self.launcher_sha256,
            self.isolated_config_sha256,
            self.disclosed_case_sha256,
            self.instruction_sha256,
            self.output_schema_sha256,
            self.selection_sha256,
        ):
            validate_sha256_digest(value)
        if self.upstream_body_observability != "unavailable":
            raise ProtocolValueError("invalid_runtime_attempt_evidence")
        if not _valid_pattern(
            self.capability_evidence_expires_at, _RFC3339_UTC_SECONDS_PATTERN, 20
        ):
            raise ProtocolValueError("invalid_runtime_attempt_evidence")
        if self.auth_mode not in {None, "chatgpt"}:
            raise ProtocolValueError("invalid_runtime_attempt_evidence")
        if self.plan_type is not None and not _valid_pattern(self.plan_type, _IDENTITY_PATTERN, 64):
            raise ProtocolValueError("invalid_runtime_attempt_evidence")
        if not _valid_pattern(self.reasoning_effort, _IDENTITY_PATTERN, 64):
            raise ProtocolValueError("invalid_runtime_attempt_evidence")
        for correlation in (self.thread_id, self.turn_id):
            if correlation is not None and not _valid_pattern(
                correlation, _PROVIDER_REQUEST_ID_PATTERN, 256
            ):
                raise ProtocolValueError("invalid_runtime_attempt_evidence")
        if self.final_output_sha256 is not None:
            validate_sha256_digest(self.final_output_sha256)
        if type(self.case_disclosed) is not bool or type(self.turn_acknowledged) is not bool:
            raise ProtocolValueError("invalid_runtime_attempt_evidence")
        if self.turn_acknowledged and not self.case_disclosed:
            raise ProtocolValueError("invalid_runtime_attempt_evidence")
        if self.process_cleanup not in {"not_started", "terminated", "killed", "failed"}:
            raise ProtocolValueError("invalid_runtime_attempt_evidence")
        if self.failure_stage is not None and (
            type(self.failure_stage) is not str or self.failure_stage not in RUNTIME_FAILURE_STAGES
        ):
            raise ProtocolValueError("invalid_runtime_attempt_evidence")
        if self.token_usage is not None and type(self.token_usage) is not RuntimeTokenUsage:
            raise ProtocolValueError("invalid_runtime_attempt_evidence")


FINDING_KIND_TRAITS: Final[MappingProxyType[FindingKind, tuple[int, bool]]] = MappingProxyType(
    {
        FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS: (1, True),
        FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED: (2, True),
        FindingKind.FAILED_WORK_OMITTED: (1, True),
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE: (1, True),
        FindingKind.RESULT_WITHOUT_ACTION: (2, True),
        FindingKind.ACTION_WITHOUT_RESULT: (3, True),
        FindingKind.STALE_EVIDENCE_FOR_CHANGED_STATE: (2, True),
        FindingKind.CONTRADICTORY_CLAIMS_UNRESOLVED: (1, True),
        FindingKind.LEDGER_STALE_OR_INCOMPLETE: (3, False),
        FindingKind.WEAK_OR_STALE_RESPONSE: (2, True),
        FindingKind.EVIDENCE_DOES_NOT_SUPPORT_CLAIM: (1, True),
        FindingKind.DIFF_DOES_NOT_MATCH_ACCOUNT: (1, True),
        FindingKind.MATERIAL_LIMITATION_OMITTED: (1, True),
        FindingKind.QUESTIONABLE_FINDING_REJECTION: (2, True),
        FindingKind.COORDINATION_OVERLAP: (2, True),
        FindingKind.CODE_DEFECT: (1, True),
        FindingKind.TASK_REQUIREMENT_UNMET: (1, True),
    }
)

_WORK_INTEGRITY_KINDS: Final = frozenset(
    {
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
    }
)
# The pack that owns each kind and the current version new findings carry. A recorded finding may
# carry any earlier version of the same pack (``yoetz.protocol.policy_packs``).
_POLICY_IDENTITY_BY_KIND: Final[MappingProxyType[FindingKind, tuple[str, str]]] = MappingProxyType(
    {
        kind: (
            policy_id,
            CURRENT_POLICY_VERSIONS[policy_id],
        )
        for kind in FindingKind
        for policy_id in (
            WORK_INTEGRITY_POLICY_ID
            if kind in _WORK_INTEGRITY_KINDS
            else RESEARCH_EVIDENCE_POLICY_ID
            if kind is not FindingKind.COORDINATION_OVERLAP
            else COORDINATION_POLICY_ID,
        )
    }
)


def finding_policy_identity(kind: FindingKind) -> tuple[str, str]:
    """The ``(policy_id, policy_version)`` a newly raised finding of ``kind`` carries."""

    return _POLICY_IDENTITY_BY_KIND[kind]


_TERMINAL_SEMANTIC_STATUSES: Final = frozenset(
    {
        SemanticStatus.SUCCEEDED,
        SemanticStatus.REFUSED,
        SemanticStatus.TIMEOUT,
        SemanticStatus.INVALID,
        SemanticStatus.UNAVAILABLE,
        SemanticStatus.LATE,
        SemanticStatus.STALE,
        SemanticStatus.FAILED,
    }
)


def _valid_uint53(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_SAFE_INTEGER


def _validate_bounded_text(value: object) -> None:
    if type(value) is not str or not 1 <= len(value) <= _MAX_FINDING_TEXT_LENGTH:
        raise ProtocolValueError("finding_json_shape_invalid")
    ensure_canonical_value(value)


def _valid_pattern(value: object, pattern: re.Pattern[str], maximum: int, minimum: int = 1) -> bool:
    return (
        type(value) is str
        and minimum <= len(value) <= maximum
        and pattern.fullmatch(value) is not None
    )


def _snapshot_validated_id(kind: IdKind, value: object) -> str:
    validated = validate_id(kind, value)
    return str.__getitem__(validated, slice(None))


def _validate_subject_refs(
    value: object,
) -> tuple[EventId | ObligationId | ClaimId, ...]:
    if type(value) is not tuple:
        raise ProtocolValueError("invalid_finding_subject_refs")
    refs = cast(tuple[object, ...], value)
    if not 1 <= len(refs) <= _MAX_SUBJECT_REFS:
        raise ProtocolValueError("invalid_finding_subject_refs")
    ensure_canonical_set(cast(tuple[str, ...], refs))
    validated: list[EventId | ObligationId | ClaimId] = []
    for ref in refs:
        candidate = cast(str, ref)
        prefix = candidate[:4]
        if prefix == "evt_":
            validated.append(event_id(candidate))
        elif prefix == "obl_":
            validated.append(obligation_id(candidate))
        elif prefix == "clm_":
            validated.append(claim_id(candidate))
        else:
            raise ProtocolValueError("invalid_finding_subject_refs")
    return tuple(validated)


@dataclass(frozen=True, slots=True)
class SamplingParams:
    max_output_tokens: int
    temperature: str | None = None
    top_p: str | None = None
    seed: int | None = None

    def __post_init__(self) -> None:
        if type(self.max_output_tokens) is not int or not 1 <= self.max_output_tokens <= 8_192:
            raise ProtocolValueError("invalid_sampling_params")
        for value in (self.temperature, self.top_p):
            if value is not None and not _valid_pattern(value, _FIXED_DECIMAL_PATTERN, 32):
                raise ProtocolValueError("invalid_sampling_params")
        if self.seed is not None and not _valid_uint53(self.seed):
            raise ProtocolValueError("invalid_sampling_params")


@dataclass(frozen=True, slots=True)
class TokenUsage:
    input_tokens: int
    output_tokens: int
    total_tokens: int

    def __post_init__(self) -> None:
        if not all(
            _valid_uint53(value)
            for value in (self.input_tokens, self.output_tokens, self.total_tokens)
        ):
            raise ProtocolValueError("invalid_token_usage")


@dataclass(frozen=True, slots=True)
class RuntimeTokenUsage:
    """Provider-reported cumulative usage for one external-runtime attempt.

    The cached-input and reasoning-output values are subsets of the input/output totals. They are
    retained separately for analysis and must never be added to ``total_tokens`` again.
    """

    input_tokens: int
    cached_input_tokens: int
    cache_write_input_tokens: int
    output_tokens: int
    reasoning_output_tokens: int
    total_tokens: int

    def __post_init__(self) -> None:
        if not all(
            _valid_uint53(value)
            for value in (
                self.input_tokens,
                self.cached_input_tokens,
                self.cache_write_input_tokens,
                self.output_tokens,
                self.reasoning_output_tokens,
                self.total_tokens,
            )
        ):
            raise ProtocolValueError("invalid_token_usage")
        if (
            self.cached_input_tokens > self.input_tokens
            or self.reasoning_output_tokens > self.output_tokens
            or self.input_tokens + self.output_tokens != self.total_tokens
        ):
            raise ProtocolValueError("invalid_token_usage")

    @property
    def aggregate(self) -> TokenUsage:
        """Return the non-overlapping aggregate fields used by AI-powered review provenance."""

        return TokenUsage(
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            total_tokens=self.total_tokens,
        )


@dataclass(frozen=True, slots=True)
class CostFields:
    currency: str
    input_microunits: int
    output_microunits: int
    total_microunits: int

    def __post_init__(self) -> None:
        if type(self.currency) is not str or _CURRENCY_PATTERN.fullmatch(self.currency) is None:
            raise ProtocolValueError("invalid_cost_fields")
        if not all(
            _valid_uint53(value)
            for value in (
                self.input_microunits,
                self.output_microunits,
                self.total_microunits,
            )
        ):
            raise ProtocolValueError("invalid_cost_fields")


# The only reasons a primary can be given up for (issue #582): the closed fallback-licensing set
# plus the one pre-dispatch reason, `credential_unavailable`. Pinned by the provenance schema.
FALLBACK_ORIGIN_REASONS: Final[frozenset[SemanticReason]] = frozenset(
    {
        SemanticReason.CREDENTIAL_UNAVAILABLE,
        SemanticReason.PROVIDER_QUOTA_EXHAUSTED,
        SemanticReason.PROVIDER_RATE_LIMITED,
        SemanticReason.PROVIDER_TIMEOUT,
        SemanticReason.TRANSPORT_UNAVAILABLE,
    }
)


@dataclass(frozen=True, slots=True)
class SemanticFallbackOrigin:
    """The primary endpoint a fallback attempt stood in for, and why (issue #582).

    Structural identity only. ``attempted_count`` is the primary's physical attempts before the
    fallback engaged (zero when the primary could not be resolved at all); ``reason`` is the
    primary's last closed failure reason, always a fallback-licensing or pre-dispatch one.
    """

    provider: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    model: str
    attempted_count: int
    reason: SemanticReason

    def __post_init__(self) -> None:
        if not _valid_pattern(self.provider, _IDENTITY_PATTERN, 128):
            raise ProtocolValueError("invalid_semantic_fallback_origin")
        if not _valid_pattern(self.endpoint_profile_id, _IDENTITY_PATTERN, 128):
            raise ProtocolValueError("invalid_semantic_fallback_origin")
        if not _valid_pattern(
            self.endpoint_profile_version, _SEMANTIC_VERSION_PATTERN, 128, minimum=5
        ):
            raise ProtocolValueError("invalid_semantic_fallback_origin")
        if not _valid_pattern(self.model, _MODEL_IDENTITY_PATTERN, 256):
            raise ProtocolValueError("invalid_semantic_fallback_origin")
        if type(self.attempted_count) is not int or not 0 <= self.attempted_count <= 8:
            raise ProtocolValueError("invalid_semantic_fallback_origin")
        if type(self.reason) is not SemanticReason or self.reason not in FALLBACK_ORIGIN_REASONS:
            raise ProtocolValueError("invalid_semantic_fallback_origin")


@dataclass(frozen=True, slots=True)
class SemanticProvenance:
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
    semantic_attempt_id: str
    dispatch_kind: SemanticDispatchKind
    privacy_receipt_id: str
    status: SemanticStatus
    reason: SemanticReason
    provider_request_id: str | None = None
    token_usage: TokenUsage | None = None
    cost_fields: CostFields | None = None
    failure_class: SemanticFailureClass | None = None
    egress_authorization_id: str | None = None
    local_disclosure_reservation_id: str | None = None
    request_commitment: str | None = None
    runtime_evidence: RuntimeAttemptEvidence | None = None
    # Present exactly when this attempt was served by the declared fallback endpoint; the
    # provider/model/endpoint fields above then name the fallback and this names the primary.
    fallback_from: SemanticFallbackOrigin | None = None

    def __post_init__(self) -> None:
        if (
            self.fallback_from is not None
            and type(self.fallback_from) is not SemanticFallbackOrigin
        ):
            raise ProtocolValueError("invalid_semantic_fallback_origin")
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
        if type(self.sampling_params) is not SamplingParams or not _valid_uint53(self.latency_ms):
            raise ProtocolValueError("invalid_semantic_provenance")

        object.__setattr__(
            self,
            "semantic_attempt_id",
            _snapshot_validated_id(IdKind.SEMANTIC_ATTEMPT, self.semantic_attempt_id),
        )
        if type(self.dispatch_kind) is not SemanticDispatchKind:
            raise ProtocolValueError("invalid_semantic_dispatch_kind")
        object.__setattr__(
            self,
            "privacy_receipt_id",
            _snapshot_validated_id(IdKind.EGRESS_RECEIPT, self.privacy_receipt_id),
        )

        validate_semantic_outcome(self.status, self.reason)
        if self.status not in _TERMINAL_SEMANTIC_STATUSES:
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

        if self.egress_authorization_id is not None:
            object.__setattr__(
                self,
                "egress_authorization_id",
                _snapshot_validated_id(IdKind.EGRESS_AUTHORIZATION, self.egress_authorization_id),
            )
        if self.local_disclosure_reservation_id is not None:
            object.__setattr__(
                self,
                "local_disclosure_reservation_id",
                _snapshot_validated_id(
                    IdKind.PRIVACY_PROPOSAL, self.local_disclosure_reservation_id
                ),
            )
        if self.request_commitment is not None:
            validate_commitment(self.request_commitment)

        if self.dispatch_kind in {
            SemanticDispatchKind.EXTERNAL,
            SemanticDispatchKind.EXTERNAL_RUNTIME_OAUTH,
        }:
            if (
                self.egress_authorization_id is None
                or self.request_commitment is None
                or self.local_disclosure_reservation_id is not None
            ):
                raise ProtocolValueError("invalid_semantic_provenance")
            if (
                self.dispatch_kind is SemanticDispatchKind.EXTERNAL_RUNTIME_OAUTH
                and type(self.runtime_evidence) is not RuntimeAttemptEvidence
            ):
                raise ProtocolValueError("invalid_semantic_provenance")
            if (
                self.dispatch_kind is SemanticDispatchKind.EXTERNAL
                and self.runtime_evidence is not None
            ):
                raise ProtocolValueError("invalid_semantic_provenance")
        elif (
            self.local_disclosure_reservation_id is None
            or self.egress_authorization_id is not None
            or self.request_commitment is not None
            or self.runtime_evidence is not None
        ):
            raise ProtocolValueError("invalid_semantic_provenance")


def _validate_finding_fields(
    *,
    kind: object,
    origin: object,
    priority: object,
    summary: object,
    detail: object,
    subject_refs: object,
    policy_id: object,
    policy_version: object,
    subject_frontier: object,
    coverage: object,
    provenance: object,
) -> tuple[EventId | ObligationId | ClaimId, ...]:
    if type(kind) is not FindingKind:
        raise ProtocolValueError("invalid_finding_kind")
    validated_kind = kind
    if type(origin) is not FindingOrigin:
        raise ProtocolValueError("invalid_finding_origin")
    validated_origin = origin
    required_priority, _ = FINDING_KIND_TRAITS[validated_kind]
    if type(priority) is not int or priority != required_priority:
        raise ProtocolValueError("finding_priority_mismatch")
    _validate_bounded_text(summary)
    _validate_bounded_text(detail)
    validated_refs = _validate_subject_refs(subject_refs)

    expected_policy_id, _ = _POLICY_IDENTITY_BY_KIND[validated_kind]
    if (
        type(policy_id) is not str
        or policy_id != expected_policy_id
        or not is_recorded_policy_identity(policy_id, policy_version)
    ):
        raise ProtocolValueError("invalid_finding_policy_identity")
    if type(subject_frontier) is not Frontier:
        raise ProtocolValueError("invalid_frontier")
    if type(coverage) is not Coverage:
        raise ProtocolValueError("invalid_coverage_value")

    if validated_origin is FindingOrigin.DETERMINISTIC:
        if provenance is not None:
            raise ProtocolValueError("invalid_finding_provenance")
    elif (
        type(provenance) is not SemanticProvenance
        or provenance.status is not SemanticStatus.SUCCEEDED
        or provenance.reason is not SemanticReason.SEMANTIC_COMPLETED
    ):
        raise ProtocolValueError("invalid_finding_provenance")
    return validated_refs


# The closed next-step vocabulary a reviewer challenge names (provider-judgment 1.0.0).
REVIEWER_NEXT_STEPS: Final = frozenset(
    {
        "act",
        "provide_evidence",
        "revise_claim",
        "dispute_with_evidence",
        "state_unresolved_limitation",
        "answer_question",
    }
)
# A challenge cites at most 16 refs, so it can name at most 16 earlier findings.
MAX_RELATED_FINDING_IDS: Final = 16


def _validate_review_text(value: object) -> str:
    """Bound reviewer prose by UTF-8 bytes, exactly as the provider-facing challenge does."""

    if type(value) is not str:
        raise ProtocolValueError("finding_json_shape_invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ProtocolValueError("finding_json_shape_invalid") from exc
    if not 1 <= len(encoded) <= MAX_REVIEW_TEXT_BYTES:
        raise ProtocolValueError("finding_json_shape_invalid")
    ensure_canonical_value(value)
    return str.__getitem__(value, slice(None))


@dataclass(frozen=True, slots=True)
class FindingChallenge:
    """What the reviewer asked for when it raised an AI-powered finding (issue #905).

    ``summary`` and ``message_to_main_agent`` already travel as the finding's summary and
    detail. These are the remaining challenge fields, persisted so a later review and the agent
    can see what the reviewer said would settle the finding instead of only its headline.
    """

    discrepancy: str
    alternative_interpretation: str
    requested_next_step: str
    uncertainty: str
    # Verbatim support from the packet. Older finding records omit this field; new provider
    # judgments may supply it and the check fence validates it against the frozen case.
    snippet: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("discrepancy", "alternative_interpretation", "uncertainty"):
            object.__setattr__(self, field_name, _validate_review_text(getattr(self, field_name)))
        if (
            type(self.requested_next_step) is not str
            or self.requested_next_step not in REVIEWER_NEXT_STEPS
        ):
            raise ProtocolValueError("finding_json_shape_invalid")
        if self.snippet is not None:
            object.__setattr__(self, "snippet", _validate_review_text(self.snippet))


def _validate_dialogue_fields(
    *,
    origin: FindingOrigin,
    challenge: object,
    related_finding_ids: object,
    own_id: FindingId | None,
) -> tuple[FindingId, ...]:
    """Challenge fields and prior-finding links exist only on AI-powered findings."""

    if challenge is not None and type(challenge) is not FindingChallenge:
        raise ProtocolValueError("finding_json_shape_invalid")
    if type(related_finding_ids) is not tuple:
        raise ProtocolValueError("finding_json_shape_invalid")
    related = cast(tuple[object, ...], related_finding_ids)
    if len(related) > MAX_RELATED_FINDING_IDS:
        raise ProtocolValueError("finding_json_shape_invalid")
    ensure_canonical_set(cast(tuple[str, ...], related))
    validated = tuple(finding_id(item) for item in related)
    if own_id is not None and own_id in validated:
        raise ProtocolValueError("finding_json_shape_invalid")
    if origin is not FindingOrigin.SEMANTIC_MODEL_DERIVED and (challenge is not None or validated):
        raise ProtocolValueError("finding_json_shape_invalid")
    return validated


@dataclass(frozen=True, slots=True)
class CandidateFinding:
    kind: FindingKind
    origin: FindingOrigin
    priority: int
    summary: str
    detail: str
    subject_refs: tuple[EventId | ObligationId | ClaimId, ...]
    policy_id: str
    policy_version: str
    subject_frontier: Frontier
    coverage: Coverage
    provenance: SemanticProvenance | None = None
    challenge: FindingChallenge | None = None
    related_finding_ids: tuple[FindingId, ...] = ()

    def __post_init__(self) -> None:
        validated_refs = _validate_finding_fields(
            kind=self.kind,
            origin=self.origin,
            priority=self.priority,
            summary=self.summary,
            detail=self.detail,
            subject_refs=self.subject_refs,
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            subject_frontier=self.subject_frontier,
            coverage=self.coverage,
            provenance=self.provenance,
        )
        object.__setattr__(self, "subject_refs", validated_refs)
        object.__setattr__(
            self,
            "related_finding_ids",
            _validate_dialogue_fields(
                origin=self.origin,
                challenge=self.challenge,
                related_finding_ids=self.related_finding_ids,
                own_id=None,
            ),
        )


@dataclass(frozen=True, slots=True)
class Finding:
    """One recorded finding.

    ``challenge`` and ``related_finding_ids`` (the ``relates_to`` link to earlier findings the
    reviewer cited) are optional fields of ``finding_recorded/1.3.0``, only on AI-powered findings
    (issue #905). They are event facts, not part of the public ``finding`` wire: the public
    encoding (:func:`finding_to_json`) is unchanged, and :func:`finding_event_to_json` carries
    them on the ledger.
    """

    finding_id: FindingId
    kind: FindingKind
    origin: FindingOrigin
    priority: int
    summary: str
    detail: str
    subject_refs: tuple[EventId | ObligationId | ClaimId, ...]
    policy_id: str
    policy_version: str
    subject_frontier: Frontier
    coverage: Coverage
    provenance: SemanticProvenance | None = None
    challenge: FindingChallenge | None = None
    related_finding_ids: tuple[FindingId, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "finding_id", finding_id(self.finding_id))
        validated_refs = _validate_finding_fields(
            kind=self.kind,
            origin=self.origin,
            priority=self.priority,
            summary=self.summary,
            detail=self.detail,
            subject_refs=self.subject_refs,
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            subject_frontier=self.subject_frontier,
            coverage=self.coverage,
            provenance=self.provenance,
        )
        object.__setattr__(self, "subject_refs", validated_refs)
        object.__setattr__(
            self,
            "related_finding_ids",
            _validate_dialogue_fields(
                origin=self.origin,
                challenge=self.challenge,
                related_finding_ids=self.related_finding_ids,
                own_id=self.finding_id,
            ),
        )


# The reviewer's closed per-finding rulings (issue #905). ``fixed`` proves nothing on its own:
# post-validation admits it only with cited material recorded after the finding, and finding
# resolution still applies the freshness and material-change rules.
PRIOR_FINDING_VERDICTS: Final = frozenset(
    {"fixed", "still_present", "answered_not_fixed", "unassessable", "withdrawn"}
)
MAX_RECORDED_VERDICTS: Final = 16


@dataclass(frozen=True, slots=True)
class PriorFindingVerdictRecord:
    """One post-validated reviewer ruling on an earlier AI-powered finding, as recorded."""

    finding_id: FindingId
    verdict: str
    cited_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "finding_id", finding_id(self.finding_id))
        if type(self.verdict) is not str or self.verdict not in PRIOR_FINDING_VERDICTS:
            raise ProtocolValueError("finding_json_shape_invalid")
        if type(self.cited_refs) is not tuple or len(self.cited_refs) > 16:
            raise ProtocolValueError("finding_json_shape_invalid")
        ensure_canonical_set(cast(tuple[str, ...], self.cited_refs))
        for ref in self.cited_refs:
            validate_id(_REF_KINDS.get(ref[:4], IdKind.EVENT), ref)


_REF_KINDS: Final[Mapping[str, IdKind]] = MappingProxyType(
    {
        "act_": IdKind.ACTION,
        "clm_": IdKind.CLAIM,
        "evd_": IdKind.EVIDENCE,
        "evt_": IdKind.EVENT,
        "fnd_": IdKind.FINDING,
        "obl_": IdKind.OBLIGATION,
        "res_": IdKind.RESULT,
    }
)


def finding_has_dialogue_fields(finding: Finding) -> bool:
    """Whether the finding carries the optional ``finding_recorded/1.3.0`` dialogue fields."""

    return finding.challenge is not None or bool(finding.related_finding_ids)


DeterministicFinding = Finding
SemanticFinding = Finding


@dataclass(frozen=True, slots=True)
class RankedFindings:
    findings: tuple[Finding, ...]
    suppressed_count: int
    verdict: CheckVerdict
    coverage: Coverage

    def __post_init__(self) -> None:
        if type(self.findings) is not tuple or any(
            type(finding) is not Finding for finding in self.findings
        ):
            raise ProtocolValueError("invalid_ranked_findings")
        ids = tuple(finding.finding_id for finding in self.findings)
        if len(ids) != len(set(ids)):
            raise ProtocolValueError("invalid_ranked_findings")
        if not _valid_uint53(self.suppressed_count):
            raise ProtocolValueError("invalid_ranked_findings")
        if type(self.verdict) is not CheckVerdict or type(self.coverage) is not Coverage:
            raise ProtocolValueError("invalid_ranked_findings")


def _require_json_object(
    value: JsonValue,
    *,
    required: frozenset[str],
    allowed: frozenset[str],
    reason: str,
) -> JsonObject:
    if type(value) is not JsonObject:
        raise ProtocolValueError(reason)
    source = value
    try:
        keys = frozenset(source)
    except Exception as exc:
        raise ProtocolValueError(reason) from exc
    if not required <= keys or not keys <= allowed:
        raise ProtocolValueError(reason)
    return source


def _field(source: Mapping[str, JsonValue], key: str, reason: str) -> JsonValue:
    try:
        return source[key]
    except Exception as exc:
        raise ProtocolValueError(reason) from exc


def _optional_field(source: Mapping[str, JsonValue], key: str) -> JsonValue | None:
    if key not in source:
        return None
    return source[key]


def _parse_uint53_wire(value: JsonValue, reason: str) -> int:
    parsed = parse_wire_sequence(cast(str, value))
    if parsed > _MAX_SAFE_INTEGER:
        raise ProtocolValueError(reason)
    return parsed


def _sampling_params_from_json(value: JsonValue) -> SamplingParams:
    required = frozenset({"max_output_tokens"})
    allowed = frozenset({"max_output_tokens", "temperature", "top_p", "seed"})
    source = _require_json_object(
        value,
        required=required,
        allowed=allowed,
        reason="semantic_provenance_json_shape_invalid",
    )
    if any(key in source and source[key] is None for key in allowed - required):
        raise ProtocolValueError("semantic_provenance_json_shape_invalid")
    temperature = _optional_field(source, "temperature")
    top_p = _optional_field(source, "top_p")
    seed = _optional_field(source, "seed")
    return SamplingParams(
        max_output_tokens=_parse_uint53_wire(
            _field(source, "max_output_tokens", "semantic_provenance_json_shape_invalid"),
            "invalid_sampling_params",
        ),
        temperature=cast(str | None, temperature),
        top_p=cast(str | None, top_p),
        seed=None if seed is None else _parse_uint53_wire(seed, "invalid_sampling_params"),
    )


def _token_usage_from_json(value: JsonValue) -> TokenUsage:
    keys = frozenset({"input_tokens", "output_tokens", "total_tokens"})
    source = _require_json_object(
        value,
        required=keys,
        allowed=keys,
        reason="semantic_provenance_json_shape_invalid",
    )
    return TokenUsage(
        input_tokens=_parse_uint53_wire(source["input_tokens"], "invalid_token_usage"),
        output_tokens=_parse_uint53_wire(source["output_tokens"], "invalid_token_usage"),
        total_tokens=_parse_uint53_wire(source["total_tokens"], "invalid_token_usage"),
    )


def _runtime_token_usage_from_json(value: JsonValue) -> RuntimeTokenUsage:
    keys = frozenset(
        {
            "input_tokens",
            "cached_input_tokens",
            "cache_write_input_tokens",
            "output_tokens",
            "reasoning_output_tokens",
            "total_tokens",
        }
    )
    source = _require_json_object(
        value,
        required=keys,
        allowed=keys,
        reason="runtime_attempt_evidence_json_shape_invalid",
    )
    return RuntimeTokenUsage(
        input_tokens=_parse_uint53_wire(source["input_tokens"], "invalid_token_usage"),
        cached_input_tokens=_parse_uint53_wire(
            source["cached_input_tokens"], "invalid_token_usage"
        ),
        cache_write_input_tokens=_parse_uint53_wire(
            source["cache_write_input_tokens"], "invalid_token_usage"
        ),
        output_tokens=_parse_uint53_wire(source["output_tokens"], "invalid_token_usage"),
        reasoning_output_tokens=_parse_uint53_wire(
            source["reasoning_output_tokens"], "invalid_token_usage"
        ),
        total_tokens=_parse_uint53_wire(source["total_tokens"], "invalid_token_usage"),
    )


def _cost_fields_from_json(value: JsonValue) -> CostFields:
    keys = frozenset({"currency", "input_microunits", "output_microunits", "total_microunits"})
    source = _require_json_object(
        value,
        required=keys,
        allowed=keys,
        reason="semantic_provenance_json_shape_invalid",
    )
    return CostFields(
        currency=cast(str, source["currency"]),
        input_microunits=_parse_uint53_wire(source["input_microunits"], "invalid_cost_fields"),
        output_microunits=_parse_uint53_wire(source["output_microunits"], "invalid_cost_fields"),
        total_microunits=_parse_uint53_wire(source["total_microunits"], "invalid_cost_fields"),
    )


def _runtime_attempt_evidence_from_json(value: JsonValue | None) -> RuntimeAttemptEvidence | None:
    if value is None:
        return None
    required = frozenset(
        {
            "app_server_schema_sha256",
            "capability_cell_sha256",
            "capability_evidence_expires_at",
            "capability_profile",
            "case_disclosed",
            "credential_authority",
            "disclosed_case_sha256",
            "executable_sha256",
            "instruction_sha256",
            "isolated_config_sha256",
            "launcher_sha256",
            "output_schema_sha256",
            "reasoning_effort",
            "selection_sha256",
            "process_cleanup",
            "runtime_source_identity",
            "runtime_version",
            "turn_acknowledged",
            "upstream_body_observability",
        }
    )
    optional = frozenset(
        {
            "auth_mode",
            "failure_stage",
            "final_output_sha256",
            "plan_type",
            "thread_id",
            "token_usage",
            "turn_id",
        }
    )
    source = _require_json_object(
        value,
        required=required,
        allowed=required | optional,
        reason="runtime_attempt_evidence_json_shape_invalid",
    )
    if any(key in source and source[key] is None for key in optional):
        raise ProtocolValueError("runtime_attempt_evidence_json_shape_invalid")
    return RuntimeAttemptEvidence(
        credential_authority=cast(
            Literal["external_runtime_oauth"], source["credential_authority"]
        ),
        runtime_version=cast(str, source["runtime_version"]),
        runtime_source_identity=cast(str, source["runtime_source_identity"]),
        executable_sha256=cast(str, source["executable_sha256"]),
        app_server_schema_sha256=cast(str, source["app_server_schema_sha256"]),
        capability_cell_sha256=cast(str, source["capability_cell_sha256"]),
        capability_profile=cast(str, source["capability_profile"]),
        capability_evidence_expires_at=cast(str, source["capability_evidence_expires_at"]),
        launcher_sha256=cast(str, source["launcher_sha256"]),
        isolated_config_sha256=cast(str, source["isolated_config_sha256"]),
        disclosed_case_sha256=cast(str, source["disclosed_case_sha256"]),
        instruction_sha256=cast(str, source["instruction_sha256"]),
        output_schema_sha256=cast(str, source["output_schema_sha256"]),
        selection_sha256=cast(str, source["selection_sha256"]),
        upstream_body_observability=cast(
            Literal["unavailable"], source["upstream_body_observability"]
        ),
        auth_mode=cast(Literal["chatgpt"] | None, _optional_field(source, "auth_mode")),
        plan_type=cast(str | None, _optional_field(source, "plan_type")),
        reasoning_effort=cast(str, source["reasoning_effort"]),
        thread_id=cast(str | None, _optional_field(source, "thread_id")),
        turn_id=cast(str | None, _optional_field(source, "turn_id")),
        final_output_sha256=cast(str | None, _optional_field(source, "final_output_sha256")),
        case_disclosed=cast(bool, source["case_disclosed"]),
        turn_acknowledged=cast(bool, source["turn_acknowledged"]),
        process_cleanup=cast(
            Literal["not_started", "terminated", "killed", "failed"],
            source["process_cleanup"],
        ),
        failure_stage=cast(str | None, source.get("failure_stage")),
        token_usage=(
            None
            if _optional_field(source, "token_usage") is None
            else _runtime_token_usage_from_json(_optional_field(source, "token_usage"))
        ),
    )


_PROVENANCE_REQUIRED_KEYS: Final = frozenset(
    {
        "provider",
        "endpoint_profile_id",
        "endpoint_profile_version",
        "model",
        "sdk_version",
        "prompt_digest",
        "schema_digest",
        "policy_digest",
        "privacy_policy_digest",
        "sampling_params",
        "latency_ms",
        "semantic_attempt_id",
        "dispatch_kind",
        "privacy_receipt_id",
        "status",
        "reason",
    }
)
_PROVENANCE_OPTIONAL_KEYS: Final = frozenset(
    {
        "provider_request_id",
        "token_usage",
        "cost_fields",
        "failure_class",
        "egress_authorization_id",
        "local_disclosure_reservation_id",
        "request_commitment",
        "runtime_evidence",
        "fallback_from",
    }
)
_FALLBACK_ORIGIN_KEYS: Final = frozenset(
    {
        "provider",
        "endpoint_profile_id",
        "endpoint_profile_version",
        "model",
        "attempted_count",
        "reason",
    }
)


def _fallback_origin_from_json(value: JsonValue | None) -> SemanticFallbackOrigin | None:
    if value is None:
        return None
    source = _require_json_object(
        value,
        required=_FALLBACK_ORIGIN_KEYS,
        allowed=_FALLBACK_ORIGIN_KEYS,
        reason="semantic_provenance_json_shape_invalid",
    )
    try:
        reason = SemanticReason(source["reason"])
    except (TypeError, ValueError) as exc:
        raise ProtocolValueError("invalid_semantic_fallback_origin") from exc
    return SemanticFallbackOrigin(
        provider=cast(str, source["provider"]),
        endpoint_profile_id=cast(str, source["endpoint_profile_id"]),
        endpoint_profile_version=cast(str, source["endpoint_profile_version"]),
        model=cast(str, source["model"]),
        attempted_count=_parse_uint53_wire(
            source["attempted_count"], "invalid_semantic_fallback_origin"
        ),
        reason=reason,
    )


def semantic_fallback_origin_to_json(value: SemanticFallbackOrigin) -> JsonObject:
    if type(value) is not SemanticFallbackOrigin:
        raise ProtocolValueError("invalid_semantic_fallback_origin")
    return JsonObject(
        {
            "provider": value.provider,
            "endpoint_profile_id": value.endpoint_profile_id,
            "endpoint_profile_version": value.endpoint_profile_version,
            "model": value.model,
            "attempted_count": render_wire_sequence(value.attempted_count),
            "reason": value.reason.value,
        }
    )


def semantic_provenance_from_json(value: JsonValue) -> SemanticProvenance:
    """Decode one exact finalized AI-powered review provenance object."""

    source = _require_json_object(
        value,
        required=_PROVENANCE_REQUIRED_KEYS,
        allowed=_PROVENANCE_REQUIRED_KEYS | _PROVENANCE_OPTIONAL_KEYS,
        reason="semantic_provenance_json_shape_invalid",
    )
    if any(key in source and source[key] is None for key in _PROVENANCE_OPTIONAL_KEYS):
        raise ProtocolValueError("semantic_provenance_json_shape_invalid")
    dispatch_wire = source["dispatch_kind"]
    failure_wire = _optional_field(source, "failure_class")
    status_wire = source["status"]
    reason_wire = source["reason"]
    try:
        dispatch_kind = SemanticDispatchKind(dispatch_wire)
    except (TypeError, ValueError) as exc:
        raise ProtocolValueError("invalid_semantic_dispatch_kind") from exc
    try:
        status = SemanticStatus(status_wire)
        semantic_reason = SemanticReason(reason_wire)
    except (TypeError, ValueError) as exc:
        raise ProtocolValueError("invalid_semantic_provenance") from exc
    if failure_wire is None:
        failure_class = None
    else:
        try:
            failure_class = SemanticFailureClass(failure_wire)
        except (TypeError, ValueError) as exc:
            raise ProtocolValueError("invalid_semantic_failure_class") from exc

    token_usage_value = _optional_field(source, "token_usage")
    cost_fields_value = _optional_field(source, "cost_fields")
    return SemanticProvenance(
        provider=cast(str, source["provider"]),
        endpoint_profile_id=cast(str, source["endpoint_profile_id"]),
        endpoint_profile_version=cast(str, source["endpoint_profile_version"]),
        model=cast(str, source["model"]),
        sdk_version=cast(str, source["sdk_version"]),
        prompt_digest=cast(str, source["prompt_digest"]),
        schema_digest=cast(str, source["schema_digest"]),
        policy_digest=cast(str, source["policy_digest"]),
        privacy_policy_digest=cast(str, source["privacy_policy_digest"]),
        sampling_params=_sampling_params_from_json(source["sampling_params"]),
        latency_ms=_parse_uint53_wire(source["latency_ms"], "invalid_semantic_provenance"),
        semantic_attempt_id=cast(str, source["semantic_attempt_id"]),
        dispatch_kind=dispatch_kind,
        privacy_receipt_id=cast(str, source["privacy_receipt_id"]),
        status=status,
        reason=semantic_reason,
        provider_request_id=cast(str | None, _optional_field(source, "provider_request_id")),
        token_usage=(
            None if token_usage_value is None else _token_usage_from_json(token_usage_value)
        ),
        cost_fields=(
            None if cost_fields_value is None else _cost_fields_from_json(cost_fields_value)
        ),
        failure_class=failure_class,
        egress_authorization_id=cast(
            str | None, _optional_field(source, "egress_authorization_id")
        ),
        local_disclosure_reservation_id=cast(
            str | None, _optional_field(source, "local_disclosure_reservation_id")
        ),
        request_commitment=cast(str | None, _optional_field(source, "request_commitment")),
        runtime_evidence=_runtime_attempt_evidence_from_json(
            _optional_field(source, "runtime_evidence")
        ),
        fallback_from=_fallback_origin_from_json(_optional_field(source, "fallback_from")),
    )


def semantic_provenance_to_json(value: SemanticProvenance) -> JsonObject:
    """Encode finalized AI-powered review provenance into its one closed wire object."""

    if type(value) is not SemanticProvenance:
        raise ProtocolValueError("invalid_semantic_provenance")
    sampling: dict[str, JsonValue] = {
        "max_output_tokens": render_wire_sequence(value.sampling_params.max_output_tokens)
    }
    if value.sampling_params.temperature is not None:
        sampling["temperature"] = value.sampling_params.temperature
    if value.sampling_params.top_p is not None:
        sampling["top_p"] = value.sampling_params.top_p
    if value.sampling_params.seed is not None:
        sampling["seed"] = render_wire_sequence(value.sampling_params.seed)

    result: dict[str, JsonValue] = {
        "provider": value.provider,
        "endpoint_profile_id": value.endpoint_profile_id,
        "endpoint_profile_version": value.endpoint_profile_version,
        "model": value.model,
        "sdk_version": value.sdk_version,
        "prompt_digest": value.prompt_digest,
        "schema_digest": value.schema_digest,
        "policy_digest": value.policy_digest,
        "privacy_policy_digest": value.privacy_policy_digest,
        "sampling_params": JsonObject(sampling),
        "latency_ms": render_wire_sequence(value.latency_ms),
        "semantic_attempt_id": value.semantic_attempt_id,
        "dispatch_kind": value.dispatch_kind.value,
        "privacy_receipt_id": value.privacy_receipt_id,
        "status": value.status.value,
        "reason": value.reason.value,
    }
    if value.provider_request_id is not None:
        result["provider_request_id"] = value.provider_request_id
    if value.token_usage is not None:
        result["token_usage"] = JsonObject(
            {
                "input_tokens": render_wire_sequence(value.token_usage.input_tokens),
                "output_tokens": render_wire_sequence(value.token_usage.output_tokens),
                "total_tokens": render_wire_sequence(value.token_usage.total_tokens),
            }
        )
    if value.cost_fields is not None:
        result["cost_fields"] = JsonObject(
            {
                "currency": value.cost_fields.currency,
                "input_microunits": render_wire_sequence(value.cost_fields.input_microunits),
                "output_microunits": render_wire_sequence(value.cost_fields.output_microunits),
                "total_microunits": render_wire_sequence(value.cost_fields.total_microunits),
            }
        )
    if value.failure_class is not None:
        result["failure_class"] = value.failure_class.value
    if value.egress_authorization_id is not None:
        result["egress_authorization_id"] = value.egress_authorization_id
    if value.local_disclosure_reservation_id is not None:
        result["local_disclosure_reservation_id"] = value.local_disclosure_reservation_id
    if value.request_commitment is not None:
        result["request_commitment"] = value.request_commitment
    if value.runtime_evidence is not None:
        runtime = value.runtime_evidence
        runtime_json: dict[str, JsonValue] = {
            "app_server_schema_sha256": runtime.app_server_schema_sha256,
            "capability_cell_sha256": runtime.capability_cell_sha256,
            "capability_evidence_expires_at": runtime.capability_evidence_expires_at,
            "capability_profile": runtime.capability_profile,
            "case_disclosed": runtime.case_disclosed,
            "credential_authority": runtime.credential_authority,
            "disclosed_case_sha256": runtime.disclosed_case_sha256,
            "executable_sha256": runtime.executable_sha256,
            "instruction_sha256": runtime.instruction_sha256,
            "isolated_config_sha256": runtime.isolated_config_sha256,
            "launcher_sha256": runtime.launcher_sha256,
            "output_schema_sha256": runtime.output_schema_sha256,
            "reasoning_effort": runtime.reasoning_effort,
            "selection_sha256": runtime.selection_sha256,
            "process_cleanup": runtime.process_cleanup,
            "runtime_source_identity": runtime.runtime_source_identity,
            "runtime_version": runtime.runtime_version,
            "turn_acknowledged": runtime.turn_acknowledged,
            "upstream_body_observability": runtime.upstream_body_observability,
        }
        if runtime.auth_mode is not None:
            runtime_json["auth_mode"] = runtime.auth_mode
        if runtime.plan_type is not None:
            runtime_json["plan_type"] = runtime.plan_type
        if runtime.thread_id is not None:
            runtime_json["thread_id"] = runtime.thread_id
        if runtime.turn_id is not None:
            runtime_json["turn_id"] = runtime.turn_id
        if runtime.final_output_sha256 is not None:
            runtime_json["final_output_sha256"] = runtime.final_output_sha256
        if runtime.failure_stage is not None:
            runtime_json["failure_stage"] = runtime.failure_stage
        if runtime.token_usage is not None:
            runtime_json["token_usage"] = JsonObject(
                {
                    "input_tokens": render_wire_sequence(runtime.token_usage.input_tokens),
                    "cached_input_tokens": render_wire_sequence(
                        runtime.token_usage.cached_input_tokens
                    ),
                    "cache_write_input_tokens": render_wire_sequence(
                        runtime.token_usage.cache_write_input_tokens
                    ),
                    "output_tokens": render_wire_sequence(runtime.token_usage.output_tokens),
                    "reasoning_output_tokens": render_wire_sequence(
                        runtime.token_usage.reasoning_output_tokens
                    ),
                    "total_tokens": render_wire_sequence(runtime.token_usage.total_tokens),
                }
            )
        result["runtime_evidence"] = JsonObject(runtime_json)
    if value.fallback_from is not None:
        result["fallback_from"] = semantic_fallback_origin_to_json(value.fallback_from)
    return JsonObject(result)


_FINDING_REQUIRED_KEYS: Final = frozenset(
    {
        "finding_id",
        "kind",
        "origin",
        "priority",
        "summary",
        "detail",
        "subject_refs",
        "policy_id",
        "policy_version",
        "subject_frontier",
        "coverage",
    }
)
_FINDING_ALLOWED_KEYS: Final = _FINDING_REQUIRED_KEYS | {"provenance"}


def finding_from_json(value: JsonValue) -> Finding:
    """Decode one exact finding-schema object."""

    source = _require_json_object(
        value,
        required=_FINDING_REQUIRED_KEYS,
        allowed=_FINDING_ALLOWED_KEYS,
        reason="finding_json_shape_invalid",
    )
    if "provenance" in source and source["provenance"] is None:
        raise ProtocolValueError("finding_json_shape_invalid")
    try:
        kind = FindingKind(source["kind"])
    except (TypeError, ValueError) as exc:
        raise ProtocolValueError("invalid_finding_kind") from exc
    try:
        origin = FindingOrigin(source["origin"])
    except (TypeError, ValueError) as exc:
        raise ProtocolValueError("invalid_finding_origin") from exc
    refs_value = source["subject_refs"]
    if type(refs_value) is not tuple:
        raise ProtocolValueError("invalid_finding_subject_refs")
    provenance_value = _optional_field(source, "provenance")
    return Finding(
        finding_id=finding_id(source["finding_id"]),
        kind=kind,
        origin=origin,
        priority=cast(int, source["priority"]),
        summary=cast(str, source["summary"]),
        detail=cast(str, source["detail"]),
        subject_refs=cast(tuple[EventId | ObligationId | ClaimId, ...], refs_value),
        policy_id=cast(str, source["policy_id"]),
        policy_version=cast(str, source["policy_version"]),
        subject_frontier=frontier_from_json(source["subject_frontier"]),
        coverage=coverage_from_json(cast(CanonicalJsonValue, source["coverage"])),
        provenance=(
            None if provenance_value is None else semantic_provenance_from_json(provenance_value)
        ),
    )


def finding_to_json(finding: Finding) -> JsonObject:
    """Encode one finding into its exact closed schema object."""

    if type(finding) is not Finding:
        raise ProtocolValueError("finding_json_shape_invalid")
    result: dict[str, JsonValue] = {
        "finding_id": finding.finding_id,
        "kind": finding.kind.value,
        "origin": finding.origin.value,
        "priority": finding.priority,
        "summary": finding.summary,
        "detail": finding.detail,
        "subject_refs": finding.subject_refs,
        "policy_id": finding.policy_id,
        "policy_version": finding.policy_version,
        "subject_frontier": finding.subject_frontier.as_wire(),
        "coverage": JsonObject(coverage_to_json(finding.coverage)),
    }
    if finding.provenance is not None:
        result["provenance"] = semantic_provenance_to_json(finding.provenance)
    return JsonObject(result)


_CHALLENGE_KEYS: Final = frozenset(
    {
        "discrepancy",
        "alternative_interpretation",
        "requested_next_step",
        "uncertainty",
        "snippet",
    }
)
_CHALLENGE_REQUIRED_KEYS: Final = frozenset(
    {"discrepancy", "alternative_interpretation", "requested_next_step", "uncertainty"}
)
_FINDING_EVENT_ALLOWED_KEYS: Final = _FINDING_ALLOWED_KEYS | {"challenge", "relates_to"}


def finding_event_from_json(value: JsonValue) -> Finding:
    """Decode one ``finding_recorded`` payload, including the optional dialogue fields.

    The shape is the public finding object plus, on event version 1.3.0, ``challenge`` and
    ``relates_to``. Which versions admit them is the event decoder's decision.
    """

    source = _require_json_object(
        value,
        required=_FINDING_REQUIRED_KEYS,
        allowed=_FINDING_EVENT_ALLOWED_KEYS,
        reason="finding_json_shape_invalid",
    )
    public = JsonObject({key: item for key, item in source.items() if key in _FINDING_ALLOWED_KEYS})
    finding = finding_from_json(public)
    challenge_value = _optional_field(source, "challenge")
    related_value = _optional_field(source, "relates_to")
    if "challenge" in source and challenge_value is None:
        raise ProtocolValueError("finding_json_shape_invalid")
    if "relates_to" in source and (type(related_value) is not tuple or not related_value):
        raise ProtocolValueError("finding_json_shape_invalid")
    challenge: FindingChallenge | None = None
    if challenge_value is not None:
        fields = _require_json_object(
            challenge_value,
            required=_CHALLENGE_REQUIRED_KEYS,
            allowed=_CHALLENGE_KEYS,
            reason="finding_json_shape_invalid",
        )
        challenge = FindingChallenge(
            discrepancy=cast(str, fields["discrepancy"]),
            alternative_interpretation=cast(str, fields["alternative_interpretation"]),
            requested_next_step=cast(str, fields["requested_next_step"]),
            uncertainty=cast(str, fields["uncertainty"]),
            snippet=(None if fields.get("snippet") is None else cast(str, fields["snippet"])),
        )
    return Finding(
        finding_id=finding.finding_id,
        kind=finding.kind,
        origin=finding.origin,
        priority=finding.priority,
        summary=finding.summary,
        detail=finding.detail,
        subject_refs=finding.subject_refs,
        policy_id=finding.policy_id,
        policy_version=finding.policy_version,
        subject_frontier=finding.subject_frontier,
        coverage=finding.coverage,
        provenance=finding.provenance,
        challenge=challenge,
        related_finding_ids=(
            () if related_value is None else cast(tuple[FindingId, ...], related_value)
        ),
    )


def finding_event_to_json(finding: Finding) -> JsonObject:
    """Encode one ``finding_recorded`` payload: the public object plus any dialogue fields.

    A finding without dialogue fields encodes byte-identically to :func:`finding_to_json`, so
    every local finding and every pre-#905 AI-powered finding keeps its recorded bytes.
    """

    result = dict(finding_to_json(finding).items())
    if finding.challenge is not None:
        result["challenge"] = JsonObject(
            {
                "alternative_interpretation": finding.challenge.alternative_interpretation,
                "discrepancy": finding.challenge.discrepancy,
                "requested_next_step": finding.challenge.requested_next_step,
                "uncertainty": finding.challenge.uncertainty,
                **(
                    {}
                    if finding.challenge.snippet is None
                    else {"snippet": finding.challenge.snippet}
                ),
            }
        )
    if finding.related_finding_ids:
        result["relates_to"] = tuple(finding.related_finding_ids)
    return JsonObject(result)


type RankKey = tuple[int, int, int, int, int, int, int, int, int, bytes]


def rank_key(finding: Finding) -> RankKey:
    """Return the registered ascending lexicographic ranking tuple."""

    if type(finding) is not Finding:
        raise ProtocolValueError("invalid_ranked_findings")
    priority, actionable = FINDING_KIND_TRAITS[finding.kind]
    coverage = finding.coverage
    real_check_present = int(
        CheckType.DETERMINISTIC in coverage.check_types
        or CheckType.SEMANTIC_MODEL_DERIVED in coverage.check_types
    )
    origin_ordinal = int(finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED)
    return (
        priority,
        -int(actionable),
        -ARTIFACT_OBSERVATION_ORDER[coverage.artifact_observation],
        -EVIDENCE_IMMUTABILITY_ORDER[coverage.evidence_immutability],
        -LEDGER_FRESHNESS_ORDER[coverage.ledger_freshness],
        -AUTHORSHIP_ASSURANCE_ORDER[coverage.authorship_assurance],
        -real_check_present,
        len(coverage.known_gaps),
        origin_ordinal,
        finding.finding_id.encode("ascii"),
    )
