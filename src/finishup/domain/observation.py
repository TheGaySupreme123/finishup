"""Live Codex observation values, cursors, status, and advice snapshots."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType, NotImplementedType
from typing import Final, Literal, cast

from finishup.domain.observation_profiles import (
    content_capture_profile_matches_source,
    is_content_capture_profile,
    validate_content_capture_profile,
)
from finishup.domain.observation_settings import (
    ObservationSelectionRuntimeStatus,
    observation_selection_runtime_status_from_json,
    observation_selection_runtime_status_to_json,
)
from finishup.domain.values import (
    FindingId,
    JsonObject,
    JsonValue,
    Timestamp,
    finding_id,
    object_id,
    session_id,
    task_id,
    timestamp_from_string,
    validate_commitment,
    validate_sha256_digest,
    writer_id,
)
from finishup.domain.workspace_effect import WORKSPACE_EFFECTS
from finishup.domain.write_scope import WRITE_SCOPES
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.coverage import Coverage, coverage_from_json, coverage_to_json
from finishup.protocol.errors import PROTOCOL_REASON_CODES, ProtocolValueError
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "AdviceItem",
    "AdviceSemanticState",
    "AdviceSnapshot",
    "CAPTURE_HANDOFF_RECONCILE_AGE_MS",
    "CaptureHandoffRetirementReason",
    "CaptureHandoffRetirementStage",
    "OBSERVATION_BACKPRESSURE_REASON",
    "OBSERVATION_COMMAND_COMMITMENT_DOMAIN",
    "OBSERVATION_CONTENT_CAPTURE_PENDING_REASON",
    "OBSERVATION_HOOK_COMMITMENT_DOMAIN",
    "OBSERVATION_STREAM_LINE_DOMAIN",
    "OBSERVATION_WORKSPACE_DOMAIN",
    "ROUTINE_READ_SUMMARY_CONTENT_SCOPE",
    "ROUTINE_READ_SUMMARY_MAPPING_VERSION",
    "ROUTINE_READ_SUMMARY_PROVENANCE",
    "ROUTINE_READ_SUMMARY_SCHEMA",
    "ROUTINE_READ_SUMMARY_ALLOWED_GAPS",
    "RoutineReadSummary",
    "RoutineReadSummaryMember",
    "ObservationControlCommand",
    "ObservationContentChunk",
    "ObservationContentManifest",
    "ObservationContentKind",
    "ObservationCapturePart",
    "ObservationCaptureBacklog",
    "ObservationCaptureTicket",
    "ObservationCursor",
    "ObservationEnvelope",
    "ObservationGapCode",
    "MATERIAL_OBSERVATION_GAPS",
    "ObservationIngestDisposition",
    "ObservationIngestRequest",
    "ObservationIngestResult",
    "ObservationLifecycle",
    "ObservationInspectionSnapshot",
    "ObservationRevokeCommand",
    "ObservationSource",
    "ObservationStatus",
    "ObservationSelectionRuntimeStatus",
    "ObservationStatusQuery",
    "advice_item_from_json",
    "advice_item_to_json",
    "advice_snapshot_from_json",
    "advice_snapshot_to_json",
    "hook_source_commitment",
    "normalize_observed_command",
    "observed_command_commitment",
    "observation_control_command_from_json",
    "observation_control_command_to_json",
    "observation_content_chunk_from_json",
    "observation_content_chunk_to_json",
    "observation_capture_ticket_id",
    "observation_capture_part_descriptors",
    "observation_content_binding_matches",
    "observation_source_qualified_content_binding_matches",
    "observation_cursor_from_json",
    "observation_cursor_to_json",
    "observation_earns_hook_observed",
    "observation_envelope_from_json",
    "observation_envelope_to_json",
    "observation_selection_route",
    "observation_selection_runtime_status_from_json",
    "observation_selection_runtime_status_to_json",
    "validate_observation_protection_reference",
    "observation_ingest_request_from_json",
    "observation_ingest_request_to_json",
    "observation_ingest_result_from_json",
    "observation_ingest_result_to_json",
    "observation_revoke_command_from_json",
    "observation_revoke_command_to_json",
    "observation_status_from_json",
    "observation_status_query_from_json",
    "observation_status_query_to_json",
    "observation_status_to_json",
    "routine_read_summary_from_json",
    "routine_read_summary_from_envelope",
    "routine_read_summary_identity",
    "routine_read_summary_member_digest",
    "routine_read_summary_member_from_json",
    "routine_read_summary_member_to_json",
    "routine_read_summary_to_json",
    "stream_line_commitment",
    "workspace_commitment_from_path",
    "is_content_capture_profile",
    "validate_content_capture_profile",
]

_MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991
_MAX_STRUCTURAL_BYTES: Final = 65_536
_MAX_CONTENT_REFS: Final = 16
_MAX_GAP_CODES: Final = 64
_MAX_UNSUPPORTED_EVENTS: Final = 64
_MAX_RANKED_FINDINGS: Final = 64
_MAX_SOURCE_COVERAGE: Final = 8
_MAX_ADVICE_SUMMARY: Final = 160
_MAX_ADVICE_DETAIL: Final = 240
_MAX_EVIDENCE_REFS: Final = 16
_MAX_CONTENT_CHUNKS: Final = 16
_MAX_CONTENT_CHUNK_BYTES: Final = 524_288
# Base64 plus structural framing must stay below the existing 1 MiB ordinary
# control-frame ceiling. Larger logical content is sent over multiple requests
# and assembled from independently encrypted chunk objects.
_MAX_CONTENT_TOTAL_BYTES: Final = 700_000
_MAX_ROUTINE_READ_SUMMARY_CALLS: Final = 16
_MAX_ROUTINE_READ_SUMMARY_INPUTS: Final = 32

_TOKEN_RE: Final = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/+-]{0,127}$", re.ASCII)
_GAP_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,127}$", re.ASCII)
_ADVICE_TEXT_RE: Final = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9 .,:;'_+/-]{0,239}$",
    re.ASCII,
)
_ADVICE_ORIGINS: Final = frozenset({"deterministic", "semantic_model_derived"})
_MEDIA_TYPE_RE: Final = re.compile(
    r"^[a-z][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$",
    re.ASCII,
)

ObservationCapturePart = tuple[str, str, str, int, int]

OBSERVATION_WORKSPACE_DOMAIN: Final = b"yoetz/observation-workspace/v1\x00"
OBSERVATION_STREAM_LINE_DOMAIN: Final = b"yoetz/observation-stream-line/v1\x00"
OBSERVATION_HOOK_COMMITMENT_DOMAIN: Final = b"yoetz/observation-hook-commitment/v1\x00"
# Installation-keyed command identity (#909). The hook commits to the light-normalized command
# text and discards it; only the ``hmac-sha256:`` value leaves the hook process.
OBSERVATION_COMMAND_COMMITMENT_DOMAIN: Final = b"yoetz/observation-command-commitment/v1\x00"
_MAX_OBSERVED_COMMAND_CHARS: Final = 16_384
_MAX_OBSERVED_ARGV: Final = 1_024
_SHELL_WRAPPERS: Final = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
_SHELL_COMMAND_FLAG_RE: Final = re.compile(r"^-[a-z]*c[a-z]*$", re.ASCII)

# A summary is an observation-store record.  It is intentionally kept separate
# from the task-ledger event families: the local writer can account for every
# native input before optional materialization, while a later schema decision
# can choose how (or whether) to publish the bounded account.
ROUTINE_READ_SUMMARY_SCHEMA: Final = "yoetz.observation-routine-read-summary/1.0.0"
ROUTINE_READ_SUMMARY_MAPPING_VERSION: Final = "obs-selection/1.0.0"
ROUTINE_READ_SUMMARY_PROVENANCE: Final = "routine_success_summary"
ROUTINE_READ_SUMMARY_CONTENT_SCOPE: Final = "structural_only"
ROUTINE_READ_SUMMARY_DETAIL_GAP: Final = "routine_read_detail_omitted"
ROUTINE_READ_SUMMARY_ALLOWED_GAPS: Final = frozenset(
    {"content_unselected", "observation_input_loss"}
)
SELECTION_ROUTE_KEYS: Final = (
    "selection_task_id",
    "selection_session_id",
    "selection_writer_id",
    "selection_authority_generation",
)


def observation_selection_route(
    payload: object,
) -> tuple[str, str, str, str] | None:
    """Return the authenticated selection route carried by an envelope.

    Route fields form one closed group.  An envelope from the legacy path may
    omit the group, while a selected envelope must carry every field so a
    buffered row cannot be silently rebound to a later task or authority.
    """

    if not isinstance(payload, Mapping):
        raise _invalid("invalid_event_value_type")
    mapping = cast(Mapping[str, JsonValue], payload)
    present = tuple(key in mapping for key in SELECTION_ROUTE_KEYS)
    if not any(present):
        return None
    if not all(present):
        raise _invalid("invalid_event_value_type")
    raw_task, raw_session, raw_writer, raw_generation = (
        mapping[key] for key in SELECTION_ROUTE_KEYS
    )
    try:
        selected_task = str(task_id(raw_task))
        selected_session = str(session_id(raw_session))
        selected_writer = str(writer_id(raw_writer))
        if type(raw_generation) is not str:
            raise ProtocolValueError("invalid_digest")
        selected_generation = validate_sha256_digest(raw_generation)
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise _invalid("invalid_event_value_type") from exc
    return selected_task, selected_session, selected_writer, selected_generation


_PROTECTION_REFERENCE_KINDS: Final = (
    ("obl_", IdKind.OBLIGATION),
    ("clm_", IdKind.CLAIM),
    ("fnd_", IdKind.FINDING),
)


def validate_observation_protection_reference(value: object) -> str:
    """Validate the optional structural reference for one protected read.

    The value is intentionally checked for identifier shape only. Existence
    and authorization belong to the local read-protection store, which keeps
    this envelope module independent from that store's domain adapter.
    """

    if type(value) is not str:
        raise _invalid("invalid_event_value_type")
    for prefix, kind in _PROTECTION_REFERENCE_KINDS:
        if value.startswith(prefix):
            try:
                return str(validate_id(kind, value))
            except (ProtocolValueError, TypeError, ValueError) as exc:
                raise _invalid("invalid_event_value_type") from exc
    raise _invalid("invalid_event_value_type")


_STRUCTURAL_KEYS: Final = frozenset(
    {
        "tool_name",
        "runner_class",
        "action",
        "exit_status",
        "correlation_id",
        "changed_paths_digest",
        "result_status",
        "permission_decision",
        "subagent_id",
        "claim_kind",
        "event_ordinal",
        "duration_ms",
        "attempt",
        "success",
        "denied",
        "truncated",
        "source_lag_ms",
        "hook_name",
        "stream_kind",
        "command_digest",
        "command_commitment",
        "argv_digest",
        "cwd_commitment",
        "file_count",
        "bytes_touched",
        "tool_call_id",
        "parent_tool_call_id",
        "lineage_child_task_id",
        "lineage_child_session_id",
        "lineage_child_writer_id",
        "lineage_parent_task_id",
        "permission_kind",
        "decision_reason_code",
        "mapping_hint",
        "capability_profile_id",
        "codex_version",
        "cursor_version",
        "model_id",
        "model_effort",
        "pairing_mode",
        "correlation_kind",
        "generation_id",
        "summary_count",
        "input_count",
        "member_digest",
        "fence",
        "provenance",
        "summary_schema",
        "selection_policy_version",
        "content_scope",
        "coverage_gaps",
        "subject_state_digest",
        "members",
        "selection_task_id",
        "selection_session_id",
        "selection_writer_id",
        "selection_authority_generation",
        "protection_reference",
        # Closed runtime facts a hook derives at the host boundary (#977).
        "install_target",
        "write_scope",
        "effective_user",
        # Whether a before/after fingerprint of the workspace saw this call change it (PR #1080).
        "workspace_effect",
        "workspace_write_scopes",
        # Digest-only facts for image tool results the hook saw (P3-2, issue #1013).
        "observed_images",
        # Keyed commitments to the simple commands of a compound or wrapped command, and what the
        # whole outcome means for one of them (#977): planned-verification matching only.
        "command_segment_commitments",
        "command_composition",
    }
)
_STRUCTURAL_TOKEN_KEYS: Final = frozenset(
    {
        "cursor_version",
        "model_id",
        "model_effort",
        "pairing_mode",
        "correlation_kind",
        "generation_id",
        "provenance",
        "summary_schema",
        "selection_policy_version",
        "content_scope",
        "subject_state_digest",
        "selection_task_id",
        "selection_session_id",
        "selection_writer_id",
        "selection_authority_generation",
        "protection_reference",
        "runner_class",
    }
)
_RUNNER_CLASSES: Final = frozenset(
    {"exploration", "test", "build", "lint", "typecheck", "vcs", "other", "compound"}
)
_RUNTIME_FACT_VALUES: Final = {
    "install_target": frozenset(
        {"yoetz_runtime", "workspace_env", "private_env", "system", "unresolved"}
    ),
    "write_scope": WRITE_SCOPES,
    "effective_user": frozenset({"root", "non_root"}),
    "command_composition": frozenset({"single", "and_chain", "masked"}),
    "workspace_effect": WORKSPACE_EFFECTS,
}
# 32 segment commitments plus 48 domain-separated canonical commitments (ADR-045); a test pins
# this to ``domain.command_segments.MAX_COMMAND_COMMITMENTS``, which this module cannot import.
_MAX_COMMAND_SEGMENT_COMMITMENTS: Final = 80

# One image tool result as the hook recorded it: the SHA-256 and byte count of the decoded image,
# a media type sniffed from its bytes, and the header's pixel size when it could be read. No pixel
# ever enters the envelope. ``cli/hook_io`` produces exactly this shape (P3-2, issue #1013).
OBSERVED_IMAGE_MEDIA_TYPES: Final = frozenset(
    {"image/gif", "image/jpeg", "image/png", "image/unknown", "image/webp"}
)
MAX_OBSERVED_IMAGES: Final = 8
MAX_OBSERVED_IMAGE_DIMENSION: Final = 2_147_483_647
_MAX_OBSERVED_IMAGE_BYTES: Final = 2**53 - 1
_OBSERVED_IMAGE_KEYS: Final = frozenset(
    {"byte_count", "content_digest", "height", "media_type", "width"}
)


def _bounded_int(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise _invalid("invalid_event_value_type")
    return value


def validate_observed_images(value: object) -> tuple[JsonObject, ...]:
    """Validate the closed ``observed_images`` structural fact and return its items.

    At most ``MAX_OBSERVED_IMAGES`` objects, each with exactly ``content_digest`` (``sha256:``),
    a positive ``byte_count``, a closed ``media_type``, and either both pixel dimensions or none;
    ``image/unknown`` never carries dimensions.
    """

    if type(value) is tuple:
        items: tuple[object, ...] = cast(tuple[object, ...], value)
    elif type(value) is list:
        items = tuple(cast(list[object], value))
    else:
        raise _invalid("invalid_event_value_type")
    if not 1 <= len(items) <= MAX_OBSERVED_IMAGES:
        raise _invalid("invalid_event_value_type")
    result: list[JsonObject] = []
    for raw in items:
        if not isinstance(raw, Mapping):
            raise _invalid("invalid_event_value_type")
        item = cast(Mapping[str, object], raw)
        keys = set(item)
        if (
            not keys <= _OBSERVED_IMAGE_KEYS
            or not {
                "byte_count",
                "content_digest",
                "media_type",
            }
            <= keys
        ):
            raise _invalid("unknown_payload_field")
        digest = item["content_digest"]
        if type(digest) is not str:
            raise _invalid("invalid_event_value_type")
        try:
            validate_sha256_digest(digest)
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise _invalid("invalid_event_value_type") from exc
        _bounded_int(item["byte_count"], 1, _MAX_OBSERVED_IMAGE_BYTES)
        media = item["media_type"]
        if type(media) is not str or media not in OBSERVED_IMAGE_MEDIA_TYPES:
            raise _invalid("invalid_event_value_type")
        sized = {"width", "height"} & keys
        if sized and (sized != {"width", "height"} or media == "image/unknown"):
            raise _invalid("invalid_event_value_type")
        for side in sized:
            _bounded_int(item[side], 1, MAX_OBSERVED_IMAGE_DIMENSION)
        result.append(JsonObject(dict(cast(Mapping[str, JsonValue], item))))
    return tuple(result)


_PROSE_KEYS: Final = frozenset(
    {
        "transcript",
        "reasoning",
        "content_full",
        "content",
        "message",
        "output",
        "stderr",
        "stdout",
        "prompt",
        "hidden_reasoning",
        "thinking",
        "raw_text",
        "body",
        "text",
        "command",
        "argv",
        "cwd",
        "path",
        "paths",
        "working_directory",
    }
)


class ObservationSource(str, Enum):  # noqa: UP042 - exact durable wire enum
    CLAUDE_HOOK = "claude_hook"
    CODEX_HOOK = "codex_hook"
    CODEX_SESSION_STREAM = "codex_session_stream"
    CURSOR_HOOK = "cursor_hook"


class ObservationLifecycle(str, Enum):  # noqa: UP042 - exact durable wire enum
    ACTIVE = "active"
    DEGRADED = "degraded"
    STALE = "stale"
    STOPPED = "stopped"


# Retryable ingest-rejection reason for designed back-pressure (#351): the
# observation ledger deferred the append behind an ADR-022 check-acquisition or
# frozen-case barrier (or equivalent transient bundle/frontier contention). It
# is deliberately not an ObservationGapCode — a deferral is expected
# coordination, never a current coverage gap, and must not project into
# observation status, advice, coverage, or receipt inputs. The durable outbox
# simply keeps the row pending and retries after the barrier clears.
OBSERVATION_BACKPRESSURE_REASON: Final = "operation_pending"
# A native content capture has crossed the authenticated service boundary and
# its encrypted manifests plus a retry ticket are durable, but the structural
# envelope has deliberately not advanced the observation cursor yet.  Hooks
# may safely leave the row pending under this reason; it is distinct from
# ``operation_pending`` because the latter says nothing about content
# retention.
OBSERVATION_CONTENT_CAPTURE_PENDING_REASON: Final = "content_capture_pending"
# A native handoff normally completes inside the hook drain that staged it, and
# a committed or terminally refused structural row retires its own ticket.  Only
# a handoff at least this old is compared with the structural rows that could
# still consume it, so a handoff whose own drain is still in progress is never
# retired as stranded.  This is half of the default pending-age ceiling: a
# stranded handoff becomes eligible before it alone can hold oldest-age pressure
# at the hard limit, and the READY sweep retires it on its next maintenance turn
# (#836).
CAPTURE_HANDOFF_RECONCILE_AGE_MS: Final = 30_000


class CaptureHandoffRetirementStage(str, Enum):  # noqa: UP042 - stable diagnostic value
    """The bounded transition that retired an unfinished native capture handoff."""

    # The structural row committed through this delivery without consuming the
    # handoff: its content was blocked, unauthorized, or fenced, or the handoff
    # was staged after the row had passed its capture fence.
    STRUCTURAL_COMMITTED = "structural_committed"
    # The structural row was refused terminally after its handoff was matched.
    STRUCTURAL_REFUSED = "structural_refused"
    # The READY maintenance sweep, independent of native admission.
    SWEEP = "sweep"
    # The exact-task reconciliation a new CHECK runs at the capture barrier.
    CHECK_PREFLIGHT = "check_preflight"


class CaptureHandoffRetirementReason(str, Enum):  # noqa: UP042 - stable diagnostic value
    """Why a handoff can no longer be consumed by its structural row."""

    CONTENT_NOT_ADMITTED = "content_not_admitted"
    TERMINAL_REFUSAL = "terminal_refusal"
    STRUCTURAL_ROW_ABSENT = "structural_row_absent"
    STRUCTURAL_ROW_QUARANTINED = "structural_row_quarantined"
    AUTHORITY_ABSENT = "authority_absent"
    AUTHORITY_INACTIVE = "authority_inactive"
    RUNTIME_DISABLED = "runtime_disabled"
    AUTHORITY_GENERATION_CHANGED = "authority_generation_changed"
    PROFILE_UNSELECTED = "profile_unselected"


class ObservationGapCode(str, Enum):  # noqa: UP042 - exact durable wire enum
    UNPAIRED_EVENT = "unpaired_event"
    UNSUPPORTED_EVENT = "unsupported_event"
    UNSUPPORTED_FORMAT = "unsupported_format"
    TRUNCATED_PAYLOAD = "truncated_payload"
    SERVICE_UNAVAILABLE = "service_unavailable"
    VAULT_LOCKED = "vault_locked"
    LEDGER_REJECTED = "ledger_rejected"
    DEDUP_CONFLICT = "dedup_conflict"
    CURSOR_STALE = "cursor_stale"
    CONSENT_MISSING = "consent_missing"
    CONSENT_REVOKED = "consent_revoked"
    SOURCE_LAG = "source_lag"
    MAPPING_MISSING = "mapping_missing"
    MISSING_SUBAGENT_IDENTITY = "missing_subagent_identity"
    SESSION_SUPERSEDED = "session_superseded"
    OUTBOX_OVERFLOW = "outbox_overflow"
    OBSERVATION_INPUT_LOSS = "observation_input_loss"
    OUTBOX_QUARANTINED = "outbox_quarantined"
    OBSERVATION_STORAGE_CORRUPT = "observation_storage_corrupt"
    QUARANTINE_DETAIL_EVICTED = "quarantine_detail_evicted"
    CONTENT_CAPTURE_UNAVAILABLE = "content_capture_unavailable"
    CAPTURE_BUDGET_EXHAUSTED = "capture_budget_exhausted"
    CONTENT_CAPTURE_PROFILE_MISMATCH = "content_capture_profile_mismatch"
    CONTENT_UNSELECTED = "content_unselected"
    CONTENT_REDACTED = "content_redacted"
    ROUTINE_READ_SUMMARY_DETAIL_OMITTED = "routine_read_detail_omitted"
    ROUTINE_READ_SUMMARY_INVALID = "routine_read_summary_invalid"
    # Distinct from ``routine_read_summary_invalid`` above, which describes a
    # delivered summary envelope that materialization refused.  This one
    # describes a summary that was never built: the admission flush refused one
    # buffered lane, so its members were admitted individually instead of being
    # represented by a bounded summary account (issue #753).
    ROUTINE_SUMMARY_INVALID = "routine_summary_invalid"
    # One host hook event whose body exceeded the trusted stdin cap and was not
    # admitted as a structural row. Distinct from ``truncated_payload``, which is
    # a payload that was admitted and then clipped after parsing. Every host
    # stops here when the body does not fit the skim cap or the skim cannot
    # validate a complete document (#667; Codex and Claude Code skim since tb4n1).
    PAYLOAD_TOO_LARGE = "payload_too_large"
    # One host hook event whose complete body fit the skim cap but not, even
    # without its image bytes, the trusted cap. The structural row keeps closed
    # identity and carries no native content. A FinishUP-owned tool records no gap:
    # its content is never captured. Distinct from ``payload_too_large``, which
    # minted no row, and from ``truncated_payload``, which clipped an
    # already-admitted body (#667, tb4n1 B5).
    PAYLOAD_CONTENT_OMITTED = "payload_content_omitted"
    SELECTION_ROUTE_CHANGED = "selection_route_changed"
    POLICY_UNTRUSTED = "policy_untrusted"
    VERIFICATION_STALE = "verification_stale"
    COMPOUND_OUTCOME_UNAVAILABLE = "compound_outcome_unavailable"
    NETWORK_CHECK_UNSUPPORTED = "network_check_unsupported"


# Gap codes that describe a currently unhealthy observation path.  Other gap codes remain
# visible coverage limitations, but do not by themselves turn a healthy, draining observation
# session into ``degraded``.  Keep this in the observation domain so the local fallback store,
# the SQLite store, and the lifecycle policy use the same classification (#974).
MATERIAL_OBSERVATION_GAPS: Final[frozenset[str]] = frozenset(
    {
        ObservationGapCode.SERVICE_UNAVAILABLE.value,
        ObservationGapCode.VAULT_LOCKED.value,
        ObservationGapCode.UNSUPPORTED_EVENT.value,
        ObservationGapCode.UNSUPPORTED_FORMAT.value,
        ObservationGapCode.SOURCE_LAG.value,
        ObservationGapCode.CURSOR_STALE.value,
    }
)


class ObservationContentKind(str, Enum):  # noqa: UP042 - exact durable wire enum
    VISIBLE_USER_MESSAGE = "visible_user_message"
    VISIBLE_ASSISTANT_MESSAGE = "visible_assistant_message"
    VISIBLE_SUBAGENT_MESSAGE = "visible_subagent_message"
    TOOL_INPUT = "tool_input"
    TOOL_OUTPUT = "tool_output"
    CHANGED_FILE = "changed_file"
    WORKSPACE_DIFF = "workspace_diff"
    APPROVED_CHECK_OUTPUT = "approved_check_output"
    UNSUPPORTED_VISIBLE_PAYLOAD = "unsupported_visible_payload"
    WORKSPACE_LOCATOR = "workspace_locator"


@dataclass(frozen=True, slots=True)
class ObservationCaptureTicket:
    """Metadata-only handoff for encrypted native content awaiting ledger ingest.

    The ticket never contains plaintext.  Its source, cursor, phase identity,
    profile, and local authority generation are all bound to the encrypted
    manifest object IDs, so a retry cannot borrow content from another event,
    consent generation, or host session.  Codex hook captures are deliberately
    profile-less; the ``source`` field is their closed source qualification.
    """

    workspace_commitment: str
    task_id: str
    finishup_session_id: str
    session_commitment: str
    source: ObservationSource
    source_identity: str
    cursor: ObservationCursor
    logical_identity: str
    content_capture_profile: str | None
    authority_generation: str
    object_ids: tuple[str, ...]
    captured_at: Timestamp
    state: Literal["staging", "pending", "revoked"] = "staging"
    expected_parts: tuple[ObservationCapturePart, ...] = ()

    def __post_init__(self) -> None:
        validate_commitment(self.workspace_commitment)
        object.__setattr__(self, "task_id", task_id(self.task_id))
        object.__setattr__(self, "finishup_session_id", session_id(self.finishup_session_id))
        validate_commitment(self.session_commitment)
        if type(self.source) is not ObservationSource or self.source not in {
            ObservationSource.CLAUDE_HOOK,
            ObservationSource.CODEX_HOOK,
            ObservationSource.CURSOR_HOOK,
        }:
            raise _invalid("invalid_event_enum")
        object.__setattr__(self, "source_identity", _token(self.source_identity))
        if type(self.cursor) is not ObservationCursor:
            raise _invalid()
        object.__setattr__(self, "logical_identity", _token(self.logical_identity))
        if self.content_capture_profile is None:
            if self.source is not ObservationSource.CODEX_HOOK:
                raise _invalid("invalid_event_value_type")
        elif not content_capture_profile_matches_source(
            self.source.value, self.content_capture_profile
        ):
            raise _invalid("invalid_event_value_type")
        try:
            validate_sha256_digest(self.authority_generation)
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise _invalid("invalid_event_value_type") from exc
        if type(self.object_ids) is not tuple or len(self.object_ids) > 16:
            raise _invalid()
        if self.state not in {"staging", "revoked"} and not self.object_ids:
            raise _invalid()
        normalized = tuple(sorted({object_id(item) for item in self.object_ids}, key=str.encode))
        if normalized != self.object_ids:
            raise _invalid("duplicate_set_member")
        if type(self.captured_at) is not Timestamp:
            raise _invalid("invalid_timestamp")
        if self.state not in {"staging", "pending", "revoked"}:
            raise _invalid("invalid_event_value_type")
        if type(self.expected_parts) is not tuple or len(self.expected_parts) > 16:
            raise _invalid()
        normalized_parts: list[ObservationCapturePart] = []
        for raw_part in self.expected_parts:
            if type(raw_part) is not tuple or len(raw_part) != 5:
                raise _invalid()
            raw_kind, raw_correlation, raw_source, raw_index, raw_count = raw_part
            try:
                kind = ObservationContentKind(raw_kind)
                correlation = _token(raw_correlation)
                source = raw_source
                validate_commitment(source)
                index = _nonnegative(raw_index, maximum=15)
                count = _positive(raw_count, maximum=16)
            except (ProtocolValueError, TypeError, ValueError) as exc:
                raise _invalid() from exc
            if index >= count:
                raise _invalid()
            normalized_parts.append((kind.value, correlation, source, index, count))
        expected_parts = tuple(
            sorted(
                normalized_parts,
                key=lambda item: (
                    item[0].encode("utf-8"),
                    item[1].encode("utf-8"),
                    item[2].encode("utf-8"),
                    item[3],
                    item[4],
                ),
            )
        )
        if len(set(expected_parts)) != len(expected_parts):
            raise _invalid("duplicate_set_member")
        if expected_parts != self.expected_parts:
            raise _invalid("unsorted_set_field")
        if self.state == "pending" and not expected_parts:
            raise _invalid()
        object.__setattr__(self, "expected_parts", expected_parts)


@dataclass(frozen=True, slots=True)
class ObservationCaptureBacklog:
    """Read-only accounting for unfinished native content handoffs.

    Capture tickets intentionally expose metadata only.  ``byte_count`` is the
    sum of the secret-scanned plaintext byte counts recorded in their manifests;
    encrypted envelope sizes are not part of the capture budget.  The backlog
    includes both staging and pending tickets and excludes revoked or committed
    tickets.  ``oldest_receipt_time`` is the durable ticket capture timestamp,
    so callers can derive an age against their own trusted clock without the
    adapter reading wall-clock state.

    Until a trusted envelope proves that a handoff is optional, every active
    ticket is treated as protected by the capture admission layer.  This DTO
    therefore reports only aggregate usage; it does not grant optional detail
    or turn a larger structural queue into additional content authority.
    """

    count: int
    byte_count: int
    oldest_receipt_time: Timestamp | None

    def __post_init__(self) -> None:
        if type(self.count) is not int or self.count < 0:
            raise _invalid("invalid_event_value_type")
        if type(self.byte_count) is not int or self.byte_count < 0:
            raise _invalid("invalid_event_value_type")
        if self.oldest_receipt_time is not None and type(self.oldest_receipt_time) is not Timestamp:
            raise _invalid("invalid_timestamp")
        if self.count == 0 and self.oldest_receipt_time is not None:
            raise _invalid("invalid_event_value_type")

    @property
    def ticket_count(self) -> int:
        """Alias used by pressure readers that distinguish tickets from rows."""

        return self.count

    @property
    def captured_bytes(self) -> int:
        """Alias for the aggregate secret-scanned content byte count."""

        return self.byte_count

    @property
    def protected_count(self) -> int:
        """All active handoffs are protected until trusted classification exists."""

        return self.count

    @property
    def protected_bytes(self) -> int:
        """All active handoff bytes remain in the protected reserve."""

        return self.byte_count


def observation_capture_ticket_id(ticket: ObservationCaptureTicket) -> str:
    """Derive the idempotency identity for one staged native capture."""

    if type(ticket) is not ObservationCaptureTicket:
        raise _invalid()
    return canonical_digest(
        JsonObject(
            {
                "workspace_commitment": ticket.workspace_commitment,
                "task_id": ticket.task_id,
                # Frozen legacy identifier (ADR-048): a key of the digested ticket identity.
                "yoetz_session_id": ticket.finishup_session_id,
                "session_commitment": ticket.session_commitment,
                "source": ticket.source.value,
                "source_identity": ticket.source_identity,
                "cursor": observation_cursor_to_json(ticket.cursor),
                "logical_identity": ticket.logical_identity,
                "content_capture_profile": ticket.content_capture_profile,
                "authority_generation": ticket.authority_generation,
            }
        )
    )


def observation_capture_part_descriptors(
    chunks: tuple[ObservationContentChunk, ...],
) -> tuple[ObservationCapturePart, ...]:
    """Return the exact structural descriptors a native handoff must contain."""

    if type(chunks) is not tuple:
        raise _invalid()
    parts = tuple(
        (
            chunk.content_kind.value,
            chunk.correlation_identity,
            chunk.source_commitment,
            chunk.part_index,
            chunk.part_count,
        )
        for chunk in chunks
    )
    return tuple(
        sorted(
            parts,
            key=lambda item: (
                item[0].encode("utf-8"),
                item[1].encode("utf-8"),
                item[2].encode("utf-8"),
                item[3],
                item[4],
            ),
        )
    )


class ObservationIngestDisposition(str, Enum):  # noqa: UP042 - exact durable wire enum
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"


def _invalid(reason: str = "invalid_event_value_type") -> ProtocolValueError:
    if reason not in PROTOCOL_REASON_CODES:
        reason = "invalid_event_value_type"
    return ProtocolValueError(reason)


def _token(value: object) -> str:
    if type(value) is not str or _TOKEN_RE.fullmatch(value) is None:
        raise _invalid()
    return value


def _gap_code(value: object) -> str:
    if type(value) is ObservationGapCode:
        return value.value
    if type(value) is not str or _GAP_RE.fullmatch(value) is None:
        raise _invalid("invalid_known_gap")
    return value


def _nonnegative(value: object, *, maximum: int = _MAX_SAFE_INTEGER) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise _invalid()
    return value


def _positive(value: object, *, maximum: int = _MAX_SAFE_INTEGER) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise _invalid()
    return value


def _exact_tuple(value: object, *, maximum: int) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise _invalid()
    result = cast(tuple[object, ...], value)
    if len(result) > maximum:
        raise _invalid()
    return result


def _sorted_unique_tokens(value: object, *, maximum: int) -> tuple[str, ...]:
    raw = _exact_tuple(value, maximum=maximum)
    result: list[str] = []
    previous: str | None = None
    for item in raw:
        member = _token(item)
        if previous is not None and member.encode("ascii") <= previous.encode("ascii"):
            raise _invalid("duplicate_set_member" if member == previous else "unsorted_set_field")
        result.append(member)
        previous = member
    return tuple(result)


def _sorted_unique_gap_codes(value: object, *, maximum: int = _MAX_GAP_CODES) -> tuple[str, ...]:
    raw = _exact_tuple(value, maximum=maximum)
    result: list[str] = []
    previous: str | None = None
    for item in raw:
        member = _gap_code(item)
        if previous is not None and member.encode("ascii") <= previous.encode("ascii"):
            raise _invalid("duplicate_set_member" if member == previous else "unsorted_set_field")
        result.append(member)
        previous = member
    return tuple(result)


def _looks_like_path(value: str) -> bool:
    if "\x00" in value or "\r" in value or "\n" in value:
        return True
    if value.startswith(("/", "\\", "./", "../", "~/", "~\\")):
        return True
    if len(value) >= 3 and value[1] == ":" and value[0].isalpha() and value[2] in {"/", "\\"}:
        return True
    return False


def _reject_path_like(value: object) -> None:
    if type(value) is str:
        if _looks_like_path(value):
            raise _invalid()
        return
    if type(value) is tuple:
        for item in cast(tuple[object, ...], value):
            _reject_path_like(item)
        return
    if type(value) is JsonObject:
        for item in value.values():
            _reject_path_like(item)


def _command_segment_commitments(value: object) -> None:
    """A non-empty, bounded, ascending set of ``hmac-sha256:`` segment commitments."""

    if type(value) is not tuple:
        raise _invalid("invalid_event_value_type")
    items = cast(tuple[object, ...], value)
    if not 1 <= len(items) <= _MAX_COMMAND_SEGMENT_COMMITMENTS:
        raise _invalid("invalid_event_value_type")
    previous: str | None = None
    for item in items:
        if type(item) is not str:
            raise _invalid("invalid_event_value_type")
        try:
            validate_commitment(item)
        except ProtocolValueError as exc:
            raise _invalid("invalid_event_value_type") from exc
        if previous is not None and item <= previous:
            raise _invalid("duplicate_set_member" if item == previous else "unsorted_set_field")
        previous = item


def _structural_payload(value: object) -> JsonObject:
    if type(value) is not JsonObject:
        try:
            payload = JsonObject(value)
        except ProtocolValueError as exc:
            raise _invalid() from exc
    else:
        payload = value
    if any(key in _PROSE_KEYS for key in payload):
        raise _invalid("unknown_payload_field")
    if any(key not in _STRUCTURAL_KEYS for key in payload):
        raise _invalid("unknown_payload_field")
    for key, item in payload.items():
        if key.endswith(("_path", "_paths", "_cwd", "_directory")):
            raise _invalid("unknown_payload_field")
        if key in _STRUCTURAL_TOKEN_KEYS:
            _token(item)
        if key == "runner_class" and item not in _RUNNER_CLASSES:
            raise _invalid("invalid_event_value_type")
        if key in _RUNTIME_FACT_VALUES and item not in _RUNTIME_FACT_VALUES[key]:
            raise _invalid("invalid_event_value_type")
        if key == "observed_images":
            validate_observed_images(item)
        if key == "workspace_write_scopes":
            from finishup.domain.workspace_effect import workspace_write_scopes

            if workspace_write_scopes(item) is None:
                raise _invalid("invalid_event_value_type")
        if key == "protection_reference":
            validate_observation_protection_reference(item)
        if key == "command_commitment":
            if type(item) is not str:
                raise _invalid("invalid_event_value_type")
            try:
                validate_commitment(item)
            except ProtocolValueError as exc:
                raise _invalid("invalid_event_value_type") from exc
        if key == "command_segment_commitments":
            _command_segment_commitments(item)
        _reject_path_like(item)
    encoded = canonical_encode(payload)
    if len(encoded) > _MAX_STRUCTURAL_BYTES:
        raise _invalid()
    return payload


def _content_object_refs(value: object) -> tuple[str, ...]:
    raw = _exact_tuple(value, maximum=_MAX_CONTENT_REFS)
    result: list[str] = []
    previous: str | None = None
    for item in raw:
        if type(item) is not str:
            raise _invalid()
        if item.startswith("hmac-sha256:"):
            member = validate_commitment(item)
        elif item.startswith("sha256:"):
            member = validate_sha256_digest(item)
        else:
            # Object IDs use the ordinary obj_ prefix; commitments stay path-free.
            if not item.isascii() or not 1 <= len(item) <= 128 or _looks_like_path(item):
                raise _invalid()
            member = item
        if previous is not None and member.encode("ascii") <= previous.encode("ascii"):
            raise _invalid("duplicate_set_member" if member == previous else "unsorted_set_field")
        result.append(member)
        previous = member
    return tuple(result)


def _ranked_finding_ids(value: object) -> tuple[FindingId, ...]:
    raw = _exact_tuple(value, maximum=_MAX_RANKED_FINDINGS)
    result: list[FindingId] = []
    seen: set[str] = set()
    for item in raw:
        member = finding_id(item)
        if member in seen:
            raise _invalid("duplicate_set_member")
        seen.add(member)
        result.append(member)
    return tuple(result)


def _advice_text(value: object, *, maximum: int) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise _invalid()
    if _ADVICE_TEXT_RE.fullmatch(value) is None or _looks_like_path(value):
        raise _invalid()
    lowered = value.lower()
    for banned in ("secret", "password", "token=", "api_key", "bearer ", "/users/", "c:\\"):
        if banned in lowered:
            raise _invalid()
    return value


def _evidence_refs(value: object) -> tuple[str, ...]:
    raw = _exact_tuple(value, maximum=_MAX_EVIDENCE_REFS)
    result: list[str] = []
    previous: str | None = None
    for item in raw:
        member = _token(item)
        if previous is not None and member.encode("ascii") <= previous.encode("ascii"):
            raise _invalid("duplicate_set_member" if member == previous else "unsorted_set_field")
        result.append(member)
        previous = member
    return tuple(result)


def _advice_origin(value: object) -> Literal["deterministic", "semantic_model_derived"]:
    if type(value) is not str or value not in _ADVICE_ORIGINS:
        raise _invalid("invalid_event_enum")
    return cast(Literal["deterministic", "semantic_model_derived"], value)


def _source_coverage(value: object) -> Mapping[ObservationSource, bool]:
    if not isinstance(value, Mapping):
        raise _invalid()
    mapping = cast(Mapping[object, object], value)
    if len(mapping) > _MAX_SOURCE_COVERAGE:
        raise _invalid()
    result: dict[ObservationSource, bool] = {}
    for raw_key, raw_present in mapping.items():
        if type(raw_key) is ObservationSource:
            key = raw_key
        elif type(raw_key) is str:
            try:
                key = ObservationSource(raw_key)
            except ValueError as exc:
                raise _invalid("invalid_event_enum") from exc
        else:
            raise _invalid("invalid_event_enum")
        if type(raw_present) is not bool:
            raise _invalid()
        if key in result:
            raise _invalid("duplicate_set_member")
        result[key] = raw_present
    return MappingProxyType(result)


def workspace_commitment_from_path(key_material: bytes, path: str) -> str:
    """Return an HMAC-SHA-256 commitment for exact filesystem-encoded path bytes.

    The commitment never embeds the raw path. Callers must supply exact key material
    (for example ``K_lookup`` / commitment MAC bytes). Empty or control-bearing paths
    are rejected before hashing.
    """

    if type(key_material) is not bytes or not 16 <= len(key_material) <= 64:
        raise _invalid("invalid_commitment")
    if type(path) is not str or not path or "\x00" in path:
        raise _invalid()
    digest = hmac.new(
        key_material,
        OBSERVATION_WORKSPACE_DOMAIN + os.fsencode(path),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{digest}"


def stream_line_commitment(key_material: bytes, content: bytes) -> str:
    """Keyed HMAC over one session-stream line body (never labeled as plain sha256)."""

    if type(key_material) is not bytes or not 16 <= len(key_material) <= 64:
        raise _invalid("invalid_commitment")
    if type(content) is not bytes:
        raise _invalid()
    digest = hmac.new(
        key_material,
        OBSERVATION_STREAM_LINE_DOMAIN + content,
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{digest}"


def hook_source_commitment(key_material: bytes, source_identity: str) -> str:
    """Keyed HMAC over a hook source-identity token for cursor last-commitment."""

    if type(key_material) is not bytes or not 16 <= len(key_material) <= 64:
        raise _invalid("invalid_commitment")
    if type(source_identity) is not str or not source_identity or "\x00" in source_identity:
        raise _invalid()
    digest = hmac.new(
        key_material,
        OBSERVATION_HOOK_COMMITMENT_DOMAIN + source_identity.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{digest}"


def _shell_wrapped_command(argv: list[str]) -> str | None:
    """Return ``X`` for a host shell wrapper such as ``/bin/bash -lc X`` or ``sh -c X``."""

    if len(argv) != 3:
        return None
    shell = argv[0].replace("\\", "/").rsplit("/", 1)[-1]
    if shell not in _SHELL_WRAPPERS or _SHELL_COMMAND_FLAG_RE.fullmatch(argv[1]) is None:
        return None
    return argv[2]


def _collapse_unquoted_blanks(text: str) -> str:
    """Collapse runs of unquoted spaces and tabs to one space and trim them at both ends.

    Shell quoting and escapes are tracked so quoted or escaped blanks, quote characters, and line
    breaks (command separators) are kept byte for byte: the result has the same shell meaning.
    """

    output: list[str] = []
    quote: str | None = None
    escaped = False
    pending_blank = False
    for char in text:
        if quote is None and not escaped and char in " \t":
            pending_blank = True
            continue
        if pending_blank and output:
            output.append(" ")
        pending_blank = False
        output.append(char)
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote is None and char in "'\"":
            quote = char
        elif char == quote:
            quote = None
    return "".join(output)


def normalize_observed_command(value: object) -> str | None:
    """Light, semantics-preserving normalization of a host command argument, or ``None``.

    Accepts the command string (``tool_input.cmd`` / ``command``) or an argv list. Only rewrites
    that cannot change what the shell runs are applied: unquoted runs of spaces and tabs collapse
    to one space, and a host shell wrapper (``/bin/bash -lc '...'``, ``bash -lc``, ``sh -c``,
    including the WSL 2 ``bash -lc`` form) is stripped when its command argument is exact: an argv
    wrapper always, a string wrapper only when it is the canonical single-quoted form, so an
    outer shell cannot have expanded anything first. Quoting, expansions, escapes and line breaks
    are never rewritten, so two commands with different meaning never share an identity; a missed
    equivalence only keeps two identities apart. The result exists only to be committed; it is
    never stored, displayed, or sent.
    """

    text: str | None = None
    if type(value) is str:
        text = value
    elif type(value) is list or type(value) is tuple:
        items = list(cast(list[object] | tuple[object, ...], value))
        if (
            not items
            or len(items) > _MAX_OBSERVED_ARGV
            or any(type(item) is not str for item in items)
        ):
            return None
        argv = cast(list[str], items)
        text = _shell_wrapped_command(argv) or shlex.join(argv)
    if text is None or "\x00" in text or len(text) > _MAX_OBSERVED_COMMAND_CHARS:
        return None
    for _ in range(3):
        text = _collapse_unquoted_blanks(text)
        try:
            words = shlex.split(text, posix=True)
        except ValueError:
            return text or None
        inner = _shell_wrapped_command(words)
        # ``shlex.join`` single-quotes its argument, so equality proves the wrapper's command
        # argument reached the inner shell literally, with nothing expanded by an outer shell.
        if inner is None or shlex.join(words) != text:
            return text or None
        text = inner
    return None


def observed_command_commitment(key_material: bytes, command: str) -> str:
    """Installation-keyed HMAC commitment to one normalized command (never plain sha256)."""

    if type(key_material) is not bytes or not 16 <= len(key_material) <= 64:
        raise _invalid("invalid_commitment")
    if type(command) is not str or not command or "\x00" in command:
        raise _invalid()
    digest = hmac.new(
        key_material,
        OBSERVATION_COMMAND_COMMITMENT_DOMAIN + command.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{digest}"


@dataclass(frozen=True, slots=True)
class ObservationContentChunk:
    """Bounded ephemeral plaintext accepted only by ready-service ingest.

    Chunks are never written to the local structural outbox. They exist long
    enough for the ready service to assemble and encrypt a captured-content
    object, then the mutable byte buffer is discarded by the caller.
    """

    content_kind: ObservationContentKind
    correlation_identity: str
    source_commitment: str
    media_type: str
    part_index: int
    part_count: int
    content: bytes
    redacted: bool = False

    def __post_init__(self) -> None:
        if type(self.content_kind) is not ObservationContentKind:
            raise _invalid("invalid_event_enum")
        object.__setattr__(self, "correlation_identity", _token(self.correlation_identity))
        validate_commitment(self.source_commitment)
        if (
            type(self.media_type) is not str
            or len(self.media_type) > 128
            or _MEDIA_TYPE_RE.fullmatch(self.media_type) is None
        ):
            raise _invalid()
        object.__setattr__(self, "part_index", _nonnegative(self.part_index, maximum=15))
        object.__setattr__(self, "part_count", _positive(self.part_count, maximum=16))
        if self.part_index >= self.part_count:
            raise _invalid()
        if (
            type(self.content) is not bytes
            or not self.content
            or len(self.content) > _MAX_CONTENT_CHUNK_BYTES
            or type(self.redacted) is not bool
        ):
            raise _invalid()

    def __repr__(self) -> str:
        return (
            "ObservationContentChunk("
            f"kind={self.content_kind.value!r}, "
            f"correlation_identity={self.correlation_identity!r}, "
            f"part={self.part_index + 1}/{self.part_count}, "
            f"bytes={len(self.content)}, redacted={self.redacted})"
        )

    __str__ = __repr__


_NATIVE_CONTENT_CORRELATION_KEYS: Final = (
    "tool_use_id",
    "tool_call_id",
    "correlation_id",
    "parent_tool_call_id",
)
_NATIVE_CONTENT_CORRELATION_SUFFIXES: Final = MappingProxyType(
    {
        ObservationContentKind.VISIBLE_USER_MESSAGE: frozenset({"user"}),
        ObservationContentKind.VISIBLE_ASSISTANT_MESSAGE: frozenset({"assistant"}),
        ObservationContentKind.VISIBLE_SUBAGENT_MESSAGE: frozenset({"subagent"}),
        ObservationContentKind.TOOL_INPUT: frozenset({"tool-input"}),
        ObservationContentKind.TOOL_OUTPUT: frozenset({"tool-output"}),
        ObservationContentKind.CHANGED_FILE: frozenset({"changed-file"}),
        ObservationContentKind.WORKSPACE_DIFF: frozenset({"diff", "patch"}),
        ObservationContentKind.UNSUPPORTED_VISIBLE_PAYLOAD: frozenset({"unsupported"}),
        ObservationContentKind.WORKSPACE_LOCATOR: frozenset({"workspace"}),
    }
)


def observation_content_binding_matches(
    envelope: ObservationEnvelope,
    *,
    content_kind: ObservationContentKind,
    correlation_identity: str | None,
    source_commitment: str | None,
) -> bool:
    """Check the historical materialization binding for an observation.

    Codex hook and session-stream observations predate the source-qualified
    content ticket and keep their replay behavior. Claude/Cursor ordinary
    content uses the exact native binding introduced for their profile arms.
    New ticketed capture must call
    :func:`observation_source_qualified_content_binding_matches` instead.
    """

    if envelope.source not in {
        ObservationSource.CLAUDE_HOOK,
        ObservationSource.CURSOR_HOOK,
    }:
        return True
    return _source_qualified_content_binding_matches(
        envelope,
        content_kind=content_kind,
        correlation_identity=correlation_identity,
        source_commitment=source_commitment,
    )


def _source_qualified_content_binding_matches(
    envelope: ObservationEnvelope,
    *,
    content_kind: ObservationContentKind,
    correlation_identity: str | None,
    source_commitment: str | None,
) -> bool:
    if envelope.source not in {
        ObservationSource.CLAUDE_HOOK,
        ObservationSource.CODEX_HOOK,
        ObservationSource.CURSOR_HOOK,
    }:
        return False
    if source_commitment != envelope.cursor.last_source_commitment:
        return False
    if type(correlation_identity) is not str or not correlation_identity:
        return False
    structural = envelope.structural_payload
    if correlation_identity in {
        value
        for key in _NATIVE_CONTENT_CORRELATION_KEYS
        for value in (structural.get(key),)
        if type(value) is str and value
    }:
        return True
    prefix = f"{envelope.source_identity}:"
    if not correlation_identity.startswith(prefix):
        return False
    suffix = correlation_identity[len(prefix) :]
    if (
        envelope.source is ObservationSource.CODEX_HOOK
        and suffix == "captured"
        and content_kind
        in {
            ObservationContentKind.TOOL_INPUT,
            ObservationContentKind.TOOL_OUTPUT,
        }
    ):
        # Preserve the pre-ticket Codex inline-capture label without widening
        # the Claude/Cursor binding vocabulary.
        return True
    return suffix in _NATIVE_CONTENT_CORRELATION_SUFFIXES.get(content_kind, frozenset())


def observation_source_qualified_content_binding_matches(
    envelope: ObservationEnvelope,
    *,
    content_kind: ObservationContentKind,
    correlation_identity: str | None,
    source_commitment: str | None,
) -> bool:
    """Check the closed source binding for a ticketed native capture.

    The caller cannot opt out of this check.  In particular, profileless
    Codex content is eligible only when its hook source identity, cursor
    commitment, and correlation label all match the same envelope.  Session
    stream content is intentionally outside this capture-only contract.
    """

    return _source_qualified_content_binding_matches(
        envelope,
        content_kind=content_kind,
        correlation_identity=correlation_identity,
        source_commitment=source_commitment,
    )


@dataclass(frozen=True, slots=True)
class ObservationContentManifest:
    """Trusted-local descriptor for one encrypted observation-content object.

    ``content_digest`` and ``content_bytes`` describe the secret-scanned bytes inside the
    encrypted manifest, not the encrypted envelope or its structural wrapper. Historical rows
    created before that binding was stored leave both values ``None`` and cannot earn captured
    evidence provenance until the service re-observes and backfills them. ``envelope_digest`` may
    be ``None`` only for lookup-only recovery of an orphaned manifest whose object inventory row
    is unavailable; such a descriptor cannot earn captured coverage.
    """

    object_id: str
    envelope_digest: str | None
    content_kind: ObservationContentKind
    part_index: int
    part_count: int
    redacted: bool
    content_digest: str | None = None
    content_bytes: int | None = None
    correlation_identity: str | None = None
    source_commitment: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "object_id", object_id(self.object_id))
        if self.envelope_digest is not None:
            validate_sha256_digest(self.envelope_digest)
        if type(self.content_kind) is not ObservationContentKind:
            raise _invalid("invalid_event_enum")
        object.__setattr__(self, "part_index", _nonnegative(self.part_index, maximum=15))
        object.__setattr__(self, "part_count", _positive(self.part_count, maximum=16))
        if self.part_index >= self.part_count or type(self.redacted) is not bool:
            raise _invalid()
        if (self.content_digest is None) != (self.content_bytes is None):
            raise _invalid()
        if self.content_digest is not None:
            validate_sha256_digest(self.content_digest)
            object.__setattr__(
                self,
                "content_bytes",
                _positive(self.content_bytes, maximum=_MAX_CONTENT_CHUNK_BYTES),
            )
        if self.correlation_identity is not None:
            object.__setattr__(
                self,
                "correlation_identity",
                _token(self.correlation_identity),
            )
        if self.source_commitment is not None:
            validate_commitment(self.source_commitment)


@dataclass(frozen=True, slots=True)
class ObservationInspectionSnapshot:
    """Immutable object bindings for one current changed-path inspection snapshot."""

    snapshot_id: str
    finishup_session_id: str
    subject_state_digest: str
    changed_paths_digest: str
    facts_object_id: str | None
    facts_content_digest: str | None
    facts_content_bytes: int | None
    excerpt_object_id: str | None
    excerpt_content_digest: str | None
    excerpt_content_bytes: int | None
    excerpt_redacted: bool
    excerpt_truncated: bool
    recorded_at: Timestamp

    def __post_init__(self) -> None:
        object.__setattr__(self, "snapshot_id", _token(self.snapshot_id))
        object.__setattr__(self, "finishup_session_id", session_id(self.finishup_session_id))
        validate_sha256_digest(self.subject_state_digest)
        validate_sha256_digest(self.changed_paths_digest)
        if type(self.recorded_at) is not Timestamp:
            raise _invalid("invalid_timestamp")
        if type(self.excerpt_redacted) is not bool or type(self.excerpt_truncated) is not bool:
            raise _invalid()
        if self.excerpt_object_id is None and (self.excerpt_redacted or self.excerpt_truncated):
            raise _invalid()
        for object_value, digest_value, byte_value in (
            (self.facts_object_id, self.facts_content_digest, self.facts_content_bytes),
            (self.excerpt_object_id, self.excerpt_content_digest, self.excerpt_content_bytes),
        ):
            if (object_value is None, digest_value is None, byte_value is None) not in {
                (True, True, True),
                (False, False, False),
            }:
                raise _invalid()
            if object_value is not None:
                object_id(object_value)
                validate_sha256_digest(cast(str, digest_value))
                _positive(byte_value, maximum=4_194_304)


def _content_chunks(value: object) -> tuple[ObservationContentChunk, ...]:
    raw = _exact_tuple(value, maximum=_MAX_CONTENT_CHUNKS)
    chunks: list[ObservationContentChunk] = []
    total = 0
    groups: dict[tuple[str, str, str, str], tuple[int, set[int]]] = {}
    for item in raw:
        if type(item) is not ObservationContentChunk:
            raise _invalid()
        chunks.append(item)
        total += len(item.content)
        key = (
            item.content_kind.value,
            item.correlation_identity,
            item.source_commitment,
            item.media_type,
        )
        expected, indexes = groups.setdefault(key, (item.part_count, set()))
        if expected != item.part_count or item.part_index in indexes:
            raise _invalid()
        indexes.add(item.part_index)
    if total > _MAX_CONTENT_TOTAL_BYTES:
        raise _invalid()
    return tuple(chunks)


@dataclass(frozen=True, slots=True)
class ObservationCursor:
    source_generation: int
    byte_position: int
    event_position: int
    last_source_commitment: str
    mapping_version: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_generation", _positive(self.source_generation))
        object.__setattr__(self, "byte_position", _nonnegative(self.byte_position))
        object.__setattr__(self, "event_position", _nonnegative(self.event_position))
        validate_commitment(self.last_source_commitment)
        object.__setattr__(self, "mapping_version", _token(self.mapping_version))

    def _compare_key(self) -> tuple[int, int, int]:
        return (self.source_generation, self.byte_position, self.event_position)

    def __lt__(self, other: object) -> bool | NotImplementedType:
        if type(other) is not ObservationCursor:
            return NotImplemented
        return self._compare_key() < other._compare_key()

    def __le__(self, other: object) -> bool | NotImplementedType:
        if type(other) is not ObservationCursor:
            return NotImplemented
        return self._compare_key() <= other._compare_key()

    def is_stale_relative_to(self, other: ObservationCursor) -> bool:
        if type(other) is not ObservationCursor:
            raise _invalid()
        if self.source_generation < other.source_generation:
            return True
        if self.source_generation > other.source_generation:
            return False
        return (self.byte_position, self.event_position) < (
            other.byte_position,
            other.event_position,
        )


@dataclass(frozen=True, slots=True, repr=False)
class ObservationEnvelope:
    session_commitment: str
    event_kind: str
    source_identity: str
    source: ObservationSource
    cursor: ObservationCursor
    receipt_time: Timestamp
    structural_payload: JsonObject
    content_object_refs: tuple[str, ...]
    gap_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_commitment(self.session_commitment)
        object.__setattr__(self, "event_kind", _token(self.event_kind))
        object.__setattr__(self, "source_identity", _token(self.source_identity))
        if type(self.source) is not ObservationSource:
            raise _invalid("invalid_event_enum")
        if type(self.cursor) is not ObservationCursor:
            raise _invalid()
        if type(self.receipt_time) is not Timestamp:
            raise _invalid("invalid_timestamp")
        object.__setattr__(self, "structural_payload", _structural_payload(self.structural_payload))
        object.__setattr__(
            self, "content_object_refs", _content_object_refs(self.content_object_refs)
        )
        object.__setattr__(self, "gap_codes", _sorted_unique_gap_codes(self.gap_codes))

    def __repr__(self) -> str:
        return (
            "ObservationEnvelope("
            f"source={self.source.value!r}, "
            f"event_kind={self.event_kind!r}, "
            f"source_identity={self.source_identity!r})"
        )

    __str__ = __repr__


RoutineReadSummaryPhase = Literal["pre", "post"]


@dataclass(frozen=True, slots=True)
class RoutineReadSummaryMember:
    """The identity of one source input represented by a routine-read summary.

    A member deliberately carries only native identity, cursor and phase.  In
    particular it never carries a command, path, prompt, output, or any other
    content that could turn a bounded accounting record into an implicit
    capture channel.
    """

    source_identity: str
    cursor: ObservationCursor
    tool_call_id: str | None
    phase: RoutineReadSummaryPhase
    receipt_time: Timestamp
    subject_state_digest: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_identity", _token(self.source_identity))
        if type(self.cursor) is not ObservationCursor:
            raise _invalid()
        if self.tool_call_id is not None:
            object.__setattr__(self, "tool_call_id", _token(self.tool_call_id))
        if self.phase not in {"pre", "post"}:
            raise _invalid("invalid_event_enum")
        if type(self.receipt_time) is not Timestamp:
            raise _invalid("invalid_timestamp")
        if self.subject_state_digest is not None:
            validate_sha256_digest(self.subject_state_digest)


def routine_read_summary_member_to_json(value: RoutineReadSummaryMember) -> JsonObject:
    """Encode one summary member without exposing host content."""

    if type(value) is not RoutineReadSummaryMember:
        raise _invalid()
    return JsonObject(
        {
            "source_identity": value.source_identity,
            "cursor": observation_cursor_to_json(value.cursor),
            "tool_call_id": value.tool_call_id,
            "phase": value.phase,
            "receipt_time": value.receipt_time.wire,
            "subject_state_digest": value.subject_state_digest,
        }
    )


def routine_read_summary_member_from_json(value: JsonValue) -> RoutineReadSummaryMember:
    """Decode one exact summary member object."""

    if type(value) is not JsonObject or set(value) != {
        "source_identity",
        "cursor",
        "tool_call_id",
        "phase",
        "receipt_time",
        "subject_state_digest",
    }:
        raise _invalid()
    phase = value["phase"]
    if type(phase) is not str or phase not in {"pre", "post"}:
        raise _invalid("invalid_event_enum")
    tool_call_id = value["tool_call_id"]
    if tool_call_id is not None and type(tool_call_id) is not str:
        raise _invalid()
    return RoutineReadSummaryMember(
        source_identity=cast(str, value["source_identity"]),
        cursor=observation_cursor_from_json(value["cursor"]),
        tool_call_id=tool_call_id,
        phase=cast(RoutineReadSummaryPhase, phase),
        receipt_time=timestamp_from_string(cast(str, value["receipt_time"])),
        subject_state_digest=cast(str | None, value["subject_state_digest"]),
    )


def _routine_read_summary_members(
    value: object,
) -> tuple[RoutineReadSummaryMember, ...]:
    raw = _exact_tuple(value, maximum=_MAX_ROUTINE_READ_SUMMARY_INPUTS)
    result: list[RoutineReadSummaryMember] = []
    seen: set[tuple[str, int, int, int, str]] = set()
    for item in raw:
        if type(item) is not RoutineReadSummaryMember:
            raise _invalid()
        identity = (
            item.source_identity,
            item.cursor.source_generation,
            item.cursor.byte_position,
            item.cursor.event_position,
            item.phase,
        )
        if identity in seen:
            raise _invalid("duplicate_set_member")
        seen.add(identity)
        result.append(item)
    return tuple(result)


def routine_read_summary_member_digest(
    members: tuple[RoutineReadSummaryMember, ...],
) -> str:
    """Bind the ordered exact member list to a SHA-256 digest."""

    normalized = _routine_read_summary_members(members)
    if not normalized:
        raise _invalid()
    return canonical_digest(
        JsonObject(
            {"members": tuple(routine_read_summary_member_to_json(item) for item in normalized)}
        )
    )


def routine_read_summary_identity(
    *,
    source: ObservationSource,
    session_commitment: str,
    source_generation: int,
    selection_policy_version: str,
    fence: str,
    member_digest: str,
    selection_task_id: str,
    selection_session_id: str,
    selection_writer_id: str,
    selection_authority_generation: str,
) -> str:
    """Derive the stable, lane-bound identity of one summary envelope."""

    if type(source) is not ObservationSource:
        raise _invalid("invalid_event_enum")
    validate_commitment(session_commitment)
    source_generation = _positive(source_generation)
    selection_policy_version = _token(selection_policy_version)
    validate_sha256_digest(fence)
    validate_sha256_digest(member_digest)
    route = observation_selection_route(
        JsonObject(
            {
                "selection_task_id": selection_task_id,
                "selection_session_id": selection_session_id,
                "selection_writer_id": selection_writer_id,
                "selection_authority_generation": selection_authority_generation,
            }
        )
    )
    if route is None:  # pragma: no cover - the closed object above is complete
        raise _invalid("invalid_event_value_type")
    selected_task, selected_session, selected_writer, selected_generation = route
    digest = canonical_digest(
        JsonObject(
            {
                "source": source.value,
                "session_commitment": session_commitment,
                "source_generation": source_generation,
                "selection_policy_version": selection_policy_version,
                "fence": fence,
                "member_digest": member_digest,
                "selection_task_id": selected_task,
                "selection_session_id": selected_session,
                "selection_writer_id": selected_writer,
                "selection_authority_generation": selected_generation,
            }
        )
    )
    return f"summary:{digest[7:]}"


@dataclass(frozen=True, slots=True)
class RoutineReadSummary:
    """Bounded structural account emitted before routine-read materialization.

    ``summary_count`` counts completed routine calls (post phases), while
    ``input_count`` counts every represented source input.  The constructor
    checks both against the exact member list so a cursor cannot be advanced by
    an aggregate that hides an unaccounted native input.
    """

    summary_identity: str
    session_commitment: str
    source: ObservationSource
    source_generation: int
    selection_policy_version: str
    fence: str
    provenance: str
    content_scope: str
    coverage_gaps: tuple[str, ...]
    summary_count: int
    input_count: int
    member_digest: str
    members: tuple[RoutineReadSummaryMember, ...]
    cursor: ObservationCursor
    receipt_time: Timestamp
    selection_task_id: str
    selection_session_id: str
    selection_writer_id: str
    selection_authority_generation: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "summary_identity", _token(self.summary_identity))
        validate_commitment(self.session_commitment)
        if type(self.source) is not ObservationSource:
            raise _invalid("invalid_event_enum")
        source_generation = _positive(self.source_generation)
        object.__setattr__(self, "source_generation", source_generation)
        route = observation_selection_route(
            JsonObject(
                {
                    "selection_task_id": self.selection_task_id,
                    "selection_session_id": self.selection_session_id,
                    "selection_writer_id": self.selection_writer_id,
                    "selection_authority_generation": self.selection_authority_generation,
                }
            )
        )
        if route is None:  # pragma: no cover - the closed object above is complete
            raise _invalid("invalid_event_value_type")
        (
            selected_task,
            selected_session,
            selected_writer,
            selected_generation,
        ) = route
        object.__setattr__(self, "selection_task_id", selected_task)
        object.__setattr__(self, "selection_session_id", selected_session)
        object.__setattr__(self, "selection_writer_id", selected_writer)
        object.__setattr__(self, "selection_authority_generation", selected_generation)
        selection_policy_version = _token(self.selection_policy_version)
        object.__setattr__(self, "selection_policy_version", selection_policy_version)
        validate_sha256_digest(self.fence)
        if self.provenance != ROUTINE_READ_SUMMARY_PROVENANCE:
            raise _invalid("invalid_event_value_type")
        if self.content_scope != ROUTINE_READ_SUMMARY_CONTENT_SCOPE:
            raise _invalid("invalid_event_value_type")
        coverage_gaps = _sorted_unique_gap_codes(self.coverage_gaps)
        if any(gap not in ROUTINE_READ_SUMMARY_ALLOWED_GAPS for gap in coverage_gaps):
            raise _invalid("invalid_known_gap")
        object.__setattr__(self, "coverage_gaps", coverage_gaps)
        object.__setattr__(
            self,
            "summary_count",
            _positive(self.summary_count, maximum=_MAX_ROUTINE_READ_SUMMARY_CALLS),
        )
        object.__setattr__(
            self,
            "input_count",
            _positive(self.input_count, maximum=_MAX_ROUTINE_READ_SUMMARY_INPUTS),
        )
        members = _routine_read_summary_members(self.members)
        if len(members) != self.input_count:
            raise _invalid("summary_count_mismatch")
        post_count = sum(item.phase == "post" for item in members)
        if post_count != self.summary_count:
            raise _invalid("summary_count_mismatch")
        if self.input_count > 2 * self.summary_count:
            raise _invalid("summary_count_mismatch")
        if any(item.cursor.source_generation != source_generation for item in members):
            raise _invalid("cursor_generation_mismatch")
        if not members or self.cursor != members[-1].cursor:
            raise _invalid("cursor_accounting_mismatch")
        digest = routine_read_summary_member_digest(members)
        if digest != self.member_digest:
            raise _invalid("summary_digest_mismatch")
        expected_identity = routine_read_summary_identity(
            source=self.source,
            session_commitment=self.session_commitment,
            source_generation=source_generation,
            selection_policy_version=selection_policy_version,
            fence=self.fence,
            member_digest=digest,
            selection_task_id=selected_task,
            selection_session_id=selected_session,
            selection_writer_id=selected_writer,
            selection_authority_generation=selected_generation,
        )
        if self.summary_identity != expected_identity:
            raise _invalid("summary_identity_mismatch")
        if type(self.cursor) is not ObservationCursor:
            raise _invalid()
        if type(self.receipt_time) is not Timestamp:
            raise _invalid("invalid_timestamp")
        object.__setattr__(self, "members", members)


def routine_read_summary_to_json(value: RoutineReadSummary) -> JsonObject:
    """Encode one exact local summary record."""

    if type(value) is not RoutineReadSummary:
        raise _invalid()
    return JsonObject(
        {
            "schema": ROUTINE_READ_SUMMARY_SCHEMA,
            "summary_identity": value.summary_identity,
            "session_commitment": value.session_commitment,
            "source": value.source.value,
            "source_generation": value.source_generation,
            "selection_policy_version": value.selection_policy_version,
            "fence": value.fence,
            "provenance": value.provenance,
            "content_scope": value.content_scope,
            "coverage_gaps": value.coverage_gaps,
            "summary_count": value.summary_count,
            "input_count": value.input_count,
            "member_digest": value.member_digest,
            "members": tuple(routine_read_summary_member_to_json(item) for item in value.members),
            "cursor": observation_cursor_to_json(value.cursor),
            "receipt_time": value.receipt_time.wire,
            "selection_task_id": value.selection_task_id,
            "selection_session_id": value.selection_session_id,
            "selection_writer_id": value.selection_writer_id,
            "selection_authority_generation": value.selection_authority_generation,
        }
    )


def routine_read_summary_from_json(value: JsonValue) -> RoutineReadSummary:
    """Decode one exact local summary record and re-check its identity binding."""

    if type(value) is not JsonObject:
        raise _invalid()
    required = {
        "schema",
        "summary_identity",
        "session_commitment",
        "source",
        "source_generation",
        "selection_policy_version",
        "fence",
        "provenance",
        "content_scope",
        "coverage_gaps",
        "summary_count",
        "input_count",
        "member_digest",
        "members",
        "cursor",
        "receipt_time",
        "selection_task_id",
        "selection_session_id",
        "selection_writer_id",
        "selection_authority_generation",
    }
    if set(value) != required or value["schema"] != ROUTINE_READ_SUMMARY_SCHEMA:
        raise _invalid("unknown_payload_field")
    try:
        source = ObservationSource(cast(str, value["source"]))
    except (TypeError, ValueError) as exc:
        raise _invalid("invalid_event_enum") from exc
    members_raw = value["members"]
    if type(members_raw) is not tuple:
        raise _invalid()
    members = tuple(
        routine_read_summary_member_from_json(item)
        for item in cast(tuple[JsonValue, ...], members_raw)
    )
    return RoutineReadSummary(
        summary_identity=cast(str, value["summary_identity"]),
        session_commitment=cast(str, value["session_commitment"]),
        source=source,
        source_generation=cast(int, value["source_generation"]),
        selection_policy_version=cast(str, value["selection_policy_version"]),
        fence=cast(str, value["fence"]),
        provenance=cast(str, value["provenance"]),
        content_scope=cast(str, value["content_scope"]),
        coverage_gaps=cast(tuple[str, ...], value["coverage_gaps"]),
        summary_count=cast(int, value["summary_count"]),
        input_count=cast(int, value["input_count"]),
        member_digest=cast(str, value["member_digest"]),
        members=members,
        cursor=observation_cursor_from_json(value["cursor"]),
        receipt_time=timestamp_from_string(cast(str, value["receipt_time"])),
        selection_task_id=cast(str, value["selection_task_id"]),
        selection_session_id=cast(str, value["selection_session_id"]),
        selection_writer_id=cast(str, value["selection_writer_id"]),
        selection_authority_generation=cast(str, value["selection_authority_generation"]),
    )


def routine_read_summary_from_envelope(envelope: ObservationEnvelope) -> RoutineReadSummary:
    """Decode a summary envelope after validating its source-accounting fields."""

    if type(envelope) is not ObservationEnvelope or envelope.event_kind != "RoutineReadSummary":
        raise _invalid("invalid_event_value_type")
    if envelope.content_object_refs or envelope.gap_codes:
        raise _invalid("invalid_event_value_type")
    structural = envelope.structural_payload
    required = {
        "action",
        "summary_count",
        "input_count",
        "member_digest",
        "fence",
        "provenance",
        "summary_schema",
        "selection_policy_version",
        "content_scope",
        "coverage_gaps",
        "members",
        "selection_task_id",
        "selection_session_id",
        "selection_writer_id",
        "selection_authority_generation",
    }
    if set(structural) != required or structural["action"] != "routine_read_summary":
        raise _invalid("unknown_payload_field")
    if structural["summary_schema"] != ROUTINE_READ_SUMMARY_SCHEMA:
        raise _invalid("invalid_event_schema")
    payload = JsonObject(
        {
            "schema": ROUTINE_READ_SUMMARY_SCHEMA,
            "summary_identity": envelope.source_identity,
            "session_commitment": envelope.session_commitment,
            "source": envelope.source.value,
            "source_generation": envelope.cursor.source_generation,
            "selection_policy_version": structural["selection_policy_version"],
            "fence": structural["fence"],
            "provenance": structural["provenance"],
            "content_scope": structural["content_scope"],
            "coverage_gaps": structural["coverage_gaps"],
            "summary_count": structural["summary_count"],
            "input_count": structural["input_count"],
            "member_digest": structural["member_digest"],
            "members": structural["members"],
            "cursor": observation_cursor_to_json(envelope.cursor),
            "receipt_time": envelope.receipt_time.wire,
            "selection_task_id": structural["selection_task_id"],
            "selection_session_id": structural["selection_session_id"],
            "selection_writer_id": structural["selection_writer_id"],
            "selection_authority_generation": structural["selection_authority_generation"],
        }
    )
    return routine_read_summary_from_json(payload)


@dataclass(frozen=True, slots=True)
class AdviceItem:
    """Bounded durable advice value safe for status, observe status, and hooks."""

    finding_id: FindingId
    rule_code: str
    priority: int
    summary: str
    detail: str
    recommended_next_action: str
    evidence_refs: tuple[str, ...]
    coverage: Coverage
    freshness_frontier: str
    origin: Literal["deterministic", "semantic_model_derived"] = "deterministic"
    condition_identity: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "finding_id", finding_id(self.finding_id))
        object.__setattr__(self, "rule_code", _token(self.rule_code))
        object.__setattr__(self, "priority", _nonnegative(self.priority, maximum=1_000))
        object.__setattr__(self, "summary", _advice_text(self.summary, maximum=_MAX_ADVICE_SUMMARY))
        object.__setattr__(self, "detail", _advice_text(self.detail, maximum=_MAX_ADVICE_DETAIL))
        object.__setattr__(self, "recommended_next_action", _token(self.recommended_next_action))
        object.__setattr__(self, "evidence_refs", _evidence_refs(self.evidence_refs))
        if type(self.coverage) is not Coverage:
            raise _invalid("invalid_coverage_value")
        object.__setattr__(self, "freshness_frontier", _token(self.freshness_frontier))
        object.__setattr__(self, "origin", _advice_origin(self.origin))
        if self.condition_identity is not None:
            object.__setattr__(self, "condition_identity", _token(self.condition_identity))


def _ranked_advice_items(value: object) -> tuple[AdviceItem, ...]:
    raw = _exact_tuple(value, maximum=_MAX_RANKED_FINDINGS)
    result: list[AdviceItem] = []
    seen: set[str] = set()
    for item in raw:
        if type(item) is not AdviceItem:
            raise _invalid()
        key = str(item.finding_id)
        if key in seen:
            raise _invalid("duplicate_set_member")
        seen.add(key)
        result.append(item)
    return tuple(result)


type AdviceSemanticState = Literal["ready", "disabled", "unavailable", "failed"]
_ADVICE_SEMANTIC_STATES: Final[frozenset[str]] = frozenset(
    {"ready", "disabled", "unavailable", "failed"}
)


@dataclass(frozen=True, slots=True)
class AdviceSnapshot:
    ranked_finding_ids: tuple[FindingId, ...]
    evidence_basis_digest: str
    confidence_coverage: Coverage
    recommended_next_action: str
    freshness_frontier: str
    suppression_identity: str
    ranked_items: tuple[AdviceItem, ...] = ()
    # Recorded AI-powered review attempt status for this snapshot (issue #742).
    # Derived from the durable attempt row, never from finding count.
    semantic_attempt_state: AdviceSemanticState = "disabled"

    def __post_init__(self) -> None:
        items = _ranked_advice_items(self.ranked_items)
        if items:
            derived = tuple(item.finding_id for item in items)
            if self.ranked_finding_ids and _ranked_finding_ids(self.ranked_finding_ids) != derived:
                raise _invalid()
            object.__setattr__(self, "ranked_items", items)
            object.__setattr__(self, "ranked_finding_ids", derived)
        else:
            object.__setattr__(
                self, "ranked_finding_ids", _ranked_finding_ids(self.ranked_finding_ids)
            )
            object.__setattr__(self, "ranked_items", ())
        validate_sha256_digest(self.evidence_basis_digest)
        if type(self.confidence_coverage) is not Coverage:
            raise _invalid("invalid_coverage_value")
        object.__setattr__(self, "recommended_next_action", _token(self.recommended_next_action))
        object.__setattr__(self, "freshness_frontier", _token(self.freshness_frontier))
        object.__setattr__(self, "suppression_identity", _token(self.suppression_identity))
        if self.semantic_attempt_state not in _ADVICE_SEMANTIC_STATES:
            raise _invalid()
        object.__setattr__(self, "semantic_attempt_state", self.semantic_attempt_state)


@dataclass(frozen=True, slots=True)
class ObservationStatus:
    lifecycle: ObservationLifecycle
    workspace_commitment: str
    source_coverage: Mapping[ObservationSource, bool]
    last_observation_receipt_time: Timestamp | None
    lag_events: int
    gaps: tuple[str, ...]
    unsupported_events: tuple[str, ...]
    advice_frontier: str | None
    # Added as an optional projection so legacy status callers remain valid
    # while newer local-control readers can inspect selected/effective
    # observation pressure and bounded accounting.
    selection_runtime: ObservationSelectionRuntimeStatus | None = None

    def __post_init__(self) -> None:
        if type(self.lifecycle) is not ObservationLifecycle:
            raise _invalid("invalid_event_enum")
        validate_commitment(self.workspace_commitment)
        object.__setattr__(self, "source_coverage", _source_coverage(self.source_coverage))
        if (
            self.last_observation_receipt_time is not None
            and type(self.last_observation_receipt_time) is not Timestamp
        ):
            raise _invalid("invalid_timestamp")
        object.__setattr__(self, "lag_events", _nonnegative(self.lag_events))
        object.__setattr__(self, "gaps", _sorted_unique_gap_codes(self.gaps))
        object.__setattr__(
            self,
            "unsupported_events",
            _sorted_unique_tokens(self.unsupported_events, maximum=_MAX_UNSUPPORTED_EVENTS),
        )
        if self.advice_frontier is not None:
            object.__setattr__(self, "advice_frontier", _token(self.advice_frontier))
        if (
            self.selection_runtime is not None
            and type(self.selection_runtime) is not ObservationSelectionRuntimeStatus
        ):
            raise _invalid("invalid_event_value_type")


@dataclass(frozen=True, slots=True)
class ObservationIngestResult:
    disposition: ObservationIngestDisposition
    reason: str | None
    advanced_cursor: ObservationCursor | None

    def __post_init__(self) -> None:
        if type(self.disposition) is not ObservationIngestDisposition:
            raise _invalid("invalid_event_enum")
        if self.disposition is ObservationIngestDisposition.ACCEPTED:
            if self.reason is not None:
                raise _invalid()
            if type(self.advanced_cursor) is not ObservationCursor:
                raise _invalid()
        elif self.disposition is ObservationIngestDisposition.DUPLICATE:
            if self.reason is not None:
                object.__setattr__(self, "reason", _token(self.reason))
            if (
                self.advanced_cursor is not None
                and type(self.advanced_cursor) is not ObservationCursor
            ):
                raise _invalid()
        else:
            if self.reason is None:
                raise _invalid()
            object.__setattr__(self, "reason", _token(self.reason))
            if (
                self.advanced_cursor is not None
                and type(self.advanced_cursor) is not ObservationCursor
            ):
                raise _invalid()


@dataclass(frozen=True, slots=True)
class ObservationIngestRequest:
    """Redacted local-control ingest body: session routing, envelope, and bounded chunks.

    Callers MUST NOT supply FinishUP task/session/writer IDs. The service coordinator
    resolves those from the validated lifecycle mapping. Native-host chunks also
    carry the exact user-enabled content profile; profile-less requests preserve
    the historical structural-only path.
    """

    codex_session_id: str
    envelope: ObservationEnvelope
    content_chunks: tuple[ObservationContentChunk, ...] = ()
    # Native Claude/Cursor content is admitted only with the exact profile
    # explicitly enabled by the user.  Profile-less Codex hook content is
    # admitted only by the source-qualified capture-only arm below; the
    # historical session-stream path remains profile-less and unchanged.
    content_capture_profile: str | None = None
    # Internal service handoff: stage authenticated native content and a
    # durable capture ticket without advancing the observation cursor/ledger.
    # This is intentionally opt-in and is emitted only by the native hook
    # drain before FIFO structural delivery.
    capture_only: bool = False

    def __post_init__(self) -> None:
        if type(self.codex_session_id) is not str or not self.codex_session_id:
            raise _invalid()
        if (
            "\x00" in self.codex_session_id
            or "/" in self.codex_session_id
            or "\\" in self.codex_session_id
        ):
            raise _invalid()
        if len(self.codex_session_id) > 128:
            raise _invalid()
        if type(self.envelope) is not ObservationEnvelope:
            raise _invalid()
        object.__setattr__(self, "content_chunks", _content_chunks(self.content_chunks))
        if self.content_capture_profile is not None:
            try:
                validate_content_capture_profile(self.content_capture_profile)
            except ProtocolValueError as exc:
                raise _invalid() from exc
        if type(self.capture_only) is not bool:
            raise _invalid()
        if self.capture_only:
            native_capture_sources = {
                ObservationSource.CLAUDE_HOOK,
                ObservationSource.CODEX_HOOK,
                ObservationSource.CURSOR_HOOK,
            }
            if self.envelope.source not in native_capture_sources or not self.content_chunks:
                raise _invalid()
            if self.envelope.source is ObservationSource.CODEX_HOOK:
                if self.content_capture_profile is not None:
                    raise _invalid("invalid_event_value_type")
            elif self.content_capture_profile is None:
                raise _invalid("invalid_event_value_type")


@dataclass(frozen=True, slots=True)
class ObservationStatusQuery:
    workspace_commitment: str

    def __post_init__(self) -> None:
        validate_commitment(self.workspace_commitment)


@dataclass(frozen=True, slots=True)
class ObservationControlCommand:
    workspace_commitment: str

    def __post_init__(self) -> None:
        validate_commitment(self.workspace_commitment)


@dataclass(frozen=True, slots=True)
class ObservationRevokeCommand:
    workspace_commitment: str
    retain_evidence: Literal[True] = True

    def __post_init__(self) -> None:
        validate_commitment(self.workspace_commitment)
        if self.retain_evidence is not True:
            raise _invalid()


def observation_earns_hook_observed(status: ObservationStatus, has_real_evidence: bool) -> bool:
    """Return True only for active lifecycle with real observation evidence."""

    if type(status) is not ObservationStatus:
        raise _invalid()
    if type(has_real_evidence) is not bool:
        raise _invalid()
    return status.lifecycle is ObservationLifecycle.ACTIVE and has_real_evidence is True


def observation_cursor_to_json(value: ObservationCursor) -> JsonObject:
    return JsonObject(
        {
            "source_generation": value.source_generation,
            "byte_position": value.byte_position,
            "event_position": value.event_position,
            "last_source_commitment": value.last_source_commitment,
            "mapping_version": value.mapping_version,
        }
    )


def observation_cursor_from_json(value: JsonValue) -> ObservationCursor:
    if type(value) is not JsonObject:
        raise _invalid()
    source = value
    required = (
        "source_generation",
        "byte_position",
        "event_position",
        "last_source_commitment",
        "mapping_version",
    )
    if set(source) != set(required):
        raise _invalid()
    return ObservationCursor(
        source_generation=cast(int, source["source_generation"]),
        byte_position=cast(int, source["byte_position"]),
        event_position=cast(int, source["event_position"]),
        last_source_commitment=cast(str, source["last_source_commitment"]),
        mapping_version=cast(str, source["mapping_version"]),
    )


def observation_envelope_to_json(value: ObservationEnvelope) -> JsonObject:
    return JsonObject(
        {
            "session_commitment": value.session_commitment,
            "event_kind": value.event_kind,
            "source_identity": value.source_identity,
            "source": value.source.value,
            "cursor": observation_cursor_to_json(value.cursor),
            "receipt_time": value.receipt_time.wire,
            "structural_payload": value.structural_payload,
            "content_object_refs": value.content_object_refs,
            "gap_codes": value.gap_codes,
        }
    )


def observation_envelope_from_json(value: JsonValue) -> ObservationEnvelope:
    if type(value) is not JsonObject:
        raise _invalid()
    source = value
    required = (
        "session_commitment",
        "event_kind",
        "source_identity",
        "source",
        "cursor",
        "receipt_time",
        "structural_payload",
        "content_object_refs",
        "gap_codes",
    )
    if set(source) != set(required):
        raise _invalid()
    try:
        observation_source = ObservationSource(cast(str, source["source"]))
    except ValueError as exc:
        raise _invalid("invalid_event_enum") from exc
    return ObservationEnvelope(
        session_commitment=cast(str, source["session_commitment"]),
        event_kind=cast(str, source["event_kind"]),
        source_identity=cast(str, source["source_identity"]),
        source=observation_source,
        cursor=observation_cursor_from_json(source["cursor"]),
        receipt_time=timestamp_from_string(source["receipt_time"]),
        structural_payload=_structural_payload(source["structural_payload"]),
        content_object_refs=_content_object_refs(source["content_object_refs"]),
        gap_codes=_sorted_unique_gap_codes(source["gap_codes"]),
    )


def advice_item_to_json(value: AdviceItem) -> JsonObject:
    return JsonObject(
        {
            "finding_id": str(value.finding_id),
            "rule_code": value.rule_code,
            "priority": value.priority,
            "summary": value.summary,
            "detail": value.detail,
            "recommended_next_action": value.recommended_next_action,
            "evidence_refs": value.evidence_refs,
            "coverage": JsonObject(coverage_to_json(value.coverage)),
            "freshness_frontier": value.freshness_frontier,
            "origin": value.origin,
            "condition_identity": value.condition_identity,
        }
    )


def advice_item_from_json(value: JsonValue) -> AdviceItem:
    if type(value) is not JsonObject:
        raise _invalid()
    source = value
    required = (
        "finding_id",
        "rule_code",
        "priority",
        "summary",
        "detail",
        "recommended_next_action",
        "evidence_refs",
        "coverage",
        "freshness_frontier",
        "origin",
    )
    source_keys = set(source)
    if source_keys != set(required) and source_keys != {*required, "condition_identity"}:
        raise _invalid()
    refs = source["evidence_refs"]
    return AdviceItem(
        finding_id=finding_id(source["finding_id"]),
        rule_code=cast(str, source["rule_code"]),
        priority=cast(int, source["priority"]),
        summary=cast(str, source["summary"]),
        detail=cast(str, source["detail"]),
        recommended_next_action=cast(str, source["recommended_next_action"]),
        evidence_refs=_evidence_refs(refs),
        coverage=coverage_from_json(source["coverage"]),
        freshness_frontier=cast(str, source["freshness_frontier"]),
        origin=_advice_origin(source["origin"]),
        condition_identity=(
            cast(str, source["condition_identity"]) if "condition_identity" in source else None
        ),
    )


def advice_snapshot_to_json(value: AdviceSnapshot) -> JsonObject:
    return JsonObject(
        {
            "ranked_finding_ids": tuple(str(item) for item in value.ranked_finding_ids),
            "ranked_items": tuple(advice_item_to_json(item) for item in value.ranked_items),
            "evidence_basis_digest": value.evidence_basis_digest,
            "confidence_coverage": JsonObject(coverage_to_json(value.confidence_coverage)),
            "recommended_next_action": value.recommended_next_action,
            "freshness_frontier": value.freshness_frontier,
            "suppression_identity": value.suppression_identity,
            "semantic_attempt_state": value.semantic_attempt_state,
        }
    )


def advice_snapshot_from_json(value: JsonValue) -> AdviceSnapshot:
    if type(value) is not JsonObject:
        raise _invalid()
    source = value
    required = {
        "ranked_finding_ids",
        "evidence_basis_digest",
        "confidence_coverage",
        "recommended_next_action",
        "freshness_frontier",
        "suppression_identity",
    }
    optional = {"ranked_items", "semantic_attempt_state"}
    if not required.issubset(set(source)) or set(source) - required - optional:
        raise _invalid()
    items_raw = source.get("ranked_items", ())
    if type(items_raw) is not tuple:
        raise _invalid()
    ids_raw = source["ranked_finding_ids"]
    items = tuple(advice_item_from_json(item) for item in cast(tuple[JsonValue, ...], items_raw))
    # A snapshot stored before issue #742 has no recorded attempt state. AI-powered items exist
    # only after a succeeded review, so they are the one fact such a snapshot still carries.
    legacy_state = (
        "ready" if any(item.origin == "semantic_model_derived" for item in items) else "disabled"
    )
    attempt_state = source.get("semantic_attempt_state", legacy_state)
    if type(attempt_state) is not str or attempt_state not in _ADVICE_SEMANTIC_STATES:
        raise _invalid()
    return AdviceSnapshot(
        ranked_finding_ids=_ranked_finding_ids(ids_raw),
        evidence_basis_digest=cast(str, source["evidence_basis_digest"]),
        confidence_coverage=coverage_from_json(source["confidence_coverage"]),
        recommended_next_action=cast(str, source["recommended_next_action"]),
        freshness_frontier=cast(str, source["freshness_frontier"]),
        suppression_identity=cast(str, source["suppression_identity"]),
        ranked_items=items,
        semantic_attempt_state=cast(AdviceSemanticState, attempt_state),
    )


def observation_status_to_json(value: ObservationStatus) -> JsonObject:
    coverage = {
        key.value: present
        for key, present in sorted(value.source_coverage.items(), key=lambda item: item[0].value)
    }
    payload: dict[str, JsonValue] = {
        "lifecycle": value.lifecycle.value,
        "workspace_commitment": value.workspace_commitment,
        "source_coverage": JsonObject(coverage),
        "last_observation_receipt_time": (
            None
            if value.last_observation_receipt_time is None
            else value.last_observation_receipt_time.wire
        ),
        "lag_events": value.lag_events,
        "gaps": value.gaps,
        "unsupported_events": value.unsupported_events,
        "advice_frontier": value.advice_frontier,
    }
    if value.selection_runtime is not None:
        payload["selection_runtime"] = observation_selection_runtime_status_to_json(
            value.selection_runtime
        )
    return JsonObject(payload)


def observation_status_from_json(value: JsonValue) -> ObservationStatus:
    if type(value) is not JsonObject:
        raise _invalid()
    source = value
    required = (
        "lifecycle",
        "workspace_commitment",
        "source_coverage",
        "last_observation_receipt_time",
        "lag_events",
        "gaps",
        "unsupported_events",
        "advice_frontier",
    )
    optional = {"selection_runtime"}
    if set(source) - set(required) - optional or not set(required).issubset(set(source)):
        raise _invalid()
    try:
        lifecycle = ObservationLifecycle(cast(str, source["lifecycle"]))
    except ValueError as exc:
        raise _invalid("invalid_event_enum") from exc
    coverage_raw = source["source_coverage"]
    if type(coverage_raw) is not JsonObject:
        raise _invalid()
    coverage = {
        ObservationSource(key): cast(bool, present) for key, present in coverage_raw.items()
    }
    receipt = source["last_observation_receipt_time"]
    return ObservationStatus(
        lifecycle=lifecycle,
        workspace_commitment=cast(str, source["workspace_commitment"]),
        source_coverage=coverage,
        last_observation_receipt_time=(None if receipt is None else timestamp_from_string(receipt)),
        lag_events=cast(int, source["lag_events"]),
        gaps=_sorted_unique_gap_codes(source["gaps"]),
        unsupported_events=_sorted_unique_tokens(
            source["unsupported_events"], maximum=_MAX_UNSUPPORTED_EVENTS
        ),
        advice_frontier=cast(str | None, source["advice_frontier"]),
        selection_runtime=(
            None
            if "selection_runtime" not in source
            else observation_selection_runtime_status_from_json(source["selection_runtime"])
        ),
    )


def observation_ingest_request_to_json(value: ObservationIngestRequest) -> JsonObject:
    payload: dict[str, JsonValue] = {
        "codex_session_id": value.codex_session_id,
        "envelope": observation_envelope_to_json(value.envelope),
    }
    if value.content_chunks:
        payload["content_chunks"] = tuple(
            observation_content_chunk_to_json(item) for item in value.content_chunks
        )
    if value.content_capture_profile is not None:
        payload["content_capture_profile"] = value.content_capture_profile
    if value.capture_only:
        payload["capture_only"] = True
    return JsonObject(payload)


def observation_ingest_request_from_json(value: JsonValue) -> ObservationIngestRequest:
    if type(value) is not JsonObject:
        raise _invalid()
    source = value
    if not {"codex_session_id", "envelope"}.issubset(source) or set(source) - {
        "codex_session_id",
        "envelope",
        "content_chunks",
        "content_capture_profile",
        "capture_only",
    }:
        raise _invalid()
    envelope_raw = source["envelope"]
    if type(envelope_raw) is not JsonObject:
        if isinstance(envelope_raw, Mapping):
            envelope_raw = JsonObject(cast(Mapping[str, JsonValue], envelope_raw))
        else:
            raise _invalid()
    chunks_raw = source.get("content_chunks", ())
    if type(chunks_raw) is not tuple:
        raise _invalid()
    return ObservationIngestRequest(
        codex_session_id=cast(str, source["codex_session_id"]),
        envelope=observation_envelope_from_json(envelope_raw),
        content_chunks=tuple(
            observation_content_chunk_from_json(item)
            for item in cast(tuple[JsonValue, ...], chunks_raw)
        ),
        content_capture_profile=(
            None
            if source.get("content_capture_profile") is None
            else cast(str, source["content_capture_profile"])
        ),
        capture_only=cast(bool, source.get("capture_only", False)),
    )


def observation_content_chunk_to_json(value: ObservationContentChunk) -> JsonObject:
    if type(value) is not ObservationContentChunk:
        raise _invalid()
    return JsonObject(
        {
            "content_kind": value.content_kind.value,
            "correlation_identity": value.correlation_identity,
            "source_commitment": value.source_commitment,
            "media_type": value.media_type,
            "part_index": value.part_index,
            "part_count": value.part_count,
            "content_b64": base64.b64encode(value.content).decode("ascii"),
            "redacted": value.redacted,
        }
    )


def observation_content_chunk_from_json(value: JsonValue) -> ObservationContentChunk:
    if type(value) is not JsonObject:
        if isinstance(value, Mapping):
            value = JsonObject(cast(Mapping[str, JsonValue], value))
        else:
            raise _invalid()
    required = {
        "content_kind",
        "correlation_identity",
        "source_commitment",
        "media_type",
        "part_index",
        "part_count",
        "content_b64",
        "redacted",
    }
    if set(value) != required:
        raise _invalid()
    encoded = value["content_b64"]
    if type(encoded) is not str or len(encoded) > ((_MAX_CONTENT_CHUNK_BYTES + 2) // 3) * 4:
        raise _invalid()
    try:
        content = base64.b64decode(encoded, validate=True)
        kind = ObservationContentKind(cast(str, value["content_kind"]))
    except ValueError as exc:
        raise _invalid() from exc
    return ObservationContentChunk(
        content_kind=kind,
        correlation_identity=cast(str, value["correlation_identity"]),
        source_commitment=cast(str, value["source_commitment"]),
        media_type=cast(str, value["media_type"]),
        part_index=cast(int, value["part_index"]),
        part_count=cast(int, value["part_count"]),
        content=content,
        redacted=cast(bool, value["redacted"]),
    )


def observation_ingest_result_to_json(value: ObservationIngestResult) -> JsonObject:
    return JsonObject(
        {
            "disposition": value.disposition.value,
            "reason": value.reason,
            "advanced_cursor": (
                None
                if value.advanced_cursor is None
                else observation_cursor_to_json(value.advanced_cursor)
            ),
        }
    )


def observation_ingest_result_from_json(value: JsonValue) -> ObservationIngestResult:
    if type(value) is not JsonObject:
        raise _invalid()
    source = value
    required = ("disposition", "reason", "advanced_cursor")
    if set(source) != set(required):
        raise _invalid()
    try:
        disposition = ObservationIngestDisposition(cast(str, source["disposition"]))
    except ValueError as exc:
        raise _invalid("invalid_event_enum") from exc
    cursor_value = source["advanced_cursor"]
    return ObservationIngestResult(
        disposition=disposition,
        reason=cast(str | None, source["reason"]),
        advanced_cursor=(
            None if cursor_value is None else observation_cursor_from_json(cursor_value)
        ),
    )


def observation_status_query_to_json(value: ObservationStatusQuery) -> JsonObject:
    return JsonObject({"workspace_commitment": value.workspace_commitment})


def observation_status_query_from_json(value: JsonValue) -> ObservationStatusQuery:
    if type(value) is not JsonObject:
        raise _invalid()
    source = value
    if set(source) != {"workspace_commitment"}:
        raise _invalid()
    return ObservationStatusQuery(workspace_commitment=cast(str, source["workspace_commitment"]))


def observation_control_command_to_json(value: ObservationControlCommand) -> JsonObject:
    return JsonObject({"workspace_commitment": value.workspace_commitment})


def observation_control_command_from_json(value: JsonValue) -> ObservationControlCommand:
    if type(value) is not JsonObject:
        raise _invalid()
    source = value
    if set(source) != {"workspace_commitment"}:
        raise _invalid()
    return ObservationControlCommand(workspace_commitment=cast(str, source["workspace_commitment"]))


def observation_revoke_command_to_json(value: ObservationRevokeCommand) -> JsonObject:
    return JsonObject(
        {
            "workspace_commitment": value.workspace_commitment,
            "retain_evidence": True,
        }
    )


def observation_revoke_command_from_json(value: JsonValue) -> ObservationRevokeCommand:
    if type(value) is not JsonObject:
        raise _invalid()
    source = value
    if set(source) != {"workspace_commitment", "retain_evidence"}:
        raise _invalid()
    return ObservationRevokeCommand(
        workspace_commitment=cast(str, source["workspace_commitment"]),
        retain_evidence=cast(Literal[True], source["retain_evidence"]),
    )
