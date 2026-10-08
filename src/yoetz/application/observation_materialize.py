"""Conservative observation → task-ledger materialization.

Supported envelopes become service-authored ledger events with ``hook_observed``
(or an honest weaker coverage). Unknown/unmapped shapes stay observation-only
with explicit gaps and never invent success proof.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Final, Literal, TypedDict, cast

from yoetz.domain.events import (
    EVIDENCE_SCHEMA_VERSION,
    OBSERVATION_COORDINATOR_ACTOR_ID,
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayload,
    DecisionRecordedPayload,
    EventDraft,
    EventSchema,
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceImmutability,
    EvidenceKind,
    EvidenceRecordedPayload,
    ResultOutcome,
    ResultRecordedPayload,
    encode_payload,
    media_type_for,
)
from yoetz.domain.host_lineage import host_lineage_from_envelope
from yoetz.domain.observation import (
    ROUTINE_READ_SUMMARY_DETAIL_GAP,
    ObservationContentKind,
    ObservationContentManifest,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationInspectionSnapshot,
    ObservationSource,
    RoutineReadSummary,
    observation_content_binding_matches,
    routine_read_summary_from_envelope,
    validate_observed_images,
)
from yoetz.domain.observation_loss import ObservationSelectionLoss
from yoetz.domain.receipts import CAPTURE_HANDOFF_RETIRED_GAP
from yoetz.domain.values import (
    Actor,
    ActorType,
    JsonObject,
    JsonValue,
    SubjectStateRef,
    Timestamp,
    action_id,
    actor_id,
    claim_id,
    event_id,
    evidence_id,
    object_id,
    result_id,
)
from yoetz.domain.write_scope import WRITE_SCOPES
from yoetz.kernel.observed_failures import observed_action_description, observed_command_field
from yoetz.ports.integrations import observation_pairing_contract
from yoetz.protocol.canonical import request_digest
from yoetz.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    Coverage,
    PublicationChannel,
    coverage_for_channel,
)
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.ids import PREFIX_BY_KIND, IdKind

__all__ = [
    "HOST_OUTCOME_UNAVAILABLE_GAP",
    "approved_check_author",
    "MATERIALIZATION_LEGACY_MAPPING_VERSIONS",
    "MATERIALIZATION_MAPPING_VERSION",
    "SESSION_BOUND_MAPPING_VERSIONS",
    "MaterializedObservationBatch",
    "MaterializedObservationDraft",
    "PAIRED_ACTION_ROLE",
    "PairedActionLink",
    "materialize_routine_read_summary",
    "STREAM_COMPLETED_EVENT_KINDS",
    "canonical_logical_identity",
    "materialize_observation_envelope",
    "materialize_selection_loss",
    "materialize_observation_inspection_snapshot",
    "materialize_observation_outcome_correction",
    "observation_claim_identity",
    "paired_action_link",
    "paired_action_linked_roles",
    "observation_content_identity",
    "observation_writer_id",
    "stable_observation_id",
    "stream_event_is_completed_tool",
]

# 1.7 preserves parent-call discriminators for host subagent evidence. Partial
# copies reconcile through registry aliases, not a weaker global evidence key.
# 1.6 and earlier remain available for explicit historical replay.
MATERIALIZATION_MAPPING_VERSION: Final = "obs-ledger/1.7.0"
MATERIALIZATION_LEGACY_MAPPING_VERSIONS: Final = (
    "obs-ledger/1.4.0",
    "obs-ledger/1.3.0",
    "obs-ledger/1.2.0",
    "obs-ledger/1.5.0",
    "obs-ledger/1.6.0",
)
# Mapping versions whose operation digest was bound to the routed Yoetz session
# and its observation writer. A workflow reattach in the same host session
# rotates both, so their committed operations can only be found from the
# session that committed them (#560). ``obs-ledger/1.5.0`` keys the digest on
# the task, the canonical logical identity, and the role tuple only — exactly
# the facts the stable event ids are derived from — and is resolved task-wide.
SESSION_BOUND_MAPPING_VERSIONS: Final = frozenset(
    {
        "obs-ledger/1.4.0",
        "obs-ledger/1.3.0",
        "obs-ledger/1.2.0",
    }
)
# One bounded coverage condition for "the host emitted a paired tool result with
# no outcome semantics at all" (#350). It rides the entry coverage of the
# affected action/result records, so any number of outcome-less observed calls
# fold into a single known-gap code in check coverage and the receipt instead of
# one material-limitation candidate per call. It is deliberately not an
# ObservationGapCode: envelopes are complete observations; the gap belongs to
# the materialized ledger records whose outcome the host did not state.
HOST_OUTCOME_UNAVAILABLE_GAP: Final = "host_outcome_unavailable"
_LOGICAL_IDENTITY_DOMAIN: Final = "yoetz/observation-logical-identity/v1"
_ID_DOMAIN: Final = b"yoetz/observation-materialize-id/v1\x00"
_FILE_TOOLS: Final = frozenset(
    {
        # A Codex rollout ``FileChange`` item is the patch a hooked or stream-only call applied
        # (#910); it belongs to the edit family, but an edit alone never retires a failure (#909).
        "file_change",
        "apply_patch",
        "edit",
        "write_file",
        "write",
        "create_file",
        "multi_edit",
        "str_replace",
    }
)
_COMMAND_TOOLS: Final = frozenset(
    {
        "shell",
        "bash",
        "exec",
        "command",
        "run_terminal_cmd",
        "local_shell",
    }
)
_COMPLETION_KINDS: Final = frozenset(
    {
        "Stop",
        "AgentMessage",
        "UserPromptSubmit",
    }
)
_PERMISSION_KINDS: Final = frozenset({"PermissionRequest", "PermissionDecision"})
_SUBAGENT_START: Final = frozenset({"SubagentStart"})
_SUBAGENT_STOP: Final = frozenset({"SubagentStop"})
STREAM_COMPLETED_EVENT_KINDS: Final = frozenset(
    {
        "custom_tool_call_output",
        "function_call_output",
        "item.completed",
        "item_completed",
    }
)
_CAPTURED_EVIDENCE_KINDS: Final = frozenset(
    {
        ObservationContentKind.TOOL_OUTPUT,
        ObservationContentKind.CHANGED_FILE,
        ObservationContentKind.WORKSPACE_DIFF,
    }
)


def stream_event_is_completed_tool(kind: str, structural: Mapping[str, JsonValue]) -> bool:
    """True when a session-stream envelope is a completed host tool call."""

    if kind in STREAM_COMPLETED_EVENT_KINDS:
        return True
    action = structural.get("action")
    return (
        kind == "response_item" and type(action) is str and action in STREAM_COMPLETED_EVENT_KINDS
    )


@dataclass(frozen=True, slots=True)
class MaterializedObservationDraft:
    draft: EventDraft
    payload_bytes: bytes
    projection_status: Literal["projected", "unknown_unprojected"]
    role: str


@dataclass(frozen=True, slots=True)
class MaterializedObservationBatch:
    drafts: tuple[MaterializedObservationDraft, ...]
    coverage: Coverage
    channel: PublicationChannel
    gaps: tuple[str, ...]
    skip_reason: str | None = None
    summary: RoutineReadSummary | None = None


def stable_observation_id(
    *,
    kind: IdKind,
    task_id: str,
    source_identity: str,
    mapping_version: str,
    role: str,
) -> str:
    """Allocate a deterministic UUIDv4-shaped ID for observation materialization."""

    material = (
        _ID_DOMAIN
        + f"{kind.value}\0{task_id}\0{source_identity}\0{mapping_version}\0{role}".encode()
    )
    digest = hashlib.sha256(material).digest()
    raw = bytearray(digest[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return PREFIX_BY_KIND[kind] + str(uuid.UUID(bytes=bytes(raw)))


def _tool_name(payload: Mapping[str, JsonValue]) -> str | None:
    value = payload.get("tool_name")
    return value if type(value) is str else None


def _pairing_contract(
    envelope: ObservationEnvelope, payload: Mapping[str, JsonValue]
) -> tuple[str, str]:
    """Resolve the installed host/profile pairing contract for an envelope.

    The structural marker is emitted by the host adapter, while the exact
    profile lookup remains the authority for historical envelopes that
    predate the marker.  Generation identities are intentionally retained as
    metadata only and never become tool-call identities.
    """

    harness = (
        "claude"
        if envelope.source is ObservationSource.CLAUDE_HOOK
        else "cursor"
        if envelope.source is ObservationSource.CURSOR_HOOK
        else "codex"
    )
    profile_id = payload.get("capability_profile_id")
    return observation_pairing_contract(harness, profile_id if type(profile_id) is str else None)


def _correlation(
    payload: Mapping[str, JsonValue], *, correlation_kind: str | None = None
) -> str | None:
    # Codex spells the host tool-call id ``tool_use_id``; ingress normalizes it
    # to ``tool_call_id``, but read the host spelling first too so a payload
    # that reaches this seam un-normalized still correlates (#274).
    kind = correlation_kind
    if kind is None:
        raw_kind = payload.get("correlation_kind")
        kind = raw_kind if type(raw_kind) is str else "tool_call_id"
    if kind == "none":
        return None
    direct_keys = ("tool_use_id", "tool_call_id")
    for key in direct_keys:
        value = payload.get(key)
        if type(value) is str and value:
            return value
    if kind == "generation_id":
        return None
    for key in ("correlation_id", "parent_tool_call_id"):
        value = payload.get(key)
        if type(value) is str and value:
            return value
    return None


def _exit_status(payload: Mapping[str, JsonValue]) -> int | None:
    value = payload.get("exit_status")
    if type(value) is int and not isinstance(value, bool):
        return value
    return None


# Closed result_status vocabularies. Codex hosts spell tool outcomes several
# ways; only exact known spellings map to an outcome, and any other string
# stays UNKNOWN so an unrecognized status is never upgraded to success.
_RESULT_STATUS_SUCCESS: Final = frozenset({"success", "succeeded", "ok", "completed", "passed"})
_RESULT_STATUS_FAILURE: Final = frozenset(
    {
        "failure",
        "failed",
        "error",
        "errored",
        "denied",
        "aborted",
        "cancelled",
        "canceled",
        "timeout",
        "timed_out",
        "interrupted",
    }
)
_RESULT_STATUS_PARTIAL: Final = frozenset({"partial", "partially_completed"})


def _post_outcome(payload: Mapping[str, JsonValue]) -> ResultOutcome:
    """Map every host-provided outcome fact to a result outcome (#350).

    The real Codex ``PostToolUse`` payload may state its outcome as
    ``exit_status``, ``denied``, boolean ``success``, or a ``result_status``
    string; all of them are consumed rather than discarded. Any explicit
    failure signal wins over any success signal — conflicting facts must never
    launder a stated failure into success — and only a payload with no outcome
    fact at all is UNKNOWN: a missing outcome is never upgraded to success.
    """

    exit_status = _exit_status(payload)
    status = payload.get("result_status")
    lowered = status.lower() if type(status) is str else None
    if (
        (exit_status is not None and exit_status != 0)
        or payload.get("denied") is True
        or payload.get("success") is False
        or lowered in _RESULT_STATUS_FAILURE
    ):
        return ResultOutcome.FAILURE
    if lowered in _RESULT_STATUS_PARTIAL:
        return ResultOutcome.PARTIAL
    if exit_status == 0 or payload.get("success") is True or lowered in _RESULT_STATUS_SUCCESS:
        return ResultOutcome.SUCCESS
    return ResultOutcome.UNKNOWN


class _RuntimeDescriptionFacts(TypedDict, total=False):
    install_target: str | None
    write_outside_workspace: bool
    effective_user: str | None
    write_scope: str | None


def _runtime_description_facts(structural: Mapping[str, JsonValue]) -> _RuntimeDescriptionFacts:
    """The closed runtime tokens (#977) the observed action description carries.

    ``write_scope`` also names an edit whose every path was scratch or Yoetz-owned (ADR-042);
    the kernel never lets such an edit make an earlier verification stale.
    """

    install = structural.get("install_target")
    user = structural.get("effective_user")
    scope = structural.get("write_scope")
    return {
        "install_target": install if type(install) is str else None,
        "write_outside_workspace": scope == "outside_workspace",
        "effective_user": user if type(user) is str else None,
        "write_scope": scope if type(scope) is str and scope in WRITE_SCOPES else None,
    }


def _omitted_command(structural: Mapping[str, JsonValue]) -> str:
    """The command field of an observed command action: never command text.

    The hook's installation-keyed ``command_commitment`` (#909) is the command identity the
    failure-supersession rule compares. Plain digests keep their historical form, and a row with
    neither stays ``omitted:structural`` exactly as every pre-commitment ledger recorded it.
    """

    commitment = structural.get("command_commitment")
    if type(commitment) is str:
        # A compound or wrapped command also carries its simple commands' keyed commitments
        # (#977): planned-verification matching reads them; failure supersession does not.
        segments = structural.get("command_segment_commitments")
        composition = structural.get("command_composition")
        return observed_command_field(
            commitment,
            tuple(item for item in segments if type(item) is str)
            if isinstance(segments, tuple | list)
            else None,
            composition if type(composition) is str else None,
        )
    for key in ("command_digest", "argv_digest"):
        digest = structural.get(key)
        if type(digest) is str:
            return f"omitted:{digest}"
    return "omitted:structural"


def _yoetz_mcp_tool(lowered: str) -> bool:
    """Whether a lower-cased host tool name is a server-qualified Yoetz MCP tool."""

    if not lowered.startswith("mcp__"):
        return False
    server, separator, _tool = lowered[len("mcp__") :].partition("__")
    return bool(separator) and "yoetz" in server.split("_")


def _action_kind(tool: str | None) -> ActionKind:
    if tool is None:
        return ActionKind.OTHER
    lowered = tool.lower()
    if _yoetz_mcp_tool(lowered):
        # Yoetz's own MCP tools (``mcp__yoetz__check``, ``mcp__plugin_yoetz_yoetz__receipt``)
        # record and read the ledger; they never change the work under test, so they are never an
        # edit or a command whatever their name contains (ADR-042, tb4n2 R4). Another server's
        # tool keeps the name rules below: ``mcp__fs__edit_file`` may really edit a file.
        return ActionKind.OTHER
    if lowered in _FILE_TOOLS or "edit" in lowered or "patch" in lowered:
        return ActionKind.EDIT
    if lowered in _COMMAND_TOOLS or "shell" in lowered or "exec" in lowered:
        return ActionKind.COMMAND
    return ActionKind.OTHER


def _materialization_call_source(
    envelope: ObservationEnvelope, *, phase: str, correlation: str, family: str
) -> str:
    """Build a source identity that cannot cross session or generation lanes."""

    return (
        f"{phase}:{_logical_source_lane(envelope.source)}:"
        f"{envelope.session_commitment}:{envelope.cursor.source_generation}:"
        f"{correlation}:{family}"
    )


def _observation_host_label(source: ObservationSource) -> str:
    """Name the host that supplied a native observation in user-facing text."""

    if source is ObservationSource.CLAUDE_HOOK:
        return "Claude Code hook"
    if source is ObservationSource.CURSOR_HOOK:
        return "Cursor hook"
    return "Codex hook"


def _coverage_for(
    envelope: ObservationEnvelope,
    *,
    gaps: tuple[str, ...] | None = None,
    content_captured: bool = False,
) -> Coverage:
    effective_gaps = envelope.gap_codes if gaps is None else gaps
    if (
        envelope.source is ObservationSource.CODEX_HOOK
        and not effective_gaps
        and not content_captured
    ):
        return coverage_for_channel(PublicationChannel.HOOK_OBSERVED)
    baseline = coverage_for_channel(PublicationChannel.HOOK_OBSERVED)
    known_gaps = tuple(sorted({*baseline.known_gaps, *effective_gaps}, key=str.encode))
    # Weaker honest coverage when gaps or stream-only evidence.
    observation = (
        ArtifactObservation.CONTENT_CAPTURED
        if content_captured
        else ArtifactObservation.HOOK_OBSERVED
        if envelope.source is ObservationSource.CODEX_HOOK
        and ObservationGapCode.UNSUPPORTED_EVENT.value not in effective_gaps
        else ArtifactObservation.PUBLISHED_ONLY
    )
    authorship = (
        AuthorshipAssurance.HARNESS_OBSERVED
        if envelope.source is ObservationSource.CODEX_HOOK
        and observation in {ArtifactObservation.HOOK_OBSERVED, ArtifactObservation.CONTENT_CAPTURED}
        else AuthorshipAssurance.SERVICE_AUTHENTICATED
    )
    return Coverage(
        publication_channels=(PublicationChannel.HOOK_OBSERVED,),
        authorship_assurance=authorship,
        artifact_observation=observation,
        evidence_immutability=(
            EvidenceImmutability.IMMUTABLE_SNAPSHOT
            if content_captured
            else baseline.evidence_immutability
        ),
        ledger_freshness=baseline.ledger_freshness,
        check_types=baseline.check_types,
        known_gaps=known_gaps,
    )


def _draft(
    *,
    event: str,
    schema_name: str,
    occurred_at: Timestamp,
    payload: object,
    parents: tuple[str, ...] = (),
    artifact_refs: tuple[str, ...] = (),
    evidence_refs: tuple[str, ...] = (),
    role: str,
) -> MaterializedObservationDraft:
    from yoetz.protocol.canonical import canonical_encode

    schema = EventSchema(
        schema_name,
        EVIDENCE_SCHEMA_VERSION if schema_name == "evidence_recorded" else "1.0.0",
    )
    draft = EventDraft(
        event_id(event),
        schema,
        occurred_at,
        tuple(event_id(parent) for parent in parents),
        payload,  # pyright: ignore[reportArgumentType]
        tuple(object_id(value) for value in artifact_refs),
        tuple(evidence_id(value) for value in evidence_refs),
    )
    encoded = encode_payload(payload)  # pyright: ignore[reportArgumentType]
    return MaterializedObservationDraft(
        draft=draft,
        payload_bytes=canonical_encode(encoded),
        projection_status="projected",
        role=role,
    )


def _eligible_captured_content(
    envelope: ObservationEnvelope,
    manifests: tuple[ObservationContentManifest, ...],
) -> tuple[tuple[ObservationContentManifest, ...], tuple[str, ...]]:
    """Select only service-bound content and name every missing eligible object honestly."""

    by_object = {
        item.object_id: item for item in manifests if type(item) is ObservationContentManifest
    }
    gaps = set(envelope.gap_codes)
    eligible: list[ObservationContentManifest] = []
    for ref in envelope.content_object_refs:
        if not ref.startswith("obj_"):
            continue
        manifest = by_object.get(ref)
        if manifest is None:
            gaps.add(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
            continue
        if manifest.content_kind not in _CAPTURED_EVIDENCE_KINDS:
            gaps.add(ObservationGapCode.CONTENT_UNSELECTED.value)
            continue
        if manifest.content_digest is None or manifest.content_bytes is None:
            gaps.add(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
            continue
        if not observation_content_binding_matches(
            envelope,
            content_kind=manifest.content_kind,
            correlation_identity=manifest.correlation_identity,
            source_commitment=manifest.source_commitment,
        ):
            gaps.add(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
            continue
        if manifest.redacted:
            gaps.add(ObservationGapCode.CONTENT_REDACTED.value)
        eligible.append(manifest)
    return (
        tuple(sorted(eligible, key=lambda item: item.object_id.encode("ascii"))),
        tuple(sorted(gaps, key=str.encode)),
    )


def _captured_evidence_drafts(
    envelope: ObservationEnvelope,
    *,
    task_id: str,
    manifests: tuple[ObservationContentManifest, ...],
    parents: tuple[str, ...] = (),
    mapping_version: str = MATERIALIZATION_MAPPING_VERSION,
) -> tuple[tuple[MaterializedObservationDraft, ...], tuple[str, ...]]:
    drafts: list[MaterializedObservationDraft] = []
    refs: list[str] = []
    for item in manifests:
        source = f"{envelope.source_identity}:captured:{item.object_id}"
        evidence = stable_observation_id(
            kind=IdKind.EVIDENCE,
            task_id=task_id,
            source_identity=source,
            mapping_version=mapping_version,
            role="captured_evidence",
        )
        event = stable_observation_id(
            kind=IdKind.EVENT,
            task_id=task_id,
            source_identity=source,
            mapping_version=mapping_version,
            role="captured_evidence_event",
        )
        refs.append(evidence)
        drafts.append(
            _draft(
                event=event,
                schema_name="evidence_recorded",
                occurred_at=envelope.receipt_time,
                payload=EvidenceRecordedPayload(
                    evidence_id(evidence),
                    EvidenceKind.OTHER,
                    EvidenceImmutability.IMMUTABLE_SNAPSHOT,
                    envelope.receipt_time,
                    captured_object_id=object_id(item.object_id),
                    content_digest=item.content_digest,
                    description=(
                        f"Observation-captured {item.content_kind.value} bytes "
                        f"part={item.part_index + 1}/{item.part_count}"
                    ),
                    digest_binding=EvidenceDigestBinding(
                        subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
                        content_availability=EvidenceContentAvailability.CAPTURED,
                        byte_count=cast(int, item.content_bytes),
                        provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
                    ),
                ),
                parents=parents,
                artifact_refs=(item.object_id,),
                role=(
                    f"captured_{item.content_kind.value}_{item.part_index}_{item.content_digest}"
                ),
            )
        )
    # Object order does not imply evidence-ID order; result references are a canonical set.
    return tuple(drafts), tuple(sorted(refs, key=str.encode))


def _observed_image_drafts(
    envelope: ObservationEnvelope,
    *,
    task_id: str,
    parents: tuple[str, ...],
    mapping_version: str,
) -> tuple[tuple[MaterializedObservationDraft, ...], tuple[str, ...]]:
    """One digest-only ``evidence_recorded`` per image the hook saw in this tool result.

    P3-2 (issue #1013): the hook hashed the decoded image and read its header before dropping
    the bytes, so the ledger can name what the agent looked at without holding or sending a
    pixel. The description carries only closed tokens and integers. A malformed fact set
    materializes nothing rather than a guessed row.
    """

    raw = envelope.structural_payload.get("observed_images")
    if raw is None:
        return (), ()
    try:
        images = validate_observed_images(raw)
    except ProtocolValueError, TypeError, ValueError:
        return (), ()
    drafts: list[MaterializedObservationDraft] = []
    refs: list[str] = []
    for index, image in enumerate(images):
        source = f"{envelope.source_identity}:image:{index}"
        evidence = stable_observation_id(
            kind=IdKind.EVIDENCE,
            task_id=task_id,
            source_identity=source,
            mapping_version=mapping_version,
            role="observed_image",
        )
        event = stable_observation_id(
            kind=IdKind.EVENT,
            task_id=task_id,
            source_identity=source,
            mapping_version=mapping_version,
            role="observed_image_event",
        )
        media = cast(str, image["media_type"])
        byte_count = cast(int, image["byte_count"])
        width, height = image.get("width"), image.get("height")
        size = f" {width}x{height}" if type(width) is int and type(height) is int else ""
        refs.append(evidence)
        drafts.append(
            _draft(
                event=event,
                schema_name="evidence_recorded",
                occurred_at=envelope.receipt_time,
                payload=EvidenceRecordedPayload(
                    evidence_id(evidence),
                    EvidenceKind.ARTIFACT,
                    EvidenceImmutability.CONTENT_DIGEST,
                    envelope.receipt_time,
                    content_digest=cast(str, image["content_digest"]),
                    description=(
                        f"Observed image tool result {media}{size} ({byte_count} bytes); "
                        "pixels were not captured or sent"
                    ),
                    digest_binding=EvidenceDigestBinding(
                        subject=EvidenceDigestSubject.ARTIFACT_BYTES,
                        content_availability=EvidenceContentAvailability.DIGEST_ONLY,
                        byte_count=byte_count,
                        provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
                    ),
                ),
                parents=parents,
                role=f"observed_image_{index}",
            )
        )
    return tuple(drafts), tuple(sorted(refs, key=str.encode))


def materialize_routine_read_summary(
    summary: RoutineReadSummary,
    *,
    task_id: str,
    mapping_version: str = MATERIALIZATION_MAPPING_VERSION,
) -> MaterializedObservationBatch:
    """Materialize one bounded summary without inventing per-call evidence.

    The local summary envelope remains the source of the exact member list.
    The task ledger receives one metadata-only pointer whose description binds
    only fixed structural counters and digests.  In particular, this function
    never turns an aggregate into content coverage or a verification result.
    """

    baseline = coverage_for_channel(PublicationChannel.HOOK_OBSERVED)
    try:
        _validate_materialization_mapping_version(mapping_version)
    except TypeError, ValueError:
        return MaterializedObservationBatch(
            (), baseline, PublicationChannel.HOOK_OBSERVED, (), "unsupported_mapping_version"
        )
    if type(summary) is not RoutineReadSummary:
        return MaterializedObservationBatch(
            (), baseline, PublicationChannel.HOOK_OBSERVED, (), "invalid_routine_read_summary"
        )
    gap = ROUTINE_READ_SUMMARY_DETAIL_GAP
    summary_gaps = tuple(sorted({gap, *summary.coverage_gaps}, key=str.encode))
    coverage = Coverage(
        publication_channels=baseline.publication_channels,
        authorship_assurance=baseline.authorship_assurance,
        artifact_observation=baseline.artifact_observation,
        evidence_immutability=baseline.evidence_immutability,
        ledger_freshness=baseline.ledger_freshness,
        check_types=baseline.check_types,
        known_gaps=tuple(sorted({*baseline.known_gaps, *summary_gaps}, key=str.encode)),
    )
    source = f"routine-read-summary:{summary.summary_identity}"
    evidence = stable_observation_id(
        kind=IdKind.EVIDENCE,
        task_id=task_id,
        source_identity=source,
        mapping_version=mapping_version,
        role="routine_read_summary",
    )
    event = stable_observation_id(
        kind=IdKind.EVENT,
        task_id=task_id,
        source_identity=source,
        mapping_version=mapping_version,
        role="routine_read_summary_event",
    )
    description = (
        "Routine-read summary observed "
        f"calls={summary.summary_count} inputs={summary.input_count} "
        f"member_digest={summary.member_digest} content_scope={summary.content_scope}"
    )
    draft = _draft(
        event=event,
        schema_name="evidence_recorded",
        occurred_at=summary.receipt_time,
        payload=EvidenceRecordedPayload(
            evidence_id(evidence),
            EvidenceKind.OTHER,
            EvidenceImmutability.METADATA_ONLY,
            summary.receipt_time,
            reference=f"routine_read_summary:{summary.summary_identity}",
            description=description,
        ),
        role="routine_read_summary",
    )
    return MaterializedObservationBatch(
        (draft,),
        coverage,
        PublicationChannel.HOOK_OBSERVED,
        summary_gaps,
        None,
        summary,
    )


def materialize_observation_inspection_snapshot(
    snapshot: ObservationInspectionSnapshot,
    *,
    task_id: str,
) -> MaterializedObservationBatch:
    """Materialize trusted inspection objects without exposing their captured bytes.

    Inspection facts and excerpts are independently encrypted before this seam. The ledger binds
    their exact secret-scanned plaintext digests and object identities, while descriptions remain
    structural so observation intake does not silently become AI-powered review egress.
    """

    baseline = coverage_for_channel(PublicationChannel.HOOK_OBSERVED)
    if type(snapshot) is not ObservationInspectionSnapshot:
        return MaterializedObservationBatch(
            (), baseline, PublicationChannel.HOOK_OBSERVED, (), "invalid_inspection_snapshot"
        )
    subject_state = SubjectStateRef(
        described_state=f"observation-inspection:{snapshot.subject_state_digest}"
    )
    candidates = (
        (
            "facts",
            snapshot.facts_object_id,
            snapshot.facts_content_digest,
            snapshot.facts_content_bytes,
            "Observation inspection facts snapshot",
        ),
        (
            "excerpt",
            snapshot.excerpt_object_id,
            snapshot.excerpt_content_digest,
            snapshot.excerpt_content_bytes,
            "Observation inspection bounded excerpt snapshot",
        ),
    )
    drafts: list[MaterializedObservationDraft] = []
    for role, captured_object, content_digest, content_bytes, description in candidates:
        if captured_object is None:
            continue
        source = f"inspection:{snapshot.snapshot_id}:{role}:{captured_object}"
        evidence = stable_observation_id(
            kind=IdKind.EVIDENCE,
            task_id=task_id,
            source_identity=source,
            mapping_version=MATERIALIZATION_MAPPING_VERSION,
            role=f"inspection_{role}",
        )
        event = stable_observation_id(
            kind=IdKind.EVENT,
            task_id=task_id,
            source_identity=source,
            mapping_version=MATERIALIZATION_MAPPING_VERSION,
            role=f"inspection_{role}_event",
        )
        drafts.append(
            _draft(
                event=event,
                schema_name="evidence_recorded",
                occurred_at=snapshot.recorded_at,
                payload=EvidenceRecordedPayload(
                    evidence_id=evidence_id(evidence),
                    evidence_kind=EvidenceKind.OTHER,
                    strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
                    observed_at=snapshot.recorded_at,
                    captured_object_id=object_id(captured_object),
                    content_digest=cast(str, content_digest),
                    description=description,
                    subject_state=subject_state,
                    digest_binding=EvidenceDigestBinding(
                        subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
                        content_availability=EvidenceContentAvailability.CAPTURED,
                        byte_count=cast(int, content_bytes),
                        provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
                    ),
                ),
                artifact_refs=(captured_object,),
                role=f"inspection_{role}",
            )
        )
    if not drafts:
        gap = ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
        coverage = Coverage(
            publication_channels=baseline.publication_channels,
            authorship_assurance=baseline.authorship_assurance,
            artifact_observation=baseline.artifact_observation,
            evidence_immutability=baseline.evidence_immutability,
            ledger_freshness=baseline.ledger_freshness,
            check_types=baseline.check_types,
            known_gaps=tuple(sorted({*baseline.known_gaps, gap}, key=str.encode)),
        )
        return MaterializedObservationBatch(
            (), coverage, PublicationChannel.HOOK_OBSERVED, (gap,), "inspection_content_unavailable"
        )
    inspection_gaps = set(baseline.known_gaps)
    if snapshot.excerpt_redacted:
        inspection_gaps.add(ObservationGapCode.CONTENT_REDACTED.value)
    if snapshot.excerpt_truncated:
        inspection_gaps.add(ObservationGapCode.TRUNCATED_PAYLOAD.value)
    coverage = Coverage(
        publication_channels=(PublicationChannel.HOOK_OBSERVED,),
        authorship_assurance=AuthorshipAssurance.HARNESS_OBSERVED,
        artifact_observation=ArtifactObservation.CONTENT_CAPTURED,
        evidence_immutability=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        ledger_freshness=baseline.ledger_freshness,
        check_types=baseline.check_types,
        known_gaps=tuple(sorted(inspection_gaps, key=str.encode)),
    )
    return MaterializedObservationBatch(
        tuple(drafts),
        coverage,
        PublicationChannel.HOOK_OBSERVED,
        tuple(sorted(inspection_gaps, key=str.encode)),
        None,
    )


def materialize_selection_loss(
    loss: ObservationSelectionLoss, *, observed_at: Timestamp
) -> MaterializedObservationBatch:
    """Publish one permanent coverage limitation per exact historical loss lane.

    This is a service report of retained accounting, not a fabricated host
    action/result, cursor advancement, captured content, or a count reset.
    """

    from yoetz.protocol.canonical import canonical_encode

    identity = "selection-loss:" + loss.lane
    version = "selection-loss/1.0.0"
    payload = EvidenceRecordedPayload(
        evidence_id(
            stable_observation_id(
                kind=IdKind.EVIDENCE,
                task_id=loss.task_id,
                source_identity=identity,
                mapping_version=version,
                role="loss_evidence",
            )
        ),
        EvidenceKind.OTHER,
        EvidenceImmutability.METADATA_ONLY,
        observed_at,
        description=(
            "At least one non-replayable observation was lost. This permanent lane "
            + (
                "marker carries route-valid but unreconciled local metadata; "
                if loss.unreconciled
                else "marker reports historical coverage loss; "
            )
            + "exact aggregate counts remain in local selection accounting. "
            + ("Refusal cause: " + ", ".join(loss.causes) + ". " if loss.causes else "")
            + "Attribution: "
            + canonical_encode(loss.identity()).decode()
        ),
    )
    coverage = replace(
        coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
        known_gaps=(ObservationGapCode.OBSERVATION_INPUT_LOSS.value,),
    )
    item = _draft(
        event=stable_observation_id(
            kind=IdKind.EVENT,
            task_id=loss.task_id,
            source_identity=identity,
            mapping_version=version,
            role="loss_event",
        ),
        schema_name="evidence_recorded",
        occurred_at=observed_at,
        payload=payload,
        role="selection_loss",
    )
    return MaterializedObservationBatch(
        (item,),
        coverage,
        PublicationChannel.HOOK_OBSERVED,
        (ObservationGapCode.OBSERVATION_INPUT_LOSS.value,),
        None,
    )


def materialize_capture_handoff_retirement(
    *, task_id: str, ticket_id: str, reason: str, observed_at: Timestamp
) -> MaterializedObservationBatch:
    """Publish one task-scoped marker for a retired native content handoff (issue #1019).

    The staged content of one observed call could not be attached to its structural row. The
    marker carries ``capture_handoff_retired`` on this task's coverage and names only the closed
    retirement reason; the ticket identity is a digest, and no path or content is recorded.
    """

    identity = "capture-handoff-retired:" + ticket_id
    version = "capture-handoff-retirement/1.0.0"
    payload = EvidenceRecordedPayload(
        evidence_id(
            stable_observation_id(
                kind=IdKind.EVIDENCE,
                task_id=task_id,
                source_identity=identity,
                mapping_version=version,
                role="retirement_evidence",
            )
        ),
        EvidenceKind.OTHER,
        EvidenceImmutability.METADATA_ONLY,
        observed_at,
        description=(
            "Captured content staged for one observed call was retired before it could be"
            " attached, so it is not available; this marker does not show whether the call's"
            " own record was committed. Retirement reason: " + reason + "."
        ),
    )
    coverage = replace(
        coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
        known_gaps=(CAPTURE_HANDOFF_RETIRED_GAP,),
    )
    item = _draft(
        event=stable_observation_id(
            kind=IdKind.EVENT,
            task_id=task_id,
            source_identity=identity,
            mapping_version=version,
            role="retirement_event",
        ),
        schema_name="evidence_recorded",
        occurred_at=observed_at,
        payload=payload,
        role="capture_handoff_retired",
    )
    return MaterializedObservationBatch(
        (item,),
        coverage,
        PublicationChannel.HOOK_OBSERVED,
        (CAPTURE_HANDOFF_RETIRED_GAP,),
        None,
    )


def materialize_observation_envelope(
    envelope: ObservationEnvelope,
    *,
    task_id: str,
    captured_content: tuple[ObservationContentManifest, ...] = (),
    mapping_version: str = MATERIALIZATION_MAPPING_VERSION,
) -> MaterializedObservationBatch:
    """Map one envelope to zero or more ledger drafts.

    ``mapping_version`` is the materialization schema, never the source cursor
    version. New calls use the current ``obs-ledger/1.7.0`` default; a caller
    replaying an already committed historical operation may explicitly select
    one of the supported legacy versions.

    Returns ``skip_reason`` when the envelope should remain observation-store-only.
    """

    try:
        _validate_materialization_mapping_version(mapping_version)
    except TypeError, ValueError:
        return MaterializedObservationBatch(
            (),
            coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
            PublicationChannel.HOOK_OBSERVED,
            (),
            "unsupported_mapping_version",
        )

    if type(envelope) is not ObservationEnvelope:
        return MaterializedObservationBatch(
            (),
            coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
            PublicationChannel.HOOK_OBSERVED,
            (),
            "invalid_envelope",
        )

    if envelope.event_kind == "RoutineReadSummary":
        try:
            summary = routine_read_summary_from_envelope(envelope)
        except ProtocolValueError:
            # Summary envelopes are local, bounded accounting records. A
            # malformed one must stay out of the ledger rather than degrade to
            # an opaque evidence record that hides the accounting failure.
            return MaterializedObservationBatch(
                (),
                coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
                PublicationChannel.HOOK_OBSERVED,
                (ObservationGapCode.ROUTINE_READ_SUMMARY_INVALID.value,),
                "invalid_routine_read_summary",
            )
        return materialize_routine_read_summary(
            summary, task_id=task_id, mapping_version=mapping_version
        )

    structural = cast(Mapping[str, JsonValue], envelope.structural_payload)
    pairing_mode, correlation_kind = _pairing_contract(envelope, structural)
    # ``unpaired_event`` on an old Claude/Cursor envelope records the shared
    # ingress defect, not a missing host event: those profiles never promised
    # a pre hook.  Keep the original envelope and its gap history intact, but
    # remove the false current limitation from this materialization attempt.
    effective_gaps = tuple(
        gap
        for gap in envelope.gap_codes
        if not (gap == ObservationGapCode.UNPAIRED_EVENT.value and pairing_mode == "post_only")
        and not (
            gap == ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value
            and host_lineage_from_envelope(envelope) is not None
        )
    )
    materialized_envelope = (
        envelope
        if effective_gaps == envelope.gap_codes
        else replace(envelope, gap_codes=effective_gaps)
    )
    captured, gaps = _eligible_captured_content(materialized_envelope, captured_content)
    coverage = _coverage_for(materialized_envelope, gaps=gaps, content_captured=bool(captured))
    channel = PublicationChannel.HOOK_OBSERVED
    # Cursor mappings describe the transport that delivered the envelope. They
    # must never select ledger record identities: equivalent hook/stream input
    # has one source-independent materialization mapping. Historical replay is
    # explicit through the keyword above so a legacy committed graph can still
    # be reconstructed without allowing a transport version to mint new IDs.
    mapping = mapping_version
    kind = envelope.event_kind
    # Codex hook ``PostToolUse`` and a completed session-stream tool record
    # (rollout ``function_call_output``, historically exec ``item.completed``)
    # are two observations of the same host call. Normalize the stream form
    # before choosing ledger roles so both sources produce the same
    # action/result batch and therefore the same operation digest.
    completed_stream = stream_event_is_completed_tool(kind, structural)
    if (
        envelope.source is ObservationSource.CODEX_SESSION_STREAM
        and completed_stream
        and _correlation(structural, correlation_kind=correlation_kind) is not None
    ):
        kind = "PostToolUse"
    tool = _tool_name(structural)
    correlation = _correlation(structural, correlation_kind=correlation_kind)
    unpaired = ObservationGapCode.UNPAIRED_EVENT.value in gaps and pairing_mode == "paired"
    unsupported = (
        ObservationGapCode.UNSUPPORTED_EVENT.value in gaps
        or kind in {"unsupported_event", "observation_gap"}
        or kind.startswith("unsupported")
    )

    if unsupported or kind == "observation_gap":
        return MaterializedObservationBatch((), coverage, channel, gaps, "unsupported_or_gap")

    if kind in {"SessionStart", "SessionEnd", "PreCompact", "PostCompact"}:
        # Lifecycle bookkeeping stays in observation store / mapping; no ledger claim.
        return MaterializedObservationBatch((), coverage, channel, gaps, "lifecycle_only")

    drafts: list[MaterializedObservationDraft] = []
    if kind == "PreToolUse":
        # A selected routine pre normally reaches the ledger only through its
        # completed summary.  When the admission buffer has to flush an
        # incomplete attempt (deadline, boundary, or session close), or the
        # call is not routine, this envelope is delivered individually.
        # Preserve it as a pending action so a missing post remains visible as
        # an action-without-result condition; do not synthesize an outcome.
        if correlation is None:
            return MaterializedObservationBatch(
                (), coverage, channel, gaps, "missing_tool_identity"
            )
        # A paired profile keys the pending action on the host call itself,
        # exactly as its post keys the action it links a result to, so the
        # two phases of one call name one action (#917).  Only the service's
        # append step decides which phase records it; see
        # ``paired_action_link``.  Other profiles keep the historical
        # per-envelope identity unchanged.
        action_source = (
            _materialization_call_source(
                envelope,
                phase="pre",
                correlation=correlation,
                family=_action_kind(tool).value,
            )
            if pairing_mode == "paired"
            else (
                f"pre-event:{_logical_source_lane(envelope.source)}:"
                f"{envelope.session_commitment}:{envelope.cursor.source_generation}:"
                f"{envelope.source_identity}"
            )
        )
        action = stable_observation_id(
            kind=IdKind.ACTION,
            task_id=task_id,
            source_identity=action_source,
            mapping_version=mapping,
            role="action",
        )
        event = stable_observation_id(
            kind=IdKind.EVENT,
            task_id=task_id,
            source_identity=action_source,
            mapping_version=mapping,
            role="action_event",
        )
        action_kind = _action_kind(tool)
        # The pending action is now the call's one action, so a paired
        # Claude/Cursor ordinary profile names its own host (#917).
        host = (
            _observation_host_label(envelope.source) if pairing_mode == "paired" else "Codex hook"
        )
        description = observed_action_description(
            f"Observed pending {action_kind.value} via {host}",
            tool,
            cast(str | None, structural.get("runner_class")),
            **_runtime_description_facts(structural),
        )
        command = None
        if action_kind is ActionKind.COMMAND:
            # Command text is never recorded; the keyed identity or a placeholder stands in.
            command = _omitted_command(structural)
        drafts.append(
            _draft(
                event=event,
                schema_name="action_recorded",
                occurred_at=envelope.receipt_time,
                payload=ActionRecordedPayload(
                    action_id(action),
                    action_kind,
                    description,
                    command=command,
                    attempted_items=(),
                ),
                role="action",
            )
        )
        captured_drafts, _captured_refs = _captured_evidence_drafts(
            envelope,
            task_id=task_id,
            manifests=captured,
            parents=(event,),
            mapping_version=mapping,
        )
        drafts.extend(captured_drafts)
        return MaterializedObservationBatch(tuple(drafts), coverage, channel, gaps, None)

    if kind == "PostToolUse":
        # Successful routine reads are summarized before this boundary when
        # the selection contract is valid.  Any individually admitted copy
        # (legacy input, an unknown route/fence, a builder fallback, or a
        # context boundary) must still materialize its own action/result.  The
        # summary event has its separate branch above, so this cannot turn a
        # real summary into per-call records.
        if unpaired or correlation is None:
            # Standalone structural observation: evidence only; do not invent
            # an action.  A post-only profile has an intentional identity
            # limit, so its generation-only result is evidence without the
            # paired-profile ``unpaired_event`` gap.
            post_only = pairing_mode == "post_only"
            evidence_role = "post_only_result" if post_only else "unpaired_result"
            event_role = "post_only_result_event" if post_only else "unpaired_result_event"
            evidence = stable_observation_id(
                kind=IdKind.EVIDENCE,
                task_id=task_id,
                source_identity=envelope.source_identity,
                mapping_version=mapping,
                role=evidence_role,
            )
            event = stable_observation_id(
                kind=IdKind.EVENT,
                task_id=task_id,
                source_identity=envelope.source_identity,
                mapping_version=mapping,
                role=event_role,
            )
            exit_status = _exit_status(structural)
            summary = (
                (
                    f"Observed post-only tool result exit={exit_status}"
                    if post_only
                    else f"Unpaired observed tool result exit={exit_status}"
                )
                if exit_status is not None
                else "Observed post-only tool result"
                if post_only
                else "Unpaired observed tool result"
            )
            drafts.append(
                _draft(
                    event=event,
                    schema_name="evidence_recorded",
                    occurred_at=envelope.receipt_time,
                    payload=EvidenceRecordedPayload(
                        evidence_id(evidence),
                        EvidenceKind.OTHER,
                        EvidenceImmutability.METADATA_ONLY,
                        envelope.receipt_time,
                        description=summary,
                    ),
                    role="post_only_evidence" if post_only else "unpaired_evidence",
                )
            )
            captured_drafts, _captured_refs = _captured_evidence_drafts(
                envelope,
                task_id=task_id,
                manifests=captured,
                parents=(event,),
                mapping_version=mapping,
            )
            drafts.extend(captured_drafts)
            image_drafts, _image_refs = _observed_image_drafts(
                envelope, task_id=task_id, parents=(event,), mapping_version=mapping
            )
            drafts.extend(image_drafts)
            merged_gaps = (
                gaps
                if post_only
                else tuple(sorted({*gaps, ObservationGapCode.UNPAIRED_EVENT.value}, key=str.encode))
            )
            return MaterializedObservationBatch(tuple(drafts), coverage, channel, merged_gaps, None)

        # Linked post: action (idempotent stable IDs from correlation) + result.
        # Post-only profiles may use an actual tool-call id when supplied, but
        # their action identity is explicitly separate from a paired pre.
        family = _action_kind(tool).value
        action_phase = "post-only" if pairing_mode == "post_only" else "pre"
        action_source = _materialization_call_source(
            envelope, phase=action_phase, correlation=correlation, family=family
        )
        action = stable_observation_id(
            kind=IdKind.ACTION,
            task_id=task_id,
            source_identity=action_source,
            mapping_version=mapping,
            role="action",
        )
        action_event = stable_observation_id(
            kind=IdKind.EVENT,
            task_id=task_id,
            source_identity=action_source,
            mapping_version=mapping,
            role="action_event",
        )
        result_source = _materialization_call_source(
            envelope, phase="post", correlation=correlation, family=family
        )
        result = stable_observation_id(
            kind=IdKind.RESULT,
            task_id=task_id,
            source_identity=result_source,
            mapping_version=mapping,
            role="result",
        )
        result_event = stable_observation_id(
            kind=IdKind.EVENT,
            task_id=task_id,
            source_identity=result_source,
            mapping_version=mapping,
            role="result_event",
        )
        action_kind = _action_kind(tool)
        command = None
        if action_kind is ActionKind.COMMAND:
            command = _omitted_command(structural)
        drafts.append(
            _draft(
                event=action_event,
                schema_name="action_recorded",
                occurred_at=envelope.receipt_time,
                payload=ActionRecordedPayload(
                    action_id(action),
                    action_kind,
                    observed_action_description(
                        (
                            f"Observed {action_kind.value} via post-only hook"
                            if pairing_mode == "post_only"
                            else f"Observed {action_kind.value} via "
                            f"{_observation_host_label(envelope.source)}"
                        ),
                        tool,
                        cast(str | None, structural.get("runner_class")),
                        **_runtime_description_facts(structural),
                    ),
                    command=command,
                ),
                role="action",
            )
        )
        captured_drafts, captured_refs = _captured_evidence_drafts(
            envelope,
            task_id=task_id,
            manifests=captured,
            parents=(action_event,),
            mapping_version=mapping,
        )
        drafts.extend(captured_drafts)
        image_drafts, image_refs = _observed_image_drafts(
            envelope, task_id=task_id, parents=(action_event,), mapping_version=mapping
        )
        drafts.extend(image_drafts)
        captured_drafts = (*captured_drafts, *image_drafts)
        captured_refs = tuple(sorted({*captured_refs, *image_refs}, key=str.encode))
        exit_status = _exit_status(structural)
        outcome = _post_outcome(structural)
        if outcome is ResultOutcome.UNKNOWN:
            # The host stated no outcome for this call. The per-call record stays
            # durable, but its coverage names the one standing capability
            # condition so check/receipt fold every such call into a single
            # bounded known gap instead of per-result limitation candidates.
            coverage = Coverage(
                publication_channels=coverage.publication_channels,
                authorship_assurance=coverage.authorship_assurance,
                artifact_observation=coverage.artifact_observation,
                evidence_immutability=coverage.evidence_immutability,
                ledger_freshness=coverage.ledger_freshness,
                check_types=coverage.check_types,
                known_gaps=tuple(
                    sorted({*coverage.known_gaps, HOST_OUTCOME_UNAVAILABLE_GAP}, key=str.encode)
                ),
            )
        drafts.append(
            _draft(
                event=result_event,
                schema_name="result_recorded",
                occurred_at=envelope.receipt_time,
                payload=ResultRecordedPayload(
                    result_id(result),
                    action_id(action),
                    outcome,
                    exit_status=exit_status,
                    summary=f"Observed result status={outcome.value}",
                    evidence_refs=tuple(evidence_id(value) for value in captured_refs),
                ),
                parents=tuple(
                    sorted(
                        (action_event, *(item.draft.event_id for item in captured_drafts)),
                        key=str.encode,
                    )
                ),
                evidence_refs=captured_refs,
                role="result",
            )
        )
        return MaterializedObservationBatch(tuple(drafts), coverage, channel, gaps, None)

    if kind in _PERMISSION_KINDS:
        event = stable_observation_id(
            kind=IdKind.EVENT,
            task_id=task_id,
            source_identity=envelope.source_identity,
            mapping_version=mapping,
            role="permission_decision",
        )
        decision = structural.get("permission_decision") or structural.get("decision_reason_code")
        statement = (
            f"Permission decision observed: {decision}"
            if type(decision) is str
            else "Permission decision observed"
        )
        drafts.append(
            _draft(
                event=event,
                schema_name="decision_recorded",
                occurred_at=envelope.receipt_time,
                payload=DecisionRecordedPayload(
                    statement=statement,
                    rationale="codex_hook_permission_evidence",
                    authority=actor_id("yoetz:observation-coordinator"),
                ),
                role="permission",
            )
        )
        captured_drafts, _captured_refs = _captured_evidence_drafts(
            envelope,
            task_id=task_id,
            manifests=captured,
            parents=(event,),
            mapping_version=mapping,
        )
        drafts.extend(captured_drafts)
        return MaterializedObservationBatch(tuple(drafts), coverage, channel, gaps, None)

    if kind in _SUBAGENT_START or kind in _SUBAGENT_STOP:
        # Assignment requires obligations; record evidence-only until the service lineage
        # coordinator binds this host observation to a child. Keep a stable, path-free
        # correlation reference so a late stop can reconcile with its start without minting a
        # second annotation.
        lineage = host_lineage_from_envelope(envelope)
        if lineage is None:
            missing = ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value
            gaps = tuple(sorted({*gaps, missing}, key=str.encode))
            coverage = _coverage_for(materialized_envelope, gaps=gaps)
            return MaterializedObservationBatch((), coverage, channel, gaps, missing)
        lineage_identity = (
            lineage.logical_identity
            if mapping == MATERIALIZATION_MAPPING_VERSION
            else lineage.correlation.legacy_logical_identity
        )
        lineage_source = f"{lineage_identity}:{lineage.phase}"
        evidence = stable_observation_id(
            kind=IdKind.EVIDENCE,
            task_id=task_id,
            source_identity=lineage_source,
            mapping_version=mapping,
            role="subagent_observation",
        )
        event = stable_observation_id(
            kind=IdKind.EVENT,
            task_id=task_id,
            source_identity=lineage_source,
            mapping_version=mapping,
            role="subagent_observation_event",
        )
        phase = lineage.phase
        drafts.append(
            _draft(
                event=event,
                schema_name="evidence_recorded",
                occurred_at=envelope.receipt_time,
                payload=EvidenceRecordedPayload(
                    evidence_id(evidence),
                    EvidenceKind.OTHER,
                    EvidenceImmutability.METADATA_ONLY,
                    envelope.receipt_time,
                    reference=f"host-lineage:{lineage_identity}",
                    description=(
                        f"Observed host subagent {phase}; origin=host_observed; "
                        f"acceptance=pending; correlation={lineage_identity}"
                    ),
                ),
                role="subagent",
            )
        )
        captured_drafts, _captured_refs = _captured_evidence_drafts(
            envelope,
            task_id=task_id,
            manifests=captured,
            parents=(event,),
            mapping_version=mapping,
        )
        drafts.extend(captured_drafts)
        return MaterializedObservationBatch(tuple(drafts), coverage, channel, gaps, None)

    explicit_claim_kind = structural.get("claim_kind")
    if type(explicit_claim_kind) is str and explicit_claim_kind in {
        member.value for member in ClaimKind
    }:
        claim = stable_observation_id(
            kind=IdKind.CLAIM,
            task_id=task_id,
            source_identity=envelope.source_identity,
            mapping_version=mapping,
            role="claim",
        )
        event = stable_observation_id(
            kind=IdKind.EVENT,
            task_id=task_id,
            source_identity=envelope.source_identity,
            mapping_version=mapping,
            role="claim_event",
        )
        drafts.append(
            _draft(
                event=event,
                schema_name="claim_recorded",
                occurred_at=envelope.receipt_time,
                payload=ClaimRecordedPayload(
                    claim_id(claim),
                    ClaimKind(explicit_claim_kind),
                    "Explicit claim signal observed; not automatic completion proof",
                    (),
                ),
                role="claim",
            )
        )
        captured_drafts, _captured_refs = _captured_evidence_drafts(
            envelope,
            task_id=task_id,
            manifests=captured,
            parents=(event,),
            mapping_version=mapping,
        )
        drafts.extend(captured_drafts)
        return MaterializedObservationBatch(tuple(drafts), coverage, channel, gaps, None)

    if kind in _COMPLETION_KINDS or kind.endswith("Complete") or "claim" in kind.lower():
        evidence = stable_observation_id(
            kind=IdKind.EVIDENCE,
            task_id=task_id,
            source_identity=envelope.source_identity,
            mapping_version=mapping,
            role="completion_signal",
        )
        event = stable_observation_id(
            kind=IdKind.EVENT,
            task_id=task_id,
            source_identity=envelope.source_identity,
            mapping_version=mapping,
            role="completion_signal_event",
        )
        drafts.append(
            _draft(
                event=event,
                schema_name="evidence_recorded",
                occurred_at=envelope.receipt_time,
                payload=EvidenceRecordedPayload(
                    evidence_id(evidence),
                    EvidenceKind.OTHER,
                    EvidenceImmutability.METADATA_ONLY,
                    envelope.receipt_time,
                    description=f"Observed completion signal kind={kind}",
                ),
                role="completion_signal",
            )
        )
        captured_drafts, _captured_refs = _captured_evidence_drafts(
            envelope,
            task_id=task_id,
            manifests=captured,
            parents=(event,),
            mapping_version=mapping,
        )
        drafts.extend(captured_drafts)
        return MaterializedObservationBatch(tuple(drafts), coverage, channel, gaps, None)

    # Opaque structural observation for unrecognized but admitted kinds.
    evidence = stable_observation_id(
        kind=IdKind.EVIDENCE,
        task_id=task_id,
        source_identity=envelope.source_identity,
        mapping_version=mapping,
        role="opaque",
    )
    event = stable_observation_id(
        kind=IdKind.EVENT,
        task_id=task_id,
        source_identity=envelope.source_identity,
        mapping_version=mapping,
        role="opaque_event",
    )
    drafts.append(
        _draft(
            event=event,
            schema_name="evidence_recorded",
            occurred_at=envelope.receipt_time,
            payload=EvidenceRecordedPayload(
                evidence_id(evidence),
                EvidenceKind.OTHER,
                EvidenceImmutability.METADATA_ONLY,
                envelope.receipt_time,
                description=f"Opaque observation kind={kind}",
            ),
            role="opaque",
        )
    )
    captured_drafts, _captured_refs = _captured_evidence_drafts(
        envelope,
        task_id=task_id,
        manifests=captured,
        parents=(event,),
        mapping_version=mapping,
    )
    drafts.extend(captured_drafts)
    return MaterializedObservationBatch(tuple(drafts), coverage, channel, gaps, None)


def materialize_observation_outcome_correction(
    envelope: ObservationEnvelope,
    *,
    task_id: str,
    conflict: bool = False,
    target_action_id: str | None = None,
    target_action_event_id: str | None = None,
) -> MaterializedObservationBatch:
    """Append an explicit stream outcome that enriches an earlier UNKNOWN hook result.

    Historical action/result rows stay immutable. The correction is a second,
    source-independent result linked to the same canonical action, so retries are
    idempotent and explicit host failure/success facts remain visible. A replayed
    legacy-mapping operation committed its graph under pre-upgrade record
    identities; ``target_action_id`` (with an optional committed action event as
    causal parent) binds the correction to that exact committed action instead of
    the current canonical one.
    """

    structural = cast(Mapping[str, JsonValue], envelope.structural_payload)
    _pairing_mode, correlation_kind = _pairing_contract(envelope, structural)
    correlation = _correlation(structural, correlation_kind=correlation_kind)
    tool = _tool_name(structural)
    coverage = _coverage_for(envelope)
    channel = PublicationChannel.HOOK_OBSERVED
    gaps = tuple(envelope.gap_codes)
    if (
        envelope.source is not ObservationSource.CODEX_SESSION_STREAM
        or not stream_event_is_completed_tool(envelope.event_kind, structural)
        or correlation is None
        or ObservationGapCode.UNPAIRED_EVENT.value in gaps
    ):
        return MaterializedObservationBatch((), coverage, channel, gaps, "no_outcome_correction")
    outcome = _post_outcome(structural)
    if outcome is ResultOutcome.UNKNOWN:
        return MaterializedObservationBatch((), coverage, channel, gaps, "outcome_unknown")

    family = _action_kind(tool).value
    action_source = _materialization_call_source(
        envelope, phase="pre", correlation=correlation, family=family
    )
    if target_action_id is not None:
        action = action_id(target_action_id)
        action_parents = (
            (event_id(target_action_event_id),) if target_action_event_id is not None else ()
        )
    else:
        action = action_id(
            stable_observation_id(
                kind=IdKind.ACTION,
                task_id=task_id,
                source_identity=action_source,
                mapping_version=MATERIALIZATION_MAPPING_VERSION,
                role="action",
            )
        )
        action_parents = (
            event_id(
                stable_observation_id(
                    kind=IdKind.EVENT,
                    task_id=task_id,
                    source_identity=action_source,
                    mapping_version=MATERIALIZATION_MAPPING_VERSION,
                    role="action_event",
                )
            ),
        )
    exit_status = _exit_status(structural)
    correction_source = (
        f"outcome-correction:{_logical_source_lane(envelope.source)}:"
        f"{envelope.session_commitment}:{envelope.cursor.source_generation}:"
        f"{correlation}:{family}:{outcome.value}:"
        f"{exit_status if exit_status is not None else 'none'}"
    )
    correction_role = (
        f"result_correction_{outcome.value}_{exit_status if exit_status is not None else 'none'}"
    )
    result = stable_observation_id(
        kind=IdKind.RESULT,
        task_id=task_id,
        source_identity=correction_source,
        mapping_version=MATERIALIZATION_MAPPING_VERSION,
        role=correction_role,
    )
    result_event = stable_observation_id(
        kind=IdKind.EVENT,
        task_id=task_id,
        source_identity=correction_source,
        mapping_version=MATERIALIZATION_MAPPING_VERSION,
        role=f"{correction_role}_event",
    )
    if conflict:
        coverage = Coverage(
            publication_channels=coverage.publication_channels,
            authorship_assurance=coverage.authorship_assurance,
            artifact_observation=coverage.artifact_observation,
            evidence_immutability=coverage.evidence_immutability,
            ledger_freshness=coverage.ledger_freshness,
            check_types=coverage.check_types,
            known_gaps=tuple(
                sorted(
                    {*coverage.known_gaps, ObservationGapCode.DEDUP_CONFLICT.value},
                    key=str.encode,
                )
            ),
        )
        gaps = tuple(sorted({*gaps, ObservationGapCode.DEDUP_CONFLICT.value}, key=str.encode))
    draft = _draft(
        event=result_event,
        schema_name="result_recorded",
        occurred_at=envelope.receipt_time,
        payload=ResultRecordedPayload(
            result_id(result),
            action,
            outcome,
            exit_status=exit_status,
            summary=(
                f"Observed conflicting corrected result status={outcome.value}"
                if conflict
                else f"Observed corrected result status={outcome.value}"
            ),
        ),
        parents=action_parents,
        role=correction_role,
    )
    return MaterializedObservationBatch((draft,), coverage, channel, gaps, None)


def _logical_source_lane(source: ObservationSource) -> str:
    """Collapse only Codex hook/stream copies into one source lane."""

    if source in {ObservationSource.CODEX_HOOK, ObservationSource.CODEX_SESSION_STREAM}:
        return "codex"
    return source.value


def _legacy_logical_identity(envelope: ObservationEnvelope) -> str:
    """Reproduce the pre-1.6 identity for committed-operation recovery."""

    structural = cast(Mapping[str, JsonValue], envelope.structural_payload)
    # Explicit legacy replay keeps the old payload interpretation.  This is
    # only used to locate already-committed pre-1.6 rows; current materialized
    # identities still derive from the reviewed source/profile contract, so a
    # historical Cursor generation id cannot become a new tool identity.
    host_call = _correlation(structural)
    if host_call is None:
        return _logical_identity_digest(("opaque", envelope.source.value, envelope.source_identity))
    family = _action_kind(_tool_name(structural)).value
    return _logical_identity_digest(("action", envelope.session_commitment, host_call, family))


def canonical_logical_identity(
    envelope: ObservationEnvelope, *, mapping_version: str | None = None
) -> str:
    """Return the canonical logical-observation identity for one envelope.

    Hook ``PostToolUse`` and stream completed-tool copies of the same Codex
    call collapse to one identity (source lane + session + generation + host
    call/correlation id + tool family), so cross-source duplicates materialize
    a single ledger action or result. Claude and Cursor remain separate lanes.
    Consecutive identical commands with different host ids, sessions, or
    generations stay distinct. Events without a host call id (lifecycle,
    unsupported, or gap envelopes) fall back to a source-specific opaque
    identity so unrelated look-alikes never collide.

    ``mapping_version`` is accepted for replay of pre-1.6 operations, whose
    committed identities intentionally omitted the lane and generation.
    """

    if type(envelope) is not ObservationEnvelope:
        return _logical_identity_digest(("opaque", "invalid"))
    if mapping_version in set(MATERIALIZATION_LEGACY_MAPPING_VERSIONS) - {"obs-ledger/1.6.0"}:
        return _legacy_logical_identity(envelope)
    lineage = host_lineage_from_envelope(envelope)
    if lineage is not None:
        # Hook and session-stream copies of one host subagent signal share a source-stable
        # identity. Keep the phase in the key so start and stop remain distinct.
        identity = (
            lineage.correlation.legacy_logical_identity
            if mapping_version == "obs-ledger/1.6.0"
            else lineage.logical_identity
        )
        return _logical_identity_digest(("subagent", identity, lineage.phase))
    structural = cast(Mapping[str, JsonValue], envelope.structural_payload)
    _pairing_mode, correlation_kind = _pairing_contract(envelope, structural)
    host_call = _correlation(structural, correlation_kind=correlation_kind)
    if host_call is None:
        return _logical_identity_digest(("opaque", envelope.source.value, envelope.source_identity))
    family = _action_kind(_tool_name(structural)).value
    return _logical_identity_digest(
        (
            "action",
            _logical_source_lane(envelope.source),
            envelope.session_commitment,
            str(envelope.cursor.source_generation),
            host_call,
            family,
        )
    )


def observation_content_identity(
    envelope: ObservationEnvelope, *, mapping_version: str | None = None
) -> str:
    """Return the phase-scoped identity used to recover captured manifests.

    Ledger action/result identity intentionally collapses hook/stream copies and
    several phases of one host call. Captured content follows only the first
    half of that rule: equivalent same-phase copies share recovery, while
    Pre/Post/unpaired siblings remain isolated so they cannot change one
    another's materialized role sets.  ``mapping_version`` selects the
    historical identity when replaying a pre-1.6 manifest key.
    """

    if type(envelope) is not ObservationEnvelope:
        return _logical_identity_digest(("content", "opaque", "invalid"))
    structural = cast(Mapping[str, JsonValue], envelope.structural_payload)
    pairing_mode, correlation_kind = _pairing_contract(envelope, structural)
    kind = envelope.event_kind
    if (
        envelope.source is ObservationSource.CODEX_SESSION_STREAM
        and stream_event_is_completed_tool(kind, structural)
        and _correlation(structural, correlation_kind=correlation_kind) is not None
    ):
        kind = "PostToolUse"
    phase = (
        f"{kind}:unpaired"
        if (
            kind == "PostToolUse"
            and pairing_mode == "paired"
            and ObservationGapCode.UNPAIRED_EVENT.value in envelope.gap_codes
        )
        else kind
    )
    return _logical_identity_digest(
        (
            "content",
            canonical_logical_identity(envelope, mapping_version=mapping_version),
            phase,
        )
    )


def observation_claim_identity(
    envelope: ObservationEnvelope,
    draft_roles: tuple[str, ...],
    *,
    mapping_version: str = MATERIALIZATION_MAPPING_VERSION,
) -> str:
    """Return the role-scoped key for one durable logical-identity claim.

    One host call legitimately materializes several role-sets against the same
    canonical logical identity: hook ``PreToolUse`` (``action``), a paired
    ``PostToolUse`` (``action`` + ``result``), unpaired evidence, permission and
    subagent events carrying the call id, and opaque stream phases. Each has its
    own operation digest, so claims keyed on the bare logical identity conflict
    with their own siblings. Scoping the claim by roles (and by the mapping
    version, matching the digest) keeps each phase's claim independent while
    cross-source copies of the *same* phase still merge their source masks.
    """

    _validate_materialization_mapping_version(mapping_version)
    logical_identity = canonical_logical_identity(envelope, mapping_version=mapping_version)
    return _logical_identity_digest(
        (
            "claim",
            mapping_version,
            logical_identity,
            *draft_roles,
        )
    )


PAIRED_ACTION_ROLE: Final = "action"


@dataclass(frozen=True, slots=True)
class PairedActionLink:
    """The one canonical action of a paired host call carried by a batch (#917).

    The pre and the post of one paired call both key their action on the host
    call (lane, session, generation, correlation, family), so they name the same
    action and action event.  Whichever phase is appended first records it; the
    later phase appends ``linked``: the same batch without that action draft,
    whose result and captured evidence still reference the committed action.
    """

    action_id: str
    action_event_id: str
    linked: MaterializedObservationBatch


def paired_action_link(
    envelope: ObservationEnvelope,
    batch: MaterializedObservationBatch,
    *,
    task_id: str,
) -> PairedActionLink | None:
    """Return the canonical paired-call action a current-mapping batch carries, if any.

    Only a paired profile's ``PreToolUse`` pending action or linked ``PostToolUse``
    action qualifies.  Post-only profiles (the installed Claude Code and Cursor
    carriers), unpaired evidence, and every other role set return ``None`` and
    keep their materialization byte for byte.
    """

    if type(envelope) is not ObservationEnvelope or type(batch) is not MaterializedObservationBatch:
        return None
    if batch.skip_reason is not None or not batch.drafts:
        return None
    structural = cast(Mapping[str, JsonValue], envelope.structural_payload)
    pairing_mode, correlation_kind = _pairing_contract(envelope, structural)
    if pairing_mode != "paired":
        return None
    correlation = _correlation(structural, correlation_kind=correlation_kind)
    if correlation is None:
        return None
    source = _materialization_call_source(
        envelope,
        phase="pre",
        correlation=correlation,
        family=_action_kind(_tool_name(structural)).value,
    )
    action = stable_observation_id(
        kind=IdKind.ACTION,
        task_id=task_id,
        source_identity=source,
        mapping_version=MATERIALIZATION_MAPPING_VERSION,
        role="action",
    )
    action_event = stable_observation_id(
        kind=IdKind.EVENT,
        task_id=task_id,
        source_identity=source,
        mapping_version=MATERIALIZATION_MAPPING_VERSION,
        role="action_event",
    )
    matches = tuple(
        item
        for item in batch.drafts
        if item.role == PAIRED_ACTION_ROLE and str(item.draft.event_id) == action_event
    )
    if len(matches) != 1:
        return None
    remaining = tuple(item for item in batch.drafts if item is not matches[0])
    return PairedActionLink(action, action_event, replace(batch, drafts=remaining))


def paired_action_linked_roles(draft_roles: tuple[str, ...]) -> tuple[str, ...]:
    """Return the role set a batch has once its canonical paired action is linked."""

    return tuple(role for role in draft_roles if role != PAIRED_ACTION_ROLE)


@dataclass(frozen=True, slots=True)
class CodexCallGenerationLink:
    """The paired action one Codex stream command completion names in one generation.

    ``command_identity`` is the base ``omitted:<commitment>`` command identity the
    completion carries; an aliasing caller compares it with the committed action.
    """

    generation: int
    action_id: str
    action_event_id: str
    command_identity: str


def codex_stream_call_generation_links(
    envelope: ObservationEnvelope,
    *,
    task_id: str,
    generations: tuple[int, ...],
) -> tuple[CodexCallGenerationLink, ...]:
    """Return the paired-call action identities a stream completion would name per generation.

    A Codex hook advances its session generation at every ``SessionStart``, including the
    ``compact`` start after a context compaction, while the session stream's generation follows
    the rollout file, which compaction does not rotate. The pair's action identity includes the
    generation, so after a compaction a stream completion no longer names its hook call (#1019).
    This returns the candidate identities for the given generations so the coordinator can find
    the hook call. Only a completed, paired Codex stream command with a host call id and a keyed
    command commitment qualifies; every other envelope returns ``()``.
    """

    if type(envelope) is not ObservationEnvelope:
        return ()
    structural = cast(Mapping[str, JsonValue], envelope.structural_payload)
    if (
        envelope.source is not ObservationSource.CODEX_SESSION_STREAM
        or not stream_event_is_completed_tool(envelope.event_kind, structural)
        or ObservationGapCode.UNPAIRED_EVENT.value in envelope.gap_codes
    ):
        return ()
    pairing_mode, correlation_kind = _pairing_contract(envelope, structural)
    if pairing_mode != "paired":
        return ()
    correlation = _correlation(structural, correlation_kind=correlation_kind)
    commitment = structural.get("command_commitment")
    family = _action_kind(_tool_name(structural))
    if correlation is None or type(commitment) is not str or family is not ActionKind.COMMAND:
        return ()
    links: list[CodexCallGenerationLink] = []
    for generation in generations:
        if type(generation) is not int or isinstance(generation, bool) or generation < 1:
            continue
        aliased = replace(envelope, cursor=replace(envelope.cursor, source_generation=generation))
        source = _materialization_call_source(
            aliased, phase="pre", correlation=correlation, family=family.value
        )
        links.append(
            CodexCallGenerationLink(
                generation,
                stable_observation_id(
                    kind=IdKind.ACTION,
                    task_id=task_id,
                    source_identity=source,
                    mapping_version=MATERIALIZATION_MAPPING_VERSION,
                    role="action",
                ),
                stable_observation_id(
                    kind=IdKind.EVENT,
                    task_id=task_id,
                    source_identity=source,
                    mapping_version=MATERIALIZATION_MAPPING_VERSION,
                    role="action_event",
                ),
                observed_command_field(commitment),
            )
        )
    return tuple(links)


def _logical_identity_digest(components: tuple[str, ...]) -> str:
    """Hash domain-separated components into a nul-free ``sha256:`` identity.

    The result is safe to embed in canonical request digests (which forbid nul
    bytes) while remaining a stable equality key across sources.
    """

    material = _LOGICAL_IDENTITY_DOMAIN.encode() + b"\x00"
    material += b"\x00".join(component.encode() for component in components)
    return "sha256:" + hashlib.sha256(material).hexdigest()


def observation_operation_digest(
    *,
    task_id: str,
    logical_identity: str,
    draft_roles: tuple[str, ...],
    mapping_version: str = MATERIALIZATION_MAPPING_VERSION,
    session_id: str | None = None,
    writer_id: str | None = None,
) -> str:
    """Stable request digest for idempotent observation appends.

    Keyed on the canonical *logical* identity rather than the source-specific
    identity so matching hook/stream copies produce one ledger operation.

    Under the current mapping the digest is task-scoped: the stable event ids it
    commits depend on the task and the source identity (which includes the
    source lane, host session, and generation), so the operation that owns them
    must be findable from any later Yoetz session of the same task (a workflow
    reattach rotates the routed session and writer, #560). The legacy
    session-bound versions still require ``session_id`` and ``writer_id`` so a
    pre-upgrade committed operation keeps its exact replay identity.
    """

    _validate_materialization_mapping_version(mapping_version)
    material: dict[str, JsonValue] = {
        "protocol": "yoetz",
        "kind": "observation_materialize",
        "task_id": task_id,
        "logical_identity": logical_identity,
        "roles": draft_roles,
        "mapping_version": mapping_version,
    }
    if mapping_version in SESSION_BOUND_MAPPING_VERSIONS:
        if type(session_id) is not str or type(writer_id) is not str:
            raise ValueError("session-bound observation mapping requires session and writer")
        material["session_id"] = session_id
        material["writer_id"] = writer_id
    elif session_id is not None or writer_id is not None:
        raise ValueError("task-scoped observation mapping digest takes no session or writer")
    return request_digest(JsonObject(material))


def _validate_materialization_mapping_version(mapping_version: str) -> None:
    if type(mapping_version) is not str or mapping_version not in {
        MATERIALIZATION_MAPPING_VERSION,
        *MATERIALIZATION_LEGACY_MAPPING_VERSIONS,
    }:
        raise ValueError("unsupported observation materialization mapping version")


def observation_author() -> Actor:
    return Actor(
        actor_id(OBSERVATION_COORDINATOR_ACTOR_ID),
        ActorType.HARNESS,
        AuthorshipAssurance.HARNESS_OBSERVED,
    )


def observation_writer_id(task_id: str, session_id: str) -> str:
    """Derive the admitted harness writer for one task session."""

    return stable_observation_id(
        kind=IdKind.WRITER,
        task_id=task_id,
        source_identity=session_id,
        mapping_version="obs-writer/1.0.0",
        role="observation",
    )


def approved_check_author() -> Actor:
    return Actor(
        actor_id("yoetz:approved-check-service"),
        ActorType.YOETZ_ENGINE,
        AuthorshipAssurance.SERVICE_AUTHENTICATED,
    )


# Re-export for callers that stage objects.
media_type_for_schema = media_type_for
