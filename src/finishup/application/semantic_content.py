"""Service-side authentication and selection of retained observation content.

The AI-powered review case builder stays pure. This module is the narrow application boundary that reads
the current observation consent, resolves only manifests referenced by current envelopes, verifies
the encrypted object and canonical inner wrapper, and hands bounded frozen values to the builder.
No structural event or outbox row is modified here, and no provider is contacted.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Final, cast

from finishup.application.observation_materialize import (
    MATERIALIZATION_MAPPING_VERSION,
    observation_content_identity,
    stable_observation_id,
)
from finishup.application.semantic_case import (
    MAX_CAPTURED_SEMANTIC_CONTENT_BYTES,
    CapturedContentScope,
    CapturedSemanticContent,
    declared_output_capture_refs,
    repair_evidence_refs,
)
from finishup.domain.events import (
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceImmutability,
    EvidenceKind,
    EvidenceRecordedPayload,
)
from finishup.domain.observation import (
    ObservationContentChunk,
    ObservationContentKind,
    ObservationContentManifest,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationSource,
    observation_source_qualified_content_binding_matches,
)
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_HOOK_MAPPING_VERSION,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.domain.values import validate_sha256_digest
from finishup.kernel.claims import effective_claim_items
from finishup.kernel.observed_failures import observed_command_field
from finishup.kernel.projections import EvidenceProjectionRecord, ProjectionState
from finishup.kernel.verification_capture import verification_capture_command
from finishup.ports.ledger import FrozenCase
from finishup.ports.objects import ObjectKind, ObjectRef
from finishup.ports.runtime import TaskRuntime
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind

__all__ = [
    "CapturedContentResolution",
    "edit_capture_evidence_count",
    "resolve_captured_semantic_content",
]

_CAPTURED_CONTENT_MEDIA_TYPE: Final = "application/vnd.yoetz.observation-content+json"
_CAPTURED_CONTENT_INNER_MEDIA_TYPE: Final = "text/plain"
_MAX_WRAPPER_BYTES: Final = 1_048_576
_CLAUDE_ORDINARY_PROFILE: Final = CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
_CURSOR_ORDINARY_PROFILE: Final = CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
# Codex's original observation grant predates the opt-in Claude/Cursor content
# profile selector. This source token is an internal AI-powered review scope label for
# that historical, profileless grant; it is never accepted as a local consent
# profile or as a capture-only request profile.
_CODEX_HISTORICAL_CAPTURE_SCOPE: Final = ObservationSource.CODEX_HOOK.value
# Only the reviewed native hook vocabulary can authorize selection. A shared
# source token does not make future or session-stream mappings compatible.
_CODEX_REVIEWED_HOOK_MAPPINGS: Final = frozenset({"codex-obs-hook/1.0.0"})
# These are the only Claude ordinary hook mappings whose captured-content wire
# contract has been reviewed. Keep the historical v1 literal so upgrading the
# ingress mapping does not make already-authenticated v1 envelopes unreadable;
# future or malformed hints must still fail closed until reviewed explicitly.
_CLAUDE_ORDINARY_REVIEWED_MAPPINGS: Final = frozenset(
    {
        "claude-code-hooks-ordinary-v1",
        "claude-code-hooks-ordinary-v2",
    }
)
_ORDINARY_CAPTURE_PROFILES: Final = frozenset({_CLAUDE_ORDINARY_PROFILE, _CURSOR_ORDINARY_PROFILE})
_AUTHORIZED_CAPTURE_PROFILES: Final = frozenset(
    {*_ORDINARY_CAPTURE_PROFILES, _CODEX_HISTORICAL_CAPTURE_SCOPE}
)
_MAX_CAPTURED_SEMANTIC_PARTS: Final = 64
_MAX_CAPTURED_SEMANTIC_INPUT_BYTES: Final = 2 * MAX_CAPTURED_SEMANTIC_CONTENT_BYTES
_CONTENT_GAPS: Final = frozenset(
    {
        ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
        ObservationGapCode.CONTENT_REDACTED.value,
        ObservationGapCode.CONTENT_UNSELECTED.value,
        ObservationGapCode.TRUNCATED_PAYLOAD.value,
    }
)
_CORRELATION_KEYS: Final = (
    "tool_use_id",
    "tool_call_id",
    "correlation_id",
    "parent_tool_call_id",
)


@dataclass(frozen=True, slots=True)
class _LocalCaptureFence:
    """Validated, plaintext-free snapshot of the authoritative local consent arm."""

    generation: str
    active: bool
    revoked: bool
    runtime_enabled: bool
    profiles: tuple[str, ...]


def _local_capture_fence(
    local_observation: object | None,
    workspace: str,
) -> tuple[_LocalCaptureFence | None, set[str], bool]:
    """Read the local consent fence, distinguishing missing from no local seam.

    ``TaskRuntime.observation`` is the mapped task bundle and can lag the owner-private local
    store while a pause, disable, or revoke is being propagated. Production passes the local
    store explicitly; the third return value preserves compatibility for pure/fake callers that
    have no local adapter at all.
    """

    if local_observation is None:
        return None, set(), False
    reader = getattr(local_observation, "content_capture_authority", None)
    if not callable(reader):
        return None, {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}, True
    try:
        raw = reader(workspace)
    except Exception:
        return None, {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}, True
    if raw is None:
        return None, {ObservationGapCode.CONSENT_MISSING.value}, True
    authority_workspace = getattr(raw, "workspace_commitment", None)
    generation = getattr(raw, "generation", None)
    active = getattr(raw, "active", None)
    revoked = getattr(raw, "revoked", False)
    runtime_enabled = getattr(raw, "runtime_enabled", None)
    raw_profiles = getattr(raw, "profiles", None)
    if (
        type(authority_workspace) is not str
        or authority_workspace != workspace
        or type(generation) is not str
        or type(active) is not bool
        or type(revoked) is not bool
        or type(runtime_enabled) is not bool
        or type(raw_profiles) is not tuple
    ):
        return None, {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}, True
    profiles = cast(tuple[object, ...], raw_profiles)
    if len(profiles) > 2 or any(type(profile) is not str for profile in profiles):
        return None, {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}, True
    profile_values = tuple(cast(str, profile) for profile in profiles)
    if (
        any(profile not in _ORDINARY_CAPTURE_PROFILES for profile in profile_values)
        or tuple(sorted(set(profile_values), key=str.encode)) != profile_values
    ):
        return None, {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}, True
    try:
        generation = validate_sha256_digest(generation)
    except (TypeError, ValueError):
        return None, {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}, True
    return (
        _LocalCaptureFence(
            generation,
            active,
            revoked,
            runtime_enabled,
            profile_values,
        ),
        set(),
        True,
    )


def _local_capture_fence_current(
    local_observation: object | None,
    workspace: str,
    fence: _LocalCaptureFence,
) -> bool:
    """Check the local fence at a linearization point before opening/dispatching."""

    if local_observation is None:
        return True
    checker = getattr(local_observation, "content_capture_authority_is_current", None)
    if callable(checker):
        try:
            return checker(workspace, fence.generation, fence.profiles) is True
        except Exception:
            return False
    current, _gaps, _provided = _local_capture_fence(local_observation, workspace)
    return current is not None and current == fence and current.active


type _CandidateRow = tuple[str, EvidenceRecordedPayload, EvidenceProjectionRecord]
type _PendingRow = tuple[
    ObservationEnvelope,
    str,
    str,
    str,
    str,
    frozenset[str],
    EvidenceRecordedPayload,
]
type _MetadataRow = tuple[
    ObservationEnvelope,
    str,
    str,
    str,
    str,
    frozenset[str],
    EvidenceRecordedPayload,
    ObservationContentManifest,
]


@dataclass(frozen=True, slots=True)
class CapturedContentResolution:
    """Frozen result of one current-consent observation-content read."""

    scope: CapturedContentScope | None
    content: tuple[CapturedSemanticContent, ...]
    gaps: tuple[str, ...]
    # A local-store generation is carried back to the dispatch seam. The AI-powered
    # case may contain authenticated bytes only while this same generation is
    # still active; a pause/disable/revoke therefore invalidates the case before
    # another object open or provider call.
    local_fence_generation: str | None = None
    local_fence_profiles: tuple[str, ...] = ()
    local_fence_required: bool = False

    def __post_init__(self) -> None:
        if self.scope is not None and type(self.scope) is not CapturedContentScope:
            raise ValueError("semantic_content_resolution_invalid")
        if type(self.content) is not tuple or len(self.content) > _MAX_CAPTURED_SEMANTIC_PARTS:
            raise ValueError("semantic_content_resolution_invalid")
        if any(type(item) is not CapturedSemanticContent for item in self.content):
            raise ValueError("semantic_content_resolution_invalid")
        if type(self.gaps) is not tuple or len(self.gaps) > 16:
            raise ValueError("semantic_content_resolution_invalid")
        if any(type(gap) is not str or not gap for gap in self.gaps):
            raise ValueError("semantic_content_resolution_invalid")
        if self.gaps != tuple(sorted(set(self.gaps), key=str.encode)):
            raise ValueError("semantic_content_resolution_invalid")
        if self.local_fence_generation is not None and (
            type(self.local_fence_generation) is not str
        ):
            raise ValueError("semantic_content_resolution_invalid")
        if self.local_fence_generation is not None:
            try:
                validate_sha256_digest(self.local_fence_generation)
            except (TypeError, ValueError):
                raise ValueError("semantic_content_resolution_invalid") from None
        if (
            type(self.local_fence_profiles) is not tuple
            or len(self.local_fence_profiles) > 2
            or any(
                profile not in _ORDINARY_CAPTURE_PROFILES for profile in self.local_fence_profiles
            )
            or tuple(sorted(set(self.local_fence_profiles), key=str.encode))
            != self.local_fence_profiles
        ):
            raise ValueError("semantic_content_resolution_invalid")
        if type(self.local_fence_required) is not bool:
            raise ValueError("semantic_content_resolution_invalid")


def _profile_for_envelope(envelope: ObservationEnvelope) -> str | None:
    """Return a profile only for the exact ordinary renderer identity.

    Source enum alone is insufficient: legacy/native hook envelopes use the same
    source while carrying different structural vocabularies and must never gain
    the ordinary captured-content arm by inference. Codex's historical structural
    grant is represented by the existing source token, but only on the hook lane;
    the session-stream lane remains structural-only.
    """

    structural = envelope.structural_payload
    profile = structural.get("capability_profile_id")
    mapping_hint = structural.get("mapping_hint")
    if envelope.source is ObservationSource.CODEX_HOOK:
        # A Codex hook has no native content-profile selector. If a caller stamps
        # a foreign profile/mapping into its structural payload, leave it
        # unselected rather than letting the source-only historical arm hide that
        # contradiction. The hook mapper itself does not stamp either field for
        # Codex.
        if (
            profile is None
            and mapping_hint is None
            and envelope.cursor.mapping_version in _CODEX_REVIEWED_HOOK_MAPPINGS
        ):
            return _CODEX_HISTORICAL_CAPTURE_SCOPE
    elif envelope.source is ObservationSource.CLAUDE_HOOK:
        if (
            profile == _CLAUDE_ORDINARY_PROFILE
            and mapping_hint in _CLAUDE_ORDINARY_REVIEWED_MAPPINGS
        ):
            return _CLAUDE_ORDINARY_PROFILE
    elif envelope.source is ObservationSource.CURSOR_HOOK:
        if (
            profile == _CURSOR_ORDINARY_PROFILE
            and mapping_hint == CURSOR_ORDINARY_HOOK_MAPPING_VERSION
        ):
            return _CURSOR_ORDINARY_PROFILE
    return None


def _consent_profiles(observation: object, workspace: str) -> tuple[tuple[str, ...], set[str]]:
    """Read and validate the current closed content-consent vocabulary.

    New stores expose the plural profile accessor.  The consent-object fallback
    keeps older in-process stores useful, but both paths reject unknown profile
    strings before any object can be opened.
    """

    profiles_reader = cast(
        Callable[[str], object] | None,
        getattr(observation, "content_capture_profiles", None),
    )
    if callable(profiles_reader):
        try:
            raw_profiles = profiles_reader(workspace)
        except Exception:
            return (), {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}
        if type(raw_profiles) is not tuple:
            return (), {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}
        profiles = cast(tuple[object, ...], raw_profiles)
        if any(type(profile) is not str for profile in profiles):
            return (), {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}
        profile_values = tuple(cast(str, profile) for profile in profiles)
        if (
            len(profile_values) > 2
            or any(profile not in _ORDINARY_CAPTURE_PROFILES for profile in profile_values)
            or tuple(sorted(set(profile_values), key=str.encode)) != profile_values
        ):
            return (), {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}
        if not profile_values:
            return (), {ObservationGapCode.CONTENT_UNSELECTED.value}
        return profile_values, set()

    consent_for = cast(Callable[[str], object] | None, getattr(observation, "consent_for", None))
    if not callable(consent_for):
        return (), {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}
    try:
        consent = consent_for(workspace)
    except Exception:
        return (), {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}
    if consent is None:
        return (), {ObservationGapCode.CONSENT_MISSING.value}
    if getattr(consent, "revoked_at", None) is not None:
        return (), {
            ObservationGapCode.CONSENT_REVOKED.value,
            ObservationGapCode.CONTENT_UNSELECTED.value,
        }
    if getattr(consent, "paused", False):
        return (), {ObservationGapCode.CONTENT_UNSELECTED.value}
    raw_profiles = getattr(consent, "content_capture_profiles", ())
    if type(raw_profiles) is not tuple:
        return (), {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}
    profiles = cast(tuple[object, ...], raw_profiles)
    if any(type(profile) is not str for profile in profiles):
        return (), {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}
    profile_values = tuple(cast(str, profile) for profile in profiles)
    if (
        len(profile_values) > 2
        or any(profile not in _ORDINARY_CAPTURE_PROFILES for profile in profile_values)
        or tuple(sorted(set(profile_values), key=str.encode)) != profile_values
    ):
        return (), {ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value}
    if not profile_values:
        return (), {ObservationGapCode.CONTENT_UNSELECTED.value}
    return profile_values, set()


async def _read_wrapper(
    runtime: TaskRuntime,
    ref: ObjectRef,
    *,
    fence_check: Callable[[], bool] | None = None,
) -> bytes:
    if fence_check is not None and not fence_check():
        raise ValueError("content_capture_unavailable")
    collected = bytearray()
    async for chunk in runtime.objects.open_verified(ref):
        if fence_check is not None and not fence_check():
            collected.clear()
            raise ValueError("content_capture_unavailable")
        if type(chunk) is not bytes or len(collected) + len(chunk) > _MAX_WRAPPER_BYTES:
            collected.clear()
            raise ValueError("content_capture_unavailable")
        collected.extend(chunk)
    if not collected:
        raise ValueError("content_capture_unavailable")
    result = bytes(collected)
    collected.clear()
    if len(result) != ref.plaintext_size:
        raise ValueError("content_capture_unavailable")
    if fence_check is not None and not fence_check():
        raise ValueError("content_capture_unavailable")
    return result


def _manifest_from_wrapper(
    material: bytes,
    *,
    object_id: str,
    envelope_digest: str,
) -> tuple[ObservationContentManifest, bytes]:
    try:
        parsed = strict_json_parse(material)
    except (TypeError, ValueError) as exc:
        raise ValueError("content_capture_unavailable") from exc
    expected_keys = {
        "format",
        "content_kind",
        "correlation_identity",
        "source_commitment",
        "media_type",
        "part_index",
        "part_count",
        "redacted",
        "content_b64",
    }
    if (
        not isinstance(parsed, Mapping)
        or set(parsed) != expected_keys
        or canonical_encode(cast(JsonValue, parsed)) != material
        or parsed.get("format") != "yoetz.observation-content/1"
        or type(parsed.get("content_b64")) is not str
        or type(parsed.get("redacted")) is not bool
        or parsed.get("media_type") != _CAPTURED_CONTENT_INNER_MEDIA_TYPE
    ):
        raise ValueError("content_capture_unavailable")
    encoded = cast(str, parsed["content_b64"])
    try:
        content = base64.b64decode(encoded, validate=True)
        chunk = ObservationContentChunk(
            content_kind=ObservationContentKind(cast(str, parsed["content_kind"])),
            correlation_identity=cast(str, parsed["correlation_identity"]),
            source_commitment=cast(str, parsed["source_commitment"]),
            media_type=cast(str, parsed["media_type"]),
            part_index=cast(int, parsed["part_index"]),
            part_count=cast(int, parsed["part_count"]),
            content=content,
            redacted=cast(bool, parsed["redacted"]),
        )
        manifest = ObservationContentManifest(
            object_id=object_id,
            envelope_digest=envelope_digest,
            content_kind=chunk.content_kind,
            part_index=chunk.part_index,
            part_count=chunk.part_count,
            redacted=chunk.redacted,
            content_digest="sha256:" + hashlib.sha256(chunk.content).hexdigest(),
            content_bytes=len(chunk.content),
            correlation_identity=chunk.correlation_identity,
            source_commitment=chunk.source_commitment,
        )
    except (binascii.Error, TypeError, ValueError) as exc:
        raise ValueError("content_capture_unavailable") from exc
    return manifest, content


def _correlations(envelope: ObservationEnvelope) -> frozenset[str]:
    structural = cast(Mapping[str, object], envelope.structural_payload)
    return frozenset(
        value
        for key in _CORRELATION_KEYS
        for value in (structural.get(key),)
        if type(value) is str and value
    )


def _correlation_matches(
    envelope: ObservationEnvelope,
    manifest: ObservationContentManifest,
    correlations: frozenset[str],
) -> bool:
    """Accept only the correlation forms emitted by the native hook mapper."""

    correlation = manifest.correlation_identity
    if correlation is None:
        return False
    if correlation in correlations:
        return True
    prefix = f"{envelope.source_identity}:"
    if not correlation.startswith(prefix):
        return False
    suffix = correlation[len(prefix) :]
    allowed_suffixes = {
        ObservationContentKind.TOOL_OUTPUT: frozenset({"tool-output"}),
        ObservationContentKind.TOOL_INPUT: frozenset({"tool-input"}),
        ObservationContentKind.CHANGED_FILE: frozenset({"changed-file"}),
        ObservationContentKind.WORKSPACE_DIFF: frozenset({"diff", "patch"}),
    }
    return suffix in allowed_suffixes.get(manifest.content_kind, frozenset())


def _sort_gaps(gaps: set[str]) -> tuple[str, ...]:
    return tuple(sorted(gaps, key=str.encode))[:16]


_EDIT_CONTENT_KINDS: Final = frozenset(
    {ObservationContentKind.WORKSPACE_DIFF, ObservationContentKind.CHANGED_FILE}
)
_EDIT_CAPTURE_DESCRIPTIONS: Final = tuple(
    f"Observation-captured {kind.value} bytes " for kind in sorted(_EDIT_CONTENT_KINDS)
)


def _is_edit_capture(payload: EvidenceRecordedPayload) -> bool:
    """Return the service-authored edit-kind hint of one materialized captured row."""

    return (payload.description or "").startswith(_EDIT_CAPTURE_DESCRIPTIONS)


def edit_capture_evidence_count(projection: ProjectionState) -> int:
    """Count evidence rows that materialized a native edit capture; a diagnostic integer only.

    Compared with ``semantic_diff_parts_resolved``, it separates edits whose captures never reached
    the ledger (zero here) from captures the resolver or selection then declined.
    """

    return sum(
        1
        for record in projection.evidence.values()
        if record.payload is not None
        and record.payload.captured_object_id is not None
        and _is_edit_capture(record.payload)
    )


def _projected_candidates(
    frozen: FrozenCase,
    *,
    allowed: frozenset[str],
) -> tuple[dict[str, tuple[_CandidateRow, ...]], set[str]]:
    """Index only case-allowed, typed captured evidence before any object read."""

    candidates: dict[str, list[_CandidateRow]] = {}
    gaps: set[str] = set()
    for raw_ref, record in frozen.case.projection.evidence.items():
        evidence_ref = str(raw_ref)
        if evidence_ref not in allowed:
            continue
        typed_record = record
        payload = typed_record.payload
        object_value = None if payload is None else payload.captured_object_id
        if object_value is None:
            continue
        if (
            type(payload) is not EvidenceRecordedPayload
            or payload.evidence_kind is not EvidenceKind.OTHER
            or payload.strength is not EvidenceImmutability.IMMUTABLE_SNAPSHOT
            or payload.content_digest is None
            or type(payload.digest_binding) is not EvidenceDigestBinding
            or payload.digest_binding.subject is not EvidenceDigestSubject.BOUNDED_EXCERPT
            or payload.digest_binding.content_availability
            is not EvidenceContentAvailability.CAPTURED
            or payload.digest_binding.provenance
            is not EvidenceDigestProvenance.OBSERVATION_CAPTURED
            or type(payload.digest_binding.byte_count) is not int
            or payload.digest_binding.byte_count <= 0
        ):
            gaps.add(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
            continue
        if (
            typed_record.redacted
            or not typed_record.object_available
            or typed_record.redacted_object_id is not None
        ):
            gaps.add(
                ObservationGapCode.CONTENT_REDACTED.value
                if typed_record.redacted
                else ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
            )
            continue
        assert payload is not None
        candidates.setdefault(str(object_value), []).append((evidence_ref, payload, typed_record))
    return (
        {
            object_value: tuple(sorted(rows, key=lambda row: row[0].encode("ascii")))
            for object_value, rows in candidates.items()
        },
        gaps,
    )


def _session_commitment_for_runtime(
    observation: object,
    workspace: str,
    session_id: str,
    task_id: str,
) -> str:
    route_reader = getattr(observation, "observation_route_for_session", None)
    if callable(route_reader):
        try:
            route = route_reader(workspace=workspace, finishup_session_id=session_id)
        except Exception as exc:
            raise ValueError("content_capture_unavailable") from exc
        if type(route) is not tuple:
            raise ValueError("content_capture_unavailable")
        route_values = cast(tuple[object, ...], route)
        if (
            len(route_values) != 3
            or type(route_values[0]) is not str
            or type(route_values[1]) is not str
            or type(route_values[2]) is not bool
            or route_values[1] != task_id
        ):
            raise ValueError("content_capture_unavailable")
        # An inactive historical route is admitted only for this exact runtime
        # task. This explicit same-task reattach case retains task evidence while
        # refusing a row from another task; no broad workspace fallback exists.
        commitment = route_values[0]
        if not commitment:
            raise ValueError("content_capture_unavailable")
        return commitment
    # The historical commitment-only accessor cannot prove the runtime task or whether the
    # route is an explicit same-task reattach. Captured-content disclosure therefore fails closed
    # when the strengthened route seam is unavailable.
    raise ValueError("content_capture_unavailable")


async def _session_envelopes(
    observation: object,
    *,
    workspace: str,
    session_id: str,
    task_id: str,
    gaps: set[str],
    content_refs: frozenset[str] = frozenset(),
) -> tuple[ObservationEnvelope, ...]:
    """Read envelopes for the exact routed task session and reattach route.

    The latest-256 window bounds the ordinary read. Selected captured objects referenced only by
    older envelopes (for example, edits made early in a long session) are then read by exact
    content reference, so recency never silently drops an already-selected capture.
    """

    try:
        session_commitment = _session_commitment_for_runtime(
            observation,
            workspace,
            session_id,
            task_id,
        )
    except ValueError:
        gaps.add(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
        return ()

    status_reader = cast(
        Callable[[str, str], Awaitable[object]] | None,
        getattr(observation, "status_for_session", None),
    )
    if callable(status_reader):
        try:
            await status_reader(workspace, session_commitment)
        except Exception:
            gaps.add(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
            return ()

    list_for_session = cast(
        Callable[..., object] | None,
        getattr(observation, "list_envelopes_for_session", None),
    )
    try:
        if callable(list_for_session):
            loaded = list_for_session(workspace, session_commitment, limit=256)
        else:
            list_envelopes = cast(Callable[..., object], getattr(observation, "list_envelopes"))
            loaded = list_envelopes(workspace, limit=256)
    except Exception:
        gaps.add(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
        return ()
    if type(loaded) is not tuple:
        gaps.add(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
        return ()
    loaded_items = cast(tuple[object, ...], loaded)
    envelopes = tuple(
        item
        for item in loaded_items
        if type(item) is ObservationEnvelope and item.session_commitment == session_commitment
    )
    if len(envelopes) != len(loaded_items):
        gaps.add(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
    referenced = {ref for item in envelopes for ref in item.content_object_refs}
    missing = content_refs - referenced
    if missing:
        list_for_refs = cast(
            Callable[..., object] | None,
            getattr(observation, "list_envelopes_for_content_refs", None),
        )
        older: object = ()
        if callable(list_for_refs):
            try:
                older = list_for_refs(
                    workspace,
                    session_commitment,
                    tuple(sorted(missing, key=str.encode)),
                )
            except Exception:
                older = ()
        known = {item.source_identity for item in envelopes}
        extra = tuple(
            item
            for item in (cast(tuple[object, ...], older) if type(older) is tuple else ())
            if type(item) is ObservationEnvelope
            and item.session_commitment == session_commitment
            and item.source_identity not in known
        )
        envelopes = (*envelopes, *extra)
        if missing - {ref for item in extra for ref in item.content_object_refs}:
            # Disclose selected captures that no bounded read could reach.
            gaps.add(ObservationGapCode.CONTENT_UNSELECTED.value)
    return tuple(
        sorted(
            envelopes,
            key=lambda item: (
                item.cursor.source_generation,
                item.cursor.event_position,
                item.source_identity.encode("ascii"),
            ),
        )
    )


async def resolve_captured_semantic_content(
    *,
    runtime: TaskRuntime,
    frozen: FrozenCase,
    workspace_commitment: str,
    local_observation: object | None = None,
    max_parts: int = _MAX_CAPTURED_SEMANTIC_PARTS,
    max_total_bytes: int = _MAX_CAPTURED_SEMANTIC_INPUT_BYTES,
    workspace_root: str | None = None,
) -> CapturedContentResolution:
    """Resolve current-consent native content for one frozen task.

    Every returned part is authenticated twice: the object store verifies the encrypted envelope,
    then this seam verifies the canonical observation wrapper and its digest/byte binding. Content
    is selected only from envelopes in the exact observation workspace and is later rechecked by
    ``build_semantic_case`` against the frozen evidence projection. The historical profileless
    Codex arm is activated only after an active local structural grant and a linked Codex hook
    envelope are both present; Codex session-stream envelopes never activate it.
    """

    if type(runtime) is not TaskRuntime or type(frozen) is not FrozenCase:
        raise TypeError("semantic_content_runtime_invalid")
    if (
        type(max_parts) is not int
        or not 0 <= max_parts <= _MAX_CAPTURED_SEMANTIC_PARTS
        or type(max_total_bytes) is not int
        or not 1 <= max_total_bytes <= _MAX_CAPTURED_SEMANTIC_INPUT_BYTES
    ):
        raise ValueError("semantic_content_bounds_invalid")
    observation = runtime.observation
    if observation is None:
        return CapturedContentResolution(
            None,
            (),
            ("content_capture_unavailable",),
            local_fence_required=False,
        )
    local_fence, local_gaps, local_fence_provided = _local_capture_fence(
        local_observation,
        workspace_commitment,
    )
    profiles, gaps = _consent_profiles(observation, workspace_commitment)
    gaps.update(local_gaps)
    if local_fence_provided and (
        local_fence is None or not local_fence.active or not local_fence.runtime_enabled
    ):
        if local_fence is not None and local_fence.revoked:
            gaps.add(ObservationGapCode.CONSENT_REVOKED.value)
        else:
            gaps.add(ObservationGapCode.CONTENT_UNSELECTED.value)
        return CapturedContentResolution(
            None,
            (),
            _sort_gaps(gaps),
            None if local_fence is None else local_fence.generation,
            () if local_fence is None else local_fence.profiles,
            False,
        )
    if local_fence is not None:
        # Local consent is authoritative for the content arm. Task-store profiles
        # may lag after a CLI change; selecting their intersection preserves the
        # durable task boundary while local disable/pause/revoke remains immediate.
        profiles = tuple(profile for profile in profiles if profile in local_fence.profiles)
        if not profiles:
            gaps.add(ObservationGapCode.CONTENT_UNSELECTED.value)
    # The historical Codex grant is profileless and is admitted only after the
    # exact session route yields a CODEX_HOOK envelope with linked content. Keep
    # this as a candidate gate until then; an active local fence by itself must
    # never create an AI-powered review disclosure scope.
    codex_historical_candidate = (
        local_fence_provided
        and local_fence is not None
        and ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value not in gaps
    )
    scope = (
        None
        if not profiles
        else CapturedContentScope(
            task_id=runtime.task_id,
            session_id=runtime.session_id,
            workspace_commitment=workspace_commitment,
            authorized_profiles=profiles,
        )
    )
    if scope is None and not codex_historical_candidate:
        return CapturedContentResolution(
            None,
            (),
            _sort_gaps(gaps),
            None if local_fence is None else local_fence.generation,
            () if local_fence is None else local_fence.profiles,
            False,
        )

    if max_parts == 0:
        gaps.add(ObservationGapCode.CONTENT_UNSELECTED.value)
        return CapturedContentResolution(
            scope,
            (),
            _sort_gaps(gaps),
            None if local_fence is None else local_fence.generation,
            () if local_fence is None else local_fence.profiles,
            False,
        )

    allowed = frozenset(str(ref) for ref in frozen.case.allowed_ids)
    candidates, candidate_gaps = _projected_candidates(frozen, allowed=allowed)
    gaps.update(candidate_gaps)
    # Metadata selection is bounded independently from AI-powered review part admission:
    # selecting only the first object ID could split a valid multipart group and
    # turn an otherwise admissible capture into a false unavailable gap.
    repair_refs = repair_evidence_refs(frozen.case.projection, allowed)
    # Captures of a declared output outside the workspace are read first too (tb4n2 R7): the
    # check-time change never holds them, so the case builder reserves them beside the diff.
    repair_refs |= declared_output_capture_refs(frozen.case.projection, allowed, workspace_root)
    linked_evidence = {
        str(ref)
        for _, claim in effective_claim_items(frozen.case.projection)
        if claim.payload is not None
        for ref in claim.payload.supporting_refs
    }
    # Captured code edits (workspace diffs and changed files) outrank other captures: they are
    # the change under review (#883). The kind hint is the service-authored materialization
    # description; the manifest check below still authenticates the actual kind. Newer
    # edits win among edits, so the latest edit of a file is preferred under the cap.
    object_frontier = {
        object_id: max(row[2].source_frontier for row in rows)
        for object_id, rows in candidates.items()
    }
    edit_objects = frozenset(
        object_id
        for object_id, rows in candidates.items()
        if any(_is_edit_capture(row[1]) for row in rows)
    )
    selected_objects = tuple(
        sorted(
            candidates,
            key=lambda object_id: (
                0 if any(row[0] in repair_refs for row in candidates[object_id]) else 1,
                0 if any(row[0] in linked_evidence for row in candidates[object_id]) else 1,
                0 if object_id in edit_objects else 1,
                -object_frontier[object_id] if object_id in edit_objects else 0,
                object_id.encode("ascii"),
            ),
        )
    )[:_MAX_CAPTURED_SEMANTIC_PARTS]
    metadata_selection_truncated = len(candidates) > len(selected_objects)
    if metadata_selection_truncated:
        gaps.add(ObservationGapCode.CONTENT_UNSELECTED.value)
    if not selected_objects:
        return CapturedContentResolution(
            scope,
            (),
            _sort_gaps(gaps),
            None if local_fence is None else local_fence.generation,
            () if local_fence is None else local_fence.profiles,
            False,
        )

    envelopes = await _session_envelopes(
        observation,
        workspace=workspace_commitment,
        session_id=runtime.session_id,
        task_id=runtime.task_id,
        gaps=gaps,
        content_refs=frozenset(selected_objects),
    )
    if codex_historical_candidate:
        # Only this exact source/session route can activate the profileless
        # historical arm. Structural Codex envelopes without linked content do
        # not establish a disclosure scope. This arm is independent of the
        # ordinary Claude/Cursor profile intersection: enabling one of those
        # profiles must not disable an otherwise authorized Codex hook.
        codex_content_present = any(
            envelope.source is ObservationSource.CODEX_HOOK
            and _profile_for_envelope(envelope) == _CODEX_HISTORICAL_CAPTURE_SCOPE
            and envelope.content_object_refs
            for envelope in envelopes
        )
        if codex_content_present:
            scope = CapturedContentScope(
                task_id=runtime.task_id,
                session_id=runtime.session_id,
                workspace_commitment=workspace_commitment,
                authorized_profiles=tuple(
                    sorted(
                        {*profiles, _CODEX_HISTORICAL_CAPTURE_SCOPE},
                        key=str.encode,
                    )
                ),
            )
            gaps.discard(ObservationGapCode.CONTENT_UNSELECTED.value)
        elif scope is None:
            return CapturedContentResolution(
                None,
                (),
                _sort_gaps(gaps),
                None if local_fence is None else local_fence.generation,
                () if local_fence is None else local_fence.profiles,
                False,
            )
    assert scope is not None
    pending: list[_PendingRow] = []
    pending_keys: set[tuple[str, str]] = set()
    selected_set = frozenset(selected_objects)
    for envelope in envelopes:
        profile = _profile_for_envelope(envelope)
        if profile is None:
            if envelope.content_object_refs:
                gaps.add(ObservationGapCode.CONTENT_UNSELECTED.value)
            continue
        if profile not in scope.authorized_profiles:
            if envelope.content_object_refs:
                gaps.add(ObservationGapCode.CONTENT_UNSELECTED.value)
            continue
        phase_identity = observation_content_identity(envelope)
        correlations = _correlations(envelope)
        for object_value in envelope.content_object_refs:
            if object_value not in selected_set:
                continue
            associations = candidates.get(object_value, ())
            source = f"{envelope.source_identity}:captured:{object_value}"
            expected_event = stable_observation_id(
                kind=IdKind.EVENT,
                task_id=runtime.task_id,
                source_identity=source,
                mapping_version=MATERIALIZATION_MAPPING_VERSION,
                role="captured_evidence_event",
            )
            matching = tuple(
                row for row in associations if str(row[2].source_event_id) == expected_event
            )
            if len(matching) != 1:
                gaps.add(ObservationGapCode.CONTENT_UNSELECTED.value)
                continue
            evidence_ref, payload, _record = matching[0]
            key = (evidence_ref, object_value)
            if key in pending_keys:
                continue
            pending_keys.add(key)
            pending.append(
                (
                    envelope,
                    profile,
                    phase_identity,
                    evidence_ref,
                    object_value,
                    correlations,
                    payload,
                )
            )

    if not pending:
        return CapturedContentResolution(
            scope,
            (),
            _sort_gaps(gaps),
            None if local_fence is None else local_fence.generation,
            () if local_fence is None else local_fence.profiles,
            False,
        )

    # Read manifest metadata first. This bounds aggregate bytes and validates complete
    # multipart groups before the object store is asked for any plaintext wrapper.
    metadata_groups: dict[
        tuple[str, str, ObservationContentKind, str, str, int], list[_MetadataRow]
    ] = {}
    manifest_reader = cast(Callable[[str], object], getattr(observation, "load_content_manifest"))
    for (
        envelope,
        profile,
        phase_identity,
        evidence_ref,
        object_value,
        correlations,
        payload,
    ) in pending:
        try:
            loaded = manifest_reader(object_value)
            binding = payload.digest_binding
            if type(loaded) is not ObservationContentManifest:
                raise ValueError("content_capture_unavailable")
            if type(binding) is not EvidenceDigestBinding:
                raise ValueError("content_capture_unavailable")
            if (
                loaded.content_kind is ObservationContentKind.TOOL_INPUT
                and type(envelope.structural_payload.get("command_commitment")) is not str
            ):
                raise ValueError("content_unselected")
            envelope_digest = loaded.envelope_digest
            content_bytes = loaded.content_bytes
            if (
                loaded.object_id != object_value
                or envelope_digest is None
                or loaded.content_digest != payload.content_digest
                or content_bytes is None
                or content_bytes != binding.byte_count
                or loaded.content_kind
                not in {
                    ObservationContentKind.TOOL_OUTPUT,
                    ObservationContentKind.TOOL_INPUT,
                    ObservationContentKind.CHANGED_FILE,
                    ObservationContentKind.WORKSPACE_DIFF,
                }
                or loaded.correlation_identity is None
                or not observation_source_qualified_content_binding_matches(
                    envelope,
                    content_kind=loaded.content_kind,
                    correlation_identity=loaded.correlation_identity,
                    source_commitment=loaded.source_commitment,
                )
                or not _correlation_matches(envelope, loaded, correlations)
                or loaded.source_commitment != envelope.cursor.last_source_commitment
                or content_bytes > MAX_CAPTURED_SEMANTIC_CONTENT_BYTES
            ):
                raise ValueError("content_unselected")
            group_key = (
                phase_identity,
                profile,
                loaded.content_kind,
                loaded.correlation_identity,
                loaded.source_commitment or "",
                loaded.part_count,
            )
            metadata_groups.setdefault(group_key, []).append(
                (
                    envelope,
                    profile,
                    phase_identity,
                    evidence_ref,
                    object_value,
                    correlations,
                    payload,
                    loaded,
                )
            )
        except Exception as exc:
            gaps.add(
                ObservationGapCode.CONTENT_UNSELECTED.value
                if str(exc) == "content_unselected"
                else ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
            )

    complete_groups: list[list[_MetadataRow]] = []
    for rows in metadata_groups.values():
        rows.sort(key=lambda row: (row[-1].part_index, row[3].encode("ascii")))
        count = rows[0][-1].part_count
        if (
            len(rows) != count
            or [row[-1].part_index for row in rows] != list(range(count))
            or len({row[3] for row in rows}) != len(rows)
        ):
            # A metadata prefix can strand a valid multipart group at the
            # selection boundary. Its missing parts are outside this bounded
            # read, so report capacity withholding rather than claiming that
            # retained content is unavailable. Without prefix truncation, an
            # incomplete group is a durable capture defect and remains an
            # unavailable gap.
            gaps.add(
                ObservationGapCode.CONTENT_UNSELECTED.value
                if metadata_selection_truncated
                else ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
            )
            continue
        complete_groups.append(rows)
    complete_groups.sort(
        key=lambda rows: (
            0 if any(row[3] in repair_refs for row in rows) else 1,
            0 if any(row[3] in linked_evidence for row in rows) else 1,
            0 if rows[0][-1].content_kind in _EDIT_CONTENT_KINDS else 1,
            -max(object_frontier.get(row[4], 0) for row in rows)
            if rows[0][-1].content_kind in _EDIT_CONTENT_KINDS
            else 0,
            rows[0][2].encode("ascii"),
            rows[0][1].encode("ascii"),
            rows[0][-1].content_kind.value.encode("ascii"),
            rows[0][-1].correlation_identity.encode("ascii")
            if rows[0][-1].correlation_identity is not None
            else b"",
        )
    )

    bounded_groups: list[list[_MetadataRow]] = []
    admitted_bytes = 0
    admitted_parts = 0
    for rows in complete_groups:
        group_bytes = sum(row[-1].content_bytes or 0 for row in rows)
        if admitted_parts + len(rows) > max_parts or admitted_bytes + group_bytes > max_total_bytes:
            gaps.add(ObservationGapCode.CONTENT_UNSELECTED.value)
            continue
        admitted_bytes += group_bytes
        admitted_parts += len(rows)
        bounded_groups.append(rows)

    parts: list[CapturedSemanticContent] = []
    command_context: dict[str, tuple[str, str]] = {}
    admitted_phase_bindings: dict[str, str] = {}

    def _open_fence_current() -> bool:
        return not local_fence_provided or (
            local_fence is not None
            and _local_capture_fence_current(
                local_observation,
                workspace_commitment,
                local_fence,
            )
        )

    bounded_groups.sort(
        key=lambda rows: rows[0][-1].content_kind is not ObservationContentKind.TOOL_INPUT
    )
    for rows in bounded_groups:
        opened: list[CapturedSemanticContent] = []
        failed = False
        for (
            envelope,
            profile,
            phase_identity,
            evidence_ref,
            object_value,
            _correlation_values,
            _payload,
            loaded,
        ) in rows:
            if not _open_fence_current():
                # A local pause/disable/revoke that wins before this linearization
                # point invalidates the whole multipart group. Do not open even
                # an authenticated object from the stale task-store snapshot.
                gaps.add(ObservationGapCode.CONTENT_UNSELECTED.value)
                failed = True
                break
            try:
                assert loaded.envelope_digest is not None
                resolved = await runtime.objects.resolve_verified(
                    loaded.object_id, loaded.envelope_digest
                )
                if (
                    type(resolved) is not ObjectRef
                    or resolved.metadata.kind is not ObjectKind.CAPTURED_CONTENT
                    or resolved.metadata.media_type != _CAPTURED_CONTENT_MEDIA_TYPE
                    or resolved.metadata.task_id != runtime.task_id
                    or resolved.object_id != loaded.object_id
                    or resolved.envelope_digest != loaded.envelope_digest
                ):
                    raise ValueError("content_capture_unavailable")
                material = await _read_wrapper(
                    runtime,
                    resolved,
                    fence_check=_open_fence_current,
                )
                parsed, content_bytes = _manifest_from_wrapper(
                    material,
                    object_id=resolved.object_id,
                    envelope_digest=resolved.envelope_digest,
                )
                if parsed != loaded:
                    raise ValueError("content_capture_unavailable")
                if parsed.content_kind is ObservationContentKind.TOOL_INPUT:
                    # Complete unredacted same-phase input only. A truncated command
                    # must not become safer after losing its tail. Pre-tool input
                    # has a different phase and cannot authorize a completed run.
                    if len(rows) == 1 and not parsed.redacted and not envelope.gap_codes:
                        value = strict_json_parse(content_bytes)
                        commitment = envelope.structural_payload.get("command_commitment")
                        if isinstance(value, Mapping) and type(commitment) is str:
                            command = next(
                                (
                                    value.get(key)
                                    for key in ("cmd", "command", "argv")
                                    if type(value.get(key)) is str
                                ),
                                None,
                            )
                            segments = envelope.structural_payload.get(
                                "command_segment_commitments"
                            )
                            composition = envelope.structural_payload.get("command_composition")
                            identity = observed_command_field(
                                commitment,
                                cast(tuple[str, ...], segments)
                                if type(segments) is tuple
                                else None,
                                composition if type(composition) is str else None,
                            )
                            if type(command) is str:
                                command_context[phase_identity] = (command, identity)
                    continue
                # Custom scripts and inline programs have no globally recognized runner
                # name, so their hook need not retain an extra copy of the command input.
                # Recover only exact declared text whose installation-keyed commitment
                # matches this authenticated post phase. All consent, object, source,
                # correlation and completeness checks above remain mandatory.
                if (
                    phase_identity not in command_context
                    and parsed.content_kind is ObservationContentKind.TOOL_OUTPUT
                    and envelope.event_kind == "PostToolUse"
                    and not (
                        set(envelope.gap_codes)
                        - {ObservationGapCode.COMPOUND_OUTCOME_UNAVAILABLE.value}
                    )
                    and not parsed.redacted
                ):
                    commitment = envelope.structural_payload.get("command_commitment")
                    if type(commitment) is str:
                        command = verification_capture_command(frozen.case.projection, commitment)
                        if command is not None:
                            segments = envelope.structural_payload.get(
                                "command_segment_commitments"
                            )
                            composition = envelope.structural_payload.get("command_composition")
                            command_context[phase_identity] = (
                                command,
                                observed_command_field(
                                    commitment,
                                    cast(tuple[str, ...], segments)
                                    if type(segments) is tuple
                                    else None,
                                    composition if type(composition) is str else None,
                                ),
                            )
                opened.append(
                    CapturedSemanticContent(
                        object_ref=resolved,
                        manifest=parsed,
                        content=content_bytes,
                        task_id=runtime.task_id,
                        session_id=runtime.session_id,
                        workspace_commitment=workspace_commitment,
                        phase_identity=phase_identity,
                        capture_profile=profile,
                        observed_command=command_context.get(phase_identity, (None, None))[0],
                        observed_command_identity=command_context.get(phase_identity, (None, None))[
                            1
                        ],
                        capture_gaps=tuple(
                            sorted(
                                set(envelope.gap_codes) & _CONTENT_GAPS,
                                key=str.encode,
                            )
                        ),
                    )
                )
                admitted_phase_bindings[evidence_ref] = phase_identity
            except Exception:
                failed = True
                break
        if failed:
            gaps.add(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
            for (
                _envelope,
                _profile,
                _phase,
                evidence_ref,
                _object,
                _correlation_values,
                _payload,
                _loaded,
            ) in rows:
                admitted_phase_bindings.pop(evidence_ref, None)
            continue
        parts.extend(opened)

    parts.sort(
        key=lambda item: (
            item.phase_identity.encode("ascii"),
            item.manifest.content_kind.value.encode("ascii"),
            item.manifest.correlation_identity.encode("ascii")
            if item.manifest.correlation_identity is not None
            else b"",
            item.manifest.part_index,
            item.object_ref.object_id.encode("ascii"),
        )
    )
    scope = CapturedContentScope(
        task_id=runtime.task_id,
        session_id=runtime.session_id,
        workspace_commitment=workspace_commitment,
        authorized_profiles=scope.authorized_profiles,
        phase_bindings=tuple(
            sorted(admitted_phase_bindings.items(), key=lambda item: item[0].encode("ascii"))
        ),
    )
    return CapturedContentResolution(
        scope,
        tuple(parts),
        _sort_gaps(gaps),
        None if local_fence is None else local_fence.generation,
        () if local_fence is None else local_fence.profiles,
        local_fence_provided and bool(parts),
    )
