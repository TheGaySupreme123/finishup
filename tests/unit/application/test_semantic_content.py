"""Adversarial service-boundary tests for retained ordinary observation content."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from builders.observed_runs import INSTALLATION_KEY
from builders.policy_cases import (
    claim_record,
    clm,
    evd,
    make_case,
    obl,
    obligation_record,
    plan_record,
)
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_materialize import (
    MATERIALIZATION_MAPPING_VERSION,
    materialize_observation_envelope,
    stable_observation_id,
)
from finishup.application.semantic_case import (
    build_semantic_case,
    semantic_case_to_prepared_payload,
)
from finishup.application.semantic_content import resolve_captured_semantic_content
from finishup.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    EvidenceContentAvailability,
    EvidenceDigestBinding,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceImmutability,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    ResultOutcome,
    ResultRecordedPayload,
    encode_payload,
)
from finishup.domain.observation import (
    ObservationContentKind,
    ObservationContentManifest,
    ObservationControlCommand,
    ObservationCursor,
    ObservationEnvelope,
    ObservationRevokeCommand,
    ObservationSource,
    observed_command_commitment,
)
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_HOOK_MAPPING_VERSION,
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_HOOK_MAPPING_VERSION,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.domain.observation_selection import compound_verification_gap_required
from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from finishup.domain.values import (
    EvidenceId,
    JsonObject,
    JsonValue,
    event_id,
    object_id,
    timestamp_from_string,
)
from finishup.kernel.projections import EvidenceProjectionRecord
from finishup.kernel.task_facts import register_command_identity_key
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.importer import ImporterPort
from finishup.ports.ledger import CheckPhase, FrozenCase, LedgerPort, OperationLease
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectStorePort
from finishup.ports.observation import TaskObservationPort
from finishup.ports.runtime import OwnershipFence, TaskRuntime
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.ids import IdKind

_TASK = "tsk_10000000-0000-4000-8000-000000000001"
_SESSION = "ses_10000000-0000-4000-8000-000000000001"
_WRITER = "wri_10000000-0000-4000-8000-000000000001"
_REQUEST = "req_10000000-0000-4000-8000-000000000001"
_WORKSPACE = "hmac-sha256:" + "8" * 64
_SESSION_COMMITMENT = "hmac-sha256:" + "2" * 64
_SOURCE_COMMITMENT = "hmac-sha256:" + "3" * 64
_PROFILE = CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID


class _Objects:
    def __init__(
        self,
        ref: ObjectRef,
        wrapper: bytes,
        *,
        refs: dict[str, ObjectRef] | None = None,
        wrappers: dict[str, bytes] | None = None,
    ) -> None:
        self.ref = replace(ref, plaintext_size=len(wrapper))
        self.wrapper = wrapper
        self.refs = refs or {self.ref.object_id: self.ref}
        self.wrappers = wrappers or {self.ref.object_id: wrapper}
        self.resolve_calls: list[tuple[str, str]] = []
        self.open_calls = 0

    async def resolve_verified(self, object_id: str, envelope_digest: str) -> ObjectRef:
        self.resolve_calls.append((object_id, envelope_digest))
        return self.refs.get(object_id, self.ref)

    async def open_verified(self, _ref: ObjectRef):
        self.open_calls += 1
        yield (
            self.wrapper
            if _ref.object_id == self.ref.object_id
            else self.wrappers.get(_ref.object_id, self.wrapper)
        )


class _Observation:
    def __init__(
        self,
        envelope: ObservationEnvelope,
        manifest: ObservationContentManifest,
        *,
        profiles: tuple[str, ...] = (_PROFILE,),
        lifecycle: str = "active",
        manifests: dict[str, ObservationContentManifest] | None = None,
        route_task: str = _TASK,
        route_active: bool = True,
    ) -> None:
        self.envelope = envelope
        self.manifest = manifest
        self.profiles = profiles
        self.lifecycle = lifecycle
        self.manifests = manifests or {manifest.object_id: manifest}
        self.route_task = route_task
        self.route_active = route_active

    def content_capture_profiles(self, _workspace: str) -> tuple[str, ...]:
        return self.profiles

    def codex_session_commitment_for_session(
        self, *, workspace: str, finishup_session_id: str
    ) -> str | None:
        if workspace != _WORKSPACE or finishup_session_id != _SESSION:
            return None
        return _SESSION_COMMITMENT

    def observation_route_for_session(
        self, *, workspace: str, finishup_session_id: str
    ) -> tuple[str, str, bool] | None:
        if workspace != _WORKSPACE or finishup_session_id != _SESSION:
            return None
        return _SESSION_COMMITMENT, self.route_task, self.route_active

    async def status_for_session(self, _workspace: str, _session_commitment: str) -> object:
        return SimpleNamespace(lifecycle=SimpleNamespace(value=self.lifecycle))

    def list_envelopes_for_session(
        self, _workspace: str, _session_commitment: str, *, limit: int | None = None
    ) -> tuple[ObservationEnvelope, ...]:
        assert limit == 256
        return (self.envelope,)

    def load_content_manifest(self, _object_id: str) -> ObservationContentManifest:
        if _object_id == self.manifest.object_id:
            return self.manifest
        return self.manifests.get(_object_id, self.manifest)


def _fixture(
    *,
    content: bytes = b"planted-defect-marker: missing validation",
    allowed: bool = True,
) -> tuple[FrozenCase, TaskRuntime, _Objects, _Observation, ObservationEnvelope]:
    object_value = object_id("obj_00000000-0000-4000-8000-000000000302")
    content_digest = "sha256:" + hashlib.sha256(content).hexdigest()
    envelope = ObservationEnvelope(
        session_commitment=_SESSION_COMMITMENT,
        event_kind="PostToolUse",
        source_identity="claude-phase-1",
        source=ObservationSource.CLAUDE_HOOK,
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=0,
            event_position=1,
            last_source_commitment=_SOURCE_COMMITMENT,
            mapping_version=MATERIALIZATION_MAPPING_VERSION,
        ),
        receipt_time=timestamp_from_string("2026-07-01T00:00:00.000Z"),
        structural_payload=JsonObject(
            {
                "tool_name": "Bash",
                "correlation_id": "tool-use-1",
                "capability_profile_id": _PROFILE,
                "mapping_hint": CLAUDE_CODE_ORDINARY_HOOK_MAPPING_VERSION,
            }
        ),
        content_object_refs=(object_value,),
        gap_codes=(),
    )
    expected_event = stable_observation_id(
        kind=IdKind.EVENT,
        task_id=_TASK,
        source_identity=f"{envelope.source_identity}:captured:{object_value}",
        mapping_version=MATERIALIZATION_MAPPING_VERSION,
        role="captured_evidence_event",
    )
    payload = EvidenceRecordedPayload(
        evidence_id=evd(1),
        evidence_kind=EvidenceKind.OTHER,
        strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        observed_at=timestamp_from_string("2026-07-01T00:00:00.000Z"),
        captured_object_id=object_value,
        content_digest=content_digest,
        description="Observation-captured tool output bytes part=1/1",
        digest_binding=EvidenceDigestBinding(
            subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
            content_availability=EvidenceContentAvailability.CAPTURED,
            byte_count=len(content),
            provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
        ),
    )
    evidence_record_value = EvidenceProjectionRecord(
        payload=payload,
        payload_digest=canonical_digest(encode_payload(payload)),
        redacted=False,
        source_event_id=event_id(expected_event),
        source_frontier=4,
    )
    case = make_case(
        evidence={evd(1): evidence_record_value},
        extra_refs=(evd(1),) if allowed else (),
    )
    if not allowed:
        # Keep the evidence projection durable while fencing its evidence ref
        # out of this frozen case's allowlist.
        case = replace(
            case,
            allowed_ids=frozenset({event_id(expected_event)}),
            coverage_by_ref={
                event_id(expected_event): case.coverage_by_ref[event_id(expected_event)]
            },
        )
    envelope_digest = "sha256:" + "5" * 64
    ref = ObjectRef(
        object_id=object_value,
        plaintext_size=1,
        commitment="hmac-sha256:" + "6" * 64,
        envelope_digest=envelope_digest,
        encryption_format="yoetz-object/1",
        key_slot="task",
        metadata=ObjectMetadata(
            ObjectKind.CAPTURED_CONTENT,
            "application/vnd.yoetz.observation-content+json",
            _TASK,
            datetime(2026, 7, 1, tzinfo=UTC),
        ),
    )
    manifest = ObservationContentManifest(
        object_id=object_value,
        envelope_digest=envelope_digest,
        content_kind=ObservationContentKind.TOOL_OUTPUT,
        part_index=0,
        part_count=1,
        redacted=False,
        content_digest=content_digest,
        content_bytes=len(content),
        correlation_identity="tool-use-1",
        source_commitment=_SOURCE_COMMITMENT,
    )
    wrapper = canonical_encode(
        JsonObject(
            {
                "format": "yoetz.observation-content/1",
                "content_kind": manifest.content_kind.value,
                "correlation_identity": cast(str, manifest.correlation_identity),
                "source_commitment": cast(str, manifest.source_commitment),
                "media_type": "text/plain",
                "part_index": manifest.part_index,
                "part_count": manifest.part_count,
                "redacted": manifest.redacted,
                "content_b64": base64.b64encode(content).decode("ascii"),
            }
        )
    )
    objects = _Objects(ref, wrapper)
    observation = _Observation(envelope, manifest)
    runtime = TaskRuntime(
        task_id=_TASK,
        session_id=_SESSION,
        writer_id=_WRITER,
        capabilities=frozenset({RuntimeCapability.WRITE}),
        ledger=cast(LedgerPort, object()),
        objects=cast(ObjectStorePort, objects),
        importer=cast(ImporterPort, object()),
        projection_version="0.1.0",
        engine_version="0.1.0",
        protocol_version="0.1",
        bundle_schema_version="1.0.0",
        fence=OwnershipFence("svc_10000000-0000-4000-8000-000000000001", 1, 1, "n" * 16),
        observation=cast(TaskObservationPort, observation),
    )
    lease = OperationLease(
        writer_id=_WRITER,
        operation_id=_REQUEST,
        session_id=_SESSION,
        phase=CheckPhase.SEMANTIC_WAIT,
        owner_generation="owner-1",
        lease_owner_id="svc-1",
        lease_generation=1,
        lease_expires_at=datetime(2026, 7, 1, 1, tzinfo=UTC),
        frontier=case.frontier,
        dependency_digest="sha256:" + "b" * 64,
    )
    return FrozenCase(case, lease), runtime, objects, observation, envelope


def _codex_profileless_fixture() -> tuple[FrozenCase, TaskRuntime, _Objects, _Observation]:
    """Build a Codex-hook capture with the original profileless grant semantics."""

    frozen, runtime, objects, observation, envelope = _fixture()
    codex_envelope = replace(
        envelope,
        source=ObservationSource.CODEX_HOOK,
        source_identity="codex-phase-1",
        cursor=replace(envelope.cursor, mapping_version="codex-obs-hook/1.0.0"),
        structural_payload=JsonObject(
            {
                "tool_name": "Bash",
                "tool_call_id": "tool-use-1",
            }
        ),
    )
    expected_event = stable_observation_id(
        kind=IdKind.EVENT,
        task_id=_TASK,
        source_identity=f"{codex_envelope.source_identity}:captured:{observation.manifest.object_id}",
        mapping_version=MATERIALIZATION_MAPPING_VERSION,
        role="captured_evidence_event",
    )
    current_record = frozen.case.projection.evidence[evd(1)]
    projection = replace(
        frozen.case.projection,
        evidence={evd(1): replace(current_record, source_event_id=event_id(expected_event))},
    )
    observation.envelope = codex_envelope
    observation.profiles = ()
    runtime = replace(runtime, observation=cast(TaskObservationPort, observation))
    return (
        FrozenCase(replace(frozen.case, projection=projection), frozen.lease),
        runtime,
        objects,
        observation,
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "source",
    (
        ObservationSource.CODEX_HOOK,
        ObservationSource.CLAUDE_HOOK,
        ObservationSource.CURSOR_HOOK,
    ),
)
@pytest.mark.parametrize("command", ("python stress.py", "python - <<'PY'\nassert 2 + 2 == 4\nPY"))
async def test_custom_output_recovers_only_exact_declared_command(
    tmp_path: Path,
    source: ObservationSource,
    command: str,
) -> None:
    if source is ObservationSource.CODEX_HOOK:
        frozen, runtime, _objects, observation = _codex_profileless_fixture()
    else:
        frozen, runtime, _objects, observation, _envelope = _fixture()
    commitment = observed_command_commitment(INSTALLATION_KEY, command)
    fields = dict(observation.envelope.structural_payload)
    fields["command_commitment"] = commitment
    profiles = observation.profiles
    if source is ObservationSource.CURSOR_HOOK:
        profiles = (CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,)
        fields.update(
            capability_profile_id=profiles[0], mapping_hint=CURSOR_ORDINARY_HOOK_MAPPING_VERSION
        )
        observation.profiles = profiles
    # Use the real mapper's outcome-gap rule: an inline program's newline is
    # compound-shaped even though its full command identity is known exactly.
    gaps = (
        ("compound_outcome_unavailable",)
        if compound_verification_gap_required(
            {"tool_name": "Bash", "tool_input": {"command": command}}
        )
        else ()
    )
    observation.envelope = replace(
        observation.envelope, source=source, structural_payload=JsonObject(fields), gap_codes=gaps
    )
    obligation = ObligationPublishedPayload(
        obl(1),
        "Check the result",
        "A discriminating check",
        ObligationStatus.OPEN,
        requested_items=(RequestedItem(RequestedItemKind.COMMAND, command),),
    )
    projection = replace(
        frozen.case.projection,
        plans={1: plan_record(PlanPublishedPayload(1, "Plan", (obl(1),)), 2)},
        obligations={obl(1): obligation_record(obligation, 1)},
    )
    frozen = replace(frozen, case=replace(frozen.case, projection=projection))
    local = LocalObservationStore(_state=tmp_path / "local-state")
    local.grant_consent(
        _WORKSPACE,
        timestamp_from_string("2026-07-01T00:00:00.000Z"),
        content_capture_profiles=profiles,
    )
    register_command_identity_key(INSTALLATION_KEY)
    try:
        resolved = await resolve_captured_semantic_content(
            runtime=runtime,
            frozen=frozen,
            workspace_commitment=_WORKSPACE,
            local_observation=local,
        )
        assert len(resolved.content) == 1
        assert resolved.content[0].observed_command == command
        assert resolved.content[0].observed_command_identity == "omitted:" + commitment
        observation.envelope = replace(
            observation.envelope,
            structural_payload=JsonObject(
                {
                    **fields,
                    "command_commitment": observed_command_commitment(
                        INSTALLATION_KEY, command + " --other"
                    ),
                }
            ),
        )
        unmatched = await resolve_captured_semantic_content(
            runtime=runtime,
            frozen=frozen,
            workspace_commitment=_WORKSPACE,
            local_observation=local,
        )
        assert len(unmatched.content) == 1
        assert unmatched.content[0].observed_command is None
        observation.envelope = replace(
            observation.envelope,
            structural_payload=JsonObject(fields),
            gap_codes=("truncated_payload",),
        )
        truncated = await resolve_captured_semantic_content(
            runtime=runtime,
            frozen=frozen,
            workspace_commitment=_WORKSPACE,
            local_observation=local,
        )
        assert len(truncated.content) == 1
        assert truncated.content[0].observed_command is None
    finally:
        register_command_identity_key(None)


def _multipart_fixture() -> tuple[FrozenCase, TaskRuntime, _Objects]:
    base_frozen, base_runtime, base_objects, _observation, base_envelope = _fixture()
    object_values = tuple(
        object_id(f"obj_00000000-0000-4000-8000-00000000040{index}") for index in range(1, 5)
    )
    chunks = (
        (ObservationContentKind.TOOL_OUTPUT, "claude-phase-1:tool-output", b"group-a-0:"),
        (ObservationContentKind.WORKSPACE_DIFF, "claude-phase-1:diff", b"group-b-0:"),
        (
            ObservationContentKind.TOOL_OUTPUT,
            "claude-phase-1:tool-output",
            b"group-a-1: planted-defect-marker",
        ),
        (ObservationContentKind.WORKSPACE_DIFF, "claude-phase-1:diff", b"group-b-1:"),
    )
    manifests: dict[str, ObservationContentManifest] = {}
    refs: dict[str, ObjectRef] = {}
    wrappers: dict[str, bytes] = {}
    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {}
    for index, (kind, correlation, content) in enumerate(chunks):
        object_value = object_values[index]
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        manifest = ObservationContentManifest(
            object_id=object_value,
            envelope_digest="sha256:" + "abcdef0123456789"[index] * 64,
            content_kind=kind,
            part_index=index // 2,
            part_count=2,
            redacted=False,
            content_digest=digest,
            content_bytes=len(content),
            correlation_identity=correlation,
            source_commitment=_SOURCE_COMMITMENT,
        )
        wrapper = canonical_encode(
            JsonObject(
                {
                    "format": "yoetz.observation-content/1",
                    "content_kind": kind.value,
                    "correlation_identity": correlation,
                    "source_commitment": _SOURCE_COMMITMENT,
                    "media_type": "text/plain",
                    "part_index": manifest.part_index,
                    "part_count": manifest.part_count,
                    "redacted": False,
                    "content_b64": base64.b64encode(content).decode("ascii"),
                }
            )
        )
        wrappers[object_value] = wrapper
        ref = replace(
            base_objects.ref,
            object_id=object_value,
            plaintext_size=len(wrapper),
            envelope_digest=manifest.envelope_digest,
        )
        refs[object_value] = ref
        manifests[object_value] = manifest
        evidence_id = evd(index + 1)
        payload = EvidenceRecordedPayload(
            evidence_id=evidence_id,
            evidence_kind=EvidenceKind.OTHER,
            strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
            observed_at=timestamp_from_string("2026-07-01T00:00:00.000Z"),
            captured_object_id=object_value,
            content_digest=digest,
            description=f"Observation-captured {kind.value} bytes part={manifest.part_index + 1}/2",
            digest_binding=EvidenceDigestBinding(
                subject=EvidenceDigestSubject.BOUNDED_EXCERPT,
                content_availability=EvidenceContentAvailability.CAPTURED,
                byte_count=len(content),
                provenance=EvidenceDigestProvenance.OBSERVATION_CAPTURED,
            ),
        )
        expected_event = stable_observation_id(
            kind=IdKind.EVENT,
            task_id=_TASK,
            source_identity=f"{base_envelope.source_identity}:captured:{object_value}",
            mapping_version=MATERIALIZATION_MAPPING_VERSION,
            role="captured_evidence_event",
        )
        evidence[evidence_id] = EvidenceProjectionRecord(
            payload=payload,
            payload_digest=canonical_digest(encode_payload(payload)),
            redacted=False,
            source_event_id=event_id(expected_event),
            source_frontier=4 + index,
        )
    case = make_case(
        evidence=evidence,
        extra_refs=tuple(evidence),
    )
    envelope = replace(base_envelope, content_object_refs=object_values)
    observation = _Observation(
        envelope,
        manifests[object_values[0]],
        manifests=manifests,
    )
    multi_objects = _Objects(
        refs[object_values[0]],
        wrappers[object_values[0]],
        refs=refs,
        wrappers=wrappers,
    )
    runtime = replace(
        base_runtime,
        objects=cast(ObjectStorePort, multi_objects),
        observation=cast(TaskObservationPort, observation),
    )
    return FrozenCase(case, base_frozen.lease), runtime, multi_objects


def _lexical_boundary_multipart_fixture() -> tuple[FrozenCase, TaskRuntime, _Objects, _Observation]:
    """Build a valid two-part group whose second ID falls outside the metadata prefix."""

    base_frozen, base_runtime, objects, observation, envelope = _fixture(
        content=b"boundary-part-0",
    )
    first_id = observation.manifest.object_id
    second_id = object_id("obj_00000000-0000-4000-8000-000000000303")
    first_content = b"boundary-part-0"
    second_content = b"boundary-part-1"

    def _manifest_and_wrapper(
        object_value: str,
        content: bytes,
        *,
        part_index: int,
        envelope_digest: str,
    ) -> tuple[ObservationContentManifest, bytes]:
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        manifest = replace(
            observation.manifest,
            object_id=object_value,
            envelope_digest=envelope_digest,
            part_index=part_index,
            part_count=2,
            content_digest=digest,
            content_bytes=len(content),
        )
        wrapper = canonical_encode(
            JsonObject(
                {
                    "format": "yoetz.observation-content/1",
                    "content_kind": manifest.content_kind.value,
                    "correlation_identity": cast(str, manifest.correlation_identity),
                    "source_commitment": cast(str, manifest.source_commitment),
                    "media_type": "text/plain",
                    "part_index": manifest.part_index,
                    "part_count": manifest.part_count,
                    "redacted": manifest.redacted,
                    "content_b64": base64.b64encode(content).decode("ascii"),
                }
            )
        )
        return manifest, wrapper

    first_manifest, first_wrapper = _manifest_and_wrapper(
        first_id,
        first_content,
        part_index=0,
        envelope_digest="sha256:" + "7" * 64,
    )
    second_manifest, second_wrapper = _manifest_and_wrapper(
        second_id,
        second_content,
        part_index=1,
        envelope_digest="sha256:" + "8" * 64,
    )
    observation.manifest = first_manifest
    observation.manifests = {first_id: first_manifest, second_id: second_manifest}
    observation.envelope = replace(envelope, content_object_refs=(first_id, second_id))

    first_ref = replace(
        objects.ref,
        object_id=first_id,
        plaintext_size=len(first_wrapper),
        envelope_digest=first_manifest.envelope_digest,
    )
    second_ref = replace(
        first_ref,
        object_id=second_id,
        plaintext_size=len(second_wrapper),
        envelope_digest=second_manifest.envelope_digest,
    )
    objects.ref = first_ref
    objects.wrapper = first_wrapper
    objects.refs[first_id] = first_ref
    objects.refs[second_id] = second_ref
    objects.wrappers[first_id] = first_wrapper
    objects.wrappers[second_id] = second_wrapper

    base_record = base_frozen.case.projection.evidence[evd(1)]
    base_payload = base_record.payload
    assert type(base_payload) is EvidenceRecordedPayload
    base_binding = base_payload.digest_binding
    assert type(base_binding) is EvidenceDigestBinding

    def _evidence_record(
        evidence_value: EvidenceId,
        object_value: str,
        content: bytes,
        *,
        part_index: int,
        frontier: int,
    ) -> EvidenceProjectionRecord:
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        payload = replace(
            base_payload,
            evidence_id=evidence_value,
            captured_object_id=object_value,
            content_digest=digest,
            description=(f"Observation-captured tool output bytes part={part_index + 1}/2"),
            digest_binding=replace(base_binding, byte_count=len(content)),
        )
        expected_event = stable_observation_id(
            kind=IdKind.EVENT,
            task_id=_TASK,
            source_identity=f"{envelope.source_identity}:captured:{object_value}",
            mapping_version=MATERIALIZATION_MAPPING_VERSION,
            role="captured_evidence_event",
        )
        return EvidenceProjectionRecord(
            payload=payload,
            payload_digest=canonical_digest(encode_payload(payload)),
            redacted=False,
            source_event_id=event_id(expected_event),
            source_frontier=frontier,
        )

    evidence: dict[EvidenceId, EvidenceProjectionRecord] = {
        evd(1): _evidence_record(evd(1), first_id, first_content, part_index=0, frontier=4),
        evd(2): _evidence_record(evd(2), second_id, second_content, part_index=1, frontier=5),
    }
    # These 63 ordinary candidates sort before the two group members. They
    # force the resolver's bounded metadata prefix to end after part zero while
    # leaving the complete group durably represented by the envelope/evidence.
    for index in range(63):
        extra_id = object_id(f"obj_00000000-0000-4000-8000-{0x100 + index:012x}")
        extra_evidence = evd(index + 3)
        evidence[extra_evidence] = _evidence_record(
            extra_evidence,
            extra_id,
            b"bounded filler",
            part_index=0,
            frontier=6 + index,
        )

    case = make_case(evidence=evidence, extra_refs=tuple(evidence))
    return FrozenCase(case, base_frozen.lease), base_runtime, objects, observation


@pytest.mark.anyio
async def test_resolver_authenticates_content_and_binds_phase_before_builder() -> None:
    frozen, runtime, objects, _observation, _envelope = _fixture()
    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
    )

    assert len(objects.resolve_calls) == 1
    assert objects.open_calls == 1
    assert len(resolved.content) == 1
    captured = resolved.content[0]
    assert captured.content == b"planted-defect-marker: missing validation"
    assert resolved.scope is not None
    assert resolved.scope.phase_bindings == ((str(evd(1)), captured.phase_identity),)
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000001",
        frozen_case=frozen.case,
        dependency_digest=frozen.lease.dependency_digest,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
        captured_content=resolved.content,
        captured_content_scope=resolved.scope,
        captured_content_gaps=resolved.gaps,
    )
    prepared = semantic_case_to_prepared_payload(
        semantic,
        {item.item_id for item in semantic.items},
    )
    assert captured.content in prepared


@pytest.mark.anyio
async def test_profileless_codex_hook_content_reaches_guarded_semantic_packet(
    tmp_path: Path,
) -> None:
    frozen, runtime, objects, _observation = _codex_profileless_fixture()
    local = LocalObservationStore(_state=tmp_path / "local-state")
    local.grant_consent(
        _WORKSPACE,
        timestamp_from_string("2026-07-01T00:00:00.000Z"),
    )

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
        local_observation=local,
    )

    assert len(objects.resolve_calls) == 1
    assert objects.open_calls == 1
    assert len(resolved.content) == 1
    assert resolved.content[0].capture_profile == ObservationSource.CODEX_HOOK.value
    assert resolved.scope is not None
    assert resolved.scope.authorized_profiles == (ObservationSource.CODEX_HOOK.value,)
    assert resolved.gaps == ()

    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000000002",
        frozen_case=frozen.case,
        dependency_digest=frozen.lease.dependency_digest,
        findings=(),
        review_context_profile=ReviewContextProfile.EXPANDED,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED),
        policy_id="pvy_10000000-0000-4000-8000-000000000002",
        policy_version="1",
        captured_content=resolved.content,
        captured_content_scope=resolved.scope,
        captured_content_gaps=resolved.gaps,
    )
    prepared = semantic_case_to_prepared_payload(
        semantic,
        {item.item_id for item in semantic.items},
    )
    assert b"planted-defect-marker: missing validation" in prepared


@pytest.mark.anyio
@pytest.mark.parametrize(
    "mapping_version",
    (
        "codex-obs-hook/9.9.9",
        "codex-obs-session/1.0.0",
        "claude-code-hooks-ordinary-v2",
        "cursor-hooks-ordinary-v1",
    ),
)
async def test_profileless_codex_rejects_unreviewed_mapping_before_object_access(
    tmp_path: Path,
    mapping_version: str,
) -> None:
    frozen, runtime, objects, observation = _codex_profileless_fixture()
    observation.envelope = replace(
        observation.envelope,
        cursor=replace(observation.envelope.cursor, mapping_version=mapping_version),
    )
    local = LocalObservationStore(_state=tmp_path / "local-state")
    local.grant_consent(_WORKSPACE, timestamp_from_string("2026-07-01T00:00:00.000Z"))

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
        local_observation=local,
    )

    assert resolved.content == ()
    assert resolved.gaps == ("content_unselected",)
    assert objects.resolve_calls == []
    assert objects.open_calls == 0


@pytest.mark.anyio
async def test_profileless_codex_selection_coexists_with_ordinary_host_profiles(
    tmp_path: Path,
) -> None:
    frozen, runtime, objects, observation = _codex_profileless_fixture()
    ordinary_profiles = (
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    )
    observation.profiles = ordinary_profiles
    local = LocalObservationStore(_state=tmp_path / "local-state")
    local.grant_consent(
        _WORKSPACE,
        timestamp_from_string("2026-07-01T00:00:00.000Z"),
        content_capture_profiles=ordinary_profiles,
    )

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
        local_observation=local,
    )

    assert len(resolved.content) == 1
    assert resolved.scope is not None
    assert resolved.scope.authorized_profiles == tuple(
        sorted(
            (*ordinary_profiles, ObservationSource.CODEX_HOOK.value),
            key=str.encode,
        )
    )
    assert objects.open_calls == 1


@pytest.mark.anyio
async def test_profileless_codex_session_stream_never_selects_captured_content(
    tmp_path: Path,
) -> None:
    frozen, runtime, objects, observation = _codex_profileless_fixture()
    observation.envelope = replace(
        observation.envelope,
        source=ObservationSource.CODEX_SESSION_STREAM,
    )
    local = LocalObservationStore(_state=tmp_path / "local-state")
    local.grant_consent(
        _WORKSPACE,
        timestamp_from_string("2026-07-01T00:00:00.000Z"),
    )

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
        local_observation=local,
    )

    assert resolved.content == ()
    assert resolved.scope is None
    assert objects.resolve_calls == []
    assert objects.open_calls == 0
    assert "content_unselected" in resolved.gaps


@pytest.mark.anyio
async def test_profileless_codex_selection_requires_a_codex_hook_envelope(
    tmp_path: Path,
) -> None:
    frozen, runtime, objects, observation = _codex_profileless_fixture()
    observation.envelope = replace(
        observation.envelope,
        source=ObservationSource.CLAUDE_HOOK,
    )
    local = LocalObservationStore(_state=tmp_path / "local-state")
    local.grant_consent(
        _WORKSPACE,
        timestamp_from_string("2026-07-01T00:00:00.000Z"),
    )

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
        local_observation=local,
    )

    assert resolved.content == ()
    assert resolved.scope is None
    assert objects.resolve_calls == []
    assert objects.open_calls == 0
    assert "content_unselected" in resolved.gaps


@pytest.mark.anyio
@pytest.mark.parametrize("mutation", ("correlation", "source_commitment"))
async def test_profileless_codex_capture_rejects_binding_mismatch_before_open(
    tmp_path: Path,
    mutation: str,
) -> None:
    frozen, runtime, objects, observation = _codex_profileless_fixture()
    if mutation == "correlation":
        observation.envelope = replace(
            observation.envelope,
            structural_payload=JsonObject(
                {
                    "tool_name": "Bash",
                    "tool_call_id": "foreign-tool",
                }
            ),
        )
    else:
        observation.envelope = replace(
            observation.envelope,
            cursor=replace(
                observation.envelope.cursor,
                last_source_commitment="hmac-sha256:" + "4" * 64,
            ),
        )
    local = LocalObservationStore(_state=tmp_path / "local-state")
    local.grant_consent(
        _WORKSPACE,
        timestamp_from_string("2026-07-01T00:00:00.000Z"),
    )

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
        local_observation=local,
    )

    assert resolved.content == ()
    assert objects.resolve_calls == []
    assert objects.open_calls == 0
    assert "content_unselected" in resolved.gaps


@pytest.mark.anyio
@pytest.mark.parametrize(
    "content_kind",
    (ObservationContentKind.TOOL_INPUT, ObservationContentKind.WORKSPACE_LOCATOR),
)
async def test_profileless_codex_input_and_locator_are_excluded(
    tmp_path: Path,
    content_kind: ObservationContentKind,
) -> None:
    frozen, runtime, objects, observation = _codex_profileless_fixture()
    observation.manifest = replace(observation.manifest, content_kind=content_kind)
    local = LocalObservationStore(_state=tmp_path / "local-state")
    local.grant_consent(
        _WORKSPACE,
        timestamp_from_string("2026-07-01T00:00:00.000Z"),
    )

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
        local_observation=local,
    )

    assert resolved.content == ()
    assert objects.resolve_calls == []
    assert objects.open_calls == 0
    assert "content_unselected" in resolved.gaps


@pytest.mark.anyio
async def test_resolver_admits_multipart_groups_atomically_under_part_bound() -> None:
    frozen, runtime, objects = _multipart_fixture()
    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
        max_parts=2,
        max_total_bytes=1_024,
    )

    # Four in-scope object IDs are metadata candidates, but the two-part group
    # is the atomic semantic unit. The captured workspace diff outranks the tool
    # output (#883); the tool-output group is withheld as a whole and no
    # fragment of it is opened merely because its ID sorts early.
    assert len(resolved.content) == 2
    assert b"group-b-0:" in resolved.content[0].content
    assert b"group-b-1:" in resolved.content[1].content
    assert b"group-a" not in b"".join(item.content for item in resolved.content)
    assert len(objects.resolve_calls) == 2
    assert objects.open_calls == 2
    assert "content_unselected" in resolved.gaps


@pytest.mark.anyio
async def test_resolver_reports_capacity_for_multipart_group_crossing_metadata_cutoff() -> None:
    frozen, runtime, objects, _observation = _lexical_boundary_multipart_fixture()

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
    )

    # The bounded metadata prefix sees only part zero. It withholds the whole
    # group and reports capacity, rather than mislabeling the retained group as
    # unavailable or opening a fragment.
    assert resolved.content == ()
    assert "content_unselected" in resolved.gaps
    assert "content_capture_unavailable" not in resolved.gaps
    assert objects.resolve_calls == []
    assert objects.open_calls == 0


@pytest.mark.anyio
async def test_resolver_does_not_open_irrelevant_or_out_of_scope_objects() -> None:
    frozen, runtime, objects, observation, envelope = _fixture(allowed=False)
    irrelevant = tuple(
        object_id(f"obj_00000000-0000-4000-8000-{index:012x}") for index in range(1, 16)
    )
    observation.envelope = replace(
        envelope,
        content_object_refs=tuple(sorted(irrelevant, key=str.encode)),
    )
    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
    )

    assert resolved.content == ()
    assert objects.resolve_calls == []
    assert objects.open_calls == 0


@pytest.mark.anyio
async def test_resolver_rejects_wrong_phase_without_reading_object() -> None:
    frozen, runtime, objects, observation, envelope = _fixture()
    observation.envelope = replace(envelope, source_identity="claude-phase-2")

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
    )

    assert resolved.content == ()
    assert "content_unselected" in resolved.gaps
    assert objects.resolve_calls == []
    assert objects.open_calls == 0


@pytest.mark.anyio
async def test_resolver_requires_exact_ordinary_renderer_profile_identity() -> None:
    frozen, runtime, objects, observation, envelope = _fixture()
    observation.envelope = replace(
        envelope,
        structural_payload=JsonObject(
            {
                "tool_name": "Bash",
                "correlation_id": "tool-use-1",
                "capability_profile_id": "claude-code-cli-local-project-2.1.241",
                "mapping_hint": "claude-code-hooks-2.1.241-v1",
            }
        ),
    )
    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
    )
    assert resolved.content == ()
    assert "content_unselected" in resolved.gaps
    assert objects.resolve_calls == []
    assert objects.open_calls == 0


@pytest.mark.anyio
async def test_resolver_keeps_v1_content_and_unknown_result() -> None:
    frozen, runtime, objects, observation, envelope = _fixture()
    historical = replace(
        envelope,
        structural_payload=JsonObject(
            {
                **envelope.structural_payload,
                "mapping_hint": "claude-code-hooks-ordinary-v1",
                "result_status": "unknown",
            }
        ),
    )
    observation.envelope = historical

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
    )

    assert len(resolved.content) == 1
    assert resolved.content[0].content == b"planted-defect-marker: missing validation"
    assert objects.open_calls == 1

    batch = materialize_observation_envelope(
        historical,
        task_id=_TASK,
        captured_content=(observation.manifest,),
    )
    result_payloads = [
        cast(ResultRecordedPayload, item.draft.payload)
        for item in batch.drafts
        if item.draft.schema.name == "result_recorded"
    ]
    assert len(result_payloads) == 1
    assert result_payloads[0].outcome is ResultOutcome.UNKNOWN


@pytest.mark.anyio
@pytest.mark.parametrize(
    "mapping_hint",
    ("claude-code-hooks-ordinary-v3", "claude-code-hooks-ordinary", None),
)
async def test_resolver_rejects_unreviewed_or_malformed_claude_mapping_hint(
    mapping_hint: JsonValue,
) -> None:
    frozen, runtime, objects, observation, envelope = _fixture()
    observation.envelope = replace(
        envelope,
        structural_payload=JsonObject(
            {
                **envelope.structural_payload,
                "mapping_hint": mapping_hint,
            }
        ),
    )

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
    )

    assert resolved.content == ()
    assert "content_unselected" in resolved.gaps
    assert objects.resolve_calls == []
    assert objects.open_calls == 0


@pytest.mark.anyio
async def test_resolver_rejects_unknown_profile_and_revoked_session_before_open() -> None:
    frozen, runtime, objects, observation, _envelope = _fixture()
    observation.profiles = ("invented-profile",)
    unknown = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
    )
    assert unknown.content == ()
    assert "content_capture_unavailable" in unknown.gaps
    assert objects.open_calls == 0

    observation.profiles = (_PROFILE,)
    observation.lifecycle = "stopped"
    observation.route_active = False
    natural_end = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
    )
    assert len(natural_end.content) == 1
    assert objects.open_calls == 1


@pytest.mark.anyio
async def test_resolver_rejects_route_for_another_task_before_open() -> None:
    frozen, runtime, objects, observation, _envelope = _fixture()
    observation.route_task = "tsk_10000000-0000-4000-8000-000000000099"

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
    )

    assert resolved.content == ()
    assert "content_capture_unavailable" in resolved.gaps
    assert objects.resolve_calls == []
    assert objects.open_calls == 0


@pytest.mark.anyio
async def test_resolver_rejects_forged_wrapper_and_prebounds_metadata_bytes() -> None:
    frozen, runtime, objects, observation, _envelope = _fixture()
    objects.wrapper = objects.wrapper.replace(b"cGxhbnRlZC", b"Zm9yZ2Vk")
    forged = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
    )
    assert forged.content == ()
    assert "content_capture_unavailable" in forged.gaps
    assert objects.open_calls == 1

    objects.open_calls = 0
    objects.wrapper = objects.wrapper
    observation.manifest = replace(observation.manifest, content_bytes=100)
    bounded = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
        max_total_bytes=1,
    )
    assert bounded.content == ()
    assert "content_unselected" in bounded.gaps
    assert objects.open_calls == 0


@pytest.mark.anyio
async def test_resolver_rejects_non_text_inner_media_after_authenticated_open() -> None:
    frozen, runtime, objects, _observation, _envelope = _fixture()
    objects.wrapper = objects.wrapper.replace(b'"text/plain"', b'"text/htmlx"')

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
    )

    assert resolved.content == ()
    assert "content_capture_unavailable" in resolved.gaps
    assert objects.open_calls == 1


@pytest.mark.anyio
async def test_resolver_withholds_incomplete_multipart_group_before_open() -> None:
    frozen, runtime, objects, observation, _envelope = _fixture()
    observation.manifest = replace(observation.manifest, part_count=2)

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
    )

    assert resolved.content == ()
    assert "content_capture_unavailable" in resolved.gaps
    assert objects.resolve_calls == []
    assert objects.open_calls == 0


@pytest.mark.anyio
@pytest.mark.parametrize("mutation", ("pause", "disable", "revoke", "runtime-disable"))
async def test_local_consent_fence_blocks_stale_task_content_before_open(
    tmp_path: Path, mutation: str
) -> None:
    frozen, runtime, objects, observation, _envelope = _fixture()
    local = LocalObservationStore(_state=tmp_path / "state")
    local.grant_consent(
        _WORKSPACE,
        timestamp_from_string("2026-07-01T00:00:00.000Z"),
        content_capture_profiles=(_PROFILE,),
    )

    initial = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
        local_observation=local,
    )
    assert len(initial.content) == 1
    objects.resolve_calls.clear()
    objects.open_calls = 0

    if mutation == "pause":
        local.pause(ObservationControlCommand(_WORKSPACE))
    elif mutation == "disable":
        local.disable_content_capture(_WORKSPACE, _PROFILE)
    elif mutation == "revoke":
        local.revoke(ObservationRevokeCommand(_WORKSPACE))
    else:
        local.set_runtime_enabled(False)

    # The task bundle intentionally remains stale. The owner-private local
    # store is the immediate authority for the retained-content arm.
    assert observation.profiles == (_PROFILE,)
    blocked = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
        local_observation=local,
    )
    assert blocked.content == ()
    assert objects.resolve_calls == []
    assert objects.open_calls == 0
    assert "content_unselected" in blocked.gaps or "consent_revoked" in blocked.gaps


@pytest.mark.anyio
async def test_local_revoke_winning_at_open_linearization_has_zero_object_open(
    tmp_path: Path,
) -> None:
    frozen, runtime, objects, _observation, _envelope = _fixture()
    local = LocalObservationStore(_state=tmp_path / "state")
    local.grant_consent(
        _WORKSPACE,
        timestamp_from_string("2026-07-01T00:00:00.000Z"),
        content_capture_profiles=(_PROFILE,),
    )

    class _RevokeBeforeOpen:
        def content_capture_authority(self, workspace: str) -> object:
            authority = local.content_capture_authority(workspace)
            assert authority is not None
            return authority

        def content_capture_authority_is_current(
            self, workspace: str, _generation: str, _profiles: tuple[str, ...]
        ) -> bool:
            # This models a revoke that commits while the resolver is between
            # metadata validation and the plaintext object-open boundary.
            local.revoke(ObservationRevokeCommand(workspace))
            return False

    blocked = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
        local_observation=_RevokeBeforeOpen(),
    )
    assert blocked.content == ()
    assert objects.resolve_calls == []
    assert objects.open_calls == 0


@pytest.mark.anyio
async def test_local_resume_rearms_content_after_pause(tmp_path: Path) -> None:
    frozen, runtime, objects, _observation, _envelope = _fixture()
    local = LocalObservationStore(_state=tmp_path / "state")
    command = ObservationControlCommand(_WORKSPACE)
    local.grant_consent(
        _WORKSPACE,
        timestamp_from_string("2026-07-01T00:00:00.000Z"),
        content_capture_profiles=(_PROFILE,),
    )

    local.pause(command)
    local.resume(command)
    after = local.content_capture_authority(_WORKSPACE)
    assert after is not None

    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=frozen,
        workspace_commitment=_WORKSPACE,
        local_observation=local,
    )
    assert len(resolved.content) == 1
    assert resolved.local_fence_generation == after.generation
    assert objects.open_calls == 1


@pytest.mark.anyio
async def test_linked_multipart_code_group_wins_bounded_resolver_admission() -> None:
    frozen, runtime, objects = _multipart_fixture()
    claim = ClaimRecordedPayload(clm(1), ClaimKind.MATERIAL, "Review group B", (evd(4),))
    case = make_case(
        evidence=frozen.case.projection.evidence,
        claims={clm(1): claim_record(claim, 10)},
        extra_refs=tuple(sorted(frozen.case.allowed_ids)),
    )
    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=FrozenCase(case, frozen.lease),
        workspace_commitment=_WORKSPACE,
        max_parts=2,
        max_total_bytes=1024,
    )
    assert len(resolved.content) == 2
    assert b"".join(item.content for item in resolved.content) == b"group-b-0:group-b-1:"
    assert objects.open_calls == 2
    assert "content_unselected" in resolved.gaps


class _WindowedObservation(_Observation):
    """The selected capture's envelope has aged out of the latest-256 session window."""

    def __init__(self, base: _Observation, *, by_ref: bool) -> None:
        super().__init__(base.envelope, base.manifest, profiles=base.profiles)
        self.by_ref = by_ref
        self.ref_calls: list[tuple[str, ...]] = []

    def list_envelopes_for_session(
        self, _workspace: str, _session_commitment: str, *, limit: int | None = None
    ) -> tuple[ObservationEnvelope, ...]:
        assert limit == 256
        return ()

    def list_envelopes_for_content_refs(
        self, _workspace: str, session_commitment: str, object_ids: tuple[str, ...]
    ) -> tuple[ObservationEnvelope, ...]:
        self.ref_calls.append(object_ids)
        if not self.by_ref or session_commitment != _SESSION_COMMITMENT:
            return ()
        return tuple(
            self.envelope for ref in self.envelope.content_object_refs if ref in object_ids
        )[:1]


@pytest.mark.anyio
async def test_resolver_reaches_selected_capture_outside_latest_envelope_window() -> None:
    frozen, runtime, _objects, observation, envelope = _fixture()
    windowed = _WindowedObservation(observation, by_ref=True)
    runtime = replace(runtime, observation=cast(TaskObservationPort, windowed))

    resolved = await resolve_captured_semantic_content(
        runtime=runtime, frozen=frozen, workspace_commitment=_WORKSPACE
    )

    assert windowed.ref_calls == [tuple(envelope.content_object_refs)]
    assert resolved.gaps == ()
    assert [part.content for part in resolved.content] == [
        b"planted-defect-marker: missing validation"
    ]


@pytest.mark.anyio
async def test_resolver_discloses_selected_capture_it_cannot_reach() -> None:
    frozen, runtime, _objects, observation, _envelope = _fixture()
    runtime = replace(
        runtime,
        observation=cast(TaskObservationPort, _WindowedObservation(observation, by_ref=False)),
    )

    resolved = await resolve_captured_semantic_content(
        runtime=runtime, frozen=frozen, workspace_commitment=_WORKSPACE
    )

    assert resolved.content == ()
    assert "content_unselected" in resolved.gaps


@pytest.mark.anyio
async def test_response_linked_multipart_repair_precedes_old_claim_evidence() -> None:
    from builders.policy_cases import BASE_COVERAGE, finding_record, fnd, record
    from finishup.domain.events import ResponseRecordedPayload
    from finishup.domain.findings import Finding, FindingKind, FindingOrigin, ResponseDisposition

    frozen, runtime, objects = _multipart_fixture()
    finding = Finding(
        finding_id=fnd(1),
        kind=FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
        origin=FindingOrigin.DETERMINISTIC,
        priority=1,
        summary="Repair needs review",
        detail="Review the changed evidence",
        subject_refs=(clm(1),),
        policy_id="work-integrity",
        policy_version="0.1.0",
        subject_frontier=frozen.case.frontier,
        coverage=BASE_COVERAGE,
    )
    response = ResponseRecordedPayload(
        fnd(1), frozen.case.frontier, ResponseDisposition.ACKNOWLEDGED, evidence_refs=(evd(4),)
    )
    case = make_case(
        evidence=frozen.case.projection.evidence,
        claims={
            clm(1): claim_record(
                ClaimRecordedPayload(
                    clm(1), ClaimKind.MATERIAL, "Old evidence in group A", (evd(1),)
                ),
                10,
            )
        },
        findings={fnd(1): finding_record(finding, 11)},
        responses={fnd(1): record(response, 12)},
        extra_refs=tuple(sorted(frozen.case.allowed_ids)),
    )
    resolved = await resolve_captured_semantic_content(
        runtime=runtime,
        frozen=FrozenCase(case, frozen.lease),
        workspace_commitment=_WORKSPACE,
        max_parts=2,
        max_total_bytes=1024,
    )
    assert b"".join(item.content for item in resolved.content) == b"group-b-0:group-b-1:"
    assert objects.open_calls == 2
    assert "content_unselected" in resolved.gaps
