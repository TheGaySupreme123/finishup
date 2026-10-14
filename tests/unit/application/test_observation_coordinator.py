"""Focused tests for observation coordinator, materialization, and local outbox."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import uuid
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import apsw
import pytest

from yoetz.adapters.integrations.codex_lifecycle import LifecycleMapping
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.adapters.sqlite import connection as connection_module
from yoetz.adapters.sqlite.migrations import initialize_bundle as initialize_schema
from yoetz.adapters.sqlite.observation import SqliteObservationStore
from yoetz.application.observation_control import build_observation_support_handlers
from yoetz.application.observation_coordinator import ObservationCoordinator
from yoetz.application.observation_drain import (
    ObservationCaptureRecoveryOutcome,
    ObservationDrainAction,
    ObservationOutboxSweeper,
    route_observation_ingest,
)
from yoetz.application.observation_materialize import (
    MATERIALIZATION_LEGACY_MAPPING_VERSIONS,
    MATERIALIZATION_MAPPING_VERSION,
    MaterializedObservationBatch,
    canonical_logical_identity,
    materialize_observation_envelope,
    materialize_observation_outcome_correction,
    observation_operation_digest,
    observation_writer_id,
    stable_observation_id,
)
from yoetz.domain.events import AcceptedEvent
from yoetz.domain.findings import Finding
from yoetz.domain.observation import (
    ObservationContentChunk,
    ObservationContentKind,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationIngestResult,
    ObservationSource,
    ObservationStatusQuery,
    observation_ingest_request_from_json,
    observation_ingest_request_to_json,
)
from yoetz.domain.observation_profiles import CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
from yoetz.domain.values import Frontier, JsonObject, Timestamp, finding_id
from yoetz.ports.ledger import CheckPhase, OperationKind, OperationRecord, OperationState
from yoetz.ports.observation import TaskObservationPort
from yoetz.ports.runtime import TaskRuntime
from yoetz.protocol.canonical import canonical_digest, canonical_encode
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import PREFIX_BY_KIND, IdKind


def initialize_bundle(db: apsw.Connection, seed: Mapping[str, str]) -> None:
    """Stage a fixture schema, then enforce the production writer SQL policy (#616)."""

    initialize_schema(db, seed)
    db.set_authorizer(connection_module._writer_authorizer)  # pyright: ignore[reportPrivateUsage]


def _task_id() -> str:
    return PREFIX_BY_KIND[IdKind.TASK] + str(uuid.uuid4())


def _envelope(
    *,
    session: str,
    kind: str = "PreToolUse",
    identity: str = "hook:test1",
    ordinal: int = 1,
    gaps: tuple[str, ...] = (),
    tool: str = "shell",
    corr: str = "c1",
    exit_status: int | None = None,
    source: ObservationSource = ObservationSource.CODEX_HOOK,
    generation: int = 1,
) -> ObservationEnvelope:
    structural: dict[str, object] = {
        "tool_name": tool,
        "tool_call_id": corr,
        "correlation_id": corr,
    }
    if exit_status is not None:
        structural["exit_status"] = exit_status
    return ObservationEnvelope(
        session_commitment=session,
        event_kind=kind,
        source_identity=identity,
        source=source,
        cursor=ObservationCursor(
            generation, 0, ordinal, f"hmac-sha256:{'ab' * 32}", "codex-obs-hook/1.0.0"
        ),
        receipt_time=Timestamp("2026-01-01T00:00:00.000Z"),
        structural_payload=JsonObject(structural),
        content_object_refs=(),
        gap_codes=gaps,
    )


def test_observation_ingest_request_round_trip() -> None:
    session = f"hmac-sha256:{'cd' * 32}"
    envelope = _envelope(session=session)
    request = ObservationIngestRequest(codex_session_id="codex-sess-1", envelope=envelope)
    wire = observation_ingest_request_to_json(request)
    assert set(wire) == {"codex_session_id", "envelope"}
    assert "task_id" not in wire
    assert "writer_id" not in wire
    restored = observation_ingest_request_from_json(wire)
    assert restored.codex_session_id == "codex-sess-1"
    assert restored.envelope.source_identity == envelope.source_identity


def test_materialize_pre_post_and_unpaired() -> None:
    task = _task_id()
    session = f"hmac-sha256:{'ef' * 32}"
    pre = materialize_observation_envelope(
        _envelope(session=session, kind="PreToolUse", identity="hook:pre"), task_id=task
    )
    assert pre.skip_reason is None
    assert len(pre.drafts) == 1
    assert pre.drafts[0].draft.schema.name == "action_recorded"

    post = materialize_observation_envelope(
        _envelope(
            session=session,
            kind="PostToolUse",
            identity="hook:post",
            exit_status=1,
        ),
        task_id=task,
    )
    assert post.skip_reason is None
    assert [item.draft.schema.name for item in post.drafts] == [
        "action_recorded",
        "result_recorded",
    ]

    unpaired = materialize_observation_envelope(
        _envelope(
            session=session,
            kind="PostToolUse",
            identity="hook:unpaired",
            gaps=(ObservationGapCode.UNPAIRED_EVENT.value,),
            exit_status=1,
        ),
        task_id=task,
    )
    assert unpaired.skip_reason is None
    assert len(unpaired.drafts) == 1
    assert unpaired.drafts[0].draft.schema.name == "evidence_recorded"
    assert ObservationGapCode.UNPAIRED_EVENT.value in unpaired.gaps
    assert ObservationGapCode.UNPAIRED_EVENT.value in unpaired.coverage.known_gaps

    unselected = materialize_observation_envelope(
        _envelope(
            session=session,
            kind="PreToolUse",
            identity="hook:unselected",
            gaps=(ObservationGapCode.CONTENT_UNSELECTED.value,),
        ),
        task_id=task,
    )
    assert ObservationGapCode.CONTENT_UNSELECTED.value in unselected.coverage.known_gaps


def test_materialization_uses_ledger_mapping_independent_of_transport_cursor() -> None:
    """New IDs use obs-ledger/1.6 while explicit replay can select a legacy map."""

    task = _task_id()
    session = f"hmac-sha256:{'74' * 32}"
    envelope = _envelope(session=session, kind="PreToolUse", identity="hook:mapping-source")
    stream_cursor = replace(envelope.cursor, mapping_version="codex-obs-stream/1.4.0")
    stream_transport = replace(envelope, cursor=stream_cursor)

    current = materialize_observation_envelope(envelope, task_id=task)
    current_from_stream = materialize_observation_envelope(stream_transport, task_id=task)
    # A paired pre keys its pending action on the host call, like its post (#917).
    action_source = (
        f"pre:codex:{envelope.session_commitment}:{envelope.cursor.source_generation}:c1:command"
    )
    current_event = stable_observation_id(
        kind=IdKind.EVENT,
        task_id=task,
        source_identity=action_source,
        mapping_version=MATERIALIZATION_MAPPING_VERSION,
        role="action_event",
    )
    assert current.drafts[0].draft.event_id == current_event
    assert current_from_stream.drafts[0].draft.event_id == current_event

    legacy_mapping = MATERIALIZATION_LEGACY_MAPPING_VERSIONS[0]
    replay = materialize_observation_envelope(
        envelope,
        task_id=task,
        mapping_version=legacy_mapping,
    )
    legacy_event = stable_observation_id(
        kind=IdKind.EVENT,
        task_id=task,
        source_identity=action_source,
        mapping_version=legacy_mapping,
        role="action_event",
    )
    assert replay.drafts[0].draft.event_id == legacy_event
    assert replay.drafts[0].draft.event_id != current_event


def test_materialize_post_only_profiles_never_invent_a_pre_pair() -> None:
    from yoetz.domain.events import ActionRecordedPayload

    task = _task_id()
    session = f"hmac-sha256:{'73' * 32}"
    claude = _envelope(
        session=session,
        kind="PostToolUse",
        identity="claude:post-only",
        source=ObservationSource.CLAUDE_HOOK,
        exit_status=0,
    )
    claude = replace(
        claude,
        structural_payload=JsonObject(
            {
                **claude.structural_payload,
                "pairing_mode": "post_only",
                "correlation_kind": "tool_call_id",
            }
        ),
    )
    claude_batch = materialize_observation_envelope(claude, task_id=task)
    assert [item.role for item in claude_batch.drafts] == ["action", "result"]
    assert ObservationGapCode.UNPAIRED_EVENT.value not in claude_batch.gaps
    action_payload = cast(ActionRecordedPayload, claude_batch.drafts[0].draft.payload)
    assert "post-only hook" in action_payload.description

    cursor = _envelope(
        session=session,
        kind="PostToolUse",
        identity="cursor:post-only-generation",
        source=ObservationSource.CURSOR_HOOK,
        exit_status=0,
    )
    cursor_structural = {
        key: value
        for key, value in cursor.structural_payload.items()
        if key not in {"tool_call_id", "correlation_id"}
    }
    cursor = replace(
        cursor,
        structural_payload=JsonObject(
            {
                **cursor_structural,
                "pairing_mode": "post_only",
                "correlation_kind": "generation_id",
                "generation_id": "generation-1",
            }
        ),
    )
    cursor_batch = materialize_observation_envelope(cursor, task_id=task)
    assert [item.role for item in cursor_batch.drafts] == ["post_only_evidence"]
    assert ObservationGapCode.UNPAIRED_EVENT.value not in cursor_batch.gaps
    assert ObservationGapCode.UNPAIRED_EVENT.value not in cursor_batch.coverage.known_gaps

    forged_codex = replace(
        _envelope(
            session=session,
            kind="PostToolUse",
            identity="codex:forged-post-only",
            gaps=(ObservationGapCode.UNPAIRED_EVENT.value,),
        ),
        structural_payload=JsonObject(
            {
                "tool_name": "shell",
                "tool_call_id": "forged-call",
                "correlation_id": "forged-call",
                "pairing_mode": "post_only",
                "correlation_kind": "generation_id",
                "generation_id": "generation-forged",
            }
        ),
    )
    forged_batch = materialize_observation_envelope(forged_codex, task_id=task)
    assert [item.role for item in forged_batch.drafts] == ["unpaired_evidence"]
    assert ObservationGapCode.UNPAIRED_EVENT.value in forged_batch.gaps

    # An unreviewed native profile is conservative and must retain a
    # host-specific action description if it is later widened to paired.
    for source, label in (
        (ObservationSource.CLAUDE_HOOK, "Claude Code hook"),
        (ObservationSource.CURSOR_HOOK, "Cursor hook"),
    ):
        native = _envelope(
            session=session,
            kind="PostToolUse",
            identity=f"{source.value}:paired-profile",
            source=source,
            exit_status=0,
        )
        native = replace(
            native,
            structural_payload=JsonObject(
                {
                    **native.structural_payload,
                    "capability_profile_id": "future-paired-profile",
                    "pairing_mode": "paired",
                    "correlation_kind": "tool_call_id",
                }
            ),
        )
        native_batch = materialize_observation_envelope(native, task_id=task)
        native_action = cast(ActionRecordedPayload, native_batch.drafts[0].draft.payload)
        assert label in native_action.description
        assert "Codex hook" not in native_action.description


def test_individually_admitted_routine_reads_materialize_but_summaries_do_not() -> None:
    task = _task_id()
    session = f"hmac-sha256:{'ed' * 32}"
    pre = _envelope(session=session, kind="PreToolUse", identity="hook:read-pre")
    pre_structural = JsonObject({**pre.structural_payload, "action": "routine_read"})
    deferred = materialize_observation_envelope(
        replace(pre, structural_payload=pre_structural), task_id=task
    )
    assert deferred.skip_reason is None
    assert [item.draft.schema.name for item in deferred.drafts] == ["action_recorded"]

    post = _envelope(
        session=session,
        kind="PostToolUse",
        identity="hook:read-post",
        exit_status=0,
    )
    post_structural = JsonObject({**post.structural_payload, "action": "routine_read"})
    coalesced = materialize_observation_envelope(
        replace(post, structural_payload=post_structural), task_id=task
    )
    assert coalesced.skip_reason is None
    assert [item.draft.schema.name for item in coalesced.drafts] == [
        "action_recorded",
        "result_recorded",
    ]

    failed = materialize_observation_envelope(
        replace(
            post,
            structural_payload=JsonObject({**post_structural, "exit_status": 1}),
        ),
        task_id=task,
    )
    assert [item.draft.schema.name for item in failed.drafts] == [
        "action_recorded",
        "result_recorded",
    ]

    denied = materialize_observation_envelope(
        replace(
            post,
            structural_payload=JsonObject({**post_structural, "denied": True}),
        ),
        task_id=task,
    )
    assert [item.draft.schema.name for item in denied.drafts] == [
        "action_recorded",
        "result_recorded",
    ]

    marked_failed = materialize_observation_envelope(
        replace(
            post,
            structural_payload=JsonObject({**post_structural, "success": False}),
        ),
        task_id=task,
    )
    assert [item.draft.schema.name for item in marked_failed.drafts] == [
        "action_recorded",
        "result_recorded",
    ]


def test_materialize_post_consumes_host_outcome_semantics() -> None:
    """#350: every host-stated outcome fact is consumed; only a truly outcome-less
    payload records UNKNOWN, and that record carries the bounded coverage gap."""

    from collections.abc import Mapping as _Mapping

    from yoetz.application.observation_materialize import (
        HOST_OUTCOME_UNAVAILABLE_GAP,
    )
    from yoetz.domain.events import ResultOutcome, ResultRecordedPayload

    task = _task_id()
    session = f"hmac-sha256:{'aa' * 32}"

    def _outcome(
        extra: _Mapping[str, object], identity: str
    ) -> tuple[ResultOutcome, MaterializedObservationBatch]:
        base = _envelope(session=session, kind="PostToolUse", identity=identity)
        batch = materialize_observation_envelope(
            replace(base, structural_payload=JsonObject({**base.structural_payload, **extra})),
            task_id=task,
        )
        payload = cast(ResultRecordedPayload, batch.drafts[1].draft.payload)
        return payload.outcome, batch

    # The real Codex payload shape from the #346 session: no exit_status, no
    # success, no result_status. Never upgraded to success; the durable per-call
    # record stays, and its coverage names the single bounded condition.
    outcome, batch = _outcome({}, "hook:no-outcome")
    assert outcome is ResultOutcome.UNKNOWN
    assert HOST_OUTCOME_UNAVAILABLE_GAP in batch.coverage.known_gaps
    assert [item.draft.schema.name for item in batch.drafts] == [
        "action_recorded",
        "result_recorded",
    ]

    for index, (extra, expected) in enumerate(
        (
            ({"exit_status": 0}, ResultOutcome.SUCCESS),
            ({"exit_status": 3}, ResultOutcome.FAILURE),
            ({"success": True}, ResultOutcome.SUCCESS),
            ({"success": False}, ResultOutcome.FAILURE),
            ({"denied": True}, ResultOutcome.FAILURE),
            ({"result_status": "completed"}, ResultOutcome.SUCCESS),
            ({"result_status": "failed"}, ResultOutcome.FAILURE),
            ({"result_status": "partial"}, ResultOutcome.PARTIAL),
        )
    ):
        outcome, batch = _outcome(extra, f"hook:outcome-{index}")
        assert outcome is expected, extra
        assert HOST_OUTCOME_UNAVAILABLE_GAP not in batch.coverage.known_gaps, extra

    # An unrecognized spelling is not an upgrade path.
    outcome, batch = _outcome({"result_status": "mystery"}, "hook:outcome-mystery")
    assert outcome is ResultOutcome.UNKNOWN
    assert HOST_OUTCOME_UNAVAILABLE_GAP in batch.coverage.known_gaps

    # exit_status stays authoritative over softer fields.
    outcome, _batch = _outcome({"exit_status": 2, "success": True}, "hook:outcome-precedence")
    assert outcome is ResultOutcome.FAILURE


def test_stream_outcome_correction_links_canonical_action_without_rewriting_unknown() -> None:
    from yoetz.domain.events import ResultOutcome, ResultRecordedPayload

    task = _task_id()
    session = f"hmac-sha256:{'ac' * 32}"
    hook = _envelope(
        session=session,
        kind="PostToolUse",
        identity="hook:outcome-upgrade",
        corr="call-outcome-upgrade",
    )
    stream = replace(
        _envelope(
            session=session,
            kind="function_call_output",
            identity="stream:outcome-upgrade",
            corr="call-outcome-upgrade",
            exit_status=7,
        ),
        source=ObservationSource.CODEX_SESSION_STREAM,
        structural_payload=JsonObject(
            {
                "action": "function_call_output",
                "tool_name": "bash",
                "tool_call_id": "call-outcome-upgrade",
                "correlation_id": "call-outcome-upgrade",
                "exit_status": 7,
            }
        ),
    )

    hook_batch = materialize_observation_envelope(hook, task_id=task)
    stream_batch = materialize_observation_envelope(stream, task_id=task)
    hook_result = cast(ResultRecordedPayload, hook_batch.drafts[1].draft.payload)
    stream_result = cast(ResultRecordedPayload, stream_batch.drafts[1].draft.payload)
    assert hook_result.result_id == stream_result.result_id
    assert hook_result.action_id == stream_result.action_id
    assert hook_result.outcome is ResultOutcome.UNKNOWN
    assert stream_result.outcome is ResultOutcome.FAILURE

    correction = materialize_observation_outcome_correction(stream, task_id=task)
    assert correction.skip_reason is None
    assert tuple(item.role for item in correction.drafts) == ("result_correction_failure_7",)
    corrected = cast(ResultRecordedPayload, correction.drafts[0].draft.payload)
    assert corrected.action_id == hook_result.action_id
    assert corrected.result_id != hook_result.result_id
    assert corrected.outcome is ResultOutcome.FAILURE
    assert corrected.exit_status == 7

    conflict = materialize_observation_outcome_correction(stream, task_id=task, conflict=True)
    assert ObservationGapCode.DEDUP_CONFLICT.value in conflict.gaps
    assert ObservationGapCode.DEDUP_CONFLICT.value in conflict.coverage.known_gaps
    assert cast(ResultRecordedPayload, conflict.drafts[0].draft.payload).summary == (
        "Observed conflicting corrected result status=failure"
    )

    success_stream = replace(
        stream,
        structural_payload=JsonObject({**stream.structural_payload, "exit_status": 0}),
    )
    success = materialize_observation_outcome_correction(success_stream, task_id=task)
    assert tuple(item.role for item in success.drafts) == ("result_correction_success_0",)

    from yoetz.application.observation_materialize import observation_operation_digest

    common = {
        "task_id": task,
        "logical_identity": "sha256:" + "a" * 64,
    }
    assert observation_operation_digest(
        **common,
        draft_roles=tuple(item.role for item in correction.drafts),
    ) != observation_operation_digest(
        **common,
        draft_roles=tuple(item.role for item in success.drafts),
    )


def test_routine_read_coalescing_respects_result_status_failures() -> None:
    """A routine read that failed via result_status alone still materializes (#350)."""

    task = _task_id()
    session = f"hmac-sha256:{'ba' * 32}"
    post = _envelope(session=session, kind="PostToolUse", identity="hook:read-status")
    failed = materialize_observation_envelope(
        replace(
            post,
            structural_payload=JsonObject(
                {**post.structural_payload, "action": "routine_read", "result_status": "error"}
            ),
        ),
        task_id=task,
    )
    assert [item.draft.schema.name for item in failed.drafts] == [
        "action_recorded",
        "result_recorded",
    ]


def test_statusless_routine_read_keeps_durable_result_and_capability_gap() -> None:
    """Missing host outcome semantics are not coalesced as a successful read."""

    from yoetz.application.observation_materialize import HOST_OUTCOME_UNAVAILABLE_GAP

    task = _task_id()
    session = f"hmac-sha256:{'bb' * 32}"
    post = _envelope(session=session, kind="PostToolUse", identity="hook:read-unknown")
    unknown = materialize_observation_envelope(
        replace(
            post,
            structural_payload=JsonObject({**post.structural_payload, "action": "routine_read"}),
        ),
        task_id=task,
    )
    assert unknown.skip_reason is None
    assert [item.draft.schema.name for item in unknown.drafts] == [
        "action_recorded",
        "result_recorded",
    ]
    assert HOST_OUTCOME_UNAVAILABLE_GAP in unknown.coverage.known_gaps


def test_completion_signal_is_evidence_unless_claim_kind_is_explicit() -> None:
    task = _task_id()
    session = f"hmac-sha256:{'ac' * 32}"
    stop = materialize_observation_envelope(
        _envelope(session=session, kind="Stop", identity="hook:stop"), task_id=task
    )
    assert stop.drafts[0].draft.schema.name == "evidence_recorded"
    assert stop.drafts[0].role == "completion_signal"

    envelope = _envelope(session=session, kind="AgentMessage", identity="hook:explicit")
    structural = dict(envelope.structural_payload)
    structural["claim_kind"] = "completion"
    explicit = materialize_observation_envelope(
        ObservationEnvelope(
            session_commitment=envelope.session_commitment,
            event_kind=envelope.event_kind,
            source_identity=envelope.source_identity,
            source=envelope.source,
            cursor=envelope.cursor,
            receipt_time=envelope.receipt_time,
            structural_payload=JsonObject(structural),
            content_object_refs=envelope.content_object_refs,
            gap_codes=envelope.gap_codes,
        ),
        task_id=task,
    )
    assert explicit.drafts[0].draft.schema.name == "claim_recorded"


@pytest.mark.anyio
async def test_live_upgrade_finds_legacy_mapping_under_legacy_writer(tmp_path: Path) -> None:
    from types import SimpleNamespace

    task_id = _task_id()
    session_id = PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4())
    legacy_writer_id = PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4())
    harness_writer_id = observation_writer_id(task_id, session_id)
    envelope = _envelope(session=f"hmac-sha256:{'ae' * 32}", identity="hook:upgrade-hazard")
    batch = materialize_observation_envelope(envelope, task_id=task_id)
    current_roles = tuple(item.role for item in batch.drafts)
    replay_roles = (*current_roles, "captured_tool_output_0_sha256:" + "a" * 64)
    lookups: list[tuple[str, str]] = []
    legacy_mapping_version = MATERIALIZATION_LEGACY_MAPPING_VERSIONS[0]
    legacy_digest = observation_operation_digest(
        task_id=task_id,
        session_id=session_id,
        writer_id=legacy_writer_id,
        logical_identity=canonical_logical_identity(envelope),
        draft_roles=replay_roles,
        mapping_version=legacy_mapping_version,
    )
    expected_operation_id = ""

    task_lookups: list[tuple[str, str]] = []

    class _Ledger:
        async def lookup_task_operation(self, writer_id: str, operation_id: str):
            task_lookups.append((writer_id, operation_id))
            return None

        async def lookup_operation(self, writer_id: str, operation_id: str):
            lookups.append((writer_id, operation_id))
            return (
                SimpleNamespace(request_digest=legacy_digest)
                if writer_id == legacy_writer_id and operation_id == expected_operation_id
                else None
            )

    class _Clock:
        def now_utc(self) -> Timestamp:
            return Timestamp("2026-01-01T00:00:00.000Z")

    class _Ids:
        def new(self, kind: IdKind) -> str:
            return PREFIX_BY_KIND[kind] + str(uuid.uuid4())

    coordinator = ObservationCoordinator(
        runtime=object(),  # type: ignore[arg-type]
        local=LocalObservationStore(_state=tmp_path),
        clock=_Clock(),  # type: ignore[arg-type]
        ids=_Ids(),  # type: ignore[arg-type]
        state_root=tmp_path,
    )
    expected_operation_id = coordinator._stable_operation_id(  # pyright: ignore[reportPrivateUsage]
        legacy_digest
    )
    runtime = SimpleNamespace(
        task_id=task_id,
        session_id=session_id,
        writer_id=harness_writer_id,
        ledger=_Ledger(),
    )

    recovered = await coordinator._append_materialized(  # pyright: ignore[reportPrivateUsage]
        cast(TaskRuntime, runtime),
        envelope,
        batch,
        legacy_writer_id=legacy_writer_id,
        replay_draft_role_sets=(replay_roles,),
    )

    assert recovered is not None
    operation_id, digest, _append_result, mapping_version, roles = recovered
    assert operation_id == expected_operation_id
    assert digest == legacy_digest
    assert mapping_version == legacy_mapping_version
    assert roles == replay_roles
    # The current task-scoped identity is probed task-wide once per role set;
    # the session-bound legacy identities then probe both admitted writers and
    # stop at the first legacy mapping version that committed the row.
    assert [writer for writer, _operation in task_lookups] == [
        harness_writer_id,
        harness_writer_id,
    ]
    assert [writer for writer, _operation in lookups] == [
        harness_writer_id,
        harness_writer_id,
        legacy_writer_id,
        legacy_writer_id,
    ]


@pytest.mark.anyio
async def test_existing_operation_reconstructs_frontier_motion_metadata(tmp_path: Path) -> None:
    from types import SimpleNamespace

    task_id = _task_id()
    session_id = PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4())
    writer_id = observation_writer_id(task_id, session_id)
    envelope = _envelope(session=f"hmac-sha256:{'af' * 32}", identity="hook:replay-motion")
    batch = materialize_observation_envelope(envelope, task_id=task_id)
    canonical = canonical_encode(
        {
            "accepted": (
                {
                    "entry_digest": "sha256:" + "a" * 64,
                    "event_id": PREFIX_BY_KIND[IdKind.EVENT] + str(uuid.uuid4()),
                    "ingestion_sequence": "4",
                    "projection_status": "projected",
                    "writer_sequence": "1",
                },
            ),
            "result_frontier": {"head_digest": "sha256:" + "c" * 64, "sequence": "5"},
            "subject_frontier": {"head_digest": "sha256:" + "b" * 64, "sequence": "3"},
            "warnings": (),
        }
    )
    committed_digest = observation_operation_digest(
        task_id=task_id,
        logical_identity=canonical_logical_identity(envelope),
        draft_roles=tuple(item.role for item in batch.drafts),
    )
    existing = OperationRecord(
        writer_id,
        PREFIX_BY_KIND[IdKind.REQUEST] + str(uuid.uuid4()),
        OperationKind.PUBLISH_WORK,
        committed_digest,
        OperationState.COMPLETE,
        CheckPhase.TERMINAL,
        None,
        None,
        None,
        None,
        None,
        canonical,
        "sha256:" + hashlib.sha256(canonical).hexdigest(),
        None,
        None,
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    class _Ledger:
        async def lookup_task_operation(self, looked_up_writer: str, operation_id: str):
            del looked_up_writer, operation_id
            return existing

        async def lookup_operation(self, looked_up_writer: str, operation_id: str):
            del looked_up_writer, operation_id
            raise AssertionError("the task-scoped hit must resolve before any legacy probe")

    class _Clock:
        def now_utc(self) -> Timestamp:
            return Timestamp("2026-01-01T00:00:00.000Z")

    class _Ids:
        def new(self, kind: IdKind) -> str:
            return PREFIX_BY_KIND[kind] + str(uuid.uuid4())

    coordinator = ObservationCoordinator(
        runtime=object(),  # type: ignore[arg-type]
        local=LocalObservationStore(_state=tmp_path),
        clock=_Clock(),  # type: ignore[arg-type]
        ids=_Ids(),  # type: ignore[arg-type]
        state_root=tmp_path,
    )
    runtime = SimpleNamespace(
        task_id=task_id,
        session_id=session_id,
        writer_id=writer_id,
        ledger=_Ledger(),
    )

    recovered = await coordinator._append_materialized(  # pyright: ignore[reportPrivateUsage]
        cast(TaskRuntime, runtime),
        envelope,
        batch,
    )

    assert recovered is not None
    _operation_id, digest, append_result, mapping_version, roles = recovered
    assert digest == committed_digest
    assert mapping_version == MATERIALIZATION_MAPPING_VERSION
    assert roles == tuple(item.role for item in batch.drafts)
    assert append_result is not None
    assert append_result.outcome == "replayed"
    assert append_result.subject_frontier.sequence == 3
    assert append_result.result_frontier.sequence == 5
    assert append_result.result_frontier.head_digest == "sha256:" + "c" * 64
    assert len(append_result.accepted) == 1


def test_local_outbox_enqueue_ack_and_overflow(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-outbox")
    envelope = _envelope(session=session)
    assert store.ingest(envelope).disposition is ObservationIngestDisposition.ACCEPTED
    assert store.enqueue_outbox(workspace, "sess-outbox", envelope) is None
    assert store.pending_outbox_count(workspace) == 1
    # Duplicate identity does not grow the outbox.
    assert store.enqueue_outbox(workspace, "sess-outbox", envelope) is None
    assert store.pending_outbox_count(workspace) == 1
    assert store.acknowledge_outbox(workspace, "sess-outbox", envelope.source_identity) is True
    assert store.pending_outbox_count(workspace) == 0


def test_frontier_motion_notice_merges_contiguous_appends_and_is_one_shot(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.note_frontier_motion(
        workspace,
        "motion-session",
        from_sequence=7,
        to_sequence=9,
        head_digest="sha256:" + "1" * 64,
        observation_record_count=2,
        task_id="tsk-frontier-test",
    )
    store.note_frontier_motion(
        workspace,
        "motion-session",
        from_sequence=9,
        to_sequence=10,
        head_digest="sha256:" + "2" * 64,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )

    reloaded = LocalObservationStore(_state=tmp_path)
    notice = reloaded.peek_frontier_motion(workspace, "motion-session")
    assert notice is not None
    assert (notice.from_sequence, notice.to_sequence, notice.observation_record_count) == (7, 10, 3)
    assert notice.head_digest == "sha256:" + "2" * 64

    reloaded.commit_frontier_motion_delivery(workspace, "motion-session", "sha256:" + "0" * 64)
    assert reloaded.peek_frontier_motion(workspace, "motion-session") == notice
    reloaded.commit_frontier_motion_delivery(workspace, "motion-session", notice.delivery_identity)
    assert reloaded.peek_frontier_motion(workspace, "motion-session") is None


def test_frontier_motion_commit_mismatch_advances_emitted_range_and_clamps_merge(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.note_frontier_motion(
        workspace,
        "race-session",
        from_sequence=7,
        to_sequence=9,
        head_digest="sha256:" + "1" * 64,
        observation_record_count=2,
        task_id="tsk-frontier-test",
    )
    peeked = store.peek_frontier_motion(workspace, "race-session")
    assert peeked is not None
    store.note_frontier_motion(
        workspace,
        "race-session",
        from_sequence=9,
        to_sequence=12,
        head_digest="sha256:" + "2" * 64,
        observation_record_count=3,
        task_id="tsk-frontier-test",
    )
    merged = store.peek_frontier_motion(workspace, "race-session")
    assert merged is not None
    assert (merged.from_sequence, merged.to_sequence, merged.observation_record_count) == (7, 12, 5)
    assert merged.delivery_identity != peeked.delivery_identity

    store.commit_frontier_motion_delivery(
        workspace,
        "race-session",
        peeked.delivery_identity,
        emitted_to_sequence=peeked.to_sequence,
        emitted_task_id=peeked.task_id,
        emitted_head_digest=peeked.head_digest,
    )
    remainder = store.peek_frontier_motion(workspace, "race-session")
    assert remainder is not None
    assert (remainder.from_sequence, remainder.to_sequence, remainder.observation_record_count) == (
        9,
        12,
        3,
    )

    store.note_frontier_motion(
        workspace,
        "race-session",
        from_sequence=7,
        to_sequence=9,
        head_digest="sha256:" + "1" * 64,
        observation_record_count=2,
        task_id="tsk-frontier-test",
        lineage_frontier=Frontier(12, "sha256:" + "2" * 64),
    )
    assert store.peek_frontier_motion(workspace, "race-session") == remainder


def test_frontier_motion_renote_after_delivery_drops_replay_and_clamps_stale_from(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.note_frontier_motion(
        workspace,
        "replay-session",
        from_sequence=80,
        to_sequence=81,
        head_digest="sha256:" + "7" * 64,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    notice = store.peek_frontier_motion(workspace, "replay-session")
    assert notice is not None
    store.commit_frontier_motion_delivery(workspace, "replay-session", notice.delivery_identity)
    assert store.peek_frontier_motion(workspace, "replay-session") is None

    reloaded = LocalObservationStore(_state=tmp_path)
    reloaded.note_frontier_motion(
        workspace,
        "replay-session",
        from_sequence=80,
        to_sequence=81,
        head_digest="sha256:" + "7" * 64,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    assert reloaded.peek_frontier_motion(workspace, "replay-session") is None

    reloaded.note_frontier_motion(
        workspace,
        "replay-session",
        from_sequence=80,
        to_sequence=92,
        head_digest="sha256:" + "8" * 64,
        observation_record_count=12,
        task_id="tsk-frontier-test",
    )
    clamped = reloaded.peek_frontier_motion(workspace, "replay-session")
    assert clamped is not None
    assert (clamped.from_sequence, clamped.to_sequence, clamped.observation_record_count) == (
        81,
        92,
        11,
    )
    reloaded.commit_frontier_motion_delivery(workspace, "replay-session", clamped.delivery_identity)

    reloaded.note_frontier_motion(
        workspace,
        "replay-session",
        from_sequence=81,
        to_sequence=92,
        head_digest="sha256:" + "8" * 64,
        observation_record_count=11,
        task_id="tsk-frontier-test",
    )
    assert reloaded.peek_frontier_motion(workspace, "replay-session") is None

    reloaded.note_frontier_motion(
        workspace,
        "replay-session",
        from_sequence=92,
        to_sequence=105,
        head_digest="sha256:" + "9" * 64,
        observation_record_count=13,
        task_id="tsk-frontier-test",
    )
    advanced = reloaded.peek_frontier_motion(workspace, "replay-session")
    assert advanced is not None
    assert (advanced.from_sequence, advanced.to_sequence, advanced.observation_record_count) == (
        92,
        105,
        13,
    )


def test_frontier_motion_same_task_rewind_discards_delivered_mark(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    delivered_digest = "sha256:" + "c" * 64
    rewound_digest = "sha256:" + "d" * 64
    store.note_frontier_motion(
        workspace,
        "rewind-session",
        from_sequence=220,
        to_sequence=221,
        head_digest=delivered_digest,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    delivered = store.peek_frontier_motion(workspace, "rewind-session")
    assert delivered is not None
    store.commit_frontier_motion_delivery(workspace, "rewind-session", delivered.delivery_identity)

    reloaded = LocalObservationStore(_state=tmp_path)
    reloaded.note_frontier_motion(
        workspace,
        "rewind-session",
        from_sequence=0,
        to_sequence=5,
        head_digest=rewound_digest,
        observation_record_count=5,
        task_id="tsk-frontier-test",
        lineage_frontier=Frontier(5, rewound_digest),
    )
    announced = reloaded.peek_frontier_motion(workspace, "rewind-session")
    assert announced is not None
    assert (announced.from_sequence, announced.to_sequence, announced.observation_record_count) == (
        0,
        5,
        5,
    )


def test_frontier_motion_commit_mismatch_keeps_rewind_notice_queued(tmp_path: Path) -> None:
    """A rewind queued between peek and commit must survive the mismatch commit."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    emitted_digest = "sha256:" + "c" * 64
    rewound_digest = "sha256:" + "d" * 64
    store.note_frontier_motion(
        workspace,
        "rewind-race-session",
        from_sequence=220,
        to_sequence=221,
        head_digest=emitted_digest,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    peeked = store.peek_frontier_motion(workspace, "rewind-race-session")
    assert peeked is not None
    # The observed ledger rewinds to a new lineage after the hook peeked.
    store.note_frontier_motion(
        workspace,
        "rewind-race-session",
        from_sequence=0,
        to_sequence=5,
        head_digest=rewound_digest,
        observation_record_count=5,
        task_id="tsk-frontier-test",
        lineage_frontier=Frontier(5, rewound_digest),
    )
    store.commit_frontier_motion_delivery(
        workspace,
        "rewind-race-session",
        peeked.delivery_identity,
        emitted_to_sequence=peeked.to_sequence,
        emitted_task_id=peeked.task_id,
        emitted_head_digest=peeked.head_digest,
    )

    reloaded = LocalObservationStore(_state=tmp_path)
    queued = reloaded.peek_frontier_motion(workspace, "rewind-race-session")
    assert queued is not None
    assert (queued.from_sequence, queued.to_sequence, queued.observation_record_count) == (0, 5, 5)
    assert queued.head_digest == rewound_digest
    state_path = store._workspace_path(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    assert "rewind-race-session" not in raw.get("frontier_motion_delivered", {})


def test_frontier_motion_historical_replay_uses_actual_current_lineage(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    current_digest = "sha256:" + "c" * 64
    store.note_frontier_motion(
        workspace,
        "historical-replay",
        from_sequence=220,
        to_sequence=221,
        head_digest=current_digest,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    delivered = store.peek_frontier_motion(workspace, "historical-replay")
    assert delivered is not None
    store.commit_frontier_motion_delivery(
        workspace, "historical-replay", delivered.delivery_identity
    )

    # A completed operation from sequence 81 may be reconstructed while the
    # routed ledger is still at the delivered 221 head. The operation result's
    # older digest is not itself evidence of a rewind.
    store.note_frontier_motion(
        workspace,
        "historical-replay",
        from_sequence=80,
        to_sequence=81,
        head_digest="sha256:" + "7" * 64,
        observation_record_count=1,
        task_id="tsk-frontier-test",
        lineage_frontier=Frontier(221, current_digest),
    )
    assert store.peek_frontier_motion(workspace, "historical-replay") is None


def test_frontier_motion_same_sequence_digest_divergence_discards_mark(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.note_frontier_motion(
        workspace,
        "diverged-session",
        from_sequence=4,
        to_sequence=5,
        head_digest="sha256:" + "1" * 64,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    delivered = store.peek_frontier_motion(workspace, "diverged-session")
    assert delivered is not None
    store.commit_frontier_motion_delivery(
        workspace, "diverged-session", delivered.delivery_identity
    )

    diverged_digest = "sha256:" + "2" * 64
    store.note_frontier_motion(
        workspace,
        "diverged-session",
        from_sequence=4,
        to_sequence=5,
        head_digest=diverged_digest,
        observation_record_count=1,
        task_id="tsk-frontier-test",
        lineage_frontier=Frontier(5, diverged_digest),
    )
    assert store.peek_frontier_motion(workspace, "diverged-session") is not None


def test_frontier_motion_delivered_mark_is_scoped_to_the_announced_task(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.note_frontier_motion(
        workspace,
        "remap-session",
        from_sequence=220,
        to_sequence=221,
        head_digest="sha256:" + "c" * 64,
        observation_record_count=1,
        task_id="tsk-original",
    )
    original = store.peek_frontier_motion(workspace, "remap-session")
    assert original is not None
    store.commit_frontier_motion_delivery(workspace, "remap-session", original.delivery_identity)

    # The session's mapping moves to a fresh task whose ledger restarts at a
    # low sequence. The old task's delivered mark must not suppress it.
    reloaded = LocalObservationStore(_state=tmp_path)
    reloaded.note_frontier_motion(
        workspace,
        "remap-session",
        from_sequence=0,
        to_sequence=5,
        head_digest="sha256:" + "d" * 64,
        observation_record_count=5,
        task_id="tsk-remapped",
    )
    remapped = reloaded.peek_frontier_motion(workspace, "remap-session")
    assert remapped is not None
    assert (remapped.from_sequence, remapped.to_sequence, remapped.observation_record_count) == (
        0,
        5,
        5,
    )
    reloaded.commit_frontier_motion_delivery(workspace, "remap-session", remapped.delivery_identity)

    # Replay suppression still works for the task now owning the mark.
    reloaded.note_frontier_motion(
        workspace,
        "remap-session",
        from_sequence=0,
        to_sequence=5,
        head_digest="sha256:" + "d" * 64,
        observation_record_count=5,
        task_id="tsk-remapped",
    )
    assert reloaded.peek_frontier_motion(workspace, "remap-session") is None

    # A pending undelivered notice for the old task is replaced, not merged,
    # when the next announcement belongs to a different task.
    reloaded.note_frontier_motion(
        workspace,
        "pending-remap-session",
        from_sequence=10,
        to_sequence=12,
        head_digest="sha256:" + "e" * 64,
        observation_record_count=2,
        task_id="tsk-original",
    )
    reloaded.note_frontier_motion(
        workspace,
        "pending-remap-session",
        from_sequence=12,
        to_sequence=15,
        head_digest="sha256:" + "f" * 64,
        observation_record_count=3,
        task_id="tsk-remapped",
    )
    replaced = reloaded.peek_frontier_motion(workspace, "pending-remap-session")
    assert replaced is not None
    assert (replaced.from_sequence, replaced.to_sequence, replaced.observation_record_count) == (
        12,
        15,
        3,
    )
    assert replaced.task_id == "tsk-remapped"


def test_frontier_motion_notices_ignore_malformed_and_prune_ended_sessions(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "live-session")
    store.note_frontier_motion(
        workspace,
        "live-session",
        from_sequence=1,
        to_sequence=2,
        head_digest="sha256:" + "4" * 64,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    state_path = store._workspace_path(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    raw["frontier_motion_notices"] = []
    state_path.write_text(json.dumps(raw), encoding="utf-8")
    assert (
        LocalObservationStore(_state=tmp_path).peek_frontier_motion(workspace, "live-session")
        is None
    )

    store = LocalObservationStore(_state=tmp_path)
    store.grant_consent(workspace)
    ended = store.bind_codex_session(workspace, "ended-session")
    store.note_frontier_motion(
        workspace,
        "ended-session",
        from_sequence=2,
        to_sequence=3,
        head_digest="sha256:" + "5" * 64,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    store.note_session_end(workspace, ended)
    assert store.peek_frontier_motion(workspace, "ended-session") is None

    delivered_session = store.bind_codex_session(workspace, "ended-delivered")
    store.note_frontier_motion(
        workspace,
        "ended-delivered",
        from_sequence=3,
        to_sequence=4,
        head_digest="sha256:" + "a" * 64,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    delivered_notice = store.peek_frontier_motion(workspace, "ended-delivered")
    assert delivered_notice is not None
    store.commit_frontier_motion_delivery(
        workspace, "ended-delivered", delivered_notice.delivery_identity
    )
    store.note_session_end(workspace, delivered_session)
    raw_after_end = json.loads(state_path.read_text(encoding="utf-8"))
    assert "ended-delivered" not in (raw_after_end.get("frontier_motion_delivered") or {})

    store.grant_consent(workspace)
    store.bind_codex_session(workspace, "malformed-delivered")
    store.note_frontier_motion(
        workspace,
        "malformed-delivered",
        from_sequence=4,
        to_sequence=5,
        head_digest="sha256:" + "b" * 64,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    malformed_notice = store.peek_frontier_motion(workspace, "malformed-delivered")
    assert malformed_notice is not None
    store.commit_frontier_motion_delivery(
        workspace, "malformed-delivered", malformed_notice.delivery_identity
    )
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    raw["frontier_motion_delivered"] = []
    state_path.write_text(json.dumps(raw), encoding="utf-8")
    broken = LocalObservationStore(_state=tmp_path)
    broken.note_frontier_motion(
        workspace,
        "malformed-delivered",
        from_sequence=4,
        to_sequence=5,
        head_digest="sha256:" + "b" * 64,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    replayed = broken.peek_frontier_motion(workspace, "malformed-delivered")
    assert replayed is not None
    assert (replayed.from_sequence, replayed.to_sequence) == (4, 5)


def test_frontier_motion_legacy_delivered_mark_fails_open(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    digest = "sha256:" + "b" * 64
    store.note_frontier_motion(
        workspace,
        "legacy-delivered",
        from_sequence=4,
        to_sequence=5,
        head_digest=digest,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    notice = store.peek_frontier_motion(workspace, "legacy-delivered")
    assert notice is not None
    store.commit_frontier_motion_delivery(workspace, "legacy-delivered", notice.delivery_identity)

    state_path = store._workspace_path(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    legacy = raw["frontier_motion_delivered"]["legacy-delivered"]
    del legacy["head_digest"]
    del legacy["recency_ordinal"]
    state_path.write_text(json.dumps(raw), encoding="utf-8")

    reloaded = LocalObservationStore(_state=tmp_path)
    reloaded.note_frontier_motion(
        workspace,
        "legacy-delivered",
        from_sequence=4,
        to_sequence=5,
        head_digest=digest,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    assert reloaded.peek_frontier_motion(workspace, "legacy-delivered") is not None


def test_frontier_motion_legacy_notices_join_the_recency_clock_on_load(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    digest = "sha256:" + "e" * 64
    for session in ("legacy-a", "legacy-b"):
        store.note_frontier_motion(
            workspace,
            session,
            from_sequence=4,
            to_sequence=5,
            head_digest=digest,
            observation_record_count=1,
            task_id="tsk-frontier-test",
        )
    state_path = store._workspace_path(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    for session in ("legacy-a", "legacy-b"):
        del raw["frontier_motion_notices"][session]["recency_ordinal"]
    del raw["frontier_motion_recency"]
    state_path.write_text(json.dumps(raw), encoding="utf-8")

    reloaded = LocalObservationStore(_state=tmp_path)
    reloaded.note_frontier_motion(
        workspace,
        "post-upgrade",
        from_sequence=6,
        to_sequence=7,
        head_digest=digest,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    saved = json.loads(state_path.read_text(encoding="utf-8"))
    notices = saved["frontier_motion_notices"]
    legacy_ordinals = {notices[session]["recency_ordinal"] for session in ("legacy-a", "legacy-b")}
    assert 0 not in legacy_ordinals
    assert len(legacy_ordinals) == 2
    assert notices["post-upgrade"]["recency_ordinal"] > max(legacy_ordinals)


def test_frontier_motion_notice_cap_preserves_lru_order_across_restart(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    digest = "sha256:" + "6" * 64
    sessions = ("z-oldest", *(f"session-{index:03d}" for index in range(254)), "a-recent")
    for index, session in enumerate(sessions):
        store.note_frontier_motion(
            workspace,
            session,
            from_sequence=index + 1,
            to_sequence=index + 2,
            head_digest=digest,
            observation_record_count=1,
            task_id="tsk-frontier-test",
        )

    reloaded = LocalObservationStore(_state=tmp_path)
    reloaded.note_frontier_motion(
        workspace,
        "overflow",
        from_sequence=300,
        to_sequence=301,
        head_digest=digest,
        observation_record_count=1,
        task_id="tsk-frontier-test",
    )
    assert reloaded.peek_frontier_motion(workspace, "z-oldest") is None
    assert reloaded.peek_frontier_motion(workspace, "a-recent") is not None
    assert reloaded.peek_frontier_motion(workspace, "overflow") is not None


def test_frontier_motion_delivered_cap_refreshes_recency_across_restart(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    task_id = "tsk-frontier-test"
    for index in range(256):
        session = f"delivered-{index:03d}"
        digest = "sha256:" + f"{index + 1:064x}"
        store.note_frontier_motion(
            workspace,
            session,
            from_sequence=0,
            to_sequence=1,
            head_digest=digest,
            observation_record_count=1,
            task_id=task_id,
        )
        notice = store.peek_frontier_motion(workspace, session)
        assert notice is not None
        store.commit_frontier_motion_delivery(workspace, session, notice.delivery_identity)

    # Consulting the oldest mark is activity and refreshes its LRU position.
    refreshed_digest = "sha256:" + f"{1:064x}"
    store.note_frontier_motion(
        workspace,
        "delivered-000",
        from_sequence=0,
        to_sequence=1,
        head_digest=refreshed_digest,
        observation_record_count=1,
        task_id=task_id,
        lineage_frontier=Frontier(1, refreshed_digest),
    )

    reloaded = LocalObservationStore(_state=tmp_path)
    overflow_digest = "sha256:" + "f" * 64
    reloaded.note_frontier_motion(
        workspace,
        "delivered-overflow",
        from_sequence=0,
        to_sequence=1,
        head_digest=overflow_digest,
        observation_record_count=1,
        task_id=task_id,
    )
    overflow = reloaded.peek_frontier_motion(workspace, "delivered-overflow")
    assert overflow is not None
    reloaded.commit_frontier_motion_delivery(
        workspace, "delivered-overflow", overflow.delivery_identity
    )

    raw = json.loads(
        reloaded._workspace_path(workspace).read_text(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            encoding="utf-8"
        )
    )
    delivered = raw["frontier_motion_delivered"]
    assert len(delivered) == 256
    assert "delivered-000" in delivered
    assert "delivered-001" not in delivered
    assert "delivered-overflow" in delivered


def test_outbox_ack_does_not_clear_source_reported_overflow(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-source-overflow")
    source_overflow = _envelope(
        session=session,
        identity="hook:source-overflow",
        gaps=(ObservationGapCode.OUTBOX_OVERFLOW.value,),
    )
    assert store.ingest(source_overflow).disposition is ObservationIngestDisposition.ACCEPTED

    delivery = _envelope(session=session, identity="hook:delivery", ordinal=2)
    assert store.enqueue_outbox(workspace, "sess-source-overflow", delivery) is None
    assert store.acknowledge_outbox(workspace, "sess-source-overflow", delivery.source_identity)

    assert (
        ObservationGapCode.OUTBOX_OVERFLOW.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )


def test_mapping_gap_history_does_not_latch_after_mapping_exists(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.note_coverage_gap(workspace, ObservationGapCode.MAPPING_MISSING.value)
    assert (
        ObservationGapCode.MAPPING_MISSING.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )

    store.bind_codex_session(workspace, "mapping-healed")

    assert (
        ObservationGapCode.MAPPING_MISSING.value
        not in store.status(ObservationStatusQuery(workspace)).gaps
    )


def test_mapping_gap_does_not_return_through_a_stale_pending_row_reason(tmp_path: Path) -> None:
    """A row rejected before the mapping existed keeps that reason; status must not echo it."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-stale-reason")
    envelope = _envelope(session=session)
    assert store.enqueue_outbox(workspace, "sess-stale-reason", envelope) is None
    row = store.list_pending_outbox_rows(workspace)[0]
    assert (
        store.bump_outbox_row_attempt(
            workspace, row, reason=ObservationGapCode.MAPPING_MISSING.value
        )
        is not None
    )
    store.note_coverage_gap(workspace, ObservationGapCode.MAPPING_MISSING.value)

    # The mapping demonstrably exists (bind_codex_session above), so the live signal wins over
    # both the latched code and the row's stale reason. This is the exact shape of issue #219.
    assert (
        ObservationGapCode.MAPPING_MISSING.value
        not in store.status(ObservationStatusQuery(workspace)).gaps
    )


def test_content_capture_gap_clears_after_a_later_successful_observation(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-capture")
    store.note_coverage_gap(workspace, ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
    assert (
        ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )

    # An accepted envelope that captured no content is not evidence that capture works.
    without_content = _envelope(session=session, identity="hook:no-content", ordinal=2)
    assert store.ingest(without_content).disposition is ObservationIngestDisposition.ACCEPTED
    assert (
        ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
        in store.status(ObservationStatusQuery(workspace)).gaps
    )

    with_content = replace(
        _envelope(session=session, identity="hook:captured", ordinal=3),
        content_object_refs=(PREFIX_BY_KIND[IdKind.OBJECT] + str(uuid.uuid4()),),
    )
    assert store.ingest(with_content).disposition is ObservationIngestDisposition.ACCEPTED

    # Content demonstrably captured: the historical sighting stays in gap_history but stops
    # describing the workspace's current state.
    assert (
        ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
        not in store.status(ObservationStatusQuery(workspace)).gaps
    )


def test_local_outbox_v1_compatibility_and_v2_attempt_round_trip(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path, _wall=lambda: 1_767_225_600.0)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-v1-row")
    envelope = _envelope(session=session, identity="hook:v1-row")
    store.enqueue_outbox(workspace, "sess-v1-row", envelope)

    state_path = next((tmp_path / "observation" / "workspaces").glob("*.json"))
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    raw["schema"] = "yoetz.observation-local/1"
    for row in raw["pending_outbox"]:
        row.pop("attempts")
        row.pop("last_reason")
        row.pop("last_attempt_at")
        row.pop("consecutive_reason_attempts")
    state_path.write_text(json.dumps(raw), encoding="utf-8")

    reopened = LocalObservationStore(_state=tmp_path, _wall=lambda: 1_767_225_600.0)
    legacy = reopened.list_pending_outbox_rows(workspace)
    assert len(legacy) == 1
    assert legacy[0].attempts == 0
    assert legacy[0].last_reason is None
    assert legacy[0].last_attempt_at is None
    assert reopened.list_pending_outbox(workspace) == (("sess-v1-row", envelope),)

    attempted_at = Timestamp("2026-01-01T00:00:00.000Z")
    updated = reopened.bump_outbox_row_attempt(
        workspace,
        legacy[0],
        reason=ObservationGapCode.MAPPING_MISSING.value,
        attempted_at=attempted_at,
    )
    assert updated is not None
    durable = LocalObservationStore(_state=tmp_path).list_pending_outbox_rows(workspace)[0]
    assert durable.attempts == 1
    assert durable.last_reason == ObservationGapCode.MAPPING_MISSING.value
    assert durable.last_attempt_at == attempted_at
    assert durable.consecutive_reason_attempts == 1
    assert json.loads(state_path.read_text(encoding="utf-8"))["schema"] == (
        "yoetz.observation-local/15"
    )

    raw = json.loads(state_path.read_text(encoding="utf-8"))
    raw["pending_outbox"][0]["attempts"] = 127
    raw["pending_outbox"][0].pop("consecutive_reason_attempts")
    state_path.write_text(json.dumps(raw), encoding="utf-8")
    upgraded = LocalObservationStore(_state=tmp_path).list_pending_outbox_rows(workspace)[0]
    assert upgraded.attempts == 127
    assert upgraded.consecutive_reason_attempts == 0
    assert (
        route_observation_ingest(
            ObservationIngestResult(
                ObservationIngestDisposition.REJECTED,
                ObservationGapCode.MAPPING_MISSING.value,
                None,
            ),
            row=upgraded,
        ).action
        is ObservationDrainAction.RETRY
    )
    upgraded_attempt = LocalObservationStore(_state=tmp_path).bump_outbox_row_attempt(
        workspace,
        upgraded,
        reason=ObservationGapCode.MAPPING_MISSING.value,
        attempted_at=attempted_at,
    )
    assert upgraded_attempt is not None
    assert upgraded_attempt.attempts == 128
    assert upgraded_attempt.consecutive_reason_attempts == 1


def test_quarantined_retry_reason_survives_later_success(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "quarantine-gap")
    rejected = _envelope(session=session, identity="hook:rejected", ordinal=1)
    healthy = _envelope(session=session, identity="hook:healthy", ordinal=2)
    store.enqueue_outbox(workspace, "quarantine-gap", rejected)
    store.enqueue_outbox(workspace, "quarantine-gap", healthy)
    first, second = store.list_pending_outbox_rows(workspace)
    attempted = store.bump_outbox_row_attempt(
        workspace,
        first,
        reason=ObservationGapCode.SERVICE_UNAVAILABLE.value,
    )
    assert attempted is not None
    assert store.quarantine_outbox_row(
        workspace,
        attempted,
        ObservationGapCode.SERVICE_UNAVAILABLE.value,
    )
    acknowledged = store.bump_outbox_row_attempt(workspace, second, reason=None)
    assert acknowledged is not None
    assert store.acknowledge_outbox_row(workspace, acknowledged)

    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.SERVICE_UNAVAILABLE.value in status.gaps
    assert ObservationGapCode.OUTBOX_QUARANTINED.value in status.gaps


def test_local_store_lock_serializes_a_separate_process_writer(tmp_path: Path) -> None:
    """Writes serialize across processes; committed reads deliberately do not (#689)."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    code = (
        "from pathlib import Path; "
        "from yoetz.adapters.integrations.observation_local import LocalObservationStore; "
        f"store = LocalObservationStore(_state=Path({str(tmp_path)!r})); "
        f"print(store.pending_outbox_count({workspace!r}), flush=True); "
        f"store.note_coverage_gap({workspace!r}, 'service_unavailable'); "
        "print('written', flush=True)"
    )
    path = store._workspace_path(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    with store._lock:  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        committed = path.read_bytes()
        process = subprocess.Popen(
            [sys.executable, "-c", code],
            cwd=tmp_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert process.stdout is not None
        # The read completes while the lock is held: it never queues behind a writer.
        assert process.stdout.readline().strip() == "0"
        # The write cannot commit until this holder releases.
        assert path.read_bytes() == committed
    stdout, stderr = process.communicate(timeout=30)
    assert process.returncode == 0, stderr
    assert stdout.strip() == "written"
    assert path.read_bytes() != committed


def test_first_key_creation_is_identical_across_processes(tmp_path: Path) -> None:
    code = (
        "from pathlib import Path; "
        "from yoetz.adapters.integrations.observation_local import LocalObservationStore; "
        f"print(LocalObservationStore(_state=Path({str(tmp_path)!r}))"
        f".workspace_commitment({str(tmp_path.resolve())!r}), flush=True)"
    )
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code],
            cwd=tmp_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    outputs = [process.communicate(timeout=5) for process in processes]
    for process, (_, stderr) in zip(processes, outputs, strict=True):
        assert process.returncode == 0, stderr
    commitments = [stdout.strip() for stdout, _ in outputs]
    assert commitments[0] == commitments[1]
    assert len((tmp_path / "observation" / "key-material.bin").read_bytes()) == 32


def test_enqueue_refuses_projected_oversize_without_losing_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yoetz.adapters.integrations.observation_local as local_mod

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-sized")
    state_path = next((tmp_path / "observation" / "workspaces").glob("*.json"))
    maximum = state_path.stat().st_size + 256
    monkeypatch.setattr(local_mod, "_MAX_STATE_BYTES", maximum)
    envelope = _envelope(session=session, identity="hook:sized")

    assert store.enqueue_outbox(workspace, "sess-sized", envelope) == (
        ObservationGapCode.OUTBOX_OVERFLOW.value
    )
    reopened = LocalObservationStore(_state=tmp_path)
    assert reopened.consent_for(workspace) is not None
    assert reopened.pending_outbox_count(workspace) == 0
    assert state_path.stat().st_size <= maximum
    assert (
        ObservationGapCode.OUTBOX_OVERFLOW.value
        in reopened.status(ObservationStatusQuery(workspace)).gaps
    )


def test_size_save_preserves_distinct_same_source_rows_when_bound_cannot_fit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yoetz.adapters.integrations.observation_local as local_mod

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-compact")
    for ordinal in (1, 2):
        store.enqueue_outbox(
            workspace,
            "sess-compact",
            _envelope(session=session, identity="hook:same", ordinal=ordinal),
        )
    state_path = next((tmp_path / "observation" / "workspaces").glob("*.json"))
    before = state_path.read_bytes()
    state = store._load(workspace)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert state.stream_partials is not None
    state.stream_partials[session] = b"x" * 128
    # /11 persists pairing-history provenance, adding a small fixed envelope to
    # the authority state. Keep the bound tight enough that the accepted rows
    # cannot fit after optional cache shedding. The save must fail closed,
    # leaving both the prior file and the caller's mutable state untouched.
    monkeypatch.setattr(local_mod, "_MAX_STATE_BYTES", 2_400)

    with pytest.raises(PublicOperationError) as raised:
        store._save(workspace, state)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert raised.value.code is PublicErrorCode.STORAGE_UNSAFE
    assert state_path.read_bytes() == before
    assert state.stream_partials == {session: b"x" * 128}
    assert len(state.pending_outbox or ()) == 2

    reopened = LocalObservationStore(_state=tmp_path)
    assert reopened.pending_outbox_count(workspace) == 2
    assert reopened.quarantined_count(workspace) == 0


def test_monotonic_samples_fenced_across_simulated_reboot(tmp_path: Path) -> None:
    """After a reboot the monotonic clock resets, so persisted samples are fenced.

    Without fencing, ``compute_observation_lifecycle`` sees ``now - progress``
    go negative and raises, crashing status. Fencing drops the incomparable
    samples so status reports DEGRADED until fresh progress in the new epoch.
    """

    from yoetz.domain.observation import ObservationLifecycle

    # Boot 1: monotonic 1000, wall 5000 -> epoch 4000.
    boot1 = LocalObservationStore(_state=tmp_path, _monotonic=lambda: 1000.0, _wall=lambda: 5000.0)
    workspace = boot1.workspace_commitment(str(tmp_path.resolve()))
    boot1.grant_consent(workspace)
    session = boot1.session_commitment("sess-epoch")
    boot1.bind_session(workspace, session)
    boot1.ingest(_envelope(session=session))
    assert boot1.status(ObservationStatusQuery(workspace)).lifecycle is ObservationLifecycle.ACTIVE

    # Reboot: monotonic reset to 5, same wall -> epoch 4995, far from 4000.
    rebooted = LocalObservationStore(_state=tmp_path, _monotonic=lambda: 5.0, _wall=lambda: 5000.0)
    # Must not raise on the now-incomparable persisted sample.
    assert (
        rebooted.status(ObservationStatusQuery(workspace)).lifecycle
        is ObservationLifecycle.DEGRADED
    )

    # Same-boot tiny drift stays within tolerance and keeps using the samples.
    same_boot = LocalObservationStore(
        _state=tmp_path, _monotonic=lambda: 1000.5, _wall=lambda: 5000.5
    )
    assert (
        same_boot.status(ObservationStatusQuery(workspace)).lifecycle is ObservationLifecycle.ACTIVE
    )


def test_session_end_reports_stopped_and_persists(tmp_path: Path) -> None:
    from yoetz.domain.observation import ObservationLifecycle

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment("sess-end")
    store.bind_session(workspace, session)
    store.ingest(_envelope(session=session))
    assert store.status(ObservationStatusQuery(workspace)).lifecycle is not (
        ObservationLifecycle.STOPPED
    )

    store.note_session_end(workspace, session)
    assert store.status(ObservationStatusQuery(workspace)).lifecycle is ObservationLifecycle.STOPPED
    # Durable across a fresh store instance.
    reopened = LocalObservationStore(_state=tmp_path)
    assert (
        reopened.status(ObservationStatusQuery(workspace)).lifecycle is ObservationLifecycle.STOPPED
    )


def test_new_session_generation_resumes_and_stale_end_remains_fenced(tmp_path: Path) -> None:
    from yoetz.domain.observation import ObservationLifecycle

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment("sess-generation")
    store.bind_session(workspace, session)
    first = store.begin_session_generation(workspace, session)
    store.note_session_end(workspace, session, generation=first)
    assert store.status(ObservationStatusQuery(workspace)).lifecycle is ObservationLifecycle.STOPPED

    second = store.begin_session_generation(workspace, session)
    assert second == first + 1
    assert store.status(ObservationStatusQuery(workspace)).lifecycle is not (
        ObservationLifecycle.STOPPED
    )
    store.note_session_end(workspace, session, generation=first)
    assert store.status(ObservationStatusQuery(workspace)).lifecycle is not (
        ObservationLifecycle.STOPPED
    )


def test_local_outbox_quarantine_is_visible_and_durable(tmp_path: Path) -> None:
    # Wall clock pinned near the fixture receipt_time (2026-01-01) so the #211
    # quarantine age bound does not see these entries as expired detail.
    store = LocalObservationStore(_state=tmp_path, _wall=lambda: 1767312000.0)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-quar")
    envelope = _envelope(session=session, identity="hook:quar")
    store.ingest(envelope)
    assert store.enqueue_outbox(workspace, "sess-quar", envelope) is None
    assert store.pending_outbox_count(workspace) == 1

    # A permanently-invalid entry is quarantined, not acknowledged as committed.
    moved = store.quarantine_outbox(
        workspace, "sess-quar", envelope.source_identity, ObservationGapCode.CONSENT_REVOKED.value
    )
    assert moved is True
    assert store.pending_outbox_count(workspace) == 0
    assert store.quarantined_count(workspace) == 1
    quarantined = store.list_quarantine(workspace)
    assert quarantined[0][0] == "sess-quar"
    assert quarantined[0][2] == ObservationGapCode.CONSENT_REVOKED.value

    # Visible as a coverage gap and durable across a fresh store instance.
    observed = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.OUTBOX_QUARANTINED.value in observed.gaps
    reopened = LocalObservationStore(_state=tmp_path)
    assert reopened.quarantined_count(workspace) == 1
    assert (
        ObservationGapCode.OUTBOX_QUARANTINED.value
        in reopened.status(ObservationStatusQuery(workspace)).gaps
    )


def test_quarantine_eviction_retains_aggregate_loss_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yoetz.adapters.integrations.observation_local as local_mod

    monkeypatch.setattr(local_mod, "_MAX_QUARANTINE", 2)
    # Wall clock pinned near the fixture receipt_time (2026-01-01) so only the
    # count bound under test — not the #211 age bound — causes evictions.
    store = LocalObservationStore(_state=tmp_path, _wall=lambda: 1767312000.0)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-quarantine-eviction")
    for index in range(3):
        envelope = _envelope(
            session=session,
            identity=f"hook:quarantine:{index}",
            ordinal=index + 1,
        )
        store.ingest(envelope)
        store.enqueue_outbox(workspace, "sess-quarantine-eviction", envelope)
        assert store.quarantine_outbox(
            workspace,
            "sess-quarantine-eviction",
            envelope.source_identity,
            ObservationGapCode.CONSENT_REVOKED.value,
        )
    assert store.quarantined_count(workspace) == 2
    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.QUARANTINE_DETAIL_EVICTED.value in status.gaps
    state_bytes = b"".join(path.read_bytes() for path in tmp_path.rglob("*.json") if path.is_file())
    assert b'"quarantine_evicted_count":1' in state_bytes
    assert b'"quarantine_evicted_commitment":"sha256:' in state_bytes
    assert b'"quarantine_evicted_first":' in state_bytes
    assert b'"quarantine_evicted_last":' in state_bytes


def test_quarantine_detail_expires_by_age_into_aggregate_evidence(tmp_path: Path) -> None:
    """#211: quarantine is bounded by age, not only by count and byte cap.

    Age is measured from the store-authored quarantined_at (never the possibly
    far older envelope receipt_time), and the destructive prune is fenced on a
    trusted clock epoch, so both stores here pin wall AND monotonic clocks to
    keep the persisted epoch comparable across the simulated 15 days.
    """

    quarantine_day = 1767312000.0  # 2026-01-02, one day after the fixture receipt_time
    store = LocalObservationStore(
        _state=tmp_path, _wall=lambda: quarantine_day, _monotonic=lambda: 100.0
    )
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-quarantine-age")
    envelope = _envelope(session=session, identity="hook:quarantine-age")
    store.ingest(envelope)
    store.enqueue_outbox(workspace, "sess-quarantine-age", envelope)
    assert store.quarantine_outbox(
        workspace,
        "sess-quarantine-age",
        envelope.source_identity,
        ObservationGapCode.CONSENT_REVOKED.value,
    )
    store.note_stream_reconcile(workspace, mono=100.0)  # persists the clock epoch
    assert store.quarantine_facts(workspace) == (1, 0, 0)

    day = 86_400.0
    aged = LocalObservationStore(
        _state=tmp_path,
        _wall=lambda: quarantine_day + 15 * day,
        _monotonic=lambda: 100.0 + 15 * day,
    )
    # Any mutation-driven save prunes expired detail; a consent re-grant is the
    # cheapest one that touches no other quarantine machinery.
    aged.grant_consent(workspace, granted_at=Timestamp("2026-01-17T00:00:00.000Z"))
    assert aged.quarantine_facts(workspace) == (0, 1, 0)
    status = aged.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.QUARANTINE_DETAIL_EVICTED.value in status.gaps

    # A wall-clock jump with an unchanged monotonic clock (snapshot restore,
    # NTP correction) must NOT destroy detail: the epoch no longer matches.
    jumped = LocalObservationStore(
        _state=tmp_path,
        _wall=lambda: quarantine_day + 4 * 365 * day,
        _monotonic=lambda: 100.0 + 15 * day,
    )
    second = _envelope(session=session, identity="hook:quarantine-age-2", ordinal=2)
    jumped.ingest(second)
    jumped.enqueue_outbox(workspace, "sess-quarantine-age", second)
    assert jumped.quarantine_outbox(
        workspace,
        "sess-quarantine-age",
        second.source_identity,
        ObservationGapCode.CONSENT_REVOKED.value,
    )
    assert jumped.quarantine_facts(workspace) == (1, 1, 0), (
        "a clock jump must pause the age bound, not trigger it"
    )


def test_reclaim_quarantine_empties_detail_and_records_the_drop(tmp_path: Path) -> None:
    """#211: a recovered install sheds the quarantine tax loudly, not silently."""

    store = LocalObservationStore(_state=tmp_path, _wall=lambda: 1767312000.0)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-reclaim")
    for index in range(3):
        envelope = _envelope(session=session, identity=f"hook:reclaim:{index}", ordinal=index + 1)
        store.ingest(envelope)
        store.enqueue_outbox(workspace, "sess-reclaim", envelope)
        assert store.quarantine_outbox(
            workspace,
            "sess-reclaim",
            envelope.source_identity,
            ObservationGapCode.CONSENT_REVOKED.value,
        )
    assert store.quarantine_facts(workspace) == (3, 0, 0)
    assert store.reclaim_quarantine(workspace) == 3
    # Operator reclaims are counted separately from involuntary evictions so a
    # deliberate cleanup never reads as data loss.
    assert store.quarantine_facts(workspace) == (0, 0, 3)
    assert store.reclaim_quarantine(workspace) == 0
    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.QUARANTINE_DETAIL_EVICTED.value in status.gaps
    state_bytes = b"".join(path.read_bytes() for path in tmp_path.rglob("*.json") if path.is_file())
    assert b'"quarantine_reclaimed_count":3' in state_bytes
    assert b'"quarantine_evicted_count":0' in state_bytes
    assert b'"quarantine_evicted_commitment":"sha256:' in state_bytes


def test_local_outbox_overflow_records_gap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import yoetz.adapters.integrations.observation_local as local_mod

    monkeypatch.setattr(local_mod, "_MAX_OUTBOX", 2)
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "sess-overflow")
    for index in range(3):
        envelope = _envelope(session=session, identity=f"hook:overflow:{index}", ordinal=index + 1)
        store.ingest(envelope)
        overflow = store.enqueue_outbox(workspace, "sess-overflow", envelope)
        if index < 2:
            assert overflow is None
        else:
            assert overflow == ObservationGapCode.OUTBOX_OVERFLOW.value
    observed = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.OUTBOX_OVERFLOW.value in observed.gaps


@pytest.mark.anyio
async def test_sqlite_ingest_after_consent_bind() -> None:
    import apsw

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_obs", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    workspace = f"hmac-sha256:{'11' * 32}"
    session = f"hmac-sha256:{'22' * 32}"
    store.grant_consent(workspace, Timestamp("2026-01-01T00:00:00.000Z"))
    store.bind_session(workspace, session)
    result = await store.ingest(_envelope(session=session))
    assert result.disposition is ObservationIngestDisposition.ACCEPTED
    duplicate = await store.ingest(_envelope(session=session))
    assert duplicate.disposition is ObservationIngestDisposition.DUPLICATE


@pytest.mark.anyio
async def test_coordinator_rejects_without_mapping(tmp_path: Path) -> None:
    class _NoRuntime:
        async def route(self, command: object) -> object:
            raise AssertionError("route must not be called without mapping")

        async def release(self, runtime: object) -> None:
            return None

    class _Clock:
        def now_utc(self) -> Timestamp:
            return Timestamp("2026-01-01T00:00:00.000Z")

    class _Ids:
        def new(self, kind: IdKind) -> str:
            return PREFIX_BY_KIND[kind] + str(uuid.uuid4())

    local = LocalObservationStore(_state=tmp_path)
    workspace = local.workspace_commitment(str(tmp_path.resolve()))
    local.grant_consent(workspace)
    session = local.bind_codex_session(workspace, "unmapped-sess")
    coordinator = ObservationCoordinator(
        runtime=_NoRuntime(),  # type: ignore[arg-type]
        local=local,
        clock=_Clock(),  # type: ignore[arg-type]
        ids=_Ids(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: None,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )
    result = await coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id="unmapped-sess",
            envelope=_envelope(session=session),
        )
    )
    assert result.disposition is ObservationIngestDisposition.REJECTED
    assert result.reason == ObservationGapCode.MAPPING_MISSING.value


@pytest.mark.anyio
@pytest.mark.parametrize(
    "code",
    [
        code
        for code in PublicErrorCode
        if code not in {PublicErrorCode.STORAGE_CORRUPT, PublicErrorCode.SESSION_CONFLICT}
    ],
)
async def test_nonretryable_public_ingest_errors_are_terminal(
    tmp_path: Path, code: PublicErrorCode
) -> None:
    """#540: the error contract, not its spelling, decides retryability."""

    class _RejectedRuntime:
        async def route(self, command: object) -> object:
            del command
            raise PublicOperationError(code, "Observation ingest was rejected.", False)

        async def release(self, runtime: object) -> None:
            raise AssertionError(f"unrouted runtime released: {runtime!r}")

    local, _workspace, session, mapping = _mapped_local(tmp_path, f"terminal-{code.value}")
    coordinator = ObservationCoordinator(
        runtime=_RejectedRuntime(),  # type: ignore[arg-type]
        local=local,
        clock=object(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )

    result = await coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id=mapping.codex_session_id,
            envelope=_envelope(session=session),
        )
    )

    assert result.reason == ObservationGapCode.LEDGER_REJECTED.value
    assert route_observation_ingest(result).action is ObservationDrainAction.QUARANTINE


@pytest.mark.anyio
async def test_nonretryable_route_session_conflict_is_mapping_missing(
    tmp_path: Path,
) -> None:
    """A route conflict keeps the row recoverable while the lifecycle mapping is repaired."""

    class _RejectedRuntime:
        async def route(self, command: object) -> object:
            del command
            raise PublicOperationError(
                PublicErrorCode.SESSION_CONFLICT,
                "Observation route is already bound.",
                retryable=False,
            )

        async def release(self, runtime: object) -> None:
            raise AssertionError(f"unrouted runtime released: {runtime!r}")

    local, _workspace, session, mapping = _mapped_local(tmp_path, "route-conflict-952")
    coordinator = ObservationCoordinator(
        runtime=_RejectedRuntime(),  # type: ignore[arg-type]
        local=local,
        clock=object(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )

    result = await coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id=mapping.codex_session_id,
            envelope=_envelope(session=session),
        )
    )

    assert result.disposition is ObservationIngestDisposition.REJECTED
    assert result.reason == ObservationGapCode.MAPPING_MISSING.value
    assert route_observation_ingest(result).action is ObservationDrainAction.RETRY


@pytest.mark.anyio
async def test_route_session_conflict_retries_after_mapping_repair_and_delivers_once(
    tmp_path: Path,
) -> None:
    """A repaired lifecycle mapping drains the same queued observation exactly once."""

    cell = _reattach_fixture(tmp_path, "route-recovery-952")
    envelope = _envelope(
        session=cell.session,
        kind="PostToolUse",
        identity="hook:route-recovery-952",
        exit_status=1,
    )
    cell.local.enqueue_outbox(cell.workspace, cell.codex_id, envelope)
    route_available = False
    inner_route = cell.runtime_port.route

    async def route(command: object) -> TaskRuntime:
        if not route_available:
            raise PublicOperationError(
                PublicErrorCode.SESSION_CONFLICT,
                "Observation route is inactive.",
                retryable=False,
            )
        return await inner_route(command)

    cell.runtime_port.route = route  # type: ignore[method-assign]
    sweeper = ObservationOutboxSweeper(cell.local, cell.coordinator, budget_seconds=None)
    try:
        first = await sweeper.sweep()
        assert first.retry_pending == 1
        assert first.quarantined == 0
        assert cell.local.pending_outbox_count(cell.workspace) == 1

        # A host reattach persists a successor lifecycle mapping before the next drain pass.
        cell.reattach()
        route_available = True
        second = await sweeper.sweep()
    finally:
        sweeper.close()
        cell.coordinator.close()

    assert second.acknowledged == 1
    assert second.quarantined == 0
    assert cell.local.pending_outbox_count(cell.workspace) == 0
    assert cell.operation_count() == 1


@pytest.mark.anyio
async def test_nonretryable_post_route_session_conflict_is_ledger_rejected(
    tmp_path: Path,
) -> None:
    """A conflict after route acquisition remains terminal and is quarantined."""

    from types import SimpleNamespace

    local, _workspace, session, mapping = _mapped_local(tmp_path, "store-conflict-952")

    class _Store:
        def grant_consent(self, *args: object, **kwargs: object) -> None:
            del args, kwargs
            raise PublicOperationError(
                PublicErrorCode.SESSION_CONFLICT,
                "Observation session is already bound.",
                retryable=False,
            )

    runtime = SimpleNamespace(
        task_id=mapping.yoetz_task_id,
        session_id=mapping.yoetz_session_id,
        writer_id=observation_writer_id(mapping.yoetz_task_id, mapping.yoetz_session_id),
        observation=_Store(),
    )

    class _RuntimePort:
        async def route(self, command: object) -> object:
            del command
            return runtime

        async def release(self, released: object) -> None:
            assert released is runtime

    result = await ObservationCoordinator(
        runtime=_RuntimePort(),  # type: ignore[arg-type]
        local=local,
        clock=object(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    ).ingest_request(
        ObservationIngestRequest(
            codex_session_id=mapping.codex_session_id,
            envelope=_envelope(session=session),
        )
    )

    assert result.reason == ObservationGapCode.LEDGER_REJECTED.value
    assert route_observation_ingest(result).action is ObservationDrainAction.QUARANTINE


@pytest.mark.anyio
@pytest.mark.parametrize(
    "code", [PublicErrorCode.SESSION_NOT_FOUND, PublicErrorCode.SESSION_CONFLICT]
)
async def test_retryable_session_route_errors_stay_pending_as_service_unavailable(
    tmp_path: Path, code: PublicErrorCode
) -> None:
    """#554: no ingest authority raises these codes retryable, and the removed
    per-code branches must not come back by accident. A retryable answer, should
    one ever appear, is transient coordination that keeps the row pending under
    the generic retryable class; it is never `mapping_missing`, which would
    retire the lane and terminalize an ended session."""

    class _RetryableRuntime:
        async def route(self, command: object) -> object:
            del command
            raise PublicOperationError(code, "Observation route is busy.", True)

        async def release(self, runtime: object) -> None:
            raise AssertionError(f"unrouted runtime released: {runtime!r}")

    local, _workspace, session, mapping = _mapped_local(tmp_path, f"retryable-{code.value}")
    coordinator = ObservationCoordinator(
        runtime=_RetryableRuntime(),  # type: ignore[arg-type]
        local=local,
        clock=object(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )

    result = await coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id=mapping.codex_session_id,
            envelope=_envelope(session=session),
        )
    )

    assert result.disposition is ObservationIngestDisposition.REJECTED
    assert result.reason == ObservationGapCode.SERVICE_UNAVAILABLE.value
    assert result.reason != ObservationGapCode.MAPPING_MISSING.value
    assert route_observation_ingest(result).action is ObservationDrainAction.RETRY


@pytest.mark.anyio
async def test_ledger_event_invalid_is_terminal_not_service_unavailable(tmp_path: Path) -> None:
    """#540: a ledger validation refusal quarantines its envelope immediately."""

    from types import SimpleNamespace

    local, _workspace, session, mapping = _mapped_local(tmp_path, "ledger-event-invalid")

    class _Store:
        def load_capture_ticket(self, *, workspace: str, logical_identity: str) -> None:
            # This structural-only fixture has no staged native capture to recover.
            del workspace, logical_identity
            return None

        def grant_consent(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def bind_session(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        async def ingest(self, envelope: ObservationEnvelope) -> ObservationIngestResult:
            return ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED,
                None,
                envelope.cursor,
            )

    runtime = SimpleNamespace(
        task_id=mapping.yoetz_task_id,
        session_id=mapping.yoetz_session_id,
        writer_id=observation_writer_id(mapping.yoetz_task_id, mapping.yoetz_session_id),
        observation=_Store(),
    )

    class _RuntimePort:
        async def route(self, command: object) -> object:
            del command
            return runtime

        async def release(self, released: object) -> None:
            assert released is runtime

    class _Coordinator(ObservationCoordinator):
        async def _capture_content(  # type: ignore[override]
            self, runtime: object, store: object, **kwargs: object
        ) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...], bool, bool]:
            del runtime, store, kwargs
            return (), (), False, False

        async def _append_materialized(  # type: ignore[override]
            self, *args: object, **kwargs: object
        ) -> tuple[str, str, None, str, tuple[str, ...]]:
            del args, kwargs
            raise PublicOperationError(
                PublicErrorCode.EVENT_INVALID,
                "Observation event was rejected.",
                retryable=False,
            )

    coordinator = _Coordinator(
        runtime=_RuntimePort(),  # type: ignore[arg-type]
        local=local,
        clock=object(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )

    result = await coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id=mapping.codex_session_id,
            envelope=_envelope(
                session=session,
                kind="PostToolUse",
                identity="hook:event-invalid",
                exit_status=1,
            ),
        )
    )

    assert result.reason == ObservationGapCode.LEDGER_REJECTED.value
    assert result.reason != ObservationGapCode.SERVICE_UNAVAILABLE.value
    assert route_observation_ingest(result).action is ObservationDrainAction.QUARANTINE


@pytest.mark.anyio
async def test_storage_corrupt_blocks_session_for_coordinator_generation(tmp_path: Path) -> None:
    class _CorruptRuntime:
        def __init__(self) -> None:
            self.calls = 0

        async def route(self, command: object) -> object:
            del command
            self.calls += 1
            raise PublicOperationError(
                PublicErrorCode.STORAGE_CORRUPT,
                "The task ledger is unreadable.",
                False,
            )

        async def release(self, runtime: object) -> None:
            raise AssertionError(f"unrouted runtime released: {runtime!r}")

    local = LocalObservationStore(_state=tmp_path)
    workspace = local.workspace_commitment(str(tmp_path.resolve()))
    local.grant_consent(workspace)
    codex_id = "storage-corrupt-session"
    session = local.bind_codex_session(workspace, codex_id)
    mapping = LifecycleMapping(
        mapping_version=1,
        codex_session_id=codex_id,
        yoetz_task_id=_task_id(),
        yoetz_session_id=PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4()),
        yoetz_writer_id=PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4()),
        last_frontier=None,
    )
    runtime = _CorruptRuntime()

    def build_coordinator() -> ObservationCoordinator:
        return ObservationCoordinator(
            runtime=runtime,  # type: ignore[arg-type]
            local=local,
            clock=object(),  # type: ignore[arg-type]
            ids=object(),  # type: ignore[arg-type]
            state_root=tmp_path,
            mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
        )

    request = ObservationIngestRequest(
        codex_session_id=codex_id, envelope=_envelope(session=session)
    )
    coordinator = build_coordinator()
    first = await coordinator.ingest_request(request)
    second = await coordinator.ingest_request(request)

    assert first.disposition is ObservationIngestDisposition.REJECTED
    assert first.reason == ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value
    assert second == first
    assert runtime.calls == 1

    future = replace(request.envelope, source_identity="hook:future")
    local.enqueue_outbox(workspace, codex_id, future)
    sweep = await ObservationOutboxSweeper(local, coordinator).sweep()
    assert sweep.quarantined == 1
    assert local.pending_outbox_count(workspace) == 0
    assert runtime.calls == 1

    restarted = await build_coordinator().ingest_request(request)
    assert restarted.reason == ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value
    assert runtime.calls == 2


@pytest.mark.anyio
async def test_coordinator_rejects_disabled_stream_before_mapping_or_runtime(
    tmp_path: Path,
) -> None:
    class _NoRuntime:
        async def route(self, command: object) -> object:
            raise AssertionError("disabled observation must not route")

        async def release(self, runtime: object) -> None:
            return None

    local = LocalObservationStore(_state=tmp_path)
    workspace = local.workspace_commitment(str(tmp_path.resolve()))
    local.grant_consent(workspace)
    session = local.bind_codex_session(workspace, "disabled-sess")

    def mapping_loader(
        codex_session_id: str, *, _state: Path | None = None
    ) -> LifecycleMapping | None:
        del codex_session_id, _state
        raise AssertionError("disabled observation must not load mapping")

    coordinator = ObservationCoordinator(
        runtime=_NoRuntime(),  # type: ignore[arg-type]
        local=local,
        clock=object(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=mapping_loader,
        observation_enabled=False,
    )
    result = await coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id="disabled-sess",
            envelope=replace(
                _envelope(session=session), source=ObservationSource.CODEX_SESSION_STREAM
            ),
        )
    )
    assert result.disposition is ObservationIngestDisposition.REJECTED
    assert result.reason == "observation_disabled"


@pytest.mark.anyio
async def test_capture_handoff_recovery_rotates_past_unavailable_routes() -> None:
    """A permanently unavailable prefix cannot starve the ninth route."""

    task_ids = tuple(f"task-{index}" for index in range(9))

    class _Local:
        def capture_handoff_candidates(self, workspace: str) -> tuple[str, ...]:
            del workspace
            return task_ids

    calls: list[tuple[str, ...]] = []

    async def reconcile(
        workspace: str,
        candidates: tuple[str, ...],
        visit: object,
    ) -> bool:
        del workspace, visit
        calls.append(candidates)
        # Model a route opener that cannot reach any named task this turn.
        return False

    coordinator = ObservationCoordinator(
        runtime=object(),  # type: ignore[arg-type]
        local=cast(LocalObservationStore, _Local()),
        clock=object(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        capture_handoff_reconcile=reconcile,
    )
    try:
        first = await coordinator._reconcile_capture_handoffs(  # pyright: ignore[reportPrivateUsage]
            "workspace"
        )
        second = await coordinator._reconcile_capture_handoffs(  # pyright: ignore[reportPrivateUsage]
            "workspace"
        )
    finally:
        coordinator.close()

    assert first is ObservationCaptureRecoveryOutcome.HANDOFF_UNAVAILABLE
    assert second is ObservationCaptureRecoveryOutcome.HANDOFF_UNAVAILABLE
    assert calls == [task_ids[:8], (task_ids[8], *task_ids[:7])]


def _obs(
    *, source: ObservationSource, identity: str, corr: str | None, session: str, kind: str
) -> ObservationEnvelope:
    structural: dict[str, object] = {"tool_name": "shell"}
    if corr is not None:
        structural["tool_call_id"] = corr
        structural["correlation_id"] = corr
    return ObservationEnvelope(
        session_commitment=session,
        event_kind=kind,
        source_identity=identity,
        source=source,
        cursor=ObservationCursor(1, 0, 1, f"hmac-sha256:{'ab' * 32}", "codex-obs-hook/1.1.0"),
        receipt_time=Timestamp("2026-01-01T00:00:00.000Z"),
        structural_payload=JsonObject(structural),
        content_object_refs=(),
        gap_codes=(),
    )


def test_hook_and_stream_copies_share_one_logical_operation() -> None:
    from yoetz.application.observation_materialize import (
        canonical_logical_identity,
        observation_operation_digest,
    )

    session = f"hmac-sha256:{'66' * 32}"
    hook = _obs(
        source=ObservationSource.CODEX_HOOK,
        identity="hook:post:call-1",
        corr="call-1",
        session=session,
        kind="PostToolUse",
    )
    stream = _obs(
        source=ObservationSource.CODEX_SESSION_STREAM,
        identity="stream:item.completed:call-1",
        corr="call-1",
        session=session,
        kind="item.completed",
    )
    # Same host call id + tool family -> one logical identity across sources.
    assert canonical_logical_identity(hook) == canonical_logical_identity(stream)

    def _digest(env: ObservationEnvelope) -> str:
        return observation_operation_digest(
            task_id="task_x",
            logical_identity=canonical_logical_identity(env),
            draft_roles=("action", "result"),
        )

    assert _digest(hook) == _digest(stream)

    # A different host call id stays distinct.
    other = _obs(
        source=ObservationSource.CODEX_HOOK,
        identity="hook:post:call-2",
        corr="call-2",
        session=session,
        kind="PostToolUse",
    )
    assert canonical_logical_identity(other) != canonical_logical_identity(hook)

    # No host call id -> source-specific opaque identity (hook != stream).
    opaque_hook = _obs(
        source=ObservationSource.CODEX_HOOK,
        identity="hook:session-start",
        corr=None,
        session=session,
        kind="SessionStart",
    )
    opaque_stream = _obs(
        source=ObservationSource.CODEX_SESSION_STREAM,
        identity="stream:session-start",
        corr=None,
        session=session,
        kind="SessionStart",
    )
    assert canonical_logical_identity(opaque_hook) != canonical_logical_identity(opaque_stream)


def test_reused_call_id_isolated_by_source_session_and_generation() -> None:
    """A host call id is meaningful only inside its source generation lane."""

    from yoetz.application.observation_materialize import materialize_observation_envelope
    from yoetz.domain.events import ActionRecordedPayload, ResultRecordedPayload

    task = "task_identity_scope"
    base = _envelope(
        session=f"hmac-sha256:{'71' * 32}",
        kind="PostToolUse",
        identity="hook:post:reused",
        corr="reused-call",
        exit_status=0,
        generation=1,
    )
    same_codex_stream = replace(
        base,
        source=ObservationSource.CODEX_SESSION_STREAM,
        event_kind="item.completed",
        source_identity="stream:post:reused",
    )
    next_generation = replace(
        base,
        cursor=replace(base.cursor, source_generation=2),
        source_identity="hook:post:reused-generation-2",
    )
    different_session = replace(
        base,
        session_commitment=f"hmac-sha256:{'72' * 32}",
        source_identity="hook:post:reused-session-2",
    )
    different_host = replace(
        base,
        source=ObservationSource.CLAUDE_HOOK,
        session_commitment=f"hmac-sha256:{'71' * 32}",
        source_identity="claude:post:reused",
    )

    assert canonical_logical_identity(base) == canonical_logical_identity(same_codex_stream)
    assert (
        len(
            {
                canonical_logical_identity(item)
                for item in (base, next_generation, different_session, different_host)
            }
        )
        == 4
    )
    batches = [
        materialize_observation_envelope(item, task_id=task)
        for item in (base, next_generation, different_session, different_host)
    ]
    action_ids = {
        cast(ActionRecordedPayload, item.draft.payload).action_id
        for batch in batches
        for item in batch.drafts
        if item.draft.schema.name == "action_recorded"
    }
    result_ids = {
        cast(ResultRecordedPayload, item.draft.payload).result_id
        for batch in batches
        for item in batch.drafts
        if item.draft.schema.name == "result_recorded"
    }
    assert len(action_ids) == 4
    assert len(result_ids) == 4


@pytest.mark.anyio
async def test_run_advice_persists_snapshot_with_real_datetime_clock(tmp_path: Path) -> None:
    """Regression: production clocks return ``datetime``, not ``Timestamp``.

    ``_run_advice`` must persist the advice snapshot through the durable
    observation store, which requires a ``Timestamp``. A raw ``datetime`` would
    ``AttributeError`` on ``updated_at.wire`` and get swallowed by the ingest
    guard, silently dropping advice. This exercises the real datetime path.
    """

    from datetime import UTC, datetime

    import apsw

    from yoetz.adapters.sqlite.migrations import initialize_bundle

    class _DatetimeClock:
        def now_utc(self) -> datetime:
            # Mirror the production ``_SystemClock``: a real ``datetime`` truncated
            # to millisecond precision (never a ``Timestamp``).
            now = datetime.now(UTC)
            return now.replace(microsecond=(now.microsecond // 1_000) * 1_000)

    class _UnusedRuntime:
        async def route(self, command: object) -> object:
            raise AssertionError("route must not be called in this unit path")

        async def release(self, runtime: object) -> None:
            return None

    class _Ids:
        def new(self, kind: IdKind) -> str:
            return PREFIX_BY_KIND[kind] + str(uuid.uuid4())

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "task_advice", "owner_generation": "1"})
    store = SqliteObservationStore(db)
    workspace = f"hmac-sha256:{'44' * 32}"
    session = f"hmac-sha256:{'55' * 32}"
    store.grant_consent(workspace, Timestamp("2026-01-01T00:00:00.000Z"))
    store.bind_session(workspace, session)
    ingested = await store.ingest(
        _envelope(session=session, kind="PostToolUse", identity="hook:fail", exit_status=2)
    )
    assert ingested.disposition is ObservationIngestDisposition.ACCEPTED
    assert store.load_advice_snapshot(workspace) is None

    local = LocalObservationStore(_state=tmp_path)
    coordinator = ObservationCoordinator(
        runtime=_UnusedRuntime(),  # type: ignore[arg-type]
        local=local,
        clock=_DatetimeClock(),  # type: ignore[arg-type]
        ids=_Ids(),  # type: ignore[arg-type]
        state_root=tmp_path,
    )

    await coordinator._run_advice(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        workspace, "task_advice", store
    )

    persisted = store.load_advice_snapshot(workspace)
    assert persisted is not None
    assert persisted.ranked_finding_ids


@pytest.mark.anyio
async def test_advice_finding_materialization_uses_canonical_schema_and_envelope_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Advice detail may retain mixed coverage; its append envelope may not.

    The ledger validates the publication-channel coverage on every append entry.
    This regression also locks the canonical underscore spelling of the event
    schema so a post-ingest advice failure cannot strand an otherwise durable
    observation in the local outbox.
    """

    from datetime import UTC, datetime
    from types import SimpleNamespace

    from yoetz.application import observation_coordinator as coordinator_module
    from yoetz.application.unit_of_work import PreparedMutation
    from yoetz.domain.observation import AdviceItem, AdviceSnapshot
    from yoetz.ports.ledger import ProjectionView
    from yoetz.ports.objects import ObjectRef
    from yoetz.protocol.coverage import PublicationChannel, coverage_for_channel, weakest

    task_id = PREFIX_BY_KIND[IdKind.TASK] + str(uuid.uuid4())
    session_id = PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4())
    writer_id = PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4())
    item_coverage = weakest(
        coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
        coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
    )
    item = AdviceItem(
        finding_id=finding_id(PREFIX_BY_KIND[IdKind.FINDING] + str(uuid.uuid4())),
        rule_code="failed_command_unresolved",
        priority=10,
        summary="A failed command remains unresolved.",
        detail="Resolve the failed command and rerun the check.",
        recommended_next_action="rerun_check",
        evidence_refs=("hook:advice-materialization",),
        coverage=item_coverage,
        freshness_frontier="frontier-1",
    )
    snapshot = AdviceSnapshot(
        ranked_finding_ids=(item.finding_id,),
        evidence_basis_digest="sha256:" + "a" * 64,
        confidence_coverage=item_coverage,
        recommended_next_action="rerun_check",
        freshness_frontier="frontier-1",
        suppression_identity="advice-materialization-1",
        ranked_items=(item,),
    )

    ledger_events: list[SimpleNamespace] = []

    def _remember_envelope_events(source: ObservationEnvelope) -> None:
        batch = materialize_observation_envelope(source, task_id=task_id)
        for draft in batch.drafts:
            ledger_events.append(
                SimpleNamespace(event_id=draft.draft.event_id, schema=draft.draft.schema)
            )

    class _Ledger:
        async def load_projection(self, loaded_session_id: str, view: ProjectionView):
            assert loaded_session_id == session_id
            assert view in {ProjectionView.COMPACT, ProjectionView.CANDIDATE_FINDINGS}
            return None

        async def _events(self):
            for record in ledger_events:
                yield record

        def load_events(self, loaded_session_id: str):
            assert loaded_session_id == session_id
            return self._events()

        async def lookup_operation(self, loaded_writer_id: str, operation_id: str):
            assert loaded_writer_id == writer_id
            assert operation_id.startswith(PREFIX_BY_KIND[IdKind.REQUEST])
            return None

        async def lookup_task_operation(self, loaded_writer_id: str, operation_id: str):
            return await self.lookup_operation(loaded_writer_id, operation_id)

    class _Objects:
        async def stage(self, source: object, metadata: object):
            return source, metadata

        async def finalize(self, staged: tuple[object, object]) -> ObjectRef:
            source, metadata = staged
            data = source.data  # type: ignore[attr-defined]
            assert isinstance(data, bytes)
            return ObjectRef(
                PREFIX_BY_KIND[IdKind.OBJECT] + str(uuid.uuid4()),
                len(data),
                "hmac-sha256:" + "b" * 64,
                "sha256:" + "c" * 64,
                "yoetz-object/1",
                "test-key-1",
                metadata,  # type: ignore[arg-type]
            )

    captured: list[PreparedMutation] = []

    async def _capture_append(ledger: object, prepared: PreparedMutation):
        assert ledger is runtime.ledger
        captured.append(prepared)
        return None

    monkeypatch.setattr(coordinator_module, "run_prepared_append", _capture_append)
    materialize_calls: list[str] = []
    real_materialize = coordinator_module.materialize_observation_envelope

    def _count_materialize(envelope: ObservationEnvelope, *, task_id: str):
        materialize_calls.append(envelope.source_identity)
        return real_materialize(envelope, task_id=task_id)

    monkeypatch.setattr(coordinator_module, "materialize_observation_envelope", _count_materialize)

    class _Clock:
        def now_utc(self) -> datetime:
            return datetime(2026, 1, 1, tzinfo=UTC)

    class _Ids:
        def new(self, kind: IdKind) -> str:
            return PREFIX_BY_KIND[kind] + str(uuid.uuid4())

    class _UnusedRuntimePort:
        async def route(self, command: object) -> object:
            raise AssertionError("route must not be called")

        async def release(self, runtime: object) -> None:
            return None

    runtime = SimpleNamespace(
        task_id=task_id,
        session_id=session_id,
        writer_id=writer_id,
        ledger=_Ledger(),
        objects=_Objects(),
    )
    coordinator = ObservationCoordinator(
        runtime=_UnusedRuntimePort(),  # type: ignore[arg-type]
        local=LocalObservationStore(_state=tmp_path),
        clock=_Clock(),  # type: ignore[arg-type]
        ids=_Ids(),  # type: ignore[arg-type]
        state_root=tmp_path,
    )
    envelope = _envelope(
        session=f"hmac-sha256:{'d' * 64}",
        kind="PostToolUse",
        identity="hook:advice-materialization",
        exit_status=2,
    )
    _remember_envelope_events(envelope)

    await coordinator._materialize_advice_findings(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        cast(TaskRuntime, runtime),
        (envelope,),
        snapshot,  # type: ignore[arg-type]
    )

    assert len(captured) == 1
    entries = captured[0].command.entries
    assert len(entries) == 1
    assert entries[0].draft.schema.name == "finding_recorded"
    assert entries[0].draft.payload.coverage == item_coverage  # type: ignore[union-attr]
    assert entries[0].publication_channel is PublicationChannel.ENGINE_DERIVED
    assert entries[0].coverage == coverage_for_channel(PublicationChannel.ENGINE_DERIVED)

    revised_item = replace(item, evidence_refs=("hook:advice-revision",))
    revised_snapshot = replace(
        snapshot,
        ranked_items=(revised_item,),
        evidence_basis_digest="sha256:" + "d" * 64,
        suppression_identity="advice-materialization-2",
    )
    revision_envelope = _envelope(
        session=f"hmac-sha256:{'d' * 64}",
        kind="PostToolUse",
        identity="hook:advice-revision",
        ordinal=2,
        corr="c2",
        exit_status=2,
    )
    _remember_envelope_events(revision_envelope)
    await coordinator._materialize_advice_findings(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        cast(TaskRuntime, runtime),
        (envelope, revision_envelope),
        revised_snapshot,  # type: ignore[arg-type]
    )
    assert len(captured) == 2
    assert captured[0].command.entries[0].draft.event_id != (
        captured[1].command.entries[0].draft.event_id
    )
    assert materialize_calls == ["hook:advice-materialization", "hook:advice-revision"]
    first_payload = captured[0].command.entries[0].draft.payload
    assert type(first_payload) is Finding
    assert first_payload.subject_refs
    assert {str(ref) for ref in first_payload.subject_refs} <= {
        str(record.event_id) for record in ledger_events
    }


@pytest.mark.anyio
async def test_advice_finding_subject_refs_never_cite_unappended_drafts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Computed materialization IDs that never entered the ledger must not become citations."""

    from datetime import UTC, datetime
    from types import SimpleNamespace

    from yoetz.application import observation_coordinator as coordinator_module
    from yoetz.application.unit_of_work import PreparedMutation
    from yoetz.domain.observation import AdviceItem, AdviceSnapshot
    from yoetz.ports.ledger import ProjectionView
    from yoetz.ports.objects import ObjectRef
    from yoetz.protocol.coverage import PublicationChannel, coverage_for_channel

    task_id = PREFIX_BY_KIND[IdKind.TASK] + str(uuid.uuid4())
    session_id = PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4())
    writer_id = PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4())
    lifecycle = PREFIX_BY_KIND[IdKind.EVENT] + "00000000-0000-4000-8000-000000000001"
    item_coverage = coverage_for_channel(PublicationChannel.HOOK_OBSERVED)
    item = AdviceItem(
        finding_id=finding_id(PREFIX_BY_KIND[IdKind.FINDING] + str(uuid.uuid4())),
        rule_code="failed_command_unresolved",
        priority=10,
        summary="A failed command remains unresolved.",
        detail="Resolve the failed command and rerun the check.",
        recommended_next_action="rerun_check",
        evidence_refs=("hook:unappended-draft",),
        coverage=item_coverage,
        freshness_frontier="frontier-1",
    )
    snapshot = AdviceSnapshot(
        ranked_finding_ids=(item.finding_id,),
        evidence_basis_digest="sha256:" + "a" * 64,
        confidence_coverage=item_coverage,
        recommended_next_action="rerun_check",
        freshness_frontier="frontier-1",
        suppression_identity="advice-unappended-1",
        ranked_items=(item,),
    )

    class _Ledger:
        async def load_projection(self, loaded_session_id: str, view: ProjectionView):
            del loaded_session_id, view
            return None

        async def _events(self):
            yield SimpleNamespace(
                event_id=lifecycle,
                schema=SimpleNamespace(name="session_opened"),
            )

        def load_events(self, loaded_session_id: str):
            del loaded_session_id
            return self._events()

        async def lookup_operation(self, loaded_writer_id: str, operation_id: str):
            del loaded_writer_id, operation_id
            return None

        async def lookup_task_operation(self, loaded_writer_id: str, operation_id: str):
            return await self.lookup_operation(loaded_writer_id, operation_id)

    class _Objects:
        async def stage(self, source: object, metadata: object):
            return source, metadata

        async def finalize(self, staged: tuple[object, object]) -> ObjectRef:
            source, metadata = staged
            data = source.data  # type: ignore[attr-defined]
            assert isinstance(data, bytes)
            return ObjectRef(
                PREFIX_BY_KIND[IdKind.OBJECT] + str(uuid.uuid4()),
                len(data),
                "hmac-sha256:" + "b" * 64,
                "sha256:" + "c" * 64,
                "yoetz-object/1",
                "test-key-1",
                metadata,  # type: ignore[arg-type]
            )

    captured: list[PreparedMutation] = []

    async def _capture_append(ledger: object, prepared: PreparedMutation):
        del ledger
        captured.append(prepared)
        return None

    monkeypatch.setattr(coordinator_module, "run_prepared_append", _capture_append)

    class _Clock:
        def now_utc(self) -> datetime:
            return datetime(2026, 1, 1, tzinfo=UTC)

    class _Ids:
        def new(self, kind: IdKind) -> str:
            return PREFIX_BY_KIND[kind] + str(uuid.uuid4())

    class _UnusedRuntimePort:
        async def route(self, command: object) -> object:
            raise AssertionError("route must not be called")

        async def release(self, runtime: object) -> None:
            return None

    runtime = SimpleNamespace(
        task_id=task_id,
        session_id=session_id,
        writer_id=writer_id,
        ledger=_Ledger(),
        objects=_Objects(),
    )
    coordinator = ObservationCoordinator(
        runtime=_UnusedRuntimePort(),  # type: ignore[arg-type]
        local=LocalObservationStore(_state=tmp_path),
        clock=_Clock(),  # type: ignore[arg-type]
        ids=_Ids(),  # type: ignore[arg-type]
        state_root=tmp_path,
    )
    envelope = _envelope(
        session=f"hmac-sha256:{'d' * 64}",
        kind="PostToolUse",
        identity="hook:unappended-draft",
        exit_status=2,
    )
    computed = {
        str(draft.draft.event_id)
        for draft in materialize_observation_envelope(envelope, task_id=task_id).drafts
    }
    assert computed
    await coordinator._materialize_advice_findings(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        cast(TaskRuntime, runtime),
        (envelope,),
        snapshot,  # type: ignore[arg-type]
    )

    assert len(captured) == 1
    payload = captured[0].command.entries[0].draft.payload
    assert type(payload) is Finding
    assert tuple(str(ref) for ref in payload.subject_refs) == (lifecycle,)
    assert computed.isdisjoint(str(ref) for ref in payload.subject_refs)


@pytest.mark.anyio
async def test_deferred_verification_uses_a_dedicated_runtime_lease(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from yoetz.application.observation_verification import ObservationVerificationSupervisor

    task_id = PREFIX_BY_KIND[IdKind.TASK] + str(uuid.uuid4())
    session_id = PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4())
    writer_id = observation_writer_id(task_id, session_id)
    current_worker = object()
    deferred_worker = object()
    deferred_store = object()
    current_runtime = SimpleNamespace(
        task_id=task_id,
        session_id=session_id,
        writer_id=writer_id,
    )
    deferred_runtime = SimpleNamespace(
        task_id=task_id,
        session_id=session_id,
        writer_id=writer_id,
        observation=deferred_store,
    )
    routed: list[object] = []
    released: list[object] = []
    advised: list[tuple[object, object]] = []

    class _RuntimePort:
        async def route(self, command: object) -> object:
            routed.append(command)
            return deferred_runtime

        async def release(self, runtime: object) -> None:
            released.append(runtime)

    class _Coordinator(ObservationCoordinator):
        async def _prepare_verification_worker(self, *args: object, **kwargs: object):  # type: ignore[override]  # noqa: SLF001
            del args, kwargs
            return current_worker

        async def _rebuild_verification_worker(self, *args: object, **kwargs: object):  # type: ignore[override]  # noqa: SLF001
            del kwargs
            assert args[0] is deferred_runtime
            assert args[2] is deferred_store
            return deferred_worker

        async def _run_advice(
            self, workspace: str, runtime: object, store: object, **kwargs: object
        ):  # type: ignore[override]  # noqa: SLF001
            del workspace, kwargs
            advised.append((runtime, store))

    supervisor = ObservationVerificationSupervisor(service_generation=1)
    coordinator = _Coordinator(
        runtime=_RuntimePort(),  # type: ignore[arg-type]
        local=LocalObservationStore(_state=tmp_path),
        clock=object(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        verification_supervisor=supervisor,
    )
    envelope = _envelope(session=f"hmac-sha256:{'9' * 64}")
    await coordinator._enqueue_verification(  # pyright: ignore[reportPrivateUsage]
        cast(TaskRuntime, current_runtime),
        "hmac-sha256:" + "8" * 64,
        cast(object, object()),  # type: ignore[arg-type]
        envelope,
    )

    handle = next(iter(supervisor._handles.values()))  # pyright: ignore[reportPrivateUsage]
    assert routed
    assert handle.worker is deferred_worker
    assert handle.worker is not current_worker
    assert handle.after_complete is not None
    await handle.after_complete()
    assert advised == [(deferred_runtime, deferred_store)]
    assert handle.on_idle is not None
    await handle.on_idle()
    assert released == [deferred_runtime]


@pytest.mark.anyio
async def test_rediscovery_drains_pending_repositories_for_every_bound_session(
    tmp_path: Path,
) -> None:
    from types import SimpleNamespace

    from yoetz.application.observation_verification import ObservationVerificationSupervisor

    workspace = "hmac-sha256:" + "7" * 64
    task_ids = (_task_id(), _task_id())
    session_ids = (
        PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4()),
        PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4()),
    )
    codex_ids = ("codex-rediscover-a", "codex-rediscover-b")
    local = LocalObservationStore(_state=tmp_path)
    local.grant_consent(workspace)
    for codex_id in codex_ids:
        local.bind_codex_session(workspace, codex_id)

    mappings = {
        codex_id: LifecycleMapping(
            mapping_version=1,
            codex_session_id=codex_id,
            yoetz_task_id=task_id,
            yoetz_session_id=session_id,
            yoetz_writer_id=PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4()),
            last_frontier=None,
        )
        for codex_id, task_id, session_id in zip(codex_ids, task_ids, session_ids, strict=True)
    }

    class _Repository:
        def __init__(self) -> None:
            self.pending = True

        def list_pending_workspaces(self) -> tuple[str, ...]:
            return (workspace,) if self.pending else ()

    class _Worker:
        service_generation = 1

        def __init__(self, repository: _Repository) -> None:
            self.repository = repository

        async def run_once(self) -> None:
            self.repository.pending = False
            return None

    class _Store:
        def __init__(self, repository: _Repository) -> None:
            self._repository = repository

        def verification_repository(self) -> _Repository:
            return self._repository

    repositories = {session_id: _Repository() for session_id in session_ids}
    runtimes = {
        session_id: SimpleNamespace(
            task_id=task_id,
            session_id=session_id,
            writer_id=observation_writer_id(task_id, session_id),
            observation=_Store(repositories[session_id]),
        )
        for task_id, session_id in zip(task_ids, session_ids, strict=True)
    }
    released: list[str] = []

    class _RuntimePort:
        async def route(self, command: object) -> object:
            return runtimes[command.session_id]  # type: ignore[attr-defined]

        async def release(self, runtime: object) -> None:
            released.append(runtime.session_id)  # type: ignore[attr-defined]

    class _Coordinator(ObservationCoordinator):
        async def _rebuild_verification_worker(  # type: ignore[override]  # noqa: SLF001
            self, runtime: object, *args: object, **kwargs: object
        ) -> object:
            del args, kwargs
            return _Worker(repositories[runtime.session_id])  # type: ignore[attr-defined]

    def _mapping_loader(codex_session_id: str, *, _state: Path | None = None):
        del _state
        return mappings[codex_session_id]

    supervisor = ObservationVerificationSupervisor(service_generation=1)
    coordinator = _Coordinator(
        runtime=_RuntimePort(),  # type: ignore[arg-type]
        local=local,
        clock=object(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        mapping_loader=_mapping_loader,
        state_root=tmp_path,
        verification_supervisor=supervisor,
    )

    await coordinator.rediscover_pending_verification()
    # Multi-task discovery keeps one supervisor lane per routed task.  Both sibling repositories
    # must be visible before a drain round; the old workspace-only key would hide the second lane.
    assert supervisor.has_handle(workspace, task_ids[0])
    assert supervisor.has_handle(workspace, task_ids[1])
    assert len(supervisor._handles) == 2  # pyright: ignore[reportPrivateUsage]
    await supervisor._drain_once()  # pyright: ignore[reportPrivateUsage]
    assert supervisor.has_handle(workspace) is False
    assert sorted(released) == sorted(session_ids)


@pytest.mark.anyio
async def test_advice_materialization_failure_does_not_advance_suppression_snapshot(
    tmp_path: Path,
) -> None:
    """A failed finding append must remain retryable with the same snapshot."""

    from datetime import UTC, datetime

    from yoetz.domain.observation import AdviceItem, AdviceSnapshot
    from yoetz.ports.runtime import OwnershipFence, RuntimeCapability, TaskRuntime
    from yoetz.protocol.coverage import PublicationChannel, coverage_for_channel

    task_id = PREFIX_BY_KIND[IdKind.TASK] + str(uuid.uuid4())
    session_id = PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4())
    writer_id = PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4())
    workspace = f"hmac-sha256:{'e' * 64}"
    coverage = coverage_for_channel(PublicationChannel.ENGINE_DERIVED)
    item = AdviceItem(
        finding_id=finding_id(PREFIX_BY_KIND[IdKind.FINDING] + str(uuid.uuid4())),
        rule_code="failed_command_unresolved",
        priority=1,
        summary="A failed command remains unresolved.",
        detail="Resolve the failed command and rerun the check.",
        recommended_next_action="rerun_check",
        evidence_refs=(),
        coverage=coverage,
        freshness_frontier="frontier-retry",
    )
    snapshot = AdviceSnapshot(
        ranked_finding_ids=(item.finding_id,),
        evidence_basis_digest="sha256:" + "f" * 64,
        confidence_coverage=coverage,
        recommended_next_action="rerun_check",
        freshness_frontier="frontier-retry",
        suppression_identity="advice-retry-1",
        ranked_items=(item,),
    )
    envelope = _envelope(
        session=f"hmac-sha256:{'1' * 64}",
        kind="PostToolUse",
        identity="hook:advice-retry",
        exit_status=2,
    )

    class _Store:
        published: list[AdviceSnapshot] = []

        def list_envelopes(self, loaded_workspace: str):
            assert loaded_workspace == workspace
            return (envelope,)

        def set_advice_snapshot(
            self, loaded_workspace: str, published: AdviceSnapshot, updated_at: Timestamp
        ) -> None:
            assert loaded_workspace == workspace
            assert type(updated_at) is Timestamp
            self.published.append(published)

        def set_session_advice_snapshot(self, **kwargs: object) -> None:
            assert kwargs["workspace"] == workspace

        def record_advice_history(self, **kwargs: object) -> None:
            assert kwargs["workspace"] == workspace

    class _Builder:
        async def build(self, *args: object, **kwargs: object) -> AdviceSnapshot:
            return snapshot

    class _Clock:
        def now_utc(self) -> datetime:
            return datetime(2026, 1, 1, tzinfo=UTC)

    class _Ids:
        def new(self, kind: IdKind) -> str:
            return PREFIX_BY_KIND[kind] + str(uuid.uuid4())

    attempts = 0

    class _RetryCoordinator(ObservationCoordinator):
        async def _materialize_advice_findings(  # type: ignore[override]
            self,
            runtime: TaskRuntime,
            envelopes: tuple[ObservationEnvelope, ...],
            value: object,
            **_kwargs: object,
        ) -> None:
            nonlocal attempts
            attempts += 1
            assert envelopes == (envelope,)
            assert value is snapshot
            if attempts == 1:
                raise RuntimeError("synthetic_append_failure")

    runtime = TaskRuntime(
        task_id,
        session_id,
        writer_id,
        frozenset({RuntimeCapability.WRITE}),
        object(),  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
        "0.1.0",
        "0.1.0",
        "0.1",
        "1.0.0",
        OwnershipFence(
            PREFIX_BY_KIND[IdKind.SERVICE_INSTANCE] + str(uuid.uuid4()),
            1,
            1,
            "retry_test_nonce",
        ),
    )
    local = LocalObservationStore(_state=tmp_path)
    store = _Store()
    coordinator = _RetryCoordinator(
        runtime=object(),  # type: ignore[arg-type]
        local=local,
        clock=_Clock(),  # type: ignore[arg-type]
        ids=_Ids(),  # type: ignore[arg-type]
        state_root=tmp_path,
        advice_context_builder=_Builder(),  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError, match="synthetic_append_failure"):
        await coordinator._run_advice(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
            workspace,
            runtime,
            store,  # type: ignore[arg-type]
        )
    assert store.published == []
    assert local.advice_snapshot_for(workspace) is None

    await coordinator._run_advice(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        workspace,
        runtime,
        store,  # type: ignore[arg-type]
    )
    assert attempts == 2
    assert store.published == [snapshot]
    assert local.advice_snapshot_for(workspace) == snapshot


@pytest.mark.anyio
async def test_duplicate_ingest_reconciles_ledger_instead_of_early_return(tmp_path: Path) -> None:
    """Regression: a DUPLICATE observation row must still reconcile the ledger.

    The observation row can already exist while an earlier ledger append failed
    (and its retryable rejection kept the outbox entry pending). On retry the
    store reports DUPLICATE; the coordinator must NOT return early — it must
    re-run the idempotent materialize/append to repair the missing ledger
    operation and refresh advice.
    """

    from yoetz.adapters.integrations.codex_lifecycle import LifecycleMapping

    calls = {"append": 0, "advice": 0}

    class _DuplicateStore:
        def load_capture_ticket(self, *, workspace: str, logical_identity: str) -> None:
            # This structural-only fixture has no staged native capture to recover.
            del workspace, logical_identity
            return None

        def grant_consent(self, *args: object) -> None:
            return None

        def bind_session(self, *args: object) -> None:
            return None

        async def ingest(self, envelope: ObservationEnvelope):
            return ObservationIngestResult(
                ObservationIngestDisposition.DUPLICATE, None, envelope.cursor
            )

        def content_manifests_for_logical_identity(self, **_kwargs: object) -> tuple[object, ...]:
            return ()

    class _Runtime:
        task_id = PREFIX_BY_KIND[IdKind.TASK] + str(uuid.uuid4())
        session_id = PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4())
        writer_id = PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4())
        observation = _DuplicateStore()

    class _RuntimePort:
        async def route(self, command: object) -> object:
            return _Runtime()

        async def release(self, runtime: object) -> None:
            return None

    class _Clock:
        def now_utc(self) -> Timestamp:
            return Timestamp("2026-01-01T00:00:00.000Z")

    class _Ids:
        def new(self, kind: IdKind) -> str:
            return PREFIX_BY_KIND[kind] + str(uuid.uuid4())

    class _RecordingCoordinator(ObservationCoordinator):
        async def _append_materialized(  # type: ignore[override]  # noqa: SLF001
            self, runtime: object, envelope: object, batch: object, **_kwargs: object
        ):
            calls["append"] += 1

        async def _run_advice(  # type: ignore[override]  # noqa: SLF001
            self, workspace: str, task_id: str, store: object, **_kwargs: object
        ):
            calls["advice"] += 1

    local = LocalObservationStore(_state=tmp_path)
    workspace = local.workspace_commitment(str(tmp_path.resolve()))
    local.grant_consent(workspace)
    codex_id = "codex-dup-repair"
    session = local.bind_codex_session(workspace, codex_id)

    mapping = LifecycleMapping(
        mapping_version=1,
        codex_session_id=codex_id,
        yoetz_task_id=_Runtime.task_id,
        yoetz_session_id=_Runtime.session_id,
        yoetz_writer_id=_Runtime.writer_id,
        last_frontier=None,
    )

    coordinator = _RecordingCoordinator(
        runtime=_RuntimePort(),  # type: ignore[arg-type]
        local=local,
        clock=_Clock(),  # type: ignore[arg-type]
        ids=_Ids(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )

    result = await coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id=codex_id,
            envelope=_envelope(
                session=session, kind="PostToolUse", identity="hook:dup", exit_status=1
            ),
        )
    )

    # Reported disposition stays DUPLICATE, but reconciliation still ran.
    assert result.disposition is ObservationIngestDisposition.DUPLICATE
    assert calls["append"] == 1, "duplicate must still reconcile the ledger append"
    assert calls["advice"] == 1, "duplicate must still refresh advice"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "code",
    [
        PublicErrorCode.OPERATION_PENDING,
        PublicErrorCode.BUNDLE_BUSY,
        PublicErrorCode.FRONTIER_CONFLICT,
    ],
)
async def test_check_barrier_deferral_is_designed_backpressure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: PublicErrorCode
) -> None:
    """#351: an ADR-022 barrier deferral keeps the row retryable without an
    unexpected-exception diagnostic or a false service_unavailable gap."""

    from types import SimpleNamespace

    import yoetz.application.observation_coordinator as coordinator_module
    from yoetz.domain.observation import OBSERVATION_BACKPRESSURE_REASON

    recorded: list[str] = []

    def _recording(exc: object, *, component: str, operation: str) -> None:
        del exc, component
        recorded.append(operation)

    monkeypatch.setattr(
        coordinator_module, "record_unexpected_exception_without_raising", _recording
    )

    local, _workspace, session, mapping = _mapped_local(tmp_path, f"barrier-{code.value.lower()}")

    class _BarrierStore:
        def load_capture_ticket(self, *, workspace: str, logical_identity: str) -> None:
            # This structural-only fixture has no staged native capture to recover.
            del workspace, logical_identity
            return None

        def grant_consent(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def bind_session(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        async def ingest(self, envelope: ObservationEnvelope) -> ObservationIngestResult:
            return ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED, None, envelope.cursor
            )

    runtime = SimpleNamespace(
        task_id=mapping.yoetz_task_id,
        session_id=mapping.yoetz_session_id,
        writer_id=observation_writer_id(mapping.yoetz_task_id, mapping.yoetz_session_id),
        observation=_BarrierStore(),
    )

    class _RuntimePort:
        async def route(self, command: object) -> object:
            del command
            return runtime

        async def release(self, released: object) -> None:
            del released

    class _Clock:
        def now_utc(self) -> datetime:
            return datetime(2026, 1, 1, tzinfo=UTC)

    class _Coordinator(ObservationCoordinator):
        async def _capture_content(  # type: ignore[override]
            self, runtime: object, store: object, **kwargs: object
        ) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...], bool, bool]:
            del runtime, store, kwargs
            return ((), (), False, False)

        async def _append_materialized(  # type: ignore[override]
            self, *args: object, **kwargs: object
        ) -> tuple[str, str, None, str, tuple[str, ...]]:
            del args, kwargs
            raise PublicOperationError(code, "Deferred behind the check barrier.", True)

    coordinator = _Coordinator(
        runtime=_RuntimePort(),  # type: ignore[arg-type]
        local=local,
        clock=_Clock(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )

    result = await coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id=f"barrier-{code.value.lower()}",
            envelope=_envelope(session=session, kind="PostToolUse", identity="hook:barrier"),
        )
    )

    assert result.disposition is ObservationIngestDisposition.REJECTED
    assert result.reason == OBSERVATION_BACKPRESSURE_REASON
    assert result.reason != ObservationGapCode.SERVICE_UNAVAILABLE.value
    assert recorded == [], "a designed deferral must not record an unexpected exception"


@pytest.mark.anyio
async def test_run_advice_scopes_envelopes_to_the_mapped_session(tmp_path: Path) -> None:
    """#352: the advice pipeline sees only the mapped session's envelopes, and a
    post-commit caller without an envelope recovers the scope from the route."""

    from types import SimpleNamespace

    session_a = f"hmac-sha256:{'0a' * 32}"
    session_b = f"hmac-sha256:{'0b' * 32}"
    envelope_a = _envelope(session=session_a, kind="PostToolUse", identity="hook:a", exit_status=2)
    envelope_b = _envelope(session=session_b, kind="PostToolUse", identity="hook:b", exit_status=0)
    yoetz_session = PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4())

    class _Store:
        def list_envelopes(self, workspace: str) -> tuple[ObservationEnvelope, ...]:
            del workspace
            return (envelope_a, envelope_b)

        def list_envelopes_for_session(
            self, workspace: str, session_commitment: str
        ) -> tuple[ObservationEnvelope, ...]:
            del workspace
            return tuple(
                env
                for env in (envelope_a, envelope_b)
                if env.session_commitment == session_commitment
            )

        def codex_session_commitment_for_session(
            self, *, workspace: str, yoetz_session_id: str
        ) -> str | None:
            del workspace
            return session_b if yoetz_session_id == yoetz_session else None

        def load_advice_snapshot(self, workspace: str) -> None:
            del workspace
            return None

        async def status(self, query: ObservationStatusQuery) -> object:
            raise AssertionError("mapped build must not read workspace-wide status")

        async def status_for_session(self, workspace: str, session_commitment: str) -> object:
            from yoetz.domain.observation import ObservationLifecycle, ObservationStatus

            del workspace
            return ObservationStatus(
                ObservationLifecycle.ACTIVE,
                session_commitment,
                {},
                None,
                0,
                (),
                (),
                None,
            )

        def set_advice_snapshot(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

    seen: list[tuple[str, ...]] = []

    def _hook(
        *,
        workspace_commitment: str,
        task_id: str,
        store: object,
        envelopes: tuple[ObservationEnvelope, ...],
        frontier: object,
    ) -> None:
        del workspace_commitment, task_id, store, frontier
        seen.append(tuple(env.source_identity for env in envelopes))

    class _Clock:
        def now_utc(self) -> datetime:
            return datetime(2026, 1, 1, tzinfo=UTC)

    coordinator = ObservationCoordinator(
        runtime=object(),  # type: ignore[arg-type]
        local=LocalObservationStore(_state=tmp_path),
        clock=_Clock(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        advice_hook=_hook,
    )
    runtime = SimpleNamespace(
        task_id=_task_id(),
        session_id=yoetz_session,
        writer_id=None,
    )

    # Explicit scope from the ingest path.
    await coordinator._run_advice(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        "hmac-sha256:" + "9" * 64,
        cast(TaskRuntime, runtime),
        _Store(),  # type: ignore[arg-type]
        session_commitment=session_b,
    )
    # Route-recovered scope for post-commit callers with no envelope in hand.
    await coordinator._run_advice(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        "hmac-sha256:" + "9" * 64,
        cast(TaskRuntime, runtime),
        _Store(),  # type: ignore[arg-type]
    )
    assert seen == [("hook:b",), ("hook:b",)]


def test_backpressure_reason_routes_to_retry_without_gap_projection() -> None:
    """#351: operation_pending is retryable, safe, and marked as expected."""

    from yoetz.application.observation_drain import (
        EXPECTED_OBSERVATION_BACKPRESSURE_REASONS,
        ObservationDrainAction,
        route_observation_ingest,
    )
    from yoetz.domain.observation import OBSERVATION_BACKPRESSURE_REASON

    decision = route_observation_ingest(
        ObservationIngestResult(
            ObservationIngestDisposition.REJECTED,
            OBSERVATION_BACKPRESSURE_REASON,
            None,
        )
    )
    assert decision.action is ObservationDrainAction.RETRY
    assert decision.reason == OBSERVATION_BACKPRESSURE_REASON
    assert OBSERVATION_BACKPRESSURE_REASON in EXPECTED_OBSERVATION_BACKPRESSURE_REASONS


@pytest.mark.anyio
async def test_control_handlers_accept_ingest_request(tmp_path: Path) -> None:
    class _Port:
        async def ingest_request(self, request: ObservationIngestRequest):
            assert request.codex_session_id == "sess-control"
            from yoetz.domain.observation import ObservationIngestResult

            return ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED,
                None,
                request.envelope.cursor,
            )

        async def status(self, query: object) -> object:
            raise AssertionError("unused")

        async def pause(self, command: object) -> object:
            raise AssertionError("unused")

        async def resume(self, command: object) -> object:
            raise AssertionError("unused")

        async def revoke(self, command: object) -> object:
            raise AssertionError("unused")

    handlers = build_observation_support_handlers(_Port())  # type: ignore[arg-type]
    from yoetz.ports.control import ControlMethod

    session = f"hmac-sha256:{'33' * 32}"
    body = observation_ingest_request_to_json(
        ObservationIngestRequest(
            codex_session_id="sess-control",
            envelope=_envelope(session=session),
        )
    )
    result = await handlers[ControlMethod.OBSERVATION_INGEST](body)
    assert result["disposition"] == "accepted"


def test_materialization_phases_claim_distinct_role_scoped_identities() -> None:
    from yoetz.application.observation_materialize import (
        canonical_logical_identity,
        observation_claim_identity,
        observation_content_identity,
    )

    session = f"hmac-sha256:{'67' * 32}"

    def _claim(env: ObservationEnvelope) -> str:
        roles = tuple(
            item.role for item in materialize_observation_envelope(env, task_id="task_x").drafts
        )
        assert roles
        return observation_claim_identity(env, roles)

    pre = _envelope(session=session, kind="PreToolUse", identity="hook:pre:call-9")
    post = _envelope(
        session=session, kind="PostToolUse", identity="hook:post:call-9", exit_status=0
    )
    unpaired = _envelope(
        session=session,
        kind="PostToolUse",
        identity="hook:post-unpaired:call-9",
        exit_status=0,
        gaps=(ObservationGapCode.UNPAIRED_EVENT.value,),
    )
    stream = replace(
        _envelope(session=session, kind="item.completed", identity="stream:post:call-9"),
        source=ObservationSource.CODEX_SESSION_STREAM,
    )

    # One host call, one canonical identity: the content-dedup key is unchanged.
    assert len({canonical_logical_identity(env) for env in (pre, post, unpaired, stream)}) == 1
    # The pre-action, paired-result, and unpaired-evidence phases never contend
    # for one claim row (issue #309), while cross-source copies of the same
    # phase still share theirs so the source-mask union stays reachable.
    assert _claim(pre) != _claim(post)
    assert _claim(unpaired) != _claim(post)
    assert _claim(post) == _claim(stream)
    # Captured content recovery is phase scoped. Equivalent hook/stream copies
    # share the stable role set, while Pre/Post/unpaired siblings remain
    # isolated so they cannot lend roles across phases (#539).
    assert observation_content_identity(post) == observation_content_identity(stream)
    assert len({observation_content_identity(env) for env in (pre, post, unpaired)}) == 3


def _mapped_local(
    tmp_path: Path, codex_id: str
) -> tuple[LocalObservationStore, str, str, LifecycleMapping]:
    local = LocalObservationStore(_state=tmp_path)
    workspace = local.workspace_commitment(str(tmp_path.resolve()))
    local.grant_consent(workspace)
    session = local.bind_codex_session(workspace, codex_id)
    mapping = LifecycleMapping(
        mapping_version=1,
        codex_session_id=codex_id,
        yoetz_task_id=_task_id(),
        yoetz_session_id=PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4()),
        yoetz_writer_id=PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4()),
        last_frontier=None,
    )
    return local, workspace, session, mapping


@pytest.mark.anyio
async def test_native_content_requires_matching_local_and_task_profile_grants(
    tmp_path: Path,
) -> None:
    """Native chunks need the same explicit host profile at both consent boundaries."""

    from types import SimpleNamespace

    import apsw

    codex_id = "native-content-profile"
    local, workspace, session, mapping = _mapped_local(tmp_path, codex_id)
    local.enable_content_capture(workspace, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID)

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": mapping.yoetz_task_id, "owner_generation": "1"})
    task_store = SqliteObservationStore(db)
    runtime = SimpleNamespace(
        task_id=mapping.yoetz_task_id,
        session_id=mapping.yoetz_session_id,
        writer_id=observation_writer_id(mapping.yoetz_task_id, mapping.yoetz_session_id),
        observation=task_store,
    )

    class _RuntimePort:
        def __init__(self) -> None:
            self.disable_before_capture = False

        async def route(self, command: object) -> object:
            del command
            if self.disable_before_capture:
                self.disable_before_capture = False
                # Model a queued request whose runtime gate is disabled after
                # the coordinator's initial consent read but before capture.
                local.set_runtime_enabled(False)
            return runtime

        async def release(self, released: object) -> None:
            assert released is runtime

    captured: list[tuple[ObservationContentChunk, ...]] = []

    class _Coordinator(ObservationCoordinator):
        async def _capture_content(  # type: ignore[override]
            self, runtime: object, store: object, **kwargs: object
        ) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...], bool, bool]:
            del runtime, store
            captured.append(cast(tuple[ObservationContentChunk, ...], kwargs["chunks"]))
            return (), (), False, False

        async def _append_materialized(  # type: ignore[override]
            self, *args: object, **kwargs: object
        ) -> None:
            del args, kwargs
            return None

        async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

        async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

    class _Clock:
        def now_utc(self) -> datetime:
            return datetime(2026, 1, 1, tzinfo=UTC)

    async def bootstrap(workspace: str, runtime: TaskRuntime, store: TaskObservationPort) -> bool:
        # This fixture owns exactly one task bundle. Capture authority still
        # needs a complete budget inventory independently of its profile grant.
        assert runtime.task_id == mapping.yoetz_task_id
        assert store is task_store
        return local.bootstrap_capture_reservations(
            workspace,
            {runtime.task_id: store.capture_backlog(workspace)},
        )

    runtime_port = _RuntimePort()
    coordinator = _Coordinator(
        runtime=runtime_port,  # type: ignore[arg-type]
        local=local,
        clock=_Clock(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
        capture_budget_bootstrap=bootstrap,
    )
    chunk = ObservationContentChunk(
        content_kind=ObservationContentKind.TOOL_OUTPUT,
        correlation_identity="hook:native-content:tool-output",
        source_commitment="hmac-sha256:" + "ab" * 32,
        media_type="text/plain",
        part_index=0,
        part_count=1,
        content=b"bounded native output",
        redacted=False,
    )

    def request(
        identity: str, *, profile: str | None = CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    ) -> ObservationIngestRequest:
        return ObservationIngestRequest(
            codex_session_id=codex_id,
            envelope=_envelope(
                session=session,
                kind="PostToolUse",
                identity=identity,
                ordinal=len(captured) + 1,
                source=ObservationSource.CLAUDE_HOOK,
                corr=identity,
            ),
            content_chunks=(chunk,),
            content_capture_profile=profile,
        )

    # A native request without the profile is retained structurally, but no
    # plaintext chunk reaches the service capture hook and the gap is explicit.
    omitted = await coordinator.ingest_request(request("hook:native-content-omitted", profile=None))
    assert omitted.disposition is ObservationIngestDisposition.ACCEPTED
    assert captured == [()]
    assert (
        ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
        in task_store.list_envelopes(workspace)[0].gap_codes
    )

    selected = await coordinator.ingest_request(request("hook:native-content-selected"))
    assert selected.disposition is ObservationIngestDisposition.ACCEPTED
    assert captured[-1] == (chunk,)
    assert task_store.content_capture_profiles(workspace) == (
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    )

    mismatch = await coordinator.ingest_request(
        request(
            "hook:native-content-mismatch",
            profile="cursor-ordinary-observation-v1",
        )
    )
    assert mismatch.disposition is ObservationIngestDisposition.REJECTED
    assert mismatch.reason == ObservationGapCode.CONTENT_CAPTURE_PROFILE_MISMATCH.value
    assert captured[-1] == (chunk,)

    # A direct/queued native request still admits its structural envelope, but
    # the authoritative runtime fence blocks the plaintext capture path.
    runtime_port.disable_before_capture = True
    before_blocked_capture_count = len(captured)
    queued = await coordinator.ingest_request(request("hook:native-content-runtime-off"))
    assert queued.disposition is ObservationIngestDisposition.ACCEPTED
    assert len(captured) == before_blocked_capture_count
    retained = task_store.list_envelopes(workspace)
    assert ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value in retained[-1].gap_codes


@pytest.mark.anyio
async def test_duplicate_ingest_reconstructed_append_detects_same_task_rewind(
    tmp_path: Path,
) -> None:
    """Exercise issue #331 through DUPLICATE -> committed result -> local notice."""

    from types import SimpleNamespace

    import apsw

    codex_id = "rewind-duplicate"
    local, workspace, session, mapping = _mapped_local(tmp_path, codex_id)
    delivered_digest = "sha256:" + "c" * 64
    local.note_frontier_motion(
        workspace,
        codex_id,
        from_sequence=220,
        to_sequence=221,
        head_digest=delivered_digest,
        observation_record_count=1,
        task_id=mapping.yoetz_task_id,
    )
    delivered = local.peek_frontier_motion(workspace, codex_id)
    assert delivered is not None
    local.commit_frontier_motion_delivery(workspace, codex_id, delivered.delivery_identity)

    envelope = _envelope(session=session, identity="hook:rewound-duplicate")
    batch = materialize_observation_envelope(envelope, task_id=mapping.yoetz_task_id)
    assert batch.drafts
    writer_id = observation_writer_id(mapping.yoetz_task_id, mapping.yoetz_session_id)
    rewound_digest = "sha256:" + "d" * 64
    committed_digest = observation_operation_digest(
        task_id=mapping.yoetz_task_id,
        logical_identity=canonical_logical_identity(envelope),
        draft_roles=tuple(item.role for item in batch.drafts),
    )
    canonical = canonical_encode(
        {
            "accepted": (
                {
                    "entry_digest": rewound_digest,
                    "event_id": batch.drafts[0].draft.event_id,
                    "ingestion_sequence": "5",
                    "projection_status": "projected",
                    "writer_sequence": "1",
                },
            ),
            "result_frontier": {"head_digest": rewound_digest, "sequence": "5"},
            "subject_frontier": {
                "head_digest": "sha256:" + "a" * 64,
                "sequence": "4",
            },
            "warnings": (),
        }
    )
    existing = OperationRecord(
        writer_id,
        PREFIX_BY_KIND[IdKind.REQUEST] + str(uuid.uuid4()),
        OperationKind.PUBLISH_WORK,
        committed_digest,
        OperationState.COMPLETE,
        CheckPhase.TERMINAL,
        None,
        None,
        None,
        None,
        None,
        canonical,
        "sha256:" + hashlib.sha256(canonical).hexdigest(),
        None,
        None,
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    class _Ledger:
        async def lookup_task_operation(self, looked_up_writer: str, operation_id: str):
            del operation_id
            assert looked_up_writer == writer_id
            return existing

        async def lookup_operation(self, looked_up_writer: str, operation_id: str):
            del looked_up_writer, operation_id
            raise AssertionError("the task-scoped hit must resolve before any legacy probe")

        async def load_frontier(self) -> Frontier:
            return Frontier(5, rewound_digest)

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": mapping.yoetz_task_id, "owner_generation": "1"})
    observation = SqliteObservationStore(db)
    observation.grant_consent(workspace, Timestamp("2026-01-01T00:00:00.000Z"))
    observation.bind_session(workspace, session)
    assert (await observation.ingest(envelope)).disposition is ObservationIngestDisposition.ACCEPTED
    runtime = SimpleNamespace(
        task_id=mapping.yoetz_task_id,
        session_id=mapping.yoetz_session_id,
        writer_id=writer_id,
        ledger=_Ledger(),
        observation=observation,
    )

    class _RuntimePort:
        async def route(self, command: object) -> object:
            del command
            return runtime

        async def release(self, released: object) -> None:
            assert released is runtime

    class _Clock:
        def now_utc(self) -> datetime:
            return datetime(2026, 1, 1, tzinfo=UTC)

    class _Coordinator(ObservationCoordinator):
        async def _capture_content(  # type: ignore[override]
            self, runtime: object, store: object, **kwargs: object
        ) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...], bool, bool]:
            del runtime, store, kwargs
            return ((), (), False, False)

        async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

        async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

    coordinator = _Coordinator(
        runtime=_RuntimePort(),  # type: ignore[arg-type]
        local=local,
        clock=_Clock(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )
    result = await coordinator.ingest_request(
        ObservationIngestRequest(codex_session_id=codex_id, envelope=envelope)
    )

    assert result.disposition is ObservationIngestDisposition.DUPLICATE
    notice = local.peek_frontier_motion(workspace, codex_id)
    assert notice is not None
    assert (notice.from_sequence, notice.to_sequence, notice.head_digest) == (
        4,
        5,
        rewound_digest,
    )


@pytest.mark.anyio
async def test_pre_post_and_stream_copies_claim_without_storage_corrupt(tmp_path: Path) -> None:
    """Regression for issue #309 against the real SQLite claim repository.

    A Pre/Post pair for one ``tool_call_id`` must both materialize without
    ``STORAGE_CORRUPT``, and a hook/stream copy of the paired result must merge
    to ``source_mask == 3``.
    """

    from types import SimpleNamespace

    import apsw

    from yoetz.application.observation_materialize import (
        canonical_logical_identity as _identity,
    )
    from yoetz.application.observation_materialize import (
        observation_operation_digest as _digest,
    )

    local, _workspace, session, mapping = _mapped_local(tmp_path, "claim-repro-309")
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": mapping.yoetz_task_id, "owner_generation": "1"})
    store = SqliteObservationStore(db)
    runtime = SimpleNamespace(
        task_id=mapping.yoetz_task_id,
        session_id=mapping.yoetz_session_id,
        writer_id=observation_writer_id(mapping.yoetz_task_id, mapping.yoetz_session_id),
        observation=store,
    )

    class _RuntimePort:
        async def route(self, command: object) -> object:
            del command
            return runtime

        async def release(self, released: object) -> None:
            del released

    class _Clock:
        def now_utc(self) -> datetime:
            return datetime(2026, 1, 1, tzinfo=UTC)

    class _Coordinator(ObservationCoordinator):
        async def _capture_content(  # type: ignore[override]
            self, runtime: object, store: object, **kwargs: object
        ) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...], bool, bool]:
            del runtime, store, kwargs
            return ((), (), False, False)

        async def _append_materialized(  # type: ignore[override]
            self,
            runtime: object,
            envelope: ObservationEnvelope,
            batch: MaterializedObservationBatch,
            *,
            legacy_session_id: str | None = None,
            legacy_writer_id: str | None = None,
            legacy_writer_routes: tuple[tuple[str, str], ...] = (),
            replay_required: bool = False,
            replay_claims: tuple[tuple[tuple[str, str, str], tuple[str, ...]], ...] = (),
            replay_draft_role_sets: tuple[tuple[str, ...], ...] = (),
        ) -> tuple[str, str, None, str, tuple[str, ...]]:
            del (
                legacy_session_id,
                legacy_writer_id,
                legacy_writer_routes,
                replay_required,
                replay_claims,
                replay_draft_role_sets,
            )
            roles = tuple(item.role for item in batch.drafts)
            digest = _digest(
                task_id=runtime.task_id,  # type: ignore[attr-defined]
                session_id=runtime.session_id,  # type: ignore[attr-defined]
                writer_id=runtime.writer_id,  # type: ignore[attr-defined]
                logical_identity=_identity(envelope),
                draft_roles=roles,
                mapping_version=MATERIALIZATION_LEGACY_MAPPING_VERSIONS[0],
            )
            return (
                self._stable_operation_id(digest),
                digest,
                None,
                MATERIALIZATION_LEGACY_MAPPING_VERSIONS[0],
                roles,
            )

        async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

        async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

    coordinator = _Coordinator(
        runtime=_RuntimePort(),  # type: ignore[arg-type]
        local=local,
        clock=_Clock(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )

    pre = _envelope(session=session, kind="PreToolUse", identity="hook:pre:call-309", ordinal=1)
    post = _envelope(
        session=session,
        kind="PostToolUse",
        identity="hook:post:call-309",
        ordinal=2,
        exit_status=0,
    )
    stream_post = replace(
        _envelope(
            session=session,
            kind="item.completed",
            identity="stream:post:call-309",
            ordinal=3,
        ),
        source=ObservationSource.CODEX_SESSION_STREAM,
    )

    for envelope in (pre, post, stream_post):
        result = await coordinator.ingest_request(
            ObservationIngestRequest(codex_session_id="claim-repro-309", envelope=envelope)
        )
        assert result.disposition is ObservationIngestDisposition.ACCEPTED, result.reason

    assert not coordinator._storage_corrupt_sessions  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    rows = db.execute(
        "SELECT source_mask,mapping_version FROM observation_logical_identity ORDER BY source_mask"
    ).fetchall()
    # Pre keeps its own hook-only claim; the paired result claim unions hook and
    # stream coverage into source_mask == 3 (previously dead code, issue #309).
    assert [row[0] for row in rows] == [1, 3]
    assert {row[1] for row in rows} == {MATERIALIZATION_LEGACY_MAPPING_VERSIONS[0]}


@pytest.mark.anyio
async def test_post_only_replay_includes_historical_unpaired_role_set(tmp_path: Path) -> None:
    """A native post-only retry can find the old unpaired-evidence operation."""

    from types import SimpleNamespace

    local, _workspace, session, mapping = _mapped_local(tmp_path, "legacy-post-only-replay")
    replay_sets: list[tuple[tuple[str, ...], ...]] = []

    class _Store:
        def load_capture_ticket(self, **kwargs: object) -> None:
            del kwargs

        def grant_consent(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def bind_session(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        async def ingest(self, envelope: ObservationEnvelope) -> ObservationIngestResult:
            return ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED, None, envelope.cursor
            )

        def record_logical_identity_claim(self, **kwargs: object) -> None:
            del kwargs

    runtime = SimpleNamespace(
        task_id=mapping.yoetz_task_id,
        session_id=mapping.yoetz_session_id,
        writer_id=observation_writer_id(mapping.yoetz_task_id, mapping.yoetz_session_id),
        observation=_Store(),
    )

    class _RuntimePort:
        async def route(self, command: object) -> object:
            del command
            return runtime

        async def release(self, released: object) -> None:
            del released

    class _Clock:
        def now_utc(self) -> datetime:
            return datetime(2026, 1, 1, tzinfo=UTC)

    class _Coordinator(ObservationCoordinator):
        async def _capture_content(  # type: ignore[override]
            self, runtime: object, store: object, **kwargs: object
        ) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...], bool, bool]:
            del runtime, store, kwargs
            return (), (), False, False

        async def _append_materialized(  # type: ignore[override]
            self,
            runtime: object,
            envelope: ObservationEnvelope,
            batch: MaterializedObservationBatch,
            *,
            legacy_session_id: str | None = None,
            legacy_writer_id: str | None = None,
            legacy_writer_routes: tuple[tuple[str, str], ...] = (),
            replay_required: bool = False,
            replay_claims: tuple[tuple[tuple[str, str, str], tuple[str, ...]], ...] = (),
            replay_draft_role_sets: tuple[tuple[str, ...], ...] = (),
        ) -> tuple[str, str, None, str, tuple[str, ...]]:
            del (
                legacy_session_id,
                legacy_writer_id,
                legacy_writer_routes,
                replay_required,
                replay_claims,
            )
            replay_sets.append(replay_draft_role_sets)
            roles = tuple(item.role for item in batch.drafts)
            digest = observation_operation_digest(
                task_id=runtime.task_id,  # type: ignore[attr-defined]
                logical_identity=canonical_logical_identity(envelope),
                draft_roles=roles,
            )
            return (
                self._stable_operation_id(digest),
                digest,
                None,
                MATERIALIZATION_MAPPING_VERSION,
                roles,
            )

        async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

        async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

    coordinator = _Coordinator(
        runtime=_RuntimePort(),  # type: ignore[arg-type]
        local=local,
        clock=_Clock(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )
    base_envelope = _envelope(
        session=session,
        kind="PostToolUse",
        identity="claude:historical-unpaired",
        source=ObservationSource.CLAUDE_HOOK,
        exit_status=0,
        corr="historical-call",
        gaps=(ObservationGapCode.UNPAIRED_EVENT.value,),
    )
    envelope = replace(
        base_envelope,
        structural_payload=JsonObject(
            {
                **base_envelope.structural_payload,
                "capability_profile_id": "claude-code-cli-local-project-2.1.241",
                "pairing_mode": "post_only",
                "correlation_kind": "tool_call_id",
            }
        ),
    )

    result = await coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id="legacy-post-only-replay",
            envelope=envelope,
        )
    )
    assert result.disposition is ObservationIngestDisposition.ACCEPTED
    assert replay_sets == [(("action", "result"), ("unpaired_evidence",))]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "projection_mode",
    [
        "ready",
        "missing",
        "lagging",
        "rebuilding",
        "result_missing",
        "result_redacted",
        "legacy_mapping",
    ],
)
async def test_later_stream_failure_correction_projection_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    projection_mode: str,
) -> None:
    from types import SimpleNamespace

    import apsw

    from yoetz.application import observation_coordinator as coordinator_module
    from yoetz.application.observation_materialize import (
        canonical_logical_identity as _identity,
    )
    from yoetz.application.observation_materialize import (
        observation_operation_digest as _digest,
    )
    from yoetz.domain.events import ActionRecordedPayload, ResultRecordedPayload, encode_payload
    from yoetz.kernel.projections import ProjectionRecord, empty_projection_state
    from yoetz.ports.ledger import (
        AcceptedEventSummary,
        AppendResult,
        ProjectionView,
        StoredProjection,
    )
    from yoetz.protocol.canonical import canonical_digest

    local, _workspace, session, mapping = _mapped_local(tmp_path, "outcome-correction")

    recorded_errors: list[Exception] = []

    def _record_error(error: Exception, **_kwargs: object) -> None:
        recorded_errors.append(error)

    monkeypatch.setattr(
        coordinator_module,
        "record_unexpected_exception_without_raising",
        _record_error,
    )
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": mapping.yoetz_task_id, "owner_generation": "1"})
    store = SqliteObservationStore(db)
    core_unknown: MaterializedObservationBatch | None = None
    appended_roles: list[tuple[str, ...]] = []
    appended_batches: list[MaterializedObservationBatch] = []
    head = "sha256:" + "a" * 64
    projection_state = [projection_mode]

    class _Ledger:
        async def load_frontier(self) -> Frontier:
            return Frontier(3, head)

        async def load_projection(
            self, loaded_session: str, view: object
        ) -> StoredProjection | None:
            assert loaded_session == mapping.yoetz_session_id
            assert view is ProjectionView.CANDIDATE_FINDINGS
            assert core_unknown is not None
            if projection_state[0] == "missing":
                return None
            batch = core_unknown
            action_draft = batch.drafts[0]
            action_payload = cast(ActionRecordedPayload, action_draft.draft.payload)
            result_draft = batch.drafts[1]
            payload = cast(ResultRecordedPayload, result_draft.draft.payload)
            results = {
                payload.result_id: ProjectionRecord(
                    None if projection_state[0] == "result_redacted" else payload,
                    canonical_digest(encode_payload(payload)),
                    projection_state[0] == "result_redacted",
                    result_draft.draft.event_id,
                    1,
                )
            }
            if projection_state[0] == "result_missing":
                results = {}
            state = replace(
                empty_projection_state(),
                frontier=1,
                head_digest=head,
                actions={
                    action_payload.action_id: ProjectionRecord(
                        action_payload,
                        canonical_digest(encode_payload(action_payload)),
                        False,
                        action_draft.draft.event_id,
                        1,
                    )
                },
                results=results,
            )
            return StoredProjection(
                ProjectionView.CANDIDATE_FINDINGS,
                state,
                Frontier(1, head),
                1 if projection_state[0] == "lagging" else 0,
                "projection-test-1",
                projection_state[0] == "rebuilding",
            )

    runtime = SimpleNamespace(
        task_id=mapping.yoetz_task_id,
        session_id=mapping.yoetz_session_id,
        writer_id=observation_writer_id(mapping.yoetz_task_id, mapping.yoetz_session_id),
        observation=store,
        ledger=_Ledger(),
    )

    class _RuntimePort:
        async def route(self, command: object) -> object:
            del command
            return runtime

        async def release(self, released: object) -> None:
            del released

    class _Clock:
        def now_utc(self) -> datetime:
            return datetime(2026, 1, 1, tzinfo=UTC)

    class _Coordinator(ObservationCoordinator):
        async def _capture_content(  # type: ignore[override]
            self, runtime: object, store: object, **kwargs: object
        ) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...], bool, bool]:
            del runtime, store, kwargs
            return ((), (), False, False)

        async def _append_materialized(  # type: ignore[override]
            self,
            runtime: object,
            envelope: ObservationEnvelope,
            batch: MaterializedObservationBatch,
            *,
            legacy_session_id: str | None = None,
            legacy_writer_id: str | None = None,
            legacy_writer_routes: tuple[tuple[str, str], ...] = (),
            replay_required: bool = False,
            replay_claims: tuple[tuple[tuple[str, str, str], tuple[str, ...]], ...] = (),
            replay_draft_role_sets: tuple[tuple[str, ...], ...] = (),
        ) -> tuple[str, str, AppendResult, str, tuple[str, ...]]:
            nonlocal core_unknown
            del (
                legacy_session_id,
                legacy_writer_id,
                legacy_writer_routes,
                replay_required,
                replay_claims,
                replay_draft_role_sets,
            )
            roles = tuple(item.role for item in batch.drafts)
            appended_roles.append(roles)
            appended_batches.append(batch)
            resolved_version = (
                MATERIALIZATION_LEGACY_MAPPING_VERSIONS[0]
                if projection_mode == "legacy_mapping"
                else MATERIALIZATION_MAPPING_VERSION
            )
            digest = _digest(
                task_id=runtime.task_id,  # type: ignore[attr-defined]
                logical_identity=_identity(envelope),
                draft_roles=roles,
                mapping_version=resolved_version,
                **(
                    {
                        "session_id": runtime.session_id,  # type: ignore[attr-defined]
                        "writer_id": runtime.writer_id,  # type: ignore[attr-defined]
                    }
                    if projection_mode == "legacy_mapping"
                    else {}
                ),
            )
            if roles == ("action", "result") and core_unknown is None:
                core_unknown = batch
                outcome = "accepted"
            elif roles == ("action", "result"):
                outcome = "replayed"
            else:
                outcome = "accepted"
            accepted = tuple(
                AcceptedEventSummary(
                    item.draft.event_id,
                    index,
                    index,
                    "sha256:" + f"{index:064x}",
                    "projected",
                )
                for index, item in enumerate(batch.drafts, 1)
            )
            return (
                self._stable_operation_id(digest),
                digest,
                AppendResult(
                    outcome,  # type: ignore[arg-type]
                    accepted,
                    Frontier(1, head),
                    Frontier(1 + len(accepted), head),
                    (),
                ),
                resolved_version,
                roles,
            )

        async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

        async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

    coordinator = _Coordinator(
        runtime=_RuntimePort(),  # type: ignore[arg-type]
        local=local,
        clock=_Clock(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )
    hook = _envelope(
        session=session,
        kind="PostToolUse",
        identity="hook:outcome-correction",
        corr="call-outcome-correction",
    )
    stream = replace(
        _envelope(
            session=session,
            kind="function_call_output",
            identity="stream:outcome-correction",
            corr="call-outcome-correction",
            exit_status=9,
        ),
        source=ObservationSource.CODEX_SESSION_STREAM,
        structural_payload=JsonObject(
            {
                "action": "function_call_output",
                "tool_name": "shell",
                "tool_call_id": "call-outcome-correction",
                "correlation_id": "call-outcome-correction",
                "exit_status": 9,
            }
        ),
    )

    hook_result = await coordinator.ingest_request(
        ObservationIngestRequest(codex_session_id="outcome-correction", envelope=hook)
    )
    assert hook_result.disposition is ObservationIngestDisposition.ACCEPTED, hook_result.reason
    stream_result = await coordinator.ingest_request(
        ObservationIngestRequest(codex_session_id="outcome-correction", envelope=stream)
    )

    if projection_mode in {"ready", "legacy_mapping"}:
        assert stream_result.disposition is ObservationIngestDisposition.ACCEPTED
        assert recorded_errors == []
    else:
        # The core operation may already be committed, but the authoritative
        # correction is part of acceptance. Keep the durable outbox row
        # retryable until the projection can prove what needs correcting.
        assert stream_result.disposition is ObservationIngestDisposition.REJECTED
        assert stream_result.reason == ObservationGapCode.SERVICE_UNAVAILABLE.value
        assert len(recorded_errors) == 1
        assert appended_roles == [("action", "result"), ("action", "result")]

        projection_state[0] = "ready"
        recovered = await coordinator.ingest_request(
            ObservationIngestRequest(codex_session_id="outcome-correction", envelope=stream)
        )
        assert recovered.disposition is ObservationIngestDisposition.DUPLICATE

    masks = db.execute(
        "SELECT source_mask FROM observation_logical_identity ORDER BY source_mask"
    ).fetchall()
    assert appended_roles[-1] == ("result_correction_failure_9",)
    assert appended_roles.count(("result_correction_failure_9",)) == 1
    assert [row[0] for row in masks] == [2, 3]
    if projection_mode == "legacy_mapping":
        # A replayed legacy operation may be a pre-upgrade hook UNKNOWN; the
        # coordinator consults the committed result via its accepted event ids
        # and binds the explicit correction to that exact committed action.
        assert core_unknown is not None
        core_action = cast(ActionRecordedPayload, core_unknown.drafts[0].draft.payload)
        correction_batch = appended_batches[-1]
        correction_result = cast(ResultRecordedPayload, correction_batch.drafts[0].draft.payload)
        assert correction_result.action_id == core_action.action_id
        assert correction_batch.drafts[0].draft.causal_parents == (
            core_unknown.drafts[0].draft.event_id,
        )


@pytest.mark.anyio
async def test_identity_claim_conflict_rejects_one_envelope_without_latching(
    tmp_path: Path,
) -> None:
    from types import SimpleNamespace

    local, _workspace, session, mapping = _mapped_local(tmp_path, "claim-conflict-309")
    ingested: list[str] = []

    class _ConflictStore:
        def load_capture_ticket(self, *, workspace: str, logical_identity: str) -> None:
            # This structural-only fixture has no staged native capture to recover.
            del workspace, logical_identity
            return None

        def grant_consent(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def bind_session(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        async def ingest(self, envelope: ObservationEnvelope) -> ObservationIngestResult:
            ingested.append(envelope.source_identity)
            return ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED, None, envelope.cursor
            )

        def record_logical_identity_claim(self, **kwargs: object) -> None:
            del kwargs
            raise PublicOperationError(
                PublicErrorCode.STORAGE_CORRUPT,
                "Observation logical identity conflicts.",
                False,
            )

    runtime = SimpleNamespace(
        task_id=mapping.yoetz_task_id,
        session_id=mapping.yoetz_session_id,
        writer_id=observation_writer_id(mapping.yoetz_task_id, mapping.yoetz_session_id),
        observation=_ConflictStore(),
    )

    class _RuntimePort:
        def __init__(self) -> None:
            self.calls = 0

        async def route(self, command: object) -> object:
            del command
            self.calls += 1
            return runtime

        async def release(self, released: object) -> None:
            del released

    class _Clock:
        def now_utc(self) -> datetime:
            return datetime(2026, 1, 1, tzinfo=UTC)

    class _Coordinator(ObservationCoordinator):
        async def _capture_content(  # type: ignore[override]
            self, runtime: object, store: object, **kwargs: object
        ) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...], bool, bool]:
            del runtime, store, kwargs
            return ((), (), False, False)

        async def _append_materialized(  # type: ignore[override]
            self, *args: object, **kwargs: object
        ) -> tuple[str, str, None, str, tuple[str, ...]]:
            del args, kwargs
            return (
                "op_" + "0" * 32,
                "sha256:" + "ab" * 32,
                None,
                MATERIALIZATION_MAPPING_VERSION,
                ("action", "result"),
            )

        async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

        async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

    runtime_port = _RuntimePort()
    coordinator = _Coordinator(
        runtime=runtime_port,  # type: ignore[arg-type]
        local=local,
        clock=_Clock(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )

    first = await coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id="claim-conflict-309",
            envelope=_envelope(session=session, kind="PostToolUse", identity="hook:c1"),
        )
    )
    second = await coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id="claim-conflict-309",
            envelope=_envelope(session=session, kind="PostToolUse", identity="hook:c2", ordinal=2),
        )
    )

    # A claim conflict rejects only its own envelope as dedup_conflict; the
    # session is never latched, so the next envelope still reaches the store
    # (issue #309: one conflict previously quarantined 187 envelopes).
    assert first.disposition is ObservationIngestDisposition.REJECTED
    assert first.reason == ObservationGapCode.DEDUP_CONFLICT.value
    assert second.reason == ObservationGapCode.DEDUP_CONFLICT.value
    assert runtime_port.calls == 2
    assert ingested == ["hook:c1", "hook:c2"]
    assert not coordinator._storage_corrupt_sessions  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001


# --- issue #560: reattach replays stable IDs ---------------------------------


def _reattach_fixture(tmp_path: Path, codex_id: str) -> _ReattachCell:
    return _ReattachCell(tmp_path, codex_id)


class _ReattachCell:
    """A consented workspace, one task ledger, and a rotatable lifecycle mapping.

    ``route`` builds the runtime from the routed session/writer pair exactly as
    the service does, so a mapping rotation after ``start`` (a reattach in the
    same host session) changes the observation writer while the task ledger and
    its committed operations stay put.
    """

    def __init__(self, tmp_path: Path, codex_id: str) -> None:
        import apsw

        from builders.ledger_adapters import FixedClock, FixedIds, MemoryObjects, ownership_fence
        from yoetz.adapters.memory.importer import MemoryImportState
        from yoetz.adapters.memory.ledger import MemoryLedgerAdapter, MemoryLedgerState
        from yoetz.ports.runtime import RuntimeCapability, TaskRuntime

        self.local, self.workspace, self.session, mapping = _mapped_local(tmp_path, codex_id)
        self.local_root = tmp_path
        self.codex_id = codex_id
        self.task_id = mapping.yoetz_task_id
        self.mapping = mapping
        self.ids = FixedIds()
        self.objects = MemoryObjects(self.ids)
        self.ledger = MemoryLedgerAdapter(
            task_id=self.task_id,
            ownership_fence=ownership_fence(),
            state=MemoryLedgerState(),
            import_state=MemoryImportState(),
            transaction_lock=__import__("asyncio").Lock(),
            clock=FixedClock(),
            ids=self.ids,
            objects=self.objects,
        )
        db = apsw.Connection(":memory:")
        initialize_bundle(db, {"task_id": self.task_id, "owner_generation": "1"})
        self.store = SqliteObservationStore(db)
        self.routed: list[tuple[str, str]] = []
        cell = self

        class _RuntimePort:
            async def route(self, command: object) -> TaskRuntime:
                session_id = cast(str, getattr(command, "session_id"))
                writer_id = cast(str, getattr(command, "writer_id"))
                cell.routed.append((session_id, writer_id))
                return TaskRuntime(
                    cell.task_id,
                    session_id,
                    writer_id,
                    frozenset(
                        {
                            RuntimeCapability.STRUCTURAL_READ,
                            RuntimeCapability.PAYLOAD_READ,
                            RuntimeCapability.WRITE,
                        }
                    ),
                    cell.ledger,
                    cell.objects,  # type: ignore[arg-type]
                    object(),  # type: ignore[arg-type]
                    "0.1.0",
                    "0.1.0",
                    "0.1",
                    "1.0.0",
                    ownership_fence(),
                    observation=cell.store,
                )

            async def release(self, released: object) -> None:
                del released

        self.runtime_port = _RuntimePort()
        self.coordinator = self.build_coordinator()

    def build_coordinator(self) -> ObservationCoordinator:
        """A fresh coordinator over the same ledger and store (a service restart)."""

        from builders.ledger_adapters import FixedClock

        cell = self

        class _Coordinator(ObservationCoordinator):
            async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
                del args, kwargs

            async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
                del args, kwargs

        return _Coordinator(
            runtime=self.runtime_port,  # type: ignore[arg-type]
            local=self.local,
            clock=FixedClock(),  # type: ignore[arg-type]
            ids=self.ids,  # type: ignore[arg-type]
            state_root=self.local_root,
            mapping_loader=lambda *_args, **_kwargs: cell.mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
        )

    def reattach(self) -> None:
        """Rotate the mapping the way a second ``start`` in the same host session does."""

        self.mapping = LifecycleMapping(
            mapping_version=1,
            codex_session_id=self.codex_id,
            yoetz_task_id=self.task_id,
            yoetz_session_id=PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4()),
            yoetz_writer_id=PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4()),
            last_frontier=None,
        )

    async def ingest(self, envelope: ObservationEnvelope) -> ObservationIngestResult:
        return await self.coordinator.ingest_request(
            ObservationIngestRequest(codex_session_id=self.codex_id, envelope=envelope)
        )

    def operation_count(self) -> int:
        return len(self.ledger._state.operations)  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001

    def record_count(self) -> int:
        return len(self.ledger._state.records)  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001


# --- issue #576: a deterministic ledger schema rejection is terminal, not service_unavailable ---


def _schema_eight_store() -> tuple[object, SqliteObservationStore]:
    """A task ledger from before migration 0009: its DDL refuses every non-Codex source."""

    import apsw

    from yoetz.adapters.sqlite.migrations import BUNDLE_MIGRATIONS

    db = apsw.Connection(":memory:")
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA trusted_schema = OFF")
    with db:
        for migration in BUNDLE_MIGRATIONS[:8]:
            db.execute(migration.ddl.decode())
    return db, SqliteObservationStore(db)


@pytest.mark.anyio
@pytest.mark.parametrize("source", [ObservationSource.CLAUDE_HOOK, ObservationSource.CURSOR_HOOK])
async def test_host_hook_row_refused_by_ledger_schema_quarantines_then_delivers_after_migration(
    tmp_path: Path, source: ObservationSource
) -> None:
    """#576: the store's CHECK failure reaches the drain as ledger_rejected, once.

    Before this fix the bare driver exception took the coordinator's catch-all and was
    projected as retryable service_unavailable, so the FIFO head was retried forever while
    the service reported ready. After the bundle migrates, the identical envelope delivers.
    """

    from yoetz.adapters.sqlite.migrations import BUNDLE_MIGRATIONS, run_migrations

    cell = _reattach_fixture(tmp_path, f"host-{source.value}")
    db, cell.store = _schema_eight_store()
    envelope = _envelope(session=cell.session, identity=f"hook:{source.value}:1", source=source)

    rejected = await cell.ingest(envelope)

    assert rejected.disposition is ObservationIngestDisposition.REJECTED
    assert rejected.reason == ObservationGapCode.LEDGER_REJECTED.value
    decision = route_observation_ingest(rejected)
    assert decision.action is ObservationDrainAction.QUARANTINE
    assert decision.reason == ObservationGapCode.LEDGER_REJECTED.value
    assert cell.operation_count() == 0
    assert cell.coordinator._storage_corrupt_sessions == set()  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001

    run_migrations(cast(apsw.Connection, db), BUNDLE_MIGRATIONS, maintenance=None)  # type: ignore[arg-type]
    cell.coordinator = cell.build_coordinator()
    accepted = await cell.ingest(envelope)

    assert accepted.disposition is ObservationIngestDisposition.ACCEPTED
    assert route_observation_ingest(accepted).action is ObservationDrainAction.ACKNOWLEDGE
    assert cell.operation_count() == 1
    status = await cell.store.status(ObservationStatusQuery(cell.workspace))
    assert status.source_coverage[source] is True
    # A host hook claim carries the hook bit, not the Codex session-stream bit.
    assert cast(apsw.Connection, db).execute(
        "SELECT DISTINCT source_mask FROM observation_logical_identity"
    ).fetchall() == [(1,)]


_REATTACH_ENVELOPES: dict[str, dict[str, object]] = {
    "pre": {"kind": "PreToolUse", "tool": "shell", "corr": "call-560"},
    "paired_post": {"kind": "PostToolUse", "tool": "shell", "corr": "call-560", "exit_status": 0},
    "yoetz_mcp_post": {"kind": "PostToolUse", "tool": "mcp__yoetz__status", "corr": "call-560-s"},
    "unpaired_post": {
        "kind": "PostToolUse",
        "tool": "shell",
        "corr": "call-560-u",
        "exit_status": 1,
        "gaps": ("unpaired_event",),
    },
}


@pytest.mark.anyio
@pytest.mark.parametrize("shape", sorted(_REATTACH_ENVELOPES))
@pytest.mark.parametrize("lifecycle", ["dropped_ack", "restart", "reattach", "reattach_twice"])
async def test_repeated_observation_replays_committed_operation_across_reattach(
    tmp_path: Path, shape: str, lifecycle: str
) -> None:
    """#560: a repeated logical observation resolves to its committed operation.

    The stable event ids depend on the task and the source identity only, so a
    replayed envelope after a lost acknowledgement, a service restart, or a
    workflow reattach (which rotates the Yoetz session and writer) must find
    the operation that already committed those ids instead of appending a
    second operation that the ledger rejects as a duplicate event.
    """

    cell = _reattach_fixture(tmp_path, f"reattach-{shape}-{lifecycle}")
    spec = dict(_REATTACH_ENVELOPES[shape])
    envelope = _envelope(
        session=cell.session,
        kind=cast(str, spec["kind"]),
        identity=f"hook:560:{shape}",
        tool=cast(str, spec["tool"]),
        corr=cast(str, spec["corr"]),
        exit_status=cast(int | None, spec.get("exit_status")),
        gaps=cast(tuple[str, ...], spec.get("gaps", ())),
    )

    first = await cell.ingest(envelope)
    assert first.disposition is ObservationIngestDisposition.ACCEPTED, first.reason
    operations = cell.operation_count()
    records = cell.record_count()
    assert operations == 1 and records >= 1
    first_frontier = await cell.ledger.load_frontier()

    if lifecycle == "restart":
        cell.coordinator = cell.build_coordinator()
    elif lifecycle in {"reattach", "reattach_twice"}:
        cell.reattach()
        if lifecycle == "reattach_twice":
            cell.reattach()

    second = await cell.ingest(envelope)
    assert second.reason != ObservationGapCode.LEDGER_REJECTED.value
    assert second.disposition is ObservationIngestDisposition.DUPLICATE
    assert route_observation_ingest(second).action is ObservationDrainAction.ACKNOWLEDGE
    assert cell.operation_count() == operations, "an idempotent repeat appends no operation"
    assert cell.record_count() == records
    assert await cell.ledger.load_frontier() == first_frontier
    if lifecycle.startswith("reattach"):
        assert cell.routed[-1] != cell.routed[0], "the reattach rotated the routed writer"
    assert not cell.local.list_quarantine(cell.workspace)
    gaps = cell.local.status(ObservationStatusQuery(cell.workspace)).gaps
    assert ObservationGapCode.LEDGER_REJECTED.value not in gaps


@pytest.mark.anyio
async def test_conflicting_reuse_of_a_stable_event_id_still_fails_closed(tmp_path: Path) -> None:
    """#560: the same event id under a different structural identity is a conflict."""

    cell = _reattach_fixture(tmp_path, "reattach-conflict")
    # Unpaired evidence mints its event ids from the source identity, so the same
    # identity under another host call reuses committed event ids. (A paired
    # PreToolUse now keys its action on the host call itself, #917.)
    committed = _envelope(
        session=cell.session,
        kind="PostToolUse",
        identity="hook:560:conflict",
        exit_status=1,
        gaps=(ObservationGapCode.UNPAIRED_EVENT.value,),
    )
    first = await cell.ingest(committed)
    assert first.disposition is ObservationIngestDisposition.ACCEPTED, first.reason
    operations = cell.operation_count()

    cell.reattach()
    # Same source identity (hence the same stable event ids) but a different host
    # call: a different logical identity that must never be laundered into the
    # committed operation.
    conflicting = _envelope(
        session=cell.session,
        kind="PostToolUse",
        identity="hook:560:conflict",
        corr="call-other",
        exit_status=1,
        gaps=(ObservationGapCode.UNPAIRED_EVENT.value,),
    )
    second = await cell.ingest(conflicting)
    assert second.disposition is ObservationIngestDisposition.REJECTED
    assert second.reason == ObservationGapCode.LEDGER_REJECTED.value
    assert route_observation_ingest(second).action is ObservationDrainAction.QUARANTINE
    assert cell.operation_count() == operations


# --- issue #917: one ledger action per paired host call ---------------------


def _schema_rows(cell: _ReattachCell, name: str) -> list[AcceptedEvent]:
    from yoetz.domain.events import AcceptedEvent as _Accepted

    return [
        row
        for row in cell.ledger._state.records  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        if type(row) is _Accepted and row.schema.name == name
    ]


def _stream_copy(envelope: ObservationEnvelope, identity: str) -> ObservationEnvelope:
    """The Codex session-stream observation of the same completed host call."""

    return replace(
        envelope,
        source=ObservationSource.CODEX_SESSION_STREAM,
        event_kind="function_call_output",
        source_identity=identity,
    )


@pytest.mark.anyio
async def test_paired_pre_then_post_records_one_action_linked_to_its_result(
    tmp_path: Path,
) -> None:
    """#917: an individually delivered pre and its post share one action.

    Before the fix the pre minted ``pre-event:<source_identity>`` and the post a
    second action keyed on the call id, so one call held two actions.
    """

    from yoetz.domain.events import ActionRecordedPayload, ResultOutcome, ResultRecordedPayload

    cell = _reattach_fixture(tmp_path, "paired-917")
    pre = _envelope(session=cell.session, kind="PreToolUse", identity="hook:917:pre", corr="c917")
    post = _envelope(
        session=cell.session,
        kind="PostToolUse",
        identity="hook:917:post",
        corr="c917",
        exit_status=2,
    )
    first = await cell.ingest(pre)
    assert first.disposition is ObservationIngestDisposition.ACCEPTED, first.reason
    pending = _schema_rows(cell, "action_recorded")
    assert len(pending) == 1
    second = await cell.ingest(post)
    assert second.disposition is ObservationIngestDisposition.ACCEPTED, second.reason

    actions = _schema_rows(cell, "action_recorded")
    results = _schema_rows(cell, "result_recorded")
    assert [row.event_id for row in actions] == [pending[0].event_id]
    assert len(results) == 1
    action = cast(ActionRecordedPayload, actions[0].payload)
    result = cast(ResultRecordedPayload, results[0].payload)
    assert "pending" in action.description
    assert result.action_id == action.action_id
    assert result.outcome is ResultOutcome.FAILURE and result.exit_status == 2
    assert actions[0].event_id in results[0].causal_parents
    assert cell.operation_count() == 2

    # The session-stream copy of the same completed call links to the same
    # action and resolves to the hook copy's operation instead of re-recording.
    records = cell.record_count()
    stream = await cell.ingest(_stream_copy(post, "stream:917:post"))
    assert stream.disposition is ObservationIngestDisposition.ACCEPTED, stream.reason
    assert cell.record_count() == records
    assert cell.operation_count() == 2

    # A lost acknowledgement, a service restart and a workflow reattach replay
    # both phases to their committed operations; nothing is re-minted.
    for lifecycle in ("dropped_ack", "restart", "reattach"):
        if lifecycle == "restart":
            cell.coordinator = cell.build_coordinator()
        elif lifecycle == "reattach":
            cell.reattach()
        for envelope in (pre, post):
            again = await cell.ingest(envelope)
            assert again.disposition is ObservationIngestDisposition.DUPLICATE, lifecycle
        assert cell.record_count() == records
        assert cell.operation_count() == 2
    assert not cell.local.list_quarantine(cell.workspace)


@pytest.mark.anyio
async def test_post_without_delivered_pre_still_records_its_action(tmp_path: Path) -> None:
    """#917: a post whose pre never reached the ledger keeps its own action.

    Yoetz-owned calls deliver only their post (#564); a post-first order must also
    not strand a later copy of the pre as a ledger conflict.
    """

    cell = _reattach_fixture(tmp_path, "post-only-917")
    post = _envelope(
        session=cell.session,
        kind="PostToolUse",
        identity="hook:917:yoetz-post",
        tool="mcp__yoetz__publish_work",
        corr="c917-yoetz",
    )
    accepted = await cell.ingest(post)
    assert accepted.disposition is ObservationIngestDisposition.ACCEPTED, accepted.reason
    assert len(_schema_rows(cell, "action_recorded")) == 1
    assert len(_schema_rows(cell, "result_recorded")) == 1
    records = cell.record_count()
    operations = cell.operation_count()

    # A late copy of the pre (for example the session-stream call record) finds
    # the action already recorded and appends nothing.
    late_pre = replace(
        _envelope(
            session=cell.session,
            kind="PreToolUse",
            identity="stream:917:yoetz-pre",
            tool="mcp__yoetz__publish_work",
            corr="c917-yoetz",
        ),
        source=ObservationSource.CODEX_SESSION_STREAM,
    )
    late = await cell.ingest(late_pre)
    assert late.disposition is ObservationIngestDisposition.ACCEPTED, late.reason
    assert cell.record_count() == records
    assert cell.operation_count() == operations
    assert not cell.local.list_quarantine(cell.workspace)


@pytest.mark.anyio
async def test_pre_committed_before_upgrade_is_never_rematerialized_as_a_third_action(
    tmp_path: Path,
) -> None:
    """#917 lifecycle: a session spanning the upgrade keeps at most its historical double.

    A pre committed by the older mapping (``pre-event:`` action identity) shares
    the new pre's operation digest, so its redelivery replays the committed
    operation instead of minting the new action. The post then records its own
    action exactly as it did before the upgrade; no history is rewritten.
    """

    from types import SimpleNamespace

    from yoetz.application import observation_materialize as materialize_module
    from yoetz.domain.events import ActionRecordedPayload
    from yoetz.domain.values import action_id

    cell = _reattach_fixture(tmp_path, "upgrade-917")
    pre = _envelope(
        session=cell.session, kind="PreToolUse", identity="hook:917:old-pre", corr="c9u"
    )
    current = materialize_observation_envelope(pre, task_id=cell.task_id)
    legacy_source = (
        f"pre-event:codex:{pre.session_commitment}:{pre.cursor.source_generation}:"
        f"{pre.source_identity}"
    )
    payload = cast(ActionRecordedPayload, current.drafts[0].draft.payload)
    legacy_draft = materialize_module._draft(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        event=stable_observation_id(
            kind=IdKind.EVENT,
            task_id=cell.task_id,
            source_identity=legacy_source,
            mapping_version=MATERIALIZATION_MAPPING_VERSION,
            role="action_event",
        ),
        schema_name="action_recorded",
        occurred_at=pre.receipt_time,
        payload=replace(
            payload,
            action_id=action_id(
                stable_observation_id(
                    kind=IdKind.ACTION,
                    task_id=cell.task_id,
                    source_identity=legacy_source,
                    mapping_version=MATERIALIZATION_MAPPING_VERSION,
                    role="action",
                )
            ),
        ),
        role="action",
    )
    session_id = cell.mapping.yoetz_session_id
    runtime = await cell.runtime_port.route(
        SimpleNamespace(
            session_id=session_id, writer_id=observation_writer_id(cell.task_id, session_id)
        )
    )
    committed = await cell.coordinator._append_materialized(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        runtime, pre, replace(current, drafts=(legacy_draft,))
    )
    assert committed is not None
    assert len(_schema_rows(cell, "action_recorded")) == 1

    # Redelivery of the same pre after the upgrade resolves to the committed
    # pre-upgrade operation instead of minting the new action identity.
    replayed = await cell.ingest(pre)
    assert replayed.disposition is ObservationIngestDisposition.ACCEPTED, replayed.reason
    assert len(_schema_rows(cell, "action_recorded")) == 1

    post = _envelope(
        session=cell.session,
        kind="PostToolUse",
        identity="hook:917:new-post",
        corr="c9u",
        exit_status=0,
    )
    linked = await cell.ingest(post)
    assert linked.disposition is ObservationIngestDisposition.ACCEPTED, linked.reason
    assert len(_schema_rows(cell, "action_recorded")) == 2
    assert len(_schema_rows(cell, "result_recorded")) == 1
    assert not cell.local.list_quarantine(cell.workspace)


@pytest.mark.anyio
async def test_advice_findings_reuse_operation_committed_by_predecessor_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#560: a reattached session finds the task-scoped finding operation task-wide.

    Finding event ids and the finding operation digest are task-scoped, so the
    operation a predecessor session committed under its own writer must be
    found by the successor writer instead of re-appended with duplicate ids.
    """

    from types import SimpleNamespace

    import yoetz.application.observation_coordinator as coordinator_module
    from yoetz.application.unit_of_work import PreparedMutation
    from yoetz.domain.observation import AdviceItem, AdviceSnapshot
    from yoetz.ports.ledger import ProjectionView
    from yoetz.protocol.coverage import PublicationChannel, coverage_for_channel, weakest

    task_id = _task_id()
    successor_session = PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4())
    predecessor_writer = PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4())
    successor_writer = observation_writer_id(task_id, successor_session)
    item_coverage = weakest(
        coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
        coverage_for_channel(PublicationChannel.ENGINE_DERIVED),
    )
    item = AdviceItem(
        finding_id=finding_id(PREFIX_BY_KIND[IdKind.FINDING] + str(uuid.uuid4())),
        rule_code="failed_command_unresolved",
        priority=10,
        summary="A failed command remains unresolved.",
        detail="Resolve the failed command and rerun the check.",
        recommended_next_action="rerun_check",
        evidence_refs=("hook:advice-reattach",),
        coverage=item_coverage,
        freshness_frontier="frontier-1",
    )
    snapshot = AdviceSnapshot(
        ranked_finding_ids=(item.finding_id,),
        evidence_basis_digest="sha256:" + "a" * 64,
        confidence_coverage=item_coverage,
        recommended_next_action="rerun_check",
        freshness_frontier="frontier-1",
        suppression_identity="advice-reattach-1",
        ranked_items=(item,),
    )
    envelope = _envelope(
        session=f"hmac-sha256:{'d' * 64}",
        kind="PostToolUse",
        identity="hook:advice-reattach",
        exit_status=2,
    )
    ledger_events = [
        SimpleNamespace(event_id=draft.draft.event_id, schema=draft.draft.schema)
        for draft in materialize_observation_envelope(envelope, task_id=task_id).drafts
    ]
    advice_subject_refs = tuple(
        sorted((str(record.event_id) for record in ledger_events), key=str.encode)[:64]
    )
    advice_request_digest = canonical_digest(
        JsonObject(
            {
                "format": "yoetz.observation-advice-findings/1",
                "task_id": task_id,
                "findings": (
                    {
                        "finding_id": str(item.finding_id),
                        "subject_refs": advice_subject_refs,
                    },
                ),
            }
        )
    )
    committed_result = canonical_encode(
        {
            "accepted": (
                {
                    "entry_digest": "sha256:" + "a" * 64,
                    "event_id": PREFIX_BY_KIND[IdKind.EVENT] + str(uuid.uuid4()),
                    "ingestion_sequence": "4",
                    "projection_status": "projected",
                    "writer_sequence": "1",
                },
            ),
            "result_frontier": {"head_digest": "sha256:" + "c" * 64, "sequence": "4"},
            "subject_frontier": {"head_digest": "sha256:" + "b" * 64, "sequence": "3"},
            "warnings": (),
        }
    )
    committed = OperationRecord(
        predecessor_writer,
        PREFIX_BY_KIND[IdKind.REQUEST] + str(uuid.uuid4()),
        OperationKind.PUBLISH_WORK,
        advice_request_digest,
        OperationState.COMPLETE,
        CheckPhase.TERMINAL,
        None,
        None,
        None,
        None,
        None,
        committed_result,
        "sha256:" + hashlib.sha256(committed_result).hexdigest(),
        None,
        None,
        datetime(2026, 1, 1, tzinfo=UTC),
    )
    lookups: list[tuple[str, str, str]] = []

    class _Ledger:
        async def load_projection(self, loaded_session_id: str, view: ProjectionView):
            assert loaded_session_id == successor_session
            del view
            return None

        async def _events(self):
            for record in ledger_events:
                yield record

        def load_events(self, loaded_session_id: str):
            assert loaded_session_id == successor_session
            return self._events()

        async def lookup_operation(self, loaded_writer_id: str, operation_id: str):
            lookups.append(("writer", loaded_writer_id, operation_id))
            return None

        async def lookup_task_operation(self, loaded_writer_id: str, operation_id: str):
            lookups.append(("task", loaded_writer_id, operation_id))
            assert loaded_writer_id == successor_writer
            return committed

    async def _never_append(ledger: object, prepared: PreparedMutation):
        del ledger, prepared
        raise AssertionError("a task-wide committed finding operation must not be re-appended")

    monkeypatch.setattr(coordinator_module, "run_prepared_append", _never_append)

    class _Clock:
        def now_utc(self) -> datetime:
            return datetime(2026, 1, 1, tzinfo=UTC)

    class _Ids:
        def new(self, kind: IdKind) -> str:
            return PREFIX_BY_KIND[kind] + str(uuid.uuid4())

    runtime = SimpleNamespace(
        task_id=task_id,
        session_id=successor_session,
        writer_id=successor_writer,
        ledger=_Ledger(),
        objects=object(),
    )
    coordinator = ObservationCoordinator(
        runtime=object(),  # type: ignore[arg-type]
        local=LocalObservationStore(_state=tmp_path),
        clock=_Clock(),  # type: ignore[arg-type]
        ids=_Ids(),  # type: ignore[arg-type]
        state_root=tmp_path,
    )

    await coordinator._materialize_advice_findings(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        cast(TaskRuntime, runtime),
        (envelope,),
        snapshot,  # type: ignore[arg-type]
    )

    assert [kind for kind, _writer, _operation in lookups] == ["task"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "source",
    [ObservationSource.CODEX_HOOK, ObservationSource.CLAUDE_HOOK, ObservationSource.CURSOR_HOOK],
)
async def test_session_superseded_reroutes_ingest_and_persists_mapping(
    tmp_path: Path, source: ObservationSource
) -> None:
    """#577: a pending predecessor row follows the successor binding, not ledger_rejected."""

    from builders.ledger_adapters import FixedClock

    cell = _reattach_fixture(tmp_path, "superseded-577")
    predecessor_session = cell.mapping.yoetz_session_id
    successor_session = PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4())
    successor_writer = PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4())
    stored = {"mapping": cell.mapping}
    inner_route = cell.runtime_port.route

    async def route(command: object) -> TaskRuntime:
        session_id = cast(str, getattr(command, "session_id"))
        if session_id == predecessor_session:
            raise PublicOperationError(
                PublicErrorCode.SESSION_NOT_FOUND,
                "The requested session was replaced.",
                retryable=False,
                safe_details={
                    "reason_code": "session_superseded",
                    "task_id": cell.task_id,
                    "session_id": successor_session,
                    "writer_id": successor_writer,
                },
            )
        return await inner_route(command)

    cell.runtime_port.route = route  # type: ignore[method-assign]

    class _Coordinator(ObservationCoordinator):
        async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

        async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

    def _store_superseded_mapping(mapping: LifecycleMapping, *, _state: Path | None = None) -> None:
        del _state
        stored["mapping"] = mapping

    cell.coordinator = _Coordinator(
        runtime=cell.runtime_port,  # type: ignore[arg-type]
        local=cell.local,
        clock=FixedClock(),  # type: ignore[arg-type]
        ids=cell.ids,  # type: ignore[arg-type]
        state_root=cell.local_root,
        mapping_loader=lambda *_args, **_kwargs: stored["mapping"],  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
        mapping_storer=_store_superseded_mapping,
    )

    result = await cell.ingest(_envelope(session=cell.session, identity="hook:577", source=source))
    assert result.disposition is ObservationIngestDisposition.ACCEPTED, result.reason
    assert result.reason != ObservationGapCode.LEDGER_REJECTED.value
    assert stored["mapping"].yoetz_session_id == successor_session
    assert stored["mapping"].yoetz_writer_id == successor_writer
    assert cell.routed[-1][0] == successor_session
    assert cell.routed[-1][1] == observation_writer_id(cell.task_id, successor_session)
    assert not cell.local.list_quarantine(cell.workspace)
    gaps = cell.local.status(ObservationStatusQuery(cell.workspace)).gaps
    assert ObservationGapCode.LEDGER_REJECTED.value not in gaps
    assert route_observation_ingest(result).action is ObservationDrainAction.ACKNOWLEDGE


@pytest.mark.anyio
async def test_session_superseded_without_followable_binding_is_not_ledger_rejected(
    tmp_path: Path,
) -> None:
    """#577: a retired route that cannot be followed names session_superseded, not content refusal."""

    local, _workspace, session, mapping = _mapped_local(tmp_path, "superseded-mismatch-577")
    other_task = _task_id()

    class _RejectedRuntime:
        async def route(self, command: object) -> object:
            del command
            raise PublicOperationError(
                PublicErrorCode.SESSION_NOT_FOUND,
                "The requested session was replaced.",
                retryable=False,
                safe_details={
                    "reason_code": "session_superseded",
                    "task_id": other_task,
                    "session_id": PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4()),
                    "writer_id": PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4()),
                },
            )

        async def release(self, runtime: object) -> None:
            raise AssertionError(f"unrouted runtime released: {runtime!r}")

    coordinator = ObservationCoordinator(
        runtime=_RejectedRuntime(),  # type: ignore[arg-type]
        local=local,
        clock=object(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )
    result = await coordinator.ingest_request(
        ObservationIngestRequest(
            codex_session_id=mapping.codex_session_id,
            envelope=_envelope(session=session),
        )
    )
    assert result.reason == ObservationGapCode.SESSION_SUPERSEDED.value
    assert result.reason != ObservationGapCode.LEDGER_REJECTED.value
    assert result.reason != ObservationGapCode.MAPPING_MISSING.value
    assert route_observation_ingest(result).action is ObservationDrainAction.QUARANTINE


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("hop_count", "seed_index"),
    [(1, 0), (2, 1)],
    ids=["single-hop-predecessor", "multi-hop-intermediate"],
)
async def test_ingest_replays_legacy_operation_through_every_route_writer(
    tmp_path: Path, hop_count: int, seed_index: int
) -> None:
    """Legacy observation operations remain reachable after bounded reattach chains.

    The lifecycle mapping stores the cooperative start writer, while the old
    observation materializer used the deterministic writer derived from each
    routed session.  Exercise real ``ingest_request`` routing with an old 1.4
    operation under that derived writer, including an intermediate writer in a
    two-hop retirement chain.
    """

    from types import SimpleNamespace

    from builders.ledger_adapters import FixedClock

    cell = _reattach_fixture(tmp_path, f"legacy-replay-{hop_count}")
    predecessor = cell.mapping
    sessions = [predecessor.yoetz_session_id]
    cooperative_writers = [predecessor.yoetz_writer_id]
    for _ in range(hop_count):
        sessions.append(PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4()))
        cooperative_writers.append(PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4()))
    derived_writers = [observation_writer_id(cell.task_id, session) for session in sessions]

    envelope = _envelope(
        session=cell.session,
        kind="PreToolUse",
        identity=f"hook:legacy-replay:{hop_count}",
        corr=f"legacy-replay-call-{hop_count}",
    )
    batch = materialize_observation_envelope(envelope, task_id=cell.task_id)
    roles = tuple(item.role for item in batch.drafts)
    mapping_version = MATERIALIZATION_LEGACY_MAPPING_VERSIONS[0]
    seeded_digest = observation_operation_digest(
        task_id=cell.task_id,
        logical_identity=canonical_logical_identity(envelope, mapping_version=mapping_version),
        draft_roles=roles,
        mapping_version=mapping_version,
        session_id=sessions[seed_index],
        writer_id=derived_writers[seed_index],
    )
    seeded_operation_id = ""
    lookup_routes: list[tuple[str, str]] = []

    class _Ledger:
        async def lookup_task_operation(self, writer_id: str, operation_id: str):
            del writer_id, operation_id
            return None

        async def lookup_operation(self, writer_id: str, operation_id: str):
            lookup_routes.append((writer_id, operation_id))
            if writer_id == derived_writers[seed_index] and operation_id == seeded_operation_id:
                return SimpleNamespace(request_digest=seeded_digest)
            return None

    ledger = _Ledger()
    current_runtime = SimpleNamespace(
        task_id=cell.task_id,
        session_id=sessions[-1],
        writer_id=derived_writers[-1],
        ledger=ledger,
        observation=cell.store,
        objects=object(),
    )

    class _RuntimePort:
        async def route(self, command: object) -> object:
            session_id = cast(str, getattr(command, "session_id"))
            hop = sessions.index(session_id)
            if hop < hop_count:
                raise PublicOperationError(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The requested session was replaced.",
                    retryable=False,
                    safe_details={
                        "reason_code": "session_superseded",
                        "task_id": cell.task_id,
                        "session_id": sessions[hop + 1],
                        "writer_id": cooperative_writers[hop + 1],
                    },
                )
            return current_runtime

        async def release(self, released: object) -> None:
            assert released is current_runtime

    class _Coordinator(ObservationCoordinator):
        async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

        async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

    coordinator = _Coordinator(
        runtime=_RuntimePort(),  # type: ignore[arg-type]
        local=cell.local,
        clock=FixedClock(),
        ids=object(),  # type: ignore[arg-type]
        state_root=cell.local_root,
        mapping_loader=lambda *_args, **_kwargs: predecessor,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
        mapping_storer=lambda *_args, **_kwargs: None,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )
    seeded_operation_id = coordinator._stable_operation_id(seeded_digest)  # pyright: ignore[reportPrivateUsage]

    first = await coordinator.ingest_request(ObservationIngestRequest(cell.codex_id, envelope))
    replayed = await coordinator.ingest_request(ObservationIngestRequest(cell.codex_id, envelope))

    assert first.disposition is ObservationIngestDisposition.ACCEPTED, first.reason
    assert replayed.disposition is ObservationIngestDisposition.DUPLICATE, replayed.reason
    assert lookup_routes
    assert (derived_writers[seed_index], seeded_operation_id) in lookup_routes
    # The route history includes both the cooperative and deterministic writer
    # for every predecessor needed before the seeded operation is found.
    expected_operation_ids = {
        (
            writer,
            coordinator._stable_operation_id(  # pyright: ignore[reportPrivateUsage]
                observation_operation_digest(
                    task_id=cell.task_id,
                    logical_identity=canonical_logical_identity(
                        envelope, mapping_version=mapping_version
                    ),
                    draft_roles=roles,
                    mapping_version=mapping_version,
                    session_id=session_id,
                    writer_id=writer,
                )
            ),
        )
        for index in range(seed_index + 1)
        for session_id, writer in (
            (sessions[index], cooperative_writers[index]),
            (sessions[index], derived_writers[index]),
        )
    }
    assert expected_operation_ids.issubset(set(lookup_routes))


@pytest.mark.anyio
async def test_ingest_replays_legacy_operation_after_route_cache_restart(tmp_path: Path) -> None:
    """A route-cache replacement keeps predecessor replay reachable after a crash."""

    from types import SimpleNamespace

    from builders.ledger_adapters import FixedClock
    from yoetz.adapters.integrations.codex_lifecycle import (
        load_mapping,
        load_route_history,
        store_mapping,
    )

    cell = _reattach_fixture(tmp_path, "legacy-replay-restart")
    predecessor = cell.mapping
    successor = replace(
        predecessor,
        yoetz_session_id=PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4()),
        yoetz_writer_id=PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4()),
    )
    store_mapping(predecessor, _state=tmp_path)
    envelope = _envelope(
        session=cell.session,
        kind="PreToolUse",
        identity="hook:legacy-replay-restart",
        corr="legacy-replay-restart-call",
    )
    batch = materialize_observation_envelope(envelope, task_id=cell.task_id)
    roles = tuple(item.role for item in batch.drafts)
    mapping_version = MATERIALIZATION_LEGACY_MAPPING_VERSIONS[0]
    predecessor_derived_writer = observation_writer_id(cell.task_id, predecessor.yoetz_session_id)
    seeded_digest = observation_operation_digest(
        task_id=cell.task_id,
        logical_identity=canonical_logical_identity(envelope, mapping_version=mapping_version),
        draft_roles=roles,
        mapping_version=mapping_version,
        session_id=predecessor.yoetz_session_id,
        writer_id=predecessor_derived_writer,
    )
    seeded_operation_id = ""
    lookup_routes: list[tuple[str, str]] = []

    class _Ledger:
        async def lookup_task_operation(self, writer_id: str, operation_id: str):
            del writer_id, operation_id
            return None

        async def lookup_operation(self, writer_id: str, operation_id: str):
            lookup_routes.append((writer_id, operation_id))
            if writer_id == predecessor_derived_writer and operation_id == seeded_operation_id:
                return SimpleNamespace(request_digest=seeded_digest)
            return None

    current_runtime = SimpleNamespace(
        task_id=cell.task_id,
        session_id=successor.yoetz_session_id,
        writer_id=observation_writer_id(cell.task_id, successor.yoetz_session_id),
        ledger=_Ledger(),
        observation=cell.store,
        objects=object(),
    )

    class _RuntimePort:
        async def route(self, command: object) -> object:
            session_id = cast(str, getattr(command, "session_id"))
            if session_id == predecessor.yoetz_session_id:
                raise PublicOperationError(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The requested session was replaced.",
                    retryable=False,
                    safe_details={
                        "reason_code": "session_superseded",
                        "task_id": cell.task_id,
                        "session_id": successor.yoetz_session_id,
                        "writer_id": successor.yoetz_writer_id,
                    },
                )
            assert session_id == successor.yoetz_session_id
            return current_runtime

        async def release(self, released: object) -> None:
            assert released is current_runtime

    class _Interrupted(ObservationCoordinator):
        async def _capture_content(self, *args: object, **kwargs: object):  # type: ignore[override]
            del args, kwargs
            raise RuntimeError("simulated interrupted ingest")

    class _Recovered(ObservationCoordinator):
        async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

        async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs

    common = {
        "runtime": _RuntimePort(),
        "local": cell.local,
        "clock": FixedClock(),
        "ids": object(),
        "state_root": tmp_path,
        "mapping_loader": load_mapping,
        "mapping_storer": store_mapping,
    }
    interrupted = _Interrupted(**common)  # type: ignore[arg-type]
    seeded_operation_id = interrupted._stable_operation_id(seeded_digest)  # pyright: ignore[reportPrivateUsage]

    failed = await interrupted.ingest_request(ObservationIngestRequest(cell.codex_id, envelope))
    assert failed.disposition is ObservationIngestDisposition.REJECTED
    assert failed.reason == ObservationGapCode.SERVICE_UNAVAILABLE.value
    cached = load_mapping(cell.codex_id, _state=tmp_path)
    assert cached is not None
    assert cached.yoetz_session_id == successor.yoetz_session_id
    history = load_route_history(cached, _state=tmp_path)
    assert history is not None
    assert history.routes == ((predecessor.yoetz_session_id, predecessor.yoetz_writer_id),)
    assert history.truncated is False

    recovered = _Recovered(**common)  # type: ignore[arg-type]
    accepted = await recovered.ingest_request(ObservationIngestRequest(cell.codex_id, envelope))
    assert accepted.disposition is ObservationIngestDisposition.ACCEPTED, accepted.reason
    assert (predecessor_derived_writer, seeded_operation_id) in lookup_routes


@pytest.mark.anyio
async def test_truncated_route_history_uses_claim_or_rejects_without_reminting(
    tmp_path: Path,
) -> None:
    """An evicted legacy route can recover from its durable claim, or fails closed."""

    from types import SimpleNamespace

    from builders.ledger_adapters import FixedClock

    task_id = _task_id()
    current_session = PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4())
    current_writer = observation_writer_id(task_id, current_session)
    envelope = _envelope(
        session=f"hmac-sha256:{'d1' * 32}",
        kind="PreToolUse",
        identity="hook:truncated-route",
        corr="truncated-route-call",
    )
    batch = materialize_observation_envelope(envelope, task_id=task_id)
    roles = tuple(item.role for item in batch.drafts)
    mapping_version = MATERIALIZATION_LEGACY_MAPPING_VERSIONS[0]
    legacy_session = PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4())
    legacy_writer = observation_writer_id(task_id, legacy_session)
    digest = observation_operation_digest(
        task_id=task_id,
        logical_identity=canonical_logical_identity(envelope, mapping_version=mapping_version),
        draft_roles=roles,
        mapping_version=mapping_version,
        session_id=legacy_session,
        writer_id=legacy_writer,
    )

    class _Ledger:
        async def lookup_task_operation(self, writer_id: str, operation_id: str):
            del writer_id
            if operation_id == operation_id_for_claim:
                return SimpleNamespace(operation_id=operation_id, request_digest=digest)
            return None

        async def lookup_operation(self, writer_id: str, operation_id: str):
            del writer_id, operation_id
            return None

    coordinator = ObservationCoordinator(
        runtime=object(),  # type: ignore[arg-type]
        local=LocalObservationStore(_state=tmp_path),
        clock=FixedClock(),
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
    )
    operation_id_for_claim = coordinator._stable_operation_id(  # pyright: ignore[reportPrivateUsage]
        digest
    )
    runtime = cast(
        TaskRuntime,
        SimpleNamespace(
            task_id=task_id,
            session_id=current_session,
            writer_id=current_writer,
            ledger=_Ledger(),
            objects=object(),
        ),
    )
    claim = ((digest, operation_id_for_claim, mapping_version), roles)
    recovered = await coordinator._append_materialized(  # pyright: ignore[reportPrivateUsage]
        runtime,
        envelope,
        batch,
        replay_required=True,
        replay_claims=(claim,),
    )
    assert recovered is not None
    assert recovered[0] == operation_id_for_claim
    assert recovered[1] == digest
    assert recovered[3] == mapping_version
    assert recovered[4] == roles

    class _MissingLedger:
        async def lookup_task_operation(self, writer_id: str, operation_id: str):
            del writer_id, operation_id
            return None

        async def lookup_operation(self, writer_id: str, operation_id: str):
            del writer_id, operation_id
            return None

    missing_runtime = cast(
        TaskRuntime,
        SimpleNamespace(
            task_id=task_id,
            session_id=current_session,
            writer_id=current_writer,
            ledger=_MissingLedger(),
            objects=object(),
        ),
    )
    with pytest.raises(PublicOperationError) as missing:
        await coordinator._append_materialized(  # pyright: ignore[reportPrivateUsage]
            missing_runtime,
            envelope,
            batch,
            replay_required=True,
        )
    assert missing.value.code is PublicErrorCode.SESSION_NOT_FOUND
    assert missing.value.safe_details["reason_code"] == "session_superseded"


@pytest.mark.anyio
@pytest.mark.parametrize("concurrent_change", ["locked", "rebound", "frontier", "cleared", "none"])
async def test_successor_route_cache_preserves_concurrent_lifecycle_changes(
    tmp_path: Path, concurrent_change: str
) -> None:
    """Routing can continue without overwriting a lifecycle update made during the await."""

    from contextlib import ExitStack

    from yoetz.adapters.integrations.codex_lifecycle import (
        acquire_session_lock,
        clear_mapping,
        load_mapping,
        store_mapping,
    )

    local, _workspace, _session, predecessor = _mapped_local(tmp_path, "route-cache-race")
    store_mapping(predecessor, _state=tmp_path)
    successor = replace(
        predecessor,
        yoetz_session_id=PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4()),
        yoetz_writer_id=PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4()),
    )
    expected = predecessor
    routed_runtime = cast(TaskRuntime, object())
    with ExitStack() as locks:

        class _Runtime:
            async def route(self, command: object) -> TaskRuntime:
                nonlocal expected
                if getattr(command, "session_id") == successor.yoetz_session_id:
                    return routed_runtime
                if concurrent_change == "locked":
                    assert locks.enter_context(
                        acquire_session_lock(predecessor.codex_session_id, _state=tmp_path)
                    )
                elif concurrent_change == "rebound":
                    expected = replace(predecessor, yoetz_task_id=_task_id())
                    store_mapping(expected, _state=tmp_path)
                elif concurrent_change == "frontier":
                    expected = replace(predecessor, last_frontier="99:sha256:" + "a" * 64)
                    store_mapping(expected, _state=tmp_path)
                elif concurrent_change == "cleared":
                    clear_mapping(predecessor.codex_session_id, _state=tmp_path)
                raise PublicOperationError(
                    PublicErrorCode.SESSION_NOT_FOUND,
                    "The requested session was replaced.",
                    retryable=False,
                    safe_details={
                        "reason_code": "session_superseded",
                        "task_id": predecessor.yoetz_task_id,
                        "session_id": successor.yoetz_session_id,
                        "writer_id": successor.yoetz_writer_id,
                    },
                )

        coordinator = ObservationCoordinator(
            runtime=_Runtime(),  # type: ignore[arg-type]
            local=local,
            clock=object(),  # type: ignore[arg-type]
            ids=object(),  # type: ignore[arg-type]
            state_root=tmp_path,
        )
        runtime, mapping = await coordinator._route_observation_mapping(predecessor)  # pyright: ignore[reportPrivateUsage]
        assert runtime is routed_runtime
        assert mapping == successor
        persisted = load_mapping(predecessor.codex_session_id, _state=tmp_path)
        if concurrent_change == "cleared":
            assert persisted is None
        else:
            assert persisted == (successor if concurrent_change == "none" else expected)


@pytest.mark.anyio
@pytest.mark.parametrize("event_kind", ["SubagentStop", "PostToolUse"])
async def test_missing_subagent_identity_is_durable_without_annotation(
    tmp_path: Path,
    event_kind: str,
) -> None:
    from types import SimpleNamespace

    from builders.ledger_adapters import FixedClock

    local, workspace, session, mapping = _mapped_local(tmp_path, "missing-subagent")
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": mapping.yoetz_task_id, "owner_generation": "1"})
    task_store = SqliteObservationStore(db)
    runtime = SimpleNamespace(
        task_id=mapping.yoetz_task_id,
        session_id=mapping.yoetz_session_id,
        writer_id=observation_writer_id(mapping.yoetz_task_id, mapping.yoetz_session_id),
        observation=task_store,
    )

    class RuntimePort:
        async def route(self, command: object) -> object:
            del command
            return runtime

        async def release(self, released: object) -> None:
            del released

    class Registry:
        async def record_host_lineage_observation(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("missing identity must not create an annotation")

    append_request_id = PREFIX_BY_KIND[IdKind.REQUEST] + str(uuid.uuid4())

    class Coordinator(ObservationCoordinator):
        async def _append_materialized(self, *args: object, **kwargs: object) -> tuple[object, ...]:  # type: ignore[override]
            batch = cast(MaterializedObservationBatch, args[2])
            return (
                append_request_id,
                canonical_digest({"missing_identity_test": True}),
                None,
                MATERIALIZATION_MAPPING_VERSION,
                tuple(item.role for item in batch.drafts),
            )

        async def _enqueue_verification(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            pass

        async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            pass

    coordinator = Coordinator(
        runtime=RuntimePort(),  # type: ignore[arg-type]
        local=local,
        clock=FixedClock(),
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        host_lineage_registry=Registry(),  # type: ignore[arg-type]
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )
    envelope = replace(
        _envelope(session=session, kind=event_kind, identity="hook:missing-subagent"),
        structural_payload=JsonObject(
            {"lineage_child_task_id": mapping.yoetz_task_id} if event_kind == "PostToolUse" else {}
        ),
    )
    try:
        for expected in (
            ObservationIngestDisposition.ACCEPTED,
            ObservationIngestDisposition.DUPLICATE,
        ):
            result = await coordinator.ingest_request(
                ObservationIngestRequest(codex_session_id="missing-subagent", envelope=envelope)
            )
            assert result.disposition is expected, result.reason
        reloaded = LocalObservationStore(_state=tmp_path)
        status = reloaded.status(ObservationStatusQuery(workspace))
        assert ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value in status.gaps
        retained = task_store.list_envelopes(workspace)
        assert len(retained) == 1
        assert retained[0].gap_codes == (ObservationGapCode.MISSING_SUBAGENT_IDENTITY.value,)
    finally:
        db.close(force=True)


@pytest.mark.anyio
async def test_strong_subagent_pair_never_replays_a_legacy_child_only_operation(
    tmp_path: Path,
) -> None:
    from types import SimpleNamespace

    from builders.ledger_adapters import FixedClock

    task = _task_id()
    writer = PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4())
    envelope = replace(
        _envelope(session="hmac-sha256:" + "ab" * 32, kind="SubagentStart"),
        structural_payload=JsonObject({"subagent_id": "worker", "parent_tool_call_id": "call-b"}),
    )
    batch = materialize_observation_envelope(envelope, task_id=task)
    roles = tuple(item.role for item in batch.drafts)
    legacy_digest = observation_operation_digest(
        task_id=task,
        logical_identity=canonical_logical_identity(envelope, mapping_version="obs-ledger/1.6.0"),
        draft_roles=roles,
        mapping_version="obs-ledger/1.6.0",
    )
    coordinator = ObservationCoordinator(
        runtime=object(),  # type: ignore[arg-type]
        local=LocalObservationStore(_state=tmp_path),
        clock=FixedClock(),
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
    )
    legacy_id = coordinator._stable_operation_id(legacy_digest)  # pyright: ignore[reportPrivateUsage]
    looked_up: list[str] = []

    class Ledger:
        async def lookup_task_operation(self, writer_id: str, operation_id: str) -> object | None:
            del writer_id
            looked_up.append(operation_id)
            return (
                SimpleNamespace(request_digest=legacy_digest) if operation_id == legacy_id else None
            )

        async def lookup_operation(self, writer_id: str, operation_id: str) -> None:
            del writer_id
            looked_up.append(operation_id)
            return None

    runtime = SimpleNamespace(
        task_id=task,
        session_id=PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4()),
        writer_id=writer,
        ledger=Ledger(),
    )
    # If only old replay is authorized, ambiguity fails closed instead of returning an
    # unrelated invocation. Normal ingestion may append the current stronger identity.
    with pytest.raises(PublicOperationError) as error:
        await coordinator._append_materialized(  # pyright: ignore[reportPrivateUsage]
            cast(TaskRuntime, runtime),
            envelope,
            batch,
            replay_required=True,
            replay_claims=(((legacy_digest, legacy_id, "obs-ledger/1.6.0"), roles),),
        )
    assert error.value.code is PublicErrorCode.SESSION_NOT_FOUND
    assert legacy_id not in looked_up


@pytest.mark.anyio
async def test_subagent_advice_references_annotation_then_bound_child(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from builders.ledger_adapters import FixedClock

    parent = _task_id()
    child = _task_id()
    correlation = "hmac-sha256:" + "cd" * 32
    envelope = replace(
        _envelope(session="hmac-sha256:" + "ab" * 32, kind="SubagentStop"),
        structural_payload=JsonObject({"subagent_id": "worker", "parent_tool_call_id": "call-a"}),
    )
    annotation = SimpleNamespace(correlation_id=correlation, bound_child_task_id=None)

    class Registry:
        async def find_host_lineage_observation(
            self, parent_task_id: str, observation: object
        ) -> object:
            del observation
            assert parent_task_id == parent
            return annotation

    coordinator = ObservationCoordinator(
        runtime=object(),  # type: ignore[arg-type]
        local=LocalObservationStore(_state=tmp_path),
        clock=FixedClock(),
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        host_lineage_registry=Registry(),  # type: ignore[arg-type]
    )
    assert await coordinator._lineage_refs_for_advice(  # pyright: ignore[reportPrivateUsage]
        parent, (envelope,)
    ) == ((envelope.source_identity, correlation),)
    annotation.bound_child_task_id = child
    assert await coordinator._lineage_refs_for_advice(  # pyright: ignore[reportPrivateUsage]
        parent, (envelope,)
    ) == ((envelope.source_identity, child),)


@pytest.mark.anyio
async def test_native_activity_releases_runtime_before_lineage_callback(tmp_path: Path) -> None:
    """A callback waiting on lineage cannot retain the runtime that attach needs to rebind."""

    import asyncio
    from types import SimpleNamespace

    from builders.ledger_adapters import FixedClock

    local, workspace, session, mapping = _mapped_local(tmp_path, "native-activity-release")
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": mapping.yoetz_task_id, "owner_generation": "1"})
    store = SqliteObservationStore(db)
    clock = FixedClock()
    runtime = SimpleNamespace(
        task_id=mapping.yoetz_task_id,
        session_id=mapping.yoetz_session_id,
        writer_id=observation_writer_id(mapping.yoetz_task_id, mapping.yoetz_session_id),
        observation=store,
    )
    released = asyncio.Event()
    calls: list[tuple[str, str, str]] = []

    class RuntimePort:
        async def route(self, command: object) -> object:
            del command
            return runtime

        async def release(self, value: object) -> None:
            assert value is runtime
            released.set()

    async def renew(task_id: str, session_id: str, writer_id: str, observed_at: object) -> None:
        # This event stands for attach's runtime-drained condition. Awaiting it while
        # retaining the ingest runtime would deterministically deadlock until the deadline.
        async with asyncio.timeout(1):
            await released.wait()
        assert observed_at == clock.now_utc()
        calls.append((task_id, session_id, writer_id))

    class Coordinator(ObservationCoordinator):
        async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            pass

    coordinator = Coordinator(
        runtime=RuntimePort(),  # type: ignore[arg-type]
        local=local,
        clock=clock,
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        observed_activity_hook=renew,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )
    from yoetz.domain.values import timestamp_from_datetime

    envelope = replace(
        _envelope(session=session, kind="SubagentStart", identity="hook:activity-release"),
        structural_payload=JsonObject({}),
        receipt_time=timestamp_from_datetime(clock.now_utc()),
    )
    request = ObservationIngestRequest(
        codex_session_id="native-activity-release", envelope=envelope
    )
    try:
        accepted = await coordinator.ingest_request(request)
        assert accepted.disposition is ObservationIngestDisposition.ACCEPTED
        # The first admitted native event persists its exact host-session route before any
        # optional verification/advice work. A fresh READY generation can bootstrap this row.
        assert (
            store.codex_session_commitment_for_session(
                workspace=workspace,
                yoetz_session_id=mapping.yoetz_session_id,
            )
            == session
        )
        assert calls == [(mapping.yoetz_task_id, mapping.yoetz_session_id, mapping.yoetz_writer_id)]
        duplicate = await coordinator.ingest_request(request)
        assert duplicate.disposition is ObservationIngestDisposition.DUPLICATE
        # The duplicate re-offers the same evidence time; lineage applies it idempotently.
        assert len(calls) == 2 and calls[0] == calls[1]
    finally:
        db.close(force=True)


@pytest.mark.anyio
async def test_ended_predecessor_cannot_seed_successor_host_route(tmp_path: Path) -> None:
    """A rewritten ended mapping stays structural and cannot bind the successor host lane."""

    from types import SimpleNamespace

    from builders.ledger_adapters import FixedClock

    local = LocalObservationStore(_state=tmp_path)
    workspace = local.workspace_commitment(str(tmp_path.resolve()))
    local.grant_consent(workspace)
    predecessor_codex_id = "native-predecessor-route"
    current_codex_id = "native-current-route"
    predecessor_commitment = local.bind_codex_session(workspace, predecessor_codex_id)
    current_commitment = local.bind_codex_session(workspace, current_codex_id)
    local.note_session_end(workspace, predecessor_commitment)

    task = _task_id()
    current_session_id = PREFIX_BY_KIND[IdKind.SESSION] + str(uuid.uuid4())
    current_writer_id = PREFIX_BY_KIND[IdKind.WRITER] + str(uuid.uuid4())
    predecessor_mapping = LifecycleMapping(
        mapping_version=1,
        codex_session_id=predecessor_codex_id,
        yoetz_task_id=task,
        # Lifecycle recovery rewrites the ended predecessor's mapping to this successor route.
        yoetz_session_id=current_session_id,
        yoetz_writer_id=current_writer_id,
        last_frontier=None,
    )
    current_mapping = replace(predecessor_mapping, codex_session_id=current_codex_id)

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": task, "owner_generation": "1"})
    store = SqliteObservationStore(db)
    store.grant_consent(workspace, Timestamp("2026-01-01T00:00:00.000Z"))
    store.bind_session(workspace, predecessor_commitment)
    store.bind_session(workspace, current_commitment)
    runtime = SimpleNamespace(
        task_id=task,
        session_id=current_session_id,
        writer_id=observation_writer_id(task, current_session_id),
        observation=store,
    )
    calls: list[tuple[str, str, str]] = []

    class RuntimePort:
        async def route(self, command: object) -> object:
            del command
            return runtime

        async def release(self, value: object) -> None:
            assert value is runtime

    async def renew(task_id: str, session_id: str, writer_id: str, observed_at: object) -> None:
        del observed_at
        calls.append((task_id, session_id, writer_id))

    class Coordinator(ObservationCoordinator):
        async def _run_advice(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            pass

        async def _append_materialized(  # type: ignore[override]
            self, *args: object, **kwargs: object
        ) -> None:
            # Keep this regression focused on route admission and the verification worker's
            # idempotent route write; ledger projection is covered by the surrounding suite.
            del args, kwargs
            return None

    def load_mapping_for_session(
        codex_session_id: str, *, _state: Path | None = None
    ) -> LifecycleMapping:
        del _state
        return predecessor_mapping if codex_session_id == predecessor_codex_id else current_mapping

    coordinator = Coordinator(
        runtime=RuntimePort(),  # type: ignore[arg-type]
        local=local,
        clock=FixedClock(),
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        observed_activity_hook=renew,
        mapping_loader=load_mapping_for_session,
    )

    def post_tool_envelope(session: str, identity: str) -> ObservationEnvelope:
        return replace(
            _envelope(session=session, kind="PostToolUse", identity=identity, exit_status=0),
            receipt_time=Timestamp("2026-07-19T12:00:00.000Z"),
        )

    def subagent_start_envelope(session: str, identity: str) -> ObservationEnvelope:
        return replace(
            _envelope(session=session, kind="SubagentStart", identity=identity),
            structural_payload=JsonObject({}),
            receipt_time=Timestamp("2026-07-19T12:00:00.000Z"),
        )

    try:
        predecessor_first = await coordinator.ingest_request(
            ObservationIngestRequest(
                codex_session_id=predecessor_codex_id,
                envelope=post_tool_envelope(predecessor_commitment, "hook:early-predecessor"),
            )
        )
        assert predecessor_first.disposition is ObservationIngestDisposition.ACCEPTED
        assert calls == []
        assert (
            store.codex_session_commitment_for_session(
                workspace=workspace,
                yoetz_session_id=current_session_id,
            )
            is None
        )

        current = await coordinator.ingest_request(
            ObservationIngestRequest(
                codex_session_id=current_codex_id,
                envelope=subagent_start_envelope(current_commitment, "hook:current-route"),
            )
        )
        assert current.disposition is ObservationIngestDisposition.ACCEPTED
        assert calls == [(task, current_session_id, current_writer_id)]
        assert (
            store.codex_session_commitment_for_session(
                workspace=workspace,
                yoetz_session_id=current_session_id,
            )
            == current_commitment
        )

        # The old host event follows the rewritten mapping to the successor runtime. The local
        # ended-session authority and the original mapping identity fence must win before route
        # persistence or lineage liveness can see it.
        predecessor = await coordinator.ingest_request(
            ObservationIngestRequest(
                codex_session_id=predecessor_codex_id,
                envelope=post_tool_envelope(predecessor_commitment, "hook:late-predecessor-route"),
            )
        )
        assert predecessor.disposition is ObservationIngestDisposition.ACCEPTED
        assert calls == [(task, current_session_id, current_writer_id)]
        assert (
            store.codex_session_commitment_for_session(
                workspace=workspace,
                yoetz_session_id=current_session_id,
            )
            == current_commitment
        )
    finally:
        coordinator.close()
        db.close(force=True)


@pytest.mark.anyio
@pytest.mark.parametrize("cancelled", [False, True])
async def test_ingest_releases_runtime_when_final_backlog_feedback_fails(
    tmp_path: Path, cancelled: bool
) -> None:
    """Final feedback failure or repeated cancellation cannot strand an ingestion lease."""
    import asyncio
    from types import SimpleNamespace

    local, _workspace, session, mapping = _mapped_local(tmp_path, "backlog-release")

    class _Store:
        def load_capture_ticket(self, *, workspace: str, logical_identity: str) -> None:
            # This structural-only fixture has no staged native capture to recover.
            del workspace, logical_identity
            return None

        def grant_consent(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def bind_session(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        async def ingest(self, envelope: ObservationEnvelope) -> ObservationIngestResult:
            return ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED,
                None,
                envelope.cursor,
            )

    runtime = SimpleNamespace(
        task_id=mapping.yoetz_task_id,
        session_id=mapping.yoetz_session_id,
        writer_id=observation_writer_id(mapping.yoetz_task_id, mapping.yoetz_session_id),
        observation=_Store(),
    )

    released_runtimes: list[object] = []
    feedback_entered = asyncio.Event()
    release_entered = asyncio.Event()
    release_gate = asyncio.Event()
    release_finished = asyncio.Event()

    class _RuntimePort:
        async def route(self, command: object) -> object:
            del command
            return runtime

        async def release(self, released: object) -> None:
            assert released is runtime
            release_entered.set()
            if cancelled:
                await release_gate.wait()
            released_runtimes.append(released)
            release_finished.set()

    class _Coordinator(ObservationCoordinator):
        async def _publish_capture_backlog(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
            del args, kwargs
            if cancelled:
                feedback_entered.set()
                await asyncio.Event().wait()
            raise RuntimeError("feedback unavailable")

        async def _capture_content(  # type: ignore[override]
            self, runtime: object, store: object, **kwargs: object
        ) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...], bool, bool]:
            del runtime, store, kwargs
            return (), (), False, False

        async def _append_materialized(  # type: ignore[override]
            self, *args: object, **kwargs: object
        ) -> tuple[str, str, None, str, tuple[str, ...]]:
            del args, kwargs
            raise PublicOperationError(
                PublicErrorCode.EVENT_INVALID,
                "Observation event was rejected.",
                retryable=False,
            )

    coordinator = _Coordinator(
        runtime=_RuntimePort(),  # type: ignore[arg-type]
        local=local,
        clock=object(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
        mapping_loader=lambda *_args, **_kwargs: mapping,  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
    )

    ingest = asyncio.create_task(
        coordinator.ingest_request(
            ObservationIngestRequest(
                codex_session_id=mapping.codex_session_id,
                envelope=_envelope(
                    session=session,
                    kind="PostToolUse",
                    identity="hook:event-invalid",
                    exit_status=1,
                ),
            )
        )
    )
    if cancelled:
        await asyncio.wait_for(feedback_entered.wait(), timeout=5)
        ingest.cancel()
        await asyncio.wait_for(release_entered.wait(), timeout=5)
        ingest.cancel()
    with pytest.raises(asyncio.CancelledError if cancelled else RuntimeError):
        await ingest
    if cancelled:
        # Repeated cancellation unwinds the caller; the retained release still finishes.
        assert len(coordinator._pending_releases) == 1  # pyright: ignore[reportPrivateUsage]
    release_gate.set()
    await asyncio.wait_for(release_finished.wait(), timeout=5)
    assert released_runtimes == [runtime]


@pytest.mark.anyio
@pytest.mark.parametrize("policy_bytes", [None, b"not = [valid"])
async def test_verification_worker_records_no_capture_gap_for_an_absent_check_policy(
    tmp_path: Path, policy_bytes: bytes | None
) -> None:
    """No `.yoetz/checks.toml` is the ordinary opt-in state, not lost content capture (tb4v1).

    A present-but-broken policy still records the conservative capture gap, so this test fails if
    the absent branch is deleted or widened.
    """

    import base64
    from types import SimpleNamespace

    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    subprocess.run(["git", "init", "-q", str(workspace_root)], check=True)
    if policy_bytes is not None:
        (workspace_root / ".yoetz").mkdir()
        (workspace_root / ".yoetz" / "checks.toml").write_bytes(policy_bytes)
    locator = canonical_encode(
        {
            "content_kind": "workspace_locator",
            "content_b64": base64.b64encode(str(workspace_root).encode()).decode("ascii"),
        }
    )

    class _Objects:
        async def resolve_verified(self, *descriptor: object) -> object:
            return descriptor

        async def open_verified(self, _ref: object):
            yield locator

    noted: list[str] = []

    class _Local:
        def note_coverage_gap(self, _workspace: str, code: str) -> None:
            noted.append(code)

    def _unused(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("not reached before the policy gate")

    def _descriptor(_workspace: str) -> tuple[str, str]:
        return ("obj", "digest")

    store = SimpleNamespace(
        workspace_locator_descriptor=_descriptor,
        verification_repository=_unused,
        latest_verification_subject_digest=_unused,
        policy_digest_is_trusted=_unused,
        record_trusted_check_policy=_unused,
    )
    runtime = SimpleNamespace(
        task_id=_task_id(), session_id="ses", writer_id="wri", objects=_Objects()
    )
    coordinator = ObservationCoordinator(
        runtime=object(),  # type: ignore[arg-type]
        local=_Local(),  # type: ignore[arg-type]
        clock=object(),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        state_root=tmp_path,
    )

    worker = await coordinator._prepare_verification_worker(  # pyright: ignore[reportPrivateUsage]
        cast(TaskRuntime, runtime),
        "hmac-sha256:" + "8" * 64,
        cast(TaskObservationPort, store),
        _envelope(session=f"hmac-sha256:{'9' * 64}", kind="PostToolUse"),
    )

    assert worker is None
    if policy_bytes is None:
        assert noted == []
    else:
        assert noted == [ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value]
