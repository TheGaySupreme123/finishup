"""Decisive acceptance scenarios: observation + advice without cooperative MCP publications."""

from __future__ import annotations

import io
import json
import shutil
from collections.abc import Mapping
from pathlib import Path

import pytest

from builders.codex_rollout import failed_shell_rollout
from finishup.adapters.approved_checks import (
    ApprovedCheckApproval,
    ApprovedCheckCommand,
    ApprovedCheckOutcome,
    ApprovedCheckRunner,
    ApprovedCheckStatus,
    approval_commitment,
)
from finishup.adapters.integrations.codex_session_stream import (
    SessionStreamReader,
    default_stream_profile,
)
from finishup.adapters.integrations.observation_local import (
    STREAM_MAPPING_VERSION,
    LocalObservationStore,
)
from finishup.adapters.memory.observation import MemoryObservationStore
from finishup.adapters.observation_semantic_advice import NullSemanticAdvice, OptionalSemanticAdvice
from finishup.adapters.workspace_inspect import open_inspect_workspace
from finishup.application.observation_advice import (
    ObservationAdviceBuildInput,
    build_observation_advice_snapshot,
    minimized_semantic_evidence_packet,
)
from finishup.application.observation_control import build_observation_support_handlers
from finishup.cli.observe_hooks import handle_observe, map_hook_payload_to_envelope
from finishup.domain.observation import (
    ObservationControlCommand,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestResult,
    ObservationLifecycle,
    ObservationSource,
    ObservationStatusQuery,
    observation_ingest_result_to_json,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.kernel.policies.observation_advice import (
    ObservationAdviceContext,
    ObservationCheckFact,
    ObservationCompositionFact,
    observation_advice_findings,
)
from finishup.ports.control import ControlMethod

_COMMITMENT = "hmac-sha256:" + "a" * 64
_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64
_TIME = Timestamp("2026-07-22T21:00:00.000Z")
_EMPTY = "hmac-sha256:" + ("0" * 64)
_SECRET = "AWS_SECRET=should-never-appear"
_PASSWORD = "password=hunter2"
_TRUE = shutil.which("true") or "/usr/bin/true"


def _cursor(pos: int = 1) -> ObservationCursor:
    return ObservationCursor(
        source_generation=1,
        byte_position=pos * 8,
        event_position=pos,
        last_source_commitment=_COMMITMENT,
        mapping_version="codex-obs-hook/1.0.0",
    )


def _envelope(
    identity: str,
    payload: dict[str, object],
    *,
    pos: int = 1,
    kind: str = "PostToolUse",
    gaps: tuple[str, ...] = (),
    source: ObservationSource = ObservationSource.CODEX_HOOK,
) -> ObservationEnvelope:
    return ObservationEnvelope(
        session_commitment=_COMMITMENT,
        event_kind=kind,
        source_identity=identity,
        source=source,
        cursor=_cursor(pos),
        receipt_time=_TIME,
        structural_payload=JsonObject(payload),
        content_object_refs=(),
        gap_codes=gaps,
    )


# ---------------------------------------------------------------------------
# 1. Automatic task attachment without MCP start
# ---------------------------------------------------------------------------


def test_session_start_creates_binding_without_mcp_start(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    out = io.BytesIO()
    code = handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps({"session_id": "auto-attach-1", "source": "startup"}).encode(),
        stdout=out,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    assert code == 0
    bound = store.find_workspace_for_codex_session("auto-attach-1")
    assert bound == workspace
    session = store.session_commitment("auto-attach-1")
    status = store.status(ObservationStatusQuery(workspace))
    assert status.lifecycle in {
        ObservationLifecycle.ACTIVE,
        ObservationLifecycle.DEGRADED,
    }
    payload = json.loads(out.getvalue().decode() or "{}")
    serialized = json.dumps(payload)
    assert "observation" in serialized.lower() or "start" in serialized.lower()
    assert str(tmp_path) not in serialized
    assert session.startswith("hmac-sha256:")


# ---------------------------------------------------------------------------
# 2. Zero cooperative publications → local advice
# ---------------------------------------------------------------------------


def test_zero_cooperative_publications_deterministic_advice(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "zero-coop",
                "tool_name": "shell",
                "exit_status": 1,
                "correlation_id": "c-fail",
            }
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    status = store.status(ObservationStatusQuery(workspace))
    assert status.source_coverage[ObservationSource.CODEX_HOOK] is True
    assert status.advice_frontier is not None
    snapshot = store.refresh_advice(workspace)
    assert snapshot is not None
    assert snapshot.ranked_finding_ids
    assert snapshot.recommended_next_action == "resolve_failed_command"


# ---------------------------------------------------------------------------
# 3. Vault/service outage and recovery — nonblocking, degraded, no plaintext spool
# ---------------------------------------------------------------------------


def test_vault_outage_nonblocking_degraded_no_plaintext_spool(
    tmp_path: Path,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    # Drain no longer waits for a lifecycle mapping. The coordinator's typed
    # rejection keeps the exact row pending for a later READY-generation sweep.
    class Client:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del body, deadline_ms
            return observation_ingest_result_to_json(
                ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.VAULT_LOCKED.value,
                    None,
                )
            )

        async def close(self) -> None:
            return None

    async def connect(_kind: object):
        return Client()

    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "outage-1",
                "tool_name": "shell",
                "exit_status": 0,
                "stdout": _SECRET,
                "transcript": _PASSWORD,
            }
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect,  # type: ignore[arg-type]
        skip_service=False,
    )
    assert code == 0
    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.VAULT_LOCKED.value in status.gaps
    assert status.source_coverage[ObservationSource.CODEX_HOOK] is True
    # The typed vault_locked rejection is retryable: the exact row must remain
    # pending in the outbox (never dropped, never quarantined).
    assert store.pending_outbox_count(workspace) == 1
    assert store.quarantined_count(workspace) == 0
    pending_envelope = store.list_pending_outbox(workspace)[0][1]
    # No plaintext spool of secrets under observation state.
    root = tmp_path / "observation"
    if root.is_dir():
        for path in root.rglob("*"):
            if path.is_file():
                raw = path.read_bytes()
                assert _SECRET.encode() not in raw
                assert b"hunter2" not in raw
                assert b"password=" not in raw
    # Recovery: pause/resume, then a real drain against a recovered (accepting)
    # service acknowledges the spooled row and the new event.
    store.pause(ObservationControlCommand(workspace))
    store.resume(ObservationControlCommand(workspace))
    ingested: list[str] = []

    class RecoveredClient:
        async def observation_ingest(self, body: object, *, deadline_ms: int):
            del deadline_ms
            envelope = body["envelope"]  # type: ignore[index]
            ingested.append(str(envelope["source_identity"]))  # type: ignore[index]
            return observation_ingest_result_to_json(
                ObservationIngestResult(
                    ObservationIngestDisposition.ACCEPTED,
                    None,
                    ObservationCursor(
                        source_generation=1,
                        byte_position=0,
                        event_position=len(ingested),
                        last_source_commitment=workspace,
                        mapping_version="v1",
                    ),
                )
            )

        async def close(self) -> None:
            return None

    async def connect_recovered(_kind: object):
        return RecoveredClient()

    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "outage-1",
                "tool_name": "shell",
                "exit_status": 0,
                "event_ordinal": 2,
            }
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=connect_recovered,  # type: ignore[arg-type]
        skip_service=False,
    )
    assert code == 0
    # The previously-rejected envelope was re-driven through the service and
    # acknowledged, alongside the new event; nothing pending or quarantined.
    assert pending_envelope.source_identity in ingested
    assert len(ingested) == 2
    assert store.pending_outbox_count(workspace) == 0
    assert store.quarantined_count(workspace) == 0
    assert store.status(ObservationStatusQuery(workspace)).lifecycle in {
        ObservationLifecycle.ACTIVE,
        ObservationLifecycle.DEGRADED,
    }


def test_structural_lifecycle_envelopes_and_unpaired_gap(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    for event, payload in (
        ("PreCompact", {"session_id": "life-1"}),
        ("PostCompact", {"session_id": "life-1"}),
        ("SessionStart", {"session_id": "life-1", "source": "resume"}),
        ("SubagentStart", {"session_id": "life-1", "subagent_id": "sub-a"}),
        (
            "PermissionRequest",
            {
                "session_id": "life-1",
                "permission_decision": "denied",
                "denied": True,
                "correlation_id": "perm-1",
            },
        ),
        (
            "PostToolUse",
            {
                "session_id": "life-1",
                "tool_name": "shell",
                "correlation_id": "missing-pre",
                "exit_status": 0,
            },
        ),
    ):
        assert (
            handle_observe(
                event_name=event,
                stdin_bytes=json.dumps(payload).encode(),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
            )
            == 0
        )
    status = store.status(ObservationStatusQuery(workspace))
    assert status.source_coverage[ObservationSource.CODEX_HOOK] is True
    assert ObservationGapCode.UNPAIRED_EVENT.value in status.gaps


# ---------------------------------------------------------------------------
# 5. Approved checks bound to exact pre/post-edit state
# ---------------------------------------------------------------------------


def test_approved_check_stale_when_digest_changes(tmp_path: Path) -> None:
    handle = open_inspect_workspace(tmp_path)
    argv = (_TRUE,)
    commitment = approval_commitment("pytest-accept", argv, allow_network=False)
    approval = ApprovedCheckApproval(
        approval_id="pytest-accept",
        argv=argv,
        allow_network=False,
        timeout_seconds=10.0,
        approval_commitment=commitment,
    )
    runner = ApprovedCheckRunner({commitment: approval})
    ok = runner.run(
        ApprovedCheckCommand(
            workspace=handle,
            approval=approval,
            subject_state_digest=_DIGEST_A,
            expected_subject_state_digest=_DIGEST_A,
        )
    )
    assert ok.status is ApprovedCheckStatus.PASSED
    stale = runner.run(
        ApprovedCheckCommand(
            workspace=handle,
            approval=approval,
            subject_state_digest=_DIGEST_B,
            expected_subject_state_digest=_DIGEST_A,
        )
    )
    assert stale.status is ApprovedCheckStatus.STALE
    assert stale.outcome is ApprovedCheckOutcome.SUBJECT_STATE_MISMATCH
    rules = {
        item.rule_code
        for item in observation_advice_findings(
            ObservationAdviceContext(
                envelopes=(
                    _envelope(
                        "hook:edit",
                        {"tool_name": "apply_patch", "action": "write"},
                        pos=5,
                    ),
                ),
                lifecycle=ObservationLifecycle.ACTIVE,
                gaps=(),
                check_facts=(
                    ObservationCheckFact(
                        approval_commitment=commitment,
                        subject_state_digest=_DIGEST_A,
                        status="passed",
                        cursor_event_position=2,
                    ),
                ),
            )
        )
    }
    assert "edit_after_successful_check" in rules


# ---------------------------------------------------------------------------
# 6. Local-only vs configured AI-powered review
# ---------------------------------------------------------------------------


def test_deterministic_only_and_configured_semantic_additive() -> None:
    envelopes = (
        _envelope("hook:fail", {"tool_name": "shell", "exit_status": 1, "correlation_id": "x1"}),
    )
    candidates = observation_advice_findings(
        ObservationAdviceContext(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    packet = minimized_semantic_evidence_packet(candidates, _DIGEST_A)
    assert "transcript" not in packet
    assert NullSemanticAdvice().review(evidence_packet=packet) is None
    deterministic = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    assert deterministic is not None
    assert len(deterministic.ranked_finding_ids) >= 1

    def _eval(payload: Mapping[str, object]) -> Mapping[str, object]:
        assert "transcript" not in payload
        assert _SECRET not in json.dumps(payload)
        return {"detail_token": "sem-1", "next_action": "reground_status"}

    addon = OptionalSemanticAdvice(configured=True, ready=True, evaluator=_eval).review(
        evidence_packet=packet
    )
    assert addon is not None
    with_semantic = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            semantic_addon=addon,
            has_real_observation=True,
            composition=ObservationCompositionFact(
                semantic_configured=True,
                semantic_ready=True,
                provider_factory_ids=("openai",),
                connected_provider_ids=("openai",),
            ),
        )
    )
    assert with_semantic is not None
    assert len(with_semantic.ranked_finding_ids) >= len(deterministic.ranked_finding_ids)


# ---------------------------------------------------------------------------
# 7. First publication fails but tracking continues
# ---------------------------------------------------------------------------


def test_first_publication_fails_tracking_continues(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "pub-fail",
                "tool_name": "publish_work",
                "claim_kind": "completion",
                "exit_status": 1,
                "success": False,
            }
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    after_fail = store.refresh_advice(workspace)
    assert after_fail is not None
    assert after_fail.ranked_finding_ids
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "pub-fail",
                "tool_name": "shell",
                "exit_status": 1,
                "correlation_id": "retry-1",
                "event_ordinal": 2,
            }
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    status = store.status(ObservationStatusQuery(workspace))
    assert status.source_coverage[ObservationSource.CODEX_HOOK] is True
    envelopes = store.list_envelopes(workspace)
    assert len(envelopes) >= 2
    snapshot = store.refresh_advice(workspace)
    assert snapshot is not None
    assert snapshot.ranked_finding_ids


# ---------------------------------------------------------------------------
# 8. Edits after green tests → stale verification advice
# ---------------------------------------------------------------------------


def test_edits_after_green_tests_stale_verification_advice(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {"session_id": "stale-1", "tool_name": "pytest", "exit_status": 0}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "stale-1",
                "tool_name": "apply_patch",
                "action": "write",
                "changed_paths_digest": _DIGEST_B,
                "event_ordinal": 2,
            }
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    snapshot = store.refresh_advice(workspace)
    assert snapshot is not None
    rules = {
        item.rule_code
        for item in observation_advice_findings(
            ObservationAdviceContext(
                envelopes=store.list_envelopes(workspace),
                lifecycle=ObservationLifecycle.ACTIVE,
                gaps=(),
            )
        )
    }
    assert "edit_after_successful_check" in rules
    assert snapshot.recommended_next_action


# ---------------------------------------------------------------------------
# 9. Completion claim without live provider request → advice
# ---------------------------------------------------------------------------


def test_completion_without_live_provider_request_advice() -> None:
    envelopes = (
        _envelope(
            "hook:claim",
            {"tool_name": "publish_work", "claim_kind": "completion"},
        ),
    )
    rules = {
        item.rule_code
        for item in observation_advice_findings(
            ObservationAdviceContext(
                envelopes=envelopes,
                lifecycle=ObservationLifecycle.ACTIVE,
                gaps=(),
                check_facts=(),
            )
        )
    }
    assert "completion_without_verification" in rules
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    assert snapshot.ranked_finding_ids


# ---------------------------------------------------------------------------
# 10. Subagent reports defect main agent omits → advice
# ---------------------------------------------------------------------------


def test_subagent_defect_omitted_by_main_agent_advice(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    handle_observe(
        event_name="SubagentStop",
        stdin_bytes=json.dumps(
            {
                "session_id": "sub-1",
                "subagent_id": "reviewer",
                "result_status": "finding",
                "success": False,
            }
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    # Main agent Stop with no acknowledgement of the finding.
    handle_observe(
        event_name="Stop",
        stdin_bytes=json.dumps({"session_id": "sub-1"}).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    rules = {
        item.rule_code
        for item in observation_advice_findings(
            ObservationAdviceContext(
                envelopes=store.list_envelopes(workspace),
                lifecycle=ObservationLifecycle.ACTIVE,
                gaps=(),
            )
        )
    }
    assert "subagent_finding_unaddressed" in rules
    snapshot = store.refresh_advice(workspace)
    assert snapshot is not None


# ---------------------------------------------------------------------------
# 11. Hooks miss event; stream reconciliation restores it
# ---------------------------------------------------------------------------


def test_stream_reconciliation_restores_missed_hook_event(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment("stream-restore")
    store.bind_session(workspace, session)
    path = tmp_path / "session.jsonl"
    path.write_bytes(failed_shell_rollout())
    reader = SessionStreamReader(
        session_commitment=session,
        profile=default_stream_profile(),
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=0,
            event_position=0,
            last_source_commitment=_EMPTY,
            mapping_version=STREAM_MAPPING_VERSION,
        ),
        key_material=store.key_material(),
    )
    advance = reader.advance(path)
    assert len(advance.envelopes) >= 1
    for envelope in advance.envelopes:
        result = store.ingest(envelope)
        assert result.disposition.value in {"accepted", "duplicate"}
    status = store.status(ObservationStatusQuery(workspace))
    assert status.source_coverage[ObservationSource.CODEX_SESSION_STREAM] is True
    snapshot = store.refresh_advice(workspace)
    assert snapshot is not None


# ---------------------------------------------------------------------------
# 12. Unknown future fields → coverage gaps without stopping observation
# ---------------------------------------------------------------------------


def test_unknown_future_fields_record_gaps_continue_observation(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.session_commitment("future-1")
    envelope = map_hook_payload_to_envelope(
        "FutureHostEvent",
        {"session_id": "future-1", "novel_field": "ignored-prose"},
        session_commitment=session,
        event_ordinal=1,
        key_material=store.key_material(),
        gap_codes=(ObservationGapCode.UNSUPPORTED_EVENT.value,),
    )
    store.bind_session(workspace, session)
    assert store.ingest(envelope).disposition.value == "accepted"
    # Later supported event still accepted.
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {"session_id": "future-1", "tool_name": "shell", "exit_status": 0}
        ).encode(),
        stdout=io.BytesIO(),
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    status = store.status(ObservationStatusQuery(workspace))
    assert ObservationGapCode.UNSUPPORTED_EVENT.value in status.gaps
    assert status.source_coverage[ObservationSource.CODEX_HOOK] is True
    assert status.lifecycle in {
        ObservationLifecycle.ACTIVE,
        ObservationLifecycle.DEGRADED,
    }


# ---------------------------------------------------------------------------
# 13. Secret-like command output never appears in status/logs/advice/AI-powered review
# ---------------------------------------------------------------------------


def test_secrets_absent_from_status_advice_logs_and_semantic(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    out = io.BytesIO()
    handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(
            {
                "session_id": "secret-1",
                "tool_name": "shell",
                "exit_status": 1,
                "stdout": _SECRET,
                "stderr": _PASSWORD,
                "transcript": "hidden reasoning with " + _PASSWORD,
            }
        ).encode(),
        stdout=out,
        workspace=str(tmp_path),
        _state=tmp_path,
        skip_service=True,
    )
    status = store.status(ObservationStatusQuery(workspace))
    status_text = json.dumps(
        {
            "lifecycle": status.lifecycle.value,
            "gaps": list(status.gaps),
            "advice": status.advice_frontier,
        }
    )
    hook_out = out.getvalue().decode()
    snapshot = store.refresh_advice(workspace)
    assert snapshot is not None
    advice_text = repr(snapshot)
    candidates = observation_advice_findings(
        ObservationAdviceContext(
            envelopes=store.list_envelopes(workspace),
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
        )
    )
    packet = minimized_semantic_evidence_packet(candidates, _DIGEST_A)
    packet_text = json.dumps(packet)
    for surface in (
        status_text,
        hook_out,
        advice_text,
        packet_text,
        repr(store.list_envelopes(workspace)),
    ):
        assert "AWS_SECRET" not in surface
        assert "hunter2" not in surface
        assert "password=" not in surface.lower()


# ---------------------------------------------------------------------------
# Service wiring: observation_* handlers call a durable ObservationPort
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_observation_support_handlers_call_memory_port() -> None:
    port = MemoryObservationStore()
    handlers = build_observation_support_handlers(port)
    assert ControlMethod.OBSERVATION_INGEST in handlers
    port.grant_consent(_COMMITMENT, _TIME)
    envelope = _envelope("hook:svc", {"tool_name": "shell", "exit_status": 0})
    port.bind_session(_COMMITMENT, envelope.session_commitment)
    from finishup.domain.observation import observation_envelope_to_json

    result = await handlers[ControlMethod.OBSERVATION_INGEST](
        observation_envelope_to_json(envelope)
    )
    assert result["disposition"] == "accepted"
    status = await handlers[ControlMethod.OBSERVATION_STATUS]({"workspace_commitment": _COMMITMENT})
    assert status["lifecycle"] == "active"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
