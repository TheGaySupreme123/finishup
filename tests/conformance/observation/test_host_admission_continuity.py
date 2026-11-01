"""Persisted host-admission continuity rows for the #497/#509 matrix.

These scenarios cross the real local observation store, lifecycle mapping files,
hook auto-admission, and outbox drain.  The service client is a bounded typed
double: the assertions are about the persisted host state and the exact public
requests/ingest body that the hook emits, not about a private scan helper.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import observe_hooks
from finishup.cli.observe_hooks import ServiceConnector, handle_observe
from finishup.domain.observation import (
    OBSERVATION_CONTENT_CAPTURE_PENDING_REASON,
    ObservationIngestDisposition,
    ObservationIngestResult,
    observation_cursor_from_json,
    observation_ingest_result_to_json,
)
from finishup.domain.values import JsonObject, JsonValue
from finishup.ports.control import ControlClientKind
from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.models import OperationFailureModel, StartRequest

pytestmark = pytest.mark.anyio


_TASK_A = "tsk_4b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5b"
_TASK_B = "tsk_5b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5b"
_OLD_FINISHUP_SESSION = "ses_4b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5c"
_OLD_WRITER = "wri_4b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5d"
_SUCCESSOR_FINISHUP_SESSION = "ses_5b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5c"
_SUCCESSOR_WRITER = "wri_5b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5d"


def _persist_mapping(
    *,
    store: LocalObservationStore,
    workspace: str,
    state: Path,
    host_session: str,
    task_id: str,
) -> None:
    commitment = store.bind_codex_session(workspace, host_session)
    store.note_session_end(workspace, commitment)
    observe_hooks.store_mapping(
        observe_hooks.mapping_from_start_ids(
            codex_session_id=host_session,
            finishup_task_id=task_id,
            finishup_session_id=_OLD_FINISHUP_SESSION,
            finishup_writer_id=_OLD_WRITER,
            last_frontier=None,
        ),
        _state=state,
    )


class _ContinuityClient:
    """Typed start/ingest double that records the hook's public boundary calls."""

    def __init__(self, *, predecessor: str, task_id: str) -> None:
        self.predecessor = predecessor
        self.task_id = task_id
        self.start_requests: list[StartRequest] = []
        self.capture_bodies: list[JsonObject] = []
        self.ingest_bodies: list[JsonObject] = []

    async def start(self, request: object, *, deadline_ms: int | None = None) -> object:
        del deadline_ms
        assert isinstance(request, StartRequest)
        self.start_requests.append(request)
        if request.mode == "create_or_attach":
            return OperationFailureModel.model_validate(
                {
                    "protocol_version": "0.1",
                    "schema_version": "1.0.0",
                    "ok": False,
                    "error": {
                        "code": PublicErrorCode.SESSION_CONFLICT.value,
                        "message": "workspace occupied",
                        "retryable": False,
                        "correlation_id": "cor_4b4e28ba-2fa1-4d3b-8f0a-0c1d2e3f4a5e",
                        "safe_details": {"reason_code": "workspace_task_exists"},
                    },
                }
            )
        assert request.mode == "attach"
        # The attach selector is the persisted FinishUP session id; the host
        # predecessor id remains the route key for the pending observation row.
        assert request.session_id == _OLD_FINISHUP_SESSION
        return SimpleNamespace(
            ok=True,
            frontier=SimpleNamespace(sequence="4", head_digest="sha256:" + "b" * 64),
            task_id=self.task_id,
            session_id=_SUCCESSOR_FINISHUP_SESSION,
            writer_id=_SUCCESSOR_WRITER,
        )

    async def status(self, request: object, *, deadline_ms: int | None = None) -> object:
        del request, deadline_ms
        raise AssertionError("continuity fixture should recover before a status read")

    async def observation_ingest(self, body: JsonValue, *, deadline_ms: int) -> JsonValue:
        del deadline_ms
        assert isinstance(body, JsonObject)
        if body.get("capture_only") is True:
            self.capture_bodies.append(body)
            return observation_ingest_result_to_json(
                ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    OBSERVATION_CONTENT_CAPTURE_PENDING_REASON,
                    None,
                )
            )
        self.ingest_bodies.append(body)
        envelope = body["envelope"]
        assert isinstance(envelope, JsonObject)
        cursor = observation_cursor_from_json(envelope["cursor"])
        return observation_ingest_result_to_json(
            ObservationIngestResult(ObservationIngestDisposition.ACCEPTED, None, cursor)
        )

    async def close(self) -> None:
        return None


def _connector(client: _ContinuityClient) -> ServiceConnector:
    async def connect(_kind: ControlClientKind) -> _ContinuityClient:
        return client

    return connect


def _persist_pending_predecessor(
    *,
    store: LocalObservationStore,
    workspace: str,
    locator: str,
    host_session: str,
    state: Path,
) -> None:
    commitment = store.bind_codex_session(workspace, host_session)
    observe_hooks.store_mapping(
        observe_hooks.mapping_from_start_ids(
            codex_session_id=host_session,
            finishup_task_id=_TASK_A,
            finishup_session_id=_OLD_FINISHUP_SESSION,
            finishup_writer_id=_OLD_WRITER,
            last_frontier=None,
        ),
        _state=state,
    )
    # Use the public hook ingress to materialize the pending row.  The store
    # and mapping are real; ``skip_service`` leaves this predecessor durable
    # without opening a service connection before successor recovery.
    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=json.dumps(
                {
                    "session_id": host_session,
                    "hook_event_name": "PostToolUse",
                    "tool_name": "shell",
                    "exit_status": 1,
                    "correlation_id": "predecessor-pending-row",
                }
            ).encode(),
            stdout=io.BytesIO(),
            workspace=locator,
            _state=state,
            skip_service=True,
        )
        == 0
    )
    store.note_session_end(workspace, commitment)


def test_ambiguous_predecessor_refusal_is_typed_bounded_and_does_not_start(
    tmp_path: Path,
) -> None:
    """Two persisted task bindings refuse recovery without leaking selector identity."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    _persist_mapping(
        store=store,
        workspace=workspace,
        state=tmp_path,
        host_session="codex-ended-a",
        task_id=_TASK_A,
    )
    _persist_mapping(
        store=store,
        workspace=workspace,
        state=tmp_path,
        host_session="codex-ended-b",
        task_id=_TASK_B,
    )
    client = _ContinuityClient(predecessor="codex-ended-a", task_id=_TASK_A)

    assert (
        handle_observe(
            event_name="SessionStart",
            stdin_bytes=json.dumps(
                {"session_id": "codex-successor-ambiguous", "hook_event_name": "SessionStart"}
            ).encode(),
            stdout=io.BytesIO(),
            workspace=locator,
            _state=tmp_path,
            connect=_connector(client),
        )
        == 0
    )

    assert client.start_requests == []
    assert observe_hooks.load_mapping("codex-successor-ambiguous", _state=tmp_path) is None
    diagnostics = tmp_path / "observation" / "hook-diagnostics.jsonl"
    rows: list[object] = [
        json.loads(line) for line in diagnostics.read_text(encoding="utf-8").splitlines()
    ]
    reasons: set[str] = set()
    for row in rows:
        if isinstance(row, dict):
            structural = cast(dict[str, object], row)
            reason = structural.get("reason")
            if isinstance(reason, str):
                reasons.add(reason)
            if reason == "auto_attach_binding_ambiguous":
                assert structural.get("candidate_count") == 2
    assert "auto_attach_binding_ambiguous" in reasons
    raw = diagnostics.read_text(encoding="utf-8")
    for secret in (_TASK_A, _TASK_B, "codex-ended-a", "codex-ended-b"):
        assert secret not in raw


def test_persisted_predecessor_pending_row_drains_after_successor_attach(tmp_path: Path) -> None:
    """Recovery rewrites the persisted predecessor mapping before draining its row."""

    store = LocalObservationStore(_state=tmp_path)
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace)
    predecessor = "codex-ended-pending"
    _persist_pending_predecessor(
        store=store,
        workspace=workspace,
        locator=locator,
        host_session=predecessor,
        state=tmp_path,
    )
    assert len(store.list_pending_outbox_rows(workspace)) == 1
    client = _ContinuityClient(predecessor=predecessor, task_id=_TASK_A)
    assert (
        handle_observe(
            event_name="SessionStart",
            stdin_bytes=json.dumps(
                {"session_id": "codex-successor-pending", "hook_event_name": "SessionStart"}
            ).encode(),
            stdout=io.BytesIO(),
            workspace=locator,
            _state=tmp_path,
            # This is a routing/recovery test with a fake client. Freeze its foreground clock
            # so runner contention cannot exhaust the drain budget between the two rows.
            _monotonic=lambda: 0.0,
            connect=_connector(client),
        )
        == 0
    )

    # A persisted predecessor is already a recovery selector, so admission
    # goes directly through the typed attach route.  A create attempt here
    # would risk opening a second task before the pending row is recovered.
    assert [request.mode for request in client.start_requests] == ["attach"]
    assert client.start_requests[0].session_id == _OLD_FINISHUP_SESSION
    assert client.start_requests[0].workspace_ref == locator
    # SessionStart itself is one durable observation; the predecessor row is
    # the second delivery and must remain addressable by its original host
    # session until the route rewrite has completed.
    assert len(client.ingest_bodies) == 2
    assert len(client.capture_bodies) == 1
    assert client.capture_bodies[0]["envelope"] == client.ingest_bodies[0]["envelope"]
    predecessor_body = next(
        body for body in client.ingest_bodies if body["codex_session_id"] == predecessor
    )
    assert predecessor_body["codex_session_id"] == predecessor
    assert store.list_pending_outbox_rows(workspace) == ()
    successor_mapping = observe_hooks.load_mapping("codex-successor-pending", _state=tmp_path)
    predecessor_mapping = observe_hooks.load_mapping(predecessor, _state=tmp_path)
    assert successor_mapping is not None
    assert successor_mapping.finishup_task_id == _TASK_A
    assert successor_mapping.finishup_session_id == _SUCCESSOR_FINISHUP_SESSION
    assert predecessor_mapping is not None
    assert predecessor_mapping.finishup_session_id == _SUCCESSOR_FINISHUP_SESSION
    assert predecessor_mapping.finishup_writer_id == _SUCCESSOR_WRITER
