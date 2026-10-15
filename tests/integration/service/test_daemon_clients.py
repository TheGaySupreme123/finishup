from __future__ import annotations

import asyncio
import contextlib
import gc
import json
from collections.abc import Buffer, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import yoetz.service.daemon as daemon_module
from builders.privacy_policies import INSTALLATION_ID, local_only_policy
from yoetz.adapters.control.unix_socket import LocalControlTransportError
from yoetz.adapters.privacy.catalog import encode_privacy_policy_json
from yoetz.application.observation_drain import ObservationDrainSummary
from yoetz.application.publish_work import PublishWorkInternalResult
from yoetz.application.service import (
    ClientProjectionContext,
    ControlProjectionBinding,
    ProjectedControlBody,
    ProjectionBindingFacts,
    ProjectionRenderMode,
    resolve_client_disclosure_sink,
)
from yoetz.application.status import StatusInternalResult
from yoetz.config.models import LoggingConfig, YoetzConfig
from yoetz.domain.observation import (
    ObservationContentChunk,
    ObservationContentKind,
    ObservationCursor,
    ObservationEnvelope,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationIngestResult,
    ObservationSource,
    observation_ingest_request_to_json,
    observation_ingest_result_from_json,
    observation_ingest_result_to_json,
)
from yoetz.domain.observation_profiles import CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
from yoetz.domain.privacy import LocalDisclosureSink
from yoetz.domain.values import Frontier, JsonObject, Timestamp
from yoetz.observability.diagnostics import lookup_diagnostic_records
from yoetz.observability.logging import LogMode
from yoetz.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlError,
    ControlMethod,
    McpRouteProfile,
    RepositoryPrivacyContext,
    ServiceState,
)
from yoetz.ports.ledger import CheckAdmissionStage, check_admission_refused
from yoetz.protocol.canonical import canonical_digest
from yoetz.protocol.coverage import PublicationChannel, coverage_for_channel
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import (
    CheckRequest,
    CheckResult,
    OperationFailureModel,
    PublishWorkAcceptedEventModel,
    PublishWorkAcceptedProjectionUnavailableModel,
    PublishWorkRequest,
    PublishWorkResult,
    PublishWorkSuccessModel,
    PublishWorkVersionSliceModel,
    ReceiptRequest,
    ReceiptResult,
    StartRequest,
    StartResult,
    StatusRequest,
    StatusResult,
    StatusSuccessModel,
)
from yoetz.service.client import _connected_client  # pyright: ignore[reportPrivateUsage]
from yoetz.service.confidential_protocol import (
    ClientOpenEnvelope,
    ConfidentialSecretPurpose,
    EmptyVaultTarget,
    HumanCeremonyBinding,
    HumanCeremonyKind,
    KeyringRetryPhase,
    SecretIngressBinding,
    SecretRequiredPhase,
    ServerCloseEnvelope,
    ServerErrorEnvelope,
    ServerOpenedEnvelope,
    VaultUnlockPreview,
    decode_human_frame,
    encode_human_frame,
)
from yoetz.service.control_protocol import (
    client_handshake,
    parse_control_result,
    read_control_frame,
    write_control_frame,
)
from yoetz.service.daemon import ServiceComposition, ServiceDaemon
from yoetz.service.lifecycle import LifecycleError, ServiceLifecycle
from yoetz.service.session_routes import SessionRouteMemory
from yoetz.service.vault import VaultMode, VaultService

_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000001"
_UUID = "00000000-0000-4000-8000-000000000002"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 7, 19, tzinfo=UTC)

    def monotonic_seconds(self) -> float:
        return 10.0


class _GenerationStore:
    def advance(self, instance_id: str) -> int:
        assert instance_id == _INSTANCE_ID
        return 7


class _Listener:
    def __init__(self) -> None:
        self.closed = False
        self._closed = asyncio.Event()

    async def accept(self) -> object:
        await self._closed.wait()
        raise RuntimeError("closed")

    async def aclose(self) -> None:
        self.closed = True
        self._closed.set()


@dataclass(frozen=True, slots=True)
class _Capability:
    active: bool = True


class _Monitor:
    capability = _Capability()

    def __init__(self) -> None:
        self.callback = None
        self.closed = False

    async def start(self, callback: object) -> None:
        self.callback = callback

    async def close(self) -> None:
        self.closed = True


class _ConnectedControlStream:
    def __init__(self, peer_identity: object) -> None:
        self.peer_identity = peer_identity
        self.other: _ConnectedControlStream | None = None
        self._chunks: asyncio.Queue[bytes] = asyncio.Queue(maxsize=8)
        self._buffer = bytearray()

    async def receive(self, max_bytes: int) -> bytes:
        while not self._buffer:
            self._buffer.extend(await self._chunks.get())
        chunk = bytes(self._buffer[:max_bytes])
        del self._buffer[:max_bytes]
        return chunk

    async def send_all(self, data: Buffer) -> None:
        assert self.other is not None
        await self.other._chunks.put(bytes(data))

    async def aclose(self) -> None:
        return None


def _connected_control_pair() -> tuple[_ConnectedControlStream, _ConnectedControlStream]:
    client_peer = object()
    service_peer = object()
    client = _ConnectedControlStream(service_peer)
    server = _ConnectedControlStream(client_peer)
    client.other = server
    server.other = client
    return client, server


class _Vault:
    mode = VaultMode.OS_KEYRING
    generation = 3
    ready = True

    def __init__(self) -> None:
        self.lock_count = 0
        self.close_count = 0

    async def lock(self) -> None:
        self.lock_count += 1
        self.ready = False

    async def close(self) -> None:
        self.close_count += 1
        self.ready = False


class _Application:
    def __init__(self) -> None:
        self.start_calls = 0
        self.publish_work_calls = 0
        self.projections: list[ClientProjectionContext] = []
        self.projection_bindings: list[ControlProjectionBinding] = []
        self.close_count = 0
        self.publish_work_error: PublicOperationError | None = None
        self.receipt_error: PublicOperationError | None = None
        self.receipt_calls = 0
        # Stands in for an accepted, durable batch so the post-commit response path can be
        # exercised without a real ledger.
        self.publish_work_result: PublishWorkResult | None = None
        self.publish_work_internal: PublishWorkInternalResult | None = None
        self.projection_error: BaseException | None = None
        self.projection_failures = 0
        self.append_count = 0
        self.publish_response_lookups = 0
        self.publish_response_stores = 0
        self.cached_publish_response: PublishWorkResult | None = None
        self.publish_response_store_error: PublicOperationError | None = None
        self.privacy_setup_contexts: list[RepositoryPrivacyContext | None] = []
        self.observation_requests: list[JsonObject] = []
        self.check_requests: list[CheckRequest] = []

    async def start(
        self,
        request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> StartResult:
        del repository_privacy_context
        assert isinstance(request, StartRequest)
        self.start_calls += 1
        await asyncio.sleep(0)
        return StartResult.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": request.request_id,
                "ok": False,
                "error": {
                    "code": "INVALID_REQUEST",
                    "message": "The request is invalid.",
                    "retryable": False,
                    "correlation_id": f"err_{_UUID}",
                },
            }
        )

    async def check(
        self,
        request: object,
        *,
        route_profile: object = "policy",
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> JsonObject:
        del route_profile, repository_privacy_context
        assert isinstance(request, CheckRequest)
        self.check_requests.append(request)
        await asyncio.sleep(0)
        # Unprojected stand-in only. Projection is forced to fail in the dedicated correlation
        # tests before any public CheckResult is required.
        return JsonObject({"ok": True, "request_id": request.request_id})

    async def status(
        self,
        request: object,
        *,
        route_profile: object = None,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> JsonObject:
        del route_profile, repository_privacy_context
        assert isinstance(request, StatusRequest)
        await asyncio.sleep(0)
        return JsonObject({"ok": True, "request_id": request.request_id, "view": request.view})

    async def publish_work(
        self,
        request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> PublishWorkResult | PublishWorkInternalResult:
        del repository_privacy_context
        assert isinstance(request, PublishWorkRequest)
        self.publish_work_calls += 1
        await asyncio.sleep(0)
        if self.publish_work_error is not None:
            raise self.publish_work_error
        if self.publish_work_result is not None:
            return self.publish_work_result
        if self.publish_work_internal is not None:
            outcome = "accepted" if self.append_count == 0 else "replayed"
            if self.append_count == 0:
                self.append_count += 1
            return replace(self.publish_work_internal, outcome=outcome)
        raise AssertionError("publish_work_error_required")

    async def receipt(
        self,
        request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> object:
        del repository_privacy_context
        assert isinstance(request, ReceiptRequest)
        self.receipt_calls += 1
        await asyncio.sleep(0)
        if self.receipt_error is not None:
            raise self.receipt_error
        raise AssertionError("receipt_error_required")

    async def load_publish_response(
        self, result: PublishWorkInternalResult, sink: LocalDisclosureSink
    ) -> PublishWorkResult | None:
        del result
        assert sink is LocalDisclosureSink.AGENT_CONTEXT
        self.publish_response_lookups += 1
        return self.cached_publish_response

    async def store_publish_response(
        self,
        result: PublishWorkInternalResult,
        sink: LocalDisclosureSink,
        projected: ProjectedControlBody,
    ) -> PublishWorkResult:
        del result
        assert sink is LocalDisclosureSink.AGENT_CONTEXT
        assert isinstance(projected, PublishWorkResult)
        self.publish_response_stores += 1
        if self.publish_response_store_error is not None:
            raise self.publish_response_store_error
        if self.cached_publish_response is None:
            self.cached_publish_response = projected
        return self.cached_publish_response

    async def review(self, request: object) -> JsonObject:
        assert isinstance(request, JsonObject)
        return JsonObject({"accepted": True})

    async def observation_ingest(self, request: object) -> JsonObject:
        assert type(request) is JsonObject
        self.observation_requests.append(request)
        return observation_ingest_result_to_json(
            ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
        )

    async def privacy_get_setup(
        self,
        request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> JsonObject:
        assert request == JsonObject({"schema_version": "2.0.0"})
        self.privacy_setup_contexts.append(repository_privacy_context)
        return _privacy_setup_snapshot()

    async def projection_binding_facts(
        self,
        method: ControlMethod,
        request: object,
        result: object,
    ) -> ProjectionBindingFacts:
        del method, result
        request_id = getattr(request, "request_id", None)
        return ProjectionBindingFacts(request_id if type(request_id) is str else None, None)

    async def project_result_for_client(
        self,
        context: ClientProjectionContext,
        binding: ControlProjectionBinding,
        result: object,
    ) -> ProjectedControlBody:
        method = binding.method
        assert method in {
            ControlMethod.START,
            ControlMethod.REVIEW,
            ControlMethod.PUBLISH_WORK,
            ControlMethod.CHECK,
            ControlMethod.STATUS,
            ControlMethod.PRIVACY_GET_SETUP,
            ControlMethod.OBSERVATION_INGEST,
        }
        self.projections.append(context)
        self.projection_bindings.append(binding)
        if self.projection_failures:
            self.projection_failures -= 1
            raise RuntimeError("one-shot-projection-failure")
        if self.projection_error is not None:
            raise self.projection_error
        if type(result) is PublishWorkInternalResult:
            return _projected_publish_work_result(result)
        if method is ControlMethod.PRIVACY_GET_SETUP:
            assert type(result) is JsonObject
            return JsonObject(
                {
                    **dict(result.items()),
                    "privacy_projection": {
                        "sink": "local_human_view",
                        "local_disclosure_receipt_id": ("egr_00000000-0000-4000-8000-000000000060"),
                        "policy_id": "pvy_00000000-0000-4000-8000-000000000061",
                        "policy_version": "1",
                        "policy_digest": "sha256:" + "6" * 64,
                        "included_categories": [],
                        "blocked_categories": [],
                        "omitted_pointers": [],
                        "projection_commitment": "hmac-sha256:" + "7" * 64,
                    },
                }
            )
        assert isinstance(result, StartResult | PublishWorkResult | JsonObject)
        return result

    async def close(self) -> None:
        self.close_count += 1


def _start_body() -> StartRequest:
    return StartRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": f"req_{_UUID}",
            "actor": {"actor_id": "harness:test", "actor_type": "harness"},
            "client": {
                "kind": "test_client",
                "version": "0.1.0",
                "integration": "local_cli",
            },
            "mode": "create",
            "task_title": "shared service",
            "requested_view": "compact",
        }
    )


def _publish_work_body() -> PublishWorkRequest:
    return PublishWorkRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": "req_00000000-0000-4000-8000-000000000010",
            "session_id": "ses_00000000-0000-4000-8000-000000000011",
            "writer_id": "wri_00000000-0000-4000-8000-000000000012",
            "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
            "event_drafts": [
                {
                    "event_id": "evt_00000000-0000-4000-8000-000000000013",
                    "schema": {"name": "plan_published", "version": "1.0.0"},
                    "occurred_at": "2026-01-01T00:00:00.000Z",
                    # Deliberately unsorted: application rejects with unsorted_set_field.
                    "causal_parents": [
                        "evt_00000000-0000-4000-8000-000000000002",
                        "evt_00000000-0000-4000-8000-000000000001",
                    ],
                    "payload": {
                        "plan_version": 1,
                        "summary": "Plan",
                        "obligation_refs": [],
                    },
                    "artifact_refs": [],
                    "evidence_refs": [],
                }
            ],
            "actor": {"actor_id": "harness:test", "actor_type": "harness"},
            "client": {
                "kind": "test_client",
                "version": "0.1.0",
                "integration": "local_cli",
            },
        }
    )


def _receipt_body() -> ReceiptRequest:
    return ReceiptRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": "req_00000000-0000-4000-8000-000000000020",
            "task_id": "tsk_00000000-0000-4000-8000-000000000021",
            "session_id": "ses_00000000-0000-4000-8000-000000000022",
            "writer_id": "wri_00000000-0000-4000-8000-000000000023",
            "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
            "format": "json",
            "include": "standard",
            "redaction_profile": "full_local",
            "actor": {"actor_id": "harness:test", "actor_type": "harness"},
            "client": {
                "kind": "test_client",
                "version": "0.1.0",
                "integration": "local_cli",
            },
        }
    )


def _request(
    daemon: ServiceDaemon,
    method: ControlMethod,
    body: object,
    *,
    deadline_ms: int | None = None,
) -> ControlCallRequest:
    instance = daemon.composition.lifecycle.instance
    return ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=instance.instance_id,
        service_generation=str(instance.generation),
        method=method,
        body=body,  # pyright: ignore[reportArgumentType]
        deadline_ms=deadline_ms,
    )


def _capture_gate_body(*, capture_only: bool) -> JsonObject:
    """Build a fully domain-valid native handoff for the daemon gate tests."""

    commitment = "hmac-sha256:" + "1" * 64
    source_identity = "hook:capture-gate"
    envelope = ObservationEnvelope(
        session_commitment=commitment,
        event_kind="PostToolUse",
        source_identity=source_identity,
        source=ObservationSource.CLAUDE_HOOK,
        cursor=ObservationCursor(1, 0, 1, commitment, "claude-hooks-1.0"),
        receipt_time=Timestamp("2026-08-12T12:00:00.000Z"),
        structural_payload=JsonObject({"tool_name": "Bash"}),
        content_object_refs=(),
        gap_codes=(),
    )
    chunk = ObservationContentChunk(
        content_kind=ObservationContentKind.TOOL_INPUT,
        correlation_identity=f"{source_identity}:tool-input",
        source_commitment=commitment,
        media_type="text/plain",
        part_index=0,
        part_count=1,
        content=b"capture-gate-marker",
    )
    request = ObservationIngestRequest(
        codex_session_id="claude:capture-gate",
        envelope=envelope,
        content_chunks=(chunk,),
        content_capture_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        capture_only=capture_only,
    )
    return observation_ingest_request_to_json(request)


def _privacy_setup_snapshot() -> JsonObject:
    return JsonObject(
        {
            "schema_version": "2.0.0",
            "composed_policy": encode_privacy_policy_json(local_only_policy()),
            "bound_scope": {
                "kind": "workspace",
                "installation_id": INSTALLATION_ID,
                "workspace_ref_commitment": "hmac-sha256:" + "8" * 64,
            },
            "authority_digest": "sha256:" + "9" * 64,
            "grant_state": "missing",
            "migration_state": "not_applicable",
            "channel_choices": [],
            "allowed_blocked_examples": [],
            "recipes": [],
            "never_send_editable": False,
        }
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("route_profile", "expected"),
    (
        (None, "policy"),
        ("strict", "strict"),
    ),
)
async def test_ready_handler_preserves_check_route_default(
    route_profile: McpRouteProfile | None,
    expected: McpRouteProfile,
) -> None:
    seen: list[object] = []
    marker = object()

    async def handler(
        _request: object,
        *,
        route_profile: object = "policy",
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> object:
        assert repository_privacy_context is None
        seen.append(route_profile)
        return marker

    request = ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=_INSTANCE_ID,
        service_generation="7",
        method=ControlMethod.CHECK,
        body=_check_body(),
        route_profile=route_profile,
    )

    result = await ServiceDaemon._invoke_ready_handler(  # pyright: ignore[reportPrivateUsage]
        handler, request
    )

    assert result is marker
    assert seen == [expected]


def _route_call(
    method: ControlMethod, body: object, route_profile: McpRouteProfile | None
) -> ControlCallRequest:
    return ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=_INSTANCE_ID,
        service_generation="7",
        method=method,
        body=cast(Any, body),
        route_profile=route_profile,
    )


def _route_daemon(path: Path | None) -> Any:
    return SimpleNamespace(_session_routes=SessionRouteMemory(path))


def test_route_less_status_reads_the_route_the_sessions_bridge_serves(tmp_path: Path) -> None:
    """tb4n1 C8 (#985): the Stop gate and the CLI read the agent's MCP route, not policy.

    37 of 37 deterministic-arm exports listed ``semantic_review_not_requested`` as work while
    the agent's strict MCP view never did, because route-less reads used the policy route.
    """

    daemon = _route_daemon(tmp_path / "session-routes.json")
    lookup = ServiceDaemon._with_session_route  # pyright: ignore[reportPrivateUsage]
    remember = ServiceDaemon._remember_session_route  # pyright: ignore[reportPrivateUsage]
    status = _status_body()
    # Nothing remembered: a route-less status keeps the policy default (None reaches the handler).
    assert lookup(daemon, _route_call(ControlMethod.STATUS, status, None)).route_profile is None
    # A strict bridge status is looked up unchanged and remembered only once it completed.
    strict = _route_call(ControlMethod.STATUS, status, "strict")
    assert lookup(daemon, strict) is strict
    assert lookup(daemon, _route_call(ControlMethod.STATUS, status, None)).route_profile is None
    remember(daemon, strict)
    assert lookup(daemon, _route_call(ControlMethod.STATUS, status, None)).route_profile == (
        "strict"
    )
    # Another session is unaffected.
    other = status.model_copy(update={"session_id": "ses_00000000-0000-4000-8000-000000000049"})
    assert lookup(daemon, _route_call(ControlMethod.STATUS, other, None)).route_profile is None
    # A route-less check never inherits: the route decides what a check may dispatch.
    check = _check_body().model_copy(update={"session_id": status.session_id})
    assert lookup(daemon, _route_call(ControlMethod.CHECK, check, None)).route_profile is None
    # A later successful policy check for the session wins (last writer wins).
    remember(daemon, _route_call(ControlMethod.CHECK, check, "policy"))
    assert lookup(daemon, _route_call(ControlMethod.STATUS, status, None)).route_profile == (
        "policy"
    )
    # The memory survives a new service instance over the same state directory.
    restarted = _route_daemon(tmp_path / "session-routes.json")
    assert lookup(restarted, _route_call(ControlMethod.STATUS, status, None)).route_profile == (
        "policy"
    )
    stored = (tmp_path / "session-routes.json").stat()
    assert stored.st_mode & 0o777 == 0o600


def test_session_route_memory_is_bounded_lru_and_tolerates_bad_files(tmp_path: Path) -> None:
    path = tmp_path / "session-routes.json"
    memory = SessionRouteMemory(path)
    ids = [f"ses_00000000-0000-4000-8000-{index:012d}" for index in range(300)]
    for session in ids:
        memory.remember(session, "strict")
    memory.remember(ids[0], "policy")  # rewritten after eviction: newest again
    reloaded = SessionRouteMemory(path)
    assert reloaded.get(ids[0]) == "policy"
    assert reloaded.get(ids[1]) is None
    assert reloaded.get(ids[-1]) == "strict"
    assert len(json.loads(path.read_text())) == 256
    for content in ("{not json", "[1]", '{"ses_x": "loose", "not-a-session": "strict"}'):
        path.write_text(content)
        assert SessionRouteMemory(path).get("ses_x") is None
    target = tmp_path / "elsewhere.json"
    target.write_text(json.dumps({ids[5]: "strict"}))
    path.unlink()
    path.symlink_to(target)
    assert SessionRouteMemory(path).get(ids[5]) is None
    linked = SessionRouteMemory(path)
    linked.remember(ids[5], "policy")
    # The write replaced the link itself and never wrote through it.
    assert not path.is_symlink()
    assert json.loads(target.read_text()) == {ids[5]: "strict"}


@pytest.mark.anyio
async def test_failed_route_carrying_status_is_not_remembered(tmp_path: Path) -> None:
    daemon, application, _vault, _listener = _daemon(session_route_path=tmp_path / "routes.json")
    seen: list[object] = []
    failures = [True]

    async def status(
        request: object,
        *,
        route_profile: McpRouteProfile | None = None,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> object:
        del request, repository_privacy_context
        seen.append(route_profile)
        if failures.pop() if failures else False:
            raise RuntimeError("status failed")
        return JsonObject({"ok": True})

    application.status = status  # type: ignore[method-assign]
    dispatch = daemon._dispatch_ready_under_maintenance_gate  # pyright: ignore[reportPrivateUsage]
    context = cast(Any, None)
    await daemon.start()
    try:
        with pytest.raises(Exception):  # noqa: B017 - any failure: the route must not be learned
            await dispatch(
                context, _route_call(ControlMethod.STATUS, _status_body(), "strict"), None
            )
        with contextlib.suppress(Exception):
            await dispatch(context, _route_call(ControlMethod.STATUS, _status_body(), None), None)
    finally:
        await daemon.close()
    assert seen == ["strict", None]


@pytest.mark.anyio
async def test_ready_handler_forwards_serving_host_identity_to_check() -> None:
    seen: list[object] = []
    marker = object()

    async def handler(
        _request: object,
        *,
        route_profile: object = "policy",
        host_profile: object = "generic",
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> object:
        assert repository_privacy_context is None
        seen.append((route_profile, host_profile))
        return marker

    request = ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=_INSTANCE_ID,
        service_generation="7",
        method=ControlMethod.CHECK,
        body=_check_body(),
        route_profile="strict",
        host_profile="claude",
    )

    result = await ServiceDaemon._invoke_ready_handler(  # pyright: ignore[reportPrivateUsage]
        handler, request
    )

    assert result is marker
    assert seen == [("strict", "claude")]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "method",
    (
        ControlMethod.START,
        ControlMethod.PRIVACY_GET_SETUP,
        ControlMethod.PRIVACY_GET_EFFECTIVE,
        ControlMethod.PRIVACY_PROPOSE_POLICY,
    ),
)
async def test_repository_bound_handler_receives_only_the_trusted_context_keyword(
    method: ControlMethod,
) -> None:
    seen: list[object] = []
    marker = object()
    context = RepositoryPrivacyContext("hmac-sha256:" + "1" * 64, "git_common_root")

    async def handler(
        _request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> object:
        seen.append(repository_privacy_context)
        return marker

    request = ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=_INSTANCE_ID,
        service_generation="7",
        method=method,
        body=(
            _start_body()
            if method is ControlMethod.START
            else JsonObject({"schema_version": "2.0.0"})
        ),
    )

    result = await ServiceDaemon._invoke_ready_handler(  # pyright: ignore[reportPrivateUsage]
        handler, request, context
    )

    assert result is marker
    assert seen == [context]


@pytest.mark.anyio
async def test_v2_privacy_setup_snapshot_uses_generic_client_projection() -> None:
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    context = RepositoryPrivacyContext("hmac-sha256:" + "8" * 64, "git_common_root")

    result = await daemon.dispatch(
        ControlClientKind.CLI,
        _request(
            daemon,
            ControlMethod.PRIVACY_GET_SETUP,
            JsonObject({"schema_version": "2.0.0"}),
        ),
        repository_privacy_context=context,
    )

    assert result.outcome == "ok", result.body
    assert type(result.body) is JsonObject
    assert result.body.get("schema_version") == "2.0.0"
    assert result.body.get("privacy_projection") is not None
    assert application.privacy_setup_contexts == [context]
    assert len(application.projections) == 1
    assert application.projection_bindings[0].repository_privacy_commitment == context.commitment
    await daemon.close()


@pytest.mark.anyio
async def test_locator_bound_session_keeps_v1_tighten_machine_only() -> None:
    seen: list[object] = []
    marker = object()
    context = RepositoryPrivacyContext("hmac-sha256:" + "2" * 64, "git_common_root")

    async def legacy_handler(request: object) -> object:
        seen.append(request)
        return marker

    body = JsonObject({"schema_version": "1.0.0"})
    request = ControlCallRequest(
        kind="call",
        protocol_version="1.0",
        rpc_id=new_id(IdKind.CONTROL_RPC),
        service_instance_id=_INSTANCE_ID,
        service_generation="7",
        method=ControlMethod.PRIVACY_TIGHTEN_POLICY,
        body=body,
    )

    result = await ServiceDaemon._invoke_ready_handler(  # pyright: ignore[reportPrivateUsage]
        legacy_handler, request, context
    )

    assert result is marker
    assert seen == [body]


def _daemon(
    *, session_route_path: Path | None = None
) -> tuple[ServiceDaemon, _Application, _Vault, _Listener]:
    application = _Application()
    vault = _Vault()
    listener = _Listener()
    lifecycle = ServiceLifecycle(
        _Clock(),
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "1" * 64,
        instance_id=_INSTANCE_ID,
    )
    composition = ServiceComposition(
        lifecycle=lifecycle,
        control_listener=listener,  # pyright: ignore[reportArgumentType]
        secret_ingress_listener=None,
        human_control_listener=None,
        human_control_service=None,
        session_monitor=_Monitor(),  # pyright: ignore[reportArgumentType]
        vault=vault,
        application=application,
        session_route_path=session_route_path,
    )
    return ServiceDaemon(_composition=composition), application, vault, listener


def _locked_daemon(
    root: Path,
    factory: object,
) -> tuple[ServiceDaemon, _Vault]:
    vault = _Vault()
    vault.ready = False
    lifecycle = ServiceLifecycle(
        _Clock(),
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "2" * 64,
        instance_id=_INSTANCE_ID,
        singleton_lock_path=root / "service.lock",
    )
    composition = ServiceComposition(
        lifecycle=lifecycle,
        control_listener=_Listener(),  # pyright: ignore[reportArgumentType]
        secret_ingress_listener=None,
        human_control_listener=None,
        human_control_service=None,
        session_monitor=None,
        vault=vault,
        ready_application_factory=factory,  # pyright: ignore[reportArgumentType]
    )
    return ServiceDaemon(_composition=composition), vault


@pytest.mark.anyio
async def test_cli_mcp_and_ui_share_one_ready_application_and_projection() -> None:
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    body = _start_body()
    kinds = (ControlClientKind.CLI, ControlClientKind.MCP_BRIDGE, ControlClientKind.UI)
    results = await asyncio.gather(
        *(daemon.dispatch(kind, _request(daemon, ControlMethod.START, body)) for kind in kinds)
    )
    assert all(result.outcome == "ok" for result in results)
    assert application.start_calls == 3
    assert application.projections == [ClientProjectionContext.fail_safe(kind) for kind in kinds]


@pytest.mark.anyio
async def test_public_operation_error_surfaces_as_ok_false_not_internal_error() -> None:
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    application.publish_work_error = PublicOperationError(
        PublicErrorCode.EVENT_INVALID,
        "The event batch is invalid.",
        False,
        safe_details={"reason_code": "unsorted_set_field"},
    )
    body = _publish_work_body()

    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.PUBLISH_WORK, body),
    )

    assert result.outcome == "ok"
    assert isinstance(result.body, PublishWorkResult)
    assert result.body.root.ok is False
    assert result.body.root.error.code is PublicErrorCode.EVENT_INVALID
    # The directive token is attached when the application builds the error and survives the
    # daemon's wire projection unchanged (ADR-030).
    assert result.body.root.error.safe_details == {
        "continuation": "sorted_set_required",
        "reason_code": "unsorted_set_field",
    }
    assert result.body.root.request_id == body.request_id
    assert result.body.root.error.correlation_id.startswith("err_")
    assert application.publish_work_calls == 1
    assert application.projections == []
    assert not isinstance(result.body, ControlError)
    await daemon.close()


@pytest.mark.anyio
async def test_classified_receipt_storage_fault_is_ok_false_not_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Receipt object-store classification must not become the #325 internal_error diagnostic."""

    import yoetz.observability.diagnostics as diagnostics
    from yoetz.observability.logging import record_classified_exception_without_raising

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    try:
        raise ValueError("object_verification_failed")
    except ValueError as exc:
        correlation_id = record_classified_exception_without_raising(
            exc,
            component="application.receipt",
            operation="receipt_object_read",
            request_id="req_00000000-0000-4000-8000-000000000020",
        )
        application.receipt_error = PublicOperationError(
            PublicErrorCode.STORAGE_CORRUPT,
            "The stored receipt is invalid.",
            False,
            correlation_id=correlation_id,
        )
    body = _receipt_body()

    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.RECEIPT, body),
    )

    assert result.outcome == "ok"
    assert isinstance(result.body, ReceiptResult)
    assert result.body.root.ok is False
    assert result.body.root.error.code is PublicErrorCode.STORAGE_CORRUPT
    assert result.body.root.error.message == "The stored receipt is invalid."
    assert result.body.root.error.retryable is False
    assert result.body.root.error.correlation_id == correlation_id
    assert result.body.root.request_id == body.request_id
    found = lookup_diagnostic_records(correlation_id, root=tmp_path)
    assert len(found) == 1
    assert found[0]["component"] == "application.receipt"
    assert found[0]["operation"] == "receipt_object_read"
    assert found[0]["reason"] == "exception_value_error"
    recorded_operation = found[0]["operation"]
    assert type(recorded_operation) is str
    assert "internal_error" not in recorded_operation
    assert application.receipt_calls == 1
    await daemon.close()


@pytest.mark.anyio
async def test_unbound_receipt_storage_unsafe_is_ok_false_not_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even without a pre-bound id, receipt storage faults stay public_error, not internal_error."""

    import yoetz.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    application.receipt_error = PublicOperationError(
        PublicErrorCode.STORAGE_UNSAFE,
        "Receipt object storage is unavailable.",
        True,
    )
    body = _receipt_body()

    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.RECEIPT, body),
    )

    assert result.outcome == "ok"
    assert isinstance(result.body, ReceiptResult)
    assert result.body.root.ok is False
    assert result.body.root.error.code is PublicErrorCode.STORAGE_UNSAFE
    assert result.body.root.error.retryable is True
    correlation_id = result.body.root.error.correlation_id
    assert correlation_id.startswith("err_")
    found = lookup_diagnostic_records(correlation_id, root=tmp_path)
    assert len(found) == 1
    assert found[0]["operation"] == "receipt_public_error"
    assert found[0]["reason"] == "storage_unsafe"
    recorded_operation = found[0]["operation"]
    assert type(recorded_operation) is str
    assert "internal_error" not in recorded_operation
    await daemon.close()


@pytest.mark.anyio
async def test_runtime_value_error_through_dispatch_is_correlated_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Runtime ValueError after validation must not collapse into frame_invalid (#126 C9)."""

    import yoetz.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()

    async def boom(request: object) -> object:
        del request
        raise ValueError("recovery_generation_not_advanced")

    application.start = boom  # type: ignore[method-assign]

    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.START, _start_body()),
    )

    assert result.outcome == "error"
    assert isinstance(result.body, ControlError)
    assert result.body.reason == "internal_error"
    assert result.body.correlation_id is not None
    found = lookup_diagnostic_records(result.body.correlation_id, root=tmp_path)
    assert len(found) == 1
    assert found[0]["component"] == "service.daemon"
    assert found[0]["operation"] == "start_internal_error"
    await daemon.close()


@pytest.mark.anyio
async def test_genuinely_malformed_control_request_is_still_frame_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.service.control_protocol import ControlProtocolError

    daemon, _application, _vault, _listener = _daemon()
    await daemon.start()

    def _reject(_request: object) -> None:
        raise ControlProtocolError("frame_invalid")

    monkeypatch.setattr(daemon_module, "validate_request", _reject)
    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.START, _start_body()),
    )
    assert result.outcome == "error"
    assert isinstance(result.body, ControlError)
    assert result.body.reason == "frame_invalid"
    await daemon.close()


def _accepted_publish_work_result(request_id: str) -> PublishWorkResult:
    """An ok:false body is enough here: only the post-commit response path is under test."""

    return PublishWorkResult.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": request_id,
            "ok": False,
            "error": {
                "code": "INVALID_REQUEST",
                "message": "The request is invalid.",
                "retryable": False,
                "correlation_id": f"err_{_UUID}",
            },
        }
    )


def _publish_work_internal(request: PublishWorkRequest) -> PublishWorkInternalResult:
    frontier = Frontier(1, "sha256:" + "4" * 64)
    return PublishWorkInternalResult(
        protocol_version="0.1",
        schema_version="1.0.0",
        request_id=request.request_id,
        request_digest=canonical_digest({"request_id": request.request_id}),
        ok=True,
        outcome="accepted",
        task_id="tsk_00000000-0000-4000-8000-000000000020",
        session_id=request.session_id,
        writer_id=request.writer_id,
        subject_frontier=Frontier.genesis(),
        result_frontier=frontier,
        accepted_events=(
            PublishWorkAcceptedEventModel(
                event_id=cast(str, cast(Mapping[str, object], request.event_drafts[0])["event_id"]),
                schema_name="plan_published",
                schema_version="1.0.0",
                writer_sequence="1",
                ingestion_sequence="1",
                accepted_at="2026-01-01T00:00:00.000Z",
                predecessor_digest="genesis",
                entry_digest=frontier.head_digest,
                projection_status="projected",
            ),
        ),
        warning_codes=(),
        coverage=coverage_for_channel(PublicationChannel.LOCAL_CLI),
        gaps=(),
        versions=PublishWorkVersionSliceModel(
            protocol_version="0.1",
            engine_version="0.1.0",
            projection_version="0.1.0",
            policy_packs=("research-evidence/0.2.0", "work-integrity/0.3.0"),
        ),
    )


def _projected_publish_work_result(internal: PublishWorkInternalResult) -> PublishWorkResult:
    wire = internal.as_json()
    accepted = cast(tuple[dict[str, object], ...], wire["accepted_events"])
    for event in accepted:
        event.pop("summary", None)
    return PublishWorkResult.model_validate(
        {
            **wire,
            "privacy_projection": {
                "sink": "agent_context",
                "local_disclosure_receipt_id": "egr_00000000-0000-4000-8000-000000000021",
                "policy_id": "pvy_00000000-0000-4000-8000-000000000022",
                "policy_version": "1",
                "policy_digest": "sha256:" + "5" * 64,
                "included_categories": (),
                "blocked_categories": (),
                "omitted_pointers": (),
                "projection_commitment": "hmac-sha256:" + "6" * 64,
            },
        }
    )


@pytest.mark.anyio
async def test_post_commit_projection_failure_returns_total_acceptance_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An accepted write must never be surfaced to the caller as a failure.

    The handler returns (so a batch is durable) and only then does response shaping fail. The
    caller receives a reduced ``ok: true`` envelope with frontiers and accepted event facts, not
    ``response_projection_failed`` / ``INTERNAL_ERROR``. The envelope correlation id is the same
    id filed in the durable diagnostic sink.
    """

    import yoetz.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    body = _publish_work_body()
    application.publish_work_internal = _publish_work_internal(body)
    application.projection_error = RuntimeError("post-commit-shape-failure")

    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.PUBLISH_WORK, body),
    )

    assert result.outcome == "ok"
    assert isinstance(result.body, PublishWorkResult)
    root = result.body.root
    assert type(root) is PublishWorkAcceptedProjectionUnavailableModel
    assert root.ok is True
    assert root.response_completeness == "accepted_projection_unavailable"
    assert root.reason_code == "response_projection_failed"
    assert root.request_id == body.request_id
    assert root.result_frontier.sequence == "1"
    assert root.result_frontier.head_digest == "sha256:" + "4" * 64
    assert len(root.accepted_events) == 1
    assert root.accepted_events[0].event_id == "evt_00000000-0000-4000-8000-000000000013"
    assert root.correlation_id.startswith("err_")
    found = lookup_diagnostic_records(root.correlation_id, root=tmp_path)
    assert len(found) == 1
    assert found[0]["operation"] == "publish_work_response_projection_failed"
    assert found[0]["component"] == "service.daemon"
    for forbidden in ("traceback", "exception", "payload", "path", "message"):
        assert forbidden not in found[0]
    # The operation itself ran exactly once and is not retried behind the caller's back.
    assert application.publish_work_calls == 1
    assert len(application.projections) == 1
    await daemon.close()


def _check_body() -> CheckRequest:
    return CheckRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": "req_00000000-0000-4000-8000-000000000030",
            "session_id": "ses_00000000-0000-4000-8000-000000000031",
            "writer_id": "wri_00000000-0000-4000-8000-000000000032",
            "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
            "mode": "deterministic_only",
            "actor": {"actor_id": "harness:test", "actor_type": "harness"},
            "client": {
                "kind": "test_client",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
        }
    )


def _status_body() -> StatusRequest:
    return StatusRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": "req_00000000-0000-4000-8000-000000000040",
            "session_id": "ses_00000000-0000-4000-8000-000000000041",
            "writer_id": "wri_00000000-0000-4000-8000-000000000042",
            "view": "compact",
            "limit": "10",
            "actor": {"actor_id": "harness:test", "actor_type": "harness"},
            "client": {
                "kind": "test_client",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
        }
    )


@pytest.mark.anyio
async def test_check_response_projection_failure_correlation_resolves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The correlation id on a check ControlError resolves to exactly one diagnostic record."""

    import yoetz.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    application.projection_error = RuntimeError("check-shape-failure-must-not-leak")

    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.CHECK, _check_body()),
    )

    assert result.outcome == "error"
    assert isinstance(result.body, ControlError)
    assert result.body.reason == "response_projection_failed"
    assert result.body.retryable is True
    assert result.body.correlation_id is not None
    found = lookup_diagnostic_records(result.body.correlation_id, root=tmp_path)
    assert len(found) == 1
    assert found[0]["operation"] == "check_response_projection_failed"
    assert found[0]["component"] == "service.daemon"
    assert found[0]["request_id"] == "req_00000000-0000-4000-8000-000000000030"
    for forbidden in ("traceback", "exception", "payload", "path", "message"):
        assert forbidden not in found[0]
    assert "must-not-leak" not in str(found[0])
    await daemon.close()


@pytest.mark.anyio
async def test_status_read_projection_failure_correlation_resolves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The correlation id on a status ControlError resolves to exactly one diagnostic record."""

    import yoetz.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    application.projection_error = RuntimeError("status-shape-failure-must-not-leak")

    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.STATUS, _status_body()),
    )

    assert result.outcome == "error"
    assert isinstance(result.body, ControlError)
    assert result.body.reason == "read_projection_failed"
    assert result.body.retryable is True
    assert result.body.correlation_id is not None
    found = lookup_diagnostic_records(result.body.correlation_id, root=tmp_path)
    assert len(found) == 1
    assert found[0]["operation"] == "status_read_projection_failed"
    assert found[0]["component"] == "service.daemon"
    assert found[0]["request_id"] == "req_00000000-0000-4000-8000-000000000040"
    assert found[0]["phase"] == "projection"
    assert result.body.phase == "projection"
    for forbidden in ("traceback", "exception", "payload", "path", "message"):
        assert forbidden not in found[0]
    assert "must-not-leak" not in str(found[0])
    await daemon.close()


@pytest.mark.anyio
async def test_status_projection_recovery_is_one_incident_with_bounded_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fresh status retries retain the binding and report one bounded recovery incident."""

    import yoetz.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    application.projection_failures = 2
    fallback_projection = application.project_result_for_client

    async def project(
        context: ClientProjectionContext,
        binding: ControlProjectionBinding,
        result: object,
    ) -> ProjectedControlBody:
        if binding.method is ControlMethod.STATUS:
            application.projections.append(context)
            if application.projection_failures:
                application.projection_failures -= 1
                raise RuntimeError("one-shot-projection-failure")
            assert binding.original_request_id is not None
            return StatusResult.model_validate(
                {
                    "protocol_version": "0.1",
                    "schema_version": "1.0.0",
                    "request_id": binding.original_request_id,
                    "ok": False,
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": "The status read was unavailable.",
                        "retryable": True,
                        "correlation_id": "err_00000000-0000-4000-8000-000000000099",
                    },
                }
            )
        return await fallback_projection(context, binding, result)

    application.project_result_for_client = project  # type: ignore[method-assign]

    first_body = _status_body()
    first = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.STATUS, first_body),
    )
    second_body = first_body.model_copy(
        update={"request_id": "req_00000000-0000-4000-8000-000000000043"}
    )
    second = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.STATUS, second_body),
    )
    third_body = first_body.model_copy(
        update={"request_id": "req_00000000-0000-4000-8000-000000000044"}
    )
    recovered = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.STATUS, third_body),
    )

    assert isinstance(first.body, ControlError)
    assert isinstance(second.body, ControlError)
    assert first.body.reason == second.body.reason == "read_projection_failed"
    assert first.body.retryable is True and second.body.retryable is True
    assert first.body.phase == second.body.phase == "projection"
    assert first.body.correlation_id == second.body.correlation_id
    assert recovered.outcome == "ok", repr(recovered.body)
    assert first_body.session_id == second_body.session_id == third_body.session_id
    assert first_body.writer_id == second_body.writer_id == third_body.writer_id
    assert len(application.projections) == 3

    assert first.body.correlation_id is not None
    found = lookup_diagnostic_records(first.body.correlation_id, root=tmp_path)
    assert [record["operation"] for record in found] == [
        "status_read_projection_failed",
        "status_read_projection_recovered",
    ]
    assert found[0]["phase"] == found[1]["phase"] == "projection"
    duration_ms = found[1]["duration_ms"]
    assert type(duration_ms) is int and duration_ms >= 0
    assert found[1]["operation_count"] == 2
    assert (
        lookup_diagnostic_records(
            request_id="req_00000000-0000-4000-8000-000000000043", root=tmp_path
        )
        == ()
    )
    recovery_records = lookup_diagnostic_records(
        request_id="req_00000000-0000-4000-8000-000000000044", root=tmp_path
    )
    assert len(recovery_records) == 1
    assert recovery_records[0]["operation"] == "status_read_projection_recovered"
    await daemon.close()


@pytest.mark.anyio
async def test_status_handler_attribute_error_is_retryable_read_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unexpected failure during application.status is retryable, never terminal internal_error.

    Run-4 item_40: AttributeError inside the operation branch escaped as status_internal_error
    with retryable:false. A pure read that changed nothing must present as read_projection_failed.
    """

    import yoetz.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()

    async def boom(request: object) -> object:
        del request
        raise AttributeError("'NoneType' object has no attribute 'sequence'")

    application.status = boom  # type: ignore[method-assign]

    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.STATUS, _status_body()),
    )

    assert result.outcome == "error"
    assert isinstance(result.body, ControlError)
    assert result.body.reason == "read_projection_failed"
    assert result.body.retryable is True
    assert result.body.correlation_id is not None
    found = lookup_diagnostic_records(result.body.correlation_id, root=tmp_path)
    assert len(found) == 1
    assert found[0]["operation"] == "status_read_projection_failed"
    assert found[0]["component"] == "service.daemon"
    assert found[0]["request_id"] == "req_00000000-0000-4000-8000-000000000040"
    assert found[0]["phase"] == "handler"
    assert result.body.phase == "handler"
    for forbidden in ("traceback", "exception", "payload", "path", "message", "sequence"):
        assert forbidden not in found[0]
    await daemon.close()


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("code", "retryable", "safe_details"),
    [
        (
            PublicErrorCode.FRONTIER_CONFLICT,
            True,
            {"reason_code": "frontier_changed"},
        ),
        (
            PublicErrorCode.SESSION_NOT_FOUND,
            False,
            {"reason_code": "session_superseded"},
        ),
        (PublicErrorCode.INVALID_REQUEST, False, None),
    ],
)
async def test_status_handler_public_failures_keep_their_typed_recovery(
    code: PublicErrorCode,
    retryable: bool,
    safe_details: Mapping[str, object] | None,
) -> None:
    """Known status outcomes keep their code and continuation instead of becoming outages."""

    daemon, application, _vault, _listener = _daemon()
    await daemon.start()

    async def fail(
        request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> object:
        del request, repository_privacy_context
        raise PublicOperationError(
            code,
            "The status request reached a known boundary.",
            retryable,
            safe_details=safe_details,
        )

    application.status = fail  # type: ignore[method-assign]
    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.STATUS, _status_body()),
    )

    assert result.outcome == "ok"
    assert isinstance(result.body, StatusResult)
    assert isinstance(result.body.root, OperationFailureModel)
    error = result.body.root.error
    assert error.code is code
    assert error.retryable is retryable
    if safe_details is None:
        assert error.safe_details is None
    else:
        assert isinstance(error.safe_details, Mapping)
        details = error.safe_details
        assert details["reason_code"] == safe_details["reason_code"]
        expected_continuation = {
            "frontier_changed": "frontier_refresh_required",
            "session_superseded": "session_rebind_required",
        }[str(safe_details["reason_code"])]
        assert details["continuation"] == expected_continuation
    await daemon.close()


@pytest.mark.anyio
async def test_publish_one_shot_projection_failure_is_accepted_without_replay() -> None:
    """Projection failure after append still returns acceptance; replay is optional, not required."""

    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    body = _publish_work_body()
    application.publish_work_internal = _publish_work_internal(body)
    application.projection_failures = 1

    first_request = _request(daemon, ControlMethod.PUBLISH_WORK, body)
    first = await daemon.dispatch(ControlClientKind.MCP_BRIDGE, first_request)
    assert first.outcome == "ok"
    assert isinstance(first.body, PublishWorkResult)
    first_root = first.body.root
    assert type(first_root) is PublishWorkAcceptedProjectionUnavailableModel
    assert first_root.result_frontier.sequence == "1"
    assert first_root.result_frontier.head_digest == "sha256:" + "4" * 64
    assert len(first_root.accepted_events) == 1
    assert application.append_count == 1
    # Reduced envelope is not stored as a full projected success body.
    assert application.publish_response_stores == 0

    # A later identical call may still project fully and cache the complete success body.
    second_request = _request(daemon, ControlMethod.PUBLISH_WORK, body)
    second = await daemon.dispatch(ControlClientKind.MCP_BRIDGE, second_request)
    assert second.outcome == "ok"
    assert isinstance(second.body, PublishWorkResult)
    assert type(second.body.root) is PublishWorkSuccessModel
    assert application.append_count == 1
    assert len(application.projections) == 2
    assert application.publish_response_stores == 1

    third_request = _request(daemon, ControlMethod.PUBLISH_WORK, body)
    third = await daemon.dispatch(ControlClientKind.MCP_BRIDGE, third_request)
    assert third.outcome == "ok"
    assert third.body == second.body
    assert third.rpc_id != second.rpc_id
    assert application.append_count == 1
    assert len(application.projections) == 2
    assert application.publish_response_lookups == 3
    assert application.publish_response_stores == 1
    await daemon.close()


@pytest.mark.anyio
async def test_publish_response_store_failure_does_not_degrade_valid_success() -> None:
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    body = _publish_work_body()
    application.publish_work_internal = _publish_work_internal(body)
    application.publish_response_store_error = PublicOperationError(
        PublicErrorCode.STORAGE_CORRUPT,
        "The stored publish response is invalid.",
        False,
    )

    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.PUBLISH_WORK, body),
    )

    assert result.outcome == "ok"
    assert isinstance(result.body, PublishWorkResult)
    assert result.body.root.ok is True
    assert application.append_count == 1
    assert application.publish_response_stores == 1
    assert application.cached_publish_response is None
    await daemon.close()


@pytest.mark.anyio
async def test_deliberate_post_commit_control_error_is_not_reclassified() -> None:
    """Bounded projection failures already say something true and must survive unchanged."""

    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    body = _publish_work_body()
    application.publish_work_result = _accepted_publish_work_result(body.request_id)
    application.projection_error = ControlError("privacy_projection_blocked")

    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.PUBLISH_WORK, body),
    )

    assert result.outcome == "error"
    assert isinstance(result.body, ControlError)
    assert result.body.reason == "privacy_projection_blocked"
    await daemon.close()


@pytest.mark.anyio
async def test_dispatch_passes_trusted_human_projection_context() -> None:
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    body = _start_body()
    context = ClientProjectionContext(
        ControlClientKind.CLI,
        ProjectionRenderMode.HUMAN_READABLE,
        True,
    )

    result = await daemon.dispatch(
        ControlClientKind.CLI,
        _request(daemon, ControlMethod.START, body),
        projection_context=context,
    )

    assert result.outcome == "ok"
    assert application.projections == [context]

    cross_paired = await daemon.dispatch(
        ControlClientKind.UI,
        _request(daemon, ControlMethod.START, body),
        projection_context=context,
    )
    assert cross_paired.outcome == "error"
    assert isinstance(cross_paired.body, ControlError)
    assert cross_paired.body.reason == "frame_invalid"
    assert application.projections == [context]
    assert daemon.status().state is ServiceState.READY
    await daemon.close()


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("client_kind", "render_mode", "controlling_tty", "expected_sink"),
    (
        # ADR-009 round 3: the hello's terminal claim is presentation only, never owner
        # authority; without a human-control grant the projection is agent context.
        (
            ControlClientKind.CLI,
            ProjectionRenderMode.HUMAN_READABLE,
            True,
            LocalDisclosureSink.AGENT_CONTEXT,
        ),
        (
            ControlClientKind.CLI,
            ProjectionRenderMode.MACHINE_READABLE,
            True,
            LocalDisclosureSink.AGENT_CONTEXT,
        ),
        (
            ControlClientKind.CLI,
            ProjectionRenderMode.HUMAN_READABLE,
            False,
            LocalDisclosureSink.AGENT_CONTEXT,
        ),
        (
            ControlClientKind.MCP_BRIDGE,
            ProjectionRenderMode.HUMAN_READABLE,
            True,
            LocalDisclosureSink.AGENT_CONTEXT,
        ),
    ),
)
async def test_connected_control_session_carries_trusted_presentation_to_daemon_projection(
    client_kind: ControlClientKind,
    render_mode: ProjectionRenderMode,
    controlling_tty: bool,
    expected_sink: LocalDisclosureSink,
) -> None:
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    client, server = _connected_control_pair()
    server_task = asyncio.create_task(daemon._serve_control_connection(server))  # pyright: ignore[reportPrivateUsage]
    try:
        session = await client_handshake(
            client,
            client_kind,
            "0.1.0",
            projection_render_mode=render_mode,
            output_is_controlling_tty=controlling_tty,
        )
        request = _request(daemon, ControlMethod.START, _start_body())
        session.admit(request)
        await write_control_frame(client, request)
        result = parse_control_result(await read_control_frame(client))
        session.correlate(result)

        expected_context = ClientProjectionContext(
            client_kind,
            render_mode,
            controlling_tty,
        )
        assert result.outcome == "ok"
        assert application.projections == [expected_context]
        assert resolve_client_disclosure_sink(expected_context) is expected_sink
    finally:
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)
        await daemon.close()


@pytest.mark.anyio
async def test_connected_service_client_accepts_coordination_check_pack() -> None:
    """A current coordination check survives the real client and control-wire path."""

    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    client_stream, server_stream = _connected_control_pair()
    server_task = asyncio.create_task(daemon._serve_control_connection(server_stream))  # pyright: ignore[reportPrivateUsage]
    service_client = None
    try:
        session = await client_handshake(client_stream, ControlClientKind.CLI, "0.3.0")
        service_client = _connected_client(  # pyright: ignore[reportPrivateUsage]
            client_stream,  # pyright: ignore[reportArgumentType]
            session,
            ControlClientKind.CLI,
        )
        application.projection_error = RuntimeError("test_projection_failure")
        request = _check_body().model_copy(update={"policy_packs": ("coordination/0.1.0",)})

        with pytest.raises(ControlError) as caught:
            await service_client.check(request, deadline_ms=3_000)

        assert caught.value.reason == "response_projection_failed"
        assert application.check_requests == [request]
    finally:
        if service_client is not None:
            await service_client.close()
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)
        await daemon.close()


@pytest.mark.anyio
async def test_connected_status_carries_the_serving_route_into_closure_readiness() -> None:
    """PR #937 review F1 over the real client and control wire (issue #913, ADR-018).

    A strict MCP bridge cannot dispatch AI-powered review, so under a ``required`` policy the
    missing review is a standing limitation on its status read; a policy-route read of the same
    ledger still owes it. The route must survive the client, the frame and the daemon handler.
    """

    from integration.application import test_closure_readiness_checklist as checklist

    session, _checked = await checklist._bandit_b(  # pyright: ignore[reportPrivateUsage]
        "memory", semantic="required"
    )
    daemon, application, _vault, _listener = _daemon()
    routes: list[object] = []
    fallback_projection = application.project_result_for_client

    async def status(
        request: object,
        *,
        route_profile: McpRouteProfile | None = None,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> StatusInternalResult:
        assert repository_privacy_context is None
        assert isinstance(request, StatusRequest)
        routes.append(route_profile)
        return await session.app.status(request, route_profile=route_profile)

    async def project(
        context: ClientProjectionContext, binding: ControlProjectionBinding, result: object
    ) -> ProjectedControlBody:
        if binding.method is ControlMethod.STATUS:
            assert type(result) is StatusInternalResult
            return checklist.public_status(result)
        return await fallback_projection(context, binding, result)

    application.status = status  # type: ignore[method-assign]
    application.project_result_for_client = project  # type: ignore[method-assign]
    await daemon.start()
    client_stream, server_stream = _connected_control_pair()
    server_task = asyncio.create_task(daemon._serve_control_connection(server_stream))  # pyright: ignore[reportPrivateUsage]
    service_client = None
    try:
        handshake = await client_handshake(client_stream, ControlClientKind.MCP_BRIDGE, "0.3.0")
        service_client = _connected_client(  # pyright: ignore[reportPrivateUsage]
            client_stream,  # pyright: ignore[reportArgumentType]
            handshake,
            ControlClientKind.MCP_BRIDGE,
        )
        states: dict[str, tuple[str | None, tuple[str, ...] | None]] = {}
        for route in ("strict", "policy"):
            result = (
                await service_client.status(
                    session.status_request(), deadline_ms=3_000, route_profile=route
                )
            ).root
            assert type(result) is StatusSuccessModel
            readiness = result.closure_readiness
            states[route] = (readiness.state, readiness.agent_actionable)
            if route == "strict":
                assert readiness.standing_limitations is not None
                assert "semantic_review_not_requested" in readiness.standing_limitations

        assert routes == ["strict", "policy"]
        assert states == {
            "strict": ("ready_with_limitations", ()),
            "policy": ("action_required", ("semantic_review_not_requested",)),
        }
    finally:
        if service_client is not None:
            await service_client.close()
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)
        await daemon.close()


@pytest.mark.anyio
async def test_route_less_status_reads_the_remembered_strict_route_across_a_restart(
    tmp_path: Path,
) -> None:
    """tb4n1 C8 (#985) over a real status read: the gate/CLI view matches the strict MCP view.

    A route-less read used to take the policy route and list ``semantic_review_not_requested``
    as work. After the session's strict bridge has read status, a route-less read of the same
    ledger shows it as a standing limitation, also from a new service over the same state.
    """

    from integration.application import test_closure_readiness_checklist as checklist

    session, _checked = await checklist._bandit_b(  # pyright: ignore[reportPrivateUsage]
        "memory", semantic="required"
    )
    route_path = tmp_path / "session-routes.json"

    async def read(route: McpRouteProfile | None) -> tuple[str | None, tuple[str, ...] | None]:
        daemon, application, _vault, _listener = _daemon(session_route_path=route_path)
        fallback_projection = application.project_result_for_client

        async def status(
            request: object,
            *,
            route_profile: McpRouteProfile | None = None,
            repository_privacy_context: RepositoryPrivacyContext | None = None,
        ) -> StatusInternalResult:
            del repository_privacy_context
            assert isinstance(request, StatusRequest)
            return await session.app.status(request, route_profile=route_profile)

        async def project(
            context: ClientProjectionContext, binding: ControlProjectionBinding, result: object
        ) -> ProjectedControlBody:
            if binding.method is ControlMethod.STATUS:
                assert type(result) is StatusInternalResult
                return checklist.public_status(result)
            return await fallback_projection(context, binding, result)

        application.status = status  # type: ignore[method-assign]
        application.project_result_for_client = project  # type: ignore[method-assign]
        await daemon.start()
        client_stream, server_stream = _connected_control_pair()
        server_task = asyncio.create_task(daemon._serve_control_connection(server_stream))  # pyright: ignore[reportPrivateUsage]
        service_client = None
        try:
            handshake = await client_handshake(client_stream, ControlClientKind.MCP_BRIDGE, "0.3.0")
            service_client = _connected_client(  # pyright: ignore[reportPrivateUsage]
                client_stream,  # pyright: ignore[reportArgumentType]
                handshake,
                ControlClientKind.MCP_BRIDGE,
            )
            result = (
                await service_client.status(
                    session.status_request(), deadline_ms=3_000, route_profile=route
                )
            ).root
            assert type(result) is StatusSuccessModel
            readiness = result.closure_readiness
            return readiness.state, readiness.agent_actionable
        finally:
            if service_client is not None:
                await service_client.close()
            server_task.cancel()
            await asyncio.gather(server_task, return_exceptions=True)
            await daemon.close()

    # Before any bridge call the route-less read is the policy view.
    assert await read(None) == ("action_required", ("semantic_review_not_requested",))
    assert await read("strict") == ("ready_with_limitations", ())
    # Each read above ran on a fresh service over the same state: the route survived.
    assert await read(None) == ("ready_with_limitations", ())


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("source", "session_id", "mapping_version", "structural_payload"),
    [
        (
            ObservationSource.CODEX_HOOK,
            "019ff5c8-real-client",
            "codex-obs-hook/1.0.0",
            JsonObject({"tool_name": "shell"}),
        ),
        (
            ObservationSource.CURSOR_HOOK,
            "cursor:019ff5c8-real-client",
            "cursor-hooks-3.17-v1",
            JsonObject(
                {
                    "changed_paths_digest": "hmac-sha256:" + "3" * 64,
                    "tool_name": "cursor_file_edit",
                }
            ),
        ),
    ],
)
async def test_connected_client_observation_ingest_uses_current_domain_wire(
    source: ObservationSource,
    session_id: str,
    mapping_version: str,
    structural_payload: JsonObject,
) -> None:
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    client_stream, server_stream = _connected_control_pair()
    server_task = asyncio.create_task(daemon._serve_control_connection(server_stream))  # pyright: ignore[reportPrivateUsage]
    service_client = None
    try:
        session = await client_handshake(client_stream, ControlClientKind.CLI, "0.1.0")
        service_client = _connected_client(  # pyright: ignore[reportPrivateUsage]
            client_stream,  # pyright: ignore[reportArgumentType]
            session,
            ControlClientKind.CLI,
        )
        envelope = ObservationEnvelope(
            session_commitment="hmac-sha256:" + "1" * 64,
            event_kind="PostToolUse",
            source_identity="hook:real-client-boundary",
            source=source,
            cursor=ObservationCursor(
                1,
                0,
                1,
                "hmac-sha256:" + "2" * 64,
                mapping_version,
            ),
            receipt_time=Timestamp("2026-08-12T12:00:00.000Z"),
            structural_payload=structural_payload,
            content_object_refs=(),
            gap_codes=(),
        )
        body = observation_ingest_request_to_json(ObservationIngestRequest(session_id, envelope))

        raw = await service_client.observation_ingest(body, deadline_ms=3_000)

        result = observation_ingest_result_from_json(raw)
        assert result.disposition is ObservationIngestDisposition.DUPLICATE
        assert application.observation_requests == [body]
        assert application.projections == []
    finally:
        if service_client is not None:
            await service_client.close()
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)
        await daemon.close()


@pytest.mark.anyio
async def test_capture_only_endpoint_bypasses_queued_sweeper_waiter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hook handoff stays live while one sweeper row is blocked.

    This drives the daemon dispatch path, rather than the coordinator directly. A structural
    observation request must still wait behind the same row gate and report its caller deadline.
    """

    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    observation_gate = daemon.composition.observation_gate
    await observation_gate.acquire()
    structural_waiting = asyncio.Event()
    original_acquire = daemon_module._acquire_dispatch_gate  # pyright: ignore[reportPrivateUsage]

    async def traced_acquire(gate: asyncio.Lock, deadline_ms: int | None) -> None:
        if gate is observation_gate:
            structural_waiting.set()
        await original_acquire(gate, deadline_ms)

    monkeypatch.setattr(daemon_module, "_acquire_dispatch_gate", traced_acquire)
    structural_task = asyncio.create_task(
        daemon.dispatch(
            ControlClientKind.CLI,
            _request(
                daemon,
                ControlMethod.OBSERVATION_INGEST,
                _capture_gate_body(capture_only=False),
            ),
        )
    )
    try:
        await asyncio.wait_for(structural_waiting.wait(), timeout=1.0)
        capture_body = _capture_gate_body(capture_only=True)
        capture = await asyncio.wait_for(
            daemon.dispatch(
                ControlClientKind.CLI,
                _request(daemon, ControlMethod.OBSERVATION_INGEST, capture_body),
            ),
            timeout=1.0,
        )
        assert capture.outcome == "ok", capture.body
        assert application.observation_requests == [capture_body]
        assert not structural_task.done()
    finally:
        observation_gate.release()
        structural = await asyncio.wait_for(structural_task, timeout=1.0)
        assert structural.outcome == "ok", structural.body
        assert len(application.observation_requests) == 2
        assert not daemon.composition.maintenance_gate.locked()
        await daemon.close()


@pytest.mark.anyio
async def test_recovery_holds_both_dispatch_gates_and_releases_for_capture() -> None:
    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    composition = daemon.composition
    effects = daemon_module._LockedHumanEffects(  # pyright: ignore[reportPrivateUsage]
        cast(ServiceLifecycle, SimpleNamespace()),
        cast(VaultService, SimpleNamespace()),
        daemon_module._PrivacyPolicyAppRelay(),  # pyright: ignore[reportPrivateUsage]
        maintenance_gate=composition.maintenance_gate,
        observation_gate=composition.observation_gate,
    )
    await effects._acquire_recovery_maintenance("recovery-gate")  # pyright: ignore[reportPrivateUsage]
    try:
        assert composition.maintenance_gate.locked()
        assert composition.observation_gate.locked()
        blocked = await asyncio.wait_for(
            daemon.dispatch(
                ControlClientKind.CLI,
                _request(
                    daemon,
                    ControlMethod.OBSERVATION_INGEST,
                    _capture_gate_body(capture_only=True),
                    deadline_ms=50,
                ),
            ),
            timeout=1.0,
        )
        assert blocked.outcome == "error"
        assert isinstance(blocked.body, ControlError)
        assert blocked.body.reason == "request_timeout"
    finally:
        effects._release_recovery_maintenance("recovery-gate")  # pyright: ignore[reportPrivateUsage]

    recovered = await daemon.dispatch(
        ControlClientKind.CLI,
        _request(daemon, ControlMethod.OBSERVATION_INGEST, _capture_gate_body(capture_only=True)),
    )
    assert recovered.outcome == "ok", recovered.body
    assert len(application.observation_requests) == 1
    assert not composition.maintenance_gate.locked()
    assert not composition.observation_gate.locked()
    await daemon.close()


@pytest.mark.anyio
async def test_cancelled_structural_endpoint_releases_observation_when_maintenance_waits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, _application, _vault, _listener = _daemon()
    await daemon.start()
    composition = daemon.composition
    observation_gate = composition.observation_gate
    maintenance_gate = composition.maintenance_gate
    await maintenance_gate.acquire()
    observation_acquired = asyncio.Event()
    original_acquire = daemon_module._acquire_dispatch_gate  # pyright: ignore[reportPrivateUsage]

    async def traced_acquire(gate: asyncio.Lock, deadline_ms: int | None) -> None:
        await original_acquire(gate, deadline_ms)
        if gate is observation_gate:
            observation_acquired.set()

    monkeypatch.setattr(daemon_module, "_acquire_dispatch_gate", traced_acquire)
    task = asyncio.create_task(
        daemon.dispatch(
            ControlClientKind.CLI,
            _request(
                daemon,
                ControlMethod.OBSERVATION_INGEST,
                _capture_gate_body(capture_only=False),
            ),
        )
    )
    await asyncio.wait_for(observation_acquired.wait(), timeout=1.0)
    task.cancel()
    cancelled = await task
    assert cancelled.outcome == "error"
    assert isinstance(cancelled.body, ControlError)
    assert cancelled.body.reason == "request_cancelled"
    assert maintenance_gate.locked()
    assert not observation_gate.locked()
    maintenance_gate.release()
    await daemon.close()


@pytest.mark.anyio
async def test_client_kind_and_state_admission_fail_closed() -> None:
    daemon, application, vault, _listener = _daemon()
    await daemon.start()
    forbidden = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.SERVICE_STATUS, JsonObject({})),
    )
    assert forbidden.outcome == "error"
    assert isinstance(forbidden.body, ControlError)
    assert forbidden.body.reason == "method_forbidden"

    locked = await daemon.dispatch(
        ControlClientKind.CLI,
        _request(daemon, ControlMethod.SERVICE_LOCK, JsonObject({})),
    )
    assert locked.outcome == "ok"
    assert daemon.status().state is ServiceState.LOCKED
    assert application.close_count == 1
    assert vault.lock_count >= 1

    rejected = await daemon.dispatch(
        ControlClientKind.UI,
        _request(daemon, ControlMethod.START, _start_body()),
    )
    assert rejected.outcome == "error"
    assert isinstance(rejected.body, ControlError)
    assert rejected.body.reason == "vault_locked"
    await daemon.close()


@pytest.mark.anyio
async def test_shutdown_is_idempotent_and_closes_owned_listener() -> None:
    daemon, application, vault, listener = _daemon()
    await daemon.start()
    await daemon.stop()
    await daemon.stop()
    assert listener.closed
    assert application.close_count == 1
    assert vault.close_count == 1


class _PassphraseVault:
    mode = VaultMode.PASSPHRASE
    generation = 3
    ready = False

    def __init__(self) -> None:
        self.lock_count = 0
        self.close_count = 0
        self.unlock_count = 0
        self._secret: bytes | None = None

    def expect_secret(self, value: bytes) -> None:
        self._secret = value

    async def unlock(self, handle: object) -> None:
        if self._secret is not None and handle != self._secret:
            raise AssertionError("unexpected unlock secret")
        self.unlock_count += 1
        self.ready = True
        self.generation += 1

    async def lock(self) -> None:
        self.lock_count += 1
        self.ready = False

    async def close(self) -> None:
        self.close_count += 1
        self.ready = False


class _SecretMemory:
    def capture(self, purpose: object, secret: bytearray) -> object:
        del purpose
        return bytes(secret)

    def close(self) -> None:
        return None


def _patch_auto_unlock_store(
    monkeypatch: pytest.MonkeyPatch,
    secret: bytes | None,
    reason: str = "none",
    *,
    staged: bool = False,
    promote_error: Exception | None = None,
) -> None:
    class _Store:
        def load_with_reason(self) -> tuple[bytearray | None, str]:
            if secret is None:
                return None, reason
            return bytearray(secret), reason

        def load_candidates_with_reason(
            self,
        ) -> tuple[tuple[tuple[bytearray, str], ...], str]:
            if secret is None:
                return (), reason
            slot = "staged_rotation" if staged else "active"
            return ((bytearray(secret), slot),), reason

        def slot_report(self) -> dict[str, str]:
            return {
                "active": "absent" if staged or secret is None else "present",
                "staged_initialization": "absent",
                "staged_rotation": "present" if staged and secret is not None else "absent",
            }

        def promote_staged_rotation(self) -> None:
            if promote_error is not None:
                raise promote_error

        def discard_staged_rotation(self) -> None:
            return None

        def promote_staged_initialization(self) -> None:
            if promote_error is not None:
                raise promote_error

        def discard_staged_initialization(self) -> None:
            return None

    def _factory(_bundle: Path) -> _Store:
        return _Store()

    monkeypatch.setattr(daemon_module, "AutoUnlockPassphraseStore", _factory)


def _soft_lock_daemon(
    tmp_path: Path,
    *,
    factory: object,
    vault: _PassphraseVault,
) -> ServiceDaemon:
    lifecycle = ServiceLifecycle(
        _Clock(),
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "4" * 64,
        instance_id=_INSTANCE_ID,
        singleton_lock_path=tmp_path / "service.lock",
    )
    composition = ServiceComposition(
        lifecycle=lifecycle,
        control_listener=_Listener(),  # pyright: ignore[reportArgumentType]
        secret_ingress_listener=None,
        human_control_listener=None,
        human_control_service=None,
        session_monitor=None,
        vault=vault,  # pyright: ignore[reportArgumentType]
        ready_application_factory=factory,  # pyright: ignore[reportArgumentType]
        secret_memory=_SecretMemory(),  # pyright: ignore[reportArgumentType]
        auto_unlock_bundle=tmp_path,
    )
    return ServiceDaemon(_composition=composition)


@pytest.mark.anyio
async def test_soft_lock_auto_ready_reopens_on_next_ordinary_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = _Application()
    vault = _PassphraseVault()
    secret = b"correct horse battery staple!!"
    vault.expect_secret(secret)

    async def factory(service_generation: int, vault_generation: int) -> _Application:
        assert service_generation == 7
        assert vault_generation == 4
        return application

    _patch_auto_unlock_store(monkeypatch, secret)
    daemon = _soft_lock_daemon(tmp_path, factory=factory, vault=vault)
    await daemon.start()
    assert daemon.status().state is ServiceState.LOCKED
    daemon._state_reason = "idle_relock"  # pyright: ignore[reportPrivateUsage]

    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.START, _start_body()),
    )

    assert result.outcome == "ok"
    assert vault.unlock_count == 1
    assert daemon.status().state is ServiceState.READY
    assert daemon.status().state_reason == "none"
    assert application.start_calls == 1
    await daemon.close()


@pytest.mark.anyio
async def test_staged_promote_failure_after_unlock_keeps_vault_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A keyring promote failure after the staged candidate unlocked is hygiene, not a relock.

    The unlock already succeeded, so failing to reconcile the staged platform-store entry must
    not send a ready vault back to LOCKED (clients would see vault_locked until restart).
    """

    application = _Application()
    vault = _PassphraseVault()
    secret = b"correct horse battery staple!!"
    vault.expect_secret(secret)

    async def factory(service_generation: int, vault_generation: int) -> _Application:
        del service_generation, vault_generation
        return application

    _patch_auto_unlock_store(
        monkeypatch,
        secret,
        staged=True,
        promote_error=OSError("keyring write failed"),
    )
    daemon = _soft_lock_daemon(tmp_path, factory=factory, vault=vault)
    await daemon.start()
    daemon._state_reason = "idle_relock"  # pyright: ignore[reportPrivateUsage]

    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.START, _start_body()),
    )

    assert result.outcome == "ok"
    assert vault.unlock_count == 1
    assert vault.ready is True
    assert vault.lock_count == 0, "a promote failure must not relock the ready vault"
    assert daemon.status().state is ServiceState.READY
    assert daemon.status().state_reason == "none"
    assert application.start_calls == 1
    await daemon.close()


@pytest.mark.anyio
async def test_production_composition_promote_failure_keeps_unlocked_vault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Startup auto-unlock must leave a ready vault when staged promote fails (#492)."""

    from yoetz.adapters.keys.encrypted_vault import EncryptedVaultStore
    from yoetz.adapters.keys.secret_memory import LocalSecretMemory
    from yoetz.ports.secret_memory import SecretPurpose
    from yoetz.service.unlock import UnlockThrottleStore
    from yoetz.service.vault import VaultService

    root = tmp_path / "data"
    metadata = tmp_path / "state"
    root.mkdir(mode=0o700)
    metadata.mkdir(mode=0o700)
    secret = b"correct horse battery staple!!"
    clock = _Clock()
    throttle = UnlockThrottleStore(
        metadata / "unlock-throttle.json",
        installation_id=INSTALLATION_ID,
        writer_instance_id=_INSTANCE_ID,
        clock=clock,  # pyright: ignore[reportArgumentType]
    )
    record = throttle.stage_initial_record()
    marker_store = daemon_module._InstallationStateStore(  # pyright: ignore[reportPrivateUsage]
        root / "installation-state.json",
        metadata / "unlock-throttle.json",
        metadata / "service-generation.json",
    )
    memory = LocalSecretMemory()
    setup_vault = VaultService(
        installation_id=INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,  # pyright: ignore[reportArgumentType]
        vault_store_factory=lambda: EncryptedVaultStore(root / "vault"),
        pristine_state_digest="sha256:" + "1" * 64,
        publish_mode=marker_store.publish,
    )
    await setup_vault.initialize_passphrase(
        memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(secret)),
        record.record_digest,
    )
    await setup_vault.close()
    memory.close()

    _patch_auto_unlock_store(
        monkeypatch,
        secret,
        staged=True,
        promote_error=OSError("keyring write failed"),
    )

    paths = daemon_module._ProductionPaths(  # pyright: ignore[reportPrivateUsage]
        root,
        metadata / "service-generation.json",
        metadata / "unlock-throttle.json",
        metadata / "service.lock",
        metadata,
    )

    async def bind(_kind: str) -> _Listener:
        return _Listener()

    binders = daemon_module._ListenerBinders(  # pyright: ignore[reportPrivateUsage]
        lambda: bind("control"),  # pyright: ignore[reportArgumentType]
        lambda: bind("secret"),  # pyright: ignore[reportArgumentType]
        lambda: bind("human"),  # pyright: ignore[reportArgumentType]
    )
    composition = await daemon_module._production_composition(  # pyright: ignore[reportPrivateUsage]
        _config=YoetzConfig(),
        _paths=paths,
        _binders=binders,
    )
    daemon = ServiceDaemon(_composition=composition)
    try:
        assert composition.vault.ready is True
        assert composition.auto_unlock_reason == "none"
        await composition.lifecycle.transition(ServiceState.LOCKED)
    finally:
        await daemon.close()


@pytest.mark.anyio
async def test_transient_activation_failure_keeps_soft_reready_eligible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A succeeded soft unlock whose activation fails transiently must stay retryable (#276).

    One event-loop-lag blip during ready activation used to demote the service to a terminal
    LOCKED(unlock_failed) that nothing ever reconsidered; the very next dispatch must retry
    and succeed instead.
    """

    application = _Application()
    vault = _PassphraseVault()
    secret = b"correct horse battery staple!!"
    vault.expect_secret(secret)
    failures = {"remaining": 1}

    async def factory(service_generation: int, vault_generation: int) -> _Application:
        del service_generation, vault_generation
        if failures["remaining"] > 0:
            failures["remaining"] -= 1
            raise RuntimeError("transient saturation")
        return application

    _patch_auto_unlock_store(monkeypatch, secret)
    daemon = _soft_lock_daemon(tmp_path, factory=factory, vault=vault)
    await daemon.start()
    daemon._state_reason = "idle_relock"  # pyright: ignore[reportPrivateUsage]

    rejected = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.START, _start_body()),
    )
    assert rejected.outcome == "error"
    assert isinstance(rejected.body, ControlError)
    assert rejected.body.reason == "vault_locked"
    assert rejected.body.retryable is True, "a transient activation failure must say retryable"
    assert daemon.status().state is ServiceState.LOCKED
    assert daemon.status().state_reason == "idle_relock", (
        "the soft-lock reason survives so the next dispatch re-attempts auto-ready"
    )

    result = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.START, _start_body()),
    )
    assert result.outcome == "ok"
    assert daemon.status().state is ServiceState.READY
    assert daemon.status().state_reason == "none"
    await daemon.close()


@pytest.mark.anyio
async def test_repeated_activation_failures_degrade_to_terminal_unlock_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The transient-failure allowance is bounded; a persistent fault still goes terminal."""

    application = _Application()
    vault = _PassphraseVault()
    secret = b"correct horse battery staple!!"
    vault.expect_secret(secret)

    async def factory(service_generation: int, vault_generation: int) -> _Application:
        del service_generation, vault_generation
        raise RuntimeError("persistent activation fault")

    _patch_auto_unlock_store(monkeypatch, secret)
    daemon = _soft_lock_daemon(tmp_path, factory=factory, vault=vault)
    await daemon.start()
    daemon._state_reason = "idle_relock"  # pyright: ignore[reportPrivateUsage]
    limit = daemon_module._SOFT_REREADY_ACTIVATION_RETRY_LIMIT  # pyright: ignore[reportPrivateUsage]

    for _attempt in range(limit):
        rejected = await daemon.dispatch(
            ControlClientKind.MCP_BRIDGE,
            _request(daemon, ControlMethod.START, _start_body()),
        )
        assert rejected.outcome == "error"
        assert isinstance(rejected.body, ControlError)
        assert rejected.body.retryable is True
        assert daemon.status().state_reason == "idle_relock"

    exhausted = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.START, _start_body()),
    )
    assert exhausted.outcome == "error"
    assert isinstance(exhausted.body, ControlError)
    assert daemon.status().state_reason == "unlock_failed"

    final_unlocks = vault.unlock_count
    terminal = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.START, _start_body()),
    )
    assert terminal.outcome == "error"
    assert isinstance(terminal.body, ControlError)
    assert terminal.body.retryable is False, "a terminal lock must not claim to be retryable"
    assert vault.unlock_count == final_unlocks, "terminal state stops burning unlock attempts"
    assert application.start_calls == 0
    await daemon.close()


@pytest.mark.anyio
async def test_explicit_lock_does_not_auto_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = _Application()
    vault = _PassphraseVault()

    async def factory(service_generation: int, vault_generation: int) -> _Application:
        del service_generation, vault_generation
        return application

    _patch_auto_unlock_store(monkeypatch, b"correct horse battery staple!!")
    daemon = _soft_lock_daemon(tmp_path, factory=factory, vault=vault)
    await daemon.start()
    daemon._state_reason = "explicit_lock"  # pyright: ignore[reportPrivateUsage]

    rejected = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.START, _start_body()),
    )

    assert rejected.outcome == "error"
    assert isinstance(rejected.body, ControlError)
    assert rejected.body.reason == "vault_locked"
    assert vault.unlock_count == 0
    assert daemon.status().state is ServiceState.LOCKED
    await daemon.close()


@pytest.mark.anyio
async def test_monitor_loss_does_not_auto_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Losing the session monitor requires a ceremony, unlike the recoverable soft locks.

    Idle, session lock, and suspend all describe conditions the service can watch recover from.
    Monitor loss removes the capability that produces those events for the life of the process,
    so auto-re-ready would make the lock momentary and then run on with session-lock relock
    silently no longer applying -- the containment ADR-008 describes, gone without notice.
    """

    application = _Application()
    vault = _PassphraseVault()

    async def factory(service_generation: int, vault_generation: int) -> _Application:
        del service_generation, vault_generation
        return application

    _patch_auto_unlock_store(monkeypatch, b"correct horse battery staple!!")
    daemon = _soft_lock_daemon(tmp_path, factory=factory, vault=vault)
    await daemon.start()
    daemon._state_reason = "monitor_lost"  # pyright: ignore[reportPrivateUsage]

    rejected = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.START, _start_body()),
    )

    assert rejected.outcome == "error"
    assert isinstance(rejected.body, ControlError)
    assert rejected.body.reason == "vault_locked"
    assert vault.unlock_count == 0
    assert daemon.status().state is ServiceState.LOCKED
    await daemon.close()


@pytest.mark.anyio
async def test_soft_lock_absent_auto_unlock_stays_hard_locked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application = _Application()
    vault = _PassphraseVault()

    async def factory(service_generation: int, vault_generation: int) -> _Application:
        del service_generation, vault_generation
        return application

    _patch_auto_unlock_store(monkeypatch, None, "auto_unlock_absent")
    daemon = _soft_lock_daemon(tmp_path, factory=factory, vault=vault)
    await daemon.start()
    daemon._state_reason = "idle_relock"  # pyright: ignore[reportPrivateUsage]

    rejected = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.START, _start_body()),
    )
    assert rejected.outcome == "error"
    assert isinstance(rejected.body, ControlError)
    assert rejected.body.reason == "vault_locked"
    assert vault.unlock_count == 0
    assert daemon.status().state_reason == "passphrase_required"

    again = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.START, _start_body()),
    )
    assert again.outcome == "error"
    assert vault.unlock_count == 0
    await daemon.close()


@pytest.mark.anyio
async def test_idle_close_publishes_idle_relock_reason() -> None:
    daemon, application, vault, _listener = _daemon()
    await daemon.start()
    assert daemon.status().state_reason == "none"
    # Lifecycle idle drain closes ready without daemon.lock; the close path must publish
    # idle_relock so soft auto-ready can recognize the reason.
    await daemon._close_ready_locked()  # pyright: ignore[reportPrivateUsage]
    assert application.close_count == 1
    assert vault.lock_count >= 1
    assert daemon.status().state_reason == "idle_relock"
    await daemon.close()


@pytest.mark.anyio
async def test_unlock_activation_constructs_exact_generation_once(tmp_path: Path) -> None:
    application = _Application()
    calls: list[tuple[int, int]] = []

    async def factory(service_generation: int, vault_generation: int) -> _Application:
        calls.append((service_generation, vault_generation))
        return application

    daemon, vault = _locked_daemon(tmp_path, factory)
    await daemon.start()
    assert daemon.status().state is ServiceState.LOCKED
    await daemon.composition.lifecycle.transition(ServiceState.UNLOCKING)
    vault.ready = True

    await daemon.activate_ready_application(7, 3)

    assert calls == [(7, 3)]
    assert daemon.status().state is ServiceState.READY
    assert daemon.status().state_reason == "none"
    await daemon.lock()
    assert application.close_count == 1
    assert not vault.ready
    await daemon.close()


@pytest.mark.anyio
async def test_ready_maintenance_sweeps_immediately_repeats_and_cancels_before_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    two_sweeps = asyncio.Event()

    class Application(_Application):
        ready_recommendation_refresh: object
        observation_sweep: object

        async def close(self) -> None:
            events.append("application_close")
            await super().close()

    class Vault(_Vault):
        async def lock(self) -> None:
            events.append("vault_lock")
            await super().lock()

    application = Application()

    async def refresh() -> object:
        events.append("recommendation_refresh")
        return object()

    async def sweep() -> ObservationDrainSummary:
        events.append("sweep")
        if events.count("sweep") == 1:
            asyncio.get_running_loop().call_soon(events.append, "control_turn")
        if events.count("sweep") >= 2:
            two_sweeps.set()
        return ObservationDrainSummary(
            attempted=1,
            acknowledged=1,
            retry_pending=0,
            quarantined=0,
            reasons=(),
        )

    application.ready_recommendation_refresh = refresh
    application.observation_sweep = sweep
    vault = Vault()
    vault.ready = False
    lifecycle = ServiceLifecycle(
        _Clock(),
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "2" * 64,
        instance_id=_INSTANCE_ID,
        singleton_lock_path=tmp_path / "service.lock",
    )

    async def factory(_service_generation: int, _vault_generation: int) -> _Application:
        return application

    daemon = ServiceDaemon(
        _composition=ServiceComposition(
            lifecycle=lifecycle,
            control_listener=_Listener(),  # pyright: ignore[reportArgumentType]
            secret_ingress_listener=None,
            human_control_listener=None,
            human_control_service=None,
            session_monitor=None,
            vault=vault,
            ready_application_factory=factory,
        )
    )
    monkeypatch.setattr(daemon_module, "_OBSERVATION_SWEEP_INTERVAL_SECONDS", 0.01)
    await daemon.start()
    await daemon.composition.lifecycle.transition(ServiceState.UNLOCKING)
    vault.ready = True
    await daemon.activate_ready_application(7, 3)

    await asyncio.wait_for(two_sweeps.wait(), timeout=1)
    assert events[:4] == ["sweep", "recommendation_refresh", "control_turn", "sweep"]
    await daemon.lock()
    count_after_lock = events.count("sweep")
    await asyncio.sleep(0.03)
    assert events.count("sweep") == count_after_lock
    assert events.index("application_close") < events.index("vault_lock")
    await daemon.close()


@pytest.mark.anyio
async def test_ready_maintenance_recovers_lineage_before_and_during_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    recovered_twice = asyncio.Event()

    class Application(_Application):
        observation_sweep: object
        recovery_calls = 0

        async def recover_lineage(self) -> object:
            events.append("recovery")
            self.recovery_calls += 1
            if self.recovery_calls >= 2:
                recovered_twice.set()
            return (), ()

    application = Application()

    async def sweep() -> ObservationDrainSummary:
        events.append("sweep")
        return ObservationDrainSummary(
            attempted=0,
            acknowledged=0,
            retry_pending=0,
            quarantined=0,
            reasons=(),
        )

    application.observation_sweep = sweep
    vault = _Vault()
    vault.ready = False
    lifecycle = ServiceLifecycle(
        _Clock(),
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "2" * 64,
        instance_id=_INSTANCE_ID,
        singleton_lock_path=tmp_path / "service.lock",
    )

    async def factory(_service_generation: int, _vault_generation: int) -> _Application:
        return application

    daemon = ServiceDaemon(
        _composition=ServiceComposition(
            lifecycle=lifecycle,
            control_listener=_Listener(),  # pyright: ignore[reportArgumentType]
            secret_ingress_listener=None,
            human_control_listener=None,
            human_control_service=None,
            session_monitor=None,
            vault=vault,
            ready_application_factory=factory,
        )
    )
    monkeypatch.setattr(daemon_module, "_OBSERVATION_SWEEP_INTERVAL_SECONDS", 0.01)
    await daemon.start()
    await daemon.composition.lifecycle.transition(ServiceState.UNLOCKING)
    vault.ready = True
    await daemon.activate_ready_application(7, 3)

    await asyncio.wait_for(recovered_twice.wait(), timeout=1)
    assert events[0] == "recovery"
    assert events.index("sweep") > events.index("recovery")
    await daemon.lock()
    await daemon.close()


@pytest.mark.anyio
@pytest.mark.parametrize("backlog_drains", [True, False])
async def test_ready_maintenance_judges_contact_after_delivering_queued_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backlog_drains: bool
) -> None:
    """Queued host events are contact evidence, so ordinary recovery follows their delivery (#837).

    While consecutive passes still resolve rows, a due recovery waits for the next pass; an
    endless stream still yields to recovery once it is one interval overdue.
    """

    events: list[str] = []
    recovered_after_turn = asyncio.Event()
    resolving_passes = 3

    class Application(_Application):
        observation_sweep: object

        async def recover_lineage(self) -> object:
            events.append("recovery")
            if events.count("recovery") >= 2:
                recovered_after_turn.set()
            return (), ()

    application = Application()

    async def sweep() -> ObservationDrainSummary:
        ordinary = events.count("sweep") + events.count("sweep:resolved")
        # The first (startup) pass is dry; later passes drain a backlog of queued rows.
        resolving = ordinary >= 1 and (not backlog_drains or ordinary <= resolving_passes)
        events.append("sweep:resolved" if resolving else "sweep")
        return ObservationDrainSummary(
            attempted=int(resolving),
            acknowledged=int(resolving),
            retry_pending=0,
            quarantined=0,
            reasons=(),
        )

    application.observation_sweep = sweep
    vault = _Vault()
    vault.ready = False
    lifecycle = ServiceLifecycle(
        _Clock(),
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "2" * 64,
        instance_id=_INSTANCE_ID,
        singleton_lock_path=tmp_path / "service.lock",
    )

    async def factory(_service_generation: int, _vault_generation: int) -> _Application:
        return application

    daemon = ServiceDaemon(
        _composition=ServiceComposition(
            lifecycle=lifecycle,
            control_listener=_Listener(),  # pyright: ignore[reportArgumentType]
            secret_ingress_listener=None,
            human_control_listener=None,
            human_control_service=None,
            session_monitor=None,
            vault=vault,
            ready_application_factory=factory,
        )
    )
    # Three immediate passes fit well inside one interval; the endless stream outlasts it.
    monkeypatch.setattr(daemon_module, "_OBSERVATION_SWEEP_INTERVAL_SECONDS", 0.2)
    monkeypatch.setattr(daemon_module, "_OBSERVATION_SWEEP_PROGRESS_DELAY_SECONDS", 0.0)
    await daemon.start()
    await daemon.composition.lifecycle.transition(ServiceState.UNLOCKING)
    vault.ready = True
    await daemon.activate_ready_application(7, 3)

    await asyncio.wait_for(recovered_after_turn.wait(), timeout=5)
    await daemon.lock()
    await daemon.close()
    assert events[:2] == ["recovery", "sweep"]
    second = events.index("recovery", 1)
    # Recovery never precedes the pass of its own turn.
    assert events[second - 1].startswith("sweep")
    if backlog_drains:
        # It waited out the backlog and ran right after the first dry pass.
        assert events[1:second] == ["sweep", *(["sweep:resolved"] * resolving_passes), "sweep"]
    else:
        # A stream that never runs dry still cannot starve recovery.
        assert events[second - 1] == "sweep:resolved"


@pytest.mark.anyio
async def test_sweep_resolved_rows_defer_idle_relock_until_the_spool_runs_dry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A live workspace whose hooks keep resolving observation rows outlives many idle windows
    with the service still READY for check/receipt; once the spool runs dry the vault still
    relocks one full window later (#291)."""

    class _MutableClock:
        monotonic = 10.0

        def now_utc(self) -> datetime:
            return datetime(2026, 7, 19, tzinfo=UTC)

        def monotonic_seconds(self) -> float:
            return self.monotonic

    clock = _MutableClock()
    resolving = True
    sweeps = 0

    async def sweep() -> ObservationDrainSummary:
        nonlocal sweeps
        sweeps += 1
        resolved = 1 if resolving else 0
        return ObservationDrainSummary(
            attempted=resolved,
            acknowledged=resolved,
            retry_pending=0,
            quarantined=0,
            reasons=(),
        )

    application = _Application()
    application.observation_sweep = sweep  # pyright: ignore[reportAttributeAccessIssue]
    vault = _Vault()
    vault.ready = False
    ready_close_relay = daemon_module._ReadyCloseRelay()  # pyright: ignore[reportPrivateUsage]
    lifecycle = ServiceLifecycle(
        clock,  # pyright: ignore[reportArgumentType]
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "2" * 64,
        instance_id=_INSTANCE_ID,
        singleton_lock_path=tmp_path / "service.lock",
        close_ready_composition=ready_close_relay,
    )

    async def factory(_service_generation: int, _vault_generation: int) -> _Application:
        return application

    daemon = ServiceDaemon(
        _composition=ServiceComposition(
            lifecycle=lifecycle,
            control_listener=_Listener(),  # pyright: ignore[reportArgumentType]
            secret_ingress_listener=None,
            human_control_listener=None,
            human_control_service=None,
            session_monitor=None,
            vault=vault,
            ready_application_factory=factory,
            ready_close_relay=ready_close_relay,
        )
    )
    monkeypatch.setattr(daemon_module, "_OBSERVATION_SWEEP_INTERVAL_SECONDS", 0.005)
    monkeypatch.setattr(daemon_module, "_OBSERVATION_SWEEP_PROGRESS_DELAY_SECONDS", 0.005)
    await daemon.start()
    await daemon.composition.lifecycle.transition(ServiceState.UNLOCKING)
    vault.ready = True
    await daemon.activate_ready_application(7, 3)
    monitor = asyncio.create_task(lifecycle.run_idle_monitor(poll_seconds=0.001))

    # Three windows' worth of fake time with hooks resolving rows: never relocks.
    for _ in range(3):
        clock.monotonic += 3_599.0
        target = sweeps + 2
        for _ in range(400):
            await asyncio.sleep(0.005)
            if sweeps >= target:
                break
        assert daemon.status().state is ServiceState.READY

    # Spool runs dry: the next full window with nothing resolved still relocks.
    resolving = False
    target = sweeps + 2
    for _ in range(400):
        await asyncio.sleep(0.005)
        if sweeps >= target:
            break
    clock.monotonic += 3_601.0
    for _ in range(400):
        await asyncio.sleep(0.005)
        if daemon.status().state is ServiceState.LOCKED:
            break
    assert daemon.status().state is ServiceState.LOCKED
    assert daemon.status().state_reason == "idle_relock"
    assert not vault.ready

    monitor.cancel()
    with pytest.raises(asyncio.CancelledError):
        await monitor
    await daemon.close()


@pytest.mark.anyio
async def test_retrying_observation_rows_never_defer_idle_relock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only resolution is liveness. A wedged or poisoned row re-appears in every single sweep,
    so counting retries would let one such row hold the vault unlocked forever. Same timing as
    the sibling test above, which stays READY because its rows acknowledge (#291)."""

    class _MutableClock:
        monotonic = 10.0

        def now_utc(self) -> datetime:
            return datetime(2026, 7, 19, tzinfo=UTC)

        def monotonic_seconds(self) -> float:
            return self.monotonic

    clock = _MutableClock()
    sweeps = 0

    async def sweep() -> ObservationDrainSummary:
        nonlocal sweeps
        sweeps += 1
        return ObservationDrainSummary(
            attempted=1,
            acknowledged=0,
            retry_pending=1,
            quarantined=0,
            reasons=(),
        )

    application = _Application()
    application.observation_sweep = sweep  # pyright: ignore[reportAttributeAccessIssue]
    vault = _Vault()
    vault.ready = False
    ready_close_relay = daemon_module._ReadyCloseRelay()  # pyright: ignore[reportPrivateUsage]
    lifecycle = ServiceLifecycle(
        clock,  # pyright: ignore[reportArgumentType]
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "2" * 64,
        instance_id=_INSTANCE_ID,
        singleton_lock_path=tmp_path / "service.lock",
        close_ready_composition=ready_close_relay,
    )

    async def factory(_service_generation: int, _vault_generation: int) -> _Application:
        return application

    daemon = ServiceDaemon(
        _composition=ServiceComposition(
            lifecycle=lifecycle,
            control_listener=_Listener(),  # pyright: ignore[reportArgumentType]
            secret_ingress_listener=None,
            human_control_listener=None,
            human_control_service=None,
            session_monitor=None,
            vault=vault,
            ready_application_factory=factory,
            ready_close_relay=ready_close_relay,
        )
    )
    monkeypatch.setattr(daemon_module, "_OBSERVATION_SWEEP_INTERVAL_SECONDS", 0.005)
    monkeypatch.setattr(daemon_module, "_OBSERVATION_SWEEP_PROGRESS_DELAY_SECONDS", 0.005)
    await daemon.start()
    await daemon.composition.lifecycle.transition(ServiceState.UNLOCKING)
    vault.ready = True
    await daemon.activate_ready_application(7, 3)
    monitor = asyncio.create_task(lifecycle.run_idle_monitor(poll_seconds=0.001))

    # Rows really are flowing through the sweep — the retries just must not count.
    for _ in range(400):
        await asyncio.sleep(0.005)
        if sweeps >= 3:
            break
    assert sweeps >= 3
    assert daemon.status().state is ServiceState.READY

    clock.monotonic += 3_601.0
    for _ in range(400):
        await asyncio.sleep(0.005)
        if daemon.status().state is ServiceState.LOCKED:
            break
    assert daemon.status().state is ServiceState.LOCKED
    assert daemon.status().state_reason == "idle_relock"
    assert not vault.ready

    monitor.cancel()
    with pytest.raises(asyncio.CancelledError):
        await monitor
    await daemon.close()


@pytest.mark.anyio
@pytest.mark.parametrize("stall", [False, True])
async def test_only_the_deadline_reports_sweep_deadline_exceeded(
    monkeypatch: pytest.MonkeyPatch, stall: bool
) -> None:
    """asyncio.TimeoutError is TimeoutError: a socket timeout inside a sweep is not the deadline."""

    bounded_reasons: list[str] = []
    recorded_exceptions: list[BaseException] = []

    def record_bounded(*, component: str, operation: str, reason: str) -> str:
        assert component == "service.daemon"
        assert operation == "observation_sweep_failed"
        bounded_reasons.append(reason)
        return "err_00000000-0000-4000-8000-000000000000"

    def record_exception(exc: BaseException, *, component: str, operation: str) -> str:
        assert component == "service.daemon"
        assert operation == "observation_sweep_failed"
        recorded_exceptions.append(exc)
        return "err_00000000-0000-4000-8000-000000000001"

    monkeypatch.setattr(daemon_module, "record_bounded_event_without_raising", record_bounded)
    monkeypatch.setattr(
        daemon_module, "record_unexpected_exception_without_raising", record_exception
    )
    monkeypatch.setattr(daemon_module, "_OBSERVATION_SWEEP_DEADLINE_SECONDS", 0.05)

    async def sweep() -> ObservationDrainSummary:
        if stall:
            await asyncio.sleep(5)
        # A socket or OS read timeout raised by the sweep's own work, not by its deadline.
        raise TimeoutError("inner socket timeout")

    daemon, _application, _vault, _listener = _daemon()

    summary = await daemon._bounded_observation_sweep(sweep)  # pyright: ignore[reportPrivateUsage]

    assert summary is None
    if stall:
        # Only the real deadline is a non-exception operating state.
        assert bounded_reasons == ["sweep_deadline_exceeded"]
        assert recorded_exceptions == []
    else:
        # The sweep's own exception keeps its identity instead of a generic token (issue #278).
        assert bounded_reasons == []
        assert len(recorded_exceptions) == 1
        assert isinstance(recorded_exceptions[0], TimeoutError)
    await daemon.close()


@pytest.mark.anyio
async def test_ordinary_sweep_exception_keeps_its_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A raised sweep records the exception itself, not a generic token (issue #278)."""

    recorded: list[tuple[BaseException, str, str]] = []

    def record_exception(exc: BaseException, *, component: str, operation: str) -> str:
        recorded.append((exc, component, operation))
        return "err_00000000-0000-4000-8000-000000000002"

    monkeypatch.setattr(
        daemon_module, "record_unexpected_exception_without_raising", record_exception
    )

    async def sweep() -> ObservationDrainSummary:
        raise RuntimeError("sweep exploded")

    daemon, _application, _vault, _listener = _daemon()
    summary = await daemon._bounded_observation_sweep(sweep)  # pyright: ignore[reportPrivateUsage]
    assert summary is None
    assert len(recorded) == 1
    exc, component, operation = recorded[0]
    assert isinstance(exc, RuntimeError)
    assert (component, operation) == ("service.daemon", "observation_sweep_failed")
    await daemon.close()


@pytest.mark.anyio
async def test_endpoint_is_published_only_after_ready_activation(tmp_path: Path) -> None:
    """A control socket that exists must already be able to answer a handshake."""

    events: list[str] = []

    async def publish(_instance: object) -> None:
        events.append("publish")

    async def factory(_service_generation: int, _vault_generation: int) -> _Application:
        events.append("activate_start")
        for _ in range(3):
            await asyncio.sleep(0)
        events.append("activate_end")
        return _Application()

    vault = _Vault()
    vault.ready = True
    lifecycle = ServiceLifecycle(
        _Clock(),
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "2" * 64,
        instance_id=_INSTANCE_ID,
        singleton_lock_path=tmp_path / "service.lock",
        endpoint_publisher=publish,
    )
    daemon = ServiceDaemon(
        _composition=ServiceComposition(
            lifecycle=lifecycle,
            control_listener=_Listener(),  # pyright: ignore[reportArgumentType]
            secret_ingress_listener=None,
            human_control_listener=None,
            human_control_service=None,
            session_monitor=None,
            vault=vault,
            ready_application_factory=factory,
        )
    )

    await daemon.start()

    assert events == ["activate_start", "activate_end", "publish"]
    assert daemon.status().state is ServiceState.READY
    await daemon.close()


@pytest.mark.anyio
async def test_first_sweep_waits_for_the_control_accept_loop(tmp_path: Path) -> None:
    """Maintenance is created before the accept loops exist; it must not run before them."""

    events: list[str] = []
    swept = asyncio.Event()

    class Listener(_Listener):
        async def accept(self) -> object:
            if "accept_armed" not in events:
                events.append("accept_armed")
            return await super().accept()

    async def sweep() -> ObservationDrainSummary:
        events.append("sweep")
        swept.set()
        return ObservationDrainSummary(
            attempted=0,
            acknowledged=0,
            retry_pending=0,
            quarantined=0,
            reasons=(),
        )

    application = _Application()
    application.observation_sweep = sweep  # pyright: ignore[reportAttributeAccessIssue]

    async def factory(_service_generation: int, _vault_generation: int) -> _Application:
        return application

    vault = _Vault()
    vault.ready = True
    lifecycle = ServiceLifecycle(
        _Clock(),
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "2" * 64,
        instance_id=_INSTANCE_ID,
        singleton_lock_path=tmp_path / "service.lock",
    )
    daemon = ServiceDaemon(
        _composition=ServiceComposition(
            lifecycle=lifecycle,
            control_listener=Listener(),  # pyright: ignore[reportArgumentType]
            secret_ingress_listener=None,
            human_control_listener=None,
            human_control_service=None,
            session_monitor=None,
            vault=vault,
            ready_application_factory=factory,
        )
    )

    serving = asyncio.create_task(daemon.serve())
    try:
        await asyncio.wait_for(swept.wait(), timeout=2)
    finally:
        await daemon.stop()
        await asyncio.wait_for(serving, timeout=2)

    assert events.index("accept_armed") < events.index("sweep")


@pytest.mark.anyio
async def test_preunlocked_vault_activates_ready_application_on_daemon_start(
    tmp_path: Path,
) -> None:
    application = _Application()
    calls: list[tuple[int, int]] = []

    async def factory(service_generation: int, vault_generation: int) -> _Application:
        calls.append((service_generation, vault_generation))
        return application

    daemon, vault = _locked_daemon(tmp_path, factory)
    vault.ready = True

    await daemon.start()

    assert calls == [(7, 3)]
    assert daemon.status().state is ServiceState.READY
    await daemon.close()


@pytest.mark.anyio
async def test_locked_passphrase_vault_never_reports_keyring_locked(tmp_path: Path) -> None:
    async def factory(_service_generation: int, _vault_generation: int) -> _Application:
        return _Application()

    daemon, vault = _locked_daemon(tmp_path, factory)
    vault.mode = VaultMode.PASSPHRASE

    await daemon.start()

    assert daemon.status().state is ServiceState.LOCKED
    assert daemon.status().state_reason == "passphrase_required"
    await daemon.close()


@pytest.mark.anyio
async def test_unlock_activation_revalidates_after_factory_and_closes_partial(
    tmp_path: Path,
) -> None:
    application = _Application()
    daemon: ServiceDaemon
    vault: _Vault

    async def factory(_service_generation: int, _vault_generation: int) -> _Application:
        vault.generation = 4
        return application

    daemon, vault = _locked_daemon(tmp_path, factory)
    await daemon.start()
    await daemon.composition.lifecycle.transition(ServiceState.UNLOCKING)
    vault.ready = True

    with pytest.raises(LifecycleError, match="invalid_transition"):
        await daemon.activate_ready_application(7, 3)

    assert application.close_count == 1
    assert not vault.ready
    assert daemon.status().state is ServiceState.LOCKED
    assert daemon.status().state_reason == "unlock_failed"
    await daemon.close()


@pytest.mark.anyio
async def test_lock_serializes_with_in_flight_ready_activation(tmp_path: Path) -> None:
    application = _Application()
    entered = asyncio.Event()
    release = asyncio.Event()

    async def factory(_service_generation: int, _vault_generation: int) -> _Application:
        entered.set()
        await release.wait()
        return application

    daemon, vault = _locked_daemon(tmp_path, factory)
    await daemon.start()
    await daemon.composition.lifecycle.transition(ServiceState.UNLOCKING)
    vault.ready = True
    activation = asyncio.create_task(daemon.activate_ready_application(7, 3))
    await entered.wait()
    locking = asyncio.create_task(daemon.lock("explicit_lock"))
    await asyncio.sleep(0)
    assert not locking.done()

    release.set()
    await activation
    await locking

    assert daemon.status().state is ServiceState.LOCKED
    assert application.close_count == 1
    assert not vault.ready
    await daemon.close()


@pytest.mark.anyio
async def test_production_composition_starts_locked_before_ready_only_state(
    tmp_path: Path,
) -> None:
    root = tmp_path / "data"
    metadata = tmp_path / "state"
    paths = daemon_module._ProductionPaths(  # pyright: ignore[reportPrivateUsage]
        root,
        metadata / "service-generation.json",
        metadata / "unlock-throttle.json",
        metadata / "service.lock",
        metadata,
    )
    bound: list[str] = []

    async def bind(kind: str) -> _Listener:
        bound.append(kind)
        return _Listener()

    binders = daemon_module._ListenerBinders(  # pyright: ignore[reportPrivateUsage]
        lambda: bind("control"),  # pyright: ignore[reportArgumentType]
        lambda: bind("secret"),  # pyright: ignore[reportArgumentType]
        lambda: bind("human"),  # pyright: ignore[reportArgumentType]
    )
    composition = await daemon_module._production_composition(  # pyright: ignore[reportPrivateUsage]
        _config=YoetzConfig(),
        _paths=paths,
        _binders=binders,
    )
    daemon = ServiceDaemon(_composition=composition)

    await daemon.start()

    assert bound == ["control", "secret", "human"]
    assert daemon.status().state is ServiceState.LOCKED
    assert daemon.status().vault_mode == "uninitialized"
    assert daemon.status().capabilities == ("confidential_ingress",)
    assert not (root / "vault").exists()
    await daemon.close()


def test_installation_marker_round_trip_is_canonical_and_self_authenticated(
    tmp_path: Path,
) -> None:
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    marker_path = root / "installation-state.json"
    store = daemon_module._InstallationStateStore(  # pyright: ignore[reportPrivateUsage]
        marker_path,
        tmp_path / "unlock-throttle.json",
        tmp_path / "service-generation.json",
    )
    digest = "sha256:" + "3" * 64

    store.publish(VaultMode.OS_KEYRING, None, digest)
    loaded = store.load()

    assert loaded is not None
    assert loaded.vault_mode is VaultMode.OS_KEYRING
    assert loaded.mode_binding_digest == digest
    assert marker_path.read_bytes().endswith(b"\n")
    assert marker_path.stat().st_mode & 0o077 == 0

    corrupted = bytearray(marker_path.read_bytes())
    digest_start = corrupted.rfind(b"sha256:") + len(b"sha256:")
    corrupted[digest_start] = ord("0") if corrupted[digest_start] != ord("0") else ord("1")
    marker_path.write_bytes(corrupted)
    with pytest.raises(RuntimeError, match="installation_marker_invalid"):
        store.load()


@pytest.mark.anyio
async def test_service_entry_point_installs_the_structural_log_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected-dispatch correlation ids are useless unless this sink is installed."""

    installed: list[LogMode] = []

    class _Daemon:
        def __init__(self, *, _composition: object) -> None:
            del _composition

        async def serve(self) -> None:
            return None

    async def composition(*, _config: YoetzConfig) -> object:
        assert type(_config) is YoetzConfig
        return object()

    def load(
        overrides: Mapping[str, str], env: Mapping[str, str], path: Path | None
    ) -> YoetzConfig:
        del overrides, env, path
        return YoetzConfig()

    def configure(config: LoggingConfig, mode: LogMode) -> None:
        del config
        installed.append(mode)

    monkeypatch.setattr(daemon_module, "load_config", load)
    monkeypatch.setattr(daemon_module, "configure_logging", configure)
    monkeypatch.setattr(daemon_module, "_production_composition", composition)
    monkeypatch.setattr(daemon_module, "ServiceDaemon", _Daemon)

    with pytest.raises(SystemExit):
        await daemon_module.run_service()

    assert installed == [LogMode.SERVICE]


@pytest.mark.anyio
async def test_human_connection_cancels_an_open_ceremony_when_terminal_disconnects() -> None:
    """An interrupted foreground setup must not block every later ceremony."""

    ceremony_id = "a" * 64

    class _Stream:
        def __init__(self) -> None:
            self._incoming = bytearray(
                encode_human_frame(
                    ClientOpenEnvelope(
                        "b" * 64,
                        HumanCeremonyKind.VAULT_UNLOCK,
                        EmptyVaultTarget(expected_mode="passphrase"),
                    )
                )
            )
            self.sent: list[bytes] = []
            self.closed = False

        @property
        def peer_identity(self) -> object:
            return object()

        async def receive(self, max_bytes: int) -> bytes:
            if not self._incoming:
                return b""
            size = min(max_bytes, len(self._incoming))
            chunk = bytes(self._incoming[:size])
            del self._incoming[:size]
            return chunk

        async def send_all(self, data: Buffer) -> None:
            self.sent.append(bytes(data))

        async def aclose(self) -> None:
            self.closed = True

    class _HumanService:
        def __init__(self) -> None:
            self.cancelled: list[str] = []

        async def open_ceremony(self, request: ClientOpenEnvelope) -> ServerOpenedEnvelope:
            return ServerOpenedEnvelope(
                ceremony_id,
                1,
                HumanCeremonyBinding(
                    binding_version=1,
                    ceremony_id=ceremony_id,
                    connection_nonce=request.connection_nonce,
                    ceremony_kind=HumanCeremonyKind.VAULT_UNLOCK,
                    service_instance_id=_INSTANCE_ID,
                    service_generation=7,
                    vault_generation=3,
                    policy_generation=None,
                    target_digest="sha256:" + "2" * 64,
                    expires_at_monotonic_ms=1_000_000,
                ),
                VaultUnlockPreview(),
                KeyringRetryPhase(),
            )

        async def cancel(self, received_ceremony_id: str) -> ServerCloseEnvelope:
            self.cancelled.append(received_ceremony_id)
            return ServerCloseEnvelope(received_ceremony_id, 3, "cancelled")

    stream = _Stream()
    service = _HumanService()
    handler = daemon_module._HumanConnectionServer(service)  # pyright: ignore[reportPrivateUsage, reportArgumentType]

    await handler(stream)

    assert service.cancelled == [ceremony_id]
    assert stream.closed
    assert [type(decode_human_frame(item)) for item in stream.sent] == [
        ServerOpenedEnvelope,
        ServerErrorEnvelope,
    ]


@pytest.mark.anyio
async def test_human_connection_cancels_secret_phase_when_terminal_disconnects() -> None:
    """Issue #434: EOF at a passphrase prompt must not wait on YZS1."""

    ceremony_id = "a" * 64
    binding = SecretIngressBinding(
        binding_version=1,
        ceremony_id=ceremony_id,
        secret_challenge="c" * 64,
        purpose=ConfidentialSecretPurpose.VAULT_UNLOCK,
        service_instance_id=_INSTANCE_ID,
        service_generation=7,
        vault_generation=3,
        policy_generation=None,
        target_digest="sha256:" + "2" * 64,
        expires_at_monotonic_ms=1_000_000,
    )

    class _Stream:
        def __init__(self) -> None:
            self._incoming = bytearray(
                encode_human_frame(
                    ClientOpenEnvelope(
                        "b" * 64,
                        HumanCeremonyKind.VAULT_UNLOCK,
                        EmptyVaultTarget(expected_mode="passphrase"),
                    )
                )
            )
            self.sent: list[bytes] = []
            self.closed = False

        @property
        def peer_identity(self) -> object:
            return object()

        async def receive(self, max_bytes: int) -> bytes:
            if not self._incoming:
                return b""
            size = min(max_bytes, len(self._incoming))
            chunk = bytes(self._incoming[:size])
            del self._incoming[:size]
            return chunk

        async def send_all(self, data: Buffer) -> None:
            self.sent.append(bytes(data))

        async def aclose(self) -> None:
            self.closed = True

    class _HumanService:
        def __init__(self) -> None:
            self.cancelled: list[str] = []
            self.secret_started = asyncio.Event()

        async def open_ceremony(self, request: ClientOpenEnvelope) -> ServerOpenedEnvelope:
            return ServerOpenedEnvelope(
                ceremony_id,
                1,
                HumanCeremonyBinding(
                    binding_version=1,
                    ceremony_id=ceremony_id,
                    connection_nonce=request.connection_nonce,
                    ceremony_kind=HumanCeremonyKind.VAULT_UNLOCK,
                    service_instance_id=_INSTANCE_ID,
                    service_generation=7,
                    vault_generation=3,
                    policy_generation=None,
                    target_digest="sha256:" + "2" * 64,
                    expires_at_monotonic_ms=1_000_000,
                ),
                VaultUnlockPreview(),
                SecretRequiredPhase(binding),
            )

        async def secret_completed(self, received_ceremony_id: str) -> ServerOpenedEnvelope:
            del received_ceremony_id
            self.secret_started.set()
            await asyncio.Event().wait()
            raise AssertionError("secret_wait_should_have_been_cancelled")

        async def cancel(self, received_ceremony_id: str) -> ServerCloseEnvelope:
            self.cancelled.append(received_ceremony_id)
            return ServerCloseEnvelope(received_ceremony_id, 3, "cancelled")

    stream = _Stream()
    service = _HumanService()
    handler = daemon_module._HumanConnectionServer(service)  # pyright: ignore[reportPrivateUsage, reportArgumentType]

    await asyncio.wait_for(handler(stream), 1.0)

    assert service.cancelled == [ceremony_id]
    assert stream.closed


@pytest.mark.anyio
async def test_ready_recommendations_refresh_again_without_service_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    two_refreshes = asyncio.Event()

    class Application(_Application):
        ready_recommendation_refresh: object
        observation_sweep: object

        async def close(self) -> None:
            events.append("application_close")
            await super().close()

    class Vault(_Vault):
        async def lock(self) -> None:
            events.append("vault_lock")
            await super().lock()

    application = Application()

    async def refresh() -> object:
        events.append("recommendation_refresh")
        if events.count("recommendation_refresh") == 2:
            two_refreshes.set()
        return object()

    async def sweep() -> ObservationDrainSummary:
        events.append("sweep")
        if events.count("sweep") == 1:
            asyncio.get_running_loop().call_soon(events.append, "control_turn")
        return ObservationDrainSummary(
            attempted=1,
            acknowledged=1,
            retry_pending=0,
            quarantined=0,
            reasons=(),
        )

    application.ready_recommendation_refresh = refresh
    application.observation_sweep = sweep
    vault = Vault()
    vault.ready = False
    lifecycle = ServiceLifecycle(
        _Clock(),
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "2" * 64,
        instance_id=_INSTANCE_ID,
        singleton_lock_path=tmp_path / "service.lock",
    )

    async def factory(_service_generation: int, _vault_generation: int) -> _Application:
        return application

    daemon = ServiceDaemon(
        _composition=ServiceComposition(
            lifecycle=lifecycle,
            control_listener=_Listener(),  # pyright: ignore[reportArgumentType]
            secret_ingress_listener=None,
            human_control_listener=None,
            human_control_service=None,
            session_monitor=None,
            vault=vault,
            ready_application_factory=factory,
        )
    )
    monkeypatch.setattr(daemon_module, "_OBSERVATION_SWEEP_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(daemon_module, "_READY_RECOMMENDATION_REFRESH_INTERVAL_SECONDS", 0.0)
    await daemon.start()
    await daemon.composition.lifecycle.transition(ServiceState.UNLOCKING)
    vault.ready = True
    await daemon.activate_ready_application(7, 3)

    await asyncio.wait_for(two_refreshes.wait(), timeout=1)
    assert events[:4] == ["sweep", "recommendation_refresh", "control_turn", "sweep"]
    await daemon.lock()
    count_after_lock = events.count("sweep")
    assert events.count("sweep") == count_after_lock
    assert events.count("recommendation_refresh") >= 2
    assert events.index("application_close") < events.index("vault_lock")
    await daemon.close()


@pytest.mark.anyio
async def test_recommendation_deadline_includes_maintenance_gate_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, _application, _vault, _listener = _daemon()
    composition = daemon.composition
    await composition.maintenance_gate.acquire()
    called = False

    async def refresh() -> object:
        nonlocal called
        called = True
        return None

    monkeypatch.setattr(daemon_module, "_READY_RECOMMENDATION_REFRESH_DEADLINE_SECONDS", 0.01)
    try:
        await asyncio.wait_for(
            daemon._refresh_ready_recommendations(refresh),  # pyright: ignore[reportPrivateUsage]
            timeout=1,
        )
        assert not called
        assert composition.maintenance_gate.locked()
        assert not composition.observation_gate.locked()
    finally:
        composition.maintenance_gate.release()
        await daemon.close()


@pytest.mark.anyio
async def test_connected_check_wait_timeout_and_disconnect_preserve_admitted_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real client timeout must not send control cancellation for a long semantic check."""

    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    entered, release, finished, cancelled = (
        asyncio.Event(),
        asyncio.Event(),
        asyncio.Event(),
        asyncio.Event(),
    )
    original = application.check

    async def held_check(*args: object, **kwargs: object) -> object:
        entered.set()
        try:
            await release.wait()
            return await original(*args, **kwargs)  # pyright: ignore[reportArgumentType]
        except asyncio.CancelledError:
            cancelled.set()
            raise
        finally:
            finished.set()

    async def project_completed(*_args: object, **_kwargs: object) -> object:
        # This harness intentionally supplies no public CheckResult; exercise transport lifetime
        # without treating its unprojected stand-in as a projection regression.
        return JsonObject({"ok": True})

    monkeypatch.setattr(application, "check", held_check)
    monkeypatch.setattr(daemon, "_project_completed_response", project_completed)
    client_stream, server_stream = _connected_control_pair()
    server_task = asyncio.create_task(daemon._serve_control_connection(server_stream))  # pyright: ignore[reportPrivateUsage]
    service_client = None
    try:
        session = await client_handshake(client_stream, ControlClientKind.CLI, "0.3.0")
        service_client = _connected_client(client_stream, session, ControlClientKind.CLI)  # pyright: ignore[reportArgumentType]
        request = _check_body().model_copy(update={"mode": "semantic_required"})
        with pytest.raises(ControlError) as timeout:
            await service_client.check(request, deadline_ms=50)
        assert timeout.value.reason == "request_timeout"
        assert entered.is_set() and not cancelled.is_set()
        await service_client.close()
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)
        assert not cancelled.is_set()
        release.set()
        await finished.wait()
        assert application.check_requests == [request]
        assert not cancelled.is_set()
    finally:
        release.set()
        if service_client is not None:
            await service_client.close()
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)
        await daemon.close()


@pytest.mark.anyio
async def test_failed_response_write_is_a_recorded_transport_fact_not_frame_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #678: the same write wrapper serves the daemon, so the same mislabelling was here.

    A peer that stops reading between dispatch and delivery is a transport fact about one
    connection. The daemon records the bounded reason, ends that call, and leaves no exception
    for the loop to report; the operation itself already ran.
    """

    import yoetz.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    recorded: list[tuple[str, str, str, str]] = []
    written = asyncio.Event()
    record_bounded = daemon_module.record_bounded_event_without_raising

    def capture(
        *,
        component: str,
        operation: str,
        reason: str,
        request_id: str | None = None,
        context: Mapping[str, object] | None = None,
    ) -> str:
        correlation_id = record_bounded(
            component=component,
            operation=operation,
            reason=reason,
            request_id=request_id,
            context=context,
        )
        recorded.append((component, operation, reason, correlation_id))
        written.set()
        return correlation_id

    monkeypatch.setattr(daemon_module, "record_bounded_event_without_raising", capture)

    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    client, server = _connected_control_pair()
    loop = asyncio.get_running_loop()
    contexts: list[dict[str, object]] = []
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: contexts.append(context))
    server_task = asyncio.create_task(daemon._serve_control_connection(server))  # pyright: ignore[reportPrivateUsage]
    try:
        session = await client_handshake(client, ControlClientKind.CLI, "0.3.0")

        async def refuse(data: Buffer) -> None:
            del data
            raise LocalControlTransportError("connection_failed")

        # The peer is gone only after its handshake was answered, so the failing write is the
        # response to a request the daemon already dispatched.
        monkeypatch.setattr(server, "send_all", refuse)
        request = _request(daemon, ControlMethod.START, _start_body())
        session.admit(request)
        await write_control_frame(client, request)
        async with asyncio.timeout(5):
            await written.wait()
    finally:
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)
        await daemon.close()
        gc.collect()
        loop.set_exception_handler(previous)

    assert application.start_calls == 1
    assert len(recorded) == 1
    component, operation, reason, correlation_id = recorded[0]
    assert (component, operation, reason) == (
        "service.daemon",
        "control_response_write",
        "connection_failed",
    )
    found = lookup_diagnostic_records(correlation_id, root=tmp_path)
    assert [entry["reason"] for entry in found] == ["connection_failed"]
    # tb4n2 NEW-8: the abandoned write names its closed method, client kind, elapsed time and
    # public request id, and nothing from the body.
    (entry,) = found
    assert entry["control_method"] == "start"
    assert entry["client_kind"] == "cli"
    assert type(entry["duration_ms"]) is int and entry["duration_ms"] >= 0
    assert entry["request_id"] == request.body.request_id  # type: ignore[union-attr]
    assert set(entry) <= {
        "timestamp",
        "correlation_id",
        "component",
        "operation",
        "reason",
        "request_id",
        "duration_ms",
        "control_method",
        "client_kind",
    }
    assert [context.get("message") for context in contexts] == []


def _operation_status_body() -> StatusRequest:
    return StatusRequest.model_validate(
        {
            **_status_body().model_dump(mode="json", exclude_none=True),
            "request_id": "req_00000000-0000-4000-8000-000000000043",
            "view": "operation",
            "limit": "1",
            "filter": {"operation_request_id": "req_00000000-0000-4000-8000-000000000030"},
        }
    )


@pytest.mark.anyio
async def test_operation_status_reads_live_while_a_semantic_check_holds_the_gates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #571 A2: progress is readable during a long check; other reads still wait."""

    daemon, application, _vault, _listener = _daemon()
    await daemon.start()
    composition = daemon.composition
    entered, release = asyncio.Event(), asyncio.Event()
    original = application.check
    statuses: list[str] = []
    original_status = application.status

    async def held_check(*args: object, **kwargs: object) -> object:
        entered.set()
        await release.wait()
        return await original(*args, **kwargs)  # pyright: ignore[reportArgumentType]

    async def observed_status(request: object, **kwargs: object) -> object:
        assert isinstance(request, StatusRequest)
        # The admitted read runs while the check still owns both dispatch gates; record the view
        # only after proving that, so a failed proof cannot satisfy the assertion below.
        assert composition.maintenance_gate.locked()
        assert composition.observation_gate.locked()
        statuses.append(request.view)
        return await original_status(request, **kwargs)  # pyright: ignore[reportArgumentType]

    async def project_completed(*_args: object, **_kwargs: object) -> object:
        return JsonObject({"ok": True})

    monkeypatch.setattr(application, "check", held_check)
    monkeypatch.setattr(application, "status", observed_status)
    monkeypatch.setattr(daemon, "_project_completed_response", project_completed)
    check_body = _check_body().model_copy(update={"mode": "semantic_required"})
    check_task = asyncio.create_task(
        daemon.dispatch(ControlClientKind.CLI, _request(daemon, ControlMethod.CHECK, check_body))
    )
    try:
        await asyncio.wait_for(entered.wait(), timeout=5.0)
        live = await asyncio.wait_for(
            daemon.dispatch(
                ControlClientKind.MCP_BRIDGE,
                _request(daemon, ControlMethod.STATUS, _operation_status_body()),
            ),
            timeout=5.0,
        )
        # This harness supplies no public StatusResult, so the envelope itself is not the
        # subject; the handler ran to completion while the check still held both gates.
        assert not (isinstance(live.body, ControlError) and live.body.reason == "request_timeout")
        assert statuses == ["operation"]
        waiting = await daemon.dispatch(
            ControlClientKind.CLI,
            _request(daemon, ControlMethod.STATUS, _status_body(), deadline_ms=50),
        )
        assert waiting.outcome == "error"
        assert isinstance(waiting.body, ControlError)
        assert waiting.body.reason == "request_timeout"
        assert statuses == ["operation"]
        assert not check_task.done()
    finally:
        release.set()
        await asyncio.wait_for(check_task, timeout=5.0)
        assert application.check_requests == [check_body]
        assert not composition.maintenance_gate.locked()
        assert not composition.observation_gate.locked()
        await daemon.close()


@pytest.mark.anyio
async def test_operation_status_still_waits_behind_recovery_maintenance() -> None:
    """Only a service-owned check opens the read window; recovery keeps full exclusion."""

    daemon, _application, _vault, _listener = _daemon()
    await daemon.start()
    composition = daemon.composition
    effects = daemon_module._LockedHumanEffects(  # pyright: ignore[reportPrivateUsage]
        cast(ServiceLifecycle, SimpleNamespace()),
        cast(VaultService, SimpleNamespace()),
        daemon_module._PrivacyPolicyAppRelay(),  # pyright: ignore[reportPrivateUsage]
        maintenance_gate=composition.maintenance_gate,
        observation_gate=composition.observation_gate,
    )
    await effects._acquire_recovery_maintenance("recovery-gate")  # pyright: ignore[reportPrivateUsage]
    try:
        blocked = await daemon.dispatch(
            ControlClientKind.CLI,
            _request(daemon, ControlMethod.STATUS, _operation_status_body(), deadline_ms=50),
        )
        assert blocked.outcome == "error"
        assert isinstance(blocked.body, ControlError)
        assert blocked.body.reason == "request_timeout"
    finally:
        effects._release_recovery_maintenance("recovery-gate")  # pyright: ignore[reportPrivateUsage]
        await daemon.close()


@pytest.mark.anyio
async def test_capture_refused_check_wakes_the_observation_sweep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A check refused behind a capture handoff wakes the sweep that delivers it (issue #838).

    The check held both dispatch gates, so the handoff's structural delivery could not run
    during it. Without the wake the next sweep waits a full idle interval, longer than the
    caller's bounded replay; other refusals leave the cadence alone.
    """

    import yoetz.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    daemon, application, _vault, _listener = _daemon()
    sweeps = 0
    second_sweep = asyncio.Event()

    async def sweep() -> ObservationDrainSummary:
        nonlocal sweeps
        sweeps += 1
        if sweeps >= 2:
            second_sweep.set()
        return ObservationDrainSummary(
            attempted=0, acknowledged=0, retry_pending=0, quarantined=0, reasons=()
        )

    refusal = CheckAdmissionStage.ACQUIRING

    async def refuse(request: object, **_kwargs: object) -> JsonObject:
        del request
        raise check_admission_refused(refusal)

    application.observation_sweep = sweep  # pyright: ignore[reportAttributeAccessIssue]
    application.check = refuse  # type: ignore[method-assign]
    await daemon.start()
    wake = daemon._observation_sweep_wake  # pyright: ignore[reportPrivateUsage]

    acquiring = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.CHECK, _check_body()),
    )
    assert isinstance(acquiring.body, CheckResult)
    assert acquiring.body.root.ok is False
    assert not wake.is_set()

    refusal = CheckAdmissionStage.CAPTURE_HANDOFF_PENDING
    refused = await daemon.dispatch(
        ControlClientKind.MCP_BRIDGE,
        _request(daemon, ControlMethod.CHECK, _check_body()),
    )
    assert isinstance(refused.body, CheckResult)
    assert refused.body.root.ok is False
    error = refused.body.root.error
    assert error.code is PublicErrorCode.OPERATION_PENDING
    assert error.retryable is True
    assert error.safe_details == {
        "continuation": "check_admission_same_identity",
        "reason_code": "check_admission_capture_pending",
        "retry_after_ms": 5000,
    }
    # The typed stage reaches the durable diagnostic, so the correlation id names the stage.
    records = lookup_diagnostic_records(error.correlation_id, root=tmp_path)
    assert [record.get("reason_code") for record in records] == ["check_admission_capture_pending"]
    # The idle interval is 60 s; only the wake can bring the second sweep this soon.
    await asyncio.wait_for(second_sweep.wait(), timeout=5)
    await daemon.close()


@pytest.mark.anyio
async def test_observation_sweep_wake_survives_timeout_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wake arriving with the timeout result stays armed for the next sweep turn."""

    daemon, _application, _vault, _listener = _daemon()
    wake = daemon._observation_sweep_wake  # pyright: ignore[reportPrivateUsage]
    timeout_started = asyncio.Event()
    release_timeout = asyncio.Event()

    async def timeout_barrier(
        awaitables: object, *, timeout: float, return_when: object
    ) -> tuple[set[object], set[object]]:
        del timeout, return_when
        timeout_started.set()
        await release_timeout.wait()
        wake.set()
        # Report the timeout, as asyncio.wait does, with nothing completed.
        return set(), set(cast(set[object], awaitables))

    monkeypatch.setattr(daemon_module.asyncio, "wait", timeout_barrier)
    waiting = asyncio.create_task(daemon._await_observation_sweep_turn(60.0))  # pyright: ignore[reportPrivateUsage]
    await timeout_started.wait()
    release_timeout.set()
    await waiting

    assert wake.is_set()
    await daemon.close()


@pytest.mark.anyio
async def test_hook_ingest_moves_the_next_observation_sweep_forward(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hook ingest wakes an idle sweeper after a short coalescing window (issue #887).

    A hook drains only a few rows within its own budget, so the remainder must not wait the
    60 s idle interval. A burst of ingests coalesces into one early pass.
    """

    monkeypatch.setattr(daemon_module, "_OBSERVATION_SWEEP_INGEST_COALESCE_SECONDS", 0.05)
    daemon, _application, _vault, _listener = _daemon()
    ingest = daemon._observation_ingest_wake  # pyright: ignore[reportPrivateUsage]
    waiting = asyncio.create_task(daemon._await_observation_sweep_turn(60.0))  # pyright: ignore[reportPrivateUsage]
    await asyncio.sleep(0)
    assert not waiting.done()
    ingest.set()
    ingest.set()
    # The idle interval is 60 s; only the ingest wake can end this turn this soon.
    await asyncio.wait_for(waiting, timeout=5)
    assert not ingest.is_set()
    assert not daemon._observation_sweep_wake.is_set()  # pyright: ignore[reportPrivateUsage]
    await daemon.close()


@pytest.mark.anyio
async def test_idle_sweep_turn_ends_when_the_backlog_probe_finds_a_deferred_row(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hook row deferred without any service call is swept before the idle interval (#887)."""

    monkeypatch.setattr(daemon_module, "_OBSERVATION_SWEEP_BACKLOG_POLL_SECONDS", 0.01)
    daemon, _application, _vault, _listener = _daemon()
    probes = 0

    def probe() -> bool:
        nonlocal probes
        probes += 1
        if probes == 1:
            raise RuntimeError("probe_failed")
        return probes >= 3

    # The idle interval is 60 s; only the probe can end this turn this soon.
    await asyncio.wait_for(
        daemon._await_observation_sweep_turn(60.0, probe),  # pyright: ignore[reportPrivateUsage]
        timeout=5,
    )
    assert probes == 3
    await daemon.close()


@pytest.mark.anyio
async def test_observation_ingest_dispatch_arms_the_sweep_wake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every hook ingest request arms the coalesced sweep wake, even if it later fails."""

    daemon, _application, _vault, _listener = _daemon()
    ingest = daemon._observation_ingest_wake  # pyright: ignore[reportPrivateUsage]

    async def fail(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("ingest_failed")

    monkeypatch.setattr(daemon, "_dispatch_ready_once", fail)
    other = SimpleNamespace(method=ControlMethod.OBSERVATION_STATUS, body=None)
    with pytest.raises(RuntimeError):
        await daemon._dispatch_ready(cast(Any, None), cast(Any, other), None)  # pyright: ignore[reportPrivateUsage]
    assert not ingest.is_set()
    request = SimpleNamespace(method=ControlMethod.OBSERVATION_INGEST, body=None)
    with pytest.raises(RuntimeError):
        await daemon._dispatch_ready(cast(Any, None), cast(Any, request), None)  # pyright: ignore[reportPrivateUsage]
    assert ingest.is_set()
    await daemon.close()


@pytest.mark.anyio
async def test_store_contention_inside_a_deadlined_handler_stays_retryable() -> None:
    """#689: the closed wire vocabulary keeps a store lock timeout a retryable timeout."""

    from yoetz.ports.observation import ObservationStoreLockTimeout

    daemon, application, _vault, _listener = _daemon()
    await daemon.start()

    async def contended(request: object) -> JsonObject:
        del request
        raise ObservationStoreLockTimeout(
            scope="thread",
            waited_ms=2_000,
            holder_role="sweep",
            holder_phase="bump_outbox_row_attempt",
            holder_held_ms=2_100,
            holder_waiting=True,
        )

    application.observation_ingest = contended  # type: ignore[method-assign]
    try:
        response = await asyncio.wait_for(
            daemon.dispatch(
                ControlClientKind.CLI,
                _request(
                    daemon,
                    ControlMethod.OBSERVATION_INGEST,
                    _capture_gate_body(capture_only=False),
                    deadline_ms=5_000,
                ),
            ),
            timeout=10.0,
        )
        assert response.outcome == "error"
        assert isinstance(response.body, ControlError)
        assert response.body.reason == "request_timeout"
        assert response.body.retryable
        assert not daemon.composition.maintenance_gate.locked()
    finally:
        await daemon.close()
