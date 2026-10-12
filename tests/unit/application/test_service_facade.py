from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from typing import Literal, cast

import pytest

from yoetz.application.publish_work import PublishWorkInternalResult
from yoetz.application.service import (
    Application,
    ClientProjectionContext,
    ProjectionRenderMode,
    VerificationPolicy,
    resolve_client_disclosure_sink,
)
from yoetz.domain.events import RuntimeProfile
from yoetz.domain.privacy import LocalDisclosureSink
from yoetz.domain.values import Frontier, JsonObject
from yoetz.ports.control import (
    ControlClientKind,
    ControlError,
    ControlMethod,
    RepositoryPrivacyContext,
)
from yoetz.ports.publish_response_catalog import (
    PublishResponseCatalogPort,
    PublishResponseKey,
    StoredPublishResponse,
)
from yoetz.ports.start_catalog import (
    SessionBinding,
    StartCatalogPort,
    TaskRoute,
    TaskRouteState,
)
from yoetz.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from yoetz.protocol.coverage import PublicationChannel, coverage_for_channel
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.models import (
    CheckRequest,
    PublishWorkAcceptedEventModel,
    PublishWorkRequest,
    PublishWorkResult,
    PublishWorkVersionSliceModel,
    ReceiptRequest,
    RespondRequest,
    StatusRequest,
    public_model_to_wire,
)

_REQUEST = "req_00000000-0000-4000-8000-000000000001"
_TASK = "tsk_00000000-0000-4000-8000-000000000002"
_SESSION = "ses_00000000-0000-4000-8000-000000000003"
_RETIRED_SESSION = "ses_00000000-0000-4000-8000-000000000004"
_WRITER = "wri_00000000-0000-4000-8000-000000000005"


class _Catalog:
    def __init__(self, route: TaskRoute | None, binding: SessionBinding | None = None) -> None:
        self.route = route
        self.binding = binding
        self.calls = 0

    async def resolve_route(self, session_id: str) -> TaskRoute | None:
        assert session_id in {_SESSION, _RETIRED_SESSION}
        self.calls += 1
        return self.route if session_id == _SESSION else None

    async def session_binding(self, session_id: str) -> SessionBinding | None:
        if session_id == _SESSION:
            route = self.route
            if route is None:
                return None
            return SessionBinding(route.task_id, route.session_id, _WRITER)
        assert session_id == _RETIRED_SESSION
        return self.binding


class _Responses:
    def __init__(self) -> None:
        self.value: StoredPublishResponse | None = None
        self.put_calls = 0

    async def lookup(self, key: PublishResponseKey) -> StoredPublishResponse | None:
        del key
        return self.value

    async def put_if_absent(self, value: StoredPublishResponse) -> StoredPublishResponse:
        self.put_calls += 1
        if self.value is None:
            self.value = value
        return self.value


def _route(
    *,
    task_id: str = _TASK,
    state: TaskRouteState = TaskRouteState.ACTIVE,
    repository_privacy_commitment: str | None = None,
) -> TaskRoute:
    return TaskRoute(
        task_id,
        _SESSION,
        f"tasks/{task_id}",
        1,
        state,
        canonical_digest(
            {"task_id": task_id, "bundle_relpath": f"tasks/{task_id}", "route_generation": 1}
        ),
        repository_privacy_commitment,
    )


def _application(
    catalog: _Catalog,
    responses: _Responses | None = None,
    *,
    enforce_repository_identity: bool = False,
    support_handlers: Mapping[ControlMethod, Callable[..., Awaitable[JsonObject]]] | None = None,
) -> Application:
    return Application(
        start_catalog=cast(StartCatalogPort, catalog),
        publish_responses=cast(PublishResponseCatalogPort, responses or catalog),
        runtime=object(),  # pyright: ignore[reportArgumentType]
        clock=object(),  # pyright: ignore[reportArgumentType]
        ids=object(),  # pyright: ignore[reportArgumentType]
        verification_policy=VerificationPolicy(),
        privacy=object(),  # pyright: ignore[reportArgumentType]
        status_cursor_key=b"cursor",
        waiver_policy_digest="sha256:" + "0" * 64,
        semantic_evaluator=object(),  # pyright: ignore[reportArgumentType]
        disclosure_scope_for=object(),  # pyright: ignore[reportArgumentType]
        receipt_version_resolver=object(),  # pyright: ignore[reportArgumentType]
        waiver_authorizer=lambda _: False,
        import_publication_authorizer=lambda _: False,
        profile=RuntimeProfile.TEST_FAKE,
        policy_packs=("research-evidence/0.2.0", "work-integrity/0.3.0"),
        version_manifest={},
        support_handlers={} if support_handlers is None else support_handlers,
        enforce_repository_identity=enforce_repository_identity,
    )


@pytest.mark.anyio
@pytest.mark.parametrize("method", ("publish_work", "check", "respond", "status", "receipt"))
@pytest.mark.parametrize("identity_kind", ("git_common_root", "directory"))
async def test_task_workflows_reject_cross_repository_context_before_execution(
    method: str,
    identity_kind: Literal["git_common_root", "directory"],
) -> None:
    commitment_a = "hmac-sha256:" + "a" * 64
    commitment_b = "hmac-sha256:" + "b" * 64
    catalog = _Catalog(_route(repository_privacy_commitment=commitment_a))
    app = _application(catalog, enforce_repository_identity=True)
    context_b = RepositoryPrivacyContext(commitment_b, identity_kind)
    request_type = {
        "publish_work": PublishWorkRequest,
        "check": CheckRequest,
        "respond": RespondRequest,
        "status": StatusRequest,
        "receipt": ReceiptRequest,
    }[method]
    request = request_type.model_construct(session_id=_SESSION, task_id=_TASK)

    with pytest.raises(PublicOperationError) as failure:
        await getattr(app, method)(
            request,
            repository_privacy_context=context_b,
        )

    assert failure.value.code is PublicErrorCode.SESSION_CONFLICT
    assert failure.value.safe_details == {"reason_code": "repository_identity_mismatch"}
    assert commitment_a not in failure.value.message
    assert commitment_b not in failure.value.message
    assert f"current identity kind: {identity_kind}" in failure.value.message
    assert "original workspace directory" in failure.value.message
    assert catalog.calls == 1


@pytest.mark.anyio
@pytest.mark.parametrize("method", ("publish_work", "check", "respond", "status", "receipt"))
async def test_task_workflows_name_a_missing_repository_context_distinctly(method: str) -> None:
    """A handshake without a locator is `repository_identity_required`, not a stale route (#578)."""

    catalog = _Catalog(_route(repository_privacy_commitment="hmac-sha256:" + "a" * 64))
    app = _application(catalog, enforce_repository_identity=True)
    request_type = {
        "publish_work": PublishWorkRequest,
        "check": CheckRequest,
        "respond": RespondRequest,
        "status": StatusRequest,
        "receipt": ReceiptRequest,
    }[method]
    request = request_type.model_construct(session_id=_SESSION, task_id=_TASK)

    with pytest.raises(PublicOperationError) as failure:
        await getattr(app, method)(request, repository_privacy_context=None)

    assert failure.value.code is PublicErrorCode.SESSION_CONFLICT
    assert failure.value.retryable is False
    assert failure.value.safe_details == {"reason_code": "repository_identity_required"}
    assert "no repository context" in failure.value.message
    assert "original workspace directory" in failure.value.message
    assert catalog.calls == 1


@pytest.mark.anyio
async def test_task_workflow_returns_current_binding_for_superseded_session() -> None:
    binding = SessionBinding(_TASK, _SESSION, _WRITER)
    catalog = _Catalog(_route(), binding)
    app = _application(catalog, enforce_repository_identity=True)
    request = StatusRequest.model_construct(session_id=_RETIRED_SESSION, writer_id=_WRITER)

    with pytest.raises(PublicOperationError) as caught:
        await app.status(request)

    assert caught.value.code is PublicErrorCode.SESSION_NOT_FOUND
    assert caught.value.retryable is False
    assert caught.value.safe_details == {
        "continuation": "session_rebind_required",
        "reason_code": "session_superseded",
        "task_id": _TASK,
        "session_id": _SESSION,
        "writer_id": _WRITER,
    }


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("method_name", "control_method"),
    (
        ("privacy_get_setup", ControlMethod.PRIVACY_GET_SETUP),
        ("privacy_get_effective", ControlMethod.PRIVACY_GET_EFFECTIVE),
        ("privacy_propose_policy", ControlMethod.PRIVACY_PROPOSE_POLICY),
    ),
)
async def test_repository_scoped_privacy_support_forwards_trusted_context(
    method_name: str,
    control_method: ControlMethod,
) -> None:
    """The facade must not drop the daemon-authenticated repository binding."""

    seen: list[tuple[object, RepositoryPrivacyContext | None]] = []
    context = RepositoryPrivacyContext("hmac-sha256:" + "c" * 64, "git_common_root")
    expected = JsonObject({"ok": True})

    async def handler(
        request: object,
        *,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
    ) -> JsonObject:
        seen.append((request, repository_privacy_context))
        return expected

    app = _application(
        _Catalog(_route()),
        support_handlers={control_method: handler},
    )
    body = JsonObject({"schema_version": "2.0.0"})

    result = await getattr(app, method_name)(
        body,
        repository_privacy_context=context,
    )

    assert result is expected
    assert seen == [(body, context)]


def _publish_internal() -> PublishWorkInternalResult:
    return PublishWorkInternalResult(
        protocol_version="0.1",
        schema_version="1.0.0",
        request_id=_REQUEST,
        request_digest="sha256:" + "1" * 64,
        ok=True,
        outcome="accepted",
        task_id=_TASK,
        session_id=_SESSION,
        writer_id="wri_00000000-0000-4000-8000-000000000004",
        subject_frontier=Frontier.genesis(),
        result_frontier=Frontier(1, "sha256:" + "2" * 64),
        accepted_events=(
            PublishWorkAcceptedEventModel(
                event_id="evt_00000000-0000-4000-8000-000000000005",
                schema_name="action_recorded",
                schema_version="1.0.0",
                writer_sequence="1",
                ingestion_sequence="1",
                accepted_at="2026-07-27T12:00:00.000Z",
                predecessor_digest="genesis",
                entry_digest="sha256:" + "2" * 64,
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


def _projected(internal: PublishWorkInternalResult) -> PublishWorkResult:
    wire = internal.as_json()
    accepted = cast(tuple[dict[str, object], ...], wire["accepted_events"])
    for event in accepted:
        event["summary"] = {
            "omitted": True,
            "category": "command_metadata",
            "reason": "local_disclosure_not_authorized",
        }
    return PublishWorkResult.model_validate(
        {
            **wire,
            "privacy_projection": {
                "sink": "agent_context",
                "local_disclosure_receipt_id": "egr_00000000-0000-4000-8000-000000000006",
                "policy_id": "pvy_00000000-0000-4000-8000-000000000007",
                "policy_version": "1",
                "policy_digest": "sha256:" + "3" * 64,
                "included_categories": (),
                "blocked_categories": (),
                "omitted_pointers": (),
                "projection_commitment": "hmac-sha256:" + "4" * 64,
            },
        }
    )


@pytest.mark.anyio
async def test_publish_response_round_trip_is_structural_and_returns_catalog_winner() -> None:
    responses = _Responses()
    app = _application(_Catalog(_route()), responses)
    internal = _publish_internal()
    projected = _projected(internal)

    persisted = await app.store_publish_response(
        internal, LocalDisclosureSink.AGENT_CONTEXT, projected
    )
    loaded = await app.load_publish_response(internal, LocalDisclosureSink.AGENT_CONTEXT)

    assert persisted == projected
    assert loaded == projected
    assert responses.put_calls == 1
    assert responses.value is not None
    assert b'"summary":{"category":"command_metadata","omitted":true' in (
        responses.value.result_canonical
    )
    assert responses.value.key.task_id == internal.task_id
    assert responses.value.key.session_id == internal.session_id
    assert "request_digest" not in internal.as_json()


@pytest.mark.anyio
async def test_publish_response_load_rejects_content_summary_and_identity_mismatch() -> None:
    responses = _Responses()
    app = _application(_Catalog(_route()), responses)
    internal = _publish_internal()
    key = app.publish_response_key(internal, LocalDisclosureSink.AGENT_CONTEXT)
    wire = cast(dict[str, object], _projected(internal).model_dump(mode="json", exclude_unset=True))
    accepted = cast(list[dict[str, object]], wire["accepted_events"])
    accepted[0]["summary"] = "caller content"
    canonical = canonical_encode(cast(JsonValue, wire))
    responses.value = StoredPublishResponse(
        key,
        canonical,
        "sha256:" + hashlib.sha256(canonical).hexdigest(),
    )
    with pytest.raises(PublicOperationError) as content_failure:
        await app.load_publish_response(internal, LocalDisclosureSink.AGENT_CONTEXT)
    assert content_failure.value.code is PublicErrorCode.STORAGE_CORRUPT

    other = replace(internal, task_id="tsk_00000000-0000-4000-8000-000000000099")
    with pytest.raises(PublicOperationError) as identity_failure:
        await app.load_publish_response(other, LocalDisclosureSink.AGENT_CONTEXT)
    assert identity_failure.value.code is PublicErrorCode.STORAGE_CORRUPT

    altered_wire = public_model_to_wire(_projected(internal))
    altered_frontier = cast(dict[str, JsonValue], altered_wire["result_frontier"])
    altered_frontier["sequence"] = "2"
    altered_canonical = canonical_encode(altered_wire)
    responses.value = StoredPublishResponse(
        key,
        altered_canonical,
        "sha256:" + hashlib.sha256(altered_canonical).hexdigest(),
    )
    with pytest.raises(PublicOperationError) as facts_failure:
        await app.load_publish_response(internal, LocalDisclosureSink.AGENT_CONTEXT)
    assert facts_failure.value.code is PublicErrorCode.STORAGE_CORRUPT


@pytest.mark.parametrize(
    ("context", "expected"),
    (
        (
            ClientProjectionContext(
                ControlClientKind.CLI,
                ProjectionRenderMode.HUMAN_READABLE,
                True,
            ),
            LocalDisclosureSink.LOCAL_HUMAN_VIEW,
        ),
        (
            ClientProjectionContext(
                ControlClientKind.CLI,
                ProjectionRenderMode.HUMAN_READABLE,
                False,
            ),
            LocalDisclosureSink.AGENT_CONTEXT,
        ),
        (
            ClientProjectionContext(
                ControlClientKind.CLI,
                ProjectionRenderMode.MACHINE_READABLE,
                True,
            ),
            LocalDisclosureSink.AGENT_CONTEXT,
        ),
        (
            ClientProjectionContext(
                ControlClientKind.MCP_BRIDGE,
                ProjectionRenderMode.HUMAN_READABLE,
                True,
            ),
            LocalDisclosureSink.AGENT_CONTEXT,
        ),
        (
            ClientProjectionContext(
                ControlClientKind.UI,
                ProjectionRenderMode.HUMAN_READABLE,
                True,
            ),
            LocalDisclosureSink.AGENT_CONTEXT,
        ),
    ),
)
def test_projection_context_resolves_sink_fail_closed(
    context: ClientProjectionContext, expected: LocalDisclosureSink
) -> None:
    assert resolve_client_disclosure_sink(context) is expected


def test_projection_context_fail_safe_default_is_machine_agent_context() -> None:
    context = ClientProjectionContext.fail_safe(ControlClientKind.CLI)

    assert context == ClientProjectionContext(
        ControlClientKind.CLI,
        ProjectionRenderMode.MACHINE_READABLE,
        False,
    )
    assert resolve_client_disclosure_sink(context) is LocalDisclosureSink.AGENT_CONTEXT


@pytest.mark.parametrize(
    "kwargs",
    (
        {"client_kind": "cli"},
        {"render_mode": "human_readable"},
        {"output_is_controlling_tty": 1},
    ),
)
def test_projection_context_rejects_untyped_facts(kwargs: dict[str, object]) -> None:
    values: dict[str, object] = {
        "client_kind": ControlClientKind.CLI,
        "render_mode": ProjectionRenderMode.HUMAN_READABLE,
        "output_is_controlling_tty": True,
    }
    values.update(kwargs)
    with pytest.raises(TypeError):
        ClientProjectionContext(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("semantic", "mode"),
    (
        ("disabled", "deterministic_only"),
        ("optional", "semantic_if_configured"),
        ("required", "semantic_required"),
    ),
)
def test_verification_policy_maps_exact_check_mode(semantic: str, mode: str) -> None:
    policy = VerificationPolicy(semantic=semantic, max_findings=3)  # type: ignore[arg-type]

    assert policy.default_check_mode == mode


@pytest.mark.parametrize("maximum", (True, 0, 11))
def test_verification_policy_rejects_invalid_maximum(maximum: object) -> None:
    with pytest.raises(ValueError, match="verification_max_findings_invalid"):
        VerificationPolicy(max_findings=maximum)  # type: ignore[arg-type]


def test_verification_policy_rejects_unknown_semantic_mode() -> None:
    with pytest.raises(ValueError, match="verification_semantic_invalid"):
        VerificationPolicy(semantic="automatic")  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_projection_binding_facts_resolve_exact_active_catalog_route() -> None:
    route = _route()
    catalog = _Catalog(route)
    facts = await _application(catalog).projection_binding_facts(
        ControlMethod.IMPORT_CODEX_JSONL,
        {"request_id": _REQUEST},
        JsonObject(
            {
                "schema_version": "1.0.0",
                "request_id": _REQUEST,
                "task_id": _TASK,
                "session_id": _SESSION,
            }
        ),
    )

    assert facts.original_request_id == _REQUEST
    assert facts.route_identity_digest == route.route_identity_digest
    assert catalog.calls == 1


@pytest.mark.anyio
async def test_projection_binding_facts_keep_parent_route_for_delegated_start() -> None:
    """A delegated result maps through its parent host session until child attach."""

    route = _route()
    catalog = _Catalog(route)
    child = "tsk_00000000-0000-4000-8000-000000000006"
    facts = await _application(catalog).projection_binding_facts(
        ControlMethod.START,
        {"request_id": _REQUEST},
        JsonObject(
            {
                "schema_version": "1.0.0",
                "request_id": _REQUEST,
                "ok": True,
                "outcome": "delegated",
                "task_id": child,
                "parent_task_id": _TASK,
                "session_id": _SESSION,
                "writer_id": _WRITER,
            }
        ),
    )

    assert facts.original_request_id == _REQUEST
    assert facts.route_identity_digest == route.route_identity_digest
    assert catalog.calls == 1


@pytest.mark.anyio
@pytest.mark.parametrize("route", (None, _route(state=TaskRouteState.QUARANTINED)))
async def test_projection_binding_facts_fail_closed_for_missing_or_stale_route(
    route: TaskRoute | None,
) -> None:
    with pytest.raises(ControlError, match="privacy_projection_unavailable"):
        await _application(_Catalog(route)).projection_binding_facts(
            ControlMethod.IMPORT_CODEX_JSONL,
            {"request_id": _REQUEST},
            JsonObject(
                {
                    "schema_version": "1.0.0",
                    "request_id": _REQUEST,
                    "task_id": _TASK,
                    "session_id": _SESSION,
                }
            ),
        )


@pytest.mark.anyio
async def test_projection_binding_facts_fail_closed_for_route_task_mismatch() -> None:
    other_task = "tsk_00000000-0000-4000-8000-000000000099"
    with pytest.raises(ControlError, match="privacy_projection_unavailable"):
        await _application(_Catalog(_route(task_id=other_task))).projection_binding_facts(
            ControlMethod.IMPORT_CODEX_JSONL,
            {"request_id": _REQUEST},
            JsonObject(
                {
                    "schema_version": "1.0.0",
                    "request_id": _REQUEST,
                    "task_id": _TASK,
                    "session_id": _SESSION,
                }
            ),
        )


@pytest.mark.anyio
async def test_installation_scoped_support_does_not_resolve_a_task_route() -> None:
    catalog = _Catalog(None)
    facts = await _application(catalog).projection_binding_facts(
        ControlMethod.PRIVACY_GET_SETUP,
        {},
        JsonObject({"schema_version": "1.0.0", "setup_state": "ready"}),
    )

    assert facts.original_request_id is None
    assert facts.route_identity_digest is None
    assert catalog.calls == 0


def _check_request(mode: str | None) -> CheckRequest:
    payload: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _REQUEST,
        "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "session_id": _SESSION,
        "writer_id": "wri_00000000-0000-4000-8000-000000000004",
        "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
    }
    if mode is not None:
        payload["mode"] = mode
    return CheckRequest.model_validate(payload)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("semantic", "expected"),
    (
        ("disabled", "deterministic_only"),
        ("optional", "semantic_if_configured"),
        ("required", "semantic_required"),
    ),
)
async def test_omitted_check_mode_resolves_through_the_verification_policy(
    monkeypatch: pytest.MonkeyPatch, semantic: str, expected: str
) -> None:
    """The recorded check must carry a concrete mode, never an absent one to interpret later."""

    seen: list[object] = []

    async def _capture(
        _app: object,
        request: object,
        *,
        route_profile: object = "policy",
        host_profile: object = "generic",
    ) -> object:
        assert route_profile == "policy"
        assert host_profile == "generic"
        seen.append(request)
        return object()

    monkeypatch.setattr("yoetz.application.check.execute_check", _capture)
    application = _application(_Catalog(_route()))
    policy = VerificationPolicy(semantic=semantic, max_findings=3)  # type: ignore[arg-type]
    application = replace(application, verification_policy=policy)

    await application.check(_check_request(None))

    resolved = cast(CheckRequest, seen[0])
    assert resolved.mode == expected


@pytest.mark.anyio
async def test_present_check_mode_is_never_overridden_by_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller that asked for deterministic_only under a required policy still gets what it asked."""

    seen: list[object] = []

    async def _capture(
        _app: object,
        request: object,
        *,
        route_profile: object = "policy",
        host_profile: object = "generic",
    ) -> object:
        assert route_profile == "policy"
        assert host_profile == "generic"
        seen.append(request)
        return object()

    monkeypatch.setattr("yoetz.application.check.execute_check", _capture)
    application = replace(
        _application(_Catalog(_route())),
        verification_policy=VerificationPolicy(semantic="required", max_findings=3),
    )

    await application.check(_check_request("deterministic_only"))

    assert cast(CheckRequest, seen[0]).mode == "deterministic_only"
