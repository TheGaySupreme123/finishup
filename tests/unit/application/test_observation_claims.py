"""A claim-bound connection's observation runs over that claim's own attested store (ADR-051 #12).

The router decides what the service itself still decides (the claim, the route, the capacity)
before anything is written, and mirrors each row's attestation into the claim's store: the
client's consent, fence, trust, session commitments and route, never the service's own store.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, cast

import pytest

from finishup.adapters.integrations.codex_lifecycle import (
    load_mapping,
    mapping_from_start_ids,
    store_mapping,
)
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_claims import (
    CLAIM_OBSERVATION_DIRECTORY,
    ClaimObservationRouter,
    ClientAttestedObservationStore,
    claim_observation_state,
)
from finishup.application.observation_control import build_observation_support_handlers
from finishup.domain.observation import (
    ObservationClientAttestation,
    ObservationClientRoute,
    ObservationContentChunk,
    ObservationContentKind,
    ObservationCursor,
    ObservationEnvelope,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationIngestResult,
    ObservationRevokeCommand,
    ObservationSource,
    observation_ingest_request_to_json,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.ports.control import ControlError, ControlMethod, RepositoryPrivacyContext
from finishup.ports.start_catalog import TaskRoute, TaskRouteState
from finishup.ports.workspace_agent import workspace_handle_for_commitment
from finishup.protocol.canonical import canonical_digest

pytestmark = pytest.mark.anyio

_CLAIM = "hmac-sha256:" + "0a1b2c3d4e5f6071" + "8" * 48
_OTHER_CLAIM = "hmac-sha256:" + "f" * 64
_HANDLE = workspace_handle_for_commitment(_CLAIM)
_CLIENT_SESSION = "hmac-sha256:" + "5e" * 32
_HOST_SESSION = "codex-session-1"
_TASK = "tsk_00000000-0000-4000-8000-000000000c01"
_SESSION = "ses_00000000-0000-4000-8000-000000000c01"
_WRITER = "wri_00000000-0000-4000-8000-000000000c01"
_ROUTE = ObservationClientRoute(_TASK, _SESSION, _WRITER)
_GENERATION = "sha256:" + "a6" * 32
_POLICY = "sha256:" + "c4" * 32
_GRANTED = Timestamp("2026-11-05T11:00:00.000Z")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _attestation(**change: Any) -> ObservationClientAttestation:  # noqa: ANN401
    base = ObservationClientAttestation(
        consent="active",
        granted_at=_GRANTED,
        content_capture_profiles=(),
        authority_generation=_GENERATION,
        check_policy_digest=_POLICY,
        route=_ROUTE,
    )
    return replace(base, **change)


def _request(
    attestation: ObservationClientAttestation | None = None,
    *,
    chunks: tuple[ObservationContentChunk, ...] = (),
) -> ObservationIngestRequest:
    return ObservationIngestRequest(
        codex_session_id=_HOST_SESSION,
        envelope=ObservationEnvelope(
            session_commitment=_CLIENT_SESSION,
            event_kind="PostToolUse",
            source_identity="hook:codex-session-1:2",
            source=ObservationSource.CODEX_HOOK,
            cursor=ObservationCursor(1, 0, 2, _CLIENT_SESSION, "codex-obs-hook/1.0.0"),
            receipt_time=Timestamp("2026-11-05T12:00:00.000Z"),
            structural_payload=JsonObject({}),
            content_object_refs=(),
            gap_codes=(),
        ),
        content_chunks=chunks,
        client_attestation=attestation,
    )


def _route(task: str = _TASK, commitment: str | None = _CLAIM) -> TaskRoute:
    return TaskRoute(
        task_id=task,
        session_id=_SESSION,
        bundle_relpath=f"tasks/{task}",
        route_generation=1,
        state=TaskRouteState.ACTIVE,
        route_identity_digest=canonical_digest(
            {"task_id": task, "bundle_relpath": f"tasks/{task}", "route_generation": 1}
        ),
        repository_privacy_commitment=commitment,
    )


@dataclass
class _Coordinator:
    """What the router hands a row to: the claim's store, as it was when the row arrived."""

    store: ClientAttestedObservationStore
    state: Path
    seen: list[ObservationIngestRequest] = field(default_factory=list[ObservationIngestRequest])
    revoked: list[str] = field(default_factory=list[str])
    closed: bool = False
    gate: asyncio.Event | None = None

    async def ingest_request(self, request: ObservationIngestRequest) -> ObservationIngestResult:
        self.seen.append(request)
        if self.gate is not None:
            await self.gate.wait()
        return ObservationIngestResult(ObservationIngestDisposition.REJECTED, "paused", None)

    async def revoke(self, command: ObservationRevokeCommand) -> object:
        self.revoked.append(command.workspace_commitment)
        return await asyncio.to_thread(self.store.revoke, command)

    def close(self) -> None:
        self.closed = True


@dataclass
class _Harness:
    state: Path
    routes: dict[str, TaskRoute]
    coordinators: dict[str, _Coordinator] = field(default_factory=dict[str, _Coordinator])
    route_error: Exception | None = None

    def router(self, *, max_claims: int = 4) -> ClaimObservationRouter:
        def coordinator_for(handle: str, store: LocalObservationStore, state: Path) -> Any:  # noqa: ANN401
            coordinator = _Coordinator(cast(ClientAttestedObservationStore, store), state)
            self.coordinators[handle] = coordinator
            return coordinator

        async def resolve(session_id: str) -> TaskRoute | None:
            if self.route_error is not None:
                raise self.route_error
            return self.routes.get(session_id)

        return ClaimObservationRouter(
            state_root=self.state,
            coordinator_for=coordinator_for,
            resolve_route=resolve,
            observation_enabled=True,
            max_claims=max_claims,
        )


@pytest.fixture
def harness(tmp_path: Path) -> _Harness:
    state = tmp_path / "server-state"
    state.mkdir(mode=0o700)
    return _Harness(state, {_SESSION: _route()})


def _context(commitment: str = _CLAIM) -> RepositoryPrivacyContext:
    return RepositoryPrivacyContext(commitment, "client_claim")


async def test_a_row_without_an_attestation_is_refused_before_any_write(
    harness: _Harness,
) -> None:
    result = await harness.router().ingest(_context(), _request())
    assert (result.disposition, result.reason) == (
        ObservationIngestDisposition.REJECTED,
        "consent_missing",
    )
    assert not (harness.state / CLAIM_OBSERVATION_DIRECTORY).exists()


@pytest.mark.parametrize(
    "route",
    [None, _route(task="tsk_00000000-0000-4000-8000-000000000c02"), _route(commitment=None)],
)
async def test_a_route_outside_the_claim_is_refused_before_any_write(
    harness: _Harness, route: TaskRoute | None
) -> None:
    harness.routes = {} if route is None else {_SESSION: route}
    result = await harness.router().ingest(_context(), _request(_attestation()))
    assert result.reason == "consent_missing"
    assert not (harness.state / CLAIM_OBSERVATION_DIRECTORY).exists()
    # Another claim's task is outside this claim too.
    harness.routes = {_SESSION: _route()}
    other = await harness.router().ingest(_context(_OTHER_CLAIM), _request(_attestation()))
    assert other.reason == "consent_missing"


async def test_an_unreadable_route_is_retryable_unavailability(harness: _Harness) -> None:
    harness.route_error = RuntimeError("catalog")
    result = await harness.router().ingest(_context(), _request(_attestation()))
    assert result.reason == "service_unavailable"


async def test_a_local_context_is_never_routed_to_a_claim(harness: _Harness) -> None:
    with pytest.raises(ValueError, match="claim_context_required"):
        await harness.router().ingest(
            RepositoryPrivacyContext(_CLAIM, "git_common_root"), _request(_attestation())
        )


async def test_the_attestation_is_mirrored_into_the_claims_own_store(harness: _Harness) -> None:
    router = harness.router()
    chunk = ObservationContentChunk(
        content_kind=ObservationContentKind.WORKSPACE_LOCATOR,
        correlation_identity="hook:codex-session-1:2:workspace",
        source_commitment=_CLIENT_SESSION,
        media_type="text/plain",
        part_index=0,
        part_count=1,
        content=b"/home/dev/project",
    )
    result = await router.ingest(_context(), _request(_attestation(), chunks=(chunk,)))
    assert result.reason == "paused"  # the fake coordinator's answer, passed through as is
    coordinator = harness.coordinators[_HANDLE]
    state = harness.state / CLAIM_OBSERVATION_DIRECTORY / _HANDLE.removeprefix("client:")
    assert coordinator.state == state == claim_observation_state(harness.state, _HANDLE)
    assert (state.stat().st_mode & 0o777) == 0o700
    store = coordinator.store
    workspace = store.claim_workspace
    assert workspace == store.workspace_commitment(_HANDLE)
    # The client's commitment, fence and trust answer for the claim; its consent is mirrored.
    assert store.session_commitment(_HOST_SESSION) == _CLIENT_SESSION
    assert store.find_workspace_for_codex_session(_HOST_SESSION) == workspace
    consent = store.consent_for(workspace)
    assert consent is not None and consent.active and consent.granted_at == _GRANTED
    authority = store.content_capture_authority(workspace)
    assert authority is not None and authority.generation == _GENERATION
    assert store.content_capture_authority_is_current(workspace, _GENERATION, ())
    assert not store.content_capture_authority_is_current(workspace, "sha256:" + "0" * 64, ())
    assert store.policy_digest_is_trusted(workspace, _POLICY)
    mapping = load_mapping(_HOST_SESSION, _state=state)
    assert mapping is not None
    assert (mapping.finishup_task_id, mapping.finishup_session_id) == (_TASK, _SESSION)
    # The coordinator receives no attestation and no client path.
    (seen,) = coordinator.seen
    assert seen.client_attestation is None
    assert [item.content for item in seen.content_chunks] == [_HANDLE.encode()]
    assert seen.envelope == _request().envelope


async def test_consent_changes_follow_the_client(harness: _Harness) -> None:
    router = harness.router()
    await router.ingest(_context(), _request(_attestation()))
    coordinator = harness.coordinators[_HANDLE]
    store, workspace = coordinator.store, coordinator.store.claim_workspace

    await router.ingest(_context(), _request(_attestation(consent="paused")))
    paused = store.consent_for(workspace)
    assert paused is not None and paused.paused and paused.revoked_at is None
    await router.ingest(_context(), _request(_attestation(check_policy_digest=None)))
    resumed = store.consent_for(workspace)
    assert resumed is not None and resumed.active
    assert not store.policy_digest_is_trusted(workspace, _POLICY)

    await router.ingest(_context(), _request(_attestation(consent="revoked")))
    assert coordinator.revoked == [workspace]
    revoked = store.consent_for(workspace)
    assert revoked is not None and revoked.revoked_at is not None
    # A repeated revoked attestation does not revoke again.
    await router.ingest(_context(), _request(_attestation(consent="revoked")))
    assert coordinator.revoked == [workspace]


async def test_a_route_the_service_followed_to_its_successor_is_kept(
    harness: _Harness,
) -> None:
    router = harness.router()
    await router.ingest(_context(), _request(_attestation()))
    state = harness.coordinators[_HANDLE].state
    successor = (
        "ses_00000000-0000-4000-8000-000000000c09",
        "wri_00000000-0000-4000-8000-000000000c09",
    )
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=_HOST_SESSION,
            finishup_task_id=_TASK,
            finishup_session_id=successor[0],
            finishup_writer_id=successor[1],
            last_frontier=None,
        ),
        _state=state,
    )
    await router.ingest(_context(), _request(_attestation()))
    kept = load_mapping(_HOST_SESSION, _state=state)
    assert kept is not None
    assert (kept.finishup_session_id, kept.finishup_writer_id) == successor
    # A session the client no longer maps is unmapped for the claim too.
    await router.ingest(_context(), _request(_attestation(route=None)))
    assert load_mapping(_HOST_SESSION, _state=state) is None


async def test_capacity_closes_an_idle_claim_and_refuses_when_all_are_busy(
    harness: _Harness,
) -> None:
    router = harness.router(max_claims=1)
    harness.routes = {_SESSION: _route()}
    await router.ingest(_context(), _request(_attestation()))
    first = harness.coordinators[_HANDLE]
    other_handle = workspace_handle_for_commitment(_OTHER_CLAIM)
    harness.routes = {_SESSION: _route(commitment=_OTHER_CLAIM)}
    await router.ingest(_context(_OTHER_CLAIM), _request(_attestation()))
    assert first.closed
    busy = harness.coordinators[other_handle]
    busy.gate = asyncio.Event()
    pending = asyncio.create_task(router.ingest(_context(_OTHER_CLAIM), _request(_attestation())))
    while not busy.seen[1:]:
        await asyncio.sleep(0)
    harness.routes = {_SESSION: _route()}
    refused = await router.ingest(_context(), _request(_attestation()))
    assert refused.reason == "service_unavailable"
    busy.gate.set()
    await pending
    router.close()
    assert busy.closed
    closed = await router.ingest(_context(), _request(_attestation()))
    assert closed.reason == "service_unavailable"


def test_an_unattested_session_never_matches_a_client_commitment(tmp_path: Path) -> None:
    state = tmp_path / "claim"
    state.mkdir(mode=0o700)
    store = ClientAttestedObservationStore(handle=_HANDLE, _state=state)
    assert store.session_commitment(_HOST_SESSION) != _CLIENT_SESSION
    store.attest_session(_HOST_SESSION, _CLIENT_SESSION)
    assert store.session_commitment(_HOST_SESSION) == _CLIENT_SESSION
    assert "client:" not in repr(store) and os.fspath(state) not in repr(store)
    with pytest.raises(ValueError, match="workspace_handle_invalid"):
        ClientAttestedObservationStore(handle="/home/dev", _state=state)


async def test_the_support_handler_routes_only_claim_bound_rows_to_the_claims() -> None:
    routed: list[RepositoryPrivacyContext] = []

    class _Claims:
        async def ingest(
            self, context: RepositoryPrivacyContext, request: ObservationIngestRequest
        ) -> ObservationIngestResult:
            del request
            routed.append(context)
            return ObservationIngestResult(ObservationIngestDisposition.REJECTED, "paused", None)

    class _Port:
        def __init__(self) -> None:
            self.seen: list[ObservationIngestRequest] = []

        async def ingest_request(
            self, request: ObservationIngestRequest
        ) -> ObservationIngestResult:
            self.seen.append(request)
            return ObservationIngestResult(ObservationIngestDisposition.REJECTED, "paused", None)

    port = _Port()
    attested = observation_ingest_request_to_json(_request(_attestation()))
    plain = observation_ingest_request_to_json(_request())
    claimed = build_observation_support_handlers(cast(Any, port), claims=_Claims())
    ingest = claimed[ControlMethod.OBSERVATION_INGEST]
    # A locator-bound or unbound connection keeps its own path; an attestation there is malformed.
    assert (await ingest(plain))["reason"] == "paused"
    assert len(port.seen) == 1
    local = RepositoryPrivacyContext(_CLAIM, "git_common_root")
    for context in (None, local):
        kwargs = {} if context is None else {"repository_privacy_context": context}
        with pytest.raises(ControlError) as raised:
            await cast(Any, ingest)(attested, **kwargs)
        assert raised.value.reason == "frame_invalid"
    assert len(port.seen) == 1 and routed == []
    # A claim-bound connection's row goes to its claim, attested or not.
    await cast(Any, ingest)(attested, repository_privacy_context=_context())
    await cast(Any, ingest)(plain, repository_privacy_context=_context())
    assert routed == [_context(), _context()] and len(port.seen) == 1
    # With no claims composed, the service holds no consent for a client's workspace.
    bare = build_observation_support_handlers(cast(Any, port))[ControlMethod.OBSERVATION_INGEST]
    refused = await cast(Any, bare)(attested, repository_privacy_context=_context())
    assert refused["reason"] == "consent_missing"
