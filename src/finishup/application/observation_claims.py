"""Client-attested observation for claim-bound connections (ADR-051 decision 12).

A remote server target's hooks run on the client. The owner granted observation consent there,
the rows were captured there, and every session and workspace commitment was made under the
client's observation key, which never leaves the client. So on a claim-bound connection this
service cannot check a row's session commitment against its own key, nor read the consent or the
lifecycle mapping from its own state: the client attests them with each row
(``ObservationClientAttestation``), and the service accepts them as ``client_attested``.

What is attested is recorded per claim, keyed to the claim's handle, in a store of its own:
``<state>/observation-claims/<16 hex>/`` holds an ordinary observation store and lifecycle-mapping
directory with the claim's one workspace, under a key this service generates. The unchanged
``ObservationCoordinator`` runs over it in claim mode (``client_workspace_handle``), so routing,
capture, ledger materialization and verification are the local ones; verification opens the
workspace by its handle through the client's workspace agent. This machine's own observation
store, mappings and consent are never read or written for a claim.

The service still decides three things itself. Only the connection's own claim is touched. The
attested route must name a task whose route was opened under the same claim; any other route is
refused with ``consent_missing`` before anything is written. And its own observation switch and
vault gate apply as for every ingest. Logs carry closed tokens and the ``client_attested`` label
only; nothing the client sent is ever written to a log or an error.
"""

from __future__ import annotations

import asyncio
import hmac
import threading
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Final

from finishup.adapters.integrations.codex_lifecycle import (
    clear_mapping,
    load_mapping,
    load_route_history,
    mapping_from_start_ids,
    store_mapping,
)
from finishup.adapters.integrations.observation_local import (
    LocalContentCaptureAuthority,
    LocalObservationStore,
)
from finishup.application.observation_coordinator import ObservationCoordinator
from finishup.config.paths import PathSafetyError, ensure_owner_only_dir
from finishup.domain.observation import (
    ObservationClientAttestation,
    ObservationClientRoute,
    ObservationContentKind,
    ObservationControlCommand,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationIngestResult,
    ObservationRevokeCommand,
)
from finishup.domain.receipts import CLIENT_ATTESTED
from finishup.observability.logging import (
    record_bounded_event_without_raising,
    record_unexpected_exception_without_raising,
)
from finishup.ports.control import RepositoryPrivacyContext
from finishup.ports.start_catalog import TaskRoute
from finishup.ports.workspace_agent import workspace_handle_for_commitment, workspace_handle_valid
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

__all__ = [
    "CLAIM_OBSERVATION_DIRECTORY",
    "ClaimObservationRouter",
    "ClaimCoordinatorFactory",
    "ClientAttestedObservationStore",
    "claim_observation_state",
]

_COMPONENT: Final = "application.observation_claims"
CLAIM_OBSERVATION_DIRECTORY: Final = "observation-claims"
# Claims whose stores stay open at once. A client workspace is one claim, so a server sees few;
# an idle claim beyond the bound is closed and reopens from its directory on its next row.
_MAX_OPEN_CLAIMS: Final = 64
# Host sessions whose client commitment a claim store remembers between rows. Every row names
# its own, so a forgotten one is attested again by the next row of that session.
_MAX_ATTESTED_SESSIONS: Final = 4_096
_UNAPPLIED: Final = object()

type ClaimCoordinatorFactory = Callable[[str, LocalObservationStore, Path], ObservationCoordinator]
type RouteResolver = Callable[[str], Awaitable[TaskRoute | None]]


def _reject(reason: str) -> ObservationIngestResult:
    return ObservationIngestResult(ObservationIngestDisposition.REJECTED, reason, None)


def _record(operation: str, reason: str) -> None:
    record_bounded_event_without_raising(component=_COMPONENT, operation=operation, reason=reason)


def claim_observation_state(state_root: Path, handle: str) -> Path:
    """The owner-only directory holding one claim's attested observation, keyed by its handle."""

    if not workspace_handle_valid(handle):
        raise ValueError("workspace_handle_invalid")
    directory = state_root / CLAIM_OBSERVATION_DIRECTORY / handle.removeprefix("client:")
    ensure_owner_only_dir(directory)
    return directory


class ClientAttestedObservationStore(LocalObservationStore):
    """One claim's observation store: the client's commitments and fence, as attested.

    An ordinary ``LocalObservationStore`` at the claim's directory, with its one workspace keyed by
    this service's own commitment to the claim's handle. Two answers come from the client instead
    of from this store's key and state, because only the client can compute them: the session
    commitment of a host session (made under the client's observation key) and the current
    content-capture fence generation (the client's consent, epoch and runtime gate). Both are
    recorded by ``ClaimObservationRouter`` from each row's attestation before the row is
    ingested. A host session no row has attested yet answers this store's own commitment, which
    never equals a client's, so it reads as unknown.
    """

    def __init__(self, *, handle: str, _state: Path) -> None:
        if not workspace_handle_valid(handle):
            raise ValueError("workspace_handle_invalid")
        super().__init__(_state=_state)
        self._claim_handle = handle
        self._attested_guard = threading.Lock()
        self._attested_sessions: OrderedDict[str, str] = OrderedDict()
        self._attested_generation: str | None = None

    def __repr__(self) -> str:
        return "ClientAttestedObservationStore(<redacted>)"

    @property
    def claim_workspace(self) -> str:
        """This claim's one workspace key: this service's commitment to the handle."""

        return self.workspace_commitment(self._claim_handle)

    def attest_session(self, codex_session_id: str, session_commitment: str) -> None:
        with self._attested_guard:
            self._attested_sessions[codex_session_id] = session_commitment
            self._attested_sessions.move_to_end(codex_session_id)
            while len(self._attested_sessions) > _MAX_ATTESTED_SESSIONS:
                self._attested_sessions.popitem(last=False)

    def attest_generation(self, generation: str | None) -> None:
        with self._attested_guard:
            self._attested_generation = generation

    def session_commitment(self, codex_session_id: str) -> str:
        with self._attested_guard:
            attested = self._attested_sessions.get(codex_session_id)
        if attested is not None:
            return attested
        return super().session_commitment(codex_session_id)

    def content_capture_authority(
        self, workspace_commitment: str
    ) -> LocalContentCaptureAuthority | None:
        authority = super().content_capture_authority(workspace_commitment)
        with self._attested_guard:
            generation = self._attested_generation
        if authority is None or generation is None:
            return authority
        return replace(authority, generation=generation)

    def content_capture_authority_is_current(
        self,
        workspace_commitment: str,
        generation: str,
        profiles: tuple[str, ...],
    ) -> bool:
        authority = self.content_capture_authority(workspace_commitment)
        return (
            authority is not None
            and authority.active
            and authority.runtime_enabled
            and authority.generation == generation
            and authority.profiles == profiles
        )


@dataclass(slots=True)
class _Claim:
    """One open claim: its store, its coordinator, and what was last mirrored into the store."""

    handle: str
    state: Path
    store: ClientAttestedObservationStore
    workspace: str
    coordinator: ObservationCoordinator
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    in_flight: int = 0
    consent_applied: object = _UNAPPLIED
    policy_applied: object = _UNAPPLIED
    bound_sessions: set[tuple[str, str]] = field(default_factory=set[tuple[str, str]])

    def apply(
        self,
        codex_session_id: str,
        session_commitment: str,
        attestation: ObservationClientAttestation,
    ) -> bool:
        """Mirror one row's attestation into the claim store; True when a revoke must follow.

        Blocking (store and mapping files); run in a worker thread under ``lock``.
        """

        store = self.store
        workspace = self.workspace
        store.attest_session(codex_session_id, session_commitment)
        store.attest_generation(attestation.authority_generation)
        revoke = False
        consent = (
            attestation.consent,
            attestation.granted_at,
            attestation.content_capture_profiles,
        )
        if consent != self.consent_applied:
            current = store.consent_for(workspace)
            if attestation.consent == "revoked":
                # The service's own revocation runs for the claim (``ClaimObservationRouter``).
                revoke = current is not None and current.revoked_at is None
            else:
                if (
                    attestation.consent == "active"
                    or current is None
                    or current.revoked_at is not None
                    or current.content_capture_profiles != attestation.content_capture_profiles
                ):
                    store.grant_consent(
                        workspace,
                        attestation.granted_at,
                        content_capture_profiles=attestation.content_capture_profiles,
                    )
                if attestation.consent == "paused":
                    paused = store.consent_for(workspace)
                    if paused is not None and not paused.paused:
                        store.pause(ObservationControlCommand(workspace))
            if not revoke:
                self.consent_applied = consent
        if attestation.check_policy_digest != self.policy_applied:
            if attestation.check_policy_digest is None:
                store.revoke_policy_trust(workspace)
            else:
                store.trust_policy_digest(workspace, attestation.check_policy_digest)
            self.policy_applied = attestation.check_policy_digest
        # A host session binds to a workspace that holds a consent record (of any state), so a
        # revocation still finds the sessions it must fence.
        bound = (codex_session_id, session_commitment)
        if bound not in self.bound_sessions and store.consent_for(workspace) is not None:
            store.bind_codex_session(workspace, codex_session_id)
            if len(self.bound_sessions) >= _MAX_ATTESTED_SESSIONS:
                self.bound_sessions.clear()
            self.bound_sessions.add(bound)
        _mirror_route(self.state, codex_session_id, attestation.route)
        return revoke

    def revoked(self, attestation: ObservationClientAttestation) -> None:
        self.consent_applied = (
            attestation.consent,
            attestation.granted_at,
            attestation.content_capture_profiles,
        )


def _mirror_route(state: Path, codex_session_id: str, route: ObservationClientRoute | None) -> None:
    """Keep the claim's mapping for one host session equal to what the client's mapping names.

    A route the service already followed to its successor (the attested route is the claim
    mapping's recorded predecessor) is kept as the service has it. A host session the client no
    longer maps is unmapped here too.
    """

    current = load_mapping(codex_session_id, _state=state)
    if route is None:
        if current is not None:
            clear_mapping(codex_session_id, _state=state)
        return
    attested = (route.session_id, route.writer_id)
    if current is not None and current.finishup_task_id == route.task_id:
        if (current.finishup_session_id, current.finishup_writer_id) == attested:
            return
        history = load_route_history(current, _state=state)
        if history is not None and attested in history.routes:
            return
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=codex_session_id,
            finishup_task_id=route.task_id,
            finishup_session_id=route.session_id,
            finishup_writer_id=route.writer_id,
            last_frontier=None,
        ),
        _state=state,
    )


def _claim_request(request: ObservationIngestRequest, handle: str) -> ObservationIngestRequest:
    """The row as the claim's coordinator ingests it: no attestation, and no client path.

    A claim's workspace locator is only ever its handle (verification never reads a stored one),
    so any workspace-locator content is replaced by the handle before it could be stored here.
    """

    chunks = tuple(
        replace(chunk, content=handle.encode("ascii"))
        if chunk.content_kind is ObservationContentKind.WORKSPACE_LOCATOR
        else chunk
        for chunk in request.content_chunks
    )
    return replace(request, content_chunks=chunks, client_attestation=None)


class ClaimObservationRouter:
    """Ingest a claim-bound connection's rows over that claim's own attested store.

    ``coordinator_for(handle, store, state)`` builds the claim's coordinator, normally the
    service's own coordinator with ``local`` and ``state_root`` replaced and
    ``client_workspace_handle`` set. ``resolve_route`` is the catalog's session route lookup.
    """

    __slots__ = (
        "_claims",
        "_closed",
        "_coordinator_for",
        "_max_claims",
        "_observation_enabled",
        "_open_lock",
        "_resolve_route",
        "_state_root",
    )

    def __init__(
        self,
        *,
        state_root: Path,
        coordinator_for: ClaimCoordinatorFactory,
        resolve_route: RouteResolver,
        observation_enabled: bool,
        max_claims: int = _MAX_OPEN_CLAIMS,
    ) -> None:
        if type(max_claims) is not int or max_claims < 1:
            raise ValueError("claim_capacity_invalid")
        self._state_root = state_root
        self._coordinator_for = coordinator_for
        self._resolve_route = resolve_route
        self._observation_enabled = observation_enabled
        self._max_claims = max_claims
        self._claims: OrderedDict[str, _Claim] = OrderedDict()
        self._open_lock = asyncio.Lock()
        self._closed = False

    def __repr__(self) -> str:
        return "ClaimObservationRouter(<redacted>)"

    async def ingest(
        self, context: RepositoryPrivacyContext, request: ObservationIngestRequest
    ) -> ObservationIngestResult:
        """Ingest one claim-bound row; every refusal is a closed reason, decided before writes."""

        if context.identity_kind != "client_claim":
            raise ValueError("claim_context_required")
        attestation = request.client_attestation
        if attestation is None:
            # The service holds no consent of its own for a client's workspace.
            _record("observation_claim_ingest", "attestation_missing")
            return _reject(ObservationGapCode.CONSENT_MISSING.value)
        route = attestation.route
        if route is not None:
            try:
                inside = await self._route_in_claim(route, context.commitment)
            except Exception as exc:
                record_unexpected_exception_without_raising(
                    exc, component=_COMPONENT, operation="observation_claim_route"
                )
                return _reject(ObservationGapCode.SERVICE_UNAVAILABLE.value)
            if not inside:
                _record("observation_claim_ingest", "route_outside_claim")
                return _reject(ObservationGapCode.CONSENT_MISSING.value)
        handle = workspace_handle_for_commitment(context.commitment)
        claim = await self._open(handle)
        if claim is None:
            return _reject(ObservationGapCode.SERVICE_UNAVAILABLE.value)
        claim.in_flight += 1
        try:
            async with claim.lock:
                try:
                    revoke = await asyncio.to_thread(
                        claim.apply,
                        request.codex_session_id,
                        request.envelope.session_commitment,
                        attestation,
                    )
                    if revoke:
                        await claim.coordinator.revoke(ObservationRevokeCommand(claim.workspace))
                        claim.revoked(attestation)
                except PublicOperationError as exc:
                    if exc.code is PublicErrorCode.STORAGE_CORRUPT:
                        return _reject(ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value)
                    return _reject(ObservationGapCode.SERVICE_UNAVAILABLE.value)
                except Exception as exc:
                    record_unexpected_exception_without_raising(
                        exc, component=_COMPONENT, operation="observation_claim_attestation"
                    )
                    return _reject(ObservationGapCode.SERVICE_UNAVAILABLE.value)
            result = await claim.coordinator.ingest_request(_claim_request(request, handle))
            _record("observation_claim_ingest", CLIENT_ATTESTED)
            return result
        finally:
            claim.in_flight -= 1

    async def _route_in_claim(self, route: ObservationClientRoute, commitment: str) -> bool:
        """Whether the attested route's task was opened under this very claim."""

        task_route = await self._resolve_route(route.session_id)
        if task_route is None or task_route.task_id != route.task_id:
            return False
        recorded = task_route.repository_privacy_commitment
        return recorded is not None and hmac.compare_digest(recorded, commitment)

    async def _open(self, handle: str) -> _Claim | None:
        async with self._open_lock:
            if self._closed:
                return None
            claim = self._claims.get(handle)
            if claim is not None:
                self._claims.move_to_end(handle)
                return claim
            if len(self._claims) >= self._max_claims:
                idle = next(
                    (key for key, item in self._claims.items() if item.in_flight == 0), None
                )
                if idle is None:
                    _record("observation_claim_open", "claim_capacity_exhausted")
                    return None
                self._claims.pop(idle).coordinator.close()
            try:
                state, store, workspace = await asyncio.to_thread(self._open_store, handle)
            except (OSError, PathSafetyError) as exc:
                record_unexpected_exception_without_raising(
                    exc, component=_COMPONENT, operation="observation_claim_open"
                )
                return None
            claim = _Claim(
                handle=handle,
                state=state,
                store=store,
                workspace=workspace,
                coordinator=self._coordinator_for(handle, store, state),
            )
            self._claims[handle] = claim
            return claim

    def _open_store(self, handle: str) -> tuple[Path, ClientAttestedObservationStore, str]:
        state = claim_observation_state(self._state_root, handle)
        store = ClientAttestedObservationStore(handle=handle, _state=state)
        store.set_runtime_enabled(self._observation_enabled)
        return state, store, store.claim_workspace

    def close(self) -> None:
        """Release every open claim's coordinator; later rows are refused as unavailable."""

        self._closed = True
        claims, self._claims = self._claims, OrderedDict()
        for claim in claims.values():
            claim.coordinator.close()
