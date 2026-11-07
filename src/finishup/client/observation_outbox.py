"""Deliver what this client captured to a FinishUP server on another machine (ADR-051).

Hooks capture observation rows into the local outbox of the root they run under (and a legacy
Codex host appends to the hook spool) and deliver what they can on each pass, as they always
have. For a local server, that service's own sweeper delivers the rest. A server on another
machine owns no local store, so the client delivers what it captured: a long-lived client process
(which one is the approach's choice) runs ``ClientObservationDrain.drain`` in the background over
its own claim-bound connection.

One pass is the service's own: it replays this workspace's spooled hook records into the outbox
the way the service replays them (``handle_observe`` with no service), then runs the shared
``ObservationOutboxSweeper`` over the outbox, narrowed to the one workspace the connection
claimed, with each ingest sent as ``observation_ingest``, attested with what this client's store
and mapping hold for it (ADR-051 decision 12, ``finishup.client.observation_attestation``).
Routing, attempt accounting, gaps, quarantine and the per-lane FIFO order are that sweeper's. Like the CLI drain, a pass stops at
the first control failure instead of charging every later row an attempt for a connection that
is gone; rows it did not settle stay pending for the next pass.
"""

from __future__ import annotations

import asyncio
import io
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Final, Protocol, cast

from finishup.adapters.integrations.hook_spool import DEFAULT_HOOK_SPOOL_CLAIM_LIMIT, HookSpool
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_drain import (
    DEFAULT_OBSERVATION_SWEEP_BUDGET_SECONDS,
    ObservationControlFailure,
    ObservationDrainSummary,
    ObservationOutboxSweeper,
    observation_control_failure,
)
from finishup.client.observation_attestation import attest_for_connection
from finishup.domain.observation import (
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationIngestResult,
    observation_ingest_request_to_json,
    observation_ingest_result_from_json,
)
from finishup.domain.values import JsonObject
from finishup.domain.values import JsonValue as DomainJsonValue
from finishup.observability.logging import record_unexpected_exception_without_raising
from finishup.ports.control import ControlError, WorkspaceLocator
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "ClientDrainSummary",
    "ClientObservationDrain",
    "ObservationIngestClient",
    "check_policy_trusted",
    "drain_client_observation",
]

_COMPONENT: Final = "client.observation_outbox"
# The CLI drain's bound for one ingest (``finishup observe drain``).
_DEFAULT_INGEST_DEADLINE_MS: Final = 3_000


class ObservationIngestClient(Protocol):
    """The one control method a drain uses; ``ServiceClient`` is the production client."""

    async def observation_ingest(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> JsonObject: ...


@dataclass(frozen=True, slots=True)
class ClientDrainSummary:
    """One pass: the spooled records replayed into the outbox, and what delivery did.

    ``delivery`` is the shared sweeper's summary, or None when the pass stopped at a control
    failure; ``stopped`` is then that failure's closed control reason. A failure on the pass's
    last attempt keeps its summary and still names the reason. Rows not settled stay pending.
    """

    spool_replayed: int
    delivery: ObservationDrainSummary | None
    stopped: str | None = None


class _PassStopped(BaseException):
    """Unwinds a sweep after a control failure without charging any further row an attempt.

    A ``BaseException`` so the sweeper's per-row ``except Exception`` cannot turn it into a row
    outcome; the sweep's own ``finally`` still releases the workspace lease, and only
    ``ClientObservationDrain.drain`` catches it.
    """


class _ClientIngest:
    """``ObservationIngestCoordinator`` over one client connection, mapped as the CLI drain maps it.

    Each row is attested from ``store`` before it is sent when the connection is claim-bound.
    """

    __slots__ = ("_client", "_deadline_ms", "_state", "_store", "_workspace", "failure")

    def __init__(
        self,
        client: ObservationIngestClient,
        deadline_ms: int,
        *,
        store: LocalObservationStore,
        workspace_commitment: str,
        state: Path | None,
    ) -> None:
        self._client = client
        self._deadline_ms = deadline_ms
        self._store = store
        self._workspace = workspace_commitment
        self._state = state
        self.failure: str | None = None

    async def ingest_request(self, request: ObservationIngestRequest) -> ObservationIngestResult:
        if self.failure is not None:
            raise _PassStopped
        stage = "request_encode"
        try:
            request = await asyncio.get_running_loop().run_in_executor(
                None,
                partial(
                    attest_for_connection,
                    request,
                    self._client,
                    store=self._store,
                    workspace_commitment=self._workspace,
                    state=self._state,
                ),
            )
            body = observation_ingest_request_to_json(request)
            stage = "control"
            raw = await self._client.observation_ingest(body, deadline_ms=self._deadline_ms)
            stage = "response_decode"
            return observation_ingest_result_from_json(raw)
        except ControlError as error:
            self.failure = error.reason
            return observation_control_failure(error)
        except (ProtocolValueError, TypeError, ValueError):
            reason = "invalid_request" if stage == "request_encode" else "frame_invalid"
            self.failure = reason
            return ObservationControlFailure(
                ObservationIngestDisposition.REJECTED,
                "control_" + reason,
                None,
                reason,
                False,
                None,
                stage,
            )


class _WorkspaceStore(LocalObservationStore):
    """The local store with its pending inventory narrowed to the one claimed workspace."""

    def __init__(self, workspace_commitment: str, *, _state: Path | None) -> None:
        super().__init__(_state=_state)
        self._only = workspace_commitment

    def pending_workspaces(self) -> tuple[str, ...]:
        return tuple(item for item in super().pending_workspaces() if item == self._only)


def check_policy_trusted(workspace: str, policy_digest: str, *, state: Path | None = None) -> bool:
    """Whether this client's owner trusted ``policy_digest`` as ``workspace``'s check policy.

    On a remote target the client's observation store is the authority for approved-check trust
    (ADR-051 decision 12): ``finishup observe checks trust`` records it there and ``revoke``
    removes it. The workspace agent asks here before every approved check it would run, so a
    server, honest or not, can run only argv from the policy whose exact raw digest the owner
    trusted, and a revoke takes effect at once. No key material is created: a store that never
    recorded anything for ``workspace`` trusts nothing, and a store that cannot be read trusts
    nothing either.
    """

    try:
        store = LocalObservationStore(_state=state)
        commitment = store.existing_workspace_commitment(workspace)
        return commitment is not None and store.policy_digest_is_trusted(commitment, policy_digest)
    except Exception:  # noqa: BLE001 - an unreadable store trusts nothing (fail closed)
        return False


def _workspace_commitment(state: Path | None, workspace: str) -> str | None:
    """The store's commitment for ``workspace``; None while nothing was ever captured here."""

    return LocalObservationStore(_state=state).existing_workspace_commitment(workspace)


def _replay_spool(state: Path | None, workspace_commitment: str, limit: int) -> int:
    """Normalize one bounded batch of this workspace's spooled hook records into the outbox.

    The service's own replay (``ready_composition._replay_legacy_hook_spool``), narrowed to one
    workspace: each record goes through ``handle_observe`` with no service, and the spool's cursor
    advances only once the whole batch was processed.
    """

    spool = HookSpool(_state=state)
    if not spool.has_pending(workspace_commitment):
        return 0
    from finishup.cli.observe_hooks import handle_observe

    with spool.claim(workspace_commitment, limit=limit) as records:
        for record in records:
            handle_observe(
                event_name=record.event_name,
                stdin_bytes=canonical_encode(cast(DomainJsonValue, record.payload)),
                stdout=io.BytesIO(),
                _state=state,
                skip_service=True,
                _workspace_commitment=workspace_commitment,
            )
    return len(records)


class ClientObservationDrain:
    """Deliver one claimed workspace's captured rows to a remote server, one bounded pass a call.

    Keep one per workspace in a long-lived process and call ``drain`` with whichever connection
    is current; ``close`` when done. Passes never overlap: a spool batch still being replayed
    from a cancelled pass is left to finish, and the next pass skips the spool until it has.
    """

    __slots__ = (
        "_budget_seconds",
        "_deadline_ms",
        "_spool_limit",
        "_spool_work",
        "_state",
        "_sweeper",
        "_workspace",
    )

    def __init__(
        self,
        workspace: WorkspaceLocator,
        *,
        state: Path | None = None,
        budget_seconds: float = DEFAULT_OBSERVATION_SWEEP_BUDGET_SECONDS,
        ingest_deadline_ms: int = _DEFAULT_INGEST_DEADLINE_MS,
        spool_batch_limit: int = DEFAULT_HOOK_SPOOL_CLAIM_LIMIT,
    ) -> None:
        """``workspace`` is the locator the hooks bound and the connection's claim came from;
        ``state`` the root's state directory (the active root's when None)."""

        if type(workspace) is not WorkspaceLocator:
            raise TypeError("workspace_locator_invalid")
        if type(budget_seconds) is not float or not budget_seconds > 0.0:
            raise ValueError("observation_sweep_budget_invalid")
        if type(ingest_deadline_ms) is not int or not 1 <= ingest_deadline_ms <= 300_000:
            raise ValueError("observation_ingest_deadline_invalid")
        if type(spool_batch_limit) is not int or spool_batch_limit < 1:
            raise ValueError("hook_spool_claim_limit_invalid")
        self._workspace = workspace.path
        self._state = state
        self._budget_seconds = budget_seconds
        self._deadline_ms = ingest_deadline_ms
        self._spool_limit = spool_batch_limit
        self._spool_work: asyncio.Future[int] | None = None
        self._sweeper: ObservationOutboxSweeper | None = None

    async def drain(self, client: ObservationIngestClient) -> ClientDrainSummary:
        """Run one pass over ``client``; store contention and control failures are outcomes."""

        loop = asyncio.get_running_loop()
        commitment = await loop.run_in_executor(
            None, _workspace_commitment, self._state, self._workspace
        )
        if commitment is None:
            return ClientDrainSummary(0, ObservationDrainSummary(0, 0, 0, 0, ()))
        replayed = await self._replay(commitment)
        sweeper = self._sweeper
        if sweeper is None:
            store = await loop.run_in_executor(
                None, partial(_WorkspaceStore, commitment, _state=self._state)
            )
            ingest = _ClientIngest(
                client,
                self._deadline_ms,
                store=store,
                workspace_commitment=commitment,
                state=self._state,
            )
            sweeper = ObservationOutboxSweeper(store, ingest, budget_seconds=self._budget_seconds)
            self._sweeper = sweeper
        else:
            ingest = _ClientIngest(
                client,
                self._deadline_ms,
                store=sweeper.local,
                workspace_commitment=commitment,
                state=self._state,
            )
            sweeper.coordinator = ingest
        try:
            summary = await sweeper.sweep()
        except _PassStopped:
            return ClientDrainSummary(replayed, None, ingest.failure)
        return ClientDrainSummary(replayed, summary, ingest.failure)

    async def _replay(self, commitment: str) -> int:
        work = self._spool_work
        if work is not None and not work.done():
            return 0
        work = asyncio.get_running_loop().run_in_executor(
            None, _replay_spool, self._state, commitment, self._spool_limit
        )
        self._spool_work = work
        try:
            return await asyncio.shield(work)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # The batch stays in the spool for the next pass; the outbox still drains now.
            record_unexpected_exception_without_raising(
                exc, component=_COMPONENT, operation="hook_spool_replay_failed"
            )
            return 0

    def close(self) -> None:
        """Release the sweeper's worker pool; a running store hop is itself bounded."""

        sweeper, self._sweeper = self._sweeper, None
        if sweeper is not None:
            sweeper.close()


async def drain_client_observation(
    client: ObservationIngestClient,
    workspace: WorkspaceLocator,
    *,
    state: Path | None = None,
    budget_seconds: float = DEFAULT_OBSERVATION_SWEEP_BUDGET_SECONDS,
) -> ClientDrainSummary:
    """One pass of ``ClientObservationDrain`` for a caller that keeps no drain between passes."""

    drain = ClientObservationDrain(workspace, state=state, budget_seconds=budget_seconds)
    try:
        return await drain.drain(client)
    finally:
        drain.close()
