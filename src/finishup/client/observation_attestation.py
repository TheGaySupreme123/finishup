"""Attest each observation row a remote FinishUP server receives (ADR-051 decision 12).

For a remote server target this client's observation store is the authority: the owner granted
observation consent here, the hooks captured here, and every session and workspace commitment
was made under this client's observation key, which never leaves the machine. The server cannot
read any of it, so each ``observation_ingest`` sent over a claim-bound connection carries what
the store and the lifecycle mapping hold at that moment: the consent state, its grant time, the
enabled content profiles, the current content-capture fence, the trusted approved-check policy
digest and the FinishUP route mapped for the host session. The server records it for the claim as
``client_attested`` and verifies none of it.

The workspace path never leaves either: any workspace-locator content in the row is replaced by
the connection's own ``client:`` handle. A connection that is not claim-bound (every local
target) sends the row exactly as before.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Protocol

from finishup.adapters.integrations.codex_lifecycle import load_mapping
from finishup.domain.observation import (
    ObservationClientAttestation,
    ObservationClientRoute,
    ObservationContentKind,
    ObservationIngestRequest,
)
from finishup.domain.values import Timestamp
from finishup.ports.workspace_agent import workspace_handle_valid

__all__ = [
    "AttestingObservationStore",
    "attest_for_connection",
    "attest_ingest_request",
    "client_attestation",
    "connection_workspace_handle",
]


class _Consent(Protocol):
    @property
    def granted_at(self) -> Timestamp: ...

    @property
    def revoked_at(self) -> Timestamp | None: ...

    @property
    def paused(self) -> bool: ...

    @property
    def content_capture_profiles(self) -> tuple[str, ...]: ...


class _Authority(Protocol):
    @property
    def generation(self) -> str: ...


class AttestingObservationStore(Protocol):
    """The reads an attestation takes from this root's observation store.

    ``LocalObservationStore`` is the production store; it is named structurally so this client
    module stays on its side of the cut line.
    """

    def consent_for(self, workspace_commitment: str) -> _Consent | None: ...

    def content_capture_authority(self, workspace_commitment: str) -> _Authority | None: ...

    def trusted_policy_digest(self, workspace: str) -> str | None: ...


def connection_workspace_handle(connection: object) -> str | None:
    """The claim handle of a claim-bound connection; None for every other connection."""

    handle = getattr(connection, "workspace_handle", None)
    return handle if type(handle) is str and workspace_handle_valid(handle) else None


def client_attestation(
    store: AttestingObservationStore,
    workspace_commitment: str,
    codex_session_id: str,
    *,
    state: Path | None = None,
) -> ObservationClientAttestation | None:
    """What this client's store and mapping hold for one row; None while there is no consent.

    ``state`` is the root's state directory (the active root's when None), where the lifecycle
    mappings live beside the store.
    """

    consent = store.consent_for(workspace_commitment)
    if consent is None:
        return None
    if consent.revoked_at is not None:
        consent_state = "revoked"
    elif consent.paused:
        consent_state = "paused"
    else:
        consent_state = "active"
    authority = store.content_capture_authority(workspace_commitment)
    mapping = load_mapping(codex_session_id, _state=state)
    return ObservationClientAttestation(
        consent=consent_state,
        granted_at=consent.granted_at,
        content_capture_profiles=consent.content_capture_profiles,
        authority_generation=None if authority is None else authority.generation,
        check_policy_digest=store.trusted_policy_digest(workspace_commitment),
        route=(
            None
            if mapping is None
            else ObservationClientRoute(
                task_id=mapping.finishup_task_id,
                session_id=mapping.finishup_session_id,
                writer_id=mapping.finishup_writer_id,
            )
        ),
    )


def attest_ingest_request(
    request: ObservationIngestRequest,
    *,
    handle: str,
    store: AttestingObservationStore,
    workspace_commitment: str,
    state: Path | None = None,
) -> ObservationIngestRequest:
    """``request`` as a claim-bound connection sends it: attested, and naming no path.

    Without a consent the row goes unattested, and the server refuses it as ``consent_missing``
    exactly as it refuses an unconsented local row.
    """

    if not workspace_handle_valid(handle):
        raise ValueError("workspace_handle_invalid")
    chunks = tuple(
        replace(chunk, content=handle.encode("ascii"))
        if chunk.content_kind is ObservationContentKind.WORKSPACE_LOCATOR
        else chunk
        for chunk in request.content_chunks
    )
    return replace(
        request,
        content_chunks=chunks,
        client_attestation=client_attestation(
            store, workspace_commitment, request.codex_session_id, state=state
        ),
    )


def attest_for_connection(
    request: ObservationIngestRequest,
    connection: object,
    *,
    store: AttestingObservationStore,
    workspace_commitment: str,
    state: Path | None = None,
) -> ObservationIngestRequest:
    """``request`` as ``connection`` must send it: attested when claim-bound, else unchanged."""

    handle = connection_workspace_handle(connection)
    if handle is None:
        return request
    return attest_ingest_request(
        request,
        handle=handle,
        store=store,
        workspace_commitment=workspace_commitment,
        state=state,
    )
