"""Each row a remote server receives says what this client's store holds, and names no path.

ADR-051 decision 12: the client's observation store is the authority for a remote target. The
attestation is read from it when the row is sent; a connection that is not claim-bound sends the
row exactly as before.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from finishup.adapters.integrations.codex_lifecycle import mapping_from_start_ids, store_mapping
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.client.observation_attestation import (
    attest_for_connection,
    attest_ingest_request,
    client_attestation,
    connection_workspace_handle,
)
from finishup.domain.observation import (
    ObservationContentChunk,
    ObservationContentKind,
    ObservationControlCommand,
    ObservationCursor,
    ObservationEnvelope,
    ObservationIngestRequest,
    ObservationRevokeCommand,
    ObservationSource,
    observation_ingest_request_to_json,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.canonical import canonical_encode

_HANDLE = "client:0a1b2c3d4e5f6071"
_SESSION_ID = "codex-session-1"
_DIGEST = "sha256:" + "c4" * 32


class _Connection:
    def __init__(self, handle: object, binding: str | None = None) -> None:
        self.workspace_handle = handle
        if binding is not None:
            self.workspace_binding = binding


def _store(tmp_path: Path) -> tuple[LocalObservationStore, str, Path, str]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    workspace = tmp_path / "work"
    workspace.mkdir()
    path = os.fspath(workspace.resolve())
    store = LocalObservationStore(_state=state)
    return store, store.workspace_commitment(path), state, path


def _request(store: LocalObservationStore, workspace: str, path: str) -> ObservationIngestRequest:
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, _SESSION_ID)
    envelope = ObservationEnvelope(
        session_commitment=session,
        event_kind="SessionStart",
        source_identity="hook:codex-session-1:1",
        source=ObservationSource.CODEX_HOOK,
        cursor=ObservationCursor(1, 0, 1, session, "codex-obs-hook/1.0.0"),
        receipt_time=Timestamp("2026-11-05T12:00:00.000Z"),
        structural_payload=JsonObject({}),
        content_object_refs=(),
        gap_codes=(),
    )
    chunk = ObservationContentChunk(
        content_kind=ObservationContentKind.WORKSPACE_LOCATOR,
        correlation_identity="hook:codex-session-1:1:workspace",
        source_commitment=session,
        media_type="text/plain",
        part_index=0,
        part_count=1,
        content=path.encode(),
    )
    return ObservationIngestRequest(_SESSION_ID, envelope, content_chunks=(chunk,))


def test_the_attestation_is_what_the_store_and_mapping_hold(tmp_path: Path) -> None:
    store, workspace, state, path = _store(tmp_path)
    request = _request(store, workspace, path)
    store.trust_policy_digest(workspace, _DIGEST)
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=_SESSION_ID,
            finishup_task_id="tsk_00000000-0000-4000-8000-000000000b01",
            finishup_session_id="ses_00000000-0000-4000-8000-000000000b01",
            finishup_writer_id="wri_00000000-0000-4000-8000-000000000b01",
            last_frontier=None,
        ),
        _state=state,
    )
    attestation = client_attestation(store, workspace, request.codex_session_id, state=state)
    assert attestation is not None
    consent = store.consent_for(workspace)
    authority = store.content_capture_authority(workspace)
    assert consent is not None and authority is not None
    assert attestation.consent == "active"
    assert attestation.granted_at == consent.granted_at
    assert attestation.content_capture_profiles == consent.content_capture_profiles
    assert attestation.authority_generation == authority.generation
    assert attestation.check_policy_digest == _DIGEST
    assert attestation.route is not None
    assert attestation.route.task_id == "tsk_00000000-0000-4000-8000-000000000b01"


def test_paused_revoked_and_unconsented_states_are_attested_as_they_are(tmp_path: Path) -> None:
    store, workspace, state, _path = _store(tmp_path)
    assert client_attestation(store, workspace, _SESSION_ID, state=state) is None
    store.grant_consent(workspace)
    store.pause(ObservationControlCommand(workspace))
    paused = client_attestation(store, workspace, _SESSION_ID, state=state)
    assert paused is not None and paused.consent == "paused" and paused.route is None
    store.revoke(ObservationRevokeCommand(workspace))
    revoked = client_attestation(store, workspace, _SESSION_ID, state=state)
    assert revoked is not None and revoked.consent == "revoked"
    assert revoked.check_policy_digest is None


def test_an_untrusted_or_tampered_policy_is_not_attested(tmp_path: Path) -> None:
    store, workspace, state, _path = _store(tmp_path)
    store.grant_consent(workspace)
    assert store.trusted_policy_digest(workspace) is None
    store.trust_policy_digest(workspace, _DIGEST)
    assert store.trusted_policy_digest(workspace) == _DIGEST
    store.revoke_policy_trust(workspace)
    attestation = client_attestation(store, workspace, _SESSION_ID, state=state)
    assert attestation is not None and attestation.check_policy_digest is None


def test_a_claim_bound_row_carries_the_attestation_and_the_handle_not_the_path(
    tmp_path: Path,
) -> None:
    store, workspace, state, path = _store(tmp_path)
    request = _request(store, workspace, path)
    attested = attest_ingest_request(
        request, handle=_HANDLE, store=store, workspace_commitment=workspace, state=state
    )
    assert attested.client_attestation is not None
    assert [chunk.content for chunk in attested.content_chunks] == [_HANDLE.encode()]
    encoded = canonical_encode(observation_ingest_request_to_json(attested))
    assert path.encode() not in encoded
    assert attested.envelope == request.envelope


def test_only_a_claim_bound_connection_attests(tmp_path: Path) -> None:
    store, workspace, state, path = _store(tmp_path)
    request = _request(store, workspace, path)
    for unbound in (_Connection(None), _Connection("client:short"), object()):
        assert connection_workspace_handle(unbound) is None
        assert (
            attest_for_connection(
                request, unbound, store=store, workspace_commitment=workspace, state=state
            )
            is request
        )
    bound = attest_for_connection(
        request, _Connection(_HANDLE), store=store, workspace_commitment=workspace, state=state
    )
    assert bound.client_attestation is not None


def test_a_claim_bound_connection_without_a_handle_sends_nothing(tmp_path: Path) -> None:
    """ADR-051: the binding decides; a claim the server could not key never carries the path."""

    from finishup.client.observation_attestation import connection_claim_bound
    from finishup.ports.control import ControlError

    store, workspace, state, path = _store(tmp_path)
    request = _request(store, workspace, path)
    assert request.content_chunks[0].content == path.encode()  # the row holds the path
    locked = _Connection(None, "client_claim")
    assert connection_claim_bound(locked)
    assert not connection_claim_bound(_Connection(None, "local_path"))
    assert not connection_claim_bound(_Connection(None, "none"))
    with pytest.raises(ControlError) as raised:
        attest_for_connection(
            request, locked, store=store, workspace_commitment=workspace, state=state
        )
    assert (raised.value.reason, raised.value.retryable) == ("vault_locked", True)
    # A local binding still sends the row exactly as written.
    assert (
        attest_for_connection(
            request,
            _Connection(None, "local_path"),
            store=store,
            workspace_commitment=workspace,
            state=state,
        )
        is request
    )


def test_an_invalid_handle_is_refused(tmp_path: Path) -> None:
    store, workspace, state, path = _store(tmp_path)
    request = _request(store, workspace, path)
    with pytest.raises(ValueError, match="workspace_handle_invalid"):
        attest_ingest_request(
            request, handle="/home/dev", store=store, workspace_commitment=workspace, state=state
        )
