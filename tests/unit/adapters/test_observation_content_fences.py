"""Durable owner-local fences for native captured-content authority."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finishup.adapters.integrations.observation_local import (
    LocalConsentTransition,
    LocalObservationStore,
)
from finishup.domain.observation import ObservationControlCommand, ObservationRevokeCommand
from finishup.domain.observation_budget import LARGEST_CAPACITY
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.domain.observation_settings import ObservationDetailProfile, ObservationSelection
from finishup.domain.values import Timestamp
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

_PROFILE = CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
_CURSOR = CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
_STAMP = Timestamp("2026-01-01T00:00:00.000Z")


def _consented(tmp_path: Path) -> tuple[LocalObservationStore, str]:
    state = tmp_path / "isolated-state"
    state.mkdir(mode=0o700)
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.set_runtime_enabled(True)
    store.grant_consent(workspace, _STAMP, content_capture_profiles=(_PROFILE,))
    return store, workspace


def _pending_revocation_token(store: LocalObservationStore, workspace: str) -> str:
    pending = store.pending_consent_revocation(workspace)
    assert pending is not None
    return pending[0]


def _generation(store: LocalObservationStore, workspace: str) -> str:
    authority = store.content_capture_authority(workspace)
    assert authority is not None
    assert authority.active
    assert authority.runtime_enabled
    return authority.generation


def test_real_authority_transitions_fence_aba_and_noop_repeats(tmp_path: Path) -> None:
    store, workspace = _consented(tmp_path)
    command = ObservationControlCommand(workspace)
    initial = _generation(store, workspace)

    # Repeating an already-effective operation leaves an in-flight fence valid.
    store.grant_consent(workspace, _STAMP, content_capture_profiles=(_PROFILE,))
    store.enable_content_capture(workspace, _PROFILE)
    store.set_runtime_enabled(True)
    assert _generation(store, workspace) == initial
    assert store.content_capture_authority_is_current(workspace, initial, (_PROFILE,))

    # Each real transition gets a different durable epoch, even when the
    # visible fields later return to their original values.
    store.pause(command)
    paused = store.content_capture_authority(workspace)
    assert paused is not None and paused.generation != initial
    assert not store.content_capture_authority_is_current(workspace, initial, (_PROFILE,))

    store.resume(command)
    resumed = _generation(store, workspace)
    assert resumed != initial
    assert store.content_capture_authority_is_current(workspace, resumed, (_PROFILE,))

    store.disable_content_capture(workspace, _PROFILE)
    disabled = store.content_capture_authority(workspace)
    assert disabled is not None and disabled.generation != resumed
    store.enable_content_capture(workspace, _PROFILE)
    reenabled = _generation(store, workspace)
    assert reenabled not in {initial, resumed}
    assert not store.content_capture_authority_is_current(workspace, resumed, (_PROFILE,))

    store.set_runtime_enabled(False)
    off = store.content_capture_authority(workspace)
    assert off is not None and not off.runtime_enabled and off.generation != reenabled
    store.set_runtime_enabled(True)
    online = _generation(store, workspace)
    assert online not in {initial, resumed, reenabled}
    assert not store.content_capture_authority_is_current(workspace, reenabled, (_PROFILE,))

    # A repeated READY-style write does not create another epoch.
    store.set_runtime_enabled(True)
    assert _generation(store, workspace) == online

    store.revoke(ObservationRevokeCommand(workspace))
    revoked = store.content_capture_authority(workspace)
    assert revoked is not None and revoked.generation != online


def test_content_fence_epoch_migrates_legacy_state_and_survives_reopen(tmp_path: Path) -> None:
    store, workspace = _consented(tmp_path)
    store.set_runtime_enabled(False)
    store.set_runtime_enabled(True)
    before = _generation(store, workspace)
    state_path = next((tmp_path / "isolated-state" / "observation" / "workspaces").glob("*.json"))

    # A /12 state has no content epoch.  Loading it must mint and persist a
    # fresh nonce instead of deriving a reusable token from consent fields.
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    raw["schema"] = "yoetz.observation-local/12"
    raw.pop("content_capture_epoch", None)
    state_path.write_text(json.dumps(raw), encoding="utf-8")

    migrated = LocalObservationStore(_state=tmp_path / "isolated-state")
    after = _generation(migrated, workspace)
    assert after != before
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["schema"] == "yoetz.observation-local/15"
    assert isinstance(persisted["content_capture_epoch"], str)
    assert not migrated.content_capture_authority_is_current(workspace, before, (_PROFILE,))

    reopened = LocalObservationStore(_state=tmp_path / "isolated-state")
    assert _generation(reopened, workspace) == after
    assert reopened.content_capture_authority_is_current(workspace, after, (_PROFILE,))


def test_structural_grant_keeps_live_content_arms_and_fence(tmp_path: Path) -> None:
    """Issue #835: a second host's routine setup must not reset the first host's arm."""

    store, workspace = _consented(tmp_path)
    store.enable_content_capture(workspace, _CURSOR)
    store.set_workspace_selection(
        workspace,
        ObservationSelection(
            detail=ObservationDetailProfile.DETAILED,
            capacity=LARGEST_CAPACITY,
        ),
        set_at=_STAMP,
    )
    before = store.content_capture_authority(workspace)
    assert before is not None and before.profiles == (_PROFILE, _CURSOR)
    settings = store.selection_settings_for(workspace, now=_STAMP)

    # The structural path names neither a stamp nor a profile set.
    grant = store.grant_consent(workspace)
    repeated = store.grant_consent(workspace)

    assert grant.transition is LocalConsentTransition.UNCHANGED
    assert repeated.transition is LocalConsentTransition.UNCHANGED
    assert grant.consent.granted_at == _STAMP
    assert grant.consent.content_capture_profiles == (_PROFILE, _CURSOR)
    reopened = LocalObservationStore(_state=tmp_path / "isolated-state")
    assert reopened.content_capture_profiles(workspace) == (_PROFILE, _CURSOR)
    assert _generation(reopened, workspace) == before.generation
    assert reopened.content_capture_authority_is_current(
        workspace, before.generation, (_PROFILE, _CURSOR)
    )
    assert reopened.selection_settings_for(workspace, now=_STAMP) == settings


def test_structural_grant_keeps_granted_at_even_when_a_stamp_is_named(tmp_path: Path) -> None:
    store, workspace = _consented(tmp_path)
    before = _generation(store, workspace)

    grant = store.grant_consent(workspace, Timestamp("2026-06-01T00:00:00.000Z"))

    assert grant.transition is LocalConsentTransition.UNCHANGED
    assert grant.consent.granted_at == _STAMP
    assert _generation(store, workspace) == before


def test_structural_grant_resumes_a_paused_consent_with_its_arms(tmp_path: Path) -> None:
    store, workspace = _consented(tmp_path)
    initial = _generation(store, workspace)
    store.pause(ObservationControlCommand(workspace))
    paused = store.content_capture_authority(workspace)
    assert paused is not None and not paused.active
    assert paused.profiles == (_PROFILE,)

    grant = store.grant_consent(workspace)

    # Resuming is a real transition: it advances the fence exactly like ``resume``.
    assert grant.transition is LocalConsentTransition.RESUMED
    assert grant.consent.granted_at == _STAMP
    assert grant.consent.content_capture_profiles == (_PROFILE,)
    resumed = _generation(store, workspace)
    assert resumed not in {initial, paused.generation}
    assert not store.content_capture_authority_is_current(workspace, initial, (_PROFILE,))


def test_revocation_still_fences_and_a_later_grant_infers_no_content_arm(
    tmp_path: Path,
) -> None:
    store, workspace = _consented(tmp_path)
    in_flight = _generation(store, workspace)

    store.revoke(ObservationRevokeCommand(workspace))
    assert not store.content_capture_authority_is_current(workspace, in_flight, (_PROFILE,))
    # Until the project fence completes, no grant can revive the revoked authority.
    with pytest.raises(PublicOperationError) as refused:
        store.grant_consent(workspace)
    assert refused.value.code is PublicErrorCode.SESSION_CONFLICT
    store.mark_consent_revocation_fenced(workspace, _pending_revocation_token(store, workspace))

    grant = store.grant_consent(workspace)

    assert grant.transition is LocalConsentTransition.GRANTED
    assert grant.consent.content_capture_profiles == ()
    assert grant.consent.granted_at != _STAMP
    fresh = _generation(store, workspace)
    assert fresh != in_flight
    assert store.content_capture_profiles(workspace) == ()
    assert not store.content_capture_authority_is_current(workspace, in_flight, (_PROFILE,))
    assert not store.content_capture_authority_is_current(workspace, in_flight, ())


def test_explicit_disable_and_explicit_profile_sets_remain_authoritative(
    tmp_path: Path,
) -> None:
    store, workspace = _consented(tmp_path)
    enabled = _generation(store, workspace)

    store.disable_content_capture(workspace, _PROFILE)
    disabled = _generation(store, workspace)
    assert disabled != enabled

    # A later routine grant neither restores the disabled arm nor re-fences.
    grant = store.grant_consent(workspace)
    assert grant.transition is LocalConsentTransition.UNCHANGED
    assert grant.consent.content_capture_profiles == ()
    assert _generation(store, workspace) == disabled

    # A caller that names a profile set still replaces the live arms exactly.
    store.enable_content_capture(workspace, _PROFILE)
    reenabled = _generation(store, workspace)
    replaced = store.grant_consent(workspace, content_capture_profiles=())
    assert replaced.transition is LocalConsentTransition.UPDATED
    assert replaced.consent.content_capture_profiles == ()
    assert replaced.consent.granted_at == _STAMP
    assert _generation(store, workspace) != reenabled
    assert not store.content_capture_authority_is_current(workspace, reenabled, (_PROFILE,))
