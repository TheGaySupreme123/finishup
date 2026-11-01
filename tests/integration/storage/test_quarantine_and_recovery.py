from __future__ import annotations

from collections.abc import Callable, Generator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

import pytest

import finishup.adapters.sqlite.recovery as recovery_module
from finishup.adapters.sqlite.recovery import (
    RecoveryKeyState,
    RecoveryMarkerState,
    RecoveryObjectState,
    RecoveryOutcome,
    RecoveryProjectionState,
    RecoveryReason,
    RecoveryState,
    RecoveryTailState,
    acquire_bundle_ownership,
    recover_bundle,
    validate_recovery_tail,
)
from finishup.domain.values import Frontier
from finishup.ports.maintenance import BackupManifest
from finishup.ports.runtime import OwnershipFence

_DIGEST = "sha256:" + "0" * 64
_TASK_ID = "tsk_00000000-0000-4000-8000-000000000001"
_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000001"
_NOW = datetime(2026, 7, 19, tzinfo=UTC)


class _FakeRecoveryPersistence:
    quarantines: list[RecoveryReason]
    verification_count: int
    _live_generation: int | None
    _live_nonce: str | None

    def __init__(self) -> None:
        self.quarantines = []
        self.verification_count = 0
        self._live_generation = None
        self._live_nonce = None

    def inspect(
        self,
        bundle_root: Path,
        *,
        catalog_path: Path,
        task_id: str,
        route_generation: int,
        route_identity_digest: str,
    ) -> RecoveryState:
        return _state(
            bundle_root=bundle_root,
            catalog_path=catalog_path,
            task_id=task_id,
            route_generation=route_generation,
            route_identity_digest=route_identity_digest,
        )

    def acquire_ownership(
        self,
        state: RecoveryState,
        *,
        service_instance_id: str,
        service_generation: int,
        owner_nonce: str,
        now: datetime,
    ) -> int:
        del service_instance_id, service_generation, now
        # Model the production CAS: a second acquire with a stale inspected snapshot conflicts
        # and mutates nothing, rather than always returning state.owner_generation + 1.
        if self._live_generation is not None and (
            state.owner_generation != self._live_generation or state.owner_nonce != self._live_nonce
        ):
            raise ValueError("recovery_ownership_conflict")
        next_generation = state.owner_generation + 1
        self._live_generation = next_generation
        self._live_nonce = owner_nonce
        return next_generation

    def verify_fence(self, state: RecoveryState, fence: OwnershipFence) -> None:
        # Match production CAS semantics: fence must equal the live generation+nonce
        # written by acquire, not merely exceed the pre-acquire inspect snapshot.
        del state
        if (
            self._live_generation is None
            or fence.owner_generation != self._live_generation
            or fence.nonce != self._live_nonce
        ):
            raise ValueError("recovery_fence_invalid")
        self.verification_count += 1

    def complete_interrupted(
        self, state: RecoveryState, fence: OwnershipFence, *, now: datetime
    ) -> RecoveryState:
        del fence, now
        return replace(state, tail_state=RecoveryTailState.CLEAN)

    def rebuild_projection(
        self, state: RecoveryState, fence: OwnershipFence, *, now: datetime
    ) -> RecoveryState:
        del fence, now
        return replace(state, projection_state=RecoveryProjectionState.CURRENT)

    def persist_quarantine(
        self,
        state: RecoveryState,
        reason: RecoveryReason,
        fence: OwnershipFence,
        *,
        now: datetime,
    ) -> None:
        del state, fence, now
        self.quarantines.append(reason)

    def activate_restore(
        self,
        state: RecoveryState,
        manifest: BackupManifest,
        fence: OwnershipFence,
        *,
        now: datetime,
    ) -> Literal["activated", "provenance_invalid", "route_contradiction"]:
        del state, manifest, fence, now
        return "activated"


def _state(
    *,
    bundle_root: Path = Path("/private/bundle"),
    catalog_path: Path = Path("/private/catalog.sqlite3"),
    task_id: str = _TASK_ID,
    route_generation: int = 1,
    route_identity_digest: str = _DIGEST,
    tail_state: RecoveryTailState = RecoveryTailState.CLEAN,
    object_state: RecoveryObjectState = RecoveryObjectState.VERIFIED,
    key_state: RecoveryKeyState = RecoveryKeyState.READY,
    marker_state: RecoveryMarkerState = RecoveryMarkerState.ABSENT,
    projection_state: RecoveryProjectionState = RecoveryProjectionState.CURRENT,
    storage_schema_version: int = 1,
) -> RecoveryState:
    return RecoveryState(
        bundle_root=bundle_root,
        catalog_path=catalog_path,
        task_id=task_id,
        route_generation=route_generation,
        route_identity_digest=route_identity_digest,
        storage_schema_version=storage_schema_version,
        owner_generation=3,
        owner_nonce="prior-owner-nonce-00001",
        last_verified_frontier=Frontier.genesis(),
        tail_state=tail_state,
        object_state=object_state,
        key_state=key_state,
        marker_state=marker_state,
        projection_state=projection_state,
        privacy_root_generation=0,
        privacy_root_digest=_DIGEST,
    )


def _install(backend: _FakeRecoveryPersistence | None) -> None:
    installer = cast(
        Callable[[object | None], None],
        getattr(recovery_module, "_install_recovery_persistence"),
    )
    installer(backend)


def _fence(state: RecoveryState) -> OwnershipFence:
    return acquire_bundle_ownership(
        state,
        validate_recovery_tail(state),
        service_instance_id=_SERVICE_ID,
        service_generation=9,
        owner_nonce="current-owner-nonce-0001",
        now=_NOW,
    )


@pytest.fixture(autouse=True)
def _reset_backend() -> Generator[None]:  # pyright: ignore[reportUnusedFunction]
    _install(None)
    yield
    _install(None)


def test_quarantine_records_the_failed_route() -> None:
    backend = _FakeRecoveryPersistence()
    _install(backend)
    state = _state(object_state=RecoveryObjectState.AUTHENTICATION_FAILED)
    verdict = validate_recovery_tail(state)

    result = recover_bundle(state, verdict, _fence(state), now=_NOW)

    assert result.outcome is RecoveryOutcome.QUARANTINED
    assert result.reason is RecoveryReason.OBJECT_AUTHENTICATION_FAILED
    assert result.fence is None
    assert backend.quarantines == [RecoveryReason.OBJECT_AUTHENTICATION_FAILED]


def test_recovery_state_classification_is_bounded_and_stable() -> None:
    state = _state(tail_state=RecoveryTailState.CORRUPT_AMBIGUOUS)

    first = validate_recovery_tail(state)
    second = validate_recovery_tail(state)

    assert first == second
    assert first.reason is RecoveryReason.LEDGER_TAIL_AMBIGUOUS
    assert first.ownership_admissible
    assert repr(state) == "RecoveryState(<redacted>)"


def test_corrupt_object_envelope_is_classified_before_route_switch() -> None:
    state = _state(object_state=RecoveryObjectState.AUTHENTICATION_FAILED)

    verdict = validate_recovery_tail(state)

    assert verdict.reason is RecoveryReason.OBJECT_AUTHENTICATION_FAILED
    assert verdict.ownership_admissible


def test_projection_rebuild_must_verify_before_writable() -> None:
    backend = _FakeRecoveryPersistence()
    _install(backend)
    state = _state(projection_state=RecoveryProjectionState.REBUILD_REQUIRED)

    result = recover_bundle(state, validate_recovery_tail(state), _fence(state), now=_NOW)

    assert result.outcome is RecoveryOutcome.WRITABLE
    assert result.reason is RecoveryReason.PROJECTION_REBUILD
    assert result.projection_rebuilt
    assert backend.verification_count == 2


@pytest.mark.parametrize(
    ("key_state", "reason"),
    (
        (RecoveryKeyState.LOCKED, RecoveryReason.KEY_LOCKED),
        (RecoveryKeyState.MISSING, RecoveryReason.KEY_MISSING),
        (RecoveryKeyState.BACKEND_UNAVAILABLE, RecoveryReason.KEY_BACKEND_UNAVAILABLE),
    ),
)
def test_key_failure_never_becomes_empty_writable_bundle(
    key_state: RecoveryKeyState, reason: RecoveryReason
) -> None:
    backend = _FakeRecoveryPersistence()
    _install(backend)
    state = _state(key_state=key_state)

    result = recover_bundle(state, validate_recovery_tail(state), _fence(state), now=_NOW)

    assert result.outcome is RecoveryOutcome.READ_ONLY
    assert result.reason is reason
    assert result.fence is None


def test_unsupported_schema_never_opens_writer() -> None:
    backend = _FakeRecoveryPersistence()
    _install(backend)
    state = _state(storage_schema_version=2)

    result = recover_bundle(state, validate_recovery_tail(state), _fence(state), now=_NOW)

    assert result.outcome is RecoveryOutcome.MANUAL_INTERVENTION
    assert result.reason is RecoveryReason.SCHEMA_UNSUPPORTED
