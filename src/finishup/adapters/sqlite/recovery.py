"""Fail-closed bundle recovery classification and fenced recovery orchestration."""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Literal, Protocol, cast

import finishup.adapters.sqlite.connection as connection_module
from finishup.domain.values import (
    Frontier,
    format_rfc3339_millis,
    task_id,
    validate_sha256_digest,
)
from finishup.ports.maintenance import BackupManifest
from finishup.ports.runtime import OwnershipFence

__all__ = [
    "RecoveryKeyState",
    "RecoveryMarkerState",
    "RecoveryObjectState",
    "RecoveryOutcome",
    "RecoveryProjectionState",
    "RecoveryReason",
    "RecoveryResult",
    "RecoveryState",
    "RecoveryTailState",
    "RecoveryTailVerdict",
    "acquire_bundle_ownership",
    "inspect_recovery_state",
    "quarantine_bundle",
    "recover_bundle",
    "restore_bundle",
    "validate_recovery_tail",
]

_MAX_SQLITE_SIGNED_INTEGER = 2**63 - 1
_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$", re.ASCII)
_QUARANTINE_REASONS = frozenset(
    {
        "ledger_tail_corrupt",
        "ledger_tail_ambiguous",
        "object_missing",
        "object_authentication_failed",
        "recovery_marker_malformed",
        "restore_provenance_invalid",
    }
)


class RecoveryTailState(str, Enum):  # noqa: UP042 - exact durable value enum
    CLEAN = "clean"
    INTERRUPTED_RECOVERABLE = "interrupted_recoverable"
    CORRUPT_AMBIGUOUS = "corrupt_ambiguous"
    GENERATION_CONFLICT = "generation_conflict"


class RecoveryObjectState(str, Enum):  # noqa: UP042 - exact durable value enum
    VERIFIED = "verified"
    MISSING = "missing"
    AUTHENTICATION_FAILED = "authentication_failed"


class RecoveryKeyState(str, Enum):  # noqa: UP042 - exact durable value enum
    READY = "ready"
    LOCKED = "locked"
    MISSING = "missing"
    BACKEND_UNAVAILABLE = "backend_unavailable"


class RecoveryMarkerState(str, Enum):  # noqa: UP042 - exact durable value enum
    ABSENT = "absent"
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    MALFORMED = "malformed"


class RecoveryProjectionState(str, Enum):  # noqa: UP042 - exact durable value enum
    CURRENT = "current"
    REBUILD_REQUIRED = "rebuild_required"
    UNREADABLE = "unreadable"


class RecoveryOutcome(str, Enum):  # noqa: UP042 - exact durable value enum
    WRITABLE = "writable"
    READ_ONLY = "read_only"
    QUARANTINED = "quarantined"
    RESTORE_REQUIRED = "restore_required"
    MANUAL_INTERVENTION = "manual_intervention"


class RecoveryReason(str, Enum):  # noqa: UP042 - exact durable value enum
    CLEAN = "clean"
    INTERRUPTED_WRITE = "interrupted_write"
    PROJECTION_REBUILD = "projection_rebuild"
    KEY_LOCKED = "key_locked"
    KEY_MISSING = "key_missing"
    KEY_BACKEND_UNAVAILABLE = "key_backend_unavailable"
    SCHEMA_UNSUPPORTED = "schema_unsupported"
    LEDGER_TAIL_CORRUPT = "ledger_tail_corrupt"
    LEDGER_TAIL_AMBIGUOUS = "ledger_tail_ambiguous"
    GENERATION_CONFLICT = "generation_conflict"
    OBJECT_MISSING = "object_missing"
    OBJECT_AUTHENTICATION_FAILED = "object_authentication_failed"
    PRIVACY_ROOT_INVALID = "privacy_root_invalid"
    RECOVERY_MARKER_MALFORMED = "recovery_marker_malformed"
    RESTORE_PROVENANCE_INVALID = "restore_provenance_invalid"
    CATALOG_ROUTE_CONTRADICTION = "catalog_route_contradiction"


class _RecoveryUnavailableError(Exception):
    """A bounded fail-closed signal while concrete recovery persistence is unavailable."""

    def __init__(self) -> None:
        super().__init__("recovery_persistence_unavailable")


def _nonnegative(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SQLITE_SIGNED_INTEGER:
        raise ValueError("recovery_value_invalid")
    return value


def _positive(value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_SQLITE_SIGNED_INTEGER:
        raise ValueError("recovery_value_invalid")
    return value


def _nonce(value: object) -> str:
    if type(value) is not str or _NONCE_PATTERN.fullmatch(value) is None:
        raise ValueError("recovery_value_invalid")
    return value


def _digest(value: object) -> str:
    if type(value) is not str:
        raise ValueError("recovery_value_invalid")
    try:
        return validate_sha256_digest(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("recovery_value_invalid") from exc


@dataclass(frozen=True, slots=True, repr=False)
class RecoveryState:
    bundle_root: Path
    catalog_path: Path
    task_id: str
    route_generation: int
    route_identity_digest: str
    storage_schema_version: int
    owner_generation: int
    owner_nonce: str
    last_verified_frontier: Frontier
    tail_state: RecoveryTailState
    object_state: RecoveryObjectState
    key_state: RecoveryKeyState
    marker_state: RecoveryMarkerState
    projection_state: RecoveryProjectionState
    privacy_root_generation: int
    privacy_root_digest: str

    def __post_init__(self) -> None:
        if not self.bundle_root.is_absolute() or not self.catalog_path.is_absolute():
            raise ValueError("recovery_value_invalid")
        object.__setattr__(self, "task_id", str(task_id(self.task_id)))
        _positive(self.route_generation)
        _digest(self.route_identity_digest)
        _nonnegative(self.storage_schema_version)
        _nonnegative(self.owner_generation)
        _nonce(self.owner_nonce)
        if type(self.last_verified_frontier) is not Frontier:
            raise ValueError("recovery_value_invalid")
        if type(self.tail_state) is not RecoveryTailState:
            raise ValueError("recovery_value_invalid")
        if type(self.object_state) is not RecoveryObjectState:
            raise ValueError("recovery_value_invalid")
        if type(self.key_state) is not RecoveryKeyState:
            raise ValueError("recovery_value_invalid")
        if type(self.marker_state) is not RecoveryMarkerState:
            raise ValueError("recovery_value_invalid")
        if type(self.projection_state) is not RecoveryProjectionState:
            raise ValueError("recovery_value_invalid")
        _nonnegative(self.privacy_root_generation)
        _digest(self.privacy_root_digest)

    def __repr__(self) -> str:
        return "RecoveryState(<redacted>)"


@dataclass(frozen=True, slots=True)
class RecoveryTailVerdict:
    state: RecoveryTailState
    frontier: Frontier
    reason: RecoveryReason
    ownership_admissible: bool

    def __post_init__(self) -> None:
        if (
            type(self.state) is not RecoveryTailState
            or type(self.frontier) is not Frontier
            or type(self.reason) is not RecoveryReason
            or type(self.ownership_admissible) is not bool
        ):
            raise ValueError("recovery_value_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class RecoveryResult:
    outcome: RecoveryOutcome
    task_id: str
    frontier: Frontier
    reason: RecoveryReason
    fence: OwnershipFence | None
    projection_rebuilt: bool
    privacy_audit_degraded: bool

    def __post_init__(self) -> None:
        if type(self.outcome) is not RecoveryOutcome:
            raise ValueError("recovery_value_invalid")
        object.__setattr__(self, "task_id", str(task_id(self.task_id)))
        if type(self.frontier) is not Frontier or type(self.reason) is not RecoveryReason:
            raise ValueError("recovery_value_invalid")
        if self.fence is not None and type(self.fence) is not OwnershipFence:
            raise ValueError("recovery_value_invalid")
        if (self.outcome is RecoveryOutcome.WRITABLE) != (self.fence is not None):
            raise ValueError("recovery_value_invalid")
        if (
            type(self.projection_rebuilt) is not bool
            or type(self.privacy_audit_degraded) is not bool
        ):
            raise ValueError("recovery_value_invalid")
        if self.outcome is not RecoveryOutcome.WRITABLE and (
            self.projection_rebuilt or self.privacy_audit_degraded
        ):
            raise ValueError("recovery_value_invalid")

    def __repr__(self) -> str:
        return "RecoveryResult(<redacted>)"


class _RecoveryPersistence(Protocol):
    """Concrete evidence/mutation seam owned by repository/object/privacy adapters."""

    def inspect(
        self,
        bundle_root: Path,
        *,
        catalog_path: Path,
        task_id: str,
        route_generation: int,
        route_identity_digest: str,
    ) -> RecoveryState: ...

    def acquire_ownership(
        self,
        state: RecoveryState,
        *,
        service_instance_id: str,
        service_generation: int,
        owner_nonce: str,
        now: datetime,
    ) -> int: ...

    def verify_fence(self, state: RecoveryState, fence: OwnershipFence) -> None: ...

    def complete_interrupted(
        self, state: RecoveryState, fence: OwnershipFence, *, now: datetime
    ) -> RecoveryState: ...

    def rebuild_projection(
        self, state: RecoveryState, fence: OwnershipFence, *, now: datetime
    ) -> RecoveryState: ...

    def persist_quarantine(
        self,
        state: RecoveryState,
        reason: RecoveryReason,
        fence: OwnershipFence,
        *,
        now: datetime,
    ) -> None: ...

    def activate_restore(
        self,
        state: RecoveryState,
        manifest: BackupManifest,
        fence: OwnershipFence,
        *,
        now: datetime,
    ) -> Literal["activated", "provenance_invalid", "route_contradiction"]: ...


_persistence: _RecoveryPersistence | None = None
_persistence_lock = threading.Lock()


def _install_recovery_persistence(  # pyright: ignore[reportUnusedFunction]
    persistence: _RecoveryPersistence | None,
) -> None:
    """Install the composed evidence backend; focused tests use the same explicit seam."""

    global _persistence
    with _persistence_lock:
        _persistence = persistence


def _backend() -> _RecoveryPersistence:
    with _persistence_lock:
        persistence = _persistence
    if persistence is None:
        raise _RecoveryUnavailableError()
    return persistence


def _register_fence(path: Path, fence: OwnershipFence) -> None:
    registrar = cast(
        Callable[[Path, OwnershipFence], None],
        getattr(connection_module, "_register_active_fence"),
    )
    registrar(path, fence)


def _clear_fence(path: Path, fence: OwnershipFence) -> None:
    clearer = cast(
        Callable[[Path, OwnershipFence | None], None],
        getattr(connection_module, "_clear_active_fence"),
    )
    clearer(path, fence)


def _same_recovery_identity(before: RecoveryState, after: RecoveryState) -> None:
    if (
        after.bundle_root != before.bundle_root
        or after.catalog_path != before.catalog_path
        or after.task_id != before.task_id
        or after.route_generation != before.route_generation
        or after.route_identity_digest != before.route_identity_digest
        or after.last_verified_frontier != before.last_verified_frontier
    ):
        raise ValueError("recovery_evidence_binding_mismatch")


def _validate_now(now: datetime) -> None:
    try:
        format_rfc3339_millis(now)
    except (TypeError, ValueError) as exc:
        raise ValueError("recovery_value_invalid") from exc


def inspect_recovery_state(
    bundle_root: Path,
    *,
    catalog_path: Path,
    task_id: str,
    route_generation: int,
    route_identity_digest: str,
) -> RecoveryState:
    """Inspect through the explicitly composed, read-only evidence backend."""

    validated_task_id = str(globals()["task_id"](task_id))
    _positive(route_generation)
    _digest(route_identity_digest)
    state = _backend().inspect(
        bundle_root,
        catalog_path=catalog_path,
        task_id=validated_task_id,
        route_generation=route_generation,
        route_identity_digest=route_identity_digest,
    )
    if type(state) is not RecoveryState:
        raise ValueError("recovery_value_invalid")
    if (
        state.bundle_root != bundle_root
        or state.catalog_path != catalog_path
        or state.task_id != validated_task_id
        or state.route_generation != route_generation
        or state.route_identity_digest != route_identity_digest
    ):
        raise ValueError("recovery_evidence_binding_mismatch")
    return state


def validate_recovery_tail(state: RecoveryState) -> RecoveryTailVerdict:
    """Classify the already verified structural tail without mutating it."""

    if type(state) is not RecoveryState:
        raise ValueError("recovery_value_invalid")
    if state.tail_state is RecoveryTailState.GENERATION_CONFLICT:
        reason = RecoveryReason.GENERATION_CONFLICT
        admissible = False
    elif state.tail_state is RecoveryTailState.CORRUPT_AMBIGUOUS:
        reason = RecoveryReason.LEDGER_TAIL_AMBIGUOUS
        admissible = True
    elif state.marker_state is RecoveryMarkerState.MALFORMED:
        reason = RecoveryReason.RECOVERY_MARKER_MALFORMED
        admissible = True
    elif state.object_state is RecoveryObjectState.MISSING:
        reason = RecoveryReason.OBJECT_MISSING
        admissible = True
    elif state.object_state is RecoveryObjectState.AUTHENTICATION_FAILED:
        reason = RecoveryReason.OBJECT_AUTHENTICATION_FAILED
        admissible = True
    elif state.tail_state is RecoveryTailState.INTERRUPTED_RECOVERABLE:
        reason = RecoveryReason.INTERRUPTED_WRITE
        admissible = True
    elif state.projection_state is not RecoveryProjectionState.CURRENT:
        reason = RecoveryReason.PROJECTION_REBUILD
        admissible = True
    else:
        reason = RecoveryReason.CLEAN
        admissible = True
    return RecoveryTailVerdict(
        state=state.tail_state,
        frontier=state.last_verified_frontier,
        reason=reason,
        ownership_admissible=admissible,
    )


def acquire_bundle_ownership(
    state: RecoveryState,
    verdict: RecoveryTailVerdict,
    *,
    service_instance_id: str,
    service_generation: int,
    owner_nonce: str,
    now: datetime,
) -> OwnershipFence:
    """Perform the route-bound bundle CAS, then register exactly its returned fence."""

    if type(state) is not RecoveryState or type(verdict) is not RecoveryTailVerdict:
        raise ValueError("recovery_value_invalid")
    if verdict.state is not state.tail_state or verdict.frontier != state.last_verified_frontier:
        raise ValueError("recovery_evidence_binding_mismatch")
    if not verdict.ownership_admissible:
        raise ValueError("recovery_ownership_inadmissible")
    _positive(service_generation)
    _nonce(owner_nonce)
    _validate_now(now)
    owner_generation = _backend().acquire_ownership(
        state,
        service_instance_id=service_instance_id,
        service_generation=service_generation,
        owner_nonce=owner_nonce,
        now=now,
    )
    _positive(owner_generation)
    if owner_generation <= state.owner_generation:
        raise ValueError("recovery_generation_not_advanced")
    fence = OwnershipFence(
        service_instance_id=service_instance_id,
        service_generation=service_generation,
        owner_generation=owner_generation,
        nonce=owner_nonce,
    )
    _register_fence(state.bundle_root / "ledger.sqlite3", fence)
    return fence


def _result(
    state: RecoveryState,
    *,
    outcome: RecoveryOutcome,
    reason: RecoveryReason,
    fence: OwnershipFence | None = None,
    projection_rebuilt: bool = False,
    privacy_audit_degraded: bool = False,
) -> RecoveryResult:
    return RecoveryResult(
        outcome=outcome,
        task_id=state.task_id,
        frontier=state.last_verified_frontier,
        reason=reason,
        fence=fence,
        projection_rebuilt=projection_rebuilt,
        privacy_audit_degraded=privacy_audit_degraded,
    )


def recover_bundle(
    state: RecoveryState,
    verdict: RecoveryTailVerdict,
    fence: OwnershipFence,
    *,
    now: datetime,
) -> RecoveryResult:
    """Apply the frozen effect table after revalidating the current fence."""

    if (
        type(state) is not RecoveryState
        or type(verdict) is not RecoveryTailVerdict
        or type(fence) is not OwnershipFence
    ):
        raise ValueError("recovery_value_invalid")
    _validate_now(now)
    backend = _backend()
    backend.verify_fence(state, fence)
    if verdict != validate_recovery_tail(state):
        raise ValueError("recovery_evidence_binding_mismatch")

    if state.storage_schema_version > 1:
        _clear_fence(state.bundle_root / "ledger.sqlite3", fence)
        return _result(
            state,
            outcome=RecoveryOutcome.MANUAL_INTERVENTION,
            reason=RecoveryReason.SCHEMA_UNSUPPORTED,
        )
    if verdict.reason is RecoveryReason.GENERATION_CONFLICT:
        _clear_fence(state.bundle_root / "ledger.sqlite3", fence)
        return _result(
            state,
            outcome=RecoveryOutcome.MANUAL_INTERVENTION,
            reason=RecoveryReason.GENERATION_CONFLICT,
        )
    if verdict.reason in {
        RecoveryReason.LEDGER_TAIL_CORRUPT,
        RecoveryReason.LEDGER_TAIL_AMBIGUOUS,
        RecoveryReason.OBJECT_MISSING,
        RecoveryReason.OBJECT_AUTHENTICATION_FAILED,
        RecoveryReason.RECOVERY_MARKER_MALFORMED,
    }:
        return quarantine_bundle(state, verdict.reason, fence, now=now)
    if state.key_state is not RecoveryKeyState.READY:
        key_reason = {
            RecoveryKeyState.LOCKED: RecoveryReason.KEY_LOCKED,
            RecoveryKeyState.MISSING: RecoveryReason.KEY_MISSING,
            RecoveryKeyState.BACKEND_UNAVAILABLE: RecoveryReason.KEY_BACKEND_UNAVAILABLE,
        }[state.key_state]
        _clear_fence(state.bundle_root / "ledger.sqlite3", fence)
        return _result(state, outcome=RecoveryOutcome.READ_ONLY, reason=key_reason)

    working_state = state
    if state.tail_state is RecoveryTailState.INTERRUPTED_RECOVERABLE:
        working_state = backend.complete_interrupted(state, fence, now=now)
        _same_recovery_identity(state, working_state)
        working_verdict = validate_recovery_tail(working_state)
        if working_verdict.state is not RecoveryTailState.CLEAN:
            raise ValueError("recovery_interruption_not_resolved")
    projection_rebuilt = False
    if working_state.projection_state is not RecoveryProjectionState.CURRENT:
        rebuilt_state = backend.rebuild_projection(working_state, fence, now=now)
        _same_recovery_identity(working_state, rebuilt_state)
        working_state = rebuilt_state
        if rebuilt_state.projection_state is not RecoveryProjectionState.CURRENT:
            raise ValueError("recovery_projection_not_rebuilt")
        projection_rebuilt = True
    backend.verify_fence(working_state, fence)
    return _result(
        working_state,
        outcome=RecoveryOutcome.WRITABLE,
        reason=(RecoveryReason.PROJECTION_REBUILD if projection_rebuilt else RecoveryReason.CLEAN),
        fence=fence,
        projection_rebuilt=projection_rebuilt,
    )


def quarantine_bundle(
    state: RecoveryState,
    reason: RecoveryReason,
    fence: OwnershipFence,
    *,
    now: datetime,
) -> RecoveryResult:
    """Persist the smallest fenced structural quarantine envelope before reporting it."""

    if (
        type(state) is not RecoveryState
        or type(reason) is not RecoveryReason
        or reason.value not in _QUARANTINE_REASONS
        or type(fence) is not OwnershipFence
    ):
        raise ValueError("recovery_quarantine_reason_invalid")
    _validate_now(now)
    backend = _backend()
    backend.verify_fence(state, fence)
    backend.persist_quarantine(state, reason, fence, now=now)
    _clear_fence(state.bundle_root / "ledger.sqlite3", fence)
    return _result(state, outcome=RecoveryOutcome.QUARANTINED, reason=reason)


def restore_bundle(
    state: RecoveryState,
    manifest: BackupManifest,
    fence: OwnershipFence,
    *,
    now: datetime,
) -> RecoveryResult:
    """Activate only a backend-verified staged target through the catalog route CAS."""

    if (
        type(state) is not RecoveryState
        or type(manifest) is not BackupManifest
        or type(fence) is not OwnershipFence
    ):
        raise ValueError("recovery_value_invalid")
    _validate_now(now)
    backend = _backend()
    backend.verify_fence(state, fence)
    outcome = backend.activate_restore(state, manifest, fence, now=now)
    if outcome == "activated":
        if manifest.task_id != state.task_id:
            raise ValueError("recovery_evidence_binding_mismatch")
        activated_state = replace(state, last_verified_frontier=manifest.frontier)
        return _result(
            activated_state,
            outcome=RecoveryOutcome.WRITABLE,
            reason=RecoveryReason.CLEAN,
            fence=fence,
        )
    if outcome == "route_contradiction":
        _clear_fence(state.bundle_root / "ledger.sqlite3", fence)
        return _result(
            state,
            outcome=RecoveryOutcome.MANUAL_INTERVENTION,
            reason=RecoveryReason.CATALOG_ROUTE_CONTRADICTION,
        )
    if outcome == "provenance_invalid":
        return quarantine_bundle(
            state,
            RecoveryReason.RESTORE_PROVENANCE_INVALID,
            fence,
            now=now,
        )
    raise ValueError("recovery_backend_outcome_invalid")
