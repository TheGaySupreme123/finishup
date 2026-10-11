"""Maintenance preview, confirmation, and recovery-secret orchestration."""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from enum import Enum
from typing import Final, Literal, cast

from yoetz.domain.values import (
    Frontier,
    RequestId,
    SessionId,
    TaskId,
    format_rfc3339_millis,
    validate_sha256_digest,
)
from yoetz.ports.clock import ClockPort
from yoetz.ports.diagnostics import (
    MaintenanceDiagnostic,
    MaintenanceDiagnosticSink,
)
from yoetz.ports.maintenance import (
    BackupCommand,
    BackupMode,
    BackupPlan,
    BackupResult,
    MaintenanceError,
    MaintenanceKind,
    MaintenanceLocation,
    MaintenancePort,
    MaintenanceReason,
    MigrationCommand,
    MigrationPlan,
    MigrationResult,
    RecoveryOperation,
    RecoverySecret,
    RecoverySecretAcquirer,
    RecoverySecretAcquisition,
    RestoreCommand,
    RestorePlan,
    RestoreResult,
)
from yoetz.ports.secret_memory import SecretPurpose
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError

__all__ = [
    "BackupRequest",
    "Confirmation",
    "ConfirmationChannel",
    "MaintenanceService",
    "MigrationRequest",
    "RestoreRequest",
]

type DestinationPolicy = Literal["new_route_only"]

_MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991


class ConfirmationChannel(str, Enum):  # noqa: UP042 - exact shared vocabulary
    INTERACTIVE = "interactive"
    NONINTERACTIVE_FLAG = "noninteractive_flag"
    RELEASE_AUTOMATION = "release_automation"


@dataclass(frozen=True, slots=True)
class Confirmation:
    plan_digest: str
    explicitly_accepted: bool
    channel: ConfirmationChannel

    def __post_init__(self) -> None:
        validate_sha256_digest(self.plan_digest)
        if (
            type(self.explicitly_accepted) is not bool
            or type(self.channel) is not ConfirmationChannel
        ):
            raise ValueError("maintenance_confirmation_invalid")


@dataclass(frozen=True, slots=True, repr=False)
class BackupRequest:
    request_id: RequestId
    session_id: SessionId
    destination: MaintenanceLocation
    mode: BackupMode
    expected_frontier: Frontier

    def __post_init__(self) -> None:
        command = BackupCommand(
            self.request_id,
            self.session_id,
            self.destination,
            self.mode,
            self.expected_frontier,
        )
        object.__setattr__(self, "request_id", command.request_id)
        object.__setattr__(self, "session_id", command.session_id)

    def __repr__(self) -> str:
        return "<BackupRequest redacted>"

    __str__ = __repr__

    def to_command(self) -> BackupCommand:
        return BackupCommand(
            self.request_id,
            self.session_id,
            self.destination,
            self.mode,
            self.expected_frontier,
        )


@dataclass(frozen=True, slots=True, repr=False)
class RestoreRequest:
    request_id: RequestId
    source: MaintenanceLocation
    recovery_mode: BackupMode
    expected_task_id: TaskId | None
    expected_active_frontier: Frontier | None
    destination_policy: DestinationPolicy = "new_route_only"

    def __post_init__(self) -> None:
        command = RestoreCommand(
            self.request_id,
            self.source,
            self.destination_policy,
            self.recovery_mode,
            self.expected_task_id,
            self.expected_active_frontier,
        )
        object.__setattr__(self, "request_id", command.request_id)
        object.__setattr__(self, "expected_task_id", command.expected_task_id)

    def __repr__(self) -> str:
        return "<RestoreRequest redacted>"

    __str__ = __repr__

    def to_command(self) -> RestoreCommand:
        return RestoreCommand(
            self.request_id,
            self.source,
            self.destination_policy,
            self.recovery_mode,
            self.expected_task_id,
            self.expected_active_frontier,
        )


@dataclass(frozen=True, slots=True, repr=False)
class MigrationRequest:
    request_id: RequestId
    session_id: SessionId
    target_storage_version: str
    expected_frontier: Frontier

    def __post_init__(self) -> None:
        command = MigrationCommand(
            self.request_id,
            self.session_id,
            self.target_storage_version,
            self.expected_frontier,
        )
        object.__setattr__(self, "request_id", command.request_id)
        object.__setattr__(self, "session_id", command.session_id)
        object.__setattr__(self, "target_storage_version", command.target_storage_version)

    def __repr__(self) -> str:
        return "<MigrationRequest redacted>"

    __str__ = __repr__

    def to_command(self) -> MigrationCommand:
        return MigrationCommand(
            self.request_id,
            self.session_id,
            self.target_storage_version,
            self.expected_frontier,
        )


_ERROR_CODES: Final[dict[MaintenanceReason, PublicErrorCode]] = {
    MaintenanceReason.PLAN_STALE: PublicErrorCode.FRONTIER_CONFLICT,
    MaintenanceReason.CONFIRMATION_REQUIRED: PublicErrorCode.INVALID_REQUEST,
    MaintenanceReason.TARGET_EXISTS: PublicErrorCode.INVALID_REQUEST,
    MaintenanceReason.TARGET_UNSAFE: PublicErrorCode.STORAGE_UNSAFE,
    MaintenanceReason.SOURCE_INVALID: PublicErrorCode.INVALID_REQUEST,
    MaintenanceReason.MANIFEST_INVALID: PublicErrorCode.INVALID_REQUEST,
    MaintenanceReason.MANIFEST_TAMPERED: PublicErrorCode.STORAGE_CORRUPT,
    MaintenanceReason.BACKUP_INCOMPLETE: PublicErrorCode.STORAGE_CORRUPT,
    MaintenanceReason.KEY_UNAVAILABLE: PublicErrorCode.VAULT_LOCKED,
    MaintenanceReason.RECOVERY_SECRET_WRONG: PublicErrorCode.VAULT_LOCKED,
    MaintenanceReason.RECOVERY_ARTIFACT_INVALID: PublicErrorCode.STORAGE_CORRUPT,
    MaintenanceReason.OBJECT_MISSING: PublicErrorCode.STORAGE_CORRUPT,
    MaintenanceReason.OBJECT_TAMPERED: PublicErrorCode.STORAGE_CORRUPT,
    MaintenanceReason.DATABASE_INVALID: PublicErrorCode.STORAGE_CORRUPT,
    MaintenanceReason.REPLAY_MISMATCH: PublicErrorCode.STORAGE_CORRUPT,
    MaintenanceReason.CATALOG_ROUTE_CHANGED: PublicErrorCode.FRONTIER_CONFLICT,
    MaintenanceReason.MAINTENANCE_BUSY: PublicErrorCode.BUNDLE_BUSY,
    MaintenanceReason.MIGRATION_UNSUPPORTED: PublicErrorCode.MIGRATION_REQUIRED,
    MaintenanceReason.MIGRATION_FAILED: PublicErrorCode.STORAGE_CORRUPT,
    MaintenanceReason.ROLLBACK_REQUIRED: PublicErrorCode.STORAGE_CORRUPT,
    MaintenanceReason.GENERATION_LOST: PublicErrorCode.BUNDLE_BUSY,
}

_ERROR_MESSAGES: Final[dict[PublicErrorCode, str]] = {
    PublicErrorCode.INVALID_REQUEST: "The maintenance request is invalid.",
    PublicErrorCode.FRONTIER_CONFLICT: "The maintenance plan changed; preview and confirm again.",
    PublicErrorCode.BUNDLE_BUSY: "Maintenance is busy; retry the same request.",
    PublicErrorCode.STORAGE_UNSAFE: "The maintenance target is unsafe.",
    PublicErrorCode.STORAGE_CORRUPT: "Maintenance verification failed.",
    PublicErrorCode.MIGRATION_REQUIRED: "The requested storage migration is unsupported.",
    PublicErrorCode.VAULT_LOCKED: "The required recovery key is unavailable.",
}


def _public_error(error: MaintenanceError, kind: MaintenanceKind) -> PublicOperationError:
    code = _ERROR_CODES[error.reason]
    return PublicOperationError(
        code,
        _ERROR_MESSAGES[code],
        error.retryable,
        safe_details={"operation": kind},
    )


def _confirmation_required() -> PublicOperationError:
    return PublicOperationError(
        PublicErrorCode.INVALID_REQUEST,
        "Current maintenance plan confirmation is required.",
        False,
    )


def _plan_stale() -> PublicOperationError:
    return PublicOperationError(
        PublicErrorCode.FRONTIER_CONFLICT,
        "The maintenance plan changed; preview and confirm again.",
        True,
    )


def _service_unavailable() -> PublicOperationError:
    return PublicOperationError(
        PublicErrorCode.SERVICE_UNAVAILABLE,
        "The maintenance service is closed.",
        True,
    )


def _internal_error() -> PublicOperationError:
    return PublicOperationError(
        PublicErrorCode.INTERNAL_ERROR,
        "Maintenance could not verify its internal state and changed nothing; preview the plan "
        "again.",
        False,
        safe_details={"reason_code": "maintenance_state_unverified"},
    )


def _validated_recovery_secret(candidate: object) -> RecoverySecret:
    if isinstance(candidate, str | bytes | bytearray | memoryview):
        raise _internal_error()
    handle = cast(RecoverySecret, candidate)
    try:
        if handle.purpose is not SecretPurpose.PORTABLE_RECOVERY or not callable(handle.consume):
            raise _internal_error()
    except PublicOperationError:
        raise
    except Exception:
        raise _internal_error() from None
    return handle


class MaintenanceService:
    """Generation-bound support facade for backup, restore, and migration."""

    __slots__ = (
        "_clock",
        "_closed",
        "_diagnostics",
        "_maintenance",
        "_recovery_secrets",
        "_service_generation",
    )

    def __init__(
        self,
        maintenance: MaintenancePort,
        clock: ClockPort,
        diagnostics: MaintenanceDiagnosticSink,
        recovery_secrets: RecoverySecretAcquirer,
        service_generation: int,
    ) -> None:
        if type(service_generation) is not int or not 1 <= service_generation <= _MAX_SAFE_INTEGER:
            raise ValueError("service_generation_invalid")
        self._maintenance = maintenance
        self._clock = clock
        self._diagnostics = diagnostics
        self._recovery_secrets = recovery_secrets
        self._service_generation = service_generation
        self._closed = False

    async def preview_backup(self, request: BackupRequest) -> BackupPlan:
        self._require_open()
        if type(request) is not BackupRequest:
            raise _confirmation_required()
        return await self._preview_backup(request.to_command())

    async def backup(self, request: BackupRequest, confirmation: Confirmation) -> BackupResult:
        self._require_open()
        if type(request) is not BackupRequest or type(confirmation) is not Confirmation:
            raise _confirmation_required()
        self._require_acceptance(confirmation)
        command = request.to_command()
        plan = await self._preview_backup(command)
        self._require_plan(confirmation, plan.plan_digest)
        if plan.mode is not request.mode or plan.frontier != request.expected_frontier:
            raise _internal_error()
        started = self._start_sample()
        try:
            secret = await self._recovery_secret(
                request_id=command.request_id,
                plan_digest=plan.plan_digest,
                mode=plan.mode,
                operation=RecoveryOperation.CREATE,
            )
            result = await self._maintenance.backup(
                command,
                confirmed_plan_digest=plan.plan_digest,
                recovery_secret=secret,
            )
        except asyncio.CancelledError:
            self._record(
                kind=MaintenanceKind.BACKUP,
                phase="execute",
                request_id=str(command.request_id),
                started=started,
                plan_digest=plan.plan_digest,
                reason="cancelled",
            )
            raise
        except MaintenanceError as exc:
            self._record(
                kind=MaintenanceKind.BACKUP,
                phase="execute",
                request_id=str(command.request_id),
                started=started,
                plan_digest=plan.plan_digest,
                reason=exc.reason.value,
            )
            raise _public_error(exc, MaintenanceKind.BACKUP) from None
        except PublicOperationError as exc:
            self._record(
                kind=MaintenanceKind.BACKUP,
                phase="execute",
                request_id=str(command.request_id),
                started=started,
                plan_digest=plan.plan_digest,
                reason=exc.code.value.lower(),
            )
            raise
        self._record(
            kind=MaintenanceKind.BACKUP,
            phase="execute",
            request_id=command.request_id,
            started=started,
            task_id=str(result.task_id),
            plan_digest=plan.plan_digest,
            result_digest=result.backup_manifest_digest,
            count=result.object_count,
        )
        return result

    async def preview_restore(self, request: RestoreRequest) -> RestorePlan:
        self._require_open()
        if type(request) is not RestoreRequest:
            raise _confirmation_required()
        return await self._preview_restore(request.to_command())

    async def restore(self, request: RestoreRequest, confirmation: Confirmation) -> RestoreResult:
        self._require_open()
        if type(request) is not RestoreRequest or type(confirmation) is not Confirmation:
            raise _confirmation_required()
        self._require_acceptance(confirmation)
        command = request.to_command()
        plan = await self._preview_restore(command)
        self._require_plan(confirmation, plan.plan_digest)
        if plan.key_classification is not request.recovery_mode:
            raise _internal_error()
        started = self._start_sample()
        try:
            secret = await self._recovery_secret(
                request_id=command.request_id,
                plan_digest=plan.plan_digest,
                mode=plan.key_classification,
                operation=RecoveryOperation.RESTORE,
            )
            result = await self._maintenance.restore(
                command,
                confirmed_plan_digest=plan.plan_digest,
                recovery_secret=secret,
            )
        except asyncio.CancelledError:
            self._record(
                kind=MaintenanceKind.RESTORE,
                phase="execute",
                request_id=str(command.request_id),
                started=started,
                plan_digest=plan.plan_digest,
                reason="cancelled",
            )
            raise
        except MaintenanceError as exc:
            self._record(
                kind=MaintenanceKind.RESTORE,
                phase="execute",
                request_id=str(command.request_id),
                started=started,
                plan_digest=plan.plan_digest,
                reason=exc.reason.value,
            )
            raise _public_error(exc, MaintenanceKind.RESTORE) from None
        except PublicOperationError as exc:
            self._record(
                kind=MaintenanceKind.RESTORE,
                phase="execute",
                request_id=str(command.request_id),
                started=started,
                plan_digest=plan.plan_digest,
                reason=exc.code.value.lower(),
            )
            raise
        self._record(
            kind=MaintenanceKind.RESTORE,
            phase="execute",
            request_id=str(command.request_id),
            started=started,
            task_id=str(result.task_id),
            plan_digest=plan.plan_digest,
            result_digest=result.replay_digest,
        )
        return result

    async def preview_migration(self, request: MigrationRequest) -> MigrationPlan:
        self._require_open()
        if type(request) is not MigrationRequest:
            raise _confirmation_required()
        return await self._preview_migration(request.to_command())

    async def migrate(
        self,
        request: MigrationRequest,
        confirmation: Confirmation,
    ) -> MigrationResult:
        self._require_open()
        if type(request) is not MigrationRequest or type(confirmation) is not Confirmation:
            raise _confirmation_required()
        self._require_acceptance(confirmation)
        command = request.to_command()
        plan = await self._preview_migration(command)
        self._require_plan(confirmation, plan.plan_digest)
        if (
            plan.current_frontier != request.expected_frontier
            or plan.to_version != request.target_storage_version
            or plan.preflight_backup_mode is not BackupMode.MACHINE_BOUND
        ):
            raise _internal_error()
        started = self._start_sample()
        try:
            result = await self._maintenance.migrate(command, plan.plan_digest)
        except asyncio.CancelledError:
            self._record(
                kind=MaintenanceKind.MIGRATION,
                phase="execute",
                request_id=str(command.request_id),
                started=started,
                plan_digest=plan.plan_digest,
                reason="cancelled",
            )
            raise
        except MaintenanceError as exc:
            self._record(
                kind=MaintenanceKind.MIGRATION,
                phase="execute",
                request_id=str(command.request_id),
                started=started,
                plan_digest=plan.plan_digest,
                reason=exc.reason.value,
            )
            raise _public_error(exc, MaintenanceKind.MIGRATION) from None
        self._record(
            kind=MaintenanceKind.MIGRATION,
            phase="execute",
            request_id=str(command.request_id),
            started=started,
            task_id=str(result.task_id),
            plan_digest=plan.plan_digest,
            result_digest=result.replay_digest,
            from_version=result.from_version,
            to_version=result.to_version,
        )
        return result

    async def close(self) -> None:
        self._closed = True

    async def _preview_backup(self, command: BackupCommand) -> BackupPlan:
        started = self._start_sample()
        try:
            result = await self._maintenance.preview_backup(command)
        except asyncio.CancelledError:
            self._record(
                kind=MaintenanceKind.BACKUP,
                phase="preview",
                request_id=str(command.request_id),
                started=started,
                reason="cancelled",
            )
            raise
        except MaintenanceError as exc:
            self._record(
                kind=MaintenanceKind.BACKUP,
                phase="preview",
                request_id=str(command.request_id),
                started=started,
                reason=exc.reason.value,
            )
            raise _public_error(exc, MaintenanceKind.BACKUP) from None
        self._record(
            kind=MaintenanceKind.BACKUP,
            phase="preview",
            request_id=str(command.request_id),
            started=started,
            task_id=str(result.task_id),
            plan_digest=result.plan_digest,
            count=result.object_count,
        )
        return result

    async def _preview_restore(self, command: RestoreCommand) -> RestorePlan:
        started = self._start_sample()
        try:
            result = await self._maintenance.preview_restore(command)
        except asyncio.CancelledError:
            self._record(
                kind=MaintenanceKind.RESTORE,
                phase="preview",
                request_id=str(command.request_id),
                started=started,
                reason="cancelled",
            )
            raise
        except MaintenanceError as exc:
            self._record(
                kind=MaintenanceKind.RESTORE,
                phase="preview",
                request_id=str(command.request_id),
                started=started,
                reason=exc.reason.value,
            )
            raise _public_error(exc, MaintenanceKind.RESTORE) from None
        self._record(
            kind=MaintenanceKind.RESTORE,
            phase="preview",
            request_id=str(command.request_id),
            started=started,
            task_id=str(result.task_id),
            plan_digest=result.plan_digest,
        )
        return result

    async def _preview_migration(self, command: MigrationCommand) -> MigrationPlan:
        started = self._start_sample()
        try:
            result = await self._maintenance.preview_migration(command)
        except asyncio.CancelledError:
            self._record(
                kind=MaintenanceKind.MIGRATION,
                phase="preview",
                request_id=str(command.request_id),
                started=started,
                reason="cancelled",
            )
            raise
        except MaintenanceError as exc:
            self._record(
                kind=MaintenanceKind.MIGRATION,
                phase="preview",
                request_id=str(command.request_id),
                started=started,
                reason=exc.reason.value,
            )
            raise _public_error(exc, MaintenanceKind.MIGRATION) from None
        self._record(
            kind=MaintenanceKind.MIGRATION,
            phase="preview",
            request_id=str(command.request_id),
            started=started,
            task_id=str(result.task_id),
            plan_digest=result.plan_digest,
            from_version=result.from_version,
            to_version=result.to_version,
        )
        return result

    async def _recovery_secret(
        self,
        *,
        request_id: RequestId,
        plan_digest: str,
        mode: BackupMode,
        operation: RecoveryOperation,
    ) -> RecoverySecret | None:
        if mode is BackupMode.MACHINE_BOUND:
            return None
        acquisition = RecoverySecretAcquisition(
            request_id=request_id,
            confirmed_plan_digest=plan_digest,
            service_generation=self._service_generation,
            operation=operation,
        )
        candidate: object = await self._recovery_secrets.acquire_recovery_secret(acquisition)
        return _validated_recovery_secret(candidate)

    def _require_open(self) -> None:
        if self._closed:
            raise _service_unavailable()

    @staticmethod
    def _require_acceptance(confirmation: Confirmation) -> None:
        if not confirmation.explicitly_accepted:
            raise _confirmation_required()

    @staticmethod
    def _require_plan(confirmation: Confirmation, plan_digest: str) -> None:
        if confirmation.plan_digest != plan_digest:
            raise _plan_stale()

    def _start_sample(self) -> float:
        sample = self._clock.monotonic_seconds()
        if type(sample) is not float or not math.isfinite(sample) or sample < 0.0:
            raise _internal_error()
        return sample

    def _record(
        self,
        *,
        kind: MaintenanceKind,
        phase: Literal["preview", "execute"],
        request_id: str,
        started: float,
        reason: str | None = None,
        task_id: str | None = None,
        plan_digest: str | None = None,
        result_digest: str | None = None,
        from_version: str | None = None,
        to_version: str | None = None,
        count: int | None = None,
    ) -> None:
        try:
            ended = self._clock.monotonic_seconds()
            observed_at = self._clock.now_utc()
            if (
                type(ended) is not float
                or not math.isfinite(ended)
                or ended < started
                or format_rfc3339_millis(observed_at) == ""
            ):
                return
            diagnostic = MaintenanceDiagnostic(
                operation=kind.value,
                phase=phase,
                outcome=(
                    "success"
                    if reason is None
                    else "cancelled"
                    if reason == "cancelled"
                    else "failed"
                ),
                request_id=request_id,
                task_id=task_id,
                plan_digest=plan_digest,
                result_digest=result_digest,
                from_version=from_version,
                to_version=to_version,
                count=count,
                duration_ms=min(int((ended - started) * 1000), _MAX_SAFE_INTEGER),
                reason_code=reason,
                observed_at=observed_at,
            )
            self._diagnostics.record_maintenance(diagnostic)
        except Exception:
            return
