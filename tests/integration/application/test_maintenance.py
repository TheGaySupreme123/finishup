"""Maintenance service preview, consent, and secret-ordering integration tests."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal, cast

import pytest

from finishup.application.maintenance import (
    BackupRequest,
    Confirmation,
    ConfirmationChannel,
    MaintenanceService,
    MigrationRequest,
    RestoreRequest,
)
from finishup.domain.values import (
    Frontier,
    JsonObject,
    Timestamp,
    request_id,
    session_id,
    task_id,
)
from finishup.ports.diagnostics import MaintenanceDiagnostic
from finishup.ports.keys import RecoverySecret
from finishup.ports.maintenance import (
    BackupCommand,
    BackupMode,
    BackupPlan,
    BackupResult,
    MaintenanceError,
    MaintenanceLocation,
    MaintenanceReason,
    MigrationCommand,
    MigrationPlan,
    MigrationResult,
    RecoveryOperation,
    RecoverySecretAcquisition,
    RestoreCommand,
    RestorePlan,
    RestoreResult,
)
from finishup.ports.secret_memory import SecretConsumer, SecretPurpose
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

_D0 = "sha256:" + "0" * 64
_D1 = "sha256:" + "1" * 64
_D2 = "sha256:" + "2" * 64
_D3 = "sha256:" + "3" * 64
_D4 = "sha256:" + "4" * 64
_D5 = "sha256:" + "5" * 64
_COMMITMENT = "hmac-sha256:" + "a" * 64
_REQUEST_ID = request_id("req_10000000-0000-4000-8000-000000000001")
_SESSION_ID = session_id("ses_20000000-0000-4000-8000-000000000001")
_TASK_ID = task_id("tsk_30000000-0000-4000-8000-000000000001")
_FRONTIER = Frontier(3, _D3)
_TIME = datetime(2026, 7, 19, 8, 30, tzinfo=UTC)
_TIMESTAMP = Timestamp("2026-07-19T08:30:00.000Z")
_SECRET_CANARY = "portable-secret-must-not-escape"
_PATH_CANARY = "/private/sensitive/backup-location"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Clock:
    def __init__(self) -> None:
        self.sample = 10.0

    def now_utc(self) -> datetime:
        return _TIME

    def monotonic_seconds(self) -> float:
        self.sample += 0.125
        return self.sample


class _Diagnostics:
    def __init__(self) -> None:
        self.records: list[MaintenanceDiagnostic] = []

    def record_maintenance(self, diagnostic: MaintenanceDiagnostic) -> None:
        self.records.append(diagnostic)


class _RecoverySecret:
    def __init__(self) -> None:
        self._value = bytearray(_SECRET_CANARY.encode())
        self._consumed = False

    @property
    def purpose(self) -> Literal[SecretPurpose.PORTABLE_RECOVERY]:
        return SecretPurpose.PORTABLE_RECOVERY

    def consume[T](self, consumer: SecretConsumer, fn: Callable[[memoryview], T]) -> T:
        if consumer is not SecretConsumer.RECOVERY_WRAPPER or self._consumed:
            raise ValueError("recovery_secret_invalid")
        self._consumed = True
        try:
            return fn(memoryview(self._value))
        finally:
            self._value[:] = b"\0" * len(self._value)

    def __repr__(self) -> str:
        return "<_RecoverySecret redacted>"


class _Acquirer:
    def __init__(self, ordering: list[str]) -> None:
        self.acquisitions: list[RecoverySecretAcquisition] = []
        self.ordering = ordering

    async def acquire_recovery_secret(
        self,
        acquisition: RecoverySecretAcquisition,
    ) -> RecoverySecret:
        self.ordering.append("secret")
        self.acquisitions.append(acquisition)
        return _RecoverySecret()


def _backup_plan(mode: BackupMode, *, frontier: Frontier = _FRONTIER) -> BackupPlan:
    return BackupPlan(
        request_digest=_D0,
        task_id=_TASK_ID,
        frontier=frontier,
        mode=mode,
        destination_commitment=_COMMITMENT,
        object_count=2,
        estimated_ciphertext_bytes=100,
        privacy_audit_object_count=1,
        privacy_audit_snapshot_digest=_D1,
        version_manifest=JsonObject({}),
        warnings=(),
        plan_digest=_D2,
    )


def _backup_result(mode: BackupMode) -> BackupResult:
    return BackupResult(
        request_id=_REQUEST_ID,
        task_id=_TASK_ID,
        frontier=_FRONTIER,
        mode=mode,
        backup_manifest_digest=_D4,
        backup_set_digest=_D5,
        object_count=2,
        privacy_audit_object_count=1,
        privacy_audit_snapshot_digest=_D1,
        database_digest=_D0,
        recovery_artifact_digest=_D3 if mode is BackupMode.PORTABLE_RECOVERY else None,
        completed_at=_TIMESTAMP,
    )


def _restore_plan(mode: BackupMode) -> RestorePlan:
    return RestorePlan(
        request_digest=_D0,
        source_manifest_digest=_D1,
        task_id=_TASK_ID,
        backup_frontier=_FRONTIER,
        active_frontier=_FRONTIER,
        new_route_identity_digest=_D4,
        key_classification=mode,
        migration_needed=False,
        warnings=(),
        plan_digest=_D2,
    )


def _restore_result() -> RestoreResult:
    return RestoreResult(
        request_id=_REQUEST_ID,
        task_id=_TASK_ID,
        restored_frontier=_FRONTIER,
        prior_route_identity_digest=_D0,
        active_route_identity_digest=_D4,
        backup_manifest_digest=_D1,
        replay_digest=_D5,
        completed_at=_TIMESTAMP,
    )


def _migration_plan(*, frontier: Frontier = _FRONTIER) -> MigrationPlan:
    return MigrationPlan(
        request_digest=_D0,
        task_id=_TASK_ID,
        from_version="1",
        to_version="2",
        current_frontier=frontier,
        required_migration_ids=("0002",),
        preflight_backup_mode=BackupMode.MACHINE_BOUND,
        warnings=(),
        plan_digest=_D2,
    )


def _migration_result() -> MigrationResult:
    return MigrationResult(
        request_id=_REQUEST_ID,
        task_id=_TASK_ID,
        from_version="1",
        to_version="2",
        backup_manifest_digest=_D4,
        frontier_before=_FRONTIER,
        frontier_after=_FRONTIER,
        replay_digest=_D5,
        completed_at=_TIMESTAMP,
    )


class _Maintenance:
    def __init__(self, ordering: list[str]) -> None:
        self.ordering = ordering
        self.backup_plan = _backup_plan(BackupMode.MACHINE_BOUND)
        self.backup_result = _backup_result(BackupMode.MACHINE_BOUND)
        self.restore_plan = _restore_plan(BackupMode.MACHINE_BOUND)
        self.restore_result = _restore_result()
        self.migration_plan = _migration_plan()
        self.migration_result = _migration_result()
        self.calls: list[tuple[str, object, str | None, RecoverySecret | None]] = []
        self.fail: MaintenanceError | None = None
        self.cancel_method: str | None = None

    async def preview_backup(self, command: BackupCommand) -> BackupPlan:
        self.ordering.append("preview_backup")
        self.calls.append(("preview_backup", command, None, None))
        self._raise("preview_backup")
        return self.backup_plan

    async def backup(
        self,
        command: BackupCommand,
        *,
        confirmed_plan_digest: str,
        recovery_secret: RecoverySecret | None,
    ) -> BackupResult:
        self.ordering.append("backup")
        self.calls.append(("backup", command, confirmed_plan_digest, recovery_secret))
        self._raise("backup")
        return self.backup_result

    async def preview_restore(self, command: RestoreCommand) -> RestorePlan:
        self.ordering.append("preview_restore")
        self.calls.append(("preview_restore", command, None, None))
        self._raise("preview_restore")
        return self.restore_plan

    async def restore(
        self,
        command: RestoreCommand,
        *,
        confirmed_plan_digest: str,
        recovery_secret: RecoverySecret | None,
    ) -> RestoreResult:
        self.ordering.append("restore")
        self.calls.append(("restore", command, confirmed_plan_digest, recovery_secret))
        self._raise("restore")
        return self.restore_result

    async def preview_migration(self, command: MigrationCommand) -> MigrationPlan:
        self.ordering.append("preview_migration")
        self.calls.append(("preview_migration", command, None, None))
        self._raise("preview_migration")
        return self.migration_plan

    async def migrate(
        self,
        command: MigrationCommand,
        confirmed_plan_digest: str,
    ) -> MigrationResult:
        self.ordering.append("migrate")
        self.calls.append(("migrate", command, confirmed_plan_digest, None))
        self._raise("migrate")
        return self.migration_result

    def _raise(self, method: str) -> None:
        if self.cancel_method == method:
            raise asyncio.CancelledError
        if self.fail is not None:
            raise self.fail


def _backup_request(mode: BackupMode) -> BackupRequest:
    return BackupRequest(
        _REQUEST_ID,
        _SESSION_ID,
        MaintenanceLocation(_PATH_CANARY),
        mode,
        _FRONTIER,
    )


def _restore_request(mode: BackupMode) -> RestoreRequest:
    return RestoreRequest(
        _REQUEST_ID,
        MaintenanceLocation(_PATH_CANARY),
        mode,
        _TASK_ID,
        _FRONTIER,
    )


def _migration_request() -> MigrationRequest:
    return MigrationRequest(_REQUEST_ID, _SESSION_ID, "2", _FRONTIER)


def _service(
    port: _Maintenance,
    acquirer: _Acquirer,
    diagnostics: _Diagnostics,
    *,
    generation: int = 7,
) -> MaintenanceService:
    return MaintenanceService(port, _Clock(), diagnostics, acquirer, generation)


def _accepted(digest: str = _D2) -> Confirmation:
    return Confirmation(digest, True, ConfirmationChannel.INTERACTIVE)


@pytest.mark.anyio
async def test_preview_and_confirmation_digest_binding_precedes_every_effect() -> None:
    ordering: list[str] = []
    port = _Maintenance(ordering)
    diagnostics = _Diagnostics()
    acquirer = _Acquirer(ordering)
    service = _service(port, acquirer, diagnostics)
    request = _backup_request(BackupMode.MACHINE_BOUND)

    assert await service.preview_backup(request) is port.backup_plan
    declined = Confirmation(_D2, False, ConfirmationChannel.NONINTERACTIVE_FLAG)
    with pytest.raises(PublicOperationError) as declined_error:
        await service.backup(request, declined)
    assert declined_error.value.code is PublicErrorCode.INVALID_REQUEST
    assert ordering == ["preview_backup"]

    with pytest.raises(PublicOperationError) as stale_error:
        await service.backup(request, _accepted(_D3))
    assert stale_error.value.code is PublicErrorCode.FRONTIER_CONFLICT
    assert ordering == ["preview_backup", "preview_backup"]
    assert not acquirer.acquisitions


@pytest.mark.anyio
async def test_backup_dispatches_machine_bound_without_secret_and_portable_after_confirmation() -> (
    None
):
    ordering: list[str] = []
    port = _Maintenance(ordering)
    diagnostics = _Diagnostics()
    acquirer = _Acquirer(ordering)
    service = _service(port, acquirer, diagnostics)

    result = await service.backup(_backup_request(BackupMode.MACHINE_BOUND), _accepted())
    assert result is port.backup_result
    assert ordering == ["preview_backup", "backup"]
    assert port.calls[-1][3] is None
    assert not acquirer.acquisitions

    ordering.clear()
    port.backup_plan = _backup_plan(BackupMode.PORTABLE_RECOVERY)
    port.backup_result = _backup_result(BackupMode.PORTABLE_RECOVERY)
    result = await service.backup(_backup_request(BackupMode.PORTABLE_RECOVERY), _accepted())
    assert result is port.backup_result
    assert ordering == ["preview_backup", "secret", "backup"]
    acquisition = acquirer.acquisitions[-1]
    assert acquisition == RecoverySecretAcquisition(
        _REQUEST_ID,
        _D2,
        7,
        RecoveryOperation.CREATE,
    )
    assert port.calls[-1][3] is not None


@pytest.mark.anyio
async def test_restore_uses_restore_bound_secret_and_exact_original_command() -> None:
    ordering: list[str] = []
    port = _Maintenance(ordering)
    port.restore_plan = _restore_plan(BackupMode.PORTABLE_RECOVERY)
    diagnostics = _Diagnostics()
    acquirer = _Acquirer(ordering)
    service = _service(port, acquirer, diagnostics, generation=11)
    request = _restore_request(BackupMode.PORTABLE_RECOVERY)

    assert await service.restore(request, _accepted()) is port.restore_result
    assert ordering == ["preview_restore", "secret", "restore"]
    assert acquirer.acquisitions == [
        RecoverySecretAcquisition(_REQUEST_ID, _D2, 11, RecoveryOperation.RESTORE)
    ]
    command = cast(RestoreCommand, port.calls[-1][1])
    assert command == request.to_command()
    assert command.destination_policy == "new_route_only"


@pytest.mark.anyio
async def test_migration_dispatches_confirmed_digest_without_secret_acquisition() -> None:
    ordering: list[str] = []
    port = _Maintenance(ordering)
    diagnostics = _Diagnostics()
    acquirer = _Acquirer(ordering)
    service = _service(port, acquirer, diagnostics)

    assert await service.migrate(_migration_request(), _accepted()) is port.migration_result
    assert ordering == ["preview_migration", "migrate"]
    assert port.calls[-1][2] == _D2
    assert not acquirer.acquisitions

    port.fail = MaintenanceError(MaintenanceReason.MIGRATION_UNSUPPORTED, False, {})
    no_op = MigrationRequest(_REQUEST_ID, _SESSION_ID, "1", _FRONTIER)
    with pytest.raises(PublicOperationError) as rejected:
        await service.migrate(no_op, _accepted())
    assert rejected.value.code is PublicErrorCode.MIGRATION_REQUIRED
    assert ordering[-1] == "preview_migration"
    assert [call[0] for call in port.calls].count("migrate") == 1
    assert not acquirer.acquisitions


@pytest.mark.anyio
async def test_frontier_and_service_generation_bindings_fail_closed() -> None:
    ordering: list[str] = []
    port = _Maintenance(ordering)
    port.backup_plan = _backup_plan(
        BackupMode.PORTABLE_RECOVERY,
        frontier=Frontier(4, _D4),
    )
    port.backup_result = _backup_result(BackupMode.PORTABLE_RECOVERY)
    diagnostics = _Diagnostics()
    acquirer = _Acquirer(ordering)
    service = _service(port, acquirer, diagnostics, generation=23)

    with pytest.raises(PublicOperationError) as mismatch:
        await service.backup(_backup_request(BackupMode.PORTABLE_RECOVERY), _accepted())
    assert mismatch.value.code is PublicErrorCode.INTERNAL_ERROR
    assert not acquirer.acquisitions
    assert all(call[0] != "backup" for call in port.calls)

    port.backup_plan = _backup_plan(BackupMode.PORTABLE_RECOVERY)
    await service.backup(_backup_request(BackupMode.PORTABLE_RECOVERY), _accepted())
    assert acquirer.acquisitions[-1].service_generation == 23


@pytest.mark.anyio
async def test_replay_errors_and_cancellation_remain_bounded_and_retryable() -> None:
    ordering: list[str] = []
    port = _Maintenance(ordering)
    diagnostics = _Diagnostics()
    acquirer = _Acquirer(ordering)
    service = _service(port, acquirer, diagnostics)
    request = _migration_request()

    first = await service.migrate(request, _accepted())
    second = await service.migrate(request, _accepted())
    assert first == second == port.migration_result
    assert [call[0] for call in port.calls].count("migrate") == 2

    port.fail = MaintenanceError(MaintenanceReason.GENERATION_LOST, True, {})
    with pytest.raises(PublicOperationError) as fenced:
        await service.migrate(request, _accepted())
    assert fenced.value.code is PublicErrorCode.BUNDLE_BUSY
    assert fenced.value.retryable is True
    assert _PATH_CANARY not in str(fenced.value)

    port.fail = None
    port.cancel_method = "migrate"
    with pytest.raises(asyncio.CancelledError):
        await service.migrate(request, _accepted())
    assert diagnostics.records[-1].outcome == "cancelled"
    assert diagnostics.records[-1].reason_code == "cancelled"


@pytest.mark.anyio
async def test_results_diagnostics_repr_and_close_exclude_locations_and_secrets() -> None:
    ordering: list[str] = []
    port = _Maintenance(ordering)
    port.backup_plan = _backup_plan(BackupMode.PORTABLE_RECOVERY)
    port.backup_result = _backup_result(BackupMode.PORTABLE_RECOVERY)
    diagnostics = _Diagnostics()
    acquirer = _Acquirer(ordering)
    service = _service(port, acquirer, diagnostics)
    request = _backup_request(BackupMode.PORTABLE_RECOVERY)

    plan = await service.preview_backup(request)
    result = await service.backup(request, _accepted())
    rendered = repr((request, plan, result, diagnostics.records, acquirer.acquisitions))
    assert _PATH_CANARY not in rendered
    assert _SECRET_CANARY not in rendered
    assert all(record.request_id == str(_REQUEST_ID) for record in diagnostics.records)
    assert all(record.operation == "backup" for record in diagnostics.records)

    await service.close()
    await service.close()
    with pytest.raises(PublicOperationError) as closed:
        await service.preview_backup(request)
    assert closed.value.code is PublicErrorCode.SERVICE_UNAVAILABLE
