from __future__ import annotations

import asyncio
import hashlib
import hmac
import threading
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Protocol, cast

import apsw
import pytest

import yoetz.adapters.sqlite.connection as connection_module
import yoetz.adapters.sqlite.recovery as recovery_module
import yoetz.service.ready_composition as ready_composition_module
from builders.privacy_policies import local_only_policy, minimal_external_policy
from yoetz.adapters.integrations.codex_lifecycle import mapping_from_start_ids, store_mapping
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.adapters.keys.encrypted_vault import EncryptedVaultStore
from yoetz.adapters.keys.secret_memory import LocalSecretMemory
from yoetz.adapters.sqlite.connection import open_catalog_writer
from yoetz.adapters.sqlite.migrations import (
    BUNDLE_MIGRATIONS,
    CATALOG_MIGRATIONS,
    Migration,
    initialize_catalog,
)
from yoetz.application.service import ClientProjectionContext, ControlProjectionBinding
from yoetz.config.models import ObservationConfig, VerificationConfig, YoetzConfig
from yoetz.config.write import fireworks_provider
from yoetz.domain.host_lineage import host_lineage_from_payload
from yoetz.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationIngestRequest,
    ObservationLifecycle,
    ObservationSource,
    ObservationStatus,
    ObservationStatusQuery,
    observation_ingest_request_to_json,
)
from yoetz.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    EgressChannel,
    PrivacyPolicy,
)
from yoetz.domain.values import (
    Frontier,
    JsonObject,
    format_rfc3339_millis,
    task_id,
    timestamp_from_datetime,
)
from yoetz.kernel.policies.observation_advice import (
    ObservationAdviceContext,
    ObservationCompositionFact,
    observation_advice_findings,
)
from yoetz.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlMethod,
    ProjectionRenderMode,
    RepositoryPrivacyContext,
    ServiceState,
)
from yoetz.ports.diagnostics import StartupCheckResult
from yoetz.ports.keys import BundleKeys, WrapKeyHandle
from yoetz.ports.ledger import CheckCommitResult
from yoetz.ports.privacy import (
    EffectivePrivacyPolicy,
    HumanAuthorityCapability,
    LocalDisclosureReceiptView,
    OutboundGatewayPort,
    PrivacyAuditObjectRoots,
    PrivacyReceiptAudience,
)
from yoetz.ports.runtime import (
    BundleProvisionCommand,
    OwnershipFence,
    RouteAccess,
)
from yoetz.ports.secret_memory import HumanAuthorizationProof, SecretPurpose
from yoetz.ports.start_catalog import TaskRoute, TaskRouteState
from yoetz.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import (
    CheckRequest,
    CheckResult,
    CheckSuccessModel,
    PublishWorkRequest,
    StartRequest,
    StartResult,
)
from yoetz.service.bundle_upgrade import (
    BUNDLE_UPGRADE_TARGET_VERSION,
    BackupEvidence,
    BundleIntegrity,
    BundleUpgradeError,
    BundleUpgradeReason,
    BundleUpgradeReport,
    BundleUpgradeTarget,
)
from yoetz.service.daemon import ServiceComposition, ServiceDaemon
from yoetz.service.lifecycle import ServiceLifecycle
from yoetz.service.ready_composition import (
    IdPort,
    build_privacy_coordinator,
    build_ready_application_factory,
    open_ready_catalog,
)
from yoetz.service.vault import VaultMode, VaultService, provider_credential_profile_binding

_INSTALLATION_ID = "ins_00000000-0000-4000-8000-000000000001"
_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000002"


class _SupportPolicyFactory(Protocol):
    def __call__(
        self,
        *,
        manifest_id: str,
        required_options: frozenset[str],
        denied_options: frozenset[str],
    ) -> object: ...


class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 7, 21, 18, 0, 0, tzinfo=UTC)

    def monotonic_seconds(self) -> float:
        return 1.0


class _GenerationStore:
    def advance(self, instance_id: str) -> int:
        assert instance_id == _INSTANCE_ID
        return 1


class _Lookup:
    def mac(self, domain: bytes, message: bytes) -> str:
        return (
            "hmac-sha256:"
            + hmac.new(
                b"catalog-test-key",
                domain + message,
                hashlib.sha256,
            ).hexdigest()
        )


def _accept_private_path(_path: Path) -> None:
    return None


class _Paths:
    def __init__(self, bundle: Path) -> None:
        self._bundle = bundle

    @property
    def bundle(self) -> Path:
        return self._bundle

    @property
    def state(self) -> Path:
        return self._bundle / "state"


class _StartupLifecycle:
    instance = SimpleNamespace(instance_id=_INSTANCE_ID)

    def assert_singleton_held(self) -> None:
        return None


def _runtime_route() -> TaskRoute:
    task_id = new_id(IdKind.TASK)
    session_id = new_id(IdKind.SESSION)
    return TaskRoute(
        task_id=task_id,
        session_id=session_id,
        bundle_relpath=f"tasks/{task_id}",
        route_generation=1,
        state=TaskRouteState.ACTIVE,
        route_identity_digest=canonical_digest(
            {"task_id": task_id, "bundle_relpath": f"tasks/{task_id}", "route_generation": 1}
        ),
    )


async def _wait_thread_event(event: threading.Event) -> None:
    assert await asyncio.to_thread(event.wait, 5.0)


class _Diagnostics:
    def record(self, result: StartupCheckResult) -> None:
        assert type(result) is StartupCheckResult


class _Listener:
    def __init__(self) -> None:
        self.closed = asyncio.Event()

    async def accept(self) -> object:
        await self.closed.wait()
        raise RuntimeError("closed")

    async def aclose(self) -> None:
        self.closed.set()


@pytest.fixture(autouse=True)
def _sqlite_policy(  # pyright: ignore[reportUnusedFunction]
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _accept_private_path)
    monkeypatch.setattr(
        ready_composition_module,
        "verify_private_local_bundle",
        _accept_private_path,
    )
    factory = cast(_SupportPolicyFactory, getattr(connection_module, "_SqliteSupportPolicy"))
    installer = cast(
        Callable[[object | None], None], getattr(connection_module, "_install_support_policy")
    )
    db = apsw.Connection(":memory:")
    try:
        raw_options: object = db.pragma("compile_options")
    finally:
        db.close()
    assert type(raw_options) is list
    items = cast(list[object], raw_options)
    assert all(type(item) is str for item in items)
    installer(
        factory(
            manifest_id="test-ready-composition-runtime-support",
            required_options=frozenset(cast(list[str], items)),
            denied_options=frozenset({"OMIT_FOREIGN_KEY", "OMIT_WAL", "THREADSAFE=0"}),
        )
    )
    yield
    installer(None)


@pytest.mark.anyio
async def test_route_inspection_is_off_loop_and_closes_private_catalog_after_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cancelled route probe cannot strand the private read-only catalog connection."""

    catalog_started = threading.Event()
    catalog_release = threading.Event()
    catalog_closed = threading.Event()
    inspection_started = threading.Event()
    inspection_release = threading.Event()
    inspection_done = threading.Event()

    class _Cursor:
        def fetchall(self) -> list[tuple[object, ...]]:
            return []

    class _Catalog:
        def execute(self, _sql: str, _params: tuple[str, ...]) -> _Cursor:
            catalog_started.set()
            assert catalog_release.wait(5.0)
            return _Cursor()

        def close(self, *, force: bool = False) -> None:
            assert force
            catalog_closed.set()

    catalog = _Catalog()

    def fake_open_read_only(_path: Path) -> _Catalog:
        return catalog

    monkeypatch.setattr(ready_composition_module, "open_read_only", fake_open_read_only)

    def inspect_common(**_kwargs: object) -> object:
        inspection_started.set()
        assert inspection_release.wait(5.0)
        inspection_done.set()
        return object()

    monkeypatch.setattr(ready_composition_module, "_inspect_common", inspect_common)
    factories = ready_composition_module.build_runtime_adapter_factories(
        paths=_Paths(tmp_path),
        service_instance_id=_INSTANCE_ID,
        service_generation=1,
        clock=_Clock(),
        ids=IdPort(),
        secret_memory=object(),
    )
    route = _runtime_route()

    async def inspect_route_task() -> object:
        return await factories.inspect_route(route, RouteAccess.WRITE)

    task = asyncio.create_task(inspect_route_task())

    await _wait_thread_event(catalog_started)
    heartbeat = asyncio.Event()
    asyncio.get_running_loop().call_soon(heartbeat.set)
    await asyncio.wait_for(heartbeat.wait(), timeout=1.0)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    catalog_release.set()
    await _wait_thread_event(catalog_closed)
    inspection_release.set()
    await _wait_thread_event(inspection_started)
    await _wait_thread_event(inspection_done)


@pytest.mark.anyio
async def test_joined_blocking_worker_cleans_up_late_resource_after_cancellation() -> None:
    """A cancelled writer-open wait closes a resource returned by its joined worker."""

    started = threading.Event()
    release = threading.Event()
    cleaned = threading.Event()

    class _Resource:
        closed = False

        def close(self) -> None:
            self.closed = True
            cleaned.set()

    resource = _Resource()

    def open_resource() -> _Resource:
        started.set()
        assert release.wait(5.0)
        return resource

    def close_resource(value: _Resource) -> None:
        value.close()

    task = asyncio.create_task(
        ready_composition_module._run_blocking_joined(  # pyright: ignore[reportPrivateUsage]
            open_resource,
            operation="joined_resource_open_failed",
            cleanup_result=close_resource,
        )
    )
    await _wait_thread_event(started)
    task.cancel()
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await _wait_thread_event(cleaned)
    assert resource.closed


@pytest.mark.anyio
@pytest.mark.parametrize("recovery_failure", [False, True])
async def test_replay_cancellation_joins_shielded_ledger_recovery_before_close(
    tmp_path: Path, recovery_failure: bool
) -> None:
    """Replay teardown waits for SqliteLedger recovery before the fenced DB can be closed."""

    started = threading.Event()
    cancellation_seen = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    class _Ledger:
        _recovery_task: asyncio.Task[None] | None = None

        async def load_frontier(self) -> Frontier:
            async def recover() -> None:
                started.set()
                await asyncio.to_thread(release.wait, 5.0)
                finished.set()
                if recovery_failure:
                    raise RuntimeError("synthetic_recovery_failure")

            self._recovery_task = asyncio.create_task(recover())
            try:
                # ``asyncio.wait`` keeps the recovery task alive on cancellation without the
                # late-exception warning produced by a cancelled ``shield`` wrapper on Python
                # 3.14.  This is the same non-cancelling contract that the production adapter
                # must join before releasing its fenced connection.
                await asyncio.wait((self._recovery_task,))
            except asyncio.CancelledError:
                cancellation_seen.set()
                raise
            return Frontier.genesis()

        async def rebuild_projection(self, _projection: str) -> None:
            return None

    route = _runtime_route()
    target = BundleUpgradeTarget(
        task_id=task_id(route.task_id),
        session_id=route.session_id,
        bundle_path=tmp_path / "ledger.sqlite3",
        route_generation=route.route_generation,
        route_identity_digest=route.route_identity_digest,
        frontier=Frontier.genesis(),
        catalog_owner_generation=1,
    )
    digest = "sha256:" + "0" * 64
    after = BundleIntegrity(
        task_id=task_id(route.task_id),
        schema_version=14,
        frontier=Frontier.genesis(),
        history_digest=digest,
        event_count=0,
        object_digest=digest,
        object_count=0,
        preserved_digest=digest,
        projection_digest=digest,
    )
    backup = BackupEvidence(task_id(route.task_id), Frontier.genesis(), digest)
    ledger = _Ledger()
    adapter = ready_composition_module._BundleUpgradeReplayLedger(  # pyright: ignore[reportPrivateUsage]
        cast(ready_composition_module.SqliteLedger, ledger),
        cast(apsw.Connection, object()),
    )
    task = asyncio.create_task(
        adapter.verify_replay(target=target, before=None, after=after, backup=backup)
    )
    await _wait_thread_event(started)
    task.cancel()
    assert not task.done()
    await _wait_thread_event(cancellation_seen)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await _wait_thread_event(finished)


@pytest.mark.anyio
async def test_provision_inspection_is_off_loop_and_joins_fresh_bundle_worker_on_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cancelled fresh start waits for mkdir/schema inspection to finish before returning."""

    started = threading.Event()
    release = threading.Event()
    initialized = threading.Event()
    inspected = threading.Event()

    def initialize(_path: Path, *, command: object, clock: object) -> None:
        del command, clock
        started.set()
        assert release.wait(5.0)
        initialized.set()

    def inspect_common(**_kwargs: object) -> object:
        inspected.set()
        return object()

    monkeypatch.setattr(ready_composition_module, "_initialize_fresh_bundle", initialize)
    monkeypatch.setattr(ready_composition_module, "_inspect_common", inspect_common)
    factories = ready_composition_module.build_runtime_adapter_factories(
        paths=_Paths(tmp_path),
        service_instance_id=_INSTANCE_ID,
        service_generation=1,
        clock=_Clock(),
        ids=IdPort(),
        secret_memory=object(),
    )
    route = _runtime_route()
    command = SimpleNamespace(
        task_id=route.task_id,
        session_id=route.session_id,
        writer_id=new_id(IdKind.WRITER),
        bundle_relpath=route.bundle_relpath,
        route_generation=route.route_generation,
        route_identity_digest=route.route_identity_digest,
    )
    provision_command = cast(BundleProvisionCommand, command)

    async def inspect_provision_task() -> object:
        return await factories.inspect_provision(provision_command)

    task = asyncio.create_task(inspect_provision_task())

    await _wait_thread_event(started)
    heartbeat = asyncio.Event()
    asyncio.get_running_loop().call_soon(heartbeat.set)
    await asyncio.wait_for(heartbeat.wait(), timeout=1.0)

    task.cancel()
    task.cancel()
    # Cancellation is intentionally held until the side-effecting worker joins.
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert initialized.is_set()
    assert inspected.is_set()


@pytest.mark.anyio
async def test_fence_verification_is_off_loop_and_cancellation_leaves_no_worker_resource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fence verification remains cancellable while its read-only worker finishes independently."""

    started = threading.Event()
    release = threading.Event()
    done = threading.Event()

    class _Backend:
        def verify_fence(self, _state: object, _fence: OwnershipFence) -> None:
            started.set()
            assert release.wait(5.0)
            done.set()

    monkeypatch.setattr(recovery_module, "_backend", lambda: _Backend())
    factories = ready_composition_module.build_runtime_adapter_factories(
        paths=_Paths(tmp_path),
        service_instance_id=_INSTANCE_ID,
        service_generation=1,
        clock=_Clock(),
        ids=IdPort(),
        secret_memory=object(),
    )
    route = _runtime_route()
    inspection = ready_composition_module._BundleInspection(  # pyright: ignore[reportPrivateUsage]
        route,
        tmp_path,
        tmp_path / "ledger.sqlite3",
        tmp_path / "catalog.sqlite3",
        frozenset(),
        False,
        object(),
        object(),
    )
    fence = OwnershipFence(_INSTANCE_ID, 1, 1, "nonce_value_123456")

    async def validate_fence_task() -> None:
        await factories.validate_fence(inspection, fence)

    task = asyncio.create_task(validate_fence_task())

    await _wait_thread_event(started)
    heartbeat = asyncio.Event()
    asyncio.get_running_loop().call_soon(heartbeat.set)
    await asyncio.wait_for(heartbeat.wait(), timeout=1.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    await _wait_thread_event(done)


@pytest.mark.anyio
async def test_legacy_spool_replay_is_off_loop_and_finishes_claim_after_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stalled legacy spool cannot starve control callbacks or strand its claimed file."""

    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    calls = 0

    class _Spool:
        def __init__(self, *, _state: Path) -> None:
            assert _state == tmp_path

        def pending_workspaces(self) -> tuple[str, ...]:
            nonlocal calls
            calls += 1
            started.set()
            assert release.wait(5.0)
            finished.set()
            return ()

    monkeypatch.setattr(ready_composition_module, "HookSpool", _Spool)
    forwarder = ready_composition_module._LegacyHookSpoolForwarder(  # pyright: ignore[reportPrivateUsage]
        tmp_path
    )
    task = asyncio.create_task(forwarder.replay())
    await _wait_thread_event(started)

    heartbeat = asyncio.Event()
    asyncio.get_running_loop().call_soon(heartbeat.set)
    await asyncio.wait_for(heartbeat.wait(), timeout=1.0)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The retained worker owns the in-flight claim after its awaiter is gone.
    release.set()
    await _wait_thread_event(finished)
    assert calls == 1
    forwarder.close()


@pytest.mark.anyio
async def test_legacy_spool_retries_after_an_observed_worker_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One failed filesystem pass must not poison every later maintenance pass."""

    calls = 0

    def replay(_state: Path, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("test_spool_temporarily_unavailable")

    monkeypatch.setattr(ready_composition_module, "_replay_legacy_hook_spool", replay)
    forwarder = ready_composition_module._LegacyHookSpoolForwarder(  # pyright: ignore[reportPrivateUsage]
        tmp_path
    )
    try:
        with pytest.raises(OSError, match="test_spool_temporarily_unavailable"):
            await forwarder.replay()
        await forwarder.replay()
        assert calls == 2
    finally:
        forwarder.close()


@pytest.mark.anyio
async def test_legacy_spool_reports_a_late_failure_once_then_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = threading.Event()
    release = threading.Event()
    calls = 0

    def replay(_state: Path, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            started.set()
            assert release.wait(5.0)
            raise OSError("test_late_spool_failure")

    monkeypatch.setattr(ready_composition_module, "_replay_legacy_hook_spool", replay)
    forwarder = ready_composition_module._LegacyHookSpoolForwarder(  # pyright: ignore[reportPrivateUsage]
        tmp_path
    )
    task = asyncio.create_task(forwarder.replay())
    try:
        await _wait_thread_event(started)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        release.set()
        # Join the retained worker rather than start a competing replay. Its late failure
        # remains observable, but consuming that failure permits a subsequent retry.
        with pytest.raises(OSError, match="test_late_spool_failure"):
            await forwarder.replay()
        await forwarder.replay()
        assert calls == 2
    finally:
        release.set()
        forwarder.close()


@pytest.mark.anyio
async def test_legacy_spool_close_requests_stop_after_the_active_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = threading.Event()
    release = threading.Event()
    stop_seen = threading.Event()

    def replay(_state: Path, *, stop: threading.Event) -> None:
        started.set()
        assert release.wait(5.0)
        if stop.is_set():
            stop_seen.set()

    monkeypatch.setattr(ready_composition_module, "_replay_legacy_hook_spool", replay)
    forwarder = ready_composition_module._LegacyHookSpoolForwarder(  # pyright: ignore[reportPrivateUsage]
        tmp_path
    )
    task = asyncio.create_task(forwarder.replay())
    try:
        await _wait_thread_event(started)
        forwarder.close()
        release.set()
        await task
        assert stop_seen.is_set()
    finally:
        release.set()
        forwarder.close()


def test_legacy_spool_replay_stops_at_one_bounded_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claimed: list[tuple[str, int]] = []
    handled = 0

    class _Spool:
        def __init__(self, *, _state: Path) -> None:
            assert _state == tmp_path

        def pending_workspaces(self) -> tuple[str, ...]:
            return tuple(f"hmac-sha256:{index:064x}" for index in range(100))

        @contextmanager
        def claim(self, workspace: str, *, limit: int):
            nonlocal handled
            claimed.append((workspace, limit))
            handled += 1
            yield (SimpleNamespace(event_name="PostToolUse", payload={"session_id": "s"}),)

    monkeypatch.setattr(ready_composition_module, "HookSpool", _Spool)
    import yoetz.cli.observe_hooks as observe_hooks_module

    def handle_observe(**_kwargs: object) -> int:
        return 0

    monkeypatch.setattr(observe_hooks_module, "handle_observe", handle_observe)
    ready_composition_module._replay_legacy_hook_spool(tmp_path)  # pyright: ignore[reportPrivateUsage]

    assert handled == ready_composition_module._LEGACY_HOOK_SPOOL_BATCH_LIMIT  # pyright: ignore[reportPrivateUsage]
    assert claimed[0][1] == ready_composition_module._LEGACY_HOOK_SPOOL_BATCH_LIMIT  # pyright: ignore[reportPrivateUsage]
    assert claimed[-1][1] == 1


def test_open_catalog_writer_allows_unfenced_catalog_initialization(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    catalog_path = tmp_path / "catalog.sqlite3"

    db = open_catalog_writer(catalog_path)
    try:
        initialize_catalog(db)
        with db:
            db.execute(
                "INSERT INTO catalog_meta(key, value) VALUES ('installation_id', ?)",
                (_INSTALLATION_ID,),
            )
            db.execute("INSERT INTO catalog_meta(key, value) VALUES ('owner_generation', '7')")
        row = db.execute("SELECT value FROM catalog_meta WHERE key='owner_generation'").fetchone()
        assert row == ("7",)
    finally:
        db.close(force=True)


def _write_catalog_v2(path: Path) -> None:
    db = open_catalog_writer(path)
    try:
        with db:
            for migration in CATALOG_MIGRATIONS[:2]:
                db.execute(migration.ddl.decode("utf-8"))
            db.execute(
                "INSERT INTO catalog_meta(key, value) VALUES ('storage_schema_version', '2')"
            )
    finally:
        db.close(force=True)


@pytest.mark.anyio
async def test_open_ready_catalog_transactionally_migrates_v2_before_runtime_use(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    catalog_path = tmp_path / "catalog.sqlite3"
    _write_catalog_v2(catalog_path)
    with pytest.raises(connection_module.StorageUnsafeError, match="schema_metadata_disagrees"):
        open_catalog_writer(catalog_path)

    catalog = await open_ready_catalog(
        catalog_path,
        installation_id=_INSTALLATION_ID,
        service_generation=12,
        lookup=_Lookup(),
        clock=_Clock(),
        ids=IdPort(),
    )
    try:
        assert catalog._db.execute("PRAGMA user_version").fetchone() == (5,)  # pyright: ignore[reportPrivateUsage]
        assert catalog._db.execute(  # pyright: ignore[reportPrivateUsage]
            "SELECT value FROM catalog_meta WHERE key = 'storage_schema_version'"
        ).fetchone() == ("5",)
        assert (
            catalog._db.execute(  # pyright: ignore[reportPrivateUsage]
                "SELECT repository_privacy_commitment FROM task_routes LIMIT 1"
            ).fetchone()
            is None
        )
    finally:
        catalog._db.close(force=True)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_open_ready_catalog_failed_migration_rolls_back_and_stays_v2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    catalog_path = tmp_path / "catalog.sqlite3"
    _write_catalog_v2(catalog_path)
    failing = Migration(
        "0003",
        b"CREATE TABLE migration_partial(value TEXT) STRICT;\n"
        b"SELECT value FROM migration_failure_missing;\n"
        b"PRAGMA user_version = 3;\n",
    )
    monkeypatch.setattr(
        ready_composition_module,
        "CATALOG_MIGRATIONS",
        (*CATALOG_MIGRATIONS[:2], failing),
    )

    with pytest.raises(apsw.SQLError):
        await open_ready_catalog(
            catalog_path,
            installation_id=_INSTALLATION_ID,
            service_generation=12,
            lookup=_Lookup(),
            clock=_Clock(),
            ids=IdPort(),
        )

    db = apsw.Connection(str(catalog_path), flags=apsw.SQLITE_OPEN_READONLY)
    try:
        assert db.execute("PRAGMA user_version").fetchone() == (2,)
        assert (
            db.execute("SELECT 1 FROM sqlite_schema WHERE name = 'migration_partial'").fetchone()
            is None
        )
    finally:
        db.close(force=True)


@pytest.mark.anyio
async def test_build_privacy_coordinator_reuses_durable_seed_on_second_ready(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "7" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "8" * 64)
    catalog_path = tmp_path / "catalog.sqlite3"
    db = open_catalog_writer(catalog_path)
    try:
        initialize_catalog(db)
        with db:
            db.execute(
                "INSERT INTO catalog_meta(key, value) VALUES ('installation_id', ?)",
                (_INSTALLATION_ID,),
            )
            db.execute("INSERT INTO catalog_meta(key, value) VALUES ('owner_generation', '1')")
        first = await build_privacy_coordinator(
            catalog_db=db,
            installation_id=_INSTALLATION_ID,
            service_generation=1,
            vault_generation=vault.generation,
            vault=vault,
            clock=clock,
            ids=IdPort(),
        )
        second = await build_privacy_coordinator(
            catalog_db=db,
            installation_id=_INSTALLATION_ID,
            service_generation=2,
            vault_generation=vault.generation,
            vault=vault,
            clock=clock,
            ids=IdPort(),
        )
        assert first[1].policy_id == second[1].policy_id
        assert first[1].created_at == second[1].created_at
        assert first[1].policy_digest == second[1].policy_digest
    finally:
        db.close(force=True)
        await vault.close()
        memory.close()


@pytest.mark.anyio
async def test_open_ready_catalog_seeds_generation_property(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    catalog = await open_ready_catalog(
        tmp_path / "catalog.sqlite3",
        installation_id=_INSTALLATION_ID,
        service_generation=11,
        lookup=_Lookup(),
        clock=_Clock(),
        ids=IdPort(),
    )
    try:
        assert catalog.generation == 11
        row = catalog._db.execute(  # pyright: ignore[reportPrivateUsage]
            "SELECT value FROM catalog_meta WHERE key='installation_id'"
        ).fetchone()
        assert row == (_INSTALLATION_ID,)
    finally:
        catalog._db.close(force=True)  # pyright: ignore[reportPrivateUsage]


def test_ready_factory_synchronizes_observation_gate_from_loaded_config(tmp_path: Path) -> None:
    paths = _Paths(tmp_path)
    disabled = YoetzConfig().model_copy(
        update={"observation": YoetzConfig().observation.model_copy(update={"enabled": False})}
    )
    build_ready_application_factory(
        lifecycle=object(),  # type: ignore[arg-type]
        vault=object(),  # type: ignore[arg-type]
        config=disabled,
        paths=paths,
        clock=object(),  # type: ignore[arg-type]
        secret_memory=object(),
    )
    store = LocalObservationStore(_state=paths.state)
    assert store.runtime_enabled() is False

    build_ready_application_factory(
        lifecycle=object(),  # type: ignore[arg-type]
        vault=object(),  # type: ignore[arg-type]
        config=YoetzConfig(),
        paths=paths,
        clock=object(),  # type: ignore[arg-type]
        secret_memory=object(),
    )
    assert store.runtime_enabled() is True


@pytest.mark.anyio
async def test_startup_bundle_upgrade_precedes_lineage_and_runtime_composition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The startup upgrade callback is complete before any ready graph client is built."""

    events: list[str] = []

    class _DB:
        def close(self, *, force: bool = False) -> None:
            assert force

    class _Catalog:
        _db = _DB()

    class _Vault:
        ready = True
        generation = 2
        _installation_id = _INSTALLATION_ID

        def installation_mac_handle(self, _purpose: object) -> _Lookup:
            return _Lookup()

    catalog = _Catalog()

    async def open_catalog(_path: Path, **_kwargs: object) -> _Catalog:
        return catalog

    async def upgrade(**_kwargs: object) -> None:
        events.append("upgrade")

    def lineage(*_args: object, **_kwargs: object) -> object:
        events.append("lineage")
        raise RuntimeError("stop_after_order_probe")

    monkeypatch.setattr(ready_composition_module, "ensure_owner_only_dir", _accept_private_path)
    monkeypatch.setattr(ready_composition_module, "open_ready_catalog", open_catalog)
    monkeypatch.setattr(ready_composition_module, "SqliteLineageStore", lineage)

    with pytest.raises(RuntimeError, match="stop_after_order_probe"):
        await ready_composition_module.provide_service_ready_context(
            1,
            2,
            lifecycle=_StartupLifecycle(),
            vault=_Vault(),  # type: ignore[arg-type]
            config=YoetzConfig(),
            paths=_Paths(tmp_path),
            clock=_Clock(),
            secret_memory=object(),
            startup_bundle_upgrade=upgrade,
        )

    assert events == ["upgrade", "lineage"]


@pytest.mark.anyio
async def test_startup_bundle_upgrade_failure_closes_catalog_and_blocks_ready_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed upgrade cannot leak the catalog or compose a partially ready generation."""

    events: list[str] = []

    class _DB:
        close_count = 0

        def close(self, *, force: bool = False) -> None:
            assert force
            self.close_count += 1

    class _Catalog:
        def __init__(self, db: _DB) -> None:
            self._db = db

    class _Vault:
        ready = True
        generation = 2
        _installation_id = _INSTALLATION_ID

        def installation_mac_handle(self, _purpose: object) -> _Lookup:
            return _Lookup()

    db = _DB()
    catalog = _Catalog(db)

    async def open_catalog(_path: Path, **_kwargs: object) -> _Catalog:
        return catalog

    async def upgrade(**_kwargs: object) -> None:
        events.append("upgrade")
        raise BundleUpgradeError(BundleUpgradeReason.BACKUP_FAILED, True)

    def lineage(*_args: object, **_kwargs: object) -> object:
        events.append("lineage")
        raise AssertionError("lineage must not run after startup upgrade failure")

    monkeypatch.setattr(ready_composition_module, "ensure_owner_only_dir", _accept_private_path)
    monkeypatch.setattr(ready_composition_module, "open_ready_catalog", open_catalog)
    monkeypatch.setattr(ready_composition_module, "SqliteLineageStore", lineage)

    with pytest.raises(BundleUpgradeError) as raised:
        await ready_composition_module.provide_service_ready_context(
            1,
            2,
            lifecycle=_StartupLifecycle(),
            vault=_Vault(),  # type: ignore[arg-type]
            config=YoetzConfig(),
            paths=_Paths(tmp_path),
            clock=_Clock(),
            secret_memory=object(),
            startup_bundle_upgrade=upgrade,
        )

    assert raised.value.reason is BundleUpgradeReason.BACKUP_FAILED
    assert raised.value.retryable is True
    assert events == ["upgrade"]
    assert db.close_count == 1


@pytest.mark.anyio
async def test_startup_bundle_upgrade_retry_reenters_before_ready_composition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retry gets a fresh catalog and can proceed after a bounded startup failure."""

    attempts = 0
    catalogs: list[object] = []

    class _DB:
        def close(self, *, force: bool = False) -> None:
            assert force

    class _Catalog:
        def __init__(self) -> None:
            self._db = _DB()

    class _Vault:
        ready = True
        generation = 2
        _installation_id = _INSTALLATION_ID

        def installation_mac_handle(self, _purpose: object) -> _Lookup:
            return _Lookup()

    async def open_catalog(_path: Path, **_kwargs: object) -> _Catalog:
        catalog = _Catalog()
        catalogs.append(catalog)
        return catalog

    async def upgrade(**_kwargs: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise BundleUpgradeError(BundleUpgradeReason.MAINTENANCE_BUSY, True)
        raise RuntimeError("stop_after_retry_probe")

    monkeypatch.setattr(ready_composition_module, "ensure_owner_only_dir", _accept_private_path)
    monkeypatch.setattr(ready_composition_module, "open_ready_catalog", open_catalog)

    for _ in range(2):
        with pytest.raises((BundleUpgradeError, RuntimeError)):
            await ready_composition_module.provide_service_ready_context(
                1,
                2,
                lifecycle=_StartupLifecycle(),
                vault=_Vault(),  # type: ignore[arg-type]
                config=YoetzConfig(),
                paths=_Paths(tmp_path),
                clock=_Clock(),
                secret_memory=object(),
                startup_bundle_upgrade=upgrade,
            )

    assert attempts == 2
    assert len(catalogs) == 2


@pytest.mark.anyio
async def test_startup_bundle_upgrade_skips_legacy_route_and_keeps_v12_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unsupported dormant route is reported while a supported route remains migratable."""

    legacy = _runtime_route()
    supported = _runtime_route()
    routes = (legacy, supported)
    schemas = {legacy.task_id: 9, supported.task_id: 12}

    class _Cursor:
        def fetchall(self) -> list[tuple[object, ...]]:
            return []

    class _DB:
        def execute(self, _sql: str, _params: tuple[object, ...]) -> _Cursor:
            return _Cursor()

    class _Catalog:
        _db = _DB()
        _lookup = _Lookup()
        generation = 7

        async def recovery_routes(self) -> tuple[TaskRoute, ...]:
            return routes

    class _PrivacyStore:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        async def live_object_roots(
            self, task_id: str, route_identity_digest: str
        ) -> PrivacyAuditObjectRoots:
            assert task_id == supported.task_id
            assert route_identity_digest == supported.route_identity_digest
            return PrivacyAuditObjectRoots(
                supported.task_id,
                supported.route_identity_digest,
                4,
                (),
                canonical_digest(()),
            )

    diagnostics: list[StartupCheckResult] = []

    class _Diagnostics:
        def record(self, result: StartupCheckResult) -> None:
            diagnostics.append(result)

    def schema_and_frontier(path: Path) -> tuple[int, Frontier]:
        return schemas[path.parent.name], Frontier.genesis()

    monkeypatch.setattr(
        ready_composition_module,
        "_bundle_upgrade_schema_and_frontier",
        schema_and_frontier,
    )
    monkeypatch.setattr(ready_composition_module, "CatalogPrivacyAudit", _PrivacyStore)

    _routes, targets = await ready_composition_module._bundle_upgrade_targets(  # pyright: ignore[reportPrivateUsage, reportArgumentType]
        _Catalog(),  # pyright: ignore[reportArgumentType]
        bundle_root=tmp_path,
        installation_id=_INSTALLATION_ID,
        clock=_Clock(),
        diagnostics=_Diagnostics(),
    )

    assert tuple(target.task_id for target in targets) == (supported.task_id,)
    assert len(diagnostics) == 1
    assert diagnostics[0].reason_code == BundleUpgradeReason.SCHEMA_UPGRADE_PATH_UNKNOWN.value
    assert diagnostics[0].safe_details["route_identity_digest"] == legacy.route_identity_digest
    assert diagnostics[0].safe_details["schema_version"] == 9


@pytest.mark.anyio
async def test_default_startup_bundle_upgrade_runs_real_effects_on_isolated_v12_fixture(
    tmp_path: Path,
) -> None:
    """Exercise the production backup, migration, and replay glue against an isolated bundle."""

    tmp_path.chmod(0o700)
    route = _runtime_route()
    bundle_dir = tmp_path / "tasks" / route.task_id
    bundle_dir.mkdir(mode=0o700, parents=True)
    bundle = bundle_dir / "ledger.sqlite3"
    bundle_db = apsw.Connection(str(bundle))
    bundle_db.execute("PRAGMA foreign_keys = ON")
    bundle_db.execute("PRAGMA trusted_schema = OFF")
    with bundle_db:
        for migration in BUNDLE_MIGRATIONS[:12]:
            bundle_db.execute(migration.ddl.decode("utf-8"))
        bundle_db.execute(
            "INSERT INTO bundle_meta(key,value) VALUES"
            "('task_id',?),('owner_generation','2'),('owner_nonce','fixture_nonce_0001'),"
            "('route_generation','1'),('route_identity_digest',?),"
            "('storage_schema_version','12'),('protocol_version','0.1'),"
            "('import_schema_version','1'),('updated_at',?)",
            (route.task_id, route.route_identity_digest, format_rfc3339_millis(_Clock().now_utc())),
        )
        bundle_db.execute("INSERT INTO counters(name,next_value) VALUES('ingestion_sequence',1)")
    bundle_db.close()
    bundle.chmod(0o600)

    catalog = await open_ready_catalog(
        tmp_path / "catalog.sqlite3",
        installation_id=_INSTALLATION_ID,
        service_generation=2,
        lookup=_Lookup(),
        clock=_Clock(),
        ids=IdPort(),
    )
    catalog_db = catalog._db  # pyright: ignore[reportPrivateUsage]
    catalog_db.execute(
        "INSERT INTO task_routes(task_id,active_session_id,bundle_relpath,route_generation,"
        "active_route_identity_digest,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
        (
            route.task_id,
            route.session_id,
            route.bundle_relpath,
            route.route_generation,
            route.route_identity_digest,
            "active",
            format_rfc3339_millis(_Clock().now_utc()),
            format_rfc3339_millis(_Clock().now_utc()),
        ),
    )

    class _Mac:
        def mac(self, domain: bytes, message: bytes) -> str:
            del domain, message
            return "hmac-sha256:" + "c" * 64

    class _Vault:
        def installation_mac_handle(self, _purpose: object) -> _Mac:
            return _Mac()

        async def load_bundle_keys(self, _task: str) -> BundleKeys:
            return BundleKeys("fixture-slot", cast(WrapKeyHandle, object()), _Mac())

    class _Recovery:
        def __init__(self, _catalog_path: Path, _clock: _Clock) -> None:
            pass

        def inspect(
            self,
            bundle_root: Path,
            *,
            catalog_path: Path,
            task_id: str,
            route_generation: int,
            route_identity_digest: str,
        ) -> object:
            return recovery_module.RecoveryState(
                bundle_root=bundle_root,
                catalog_path=catalog_path,
                task_id=task_id,
                route_generation=route_generation,
                route_identity_digest=route_identity_digest,
                storage_schema_version=14,
                owner_generation=2,
                owner_nonce="fixture_nonce_0001",
                last_verified_frontier=Frontier.genesis(),
                tail_state=recovery_module.RecoveryTailState.CLEAN,
                object_state=recovery_module.RecoveryObjectState.VERIFIED,
                key_state=recovery_module.RecoveryKeyState.READY,
                marker_state=recovery_module.RecoveryMarkerState.ABSENT,
                projection_state=recovery_module.RecoveryProjectionState.CURRENT,
                privacy_root_generation=0,
                privacy_root_digest=canonical_digest(()),
            )

    class _Diagnostics:
        def record(self, result: StartupCheckResult) -> None:
            assert type(result) is StartupCheckResult

    old_recovery_persistence = getattr(ready_composition_module, "_RecoveryPersistence")
    old_install_recovery_persistence = getattr(
        ready_composition_module, "_install_recovery_persistence"
    )
    journal_row: tuple[object, ...] | None = None

    def ignore_recovery(_value: object) -> None:
        return None

    try:
        # The real callback still uses the production temporary fence and effects. The recovery
        # state itself is supplied by an isolated fixture adapter so this test does not mutate a
        # user installation or depend on a preexisting recovery sidecar.
        setattr(ready_composition_module, "_RecoveryPersistence", _Recovery)
        setattr(ready_composition_module, "_install_recovery_persistence", ignore_recovery)
        builder = cast(
            Callable[..., Callable[..., Awaitable[object]]],
            getattr(ready_composition_module, "_build_default_startup_bundle_upgrade"),
        )
        upgrade = builder(
            lifecycle=_StartupLifecycle(),
            vault=_Vault(),  # type: ignore[arg-type]
            config=YoetzConfig(),
            paths=_Paths(tmp_path),
            secret_memory=object(),
        )
        report = await upgrade(
            catalog=catalog,
            bundle_root=tmp_path,
            installation_id=_INSTALLATION_ID,
            service_generation=2,
            vault_generation=2,
            clock=_Clock(),
            ids=IdPort(),
            diagnostics=_Diagnostics(),
        )
        journal_row = catalog_db.execute(
            "SELECT state, phase, backup_manifest_digest FROM maintenance_operations"
        ).fetchone()
    finally:
        setattr(ready_composition_module, "_RecoveryPersistence", old_recovery_persistence)
        setattr(
            ready_composition_module,
            "_install_recovery_persistence",
            old_install_recovery_persistence,
        )
        catalog_db.close(force=True)

    assert type(report) is BundleUpgradeReport
    assert len(report.migrated) == 1
    assert journal_row is not None
    assert journal_row[0:2] == ("complete", "terminal")
    assert type(journal_row[2]) is str and journal_row[2].startswith("sha256:")
    backup_sets = tuple((tmp_path / "backups" / route.task_id).iterdir())
    assert len(backup_sets) == 1
    assert (backup_sets[0] / "backup-manifest.json").is_file()
    inspection = apsw.Connection(str(bundle), flags=apsw.SQLITE_OPEN_READONLY)
    try:
        assert inspection.execute("PRAGMA user_version").fetchone() == (
            BUNDLE_UPGRADE_TARGET_VERSION,
        )
    finally:
        inspection.close(force=True)


@pytest.mark.anyio
async def test_ready_factory_starts_and_reads_repository_bound_setup(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "1" * 64,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "2" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "3" * 64)
    app = None
    try:
        factory = build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=YoetzConfig(),
            paths=_Paths(tmp_path),
            clock=clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        app = await factory(1, vault.generation)
        repository_context = RepositoryPrivacyContext(
            "hmac-sha256:" + "4" * 64,
            "git_common_root",
        )
        setup = await app.privacy_get_setup(
            JsonObject({"schema_version": "2.0.0"}),
            repository_privacy_context=repository_context,
        )
        setup_rpc_id = new_id(IdKind.CONTROL_RPC)
        setup_binding = ControlProjectionBinding(
            rpc_id=setup_rpc_id,
            method=ControlMethod.PRIVACY_GET_SETUP,
            service_instance_id=_INSTANCE_ID,
            service_generation=1,
            original_request_id=None,
            route_identity_digest=None,
            control_request_canonical=canonical_encode(
                {
                    "method": ControlMethod.PRIVACY_GET_SETUP.value,
                    "rpc_id": setup_rpc_id,
                    "service_generation": "1",
                    "service_instance_id": _INSTANCE_ID,
                }
            ),
            repository_privacy_commitment=repository_context.commitment,
        )
        setup_scope = app.disclosure_scope_for(setup_binding, setup)
        assert setup_scope == AuthorizationScope(
            AuthorizationScopeKind.WORKSPACE,
            _INSTALLATION_ID,
            repository_context.commitment,
        )
        assert app.disclosure_scope_for(
            replace(setup_binding, repository_privacy_commitment=None), setup
        ) == AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION_ID)
        projected_setup = await app.project_result_for_client(
            ClientProjectionContext(
                ControlClientKind.CLI,
                ProjectionRenderMode.HUMAN_READABLE,
                True,
            ),
            setup_binding,
            setup,
        )
        assert type(projected_setup) is JsonObject
        projection = cast(dict[str, JsonValue], projected_setup)["privacy_projection"]
        assert isinstance(projection, JsonObject)
        receipt_id = cast(str, projection["local_disclosure_receipt_id"])
        policy_app = app.privacy.policy_application
        assert policy_app is not None
        receipt_view = await policy_app.audit.get_receipt(
            receipt_id, PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL
        )
        assert type(receipt_view) is LocalDisclosureReceiptView
        assert receipt_view.receipt.scope == setup_scope
        # The same receipt must be reachable over ordinary control, not only through the port:
        # the composed support-handler map used to omit both read methods (issue #730).
        fetched = cast(
            dict[str, Any],
            await app.privacy_receipts_get(
                JsonObject({"schema_version": "1.0.0", "receipt_id": receipt_id})
            ),
        )
        assert fetched["outcome"] == "found"
        assert fetched["receipt"]["kind"] == "local_disclosure"
        assert fetched["receipt"]["receipt"]["receipt_id"] == receipt_id
        listed = cast(
            dict[str, Any],
            await app.privacy_receipts_list(
                JsonObject({"schema_version": "1.0.0", "filters": {}, "page_size": 50})
            ),
        )
        assert [item["receipt"]["receipt_id"] for item in listed["receipts"]] == [receipt_id]
        request = StartRequest.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": "req_00000000-0000-4000-8000-000000000003",
                "mode": "create",
                "task_title": "Make documentation fully consistent",
                "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
                "client": {
                    "kind": "codex_cli",
                    "version": "0.144.6",
                    "integration": "local_cli",
                },
                "requested_view": "compact",
            }
        )
        result = await app.start(
            request,
            repository_privacy_context=repository_context,
        )
        rpc_id = new_id(IdKind.CONTROL_RPC)
        facts = await app.projection_binding_facts(ControlMethod.START, request, result)
        binding = ControlProjectionBinding(
            rpc_id=rpc_id,
            method=ControlMethod.START,
            service_instance_id=_INSTANCE_ID,
            service_generation=1,
            original_request_id=facts.original_request_id,
            route_identity_digest=facts.route_identity_digest,
            control_request_canonical=canonical_encode(
                {
                    "method": ControlMethod.START.value,
                    "rpc_id": rpc_id,
                    "service_generation": "1",
                    "service_instance_id": _INSTANCE_ID,
                }
            ),
        )
        projected = await app.project_result_for_client(
            ClientProjectionContext.fail_safe(ControlClientKind.CLI),
            binding,
            result,
        )

        assert setup["grant_state"] == "missing"
        bound_scope = cast(JsonObject, setup["bound_scope"])
        assert bound_scope["workspace_ref_commitment"] == repository_context.commitment
        assert result.ok is True
        assert result.outcome == "created"
        assert result.frontier.sequence == "1"
        route = await app.start_catalog.task_route(result.task_id)
        assert route is not None
        assert route.repository_privacy_commitment == repository_context.commitment
        # The runtime cache retains the inspected route after START releases its lease.  This
        # checks the production provision callback carried the catalog authority through the
        # command instead of rebuilding a route with default metadata.
        entries = cast(dict[str, object], getattr(app.runtime, "_entries"))
        entry = entries[result.task_id]
        inspection = cast(object, getattr(entry, "inspection"))
        inspected_route = cast(object, getattr(inspection, "route"))
        assert getattr(inspected_route, "repository_privacy_commitment") == (
            repository_context.commitment
        )
        verified_routes, replayed_events, verified_objects = await app.verify_recovery_candidate()
        assert verified_routes == 1
        assert replayed_events >= 1
        assert verified_objects >= 1
        assert isinstance(projected, StartResult)
        assert projected.root.ok is True
        assert projected.root.request_id == request.request_id
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()


def _bundle_meta(tmp_path: Path, task_id: str) -> dict[str, str]:
    ledger = tmp_path / "tasks" / task_id / "ledger.sqlite3"
    db = apsw.Connection(
        f"file:{ledger}?mode=ro", flags=apsw.SQLITE_OPEN_URI | apsw.SQLITE_OPEN_READONLY
    )
    try:
        rows = db.execute("SELECT key, value FROM bundle_meta").fetchall()
    finally:
        db.close(force=True)
    return {cast(str, row[0]): cast(str, row[1]) for row in rows}


@pytest.mark.anyio
async def test_create_then_attach_same_service_generation_advances_owner_once(
    tmp_path: Path,
) -> None:
    """create then attach in one service generation must succeed and advance ownership once.

    Regression for issue #126 / postmortem 019fc8b8: same-generation attach rewrote owner
    metadata then failed with recovery_generation_not_advanced, poisoning the runtime cache.
    """

    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "a" * 64,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "b" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "c" * 64)
    app = None
    try:
        factory = build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=YoetzConfig(),
            paths=_Paths(tmp_path),
            clock=clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        app = await factory(1, vault.generation)
        common = {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
            "client": {
                "kind": "codex_cli",
                "version": "0.144.6",
                "integration": "local_cli",
            },
            "requested_view": "compact",
            "task_title": "Resume ownership regression",
            "workspace_ref": "https://github.com/example/yoetz-core.git",
            "external_ref": "plan/fix-resumption-ownership",
        }
        created = await app.start(
            StartRequest.model_validate(
                {
                    **common,
                    "request_id": "req_00000000-0000-4000-8000-000000000201",
                    "mode": "create",
                }
            )
        )
        assert created.ok is True
        assert created.outcome == "created"
        after_create = _bundle_meta(tmp_path, created.task_id)
        assert after_create["owner_generation"] == "1"

        attached = await app.start(
            StartRequest.model_validate(
                {
                    **common,
                    "request_id": "req_00000000-0000-4000-8000-000000000202",
                    "mode": "attach",
                    "session_id": created.session_id,
                }
            )
        )
        assert attached.ok is True
        assert attached.outcome == "attached"
        assert attached.task_id == created.task_id
        assert attached.session_id != created.session_id
        assert attached.writer_id != created.writer_id

        after_attach = _bundle_meta(tmp_path, created.task_id)
        # Rebind keeps the create-time fence: ownership advanced exactly once from the fresh "0".
        assert after_attach["owner_generation"] == "1"
        assert after_attach["owner_nonce"] == after_create["owner_nonce"]
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()


@pytest.mark.anyio
@pytest.mark.timeout(20)
async def test_ready_lineage_bootstraps_exact_durable_host_session_route(
    tmp_path: Path,
) -> None:
    """READY recovery scopes an open host operation to the current reattached session."""

    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "1" * 64,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "2" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "3" * 64)
    app = None
    recomposed_lifecycle: ServiceLifecycle | None = None
    try:
        factory = build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=YoetzConfig(),
            paths=_Paths(tmp_path),
            clock=clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        app = await factory(1, vault.generation)
        common = {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
            "client": {
                "kind": "codex_cli",
                "version": "0.144.6",
                "integration": "local_cli",
            },
            "requested_view": "compact",
            "task_title": "READY host session bootstrap regression",
            "workspace_ref": "https://github.com/example/yoetz-core.git",
            "external_ref": "plan/ready-host-session-bootstrap",
        }
        first = await app.start(
            StartRequest.model_validate(
                {
                    **common,
                    "request_id": "req_00000000-0000-4000-8000-000000000231",
                    "mode": "create",
                }
            )
        )
        second = await app.start(
            StartRequest.model_validate(
                {
                    **common,
                    "request_id": "req_00000000-0000-4000-8000-000000000232",
                    "mode": "attach",
                    "session_id": first.session_id,
                }
            )
        )
        assert first.ok is True and second.ok is True
        assert first.task_id == second.task_id
        assert first.session_id != second.session_id
        assert first.writer_id != second.writer_id

        host_session_id = "ready-native-subagent-start"
        local = LocalObservationStore(_state=tmp_path / "state")
        workspace = local.workspace_commitment(str(tmp_path.resolve()))
        local.grant_consent(workspace)
        current_host_session = local.bind_codex_session(workspace, host_session_id)
        store_mapping(
            mapping_from_start_ids(
                codex_session_id=host_session_id,
                yoetz_task_id=second.task_id,
                yoetz_session_id=second.session_id,
                yoetz_writer_id=second.writer_id,
                last_frontier=None,
            ),
            _state=tmp_path / "state",
        )
        # Feed the first native SubagentStart through the production coordinator. Its admission
        # path must persist the host route before optional verification/advice work, so the next
        # READY generation can bootstrap from this row without a process-local cache or a manual
        # route write.
        envelope = ObservationEnvelope(
            session_commitment=current_host_session,
            event_kind="SubagentStart",
            source_identity="hook:ready-native-subagent-start",
            source=ObservationSource.CODEX_HOOK,
            cursor=ObservationCursor(1, 0, 1, current_host_session, "codex-obs-hook/1.0.0"),
            receipt_time=timestamp_from_datetime(clock.now_utc()),
            structural_payload=JsonObject({}),
            content_object_refs=(),
            gap_codes=(),
        )
        ingest = app.support_handlers[ControlMethod.OBSERVATION_INGEST]
        ingest_result = await ingest(
            observation_ingest_request_to_json(
                ObservationIngestRequest(codex_session_id=host_session_id, envelope=envelope)
            )
        )
        assert ingest_result["disposition"] == "accepted", ingest_result

        # Recompose the application so the lookup closure and lineage process cache are fresh.
        await app.close()
        await lifecycle.close()
        recomposed_lifecycle = ServiceLifecycle(
            clock,
            generation_store=_GenerationStore(),
            process_start_identity_commitment="sha256:" + "1" * 64,
            instance_id=_INSTANCE_ID,
            singleton_lock_path=tmp_path / "singleton.lock",
        )
        await recomposed_lifecycle.acquire_singleton()
        await recomposed_lifecycle.transition(ServiceState.LOCKED)
        recomposed_factory = build_ready_application_factory(
            lifecycle=recomposed_lifecycle,
            vault=vault,
            config=YoetzConfig(),
            paths=_Paths(tmp_path),
            clock=clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        app = await recomposed_factory(1, vault.generation)

        lineage = app.lineage
        assert lineage is not None
        lookup = getattr(lineage, "_host_session_commitment_lookup", None)
        assert callable(lookup)
        lookup_fn = cast(Callable[[str, str], Awaitable[str | None]], lookup)
        assert await lookup_fn(second.task_id, second.session_id) == current_host_session
        assert await lookup_fn(second.task_id, first.session_id) is None

        predecessor_host_session = "hmac-sha256:" + "a" * 64
        registry = app.host_lineage_registry
        assert registry is not None
        predecessor_start = host_lineage_from_payload(
            "codex", "SubagentStart", {"subagent_id": "worker-predecessor"}
        )
        assert predecessor_start is not None
        await registry.record_host_lineage_observation(
            first.task_id,
            predecessor_start,
            observed_session_commitment=predecessor_host_session,
            source=ObservationSource.CODEX_HOOK,
        )

        await lineage.mark_contact_lost(session_id=second.session_id)
        renewed: list[tuple[str, str, datetime]] = []

        async def renew(task_id: str, session_id: str, lease_until: datetime) -> None:
            renewed.append((task_id, session_id, lease_until))

        # The only open annotation belongs to the predecessor host session, so the current
        # reattached session cannot inherit its hold.
        assert await lineage.hold_in_flight_contact(renew) == ()
        assert renewed == []

        current_start = host_lineage_from_payload(
            "codex", "SubagentStart", {"subagent_id": "worker-current"}
        )
        assert current_start is not None
        await registry.record_host_lineage_observation(
            second.task_id,
            current_start,
            observed_session_commitment=current_host_session,
            source=ObservationSource.CODEX_HOOK,
        )
        assert await lineage.hold_in_flight_contact(renew) == (second.task_id,)
        assert renewed and renewed[0][1] == second.session_id
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        if recomposed_lifecycle is not None:
            await recomposed_lifecycle.close()
        await lifecycle.close()


@pytest.mark.anyio
async def test_attach_failure_before_ownership_commit_leaves_meta_and_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reopen-path ownership failure must not rewrite bundle_meta or strand the task."""

    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "d" * 64,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "e" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "f" * 64)
    app = None
    try:
        factory = build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=YoetzConfig(),
            paths=_Paths(tmp_path),
            clock=clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        app = await factory(1, vault.generation)
        common = {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
            "client": {
                "kind": "codex_cli",
                "version": "0.144.6",
                "integration": "local_cli",
            },
            "requested_view": "compact",
            "task_title": "Ownership failure atomicity",
            "workspace_ref": "https://github.com/example/yoetz-core.git",
            "external_ref": "plan/ownership-failure-atomicity",
        }
        created = await app.start(
            StartRequest.model_validate(
                {
                    **common,
                    "request_id": "req_00000000-0000-4000-8000-000000000211",
                    "mode": "create",
                }
            )
        )
        before = _bundle_meta(tmp_path, created.task_id)

        # Force close-then-reopen rather than same-bundle rebind: close the cached entry.
        runtime = app.runtime
        entries = cast(dict[str, object], getattr(runtime, "_entries"))
        entry = entries.pop(created.task_id)
        setattr(entry, "poisoned", True)
        close_entry = cast(
            Callable[[object], Awaitable[None]],
            getattr(runtime, "_close_entry"),
        )
        await close_entry(entry)

        backend = recovery_module._backend()  # pyright: ignore[reportPrivateUsage]
        original = backend.acquire_ownership

        def _failing_acquire(
            state: object,
            *,
            service_instance_id: str,
            service_generation: int,
            owner_nonce: str,
            now: datetime,
        ) -> int:
            del state, service_instance_id, service_generation, owner_nonce, now
            raise ValueError("injected_acquire_failure")

        monkeypatch.setattr(backend, "acquire_ownership", _failing_acquire)
        with pytest.raises(ValueError, match="injected_acquire_failure"):
            await app.start(
                StartRequest.model_validate(
                    {
                        **common,
                        "request_id": "req_00000000-0000-4000-8000-000000000212",
                        "mode": "attach",
                        "session_id": created.session_id,
                    }
                )
            )
        monkeypatch.setattr(backend, "acquire_ownership", original)

        after = _bundle_meta(tmp_path, created.task_id)
        assert after["owner_generation"] == before["owner_generation"]
        assert after["owner_nonce"] == before["owner_nonce"]
        assert after["updated_at"] == before["updated_at"]

        # Original ownership still admits a successful attach once the injection is removed.
        recovered = await app.start(
            StartRequest.model_validate(
                {
                    **common,
                    "request_id": "req_00000000-0000-4000-8000-000000000213",
                    "mode": "attach",
                    "session_id": created.session_id,
                }
            )
        )
        assert recovered.ok is True
        assert recovered.outcome == "attached"
        assert recovered.task_id == created.task_id
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()


@pytest.mark.anyio
async def test_stale_recovery_state_cas_loser_mutates_nothing(tmp_path: Path) -> None:
    """Two interleaved stale RecoveryState snapshots: exactly one CAS wins."""

    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "11" * 32,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "22" * 32,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "33" * 32)
    app = None
    try:
        factory = build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=YoetzConfig(),
            paths=_Paths(tmp_path),
            clock=clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        app = await factory(1, vault.generation)
        created = await app.start(
            StartRequest.model_validate(
                {
                    "protocol_version": "0.1",
                    "schema_version": "1.0.0",
                    "request_id": "req_00000000-0000-4000-8000-000000000221",
                    "mode": "create",
                    "task_title": "CAS interleaving",
                    "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
                    "client": {
                        "kind": "codex_cli",
                        "version": "0.144.6",
                        "integration": "local_cli",
                    },
                    "requested_view": "compact",
                }
            )
        )
        before = _bundle_meta(tmp_path, created.task_id)
        backend = cast(
            ready_composition_module._RecoveryPersistence,  # pyright: ignore[reportPrivateUsage]
            recovery_module._backend(),  # pyright: ignore[reportPrivateUsage]
        )
        ledger = tmp_path / "tasks" / created.task_id
        state = cast(
            recovery_module.RecoveryState,
            backend.inspect(
                ledger,
                catalog_path=tmp_path / "catalog.sqlite3",
                task_id=created.task_id,
                route_generation=int(before["route_generation"], 10),
                route_identity_digest=before["route_identity_digest"],
            ),
        )
        stale = replace(
            state,
            owner_generation=int(before["owner_generation"], 10),
            owner_nonce=before["owner_nonce"],
        )
        winner = backend.acquire_ownership(
            stale,
            service_instance_id=_INSTANCE_ID,
            service_generation=1,
            owner_nonce="winner-owner-nonce-0000001",
            now=clock.now_utc(),
        )
        assert winner == int(before["owner_generation"], 10) + 1
        mid = _bundle_meta(tmp_path, created.task_id)
        assert mid["owner_generation"] == str(winner)
        assert mid["owner_nonce"] == "winner-owner-nonce-0000001"

        with pytest.raises(ValueError, match="recovery_ownership_conflict"):
            backend.acquire_ownership(
                stale,
                service_instance_id=_INSTANCE_ID,
                service_generation=1,
                owner_nonce="loser-owner-nonce-00000001",
                now=clock.now_utc(),
            )
        after = _bundle_meta(tmp_path, created.task_id)
        assert after["owner_generation"] == mid["owner_generation"]
        assert after["owner_nonce"] == mid["owner_nonce"]
        assert after["updated_at"] == mid["updated_at"]
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()


@pytest.mark.anyio
async def test_ready_factory_completes_and_projects_deterministic_check(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "7" * 64,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "8" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "9" * 64)
    app = None
    try:
        factory = build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=YoetzConfig(),
            paths=_Paths(tmp_path),
            clock=clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        app = await factory(1, vault.generation)
        object.__setattr__(app, "enforce_repository_identity", False)
        common = {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
        }
        start_request = StartRequest.model_validate(
            {
                **common,
                "request_id": "req_00000000-0000-4000-8000-000000000101",
                "mode": "create",
                "task_title": "Exercise the ready check path",
                "requested_view": "compact",
            }
        )
        started = await app.start(start_request)
        assert started.ok is True
        frontier = started.frontier

        batches: tuple[tuple[str, list[JsonValue]], ...] = (
            (
                "req_00000000-0000-4000-8000-000000000102",
                [
                    {
                        "event_id": "evt_00000000-0000-4000-8000-000000000201",
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                        "occurred_at": "2026-07-21T18:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "plan_version": 1,
                            "summary": "Exercise the ready composition through a closed check.",
                            "obligation_refs": [],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            ),
            (
                "req_00000000-0000-4000-8000-000000000103",
                [
                    {
                        "event_id": "evt_00000000-0000-4000-8000-000000000202",
                        "schema": {"name": "action_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-21T18:01:00.000Z",
                        "causal_parents": ["evt_00000000-0000-4000-8000-000000000201"],
                        "payload": {
                            "action_id": "act_00000000-0000-4000-8000-000000000201",
                            "action_kind": "review",
                            "description": "Ran the ready-composition acceptance path.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    {
                        "event_id": "evt_00000000-0000-4000-8000-000000000203",
                        "schema": {"name": "result_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-21T18:02:00.000Z",
                        "causal_parents": ["evt_00000000-0000-4000-8000-000000000202"],
                        "payload": {
                            "result_id": "res_00000000-0000-4000-8000-000000000201",
                            "action_id": "act_00000000-0000-4000-8000-000000000201",
                            "outcome": "success",
                            "summary": "The bounded acceptance path completed.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            ),
            (
                "req_00000000-0000-4000-8000-000000000104",
                [
                    {
                        "event_id": "evt_00000000-0000-4000-8000-000000000204",
                        "schema": {"name": "evidence_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-21T18:03:00.000Z",
                        "causal_parents": ["evt_00000000-0000-4000-8000-000000000203"],
                        "payload": {
                            "evidence_id": "evd_00000000-0000-4000-8000-000000000201",
                            "evidence_kind": "test_result",
                            "strength": "metadata_only",
                            "observed_at": "2026-07-21T18:03:00.000Z",
                            "description": "Ready-composition regression coverage.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    {
                        "event_id": "evt_00000000-0000-4000-8000-000000000205",
                        "schema": {"name": "claim_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-07-21T18:04:00.000Z",
                        "causal_parents": ["evt_00000000-0000-4000-8000-000000000204"],
                        "payload": {
                            "claim_id": "clm_00000000-0000-4000-8000-000000000201",
                            "claim_kind": "completion",
                            "statement": "The ready-composition check path completed.",
                            "supporting_refs": ["evd_00000000-0000-4000-8000-000000000201"],
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            ),
        )
        for request_id, event_drafts in batches:
            publish_request = PublishWorkRequest.model_validate(
                {
                    **common,
                    "request_id": request_id,
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": {
                        "sequence": str(frontier.sequence),
                        "head_digest": frontier.head_digest,
                    },
                    "event_drafts": event_drafts,
                }
            )
            published = await app.publish_work(publish_request)
            assert published.ok is True
            frontier = published.result_frontier

        check_request = CheckRequest.model_validate(
            {
                **common,
                "request_id": "req_00000000-0000-4000-8000-000000000105",
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": {
                    "sequence": str(frontier.sequence),
                    "head_digest": frontier.head_digest,
                },
                "mode": "deterministic_only",
                "max_findings": "3",
                "policy_packs": ["work-integrity/0.3.0"],
            }
        )
        checked = await app.check(check_request)
        assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
        assert checked.outcome == "committed"
        assert checked.verdict.value in {
            "action_required",
            "insufficient_coverage",
            "no_issue_detected",
        }

        rpc_id = new_id(IdKind.CONTROL_RPC)
        facts = await app.projection_binding_facts(ControlMethod.CHECK, check_request, checked)
        projected = await app.project_result_for_client(
            ClientProjectionContext.fail_safe(ControlClientKind.MCP_BRIDGE),
            ControlProjectionBinding(
                rpc_id=rpc_id,
                method=ControlMethod.CHECK,
                service_instance_id=_INSTANCE_ID,
                service_generation=1,
                original_request_id=facts.original_request_id,
                route_identity_digest=facts.route_identity_digest,
                control_request_canonical=canonical_encode(
                    {
                        "method": ControlMethod.CHECK.value,
                        "rpc_id": rpc_id,
                        "service_generation": "1",
                        "service_instance_id": _INSTANCE_ID,
                    }
                ),
            ),
            checked,
        )
        assert isinstance(projected, CheckResult)
        validated = CheckResult.model_validate(
            projected.model_dump(mode="json", by_alias=True, exclude_unset=True)
        )
        assert validated.root.ok is True
        assert type(validated.root) is CheckSuccessModel
        assert validated.root.verdict == checked.verdict.value
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()


@pytest.mark.anyio
async def test_daemon_unlock_installs_real_application_and_dispatches_start(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "4" * 64,
        instance_id=_INSTANCE_ID,
    )
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "5" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "6" * 64)
    await vault.lock()
    diagnostics = _Diagnostics()
    factory = build_ready_application_factory(
        lifecycle=lifecycle,
        vault=vault,
        config=YoetzConfig(),
        paths=_Paths(tmp_path),
        clock=clock,
        secret_memory=memory,
        diagnostics=diagnostics,
    )
    daemon = ServiceDaemon(
        _composition=ServiceComposition(
            lifecycle=lifecycle,
            control_listener=_Listener(),  # pyright: ignore[reportArgumentType]
            secret_ingress_listener=None,
            human_control_listener=None,
            human_control_service=None,
            session_monitor=None,
            vault=vault,
            ready_application_factory=factory,  # pyright: ignore[reportArgumentType]
            secret_memory=memory,
            diagnostics=diagnostics,
        )
    )
    try:
        await daemon.start()
        assert daemon.status().state is ServiceState.LOCKED
        await lifecycle.transition(ServiceState.UNLOCKING)
        unlock = memory.capture(SecretPurpose.VAULT_UNLOCK, bytearray(b"correct horse battery"))
        await vault.unlock(unlock)
        await daemon.activate_ready_application(1, vault.generation)

        instance = daemon.composition.lifecycle.instance
        body = StartRequest.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": "req_00000000-0000-4000-8000-000000000004",
                "mode": "create",
                "task_title": "Make documentation fully consistent",
                "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
                "client": {
                    "kind": "codex_cli",
                    "version": "0.144.6",
                    "integration": "local_cli",
                },
                "requested_view": "compact",
            }
        )
        result = await daemon.dispatch(
            ControlClientKind.CLI,
            ControlCallRequest(
                kind="call",
                protocol_version="1.0",
                rpc_id=new_id(IdKind.CONTROL_RPC),
                service_instance_id=instance.instance_id,
                service_generation=str(instance.generation),
                method=ControlMethod.START,
                body=body,
            ),
        )

        assert result.outcome == "ok"
        assert isinstance(result.body, StartResult)
        assert result.body.root.ok is True
        assert result.body.root.request_id == body.request_id
        assert daemon.status().state is ServiceState.READY
    finally:
        await daemon.close()


@pytest.mark.anyio
async def test_ready_factory_deterministic_check_records_semantic_not_requested_gap(
    tmp_path: Path,
) -> None:
    """Local-only checks under ready composition advertise the not-requested gap."""

    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "a" * 64,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "b" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "c" * 64)
    app = None
    try:
        factory = build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=YoetzConfig(),
            paths=_Paths(tmp_path),
            clock=clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        app = await factory(1, vault.generation)
        object.__setattr__(app, "enforce_repository_identity", False)
        common = {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
        }
        started = await app.start(
            StartRequest.model_validate(
                {
                    **common,
                    "request_id": "req_00000000-0000-4000-8000-000000000201",
                    "mode": "create",
                    "task_title": "AI-powered review gap under ready composition",
                    "requested_view": "compact",
                }
            )
        )
        assert started.ok is True
        frontier = started.frontier
        published = await app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **common,
                    "request_id": "req_00000000-0000-4000-8000-000000000202",
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": {
                        "sequence": str(frontier.sequence),
                        "head_digest": frontier.head_digest,
                    },
                    "event_drafts": [
                        {
                            "event_id": "evt_00000000-0000-4000-8000-000000000301",
                            "schema": {"name": "plan_published", "version": "1.0.0"},
                            "occurred_at": "2026-07-24T12:00:00.000Z",
                            "causal_parents": [],
                            "payload": {
                                "plan_version": 1,
                                "summary": "AI-powered review gap path.",
                                "obligation_refs": [],
                            },
                            "artifact_refs": [],
                            "evidence_refs": [],
                        }
                    ],
                }
            )
        )
        assert published.ok is True
        frontier = published.result_frontier
        checked = await app.check(
            CheckRequest.model_validate(
                {
                    **common,
                    "request_id": "req_00000000-0000-4000-8000-000000000203",
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": {
                        "sequence": str(frontier.sequence),
                        "head_digest": frontier.head_digest,
                    },
                    "mode": "deterministic_only",
                    "max_findings": "3",
                    "policy_packs": ["work-integrity/0.3.0"],
                }
            )
        )
        assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
        assert checked.outcome == "committed"
        assert "semantic_review_not_requested" in checked.coverage.known_gaps
        assert checked.semantic_status.value == "not_requested"
        assert checked.semantic_reason.value == "deterministic_mode"

        # An omitted mode must resolve through VerificationPolicy.default_check_mode. The default
        # config is semantic="optional" -> semantic_if_configured, so the outcome is
        # "not configured" rather than "not requested"; the latter would prove the omission had
        # silently fallen back to deterministic_only.
        frontier = checked.result_frontier
        resolved = await app.check(
            CheckRequest.model_validate(
                {
                    **common,
                    "request_id": "req_00000000-0000-4000-8000-000000000204",
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": {
                        "sequence": str(frontier.sequence),
                        "head_digest": frontier.head_digest,
                    },
                    "max_findings": "3",
                    "policy_packs": ["work-integrity/0.3.0"],
                }
            )
        )
        assert type(resolved) is CheckCommitResult, (
            f"unexpected nonterminal check: {type(resolved)}"
        )
        assert resolved.outcome == "committed"
        assert resolved.semantic_status.value == "not_configured"
        assert resolved.semantic_reason.value == "provider_not_configured"
        assert "semantic_review_not_requested" not in resolved.coverage.known_gaps

        # The exact r4 dogfood request: semantic_required against an installation with no bound
        # provider. SEMANTIC is now advertised whenever AI-powered review is not disabled, so this path
        # advances through SEMANTIC_WAIT; it must still commit an honest incomplete check rather
        # than erroring or reporting a clean local pass.
        frontier = resolved.result_frontier
        required = await app.check(
            CheckRequest.model_validate(
                {
                    **common,
                    "request_id": "req_00000000-0000-4000-8000-000000000205",
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": {
                        "sequence": str(frontier.sequence),
                        "head_digest": frontier.head_digest,
                    },
                    "mode": "semantic_required",
                    "max_findings": "3",
                    "policy_packs": ["work-integrity/0.3.0"],
                }
            )
        )
        assert type(required) is CheckCommitResult, (
            f"unexpected nonterminal check: {type(required)}"
        )
        assert required.outcome == "committed"
        assert required.semantic_status.value == "not_configured"
        assert required.semantic_reason.value == "provider_not_configured"
        assert required.verdict.value == "incomplete_check"

        # Issue #185: the stop-rule fallback. An agent whose AI-powered review attempt the environment
        # refused re-checks with deterministic_only, and that successor replaces
        # latest_tested_state wholesale. Without the carry-forward the only surviving disclosure
        # is semantic_review_not_requested, which reads as the agent never having asked.
        frontier = required.result_frontier
        fallback = await app.check(
            CheckRequest.model_validate(
                {
                    **common,
                    "request_id": "req_00000000-0000-4000-8000-000000000206",
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": {
                        "sequence": str(frontier.sequence),
                        "head_digest": frontier.head_digest,
                    },
                    "mode": "deterministic_only",
                    "max_findings": "3",
                    "policy_packs": ["work-integrity/0.3.0"],
                }
            )
        )
        assert type(fallback) is CheckCommitResult, (
            f"unexpected nonterminal check: {type(fallback)}"
        )
        assert fallback.outcome == "committed"
        assert fallback.semantic_status.value == "not_requested"
        assert "semantic_review_not_requested" in fallback.coverage.known_gaps
        assert "semantic_review_not_configured" in fallback.coverage.known_gaps
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()


@pytest.mark.anyio
async def test_ready_composition_reports_exact_configured_credential_presence(
    tmp_path: Path,
) -> None:
    """Status can read exact vault presence without inventing repository authority."""

    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "d" * 64,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "e" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "f" * 64)
    provider = fireworks_provider(model="accounts/fireworks/models/minimax-m3")
    config = YoetzConfig(profile="local-openai", provider=provider)

    def application_factory(provider_config: YoetzConfig):
        return build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=provider_config,
            paths=_Paths(tmp_path),
            clock=clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )

    app = None
    try:
        app = await application_factory(config)(1, vault.generation)
        assert app.provider_credential_connected is False
        await app.close()
        app = None

        credential_binding = provider_credential_profile_binding(
            provider.provider_id,
            provider.model,
            provider.endpoint_profile_id,
            provider.endpoint_profile_version,
        )
        proof = HumanAuthorizationProof(
            "provider-proof-before-recomposition",
            "provider_credential_set",
            credential_binding.target_digest("set"),
            1,
            vault.generation,
            None,
            1.0,
            60.0,
        )
        credential = memory.capture(
            SecretPurpose.PROVIDER_CREDENTIAL,
            bytearray(b"test-provider-token-for-status"),
        )
        await vault.store_provider_credential("set", credential_binding, credential, proof, 2.0)

        app = await application_factory(config)(1, vault.generation)
        assert app.provider_credential_connected is True
        await app.close()
        app = None

        other_provider = fireworks_provider(model="accounts/fireworks/models/a-different-model")
        other_config = YoetzConfig(profile="local-openai", provider=other_provider)
        app = await application_factory(other_config)(1, vault.generation)
        assert app.provider_credential_connected is False
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()


@pytest.mark.anyio
@pytest.mark.parametrize("provider_bound", [False, True])
@pytest.mark.parametrize("review_enabled", [False, True])
async def test_observation_provider_fact_tracks_live_credential_within_one_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider_bound: bool,
    review_enabled: bool,
) -> None:
    """The standing-advice provider fact follows the vault, not the READY snapshot (#265).

    The incident session was advised connect_provider at Stop right after a
    successful AI-powered review dispatch because the advice fact froze
    ``semantic_ready=False`` at composition. The fact source must observe a
    credential stored or discarded mid-generation without recomposition, and
    must not fire the advice from registry lag alone.
    """

    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "d" * 64,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "e" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "f" * 64)
    provider = fireworks_provider(model="accounts/fireworks/models/minimax-m3")
    config = YoetzConfig(
        profile="local-openai" if provider_bound else "strict-local",
        provider=provider if provider_bound else None,
        verification=VerificationConfig(semantic="required" if review_enabled else "disabled"),
    )
    factory = build_ready_application_factory(
        lifecycle=lifecycle,
        vault=vault,
        config=config,
        paths=_Paths(tmp_path),
        clock=clock,
        secret_memory=memory,
        diagnostics=_Diagnostics(),
    )

    def provider_rules(fact: object) -> set[str]:
        assert type(fact) is ObservationCompositionFact
        return {
            item.rule_code
            for item in observation_advice_findings(
                ObservationAdviceContext(
                    envelopes=(),
                    lifecycle=ObservationLifecycle.ACTIVE,
                    gaps=(),
                    composition=fact,
                )
            )
        }

    app = None
    try:
        context = await factory.context_provider(1, vault.generation)
        assert context.rediscover_pending_verification is not None
        coordinator: object = getattr(context.rediscover_pending_verification, "__self__")
        builder_composition: object = getattr(coordinator, "advice_context_builder").composition
        assert callable(builder_composition), "the advice provider fact must be sourced per build"
        composition = cast(
            Callable[[], Awaitable[ObservationCompositionFact | None]], builder_composition
        )
        app = await factory.open(context)

        # The actual default machine policy permits update checks, not LLM review.
        # Required verification (including absent config's default) is not intent.
        baseline = await composition()
        assert type(baseline) is ObservationCompositionFact
        assert baseline.semantic_configured is False
        assert provider_rules(baseline) == set()
        policy_app = app.privacy.policy_application
        assert policy_app is not None
        current_policy = replace(
            minimal_external_policy(),
            effective_scope=AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION_ID),
        )

        async def effective_policy(
            store: object, scope: AuthorizationScope
        ) -> EffectivePrivacyPolicy:
            assert store is policy_app.policy_store
            assert scope == current_policy.effective_scope
            return EffectivePrivacyPolicy(current_policy, 2, current_policy.policy_digest)

        monkeypatch.setattr(type(policy_app.policy_store), "effective_policy", effective_policy)
        intended = provider_bound and review_enabled

        # Genuinely missing credential: the advice stays visible.
        fact = await composition()
        assert type(fact) is ObservationCompositionFact
        assert fact.semantic_configured is intended
        assert fact.semantic_ready is False
        assert ("provider_not_ready" in provider_rules(fact)) is intended

        # Credential ceremony lands mid-generation: the next build sees it and
        # the connect_provider recommendation becomes inapplicable, even though
        # the lazy connected registry has still never listed the provider.
        credential_binding = provider_credential_profile_binding(
            provider.provider_id,
            provider.model,
            provider.endpoint_profile_id,
            provider.endpoint_profile_version,
        )
        proof = HumanAuthorizationProof(
            "provider-proof-mid-generation",
            "provider_credential_set",
            credential_binding.target_digest("set"),
            1,
            vault.generation,
            None,
            1.0,
            60.0,
        )
        credential = memory.capture(
            SecretPurpose.PROVIDER_CREDENTIAL,
            bytearray(b"test-provider-token-mid-generation"),
        )
        await vault.store_provider_credential("set", credential_binding, credential, proof, 2.0)

        connected = await composition()
        assert type(connected) is ObservationCompositionFact
        assert connected.semantic_ready is provider_bound
        assert "fireworks" not in connected.connected_provider_ids
        assert provider_rules(connected) == set()

        # Revocation resurfaces the advice from current evidence.
        await vault.discard_provider_credential(credential_binding)
        revoked = await composition()
        assert type(revoked) is ObservationCompositionFact
        assert revoked.semantic_ready is False
        assert ("provider_not_ready" in provider_rules(revoked)) is intended

        # A policy tightening in the same generation immediately silences repair
        # advice, even with a configured provider and now-revoked credential.
        current_policy = replace(
            local_only_policy(), effective_scope=current_policy.effective_scope
        )
        private = await composition()
        assert type(private) is ObservationCompositionFact
        assert private.semantic_configured is False
        assert provider_rules(private) == set()

        async def unavailable_policy(
            store: object, scope: AuthorizationScope
        ) -> EffectivePrivacyPolicy:
            raise RuntimeError("policy unavailable")

        monkeypatch.setattr(type(policy_app.policy_store), "effective_policy", unavailable_policy)
        assert await composition() is None
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()


class _AdviceStore:
    """The observation-store slice the advice builder and scheduler touch (#923)."""

    def __init__(self, repository: object, workspace: str) -> None:
        self.repository = repository
        self.workspace = workspace
        self.failures = 1

    def list_envelopes(self, workspace: str) -> tuple[ObservationEnvelope, ...]:
        assert workspace == self.workspace
        return tuple(
            ObservationEnvelope(
                session_commitment=self.workspace,
                event_kind="PostToolUse",
                source_identity=f"hook:fail-{index}",
                source=ObservationSource.CODEX_HOOK,
                cursor=ObservationCursor(
                    source_generation=1,
                    byte_position=(index + 1) * 8,
                    event_position=index + 1,
                    last_source_commitment=self.workspace,
                    mapping_version="codex-obs-hook/1.0.0",
                ),
                receipt_time=timestamp_from_datetime(_Clock().now_utc()),
                structural_payload=JsonObject(
                    {
                        "tool_name": "shell",
                        "exit_status": 1,
                        "correlation_id": f"hook:fail-{index}",
                    }
                ),
                content_object_refs=(),
                gap_codes=(),
            )
            for index in range(self.failures)
        )

    async def status(self, query: ObservationStatusQuery) -> ObservationStatus:
        assert query.workspace_commitment == self.workspace
        return ObservationStatus(
            ObservationLifecycle.ACTIVE,
            self.workspace,
            {},
            timestamp_from_datetime(_Clock().now_utc()),
            0,
            (),
            (),
            None,
        )

    def load_advice_snapshot(self, workspace: str) -> None:
        return None

    def advice_semantic_repository(self) -> object:
        return self.repository


@pytest.mark.anyio
@pytest.mark.parametrize("provider_bound", [False, True])
async def test_background_advice_is_admitted_only_while_a_provider_is_usable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider_bound: bool,
) -> None:
    """Arm B of #923: required review, no provider, no LLM egress wrote a row per candidate.

    The real composition must write no advice row and report no pending gap while no provider
    is usable, drain rows an older service queued without provider work, admit advice once the
    provider, credential and channel are all live, and stop again when any one goes away, all
    within one service generation.
    """

    from yoetz.adapters.sqlite.migrations import initialize_bundle
    from yoetz.adapters.sqlite.observation_advice_semantic import (
        SqliteObservationAdviceSemanticRepository,
    )
    from yoetz.application.observation_advice import (
        ADVICE_SEMANTIC_PENDING_GAP,
        ADVICE_SEMANTIC_UNAVAILABLE_GAP,
        ObservationAdviceContextBuilder,
    )
    from yoetz.application.observation_advice_semantic import (
        ObservationAdviceSemanticAttempt,
        ObservationAdviceSemanticOutcome,
        ObservationAdviceSemanticScheduler,
    )

    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "d" * 64,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "e" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "f" * 64)
    provider = fireworks_provider(model="accounts/fireworks/models/minimax-m3")
    # The benchmark's arm B: review required by default, nothing bound, local-only policy. The
    # owner's explicit ``true`` keeps background advice on whatever the default (#888).
    config = YoetzConfig(
        profile="local-openai" if provider_bound else "strict-local",
        provider=provider if provider_bound else None,
        verification=VerificationConfig(semantic="required"),
        observation=ObservationConfig(semantic_advice_enabled=True),
    )
    factory = build_ready_application_factory(
        lifecycle=lifecycle,
        vault=vault,
        config=config,
        paths=_Paths(tmp_path),
        clock=clock,
        secret_memory=memory,
        diagnostics=_Diagnostics(),
    )
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "tsk_advice", "owner_generation": "1"})
    repository = SqliteObservationAdviceSemanticRepository(db)
    workspace = "hmac-sha256:" + "a" * 64
    session = "ses_00000000-0000-4000-8000-000000000923"
    store = _AdviceStore(repository, workspace)

    def rows() -> list[tuple[str, str | None]]:
        return [
            (str(row[0]), None if row[1] is None else str(row[1]))
            for row in db.execute(
                "SELECT status, failure_reason FROM observation_advice_semantic_attempts "
                "ORDER BY state_token"
            )
        ]

    app = None
    try:
        context = await factory.context_provider(1, vault.generation)
        assert context.rediscover_pending_verification is not None
        coordinator: object = getattr(context.rediscover_pending_verification, "__self__")
        scheduler = getattr(coordinator, "advice_context_builder").semantic_scheduler
        # The owner's switches still enable advice; readiness is what keeps it from running.
        assert type(scheduler) is ObservationAdviceSemanticScheduler
        dispatch = cast(
            Callable[
                [ObservationAdviceSemanticAttempt], Awaitable[ObservationAdviceSemanticOutcome]
            ],
            getattr(coordinator, "advice_semantic_dispatch"),
        )
        builder = ObservationAdviceContextBuilder(semantic_scheduler=scheduler)
        app = await factory.open(context)

        async def build(failures: int) -> tuple[str, ...]:
            store.failures = failures
            snapshot = await builder.build(workspace, store, yoetz_session_id=session)  # type: ignore[arg-type]
            assert snapshot is not None
            return snapshot.confidence_coverage.known_gaps

        # Arm B: many distinct advice candidates over a busy session.
        for failures in range(1, 9):
            gaps = await build(failures)
            assert ADVICE_SEMANTIC_PENDING_GAP not in gaps
            assert gaps.count(ADVICE_SEMANTIC_UNAVAILABLE_GAP) == 1
        assert rows() == []

        # A row an older service queued without a provider drains with no provider work (it
        # would otherwise stop at the unresolved route as authorization_missing and retry).
        legacy = repository.schedule(
            workspace=workspace,
            yoetz_session_id=session,
            basis_digest="legacy-identity",
            subject_digest="sha256:" + "c" * 64,
            coverage_gaps=(),
            packet_json=b"{}",
            enqueued_at="2026-07-21T17:00:00.000Z",
            max_pending=16,
        )
        assert type(legacy) is ObservationAdviceSemanticAttempt
        assert await dispatch(legacy) == ObservationAdviceSemanticOutcome(
            status="unavailable", failure_reason="provider_unavailable"
        )
        db.execute("DELETE FROM observation_advice_semantic_attempts")

        # The owner enables LLM inference and stores the credential in this same generation.
        policy_app = app.privacy.policy_application
        assert policy_app is not None
        scope = AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION_ID)
        current_policy = replace(minimal_external_policy(), effective_scope=scope)

        async def effective_policy(
            policy_store: object, requested: AuthorizationScope
        ) -> EffectivePrivacyPolicy:
            assert policy_store is policy_app.policy_store
            assert requested == scope
            return EffectivePrivacyPolicy(current_policy, 2, current_policy.policy_digest)

        monkeypatch.setattr(type(policy_app.policy_store), "effective_policy", effective_policy)
        credential_binding = provider_credential_profile_binding(
            provider.provider_id,
            provider.model,
            provider.endpoint_profile_id,
            provider.endpoint_profile_version,
        )
        proof = HumanAuthorizationProof(
            "provider-proof-advice-readiness",
            "provider_credential_set",
            credential_binding.target_digest("set"),
            1,
            vault.generation,
            None,
            1.0,
            60.0,
        )
        credential = memory.capture(
            SecretPurpose.PROVIDER_CREDENTIAL, bytearray(b"test-provider-token-advice")
        )
        await vault.store_provider_credential("set", credential_binding, credential, proof, 2.0)

        # The session has no task route yet, so nothing could reach a provider (route leg).
        gaps = await build(9)
        assert ADVICE_SEMANTIC_PENDING_GAP not in gaps
        assert ADVICE_SEMANTIC_UNAVAILABLE_GAP in gaps
        assert rows() == []
        if not provider_bound:
            # Channel and credential alone never make an unbound install reach a provider.
            return

        # An ACTIVE route whose repository authority is not granted still reaches nothing.
        commitment = "hmac-sha256:" + "b" * 64
        route = replace(
            _runtime_route(), session_id=session, repository_privacy_commitment=commitment
        )
        grant = "missing"

        async def resolve_route(_catalog: object, session_id: str) -> TaskRoute | None:
            return route if session_id == session else None

        repository_policy: PrivacyPolicy | None = None

        async def repository_authority(_store: object, requested: AuthorizationScope) -> object:
            assert requested.kind is AuthorizationScopeKind.TASK
            assert requested.workspace_ref_commitment == commitment
            return SimpleNamespace(
                grant_state=grant,
                effective=SimpleNamespace(policy=repository_policy or current_policy),
            )

        monkeypatch.setattr(type(app.start_catalog), "resolve_route", resolve_route)
        monkeypatch.setattr(
            type(policy_app.policy_store), "repository_authority", repository_authority
        )
        gaps = await build(10)
        assert ADVICE_SEMANTIC_PENDING_GAP not in gaps
        assert rows() == []

        grant = "granted"
        # A granted repository authority whose LLM channel is open but does not name this exact
        # provider binding, or does not allow the semantic-review purpose, would be refused by
        # the egress gateway at dispatch; admission must refuse it too (#923 review 938-R1).
        granted_llm = next(
            item
            for item in current_policy.channel_policies
            if item.channel is EgressChannel.LLM_INFERENCE
        )
        assert granted_llm.provider_binding is not None
        foreign_binding = replace(granted_llm.provider_binding, model_id="another-model")
        for narrowed in (
            replace(granted_llm, provider_binding=foreign_binding),
            replace(granted_llm, allowed_purposes=("package-update-check",)),
        ):
            repository_policy = replace(
                current_policy,
                channel_policies=tuple(
                    narrowed if item.channel is EgressChannel.LLM_INFERENCE else item
                    for item in current_policy.channel_policies
                ),
            )
            gaps = await build(21 if narrowed.provider_binding == foreign_binding else 22)
            assert ADVICE_SEMANTIC_PENDING_GAP not in gaps
            assert ADVICE_SEMANTIC_UNAVAILABLE_GAP in gaps
            assert rows() == []
        repository_policy = None

        gaps = await build(11)
        assert ADVICE_SEMANTIC_PENDING_GAP in gaps
        assert ADVICE_SEMANTIC_UNAVAILABLE_GAP not in gaps
        assert rows() == [("pending", None)]

        # Disabling the channel stops admission at once; so does a discarded credential.
        current_policy = replace(local_only_policy(), effective_scope=scope)
        gaps = await build(12)
        assert ADVICE_SEMANTIC_PENDING_GAP not in gaps
        assert ADVICE_SEMANTIC_UNAVAILABLE_GAP in gaps
        current_policy = replace(minimal_external_policy(), effective_scope=scope)
        await vault.discard_provider_credential(credential_binding)
        gaps = await build(13)
        assert ADVICE_SEMANTIC_PENDING_GAP not in gaps
        assert rows() == [("pending", None)]
    finally:
        db.close()
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()


@pytest.mark.anyio
async def test_background_advice_readiness_follows_the_primary_only_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Background advice dispatches only to the primary binding, so admission reads only it.

    Review 938-R2 of #923: with a declared fallback pairing (#582), an unusable primary and a
    credentialed, authorized fallback, the explicit check may engage the fallback, but the
    background dispatch never does. Admission must agree with that dispatch: no row, the
    unavailable gap, and a queued row closing ``provider_unavailable`` with no provider work.
    """

    from yoetz.adapters.providers.codex_app_server import codex_binding_from_config
    from yoetz.adapters.providers.openai_responses_factory import provider_binding_from_config
    from yoetz.adapters.sqlite.migrations import initialize_bundle
    from yoetz.adapters.sqlite.observation_advice_semantic import (
        SqliteObservationAdviceSemanticRepository,
    )
    from yoetz.application.observation_advice import (
        ADVICE_SEMANTIC_PENDING_GAP,
        ADVICE_SEMANTIC_UNAVAILABLE_GAP,
        ObservationAdviceContextBuilder,
    )
    from yoetz.application.observation_advice_semantic import (
        ObservationAdviceSemanticAttempt,
        ObservationAdviceSemanticOutcome,
    )
    from yoetz.config.models import ObservationConfig, SemanticFallbackConfig
    from yoetz.config.write import codex_subscription_runtime

    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "d" * 64,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "e" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "f" * 64)
    digest = "sha256:" + "a" * 64
    # The Codex subscription primary is structurally unusable here: its runtime home and
    # executable do not exist, so no process or login is ever probed.
    runtime = codex_subscription_runtime(
        executable_path=str(tmp_path / "absent" / "codex"),
        executable_sha256=digest,
        runtime_version="0.150.1",
        source_identity="openai-codex-npm-darwin-arm64-0.150.1",
        app_server_schema_sha256=digest,
        capability_cell_sha256=digest,
        isolated_config_sha256=digest,
        capability_profile="codex-evaluator/0.150.1/v1",
        capability_evidence_expires_at="2026-11-30T00:00:00Z",
        codex_home=str(tmp_path / "absent" / "codex-home"),
        model="gpt-5.6-sol",
        reasoning_effort="high",
    )
    provider = fireworks_provider(model="accounts/fireworks/models/minimax-m3")
    config = YoetzConfig(
        profile="codex-subscription",
        provider=provider,
        external_runtime=runtime,
        semantic_fallback=SemanticFallbackConfig(primary="codex_subscription"),
        verification=VerificationConfig(semantic="required"),
        # Explicit owner choice, so the test isolates readiness from the default switch.
        observation=ObservationConfig(semantic_advice_enabled=True),
    )
    factory = build_ready_application_factory(
        lifecycle=lifecycle,
        vault=vault,
        config=config,
        paths=_Paths(tmp_path),
        clock=clock,
        secret_memory=memory,
        diagnostics=_Diagnostics(),
    )
    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "tsk_advice", "owner_generation": "1"})
    repository = SqliteObservationAdviceSemanticRepository(db)
    workspace = "hmac-sha256:" + "a" * 64
    session = "ses_00000000-0000-4000-8000-000000000924"
    store = _AdviceStore(repository, workspace)

    def rows() -> list[tuple[str, str | None]]:
        return [
            (str(row[0]), None if row[1] is None else str(row[1]))
            for row in db.execute(
                "SELECT status, failure_reason FROM observation_advice_semantic_attempts "
                "ORDER BY state_token"
            )
        ]

    app = None
    try:
        context = await factory.context_provider(1, vault.generation)
        assert context.rediscover_pending_verification is not None
        coordinator: object = getattr(context.rediscover_pending_verification, "__self__")
        scheduler = getattr(coordinator, "advice_context_builder").semantic_scheduler
        dispatch = cast(
            Callable[
                [ObservationAdviceSemanticAttempt], Awaitable[ObservationAdviceSemanticOutcome]
            ],
            getattr(coordinator, "advice_semantic_dispatch"),
        )
        builder = ObservationAdviceContextBuilder(semantic_scheduler=scheduler)
        app = await factory.open(context)

        # Everything the fallback needs is in place: the machine and repository policies
        # authorize the exact pairing for semantic review, and the fallback credential is stored.
        policy_app = app.privacy.policy_application
        assert policy_app is not None
        scope = AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION_ID)
        base = replace(minimal_external_policy(), effective_scope=scope)
        llm = next(
            item for item in base.channel_policies if item.channel is EgressChannel.LLM_INFERENCE
        )
        fallback_binding = provider_binding_from_config(provider)
        paired = replace(
            llm,
            provider_binding=codex_binding_from_config(runtime),
            fallback_provider_binding=fallback_binding,
        )
        policy = replace(
            base,
            channel_policies=tuple(
                paired if item.channel is EgressChannel.LLM_INFERENCE else item
                for item in base.channel_policies
            ),
        )

        async def effective_policy(
            policy_store: object, requested: AuthorizationScope
        ) -> EffectivePrivacyPolicy:
            assert requested == scope
            return EffectivePrivacyPolicy(policy, 2, policy.policy_digest)

        commitment = "hmac-sha256:" + "b" * 64
        route = replace(
            _runtime_route(), session_id=session, repository_privacy_commitment=commitment
        )

        async def resolve_route(_catalog: object, session_id: str) -> TaskRoute | None:
            return route if session_id == session else None

        async def repository_authority(_store: object, requested: AuthorizationScope) -> object:
            return SimpleNamespace(grant_state="granted", effective=SimpleNamespace(policy=policy))

        monkeypatch.setattr(type(policy_app.policy_store), "effective_policy", effective_policy)
        monkeypatch.setattr(type(app.start_catalog), "resolve_route", resolve_route)
        monkeypatch.setattr(
            type(policy_app.policy_store), "repository_authority", repository_authority
        )
        credential_binding = provider_credential_profile_binding(
            provider.provider_id,
            provider.model,
            provider.endpoint_profile_id,
            provider.endpoint_profile_version,
        )
        proof = HumanAuthorizationProof(
            "provider-proof-advice-fallback",
            "provider_credential_set",
            credential_binding.target_digest("set"),
            1,
            vault.generation,
            None,
            1.0,
            60.0,
        )
        credential = memory.capture(
            SecretPurpose.PROVIDER_CREDENTIAL, bytearray(b"test-provider-token-fallback")
        )
        await vault.store_provider_credential("set", credential_binding, credential, proof, 2.0)
        assert await vault.has_provider_credential(credential_binding)

        store.failures = 3
        snapshot = await builder.build(workspace, store, yoetz_session_id=session)  # type: ignore[arg-type]
        assert snapshot is not None
        gaps = snapshot.confidence_coverage.known_gaps
        assert ADVICE_SEMANTIC_PENDING_GAP not in gaps
        assert gaps.count(ADVICE_SEMANTIC_UNAVAILABLE_GAP) == 1
        assert rows() == []

        queued = repository.schedule(
            workspace=workspace,
            yoetz_session_id=session,
            basis_digest="queued-identity",
            subject_digest="sha256:" + "c" * 64,
            coverage_gaps=(),
            packet_json=b"{}",
            enqueued_at="2026-07-21T17:00:00.000Z",
            max_pending=16,
        )
        assert type(queued) is ObservationAdviceSemanticAttempt
        assert await dispatch(queued) == ObservationAdviceSemanticOutcome(
            status="unavailable", failure_reason="provider_unavailable"
        )
    finally:
        db.close()
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("semantic", "chosen", "scheduled"),
    [
        ("required", None, True),
        ("optional", None, True),
        ("required", True, True),
        ("required", False, False),
        ("optional", False, False),
    ],
)
async def test_background_advice_is_on_by_default_and_an_owner_false_turns_it_off(
    tmp_path: Path,
    semantic: str,
    chosen: bool | None,
    scheduled: bool,
) -> None:
    """Issue #888 (maintainer decision 2026-09-30): background advice is on by default.

    Without an owner choice the composed service wires the background scheduler wherever
    AI-powered review is configured; an explicit ``false`` wires neither the scheduler nor its
    dispatch, even with a bound provider, and closes rows an earlier service left pending.
    """

    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "d" * 64,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "e" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "f" * 64)
    config = YoetzConfig(
        profile="local-openai",
        provider=fireworks_provider(model="accounts/fireworks/models/minimax-m3"),
        verification=VerificationConfig(semantic=cast(Any, semantic)),
        observation=ObservationConfig(semantic_advice_enabled=chosen),
    )
    factory = build_ready_application_factory(
        lifecycle=lifecycle,
        vault=vault,
        config=config,
        paths=_Paths(tmp_path),
        clock=clock,
        secret_memory=memory,
        diagnostics=_Diagnostics(),
    )
    app = None
    try:
        context = await factory.context_provider(1, vault.generation)
        assert context.rediscover_pending_verification is not None
        coordinator: object = getattr(context.rediscover_pending_verification, "__self__")
        scheduler = getattr(coordinator, "advice_context_builder").semantic_scheduler
        dispatch = getattr(coordinator, "advice_semantic_dispatch")
        app = await factory.open(context)
        assert (scheduler is not None) is scheduled
        if scheduled:
            return
        # Advice is off: a row an earlier service left pending is closed at startup drain as
        # cancelled with no provider identity (nothing sent), never held for later replay.
        from yoetz.adapters.sqlite.migrations import initialize_bundle
        from yoetz.adapters.sqlite.observation_advice_semantic import (
            SqliteObservationAdviceSemanticRepository,
        )
        from yoetz.application.observation_advice_semantic import (
            ObservationAdviceSemanticWorker,
        )

        db = apsw.Connection(":memory:")
        try:
            initialize_bundle(db, {"task_id": "tsk_advice", "owner_generation": "1"})
            repository = SqliteObservationAdviceSemanticRepository(db)
            repository.schedule(
                workspace="hmac-sha256:" + "a" * 64,
                yoetz_session_id="ses_00000000-0000-4000-8000-000000000888",
                basis_digest="queued-by-an-older-service",
                subject_digest="sha256:" + "c" * 64,
                coverage_gaps=(),
                packet_json=b"{}",
                enqueued_at="2026-07-21T17:00:00.000Z",
                max_pending=16,
            )
            worker = ObservationAdviceSemanticWorker(
                repository=repository,
                dispatch=dispatch,
                service_generation=1,
                lease_owner="svc-1",
                now=lambda: "2026-07-21T18:00:00.000Z",
                lease_expires_at=lambda: "2026-07-21T18:02:00.000Z",
            )
            closed = await worker.run_once()
            assert closed is not None
            row = repository.lookup(
                yoetz_session_id="ses_00000000-0000-4000-8000-000000000888",
                basis_digest="queued-by-an-older-service",
            )
            assert row is not None
            assert (row.status, row.failure_reason) == ("cancelled", "cancelled")
            assert (row.provider_identity, row.attempt_receipt) == (None, None)
            assert repository.list_pending_workspaces() == ()
        finally:
            db.close()
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()


@pytest.mark.anyio
async def test_ready_check_never_activates_provider_from_machine_policy_without_repository_grant(
    tmp_path: Path,
) -> None:
    """A configured provider and machine policy never outrun exact repository authority."""

    tmp_path.chmod(0o700)
    clock = _Clock()
    memory = LocalSecretMemory()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=_GenerationStore(),
        process_start_identity_commitment="sha256:" + "d" * 64,
        instance_id=_INSTANCE_ID,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    vault = VaultService(
        installation_id=_INSTALLATION_ID,
        service_generation=1,
        mode=VaultMode.UNINITIALIZED,
        secret_memory=memory,
        clock=clock,
        vault_store_factory=lambda: EncryptedVaultStore(tmp_path / "vault"),
        pristine_state_digest="sha256:" + "e" * 64,
    )
    initialize = memory.capture(SecretPurpose.VAULT_INITIALIZE, bytearray(b"correct horse battery"))
    await vault.initialize_passphrase(initialize, "sha256:" + "f" * 64)
    provider = fireworks_provider(model="accounts/fireworks/models/minimax-m3")
    config = YoetzConfig(profile="local-openai", provider=provider)
    app = None
    try:
        factory = build_ready_application_factory(
            lifecycle=lifecycle,
            vault=vault,
            config=config,
            paths=_Paths(tmp_path),
            clock=clock,
            secret_memory=memory,
            diagnostics=_Diagnostics(),
        )
        app = await factory(1, vault.generation)
        object.__setattr__(app, "enforce_repository_identity", False)
        common = {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
        }
        started = await app.start(
            StartRequest.model_validate(
                {
                    **common,
                    "request_id": "req_00000000-0000-4000-8000-000000000401",
                    "mode": "create",
                    "task_title": "Resolve provider binding after ready composition",
                    "requested_view": "compact",
                }
            )
        )
        original_request = CheckRequest.model_validate(
            {
                **common,
                "request_id": "req_00000000-0000-4000-8000-000000000402",
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": {
                    "sequence": str(started.frontier.sequence),
                    "head_digest": started.frontier.head_digest,
                },
                "mode": "semantic_required",
                "max_findings": "3",
                "policy_packs": ["work-integrity/0.3.0"],
            }
        )
        first = await app.check(original_request)
        assert type(first) is CheckCommitResult
        assert first.semantic_status.value == "blocked_by_policy"
        assert first.semantic_reason.value == "scope_not_authorized"

        evaluator = app.semantic_evaluator
        widened = replace(
            minimal_external_policy(),
            effective_scope=AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION_ID),
            created_at=clock.now_utc(),
        )
        gateway = cast(OutboundGatewayPort, getattr(app.privacy, "_gateway"))
        await gateway.reconcile_policy(
            EffectivePrivacyPolicy(widened, 2, widened.policy_digest),
            HumanAuthorityCapability(
                "established_passphrase",
                canonical_digest({"source": "test"}),
                1,
                str(getattr(vault.mode, "value", vault.mode)),
                vault.generation,
                True,
            ),
        )
        assert "fireworks" not in cast(
            tuple[str, ...], tuple(getattr(gateway, "connected_provider_ids")())
        )
        credential_binding = provider_credential_profile_binding(
            provider.provider_id,
            provider.model,
            provider.endpoint_profile_id,
            provider.endpoint_profile_version,
        )
        assert await vault.has_provider_credential(credential_binding) is False
        proof = HumanAuthorizationProof(
            "provider-proof-after-composition",
            "provider_credential_set",
            credential_binding.target_digest("set"),
            1,
            vault.generation,
            None,
            1.0,
            60.0,
        )
        credential = memory.capture(
            SecretPurpose.PROVIDER_CREDENTIAL,
            bytearray(b"test-provider-token-after-composition"),
        )
        await vault.store_provider_credential("set", credential_binding, credential, proof, 2.0)
        assert await vault.has_provider_credential(credential_binding) is True

        second = await app.check(original_request)
        assert type(second) is CheckCommitResult

        assert app.semantic_evaluator is evaluator
        # Credential rotation/storage does not create repository authority or activate the
        # provider. The second check fails at the same exact grant fence without a provider call.
        assert second.outcome == "replayed"
        assert second.semantic_status == first.semantic_status
        assert second.semantic_reason == first.semantic_reason

        third = await app.check(
            CheckRequest.model_validate(
                {
                    **common,
                    "request_id": "req_00000000-0000-4000-8000-000000000403",
                    "session_id": started.session_id,
                    "writer_id": started.writer_id,
                    "expected_frontier": {
                        "sequence": str(second.result_frontier.sequence),
                        "head_digest": second.result_frontier.head_digest,
                    },
                    "mode": "semantic_required",
                    "max_findings": "3",
                    "policy_packs": ["work-integrity/0.3.0"],
                }
            )
        )
        assert type(third) is CheckCommitResult
        assert third.outcome == "committed"
        assert third.semantic_status.value == "blocked_by_policy"
        assert third.semantic_reason.value == "scope_not_authorized"
        assert "fireworks" not in cast(
            tuple[str, ...], tuple(getattr(gateway, "connected_provider_ids")())
        )
    finally:
        if app is not None:
            await app.close()
        await vault.close()
        memory.close()
        await lifecycle.close()
