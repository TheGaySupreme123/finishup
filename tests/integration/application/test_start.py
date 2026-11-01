"""Integration coverage for crash-safe application START orchestration."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, cast

import apsw
import pytest
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from builders.ledger_adapters import FixedIds, ownership_fence
from builders.start_application import (
    FailOnceStartCatalog,
    StartTestApplication,
    StartTestClock,
    StartTestLookup,
    protocol_id,
    start_composition,
    start_request,
)
from finishup.adapters.memory.start_catalog import MemoryStartCatalogAdapter
from finishup.adapters.objects import encrypted_files as encrypted_files_module
from finishup.adapters.objects.encrypted_files import EncryptedFilesObjectStore
from finishup.adapters.objects.envelope import decode_object_envelope
from finishup.adapters.sqlite.migrations import initialize_bundle, initialize_catalog
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.adapters.sqlite.start_catalog import SqliteStartCatalog
from finishup.application.start import execute_start, start_projection_wire
from finishup.domain.values import Frontier
from finishup.ports.importer import ImporterPort
from finishup.ports.keys import BundleKeys, WrappedDek
from finishup.ports.ledger import LedgerPort
from finishup.ports.objects import (
    ObjectKind,
    ObjectRef,
    ObjectRootSnapshot,
    ObjectStorePort,
)
from finishup.ports.runtime import (
    BundleProvisionCommand,
    RouteCommand,
    StartCompletionEvidence,
    StartMilestone,
    StartMilestoneExpectation,
    TaskRuntime,
)
from finishup.ports.secret_memory import (
    SecretConsumer,
    SecretMemoryCapability,
    SecretPurpose,
)
from finishup.ports.start_catalog import StartCatalogPort
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import StartRequest

if TYPE_CHECKING:
    from finishup.ports.secret_memory import SecretHandle

pytestmark = pytest.mark.anyio


class _Secret:
    def __init__(self, value: bytes | bytearray) -> None:
        self._value = bytearray(value)
        self._consumed = False

    @property
    def purpose(self) -> SecretPurpose:
        return SecretPurpose.OBJECT_PAYLOAD

    def consume[T](self, consumer: SecretConsumer, fn: Callable[[memoryview], T]) -> T:
        if consumer is not SecretConsumer.OBJECT_CRYPTO or self._consumed:
            raise ValueError("secret_handle_invalid")
        self._consumed = True
        try:
            return fn(memoryview(self._value))
        finally:
            self._value[:] = b"\0" * len(self._value)


class _SecretMemory:
    def capability(self) -> SecretMemoryCapability:
        return SecretMemoryCapability("active", "unavailable", "unavailable", "active", "active")

    def capture(self, purpose: SecretPurpose, source: bytearray) -> _Secret:
        assert purpose is SecretPurpose.OBJECT_PAYLOAD
        result = _Secret(source)
        source[:] = b"\0" * len(source)
        return result

    def allocate(self, purpose: SecretPurpose, size: int) -> _Secret:
        assert purpose is SecretPurpose.OBJECT_PAYLOAD
        return _Secret(bytes(size))

    def close(self) -> None:
        return None


class _WrapKey:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def wrap_dek(self, dek: SecretHandle) -> WrappedDek:
        wrapped = dek.consume(
            SecretConsumer.OBJECT_CRYPTO,
            lambda value: aes_key_wrap(self._key, bytes(value)),
        )
        return WrappedDek("aes-256-kw-rfc3394", wrapped)

    def unwrap_dek(self, wrapped: WrappedDek) -> _Secret:
        return _Secret(aes_key_unwrap(self._key, wrapped.wrapped))


class _MacKey:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def mac(self, domain: bytes, message: bytes) -> str:
        digest = hmac.new(self._key, domain + message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"


class _CountingLedger:
    def __init__(self, delegate: SqliteLedger) -> None:
        self.delegate = delegate
        self.frontier_loads = 0

    def __getattr__(self, name: str) -> object:
        return getattr(self.delegate, name)

    async def load_frontier(self) -> Frontier:
        self.frontier_loads += 1
        return await self.delegate.load_frontier()


class _CountingObjects:
    def __init__(self, delegate: EncryptedFilesObjectStore) -> None:
        self.delegate = delegate
        self.resolutions: list[tuple[str, str]] = []

    def __getattr__(self, name: str) -> object:
        return getattr(self.delegate, name)

    async def resolve_verified(self, object_id: str, envelope_digest: str) -> ObjectRef:
        self.resolutions.append((object_id, envelope_digest))
        return await self.delegate.resolve_verified(object_id, envelope_digest)

    def open_verified(self, ref: ObjectRef) -> AsyncIterator[bytes]:
        return self.delegate.open_verified(ref)


@dataclass(slots=True)
class _RealResources:
    bundle_root: Path
    db: apsw.Connection
    ledger: _CountingLedger
    objects: _CountingObjects


class _RealRuntime:
    def __init__(self, root: Path, clock: StartTestClock, ids: FixedIds) -> None:
        self.root = root
        self.clock = clock
        self.ids = ids
        self.resources: dict[str, _RealResources] = {}
        self.owners: dict[tuple[str, str], int] = {}
        self.provisions: list[BundleProvisionCommand] = []
        self.release_count = 0

    async def provision_start(self, command: BundleProvisionCommand) -> TaskRuntime:
        self.provisions.append(command)
        existing = self.resources.get(command.task_id)
        if existing is None:
            bundle_root = self.root / command.bundle_relpath
            bundle_root.mkdir(mode=0o700, parents=True)
            bundle_root.chmod(0o700)
            db = apsw.Connection(str(bundle_root / "bundle.db"))
            initialize_bundle(
                db,
                {
                    "task_id": command.task_id,
                    "owner_generation": str(command.owner_generation),
                    "owner_nonce": "ledger-test-nonce",
                },
            )
        else:
            bundle_root = existing.bundle_root
            db = existing.db

        async def current_roots() -> ObjectRootSnapshot:
            digest = "sha256:" + "0" * 64
            return ObjectRootSnapshot(
                command.task_id,
                command.route_identity_digest,
                command.route_generation,
                1,
                0,
                digest,
                digest,
                digest,
                digest,
                self.clock.now_utc(),
                (),
            )

        store = EncryptedFilesObjectStore(
            bundle_root=bundle_root,
            bundle_keys=BundleKeys(
                "bmk-1",
                _WrapKey(bytes(range(32))),
                _MacKey(bytes(range(32, 64))),
            ),
            secret_memory=_SecretMemory(),
            id_port=self.ids,
            current_root_snapshot=current_roots,
        )
        fence = ownership_fence(generation=command.owner_generation)
        ledger = SqliteLedger(
            db=db,
            task_id=command.task_id,
            ownership_fence=fence,
            clock=self.clock,
            ids=self.ids,
            objects=store,
        )
        counting_ledger = _CountingLedger(ledger)
        counting_objects = _CountingObjects(store)
        self.resources[command.task_id] = _RealResources(
            bundle_root,
            db,
            counting_ledger,
            counting_objects,
        )
        self.owners[(command.session_id, command.writer_id)] = command.owner_generation
        return TaskRuntime(
            command.task_id,
            command.session_id,
            command.writer_id,
            frozenset(),
            cast(LedgerPort, counting_ledger),
            cast(ObjectStorePort, counting_objects),
            cast(ImporterPort, object()),
            command.projection_version,
            command.engine_version,
            command.protocol_version,
            command.bundle_schema_version,
            fence,
        )

    async def verify_start(
        self,
        runtime: TaskRuntime,
        expectation: StartMilestoneExpectation,
    ) -> StartCompletionEvidence:
        frontier: Frontier | None = None
        if expectation.milestone is not StartMilestone.BUNDLE_READY:
            frontier = await runtime.ledger.load_frontier()
        owner_generation = self.owners[(expectation.session_id, expectation.writer_id)]
        value: dict[str, JsonValue] = {
            "lifecycle_event_id": expectation.lifecycle_event_id,
            "lifecycle_frontier": None if frontier is None else dict(frontier.as_wire()),
            "milestone": expectation.milestone.value,
            "owner_generation": owner_generation,
            "response_envelope_digest": expectation.response_envelope_digest,
            "response_object_id": expectation.response_object_id,
            "result_digest": expectation.result_digest,
            "route_generation": expectation.route_generation,
            "route_identity_digest": expectation.route_identity_digest,
            "session_id": expectation.session_id,
            "task_id": expectation.task_id,
            "writer_id": expectation.writer_id,
        }
        return StartCompletionEvidence(
            expectation.milestone,
            expectation.task_id,
            expectation.session_id,
            expectation.writer_id,
            expectation.lifecycle_event_id,
            expectation.route_generation,
            expectation.route_identity_digest,
            owner_generation,
            frontier,
            expectation.response_object_id,
            expectation.response_envelope_digest,
            expectation.result_digest,
            canonical_digest(value),
        )

    async def release(self, runtime: TaskRuntime) -> None:
        assert runtime.task_id in self.resources
        self.release_count += 1

    async def route(self, command: RouteCommand) -> TaskRuntime:
        del command
        raise AssertionError("route_not_used_by_start")

    async def close(self) -> None:
        return None


def _real_composition(
    tmp_path: Path,
) -> tuple[
    StartTestApplication,
    _RealRuntime,
    StartTestClock,
    FailOnceStartCatalog,
    apsw.Connection,
]:
    tmp_path.chmod(0o700)
    clock = StartTestClock()
    ids = FixedIds()
    catalog_db = apsw.Connection(str(tmp_path / "catalog.db"))
    initialize_catalog(catalog_db)
    installation_id = protocol_id("ins_", 1700)
    catalog_db.executemany(
        "INSERT INTO catalog_meta(key, value) VALUES(?, ?)",
        (("installation_id", installation_id), ("owner_generation", "1")),
    )
    catalog = SqliteStartCatalog(
        catalog_db,
        installation_id=installation_id,
        lookup=StartTestLookup(),
        clock=clock,
        ids=ids,
    )
    wrapper = FailOnceStartCatalog(cast(StartCatalogPort, catalog))
    runtime = _RealRuntime(tmp_path, clock, ids)
    return (
        StartTestApplication(cast(StartCatalogPort, wrapper), runtime, clock),
        runtime,
        clock,
        wrapper,
        catalog_db,
    )


async def test_create_replays_exact_result_without_reopening_runtime() -> None:
    app, runtime, _, _ = start_composition()
    request = start_request(701)

    created = await execute_start(app, request)
    replayed = await execute_start(app, request)

    assert replayed == created
    assert start_projection_wire(replayed) == start_projection_wire(created)
    assert "next_request_template" not in created.as_wire()
    projected = start_projection_wire(created)
    template = cast(dict[str, JsonValue], projected["next_request_template"])
    arguments = cast(dict[str, JsonValue], template["arguments"])
    assert template["evidential"] is False
    assert template["operation"] == "publish_work"
    assert arguments["session_id"] == created.session_id
    assert arguments["writer_id"] == created.writer_id
    assert arguments["expected_frontier"] == created.frontier.model_dump(mode="json")
    assert created.ok is True
    assert created.outcome == "created"
    assert created.frontier.sequence == "1"
    assert len(runtime.provisions) == 1
    assert runtime.release_count == 1
    assert runtime.frontier_verifications == 2
    ledger, _ = runtime.resources[created.task_id]
    assert ledger._state.records[0].schema.name == "session_opened"  # pyright: ignore[reportPrivateUsage]


async def test_legacy_attached_result_replays_with_explicit_unknown_receipt_count() -> None:
    app, runtime, _, catalog = start_composition()
    await execute_start(app, start_request(705, refs=True))
    request = start_request(706, refs=True)
    attached = await execute_start(app, request)
    provisions_before_replay = len(runtime.provisions)

    memory_catalog = cast(MemoryStartCatalogAdapter, catalog.delegate)
    state = memory_catalog._state  # pyright: ignore[reportPrivateUsage]
    key, record = next(
        (key, record)
        for key, record in state.operations.items()
        if record.operation_id == request.request_id
    )
    legacy = attached.as_wire()
    compact = cast(dict[str, JsonValue], legacy["compact"])
    compact["unresolved_finding_count"] = compact.pop("unanswered_finding_count")
    compact.pop("receipt_blocking_finding_count")
    canonical = canonical_encode(legacy)
    state.operations[key] = replace(
        record,
        terminal_result_canonical=canonical,
        terminal_result_digest=f"sha256:{hashlib.sha256(canonical).hexdigest()}",
    )

    replayed = await execute_start(app, request)

    assert replayed.outcome == "attached"
    assert replayed.compact.unanswered_finding_count == attached.compact.unanswered_finding_count
    assert replayed.compact.receipt_blocking_finding_count is None
    assert "legacy_receipt_blocking_count_unknown" in replayed.compact.gaps
    assert len(runtime.provisions) == provisions_before_replay


async def test_legacy_created_result_replays_with_an_exact_zero_receipt_count() -> None:
    """A create result is frozen at the first lifecycle event of a brand-new task ledger, so no
    finding can have existed at its frontier. Zero is derived, not invented, and carries no gap."""

    app, runtime, _, catalog = start_composition()
    request = start_request(707)
    created = await execute_start(app, request)
    provisions_before_replay = len(runtime.provisions)

    memory_catalog = cast(MemoryStartCatalogAdapter, catalog.delegate)
    state = memory_catalog._state  # pyright: ignore[reportPrivateUsage]
    key, record = next(
        (key, record)
        for key, record in state.operations.items()
        if record.operation_id == request.request_id
    )
    legacy = created.as_wire()
    compact = cast(dict[str, JsonValue], legacy["compact"])
    compact["unresolved_finding_count"] = compact.pop("unanswered_finding_count")
    compact.pop("receipt_blocking_finding_count")
    canonical = canonical_encode(legacy)
    state.operations[key] = replace(
        record,
        terminal_result_canonical=canonical,
        terminal_result_digest=f"sha256:{hashlib.sha256(canonical).hexdigest()}",
    )

    replayed = await execute_start(app, request)

    assert replayed.outcome == "created"
    assert replayed.compact.receipt_blocking_finding_count == "0"
    assert "legacy_receipt_blocking_count_unknown" not in replayed.compact.gaps
    assert replayed == created
    assert len(runtime.provisions) == provisions_before_replay


async def test_matching_refs_attach_and_same_title_without_refs_stays_distinct() -> None:
    app, runtime, _, _ = start_composition()
    created = await execute_start(app, start_request(710, refs=True))
    attached = await execute_start(app, start_request(711, refs=True))
    separate = await execute_start(app, start_request(712, title="Exact task"))

    assert attached.outcome == "attached"
    assert attached.task_id == created.task_id
    assert attached.session_id != created.session_id
    assert separate.task_id != created.task_id
    ledger, _ = runtime.resources[created.task_id]
    assert [record.schema.name for record in ledger._state.records] == [  # pyright: ignore[reportPrivateUsage]
        "session_opened",
        "session_resumed",
    ]


async def test_historical_session_reattaches_after_same_pair_rotation() -> None:
    """Same-pair attach retires the held session but keeps it as an attach selector (#438)."""

    app, _, _, catalog = start_composition()
    created = await execute_start(app, start_request(760, refs=True))
    attached = await execute_start(app, start_request(761, refs=True))
    assert attached.outcome == "attached"
    resumed = await execute_start(
        app, start_request(762, mode="attach", session_id=created.session_id)
    )
    assert resumed.outcome == "attached"
    assert resumed.task_id == created.task_id
    assert resumed.session_id not in {created.session_id, attached.session_id}

    memory = cast(MemoryStartCatalogAdapter, catalog.delegate)
    assert await memory.resolve_route(created.session_id) is None
    binding = await memory.session_binding(created.session_id)
    assert binding is not None
    assert binding.session_id == resumed.session_id


async def test_create_or_attach_drifted_pair_creates_sibling_and_held_session_attaches() -> None:
    """A drifted pair creates independent work; an explicit held session still attaches."""

    app, _, _, _ = start_composition()
    created = await execute_start(app, start_request(770, refs=True))
    drifted = start_request(771, refs=True).model_dump(mode="json", exclude_none=True)
    drifted["external_ref"] = "external-B"
    drifted_task = await execute_start(app, StartRequest.model_validate(drifted))
    assert drifted_task.outcome == "created"
    assert drifted_task.task_id != created.task_id

    # The hook recovery path uses the held session selector and still returns to the original
    # task, even after an independent drifted pair has been admitted.
    recovery_wire = start_request(
        772, mode="attach", refs=True, session_id=created.session_id
    ).model_dump(mode="json", exclude_none=True)
    recovered = await execute_start(app, StartRequest.model_validate(recovery_wire))
    assert recovered.outcome == "attached"
    assert recovered.task_id == created.task_id
    assert recovered.session_id != created.session_id

    sibling_wire = start_request(773, mode="create", refs=True).model_dump(
        mode="json", exclude_none=True
    )
    sibling_wire["external_ref"] = "external-C"
    sibling = await execute_start(app, StartRequest.model_validate(sibling_wire))
    assert sibling.outcome == "created"
    assert sibling.task_id not in {created.task_id, drifted_task.task_id}


async def test_hook_pair_then_guidance_pair_lands_on_the_auto_attached_task() -> None:
    """Issue #580: the hook and the agent must name the workspace by one value.

    The observation hook auto-attaches with the canonical project root as ``workspace_ref``
    and ``<host>-session:<id>`` as ``external_ref``. An agent following the guidance uses
    the same root with its own work-item ``external_ref`` and gets an independent sibling;
    the explicit SessionStart session selector still attaches to the hook task. A
    ``workspace_ref`` in another vocabulary (the remote URL) is a different workspace
    commitment and creates another sibling.
    """

    app, _, _, _ = start_composition()
    root = "/workspace/project"
    hook_wire = start_request(780, refs=True, title="Claude observation auto-attach").model_dump(
        mode="json", exclude_none=True
    )
    hook_wire["workspace_ref"] = root
    hook_wire["external_ref"] = "claude-session:ad24aa95-0000-4000-8000-000000000000"
    hook_task = await execute_start(app, StartRequest.model_validate(hook_wire))
    assert hook_task.outcome == "created"

    agent_wire = start_request(781, refs=True).model_dump(mode="json", exclude_none=True)
    agent_wire["workspace_ref"] = root
    agent_wire["external_ref"] = "claude/dogfood-issue-568"
    guidance_task = await execute_start(app, StartRequest.model_validate(agent_wire))
    assert guidance_task.outcome == "created"
    assert guidance_task.task_id != hook_task.task_id

    attached = await execute_start(
        app, start_request(782, mode="attach", session_id=hook_task.session_id)
    )
    assert attached.outcome == "attached"
    assert attached.task_id == hook_task.task_id
    assert attached.session_id != hook_task.session_id

    url_wire = start_request(783, refs=True).model_dump(mode="json", exclude_none=True)
    url_wire["workspace_ref"] = "https://github.com/example/project.git"
    url_wire["external_ref"] = "claude/dogfood-issue-568"
    sibling = await execute_start(app, StartRequest.model_validate(url_wire))
    assert sibling.outcome == "created"
    assert sibling.task_id not in {hook_task.task_id, guidance_task.task_id}


async def test_result_published_crash_resumes_pinned_object_and_releases_each_runtime() -> None:
    app, runtime, clock, catalog = start_composition()
    request = start_request(720)
    catalog.fail_complete = True

    with pytest.raises(RuntimeError, match="simulated_post_publish_crash"):
        await execute_start(app, request)
    assert runtime.release_count == 1
    first_task = runtime.provisions[0].task_id
    published = runtime.start_result_refs(first_task)
    assert len(published) == 1

    clock.advance(61)
    resumed = await execute_start(app, request)

    assert resumed.ok is True
    assert resumed.outcome == "created"
    assert runtime.release_count == 2
    assert runtime.provisions[-1].phase == "result_published"
    republished = runtime.start_result_refs(first_task)
    assert republished == published


@pytest.mark.parametrize("milestone", list(StartMilestone))
async def test_busy_after_each_start_milestone_yields_for_immediate_exact_replay(
    milestone: StartMilestone, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, runtime, _clock, _catalog = start_composition()
    request = start_request(7440)
    verify = runtime.verify_start
    failed = False

    async def busy_once(
        task: TaskRuntime, expectation: StartMilestoneExpectation
    ) -> StartCompletionEvidence:
        nonlocal failed
        result = await verify(task, expectation)
        if expectation.milestone is milestone and not failed:
            failed = True
            raise PublicOperationError(PublicErrorCode.BUNDLE_BUSY, "Busy", True)
        return result

    monkeypatch.setattr(runtime, "verify_start", busy_once)
    with pytest.raises(PublicOperationError) as busy:
        await execute_start(app, request)
    assert busy.value.safe_details == {
        "reason_code": "start_busy_retry_ready",
        "continuation": "start_busy_same_identity",
    }
    original = runtime.provisions[0]
    recovered = await execute_start(app, request)
    assert recovered.task_id == original.task_id
    assert recovered.session_id == original.session_id
    assert recovered.writer_id == original.writer_id
    assert recovered.frontier.sequence == "1"
    assert await execute_start(app, request) == recovered
    assert len(runtime.start_result_refs(recovered.task_id)) == 1


async def test_cancelled_provision_keeps_live_lease_until_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, runtime, clock, _catalog = start_composition()
    request = start_request(7441)
    entered = asyncio.Event()
    release = asyncio.Event()
    provision = runtime.provision_start

    async def blocked(command: BundleProvisionCommand) -> TaskRuntime:
        entered.set()
        await release.wait()
        return await provision(command)

    monkeypatch.setattr(runtime, "provision_start", blocked)
    attempt = asyncio.create_task(execute_start(app, request))
    await asyncio.wait_for(entered.wait(), 5)
    attempt.cancel()
    with pytest.raises(asyncio.CancelledError):
        await attempt
    with pytest.raises(PublicOperationError) as pending:
        await execute_start(app, request)
    assert pending.value.safe_details == {
        "reason_code": "start_lease_pending",
        "continuation": "start_pending_same_identity",
    }
    clock.advance(61)
    release.set()
    recovered = await execute_start(app, request)
    assert recovered.frontier.sequence == "1"


async def test_sqlite_and_encrypted_files_resume_exact_catalog_pinned_object(
    tmp_path: Path,
) -> None:
    app, runtime, clock, catalog, catalog_db = _real_composition(tmp_path)
    request = start_request(1720)
    catalog.fail_complete = True

    with pytest.raises(RuntimeError, match="simulated_post_publish_crash"):
        await execute_start(app, request)

    row = catalog_db.execute(
        "SELECT task_id, response_object_id, response_envelope_digest "
        "FROM start_operations WHERE operation_id=?",
        (request.request_id,),
    ).fetchone()
    assert row is not None
    task_id, object_id, envelope_digest = cast(tuple[str, str, str], row)
    resources = runtime.resources[task_id]
    pinned_path = resources.bundle_root / "objects" / object_id[4:6] / object_id
    assert pinned_path.is_file()
    pinned_bytes = pinned_path.read_bytes()
    assert resources.ledger.frontier_loads == 3

    clock.advance(61)
    resumed = await execute_start(app, request)
    reopened = runtime.resources[task_id]

    assert resumed.task_id == task_id
    assert runtime.provisions[-1].phase == "result_published"
    assert reopened.objects.resolutions == [(object_id, envelope_digest)]
    assert reopened.ledger.frontier_loads == 3
    assert pinned_path.read_bytes() == pinned_bytes
    start_result_ids = {
        decode_object_envelope(path.read_bytes()).header.object_id
        for path in (reopened.bundle_root / "objects").rglob("obj_*")
        if path.is_file()
        and decode_object_envelope(path.read_bytes()).header.object_kind is ObjectKind.START_RESULT
    }
    assert start_result_ids == {object_id}
    assert runtime.release_count == 2


async def test_start_result_replay_eio_is_retryable_and_resumes_after_storage_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """START must keep a result-published row resumable when resolve_verified sees transient EIO."""

    app, runtime, clock, catalog, _catalog_db = _real_composition(tmp_path)
    request = start_request(1730)
    catalog.fail_complete = True

    with pytest.raises(RuntimeError, match="simulated_post_publish_crash"):
        await execute_start(app, request)

    clock.advance(61)

    def failing_read(_descriptor: int, _n: int) -> bytes:
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(encrypted_files_module.os, "read", failing_read)
    with pytest.raises(PublicOperationError) as caught:
        await execute_start(app, request)
    assert caught.value.code is PublicErrorCode.STORAGE_UNSAFE
    assert caught.value.retryable is True
    assert caught.value.message == "The start result is temporarily unavailable."
    assert "Input/output error" not in caught.value.message
    assert runtime.release_count == 2

    # The transient failure did not quarantine or consume the result-published allocation; once
    # the environment recovers, the exact request reopens and completes the original object.
    monkeypatch.undo()
    clock.advance(61)
    resumed = await execute_start(app, request)
    assert resumed.ok is True
    assert resumed.outcome == "created"
    assert runtime.release_count == 3
