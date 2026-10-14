"""Reusable application composition for START operation tests."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import cast

import anyio

from builders.ledger_adapters import FixedIds, MemoryObjects, ownership_fence
from yoetz.adapters.memory.importer import MemoryImportState
from yoetz.adapters.memory.ledger import MemoryLedgerAdapter, MemoryLedgerState
from yoetz.adapters.memory.start_catalog import (
    MemoryStartCatalogAdapter,
    MemoryStartCatalogState,
)
from yoetz.application.lineage import LineageCoordinator
from yoetz.domain.events import RuntimeProfile
from yoetz.domain.values import Frontier
from yoetz.ports.clock import ClockPort
from yoetz.ports.importer import ImporterPort
from yoetz.ports.objects import ObjectKind, ObjectRef, ObjectStorePort
from yoetz.ports.runtime import (
    BundleProvisionCommand,
    BundleRuntimePort,
    RouteCommand,
    StartCompletionEvidence,
    StartMilestone,
    StartMilestoneExpectation,
    TaskRuntime,
)
from yoetz.ports.start_catalog import (
    EncryptedResultRef,
    StartAllocation,
    StartCatalogPort,
)
from yoetz.protocol.canonical import JsonValue, canonical_digest
from yoetz.protocol.models import StartRequest


def protocol_id(prefix: str, seed: int) -> str:
    """Return one deterministic, prefix-valid protocol identifier."""

    return prefix + str(uuid.UUID(int=seed, version=4))


class StartTestClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)

    def now_utc(self) -> datetime:
        return self.current

    def monotonic_seconds(self) -> float:
        return 1.0

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


class StartTestLookup:
    def mac(self, domain: bytes, message: bytes) -> str:
        digest = hmac.new(b"\x91" * 32, domain + message, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"


class MemoryStartRuntime:
    def __init__(self, clock: StartTestClock, ids: FixedIds) -> None:
        self.clock = clock
        self.ids = ids
        self.resources: dict[str, tuple[MemoryLedgerAdapter, MemoryObjects]] = {}
        self.owners: dict[tuple[str, str], int] = {}
        self.provisions: list[BundleProvisionCommand] = []
        self.release_count = 0
        self.frontier_verifications = 0

    def start_result_refs(self, task_id: str) -> tuple[ObjectRef, ...]:
        _, objects = self.resources[task_id]
        return objects.refs_for_kind(ObjectKind.START_RESULT)

    async def provision_start(self, command: BundleProvisionCommand) -> TaskRuntime:
        self.provisions.append(command)
        resources = self.resources.get(command.task_id)
        if resources is None:
            objects = MemoryObjects(self.ids)
            ledger = MemoryLedgerAdapter(
                task_id=command.task_id,
                ownership_fence=ownership_fence(),
                state=MemoryLedgerState(),
                import_state=MemoryImportState(),
                transaction_lock=asyncio.Lock(),
                clock=self.clock,
                ids=self.ids,
                objects=objects,
            )
            resources = (ledger, objects)
            self.resources[command.task_id] = resources
        ledger, objects = resources
        self.owners[(command.session_id, command.writer_id)] = command.owner_generation
        return TaskRuntime(
            command.task_id,
            command.session_id,
            command.writer_id,
            frozenset(),
            ledger,
            cast(ObjectStorePort, objects),
            cast(ImporterPort, object()),
            command.projection_version,
            command.engine_version,
            command.protocol_version,
            command.bundle_schema_version,
            ownership_fence(),
        )

    async def verify_start(
        self,
        runtime: TaskRuntime,
        expectation: StartMilestoneExpectation,
    ) -> StartCompletionEvidence:
        assert runtime.task_id == expectation.task_id
        assert runtime.session_id == expectation.session_id
        frontier: Frontier | None = None
        if expectation.milestone is not StartMilestone.BUNDLE_READY:
            frontier = await runtime.ledger.load_frontier()
            self.frontier_verifications += 1
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


class FailOnceStartCatalog:
    def __init__(self, delegate: StartCatalogPort) -> None:
        self.delegate = delegate
        self.fail_complete = False

    def __getattr__(self, name: str) -> object:
        return getattr(self.delegate, name)

    async def complete(
        self,
        allocation: StartAllocation,
        result: EncryptedResultRef,
        evidence: StartCompletionEvidence,
    ) -> None:
        if self.fail_complete:
            self.fail_complete = False
            raise RuntimeError("simulated_post_publish_crash")
        await self.delegate.complete(allocation, result, evidence)


class StartTestApplication:
    lineage: LineageCoordinator | None = None
    profile: RuntimeProfile = RuntimeProfile.TEST_FAKE
    policy_packs: tuple[str, ...] = (
        "research-evidence/0.2.0",
        "work-integrity/0.3.0",
    )
    version_manifest: Mapping[str, JsonValue] = {
        "protocol_version": "0.1",
        "engine_version": "0.1.0",
        "projection_version": "0.1.0",
        "bundle_schema_version": "1.0.0",
    }

    def __init__(
        self,
        catalog: StartCatalogPort,
        runtime: BundleRuntimePort,
        clock: ClockPort,
    ) -> None:
        self.start_catalog = catalog
        self.runtime = runtime
        self.clock = clock
        self.ids = FixedIds()


def start_request(
    seed: int,
    *,
    mode: str = "create_or_attach",
    title: str = "Exact task",
    refs: bool = False,
    session_id: str | None = None,
) -> StartRequest:
    wire: dict[str, JsonValue] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": protocol_id("req_", seed),
        "actor": {"actor_id": "harness:test", "actor_type": "harness"},
        "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
        "mode": mode,
        "task_title": title,
        "requested_view": "compact",
    }
    if refs:
        wire["workspace_ref"] = "workspace-A"
        wire["external_ref"] = "external-A"
    if session_id is not None:
        wire["session_id"] = session_id
    return StartRequest.model_validate(wire)


def start_composition() -> tuple[
    StartTestApplication,
    MemoryStartRuntime,
    StartTestClock,
    FailOnceStartCatalog,
]:
    clock = StartTestClock()
    ids = FixedIds()
    catalog = MemoryStartCatalogAdapter(
        installation_id=protocol_id("ins_", 700),
        lookup=StartTestLookup(),
        state=MemoryStartCatalogState(),
        transaction_lock=anyio.Lock(),
        clock=clock,
        ids=ids,
    )
    wrapper = FailOnceStartCatalog(cast(StartCatalogPort, catalog))
    runtime = MemoryStartRuntime(clock, ids)
    return (
        StartTestApplication(cast(StartCatalogPort, wrapper), runtime, clock),
        runtime,
        clock,
        wrapper,
    )
