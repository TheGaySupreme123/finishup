"""Issue #839: coordination reads its typed inputs identically from warm and cold task runtimes.

Coordination extracts typed requested items, attempted edit items, and obligation identities from
encrypted accepted payloads.  It used to ask the runtime for a keyless ``STRUCTURAL_READ`` lease.
A warm cache entry opened earlier for writing served that lease with decoded payloads, but a cold
entry (evicted, restarted, or relocked) could not open the production object store at all, and
the post-publish sweep swallowed the failure.  Overlap advice therefore disappeared as soon as a
counterpart task went cold.

These scenarios use the production READY composition from ``builders.multi_agent``: the vault,
catalog, encrypted objects, task ledgers, and runtime routing are real, so a fake opener that
tolerates missing keys cannot stand in for production parity.  Every cold phase recomposes READY
around the same installation with ``relock_and_reopen_multi_agent_service``.
"""

from __future__ import annotations

import subprocess
from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest

from builders.multi_agent import (
    MultiAgentService,
    multi_agent_service,
    relock_and_reopen_multi_agent_service,
)
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application import coordination as coordination_module
from finishup.application import service as service_module
from finishup.application.coordination import CoordinationRuntime
from finishup.application.publish_work import PublishWorkInternalResult
from finishup.application.start import StartInternalResult
from finishup.application.status import StatusInternalResult
from finishup.domain.events import AcceptedEvent, ObligationPublishedPayload
from finishup.domain.findings import FindingKind
from finishup.domain.observation import ObservationRevokeCommand
from finishup.ports.control import RepositoryPrivacyContext
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.keys import BundleKeys
from finishup.ports.ledger import CheckCommitResult
from finishup.ports.runtime import RouteAccess, RouteCommand, TaskRuntime
from finishup.ports.start_catalog import TaskRoute
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import CheckRequest, PublishWorkRequest, StartRequest, StatusRequest

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _identity() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": "harness:cold-coordination", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _workspace(root: Path, name: str) -> Path:
    workspace = (root / name).resolve()
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)
    return workspace


async def _start(service: MultiAgentService, workspace: Path, label: str) -> StartInternalResult:
    return await service.app.start(
        StartRequest.model_validate(
            {
                **_identity(),
                "mode": "create",
                "task_title": f"Cold coordination {label}",
                "workspace_ref": str(workspace),
                "external_ref": f"cold-coordination-{label}",
                "requested_view": "compact",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


def _grant(service: MultiAgentService, workspace: Path) -> str:
    local = LocalObservationStore(_state=service.root / "state")
    commitment = local.workspace_commitment(str(workspace))
    local.grant_consent(commitment)
    return commitment


def _frontier(frontier: object) -> Mapping[str, object]:
    as_wire = getattr(frontier, "as_wire", None)
    assert callable(as_wire)
    return dict(cast(Mapping[str, object], as_wire()).items())


async def _status(service: MultiAgentService, task: StartInternalResult) -> StatusInternalResult:
    result = await service.app.status(
        StatusRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "view": "compact",
                "limit": "1",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, StatusInternalResult)
    return result


def _obligation(resources: Sequence[str], obligation: str | None = None) -> dict[str, object]:
    return {
        "event_id": new_id(IdKind.EVENT),
        "schema": {"name": "obligation_published", "version": "1.0.0"},
        "occurred_at": "2026-09-05T12:00:00.000Z",
        "causal_parents": (),
        "payload": {
            "obligation_id": obligation or new_id(IdKind.OBLIGATION),
            "description": "Typed shared scope.",
            "evidence_expectation": "A recorded coordination decision.",
            "status": "open",
            "requested_items": tuple({"item_kind": "file", "value": item} for item in resources),
        },
        "artifact_refs": (),
        "evidence_refs": (),
    }


async def _publish(
    service: MultiAgentService,
    task: StartInternalResult,
    drafts: Sequence[Mapping[str, object]],
) -> PublishWorkInternalResult:
    status = await _status(service, task)
    result = await service.app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(status.head_frontier),
                "event_drafts": tuple(dict(item) for item in drafts),
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, PublishWorkInternalResult)
    return result


async def _check(service: MultiAgentService, task: StartInternalResult) -> CheckCommitResult:
    status = await _status(service, task)
    result = await service.app.check(
        CheckRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(status.head_frontier),
                "mode": "deterministic_only",
                "max_findings": "10",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, CheckCommitResult)
    return result


def _coordination(service: MultiAgentService) -> CoordinationRuntime:
    return cast(
        CoordinationRuntime, getattr(service.app.project_application, "coordination_runtime")
    )


def _open_entries(service: MultiAgentService) -> int:
    return len(cast(Mapping[str, object], getattr(service.app.runtime, "_entries")))


async def _project(service: MultiAgentService, task: StartInternalResult) -> str:
    project_ids = await service.app.start_catalog.list_task_project_ids(task.task_id)
    assert len(project_ids) == 1
    return project_ids[0]


async def _pair_counts(service: MultiAgentService, project: str) -> dict[frozenset[str], int]:
    counts: dict[frozenset[str], int] = {}
    for detection in await _coordination(service).detector.store.list_detections(project):
        pair = frozenset({detection.left_task_id, detection.right_task_id})
        counts[pair] = counts.get(pair, 0) + 1
    return counts


def _record_key_loads(service: MultiAgentService, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record which task bundles have their keys loaded from the vault from now on."""

    loaded: list[str] = []
    original = service.vault.load_bundle_keys

    async def load_bundle_keys(bundle_id: str) -> BundleKeys:
        loaded.append(bundle_id)
        return await original(bundle_id)

    monkeypatch.setattr(service.vault, "load_bundle_keys", load_bundle_keys)
    return loaded


def _record_ledger_extractions(
    service: MultiAgentService, monkeypatch: pytest.MonkeyPatch
) -> list[str]:
    """Record which tasks have typed work payloads extracted as coordination input."""

    inputs = _coordination(service).inputs
    original = cast(
        Callable[[TaskRoute], Awaitable[object]], getattr(inputs, "_load_ledger_material")
    )
    extracted: list[str] = []

    async def load_ledger_material(route: TaskRoute) -> object:
        extracted.append(route.task_id)
        return await original(route)

    monkeypatch.setattr(inputs, "_load_ledger_material", load_ledger_material)
    return extracted


async def _coverage_task_ids(service: MultiAgentService, project: str) -> set[str]:
    state = await service.app.start_catalog.project_state(project)
    assert state is not None
    rows = await _coordination(service).detector.store.coverage_for(
        project, state.membership_generation
    )
    assert all(
        (row.coverage, row.gap_code.value) == ("unobservable", "not_observable") for row in rows
    )
    return {row.task_id for row in rows}


async def test_cold_inputs_match_warm_and_a_publish_after_reopen_still_detects(
    tmp_path: Path,
) -> None:
    """Same typed resources: warm and cold inputs are equal, and new overlap still lands."""

    workspace = _workspace(tmp_path, "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        left = await _start(service, workspace, "left")
        right = await _start(service, workspace, "right")
        _grant(service, workspace)
        await _publish(service, left, (_obligation(("src/shared.py",)),))
        await _publish(service, right, (_obligation(("src/shared.py", "src/later.py")),))
        project = await _project(service, left)
        assert await _pair_counts(service, project) == {frozenset({left.task_id, right.task_id}): 1}

        warm = [
            await _coordination(service).inputs.input_for(task.task_id) for task in (left, right)
        ]
        assert [item.resources if item else None for item in warm] == [
            ("src/shared.py",),
            ("src/later.py", "src/shared.py"),
        ]
        assert _open_entries(service) == 2

        await relock_and_reopen_multi_agent_service(service)
        assert _open_entries(service) == 0
        loaded = [
            await _coordination(service).inputs.input_for(task.task_id) for task in (left, right)
        ]
        # Every field, including obligation identities and the attributable-path verdict, matches.
        assert loaded == warm
        for task, item in zip((left, right), warm, strict=True):
            assert item is not None and item.obligation_ids
            for obligation in item.obligation_ids:
                assert await _coordination(service).inputs.owns_obligation(task.task_id, obligation)

        await relock_and_reopen_multi_agent_service(service)
        # The native failure: the publisher is warm after its own append, the counterpart is
        # cold, and the post-publish sweep must still read it to deliver the new overlap.
        await _publish(service, left, (_obligation(("src/later.py",)),))
        pair = frozenset({left.task_id, right.task_id})
        assert await _pair_counts(service, project) == {pair: 2}
        detections = await _coordination(service).detector.store.list_detections(project)
        for detection in detections:
            deliveries = await _coordination(service).detector.store.deliveries(
                detection.detection_id
            )
            assert {row.outcome for row in deliveries} == {"delivered"}
            assert {row.target_task_id for row in deliveries} == set(pair)


async def test_cold_distinct_resources_load_without_overlap_or_coverage_gap(
    tmp_path: Path,
) -> None:
    """Different typed resources: cold inputs load, and no pair or coverage row is invented."""

    workspace = _workspace(tmp_path, "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        left = await _start(service, workspace, "left")
        right = await _start(service, workspace, "right")
        _grant(service, workspace)
        await _publish(service, left, (_obligation(("src/left.py",)),))
        await _publish(service, right, (_obligation(("src/right.py",)),))
        project = await _project(service, left)
        # ``right`` had no typed resource during the first sweep, so that sweep already recorded
        # its bounded coverage row.  A cold sweep must not add one for a readable task.
        coverage_before = await _coverage_task_ids(service, project)

        await relock_and_reopen_multi_agent_service(service)
        assert _open_entries(service) == 0
        cold = [
            await _coordination(service).inputs.input_for(task.task_id) for task in (left, right)
        ]
        assert [item.resources if item else None for item in cold] == [
            ("src/left.py",),
            ("src/right.py",),
        ]
        assert all(item is not None and item.source_has_attributable_paths for item in cold)
        assert await _coordination(service).sweep(project) == ()
        assert await _pair_counts(service, project) == {}
        assert await _coverage_task_ids(service, project) == coverage_before


async def test_cold_duplicate_finding_advice_reads_the_counterpart_findings(
    tmp_path: Path,
) -> None:
    """Check's project advice reads a cold counterpart's typed findings through payload access."""

    workspace = _workspace(tmp_path, "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        tasks = (
            await _start(service, workspace, "left"),
            await _start(service, workspace, "right"),
        )
        _grant(service, workspace)
        for task in tasks:
            obligation = new_id(IdKind.OBLIGATION)
            claim = {
                "event_id": new_id(IdKind.EVENT),
                "schema": {"name": "claim_recorded", "version": "1.0.0"},
                "occurred_at": "2026-09-05T12:00:00.000Z",
                "causal_parents": (),
                "payload": {
                    "claim_id": new_id(IdKind.CLAIM),
                    "claim_kind": "completion",
                    "statement": "The work is complete.",
                    "supporting_refs": (obligation,),
                    "obligation_refs": (obligation,),
                },
                "artifact_refs": (),
                "evidence_refs": (),
            }
            await _publish(service, task, (_obligation(("src/shared.py",), obligation), claim))
        assert (await _check(service, tasks[1])).findings

        await relock_and_reopen_multi_agent_service(service)
        checked = await _check(service, tasks[0])
        notes = {note.kind: note for note in checked.advisory_notes}
        assert notes["duplicate_finding"].task_ids == tuple(
            sorted((tasks[0].task_id, tasks[1].task_id))
        )


async def test_cold_overlap_stays_advice_first_until_an_explicit_declaration(
    tmp_path: Path,
) -> None:
    """After a relock, ordinary overlap is advice; only a typed declaration purchases a finding."""

    workspace = _workspace(tmp_path, "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        left = await _start(service, workspace, "left")
        right = await _start(service, workspace, "right")
        _grant(service, workspace)
        left_obligation = new_id(IdKind.OBLIGATION)
        await _publish(service, left, (_obligation(("src/shared.py",), left_obligation),))

        await relock_and_reopen_multi_agent_service(service)
        # The first overlap is produced by a publish whose counterpart is cold.
        await _publish(service, right, (_obligation(("src/shared.py",)),))
        project = await _project(service, left)
        detections = await _coordination(service).detector.store.list_detections(project)
        assert len(detections) == 1
        detection = detections[0]
        assert detection.advice_only

        await relock_and_reopen_multi_agent_service(service)
        advice = await _check(service, left)
        assert [note.kind for note in advice.advisory_notes] == ["live_member_present"]
        assert not any(item.kind is FindingKind.COORDINATION_OVERLAP for item in advice.findings)

        await relock_and_reopen_multi_agent_service(service)
        # Declaration validation reads the declaring task's own obligation from a cold entry.
        await _publish(
            service,
            left,
            (
                {
                    "event_id": new_id(IdKind.EVENT),
                    "schema": {"name": "coordination_obligation_declared", "version": "1.0.0"},
                    "occurred_at": "2026-09-05T12:00:00.000Z",
                    "causal_parents": (),
                    "payload": {
                        "detection_id": detection.detection_id,
                        "project_id": project,
                        "membership_generation": str(detection.membership_generation),
                        "recipient_task_id": left.task_id,
                        "obligation_id": left_obligation,
                    },
                    "artifact_refs": (),
                    "evidence_refs": (),
                },
            ),
        )
        await relock_and_reopen_multi_agent_service(service)
        declared = await _check(service, left)
        assert [item.kind for item in declared.findings].count(
            FindingKind.COORDINATION_OVERLAP
        ) == 1


async def test_revoked_source_contributes_no_input_and_admitted_pairs_survive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Revocation: the revoked source's work payloads are never extracted; other pairs detect.

    Production admission proves workspace consent by reading the source's authenticated
    session-opened locator, so the revoked task's runtime may be opened for that check.  What
    must never happen is extracting its typed work payloads as detector input.
    """

    primary = _workspace(tmp_path, "primary")
    other = _workspace(tmp_path, "other")
    async with multi_agent_service(tmp_path / "state") as service:
        left = await _start(service, primary, "left")
        right = await _start(service, primary, "right")
        revoked = await _start(service, other, "revoked")
        _grant(service, primary)
        other_commitment = _grant(service, other)
        for task in (left, right, revoked):
            await _publish(service, task, (_obligation(("src/shared.py",)),))
        await _publish(service, revoked, (_obligation(("src/next.py",)),))
        project = await _project(service, left)
        before = await _pair_counts(service, project)
        assert set(before) == {
            frozenset({left.task_id, right.task_id}),
            frozenset({left.task_id, revoked.task_id}),
            frozenset({right.task_id, revoked.task_id}),
        }
        coverage_before = await _coverage_task_ids(service, project)

        LocalObservationStore(_state=service.root / "state").revoke(
            ObservationRevokeCommand(other_commitment)
        )
        await relock_and_reopen_multi_agent_service(service)
        extracted = _record_ledger_extractions(service, monkeypatch)
        assert await _coordination(service).inputs.input_for(revoked.task_id, project) is None
        assert extracted == []

        await _publish(service, left, (_obligation(("src/next.py",)),))
        await _publish(service, right, (_obligation(("src/next.py",)),))
        after = await _pair_counts(service, project)
        admitted_pair = frozenset({left.task_id, right.task_id})
        # The admitted pair gains the successor detection for its new shared resource even
        # though the revoked task's ledger also names that resource.
        assert after[admitted_pair] == before[admitted_pair] + 1
        assert {pair: count for pair, count in after.items() if pair != admitted_pair} == {
            pair: count for pair, count in before.items() if pair != admitted_pair
        }
        assert revoked.task_id not in extracted
        assert {left.task_id, right.task_id} <= set(extracted)
        # Rows recorded before the revocation stay durable; the revoked source gains nothing new.
        assert await _coverage_task_ids(service, project) == coverage_before


async def test_structural_leases_expose_no_payload_warm_or_cold(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No-key reads: a structural lease never sees payload content, whatever the cache state."""

    workspace = _workspace(tmp_path, "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        task = await _start(service, workspace, "structural")
        _grant(service, workspace)
        await _publish(service, task, (_obligation(("src/secret-path.py",)),))
        route = await service.app.start_catalog.task_route(task.task_id)
        assert route is not None

        async def records(access: RouteAccess) -> tuple[AcceptedEvent, ...]:
            capabilities = {RuntimeCapability.STRUCTURAL_READ}
            if access is RouteAccess.PAYLOAD_READ:
                capabilities.add(RuntimeCapability.PAYLOAD_READ)
            runtime = await service.app.runtime.route(
                RouteCommand(route.session_id, None, access, frozenset(capabilities))
            )
            assert type(runtime) is TaskRuntime
            try:
                return tuple(
                    [
                        record
                        async for record in runtime.ledger.load_events(runtime.session_id)
                        if type(record) is AcceptedEvent
                        and record.schema.name == "obligation_published"
                    ]
                )
            finally:
                await service.app.runtime.release(runtime)

        # Warm: the entry was opened for writing and holds decoded payloads.
        assert _open_entries(service) == 1
        structural = await records(RouteAccess.STRUCTURAL_READ)
        payload = await records(RouteAccess.PAYLOAD_READ)
        assert len(structural) == len(payload) == 1
        assert structural[0].payload is None
        assert structural[0].entry_digest == payload[0].entry_digest
        assert isinstance(payload[0].payload, ObligationPublishedPayload)
        assert [item.value for item in payload[0].payload.requested_items] == ["src/secret-path.py"]
        runtime = await service.app.runtime.route(
            RouteCommand(
                route.session_id,
                None,
                RouteAccess.STRUCTURAL_READ,
                frozenset({RuntimeCapability.STRUCTURAL_READ}),
            )
        )
        try:
            for name in ("load_projection", "query_projection", "load_case_availability"):
                assert not hasattr(runtime.ledger, name)
            assert not hasattr(runtime.objects, "open_verified")
        finally:
            await service.app.runtime.release(runtime)

        # Cold: a structural open loads no key and the production object opener fails closed.
        await relock_and_reopen_multi_agent_service(service)
        loaded = _record_key_loads(service, monkeypatch)
        with pytest.raises(ValueError, match="runtime_object_store_invalid"):
            await records(RouteAccess.STRUCTURAL_READ)
        assert loaded == []
        assert _open_entries(service) == 0
        cold_payload = await records(RouteAccess.PAYLOAD_READ)
        assert loaded == [task.task_id]
        assert cold_payload == payload


async def test_one_unreadable_task_is_isolated_as_bounded_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An admitted task whose input read fails becomes coverage; the other pairs still detect."""

    workspace = _workspace(tmp_path, "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        requester = await _start(service, workspace, "requester")
        busy = await _start(service, workspace, "busy")
        sibling = await _start(service, workspace, "sibling")
        _grant(service, workspace)
        await _publish(service, busy, (_obligation(("src/busy.py",)),))
        await _publish(service, sibling, (_obligation(("src/sibling.py",)),))
        project = await _project(service, requester)
        assert await _pair_counts(service, project) == {}
        # Earlier sweeps saw ``requester`` without typed resources and recorded its gap.
        coverage_before = await _coverage_task_ids(service, project)
        assert busy.task_id not in coverage_before

        await relock_and_reopen_multi_agent_service(service)
        inputs = _coordination(service).inputs
        original = cast(
            Callable[[TaskRoute], Awaitable[object]], getattr(inputs, "_load_ledger_material")
        )

        async def load_ledger_material(route: TaskRoute) -> object:
            # Admission for ``busy`` still succeeds; only its coordination read fails.
            if route.task_id == busy.task_id:
                raise PublicOperationError(
                    PublicErrorCode.BUNDLE_BUSY, "The task is temporarily busy.", True
                )
            return await original(route)

        diagnostics: list[tuple[str, str, str]] = []

        def record(exc: BaseException, *, component: str, operation: str, **_: object) -> str:
            diagnostics.append((type(exc).__name__, component, operation))
            return new_id(IdKind.CORRELATION)

        monkeypatch.setattr(inputs, "_load_ledger_material", load_ledger_material)
        monkeypatch.setattr(
            coordination_module, "record_classified_exception_without_raising", record
        )
        await _publish(service, requester, (_obligation(("src/busy.py", "src/sibling.py")),))

        assert await _pair_counts(service, project) == {
            frozenset({requester.task_id, sibling.task_id}): 1
        }
        assert await _coverage_task_ids(service, project) == coverage_before | {busy.task_id}
        assert diagnostics == [
            ("PublicOperationError", "application.coordination", "coordination_input_unavailable")
        ]

        # Once the input is readable again the next sweep delivers the missing pair.
        monkeypatch.setattr(inputs, "_load_ledger_material", original)
        await _coordination(service).sweep(project)
        assert await _pair_counts(service, project) == {
            frozenset({requester.task_id, sibling.task_id}): 1,
            frozenset({requester.task_id, busy.task_id}): 1,
        }


async def test_post_publish_sweep_failure_is_recorded_not_silent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed sweep keeps publish successful and leaves one bounded diagnostic behind."""

    workspace = _workspace(tmp_path, "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        left = await _start(service, workspace, "left")
        await _start(service, workspace, "right")
        _grant(service, workspace)
        coordination = _coordination(service)

        async def failing_sweep(**_: object) -> tuple[object, ...]:
            raise RuntimeError("synthetic sweep failure with /private/path text")

        diagnostics: list[tuple[str, str, str, str | None]] = []

        def record(
            exc: BaseException,
            *,
            component: str,
            operation: str,
            request_id: str | None = None,
        ) -> str:
            diagnostics.append((type(exc).__name__, component, operation, request_id))
            return new_id(IdKind.CORRELATION)

        monkeypatch.setattr(coordination, "sweep", failing_sweep)
        monkeypatch.setattr(service_module, "record_classified_exception_without_raising", record)
        published = await _publish(service, left, (_obligation(("src/shared.py",)),))
        assert published.outcome == "accepted"
        assert diagnostics == [
            (
                "RuntimeError",
                "application.service",
                "project_coordination_sweep",
                published.request_id,
            )
        ]
