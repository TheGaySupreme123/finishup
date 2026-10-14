"""Public receipt acceptance rows left by the #500/#509 matrix audit.

The neighboring parent-lineage scenario intentionally exercises a mixed, incomplete matrix.  This
module keeps the remaining acceptance rows small and explicit: a genuinely clean child, invalid
acceptance transition, abandoned or cancelled work with late evidence, source-read gaps,
a rejected unaccepted child, qualifying rechecks, and replay from either the parent's recorded
operation or a standalone copied parent ledger.
"""

from __future__ import annotations

import shutil
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from builders.multi_agent import multi_agent_service, private_service_root
from builders.review_manifests import provider_bound_manifest
from yoetz.adapters.sqlite.connection import open_read_only
from yoetz.adapters.sqlite.repository import SqliteLedger
from yoetz.application.check import FinalSemanticEvaluation
from yoetz.application.publish_work import PublishWorkInternalResult
from yoetz.application.receipt import (  # pyright: ignore[reportPrivateUsage]
    _context,  # pyright: ignore[reportPrivateUsage]
    _replay_result,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.application.start import StartInternalResult
from yoetz.config.models import YoetzConfig
from yoetz.domain.coordination import SessionHealth, WorkState
from yoetz.domain.findings import SemanticDispatchKind, SemanticProvenance
from yoetz.domain.receipts import receipt_document_from_json, receipt_document_to_json
from yoetz.kernel.deterministic_checks import build_deterministic_case
from yoetz.kernel.receipt_builder import build_receipt
from yoetz.kernel.reducers import replay
from yoetz.ports.control import RepositoryPrivacyContext
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.ledger import CheckCommitResult
from yoetz.ports.objects import ObjectRef, ObjectStorePort
from yoetz.ports.runtime import (
    OwnershipFence,
    RouteAccess,
    RouteCommand,
    TaskRuntime,
)
from yoetz.ports.semantic import SamplingParams, SemanticJudgment
from yoetz.ports.start_catalog import TaskRouteState
from yoetz.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptInclude,
    ReceiptRedactionProfile,
    ReceiptRequest,
    SemanticReason,
    SemanticStatus,
    StartRequest,
    StatusRequest,
)
from yoetz.service.ready_composition import IdPort

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _clean_config() -> YoetzConfig:
    """Use the normal optional semantic policy with a local scripted evaluator below."""

    return YoetzConfig()


_DIGEST = "sha256:" + "7" * 64


async def _semantic_succeeds(
    frozen: object,
    findings: object,
    runtime: object | None = None,
    lineage_evaluation: object | None = None,
) -> FinalSemanticEvaluation:
    """Provide a bounded, synthetic success so this matrix can test rollup wording locally."""

    del frozen, findings, runtime, lineage_evaluation
    return FinalSemanticEvaluation(
        SemanticStatus.SUCCEEDED,
        SemanticReason.SEMANTIC_COMPLETED,
        judgment=SemanticJudgment("no_material_discrepancy", ()),
        provenance=SemanticProvenance(
            provider="fake",
            endpoint_profile_id="fake",
            endpoint_profile_version="1.0.0",
            model="fake/model",
            sdk_version="1.0.0",
            prompt_digest=_DIGEST,
            schema_digest=_DIGEST,
            policy_digest=_DIGEST,
            privacy_policy_digest=_DIGEST,
            sampling_params=SamplingParams(128),
            latency_ms=1,
            semantic_attempt_id=new_id(IdKind.SEMANTIC_ATTEMPT),
            dispatch_kind=SemanticDispatchKind.EXTERNAL,
            privacy_receipt_id=new_id(IdKind.EGRESS_RECEIPT),
            status=SemanticStatus.SUCCEEDED,
            reason=SemanticReason.SEMANTIC_COMPLETED,
            provider_request_id="fake-request",
            egress_authorization_id=new_id(IdKind.EGRESS_AUTHORIZATION),
            request_commitment="hmac-sha256:" + "8" * 64,
        ),
        provider_input_manifest=provider_bound_manifest(),
    )


async def _evaluate_semantic_check(
    _app: object,
    frozen: object,
    findings: object,
    runtime: object | None = None,
    lineage_evaluation: object | None = None,
) -> FinalSemanticEvaluation:
    return await _semantic_succeeds(frozen, findings, runtime, lineage_evaluation)


def _identity() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": "harness:lineage-receipt-acceptance", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _workspace(root: Path) -> Path:
    import subprocess

    root.mkdir()
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
    return root.resolve()


def _event(
    name: str, payload: Mapping[str, object], *, parent: str | None = None
) -> dict[str, object]:
    return {
        "event_id": new_id(IdKind.EVENT),
        "schema": {"name": name, "version": "1.0.0"},
        "occurred_at": "2026-09-05T12:00:00.000Z",
        "causal_parents": () if parent is None else (parent,),
        "payload": dict(payload),
        "artifact_refs": (),
        "evidence_refs": (),
    }


async def _current_frontier(service: object, task: StartInternalResult) -> object:
    app = getattr(service, "app")
    status = await app.status(
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
    return status.head_frontier


def _frontier_json(frontier: object) -> Mapping[str, object]:
    as_wire = getattr(frontier, "as_wire", None)
    if callable(as_wire):
        return dict(cast(Mapping[str, object], as_wire()).items())
    model_dump = getattr(frontier, "model_dump", None)
    if callable(model_dump):
        return cast(Mapping[str, object], model_dump(mode="json"))
    raise AssertionError("frontier shape is not serializable")


async def _publish(
    service: object,
    task: StartInternalResult,
    drafts: Sequence[Mapping[str, object]],
) -> PublishWorkInternalResult:
    app = getattr(service, "app")
    frontier = await _current_frontier(service, task)
    result = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier_json(frontier),
                "event_drafts": tuple(dict(draft) for draft in drafts),
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, PublishWorkInternalResult)
    return result


async def _check(
    service: object,
    task: StartInternalResult,
    *,
    expected_frontier: object | None = None,
    mode: str = "deterministic_only",
) -> CheckCommitResult:
    app = getattr(service, "app")
    frontier = (
        await _current_frontier(service, task) if expected_frontier is None else expected_frontier
    )
    result = await app.check(
        CheckRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier_json(frontier),
                "mode": mode,
                "max_findings": "10",
                "policy_packs": ["research-evidence/0.2.0", "work-integrity/0.3.0"],
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, CheckCommitResult)
    return result


async def _receipt(
    service: object,
    task: StartInternalResult,
    checked: CheckCommitResult,
    *,
    request_id: str | None = None,
    expected_frontier: object | None = None,
):
    identity = _identity()
    if request_id is not None:
        identity["request_id"] = request_id
    return await getattr(service, "app").receipt(
        ReceiptRequest.model_validate(
            {
                **identity,
                "task_id": task.task_id,
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier_json(
                    checked.result_frontier if expected_frontier is None else expected_frontier
                ),
                "format": "json",
                "include": "standard",
                "redaction_profile": "default_local_export",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def _delegated_child(
    service: object, parent: StartInternalResult, title: str
) -> StartInternalResult:
    app = getattr(service, "app")
    delegated = await app.start(
        StartRequest.model_validate(
            {
                **_identity(),
                "mode": "delegate",
                "task_title": title,
                "session_id": parent.session_id,
                "requested_view": "compact",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert delegated.attach_handle is not None
    return await app.start(
        StartRequest.model_validate(
            {
                **_identity(),
                "mode": "attach",
                "task_title": title,
                "attach_handle": delegated.as_wire()["attach_handle"],
                "requested_view": "compact",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def _close_work(service: object, task: StartInternalResult) -> None:
    await _publish(service, task, (_event("work_closed", {}),))


async def _drain_lineage(service: object) -> None:
    sweep = getattr(getattr(service, "app"), "observation_sweep", None)
    if sweep is not None:
        await sweep()


async def _publish_clean_work(service: object, task: StartInternalResult) -> None:
    obligation_id = new_id(IdKind.OBLIGATION)
    action_id = new_id(IdKind.ACTION)
    result_id = new_id(IdKind.RESULT)
    await _publish(
        service,
        task,
        (
            _event(
                "plan_published",
                {
                    "plan_version": 1,
                    "summary": "Complete the clean child work.",
                    "obligation_refs": (obligation_id,),
                },
            ),
            _event(
                "obligation_published",
                {
                    "obligation_id": obligation_id,
                    "description": "Record the clean child result.",
                    "acceptance_criteria": "The clean child result is successful.",
                    "evidence_expectation": "A successful result is recorded.",
                    "requested_items": (),
                    "status": "open",
                },
            ),
            _event(
                "action_recorded",
                {
                    "action_id": action_id,
                    "action_kind": "review",
                    "description": "Perform the clean child review.",
                    "obligation_refs": (obligation_id,),
                },
            ),
            _event(
                "result_recorded",
                {
                    "result_id": result_id,
                    "action_id": action_id,
                    "outcome": "success",
                    "exit_status": 0,
                    "summary": "The clean child review succeeded.",
                },
            ),
            _event(
                "claim_recorded",
                {
                    "claim_id": new_id(IdKind.CLAIM),
                    "claim_kind": "completion",
                    "statement": "The clean child work is complete.",
                    "supporting_refs": (result_id,),
                    "obligation_refs": (obligation_id,),
                },
            ),
        ),
    )
    await _publish(
        service,
        task,
        (
            _event(
                "obligation_published",
                {
                    "obligation_id": obligation_id,
                    "description": "Record the clean child result.",
                    "acceptance_criteria": "The clean child result is successful.",
                    "evidence_expectation": "A successful result is recorded.",
                    "requested_items": (),
                    "status": "resolved",
                    "resolution_evidence_refs": (result_id,),
                },
            ),
        ),
    )


def _children(document: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
    section = cast(Mapping[str, object], document["children"])
    return tuple(cast(Sequence[Mapping[str, object]], section["children"]))


async def test_clean_accepted_child_produces_clean_parent_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A closed, checked, receipted accepted child can support clean parent wording."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state", config=_clean_config()) as service:
        monkeypatch.setattr(type(service.app), "evaluate_semantic_check", _evaluate_semantic_check)
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Clean parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "clean-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        await _publish_clean_work(service, parent)
        child = await _delegated_child(service, parent, "Clean accepted child")
        await _publish_clean_work(service, child)
        await _close_work(service, child)
        child_check = await _check(service, child, mode="semantic_if_configured")
        child_receipt = await _receipt(service, child, child_check)
        assert child_receipt.conclusion == "no_unresolved_deterministic_findings", (
            child_receipt.conclusion,
            getattr(child_receipt.coverage, "known_gaps", None),
            child_check.semantic_status,
            child_check.semantic_reason,
        )
        await _drain_lineage(service)

        parent_check = await _check(service, parent, mode="semantic_if_configured")
        ready = await service.app.status(
            StatusRequest.model_validate(
                {
                    **_identity(),
                    "session_id": parent.session_id,
                    "writer_id": parent.writer_id,
                    "view": "compact",
                    "limit": "1",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert ready.closure_readiness.blocking_conditions == ()
        parent_receipt = await _receipt(service, parent, parent_check)
        assert parent_receipt.conclusion == "no_unresolved_deterministic_findings"
        assert parent_receipt.document is not None
        row = next(
            item
            for item in _children(cast(Mapping[str, object], parent_receipt.document))
            if item["child_task_id"] == child.task_id
        )
        assert row["outcome"] == "clean"
        assert row["freshness"] == "known"


async def test_no_child_receipt_replays_with_empty_children_section(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The additive children section is empty and byte-stable for a parent without children."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state", config=_clean_config()) as service:
        monkeypatch.setattr(type(service.app), "evaluate_semantic_check", _evaluate_semantic_check)
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "No-child parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "no-child-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        await _publish_clean_work(service, parent)
        checked = await _check(service, parent, mode="semantic_if_configured")
        request_id = new_id(IdKind.REQUEST)
        first = await _receipt(service, parent, checked, request_id=request_id)
        replay = await _receipt(service, parent, checked, request_id=request_id)
        assert first.conclusion == "no_unresolved_deterministic_findings"
        assert first.document is not None
        assert _children(cast(Mapping[str, object], first.document)) == ()
        assert replay.receipt_digest == first.receipt_digest
        assert replay.document == first.document


async def test_later_child_manifest_is_cleared_by_qualifying_parent_recheck(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A later recorded child manifest first creates a gap, then a recheck can clear it."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state", config=_clean_config()) as service:
        monkeypatch.setattr(type(service.app), "evaluate_semantic_check", _evaluate_semantic_check)
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Recheck parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "recheck-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        await _publish_clean_work(service, parent)
        child = await _delegated_child(service, parent, "Rechecked child")
        await _drain_lineage(service)
        first_check = await _check(service, parent, mode="semantic_if_configured")
        first_receipt = await _receipt(service, parent, first_check)
        assert first_receipt.conclusion == "insufficient_coverage"

        await _publish_clean_work(service, child)
        await _close_work(service, child)
        child_check = await _check(service, child, mode="semantic_if_configured")
        await _receipt(service, child, child_check)
        await _drain_lineage(service)

        latest_parent_frontier = await _current_frontier(service, parent)
        later = await _receipt(
            service,
            parent,
            first_check,
            expected_frontier=latest_parent_frontier,
        )
        assert later.document is not None
        later_document = cast(Mapping[str, object], later.document)
        later_row = next(
            item for item in _children(later_document) if item["child_task_id"] == child.task_id
        )
        assert later_row["later_manifest_ref"] is not None
        later_coverage = cast(Mapping[str, object], later_document["coverage"])
        assert "lineage_manifest_uncovered" in cast(Sequence[object], later_coverage["known_gaps"])

        rechecked = await _check(service, parent, mode="semantic_if_configured")
        final = await _receipt(service, parent, rechecked)
        assert final.conclusion == "no_unresolved_deterministic_findings"
        assert final.document is not None
        final_row = next(
            item
            for item in _children(cast(Mapping[str, object], final.document))
            if item["child_task_id"] == child.task_id
        )
        assert final_row["outcome"] == "clean"
        assert final_row.get("later_manifest_ref") is None


async def test_parent_receipt_replay_does_not_read_child_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A receipt replay is reproducible from the parent operation after child reads are blocked."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state", config=_clean_config()) as service:
        monkeypatch.setattr(type(service.app), "evaluate_semantic_check", _evaluate_semantic_check)
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Replay parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "replay-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        await _publish_clean_work(service, parent)
        child = await _delegated_child(service, parent, "Replay child")
        await _publish_clean_work(service, child)
        await _close_work(service, child)
        child_check = await _check(service, child, mode="semantic_if_configured")
        await _receipt(service, child, child_check)
        await _drain_lineage(service)
        parent_check = await _check(service, parent, mode="semantic_if_configured")
        request_id = new_id(IdKind.REQUEST)
        first = await _receipt(service, parent, parent_check, request_id=request_id)

        original = service.app.start_catalog.task_lineage

        async def forbidden_child_read(task_id: str) -> object:
            if task_id == child.task_id:
                raise AssertionError("receipt replay read child lineage")
            return await original(task_id)

        monkeypatch.setattr(service.app.start_catalog, "task_lineage", forbidden_child_read)
        replay = await _receipt(service, parent, parent_check, request_id=request_id)
        assert replay.receipt_digest == first.receipt_digest
        assert replay.document == first.document


@pytest.mark.parametrize("source_state", ("missing", "unreadable", "quarantined", "revoked"))
async def test_parent_receipt_names_child_source_read_gaps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_state: str,
) -> None:
    """Source authority failures remain named unavailable child outcomes."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Source-gap parent",
                    "workspace_ref": str(workspace),
                    "external_ref": f"source-gap-{source_state}",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        child = await _delegated_child(service, parent, f"{source_state} child")
        catalog = service.app.start_catalog
        if source_state == "missing":
            original = catalog.task_source_provenance

            async def missing_provenance(task_id: str) -> object:
                if task_id == child.task_id:
                    return None
                return await original(task_id)

            monkeypatch.setattr(catalog, "task_source_provenance", missing_provenance)
        elif source_state == "unreadable":
            original = catalog.task_session_state

            async def unreadable_session(session_id: str) -> object:
                if session_id == child.session_id:
                    return None
                return await original(session_id)

            monkeypatch.setattr(catalog, "task_session_state", unreadable_session)
        elif source_state == "quarantined":
            original = catalog.task_route

            async def quarantined_route(task_id: str) -> object:
                route = await original(task_id)
                if task_id == child.task_id and route is not None:
                    return replace(route, state=TaskRouteState.QUARANTINED)
                return route

            monkeypatch.setattr(catalog, "task_route", quarantined_route)
        else:
            original = catalog.task_source_provenance

            async def revoked_provenance(task_id: str) -> object:
                source = await original(task_id)
                if task_id == child.task_id and source is not None:
                    return replace(
                        source,
                        repository_privacy_commitment="hmac-sha256:" + "e" * 64,
                    )
                return source

            monkeypatch.setattr(catalog, "task_source_provenance", revoked_provenance)

        await _drain_lineage(service)
        checked = await _check(service, parent)
        assert checked.children is not None
        (preview,) = checked.children.items
        assert preview.rollup_state.value == "unavailable"
        assert "lineage_child_read_gap" in preview.blocking_conditions
        receipt = await _receipt(service, parent, checked)
        assert receipt.document is not None
        document = cast(Mapping[str, object], receipt.document)
        row = next(item for item in _children(document) if item["child_task_id"] == child.task_id)
        assert row["outcome"] == "unavailable"
        coverage = cast(Mapping[str, object], document["coverage"])
        assert "lineage_child_unavailable" in cast(Sequence[object], coverage["known_gaps"])


async def test_accepted_child_cannot_be_rejected_through_public_parent_event(
    tmp_path: Path,
) -> None:
    """An accepted parent-minted child rejects the reverse transition before append."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Acceptance parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "acceptance-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        child = await _delegated_child(service, parent, "Already accepted child")
        with pytest.raises(PublicOperationError) as caught:
            await _publish(
                service,
                parent,
                (
                    _event(
                        "child_rejected",
                        {"child_task_id": child.task_id},
                    ),
                ),
            )
        assert caught.value.code is PublicErrorCode.SESSION_CONFLICT
        assert caught.value.safe_details["reason_code"] == "lineage_acceptance_transition"
        lineage = await service.app.start_catalog.task_lineage(child.task_id)
        assert lineage is not None
        assert lineage.acceptance is not None
        assert lineage.acceptance.value == "accepted"


async def test_contact_lost_abandoned_child_late_evidence_is_incomplete_gap(
    tmp_path: Path,
) -> None:
    """Abandonment stays visible when a late child publication reopens only its session."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Abandonment parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "abandonment-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        child = await _delegated_child(service, parent, "Late evidence child")
        service.clock.advance(seconds=61)
        await service.app.recover_lineage()
        contact_lost = await service.app.start_catalog.task_lineage(child.task_id)
        contact_lost_session = await service.app.start_catalog.task_session_state(child.session_id)
        assert contact_lost is not None
        assert contact_lost_session is not None
        assert contact_lost_session.health is SessionHealth.CONTACT_LOST
        assert contact_lost.work_state is WorkState.OPEN

        service.clock.advance(seconds=301)
        await service.app.recover_lineage()
        abandoned = await service.app.start_catalog.task_lineage(child.task_id)
        abandoned_session = await service.app.start_catalog.task_session_state(child.session_id)
        assert abandoned is not None
        assert abandoned_session is not None
        assert abandoned_session.health is SessionHealth.CONTACT_LOST
        assert abandoned.work_state is WorkState.ABANDONED

        # The old child session may publish a late action after the recovery window.  The parent
        # must retain the recorded incomplete dependency instead of promoting that late frontier
        # to a clean accepted-child result.
        await _publish(
            service,
            child,
            (
                _event(
                    "action_recorded",
                    {
                        "action_id": new_id(IdKind.ACTION),
                        "action_kind": "review",
                        "description": "Late evidence after recovery abandonment.",
                    },
                ),
            ),
        )
        renewed_session = await service.app.start_catalog.task_session_state(child.session_id)
        terminal_work = await service.app.start_catalog.task_lineage(child.task_id)
        assert renewed_session is not None and renewed_session.health is SessionHealth.ACTIVE
        assert terminal_work is not None and terminal_work.work_state is WorkState.ABANDONED
        await _drain_lineage(service)
        parent_check = await _check(service, parent)
        assert parent_check.children is not None
        row = next(
            item for item in parent_check.children.items if item.child_task_id == child.task_id
        )
        assert row.rollup_state.value == "incomplete"
        receipt = await _receipt(service, parent, parent_check)
        assert receipt.document is not None
        child_row = next(
            item for item in _children(receipt.document) if item["child_task_id"] == child.task_id
        )
        assert child_row["outcome"] == "incomplete"
        coverage = cast(Mapping[str, object], receipt.document["coverage"])
        assert "lineage_child_incomplete" in cast(Sequence[object], coverage["known_gaps"])


async def test_cancelled_accepted_child_retains_incomplete_parent_dependency(
    tmp_path: Path,
) -> None:
    """A public delegation cancellation keeps the accepted child and incomplete wording."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Cancellation parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "cancellation-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        child = await _delegated_child(service, parent, "Cancelled accepted child")
        await _publish(
            service,
            parent,
            (
                _event(
                    "delegation_cancelled",
                    {"child_task_id": child.task_id, "reason_code": "user_cancelled"},
                ),
            ),
        )

        lineage = await service.app.start_catalog.task_lineage(child.task_id)
        assert lineage is not None
        assert lineage.parent_task_id == parent.task_id
        assert lineage.acceptance is not None
        assert lineage.acceptance.value == "accepted"
        assert lineage.work_state is WorkState.CANCELLED

        await _drain_lineage(service)
        checked = await _check(service, parent)
        assert checked.children is not None
        preview = next(
            item for item in checked.children.items if item.child_task_id == child.task_id
        )
        assert preview.rollup_state.value == "incomplete"
        assert "lineage_child_incomplete" in preview.blocking_conditions

        receipt = await _receipt(service, parent, checked)
        assert receipt.conclusion == "insufficient_coverage"
        assert receipt.document is not None
        child_row = next(
            item for item in _children(receipt.document) if item["child_task_id"] == child.task_id
        )
        assert child_row["outcome"] == "incomplete"
        coverage = cast(Mapping[str, object], receipt.document["coverage"])
        assert "lineage_child_incomplete" in cast(Sequence[object], coverage["known_gaps"])


async def test_parent_receipt_reconstructs_from_copied_parent_bundle_without_child_runtime(
    tmp_path: Path,
) -> None:
    """A copied parent ledger and its owned objects reproduce the frozen receipt exactly."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Standalone reconstruction parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "standalone-reconstruction-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        child = await _delegated_child(service, parent, "Unreachable child runtime")
        await _drain_lineage(service)
        checked = await _check(service, parent)
        receipt_request_id = new_id(IdKind.REQUEST)
        original = await _receipt(
            service,
            parent,
            checked,
            request_id=receipt_request_id,
        )
        assert original.document is not None

        # Capture the parent route, ledger records, and parent-owned object plaintext before the
        # live composition is closed.  The copied replay below receives no catalog or child route.
        route = await service.app.start_catalog.task_route(parent.task_id)
        assert route is not None
        runtime = await service.app.runtime.route(
            RouteCommand(
                parent.session_id,
                parent.writer_id,
                RouteAccess.PAYLOAD_READ,
                frozenset({RuntimeCapability.PAYLOAD_READ}),
            )
        )
        operation = await runtime.ledger.lookup_operation(parent.writer_id, receipt_request_id)
        assert operation is not None
        assert operation.result_locator is not None
        receipt_ref = operation.result_locator.result_object_ref
        assert receipt_ref is not None
        records = tuple(
            [
                record
                async for record in runtime.ledger.load_events(
                    parent.session_id,
                    through=operation.result_locator.last_ingestion_sequence,
                )
            ]
        )
        owned_objects: dict[str, bytes] = {}
        parent_object_refs = cast(
            Mapping[str, ObjectRef],
            getattr(getattr(getattr(runtime.ledger, "_value"), "_state"), "object_refs"),
        )
        owned_refs = dict(parent_object_refs)
        owned_refs[receipt_ref.object_id] = receipt_ref
        assert {record.payload_ref.object_id for record in records} <= owned_refs.keys()
        for object_ref in owned_refs.values():
            owned_objects[object_ref.object_id] = b"".join(
                [chunk async for chunk in runtime.objects.open_verified(object_ref)]
            )
        source_bundle = service.root / route.bundle_relpath
        assert source_bundle.is_dir()
        await service.app.close()

        with private_service_root() as standalone_root:
            copied_bundle = standalone_root / route.bundle_relpath
            copied_bundle.parent.mkdir(parents=True)
            shutil.copytree(source_bundle, copied_bundle)
            owned_root = standalone_root / "owned_objects"
            owned_root.mkdir()
            for object_id, data in owned_objects.items():
                (owned_root / f"{object_id}.bin").write_bytes(data)
            assert not (standalone_root / "tasks" / child.task_id).exists()

            class _CopiedObjects:
                def __init__(self, *, reject_object_id: str | None = None) -> None:
                    self._reject_object_id = reject_object_id

                async def resolve_verified(self, object_id: str, envelope_digest: str) -> ObjectRef:
                    ref = owned_refs[object_id]
                    if ref.envelope_digest != envelope_digest:
                        raise ValueError("object_verification_failed")
                    assert (owned_root / f"{object_id}.bin").is_file()
                    return ref

                def open_verified(self, ref: object):
                    async def _read() -> object:
                        object_id = cast(str, getattr(ref, "object_id"))
                        if object_id == self._reject_object_id:
                            raise AssertionError(
                                "stored receipt object accessed during reconstruction"
                            )
                        yield (owned_root / f"{object_id}.bin").read_bytes()

                    return _read()

            copied_objects = _CopiedObjects()
            copied_db = open_read_only(copied_bundle / "ledger.sqlite3")
            try:
                copied_ledger = SqliteLedger(
                    db=copied_db,
                    task_id=parent.task_id,
                    ownership_fence=OwnershipFence(
                        "svc_00000000-0000-4000-8000-000000000001",
                        1,
                        1,
                        "standalone-replay-nonce",
                    ),
                    clock=service.clock,
                    ids=IdPort(),
                    objects=cast(ObjectStorePort, copied_objects),
                )
                standalone_runtime = cast(
                    TaskRuntime,
                    SimpleNamespace(
                        task_id=parent.task_id,
                        session_id=parent.session_id,
                        ledger=copied_ledger,
                        objects=copied_objects,
                    ),
                )
                replay_request = ReceiptRequest.model_validate(
                    {
                        **_identity(),
                        "request_id": receipt_request_id,
                        "task_id": parent.task_id,
                        "session_id": parent.session_id,
                        "writer_id": parent.writer_id,
                        "expected_frontier": _frontier_json(checked.result_frontier),
                        "format": "json",
                        "include": "standard",
                        "redaction_profile": "default_local_export",
                    }
                )
                copied_operation = await copied_ledger.lookup_operation(
                    parent.writer_id, receipt_request_id
                )
                assert copied_operation is not None
                replayed = await _replay_result(
                    standalone_runtime,
                    replay_request,
                    copied_operation,
                )

                # Reconstruct the document from the copied parent event prefix itself.  This second
                # ledger has the same SQLite bytes but refuses the stored receipt object, so this path
                # proves the projection/case/context/receipt builders rather than object replay.
                ledger_only_objects = _CopiedObjects(reject_object_id=receipt_ref.object_id)
                ledger_only_db = open_read_only(copied_bundle / "ledger.sqlite3")
                try:
                    ledger_only = SqliteLedger(
                        db=ledger_only_db,
                        task_id=parent.task_id,
                        ownership_fence=OwnershipFence(
                            "svc_00000000-0000-4000-8000-000000000001",
                            1,
                            1,
                            "standalone-ledger-reconstruction-nonce",
                        ),
                        clock=service.clock,
                        ids=IdPort(),
                        objects=cast(ObjectStorePort, ledger_only_objects),
                    )
                    original_document = receipt_document_from_json(original.document)
                    subject_frontier = original_document.subject_frontier
                    assert subject_frontier == checked.result_frontier
                    subject_records = tuple(
                        [
                            record
                            async for record in ledger_only.load_events(
                                parent.session_id,
                                through=subject_frontier.sequence,
                            )
                        ]
                    )
                    projection = replay(subject_records)
                    availability = await ledger_only.load_case_availability(
                        parent.session_id,
                        subject_frontier,
                        projection,
                    )
                    case = build_deterministic_case(projection, subject_records, availability)
                    context = _context(projection, subject_frontier, case, subject_records)
                    reconstructed_document = build_receipt(
                        context,
                        original_document.receipt_id,
                        original_document.task_id,
                        original_document.session_id,
                        original_document.generated_at,
                        original_document.versions,
                        ReceiptRedactionProfile.DEFAULT_LOCAL_EXPORT,
                        ReceiptInclude.STANDARD,
                    )
                finally:
                    ledger_only_db.close()
            finally:
                copied_db.close()

            assert replayed.receipt_digest == original.receipt_digest
            assert replayed.document == original.document
            original_wire = cast(JsonValue, receipt_document_to_json(original_document))
            reconstructed_wire = cast(JsonValue, receipt_document_to_json(reconstructed_document))
            assert canonical_encode(reconstructed_wire) == canonical_encode(original_wire)
            assert canonical_digest(reconstructed_wire) == original.receipt_digest


async def test_rejected_unaccepted_child_annotates_parent_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rejecting a pending self-registered child must not make the parent receipt unavailable.

    The sweep records NOT_AUTHORIZED because the service does not open an unaccepted bundle.
    That gap stays off parent coverage. An accepted child's source-read gaps are covered by
    ``test_parent_receipt_names_child_source_read_gaps``.
    """

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(  # pragma: allowlist secret
        tmp_path / "state", config=_clean_config()
    ) as service:
        monkeypatch.setattr(type(service.app), "evaluate_semantic_check", _evaluate_semantic_check)
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Rejection parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "rejection-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        await _publish_clean_work(service, parent)
        child = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Pending child",
                    "workspace_ref": str(workspace),
                    "external_ref": "rejection-child",
                    "parent_session_id": parent.session_id,
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert child.acceptance == "pending"
        await _drain_lineage(service)
        pending_check = await _check(service, parent, mode="semantic_if_configured")
        pending_receipt = await _receipt(service, parent, pending_check)
        assert pending_receipt.conclusion == "no_unresolved_deterministic_findings"
        assert pending_receipt.document is not None
        pending_document = cast(Mapping[str, object], pending_receipt.document)
        pending_row = next(
            item for item in _children(pending_document) if item["child_task_id"] == child.task_id
        )
        assert pending_row["outcome"] == "annotated"

        await _publish(
            service,
            parent,
            (_event("child_rejected", {"child_task_id": child.task_id}),),
        )
        await _drain_lineage(service)
        checked = await _check(service, parent, mode="semantic_if_configured")
        assert checked.children is not None
        (preview,) = checked.children.items
        assert preview.child_task_id == child.task_id
        assert preview.acceptance.value == "rejected"
        assert preview.rollup_state.value == "annotation"
        assert preview.blocking_conditions == ()
        receipt = await _receipt(service, parent, checked)
        assert receipt.conclusion == "no_unresolved_deterministic_findings"
        assert receipt.document is not None
        document = cast(Mapping[str, object], receipt.document)
        row = next(item for item in _children(document) if item["child_task_id"] == child.task_id)
        assert row["outcome"] == "annotated"
        coverage = cast(Mapping[str, object], document["coverage"])
        known_gaps = cast(Sequence[object], coverage["known_gaps"])
        assert "lineage_child_unavailable" not in known_gaps
        assert "lineage_child_read_gap" not in known_gaps
