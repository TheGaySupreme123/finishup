"""Real-service parent rollup scenarios for the lineage and receipt contract.

These tests deliberately stay on the public application boundary.  The service builder gives the
scenario an encrypted vault, a SQLite catalog, one bundle per task, and the normal runtime router;
the only deterministic seam is its injected clock.  A child dependency therefore reaches a parent
receipt only through the service-owned manifest path.
"""

from __future__ import annotations

import base64
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock

import pytest

from builders.multi_agent import MultiAgentService, multi_agent_service
from yoetz.application.publish_work import PublishWorkInternalResult
from yoetz.application.start import StartInternalResult
from yoetz.domain.coordination import WorkState
from yoetz.domain.findings import FindingKind
from yoetz.ports.control import RepositoryPrivacyContext
from yoetz.ports.ledger import CheckCommitResult
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    StartRequest,
    StatusLineagePageModel,
    StatusRequest,
)
from yoetz.service.elevated_bootstrap import (
    claim_pending_for_review,
    complete_review,
    record_import_publication_authorization,
)

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
        "actor": {"actor_id": "harness:lineage-conformance", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _workspace(root: Path) -> Path:
    root.mkdir()
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
    return root.resolve()


def _event(
    name: str, payload: Mapping[str, object], *, parent: str | None = None
) -> dict[str, object]:
    event_id = new_id(IdKind.EVENT)
    return {
        "event_id": event_id,
        "schema": {"name": name, "version": "1.0.0"},
        "occurred_at": "2026-09-05T12:00:00.000Z",
        "causal_parents": () if parent is None else (parent,),
        "payload": dict(payload),
        "artifact_refs": (),
        "evidence_refs": (),
    }


async def _current_frontier(service: MultiAgentService, task: StartInternalResult) -> object:
    status = await service.app.status(
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
    """Accept the domain frontier returned by the service and protocol model doubles."""

    as_wire = getattr(frontier, "as_wire", None)
    if callable(as_wire):
        return dict(cast(Mapping[str, object], as_wire()).items())
    model_dump = getattr(frontier, "model_dump", None)
    if callable(model_dump):
        return cast(Mapping[str, object], model_dump(mode="json"))
    raise AssertionError("frontier shape is not serializable")


async def _publish(
    service: MultiAgentService,
    task: StartInternalResult,
    drafts: Sequence[Mapping[str, object]],
) -> PublishWorkInternalResult:
    frontier = await _current_frontier(service, task)
    result = await service.app.publish_work(
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
    service: MultiAgentService,
    task: StartInternalResult,
    *,
    expected_frontier: object | None = None,
) -> CheckCommitResult:
    frontier = (
        await _current_frontier(service, task) if expected_frontier is None else expected_frontier
    )
    result = await service.app.check(
        CheckRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier_json(frontier),
                "mode": "deterministic_only",
                "max_findings": "10",
                "policy_packs": ["research-evidence/0.2.0", "work-integrity/0.3.0"],
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, CheckCommitResult)
    return result


async def _receipt(
    service: MultiAgentService,
    task: StartInternalResult,
    checked: CheckCommitResult,
    *,
    format_value: str = "json",
    request_id: str | None = None,
):
    identity = _identity()
    if request_id is not None:
        identity["request_id"] = request_id
    return await service.app.receipt(
        ReceiptRequest.model_validate(
            {
                **identity,
                "task_id": task.task_id,
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier_json(checked.result_frontier),
                "format": format_value,
                "include": "standard",
                "redaction_profile": "default_local_export",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def _delegated_child(
    service: MultiAgentService, parent: StartInternalResult, title: str
) -> StartInternalResult:
    delegated = await service.app.start(
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
    return await service.app.start(
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


async def _close_work(service: MultiAgentService, task: StartInternalResult) -> None:
    await _publish(service, task, (_event("work_closed", {}),))


async def _drain_lineage(service: MultiAgentService) -> None:
    """Run the service's normal bounded maintenance hook after public child activity."""

    sweep = service.app.observation_sweep
    if sweep is not None:
        await sweep()


async def test_compact_readiness_exposes_unswept_children_and_failed_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Readiness parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "readiness-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        await _publish(
            service,
            parent,
            (
                _event(
                    "plan_published",
                    {
                        "plan_version": 1,
                        "summary": "Readiness regression",
                        "obligation_refs": [],
                        "no_obligations_reason": "no_material_change",
                    },
                ),
            ),
        )

        async def compact():
            return await service.app.status(
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

        before = await compact()
        assert before.closure_readiness.blocking_conditions == ()
        child = await _delegated_child(service, parent, "Unswept accepted child")
        unswept = await compact()
        assert "lineage_manifest_not_recorded" in unswept.gaps
        assert "coverage_gaps_declared" in unswept.closure_readiness.blocking_conditions
        # Reading readiness neither appends a manifest nor changes the parent frontier.
        repeated = await compact()
        assert repeated.head_frontier == unswept.head_frontier
        assert repeated.gaps == unswept.gaps
        await _drain_lineage(service)
        swept = await compact()
        assert "lineage_manifest_not_recorded" not in swept.gaps
        assert "coverage_gaps_declared" in swept.closure_readiness.blocking_conditions

        with monkeypatch.context() as patcher:
            patcher.setattr(
                type(service.app.start_catalog),
                "list_child_task_ids",
                AsyncMock(side_effect=RuntimeError("synthetic inventory failure")),
            )
            unavailable = await compact()
        assert "lineage_readiness_unavailable" in unavailable.gaps
        assert "coverage_gaps_declared" in unavailable.closure_readiness.blocking_conditions
        assert unavailable.head_frontier == swept.head_frontier
        await _close_work(service, child)
        changed = await compact()
        assert "lineage_manifest_state_changed" in changed.gaps
        assert "coverage_gaps_declared" in changed.closure_readiness.blocking_conditions


async def test_parent_receipt_rolls_up_mixed_real_child_states_and_one_hop_grandchild(
    tmp_path: Path,
) -> None:
    """Exercise the #500/#501 matrix through real starts, publications, checks, and receipts."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Rollup parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "rollup-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )

        clean = await _delegated_child(service, parent, "Clean accepted child")
        await _close_work(service, clean)
        clean_check = await _check(service, clean)
        await _receipt(service, clean, clean_check)
        await _drain_lineage(service)

        clean_parent_check = await _check(service, parent)
        clean_parent_receipt = await _receipt(service, parent, clean_parent_check)
        # The real factory has no semantic provider.  deterministic_only is therefore an honest
        # finding-free but coverage-incomplete child check, which remains an open parent gap.
        assert clean_parent_receipt.conclusion == "insufficient_coverage"
        assert clean_parent_receipt.document is not None
        clean_document = cast(Mapping[str, object], clean_parent_receipt.document)
        clean_children = cast(Mapping[str, object], clean_document["children"])["children"]
        (clean_row,) = tuple(
            item
            for item in cast(Sequence[Mapping[str, object]], clean_children)
            if item["child_task_id"] == clean.task_id
        )
        assert clean_row["outcome"] == "open_gap"
        assert clean_row["freshness"] == "known"

        actionable = await _delegated_child(service, parent, "Actionable child")
        obligation_event = _event(
            "obligation_published",
            {
                "obligation_id": new_id(IdKind.OBLIGATION),
                "description": "Record the child result.",
                "evidence_expectation": "A durable result exists.",
                "status": "open",
            },
        )
        obligation_id = cast(
            str, cast(Mapping[str, object], obligation_event["payload"])["obligation_id"]
        )
        await _publish(
            service,
            actionable,
            (
                obligation_event,
                _event(
                    "claim_recorded",
                    {
                        "claim_id": new_id(IdKind.CLAIM),
                        "claim_kind": "completion",
                        "statement": "The child is complete.",
                        "supporting_refs": (obligation_id,),
                        "obligation_refs": (obligation_id,),
                    },
                    parent=cast(str, obligation_event["event_id"]),
                ),
            ),
        )
        actionable_check = await _check(service, actionable)
        assert any(
            finding.kind is FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS
            for finding in actionable_check.findings
        )
        await _receipt(service, actionable, actionable_check)

        imported_child = await _delegated_child(service, parent, "Imported observation child")
        import_request: dict[str, object] = {
            "schema_version": "1.0.0",
            "codex_capability_profile_id": "codex-exec-jsonl/0.139.0/v1",
            "codex_version": "0.139.0",
            "exit_status": 0,
            "mapping_version": "codex-jsonl/1.0.0",
            "request_id": new_id(IdKind.REQUEST),
            "session_id": imported_child.session_id,
            "source_bytes_base64": base64.b64encode(b'{"type":"future.unknown"}\n').decode("ascii"),
            "source_encoding": "base64",
            "source_kind": "stdin",
            "stderr_captured_bytes": 0,
            "stderr_present": False,
            "stderr_truncated": False,
            "writer_id": imported_child.writer_id,
        }
        # The first real import attempt prepares the exact owner-only publication plan and pauses
        # before publishing.  Complete the supported isolated one-use review ceremony, then retry
        # the same request so the durable plan resumes; the fixture never bypasses the authority.
        with pytest.raises(PublicOperationError) as pending_import:
            await service.app.import_codex_jsonl(
                import_request,
                repository_privacy_context=_REPOSITORY,
            )
        assert pending_import.value.code is PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED
        claimed = claim_pending_for_review(_state=service.root / "state")
        assert claimed.operation == "import_publication"
        record_import_publication_authorization(claimed, _state=service.root / "state")
        complete_review(claimed, outcome="approved", _state=service.root / "state")
        imported = await service.app.import_codex_jsonl(
            import_request,
            repository_privacy_context=_REPOSITORY,
        )
        assert imported.unknown_count == 1
        await _close_work(service, imported_child)
        imported_check = await _check(service, imported_child)
        await _receipt(service, imported_child, imported_check)

        # A cooperatively published plan with a missing declared obligation is the public material
        # path for a genuine informational ledger finding.  The import above intentionally has
        # source-object availability gaps and its policies stay skipped; keep that fact separate.
        informational = await _delegated_child(service, parent, "Informational child")
        informational_obligation_id = new_id(IdKind.OBLIGATION)
        await _publish(
            service,
            informational,
            (
                _event(
                    "plan_published",
                    {
                        "plan_version": 1,
                        "summary": "Reference the unavailable child obligation.",
                        "obligation_refs": (new_id(IdKind.OBLIGATION),),
                    },
                ),
                _event(
                    "obligation_published",
                    {
                        "obligation_id": informational_obligation_id,
                        "description": "Keep one ordinary work root for the ledger check.",
                        "evidence_expectation": "The missing plan reference remains visible.",
                        "status": "open",
                    },
                ),
            ),
        )
        await _close_work(service, informational)
        informational_check = await _check(service, informational)
        assert any(
            finding.kind is FindingKind.LEDGER_STALE_OR_INCOMPLETE
            for finding in informational_check.findings
        )
        await _receipt(service, informational, informational_check)

        pending = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Pending child",
                    "workspace_ref": str(workspace),
                    "external_ref": "pending-child",
                    "parent_session_id": parent.session_id,
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert pending.acceptance == "pending"

        live = await _delegated_child(service, parent, "Live child")

        contact_lost = await _delegated_child(service, parent, "Contact lost child")
        service.clock.advance(seconds=61)
        await service.app.recover_lineage()
        # Recovery expires every lease whose clock window elapsed.  Re-touch the parent and the
        # intentionally live child through the normal status route; the contact-lost child is the
        # only lane left untouched for the rollup assertion below.
        await _current_frontier(service, parent)
        await _current_frontier(service, live)
        await _current_frontier(service, informational)

        written_off = await _delegated_child(service, parent, "Written off child")
        await _publish(
            service,
            parent,
            (
                _event(
                    "child_written_off",
                    {"child_task_id": written_off.task_id, "reason_code": "superseded"},
                ),
            ),
        )

        grandchild_parent = await _delegated_child(service, parent, "Grandchild parent")
        parent_before_grandchild = await _check(service, parent)
        assert parent_before_grandchild.children is not None
        before_grandchild_manifest_frontier = (
            parent_before_grandchild.children.tested_manifest_frontier
        )
        grandchild = await _delegated_child(service, grandchild_parent, "One hop grandchild")
        await _close_work(service, grandchild)
        grandchild_check = await _check(service, grandchild)
        await _receipt(service, grandchild, grandchild_check)
        await _drain_lineage(service)
        parent_after_grandchild = await _check(service, parent)
        assert parent_after_grandchild.children is not None
        assert parent_after_grandchild.children.label == "recorded"
        assert (
            parent_after_grandchild.children.tested_manifest_frontier
            != before_grandchild_manifest_frontier
        )

        parent_status = await service.app.status(
            StatusRequest.model_validate(
                {
                    **_identity(),
                    "session_id": parent.session_id,
                    "writer_id": parent.writer_id,
                    "view": "lineage",
                    "limit": "10",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert isinstance(parent_status.page, StatusLineagePageModel)
        children = {item.task_id: item for item in parent_status.page.children}
        assert set(children) >= {
            clean.task_id,
            actionable.task_id,
            informational.task_id,
            pending.task_id,
            live.task_id,
            contact_lost.task_id,
            written_off.task_id,
            grandchild_parent.task_id,
        }
        assert children[pending.task_id].acceptance == "pending"
        assert children[clean.task_id].origin.value == "parent_minted"
        assert children[pending.task_id].origin.value == "self_registered"
        assert children[written_off.task_id].work_state is WorkState.WRITTEN_OFF
        assert grandchild.task_id not in children

        parent_check = await _check(service, parent)
        assert parent_check.children is not None
        assert parent_check.children.label == "recorded"
        preview = {item.child_task_id: item for item in parent_check.children.items}
        assert preview[actionable.task_id].rollup_state.value == "blocked"
        # The informational finding is ledger_stale_or_incomplete from a missing plan reference.
        # That reference is also a coverage gap, so this child stays open_gap independently of
        # the kernel rule that an informational finding cannot hide a lifecycle blocker.
        assert preview[informational.task_id].rollup_state.value == "open_gap"
        assert preview[pending.task_id].rollup_state.value == "annotation"
        assert preview[live.task_id].rollup_state.value == "open_gap"
        assert preview[contact_lost.task_id].rollup_state.value == "incomplete"
        assert preview[written_off.task_id].rollup_state.value == "incomplete"

        parent_receipt = await _receipt(service, parent, parent_check)
        assert parent_receipt.conclusion != "no_unresolved_deterministic_findings"
        assert parent_receipt.document is not None
        document = cast(Mapping[str, object], parent_receipt.document)
        rows = cast(Mapping[str, object], document["children"])
        child_rows = {
            cast(str, row["child_task_id"]): row
            for row in cast(Sequence[Mapping[str, object]], rows["children"])
        }
        assert child_rows[actionable.task_id]["outcome"] == "open_gap"
        assert any(
            finding["kind"] == "completion_with_open_obligations"
            for finding in cast(
                Sequence[Mapping[str, object]], child_rows[actionable.task_id]["findings"]
            )
        )
        assert child_rows[pending.task_id]["outcome"] == "annotated"
        assert child_rows[informational.task_id]["outcome"] == "open_gap"
        assert any(
            finding["kind"] == "ledger_stale_or_incomplete"
            for finding in cast(
                Sequence[Mapping[str, object]], child_rows[informational.task_id]["findings"]
            )
        )
        assert child_rows[live.task_id]["outcome"] == "open_gap"
        assert child_rows[live.task_id]["freshness"] == "unknown"
        assert child_rows[written_off.task_id]["outcome"] == "incomplete"
        assert grandchild.task_id not in child_rows


async def test_parent_receipt_renderings_keep_recorded_children_section(
    tmp_path: Path,
) -> None:
    """Each public receipt rendering must expose the same frozen parent children section."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Rendering parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "rendering-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        child = await _delegated_child(service, parent, "Rendering child")
        await _drain_lineage(service)
        checked = await _check(service, parent)
        for format_value, heading in (
            ("json", None),
            ("markdown", "## Children"),
            ("text", "Children"),
        ):
            rendered = await _receipt(
                service,
                parent,
                checked,
                format_value=format_value,
            )
            if format_value == "json":
                assert rendered.document is not None
                children = cast(Mapping[str, object], rendered.document)["children"]
                rows = cast(Mapping[str, object], children)["children"]
                assert any(
                    row["child_task_id"] == child.task_id
                    for row in cast(Sequence[Mapping[str, object]], rows)
                )
            else:
                assert rendered.document is None
                assert rendered.human_text is not None
                assert heading is not None
                assert heading in rendered.human_text
                assert child.task_id in rendered.human_text


async def test_parent_receipt_keeps_old_manifest_immutable_after_new_recorded_child_facts(
    tmp_path: Path,
) -> None:
    """A later manifest is a named receipt gap; it cannot rewrite an earlier receipt."""

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "Frozen receipt parent",
                    "workspace_ref": str(workspace),
                    "external_ref": "frozen-parent",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        child = await _delegated_child(service, parent, "Mutable child")
        await _drain_lineage(service)

        parent_check = await _check(service, parent)
        receipt_request_id = new_id(IdKind.REQUEST)
        first_receipt = await _receipt(
            service,
            parent,
            parent_check,
            request_id=receipt_request_id,
        )
        replay = await _receipt(
            service,
            parent,
            parent_check,
            request_id=receipt_request_id,
        )
        assert replay.receipt_digest == first_receipt.receipt_digest
        assert replay.document == first_receipt.document
        assert first_receipt.document is not None
        first_document = cast(Mapping[str, object], first_receipt.document)
        first_children = cast(Mapping[str, object], first_document["children"])["children"]
        first_child_row = next(
            item
            for item in cast(Sequence[Mapping[str, object]], first_children)
            if item["child_task_id"] == child.task_id
        )
        assert first_child_row["outcome"] == "open_gap"
        assert first_child_row["freshness"] == "unknown"

        await _close_work(service, child)
        child_check = await _check(service, child)
        await _receipt(service, child, child_check)
        await _drain_lineage(service)
        latest_parent_frontier = await _current_frontier(service, parent)
        later = await service.app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_identity(),
                    "task_id": parent.task_id,
                    "session_id": parent.session_id,
                    "writer_id": parent.writer_id,
                    "expected_frontier": _frontier_json(latest_parent_frontier),
                    "format": "json",
                    "include": "standard",
                    "redaction_profile": "default_local_export",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert later.document is not None
        assert later.conclusion != "no_unresolved_deterministic_findings"
        later_document = cast(Mapping[str, object], later.document)
        child_rows = cast(Mapping[str, object], later_document["children"])["children"]
        row = next(
            item
            for item in cast(Sequence[Mapping[str, object]], child_rows)
            if item["child_task_id"] == child.task_id
        )
        assert row.get("later_manifest_ref") is not None
        coverage = cast(Mapping[str, object], later_document["coverage"])
        assert "lineage_manifest_uncovered" in cast(Sequence[object], coverage["known_gaps"])
        assert later.receipt_digest != first_receipt.receipt_digest
        replay_after_manifest = await _receipt(
            service,
            parent,
            parent_check,
            request_id=receipt_request_id,
        )
        assert replay_after_manifest.receipt_digest == first_receipt.receipt_digest
        assert replay_after_manifest.document == first_receipt.document

        await _drain_lineage(service)
        parent_recheck = await _check(service, parent)
        final_receipt = await _receipt(service, parent, parent_recheck)
        assert final_receipt.document is not None
        final_document = cast(Mapping[str, object], final_receipt.document)
        final_children = cast(Mapping[str, object], final_document["children"])["children"]
        final_row = next(
            item
            for item in cast(Sequence[Mapping[str, object]], final_children)
            if item["child_task_id"] == child.task_id
        )
        assert final_row["outcome"] == "open_gap"
        assert final_row.get("later_manifest_ref") is None
        assert final_receipt.conclusion == "insufficient_coverage"
