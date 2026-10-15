"""A project read cannot disclose text under the recipient's authority alone."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

import pytest

from builders.projection_workflow import build_projection_application
from finishup.application.project_projection import (
    hydrate_project_status_coordination_resources,
    hydrate_project_status_text,
    hydrate_status_advice_coordination_resources,
    revalidate_project_status_sources,
    revalidate_status_advice_sources,
    source_denied_project_items,
)
from finishup.application.projects import (
    ProjectApplication,
    ProjectCommandError,
    ProjectMembershipView,
    ProjectStatus,
)
from finishup.domain.coordination import (
    CoordinationErrorCode,
    MemberKind,
    ProjectDescriptor,
    ProjectKind,
    ProjectMembership,
    ProjectTextRef,
)
from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    CandidateContextItem,
    DataCategory,
    LocalDisclosureApproved,
    LocalDisclosureSink,
    ProjectionAuditContext,
)
from finishup.ports.control import ControlError
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.models import OmittedContentModel, StatusProjectDetectionModel

pytestmark = pytest.mark.anyio

_TASK = "tsk_59000000-0000-4000-8000-000000000001"
_OWNER = "tsk_59000000-0000-4000-8000-000000000002"
_PROJECT = "prj_59000000-0000-4000-8000-000000000001"
_REFERENCE = ProjectTextRef(
    "obj_59000000-0000-4000-8000-000000000001",
    "sha256:" + "a" * 64,
    18,
    _OWNER,
    1,
    "sha256:" + "b" * 64,
)
_NOW = datetime(2026, 9, 5, tzinfo=UTC)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _source() -> dict[str, JsonValue]:
    return {
        "task_id": _TASK,
        "view": "project",
        "page": {
            "project_id": _PROJECT,
            "membership_generation": "3",
            "title_ref": dict(_REFERENCE.as_wire().items()),
            "members": [{"task_id": _TASK}, {"task_id": _OWNER}],
            "lineage": {"parent_task_id": None, "children": [], "annotations": []},
            "detections": [],
            "receipts": [],
        },
    }


def _view() -> ProjectStatus:
    descriptor = ProjectDescriptor(
        _PROJECT,
        ProjectKind.GENERAL,
        None,
        False,
        3,
        _REFERENCE,
        None,
        _NOW,
    )
    memberships = tuple(
        ProjectMembershipView(
            ProjectMembership(_PROJECT, 3, MemberKind.TASK, task, _NOW),
            task_id=task,
        )
        for task in (_TASK, _OWNER)
    )
    return ProjectStatus(project=descriptor, memberships=memberships, grant=None)


@pytest.mark.parametrize(
    "sink", [LocalDisclosureSink.LOCAL_HUMAN_VIEW, LocalDisclosureSink.AGENT_CONTEXT]
)
async def test_hydration_binds_text_to_owner_reference_generation_and_resolved_sink(
    sink: LocalDisclosureSink,
) -> None:
    projects = AsyncMock(spec=ProjectApplication)
    projects.project_text_for_sink.return_value = "Private project name"
    hydrated = await hydrate_project_status_text(
        cast(ProjectApplication, projects), _source(), sink
    )
    projects.project_text_for_sink.assert_awaited_once_with(
        _TASK,
        project=_PROJECT,
        field="title",
        sink=sink,
        expected_generation=3,
        expected_reference=_REFERENCE,
    )
    page = hydrated["page"]
    assert isinstance(page, Mapping)
    assert page["title"] == "Private project name"
    assert "title" not in cast(Mapping[str, JsonValue], _source()["page"])


async def test_source_denial_is_a_typed_omission_without_using_requester_permission() -> None:
    projects = AsyncMock(spec=ProjectApplication)
    projects.project_text_for_sink.side_effect = ProjectCommandError(
        CoordinationErrorCode.CONSENT_REQUIRED
    )
    hydrated = await hydrate_project_status_text(
        cast(ProjectApplication, projects),
        _source(),
        LocalDisclosureSink.AGENT_CONTEXT,
    )
    page = hydrated["page"]
    assert isinstance(page, Mapping)
    assert page["title"] == {
        "omitted": True,
        "category": "task_description",
        "reason": "local_disclosure_not_authorized",
    }
    scope = AuthorizationScope(
        AuthorizationScopeKind.TASK,
        "ins_59000000-0000-4000-8000-000000000001",
        "hmac-sha256:" + "c" * 64,
        _TASK,
    )
    items = source_denied_project_items(hydrated, scope)
    assert len(items) == 1
    assert items[0].origin_ref == "/page/title"
    assert not items[0].source_disclosure_permitted
    assert items[0].plaintext == b"null"


async def test_coordination_resource_hydration_is_sink_and_generation_bound() -> None:
    source = _source()
    page = dict(cast(Mapping[str, JsonValue], source["page"]).items())
    detection_id = "evt_59000000-0000-4000-8000-000000000003"
    page["detections"] = [
        {
            "detection_id": detection_id,
            "task_ids": [_TASK, _OWNER],
            "resource_count": "1",
            "open": True,
            "resource_paths": {
                "omitted": True,
                "category": "repository_excerpt",
                "reason": "local_disclosure_not_authorized",
            },
        }
    ]
    source["page"] = page
    projects = AsyncMock(spec=ProjectApplication)
    projects.coordination_resource_detail_for.return_value = SimpleNamespace(
        resource_paths=("src/shared.py",)
    )
    hydrated = await hydrate_project_status_coordination_resources(
        cast(ProjectApplication, projects),
        source,
        LocalDisclosureSink.AGENT_CONTEXT,
    )
    hydrated_page = cast(Mapping[str, JsonValue], hydrated["page"])
    rows = cast(list[JsonValue], hydrated_page["detections"])
    assert cast(Mapping[str, JsonValue], rows[0])["resource_paths"] == ("src/shared.py",)
    projects.coordination_resource_detail_for.assert_awaited_once_with(
        _TASK,
        project=_PROJECT,
        detection_id=detection_id,
        sink=LocalDisclosureSink.AGENT_CONTEXT,
        expected_generation=3,
    )

    projects.coordination_resource_detail_for.reset_mock()
    projects.coordination_resource_detail_for.return_value = SimpleNamespace(resource_paths=None)
    denied = await hydrate_project_status_coordination_resources(
        cast(ProjectApplication, projects),
        source,
        LocalDisclosureSink.AGENT_CONTEXT,
    )
    denied_page = cast(Mapping[str, JsonValue], denied["page"])
    denied_rows = cast(list[JsonValue], denied_page["detections"])
    assert cast(Mapping[str, JsonValue], denied_rows[0])["resource_paths"] == {
        "omitted": True,
        "category": "repository_excerpt",
        "reason": "local_disclosure_not_authorized",
    }
    StatusProjectDetectionModel.model_validate(denied_rows[0])


async def test_advice_coordination_selector_hydrates_for_recipient_or_omits() -> None:
    detection_id = "evt_59000000-0000-4000-8000-000000000004"
    source: dict[str, JsonValue] = {
        "task_id": _TASK,
        "view": "advice",
        "page": {
            "projection_format": "yoetz.advice-snapshot/1",
            "next_cursor": None,
            "items": [
                {
                    "finding_id": "fnd_59000000-0000-4000-8000-000000000005",
                    "rule_code": "coordination_overlap",
                    "priority": 50,
                    "evidence_commitments": ("sha256:" + "a" * 64,),
                    "coverage": {},
                    "freshness_frontier": "membership_generation:3",
                    "verification_state": "not_required",
                    "semantic_state": "disabled",
                    "recommended_next_action": "review_coordination_advice",
                    "coordination_project_id": _PROJECT,
                    "coordination_detection_id": detection_id,
                    "coordination_membership_generation": "3",
                    "coordination_counterpart_task_id": _OWNER,
                    "coordination_resource_paths": {
                        "omitted": True,
                        "category": "repository_excerpt",
                        "reason": "local_disclosure_not_authorized",
                    },
                }
            ],
        },
    }
    projects = AsyncMock(spec=ProjectApplication)
    projects.coordination_resource_detail_for.return_value = SimpleNamespace(
        counterpart_task_id=_OWNER,
        resource_paths=("src/shared.py",),
    )
    hydrated = await hydrate_status_advice_coordination_resources(
        cast(ProjectApplication, projects), source, LocalDisclosureSink.AGENT_CONTEXT
    )
    hydrated_page = cast(Mapping[str, JsonValue], hydrated["page"])
    hydrated_item = cast(Mapping[str, JsonValue], cast(list[JsonValue], hydrated_page["items"])[0])
    assert hydrated_item["coordination_resource_paths"] == ("src/shared.py",)
    projects.coordination_resource_detail_for.assert_awaited_once_with(
        _TASK,
        project=_PROJECT,
        detection_id=detection_id,
        sink=LocalDisclosureSink.AGENT_CONTEXT,
        expected_generation=3,
    )

    projects.coordination_resource_detail_for.reset_mock()
    projects.coordination_resource_detail_for.return_value = SimpleNamespace(
        counterpart_task_id=_OWNER,
        resource_paths=None,
    )
    denied = await hydrate_status_advice_coordination_resources(
        cast(ProjectApplication, projects), source, LocalDisclosureSink.AGENT_CONTEXT
    )
    denied_page = cast(Mapping[str, JsonValue], denied["page"])
    denied_item = cast(Mapping[str, JsonValue], cast(list[JsonValue], denied_page["items"])[0])
    assert denied_item["coordination_resource_paths"] == {
        "omitted": True,
        "category": "repository_excerpt",
        "reason": "local_disclosure_not_authorized",
    }
    OmittedContentModel.model_validate(denied_item["coordination_resource_paths"])


async def test_advice_revalidation_fences_revoked_selector_with_existing_omission() -> None:
    detection_id = "evt_59000000-0000-4000-8000-000000000006"
    omission = {
        "omitted": True,
        "category": "repository_excerpt",
        "reason": "local_disclosure_not_authorized",
    }
    source: dict[str, JsonValue] = {
        "task_id": _TASK,
        "view": "advice",
        "page": {
            "projection_format": "yoetz.advice-snapshot/1",
            "next_cursor": None,
            "items": [
                {
                    "finding_id": "fnd_59000000-0000-4000-8000-000000000007",
                    "rule_code": "coordination_overlap",
                    "priority": 50,
                    "evidence_commitments": ("sha256:" + "a" * 64,),
                    "coverage": {},
                    "freshness_frontier": "membership_generation:3",
                    "verification_state": "not_required",
                    "semantic_state": "disabled",
                    "recommended_next_action": "review_coordination_advice",
                    "coordination_project_id": _PROJECT,
                    "coordination_detection_id": detection_id,
                    "coordination_membership_generation": "3",
                    "coordination_counterpart_task_id": _OWNER,
                    "coordination_resource_paths": omission,
                }
            ],
        },
    }
    projects = AsyncMock(spec=ProjectApplication)
    projects.catalog = SimpleNamespace(list_task_project_ids=AsyncMock(return_value=(_PROJECT,)))
    projects.coordination_advice_for.return_value = (
        SimpleNamespace(
            target_task_id=_TASK,
            project_id=_PROJECT,
            detection_id=detection_id,
            membership_generation=3,
            counterpart_task_id=_OWNER,
        ),
    )
    projects.coordination_resource_detail_for.return_value = SimpleNamespace(
        counterpart_task_id=_OWNER,
        resource_paths=None,
    )
    await revalidate_status_advice_sources(
        cast(ProjectApplication, projects), source, LocalDisclosureSink.AGENT_CONTEXT
    )

    projects.coordination_advice_for.return_value = ()
    with pytest.raises(ControlError, match="privacy_projection_unavailable"):
        await revalidate_status_advice_sources(
            cast(ProjectApplication, projects), source, LocalDisclosureSink.AGENT_CONTEXT
        )


async def test_unattributed_project_text_cannot_reach_the_recipient_projection() -> None:
    source = _source()
    page = dict(cast(Mapping[str, JsonValue], source["page"]).items())
    page.pop("title_ref")
    page["title"] = "Text without a source owner"
    source["page"] = page
    projects = AsyncMock(spec=ProjectApplication)
    with pytest.raises(ControlError, match="privacy_projection_unavailable"):
        await hydrate_project_status_text(
            cast(ProjectApplication, projects), source, LocalDisclosureSink.LOCAL_HUMAN_VIEW
        )
    projects.project_text_for_sink.assert_not_called()


async def test_source_omission_is_recorded_by_real_privacy_coordinator_and_audit() -> None:
    app, policy = await build_projection_application()
    try:
        source = {
            "page": {
                "title": {
                    "omitted": True,
                    "category": "task_description",
                    "reason": "local_disclosure_not_authorized",
                }
            }
        }
        scope = AuthorizationScope(
            AuthorizationScopeKind.TASK,
            policy.effective_scope.installation_id,
            "hmac-sha256:" + "c" * 64,
            _TASK,
        )
        request_id = "req_59000000-0000-4000-8000-000000000001"
        candidate = CandidateContext(
            request_id=request_id,
            channel=None,
            local_sink=LocalDisclosureSink.LOCAL_HUMAN_VIEW,
            purpose="client_result_projection",
            scope=scope,
            subject_digest=canonical_digest(source),
            provider_binding=None,
            items=(
                *source_denied_project_items(source, scope),
                CandidateContextItem(
                    "allowed-description",
                    DataCategory.TASK_DESCRIPTION,
                    scope,
                    "/page/description",
                    b'"Allowed description"',
                ),
            ),
            projection_audit_context=ProjectionAuditContext(
                "rpc_59000000-0000-4000-8000-000000000001",
                "status",
                "svc_59000000-0000-4000-8000-000000000001",
                1,
                request_id,
                "sha256:" + "e" * 64,
                canonical_encode({"method": "status"}),
                canonical_encode(source),
            ),
        )
        result = await app.privacy.prepare_local_disclosure(candidate)
        assert isinstance(result, LocalDisclosureApproved)
        assert tuple(item.json_pointer for item in result.omissions) == ("/page/title",)
        assert tuple(item.json_pointer for item in result.approved_items) == ("/page/description",)
        assert DataCategory.TASK_DESCRIPTION in result.receipt.blocked_categories
        assert result.receipt.receipt_id.startswith("egr_")
        assert result.case_or_projection_commitment.startswith("hmac-sha256:")
    finally:
        await app.close()


@pytest.mark.parametrize("change", ["membership", "text", "source_policy"])
async def test_revocation_or_amendment_during_projection_refuses_the_stale_response(
    change: str,
) -> None:
    projects = AsyncMock(spec=ProjectApplication)
    projects.project_text_for_sink.return_value = "Original title"
    view = _view()
    projects.project_view_for.return_value = view
    sink = LocalDisclosureSink.LOCAL_HUMAN_VIEW
    hydrated = await hydrate_project_status_text(
        cast(ProjectApplication, projects), _source(), sink
    )
    if change == "membership":
        projects.project_view_for.return_value = replace(view, memberships=view.memberships[:1])
    elif change == "text":
        projects.project_view_for.return_value = replace(
            view,
            project=replace(
                view.project,
                title_ref=replace(_REFERENCE, content_digest="sha256:" + "c" * 64),
            ),
        )
    else:
        projects.project_text_for_sink.side_effect = ProjectCommandError(
            CoordinationErrorCode.CONSENT_REQUIRED
        )
    with pytest.raises(ControlError, match="privacy_projection_unavailable"):
        await revalidate_project_status_sources(cast(ProjectApplication, projects), hydrated, sink)
