"""Per-task review mode through the ready service (ADR-049).

Two tasks in one repository under the recommended hybrid setting: one turns on AI-powered review
mid-task and back off, the other never does. Each check records the mode it ran in, status shows
the task's current mode, and only the receipt of the task that switched names its switches. The
owner's setting comes from a fixed reader in place of the policy store; everything else is the
real composition (encrypted vault, SQLite catalog, one bundle per task).
"""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from builders.multi_agent import MultiAgentService, multi_agent_service
from builders.projection_workflow import ProjectionCase, project_case
from finishup.application.publish_work import PublishWorkInternalResult
from finishup.application.service import TaskRuntime
from finishup.application.start import StartInternalResult
from finishup.cli.render import render_human_check, render_human_status
from finishup.domain.events import CheckReviewMode, ReviewMode
from finishup.domain.privacy import ConversationReview
from finishup.domain.values import EventId, event_id
from finishup.kernel.review_mode import ConversationReviewContext
from finishup.mcp.summaries import summary_for_check, summary_for_status
from finishup.ports.control import ControlMethod, RepositoryPrivacyContext
from finishup.ports.ledger import CheckCommitResult
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    StartRequest,
    StatusRequest,
)

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")
_RATIONALE = "Cross-module change that local checks cannot judge."


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _identity() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": "harness:review-mode", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _frontier_json(frontier: object) -> Mapping[str, object]:
    as_wire = getattr(frontier, "as_wire", None)
    if callable(as_wire):
        return dict(cast(Mapping[str, object], as_wire()).items())
    return cast(Mapping[str, object], getattr(frontier, "model_dump")(mode="json"))


def _hybrid(service: MultiAgentService) -> None:
    """The owner chose the recommended setup answer, and a reviewer is set up."""

    async def reader(_runtime: TaskRuntime) -> ConversationReviewContext:
        return ConversationReviewContext(ConversationReview.LOCAL_AGENT_OPT_IN, True, True)

    object.__setattr__(service.app, "conversation_review_reader", reader)


class _Task:
    def __init__(self, service: MultiAgentService, started: StartInternalResult) -> None:
        self.service = service
        self.started = started

    def _ids(self) -> dict[str, object]:
        return {
            **_identity(),
            "session_id": self.started.session_id,
            "writer_id": self.started.writer_id,
        }

    async def status_wire(self) -> dict[str, object]:
        status = await self.service.app.status(
            StatusRequest.model_validate({**self._ids(), "view": "compact", "limit": "1"}),
            repository_privacy_context=_REPOSITORY,
        )
        return cast(dict[str, object], status.as_json())

    async def status_projected(self) -> Mapping[str, JsonValue]:
        body = {**self._ids(), "view": "compact", "limit": "1"}
        status = await self.service.app.status(
            StatusRequest.model_validate(body), repository_privacy_context=_REPOSITORY
        )
        return await project_case(
            self.service.app,
            ProjectionCase(
                "status", ControlMethod.STATUS, cast(Mapping[str, JsonValue], body), status
            ),
            7100,
        )

    async def frontier(self) -> Mapping[str, object]:
        return cast(Mapping[str, object], (await self.status_wire())["head_frontier"])

    async def switch(self, mode: ReviewMode) -> EventId:
        switch_id = event_id(new_id(IdKind.EVENT))
        result = await self.service.app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **self._ids(),
                    "expected_frontier": await self.frontier(),
                    "event_drafts": [
                        {
                            "event_id": switch_id,
                            "schema": {"name": "decision_recorded", "version": "1.1.0"},
                            "occurred_at": "2026-09-05T12:00:00.000Z",
                            "causal_parents": [],
                            "payload": {
                                "statement": "Switch this task's review mode.",
                                "rationale": _RATIONALE,
                                "authority": "harness:review-mode",
                                "review_mode": mode.value,
                            },
                            "artifact_refs": [],
                            "evidence_refs": [],
                        }
                    ],
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert isinstance(result, PublishWorkInternalResult)
        return switch_id

    async def check(self) -> CheckCommitResult:
        result, _wire = await self.check_with_wire()
        return result

    async def check_with_wire(self) -> tuple[CheckCommitResult, Mapping[str, JsonValue]]:
        # No mode: the check runs in the task's review mode.
        body = {**self._ids(), "expected_frontier": await self.frontier(), "max_findings": "5"}
        result = await self.service.app.check(
            CheckRequest.model_validate(body), repository_privacy_context=_REPOSITORY
        )
        assert isinstance(result, CheckCommitResult), type(result)
        wire = await project_case(
            self.service.app,
            ProjectionCase(
                "check", ControlMethod.CHECK, cast(Mapping[str, JsonValue], body), result
            ),
            7000,
        )
        return result, wire

    async def limitations(self, checked: CheckCommitResult) -> str:
        receipt = await self.service.app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_identity(),
                    "task_id": self.started.task_id,
                    "session_id": self.started.session_id,
                    "writer_id": self.started.writer_id,
                    "expected_frontier": _frontier_json(checked.result_frontier),
                    "format": "json",
                    "include": "standard",
                    "redaction_profile": "default_local_export",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        document = cast(Mapping[str, object], receipt.document)
        sections = cast(list[Mapping[str, object]], document["sections"])
        (limitations,) = (s for s in sections if s["key"] == "limitations_and_coverage")
        return cast(str, limitations["body"])


async def _start(service: MultiAgentService, workspace: Path, title: str) -> _Task:
    started = await service.app.start(
        StartRequest.model_validate(
            {
                **_identity(),
                "mode": "create",
                "task_title": title,
                "workspace_ref": str(workspace),
                "external_ref": title.lower().replace(" ", "-"),
                "requested_view": "compact",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    return _Task(service, started)


def _workspace(root: Path) -> Path:
    root.mkdir()
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, capture_output=True)
    return root.resolve()


async def test_two_concurrent_tasks_run_in_their_own_modes(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        _hybrid(service)
        opted_in = await _start(service, workspace, "Cross module change")
        local = await _start(service, workspace, "Typo fix")
        assert opted_in.started.task_id != local.started.task_id

        switch = await opted_in.switch(ReviewMode.AI_POWERED)
        checked, checked_wire = await opted_in.check_with_wire()
        other, other_wire = await local.check_with_wire()

        assert checked.review_mode == CheckReviewMode(
            ReviewMode.AI_POWERED, "conversation_switch", switch_event_id=switch
        )
        assert other.review_mode == CheckReviewMode(ReviewMode.LOCAL, "conversation_default")
        # The local task ran local checks only, on a route that did not require review.
        assert other_wire["semantic_status"] == "not_requested"
        assert other_wire.get("semantic_route_required") is False

        # MCP text names the mode and never carries the decision's prose.
        summary = summary_for_check(checked_wire)
        assert "Review mode: AI-powered review; this task turned it on" in summary
        assert _RATIONALE not in summary
        assert "Review mode: local (FinishUP)" in summary_for_check(other_wire)

        opted_status = (await opted_in.status_wire())["review_mode"]
        local_status = (await local.status_wire())["review_mode"]
        assert cast(Mapping[str, object], opted_status)["mode"] == "ai_powered"
        assert cast(Mapping[str, object], local_status)["mode"] == "local"


async def test_a_mid_task_switch_and_switching_back_reach_check_status_and_receipt(
    tmp_path: Path,
) -> None:
    from finishup.protocol.models import (
        CheckResult,
        CheckSuccessModel,
        StatusResult,
        StatusSuccessModel,
    )

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        _hybrid(service)
        task = await _start(service, workspace, "Switching task")
        untouched = await _start(service, workspace, "Untouched task")

        first = await task.check()
        assert first.review_mode == CheckReviewMode(ReviewMode.LOCAL, "conversation_default")

        on = await task.switch(ReviewMode.AI_POWERED)
        second, second_wire = await task.check_with_wire()
        assert second.review_mode == CheckReviewMode(
            ReviewMode.AI_POWERED, "conversation_switch", switch_event_id=on
        )
        human = CheckResult.model_validate(second_wire).root
        assert isinstance(human, CheckSuccessModel)
        assert f"(switch {on})" in render_human_check(human)

        off = await task.switch(ReviewMode.LOCAL)
        third = await task.check()
        assert third.review_mode == CheckReviewMode(
            ReviewMode.LOCAL, "conversation_switch", None, off
        )

        status_wire = await task.status_projected()
        review_mode = cast(Mapping[str, object], status_wire["review_mode"])
        assert review_mode["mode"] == "local"
        assert review_mode["requested"] == "local"
        assert review_mode["setting"] == "local_agent_opt_in"
        assert review_mode["local_reason"] == "switched_to_local"
        assert review_mode["switch_event_id"] == off
        status = StatusResult.model_validate(status_wire).root
        assert isinstance(status, StatusSuccessModel)
        assert f"latest switch {off}" in render_human_status(status)
        assert "Review mode: local (FinishUP)" in summary_for_status(status_wire)

        limitations = await task.limitations(third)
        assert "Review mode switches recorded for this task: to AI-powered review at" in (
            limitations
        )
        assert f"(event {on}, authority harness:review-mode)" in limitations
        assert "back to local checks at sequence" in limitations
        assert f"(event {off}, authority harness:review-mode)" in limitations
        assert "The applicable check ran local checks only (FinishUP)." in limitations
        assert _RATIONALE not in limitations

        # A task that never switched keeps its receipt free of the sentence.
        plain = await untouched.check()
        assert "Review mode switches" not in await untouched.limitations(plain)


async def test_the_composed_reader_keeps_a_legacy_install_released(tmp_path: Path) -> None:
    """The real reader over a seeded policy that predates the setting (upgrade rule).

    No reviewer is set up and the policy has no conversation setting, so a task's check keeps its
    released behaviour and records no mode; status still says the task is local and why an
    agent's switch would stay local.
    """

    workspace = _workspace(tmp_path / "workspace")
    async with multi_agent_service(tmp_path / "state") as service:
        task = await _start(service, workspace, "Legacy task")
        checked = await task.check()
        assert checked.review_mode is None
        review_mode = cast(Mapping[str, object], (await task.status_projected())["review_mode"])
        assert review_mode["mode"] == "local"
        assert review_mode["setting"] == "local_only"
        assert review_mode["ai_review_available"] is False
        assert review_mode["local_reason"] == "conversation_default"

        switch = await task.switch(ReviewMode.AI_POWERED)
        opted = await task.check()
        assert opted.review_mode == CheckReviewMode(
            ReviewMode.LOCAL, "conversation_switch", "ai_review_not_set_up", switch
        )
        status = cast(Mapping[str, object], (await task.status_projected())["review_mode"])
        assert status["local_reason"] == "ai_review_not_set_up"
        assert status["requested"] == "ai_powered"
