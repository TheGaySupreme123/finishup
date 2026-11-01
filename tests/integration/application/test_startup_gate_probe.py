"""Gate reads the real projected status contract, without inferring capture or closure."""

from __future__ import annotations

from typing import cast

import pytest

from builders.projection_workflow import ProjectionCase, project_case, run_projection_workflow
from finishup.cli.startup_gate_probe import probe
from finishup.ports.control import ControlClientKind, ControlMethod, WorkspaceLocator
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import (
    StatusCompactPageModel,
    StatusRequest,
    StatusResult,
    StatusSuccessModel,
)


@pytest.mark.anyio
async def test_probe_requires_live_exact_plan_route_and_readable_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = await run_projection_workflow()
    compact = await project_case(workflow.app, workflow.case("status/compact"), 8000)
    model = StatusResult.model_validate(compact).root
    assert isinstance(model, StatusSuccessModel)
    assert isinstance(model.page, StatusCompactPageModel)
    item = model.page.items[0]
    assert item.current_plan_event_id is not None
    assert item.declared_obligation_count is not None
    seen: list[StatusRequest] = []

    class Client:
        async def status(self, request: StatusRequest, *, deadline_ms: int) -> StatusResult:
            assert deadline_ms == 500
            seen.append(request)
            internal = await workflow.app.status(request)
            case = ProjectionCase(
                "gate",
                ControlMethod.STATUS,
                cast(dict[str, JsonValue], request.model_dump(mode="json")),
                internal,
            )
            projected = await project_case(workflow.app, case, 8100 + len(seen) * 2)
            return StatusResult.model_validate(projected)

        async def close(self) -> None:
            pass

    async def connect(kind: ControlClientKind, *, workspace_locator: WorkspaceLocator) -> Client:
        assert kind is ControlClientKind.CLI
        assert workspace_locator.path == "/project"
        return Client()

    monkeypatch.setattr("finishup.service.client.connect_service", connect)
    request: dict[str, JsonValue] = {
        "route": [model.task_id, model.session_id, model.writer_id],
        "workspace": "/project",
        "plan_id": item.current_plan_event_id,
        "obligation_count": int(item.declared_obligation_count),
    }
    # This workflow has open obligations/findings: readiness is not completion.
    assert int(item.open_obligation_count or "0") > 0
    assert await probe(request)
    assert not await probe({**request, "plan_id": "evt_11111111-1111-4111-8111-111111111111"})
    assert not await probe({**request, "obligation_count": 0})
    assert not await probe(
        {
            **request,
            "route": [
                "tsk_11111111-1111-4111-8111-111111111111",
                model.session_id,
                model.writer_id,
            ],
        }
    )
    assert all(read.view == "compact" for read in seen)
