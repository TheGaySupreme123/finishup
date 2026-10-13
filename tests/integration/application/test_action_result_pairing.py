"""Every published action needs a result naming it (tb4n5 follow-up, owner decisions 2026-10-13).

tb4n5 raised ``action_without_result`` in 13 of 18 attempts, 15 local findings, every one on an
action the agent itself published; 8 of 15 fired only because a sibling action sat in the same
``publish_work`` batch. Agents conveyed outcomes through evidence and decisions, which link
nothing, and learned the pairing rule only from the finding. These cases run the real ready
composition:

* medical S L95: one batch records an edit, a command, the command's result and evidence. The
  publish result names the edit as having no result (``action_notices``); the next check raises
  nothing for the same-batch sibling; a later batch's unrelated work raises the genuinely
  unaccounted edit; linking its result resolves it.
* the guidance example: a completed action published with its result in the same batch draws no
  notice and no finding.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import pytest

from builders.projection_workflow import (
    ProjectionCase,
    build_projection_application,
    frontier_json,
    project_case,
    request_base,
)
from builders.start_application import protocol_id, start_request
from yoetz.application.service import Application
from yoetz.domain.findings import FindingKind
from yoetz.mcp.summaries import render_publish_action_notices
from yoetz.ports.control import ControlMethod
from yoetz.ports.ledger import CheckCommitResult
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.models import (
    PUBLISH_ACTION_NOTICE_TEXTS,
    CheckRequest,
    PublishWorkRequest,
    StatusFindingsPageModel,
    StatusRequest,
)

pytestmark = pytest.mark.anyio


def _draft(event: str, name: str, payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        "event_id": event,
        "schema": {"name": name, "version": "1.0.0"},
        "occurred_at": "2026-10-12T21:40:00.000Z",
        "causal_parents": [],
        "payload": payload,
        "artifact_refs": [],
        "evidence_refs": [],
    }


def _obligation(obligation: str, text: str) -> dict[str, JsonValue]:
    return {
        "obligation_id": obligation,
        "description": text,
        "evidence_expectation": "A recorded result.",
        "status": "open",
    }


class _Run:
    def __init__(self, app: Application, session_id: str, writer_id: str, frontier: JsonValue):
        self.app = app
        self.session_id = session_id
        self.writer_id = writer_id
        self.frontier = frontier

    def body(self, seed: int, drafts: list[dict[str, JsonValue]]) -> dict[str, JsonValue]:
        return {
            **request_base(protocol_id("req_", seed)),
            "session_id": self.session_id,
            "writer_id": self.writer_id,
            "expected_frontier": self.frontier,
            "event_drafts": cast(JsonValue, drafts),
        }

    async def publish(self, seed: int, drafts: list[dict[str, JsonValue]]) -> Mapping[str, Any]:
        result = await self.app.publish_work(
            PublishWorkRequest.model_validate(self.body(seed, drafts))
        )
        self.frontier = frontier_json(result.result_frontier)
        return cast(Mapping[str, Any], cast(Any, result).as_json())

    async def check(self, seed: int) -> CheckCommitResult:
        checked = await self.app.check(
            CheckRequest.model_validate(
                {
                    **request_base(protocol_id("req_", seed)),
                    "session_id": self.session_id,
                    "writer_id": self.writer_id,
                    "expected_frontier": self.frontier,
                    "mode": "deterministic_only",
                    "max_findings": "10",
                }
            )
        )
        assert type(checked) is CheckCommitResult
        self.frontier = frontier_json(checked.result_frontier)
        return checked


async def _begin(seed: int) -> _Run:
    app, _policy = await build_projection_application(seed=seed, max_findings=10)
    started = await app.start(start_request(seed, title="Pair every action with its result"))
    return _Run(app, started.session_id, started.writer_id, frontier_json(started.frontier))


def _notices(body: Mapping[str, Any]) -> list[tuple[str, str]]:
    return [(row["action_id"], row["notice"]) for row in body.get("action_notices", ())]


def _action_findings(checked: CheckCommitResult) -> list[tuple[str, ...]]:
    return [
        tuple(str(ref) for ref in item.subject_refs)
        for item in checked.findings
        if item.kind is FindingKind.ACTION_WITHOUT_RESULT
    ]


async def test_medical_shape_names_the_unpaired_edit_and_only_later_work_raises_it() -> None:
    seed = 10500
    run = await _begin(seed)
    engine, reseed, later = (protocol_id("obl_", seed + n) for n in (1, 2, 3))
    edit, command, other = (protocol_id("act_", seed + n) for n in (4, 5, 6))
    edit_event = protocol_id("evt_", seed + 10)
    batch = [
        _draft(
            protocol_id("evt_", seed + 7),
            "plan_published",
            {"plan_version": 1, "summary": "Plan", "obligation_refs": [engine, reseed, later]},
        ),
        _draft(protocol_id("evt_", seed + 8), "obligation_published", _obligation(engine, "Edit")),
        _draft(protocol_id("evt_", seed + 9), "obligation_published", _obligation(reseed, "Seed")),
        _draft(protocol_id("evt_", seed + 11), "obligation_published", _obligation(later, "Other")),
        _draft(
            edit_event,
            "action_recorded",
            {
                "action_id": edit,
                "action_kind": "edit",
                "description": "Rewrote the triage scoring engine.",
                "obligation_refs": [engine],
            },
        ),
        _draft(
            protocol_id("evt_", seed + 12),
            "action_recorded",
            {
                "action_id": command,
                "action_kind": "command",
                "command": "python reseed.py",
                "description": "Reinstalled and reseeded the database.",
                "obligation_refs": [reseed],
            },
        ),
        _draft(
            protocol_id("evt_", seed + 13),
            "result_recorded",
            {
                "result_id": protocol_id("res_", seed + 14),
                "action_id": command,
                "outcome": "success",
            },
        ),
    ]
    # A dry run returns the same notice a real publish would, and records nothing.
    preview = await run.app.publish_work(
        PublishWorkRequest.model_validate({**run.body(seed + 20, batch), "dry_run": True})
    )
    dumped = cast(Any, preview).model_dump(mode="json", exclude_none=True)
    assert _notices(dumped) == [(edit, "result_not_linked")]

    wire = run.body(seed + 21, batch)
    published = await run.publish(seed + 21, batch)
    assert _notices(published) == [(edit, "result_not_linked")]
    assert (
        published["action_notices"][0]["text"] == PUBLISH_ACTION_NOTICE_TEXTS["result_not_linked"]
    )
    # The MCP bridge projection keeps it (an act_ id, a closed code, fixed text) and renders it.
    replayed = await run.app.publish_work(PublishWorkRequest.model_validate(wire))
    projected = await project_case(
        run.app,
        ProjectionCase(
            "publish_work",
            ControlMethod.PUBLISH_WORK,
            cast(Mapping[str, JsonValue], wire),
            cast(Any, replayed),
        ),
        seed + 22,
    )
    assert cast(Mapping[str, Any], projected)["action_notices"] == [
        {
            "action_id": edit,
            "notice": "result_not_linked",
            "text": PUBLISH_ACTION_NOTICE_TEXTS["result_not_linked"],
        }
    ]
    assert render_publish_action_notices(projected).startswith(f"Action notice for {edit}: ")
    # A replay of the same request returns the same notice.
    assert _notices(cast(Any, replayed).as_json()) == [(edit, "result_not_linked")]

    # The sibling command in the same batch is not later work: nothing is raised yet.
    first = await run.check(seed + 30)
    assert _action_findings(first) == []

    # Later unrelated work in its own batch, published with its result: no notice for it, and the
    # still-unaccounted edit is now raised (the genuinely missing result is never hidden).
    paired = await run.publish(
        seed + 40,
        [
            _draft(
                protocol_id("evt_", seed + 41),
                "action_recorded",
                {
                    "action_id": other,
                    "action_kind": "research",
                    "description": "Read the triage protocol notes.",
                    "obligation_refs": [later],
                },
            ),
            _draft(
                protocol_id("evt_", seed + 42),
                "result_recorded",
                {
                    "result_id": protocol_id("res_", seed + 43),
                    "action_id": other,
                    "outcome": "success",
                    "summary": "The notes confirm the scoring order.",
                },
            ),
        ],
    )
    assert "action_notices" not in paired
    second = await run.check(seed + 50)
    assert _action_findings(second) == [(edit_event,)]
    raised = next(
        item for item in second.findings if item.kind is FindingKind.ACTION_WITHOUT_RESULT
    )

    # Linking the edit's result resolves it.
    linked = await run.publish(
        seed + 60,
        [
            _draft(
                protocol_id("evt_", seed + 61),
                "result_recorded",
                {
                    "result_id": protocol_id("res_", seed + 62),
                    "action_id": edit,
                    "outcome": "success",
                    "summary": "The engine edit is in place.",
                },
            )
        ],
    )
    assert "action_notices" not in linked
    third = await run.check(seed + 70)
    assert _action_findings(third) == []
    status = await run.app.status(
        StatusRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 80)),
                "session_id": run.session_id,
                "writer_id": run.writer_id,
                "view": "findings",
                "limit": "50",
                "filter": {"include_resolved": True},
            }
        )
    )
    assert isinstance(status.page, StatusFindingsPageModel)
    row = next(item for item in status.page.items if item.finding_id == raised.finding_id)
    assert row.resolved is True


async def test_a_completed_action_published_with_its_result_draws_no_notice_or_finding() -> None:
    """The guidance example: the action and the result naming it in one batch."""

    seed = 10600
    run = await _begin(seed)
    first, second = protocol_id("obl_", seed + 1), protocol_id("obl_", seed + 2)
    edit, test = protocol_id("act_", seed + 3), protocol_id("act_", seed + 4)
    published = await run.publish(
        seed + 10,
        [
            _draft(
                protocol_id("evt_", seed + 5),
                "plan_published",
                {"plan_version": 1, "summary": "Plan", "obligation_refs": [first, second]},
            ),
            _draft(protocol_id("evt_", seed + 6), "obligation_published", _obligation(first, "A")),
            _draft(protocol_id("evt_", seed + 7), "obligation_published", _obligation(second, "B")),
            _draft(
                protocol_id("evt_", seed + 8),
                "action_recorded",
                {
                    "action_id": edit,
                    "action_kind": "edit",
                    "description": "Implemented the buffered worker.",
                    "obligation_refs": [first],
                },
            ),
            _draft(
                protocol_id("evt_", seed + 9),
                "result_recorded",
                {
                    "result_id": protocol_id("res_", seed + 11),
                    "action_id": edit,
                    "outcome": "success",
                    "summary": "The worker buffers writes.",
                },
            ),
        ],
    )
    assert "action_notices" not in published
    later = await run.publish(
        seed + 20,
        [
            _draft(
                protocol_id("evt_", seed + 21),
                "action_recorded",
                {
                    "action_id": test,
                    "action_kind": "command",
                    "command": "pytest -q",
                    "description": "Ran the focused tests.",
                    "obligation_refs": [second],
                },
            ),
            _draft(
                protocol_id("evt_", seed + 22),
                "result_recorded",
                {
                    "result_id": protocol_id("res_", seed + 23),
                    "action_id": test,
                    "outcome": "failure",
                },
            ),
        ],
    )
    assert "action_notices" not in later
    checked = await run.check(seed + 30)
    assert _action_findings(checked) == []
