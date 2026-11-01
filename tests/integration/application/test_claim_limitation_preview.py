"""Status names the ids a completion claim must disclose, so the first claim is accepted (F3).

tb4n1: 34 of 35 ``claim_revision_mismatch`` rejections were ``limitation_refs_complete``. The
agent learned the missing ``res_`` ids only from the rejection. Status readiness now lists them
before the claim, computed by the reducer's own rule; these cases drive the real application.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import cast

import pytest

from builders.projection_workflow import build_projection_application, frontier_json, request_base
from builders.start_application import protocol_id, start_request
from finishup.application.service import Application
from finishup.cli.closure_gate import closure_gate_from_readiness
from finishup.cli.render import render_closure_readiness_lines
from finishup.mcp.summaries import MAX_SUMMARY_BYTES, summary_for_status
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PublicOperationError
from finishup.protocol.models import PublishWorkRequest, StatusRequest

pytestmark = pytest.mark.anyio

_RESULT_ID = re.compile(r"res_[0-9a-f-]{36}")


def _draft(
    event_id: str, name: str, payload: Mapping[str, JsonValue], version: str = "1.0.0"
) -> dict[str, JsonValue]:
    return {
        "event_id": event_id,
        "schema": {"name": name, "version": version},
        "occurred_at": "2026-10-07T12:00:00.000Z",
        "causal_parents": [],
        "payload": dict(payload),
        "artifact_refs": [],
        "evidence_refs": [],
    }


class _Task:
    def __init__(self, app: Application, session_id: str, writer_id: str, seed: int) -> None:
        self.app = app
        self.session_id = session_id
        self.writer_id = writer_id
        self.seed = seed
        self.frontier: JsonValue = None

    def next(self, prefix: str) -> str:
        self.seed += 1
        return protocol_id(prefix, self.seed)

    async def publish(self, drafts: list[dict[str, JsonValue]], *, dry_run: bool = False) -> None:
        result = await self.app.publish_work(
            PublishWorkRequest.model_validate(
                {
                    **request_base(self.next("req_")),
                    "session_id": self.session_id,
                    "writer_id": self.writer_id,
                    "expected_frontier": self.frontier,
                    **({"dry_run": True} if dry_run else {}),
                    "event_drafts": drafts,
                }
            )
        )
        if not dry_run:
            self.frontier = frontier_json(result.result_frontier)  # pyright: ignore[reportAttributeAccessIssue]

    async def status(self):  # noqa: ANN201 - the internal status result
        return await self.app.status(
            StatusRequest.model_validate(
                {
                    **request_base(self.next("req_")),
                    "session_id": self.session_id,
                    "writer_id": self.writer_id,
                    "view": "compact",
                    "limit": "1",
                }
            )
        )

    def run(
        self, outcome: str, obligations: tuple[str, ...]
    ) -> tuple[list[dict[str, JsonValue]], str]:
        action, result = self.next("act_"), self.next("res_")
        return [
            _draft(
                self.next("evt_"),
                "action_recorded",
                {
                    "action_id": action,
                    "action_kind": "command",
                    "description": "Ran the acceptance suite.",
                    "command": "pytest -q tests/acceptance",
                    "obligation_refs": list(obligations),
                },
            ),
            _draft(
                self.next("evt_"),
                "result_recorded",
                {
                    "result_id": result,
                    "action_id": action,
                    "outcome": outcome,
                    "summary": f"The suite reported {outcome}.",
                },
            ),
        ], result

    def claim(self, limitations: list[str]) -> list[dict[str, JsonValue]]:
        return [
            _draft(
                self.next("evt_"),
                "claim_recorded",
                {
                    "claim_id": self.next("clm_"),
                    "claim_kind": "completion",
                    "statement": "The change is complete; the listed results stay limitations.",
                    "obligation_refs": [],
                    "supporting_refs": [],
                    "limitation_refs": cast(JsonValue, sorted(limitations)),
                    "supersedes_claim_refs": [],
                },
                version="1.1.0",
            )
        ]


async def _task(seed: int) -> tuple[_Task, dict[str, str]]:
    app, _ = await build_projection_application(seed=seed)
    started = await app.start(start_request(seed, title="Ship the parser fix"))
    task = _Task(app, started.session_id, started.writer_id, seed + 100)
    task.frontier = frontier_json(started.frontier)
    obl_a, obl_b = task.next("obl_"), task.next("obl_")
    drafts: list[dict[str, JsonValue]] = [
        _draft(
            task.next("evt_"),
            "obligation_published",
            {
                "obligation_id": obligation,
                "description": f"Deliver part {name} of the parser fix.",
                "evidence_expectation": "A recorded passing acceptance run.",
                "status": "open",
            },
        )
        for name, obligation in (("A", obl_a), ("B", obl_b))
    ]
    drafts.append(
        _draft(
            task.next("evt_"),
            "plan_published",
            {"plan_version": 1, "summary": "Fix the parser.", "obligation_refs": [obl_a, obl_b]},
        )
    )
    ids: dict[str, str] = {}
    for key, outcome, scope in (
        ("failure_a", "failure", (obl_a,)),
        ("partial_b", "partial", (obl_b,)),
        ("failure_unscoped", "failure", ()),
        ("success", "success", (obl_a,)),
        ("unknown", "unknown", ()),
    ):
        run, ids[key] = task.run(outcome, scope)
        drafts.extend(run)
    await task.publish(drafts)
    return task, ids


async def test_status_lists_exactly_the_ids_the_reducer_demands() -> None:
    task, ids = await _task(9811)
    readiness = (await task.status()).closure_readiness
    required = {ids["failure_a"], ids["partial_b"], ids["failure_unscoped"]}
    assert readiness.limitation_refs_required == tuple(sorted(required, key=str.encode))
    assert readiness.limitation_refs_required_count == "3"
    # The reducer's rejection of an undisclosed claim names the same set.
    with pytest.raises(PublicOperationError) as caught:
        await task.publish(task.claim([]), dry_run=True)
    assert set(_RESULT_ID.findall(caught.value.message)) == required


async def test_a_first_claim_built_from_status_is_accepted_and_every_surface_names_it() -> None:
    task, ids = await _task(9831)
    status = await task.status()
    readiness = status.closure_readiness
    surfaced = list(readiness.limitation_refs_required or ())
    summary = summary_for_status(status.as_json())
    assert "limitation_refs a whole-task completion claim must name (3): " in summary
    assert surfaced[0] in summary
    assert len(summary.encode()) <= MAX_SUMMARY_BYTES
    lines = render_closure_readiness_lines(readiness)
    assert any(all(value in line for value in surfaced) for line in lines)
    gate = closure_gate_from_readiness(
        readiness,
        frontier_sequence="1",
        frontier_digest="sha256:" + "0" * 64,
        observation_pending=False,
    )
    assert gate is not None and all(value in gate.text for value in surfaced)
    await task.publish(task.claim(surfaced))
    assert ids["unknown"] not in surfaced
