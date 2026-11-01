"""#1190 (owner decision B): a review-mode switch may not name a check as its only parent.

That shape is reserved for advisory responses, so a withheld one is recognised from its envelope
alone. The rule holds on the memory and SQLite ledgers alike.
"""

# pyright: reportPrivateUsage=false
from __future__ import annotations

from typing import Literal, cast

import pytest

import integration.application.test_respond_status_receipt as h
from builders.start_application import start_request
from finishup.domain.values import Frontier
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PublicOperationError
from finishup.protocol.models import PublishWorkRequest
from integration.closure.test_closure_shapes import _action, _obligation, _plan, _Run

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _switch(run: _Run, parents: list[str]) -> dict[str, JsonValue]:
    draft = run.draft(
        "decision_recorded",
        {
            "statement": "Switch this task's review mode.",
            "rationale": "The change is larger than planned.",
            "authority": "harness:review-mode",
            "review_mode": "local",
        },
    )
    cast(dict[str, JsonValue], draft["schema"])["version"] = "1.1.0"
    draft["causal_parents"] = cast(JsonValue, parents)
    return draft


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_a_switch_whose_only_parent_is_a_check_is_refused(
    backend: Literal["memory", "sqlite"],
) -> None:
    app, runtime, _ = h._build_app(seed_offset=91, ledger_backend=backend)
    run = _Run(app, runtime, await app.start(start_request(91, title="review mode parent")))
    await run.publish(_obligation(run, 1), _plan(run, 1))
    await run.check_in("deterministic_only")
    history = await run.status("history")
    check = next(
        str(item.event_id)
        for item in getattr(history.page, "items", ())
        if item.schema_name == "check_recorded"
    )
    before = run.frontier
    with pytest.raises(PublicOperationError) as refused:
        await run.publish(_switch(run, [check]))
    details = refused.value.safe_details
    assert details["reason_code"] == "review_mode_parent_is_check"
    assert details["field"] == "/event_drafts/0/causal_parents"
    assert "correctness-advisory answers" in refused.value.message
    assert run.frontier == before
    # Any other parent set is still admitted: none, or the check beside another record.
    acted = await run.publish(_action(run, 1))
    other = str(acted.accepted_events[0].event_id)
    await run.publish(_switch(run, []))
    await run.publish(_switch(run, sorted([check, other])))


async def _ledger_frontier(runtime: h._WorkflowRuntime, run: _Run) -> Frontier:
    ledger, _objects = runtime.resources[run.started.task_id]
    return await ledger.load_frontier()


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_a_dry_run_refuses_the_switch_exactly_as_the_publish_does(
    backend: Literal["memory", "sqlite"],
) -> None:
    """A preview never reports success for a batch the publish refuses, and appends nothing."""

    app, runtime, _ = h._build_app(seed_offset=92, ledger_backend=backend)
    run = _Run(app, runtime, await app.start(start_request(92, title="review mode dry run")))
    await run.publish(_obligation(run, 1), _plan(run, 1))
    await run.check_in("deterministic_only")
    history = await run.status("history")
    check = next(
        str(item.event_id)
        for item in getattr(history.page, "items", ())
        if item.schema_name == "check_recorded"
    )
    switch = _switch(run, [check])
    before = await _ledger_frontier(runtime, run)
    refusals: list[PublicOperationError] = []
    for dry_run in (True, False):
        with pytest.raises(PublicOperationError) as refused:
            await app.publish_work(
                PublishWorkRequest.model_validate(
                    {
                        **h._request_base(run.next("req_")),
                        "session_id": run.started.session_id,
                        "writer_id": run.started.writer_id,
                        "expected_frontier": h._frontier(run.frontier),
                        "event_drafts": [switch],
                        "dry_run": dry_run,
                    }
                )
            )
        refusals.append(refused.value)
        assert await _ledger_frontier(runtime, run) == before
    preview, publish = refusals
    assert publish.safe_details["reason_code"] == "review_mode_parent_is_check"
    assert (preview.code, preview.safe_details, preview.message) == (
        publish.code,
        publish.safe_details,
        publish.message,
    )
