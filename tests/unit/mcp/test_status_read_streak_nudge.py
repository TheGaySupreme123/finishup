"""A repeated ``status`` read leads with one concrete next write (tb4 n5).

In the tb4 n5 S arm the agent read ``status`` 45+ times with no write while five obligations
stayed open. From the third consecutive first-page read by the same actor on the same session with
no intervening write call through the bridge, the result's text leads with one next write drawn
from the readiness the same result carries. The structured result never changes.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final, cast

import pytest
from mcp import types

from yoetz.mcp import server as bridge
from yoetz.mcp.status_streak import (
    STATUS_STREAK_NUDGE_THRESHOLD,
    StatusReadStreaks,
    status_streak_nudge,
)
from yoetz.ports.control import McpHostProfile

_SESSION: Final = "ses_00000000-0000-4000-8000-000000000001"
_OTHER_SESSION: Final = "ses_00000000-0000-4000-8000-000000000002"
_OBLIGATION: Final = "obl_00000000-0000-4000-8000-00000000000a"
_RESOLVED: Final = "obl_00000000-0000-4000-8000-00000000000b"
_SUMMARY: Final = "Status view: obligations; frontier 12;"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _status_args(**overrides: object) -> dict[str, object]:
    args: dict[str, object] = {
        "session_id": _SESSION,
        "actor": {"actor_id": "agent:main", "actor_type": "logical_agent"},
        "view": "obligations",
    }
    args.update(overrides)
    return args


def _obligations_wire(
    state: str = "action_required", actionable: tuple[str, ...] = ("obligations_open",)
) -> dict[str, Any]:
    return {
        "ok": True,
        "view": "obligations",
        "page": {
            "items": [
                {"obligation_id": _RESOLVED, "status": "resolved"},
                {
                    "obligation_id": _OBLIGATION,
                    "status": "open",
                    "in_current_plan": True,
                    "closure_class": "agent_work",
                },
            ]
        },
        "closure_readiness": {"state": state, "agent_actionable": list(actionable)},
    }


def _streak(reads: int) -> int:
    streaks = StatusReadStreaks()
    count = 0
    for _ in range(reads):
        count = streaks.note_call("status", _status_args())
    return count


def test_streak_counts_reads_and_any_write_of_the_session_resets_it() -> None:
    streaks = StatusReadStreaks()
    assert [streaks.note_call("status", _status_args()) for _ in range(3)] == [1, 2, 3]
    # Reads of other kinds neither count nor reset.
    assert streaks.note_call("read_guidance", {"uri": "yoetz://guidance/workflow.md"}) == 0
    assert streaks.note_call("closure_prepare", {"session_id": _SESSION}) == 0
    assert streaks.note_call("status", _status_args()) == 4
    for write in ("publish_work", "check", "respond", "receipt"):
        assert streaks.note_call(write, {"session_id": _SESSION}) == 0
        assert streaks.note_call("status", _status_args()) == 1
    # A start without a session (a create) ends every streak.
    streaks.note_call("status", _status_args())
    streaks.note_call("start", {"mode": "create"})
    assert streaks.note_call("status", _status_args()) == 1


def test_streak_is_per_session_and_actor_and_skips_pages_and_operation_polls() -> None:
    streaks = StatusReadStreaks()
    streaks.note_call("status", _status_args())
    streaks.note_call("status", _status_args())
    other_actor = {"actor_id": "agent:child", "actor_type": "delegated_subagent"}
    assert streaks.note_call("status", _status_args(actor=other_actor)) == 1
    assert streaks.note_call("status", _status_args(session_id=_OTHER_SESSION)) == 1
    # Another session's write leaves this streak alone.
    streaks.note_call("publish_work", {"session_id": _OTHER_SESSION})
    assert streaks.note_call("status", _status_args()) == 3
    # A continuation page and a running-check poll are how status is meant to be reread.
    assert streaks.note_call("status", _status_args(cursor="opaque-page-2")) == 0
    assert streaks.note_call("status", _status_args(view="operation")) == 0
    assert streaks.note_call("status", _status_args()) == 4


def test_nudge_names_the_first_open_obligation_and_its_resolution_write() -> None:
    wire = _obligations_wire()
    assert status_streak_nudge(wire, STATUS_STREAK_NUDGE_THRESHOLD - 1) == ""
    nudge = status_streak_nudge(wire, _streak(3))
    assert nudge.startswith("Status read 3 times in a row with no write. No status read is needed.")
    assert (
        f"Next: publish_work obligation_published for {_OBLIGATION} with status resolved" in nudge
    )
    assert "resolution_evidence_refs" in nudge
    assert _RESOLVED not in nudge


@pytest.mark.parametrize(
    ("state", "actionable", "expected"),
    [
        ("ready", (), "Next: call receipt."),
        ("ready_with_limitations", (), "Next: call receipt."),
        ("action_required", ("findings_unanswered",), "Next: call respond"),
        ("action_required", ("receipt_findings_unresolved",), "then check."),
        ("action_required", ("no_plan_published",), "a plan that declares the obligations"),
        ("action_required", ("completion_plan_not_claimed",), "completion claim_recorded"),
        ("action_required", ("planned_verification_stale",), "run the planned verification"),
        ("action_required", ("closing_review_required",), "check with final_review: true"),
        ("action_required", ("check_not_recorded",), "Next: call check."),
        ("action_required", ("lineage_child_read_gap",), "resolve lineage_child_read_gap with"),
    ],
)
def test_nudge_follows_the_readiness_the_result_carries(
    state: str, actionable: tuple[str, ...], expected: str
) -> None:
    nudge = status_streak_nudge(_obligations_wire(state, actionable), 3)
    assert expected in nudge


def test_no_nudge_for_an_error_or_a_running_check() -> None:
    assert status_streak_nudge({"ok": False}, 9) == ""
    running = _obligations_wire(actionable=("check_in_progress", "obligations_open"))
    assert status_streak_nudge(running, 9) == ""


def _patched_status(monkeypatch: pytest.MonkeyPatch, wire: Mapping[str, Any]) -> list[str]:
    calls: list[str] = []

    async def fake_status(
        arguments: Mapping[str, object], runtime: bridge.BridgeRuntime = bridge.BRIDGE_RUNTIME
    ) -> types.CallToolResult:
        del arguments, runtime
        calls.append("status")
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=_SUMMARY)],
            structuredContent=dict(wire),
            isError=False,
        )

    async def fake_publish(
        arguments: Mapping[str, object], runtime: bridge.BridgeRuntime = bridge.BRIDGE_RUNTIME
    ) -> types.CallToolResult:
        del arguments, runtime
        calls.append("publish_work")
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="published")],
            structuredContent={"ok": True},
            isError=False,
        )

    monkeypatch.setattr(bridge, "dispatch_status", fake_status)
    monkeypatch.setattr(bridge, "dispatch_publish_work", fake_publish)
    return calls


def _texts(result: types.CallToolResult) -> list[str]:
    return [cast(types.TextContent, block).text for block in result.content]


@pytest.mark.anyio
@pytest.mark.parametrize("host", ["generic", "codex", "claude"])
async def test_third_read_leads_the_text_and_a_write_resets_it(
    monkeypatch: pytest.MonkeyPatch, host: McpHostProfile
) -> None:
    wire = _obligations_wire()
    _patched_status(monkeypatch, wire)
    runtime = bridge.build_bridge_runtime("policy", host_profile=host)
    try:
        first = await bridge.call_tool("status", _status_args(), runtime)
        second = await bridge.call_tool("status", _status_args(), runtime)
        third = await bridge.call_tool("status", _status_args(), runtime)
        await bridge.call_tool("publish_work", {"session_id": _SESSION}, runtime)
        after_write = await bridge.call_tool("status", _status_args(), runtime)
    finally:
        await bridge.close_bridge_runtime(runtime)
    assert _texts(first) == [_SUMMARY] and _texts(second) == [_SUMMARY]
    (text,) = _texts(third)
    lead, _, rest = text.partition("\n")
    assert lead.startswith("Status read 3 times in a row with no write.")
    assert _OBLIGATION in lead
    assert rest == _SUMMARY
    # The structured result is served unchanged.
    assert third.structuredContent == wire
    assert _texts(after_write) == [_SUMMARY]


@pytest.mark.anyio
async def test_cursor_keeps_its_canonical_block_and_gains_a_leading_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patched_status(monkeypatch, _obligations_wire())
    runtime = bridge.build_bridge_runtime("policy", host_profile="cursor")
    try:
        for _ in range(2):
            await bridge.call_tool("status", _status_args(), runtime)
        third = await bridge.call_tool("status", _status_args(), runtime)
    finally:
        await bridge.close_bridge_runtime(runtime)
    texts = _texts(third)
    assert len(texts) == 2
    assert texts[0].startswith("Status read 3 times in a row with no write.")
    assert texts[1] == _SUMMARY


@pytest.mark.parametrize(
    "wire",
    [
        # The service's honest unknown: its one checklist entry is to read status again.
        {
            "ok": True,
            "closure_readiness": {"state": "unknown", "agent_actionable": ["readiness_unknown"]},
        },
        {
            "ok": True,
            "closure_readiness": {
                "state": "action_required",
                "agent_actionable": ["projection_stale"],
            },
        },
        {"ok": True},
        {"ok": True, "closure_readiness": {"state": "bogus", "agent_actionable": []}},
        # A projection still catching up: rereading is what the contract asks for.
        {**_obligations_wire(), "rebuild_state": "rebuilding"},
        {**_obligations_wire(), "projection_lag": "4"},
    ],
    ids=["unknown", "stale", "absent", "unrecognized", "rebuilding", "lagging"],
)
def test_no_nudge_while_readiness_is_unknown_or_the_projection_is_catching_up(
    wire: dict[str, Any],
) -> None:
    """Round 2 (3): an unknown readiness must not become "no status read is needed"."""

    assert status_streak_nudge(wire, 9) == ""


_SUPERSEDED: Final = "obl_00000000-0000-4000-8000-00000000000c"
_SETTLED: Final = "obl_00000000-0000-4000-8000-00000000000d"


def test_nudge_names_only_an_effective_agent_work_obligation_of_the_current_plan() -> None:
    """Round 2 (2): plan v2 replaced obligation A by B; the nudge must name B, never A."""

    wire = _obligations_wire()
    wire["page"]["items"] = [
        # v1's obligation, superseded by the revision: still "open" in the history listing.
        {"obligation_id": _SUPERSEDED, "status": "open", "in_current_plan": False},
        # Effective but settled (acknowledged/disclosed): not agent work.
        {
            "obligation_id": _SETTLED,
            "status": "open",
            "in_current_plan": True,
            "closure_class": "settled_disclosed",
        },
        {
            "obligation_id": _OBLIGATION,
            "status": "open",
            "in_current_plan": True,
            "closure_class": "agent_work",
        },
    ]
    nudge = status_streak_nudge(wire, 3)
    assert _OBLIGATION in nudge
    assert _SUPERSEDED not in nudge and _SETTLED not in nudge


@pytest.mark.parametrize(
    "items",
    [
        # Plan scope unreadable: no in_current_plan, so no single obligation can be named.
        [{"obligation_id": _OBLIGATION, "status": "open"}],
        [{"obligation_id": _SUPERSEDED, "status": "open", "in_current_plan": False}],
        # The compact view's open list carries no plan scope at all.
        [{"open_obligations": [{"obligation_id": _OBLIGATION}]}],
    ],
    ids=["scope-unknown", "only-superseded", "compact"],
)
def test_nudge_names_no_obligation_it_cannot_prove_current(items: list[dict[str, Any]]) -> None:
    wire = _obligations_wire()
    wire["page"]["items"] = items
    nudge = status_streak_nudge(wire, 3)
    assert "obl_" not in nudge
    assert "each open obligation of the current plan" in nudge


def test_nudge_follows_the_agent_actionable_order() -> None:
    """The first agent-actionable entry the service listed decides the next write."""

    first_findings = _obligations_wire(actionable=("findings_unanswered", "obligations_open"))
    assert "Next: call respond" in status_streak_nudge(first_findings, 3)
    first_check = _obligations_wire(actionable=("check_not_recorded", "findings_unanswered"))
    assert "Next: call check." in status_streak_nudge(first_check, 3)
