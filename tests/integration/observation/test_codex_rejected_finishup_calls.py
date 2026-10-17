"""A FinishUP call its own MCP server rejected ends as rejected, never as a pipeline loss (tb4n5).

Codex fires no ``PostToolUse`` for a tool result that is not a success, and an MCP result with
``isError: true`` is not one (``codex-rs/core/src/tools/registry.rs`` runs post-tool hooks only
when ``success_for_logging``). In tb4n5 every rejected FinishUP call left its ``PreToolUse`` pending
until it expired as ``pending_attempt_expired`` (17 of 18 attempts). These replays drive real
Codex hook payloads through the hook ingress, with the bridge's own rejection record standing in
for the MCP server, in direct mode and nested in a code-mode cell.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import dataclasses
import time
from collections.abc import Mapping
from typing import cast

import pytest
from mcp import types

import finishup.mcp.server as bridge
from builders.codex_replay import Replay as _Replay
from builders.codex_replay import (
    exec_cell,
    exec_cell_output,
    mcp_tool_call,
    replay_cell,  # noqa: F401  # pyright: ignore[reportUnusedImport]  (registers the ``replay`` fixture)
    session_start,
    sweep_all,
)
from finishup.adapters.integrations import finishup_call_rejections
from finishup.adapters.integrations.finishup_call_rejections import record_rejected_finishup_call
from finishup.domain.observation import ObservationStatusQuery
from finishup.mcp.publish_identity import PublishRepeatGuard

pytestmark = pytest.mark.anyio

_EXPIRED = "pending_attempt_expired"
_REQUEST = "req_0b6f2d4e-8a1c-4e3b-9f7a-5c2d1e0b9a87"
_OTHER_REQUEST = "req_6e2a9c1b-3d4f-4b8a-a7e6-0f1c2d3e4b5a"
# The call's operation scope, which the hook's ``tool_input`` and the bridge's arguments share.
_SCOPE = {
    "session_id": "ses_2b8f4c1d-9e3a-4f6b-8c7d-0a1b2c3d4e5f",
    "writer_id": "wri_5c9d1e2f-3a4b-4c6d-9e8f-7a6b5c4d3e2f",
}


@pytest.fixture(autouse=True)
def _replay_wall_now(replay: _Replay) -> None:  # pyright: ignore[reportUnusedFunction]
    """Hook rows are stamped with the real clock: run the store's deadlines from the same one."""

    replay.wall[0] = time.time()


def _rejected(replay: _Replay, tool: str, request_id: str) -> None:
    """What the bridge records when it answers the call with ``isError``."""

    assert record_rejected_finishup_call(
        tool,
        {"request_id": request_id, **_SCOPE},
        state_root=replay.root,
        now_ms=int(time.time() * 1000) + 300,
    )


async def test_a_rejected_direct_finishup_call_closes_without_the_expiry_gap(
    replay: _Replay,
) -> None:
    session_start(replay, cli_version="0.159.3")
    replay.hook(
        "PreToolUse",
        tool_name="mcp__yoetz__publish_work",
        tool_use_id="call_publish",
        tool_input={"request_id": _REQUEST, **_SCOPE, "event_drafts": []},
    )
    _rejected(replay, "publish_work", _REQUEST)
    # Codex sends no PostToolUse. The next hook, past the grace, reconciles the attempt.
    replay.advance(30)
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    replay.advance(900)
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    await sweep_all(replay)

    endings = replay.store.pending_attempt_endings(replay.commitment)
    assert endings["counts"] == {"rejected_by_yoetz": 1}
    assert _EXPIRED not in replay.store.status(ObservationStatusQuery(replay.commitment)).gaps


async def test_a_rejected_nested_finishup_call_in_a_cell_closes_too(replay: _Replay) -> None:
    session_start(replay, cli_version="0.159.3")
    replay.append(
        exec_cell(
            "call_cell",
            "await tools.mcp__yoetz__check({});\n",
            "2026-10-12T19:40:00.000Z",
            item_id="ctc_call_cell",
        )
    )
    replay.hook(
        "PreToolUse",
        tool_name="mcp__yoetz__check",
        tool_use_id="call_nested",
        tool_input={"request_id": _REQUEST, **_SCOPE},
    )
    _rejected(replay, "check", _REQUEST)
    replay.append(
        mcp_tool_call("exec-check", "check", "2026-10-12T19:40:00.500Z", status="failed"),
        exec_cell_output(
            "call_cell", '{"ok":false}', "2026-10-12T19:40:00.600Z", item_id="ctco_call_cell"
        ),
    )
    replay.advance(30)
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    replay.advance(900)
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    await sweep_all(replay)

    assert replay.store.pending_attempt_endings(replay.commitment)["counts"] == {
        "rejected_by_yoetz": 1
    }
    assert _EXPIRED not in replay.store.status(ObservationStatusQuery(replay.commitment)).gaps


async def test_a_missing_post_nobody_rejected_still_expires_with_its_identity(
    replay: _Replay,
) -> None:
    """A genuine missing result keeps its gap, now with the producer named."""

    session_start(replay, cli_version="0.159.3")
    replay.hook(
        "PreToolUse",
        tool_name="mcp__yoetz__status",
        tool_use_id="call_status",
        tool_input={"request_id": _REQUEST, **_SCOPE},
    )
    # A different request was rejected: it closes nothing here.
    _rejected(replay, "status", _OTHER_REQUEST)
    replay.hook(
        "PreToolUse",
        tool_name="Bash",
        tool_use_id="call_bash",
        tool_input={"command": "sleep 1000"},
    )
    replay.advance(700)
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    await sweep_all(replay)

    endings = replay.store.pending_attempt_endings(replay.commitment)
    assert endings["counts"] == {"ttl": 2}
    recent = cast(tuple[Mapping[str, object], ...], endings["recent"])
    assert sorted(str(entry["tool"]) for entry in recent) == ["Bash", "mcp__yoetz__status"]
    assert _EXPIRED in replay.store.status(ObservationStatusQuery(replay.commitment)).gaps


# PR #1088 round 3: ``publish_work`` omits ``request_id`` by default (issue #1084). The bridge mints
# the id after Codex's PreToolUse saw the call, so both sides commit to the agent's canonical body.
_IDLESS_INVALID: dict[str, object] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    **_SCOPE,
    "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
    "client": {"kind": "cooperative_agent", "version": "0.1.0", "integration": "cooperative_mcp"},
    "event_drafts": [{"schema": {"name": "decision_recorded", "version": "9.9.9"}}],
}


async def _idless_publish_through_the_bridge(
    replay: _Replay, monkeypatch: pytest.MonkeyPatch, tool_use_id: str
) -> types.CallToolResult:
    """Codex's pre-event, then the real bridge entry point answering the agent's own arguments."""

    root = replay.root
    monkeypatch.setattr(finishup_call_rejections, "state_dir", lambda: root)
    replay.hook(
        "PreToolUse",
        tool_name="mcp__finishup__publish_work",
        tool_use_id=tool_use_id,
        tool_input=dict(_IDLESS_INVALID),
    )
    runtime = dataclasses.replace(
        bridge.build_bridge_runtime(host_profile="codex"), publish_guard=PublishRepeatGuard()
    )
    served = await bridge._handle_call_tool_request(
        types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(
                name="publish_work", arguments=dict(_IDLESS_INVALID)
            ),
        ),
        runtime,
    )
    await bridge.close_bridge_runtime(runtime)
    result = served.root
    assert isinstance(result, types.CallToolResult) and result.isError is True
    return result


async def test_a_rejected_idless_publish_closes_without_the_expiry_gap(
    replay: _Replay, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_start(replay, cli_version="0.159.3")
    await _idless_publish_through_the_bridge(replay, monkeypatch, "call_idless")
    # Codex sends no PostToolUse for the error. The next hook, past the grace, reconciles it.
    replay.advance(30)
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    replay.advance(900)
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    await sweep_all(replay)

    assert replay.store.pending_attempt_endings(replay.commitment)["counts"] == {
        "rejected_by_yoetz": 1
    }
    assert _EXPIRED not in replay.store.status(ObservationStatusQuery(replay.commitment)).gaps


async def test_two_identical_rejected_idless_publishes_pair_one_to_one(
    replay: _Replay, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_start(replay, cli_version="0.159.3")
    for tool_use_id in ("call_idless_first", "call_idless_second"):
        await _idless_publish_through_the_bridge(replay, monkeypatch, tool_use_id)
    replay.advance(30)
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    replay.advance(900)
    replay.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    await sweep_all(replay)

    assert replay.store.pending_attempt_endings(replay.commitment)["counts"] == {
        "rejected_by_yoetz": 2
    }
    assert _EXPIRED not in replay.store.status(ObservationStatusQuery(replay.commitment)).gaps
