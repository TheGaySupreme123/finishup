"""A Yoetz call its own MCP server rejected ends as rejected, never as a pipeline loss (tb4n5).

Codex fires no ``PostToolUse`` for a tool result that is not a success, and an MCP result with
``isError: true`` is not one (``codex-rs/core/src/tools/registry.rs`` runs post-tool hooks only
when ``success_for_logging``). In tb4n5 every rejected Yoetz call left its ``PreToolUse`` pending
until it expired as ``pending_attempt_expired`` (17 of 18 attempts). These replays drive real
Codex hook payloads through the hook ingress, with the bridge's own rejection record standing in
for the MCP server, in direct mode and nested in a code-mode cell.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import cast

import pytest

from builders.codex_replay import Replay as _Replay
from builders.codex_replay import (
    exec_cell,
    exec_cell_output,
    mcp_tool_call,
    replay_cell,  # noqa: F401  # pyright: ignore[reportUnusedImport]  (registers the ``replay`` fixture)
    session_start,
    sweep_all,
)
from yoetz.adapters.integrations.yoetz_call_rejections import record_rejected_yoetz_call
from yoetz.domain.observation import ObservationStatusQuery

pytestmark = pytest.mark.anyio

_EXPIRED = "pending_attempt_expired"
_REQUEST = "req_0b6f2d4e-8a1c-4e3b-9f7a-5c2d1e0b9a87"
_OTHER_REQUEST = "req_6e2a9c1b-3d4f-4b8a-a7e6-0f1c2d3e4b5a"


@pytest.fixture(autouse=True)
def _replay_wall_now(replay: _Replay) -> None:  # pyright: ignore[reportUnusedFunction]
    """Hook rows are stamped with the real clock: run the store's deadlines from the same one."""

    replay.wall[0] = time.time()


def _rejected(replay: _Replay, tool: str, request_id: str) -> None:
    """What the bridge records when it answers the call with ``isError``."""

    assert record_rejected_yoetz_call(
        tool,
        {"request_id": request_id},
        state_root=replay.root,
        now_ms=int(time.time() * 1000) + 300,
    )


async def test_a_rejected_direct_yoetz_call_closes_without_the_expiry_gap(
    replay: _Replay,
) -> None:
    session_start(replay, cli_version="0.159.3")
    replay.hook(
        "PreToolUse",
        tool_name="mcp__yoetz__publish_work",
        tool_use_id="call_publish",
        tool_input={"request_id": _REQUEST, "event_drafts": []},
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


async def test_a_rejected_nested_yoetz_call_in_a_cell_closes_too(replay: _Replay) -> None:
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
        tool_input={"request_id": _REQUEST},
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
        tool_input={"request_id": _REQUEST},
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
