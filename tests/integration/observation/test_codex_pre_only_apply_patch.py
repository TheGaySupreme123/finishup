"""A Codex shell ``apply_patch <<EOF`` is a pre-only call its observed file change closes (#1041).

Codex intercepts a shell ``apply_patch`` heredoc and applies the patch itself, so only the shell
call's ``PreToolUse`` fires. The pending attempt it opened used to expire after ten minutes (or at
the session's end) as ``pending_attempt_expired``: 44 of tb4n4's 60 deterministic attempts carried
that gap for a host behaviour, not a lost observation. The rollout's ``FileChange`` item is the
observed change; it now closes the attempt. A patch whose change is never observed, and any
other pre-event without its post, still expire with the gap.
"""

from __future__ import annotations

from typing import Any

import anyio

from builders.codex_replay import Replay as _Replay
from builders.codex_replay import (
    replay_cell,  # noqa: F401  # pyright: ignore[reportUnusedImport]  (registers the ``replay`` fixture)
    rollout_row,
    session_start,
    sweep_all,
)
from finishup.domain.observation import ObservationStatusQuery
from finishup.kernel.later_material import LaterMaterialClass, classify_later_material
from finishup.kernel.observed_failures import observed_event_ids_from_records
from finishup.kernel.reducers import replay as reduce_replay
from finishup.kernel.task_facts import cooperative_event_ids_from_records, material_edit_recorded

_EXPIRED = "pending_attempt_expired"
_PATCH = (
    "apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: src/public.py\n@@\n-a\n+b\n"
    "*** End Patch\nEOF"
)


def _shell_pre(cell: _Replay, call: str, command: str) -> None:
    cell.hook("PreToolUse", tool_name="Bash", tool_use_id=call, tool_input={"command": command})


def _file_change(item_id: str) -> dict[str, Any]:
    return rollout_row(
        "event_msg",
        {
            "item": {
                "changes": {"/app/src/public.py": {"type": "update"}},
                "id": item_id,
                "status": "completed",
                "type": "FileChange",
            },
            "type": "item_completed",
        },
        "2026-09-29T17:58:00.000Z",
    )


def _gaps_after_the_session_ends(cell: _Replay) -> tuple[str, ...]:
    """End the turn and the session, which retires every still-pending attempt, and read the gaps.

    The replay's hook envelopes carry the real wall clock, so the ten-minute deadline cannot be
    advanced here; a fenced session end retires a pending attempt the same way (ADR-029).
    """

    cell.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    cell.hook("SessionEnd", reason="exit")
    return cell.store.status(ObservationStatusQuery(cell.commitment)).gaps


def test_the_observed_file_change_closes_a_shell_apply_patch(replay: _Replay) -> None:
    session_start(replay)
    _shell_pre(replay, "call_patch", _PATCH)
    # Code mode names the item ``exec-<uuid>``, not the hook's call: the session's oldest
    # pre-only attempt is the one the change closes.
    replay.append(_file_change("exec-0e5dcfc8-patch"))
    assert _EXPIRED not in _gaps_after_the_session_ends(replay)


def test_an_unobserved_patch_and_an_ordinary_lost_post_still_expire(replay: _Replay) -> None:
    session_start(replay)
    _shell_pre(replay, "call_patch", _PATCH)
    assert _EXPIRED in _gaps_after_the_session_ends(replay)


def test_a_file_change_never_closes_an_ordinary_pending_call(replay: _Replay) -> None:
    session_start(replay)
    _shell_pre(replay, "call_build", "make build")
    replay.append(_file_change("call_build"))
    assert _EXPIRED in _gaps_after_the_session_ends(replay)


_NATIVE_PATCH = {
    "command": "*** Begin Patch\n*** Update File: src/public.py\n@@\n-b\n+c\n*** End Patch"
}


def _native_apply_patch_pre(cell: _Replay, call: str) -> None:
    cell.hook("PreToolUse", tool_name="apply_patch", tool_use_id=call, tool_input=_NATIVE_PATCH)


def _native_apply_patch_post(cell: _Replay, call: str) -> None:
    cell.hook(
        "PostToolUse",
        tool_name="apply_patch",
        tool_use_id=call,
        tool_input=_NATIVE_PATCH,
        tool_response=(
            "Exit code: 0\nWall time: 0.1 seconds\nOutput:\nSuccess. Updated the following files:\n"
            "M src/public.py\n"
        ),
    )


def test_a_hooked_call_s_own_file_change_never_closes_a_shell_patch_attempt(
    replay: _Replay,
) -> None:
    """Direct mode: the item id is the call's own id, so it names that call, not the shell patch.

    The shell patch Codex rejected wrote no change; the native ``apply_patch`` retry's change
    belongs to the retry. Its post already arrived, so only the stored hook rows name the call.
    """

    session_start(replay)
    _shell_pre(replay, "call_shell_patch", _PATCH)
    _native_apply_patch_pre(replay, "call_native_patch")
    _native_apply_patch_post(replay, "call_native_patch")
    replay.append(_file_change("call_native_patch"))
    assert _EXPIRED in _gaps_after_the_session_ends(replay)


def test_a_change_read_before_its_hooked_call_s_post_never_closes_a_shell_patch_attempt(
    replay: _Replay,
) -> None:
    """The rollout can record the change while the native call's own pre is still open."""

    session_start(replay)
    _shell_pre(replay, "call_shell_patch", _PATCH)
    replay.append(_file_change("call_native_patch"))
    _native_apply_patch_pre(replay, "call_native_patch")
    _native_apply_patch_post(replay, "call_native_patch")
    assert _EXPIRED in _gaps_after_the_session_ends(replay)


def test_an_unattributable_change_still_closes_a_shell_patch_beside_hooked_calls(
    replay: _Replay,
) -> None:
    """An id no hook reported (code mode's ``exec-<uuid>``) still closes the oldest attempt."""

    session_start(replay)
    _native_apply_patch_pre(replay, "call_native_patch")
    _native_apply_patch_post(replay, "call_native_patch")
    _shell_pre(replay, "call_shell_patch", _PATCH)
    replay.append(_file_change("exec-0e5dcfc8-patch"))
    assert _EXPIRED not in _gaps_after_the_session_ends(replay)


def test_a_shell_patch_s_own_file_change_closes_it_beside_hooked_calls(replay: _Replay) -> None:
    session_start(replay)
    _native_apply_patch_pre(replay, "call_native_patch")
    _native_apply_patch_post(replay, "call_native_patch")
    _shell_pre(replay, "call_shell_patch", _PATCH)
    replay.append(_file_change("call_shell_patch"))
    assert _EXPIRED not in _gaps_after_the_session_ends(replay)


def _ledger_after_the_turn(cell: _Replay) -> tuple[Any, ...]:
    cell.hook("Stop", last_assistant_message="Done.", stop_hook_active=False)
    anyio.run(sweep_all, cell)
    return tuple(cell.ledger._state.records)  # pyright: ignore[reportPrivateUsage]


def test_a_shell_patch_is_a_material_edit_though_its_result_never_arrives(replay: _Replay) -> None:
    """#1046 review: the ledger's only record of the patch is its pending command action.

    Codex fires only the pre-event and its ``FileChange`` stays local, so the action carries the
    write the hook read off the patch's file headers. Where the check-time capture is unavailable
    (a non-git workspace, as here) that write is what lets the first check after the edit review
    as configured instead of deferring again; it also supersedes an earlier check as an edit.
    """

    session_start(replay)
    _shell_pre(replay, "call_patch", _PATCH)
    replay.append(_file_change("call_patch"))
    records = _ledger_after_the_turn(replay)
    state = reduce_replay(records)
    (action,) = [row.payload for row in state.actions.values() if row.payload is not None]
    assert "(write workspace)" in action.description
    assert not state.results
    observed = observed_event_ids_from_records(records)
    cooperative = cooperative_event_ids_from_records(records)
    assert material_edit_recorded(state, observed, cooperative) is True
    (recorded,) = replay.rows("action_recorded")
    assert classify_later_material(recorded, state).material_class is (
        LaterMaterialClass.EDIT_OR_WRITE
    )


def test_an_ordinary_pending_command_is_still_no_edit(replay: _Replay) -> None:
    session_start(replay)
    _shell_pre(replay, "call_build", "make build")
    records = _ledger_after_the_turn(replay)
    state = reduce_replay(records)
    observed = observed_event_ids_from_records(records)
    cooperative = cooperative_event_ids_from_records(records)
    assert material_edit_recorded(state, observed, cooperative) is False
