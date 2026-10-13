"""How a pending hook attempt ends without its post (tb4n5, #1041).

``pending_attempt_expired`` appeared in 17 of 18 tb4n5 attempts, and the exports could not name
the call: expiry kept only the aggregate gap. The pre-minus-post surplus was at least the number of
Yoetz calls the server rejected in every attempt, because a host fires no ``PostToolUse`` for an
error result. Each ending now keeps its bounded structural identity, and a Yoetz call that Yoetz's
own MCP server answered with an error closes as ``rejected_by_yoetz`` without the expiry gap.
Every other missing post keeps expiring, with the gap.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

from yoetz.adapters.integrations import yoetz_call_rejections as rejections
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.domain.observation import ObservationSource, ObservationStatusQuery
from yoetz.domain.values import Timestamp

_EXPIRED = "pending_attempt_expired"
_START = 1_790_704_600.0  # 2026-09-29T17:56:40Z
_REQUEST = "req_7d1e5c2a-3b4f-4a6e-9c8d-1f2e3a4b5c6d"


class _Clock:
    def __init__(self) -> None:
        self.now = _START

    def __call__(self) -> float:
        return self.now


def _store(tmp_path: Path) -> tuple[LocalObservationStore, str, str, _Clock]:
    clock = _Clock()
    store = LocalObservationStore(_state=tmp_path, _wall=clock)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    session = store.bind_codex_session(workspace, "019f9b27-c1de-7a61-9c5e-5d0b89759417")
    return store, workspace, session, clock


def _open(
    store: LocalObservationStore,
    workspace: str,
    session: str,
    call: str,
    tool: str,
    *,
    generation: int = 1,
    request_commitment: str | None = None,
) -> None:
    assert store.note_open_pre(
        workspace,
        call,
        "PreToolUse",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=generation,
        tool_name=tool,
        request_commitment=request_commitment,
    )


def _prune(store: LocalObservationStore, workspace: str, session: str) -> bool:
    return store.has_open_pre(
        workspace,
        "call_probe",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=1,
    )


def test_an_expired_attempt_names_its_tool_generation_and_reason(tmp_path: Path) -> None:
    store, workspace, session, clock = _store(tmp_path)
    _open(store, workspace, session, "call_bash", "Bash")
    clock.now += 601
    _prune(store, workspace, session)

    endings = store.pending_attempt_endings(workspace)
    assert endings["counts"] == {"ttl": 1}
    assert endings["open"] == 0
    (recent,) = cast(tuple[Mapping[str, object], ...], endings["recent"])
    assert recent["reason"] == "ttl"
    assert recent["tool"] == "Bash"
    assert recent["generation"] == 1
    # An opaque digest, never the host call id.
    assert recent["call"] != "call_bash" and len(str(recent["call"])) == 16
    assert _EXPIRED in store.status(ObservationStatusQuery(workspace)).gaps
    # The identity survives a restart.
    assert LocalObservationStore(_state=tmp_path).pending_attempt_endings(workspace) == endings


def test_session_end_and_a_newer_generation_are_named_apart(tmp_path: Path) -> None:
    store, workspace, session, _clock = _store(tmp_path)
    assert store.begin_session_generation(workspace, session) == 1
    _open(store, workspace, session, "call_old", "apply_patch", generation=1)
    assert store.begin_session_generation(workspace, session) == 2
    assert store.pending_attempt_endings(workspace)["counts"] == {"generation": 1}

    _open(store, workspace, session, "call_last", "mcp__github__create_issue", generation=2)
    store.note_session_end(workspace, session, generation=2)
    endings = store.pending_attempt_endings(workspace)
    assert endings["counts"] == {"generation": 1, "session_end": 1}
    recent = cast(tuple[Mapping[str, object], ...], endings["recent"])
    assert [entry["tool"] for entry in recent] == [
        "apply_patch",
        "mcp__github__create_issue",
    ]


def test_a_yoetz_call_its_server_rejected_closes_without_the_expiry_gap(tmp_path: Path) -> None:
    store, workspace, session, clock = _store(tmp_path)
    commitment = rejections.rejected_call_commitment("mcp__yoetz__publish_work", _REQUEST)
    assert commitment is not None
    _open(
        store,
        workspace,
        session,
        "call_publish",
        "mcp__yoetz__publish_work",
        request_commitment=commitment,
    )
    # The bridge answers with an error a moment later; Codex then fires no PostToolUse.
    assert rejections.record_rejected_yoetz_call(
        "publish_work",
        {"request_id": _REQUEST},
        state_root=tmp_path,
        now_ms=int((clock.now + 0.2) * 1000),
    )
    # Within the grace a host that does send a post for an error still pairs it.
    clock.now += 1
    _prune(store, workspace, session)
    assert store.pending_attempt_endings(workspace)["open"] == 1

    clock.now += 10
    _prune(store, workspace, session)
    endings = store.pending_attempt_endings(workspace)
    assert endings["counts"] == {"rejected_by_yoetz": 1}
    assert endings["open"] == 0
    clock.now += 900
    _prune(store, workspace, session)
    assert _EXPIRED not in store.status(ObservationStatusQuery(workspace)).gaps


def test_a_rejection_before_the_attempt_never_closes_it(tmp_path: Path) -> None:
    """A same-request retry after a rejection is a new attempt: only its own outcome closes it."""

    store, workspace, session, clock = _store(tmp_path)
    commitment = rejections.rejected_call_commitment("mcp__yoetz__check", _REQUEST)
    rejections.record_rejected_yoetz_call(
        "check", {"request_id": _REQUEST}, state_root=tmp_path, now_ms=int(clock.now * 1000)
    )
    clock.now += 2
    _open(
        store, workspace, session, "call_retry", "mcp__yoetz__check", request_commitment=commitment
    )
    clock.now += 30
    _prune(store, workspace, session)
    assert store.pending_attempt_endings(workspace)["open"] == 1


def test_one_rejection_closes_at_most_one_attempt(tmp_path: Path) -> None:
    store, workspace, session, clock = _store(tmp_path)
    commitment = rejections.rejected_call_commitment("mcp__yoetz__status", _REQUEST)
    _open(store, workspace, session, "call_a", "mcp__yoetz__status", request_commitment=commitment)
    _open(store, workspace, session, "call_b", "mcp__yoetz__status", request_commitment=commitment)
    rejections.record_rejected_yoetz_call(
        "status", {"request_id": _REQUEST}, state_root=tmp_path, now_ms=int(clock.now * 1000) + 50
    )
    clock.now += 30
    _prune(store, workspace, session)
    endings = store.pending_attempt_endings(workspace)
    assert endings["counts"] == {"rejected_by_yoetz": 1}
    assert endings["open"] == 1
    # The other attempt still expires as a genuine missing post.
    clock.now += 600
    _prune(store, workspace, session)
    assert store.pending_attempt_endings(workspace)["counts"] == {
        "rejected_by_yoetz": 1,
        "ttl": 1,
    }
    assert _EXPIRED in store.status(ObservationStatusQuery(workspace)).gaps


def test_the_bridge_records_only_error_results_for_yoetz_tools(tmp_path: Path) -> None:
    from mcp import types

    from yoetz.mcp import server

    root = rejections.state_dir()
    (root / "observation").mkdir(parents=True, exist_ok=True)
    error = types.CallToolResult(content=[], structuredContent={"ok": False}, isError=True)
    success = types.CallToolResult(content=[], structuredContent={"ok": True}, isError=False)

    server._record_rejected_call("publish_work", {"request_id": _REQUEST}, success)
    assert rejections.read_rejected_yoetz_calls(root / "observation") == ()
    server._record_rejected_call("publish_work", {"request_id": "not-an-id"}, error)
    assert rejections.read_rejected_yoetz_calls(root / "observation") == ()
    server._record_rejected_call("publish_work", {"request_id": _REQUEST}, error)
    (recorded,) = rejections.read_rejected_yoetz_calls(root / "observation")
    assert recorded[0] == rejections.rejected_call_commitment("publish_work", _REQUEST)
    # Only the commitment and the moment are written: never the request id itself.
    assert _REQUEST not in (root / "observation" / rejections.REJECTED_CALLS_FILENAME).read_text()


def test_every_host_spelling_of_a_yoetz_tool_commits_alike() -> None:
    expected = rejections.rejected_call_commitment("check", _REQUEST)
    for spelling in (
        "mcp__yoetz__check",
        "mcp__plugin_yoetz_yoetz__check",
        "yoetz:check",
        "MCP:check",
    ):
        assert rejections.rejected_call_commitment(spelling, _REQUEST) == expected
    assert rejections.rejected_call_commitment("mcp__github__check", _REQUEST) is None
    assert rejections.rejected_call_commitment("check", None) is None


def test_no_record_is_written_where_observation_was_never_set_up(tmp_path: Path) -> None:
    assert not rejections.record_rejected_yoetz_call(
        "check", {"request_id": _REQUEST}, state_root=tmp_path / "fresh"
    )
    assert not (tmp_path / "fresh").exists()


def test_receipt_time_comparison_uses_the_attempts_own_receipt(tmp_path: Path) -> None:
    """A pre stamped with the host receipt time is matched against that moment."""

    store, workspace, session, clock = _store(tmp_path)
    commitment = rejections.rejected_call_commitment("mcp__yoetz__respond", _REQUEST)
    receipt = Timestamp("2026-09-29T17:56:40.000Z")
    assert store.note_open_pre(
        workspace,
        "call_respond",
        "PreToolUse",
        source=ObservationSource.CODEX_HOOK,
        session_commitment=session,
        source_generation=1,
        receipt_time=receipt,
        tool_name="mcp__yoetz__respond",
        request_commitment=commitment,
    )
    rejections.record_rejected_yoetz_call(
        "respond", {"request_id": _REQUEST}, state_root=tmp_path, now_ms=1_790_704_600_500
    )
    clock.now += 30
    _prune(store, workspace, session)
    assert store.pending_attempt_endings(workspace)["counts"] == {"rejected_by_yoetz": 1}
