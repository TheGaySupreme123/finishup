"""Native hook passes under shared-store contention for Codex, Claude Code and Cursor (#689).

A holder process keeps the store lock inside an open batch and reports that on stdout; the hook
runs in this process. Waiting is observed through the store's own lock state, never inferred from
a sleep.
"""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Generator, Mapping
from pathlib import Path
from typing import Any, cast

import pytest

import finishup.adapters.integrations.observation_local as local
import finishup.cli.observe_hooks as observe_hooks
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli.hook_diagnostics import hook_diagnostic_summary
from finishup.cli.observe_hooks import handle_claude_observe, handle_cursor_observe, handle_observe
from finishup.domain.observation import ObservationSource
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)

pytestmark = pytest.mark.skipif(local.fcntl is None, reason="POSIX flock is unavailable")

_HOLDER = """
import sys
from pathlib import Path
from finishup.adapters.integrations.observation_local import (
    LocalObservationStore,
    set_observation_store_lock_role,
)

set_observation_store_lock_role("service")
store = LocalObservationStore(_state=Path(sys.argv[1]))


def settle_for_contention_test():
    with store.batched(sys.argv[2]):
        print("held", flush=True)
        sys.stdin.readline()


settle_for_contention_test()
print("released", flush=True)
"""
_HOSTS = ("codex", "claude", "cursor")
_LANE_PREFIX = {"codex": "", "claude": "claude:", "cursor": "cursor:"}


def _seed(tmp_path: Path) -> tuple[Path, Path, LocalObservationStore, str]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = LocalObservationStore(_state=state)
    commitment = store.workspace_commitment(str(workspace))
    store.grant_consent(commitment)
    store.bind_codex_session(commitment, "seed")
    return state, workspace, store, commitment


def _invoke(host: str, state: Path, workspace: Path, lane: str) -> tuple[int, bytes]:
    """Run one native pre-tool hook pass exactly as the host adapters do, without a service."""

    payload: dict[str, Any] = {
        "session_id": lane,
        "tool_name": "Bash",
        "tool_use_id": f"call-{lane}",
        "tool_input": {"command": "true"},
        "event_ordinal": 1,
    }
    stdout = io.BytesIO()
    arguments: dict[str, Any] = {
        "event_name": "PreToolUse",
        "stdout": stdout,
        "workspace": str(workspace),
        "_state": state,
        "skip_service": True,
    }
    handler: Callable[..., int]
    if host == "claude":
        handler = handle_claude_observe
        arguments["observation_profile"] = CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    elif host == "cursor":
        handler = handle_cursor_observe
        arguments["event_name"] = "preToolUse"
        arguments["observation_profile"] = CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
        payload["conversation_id"] = payload.pop("session_id")
    else:
        handler = handle_observe
        payload["tool_name"] = "shell"
        payload["correlation_id"] = payload["tool_use_id"]
    arguments["stdin_bytes"] = json.dumps(payload).encode()
    code = handler(**arguments)
    return code, stdout.getvalue()


def _retained(store: LocalObservationStore, commitment: str, host: str, lane: str) -> bool:
    return any(
        row.codex_session_id == f"{_LANE_PREFIX[host]}{lane}"
        for row in store.list_pending_outbox_rows(commitment)
    )


@contextlib.contextmanager
def _holder(state: Path, commitment: str) -> Generator[Callable[[], None]]:
    process = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, str(state), commitment],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin is not None and process.stdout is not None
    released = False

    def release() -> None:
        nonlocal released
        if released:
            return
        released = True
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write("\n")
        process.stdin.flush()
        assert process.stdout.readline().strip() == "released"

    try:
        assert process.stdout.readline().strip() == "held"
        yield release
    finally:
        with contextlib.suppress(BrokenPipeError):
            release()
        _stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr


def _store_lock_state(state: Path) -> local._StoreLockState:  # pyright: ignore[reportPrivateUsage]
    key = str((state / "observation" / ".store.lock").absolute())
    return local._STORE_LOCK_REGISTRY[key]  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("host", _HOSTS)
def test_pass_that_outlasts_its_lock_budget_names_the_holder_and_fails_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    state, workspace, store, commitment = _seed(tmp_path)
    monkeypatch.setattr(
        observe_hooks, "_HOOK_STORE_LOCK_BUDGET_BY_WINDOW", {3: 0.3, 5: 0.3, 10: 0.3}
    )
    with _holder(state, commitment):
        code, output = _invoke(host, state, workspace, "blocked")
    assert code == 0
    # The host's ordinary fail-open answer: Cursor's pre-tool hook still allows the tool.
    assert json.loads(output or b"{}") == ({"permission": "allow"} if host == "cursor" else {})
    assert not _retained(store, commitment, host, "blocked")
    summary = hook_diagnostic_summary(_state=state)
    reasons = cast(Mapping[str, object], summary["reasons"])
    # Named for what it is: never an unconsented workspace or the generic degraded pass.
    assert "store_lock_timeout" in reasons
    assert "workspace_unconsented" not in reasons
    assert "observe" not in reasons
    events = cast(tuple[Mapping[str, object], ...], summary["store_lock_events"])
    assert events[-1]["reason"] == "store_lock_timeout"
    assert events[-1]["role"] == "hook"
    assert events[-1]["holder_role"] == "service"
    assert events[-1]["holder_phase"] == "settle_for_contention_test"
    assert events[-1]["scope"] == "process"
    waited = events[-1]["waited_ms"]
    assert type(waited) is int and waited < 2_000

    # After contention ends the same host retains its next input.
    code, _output = _invoke(host, state, workspace, "after")
    assert code == 0
    assert _retained(store, commitment, host, "after")


@pytest.mark.parametrize("host", _HOSTS)
def test_pass_queued_behind_a_holder_commits_once_the_holder_releases(
    tmp_path: Path, host: str
) -> None:
    state, workspace, store, commitment = _seed(tmp_path)
    outcome: dict[str, object] = {}

    def run() -> None:
        try:
            outcome["result"] = _invoke(host, state, workspace, "queued")
        except BaseException as error:  # pragma: no cover - surfaced below
            outcome["error"] = error

    with _holder(state, commitment) as release:
        hook = threading.Thread(target=run)
        hook.start()
        # Observe the hook's own lock state: it owns the process-local lock and is queueing for
        # the holder's flock. Bounded, and it fails on the deadline rather than passing on it.
        lock_state = _store_lock_state(state)
        deadline = time.monotonic() + 30
        while not (lock_state.owner == hook.ident and not lock_state.flock_held):
            assert hook.is_alive() and time.monotonic() < deadline, outcome
            time.sleep(0.001)
        release()
        hook.join(timeout=30)
    assert "error" not in outcome
    assert outcome["result"][0] == 0  # type: ignore[index]
    assert _retained(store, commitment, host, "queued")
    reasons = cast(Mapping[str, object], hook_diagnostic_summary(_state=state)["reasons"])
    assert "store_lock_timeout" not in reasons


@pytest.mark.parametrize(
    ("source", "event", "window"),
    (
        (ObservationSource.CODEX_HOOK, "PreToolUse", 10),
        (ObservationSource.CODEX_HOOK, "SessionEnd", 3),
        (ObservationSource.CLAUDE_HOOK, "PreToolUse", 5),
        (ObservationSource.CLAUDE_HOOK, "PostToolUse", 5),
        (ObservationSource.CLAUDE_HOOK, "Stop", 10),
        (ObservationSource.CLAUDE_HOOK, "SessionEnd", 3),
        (ObservationSource.CURSOR_HOOK, "PostToolUse", 5),
        (ObservationSource.CURSOR_HOOK, "SessionStart", 10),
    ),
)
def test_lock_budget_follows_the_rendered_host_window(
    source: ObservationSource, event: str, window: int
) -> None:
    host_window = observe_hooks._hook_host_window_seconds(source, event)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert host_window == window
    budget = observe_hooks._HOOK_STORE_LOCK_BUDGET_BY_WINDOW[host_window]  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    # The lock budget always leaves the host at least a second to finish the pass.
    assert 0 < budget <= host_window - 1.0
