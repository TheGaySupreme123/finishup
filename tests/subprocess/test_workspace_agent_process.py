"""A real ``finishup agent run`` process ends when ``server use`` leaves its target (ADR-051).

Decision 8: the way out of a remote selection under zero-network stops its traffic. A client's
connection started the target's workspace agent as its own detached process (``python -m finishup
agent run --root R``, ``start_new_session``), which would otherwise keep answering the server's
workspace reads for up to 15 minutes after its last workspace note. ``server use local`` (the
zero-network choice's "switch" and the terminal interface's "Use local" run the same
``use_target``) clears the selection and then stops that agent as ``server disconnect`` does,
through its owner-only request file and never by a pid or a pattern: when it returns, the agent
has released its lock.

Run with ``env -u FINISHUP_ISOLATED_ROOT -u YOETZ_ISOLATED_ROOT``.
"""

from __future__ import annotations

import time

import pytest

from builders.server_targets import ambient_home
from finishup.client import targets
from finishup.client.agent import AGENT_STOP_NAME, agent_pid, ensure_agent
from finishup.config.paths import reset_selection_memo

# How long a freshly spawned interpreter may take to import FinishUP and take the agent's lock.
_START_DEADLINE_SECONDS = 60.0


def test_switching_to_local_stops_the_workspace_agent_of_the_server_it_leaves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.cli.server import use_target

    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "lab", "ssh", user="owner", host="lab.example", port=22
            )
            targets.write_selection(record)
        reset_selection_memo()
        assert ensure_agent(root) is True
        deadline = time.monotonic() + _START_DEADLINE_SECONDS
        while agent_pid(root) is None:
            log = root / "log" / "agent.stderr.log"
            assert time.monotonic() < deadline, log.read_text("utf-8", "replace")
            time.sleep(0.05)
        try:
            switch = use_target("local")

            assert targets.read_selected_target_id() is None
            assert switch.left is not None and switch.left.target_id == record.target_id
            assert not switch.left_open
            # The agent process itself ended: nothing holds its lock, and the request it read
            # is gone, so the next agent this target starts is not stopped by it.
            assert agent_pid(root) is None
            assert not (root / "state" / AGENT_STOP_NAME).exists()
        finally:
            # Only the agent this test spawned, through its own request file, never by pattern.
            from finishup.client.agent import stop_agent

            stop_agent(root)
