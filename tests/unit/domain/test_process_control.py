"""The own-background-job stop shape and its exit judgment (#1104, ``domain.process_control``)."""

from __future__ import annotations

import pytest

from finishup.domain.process_control import (
    PROCESS_CONTROLS,
    STOP_OWN_JOB_INT,
    STOP_OWN_JOB_KILL,
    STOP_OWN_JOB_TERM,
    own_job_stop_signal,
    stopped_own_job,
)


@pytest.mark.parametrize(
    ("command", "token"),
    [
        (
            "python app.py & sleep 2; curl -s localhost:8000; kill $!; wait $!",
            STOP_OWN_JOB_TERM,
        ),
        ('python app.py & sleep 2; kill "$!"; wait "$!"', STOP_OWN_JOB_TERM),
        ("python app.py & PID=$!; sleep 1; kill $PID; wait $PID", STOP_OWN_JOB_TERM),
        ("python app.py & PID=$!; sleep 1; kill -INT ${PID}; wait ${PID}", STOP_OWN_JOB_INT),
        ("server & sleep 1 && kill -INT %1; wait", STOP_OWN_JOB_INT),
        ("server & sleep 1; kill -s KILL $! 2>/dev/null; wait $! 2>/dev/null", STOP_OWN_JOB_KILL),
        ("server & sleep 1; kill -9 %%; wait", STOP_OWN_JOB_KILL),
        ("server &\nsleep 1\nkill $!\nwait $!", STOP_OWN_JOB_TERM),
    ],
)
def test_own_job_stop_shapes(command: str, token: str) -> None:
    assert own_job_stop_signal(command) == token
    assert token in PROCESS_CONTROLS


@pytest.mark.parametrize(
    "command",
    [
        # No background job launched by this command.
        "python app.py; kill $!; wait $!",
        # Pattern matches can stop someone else's process.
        "server & sleep 1; pkill -f app; wait",
        "server & sleep 1; killall app; wait",
        # A literal process id is not provably this command's job.
        "server & sleep 1; kill 1234; wait",
        # A variable not assigned from ``$!`` at the top level.
        "server & sleep 1; kill $PID; wait",
        # A quoted ``&`` is no separator.
        "echo 'a & b'; kill $!; wait $!",
        # The kill is not followed by a final ``wait``.
        "server & sleep 1; kill $!; echo done",
        "server & sleep 1; wait $!; kill $!",
        # A wait on something else, or an unknown signal.
        "server & sleep 1; kill $!; wait 1234",
        "server & sleep 1; kill -HUP $!; wait $!",
        # Inside a nested shell: not the top level.
        "bash -c 'server & sleep 1; kill $!; wait $!'",
        "",
    ],
)
def test_other_shapes_never_qualify(command: str) -> None:
    assert own_job_stop_signal(command) is None


@pytest.mark.parametrize(
    ("token", "exit_status", "stopped"),
    [
        (STOP_OWN_JOB_TERM, 143, True),
        (STOP_OWN_JOB_INT, 130, True),
        (STOP_OWN_JOB_KILL, 137, True),
        # The job crashed before the kill: ``wait`` returns its own status.
        (STOP_OWN_JOB_TERM, 1, False),
        # A different signal than the one the command sent.
        (STOP_OWN_JOB_TERM, 137, False),
        # No stated exit (a Codex hook post): never exempt by itself.
        (STOP_OWN_JOB_TERM, None, False),
        (None, 143, False),
        ("own_job_stopped", 143, False),
    ],
)
def test_the_exit_must_be_exactly_the_stop_status(
    token: str | None, exit_status: int | None, stopped: bool
) -> None:
    assert stopped_own_job(token, exit_status) is stopped
