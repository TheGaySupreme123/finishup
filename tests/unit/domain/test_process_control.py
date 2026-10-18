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


# --- how the shape travels: inside the commitment list (#1104 round 1) ------------------------

_KEY = b"k" * 32
_SERVER = "python app.py & sleep 2; curl -s localhost:8000; kill $!; wait $!"


def _commitments(command: str) -> tuple[str, tuple[str, ...]]:
    from finishup.domain.command_segments import command_segment_commitments
    from finishup.domain.observation import observed_command_commitment

    whole = observed_command_commitment(_KEY, command)
    segments = command_segment_commitments(_KEY, command)
    return whole, () if segments is None else segments[0]


def test_the_stop_shape_is_a_marker_in_the_commitment_list() -> None:
    from finishup.domain.process_control import (
        process_control_commitment,
        process_control_from_commitments,
    )

    whole, listed = _commitments(_SERVER)
    assert process_control_commitment(STOP_OWN_JOB_TERM, whole) in listed
    assert process_control_from_commitments(whole, listed) == STOP_OWN_JOB_TERM
    # The marker binds the whole command: another command's list never carries this one's.
    other, other_listed = _commitments("server & sleep 1; kill -INT %1; wait")
    assert process_control_from_commitments(other, other_listed) == STOP_OWN_JOB_INT
    assert process_control_from_commitments(whole, other_listed) is None


@pytest.mark.parametrize(
    "command",
    [
        # A verifier stopped by its own kill proves nothing, so it carries no marker.
        "pytest -q & sleep 1; kill $!; wait $!",
        "npm run build & sleep 5; kill %1; wait %1",
        "server & sleep 1; kill $!; echo done",
    ],
)
def test_no_marker_without_the_shape_or_for_a_verifier(command: str) -> None:
    from finishup.domain.process_control import process_control_from_commitments

    whole, listed = _commitments(command)
    assert process_control_from_commitments(whole, listed) is None


def test_a_damaged_list_never_grants_the_shape() -> None:
    from finishup.domain.process_control import (
        process_control_commitment,
        process_control_from_commitments,
    )

    whole, _listed = _commitments(_SERVER)
    both = [process_control_commitment(token, whole) for token in sorted(PROCESS_CONTROLS)]
    assert process_control_from_commitments(whole, both) is None
    assert process_control_from_commitments("omitted:structural", both[:1]) is None
    assert process_control_from_commitments(whole, "not a list") is None


def test_the_envelope_and_wire_gain_no_key() -> None:
    """Version skew: an older build validates envelopes against a closed key set, so the shape
    must never become a structural key of its own (the shared local store and outbox)."""

    from finishup.domain.observation import (
        _STRUCTURAL_KEYS,  # pyright: ignore[reportPrivateUsage]
    )

    assert "process_control" not in _STRUCTURAL_KEYS


def test_markers_keep_the_list_within_its_bound() -> None:
    from finishup.domain.command_segments import MAX_COMMAND_COMMITMENTS

    chain = " && ".join(f"tool{n} --flag-a --flag-b value{n}" for n in range(40))
    _whole, listed = _commitments(chain)
    assert len(listed) <= MAX_COMMAND_COMMITMENTS
    assert list(listed) == sorted(set(listed))
