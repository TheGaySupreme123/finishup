"""The closed process-control shape of one observed shell command (#1104, owner decision D2).

An agent that probes a server it started itself stops it in the same command:
``python app.py & sleep 2; curl -s localhost:8000; kill $!; wait $!``. The final ``wait`` returns
the job's status, so the call exits ``143`` (``128 + SIGTERM``) and every host reports it as a
failure, although nothing the agent was asked to do failed. That failure carries no failed-work
duty, but only when FinishUP can tell it from a crash.

The *shape* is classified from the command text alone (never output, never an exit status), so
the same token is derived on every host, including Codex, whose ``PostToolUse`` states no exit
(``own_job_stop_signal``).

**How the shape travels (version skew, #1104 round 1).** Not as a structural key: the local
observation store and the outbox are shared on disk by every build that runs during an upgrade
(a still-running older service, hooks run from retained release copies), and an older reader
refuses an envelope with a key it does not know, for the whole workspace. The shape therefore
travels as one more entry of the existing ``command_segment_commitments`` list:
``process_control_commitment``, a keyed derivative of the whole-command commitment that every
build already accepts as an inert commitment. ``domain.command_segments`` adds it wherever a
command's commitments are computed (a host hook and the Codex session stream alike, so a
stream-first call carries it too), and ``process_control_from_commitments`` reads it back. An
older build sees nothing new and keeps the ordinary failure duty. The exit is judged later against the outcome FinishUP
finally records for the call (a hook-stated exit, or the Codex session stream's outcome joined to
the call): ``stopped_own_job`` is true only for exactly ``128 + signal``. A job that crashed
before the kill makes ``wait`` return the job's own status (say ``1``), and a ``kill`` of a job
that already exited fails, so neither is exempt.

Recognized at the top level of the command only (no wrapper argument or here-document body):

1. a top-level ``&`` separator: this command launched a background job;
2. a top-level ``kill`` whose operands are only references to that job (``$!``, ``%N``, ``%%``,
   ``%+``, or ``$V``/``${V}`` where an earlier top-level segment is exactly ``V=$!``), with no
   signal option (TERM) or one of ``-TERM|-15|-SIGTERM|-s TERM``, ``-INT|-2|-SIGINT|-s INT``,
   ``-KILL|-9|-SIGKILL|-s KILL``. ``pkill`` and ``killall`` match processes by pattern and never
   qualify, nor does a literal process id;
3. the last top-level segment is ``wait`` with no operand or only such references, after the
   ``kill``.

Deferred, because no recorded host payload exists for them: a Codex ``write_stdin`` interrupt of
a running session, a separate ``kill PID`` call, and Claude Code ``KillShell``.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from typing import Final, cast

__all__ = [
    "PROCESS_CONTROLS",
    "STOP_OWN_JOB_INT",
    "STOP_OWN_JOB_KILL",
    "STOP_OWN_JOB_TERM",
    "own_job_stop_signal",
    "process_control_commitment",
    "process_control_from_commitments",
    "stopped_own_job",
]

STOP_OWN_JOB_TERM: Final = "stop_own_job_term"
STOP_OWN_JOB_INT: Final = "stop_own_job_int"
STOP_OWN_JOB_KILL: Final = "stop_own_job_kill"
PROCESS_CONTROLS: Final = frozenset({STOP_OWN_JOB_TERM, STOP_OWN_JOB_INT, STOP_OWN_JOB_KILL})

# The shell's status for a job ended by the signal: 128 + signal number.
_EXPECTED_EXIT: Final = {STOP_OWN_JOB_TERM: 143, STOP_OWN_JOB_INT: 130, STOP_OWN_JOB_KILL: 137}
_SIGNAL_OPTIONS: Final = {
    "-TERM": STOP_OWN_JOB_TERM,
    "-15": STOP_OWN_JOB_TERM,
    "-SIGTERM": STOP_OWN_JOB_TERM,
    "-INT": STOP_OWN_JOB_INT,
    "-2": STOP_OWN_JOB_INT,
    "-SIGINT": STOP_OWN_JOB_INT,
    "-KILL": STOP_OWN_JOB_KILL,
    "-9": STOP_OWN_JOB_KILL,
    "-SIGKILL": STOP_OWN_JOB_KILL,
}
_SIGNAL_NAMES: Final = {
    "TERM": STOP_OWN_JOB_TERM,
    "SIGTERM": STOP_OWN_JOB_TERM,
    "15": STOP_OWN_JOB_TERM,
    "INT": STOP_OWN_JOB_INT,
    "SIGINT": STOP_OWN_JOB_INT,
    "2": STOP_OWN_JOB_INT,
    "KILL": STOP_OWN_JOB_KILL,
    "SIGKILL": STOP_OWN_JOB_KILL,
    "9": STOP_OWN_JOB_KILL,
}
_JOB_SPEC_RE: Final = re.compile(r"\A%(?:[0-9]{1,4}|%|\+)\Z")
_VARIABLE_RE: Final = re.compile(
    r"\A\$(?:\{([A-Za-z_][A-Za-z0-9_]{0,63})\}|([A-Za-z_][A-Za-z0-9_]{0,63}))\Z"
)
_JOB_ASSIGNMENT_RE: Final = re.compile(r"\A([A-Za-z_][A-Za-z0-9_]{0,63})=\$!\Z")


def _own_job_operand(word: str, job_variables: frozenset[str]) -> bool:
    if word == "$!" or _JOB_SPEC_RE.fullmatch(word) is not None:
        return True
    match = _VARIABLE_RE.fullmatch(word)
    return match is not None and (match.group(1) or match.group(2)) in job_variables


def _kill_signal(words: list[str], job_variables: frozenset[str]) -> str | None:
    """The token for ``kill [signal] <own job>...``, else ``None``."""

    if not words or words[0] != "kill":
        return None
    rest = words[1:]
    signal = STOP_OWN_JOB_TERM
    if rest and rest[0] == "-s":
        if len(rest) < 2 or rest[1] not in _SIGNAL_NAMES:
            return None
        signal = _SIGNAL_NAMES[rest[1]]
        rest = rest[2:]
    elif rest and rest[0].startswith("-"):
        if rest[0] not in _SIGNAL_OPTIONS:
            return None
        signal = _SIGNAL_OPTIONS[rest[0]]
        rest = rest[1:]
    if not rest or not all(_own_job_operand(word, job_variables) for word in rest):
        return None
    return signal


def own_job_stop_signal(normalized: object) -> str | None:
    """The closed token naming how this command stops its own background job, else ``None``."""

    # ``domain.command_segments`` imports ``domain.observation``, which reads this module's
    # closed token set; import the splitter here so the envelope validator stays importable.
    from finishup.domain.command_segments import (
        segment_words_without_redirections,
        top_level_segments,
    )

    if type(normalized) is not str:
        return None
    split = top_level_segments(normalized)
    if split is None:
        return None
    segments, separators = split
    if "&" not in separators or len(segments) < 3:
        return None
    words: list[list[str]] = []
    for segment in segments:
        parsed = segment_words_without_redirections(segment)
        if parsed is None:
            return None
        words.append(parsed)
    last = words[-1]
    job_variables: set[str] = set()
    signal: str | None = None
    for index, current in enumerate(words[:-1]):
        if len(current) == 1 and (assigned := _JOB_ASSIGNMENT_RE.fullmatch(current[0])):
            job_variables.add(assigned.group(1))
            continue
        if index > 0:
            found = _kill_signal(current, frozenset(job_variables))
            if found is not None:
                signal = found
    if signal is None or not last or last[0] != "wait":
        return None
    if not all(_own_job_operand(word, frozenset(job_variables)) for word in last[1:]):
        return None
    return signal


def stopped_own_job(token: object, exit_status: object) -> bool:
    """Whether a recorded exit is exactly the status the command's own job stop produces."""

    expected = _EXPECTED_EXIT.get(token) if type(token) is str else None
    return expected is not None and type(exit_status) is int and exit_status == expected


_MARKER_DOMAIN: Final = b"yoetz/process-control/v1/"
_COMMITMENT_RE: Final = re.compile(r"\Ahmac-sha256:[0-9a-f]{64}\Z", re.ASCII)


def process_control_commitment(token: str, command_commitment: str) -> str:
    """The marker that the command committed as ``command_commitment`` has stop shape ``token``.

    A keyed derivative in the ``hmac-sha256:`` form, never a commitment to text: SHA-256 over a
    fixed domain, the closed token and the installation-keyed whole-command commitment. Only the
    key's holder can produce it for a command; any reader holding the commitment can recognize
    it, and it can never equal a command, segment or canonical commitment.
    """

    digest = hashlib.sha256(
        _MARKER_DOMAIN + token.encode("ascii") + b"\x00" + command_commitment.encode("ascii")
    )
    return "hmac-sha256:" + digest.hexdigest()


def process_control_from_commitments(command_commitment: object, commitments: object) -> str | None:
    """The stop shape a command's commitment list carries for its whole commitment, else ``None``.

    Exactly one marker must match; anything malformed, or a list naming two shapes, reads as none,
    so a damaged list never grants the exemption.
    """

    if type(command_commitment) is not str or _COMMITMENT_RE.fullmatch(command_commitment) is None:
        return None
    if not isinstance(commitments, (list, tuple, frozenset, set)):
        return None
    present = {item for item in cast(Iterable[object], commitments) if type(item) is str}
    found = [
        token
        for token in sorted(PROCESS_CONTROLS)
        if process_control_commitment(token, command_commitment) in present
    ]
    return found[0] if len(found) == 1 else None
