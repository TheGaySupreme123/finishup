"""The Stop-time closure gate (issue #977, ADR-033).

When an agent stops while the mapped task's closure readiness still names work the agent can do,
the Stop hook continues it once with a message that names what remains. The decision reads only
the service's own ``status`` answer (``closure_readiness``), never the transcript or a file:

* it continues only for ``STOP_GATE_TOKENS`` in ``agent_actionable``: open obligations, an
  unacknowledged receipt-blocking finding, and the task facts the agent can repair (a planned
  verification not observed, failing or stale; a requested output Git would not deliver);
* once per ledger frontier and session: a second Stop at the same frontier passes, so an agent
  that cannot or will not act is never trapped; the host's own loop guard (``stop_hook_active``,
  Cursor ``loop_count``) is honoured before any service read;
* an obligation a recorded blocker decision names (authority, consent, credentials, an
  unobtainable dependency) is a standing disclosure in readiness. Yoetz cannot verify the claim,
  so the first Stop that finds a blocker the agent has not been asked about continues the agent
  once with a re-check that names the obligation and the claimed kind (``blocked_obligations`` in
  readiness). The re-check is remembered per session and ``(obligation, kind)``: stopping again,
  or recording the same blocker again, is the re-confirmation, and the blocker is then honoured
  without asking again. Nothing judges the claim here; the closing review does (#976);
* while hook observations are still draining, the facts that depend on observed runs are not
  used to continue the agent.

The delivered text holds only closed tokens, counts and service-minted ids. The once-per-frontier
and once-per-blocker memory is two small owner-only files in the observation state directory
holding opaque session, frontier and obligation ids and closed blocker kinds.
"""

from __future__ import annotations

import contextlib
import json
import os
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from yoetz import __version__
from yoetz.config.paths import ensure_owner_only_dir, state_dir
from yoetz.kernel.task_facts import (
    DECLARED_OUTPUT_REMOVED_GAP,
    PLANNED_VERIFICATION_FAILED_GAP,
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
    PLANNED_VERIFICATION_STALE_GAP,
    REQUESTED_OUTPUT_GIT_IGNORED_GAP,
    STOP_GATE_TOKENS,
)
from yoetz.ports.control import ControlClientKind
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import OperationFailureModel, StatusRequest

try:
    import fcntl
except ImportError:  # pragma: no cover - supported hook hosts are POSIX
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "ClosureGate",
    "ClosureGateUnavailable",
    "BLOCKER_RECHECK_ITEM",
    "closure_gate_already_delivered",
    "closure_gate_from_readiness",
    "closure_gate_reasked_blockers",
    "read_closure_gate",
    "record_closure_gate_delivered",
]

_FILE_NAME: Final = "closure-gate.json"
_BLOCKER_FILE_NAME: Final = "closure-gate-blockers.json"
_LOCK_NAME: Final = "closure-gate.lock"
_MAX_SESSIONS: Final = 128
_MAX_BLOCKER_KEYS: Final = 64
_BLOCKER_KINDS: Final = frozenset({"authority", "consent", "credential", "dependency_unavailable"})
# The closed item a blocker re-check adds to ``ClosureGate.items`` (#977).
BLOCKER_RECHECK_ITEM: Final = "blocker_recheck"
_STATUS_DEADLINE_MS: Final = 4_000
_OBSERVATION_DEPENDENT: Final = frozenset(
    {
        PLANNED_VERIFICATION_FAILED_GAP,
        PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
        PLANNED_VERIFICATION_STALE_GAP,
    }
)
_ITEM_TEXT: Final[Mapping[str, str]] = {
    "obligations_open": "{open} open obligation(s)",
    "receipt_findings_unresolved": "{blocking} receipt-blocking finding(s) not repaired",
    "closing_review_required": (
        "the closing review has not run since your last change: run `check` with"
        " `final_review: true` (a recorded blocker does not waive it)"
    ),
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP: (
        "a planned verification command (an obligation's requested command item) was never seen"
        " run exactly as recorded"
    ),
    PLANNED_VERIFICATION_FAILED_GAP: "a planned verification command failed on its latest run",
    PLANNED_VERIFICATION_STALE_GAP: (
        "a planned verification command last ran before your latest edit"
    ),
    REQUESTED_OUTPUT_GIT_IGNORED_GAP: (
        "a requested output file is git-ignored or excluded, so a diff-based delivery omits it"
    ),
    DECLARED_OUTPUT_REMOVED_GAP: (
        "a declared delivered file was deleted or renamed away; restore the delivered file, or"
        " correct the requested item if the task asked for the deletion: Yoetz review limits"
        " never justify moving, splitting or deleting deliverables"
    ),
}


class ClosureGateUnavailable(Exception):
    """The status read the gate needs did not answer; the agent is allowed to stop."""


@dataclass(frozen=True, slots=True)
class ClosureGate:
    """One Stop continuation: its once-per-frontier identity, its text and the closed items."""

    identity: str
    text: str
    items: tuple[str, ...]
    # ``<obligation id>:<kind>`` keys this gate re-asks; remembered once delivered.
    blocker_keys: tuple[str, ...] = ()


def _blocker_rows(readiness: object) -> tuple[tuple[str, str], ...]:
    """``(obligation id, kind)`` pairs from readiness ``blocked_obligations``; malformed rows drop."""

    raw = getattr(readiness, "blocked_obligations", None)
    if not isinstance(raw, (tuple, list)):
        return ()
    rows: dict[str, str] = {}
    for item in tuple(cast(tuple[object, ...], raw)):
        obligation = getattr(item, "obligation_id", None)
        kind = getattr(item, "blocker_kind", None)
        if (
            type(obligation) is str
            and obligation.startswith("obl_")
            and len(obligation) <= 64
            and type(kind) is str
            and kind in _BLOCKER_KINDS
        ):
            rows.setdefault(obligation, kind)
    return tuple(sorted(rows.items(), key=lambda row: row[0].encode()))


def _blocker_text(rows: tuple[tuple[str, str], ...]) -> str:
    named = ", ".join(f"{obligation} ({kind})" for obligation, kind in rows)
    return (
        f"Blocker re-check (asked once): you recorded {named} as blocked outside your control."
        " Confirm each is genuinely outside your control: authority or consent you do not have,"
        " a credential you lack, or a dependency you cannot obtain. Missing or inconsistent data"
        " the task says is recoverable, a failing test, or a result that looks infeasible is not"
        " a blocker: continue the work on that obligation instead. If a blocker is genuine, stop"
        " again; Yoetz will not ask again and the receipt discloses it as a standing limitation."
    )


def closure_gate_from_readiness(
    readiness: object,
    *,
    frontier_sequence: str,
    frontier_digest: str,
    observation_pending: bool,
    reasked_blockers: frozenset[str] = frozenset(),
) -> ClosureGate | None:
    """Decide the gate from one ``closure_readiness`` object; ``None`` means let the agent stop.

    ``reasked_blockers`` holds the ``<obligation id>:<kind>`` keys this session was already
    re-asked about; any other blocked obligation in readiness is re-asked once.
    """

    state = getattr(readiness, "state", None)
    if state not in {"action_required", "ready_with_limitations"}:
        return None
    rows = tuple(
        (obligation, kind)
        for obligation, kind in _blocker_rows(readiness)
        if f"{obligation}:{kind}" not in reasked_blockers
    )
    items: tuple[str, ...] = ()
    if state == "action_required":
        actionable = getattr(readiness, "agent_actionable", None)
        if not isinstance(actionable, (tuple, list)):
            return None
        present = {
            item for item in tuple(cast(tuple[object, ...], actionable)) if type(item) is str
        }
        items = tuple(
            token
            for token in STOP_GATE_TOKENS
            if token in present and not (observation_pending and token in _OBSERVATION_DEPENDENT)
        )
    identity = f"{frontier_sequence}:{frontier_digest}"
    keys = tuple(f"{obligation}:{kind}" for obligation, kind in rows)
    if not items:
        if not rows:
            return None
        text = f"Yoetz closure gate (shown once for these blockers): {_blocker_text(rows)}"
        return ClosureGate(identity, text, (BLOCKER_RECHECK_ITEM,), keys)
    open_count = str(getattr(readiness, "open_obligation_count", "?"))
    blocking_count = str(getattr(readiness, "receipt_blocking_finding_count", "?"))
    remaining = "; ".join(
        _ITEM_TEXT[token].format(open=open_count, blocking=blocking_count) for token in items
    )
    text = (
        f"Yoetz closure gate (shown once for ledger frontier {frontier_sequence}): closure still"
        f" requires action before you stop. Remaining: {remaining}. Finish the work: run each"
        " planned verification after your last edit (or correct the requested command to the one"
        " you run), write every requested output at its requested path (status"
        " view=obligations names them; an inconsistent input is not a reason to omit one, write a"
        " best-effort artifact and disclose the assumption), repair the receipt-blocking"
        " findings, then check and request the receipt. Stop without that only for a blocker"
        " outside your control (authority, consent, credentials, a dependency you cannot obtain):"
        " publish decision_recorded with affected_obligation_ids and the statement line"
        " yoetz-blocker:<authority|consent|credential|dependency_unavailable>, then say so in"
        " your final answer. Data the task says is recoverable is not such a blocker."
    )
    if rows:
        text += " " + _blocker_text(rows)
    if observation_pending:
        text += " (Hook observations were still draining; observed-run facts were not used.)"
    return ClosureGate(identity, text, items + ((BLOCKER_RECHECK_ITEM,) if rows else ()), keys)


def _status_request(session_id: str, writer_id: str, actor_id: str) -> StatusRequest:
    return StatusRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": new_id(IdKind.REQUEST),
            "actor": {"actor_id": actor_id, "actor_type": "harness"},
            "client": {"kind": "yoetz_cli", "version": __version__, "integration": "local_cli"},
            "session_id": session_id,
            "writer_id": writer_id,
            "view": "compact",
            "limit": "1",
            "at_frontier": None,
            "cursor": None,
        }
    )


async def read_closure_gate(
    *,
    session_id: str,
    writer_id: str,
    connect: Callable[[ControlClientKind], Awaitable[object]],
    actor_id: str,
    observation_pending: bool,
    reasked_blockers: frozenset[str] = frozenset(),
) -> ClosureGate | None:
    """Read the mapped session's compact status and decide the gate.

    ``None`` means the status was read and closure needs no continuation. A status the service
    could not answer raises ``ClosureGateUnavailable`` so the caller records it as unavailable;
    either way the agent may stop.
    """

    client: object | None = None
    try:
        client = await connect(ControlClientKind.CLI)
        status = getattr(client, "status", None)
        if not callable(status):
            raise ClosureGateUnavailable("status_unavailable")
        result = await cast(Callable[..., Awaitable[object]], status)(
            _status_request(session_id, writer_id, actor_id), deadline_ms=_STATUS_DEADLINE_MS
        )
        branch = getattr(result, "root", result)
        if isinstance(branch, OperationFailureModel):
            raise ClosureGateUnavailable("status_failed")
        head = getattr(branch, "head_frontier", None)
        sequence = getattr(head, "sequence", None)
        digest = getattr(head, "head_digest", None)
        if type(sequence) is not str or type(digest) is not str:
            raise ClosureGateUnavailable("status_unreadable")
        return closure_gate_from_readiness(
            getattr(branch, "closure_readiness", None),
            frontier_sequence=sequence,
            frontier_digest=digest,
            observation_pending=observation_pending,
            reasked_blockers=reasked_blockers,
        )
    except ClosureGateUnavailable:
        raise
    except Exception as exc:
        raise ClosureGateUnavailable("status_unavailable") from exc
    finally:
        close = getattr(client, "close", None)
        if callable(close):
            with contextlib.suppress(Exception):
                await cast(Callable[[], Awaitable[object]], close)()


def _paths(_state: Path | None, name: str = _FILE_NAME) -> tuple[Path, Path, Path]:
    directory = (state_dir() if _state is None else _state) / "observation"
    return directory, directory / name, directory / _LOCK_NAME


def _load(path: Path) -> dict[str, str]:
    try:
        if path.is_symlink():
            return {}
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError, ValueError:
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        key: value
        for key, value in cast(dict[object, object], raw).items()
        if type(key) is str and type(value) is str
    }


def closure_gate_already_delivered(
    session_id: str, identity: str, *, _state: Path | None = None
) -> bool:
    _directory, path, _lock = _paths(_state)
    return _load(path).get(session_id) == identity


def closure_gate_reasked_blockers(session_id: str, *, _state: Path | None = None) -> frozenset[str]:
    """The ``<obligation id>:<kind>`` blockers this session was already re-asked about."""

    _directory, path, _lock = _paths(_state, _BLOCKER_FILE_NAME)
    value = _load(path).get(session_id, "")
    return frozenset(key for key in value.split(" ") if key)


def _store(directory: Path, path: Path, name: str, entries: dict[str, str]) -> None:
    while len(entries) > _MAX_SESSIONS:
        entries.pop(next(iter(entries)))
    temporary = directory / f".{name}.{os.getpid()}.tmp"
    temporary.write_text(json.dumps(entries, sort_keys=False), encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def record_closure_gate_delivered(
    session_id: str,
    identity: str,
    *,
    blocker_keys: tuple[str, ...] = (),
    _state: Path | None = None,
) -> bool:
    """Remember that this session's gate fired at this frontier and which blockers it re-asked.

    Never raises.
    """

    try:
        directory, path, lock_path = _paths(_state)
        _directory, blocker_path, _lock = _paths(_state, _BLOCKER_FILE_NAME)
        ensure_owner_only_dir(directory)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(lock_path, flags, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            if blocker_keys:
                blockers = _load(blocker_path)
                known = [key for key in blockers.pop(session_id, "").split(" ") if key]
                merged = list(dict.fromkeys((*known, *blocker_keys)))[-_MAX_BLOCKER_KEYS:]
                blockers[session_id] = " ".join(merged)
                _store(directory, blocker_path, _BLOCKER_FILE_NAME, blockers)
            entries = _load(path)
            entries.pop(session_id, None)
            entries[session_id] = identity
            _store(directory, path, _FILE_NAME, entries)
        finally:
            os.close(descriptor)
        return True
    except Exception:
        return False
