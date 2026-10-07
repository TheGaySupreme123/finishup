"""The Stop-time closure gate (issue #977, ADR-033).

When an agent stops while the mapped task's closure readiness still names work the agent can do,
the Stop hook continues it once with a message that names what remains. The decision reads only
the service's own ``status`` answer (``closure_readiness``), never the transcript or a file:

* it continues only for ``STOP_GATE_TOKENS`` in ``agent_actionable``: open obligations, an
  unacknowledged receipt-blocking finding, and the task facts the agent can repair (a planned
  verification not observed, failing or stale; a requested output Git would not deliver);
* once per ledger frontier and session: a second Stop at the same frontier passes, so an agent
  that cannot or will not act is never trapped;
* an obligation a recorded blocker decision names (authority, consent, credentials, an
  unobtainable dependency) is a standing disclosure in readiness. Yoetz cannot verify the claim,
  so a Stop that finds a blocker the agent has not been asked about continues the agent once
  with a re-check that names the obligation and the claimed kind (``blocked_obligations`` in
  readiness). The re-check is remembered per session and ``(obligation, kind)``; the agent
  confirms a genuine blocker by publishing the same line again, and it is then never re-asked.
  This re-check also runs on a Stop the host already continued this turn (``stop_hook_active``,
  Cursor ``loop_count > 0``), because a blocker is usually published after the first gate
  (#985). On such an active Stop only a new blocker key may continue the agent, at most once per
  Stop and at most ``MAX_GATE_BLOCKS_PER_TURN`` gate continuations per host turn; anything
  else, including any error or a short time budget, lets the agent stop;
* the text pushes repair or self-verification first; ``acknowledged_not_done`` is the last
  resort, a Yoetz limit is never a ``yoetz-blocker``, and the blocker exit is offered only when
  open obligations remain (#984);
* a finding the agent acknowledged as not done that the review says the task itself requires
  (readiness ``finding_premise_disputed``, D7a) is asked about once per session and acknowledged
  count, on a Stop the host has not already continued (closed item ``premise_recheck``);
* while this task's hook observations are still draining, the facts that depend on observed
  runs are not used to continue the agent, and the text says so only when that changed the
  decision.

The delivered text holds only closed tokens, counts and service-minted ids. The memory is three
small owner-only files in the observation state directory holding opaque session, frontier and
obligation ids, closed blocker kinds and a per-session turn counter.
"""

from __future__ import annotations

import contextlib
import json
import os
from collections.abc import Awaitable, Callable, Generator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from yoetz import __version__
from yoetz.config.paths import ensure_owner_only_dir, state_dir
from yoetz.kernel.task_facts import (
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
    "BLOCKER_UNCONFIRMED_TOKEN",
    "PREMISE_RECHECK_ITEM",
    "MAX_GATE_BLOCKS_PER_TURN",
    "closure_gate_already_delivered",
    "closure_gate_from_readiness",
    "closure_gate_reasked_blockers",
    "closure_gate_turn_blocks",
    "read_closure_gate",
    "record_closure_gate_delivered",
    "reset_closure_gate_turn",
    "set_standing_advice_withheld",
    "standing_advice_withheld",
]

_FILE_NAME: Final = "closure-gate.json"
_BLOCKER_FILE_NAME: Final = "closure-gate-blockers.json"
_TURN_FILE_NAME: Final = "closure-gate-turns.json"
_STANDING_FILE_NAME: Final = "stop-withheld-standing-advice.json"
_LOCK_NAME: Final = "closure-gate.lock"
_MAX_SESSIONS: Final = 128
_MAX_BLOCKER_KEYS: Final = 64
_BLOCKER_KINDS: Final = frozenset({"authority", "consent", "credential", "dependency_unavailable"})
# The closed item a blocker re-check adds to ``ClosureGate.items`` (#977).
BLOCKER_RECHECK_ITEM: Final = "blocker_recheck"
# D7a (#984): the closed item a one-time premise-dispute ask adds, and the readiness code it reads.
PREMISE_RECHECK_ITEM: Final = "premise_recheck"
_PREMISE_DISPUTED_CODE: Final = "finding_premise_disputed"
_PREMISE_TEXT: Final = (
    "You marked finding(s) as not done that the reviewer says the task itself requires. Do that"
    " work unless it is genuinely impossible; a Yoetz limit or a hard result is not a reason."
)
_STATUS_DEADLINE_MS: Final = 4_000
# Hard caps (#985): a host turn gets at most this many gate continuations (the first Stop's gate
# plus one active-Stop blocker re-check), and an active Stop at most one.
MAX_GATE_BLOCKS_PER_TURN: Final = 2
_OBSERVATION_DEPENDENT: Final = frozenset(
    {
        PLANNED_VERIFICATION_FAILED_GAP,
        PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
        PLANNED_VERIFICATION_STALE_GAP,
    }
)
# The C4 readiness token for a recorded blocker the agent has not yet confirmed after being
# challenged (#985). The kernel owns ``STOP_GATE_TOKENS``; the gate also recognises this literal so
# it works whichever lands first, and lists it right after open obligations.
BLOCKER_UNCONFIRMED_TOKEN: Final = "obligation_blocker_unconfirmed"
_GATE_TOKENS: Final = (
    STOP_GATE_TOKENS
    if BLOCKER_UNCONFIRMED_TOKEN in STOP_GATE_TOKENS
    else (STOP_GATE_TOKENS[0], BLOCKER_UNCONFIRMED_TOKEN, *STOP_GATE_TOKENS[1:])
)
_BLOCKER_LINE: Final = "yoetz-blocker:<authority|consent|credential|dependency_unavailable>"
# Issue #995: what is not a blocker, and the line that discloses it instead.
_DISCLOSE_TEXT: Final = (
    "An inherent verification limit (a hidden verifier, a private trace) or a best-effort choice"
    " is not a blocker: finish the work and disclose it with a decision line"
    " `yoetz-assumption:<obligation id>` or `yoetz-verification-limit:<obligation id>`."
    " If you truly will not do an open obligation, after repair, republish it with status"
    " `acknowledged_not_done` and an `acknowledged_not_done_reason`: the honest last resort, never a blocker."
)
_ITEM_TEXT: Final[Mapping[str, str]] = {
    "obligations_open": "{open} open obligation(s)",
    BLOCKER_UNCONFIRMED_TOKEN: "a recorded blocker you have not confirmed",
    "receipt_findings_unresolved": "{blocking} receipt-blocking finding(s) not repaired",
    "closing_review_required": (
        "the closing review has not run since your last change: run `check` with"
        " `final_review: true` (a recorded blocker does not waive it)"
    ),
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP: "a planned verification never seen run as recorded",
    PLANNED_VERIFICATION_FAILED_GAP: "a planned verification failed on its latest run",
    PLANNED_VERIFICATION_STALE_GAP: "a planned verification last ran before your latest edit",
    REQUESTED_OUTPUT_GIT_IGNORED_GAP: "a requested output is git-ignored, so a diff omits it",
}
# Repair-first guidance, one sentence per present item family (F1, #984). Acknowledgement is the
# last resort and a Yoetz limit is never a ``yoetz-blocker``.
_OBLIGATION_TEXT: Final = (
    "Finish each open obligation: write every requested output at its path (status"
    " view=obligations names them); for an inconsistent input write a best-effort artifact and"
    " disclose the assumption (`yoetz-assumption:<obligation id>`)."
)
_VERIFICATION_TEXT: Final = (
    "Run each planned verification after your last edit, or correct the requested command."
)
_FINDING_TEXT: Final = (
    "For each receipt-blocking finding, repair what you can. If you repaired one and Yoetz still"
    " cannot prove it (its resolution names a Yoetz limit such as redaction, observation loss or a review-packet limit), verify it yourself, record that evidence, and"
    " respond `self_verified` with how you verified it and the evidence ids. Do not reshape your"
    " work for Yoetz. Respond `acknowledged_not_done` only if you truly cannot or will not do it."
)
_CLOSE_TEXT: Final = (
    "Then run `check` and request the receipt. A Yoetz limit is never a `yoetz-blocker`."
)
_BLOCKER_OFFER_TEXT: Final = (
    "Leave an open obligation undone only for a blocker outside your control (authority,"
    " consent, credentials, a dependency you cannot obtain): publish decision_recorded with"
    f" affected_obligation_ids and the line {_BLOCKER_LINE}, and Yoetz will ask you about it once."
    f" Data the task says is recoverable is not such a blocker. {_DISCLOSE_TEXT}"
)
# How to confirm a blocker appears only AFTER the challenge (the re-check, or a later gate whose
# blocker was already re-asked), so publishing a blocker twice up front never skips it (#985).
_CONFIRM_TEXT: Final = (
    "If it is genuine, confirm it by publishing the same yoetz-blocker line again in a later"
    " decision, then stop."
)
_UNCONFIRMED_AFTER_RECHECK_TEXT: Final = (
    "You were already asked about your recorded blocker: continue that work unless it is"
    f" genuinely outside your control. {_CONFIRM_TEXT}"
)
_OBLIGATION_SHORT_TEXT: Final = (
    "Finish each open obligation (status view=obligations names the requested outputs)."
)
# Every host clips the Stop text at 2,000 characters; the gate stays under that whole.
_MAX_TEXT_CHARS: Final = 2_000
_DRAIN_TEXT: Final = "(Observations were still draining; planned-verification facts unused.)"
# A re-check names at most this many blocked obligations; the rest are counted.
_MAX_NAMED_BLOCKERS: Final = 3
# F3: the gate names at most this many result ids a completion claim must disclose.
_MAX_NAMED_LIMITATIONS: Final = 5


def _limitation_text(readiness: object) -> str:
    """Name the ids a whole-task completion claim must list in ``limitation_refs`` (F3)."""

    raw = getattr(readiness, "limitation_refs_required", None)
    count = getattr(readiness, "limitation_refs_required_count", None)
    if not isinstance(raw, (tuple, list)) or type(count) is not str or not count.isdigit():
        return ""
    ids = [
        value
        for value in tuple(cast(tuple[object, ...], raw))
        if type(value) is str and value.startswith("res_") and len(value) <= 64
    ]
    if not ids:
        return ""
    named = ", ".join(ids[:_MAX_NAMED_LIMITATIONS])
    more = int(count) - min(len(ids), _MAX_NAMED_LIMITATIONS)
    if more > 0:
        named += f" and {more} more (status lists them)"
    return (
        f"Status lists the results a whole-task completion claim must name in limitation_refs:"
        f" {named}. A scoped claim names only those whose action names a claimed obligation (or"
        " none). Add any failed, partial or unknown result you publish in the same batch as the"
        " claim too."
    )


def _premise_key(readiness: object) -> str | None:
    """``premise:<acknowledged count>`` when readiness discloses a premise dispute (D7a, #984).

    Readiness carries the closed standing code, not the disputed ids; the acknowledged count
    stands in, so a later acknowledgement asks again while an unchanged one never does.
    """

    standing = getattr(readiness, "standing_limitations", None)
    if not isinstance(standing, (tuple, list)) or _PREMISE_DISPUTED_CODE not in tuple(
        cast(tuple[object, ...], standing)
    ):
        return None
    count = getattr(readiness, "acknowledged_not_done_count", None)
    if type(count) is not str or not count.isdigit() or len(count) > 8:
        return "premise:?"
    return f"premise:{count}"


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
    """``(obligation id, kind)`` pairs from readiness ``blocked_obligations``; malformed rows drop.

    A row readiness marks ``confirmation: confirmed`` (the agent re-published the same blocker in
    a later decision, #985) is a standing claim and is not re-asked; a claimed row, or one from a
    build without that field, is.
    """

    raw = getattr(readiness, "blocked_obligations", None)
    if not isinstance(raw, (tuple, list)):
        return ()
    rows: dict[str, str] = {}
    for item in tuple(cast(tuple[object, ...], raw)):
        obligation = getattr(item, "obligation_id", None)
        kind = getattr(item, "blocker_kind", None)
        if getattr(item, "confirmation", None) == "confirmed":
            continue
        if (
            type(obligation) is str
            and obligation.startswith("obl_")
            and len(obligation) <= 64
            and type(kind) is str
            and kind in _BLOCKER_KINDS
        ):
            rows.setdefault(obligation, kind)
    return tuple(sorted(rows.items(), key=lambda row: row[0].encode()))


def _blocker_text(rows: tuple[tuple[str, str], ...], *, short: bool = False) -> str:
    named = ", ".join(f"{obligation} ({kind})" for obligation, kind in rows[:_MAX_NAMED_BLOCKERS])
    if len(rows) > _MAX_NAMED_BLOCKERS:
        named += f" and {len(rows) - _MAX_NAMED_BLOCKERS} more"
    if short:
        # The blocker offer already defines a blocker; the re-check and confirmation remain.
        return (
            f"Blocker re-check (asked once): you recorded {named} as blocked. Continue that work"
            " unless it is genuinely outside your control; a Yoetz limit never is: finish the"
            f" obligation and disclose any limit in your final answer. {_CONFIRM_TEXT}"
        )
    return (
        f"Blocker re-check (asked once): you recorded {named} as blocked outside your control."
        " Repair first: missing or inconsistent data the task says is recoverable, a failing"
        " test or a result that looks infeasible is not a blocker, so continue the work on that"
        " obligation. A Yoetz limit is never a blocker either: finish the obligation and disclose"
        f" any limit in your final answer. {_DISCLOSE_TEXT} A blocker is only authority or consent"
        " you do not have,"
        f" a credential you lack, or a dependency you cannot obtain. {_CONFIRM_TEXT} Yoetz will"
        " not ask again and the receipt discloses it as a standing limitation."
    )


def closure_gate_from_readiness(
    readiness: object,
    *,
    frontier_sequence: str,
    frontier_digest: str,
    observation_pending: bool,
    reasked_blockers: frozenset[str] = frozenset(),
    active_stop: bool = False,
) -> ClosureGate | None:
    """Decide the gate from one ``closure_readiness`` object; ``None`` means let the agent stop.

    ``reasked_blockers`` holds the ``<obligation id>:<kind>`` keys this session was already
    re-asked about; any other blocked obligation in readiness is re-asked once.
    ``active_stop`` is a Stop the host already continued this turn (``stop_hook_active``,
    Cursor ``loop_count > 0``): only a blocker key not yet re-asked may continue it, never the
    ordinary items (#985).
    """

    state = getattr(readiness, "state", None)
    if state not in {"action_required", "ready_with_limitations"}:
        return None
    rows = tuple(
        (obligation, kind)
        for obligation, kind in _blocker_rows(readiness)
        if f"{obligation}:{kind}" not in reasked_blockers
    )
    identity = f"{frontier_sequence}:{frontier_digest}"
    keys = tuple(f"{obligation}:{kind}" for obligation, kind in rows)
    # D7a (#984): a premise dispute is asked once per session and acknowledged-item count, and
    # only on a Stop the host has not already continued this turn.
    premise_key = _premise_key(readiness)
    premise = not active_stop and premise_key is not None and premise_key not in reasked_blockers
    items: tuple[str, ...] = ()
    drain_changed_decision = False
    if state == "action_required" and not active_stop:
        actionable = getattr(readiness, "agent_actionable", None)
        if not isinstance(actionable, (tuple, list)):
            return None
        present = {
            item for item in tuple(cast(tuple[object, ...], actionable)) if type(item) is str
        }
        items = tuple(
            token
            for token in _GATE_TOKENS
            if token in present and not (observation_pending and token in _OBSERVATION_DEPENDENT)
        )
        drain_changed_decision = observation_pending and bool(present & _OBSERVATION_DEPENDENT)
    premise_items = (PREMISE_RECHECK_ITEM,) if premise else ()
    premise_keys = (cast(str, premise_key),) if premise else ()
    if not items:
        if not rows and not premise:
            return None
        parts = [
            "Yoetz closure gate (shown once for these blockers):"
            if rows
            else "Yoetz closure gate (shown once):"
        ]
        if premise:
            parts.append(_PREMISE_TEXT)
        if rows:
            parts.append(_blocker_text(rows))
        return ClosureGate(
            identity,
            " ".join(parts)[:_MAX_TEXT_CHARS],
            premise_items + ((BLOCKER_RECHECK_ITEM,) if rows else ()),
            keys + premise_keys,
        )
    open_count = str(getattr(readiness, "open_obligation_count", "?"))
    blocking_count = str(getattr(readiness, "receipt_blocking_finding_count", "?"))
    remaining = "; ".join(
        _ITEM_TEXT[token].format(open=open_count, blocking=blocking_count) for token in items
    )
    offers_blocker = "obligations_open" in items or BLOCKER_UNCONFIRMED_TOKEN in items
    head = (
        f"Yoetz closure gate (shown once for ledger frontier {frontier_sequence}): closure still"
        f" requires action before you stop. Remaining: {remaining}."
    )
    recheck = _blocker_text(rows, short=offers_blocker) if rows else ""
    limitations = _limitation_text(readiness)

    def compose(
        *,
        drain: bool,
        short_obligation: bool,
        verification: bool,
        limits: bool = True,
        premise_text: bool = True,
    ) -> str:
        parts = [head]
        if premise and premise_text:
            parts.append(_PREMISE_TEXT)
        if "obligations_open" in items:
            parts.append(_OBLIGATION_SHORT_TEXT if short_obligation else _OBLIGATION_TEXT)
        if verification and any(token in _OBSERVATION_DEPENDENT for token in items):
            parts.append(_VERIFICATION_TEXT)
        if "receipt_findings_unresolved" in items:
            parts.append(_FINDING_TEXT)
        if limits and limitations:
            parts.append(limitations)
        parts.append(_CLOSE_TEXT)
        # The blocker exit is offered only for open obligations: findings, reviews and Yoetz
        # limits are never excused by a blocker (F1, #984).
        if offers_blocker:
            parts.append(_BLOCKER_OFFER_TEXT)
        if BLOCKER_UNCONFIRMED_TOKEN in items and not rows:
            parts.append(_UNCONFIRMED_AFTER_RECHECK_TEXT)
        if recheck:
            parts.append(recheck)
        if drain and drain_changed_decision:
            parts.append(_DRAIN_TEXT)
        return " ".join(parts)

    # Every host clips at 2,000 characters. Drop whole optional sentences, never the re-check:
    # the drain note first, then the long obligation sentence, then the verification hint, then
    # the required limitation ids (F3).
    text = ""
    for drain, short_obligation, verification, limits, premise_text in (
        (True, False, True, True, True),
        (False, False, True, True, True),
        (False, True, True, True, True),
        (False, True, False, True, True),
        (False, True, False, False, True),
        # D7a: the premise ask goes before the re-check does.
        (False, True, False, False, False),
    ):
        text = compose(
            drain=drain,
            short_obligation=short_obligation,
            verification=verification,
            limits=limits,
            premise_text=premise_text,
        )
        if len(text) <= _MAX_TEXT_CHARS:
            asked_premise = premise and premise_text
            break
    else:
        text = " ".join(part for part in (head, recheck) if part)[:_MAX_TEXT_CHARS]
        asked_premise = False
    return ClosureGate(
        identity,
        text,
        items
        + ((BLOCKER_RECHECK_ITEM,) if rows else ())
        + ((PREMISE_RECHECK_ITEM,) if asked_premise else ()),
        keys + (premise_keys if asked_premise else ()),
    )


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
    active_stop: bool = False,
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
            active_stop=active_stop,
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
    return _load_checked(path) or {}


def _load_checked(path: Path) -> dict[str, str] | None:
    """The file's string entries; ``{}`` when absent, ``None`` when unreadable or corrupt."""

    try:
        if path.is_symlink():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except OSError, ValueError:
        return None
    if not isinstance(raw, dict):
        return None
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


@contextlib.contextmanager
def _locked(_state: Path | None) -> Generator[Path]:
    directory, _path, lock_path = _paths(_state)
    ensure_owner_only_dir(directory)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield directory
    finally:
        os.close(descriptor)


def closure_gate_turn_blocks(session_id: str, *, _state: Path | None = None) -> int:
    """How many gate continuations this session's current host turn already received (#985)."""

    _directory, path, _lock = _paths(_state, _TURN_FILE_NAME)
    entries = _load_checked(path)
    if entries is None:
        # An unreadable count must never reopen the active-Stop path: it counts as the cap.
        return MAX_GATE_BLOCKS_PER_TURN
    value = entries.get(session_id, "0")
    return int(value) if value.isdecimal() and len(value) <= 3 else MAX_GATE_BLOCKS_PER_TURN


def reset_closure_gate_turn(session_id: str, *, _state: Path | None = None) -> None:
    """Forget the turn counter at a Stop the host did not continue (a new turn). Never raises."""

    with contextlib.suppress(Exception):
        _directory, path, _lock = _paths(_state, _TURN_FILE_NAME)
        current = _load_checked(path)
        if current is not None and session_id not in current:
            return
        with _locked(_state) as directory:
            entries = _load_checked(path)
            if entries is None:
                # A corrupt count is replaced, so it caps one turn at most, not every later one.
                _store(directory, path, _TURN_FILE_NAME, {})
            elif entries.pop(session_id, None) is not None:
                _store(directory, path, _TURN_FILE_NAME, entries)


def record_closure_gate_delivered(
    session_id: str,
    identity: str,
    *,
    blocker_keys: tuple[str, ...] = (),
    active_stop: bool = False,
    _state: Path | None = None,
) -> bool:
    """Remember that this session's gate fired at this frontier and which blockers it re-asked.

    Also counts the continuation toward this host turn's cap: a Stop the host had not continued
    starts the turn at one, an active Stop adds one. Never raises.
    """

    try:
        _directory, path, _lock = _paths(_state)
        _directory, blocker_path, _lock = _paths(_state, _BLOCKER_FILE_NAME)
        _directory, turn_path, _lock = _paths(_state, _TURN_FILE_NAME)
        with _locked(_state) as directory:
            if blocker_keys:
                blockers = _load(blocker_path)
                known = [key for key in blockers.pop(session_id, "").split(" ") if key]
                merged = list(dict.fromkeys((*known, *blocker_keys)))[-_MAX_BLOCKER_KEYS:]
                blockers[session_id] = " ".join(merged)
                _store(directory, blocker_path, _BLOCKER_FILE_NAME, blockers)
            turns = _load(turn_path)
            previous = turns.pop(session_id, "0")
            count = int(previous) if active_stop and previous.isdecimal() else 0
            turns[session_id] = str(min(count + 1, 999))
            _store(directory, turn_path, _TURN_FILE_NAME, turns)
            entries = _load(path)
            entries.pop(session_id, None)
            entries[session_id] = identity
            _store(directory, path, _FILE_NAME, entries)
        return True
    except Exception:
        return False


def standing_advice_withheld(session_key: str, *, _state: Path | None = None) -> bool:
    """Whether a Stop withheld standing advice this session has not received since (#985)."""

    _directory, path, _lock = _paths(_state, _STANDING_FILE_NAME)
    return _load(path).get(session_key) == "1"


def set_standing_advice_withheld(
    session_key: str, withheld: bool, *, _state: Path | None = None
) -> None:
    """Mark or clear the withheld-standing-advice flag for one opaque session key. Never raises.

    Ordinary advice never rides a Stop; standing advice (provider repair) would otherwise wait
    for the next SessionStart, so the first later PostToolUse may carry it instead.
    """

    with contextlib.suppress(Exception):
        _directory, path, _lock = _paths(_state, _STANDING_FILE_NAME)
        if (_load(path).get(session_key) == "1") is withheld:
            return
        with _locked(_state) as directory:
            entries = _load(path)
            entries.pop(session_key, None)
            if withheld:
                entries[session_key] = "1"
            _store(directory, path, _STANDING_FILE_NAME, entries)
