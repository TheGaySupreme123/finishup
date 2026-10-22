"""The Stop-time closure gate (issue #977, ADR-033).

When an agent stops while the mapped task's closure readiness still names work the agent can do,
the Stop hook continues it once with a message that names what remains. The decision reads only
the service's own ``status`` answer (``closure_readiness``), never the transcript or a file:

* it continues only for ``STOP_GATE_TOKENS`` in ``agent_actionable``: open obligations, a
  receipt-blocking finding the agent has not repaired, a rejected finding still awaiting the
  reviewer's ruling, and the task facts the agent can repair (a planned verification not
  observed, failing or stale; an edit to the work after the last verification run, ADR-042; a
  requested output Git would not deliver; a deliverable that was emptied or removed; a delivered
  file that may read a file the agent created and never declared, #1044);
* once per ledger frontier and session: a second Stop at the same frontier passes, so an agent
  that cannot or will not act is never trapped;
* the three re-checks (tb4n3 RC-8) are not riders on those tokens. Readiness announces them in
  ``closure_readiness.rechecks`` (acknowledgement, blocker, premise: the same list status and
  ``closure_prepare`` show), each with a content key, and the gate asks exactly the announced
  ones, each once per session and key: a Stop that readiness called "nothing further to do" is
  continued only for a re-check it announced. A readiness without the list (a service older than
  this gate) announces none, so the gate asks none;
* acceptance-provenance risk is not a Stop item (ADR-033, owner decision D1): status shows it once
  and the receipt records it as a coverage limit. The gate never asks the acceptance re-read, an
  ``acceptance`` entry an earlier 0.3 service still announces is dropped, and the hook never reads
  the agent's final message. An honest downgrade (``acknowledged_not_done`` right after
  ``resolved``) is not challenged by the acknowledgement re-check, by the service's own rule;
  an acceptance invite remembered by an earlier build still exempts a later acknowledgement;
* an obligation a recorded blocker decision names (authority, consent, credentials, an
  unobtainable dependency) is a standing disclosure in readiness. FinishUP cannot verify the claim,
  so a Stop that finds a blocker the agent has not been asked about continues the agent once
  with a re-check that names the obligation and the claimed kind. The re-check is remembered per
  session and ``(obligation, kind)``; the agent confirms a genuine blocker by publishing the
  same line again, and it is then never re-asked. These re-checks also run on a Stop the host
  already continued this turn (``stop_hook_active``, Cursor ``loop_count > 0``), because they
  usually follow the first gate (#985). On such an active Stop only a re-check or an emptied or
  removed deliverable not yet asked about may continue the agent, at most once per Stop and at
  most ``MAX_GATE_BLOCKS_PER_TURN`` gate continuations per host turn; anything else, including
  any error or a short time budget, lets the agent stop;
* a deliverable that held content and is now empty or gone (``declared_output_emptied`` /
  ``declared_output_removed``) is voiced once per key on an active Stop too (tb4n3 formal-crypto
  S: every later Stop was active, so the text never reached the agent that emptied its solver);
* the text pushes repair or self-verification first; ``acknowledged_not_done`` is the last
  resort and never requires withdrawing a working deliverable, a FinishUP limit is never a
  ``finishup-blocker``, and the blocker exit is offered only when open obligations remain (#984);
* a finding the agent acknowledged as not done that the review says the task itself requires
  (readiness ``premise`` re-check, D7a) is asked about once per session and acknowledged count,
  on a Stop the host has not already continued (closed item ``premise_recheck``);
* while this task's hook observations are still draining, the facts that depend on observed
  runs are not used to continue the agent, and the text says so only when that changed the
  decision.

The delivered text holds only closed tokens, counts and service-minted ids, with one exception:
the files a delivered file loads that nothing declares are named, each quoted and bounded
(``quoted_path``), because the agent must embed, rebuild or declare exactly that file (#1044). The
memory is three small owner-only files in the observation state directory holding opaque session,
frontier and obligation ids, closed re-check keys and a per-session turn counter; no path is ever
remembered.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
from collections.abc import Awaitable, Callable, Generator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from finishup import __version__
from finishup.config.paths import ensure_owner_only_dir, state_dir
from finishup.domain.bounded_text import Part, compose_parts
from finishup.domain.task_fact_tokens import (
    DECLARED_OUTPUT_CONTENT_MOVED_GAP,
    DECLARED_OUTPUT_EMPTIED_GAP,
    DECLARED_OUTPUT_REMOVED_GAP,
    DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP,
    EDITED_AFTER_LAST_VERIFICATION_GAP,
    FINDING_REJECTION_AWAITING_RULING_GAP,
    PLANNED_VERIFICATION_FAILED_GAP,
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
    PLANNED_VERIFICATION_STALE_GAP,
    REQUESTED_OUTPUT_GIT_IGNORED_GAP,
    STOP_GATE_TOKENS,
    undeclared_reference_variants,
)
from finishup.kernel.fact_lineage import FactLineage, lineage_from_wire, lineage_texts
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.readiness_text import (
    CODEX_CHECK_CELL_PRAGMA,
    coordinator_failure_note,
    predicted_receipt_variants,
)

if TYPE_CHECKING:
    from finishup.ports.control import ControlClientKind
    from finishup.protocol.models import StatusRequest

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
    "ACKNOWLEDGEMENT_RECHECK_ITEM",
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

# #1162: shown by the host to whoever watches the session (Codex and Claude Code systemMessage,
# Cursor stderr, one sentence per line). Each sentence stays within the 200-character stderr line.
STOP_ADVISORY_NOTICE: Final = (
    "FinishUP: an earlier AI-powered review left correctness notes on this task with no recorded "
    "response. They do not block finishing; the task receipt lists each note and its status."
)
_FILE_NAME: Final = "closure-gate.json"
_BLOCKER_FILE_NAME: Final = "closure-gate-blockers.json"
_TURN_FILE_NAME: Final = "closure-gate-turns.json"
_STANDING_FILE_NAME: Final = "stop-withheld-standing-advice.json"
_LOCK_NAME: Final = "closure-gate.lock"
_MAX_SESSIONS: Final = 128
_MAX_BLOCKER_KEYS: Final = 64
# Legacy acceptance invites (written by a build that asked the acceptance re-read, before D1) kept
# when the memory is trimmed: the earliest (its frontier decides which acknowledgement answered an
# invite) and the newest few. No new ``accept:`` key is written.
_MAX_INVITE_KEYS: Final = 8
# The closed item a blocker re-check adds to ``ClosureGate.items`` (#977).
BLOCKER_RECHECK_ITEM: Final = "blocker_recheck"
# D7a (#984): the closed item a one-time premise-dispute ask adds.
PREMISE_RECHECK_ITEM: Final = "premise_recheck"
# tb4n3 RC-8 (formal-crypto S): the re-check that sent pretrain S back to work ("do that work
# unless it is genuinely impossible") also sent formal-crypto S into 35 minutes of impossibility
# research and then to an emptied solver. It keeps its push to work and now says what to do when
# the work cannot be finished: keep what works.
_KEEP_DELIVERABLE_TEXT: Final = (
    "If you cannot finish it, keep the working deliverable; acknowledgement never requires"
    " withdrawing or emptying it."
)
_PREMISE_TEXT: Final = (
    "You marked finding(s) as not done that the reviewer says the task itself requires. Do that"
    " work unless it is genuinely impossible; a FinishUP limit or a hard result is not a reason."
    f" {_KEEP_DELIVERABLE_TEXT}"
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
        EDITED_AFTER_LAST_VERIFICATION_GAP,
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
# Deliverable tokens whose text is voiced once per key even on a Stop the host already continued.
_WITHDRAWN_TOKENS: Final = (DECLARED_OUTPUT_REMOVED_GAP, DECLARED_OUTPUT_EMPTIED_GAP)
_BLOCKER_LINE: Final = "finishup-blocker:<authority|consent|credential|dependency_unavailable>"
# Issue #995: what is not a blocker, and the line that discloses it instead.
_DISCLOSE_TEXT: Final = (
    "An inherent verification limit (a hidden verifier, a private trace) or a best-effort choice"
    " is not a blocker: finish the work and disclose it with a decision line"
    " `finishup-assumption:<obligation id>` or `finishup-verification-limit:<obligation id>`."
)
# Issue #997 (owner rule): the obligation-level acknowledgement is the honest last resort after
# repair, offered only once a blocker was challenged, never on an ordinary Stop.
_ACK_LAST_RESORT_TEXT: Final = (
    "If after repair you truly will not do it, republish the obligation with status"
    " `acknowledged_not_done` and an `acknowledged_not_done_reason` instead of a blocker."
)
# The closed item an acknowledged-obligation re-check adds, asked once per obligation (#997).
ACKNOWLEDGEMENT_RECHECK_ITEM: Final = "acknowledgement_recheck"
_MAX_NAMED_ACKNOWLEDGED: Final = 3
_ITEM_TEXT: Final[Mapping[str, str]] = {
    "obligations_open": "{open} open obligation(s)",
    BLOCKER_UNCONFIRMED_TOKEN: "a recorded blocker you have not confirmed",
    "receipt_findings_unresolved": "{blocking} receipt-blocking finding(s) not repaired",
    # tb4n3 RC-8 (ks S): a finding the agent rejected with a reason awaits the reviewer's ruling.
    # An acknowledgement would concede what the agent disputes, so this item offers none.
    FINDING_REJECTION_AWAITING_RULING_GAP: (
        "{awaiting} finding(s) you rejected await a reviewer ruling: run `check` with"
        " `final_review: true` so the reviewer rules; do not acknowledge a finding you dispute"
    ),
    "closing_review_required": (
        "the closing review has not run for the latest material input (an edit, a verification,"
        " or a command FinishUP could not establish left the workspace unchanged): run `check`"
        " with `final_review: true` (a recorded blocker does not waive it)"
    ),
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP: (
        "a planned verification never seen run as recorded; run it, or link the run that"
        " executed it (`causal_parents` = its action event id; see"
        " request-templates#publish-work-action)"
    ),
    PLANNED_VERIFICATION_FAILED_GAP: "a planned verification failed on its latest run",
    PLANNED_VERIFICATION_STALE_GAP: "a planned verification last ran before your latest edit",
    EDITED_AFTER_LAST_VERIFICATION_GAP: (
        "you edited the work after your last verification run: re-run the verification you"
        " planned (or the tests you last ran) on the final state"
    ),
    REQUESTED_OUTPUT_GIT_IGNORED_GAP: "a requested output is git-ignored, so a diff omits it",
    DECLARED_OUTPUT_REMOVED_GAP: (
        "a declared delivered file was deleted or renamed away; restore the delivered file, or"
        " correct the requested item if the task asked for the deletion: FinishUP review limits"
        " never justify moving, splitting or deleting deliverables"
    ),
    DECLARED_OUTPUT_EMPTIED_GAP: (
        "a declared deliverable that held content is now empty or truncated, so it no longer"
        " counts as delivered; restore it from your copy and disclose its limits: a working"
        " partial is a delivery, and an empty file always grades as no solution. Acknowledging or"
        " republishing the obligation does not clear this. Only if the task asked for this exact"
        " file to be empty regardless of outcome, record a decision with the line"
        " `finishup-assumption:<obligation id>` that names the file path, then run `check`"
    ),
    # tb4n4 interleaved-vigenere S (#1044): the delivered cracker loaded model files the agent
    # created and never declared; the grader received only the declared files. Disclosing the
    # dependency is not a way out.
    DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP: (
        "a delivered file references a file you created but did not declare in a way that may"
        " read it, and a grader may receive only the declared files: embed its content in the"
        " deliverable, rebuild it at run time,"
        " or declare it, or the directory holding it, as a delivered output (a requested `file`"
        " or `directory` item with role `output`), then run `check`; disclosing the dependency"
        " does not clear this"
    ),
}
# Repair-first guidance, one sentence per present item family (F1, #984). Acknowledgement is the
# last resort and a FinishUP limit is never a ``finishup-blocker``.
_OBLIGATION_TEXT: Final = (
    "Finish each open obligation: write every requested output at its path (status"
    " view=obligations names them); for an inconsistent input write a best-effort artifact and"
    " disclose the assumption (`finishup-assumption:<obligation id>`)."
)
_VERIFICATION_TEXT: Final = (
    "Run each planned verification after your last edit, or correct the requested command."
)
_FINDING_TEXT: Final = (
    "For each receipt-blocking finding, repair what you can. If you repaired one and FinishUP still"
    " cannot prove it (its resolution names a FinishUP limit such as redaction, observation loss or a review-packet limit), verify it yourself, record that evidence, and"
    " respond `self_verified` with how you verified it and the evidence ids. Do not reshape your"
    " work for FinishUP. Respond `acknowledged_not_done` only if you truly cannot or will not do it."
)
# tb4n3 RC-8: `self_verified` is accepted only for a finding whose newest check resolution names a
# FinishUP limit (status counts those in ``finding_counts.self_verify_eligible``). When none is
# eligible the gate does not offer it: an offer `respond` would refuse is a wrong steer.
_FINDING_NO_SELF_VERIFY_TEXT: Final = (
    "For each receipt-blocking finding, repair what you can and run `check` again."
    " `self_verified` is not accepted for these findings now (status view=findings lists what each"
    " finding accepts). Do not reshape your work for FinishUP. Respond `acknowledged_not_done` only"
    " if you truly cannot or will not do it."
)
# Short forms used only when the full text cannot share the host bound with the rest of the gate
# (tb4n3 RC-2, A5): each keeps the instruction and drops the elaboration.
_FINDING_SHORT_TEXT: Final = (
    "Repair each receipt-blocking finding; if FinishUP still cannot prove a repaired one, verify it"
    " yourself and respond `self_verified` with the evidence ids; `acknowledged_not_done` only if"
    " you truly will not do it."
)
_FINDING_NO_SELF_VERIFY_SHORT_TEXT: Final = (
    "Repair each receipt-blocking finding and run `check` again; `self_verified` is not accepted"
    " for these now; `acknowledged_not_done` only if you truly will not do it."
)
_BLOCKER_OFFER_SHORT_TEXT: Final = (
    "Leave an open obligation undone only for a blocker outside your control: publish"
    f" decision_recorded with affected_obligation_ids and the line {_BLOCKER_LINE}."
)
_CLOSE_TEXT: Final = (
    "Then run `check` and request the receipt. A FinishUP limit is never a `finishup-blocker`."
)
# tb4n5 (P6): a code-mode `check` cell without a yield deadline yields; the yielded `exec` cell
# then lands after the check and makes it stale. The deadline pragma is for that cell only.
# Issue #1079: the gate emits it when code mode was positively observed (a recorded `exec` cell
# for this session, or ``check_cause.tool == "exec"``), never because the host brand is Codex.
# Plain Codex ``exec_command`` / ``write_stdin`` and the other hosts keep the neutral sentence.
_CLOSE_TEXT_CODEX: Final = (
    f"Then run `check`, starting its Codex cell with `{CODEX_CHECK_CELL_PRAGMA}` so it does not"
    " yield, and request the receipt. A FinishUP limit is never a `finishup-blocker`."
)


def _code_mode_observed(readiness: object, code_mode: bool) -> bool:
    """Whether this Stop has positive evidence of a code-mode ``exec`` cell.

    ``code_mode`` is the hook's session observation. ``check_cause.tool == "exec"`` is the
    recorded cause of a stale check. Either is enough. Absence is the neutral instruction.
    """

    if code_mode is True:
        return True
    cause = getattr(readiness, "check_cause", None)
    return getattr(cause, "tool", None) == "exec"


def _close_text(*, code_mode: bool) -> str:
    """The close instruction; the cell pragma only when code mode was observed."""

    return _CLOSE_TEXT_CODEX if code_mode else _CLOSE_TEXT


_BLOCKER_OFFER_TEXT: Final = (
    "Leave an open obligation undone only for a blocker outside your control (authority,"
    " consent, credentials, a dependency you cannot obtain): publish decision_recorded with"
    f" affected_obligation_ids and the line {_BLOCKER_LINE}, and FinishUP will ask you about it once."
    f" Data the task says is recoverable is not such a blocker. {_DISCLOSE_TEXT}"
)
# How to confirm a blocker appears only AFTER the challenge (the re-check, or a later gate whose
# blocker was already re-asked), so publishing a blocker twice up front never skips it (#985).
# The confirmation is a different body (its rationale names the re-check), because the MCP bridge
# refuses a writer's previous id-less body resent unchanged as a possible retry (#1084). The
# sentence stays this short so the worst-case re-check still fits the 2,000-character bound.
_CONFIRM_TEXT: Final = (
    "If genuine, confirm it: publish the same finishup-blocker line again later, with a rationale"
    " naming your re-check; then stop."
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
_DRAIN_TEXT: Final = "(Observations were still draining; verification facts unused.)"
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


_MAX_RECHECKS: Final = 256
_MAX_NAMED_LINEAGE: Final = 3
_SUBJECT_ID: Final = re.compile(r"(?:obl|fnd)_[0-9A-Za-z-]{1,60}")
_OBL_ID_SHAPE: Final = r"obl_[0-9A-Za-z-]{1,60}"
# The closed key shapes of ``closure_readiness.rechecks`` (DESIGN_RC3 3.4). A key of another shape,
# or a kind outside the three, is dropped: the gate never asks a re-check it cannot read. An
# ``acceptance`` entry from an earlier 0.3 service is dropped by this rule (ADR-033 D1).
_RECHECK_KEY_SHAPES: Final[Mapping[str, re.Pattern[str]]] = {
    "acknowledgement": re.compile(rf"ack:{_OBL_ID_SHAPE}"),
    "blocker": re.compile(
        rf"blocker:{_OBL_ID_SHAPE}:(?:authority|consent|credential|dependency_unavailable)"
    ),
    "premise": re.compile(r"premise:(?:[0-9]{1,8}|\?)"),
}


def _lineage_variants(readiness: object, items: tuple[str, ...]) -> tuple[str, ...]:
    """Why each present token fired (ADR-045): the provenance readiness carries, as sentences.

    Only lineage whose fact code is one of the tokens the gate is naming; at most
    ``_MAX_NAMED_LINEAGE`` sentences, the rest counted. Unreadable entries are skipped. The second
    variant, when there is one, names only the first sentence (the composed fallback's short form).
    """

    raw = getattr(readiness, "fact_lineage", None)
    if not isinstance(raw, (tuple, list)):
        return ()
    wanted = frozenset(items)
    parsed: list[FactLineage] = []
    for entry in tuple(cast(tuple[object, ...], raw)):
        try:
            item = lineage_from_wire(entry)
        except (TypeError, ValueError):
            continue
        if item.code in wanted:
            parsed.append(item)
    texts = lineage_texts(parsed)
    if not texts:
        return ()
    hidden = len(texts) - _MAX_NAMED_LINEAGE
    shown = " ".join(texts[:_MAX_NAMED_LINEAGE]) + (
        f" (+{hidden} more in `status`.)" if hidden > 0 else ""
    )
    if len(texts) == 1:
        return (shown,)
    return (shown, texts[0] + f" (+{len(texts) - 1} more in `status`.)")


def _field(entry: object, name: str) -> object:
    """One field of a wire model, a mapping or a test double."""

    if isinstance(entry, Mapping):
        return cast(Mapping[str, object], entry).get(name)
    return getattr(entry, name, None)


def _decimal(raw: object) -> int | None:
    """A canonical non-negative count, from the wire string or an int; anything else is None."""

    if type(raw) is int and raw >= 0:
        return raw
    if type(raw) is str and raw.isascii() and raw.isdecimal() and len(raw) <= 18:
        return int(raw)
    return None


@dataclass(frozen=True, slots=True)
class _Recheck:
    """One re-check readiness announced in ``rechecks``, validated and closed (tb4n3 RC-8)."""

    kind: str
    key: str
    subjects: tuple[str, ...]
    since: int | None

    @property
    def memory_key(self) -> str:
        """The key the gate remembers once it asked. A blocker keeps its historical
        ``<obligation id>:<kind>`` form so a memory file written by an earlier build still
        honours it."""

        return self.key.removeprefix("blocker:") if self.kind == "blocker" else self.key


def _announced_rechecks(readiness: object) -> tuple[_Recheck, ...]:
    """The re-checks readiness announces; a readiness without the list announces none.

    A service older than this gate sends no ``rechecks``. The gate then asks no re-check: status
    never announced one, and "nothing further to do" is never followed by a gate for an item the
    service did not name.
    """

    raw = getattr(readiness, "rechecks", None)
    if not isinstance(raw, (tuple, list)):
        return ()
    found: dict[str, _Recheck] = {}
    for entry in tuple(cast(tuple[object, ...], raw))[:_MAX_RECHECKS]:
        kind = _field(entry, "kind")
        key = _field(entry, "key")
        if type(kind) is not str or type(key) is not str:
            continue
        shape = _RECHECK_KEY_SHAPES.get(kind)
        if shape is None or shape.fullmatch(key) is None:
            continue
        subjects_raw = _field(entry, "subjects")
        subjects = (
            tuple(
                item
                for item in tuple(cast(tuple[object, ...], subjects_raw))
                if type(item) is str and _SUBJECT_ID.fullmatch(item)
            )
            if isinstance(subjects_raw, (tuple, list))
            else ()
        )
        found.setdefault(
            key, _Recheck(kind, key, subjects, _decimal(_field(entry, "since_frontier")))
        )
    return tuple(found.values())


def _asked(recheck: _Recheck, memory: frozenset[str]) -> bool:
    """Whether this session was already asked this re-check (by its key)."""

    return recheck.memory_key in memory


def _first_invite_frontier(memory: frozenset[str]) -> int | None:
    """The frontier of the earliest acceptance invite this session received, if any.

    Memory written by a build that asked the acceptance re-read (before D1): ``accept:<h8>@<n>``
    or ``accept:<h8>@<n>@m<material>``. Read so a session that spans the upgrade is not newly
    challenged for an acknowledgement that answered that invite; never written again.
    """

    frontiers: list[int] = []
    for item in memory:
        head, separator, tail = item.partition("@")
        number = tail.split("@", 1)[0] if separator else ""
        value = _decimal(number) if separator and head.startswith("accept:") else None
        if value is not None:
            frontiers.append(value)
    return min(frontiers) if frontiers else None


def _blocker_pairs(rechecks: tuple[_Recheck, ...]) -> tuple[tuple[str, str], ...]:
    """``(obligation id, kind)`` for the announced blocker re-checks, ordered by obligation id."""

    pairs: dict[str, str] = {}
    for recheck in rechecks:
        _prefix, obligation, kind = recheck.key.split(":", 2)
        pairs.setdefault(obligation, kind)
    return tuple(sorted(pairs.items(), key=lambda row: row[0].encode()))


def _acknowledged_listed(readiness: object) -> bool:
    """Whether readiness lists acknowledged obligations (an older build counted them as open)."""

    raw = getattr(readiness, "acknowledged_not_done", None)
    return isinstance(raw, (tuple, list)) and any(
        type(item) is str and item.startswith("obl_")
        for item in tuple(cast(tuple[object, ...], raw))
    )


def _acknowledgement_text(keys: tuple[str, ...], *, short: bool = False) -> str:
    named_ids = [key.removeprefix("ack:") for key in keys if key.startswith("ack:")]
    named = ", ".join(named_ids[:_MAX_NAMED_ACKNOWLEDGED])
    hidden = len(named_ids) - _MAX_NAMED_ACKNOWLEDGED
    if hidden > 0:
        named += f" and {hidden} more"
    subject = (
        f"you recorded {named} as not done" if named else "you recorded obligations as not done"
    )
    if short:
        return (
            f"Acknowledgement re-check (asked once): {subject}. Do that work unless it is"
            f" genuinely impossible; a FinishUP limit is not a reason. {_KEEP_DELIVERABLE_TEXT} If it"
            " truly stays undone, you may stop and the receipt discloses it; republish it `open`"
            " to take it back."
        )
    return (
        f"Acknowledgement re-check (asked once): {subject}. Repair first: do that work unless it"
        " is genuinely impossible; missing data the task says is recoverable, a hard result or a"
        f" FinishUP limit is not a reason. {_KEEP_DELIVERABLE_TEXT} If it truly stays undone, you"
        " may stop: the receipt discloses it as not done. To take it back, republish it with"
        " status `open`, repeating every meaning field, on obligation_published 1.1.0 (it keeps"
        " any role or directory item)."
    )


def _present_tokens(readiness: object) -> frozenset[str] | None:
    actionable = getattr(readiness, "agent_actionable", None)
    if not isinstance(actionable, (tuple, list)):
        return None
    return frozenset(
        item for item in tuple(cast(tuple[object, ...], actionable)) if type(item) is str
    )


def _finding_counts(readiness: object) -> tuple[int | None, int | None, int | None]:
    """``(to do, awaiting a ruling, self_verified-eligible)`` from ``finding_counts``, if sent."""

    counts = getattr(readiness, "finding_counts", None)
    if counts is None:
        return (None, None, None)
    return (
        _decimal(_field(counts, "to_do")),
        _decimal(_field(counts, "awaiting_ruling")),
        _decimal(_field(counts, "self_verify_eligible")),
    )


def _plural_ids(named: list[str]) -> str:
    shown = ", ".join(named[:_MAX_NAMED_LINEAGE])
    hidden = len(named) - _MAX_NAMED_LINEAGE
    return shown + (f" and {hidden} more" if hidden > 0 else "")


def _awaiting_clause(readiness: object) -> str:
    """Why the awaiting-ruling token fired (owner decision 10): the rule, and the findings and the
    frontier of the rejection when readiness names them (``awaiting_ruling_findings``).

    Status also lists them (``view=findings`` rows with ``closure_class awaiting_ruling``), so a
    readiness that does not name them still gets the rule and where to read them.
    """

    raw = getattr(readiness, "awaiting_ruling_findings", None)
    named: list[str] = []
    if isinstance(raw, (tuple, list)):
        for entry in tuple(cast(tuple[object, ...], raw))[:_MAX_RECHECKS]:
            finding = _field(entry, "finding_id")
            if type(finding) is not str or not _SUBJECT_ID.fullmatch(finding):
                continue
            since = _decimal(_field(entry, "since_frontier"))
            named.append(finding if since is None else f"{finding} (rejected at frontier {since})")
    if named:
        return (
            f"Why: no check has ruled on {_plural_ids(named)}."
            f" Rule {FINDING_REJECTION_AWAITING_RULING_GAP}."
        )
    return (
        "Why: you answered a finding `rejected` and no check has ruled on it since (status"
        f" view=findings lists them). Rule {FINDING_REJECTION_AWAITING_RULING_GAP}."
    )


def _withdrawn_entries(
    readiness: object, tokens: tuple[str, ...]
) -> list[tuple[str, str | None, str | None, str | None, str | None]]:
    """``(code, rule, obligation id, item index, basis)`` of the lineage naming these tokens."""

    raw = getattr(readiness, "fact_lineage", None)
    if not isinstance(raw, (tuple, list)):
        return []
    entries: list[tuple[str, str | None, str | None, str | None, str | None]] = []
    for entry in tuple(cast(tuple[object, ...], raw))[:_MAX_RECHECKS]:
        code = _field(entry, "code")
        if type(code) is not str or code not in tokens:
            continue

        def text(name: str, entry: object = entry) -> str | None:
            value = _field(entry, name)
            return value if type(value) is str and value.isascii() and len(value) <= 64 else None

        obligation = text("obligation_id")
        entries.append(
            (
                code,
                text("rule"),
                obligation if obligation is not None and obligation.startswith("obl_") else None,
                text("item_index"),
                text("basis"),
            )
        )
    return entries


def _withdrawn_key(readiness: object, tokens: tuple[str, ...]) -> str:
    """``emptied:<h8>``: once per withdrawn deliverable set, never a path.

    A deliverable is named by the obligation item that declares it (one path per item), so the
    key hashes ``(code, obligation id, item index)`` from the readiness lineage. A readiness
    without lineage keys on the token names.
    """

    material = sorted(
        f"{code}:{obligation or ''}:{index or ''}"
        for code, _rule, obligation, index, _basis in _withdrawn_entries(readiness, tokens)
    ) or sorted(tokens)
    return "emptied:" + hashlib.sha256("\n".join(material).encode("ascii")).hexdigest()[:8]


def _withdrawn_text(readiness: object, tokens: tuple[str, ...]) -> str:
    """The withdrawn-deliverable instruction, with the rule and obligation ids (never a path).

    "Passed your verification run" is said only when every lineage entry's basis is ``verified`` (a
    test, lint, typecheck or build run passed while the file had content); otherwise the
    deliverable "held content". It never says "tests": a lint or build run also verifies.
    """

    entries = _withdrawn_entries(readiness, tokens)
    verified = bool(entries) and all(basis == "verified" for *_rest, basis in entries)
    what = "passed your verification run" if verified else "held content"
    gone = "an empty file" if DECLARED_OUTPUT_EMPTIED_GAP in tokens else "a missing file"
    sentence = (
        f"You withdrew a deliverable that {what}; {gone} scores as no solution; restore it and"
        " disclose its limits."
    )
    rules = sorted({rule for _c, rule, _o, _i, _b in entries if rule is not None})
    obligations = sorted(
        {
            f"{obligation} item {index}" if index is not None else obligation
            for _c, _r, obligation, index, _b in entries
            if obligation is not None
        },
        key=str.encode,
    )
    notes: list[str] = []
    if rules:
        notes.append("rule " + ", ".join(rules))
    if obligations:
        notes.append("obligations " + _plural_ids(obligations))
    return sentence + (f" ({'; '.join(notes)}.)" if notes else "")


# tb4n5 (ADR-035 amendment): how an agent lists the files its change created, in its own shell,
# when its privacy policy withholds their names from the agent context.
_CREATED_FILES_COMMAND: Final = "`git status --porcelain --untracked-files=all`"


def _undeclared_variants(readiness: object) -> tuple[str, ...]:
    """Name the files ``deliverable_references_undeclared_file`` found (tb4n4, #1044).

    From ``closure_readiness.undeclared_references``: the declared item that names them by id and
    index, and each path quoted and bounded (``quoted_path``); a path a privacy policy withheld
    reads ``(path withheld)``. ``()`` when readiness names none (an older service), so the item's
    own clause still says what to do. When a name was withheld (tb4n5), each variant ends with
    the continuation: why, and the agent's own shell command that lists the files it created.
    """

    raw = getattr(readiness, "undeclared_references", None)
    if not isinstance(raw, (tuple, list)):
        return ()
    rows: list[tuple[str, int | None, tuple[str | None, ...], int]] = []
    withheld = False
    for entry in tuple(cast(tuple[object, ...], raw))[:_MAX_RECHECKS]:
        obligation = _field(entry, "obligation_id")
        index = _decimal(_field(entry, "item_index"))
        total = _decimal(_field(entry, "total"))
        paths_raw = _field(entry, "paths")
        if (
            type(obligation) is not str
            or not _SUBJECT_ID.fullmatch(obligation)
            or not obligation.startswith("obl_")
            or total is None
            or not isinstance(paths_raw, (tuple, list))
        ):
            continue
        paths = tuple(
            item if type(item) is str else None
            for item in tuple(cast(tuple[object, ...], paths_raw))[:8]
        )
        rows.append((obligation, index, paths, total))
        if any(path is None for path in paths):
            withheld = True
    named = undeclared_reference_variants(rows)
    if not named or not withheld:
        return named
    # tb4n5 (ADR-035 amendment): a withheld name is not actionable on its own. Say why and how to
    # find the files without widening any privacy setting: the agent's own shell lists them.
    full = (
        " Your privacy policy withheld these names (FinishUP returns only a name you published"
        f" yourself): list the files your change created with your own shell"
        f" ({_CREATED_FILES_COMMAND}), then declare the ones the delivered file may read, or their"
        " directory, or embed or rebuild them."
    )
    short = f" Names withheld: list the files you created with {_CREATED_FILES_COMMAND}."
    return tuple(dict.fromkeys((named[0] + full, named[-1] + short)))


# Informational only (ADR-035): appended when the gate already fires for another reason and
# readiness lists this standing disclosure. It is never a token, so it never fires the gate.
_CONTENT_MOVED_NOTE: Final = (
    "Note: content may have moved out of a delivered file into an undelivered one"
    " (declared_output_content_moved); check the deliverable still works where the task"
    " delivers it."
)


def _content_moved_note(readiness: object) -> str:
    standing = getattr(readiness, "standing_limitations", None)
    if isinstance(standing, (tuple, list)) and DECLARED_OUTPUT_CONTENT_MOVED_GAP in tuple(
        cast(tuple[object, ...], standing)
    ):
        return " " + _CONTENT_MOVED_NOTE
    return ""


class ClosureGateUnavailable(Exception):
    """The status read the gate needs did not answer; the agent is allowed to stop."""


@dataclass(frozen=True, slots=True)
class ClosureGate:
    """One Stop continuation: its once-per-frontier identity, its text and the closed items."""

    identity: str
    text: str
    items: tuple[str, ...]
    # The re-check keys this gate asked, remembered once it is delivered (the historical field
    # name): ``<obligation id>:<kind>`` blockers, ``ack:<obligation id>``, ``premise:<n>`` and
    # ``emptied:<h8>``. No ``accept:`` key is written since D1.
    blocker_keys: tuple[str, ...] = ()


def _blocker_text(rows: tuple[tuple[str, str], ...], *, short: bool = False) -> str:
    named = ", ".join(f"{obligation} ({kind})" for obligation, kind in rows[:_MAX_NAMED_BLOCKERS])
    if len(rows) > _MAX_NAMED_BLOCKERS:
        named += f" and {len(rows) - _MAX_NAMED_BLOCKERS} more"
    if short:
        # The blocker offer already defines a blocker; the re-check and confirmation remain.
        return (
            f"Blocker re-check (asked once): you recorded {named} as blocked. Continue that work"
            " unless it is genuinely outside your control; a FinishUP limit never is: finish the"
            f" obligation and disclose any limit in your final answer. {_CONFIRM_TEXT}"
            f" {_ACK_LAST_RESORT_TEXT}"
        )
    return (
        f"Blocker re-check (asked once): you recorded {named} as blocked outside your control."
        " Repair first: missing or inconsistent data the task says is recoverable, a failing"
        " test or a result that looks infeasible is not a blocker, so continue the work on that"
        " obligation. A FinishUP limit is never a blocker either: finish the obligation and disclose"
        f" any limit in your final answer. {_DISCLOSE_TEXT} A blocker is only authority or consent"
        " you do not have,"
        f" a credential you lack, or a dependency you cannot obtain. {_CONFIRM_TEXT} FinishUP will"
        " not ask again and the receipt discloses it as a standing limitation."
        f" {_ACK_LAST_RESORT_TEXT}"
    )


def _fallback_parts(
    *,
    head: str,
    why: str,
    items: tuple[str, ...],
    premise_text: str,
    offers_blocker: bool,
    recheck: str,
    ack_keys: tuple[str, ...],
    ack_text: str,
    limitations: str,
    moved_note: str,
    drain_note: str,
    unconfirmed: bool,
    finding_texts: tuple[str, str],
    withdrawn_text: str,
    lineage: tuple[str, ...] = (),
    undeclared: tuple[str, ...] = (),
    close_text: str = _CLOSE_TEXT,
) -> list[tuple[str, Part]]:
    """The gate's sentences as named parts, in reading order, for the composed fallback.

    Required: the head, one instruction per present item family (obligations, planned
    verification, receipt-blocking findings, a withdrawn deliverable) and the close instruction.
    Optional, in priority order: the blocker re-check, the acknowledgement re-check, the
    unconfirmed-blocker sentence, the blocker offer, the required limitation ids, the provenance
    sentence, the premise ask, then the notes and, last, the fact-lineage sentence (where the fact
    came from). This changes composition only: the short forms drop elaboration and keep the
    instruction.
    """

    parts: list[tuple[str, Part]] = [("head", Part((head,), required=True))]
    if why:
        parts.append(("why", Part((why,), priority=5)))
    if premise_text:
        parts.append(("premise", Part((premise_text,), priority=6)))
    if lineage:
        # ADR-045: where a fact came from. The lowest-priority optional sentence: the first to go.
        parts.append(("lineage", Part(lineage, priority=10)))
    if "obligations_open" in items:
        parts.append(
            (
                "obligations",
                Part((_OBLIGATION_TEXT, _OBLIGATION_SHORT_TEXT), required=True, priority=7),
            )
        )
    if any(token in _OBSERVATION_DEPENDENT for token in items):
        parts.append(("verification", Part((_VERIFICATION_TEXT,), required=True)))
    if "receipt_findings_unresolved" in items:
        parts.append(("findings", Part(finding_texts, required=True, priority=7)))
    if withdrawn_text:
        parts.append(("withdrawn", Part((withdrawn_text,), required=True)))
    if undeclared:
        # tb4n4 (#1044): the undeclared files, by name; the short form names the first one.
        parts.append(("undeclared", Part(undeclared, required=True)))
    if limitations:
        parts.append(("limitations", Part((limitations,), priority=5)))
    parts.append(("close", Part((close_text,), required=True)))
    if offers_blocker:
        parts.append(("offer", Part((_BLOCKER_OFFER_TEXT, _BLOCKER_OFFER_SHORT_TEXT), priority=4)))
    if unconfirmed:
        parts.append(("unconfirmed", Part((_UNCONFIRMED_AFTER_RECHECK_TEXT,), priority=3)))
    if recheck:
        parts.append(("recheck", Part((recheck,), priority=1)))
    if ack_text:
        parts.append(
            ("ack", Part((ack_text, _acknowledgement_text(ack_keys, short=True)), priority=2))
        )
    if drain_note:
        parts.append(("drain", Part((drain_note,), priority=9)))
    if moved_note:
        parts.append(("moved", Part((moved_note,), priority=9)))
    return parts


def closure_gate_from_readiness(
    readiness: object,
    *,
    frontier_sequence: str,
    frontier_digest: str,
    observation_pending: bool,
    reasked_blockers: frozenset[str] = frozenset(),
    active_stop: bool = False,
    code_mode: bool = False,
) -> ClosureGate | None:
    """Decide the gate from one ``closure_readiness`` object; ``None`` means let the agent stop.

    The close instruction repeats the `check` cell's ``yield_time_ms`` deadline only when
    ``code_mode`` is true or ``check_cause.tool`` is ``exec`` (a recorded code-mode cell), not
    because the host is Codex (tb4n5, #1079). The decision is the same on every host: no item is
    answered by the agent's final message, and acceptance-provenance risk never continues the
    agent (ADR-033, owner decision D1).

    ``reasked_blockers`` holds the re-check keys this session was already asked (the historical
    name: blockers as ``<obligation id>:<kind>``, ``ack:<obligation id>``, ``premise:<n>``,
    ``emptied:<h8>``, and ``accept:<h8>@<invite frontier>[@m<material>]`` invites remembered by
    a build before D1). Every announced re-check is asked once.
    ``active_stop`` is a Stop the host already continued this turn
    (``stop_hook_active``, Cursor ``loop_count > 0``): only a re-check not yet asked, or a
    withdrawn deliverable not yet voiced, may continue it, never the ordinary items (#985).
    """

    state = getattr(readiness, "state", None)
    if state not in {"action_required", "ready", "ready_with_limitations"}:
        return None
    identity = f"{frontier_sequence}:{frontier_digest}"
    # Memory written by a build that asked the acceptance re-read (before D1); never written now.
    invite = _first_invite_frontier(reasked_blockers)
    blockers: list[_Recheck] = []
    acknowledgements: list[_Recheck] = []
    premise: _Recheck | None = None
    # Whether a blocker re-check readiness announced was already delivered to this session: only
    # then may the text say "you were already asked" (absence of a candidate proves nothing, e.g.
    # a service older than the gate sends no list).
    blocker_already_asked = False
    for recheck in _announced_rechecks(readiness):
        if _asked(recheck, reasked_blockers):
            blocker_already_asked = blocker_already_asked or recheck.kind == "blocker"
            continue
        if recheck.kind == "blocker":
            blockers.append(recheck)
        elif recheck.kind == "acknowledgement":
            # An acknowledgement published after a legacy acceptance invite answered it: the
            # invite told the agent to republish an unmet obligation as `acknowledged_not_done`,
            # so challenging that answer would be invite-then-challenge (tb4n3 RC-8, cargo D).
            # Since D1 the service itself leaves an honest downgrade out of the re-checks.
            if invite is not None and recheck.since is not None and recheck.since > invite:
                continue
            acknowledgements.append(recheck)
        elif recheck.kind == "premise":
            # D7a (#984): only on a Stop the host has not already continued this turn.
            if not active_stop and premise is None:
                premise = recheck
    rows = _blocker_pairs(tuple(blockers))
    keys = tuple(f"{obligation}:{kind}" for obligation, kind in rows)
    ack_keys = tuple(sorted((recheck.key for recheck in acknowledgements), key=str.encode))
    ack_text = _acknowledgement_text(ack_keys) if ack_keys else ""
    ack_items = (ACKNOWLEDGEMENT_RECHECK_ITEM,) if ack_keys else ()
    premise_items = (PREMISE_RECHECK_ITEM,) if premise is not None else ()
    premise_keys = (premise.key,) if premise is not None else ()
    premise_text = _PREMISE_TEXT if premise is not None else ""
    present: frozenset[str] = frozenset()
    if state == "action_required":
        tokens = _present_tokens(readiness)
        if tokens is not None:
            present = tokens
        elif not active_stop:
            return None
    prediction = predicted_receipt_variants(
        getattr(readiness, "predicted_receipt", None), state=state
    )
    items: tuple[str, ...] = ()
    drain_changed_decision = False
    if active_stop:
        # tb4n3 RC-8 (formal-crypto S): every Stop after the first gate is an active Stop, so the
        # withdrawn-deliverable text never reached the agent that emptied its solver. It may
        # continue an active Stop once per key (the turn cap still bounds it).
        withdrawn = tuple(token for token in _WITHDRAWN_TOKENS if token in present)
        if withdrawn and _withdrawn_key(readiness, withdrawn) not in reasked_blockers:
            items = withdrawn
    else:
        items = tuple(
            token
            for token in _GATE_TOKENS
            if token in present and not (observation_pending and token in _OBSERVATION_DEPENDENT)
        )
        drain_changed_decision = observation_pending and bool(present & _OBSERVATION_DEPENDENT)
    coord_note = coordinator_failure_note(readiness) or ""
    if not items:
        if not rows and premise is None and not ack_keys:
            return None
        opener = (
            "FinishUP closure gate (shown once for these blockers):"
            if rows
            else "FinishUP closure gate (shown once):"
        )
        # The unchanged coordinator failure is a FinishUP limit. It rides the opener so a
        # trimmed re-check text still says not to send the same check again.
        if coord_note:
            opener = f"{opener} {coord_note}"
        blocker = _blocker_text(rows) if rows else ""
        # ADR-035: the standing content-moved disclosure rides gate text that fires anyway.
        moved = _content_moved_note(readiness).strip()
        # Keep only whole sentences under the host bound, choosing by priority (blocker re-check,
        # acknowledgement re-check, premise ask, then the note) but keeping the reading order. A
        # re-check that does not fit is not reported as asked, so its keys are not remembered and
        # the next Stop asks it again.
        used = len(opener)
        chosen: set[str] = set()
        for name, sentence in (
            ("rows", blocker),
            ("ack", ack_text),
            ("premise", premise_text),
            ("moved", moved),
        ):
            if sentence and used + 1 + len(sentence) <= _MAX_TEXT_CHARS:
                chosen.add(name)
                used += 1 + len(sentence)
        asked_rows = "rows" in chosen
        asked_ack = "ack" in chosen
        asked_premise_only = "premise" in chosen
        if not (asked_rows or asked_ack or asked_premise_only):
            return None
        # The predicted receipt conclusion is the lowest-priority sentence (owner decision Q1):
        # the longest variant that still fits, else none.
        wanted = sum(1 for sentence in (blocker, ack_text, premise_text, moved) if sentence)
        tail = (
            next(
                (variant for variant in prediction if used + 1 + len(variant) <= _MAX_TEXT_CHARS),
                "",
            )
            if len(chosen) == wanted
            else ""
        )
        short_text = " ".join(
            sentence
            for name, sentence in (
                ("opener", opener),
                ("premise", premise_text),
                ("rows", blocker),
                ("ack", ack_text),
                ("moved", moved),
                ("prediction", tail),
            )
            if sentence and (name in {"opener", "prediction"} or name in chosen)
        )
        return ClosureGate(
            identity,
            short_text,
            (premise_items if asked_premise_only else ())
            + ((BLOCKER_RECHECK_ITEM,) if asked_rows else ())
            + (ack_items if asked_ack else ()),
            (keys if asked_rows else ())
            + (premise_keys if asked_premise_only else ())
            + (ack_keys if asked_ack else ()),
        )
    open_count = str(getattr(readiness, "open_obligation_count", "?"))
    if getattr(readiness, "acknowledged_obligation_count", None) is None and _acknowledged_listed(
        readiness
    ):
        # #997: an earlier 0.3 build may count acknowledged obligations as open; name no number.
        open_count = "some"
    to_do, awaiting, eligible = _finding_counts(readiness)
    # tb4n3 RC-8: `receipt_findings_unresolved` counts the findings the agent can still act on;
    # a rejected finding awaiting a ruling has its own item. An older service sends no counts.
    blocking_count = (
        str(max(to_do - (awaiting or 0), 0))
        if to_do is not None
        else str(getattr(readiness, "receipt_blocking_finding_count", "?"))
    )
    awaiting_count = "some" if awaiting is None else str(awaiting)
    remaining = "; ".join(
        _ITEM_TEXT[token].format(open=open_count, blocking=blocking_count, awaiting=awaiting_count)
        for token in items
    )
    offers_blocker = "obligations_open" in items or BLOCKER_UNCONFIRMED_TOKEN in items
    head = (
        f"FinishUP closure gate (shown once for ledger frontier {frontier_sequence}): closure still"
        f" requires action before you stop. Remaining: {remaining}."
    )
    if coord_note:
        head = f"{head} {coord_note}"
    recheck = _blocker_text(rows, short=offers_blocker) if rows else ""
    unconfirmed_sentence = BLOCKER_UNCONFIRMED_TOKEN in items and not rows and blocker_already_asked
    limitations = _limitation_text(readiness)
    moved_note = _content_moved_note(readiness).strip()
    withdrawn_items = tuple(token for token in _WITHDRAWN_TOKENS if token in items)
    withdrawn_text = _withdrawn_text(readiness, withdrawn_items) if withdrawn_items else ""
    undeclared = (
        _undeclared_variants(readiness)
        if DELIVERABLE_REFERENCES_UNDECLARED_FILE_GAP in items
        else ()
    )
    why_text = _awaiting_clause(readiness) if FINDING_REJECTION_AWAITING_RULING_GAP in items else ""
    # `self_verified` is offered only when `respond` would accept it for some finding; an older
    # service sends no counts and keeps the offer.
    self_verify = eligible is None or eligible > 0
    finding_texts = (
        (_FINDING_TEXT, _FINDING_SHORT_TEXT)
        if self_verify
        else (_FINDING_NO_SELF_VERIFY_TEXT, _FINDING_NO_SELF_VERIFY_SHORT_TEXT)
    )
    lineage_variants = _lineage_variants(readiness, items)
    close = _close_text(code_mode=_code_mode_observed(readiness, code_mode))

    def compose(
        *,
        drain: bool,
        short_obligation: bool,
        verification: bool,
        limits: bool = True,
        premise_sentence: bool = True,
        lineage_sentence: bool = True,
        tail: str = "",
    ) -> str:
        parts = [head]
        if why_text:
            parts.append(why_text)
        if lineage_sentence and lineage_variants:
            # ADR-045: where the fact came from; the first sentence to be trimmed.
            parts.append(lineage_variants[0])
        if premise_text and premise_sentence:
            parts.append(premise_text)
        if "obligations_open" in items:
            parts.append(_OBLIGATION_SHORT_TEXT if short_obligation else _OBLIGATION_TEXT)
        if verification and any(token in _OBSERVATION_DEPENDENT for token in items):
            parts.append(_VERIFICATION_TEXT)
        if "receipt_findings_unresolved" in items:
            parts.append(finding_texts[0])
        if withdrawn_text:
            parts.append(withdrawn_text)
        if undeclared:
            parts.append(undeclared[0])
        if limits and limitations:
            parts.append(limitations)
        parts.append(close)
        # The blocker exit is offered only for open obligations: findings, reviews and FinishUP
        # limits are never excused by a blocker (F1, #984).
        if offers_blocker:
            parts.append(_BLOCKER_OFFER_TEXT)
        if unconfirmed_sentence:
            parts.append(_UNCONFIRMED_AFTER_RECHECK_TEXT)
        if recheck:
            parts.append(recheck)
        if ack_text:
            parts.append(ack_text)
        if drain and drain_changed_decision:
            parts.append(_DRAIN_TEXT)
        # ADR-035: the standing content-moved disclosure, dropped first with the drain note.
        if drain and moved_note:
            parts.append(moved_note)
        # The predicted receipt conclusion (owner decision Q1): the first sentence dropped.
        if tail:
            parts.append(tail)
        return " ".join(parts)

    # Every host clips at 2,000 characters. Drop whole optional sentences, never the re-check:
    # the drain note first, then the long obligation sentence, then the required limitation ids
    # (F3), then the premise ask. A planned-verification hint is a family instruction and stays.
    text = ""
    delivered_rows = bool(rows)
    delivered_ack = bool(ack_keys)
    # The predicted receipt conclusion (longest variant first, then none) goes before anything else,
    # then the fact-lineage sentence (tb4n3 RC-5: the lowest-priority sentence). The cause of each
    # token stays: it is the token's own "Remaining" clause, and the awaiting-ruling "Why".
    rungs: list[tuple[bool, bool, bool, bool, bool, bool, str]] = [
        (True, False, True, True, True, True, tail) for tail in (*prediction, "")
    ]
    rungs += [
        (True, False, True, True, True, False, ""),
        (False, False, True, True, True, False, ""),
        (False, True, True, True, True, False, ""),
        # tb4n3 RC-2 (A5): the required limitation ids go before a present family's instruction
        # does; the composed fallback below shortens the rest and never drops one.
        (False, True, True, False, True, False, ""),
        # D7a: the premise ask goes before the re-check does.
        (False, True, True, False, False, False, ""),
    ]
    for drain, short_obligation, verification, limits, premise_sentence, lineage_on, tail in rungs:
        text = compose(
            drain=drain,
            short_obligation=short_obligation,
            verification=verification,
            limits=limits,
            premise_sentence=premise_sentence,
            lineage_sentence=lineage_on,
            tail=tail,
        )
        if len(text) <= _MAX_TEXT_CHARS:
            asked_premise = premise is not None and premise_sentence
            break
    else:
        # The ladder could not fit the whole gate. Compose it instead of clipping the head
        # (tb4n3 RC-2, A5: the clip kept `head[:2000]` and dropped every repair and close
        # instruction, even with hundreds of characters free): the head, one instruction per
        # present item family and the close instruction are required; the re-checks, blocker
        # offer, limitation ids and notes are granted the rest by priority, each with a short
        # form where one exists. Only a re-check whose whole sentence is included is reported as
        # asked, so a re-check that did not fit is asked again at the next Stop.
        parts = _fallback_parts(
            head=head,
            why=why_text,
            items=items,
            premise_text=premise_text,
            offers_blocker=offers_blocker,
            recheck=recheck,
            ack_keys=ack_keys,
            ack_text=ack_text,
            limitations=limitations,
            moved_note=moved_note,
            drain_note=_DRAIN_TEXT if drain_changed_decision else "",
            unconfirmed=unconfirmed_sentence,
            finding_texts=finding_texts,
            withdrawn_text=withdrawn_text,
            lineage=lineage_variants,
            undeclared=undeclared,
            close_text=close,
        )
        composed = compose_parts([part for _, part in parts], _MAX_TEXT_CHARS, ascii_only=False)
        # The predicted conclusion yields before anything else: it is added only when the whole
        # gate fits at full length without it being squeezed in beside a dropped or shortened
        # sentence (Codex round 2).
        if prediction and not (composed.dropped or composed.shortened or composed.cut_required):
            with_tail = [*parts, ("prediction", Part(prediction, priority=10))]
            candidate = compose_parts(
                [part for _, part in with_tail], _MAX_TEXT_CHARS, ascii_only=False
            )
            last = len(with_tail) - 1
            if not candidate.cut_required and all(
                index == last or (index in candidate.kept and index not in candidate.shortened)
                for index in range(len(with_tail))
            ):
                parts, composed = with_tail, candidate
        text = composed.text
        included = {parts[index][0] for index in composed.kept}
        delivered_rows = bool(recheck) and "recheck" in included
        delivered_ack = bool(ack_text) and "ack" in included
        asked_premise = premise is not None and "premise" in included
    withdrawn_keys = (_withdrawn_key(readiness, withdrawn_items),) if withdrawn_items else ()
    return ClosureGate(
        identity,
        text,
        items
        + ((BLOCKER_RECHECK_ITEM,) if delivered_rows else ())
        + ((PREMISE_RECHECK_ITEM,) if asked_premise else ())
        + (ack_items if delivered_ack else ()),
        (keys if delivered_rows else ())
        + (premise_keys if asked_premise else ())
        + (ack_keys if delivered_ack else ())
        + withdrawn_keys,
    )


def _status_request(session_id: str, writer_id: str, actor_id: str) -> StatusRequest:
    # Lazy: the protocol models load pydantic, which the ordinary hook path must not import.
    from finishup.protocol.models import StatusRequest

    request: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": actor_id, "actor_type": "harness"},
        # Frozen legacy identifier (ADR-048): client-info wire enum value.
        "client": {"kind": "yoetz_cli", "version": __version__, "integration": "local_cli"},
        "session_id": session_id,
        "writer_id": writer_id,
        "view": "compact",
        "limit": "1",
        "at_frontier": None,
        "cursor": None,
    }
    return StatusRequest.model_validate(request)


async def read_closure_gate(
    *,
    session_id: str,
    writer_id: str,
    connect: Callable[[ControlClientKind], Awaitable[object]],
    actor_id: str,
    observation_pending: bool,
    reasked_blockers: frozenset[str] = frozenset(),
    active_stop: bool = False,
    code_mode: bool = False,
    advisory_notes: list[str] | None = None,
) -> ClosureGate | None:
    """Read the mapped session's compact status and decide the gate.

    ``None`` means the status was read and closure needs no continuation. A status the service
    could not answer raises ``ClosureGateUnavailable`` so the caller records it as unavailable;
    either way the agent may stop.

    ``code_mode`` is true when the hook observed a recorded code-mode cell for this session.
    The agent's final message is not an input (ADR-033 D1): no Stop item is answered by it.
    """

    # Lazy: only a status read needs the control port and the protocol models (pydantic).
    from finishup.ports.control import ControlClientKind
    from finishup.protocol.models import OperationFailureModel

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
        readiness = getattr(branch, "closure_readiness", None)
        # #1162: the readiness summary is present only while an earlier correctness note has no
        # recorded response. Its text is agent-facing, so the Stop notice is FinishUP's own fixed
        # owner-facing wording, decided by the summary's presence alone.
        note = getattr(readiness, "correctness_advisory_summary", None)
        if advisory_notes is not None and type(note) is str and note:
            advisory_notes.append(STOP_ADVISORY_NOTICE)
        return closure_gate_from_readiness(
            readiness,
            frontier_sequence=sequence,
            frontier_digest=digest,
            observation_pending=observation_pending,
            reasked_blockers=reasked_blockers,
            active_stop=active_stop,
            code_mode=code_mode,
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
    except (OSError, ValueError):
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


def _bounded_keys(keys: list[str]) -> list[str]:
    """The newest keys within the memory bound, keeping the legacy acceptance invites that matter.

    The earliest invite's frontier (memory written before D1; no new ``accept:`` key is written)
    decides which acknowledgement answered an invite, so evicting it would turn a later
    acknowledgement back into a challenge (invite-then-challenge). The earliest invite and the
    newest few are kept; everything else ages out oldest first.
    """

    if len(keys) <= _MAX_BLOCKER_KEYS:
        return keys
    invites = [key for key in keys if key.startswith("accept:")]
    kept_invites = set(invites[:1] + invites[-(_MAX_INVITE_KEYS - 1) :])
    others = [key for key in keys if key not in kept_invites]
    kept = set(others[-(_MAX_BLOCKER_KEYS - len(kept_invites)) :]) | kept_invites
    return [key for key in keys if key in kept]


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
                merged = _bounded_keys(list(dict.fromkeys((*known, *blocker_keys))))
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
