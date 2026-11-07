"""Say which FinishUP server's privacy policy a command changes (ADR-051 decision 8).

While a server on another machine, a port or the web is selected, ``finishup privacy tighten``,
``privacy propose`` and the privacy step of ``finishup setup run`` (the trusted questionnaire,
also run by the menu's setup and the terminal interface's first run) change that server's privacy
policy, not this computer's everyday FinishUP's. ``privacy decide-policy`` runs only on the server
host: on this computer it is refused with ``requires_server_host``, whose line names the server.
Following the maintainer's principle "be clear on what happened, why, and that a retry can help",
each of these says, before the change and in its result, which server's policy it changes, by the
target's generated id and closed kind only: a name the owner typed never appears.

The server named is the one this process uses (its resolved root), not the selection file read
afresh: a process that resolved this computer's server before another selected a remote one
still changes this computer's policy, and nothing is said here. A named server on this computer
(the ``local`` kind) is not named here, and neither is a root whose record cannot be read, which
the connection refuses on its own. A caller that prints a result after the change reads the
server once, before the change, and keeps it: the owner may switch servers before the result is
printed (the zero-network choice offers it), and the change stays that server's.

A change that is not a tightening waits on the server for its owner's decision, which runs only
on the server host. Its line names the proposal by its generated id and says until when it can be
decided there (the server's expiry, in UTC), and that making the change again here proposes it
anew once it expired. Setup's next steps on such a server name the same continuation instead of
``finishup --privacy`` and ``finishup --set``, which run only on the server host.

The lines are fixed sentences, the same for a human answer and for JSON. A released output format
keeps its shape: ``privacy tighten|propose`` print the service's result document, so the lines go
to standard error in both modes; the questionnaire and the setup summary are human output and
print them with the rest.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

__all__ = [
    "DECIDE_COMMAND",
    "SHOW_COMMAND",
    "PendingProposal",
    "PolicyServer",
    "selected_policy_server",
]

SHOW_COMMAND: Final = "finishup privacy show"
DECIDE_COMMAND: Final = "finishup privacy decide-policy"
_SETUP_COMMAND: Final = "finishup setup run"
# The closed shapes of a proposal id and its expiry in a ``privacy_propose_policy`` answer
# (control result body ``decision_required``). A value of any other shape is never printed.
_PROPOSAL_ID: Final = re.compile(
    r"ppr_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", re.ASCII
)
_EXPIRES_AT: Final = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}):[0-9]{2}\.[0-9]{3}Z", re.ASCII
)


@dataclass(frozen=True, slots=True)
class PendingProposal:
    """A policy proposal the server holds for its owner's decision, as the server answered it.

    ``proposal_id`` is the server's generated ``ppr_`` id and ``expires_at`` its expiry
    (``YYYY-MM-DDTHH:MM:SS.mmmZ``, UTC); either is printed only in that closed shape.
    """

    proposal_id: str
    expires_at: str | None = None

    @classmethod
    def of(cls, proposal_id: object, expires_at: object) -> PendingProposal | None:
        """The pending proposal named by a string id, or ``None`` without one."""

        if type(proposal_id) is not str:
            return None
        return cls(proposal_id, expires_at if type(expires_at) is str else None)

    @classmethod
    def from_answer(cls, answer: Mapping[str, object]) -> PendingProposal | None:
        """The proposal a ``decision_required`` answer leaves waiting."""

        return cls.of(answer.get("proposal_id"), answer.get("expires_at"))

    @classmethod
    def from_report(cls, report: object) -> PendingProposal | None:
        """The proposal a questionnaire's report (``PrivacySetupReport``) left waiting."""

        return cls.of(getattr(report, "proposal_id", None), getattr(report, "expires_at", None))

    def decide_command(self) -> str | None:
        """``finishup privacy decide-policy <id>``, or ``None`` for an id of another shape."""

        if _PROPOSAL_ID.fullmatch(self.proposal_id) is None:
            return None
        return f"{DECIDE_COMMAND} {self.proposal_id}"

    def deadline(self) -> str:
        """``before <date> <hh:mm> UTC``, rounded down to the minute; or before it expires."""

        match = None if self.expires_at is None else _EXPIRES_AT.fullmatch(self.expires_at)
        if match is None:
            return "before it expires"
        return f"before {match[1]} {match[2]} UTC"


@dataclass(frozen=True, slots=True)
class PolicyServer:
    """The selected server whose privacy policy a command changes: a generated id, a closed kind."""

    target_id: str
    kind: str

    @property
    def server(self) -> str:
        return f"{self.target_id} ({self.kind})"

    def before_line(self) -> str:
        """Said before anything is sent."""

        return (
            f"Privacy policy changes here apply to the selected FinishUP server {self.server}, "
            "not to this computer's everyday FinishUP."
        )

    def applied_line(self) -> str:
        """The server applied the change (a tightening, or a decision that committed)."""

        return (
            f"Changed the privacy policy of the FinishUP server {self.server}; this "
            "computer's everyday FinishUP was not changed."
        )

    def pending_line(self, pending: PendingProposal | None = None) -> str:
        """The server holds a proposal that waits for its owner's decision on the server host.

        Names the proposal and until when it can be decided there; without an id of the closed
        shape (a server that broke its contract), says to make the change again.
        """

        decide = None if pending is None else pending.decide_command()
        what = (
            f"The change waits for a decision on the FinishUP server {self.server}: its policy "
            "has not changed yet, because a trusted decision runs only on that server host."
        )
        if pending is None or decide is None:
            return f"{what} Make the change again here to propose it anew."
        return (
            f"{what} Run '{decide}' on that host {pending.deadline()}; after that it expires "
            "unchanged, and making the change again here proposes it anew."
        )

    def unchanged_line(self) -> str:
        """Nothing was sent, or the answer says nothing changed."""

        return f"The privacy policy of the FinishUP server {self.server} was not changed."

    def unconfirmed_line(self) -> str:
        """The command failed after it may have reached the server: say how to see the policy."""

        return (
            f"No change to the privacy policy of the FinishUP server {self.server} was "
            f"confirmed; '{SHOW_COMMAND}' shows its policy now."
        )

    def answer_line(self, answer: Mapping[str, object]) -> str:
        """The result line for a ``privacy_tighten_policy|privacy_propose_policy`` answer."""

        outcome = answer.get("outcome")
        if outcome == "tightening_applied":
            return self.applied_line()
        if outcome == "decision_required":
            return self.pending_line(PendingProposal.from_answer(answer))
        return self.unconfirmed_line()

    def result_line(self, report: object | None) -> str:
        """The result line for a privacy questionnaire's report (``PrivacySetupReport``).

        ``report`` ``None`` stands for a questionnaire that raised: its change is unconfirmed.
        A report's ``failed`` comes before anything is proposed, so nothing changed.
        """

        from finishup.cli.command_scope import REQUIRES_SERVER_HOST

        if report is None:
            return self.unconfirmed_line()
        outcome = getattr(report, "outcome", None)
        if outcome == "configured":
            return self.applied_line()
        if outcome == "cancelled" and getattr(report, "reason", None) == REQUIRES_SERVER_HOST:
            return self.pending_line(PendingProposal.from_report(report))
        if outcome in {"unchanged", "cancelled", "failed"}:
            return self.unchanged_line()
        return self.unconfirmed_line()

    def summary_suffix(self) -> str:
        """Appended to a setup summary's privacy line."""

        return f" (on the FinishUP server {self.server})"

    def privacy_next_step(self, pending: PendingProposal | None = None) -> str:
        """Setup's privacy next step on this server, in place of ``finishup --privacy``.

        ``finishup --privacy`` runs only on the server host. A proposal left waiting there is
        decided there; anything else is retried by running setup here again.
        """

        decide = None if pending is None else pending.decide_command()
        if pending is None or decide is None:
            return (
                f"rerun '{_SETUP_COMMAND}' here to choose the privacy policy of the FinishUP "
                f"server {self.server}; 'finishup --privacy' runs only on that server host"
            )
        return (
            f"decide the privacy change waiting on the FinishUP server {self.server}: run "
            f"'{decide}' on that server host {pending.deadline()}, or rerun '{_SETUP_COMMAND}' "
            "here to propose it again"
        )

    def credential_next_step(self) -> str:
        """Setup's API-key next step on this server, in place of ``finishup --set``."""

        return (
            "No API key was stored: after that, run 'finishup --set' or 'finishup provider "
            f"credential set' on the host of the FinishUP server {self.server}; they run only "
            "there."
        )


def selected_policy_server() -> PolicyServer | None:
    """The remote server this process's privacy commands change, or ``None``.

    ``None`` for this computer's everyday FinishUP, an isolated root, a named server on this
    computer, and a root that cannot be resolved or whose record cannot be read (the connection
    refuses those on its own). Reads only the target record of the process's resolved root.
    """

    from finishup.client.targets import TargetError, active_target_record

    try:
        record = active_target_record()
    except TargetError:
        return None
    if record is None or not record.is_remote:
        return None
    return PolicyServer(record.target_id, record.kind)
