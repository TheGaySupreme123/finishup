"""Say which FinishUP server's privacy policy a command changes (ADR-051 decision 8).

While a server on another machine, a port or the web is selected, ``finishup privacy tighten``,
``privacy propose`` and the privacy step of ``finishup setup run`` (the trusted questionnaire,
also run by the menu's setup and the terminal interface's first run) change that server's privacy
policy, not this computer's everyday FinishUP's. ``privacy decide-policy`` runs only on the server
host: on this computer it is refused with ``requires_server_host``, whose line names the server.
Following the maintainer's principle "be clear on what happened", each of these says, before the
change and in its result, which server's policy it changes, by the target's generated id and
closed kind only: a name the owner typed never appears.

The server named is the one this process uses (its resolved root), not the selection file read
afresh: a process that resolved this computer's server before another selected a remote one
still changes this computer's policy, and nothing is said here. A named server on this computer
(the ``local`` kind) is not named here, and neither is a root whose record cannot be read, which
the connection refuses on its own.

The lines are fixed sentences, the same for a human answer and for JSON. The before line says
"selected"; the result lines name the server without it, since the owner may switch servers
before the result is printed (the zero-network choice offers it) and the change stays that
server's. A released output format keeps its shape: ``privacy tighten|propose`` print the
service's result document, so the lines go to standard error in both modes; the questionnaire
and the setup summary are human output and print them with the rest.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

__all__ = [
    "SHOW_COMMAND",
    "PolicyServer",
    "selected_policy_server",
]

SHOW_COMMAND: Final = "finishup privacy show"
# A trusted decision runs only on the server host (ADR-051 decisions 7 and 11).
_DECIDE_ON_SERVER: Final = "decide it with 'finishup privacy decide-policy' on that server host"


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

    def pending_line(self) -> str:
        """The server holds a proposal that waits for its owner's decision on the server host."""

        return (
            f"The change waits for a decision on the FinishUP server {self.server}: its "
            f"policy has not changed yet; {_DECIDE_ON_SERVER}."
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

    def outcome_line(self, outcome: object) -> str:
        """The result line for a ``privacy_tighten_policy|privacy_propose_policy`` answer."""

        if outcome == "tightening_applied":
            return self.applied_line()
        if outcome == "decision_required":
            return self.pending_line()
        return self.unconfirmed_line()

    def report_line(self, outcome: object, reason: object = None) -> str:
        """The result line for a privacy questionnaire's report (``PrivacySetupReport``).

        ``outcome`` ``None`` stands for a questionnaire that raised: its change is unconfirmed.
        A report's ``failed`` comes before anything is proposed, so nothing changed.
        """

        from finishup.cli.command_scope import REQUIRES_SERVER_HOST

        if outcome == "configured":
            return self.applied_line()
        if outcome == "cancelled" and reason == REQUIRES_SERVER_HOST:
            return self.pending_line()
        if outcome in {"unchanged", "cancelled", "failed"}:
            return self.unchanged_line()
        return self.unconfirmed_line()

    def summary_suffix(self) -> str:
        """Appended to a setup summary's privacy line."""

        return f" (on the FinishUP server {self.server})"


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
