"""This computer's zero-network policy and a server elsewhere are never in force together.

ADR-051 decision 8, as the maintainer decided on 2026-11-07 ("remember, and if the owner uses a
remote server it cannot be zero-network"), replacing the 2026-11-06 choice to keep such a server.
This computer's zero-network state is its everyday installation's effective machine-scope
privacy policy forbidding all network use; a remote server is one on another machine, a port or
the web (``ssh``, ``https``, ``local_port``).

* **Remember.** Every time this computer's everyday service reports that policy to a client
  command (``everyday_network_state``, ``privacy show``, and every privacy change made here), the
  client records whether it was zero-network and when (``client.everyday_policy``). The surfaces
  read the live policy first; while it cannot be read (the service is stopped or locked, the
  normal case while a remote server is used) they fall back to that marker and say "this
  computer last reported" it.
* **Adding or selecting a remote server** is refused in the zero-network state, live or last
  reported (``cli.server``).
* **A change that would make this computer zero-network while a remote server is selected**
  (``guard_policy_change``, before anything is applied). On the owner's trusted foreground console
  it offers exactly two choices: ``1`` switch to this computer's everyday FinishUP and make the
  change, or ``2`` cancel the change and keep the server. Enter, end of input, Ctrl-C and any other
  answer cancel; nothing switches without the owner's ``1``. Without that console (a
  machine-readable answer, a decision relayed from an agent, a terminal that is not the owner's)
  the change is refused before it is applied, with ``zero_network_remote_selected`` (or
  ``zero_network_selection_unreadable``) and the one remedy, ``finishup server use local``, then
  the change again. The choice is read on the calling thread, never in a worker that Ctrl-C
  cannot reach.
* **Switching** (the choice ``1``, or ``finishup server use local``) also stops what this client
  runs for the server it leaves, as ``finishup server disconnect`` does (``cli.server.use_target``):
  with the edge relay, that target's connector and the background workspace agents that answer the
  server's reads of files here. Only open agent sessions, until restarted, still reach it.
* **The last line of defence** is the connection check (``targets.require_current_authorization``):
  a process whose selection predates the change is refused before anything is sent, with the same
  token, on every surface.
* **Visible while it lasts.** ``server status [--json]`` and ``list``, ``setup status [--next]``,
  the setup wizard's next steps, the menu home, and the terminal interface's ``/server`` and
  header show the item (``find_zero_network_selection``) while this computer is, or last reported
  being, zero-network and a remote server is, or may be, selected.

The selection is read from its owner-only file afresh, never from this process's memo, so a
process that resolved its root before the selection changed still sees what new hooks and agent
sessions use. A process whose root an isolation variable or runtime pin decides changes and reads
its own root's policy, not the everyday installation's, and the selection is not used there:
nothing here applies to it. A selection that cannot be read is reported with its closed reason
and a continuation, never as "no server". Targets are named by their generated id and closed kind
only: a name the owner typed never appears.

Changing the selected remote server's own policy (``privacy tighten`` or ``propose`` from a
process on that server, ``cli.policy_server``) is that server's policy, not this computer's, and
is not affected.
"""

from __future__ import annotations

import sys
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, cast

import typer

if TYPE_CHECKING:
    from finishup.client.targets import ServerTarget
    from finishup.domain.values import JsonObject
    from finishup.protocol.canonical import JsonValue

__all__ = [
    "OPEN_SESSIONS_LINE",
    "REMOTE_SELECTED",
    "SELECTION_UNREADABLE",
    "SWITCH_COMMAND",
    "NetworkState",
    "PolicyRead",
    "ZeroNetworkChangeStopped",
    "ZeroNetworkSelection",
    "after_policy_change",
    "after_policy_change_async",
    "candidate_forbids_network",
    "everyday_network_state",
    "find_zero_network_selection",
    "find_zero_network_selection_async",
    "guard_policy_change",
    "interactive_terminal",
    "machine_readable_answer",
    "machine_readable_requested",
    "read_selection_on_disk",
    "remember_reported_policy",
    "still_selected",
]

type NetworkState = Literal["zero_network", "network_permitted", "no_policy", "unreadable"]
# How the zero-network state was known: this computer's service answered now (``live``), or it
# could not be asked and the marker says it last reported zero-network (``last_reported``).
type PolicyRead = Literal["live", "last_reported"]

REMOTE_SELECTED: Final = "zero_network_remote_selected"
SELECTION_UNREADABLE: Final = "zero_network_selection_unreadable"
SWITCH_COMMAND: Final = "finishup server use local"
OPEN_SESSIONS_LINE: Final = (
    "New hooks and CLI calls use it now. Restart open agent sessions: a running FinishUP MCP "
    "bridge keeps the server it started with."
)

# Written once, when the everyday installation's vault is initialized.
_INSTALLATION_MARKER: Final = "installation-state.json"
_POLICY_READ_SECONDS: Final = 3.0
_KIND_TEXT: Final[Mapping[str, str]] = {
    "ssh": "on another machine, reached over SSH",
    "https": "reached over HTTPS",
    "local_port": "behind a port on this computer, which can forward anywhere",
}
_CHOICE_PROMPT: Final = "Choose 1 or 2 (Enter cancels the change): "
# Set while a command answers in JSON (``machine_readable_answer``): the choice is never offered.
_MACHINE_READABLE: ContextVar[bool] = ContextVar(
    "finishup_zero_network_machine_readable", default=False
)


@dataclass(frozen=True, slots=True)
class ZeroNetworkSelection:
    """This computer forbids network use while the selection names, or may name, a remote server.

    ``reason`` is ``zero_network_remote_selected`` (``target_id`` and ``kind`` name it) or
    ``zero_network_selection_unreadable`` (``detail`` is the selection's closed refusal and the
    target is unknown). ``policy_read`` says whether this computer's service answered now
    (``live``) or its last report decided (``last_reported``, at ``last_reported_at``). Every
    field is a generated id, a closed token or a fixed-shape UTC time.
    """

    reason: Literal["zero_network_remote_selected", "zero_network_selection_unreadable"]
    target_id: str | None = None
    kind: str | None = None
    detail: str | None = None
    policy_read: PolicyRead = "live"
    last_reported_at: str | None = None

    @property
    def server(self) -> str:
        return f"{self.target_id} ({self.kind})"

    def _policy(self) -> str:
        if self.policy_read == "last_reported":
            return (
                f"This computer last reported, at {self.last_reported_at}, that its privacy "
                "policy forbids all network use (its FinishUP cannot be asked now: it is stopped "
                "or locked)"
            )
        return "This computer's privacy policy forbids all network use"

    def lines(self) -> tuple[str, ...]:
        """The facts and the way out, as owner-display lines."""

        if self.reason == REMOTE_SELECTED:
            return (
                f"{self._policy()}, and the selected FinishUP server {self.server} is "
                f"{_KIND_TEXT.get(str(self.kind), 'remote')}.",
                "FinishUP never uses a server elsewhere in that state: hooks, commands and agent "
                "sessions are refused before anything is sent to it.",
                f"To keep working, run '{SWITCH_COMMAND}', then restart open agent sessions.",
            )
        return (
            f"{self._policy()}, and the server selection could not be read ({self.detail}), so "
            "FinishUP cannot tell whether a server on another machine is selected.",
            f"'finishup server status' shows the selection; '{SWITCH_COMMAND}' clears it. Then "
            "restart open agent sessions.",
        )

    def line(self) -> str:
        """One bounded line: the closed reason, then the facts."""

        return f"{self.reason}: " + " ".join(self.lines())

    def next_step(self) -> str:
        """A setup next step: the command, with the closed reason in parentheses."""

        state = (
            f"this computer last reported, at {self.last_reported_at}, that it makes no network "
            "connections"
            if self.policy_read == "last_reported"
            else "this computer makes no network connections"
        )
        if self.reason == REMOTE_SELECTED:
            return (
                f"run '{SWITCH_COMMAND}', then restart open agent sessions: {state}, so the "
                f"selected server {self.server} is refused ({self.reason})"
            )
        return (
            f"run 'finishup server status' to see the server selection, which could not be read "
            f"({self.detail}) while {state}; '{SWITCH_COMMAND}' clears it, then restart open "
            f"agent sessions ({self.reason})"
        )

    def heading(self) -> str:
        """A short title for the terminal interface's ``/server``."""

        if self.policy_read == "last_reported":
            return "This computer last reported zero-network: the selected server is refused"
        return "This computer is zero-network: the selected server is refused"

    def indicator(self) -> str:
        """The terminal interface's header text for this item."""

        state = (
            "last reported zero-network here"
            if self.policy_read == "last_reported"
            else "zero-network here"
        )
        if self.reason == REMOTE_SELECTED:
            return f"{self.kind} {self.target_id} · refused: {state}"
        return f"unreadable ({self.detail}) · {state}"

    def fact(self) -> dict[str, JsonValue]:
        """The machine-readable item (closed tokens, a generated id and a fixed-shape time)."""

        return {
            "reason": self.reason,
            "target_id": self.target_id,
            "kind": self.kind,
            "detail": self.detail,
            "policy_read": self.policy_read,
            "last_reported_at": self.last_reported_at,
        }


class ZeroNetworkChangeStopped(ValueError):
    """A privacy change that would make this computer zero-network was not applied.

    ``reason`` is ``zero_network_remote_selected`` or ``zero_network_selection_unreadable``;
    ``cancelled`` is True when the owner chose to cancel on the trusted console, False when the
    change was refused without one. The owner was already told what happened, why, and the one
    command that fixes it; callers report the change as not made.
    """

    reason: str
    cancelled: bool

    def __init__(self, reason: str, *, cancelled: bool) -> None:
        self.reason = reason
        self.cancelled = cancelled
        super().__init__(reason)


def _explicit_source() -> bool:
    """Whether an isolation variable or runtime pin decides this process's root.

    Such a process changes and reads its own root's policy, and the selection is not used there.
    A variable or pin that cannot be used still decides: it fails closed on its own path.
    """

    from finishup.config.paths import PathSafetyError, isolated_root_variable, read_runtime_pin

    try:
        return isolated_root_variable() is not None or read_runtime_pin() is not None
    except PathSafetyError:
        return True


def _on_everyday_root() -> bool:
    """Whether this process's FinishUP is this computer's everyday installation.

    Its root is resolved once per process (the memo), so a process that resolved it before a
    remote server was selected is still on this computer's server: its privacy changes are this
    computer's. A root that cannot be resolved is not answered for here; the command's own
    connection reports it.
    """

    from finishup.config.paths import PathSafetyError, active_root

    if _explicit_source():
        return False
    try:
        return active_root() is None
    except PathSafetyError:
        return False


def _everyday_installation_exists() -> bool:
    """Whether this computer's everyday FinishUP was set up (its vault initialized).

    Read under ``selection_override(None)``. The installation marker is written once, when the
    vault is initialized, so its presence means this computer has a privacy policy of its own.
    Anything that keeps the answer from being known (a configuration or folder that cannot be
    read) fails closed: it counts as set up.
    """

    import os

    from finishup.config.load import load_config
    from finishup.config.models import ConfigError
    from finishup.config.paths import PathSafetyError, bundle_root

    try:
        config = load_config({}, os.environ, None)
        (bundle_root(_data_dir=config.storage.data_dir) / _INSTALLATION_MARKER).lstat()
    except FileNotFoundError:
        return False
    except (ConfigError, OSError, PathSafetyError):
        return True
    return True


def everyday_network_state() -> NetworkState:
    """Whether this computer's own FinishUP permits network use (ADR-051 decision 8).

    When its everyday installation was set up, its running service's effective machine-scope
    policy decides (``privacy_get_effective`` for this installation's machine scope: a
    computer-wide question, so no repository is named): ``zero_network`` when that policy does not
    permit network egress, ``network_permitted`` when it does. ``unreadable`` when it cannot be
    read (the service is stopped, locked, or does not answer, or the installation's identity
    cannot be read). ``no_policy`` for a computer whose everyday FinishUP was never set up: it is a
    client of the server it names, and that server's own policy governs its data.

    Each answer the service gives is remembered (``client.everyday_policy``); ``no_policy``
    removes what was remembered, since that installation no longer exists. A process whose root
    an isolation variable or runtime pin decides remembers nothing.

    Runs its own event loop, so call it off any running loop (``asyncio.to_thread``). That loop
    runs in a fresh ``contextvars`` context: ``asyncio.to_thread`` copies the caller's context
    into the worker, and under ``anyio.run`` (every CLI command) that context names the running
    async library, so a nested ``anyio.run`` would refuse with "Already running asyncio in this
    thread". The everyday policy read needs nothing from the caller's context.
    """

    import contextvars

    import anyio

    from finishup.cli.provider_status import MachineScopeError, machine_scope_request
    from finishup.client.everyday_policy import record_reported_policy, remove_marker
    from finishup.config.paths import selection_override
    from finishup.ports.control import ControlClientKind, ControlError
    from finishup.service.client import connect_service

    async def effective(request: JsonObject) -> bool | None:
        try:
            with anyio.fail_after(_POLICY_READ_SECONDS):
                client = await connect_service(ControlClientKind.CLI, workspace_locator=None)
        except (ControlError, TimeoutError):
            return None
        try:
            response = await client.privacy_get_effective(request)
        except ControlError:
            return None
        finally:
            await client.close()
        # The reply is a frozen ``JsonObject`` (a ``Mapping``, not a ``dict``) on the wire.
        policy = response.get("policy")
        if not isinstance(policy, Mapping):
            return None
        return cast(Mapping[str, object], policy).get("network_egress_permitted") is True

    remember = not _explicit_source()
    with selection_override(None):
        if not _everyday_installation_exists():
            if remember:
                remove_marker()
            return "no_policy"
        try:
            request = machine_scope_request()
        except MachineScopeError:
            permitted = None
        else:
            permitted = contextvars.Context().run(anyio.run, effective, request)
    if permitted is None:
        return "unreadable"
    if remember:
        record_reported_policy(zero_network=not permitted)
    return "network_permitted" if permitted else "zero_network"


def remember_reported_policy(response: Mapping[str, object]) -> bool:
    """Remember this computer's policy from a ``privacy_get_effective`` answer it just gave.

    Only an answer of this computer's everyday FinishUP (this process's root is the everyday
    installation, with no isolation variable or pin) for its machine scope counts: a named or
    remote server's policy, or a repository's, is not this computer's. Returns whether the marker
    was written; never raises.
    """

    if not _on_everyday_root():
        return False
    policy = response.get("policy")
    if not isinstance(policy, Mapping):
        return False
    fields = cast(Mapping[str, object], policy)
    scope = fields.get("effective_scope")
    permitted = fields.get("network_egress_permitted")
    if (
        not isinstance(scope, Mapping)
        or cast(Mapping[str, object], scope).get("kind") != "machine"
        or type(permitted) is not bool
    ):
        return False
    from finishup.client.everyday_policy import record_reported_policy

    return record_reported_policy(zero_network=not permitted)


def read_selection_on_disk() -> ServerTarget | str | None:
    """The target the owner-only selection file names, read afresh (never from the memo).

    ``None`` when there is no selection; the target record when it can be read; otherwise the
    closed reason it cannot be (``selection_invalid`` for a damaged file or one naming a folder
    with no record, ``target_root_unsafe``, ``target_record_invalid``, or the everyday folders'
    own path-safety reason).
    """

    from finishup.client.targets import TargetError, read_selected_target_id, read_target
    from finishup.client.targets import target_root as root_of
    from finishup.config.paths import PathSafetyError

    try:
        target_id = read_selected_target_id()
        if target_id is None:
            return None
        record = read_target(root_of(target_id))
    except TargetError as error:
        return error.reason
    except PathSafetyError as error:
        return error.reason_code
    return "selection_invalid" if record is None else record


# The read every check below uses; the test suite replaces it so no test reads a real selection.
_selection_on_disk = read_selection_on_disk


def _remote_on_disk() -> ServerTarget | str | None:
    """The selection on disk when it names, or may name, a remote server; else ``None``."""

    selected = _selection_on_disk()
    if selected is None or (not isinstance(selected, str) and not selected.is_remote):
        return None
    return selected


def _item(
    selected: ServerTarget | str, *, policy_read: PolicyRead = "live", at: str | None = None
) -> ZeroNetworkSelection:
    if isinstance(selected, str):
        return ZeroNetworkSelection(
            SELECTION_UNREADABLE, detail=selected, policy_read=policy_read, last_reported_at=at
        )
    return ZeroNetworkSelection(
        REMOTE_SELECTED,
        selected.target_id,
        selected.kind,
        policy_read=policy_read,
        last_reported_at=at,
    )


def find_zero_network_selection() -> ZeroNetworkSelection | None:
    """The item while this computer is in the zero-network state and a remote server is selected.

    The live policy decides first. When it cannot be read (this computer's service is stopped or
    locked, the normal case while a remote server is used), the marker decides: an item that says
    "this computer last reported" zero-network, with when. ``None`` when nothing is selected, the
    selection names a server on this computer, this process's root is decided by an isolation
    variable or runtime pin, or this computer's policy permits network use, has never been set up,
    or cannot be read and was not last reported zero-network. The selection is read first, so the
    common case asks no service anything. Runs its own event loop when it asks.
    """

    if _explicit_source():
        return None
    selected = _remote_on_disk()
    if selected is None:
        return None
    from finishup.config.paths import PathSafetyError

    try:
        state = everyday_network_state()
    except (OSError, PathSafetyError, ValueError):
        # A display never fails on this question; the marker then decides.
        state = "unreadable"
    if state == "unreadable":
        from finishup.client.everyday_policy import last_reported_zero_network

        reported = last_reported_zero_network()
        if reported is None:
            return None
        return _item(selected, policy_read="last_reported", at=reported.reported_at)
    if state != "zero_network":
        return None
    return _item(selected)


async def find_zero_network_selection_async() -> ZeroNetworkSelection | None:
    """``find_zero_network_selection`` from a running event loop (in a worker thread)."""

    import asyncio

    return await asyncio.to_thread(find_zero_network_selection)


def still_selected(item: ZeroNetworkSelection) -> bool:
    """Whether the selection on disk still names what ``item`` describes (a file read only).

    A cheap re-check for a cached item: the policy fact is not read again, but a selection that
    was switched or cleared elsewhere drops the item rather than showing a stale one.
    """

    if _explicit_source():
        return False
    selected = _selection_on_disk()
    if item.reason == SELECTION_UNREADABLE:
        return isinstance(selected, str)
    return (
        selected is not None
        and not isinstance(selected, str)
        and selected.is_remote
        and selected.target_id == item.target_id
    )


def candidate_forbids_network(candidate: object) -> bool:
    """Whether a candidate policy would make this computer's machine-scope policy zero-network.

    ``candidate`` is a ``PrivacyPolicy`` or its wire JSON (``candidate_policy``). Only a
    machine-scope candidate that does not permit network egress counts: a repository's policy
    narrows that repository, not this computer. Anything that is not a candidate counts as not
    forbidding; the service refuses it on its own.
    """

    if isinstance(candidate, Mapping):
        fields = cast(Mapping[str, object], candidate)
        scope = fields.get("effective_scope")
        return (
            isinstance(scope, Mapping)
            and cast(Mapping[str, object], scope).get("kind") == "machine"
            and fields.get("network_egress_permitted") is False
        )
    from finishup.domain.privacy import AuthorizationScopeKind, PrivacyPolicy

    if type(candidate) is not PrivacyPolicy:
        return False
    return (
        candidate.effective_scope.kind is AuthorizationScopeKind.MACHINE
        and not candidate.network_egress_permitted
    )


@contextmanager
def _interrupt_answers_the_prompt() -> Generator[None]:
    """While the choice is read, Ctrl-C raises ``KeyboardInterrupt`` at the read itself.

    An event loop's runner (``asyncio.run``, ``anyio.run``) answers the first SIGINT by cancelling
    its main task and returning, so a console read blocked on this thread resumes and waits for
    another line (PEP 475): the owner's interrupt would be lost, and a later "1" would still
    switch. Here an interrupt is an answer, and it cancels the change. Python's default handler is
    installed for the read and the previous handler restored after; only on the main thread, and
    only over a handler set from Python (an ignored or default SIGINT is left as it is).
    """

    import signal
    import threading

    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = signal.getsignal(signal.SIGINT)
    if not callable(previous) or previous is signal.default_int_handler:
        yield
        return
    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


def _change_lines(item: ZeroNetworkSelection) -> tuple[str, str]:
    """What the change would do and why both cannot stay (the console's first two lines)."""

    if item.reason == REMOTE_SELECTED:
        first = (
            "This change makes this computer's FinishUP make no network connections, but the "
            f"selected FinishUP server {item.server} is "
            f"{_KIND_TEXT.get(str(item.kind), 'remote')}."
        )
    else:
        first = (
            "This change makes this computer's FinishUP make no network connections, and the "
            f"server selection could not be read ({item.detail}), so a server on another machine "
            "may still be selected."
        )
    return (
        first,
        "FinishUP never uses a server elsewhere while this computer makes no network "
        "connections, so both cannot stay.",
    )


def _ask_before_change(item: ZeroNetworkSelection) -> Literal["switch", "cancel"] | None:
    """Offer the two choices on the trusted console; ``None`` when there is no such console.

    Runs on the calling thread: an interrupt reaches the read and cancels the change.
    """

    from finishup.cli.trusted_console import TrustedConsoleError, TrustedForegroundConsole

    keep = (
        f"Cancel this change and keep using the server {item.server}"
        if item.reason == REMOTE_SELECTED
        else "Cancel this change and keep the server selection as it is"
    )
    try:
        with _interrupt_answers_the_prompt(), TrustedForegroundConsole() as console:
            console.write("\n")
            for line in _change_lines(item):
                console.write(line + "\n")
            console.write("  1  Switch to this computer's everyday FinishUP and make this change\n")
            console.write(f"  2  {keep}\n")
            try:
                chosen = console.read_choice(_CHOICE_PROMPT, (b"1", b"2"))
            except TrustedConsoleError as error:
                if error.reason == "trusted_console_required":
                    raise
                if error.reason in {"cancelled", "eof", "interrupted"}:
                    # No newline was echoed for Ctrl-C or Ctrl-D: end the prompt's line.
                    console.write("\n")
                # Enter, end of input, an interrupt or another answer: the safe default cancels.
                return "cancel"
            return "switch" if chosen == b"1" else "cancel"
    except TrustedConsoleError:
        return None
    except KeyboardInterrupt:
        # Ctrl-C while the choices were shown but before the read began: it cancels too.
        return "cancel"


def _switch_to_local() -> bool:
    """``finishup server use local``; reports a refusal by its closed reason and fixed text."""

    from finishup.cli.server import ServerCommandRefused, refusal_message, use_target
    from finishup.client.targets import TargetError

    try:
        switch = use_target("local")
    except ServerCommandRefused as error:
        typer.echo(f"{error.reason}: {refusal_message(error)}", err=True)
        return False
    except TargetError as error:
        typer.echo(f"{error.reason}: the server selection was not changed", err=True)
        return False
    typer.echo("Using this computer's everyday FinishUP server.")
    # The switch also stopped what this client ran for the server (its connection and the
    # background workspace agents that answer that server's reads); say so, or how to finish it.
    for line in switch.left_lines():
        typer.echo(line, err=switch.left_open)
    typer.echo(OPEN_SESSIONS_LINE)
    return True


def _refusal_line(item: ZeroNetworkSelection) -> str:
    """The bounded refusal line without the trusted console: what, why, and the one remedy."""

    if item.reason == REMOTE_SELECTED:
        why = (
            "this change would make this computer's FinishUP make no network connections while "
            f"the selected FinishUP server {item.server} is on another machine, a port or the "
            "web, and FinishUP never uses a server elsewhere in that state"
        )
    else:
        why = (
            "this change would make this computer's FinishUP make no network connections, and "
            f"the server selection could not be read ({item.detail}), so a server elsewhere may "
            "still be selected"
        )
    return (
        f"{item.reason}: {why}; nothing was changed. Run '{SWITCH_COMMAND}' in your own "
        "terminal, then make the change again."
    )


def guard_policy_change(
    *, forbids_network: bool, interactive: bool
) -> Literal["clear", "switched"]:
    """Before a privacy change is applied: never leave zero-network and a remote server together.

    ``forbids_network`` says the change would make this computer's machine-scope policy
    zero-network (``candidate_forbids_network``); ``interactive`` that the caller may prompt (a
    human terminal, not a machine-readable answer or a relayed decision). Applies only to a change
    of this computer's own policy, from a process on its everyday installation, while the
    selection on disk names (or may name) a remote server; ``clear`` otherwise.

    On the trusted console the owner chooses: ``1`` switches to this computer's everyday
    FinishUP (``switched``: the caller then applies the change), anything else cancels. Without
    that console the change is refused. A cancel or a refusal raises ``ZeroNetworkChangeStopped``
    after the owner was told what happened, why, and ``finishup server use local``; nothing was
    applied. Reads only the selection file, so it runs on the calling thread, where an interrupt
    reaches the prompt.
    """

    if not forbids_network or not _on_everyday_root():
        return "clear"
    selected = _remote_on_disk()
    if selected is None:
        return "clear"
    item = _item(selected)
    if interactive and not machine_readable_requested():
        choice = _ask_before_change(item)
        if choice == "switch":
            if _switch_to_local():
                return "switched"
            typer.echo(
                "Nothing was changed: the switch did not happen, so this computer's privacy "
                "policy is as it was.",
                err=True,
            )
            raise ZeroNetworkChangeStopped(item.reason, cancelled=True)
        if choice == "cancel":
            kept = (
                f"the server {item.server} stays selected"
                if item.reason == REMOTE_SELECTED
                else "the server selection is as it was"
            )
            typer.echo(
                f"Cancelled: nothing was changed. This computer's privacy policy is as it was, "
                f"and {kept}."
            )
            raise ZeroNetworkChangeStopped(item.reason, cancelled=True)
    typer.echo(_refusal_line(item), err=True)
    raise ZeroNetworkChangeStopped(item.reason, cancelled=False)


def _read_after_change() -> NetworkState:
    return everyday_network_state()


# The live read after a change; the test suite replaces it so no test reaches a real service.
_after_change_state = _read_after_change


def _after_change_read() -> NetworkState:
    from finishup.config.paths import PathSafetyError

    try:
        return _after_change_state()
    except (OSError, PathSafetyError, ValueError):
        return "unreadable"


def _say_if_both(state: NetworkState) -> None:
    if state != "zero_network":
        return
    selected = _remote_on_disk()
    if selected is not None:
        # A server elsewhere was selected while the change was being made (``server use`` in
        # another terminal): connections to it are refused; say so, and the way out.
        typer.echo(_item(selected).line(), err=True)


def after_policy_change() -> None:
    """After a committed change of this computer's privacy policy: remember what it is now.

    Reads this computer's policy again (``everyday_network_state``, which records the marker), so
    the zero-network state is remembered for when this computer's service can no longer be asked.
    Only for a process on this computer's everyday installation: a change made on a remote server
    is that server's. If a remote server was selected meanwhile, says so on stderr. Runs its own
    event loop; call ``after_policy_change_async`` from a running one.
    """

    if not _on_everyday_root():
        return
    _say_if_both(_after_change_read())


async def after_policy_change_async() -> None:
    """``after_policy_change`` from a running event loop (the read in a worker thread)."""

    import asyncio

    if not _on_everyday_root():
        return
    _say_if_both(await asyncio.to_thread(_after_change_read))


@contextmanager
def machine_readable_answer(enabled: bool = True) -> Generator[None]:
    """While the command answers in JSON, a privacy change here never offers the choice.

    ADR-051 decision 8: for a machine-readable answer a change that would leave this computer
    zero-network with a remote server selected is refused, and standard output keeps the document
    alone; the refusal and ``finishup server use local`` go to standard error. A command whose
    policy change happens several calls down (the privacy setting commands) sets this once around
    them, for the current task's context only.
    """

    token = _MACHINE_READABLE.set(enabled)
    try:
        yield
    finally:
        _MACHINE_READABLE.reset(token)


def machine_readable_requested() -> bool:
    """Whether the running command asked for a machine-readable answer (see above)."""

    return _MACHINE_READABLE.get()


def interactive_terminal() -> bool:
    """Whether standard input and output are both terminals (a human may answer)."""

    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (OSError, ValueError):
        return False
