"""Tell the owner when this computer forbids network use while a remote server is selected.

ADR-051 decision 8, as the maintainer decided on 2026-11-06. Adding or selecting a FinishUP server
on another machine, a port or the web is refused while this computer's privacy policy forbids all
network use (the zero-network state). When that state is set while such a server is already
selected, FinishUP tells the owner and lets them decide; it never switches servers on its own.

* After a privacy policy change, on the owner's trusted foreground console, it names the selected
  server, says the zero-network setting does not stop traffic to it, and offers two choices:
  switch to this computer's everyday FinishUP now, or keep using the server. Enter, end of input,
  an interrupt or any other answer keeps the server: switching is the one choice that is never
  made for the owner, and under zero-network it cannot be undone without relaxing the policy.
* Without that console, or for a machine-readable answer, it switches nothing and prints the same
  facts on standard error with the one command that switches, ``finishup server use local``, and
  the reminder that open agent sessions must be restarted after switching.
* ``finishup setup``, ``finishup setup status [--next]``, ``finishup server status`` and ``list``,
  the menu, and the terminal interface's ``/server`` and header show the same item while the
  state lasts.

The selection is read from its owner-only file afresh, never from this process's memo, so a
process that resolved its root before the selection changed still sees what new hooks and agent
sessions use. A process whose root an isolation variable or runtime pin decides changes and reads
its own root's policy, not the everyday installation's, and the selection is not used there:
nothing is surfaced in it. A selection that cannot be read is reported with its closed reason and
a continuation, never as "no server". This computer's policy is the everyday installation's
effective machine-scope policy, read from its running service; while it cannot be read, nothing
here claims the zero-network state either way. Targets are named by their generated id and closed
kind only: a name the owner typed never appears.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
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
    "SurfaceOutcome",
    "ZeroNetworkSelection",
    "everyday_network_state",
    "find_zero_network_selection",
    "find_zero_network_selection_async",
    "interactive_terminal",
    "read_selection_on_disk",
    "still_selected",
    "surface_after_policy_change",
    "surface_after_policy_change_async",
]

type NetworkState = Literal["zero_network", "network_permitted", "no_policy", "unreadable"]
type SurfaceOutcome = Literal["clear", "switched", "kept", "warned"]

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
_CHOICE_PROMPT: Final = "Choose 1 or 2 (Enter keeps the server): "


@dataclass(frozen=True, slots=True)
class ZeroNetworkSelection:
    """This computer forbids network use while the selection names, or may name, a remote server.

    ``reason`` is ``zero_network_remote_selected`` (``target_id`` and ``kind`` name it) or
    ``zero_network_selection_unreadable`` (``detail`` is the selection's closed refusal and the
    target is unknown). Every field is a generated id or a closed token.
    """

    reason: Literal["zero_network_remote_selected", "zero_network_selection_unreadable"]
    target_id: str | None = None
    kind: str | None = None
    detail: str | None = None

    @property
    def server(self) -> str:
        return f"{self.target_id} ({self.kind})"

    def lines(self) -> tuple[str, ...]:
        """The facts and the way out, as owner-display lines."""

        if self.reason == REMOTE_SELECTED:
            return (
                "This computer's privacy policy forbids all network use, but the selected "
                f"FinishUP server {self.server} is {_KIND_TEXT.get(str(self.kind), 'remote')}.",
                "The zero-network setting does not stop traffic to it: new hooks, commands and "
                "open agent sessions keep sending your work there.",
                f"To stop, run '{SWITCH_COMMAND}', then restart open agent sessions.",
            )
        return (
            "This computer's privacy policy forbids all network use, and the server selection "
            f"could not be read ({self.detail}), so FinishUP cannot tell whether a server on "
            "another machine is still selected.",
            f"'finishup server status' shows the selection; '{SWITCH_COMMAND}' clears it. Then "
            "restart open agent sessions.",
        )

    def line(self) -> str:
        """One bounded line: the closed reason, then the facts."""

        return f"{self.reason}: " + " ".join(self.lines())

    def next_step(self) -> str:
        """A setup next step: the command, with the closed reason in parentheses."""

        if self.reason == REMOTE_SELECTED:
            return (
                f"run '{SWITCH_COMMAND}', then restart open agent sessions, to stop sending work "
                f"to the server {self.server}: this computer's zero-network policy does not stop "
                f"it ({self.reason})"
            )
        return (
            f"run 'finishup server status' to see the server selection, which could not be read "
            f"({self.detail}) while this computer forbids network use; '{SWITCH_COMMAND}' clears "
            f"it, then restart open agent sessions ({self.reason})"
        )

    def indicator(self) -> str:
        """The terminal interface's header text for this item."""

        if self.reason == REMOTE_SELECTED:
            return f"{self.kind} {self.target_id} · zero-network here does not stop it"
        return f"unreadable ({self.detail}) · zero-network here"

    def fact(self) -> dict[str, JsonValue]:
        """The machine-readable item (closed tokens and a generated id)."""

        return {
            "reason": self.reason,
            "target_id": self.target_id,
            "kind": self.kind,
            "detail": self.detail,
        }


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

    Runs its own event loop, so call it off any running loop (``asyncio.to_thread``).
    """

    import anyio

    from finishup.cli.provider_status import MachineScopeError, machine_scope_request
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

    with selection_override(None):
        if not _everyday_installation_exists():
            return "no_policy"
        try:
            request = machine_scope_request()
        except MachineScopeError:
            permitted = None
        else:
            permitted = anyio.run(effective, request)
    if permitted is None:
        return "unreadable"
    return "network_permitted" if permitted else "zero_network"


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


def find_zero_network_selection() -> ZeroNetworkSelection | None:
    """The item while this computer is in the zero-network state and a remote server is selected.

    ``None`` when nothing is selected, the selection names a server on this computer, this
    process's root is decided by an isolation variable or runtime pin, or this computer's policy
    permits network use, has never been set up, or cannot be read. The selection is read first,
    so the common case asks no service anything. Runs its own event loop when it asks.
    """

    if _explicit_source():
        return None
    selected = _selection_on_disk()
    if selected is None:
        return None
    if not isinstance(selected, str) and not selected.is_remote:
        return None
    from finishup.config.paths import PathSafetyError

    try:
        state = everyday_network_state()
    except (OSError, PathSafetyError, ValueError):
        # A display never fails on this question; the policy is then simply not known.
        return None
    if state != "zero_network":
        return None
    if isinstance(selected, str):
        return ZeroNetworkSelection(SELECTION_UNREADABLE, detail=selected)
    return ZeroNetworkSelection(REMOTE_SELECTED, selected.target_id, selected.kind)


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


def _ask_on_trusted_console(item: ZeroNetworkSelection) -> Literal["switch", "keep"] | None:
    """Offer the choice on the trusted console; ``None`` when there is no such console."""

    from finishup.cli.trusted_console import TrustedConsoleError, TrustedForegroundConsole

    try:
        with TrustedForegroundConsole() as console:
            console.write("\n")
            for line in item.lines()[:2]:
                console.write(line + "\n")
            console.write("  1  Switch to this computer's everyday FinishUP now\n")
            console.write(f"  2  Keep using the server {item.server}\n")
            try:
                chosen = console.read_choice(_CHOICE_PROMPT, (b"1", b"2"))
            except TrustedConsoleError as error:
                if error.reason == "trusted_console_required":
                    raise
                # Enter, end of input, an interrupt or another answer: the safe default keeps it.
                return "keep"
            return "switch" if chosen == b"1" else "keep"
    except TrustedConsoleError:
        return None


def _switch_to_local() -> bool:
    """``finishup server use local``; reports a refusal by its closed reason and fixed text."""

    from finishup.cli.server import ServerCommandRefused, refusal_message, use_target
    from finishup.client.targets import TargetError

    try:
        use_target("local")
    except ServerCommandRefused as error:
        typer.echo(f"{error.reason}: {refusal_message(error)}", err=True)
        return False
    except TargetError as error:
        typer.echo(f"{error.reason}: the server selection was not changed", err=True)
        return False
    typer.echo("Using this computer's everyday FinishUP server.")
    typer.echo(OPEN_SESSIONS_LINE)
    return True


def surface_after_policy_change(*, interactive: bool) -> SurfaceOutcome:
    """After a privacy policy change: tell the owner, and on their console let them decide.

    ``interactive`` says the caller may prompt (a human terminal, not a machine-readable answer).
    Returns ``clear`` when there is nothing to say, ``switched`` or ``kept`` for the owner's choice,
    and ``warned`` when the facts were printed on standard error without a choice. Never switches
    without the owner's explicit answer. Runs its own event loop when it asks the service.
    """

    item = find_zero_network_selection()
    if item is None:
        return "clear"
    if interactive and item.reason == REMOTE_SELECTED:
        choice = _ask_on_trusted_console(item)
        if choice == "switch":
            if _switch_to_local():
                return "switched"
            typer.echo(f"To switch, run '{SWITCH_COMMAND}', then restart open agent sessions.")
            return "warned"
        if choice == "keep":
            typer.echo(
                f"Kept the server {item.server}. Traffic to it continues; to stop it, run "
                f"'{SWITCH_COMMAND}', then restart open agent sessions."
            )
            return "kept"
    typer.echo(
        item.line()
        + ("" if item.reason != REMOTE_SELECTED else " FinishUP did not switch servers."),
        err=True,
    )
    return "warned"


async def surface_after_policy_change_async(*, interactive: bool) -> SurfaceOutcome:
    """``surface_after_policy_change`` from a running event loop (in a worker thread)."""

    import asyncio

    return await asyncio.to_thread(surface_after_policy_change, interactive=interactive)


def interactive_terminal() -> bool:
    """Whether standard input and output are both terminals (a human may answer)."""

    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (OSError, ValueError):
        return False
