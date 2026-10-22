"""The slash-command catalog and its filter.

Every command here is a name for something the command tree already does. The
descriptions are written for someone who has never heard of MCP, hooks, policy
digests, or vaults — that is the whole point of the surface — but the operations
behind them keep their existing gates.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

__all__ = [
    "SLASH_COMMANDS",
    "SlashCommand",
    "command_named",
    "filter_commands",
]


@dataclass(frozen=True, slots=True)
class SlashCommand:
    """One composer command: the token typed, and what it does in plain words."""

    name: str
    summary: str

    @property
    def token(self) -> str:
        return f"/{self.name}"


SLASH_COMMANDS: Final[tuple[SlashCommand, ...]] = (
    SlashCommand("status", "show setup, readiness, and current work"),
    SlashCommand("work", "open a task by session ID to view claims, evidence, and findings"),
    SlashCommand("lineage", "show child tasks, acceptance, and completion gaps"),
    SlashCommand("project", "show project members and coordination state"),
    SlashCommand("findings", "show the task's findings as a to-do list, each with its state"),
    SlashCommand("observe", "show observation selection and change local retention capacity"),
    SlashCommand("check", "run a verification check"),
    SlashCommand("progress", "show the latest check's review phase and elapsed time"),
    SlashCommand("receipt", "view or export an honest receipt"),
    SlashCommand("connect", "connect or repair an agent integration"),
    SlashCommand("coverage", "show advisory, agent-declared test witnesses and candidate gaps"),
    SlashCommand("disconnect", "remove an agent integration and retain FinishUP data"),
    SlashCommand("privacy", "choose what may leave this computer"),
    SlashCommand("provider", "configure optional deeper review"),
    SlashCommand("service", "manage the protected local service"),
    SlashCommand("doctor", "diagnose installation problems"),
    SlashCommand("help", "show what FinishUP can do here"),
    SlashCommand("quit", "leave FinishUP"),
)


def command_named(name: str) -> SlashCommand | None:
    """Resolve an exact command name, with or without its leading slash."""

    token = name.strip()
    if token.startswith("/"):
        token = token[1:]
    token = token.split(maxsplit=1)[0].lower() if token.split() else ""
    for command in SLASH_COMMANDS:
        if command.name == token:
            return command
    return None


def filter_commands(query: str) -> tuple[SlashCommand, ...]:
    """Rank commands for ``query``: exact first, then prefix, then substring.

    Ordering matters more than cleverness here. Someone who has typed ``/st``
    wants ``/status`` on the first row even though ``/service`` also contains an
    ``s`` and a ``t``, so a substring hit never outranks a prefix hit.
    """

    token = query.strip()
    if token.startswith("/"):
        token = token[1:]
    token = token.split(maxsplit=1)[0].lower() if token.split() else ""
    if not token:
        return SLASH_COMMANDS

    exact: list[SlashCommand] = []
    prefix: list[SlashCommand] = []
    contains: list[SlashCommand] = []
    described: list[SlashCommand] = []
    for command in SLASH_COMMANDS:
        if command.name == token:
            exact.append(command)
        elif command.name.startswith(token):
            prefix.append(command)
        elif token in command.name:
            contains.append(command)
        elif token in command.summary:
            described.append(command)
    return tuple(exact + prefix + contains + described)
