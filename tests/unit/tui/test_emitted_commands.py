"""Every shell command the terminal interface tells a person to run must exist.

The interface hands over to the CLI whenever it cannot finish a ceremony itself
(a passphrase prompt that needs a real terminal, a credential store, a service
start). Those fallbacks are string literals, so nothing at import time notices
when the command they name is renamed or never existed: a person only finds out
after the ceremony has already failed once. This resolves each literal against
the real Typer tree instead, options included.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any, Final

import pytest
import typer.main

_TUI: Final = Path(__file__).resolve().parents[3] / "src" / "finishup" / "tui"

# ``finishup`` followed by one or more subcommand words, then everything up to the
# closing quote of the sentence the command is embedded in (or the end of the
# literal), which is where any options live.
_COMMAND: Final = re.compile(r"\bfinishup((?:\s+[a-z][a-z0-9-]*)+)([^'\"\n]*)")
_OPTION: Final = re.compile(r"--[a-z][a-z0-9-]*")


def _code_strings(path: Path) -> list[str]:
    """Every string literal in the file that is not a docstring, f-string parts included."""

    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = {
        ast.get_docstring(node, clean=False)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    }
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value not in docstrings
    ]


def _emitted_commands() -> list[tuple[str, tuple[str, ...], tuple[str, ...]]]:
    """``(literal, subcommand words, option names)`` for every emitted command."""

    found: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = []
    for path in sorted(_TUI.rglob("*.py")):
        for literal in _code_strings(path):
            for match in _COMMAND.finditer(literal):
                words = tuple(match.group(1).split())
                options = tuple(_OPTION.findall(match.group(2)))
                found.append((f"{path.name}: {literal!r}", words, options))
    return found


def _positional_argument_count(command: Any) -> int:
    return sum(1 for param in command.params if param.param_type_name == "argument")


def _resolve(words: tuple[str, ...]) -> Any:
    """Walk the Typer tree; ``None`` when a word is not a registered subcommand.

    A group may declare positional arguments of its own that precede the
    subcommand name (``finishup integrate {harness} mcp preview``); those words
    are consumed as argument values, not looked up as subcommands.
    """

    from finishup.cli.app import app

    command: Any = typer.main.get_command(app)
    remaining = list(words)
    while remaining:
        subcommands = getattr(command, "commands", None)
        if not subcommands:
            return None
        del remaining[: _positional_argument_count(command)]
        if not remaining:
            return command
        word = remaining.pop(0)
        if word not in subcommands:
            return None
        command = subcommands[word]
    return command


def _leaf_paths() -> set[tuple[str, ...]]:
    from finishup.cli.app import app

    leaves: set[tuple[str, ...]] = set()

    def walk(command: Any, path: tuple[str, ...]) -> None:
        subcommands = getattr(command, "commands", None)
        if not subcommands:
            leaves.add(path)
            return
        for name, child in subcommands.items():
            walk(child, (*path, name))

    walk(typer.main.get_command(app), ())
    return leaves


def test_the_interface_actually_emits_commands() -> None:
    words = {emitted for _, emitted, _ in _emitted_commands()}
    assert ("service", "initialize-passphrase") in words
    assert ("service", "rotate-passphrase") in words
    assert ("service", "run") in words


def test_the_typer_tree_is_the_real_one() -> None:
    leaves = _leaf_paths()
    assert ("service", "initialize-passphrase") in leaves
    assert ("service", "unlock") in leaves
    assert len(leaves) > 50, "the walker is not seeing the registered sub-apps"
    assert _resolve(("service", "initialize-passphrase")) is not None
    assert _resolve(("service", "unlock", "initialize")) is None
    assert _resolve(("service", "no-such-command")) is None
    # ``integrate`` takes the harness id positionally before its subcommand.
    assert _resolve(("integrate", "codex", "mcp", "preview")) is not None
    assert _resolve(("integrate", "codex", "mcp", "no-such-command")) is None


@pytest.mark.parametrize(
    ("literal", "words", "options"),
    [
        pytest.param(*entry, id=" ".join(("finishup", *entry[1], *entry[2])))
        for entry in _emitted_commands()
    ],
)
def test_every_emitted_command_resolves_in_the_cli_tree(
    literal: str, words: tuple[str, ...], options: tuple[str, ...]
) -> None:
    command = _resolve(words)
    assert command is not None, (
        f"{literal} names no registered command 'finishup {' '.join(words)}'"
    )
    registered = {
        opt
        for param in command.params
        for opt in (*getattr(param, "opts", ()), *getattr(param, "secondary_opts", ()))
    }
    unknown = [option for option in options if option not in registered]
    assert unknown == [], (
        f"{literal} uses options 'finishup {' '.join(words)}' does not take: {unknown}"
    )


def test_the_passphrase_fallback_is_the_initialize_ceremony_not_an_unlock_flag() -> None:
    """``finishup service unlock`` takes no ``--initialize``; the regression this guards."""

    assert _resolve(("service", "unlock")) is not None
    unlock_options = {opt for param in _resolve(("service", "unlock")).params for opt in param.opts}
    assert "--initialize" not in unlock_options
    assert _resolve(("service", "initialize-passphrase")) is not None
    app_source = (_TUI / "app.py").read_text(encoding="utf-8")
    assert "service unlock --initialize" not in app_source
    assert app_source.count('fallback_command="finishup service initialize-passphrase"') == 2
