"""Closed runtime facts a hook derives at the host boundary (issue #977).

The hook process sees each tool call's input before it drops the text. Three facts that matter
for delivery are reduced here to closed tokens and nothing else crosses into the envelope:

* ``install_target`` — where a Python package install resolved its interpreter:
  ``yoetz_runtime`` (Yoetz's own private runtime, the interpreter running this hook),
  ``workspace_env`` (an environment inside the workspace), ``private_env`` (another virtual
  environment outside the workspace), ``system`` (any other interpreter) or ``unresolved``.
  Resolution uses this hook process's ``PATH``, which is the host's environment; a shell that
  changes ``PATH`` before the install can resolve differently, so the fact is a disclosure.
* ``write_scope`` — ``outside_workspace`` when an edit tool names a file outside the workspace
  root, or a shell command redirects or ``tee``s into an absolute path outside it.
* ``effective_user`` — ``root`` or ``non_root``: the effective user this hook process (spawned by
  the host beside the agent's commands) runs as. It says nothing about the delivery environment.

No path, command text or environment value is returned, stored or logged.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import sys
from collections.abc import Callable, Iterator, Mapping
from typing import Final, cast

from yoetz.protocol.canonical import JsonValue

__all__ = [
    "INSTALL_TARGET_VALUES",
    "install_target_class",
    "runtime_structural_facts",
]

INSTALL_TARGET_VALUES: Final = (
    "yoetz_runtime",
    "workspace_env",
    "private_env",
    "system",
    "unresolved",
)
# Ranked: the first class any install segment reaches is reported.
_TARGET_RANK: Final = ("yoetz_runtime", "private_env", "unresolved", "system", "workspace_env")
_SEPARATORS: Final = frozenset({"&&", "||", ";", "|", "&", ";;", "(", ")"})
_PREFIX_COMMANDS: Final = frozenset({"sudo", "env", "command", "exec", "nohup", "time"})
_PIP_NAME: Final = re.compile(r"^pip(?:[0-9]+(?:\.[0-9]+)?)?$", re.ASCII)
_PYTHON_NAME: Final = re.compile(r"^python(?:[0-9]+(?:\.[0-9]+)?)?$", re.ASCII)
_ASSIGNMENT: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=", re.ASCII)
_COMMAND_KEYS: Final = ("cmd", "command", "argv")
_PATCH_TOOLS: Final = frozenset({"apply_patch", "ApplyPatch", "functions.apply_patch"})
_EDIT_TOOLS: Final = frozenset(
    {"Write", "Edit", "MultiEdit", "NotebookEdit", "write_file", "edit_file", "cursor_file_edit"}
)
_EDIT_PATH_KEYS: Final = ("file_path", "path", "target_file", "filePath", "notebook_path")
_HEREDOC: Final = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_PATCH_PATH: Final = re.compile(r"^\*\*\* (?:Add File|Update File|Move to): (.+)$", re.MULTILINE)
_REDIRECT_OPERATORS: Final = frozenset({">", ">>", ">|", "&>", "&>>"})
_SHELL_TOOLS: Final = frozenset({"Bash", "bash", "Shell", "shell", "exec_command", "local_shell"})


def _raw_command(tool_input: Mapping[str, JsonValue]) -> str | None:
    for key in _COMMAND_KEYS:
        value = tool_input.get(key)
        if type(value) is str and value:
            return value
        if type(value) is list and value and all(type(item) is str for item in value):
            return shlex.join(cast(list[str], value))
    return None


def _segments(command: str) -> list[list[str]]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return []
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in _SEPARATORS:
            segments.append([])
        else:
            segments[-1].append(token)
    return [segment for segment in segments if segment]


def _strip_prefix(segment: list[str]) -> list[str]:
    index = 0
    while index < len(segment) and (
        _ASSIGNMENT.match(segment[index]) or segment[index] in _PREFIX_COMMANDS
    ):
        index += 1
    return segment[index:]


def _interpreter_class(executable: str, workspace: str | None) -> str:
    """Classify one interpreter or pip executable by where it lives. Never follows links."""

    if "/" not in executable:
        found = shutil.which(executable)
        if found is None:
            return "unresolved"
        executable = found
    path = os.path.normpath(os.path.abspath(executable))
    if workspace is not None:
        root = os.path.normpath(os.path.abspath(workspace))
        if path == root or path.startswith(root.rstrip("/") + "/"):
            return "workspace_env"
    runtime = os.path.normpath(os.path.abspath(sys.prefix))
    # Only a virtual environment of its own is Yoetz's private runtime; a hook running from a
    # system interpreter (prefix ``/usr``, ``/usr/local`` or ``/``) says nothing about installs.
    if (
        sys.prefix != sys.base_prefix
        and runtime not in {"/", "/usr", "/usr/local"}
        and path.startswith(runtime.rstrip("/") + "/")
    ):
        return "yoetz_runtime"
    environment = os.path.dirname(os.path.dirname(path))
    if os.path.isfile(os.path.join(environment, "pyvenv.cfg")):
        return "private_env"
    return "system"


def _segment_target(segment: list[str], workspace: str | None) -> str | None:
    words = _strip_prefix(segment)
    if not words:
        return None
    head = os.path.basename(words[0])
    rest = words[1:]
    if _PIP_NAME.match(head) and "install" in rest[:2]:
        return _interpreter_class(words[0], workspace)
    if _PYTHON_NAME.match(head) and rest[:3] == ["-m", "pip", "install"]:
        return _interpreter_class(words[0], workspace)
    if head == "uv" and rest[:2] == ["pip", "install"]:
        options = rest[2:]
        for flag in ("--python", "-p"):
            if flag in options:
                position = options.index(flag)
                if position + 1 < len(options):
                    return _interpreter_class(options[position + 1], workspace)
            for option in options:
                if option.startswith(flag + "="):
                    return _interpreter_class(option.split("=", 1)[1], workspace)
        if "--system" in options:
            return "system"
        # Without --python, uv installs into the active or project environment it discovers
        # from the shell's environment, which this hook cannot see.
        return "unresolved"
    if head == "uv" and rest[:1] in (["add"], ["sync"]):
        return "workspace_env"
    if head == "pipx" and rest[:1] == ["install"]:
        return "private_env"
    return None


def install_target_class(command: str, workspace: str | None) -> str | None:
    """The ranked install-target class of a shell command, or ``None`` when it installs nothing."""

    found = {
        target
        for segment in _segments(command)
        if (target := _segment_target(segment, workspace)) is not None
    }
    return next((target for target in _TARGET_RANK if target in found), None)


def _write_targets(command: str) -> list[str]:
    """Absolute redirect and ``tee`` targets, read from shell tokens so quoted text never counts.

    Each heredoc body is dropped first (its lines are data, not shell), then the remaining text is
    tokenized with shell punctuation; only a token that follows a redirect operator, or a ``tee``
    operand, is a target. A command that does not tokenize names no target.
    """

    lines: list[str] = []
    delimiter: str | None = None
    for line in command.split("\n"):
        if delimiter is not None:
            if line.strip() == delimiter:
                delimiter = None
            continue
        lines.append(line)
        match = _HEREDOC.search(line)
        if match is not None:
            delimiter = match.group(2)
    lexer = shlex.shlex("\n".join(lines), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return []
    targets: list[str] = []
    for index, token in enumerate(tokens):
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if token in _REDIRECT_OPERATORS and following is not None:
            targets.append(following)
        elif token == "tee":
            for operand in tokens[index + 1 :]:
                if operand in _SEPARATORS or operand in _REDIRECT_OPERATORS:
                    break
                if not operand.startswith("-"):
                    targets.append(operand)
    return [target for target in targets if target.startswith("/")]


def _shell_writes_outside(command: str, inside: Callable[[str], bool]) -> bool:
    return any(
        not target.startswith("/dev/") and not inside(target) for target in _write_targets(command)
    )


def _edit_paths(
    tool: str, tool_input: Mapping[str, JsonValue], payload: Mapping[str, JsonValue]
) -> Iterator[str]:
    if tool in _PATCH_TOOLS:
        patch = next(
            (
                tool_input[key]
                for key in ("command", "patch", "input")
                if type(tool_input.get(key)) is str
            ),
            None,
        )
        if type(patch) is str:
            yield from (match.strip() for match in _PATCH_PATH.findall(patch))
        return
    source = tool_input if tool_input else payload
    for key in _EDIT_PATH_KEYS:
        value = source.get(key)
        if type(value) is str and value:
            yield value
            return


def runtime_structural_facts(
    payload: Mapping[str, JsonValue],
    *,
    tool_name: str | None,
    workspace_locator: str | None,
    inside: Callable[[str], bool],
) -> dict[str, JsonValue]:
    """Return the closed runtime facts for one tool-call payload (possibly empty).

    ``inside`` answers whether an absolute path lies under the workspace root; it must be the
    same lexical rule the hook uses for captured edit paths. Without a workspace locator no write
    scope is claimed.
    """

    facts: dict[str, JsonValue] = {}
    if tool_name is None:
        return facts
    nested = payload.get("tool_input")
    tool_input = cast(Mapping[str, JsonValue], nested) if isinstance(nested, Mapping) else payload
    lowered = tool_name.casefold()
    is_shell = tool_name in _SHELL_TOOLS or any(
        hint in lowered for hint in ("shell", "exec", "terminal")
    )
    if tool_name in _PATCH_TOOLS or tool_name in _EDIT_TOOLS:
        if workspace_locator is not None and any(
            path.startswith("/") and not inside(path)
            for path in _edit_paths(tool_name, tool_input, payload)
        ):
            facts["write_scope"] = "outside_workspace"
        return facts
    if not is_shell:
        return facts
    command = _raw_command(tool_input)
    if command is None:
        return facts
    target = install_target_class(command, workspace_locator)
    if target is not None:
        facts["install_target"] = target
    if workspace_locator is not None and _shell_writes_outside(command, inside):
        facts["write_scope"] = "outside_workspace"
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid):
        facts["effective_user"] = "root" if geteuid() == 0 else "non_root"
    return facts
