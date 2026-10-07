"""Closed runtime facts a hook derives at the host boundary (issue #977).

The hook process sees each tool call's input before it drops the text. Three facts that matter
for delivery are reduced here to closed tokens and nothing else crosses into the envelope:

* ``install_target`` — where a Python package install lands, judged against the *task
  interpreter*: ``yoetz_runtime`` (Yoetz's own private runtime, the interpreter running this
  hook), ``workspace_env`` (an environment, or a ``--target``/``--prefix``/``--root`` directory,
  inside the workspace), ``private_env`` (a non-task location: another virtual environment, a
  ``--target``/``--prefix``/``--root`` directory outside the workspace, ``pipx``, or an
  interpreter outside any virtual environment when the task interpreter is one), ``system`` (the
  task interpreter itself, or a non-task interpreter this hook cannot tell apart from it) or
  ``unresolved``.

  Yoetz records no task interpreter at setup or session start, so the task interpreter is
  resolved at observation time as the first ``python3`` and the first ``python`` on this hook
  process's ``PATH`` that are not under Yoetz's own runtime. The host spawns the hook with the
  agent's environment, so these are what the agent's shell runs as ``python``; a shell that
  changes ``PATH`` (or activates an environment) before the install can resolve differently, so
  the fact is a disclosure. Interpreters compare by environment root: the parent of the
  executable's directory, resolving directory links only. The executable's own link is never
  followed, so a virtual environment's ``python`` (a link to its base interpreter) stays that
  environment's. Only the existence of ``pyvenv.cfg`` is read. ``--user`` installs into the user
  site of the interpreter running pip, which that (non-virtual-environment) interpreter imports
  for the same user, and pip refuses it inside a virtual environment, so it classifies as that
  interpreter.
* ``write_scope`` — ``outside_workspace`` when an edit tool names a file outside the workspace
  root, or a shell command redirects or ``tee``s into an absolute path outside it. A scratch
  write into a temporary directory (``/tmp``, ``/var/tmp``, ``/dev/shm``, their macOS
  ``/private`` aliases, the per-user macOS ``/var/folders/<a>/<b>/T`` directory, or this
  process's own temporary directory) is not a misplaced deliverable and claims nothing. Paths are
  normalized lexically first, so ``/tmp/../etc/x`` is ``/etc/x``.
* ``effective_user`` — ``root`` or ``non_root``: the effective user this hook process (spawned by
  the host beside the agent's commands) runs as. It says nothing about the delivery environment.

No path, command text or environment value is returned, stored or logged.
"""

from __future__ import annotations

import os
import posixpath
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
_LOCATION_FLAGS: Final = ("--target", "-t", "--prefix", "--root")
# Scratch roots every supported OS reserves for temporary files (issue E6, tb4n1: 28 of 33
# attempts flagged only `/tmp` logs). `/dev/` stays wholly exempt below for device targets.
_TEMP_ROOTS: Final = ("/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/dev/shm")
# macOS per-user temporary directory: `/var/folders/<a>/<b>/T` (the `C` cache sibling is not
# temporary). `/var` is a symlink to `/private/var`, so both spellings name the same directory.
_MACOS_USER_TEMP: Final = re.compile(r"^/(?:private/)?var/folders/[^/]+/[^/]+/T(?:/|$)")


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


def _runtime_prefix() -> str | None:
    """Yoetz's own runtime root, or ``None`` when the hook runs from a system interpreter."""

    runtime = os.path.normpath(os.path.abspath(sys.prefix))
    # Only a virtual environment of its own is Yoetz's private runtime; a hook running from a
    # system interpreter (prefix ``/usr``, ``/usr/local`` or ``/``) says nothing about installs.
    if sys.prefix != sys.base_prefix and runtime not in {"/", "/usr", "/usr/local"}:
        return runtime
    return None


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _environment_root(path: str) -> str:
    """The environment an executable belongs to: its directory's parent, via directory links."""

    return os.path.dirname(os.path.realpath(os.path.dirname(path)))


def _is_venv(root: str) -> bool:
    return os.path.isfile(os.path.join(root, "pyvenv.cfg"))


def _task_roots() -> frozenset[str]:
    """Environment roots of the task interpreter: the agent's ``python3``/``python`` on ``PATH``.

    Observation-time fallback by design: Yoetz records no task interpreter, so this takes the
    first ``python3`` and the first ``python`` on this hook process's ``PATH`` (the agent's),
    skipping Yoetz's own runtime. Empty when neither resolves.
    """

    runtime = _runtime_prefix()
    roots: set[str] = set()
    for name in ("python3", "python"):
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            if not directory:
                continue
            candidate = os.path.normpath(os.path.abspath(os.path.join(directory, name)))
            if runtime is not None and _under(candidate, runtime):
                continue
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                roots.add(_environment_root(candidate))
                break
    return frozenset(roots)


def _interpreter_class(executable: str, workspace: str | None) -> str:
    """Classify one interpreter or pip executable against the task interpreter."""

    if "/" not in executable:
        found = shutil.which(executable)
        if found is None:
            return "unresolved"
        executable = found
    path = os.path.normpath(os.path.abspath(executable))
    if workspace is not None and _under(path, os.path.normpath(os.path.abspath(workspace))):
        return "workspace_env"
    runtime = _runtime_prefix()
    if runtime is not None and _under(path, runtime):
        return "yoetz_runtime"
    if not os.path.exists(path):
        return "unresolved"
    environment = _environment_root(path)
    task = _task_roots()
    if environment in task:
        return "system"
    if _is_venv(environment):
        return "private_env"
    # Outside any virtual environment: a different site-packages than a virtual-environment task
    # interpreter. Against a non-venv task interpreter (or none) a ``pip`` script's interpreter is
    # unknowable without reading it (``/usr/local/bin/pip`` often serves ``/usr/bin/python3``).
    if any(_is_venv(root) for root in task):
        return "private_env"
    return "system"


def _location_option(options: list[str]) -> str | None:
    """The operand of the first ``--target``/``-t``/``--prefix``/``--root`` option, if any."""

    for index, option in enumerate(options):
        for flag in _LOCATION_FLAGS:
            if option == flag and index + 1 < len(options):
                return options[index + 1]
            if flag.startswith("--") and option.startswith(flag + "="):
                return option.split("=", 1)[1]
    return None


def _location_class(location: str, workspace: str | None) -> str:
    """Classify an explicit install directory; inside the workspace is a vendoring choice."""

    if location.startswith("~"):
        location = os.path.expanduser(location)
    if not location.startswith("/") or "$" in location:
        return "unresolved"
    path = os.path.normpath(location)
    if workspace is not None and _under(path, os.path.normpath(os.path.abspath(workspace))):
        return "workspace_env"
    return "private_env"


def _segment_target(segment: list[str], workspace: str | None) -> str | None:
    words = _strip_prefix(segment)
    if not words:
        return None
    head = os.path.basename(words[0])
    rest = words[1:]
    pip_options: list[str] | None = None
    if _PIP_NAME.match(head) and "install" in rest[:2]:
        pip_options = rest[rest.index("install") + 1 :]
    elif _PYTHON_NAME.match(head) and rest[:3] == ["-m", "pip", "install"]:
        pip_options = rest[3:]
    if pip_options is not None:
        location = _location_option(pip_options)
        if location is not None:
            return _location_class(location, workspace)
        return _interpreter_class(words[0], workspace)
    if head == "uv" and rest[:2] == ["pip", "install"]:
        options = rest[2:]
        location = _location_option(options)
        if location is not None:
            return _location_class(location, workspace)
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


def _process_temp_roots(workspace: str | None) -> tuple[str, ...]:
    """This process's own temporary directory roots, from the environment only.

    ``TMPDIR``, ``TEMP`` and ``TMP`` are read lexically and never probed: ``tempfile.gettempdir``
    touches the filesystem, can fall back to the working directory and raises when no directory
    is usable, and an exception here would drop every runtime fact for the event. These values
    are host environment, so a root that is the filesystem root, contains the home directory, or
    is or contains the workspace is never trusted as scratch space.
    """

    home = os.environ.get("HOME")
    guarded = [posixpath.normpath(home)] if home and home.startswith("/") else []
    if workspace is not None and workspace.startswith("/"):
        guarded.append(posixpath.normpath(workspace))
    candidates: set[str] = set()
    for name in ("TMPDIR", "TEMP", "TMP"):
        raw = os.environ.get(name)
        if not raw or not raw.startswith("/") or "\x00" in raw:
            continue
        candidates.add(posixpath.normpath(raw))
    return tuple(
        root
        for root in sorted(candidates)
        if root != "/" and not any(_under(path, root) for path in guarded)
    )


def _scratch_path(path: str, workspace: str | None = None) -> bool:
    """Whether an absolute path lands in a temporary or device directory.

    Normalized lexically first (never through the filesystem), so ``..`` cannot climb out of a
    temporary root while still reading as inside it.
    """

    normalized = posixpath.normpath(path)
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    if normalized.startswith("/dev/"):
        return True
    if _MACOS_USER_TEMP.match(normalized):
        return True
    return any(_under(normalized, root) for root in (*_TEMP_ROOTS, *_process_temp_roots(workspace)))


def _shell_writes_outside(
    command: str, inside: Callable[[str], bool], workspace: str | None = None
) -> bool:
    return any(
        not _scratch_path(target, workspace) and not inside(target)
        for target in _write_targets(command)
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
            path.startswith("/") and not _scratch_path(path, workspace_locator) and not inside(path)
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
    if workspace_locator is not None and _shell_writes_outside(command, inside, workspace_locator):
        facts["write_scope"] = "outside_workspace"
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid):
        facts["effective_user"] = "root" if geteuid() == 0 else "non_root"
    return facts
