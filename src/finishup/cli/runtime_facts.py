"""Closed runtime facts a hook derives at the host boundary (issue #977).

The hook process sees each tool call's input before it drops the text. Three facts that matter
for delivery are reduced here to closed tokens and nothing else crosses into the envelope:

* ``install_target`` — where a Python package install lands, judged against the *task
  interpreter*: ``yoetz_runtime`` (FinishUP's own private runtime, the interpreter running this
  hook), ``workspace_env`` (an environment, or a ``--target``/``--prefix``/``--root`` directory,
  inside the workspace), ``private_env`` (a non-task location: another virtual environment, a
  ``--target``/``--prefix``/``--root`` directory outside the workspace, ``pipx``, or an
  interpreter outside any virtual environment when the task interpreter is one), ``system`` (the
  task interpreter itself, or a non-task interpreter this hook cannot tell apart from it) or
  ``unresolved``.

  FinishUP records no task interpreter at setup or session start, so the task interpreter is
  resolved at observation time as the first ``python3`` and the first ``python`` on this hook
  process's ``PATH`` that are not under FinishUP's own runtime. The host spawns the hook with the
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
  normalized lexically first, so ``/tmp/../etc/x`` is ``/etc/x``. An edit tool whose every
  path is scratch (a temporary directory outside the workspace) reports ``scratch``, and one whose
  every path is FinishUP's own material (a saved ``finishup_receipt.*``/``finishup_export.*``, FinishUP's state
  or isolation root, ``.agents/plugins/finishup``, ``.agents/skills/finishup``) reports ``yoetz_owned``
  (``domain.write_scope``, ADR-042): neither makes an earlier verification stale.
  A heredoc-fed patch (``apply_patch <<EOF``, ``git apply <<EOF``, ``patch -p1 <<EOF``) writes
  the files its patch headers name, classified the same way (Codex intercepts a sole
  ``apply_patch`` and fires only the pre-event, #1041).
* ``effective_user`` — ``root`` or ``non_root``: the effective user this hook process (spawned by
  the host beside the agent's commands) runs as. It says nothing about the delivery environment.

No path, command text or environment value is returned, stored or logged.
"""

from __future__ import annotations

import contextlib
import os
import posixpath
import re
import shlex
import shutil
import sys
from collections.abc import Callable, Iterator, Mapping
from typing import Final, cast

from finishup.domain.shell_writes import APPLY_PATCH_PATH as _PATCH_PATH
from finishup.domain.shell_writes import (
    SHELL_APPLY_PATCH,
    bound_command,
    heredoc_patch_paths,
    shell_command_text,
    shell_heredocs,
    shell_write_scope,
)
from finishup.domain.write_scope import classify_write_path, edit_write_scope, without_docs_scope
from finishup.protocol.canonical import JsonValue

__all__ = [
    "INSTALL_TARGET_VALUES",
    "SHELL_APPLY_PATCH",
    "finishup_owned_roots",
    "install_target_class",
    "runtime_structural_facts",
    "shell_apply_patch_paths",
    "shell_heredocs",
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
_SHELL_TOOLS: Final = frozenset({"Bash", "bash", "Shell", "shell", "exec_command", "local_shell"})
_LOCATION_FLAGS: Final = ("--target", "-t", "--prefix", "--root")


def shell_apply_patch_paths(command: str) -> tuple[str, ...]:
    """The files a shell heredoc patch names (``domain.shell_writes.heredoc_patch_paths``).

    Codex intercepts a sole ``apply_patch <<EOF`` and applies the patch itself (#1041); a
    ``git apply <<EOF`` or ``patch -p1 <<EOF`` (or an ``apply_patch`` with a test after it) runs
    in the shell. Either way the command's own tokens show no write: the patch's file headers are
    the write, exactly as for the native ``apply_patch`` tool.
    """

    return heredoc_patch_paths(command)


def _raw_command(tool_input: Mapping[str, JsonValue]) -> str | None:
    for key in _COMMAND_KEYS:
        value = tool_input.get(key)
        if type(value) is str and value:
            return value
        if type(value) is list and value and all(type(item) is str for item in value):
            return shlex.join(cast(list[str], value))
    return None


def _segments(command: str) -> list[list[str]]:
    # ``shlex`` builds a token by repeated concatenation: bound the text it reads, as the shell
    # write parser does, so a megabyte of one token cannot stall the hook.
    lexer = shlex.shlex(bound_command(command), posix=True, punctuation_chars=True)
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


# Prefix-command options that take a separate operand (``sudo -u user``, ``env -u NAME``,
# ``time -o file``); every other ``-x`` option of a prefix command takes none.
_PREFIX_OPTIONS_WITH_OPERAND: Final = frozenset(
    {"-u", "-g", "-C", "-D", "-R", "-T", "-h", "-p", "-r", "-t", "-U", "-o", "-f", "-S"}
)


def _strip_prefix(segment: list[str]) -> list[str]:
    index = 0
    while index < len(segment) and (
        _ASSIGNMENT.match(segment[index]) or segment[index] in _PREFIX_COMMANDS
    ):
        prefix = segment[index] in _PREFIX_COMMANDS
        index += 1
        # ``sudo -H -u builder pip install x``: skip the prefix command's own options.
        while prefix and index < len(segment) and segment[index].startswith("-"):
            option = segment[index]
            index += 1
            if option == "--":
                break
            if option in _PREFIX_OPTIONS_WITH_OPERAND and index < len(segment):
                index += 1
    return segment[index:]


def _runtime_prefix() -> str | None:
    """FinishUP's own runtime root, or ``None`` when the hook runs from a system interpreter."""

    runtime = os.path.normpath(os.path.abspath(sys.prefix))
    # Only a virtual environment of its own is FinishUP's private runtime; a hook running from a
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
    """Whether ``root`` is a Python environment of its own: a venv or a conda environment."""

    return os.path.isfile(os.path.join(root, "pyvenv.cfg")) or os.path.isdir(
        os.path.join(root, "conda-meta")
    )


def _task_roots() -> frozenset[str]:
    """Environment roots of the task interpreter: the agent's ``python3``/``python`` on ``PATH``.

    Observation-time fallback by design: FinishUP records no task interpreter, so this takes the
    first ``python3`` and the first ``python`` on this hook process's ``PATH`` (the agent's),
    skipping FinishUP's own runtime. Empty when neither resolves.
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
            # pip's short option also takes its operand attached: ``-t/opt/deps``.
            if flag == "-t" and option.startswith("-t") and len(option) > 2:
                return option[2:]
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


def _owned_roots() -> tuple[str, ...]:
    """FinishUP's own state directory, when this hook process can name it without failing."""

    roots: list[str] = []
    with contextlib.suppress(Exception):
        from finishup.config.paths import isolated_root, state_dir

        isolated = isolated_root()
        if isolated is not None:
            roots.append(str(isolated))
        roots.append(str(state_dir()))
    return tuple(roots)


def finishup_owned_roots() -> tuple[str, ...]:
    """FinishUP's own state and isolation roots (the workspace fingerprint skips them)."""

    return _owned_roots()


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


def _docs_admitted() -> bool:
    from finishup.service import write_scope_admission

    return write_scope_admission.docs_write_scope_admitted()


def _working_directory(
    value: object, workspace_locator: str | None, inside: Callable[[str], bool]
) -> tuple[str | None, bool]:
    """``(directory, relocated)`` for the directory a shell call starts in (#1106 r2).

    An absolute directory at or under the workspace root is where relative writes land. Any
    other stated directory (a relative one, one outside or spelled differently from the root)
    cannot be placed, so a relative write there is never read as documentation.
    """

    if value is None:
        return None, False
    if type(value) is not str or not value or "\x00" in value:
        return None, True
    if workspace_locator is not None and value.startswith("/"):
        normalized = posixpath.normpath(value)
        if normalized == posixpath.normpath(workspace_locator) or inside(normalized):
            return normalized, False
    return None, True


def runtime_structural_facts(
    payload: Mapping[str, JsonValue],
    *,
    tool_name: str | None,
    workspace_locator: str | None,
    inside: Callable[[str], bool],
    working_directory: str | None = None,
    docs_admitted: Callable[[], bool] | None = None,
) -> dict[str, JsonValue]:
    """Return the closed runtime facts for one tool-call payload (possibly empty).

    ``inside`` answers whether an absolute path lies under the workspace root; it must be the
    same lexical rule the hook uses for captured edit paths. Without a workspace locator no write
    scope is claimed. A shell command's relative writes are placed under ``working_directory``
    when given, else under the payload's own ``cwd`` (``domain.shell_writes``).

    ``docs`` is recorded only while ``docs_admitted`` (default: the running service reads the
    class, ``service.write_scope_admission``) says so; otherwise the older class is
    (``domain.write_scope.without_docs_scope``), so a service that predates the class never
    finds a stored row it refuses (#1106 r2).
    """

    admitted = _docs_admitted if docs_admitted is None else docs_admitted

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
        # Classify every written path (tb4n2 R4, ADR-042): only an edit whose every path is
        # scratch (temp roots outside the workspace) or FinishUP-owned (a saved receipt, FinishUP state, the
        # packaged FinishUP trees) is named so; it never makes an earlier verification stale.
        owned = _owned_roots()
        scope = edit_write_scope(
            classify_write_path(
                path,
                workspace=workspace_locator,
                inside=(
                    None if workspace_locator is None or not path.startswith("/") else inside(path)
                ),
                owned_roots=owned,
            )
            for path in _edit_paths(tool_name, tool_input, payload)
        )
        if scope == "docs" and not admitted():
            scope = without_docs_scope(scope, shell=False)
        if scope is not None:
            facts["write_scope"] = scope
        return facts
    if not is_shell:
        return facts
    command = _raw_command(tool_input)
    if command is None:
        return facts
    target = install_target_class(command, workspace_locator)
    if target is not None:
        facts["install_target"] = target
    if workspace_locator is not None:
        # ADR-045: one classifier decides every written path, the one an edit tool uses: a real
        # write outside the workspace, a write into it (an edit), or only notes, FinishUP material
        # (``cp a.json /opt/finishup_receipt.json`` is FinishUP-owned, not outside) or scratch.
        # A heredoc-fed patch (``apply_patch``, ``git apply``, ``patch``) writes the files its
        # headers name (#1046 review, n7 RC2): no shell token shows them, and for an intercepted
        # ``apply_patch`` Codex fires only this pre-event, so this token is the only record that
        # it changed the work.
        # A native argv is read as its script (``["bash", "-lc", SCRIPT]``), so a heredoc patch
        # longer than the token parsers' bound is still named (#1106 r2).
        script = next(
            (
                text
                for key in _COMMAND_KEYS
                if (text := shell_command_text(tool_input.get(key))) is not None and text
            ),
            command,
        )
        start, relocated = _working_directory(
            working_directory if working_directory is not None else payload.get("cwd"),
            workspace_locator,
            inside,
        )
        scope = shell_write_scope(
            script,
            workspace=workspace_locator,
            inside=inside,
            owned_roots=_owned_roots(),
            also_written=shell_apply_patch_paths(script),
            relocated=relocated,
            working_directory=start,
        )
        if scope == "docs" and not admitted():
            scope = without_docs_scope(scope, shell=True)
        if scope is not None:
            facts["write_scope"] = scope
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid):
        facts["effective_user"] = "root" if geteuid() == 0 else "non_root"
    return facts
