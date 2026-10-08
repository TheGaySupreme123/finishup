"""Conservative, versioned selection facts for hook observations.

Host payloads are untrusted input.  A host-supplied ``action`` label, a nested
action label, or an agent-facing tool name cannot grant routine treatment.  The
closed tool names, the small shell grammar, and closed outcome facts below are
the only inputs that can produce the service-owned routine marker.

This result is a local retention hint, not an authorship, privacy, or execution
proof.  A routine candidate is not a proven successful read until a terminal
post-event supplies a closed success fact.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Literal, cast

from yoetz.protocol.canonical import JsonValue as CanonicalJsonValue
from yoetz.protocol.canonical import strict_json_parse
from yoetz.protocol.errors import ProtocolValueError

OBSERVATION_CLASSIFICATION_VERSION: Final = "obs-selection/1.0.0"
"""Version of the closed per-observation classification rules."""

# This alias gives callers using issue terminology a stable name while keeping
# the settings module's ``ObservationSelection`` value separate.
OBSERVATION_SELECTION_VERSION: Final = OBSERVATION_CLASSIFICATION_VERSION

ObservationContentRoleValue = Literal["none", "tool_input", "tool_output", "both"]


class ObservationContentRole(StrEnum):
    """Which bounded content arm may be considered by a caller."""

    NONE = "none"
    TOOL_INPUT = "tool_input"
    TOOL_OUTPUT = "tool_output"
    BOTH = "both"


ObservationReasonToken = Literal[
    "routine_tool",
    "routine_shell",
    "routine_candidate",
    "routine_success",
    "incomplete",
    "failure",
    "denied",
    "cancelled",
    "partial",
    "unknown",
    "edit",
    "test",
    "verification",
    "ambiguous_shell",
    "unsafe_shell",
    "unknown_tool",
    "unknown_operation",
    "untrusted_action",
]

RunnerClass = Literal[
    "exploration",
    "test",
    "build",
    "lint",
    "typecheck",
    "vcs",
    "other",
    "compound",
]

ROUTINE_READ_TOOLS: Final = frozenset(
    {
        "glob",
        "grep",
        "list_files",
        "read",
        "read_file",
        "search",
        "view_file",
    }
)

SHELL_TOOLS: Final = frozenset(
    {"bash", "command", "exec", "exec_command", "local_shell", "run_terminal_cmd", "shell"}
)

READ_ONLY_COMMANDS: Final = frozenset({"head", "ls", "pwd", "rg", "tail", "wc"})

_PRE_EVENTS: Final = frozenset({"PreToolUse", "preToolUse"})
_POST_EVENTS: Final = frozenset(
    {"PostToolUse", "postToolUse", "PostToolUseFailure", "postToolUseFailure"}
)
_MAX_RESULT_JSON_BYTES: Final = 65_536
_MAX_COMMAND_CHARS: Final = 16_384

_SUCCESS_STATUSES: Final = frozenset(
    {"complete", "completed", "ok", "passed", "success", "succeeded"}
)
_FAILURE_STATUSES: Final = {
    "aborted": "failure",
    "canceled": "cancelled",
    "cancelled": "cancelled",
    "denied": "denied",
    "error": "failure",
    "errored": "failure",
    "failed": "failure",
    "failure": "failure",
    "interrupted": "cancelled",
    "nonzero": "failure",
    "nonzero_exit": "failure",
    "permission_denied": "denied",
    "timed_out": "failure",
    "timeout": "failure",
}
_PARTIAL_STATUSES: Final = frozenset({"partial", "partially_completed"})
_SHELL_WRAPPERS: Final = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
_SHELL_COMMAND_FLAG_RE: Final = re.compile(r"^-[a-z]*c[a-z]*$", re.ASCII)

# ``rg --pre`` and related forms invoke an arbitrary preprocessor.  Git's
# ext-diff/textconv/output paths likewise cross the read-only boundary.
_RG_PRE_OPTIONS: Final = frozenset({"--pre", "--pre-glob", "--pre-files"})
_GIT_SIDE_EFFECT_PREFIXES: Final = ("--output=", "--ext-diff=", "--textconv=")
_GIT_SIDE_EFFECT_OPTIONS: Final = frozenset(
    {"--ext-diff", "--output", "-o", "--textconv", "--filters"}
)

_EDIT_TOOL_HINTS: Final = frozenset(
    {
        "apply_patch",
        "create_file",
        "delete",
        "delete_file",
        "edit",
        "insert",
        "mkdir",
        "move",
        "patch",
        "remove",
        "rename",
        "replace",
        "update_file",
        "write",
        "write_file",
    }
)
_TEST_TOOL_HINTS: Final = frozenset(
    {"cargo_test", "jest", "mocha", "nox", "pytest", "test", "tox", "vitest"}
)
_VERIFICATION_TOOL_HINTS: Final = frozenset(
    {"assert", "check", "lint", "review", "typecheck", "verify"}
)
_EDIT_COMMANDS: Final = frozenset(
    {
        "apply_patch",
        "cp",
        "install",
        "mkdir",
        "mv",
        "perl",
        "rm",
        "rmdir",
        "sed",
        "tee",
        "touch",
    }
)
_TEST_COMMANDS: Final = frozenset(
    {
        "cargo",
        "go",
        "jest",
        "make",
        "mocha",
        "mypy",
        "nox",
        "npm",
        "pnpm",
        "pytest",
        "pyright",
        "ruff",
        "tox",
        "tsc",
        "uv",
        "vitest",
        "yarn",
    }
)


@dataclass(frozen=True, slots=True)
class ObservationClassification:
    """Closed selection facts derived from one host observation."""

    protected: bool
    routine_candidate: bool
    proven_routine_success: bool
    content_role: ObservationContentRole
    reason_tokens: tuple[str, ...]
    version: str = OBSERVATION_CLASSIFICATION_VERSION

    def __post_init__(self) -> None:
        if type(self.protected) is not bool:
            raise TypeError("observation_classification_protected_invalid")
        if type(self.routine_candidate) is not bool:
            raise TypeError("observation_classification_routine_candidate_invalid")
        if type(self.proven_routine_success) is not bool:
            raise TypeError("observation_classification_success_invalid")
        if type(self.content_role) is not ObservationContentRole:
            raise TypeError("observation_classification_content_role_invalid")
        if type(self.version) is not str or self.version != OBSERVATION_CLASSIFICATION_VERSION:
            raise ValueError("observation_classification_version_invalid")
        if type(self.reason_tokens) is not tuple or any(
            type(token) is not str or not token for token in self.reason_tokens
        ):
            raise TypeError("observation_classification_reasons_invalid")
        if self.proven_routine_success and not self.routine_candidate:
            raise ValueError("observation_classification_success_without_candidate")
        if self.proven_routine_success and self.protected:
            raise ValueError("observation_classification_success_protected")

    @property
    def routine_read(self) -> bool:
        """Return whether the adapter may emit its service-owned marker."""

        return self.routine_candidate and self.proven_routine_success

    @property
    def reasons(self) -> tuple[str, ...]:
        """Compatibility spelling for callers that use the shorter name."""

        return self.reason_tokens


@dataclass(frozen=True, slots=True)
class _RoutineFacts:
    candidate: bool
    reason: ObservationReasonToken


@dataclass(frozen=True, slots=True)
class _OutcomeFacts:
    state: Literal["success", "failure", "denied", "cancelled", "partial", "unknown"] | None


def _classification_token(value: object) -> str | None:
    if type(value) is not str or not value or len(value) > 256:
        return None
    return value


def _bounded_result_mapping(value: object) -> Mapping[str, CanonicalJsonValue] | None:
    if isinstance(value, Mapping):
        return cast(Mapping[str, CanonicalJsonValue], value)
    if type(value) is not str or not value:
        return None
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if len(encoded) > _MAX_RESULT_JSON_BYTES:
        return None
    try:
        parsed = strict_json_parse(encoded)
    except ProtocolValueError, TypeError, ValueError:
        return None
    return cast(Mapping[str, CanonicalJsonValue], parsed) if isinstance(parsed, Mapping) else None


def _classification_result_mappings(
    payload: Mapping[str, CanonicalJsonValue],
) -> tuple[Mapping[str, CanonicalJsonValue], ...]:
    """Collect bounded result carriers without traversing arbitrary content."""

    mappings: list[Mapping[str, CanonicalJsonValue]] = [payload]
    for key in ("tool_response", "tool_output", "result", "result_json"):
        mapping = _bounded_result_mapping(payload.get(key))
        if mapping is None:
            continue
        mappings.append(mapping)
        for nested_key in ("structuredContent", "structured_content", "data", "result"):
            nested = _bounded_result_mapping(mapping.get(nested_key))
            if nested is not None:
                mappings.append(nested)
    return tuple(mappings)


def _classification_outcome(
    payload: Mapping[str, CanonicalJsonValue], event_name: str
) -> _OutcomeFacts:
    """Reduce closed host outcome fields to one conservative state."""

    hook_event = payload.get("hook_event_name")
    denied = event_name in {"PermissionDenied", "permission_denied"}
    cancelled = False
    failure = event_name in {
        "PostToolUseFailure",
        "postToolUseFailure",
        "StopFailure",
    } or hook_event in {
        "PostToolUseFailure",
        "postToolUseFailure",
        "StopFailure",
    }
    partial = False
    success = False
    unknown = False
    invalid_exit = False
    valid_exits: list[int] = []

    for mapping in _classification_result_mappings(payload):
        for key in ("denied", "is_denied", "permission_denied"):
            if type(mapping.get(key)) is bool and mapping.get(key) is True:
                denied = True
        for key in (
            "interrupted",
            "is_interrupted",
            "is_interrupt",
            "isInterrupted",
            "cancelled",
            "canceled",
            "is_cancelled",
            "isCanceled",
        ):
            if type(mapping.get(key)) is bool and mapping.get(key) is True:
                cancelled = True
        for key in ("is_error", "isError", "failed"):
            value = mapping.get(key)
            if type(value) is bool:
                if value:
                    failure = True
                elif key in {"is_error", "isError"}:
                    # A protocol-level false error bit is a closed success fact.
                    success = True
        for key in ("success", "ok"):
            value = mapping.get(key)
            if type(value) is bool:
                if value:
                    success = True
                else:
                    failure = True
        for key in ("exit_code", "exitCode", "exit_status", "exitStatus"):
            if key not in mapping:
                continue
            value = mapping.get(key)
            if type(value) is int and not isinstance(value, bool) and -1 <= value <= 255:
                valid_exits.append(value)
            else:
                invalid_exit = True
        for key in (
            "result_status",
            "status",
            "outcome",
            "failure_type",
            "permission_decision",
        ):
            if key not in mapping:
                continue
            value = _classification_token(mapping.get(key))
            if value is None:
                if mapping.get(key) is not None:
                    unknown = True
                continue
            lowered = value.casefold()
            if lowered in _FAILURE_STATUSES:
                state = _FAILURE_STATUSES[lowered]
                if state == "denied":
                    denied = True
                elif state == "cancelled":
                    cancelled = True
                else:
                    failure = True
            elif lowered in _SUCCESS_STATUSES:
                success = True
            elif lowered in _PARTIAL_STATUSES:
                partial = True
            else:
                unknown = True
        if "error" in mapping:
            value = mapping.get("error")
            if value not in (None, False, ""):
                failure = True

    # A background launch has no terminal result at this event boundary.
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, Mapping) and tool_input.get("run_in_background") is True:
        partial = True

    # Native Claude/Cursor post hooks are themselves the host's closed success
    # signal when no more specific result fact is present.  Require the
    # validated hook-event echo so an ordinary mapping call with no outcome is
    # still classified as unknown.  Explicit failure, partial, invalid, or
    # unknown facts above always win over this fallback.
    native_post_success = (
        event_name in {"PostToolUse", "postToolUse"}
        and payload.get("hook_event_name") == event_name
    )
    if native_post_success and not (
        denied
        or cancelled
        or failure
        or partial
        or success
        or unknown
        or invalid_exit
        or valid_exits
    ):
        success = True

    if denied:
        return _OutcomeFacts("denied")
    if cancelled:
        return _OutcomeFacts("cancelled")
    if failure or any(value != 0 for value in valid_exits):
        return _OutcomeFacts("failure")
    if partial:
        return _OutcomeFacts("partial")
    if invalid_exit or unknown:
        return _OutcomeFacts("unknown")
    if valid_exits:
        return _OutcomeFacts("success" if all(value == 0 for value in valid_exits) else "failure")
    if success:
        return _OutcomeFacts("success")
    return _OutcomeFacts(None)


def _has_untrusted_routine_label(payload: Mapping[str, CanonicalJsonValue]) -> bool:
    """Detect labels that must never be used as routine authority."""

    token = _classification_token(payload.get("action"))
    if token is not None and token.casefold() == "routine_read":
        return True
    nested = payload.get("tool_input")
    if isinstance(nested, Mapping):
        token = _classification_token(nested.get("action"))
        if token is not None and token.casefold() == "routine_read":
            return True
    return False


def _routine_shell_reason(command: str, argv: list[str]) -> ObservationReasonToken:
    lowered = command.casefold()
    if lowered in _EDIT_COMMANDS:
        return "edit"
    if lowered == "git" and len(argv) >= 2 and argv[1] == "diff" and "--check" in argv[2:]:
        return "verification"
    if lowered in _TEST_COMMANDS:
        return "test"
    if lowered in {"check", "lint", "review", "verify", "typecheck"}:
        return "verification"
    return "unknown_operation"


def _routine_shell_facts(payload: Mapping[str, CanonicalJsonValue]) -> _RoutineFacts:
    nested = payload.get("tool_input")
    if not isinstance(nested, Mapping):
        return _RoutineFacts(False, "ambiguous_shell")
    raw = nested.get("cmd")
    if type(raw) is not str or not raw:
        raw = nested.get("command")
    if type(raw) is not str or not raw or len(raw) > _MAX_COMMAND_CHARS:
        return _RoutineFacts(False, "ambiguous_shell")
    # Shell composition, controls, and substitutions require a real shell parser.
    if "\x00" in raw or any(
        marker in raw for marker in ("\n", "\r", ";", "&", "|", ">", "<", "`", "$(")
    ):
        return _RoutineFacts(False, "ambiguous_shell")
    try:
        argv = shlex.split(raw, posix=True)
    except ValueError:
        return _RoutineFacts(False, "ambiguous_shell")
    if not argv:
        return _RoutineFacts(False, "ambiguous_shell")
    command = argv[0]
    if "/" in command or "\\" in command:
        return _RoutineFacts(False, "ambiguous_shell")
    lowered = command.casefold()
    if lowered in READ_ONLY_COMMANDS:
        if lowered == "rg":
            for argument in argv[1:]:
                option = argument.partition("=")[0].casefold()
                if option in _RG_PRE_OPTIONS or option.startswith("--pre"):
                    return _RoutineFacts(False, "unsafe_shell")
        return _RoutineFacts(True, "routine_shell")
    if lowered != "git" or len(argv) < 2:
        return _RoutineFacts(False, _routine_shell_reason(command, argv))
    for argument in argv[1:]:
        option = argument.casefold()
        if (
            option in _GIT_SIDE_EFFECT_OPTIONS
            or any(option.startswith(prefix) for prefix in _GIT_SIDE_EFFECT_PREFIXES)
            or "textconv" in option
            or "ext-diff" in option
        ):
            return _RoutineFacts(False, "unsafe_shell")
    subcommand = argv[1]
    if subcommand not in {"diff", "log", "rev-parse", "show", "status"}:
        return _RoutineFacts(False, _routine_shell_reason(command, argv))
    if subcommand == "diff" and "--check" in argv[2:]:
        return _RoutineFacts(False, "verification")
    return _RoutineFacts(True, "routine_shell")


# Flags that make a verifier report on itself instead of verifying anything.
_INFORMATION_FLAGS: Final = frozenset({"--help", "-h", "--version", "-V"})
_VERIFYING_CLASSES: Final = frozenset({"test", "lint", "typecheck", "build"})


def _runner_class_for_argv(argv: list[str]) -> RunnerClass | None:
    """``_classify_argv`` with information-only invocations demoted (Codex review round 3).

    ``python -m unittest --help`` or ``ruff --version`` verifies nothing, so it never counts as a
    verification run.
    """

    runner = _classify_argv(argv)
    if runner in _VERIFYING_CLASSES and any(
        argument in _INFORMATION_FLAGS for argument in argv[1:]
    ):
        return "other"
    return runner


def _classify_argv(argv: list[str]) -> RunnerClass | None:
    if not argv:
        return None
    if "/" in argv[0] or "\\" in argv[0]:
        return "other"
    command = argv[0].rsplit("/", 1)[-1].casefold()
    if command in _SHELL_WRAPPERS and len(argv) >= 3 and _SHELL_COMMAND_FLAG_RE.fullmatch(argv[1]):
        return command_runner_class({"command": argv[2]})
    wrapped = _run_wrapper_target(command, argv)
    if wrapped is not None:
        # ``uv run python build_model.py`` is the wrapped command, classified on its own; the
        # wrapper's name never makes a script a build or a test (ADR-042).
        return _runner_class_for_argv(wrapped)
    if command == "rg" and any(
        argument.partition("=")[0].casefold() in _RG_PRE_OPTIONS
        or argument.casefold().startswith("--pre")
        for argument in argv[1:]
    ):
        return "other"
    if command == "find" and any(
        argument.casefold()
        in {"-exec", "-execdir", "-delete", "-write", "-fprint", "-fls", "-fprintf", "-ok"}
        for argument in argv[1:]
    ):
        return "other"
    if command in {"cat", "cut", "find", "grep", "head", "less", "ls", "pwd", "rg", "tail", "wc"}:
        return "exploration"
    if command in {"pytest", "py.test"} and _non_executing_test_run(argv[1:]):
        return "other"
    module = _python_module(command, argv)
    if module is not None:
        if module == "pytest" and _non_executing_test_run(argv):
            # ``python -m pytest --version`` or ``--collect-only`` runs no test.
            return "other"
        # ``python -m pytest`` is a test run exactly like ``pytest`` (tb4n2 interleaved S: every
        # ``python -m pytest`` counted as ``other``, so a passing post-edit run never cleared
        # ``edited_after_last_verification``). Only a closed set of verification modules is named;
        # any other module stays ``other``.
        return _PYTHON_VERIFICATION_MODULES.get(module, "other")
    lowered = {argument.casefold() for argument in argv[1:]}
    joined = " ".join(argv).casefold()
    if command in {"git", "hg", "svn"}:
        return "vcs"
    if command in {
        "pytest",
        "jest",
        "mocha",
        "nox",
        "tox",
        "vitest",
        "ava",
        "cargo",
        "go",
        "make",
        "npm",
        "pnpm",
        "yarn",
        "uv",
    }:
        if command in {"cargo", "go", "make", "npm", "pnpm", "yarn", "uv"}:
            if "test" in lowered or "test" in joined or "pytest" in joined or "vitest" in joined:
                return "test"
            if "build" in lowered or "build" in joined:
                return "build"
            if "lint" in lowered or "lint" in joined:
                return "lint"
            if "typecheck" in joined or "type-check" in joined or "tsc" in joined:
                return "typecheck"
            return "other"
        return "test"
    if command in {"ruff", "eslint", "flake8", "black", "prettier"} or " lint" in joined:
        return "lint"
    if command in {"mypy", "pyright", "tsc", "typecheck", "type-check"} or any(
        marker in joined for marker in (" typecheck", " type-check", "mypy", "pyright", "tsc")
    ):
        return "typecheck"
    if command in _INTERPRETERS or _PYTHON_NAME_RE.fullmatch(command) is not None:
        if "build" in lowered:
            # ``python setup.py build``: an explicit build subcommand, not a file name.
            return "build"
        # A script an interpreter runs is the agent's own program, never a build because its
        # file name contains "build" (tb4n2 interleaved S: ``python build_model.py`` was the
        # only "verification" run of the task, so the edited-after-verification fact stuck).
        return "other"
    if "build" in joined:
        return "build"
    return "other"


_PYTHON_NAME_RE: Final = re.compile(r"^python(?:[0-9]+(?:\.[0-9]+)?)?$", re.ASCII)
_INTERPRETERS: Final = frozenset({"node", "deno", "bun", "ruby", "perl", "php", "rscript", "sage"})
# Python options that take a separate operand before ``-m`` (``python -X dev -m pytest``).
_PYTHON_OPTIONS_WITH_OPERAND: Final = frozenset({"-X", "-W", "-Q"})
_PYTHON_VERIFICATION_MODULES: Final[Mapping[str, RunnerClass]] = MappingProxyType(
    {
        "pytest": "test",
        "unittest": "test",
        "nose2": "test",
        "tox": "test",
        "nox": "test",
        "doctest": "test",
        "mypy": "typecheck",
        "pyright": "typecheck",
        "ruff": "lint",
        "flake8": "lint",
        "pylint": "lint",
        "pyflakes": "lint",
        "pycodestyle": "lint",
        "build": "build",
        "compileall": "build",
    }
)


# Options that make pytest report on itself or collect without running a test.
_PYTEST_NON_EXECUTING: Final = frozenset(
    {
        "--version",
        "-V",
        "-h",
        "--help",
        "--collect-only",
        "--collectonly",
        "--co",
        "--fixtures",
        "--funcargs",
        "--fixtures-per-test",
        "--markers",
        "--setup-only",
        "--setup-plan",
    }
)
# Project runners whose ``run`` subcommand executes the command that follows.
_RUN_WRAPPERS: Final = frozenset({"uv", "poetry", "pipenv", "pdm", "hatch", "rye"})
_RUN_SCRIPT_OPTIONS: Final = frozenset({"--script", "-s", "--gui-script"})
# ``uv run`` options that take a separate value (``uv run --with numpy python x.py``).
_RUN_OPTIONS_WITH_VALUE: Final = frozenset(
    {
        "--with",
        "-w",
        "--with-editable",
        "--with-requirements",
        "--python",
        "-p",
        "--project",
        "--directory",
        "--env-file",
        "--extra",
        "--group",
        "--only-group",
        "--no-group",
        "--package",
        "--index",
        "--index-url",
        "--default-index",
        "--extra-index-url",
        "--find-links",
        "-f",
        "--index-strategy",
        "--config-setting",
        "-C",
        "--resolution",
        "--prerelease",
        "--exclude-newer",
        "--link-mode",
        "--cache-dir",
        "--color",
        "--config-file",
        "-e",
        "--env",
    }
)


def _non_executing_test_run(arguments: list[str]) -> bool:
    return any(argument in _PYTEST_NON_EXECUTING for argument in arguments)


def _run_wrapper_target(command: str, argv: list[str]) -> list[str] | None:
    """The command a ``uv run``/``poetry run`` style wrapper executes, or ``None``."""

    if command not in _RUN_WRAPPERS:
        return None
    # Global options may precede ``run`` (``uv -q run ...``, ``uv --directory x run ...``).
    index = 1
    while index < len(argv) and argv[index].startswith("-"):
        index += 2 if argv[index] in _RUN_OPTIONS_WITH_VALUE else 1
    if index >= len(argv) or argv[index] != "run":
        return None
    index += 1
    while index < len(argv):
        argument = argv[index]
        if argument == "--":
            index += 1
            break
        if not argument.startswith("-"):
            break
        if argument in _RUN_SCRIPT_OPTIONS:
            # ``uv run --script build_model.py`` runs the agent's own script.
            return ["script"]
        index += 2 if argument in _RUN_OPTIONS_WITH_VALUE else 1
    return argv[index:] or None


def _python_module(command: str, argv: list[str]) -> str | None:
    """The ``-m`` module a Python interpreter runs, or ``None`` when *argv* runs no module."""

    if _PYTHON_NAME_RE.fullmatch(command) is None:
        return None
    index = 1
    while index < len(argv):
        argument = argv[index]
        if argument == "-m":
            return argv[index + 1].split(".", 1)[0] if index + 1 < len(argv) else None
        if argument.startswith("-m") and len(argument) > 2:
            return argument[2:].split(".", 1)[0]
        if argument in _PYTHON_OPTIONS_WITH_OPERAND:
            index += 2
            continue
        if not argument.startswith("-") or argument in {"-c", "-"}:
            return None
        index += 1
    return None


def _raw_command(payload: Mapping[str, CanonicalJsonValue]) -> str | None:
    nested = payload.get("tool_input")
    source: Mapping[str, CanonicalJsonValue] = nested if isinstance(nested, Mapping) else payload
    raw = source.get("cmd")
    if type(raw) is not str or not raw:
        raw = source.get("command")
    if type(raw) is not str or not raw or len(raw) > _MAX_COMMAND_CHARS:
        return None
    return raw


def command_runner_class(payload: Mapping[str, CanonicalJsonValue]) -> RunnerClass | None:
    """Classify only closed command shapes; never inspect command output text.

    The class is a bounded internal hint used to keep known read/exploration failures out of
    completion accounting. Unknown commands remain ``other`` so they retain their ordinary
    failure duty. Shell composition is explicitly ``compound`` because an outer exit status does
    not establish each nested command's outcome (#968).
    """

    raw = _raw_command(payload)
    if raw is None:
        tool = _classification_token(payload.get("tool_name"))
        if tool is None:
            return None
        lowered = tool.casefold()
        # A native read tool has a closed meaning even without a command string. A shell tool
        # named ``rg``/``find`` does not: without argv we cannot validate its flags or operands,
        # so keep it ordinary rather than granting exploration treatment.
        if lowered in ROUTINE_READ_TOOLS:
            return "exploration"
        if lowered in _TEST_TOOL_HINTS or any(
            token in lowered for token in ("test", "pytest", "vitest")
        ):
            return "test"
        if lowered in _VERIFICATION_TOOL_HINTS or any(
            token in lowered for token in ("lint", "typecheck", "verify", "check")
        ):
            return "typecheck" if "type" in lowered else "lint"
        return "other"
    try:
        argv = shlex.split(raw, posix=True)
    except ValueError:
        return "compound"
    if not argv:
        return None
    if any(marker in raw for marker in ("\n", "\r", ";", "&", "|", ">", "<", "`", "$(")):
        return "compound"
    return _runner_class_for_argv(argv)


def compound_verification_gap_required(payload: Mapping[str, CanonicalJsonValue]) -> bool:
    """Return whether a compound shell can mask a nested command failure.

    The outer exit code remains authoritative for the shell process. A plain ``&&`` chain with a
    zero exit proves each command in that chain returned zero, so it needs no extra gap. ``;``,
    ``||``, pipelines, background jobs, command substitution, and malformed shell text can hide a
    nested result; those shapes receive the bounded ``compound_outcome_unavailable`` coverage gap.
    Output text is never inspected.
    """

    raw = _raw_command(payload)
    if raw is None or command_runner_class(payload) != "compound":
        return False
    try:
        shlex.split(raw, posix=True)
    except ValueError:
        return True
    without_and = raw.replace("&&", "")
    return any(marker in without_and for marker in ("\n", "\r", ";", "|", "&", "`", "$("))


def _routine_facts(payload: Mapping[str, CanonicalJsonValue]) -> _RoutineFacts:
    tool = _classification_token(payload.get("tool_name"))
    if tool is None:
        return _RoutineFacts(False, "unknown_tool")
    lowered = tool.casefold()
    if lowered in ROUTINE_READ_TOOLS:
        return _RoutineFacts(True, "routine_tool")
    if lowered in SHELL_TOOLS:
        return _routine_shell_facts(payload)
    if _is_edit_tool_token(lowered):
        return _RoutineFacts(False, "edit")
    if lowered in _TEST_TOOL_HINTS or any(hint in lowered for hint in ("test", "pytest", "check")):
        return _RoutineFacts(
            False, "test" if "test" in lowered or "pytest" in lowered else "verification"
        )
    if lowered in _VERIFICATION_TOOL_HINTS or any(
        hint in lowered for hint in ("lint", "verify", "review", "typecheck")
    ):
        return _RoutineFacts(False, "verification")
    return _RoutineFacts(False, "unknown_operation")


def _classification_phase(event_name: str) -> Literal["pre", "post", "other"]:
    if event_name in _PRE_EVENTS:
        return "pre"
    if event_name in _POST_EVENTS:
        return "post"
    return "other"


def classify_observation(
    payload: Mapping[str, CanonicalJsonValue], event_name: str
) -> ObservationClassification:
    """Classify one observation with deterministic, fail-closed rules.

    Host action labels and agent-facing names are never authority.  A
    pre-event keeps its pending identity, while only a post-event with a
    closed success fact can become an unprotected routine success.
    """

    phase = _classification_phase(event_name)
    routine = (
        _routine_facts(payload)
        if phase in {"pre", "post"}
        else _RoutineFacts(False, "unknown_operation")
    )
    outcome = _classification_outcome(payload, event_name)
    proven = phase == "post" and routine.candidate and outcome.state == "success"
    protected = phase != "post" or not proven
    reasons: list[str] = [routine.reason]
    if routine.candidate:
        reasons.append("routine_candidate")
    if _has_untrusted_routine_label(payload):
        reasons.append("untrusted_action")

    if phase == "pre":
        reasons.append("incomplete")
    elif outcome.state is not None:
        reasons.append(outcome.state)
    elif phase == "post":
        reasons.append("unknown")

    if proven:
        reasons.append("routine_success")

    # Routine pre-events retain only their pending identity.  Protected
    # observations retain both bounded content arms, subject to existing
    # consent and redaction gates.
    if routine.candidate and (phase == "pre" or proven):
        role = ObservationContentRole.NONE
    elif protected:
        role = ObservationContentRole.BOTH
    elif phase == "pre":
        role = ObservationContentRole.TOOL_INPUT
    elif phase == "post":
        role = ObservationContentRole.TOOL_OUTPUT
    else:
        role = ObservationContentRole.BOTH

    return ObservationClassification(
        protected=protected,
        routine_candidate=routine.candidate,
        proven_routine_success=proven,
        content_role=role,
        reason_tokens=tuple(reasons),
    )


def _is_edit_tool_token(lowered: str) -> bool:
    return lowered in _EDIT_TOOL_HINTS or any(
        hint in lowered for hint in ("edit", "write", "patch")
    )


def is_edit_tool_name(tool_name: CanonicalJsonValue) -> bool:
    """Return whether a tool identity names a file edit under the shared hint rule."""

    tool = _classification_token(tool_name)
    if tool is None:
        return False
    lowered = tool.casefold()
    if lowered in ROUTINE_READ_TOOLS or lowered in SHELL_TOOLS:
        return False
    return _is_edit_tool_token(lowered)


def is_routine_read_candidate(payload: Mapping[str, CanonicalJsonValue]) -> bool:
    """Return the structural candidate bit without trusting outcome labels."""

    return _routine_facts(payload).candidate


def envelope_outcome_state(
    structural_payload: Mapping[str, CanonicalJsonValue], event_kind: str
) -> str | None:
    """Resolve an already-built envelope's outcome with the classifier's rules.

    ``classify_observation`` reduces the host payload — its nested result
    carriers and the native post-hook fallback included — to one outcome state,
    and the ingress records that decision on the envelope.  An envelope keeps
    only the allowlisted structural copy of that payload, so a second,
    independent re-derivation over those fields disagreed with the classifier
    for every Codex-shaped post and wedged the admission flush (issue #753).

    This is the one definition for a caller that holds an envelope rather than a
    host payload: the same reducer, applied to the fields the envelope actually
    carries, with the recorded ``hook_name`` standing in for the host's own
    ``hook_event_name`` echo so the native post fallback resolves identically.
    A stream envelope records no ``hook_name`` and therefore keeps needing an
    explicit outcome fact, exactly as its own classification did.
    """

    payload = dict(structural_payload)
    hook_name = payload.get("hook_name")
    if type(hook_name) is str and "hook_event_name" not in payload:
        payload["hook_event_name"] = hook_name
    return _classification_outcome(payload, event_kind).state


__all__ = [
    "OBSERVATION_CLASSIFICATION_VERSION",
    "OBSERVATION_SELECTION_VERSION",
    "ObservationClassification",
    "ObservationContentRole",
    "ObservationContentRoleValue",
    "ObservationReasonToken",
    "READ_ONLY_COMMANDS",
    "ROUTINE_READ_TOOLS",
    "SHELL_TOOLS",
    "RunnerClass",
    "classify_observation",
    "compound_verification_gap_required",
    "command_runner_class",
    "envelope_outcome_state",
    "is_edit_tool_name",
    "is_routine_read_candidate",
]
