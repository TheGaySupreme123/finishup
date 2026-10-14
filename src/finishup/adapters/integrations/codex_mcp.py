"""Codex adapter for the harness MCP registration port.

Automates exactly the runbook's manual check-then-add sequence:
``codex mcp get finishup --json`` first, a bounded ``codex mcp list --json``
fallback when ``get`` fails, and registration of this runtime's proven absolute console script
after absence is positively observed or an owned re-registration is accepted. Bare and legacy
entries remain recognizable. A foreign same-name entry is never replaced.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

from finishup.adapters.integrations.codex_launcher import installed_launcher
from finishup.adapters.integrations.launcher import invoking_launcher
from finishup.config.paths import ISOLATED_ROOT_ENV, PathSafetyError, isolated_root
from finishup.domain.values import JsonValue
from finishup.ports.harness_mcp import (
    MCP_LEGACY_SERVE_COMMAND,
    MCP_LEGACY_STRICT_SERVE_COMMAND,
    MCP_SERVE_COMMAND,
    MCP_SERVER_NAME,
    MCP_STRICT_SERVE_COMMAND,
    HarnessBinary,
    McpRegistrationAction,
    McpRegistrationCommand,
    McpRegistrationError,
    McpRegistrationObservation,
    McpRegistrationPreview,
    McpRegistrationReason,
    McpRegistrationResult,
    McpRegistrationState,
    mcp_command_profile,
)
from finishup.ports.integrations import HarnessId
from finishup.protocol.canonical import canonical_digest

__all__ = [
    "CodexMcpAdapter",
    "CommandOutput",
]

_COMMAND_TIMEOUT_SECONDS: Final = 10.0
_OUTPUT_LIMIT_BYTES: Final = 65_536


@dataclass(frozen=True, slots=True)
class CommandOutput:
    """Bounded structural result of one harness subprocess invocation."""

    exit_code: int
    stdout: bytes
    stdout_truncated: bool = False


type CommandRunner = Callable[[tuple[str, ...]], CommandOutput]


def _default_runner(argv: tuple[str, ...], *, codex_home: Path | None = None) -> CommandOutput:
    environment = None
    if codex_home is not None:
        environment = dict(os.environ)
        environment["CODEX_HOME"] = str(codex_home)
        environment["CODEX_TESTING_HOME"] = str(codex_home)
    try:
        # Stream host output to a private unnamed file so a noisy or compromised executable
        # cannot force an unbounded in-memory capture before the structural size check.
        with tempfile.TemporaryFile() as stdout_file:
            completed = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=subprocess.DEVNULL,
                timeout=_COMMAND_TIMEOUT_SECONDS,
                check=False,
                shell=False,
                env=environment,
            )
            stdout_size = stdout_file.tell()
            stdout_file.seek(0)
            stdout = stdout_file.read(_OUTPUT_LIMIT_BYTES)
    except subprocess.TimeoutExpired as exc:
        raise McpRegistrationError(McpRegistrationReason.TIMEOUT, {}) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise McpRegistrationError(McpRegistrationReason.HARNESS_UNAVAILABLE, {}) from exc
    return CommandOutput(
        completed.returncode,
        stdout,
        stdout_size > _OUTPUT_LIMIT_BYTES,
    )


def _reject_json_constant(_value: str) -> object:
    raise ValueError("nonstandard_json_constant")


def _reject_duplicate_object_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError("duplicate_json_key")
        parsed[key] = value
    return parsed


def _strict_json_loads(output: CommandOutput) -> object:
    if output.stdout_truncated:
        raise ValueError("truncated_json_output")
    return json.loads(
        output.stdout.decode("utf-8", errors="strict"),
        object_pairs_hook=_reject_duplicate_object_keys,
        parse_constant=_reject_json_constant,
    )


def _entry_command_tokens(entry: Mapping[str, object]) -> tuple[str, ...] | None:
    # Codex ≤0.144.5 returned top-level command/args; ≥0.144.6 nests them under transport.
    transport = entry.get("transport")
    source: Mapping[str, object] = entry
    if isinstance(transport, Mapping):
        nested = cast(Mapping[str, object], transport)
        if "command" in nested or "args" in nested:
            source = nested
    command = source.get("command")
    args = source.get("args")
    if isinstance(command, str):
        tokens: list[str] = [command]
        if args is None:
            return tuple(tokens)
        if isinstance(args, Sequence) and not isinstance(args, (str, bytes)):
            items = cast(Sequence[object], args)
            if all(isinstance(item, str) for item in items):
                tokens.extend(cast(Sequence[str], items))
                return tuple(tokens)
        return None
    if isinstance(command, Sequence) and not isinstance(command, (str, bytes)):
        items = cast(Sequence[object], command)
        if all(isinstance(item, str) for item in items):
            return tuple(cast(Sequence[str], items))
    return None


def _entry_isolated_root(entry: Mapping[str, object]) -> tuple[bool, str | None]:
    """Read the only environment binding this owned registration may carry.

    The command tokens establish FinishUP ownership; this separate parser refuses to bless a
    same-command entry with any other environment key, inherited variable, or malformed root.
    A known but different absolute root remains readable for legacy bare-command repair;
    absolute-launcher classification additionally requires this runtime's exact root.
    """

    transport = entry.get("transport")
    source: Mapping[str, object] = entry
    if isinstance(transport, Mapping):
        nested = cast(Mapping[str, object], transport)
        if "command" in nested or "args" in nested:
            source = nested
    env_vars = source.get("env_vars")
    if env_vars not in (None, []):
        return False, None
    environment = source.get("env")
    if environment is None:
        return True, None
    if not isinstance(environment, Mapping):
        return False, None
    values = cast(Mapping[object, object], environment)
    if not values:
        return True, None
    if set(values) != {ISOLATED_ROOT_ENV}:
        return False, None
    raw = values.get(ISOLATED_ROOT_ENV)
    if (
        type(raw) is not str
        or not 1 <= len(raw) <= 4_096
        or not Path(raw).is_absolute()
        or any(ord(char) < 32 or ord(char) == 127 for char in raw)
    ):
        return False, None
    return True, raw


class CodexMcpAdapter:
    """Implements ``HarnessMcpPort`` for the Codex CLI via bounded subprocesses."""

    __slots__ = ("_codex_home", "_route_profile", "_runner", "_serve_command")

    def __init__(
        self,
        runner: CommandRunner | None = None,
        *,
        route_profile: Literal["policy", "strict"] = "policy",
        codex_home: Path | None = None,
    ) -> None:
        if route_profile not in {"policy", "strict"}:
            raise ValueError("mcp_route_profile_invalid")
        self._runner = runner
        self._codex_home = codex_home
        self._route_profile: Literal["policy", "strict"] = route_profile
        self._serve_command: tuple[str, ...] = (
            MCP_STRICT_SERVE_COMMAND if route_profile == "strict" else MCP_SERVE_COMMAND
        )

    def _run(self, argv: tuple[str, ...]) -> CommandOutput:
        if self._runner is not None:
            return self._runner(argv)
        return _default_runner(argv, codex_home=self._codex_home)

    def _classify_entry(
        self,
        entry: Mapping[str, object],
    ) -> tuple[McpRegistrationState, tuple[str, ...] | None, str | None]:
        tokens = _entry_command_tokens(entry)
        if tokens and tokens[0] != "finishup" and mcp_command_profile(tokens) is not None:
            proof = installed_launcher()
            readable, root = _entry_isolated_root(entry)
            if (
                proof is not None
                and tokens[0] == proof[0]
                and readable
                and (root is None or root == self._expected_isolated_root())
                and self._unambiguous_absolute_entry(entry)
            ):
                return McpRegistrationState.FINISHUP_OWNED, tokens, root
            return McpRegistrationState.FOREIGN_PRESENT, None, None
        for command in (
            MCP_STRICT_SERVE_COMMAND,
            MCP_SERVE_COMMAND,
            MCP_LEGACY_STRICT_SERVE_COMMAND,
            MCP_LEGACY_SERVE_COMMAND,
        ):
            if tokens == command:
                environment_readable, registered_root = _entry_isolated_root(entry)
                if not environment_readable:
                    return McpRegistrationState.FOREIGN_PRESENT, None, None
                # Return the matched constant, not the parsed tokens, so the route mapping below
                # reads off one source of truth instead of re-comparing the argv.
                return McpRegistrationState.FINISHUP_OWNED, command, registered_root
        # An unreadable or different command is preserved, never replaced.
        return McpRegistrationState.FOREIGN_PRESENT, None, None

    @staticmethod
    def _unambiguous_absolute_entry(entry: Mapping[str, object]) -> bool:
        """Do not choose between conflicting transport definitions or execution modifiers."""

        transport = entry.get("transport")
        source = entry
        if transport is not None:
            if not isinstance(transport, Mapping):
                return False
            if any(key in entry for key in ("command", "args", "env", "env_vars", "cwd", "url")):
                return False
            source = cast(Mapping[str, object], transport)
        return (
            source.get("type") in (None, "stdio")
            and source.get("cwd") is None
            and source.get("url") is None
            and isinstance(source.get("command"), str)
            and entry.get("enabled", True) is True
        )

    def _desired_command(self) -> tuple[tuple[str, ...], str | None]:
        proof = installed_launcher()
        if proof is not None:
            return (proof[0], *self._serve_command[1:]), proof[1]
        # Embedded clients retain the historical bare command. An installed CLI with missing
        # or modified launcher evidence must never quietly fall back to PATH.
        if invoking_launcher() is not None:
            # A group- or world-writable prefix (Homebrew's ``/opt/homebrew``), a symlinked
            # script, or a modified console script: the launcher exists but cannot prove
            # itself, and the way out is a persistent owner-only install (issue #766).
            raise McpRegistrationError(
                McpRegistrationReason.HARNESS_UNAVAILABLE, {"detail": "launcher_unproven"}
            )
        return self._serve_command, None

    def _classify_get(
        self, output: CommandOutput
    ) -> tuple[McpRegistrationState, tuple[str, ...] | None, str | None]:
        if output.exit_code != 0:
            raise McpRegistrationError(McpRegistrationReason.HARNESS_UNAVAILABLE, {})
        try:
            parsed = _strict_json_loads(output)
        except (UnicodeDecodeError, ValueError) as exc:
            raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {}) from exc
        if not isinstance(parsed, Mapping):
            raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {})
        return self._classify_entry(cast(Mapping[str, object], parsed))

    def _classify_list(
        self, output: CommandOutput
    ) -> tuple[McpRegistrationState, tuple[str, ...] | None, str | None]:
        if output.exit_code != 0:
            raise McpRegistrationError(McpRegistrationReason.HARNESS_UNAVAILABLE, {})
        try:
            parsed = _strict_json_loads(output)
        except (UnicodeDecodeError, ValueError) as exc:
            raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {}) from exc
        if not isinstance(parsed, list):
            raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {})
        matches: list[Mapping[str, object]] = []
        for item in cast(list[object], parsed):
            if not isinstance(item, Mapping):
                raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {})
            entry = cast(Mapping[str, object], item)
            name = entry.get("name")
            if not isinstance(name, str):
                raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {})
            if name == MCP_SERVER_NAME:
                matches.append(entry)
        if not matches:
            return McpRegistrationState.ABSENT, None, None
        if len(matches) != 1:
            # A same-name duplicate is not a trustworthy absence or ownership observation.
            raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {})
        return self._classify_entry(matches[0])

    def _observe_registration_state(
        self, binary: HarnessBinary
    ) -> tuple[McpRegistrationState, tuple[str, ...] | None, str | None]:
        output = self._run((binary.executable_path, "mcp", "get", MCP_SERVER_NAME, "--json"))
        if output.exit_code == 0:
            return self._classify_get(output)
        # Codex reports both a missing name and host/config read failures as a nonzero ``get``.
        # Only a successful structural list may therefore establish positive absence.
        return self._classify_list(self._run((binary.executable_path, "mcp", "list", "--json")))

    async def status_registration(self, binary: HarnessBinary) -> McpRegistrationState:
        self._require_codex(binary)
        self._expected_isolated_root()
        return self._observe_registration_state(binary)[0]

    async def observe_registration(self, binary: HarnessBinary) -> McpRegistrationObservation:
        self._require_codex(binary)
        expected_root = self._expected_isolated_root()
        state, command, registered_root = self._observe_registration_state(binary)
        route_profile = None if command is None else mcp_command_profile(command)
        isolation_binding = None
        if state is McpRegistrationState.FINISHUP_OWNED:
            if expected_root is None and registered_root is None:
                isolation_binding = "ambient"
            elif expected_root is not None and registered_root == expected_root:
                isolation_binding = "isolated_exact"
            elif expected_root is not None and registered_root is None:
                isolation_binding = "missing"
            else:
                isolation_binding = "different"
        return McpRegistrationObservation(
            binary.harness_id,
            state,
            route_profile,
            isolation_binding,
            command,
        )

    @staticmethod
    def _expected_isolated_root() -> str | None:
        try:
            root = isolated_root()
        except PathSafetyError as exc:
            raise McpRegistrationError(
                McpRegistrationReason.ISOLATION_INVALID,
                {"reason": exc.reason_code},
            ) from exc
        return None if root is None else str(root)

    @staticmethod
    def _require_codex(binary: HarnessBinary) -> None:
        if type(binary) is not HarnessBinary or binary.harness_id is not HarnessId.CODEX:
            raise McpRegistrationError(McpRegistrationReason.HARNESS_UNAVAILABLE, {})

    def _preview_for(
        self,
        binary: HarnessBinary,
        state: McpRegistrationState,
        current_command: tuple[str, ...] | None,
        current_root: str | None,
    ) -> McpRegistrationPreview:
        expected_root = self._expected_isolated_root()
        serve_command, launcher_digest = self._desired_command()
        action = (
            McpRegistrationAction.REGISTER
            if state is McpRegistrationState.ABSENT
            else (
                McpRegistrationAction.REREGISTER
                if state is McpRegistrationState.FINISHUP_OWNED
                and (current_command != serve_command or current_root != expected_root)
                else McpRegistrationAction.NOOP
            )
        )
        warnings: tuple[str, ...] = ()
        if state is McpRegistrationState.FOREIGN_PRESENT:
            warnings = ("foreign_entry_present",)
        digest_input: dict[str, object] = {
            "action": action.value,
            "executable_path": binary.executable_path,
            "harness": binary.harness_id.value,
            "schema": "yoetz.mcp-registration-preview/1",
            "serve_command": list(serve_command),
            "server_name": MCP_SERVER_NAME,
            "state_before": state.value,
        }
        if expected_root is not None:
            digest_input["schema"] = "yoetz.mcp-registration-preview/2"
            digest_input["isolated_root"] = expected_root
        if launcher_digest is not None:
            digest_input.update(
                schema="yoetz.mcp-registration-preview/3",
                launcher_digest=launcher_digest,
                current_command=current_command,
                current_root=current_root,
            )
        if self._codex_home is not None:
            digest_input["codex_home"] = str(self._codex_home)
            digest_input["schema"] = "yoetz.mcp-registration-preview/4"
        digest = canonical_digest(cast(JsonValue, digest_input))
        return McpRegistrationPreview(
            binary.harness_id,
            action,
            state,
            warnings,
            digest,
            serve_command,
            self._route_profile,
            expected_root,
        )

    async def preview_registration(self, binary: HarnessBinary) -> McpRegistrationPreview:
        self._require_codex(binary)
        state, current_command, current_root = self._observe_registration_state(binary)
        return self._preview_for(binary, state, current_command, current_root)

    async def apply_registration(
        self,
        binary: HarnessBinary,
        command: McpRegistrationCommand,
    ) -> McpRegistrationResult:
        self._require_codex(binary)
        if type(command) is not McpRegistrationCommand:
            raise McpRegistrationError(McpRegistrationReason.CONFIRMATION_REQUIRED, {})
        if not command.explicitly_accepted:
            raise McpRegistrationError(McpRegistrationReason.CONFIRMATION_REQUIRED, {})
        preview = await self.preview_registration(binary)
        if command.preview_digest != preview.preview_digest:
            raise McpRegistrationError(McpRegistrationReason.PREVIEW_STALE, {})
        if preview.state_before is McpRegistrationState.FOREIGN_PRESENT:
            raise McpRegistrationError(McpRegistrationReason.FOREIGN_ENTRY_PRESENT, {})
        if preview.action is McpRegistrationAction.NOOP:
            return McpRegistrationResult(
                binary.harness_id,
                McpRegistrationAction.NOOP,
                preview.state_before,
                preview.state_before,
                preview.preview_digest,
            )
        environment_args = (
            ()
            if preview.isolated_root is None
            else ("--env", f"{ISOLATED_ROOT_ENV}={preview.isolated_root}")
        )
        add_output = self._run(
            (
                binary.executable_path,
                "mcp",
                "add",
                MCP_SERVER_NAME,
                *environment_args,
                "--",
                *preview.serve_command,
            )
        )
        if add_output.exit_code != 0:
            raise McpRegistrationError(
                McpRegistrationReason.REGISTRATION_FAILED,
                {"exit_code_class": "nonzero"},
            )
        # Verify by re-reading state rather than trusting the add exit code alone.
        state_after, command_after, root_after = self._observe_registration_state(binary)
        if (
            state_after is not McpRegistrationState.FINISHUP_OWNED
            or command_after != preview.serve_command
            or root_after != preview.isolated_root
        ):
            raise McpRegistrationError(
                McpRegistrationReason.REGISTRATION_FAILED,
                {"verified_state": state_after.value},
            )
        return McpRegistrationResult(
            binary.harness_id,
            preview.action,
            preview.state_before,
            state_after,
            preview.preview_digest,
        )

    def _unregistration_preview_for(
        self,
        binary: HarnessBinary,
        state: McpRegistrationState,
        current_command: tuple[str, ...] | None,
        current_root: str | None,
    ) -> McpRegistrationPreview:
        action = (
            McpRegistrationAction.NOOP
            if state is McpRegistrationState.ABSENT
            else McpRegistrationAction.UNREGISTER
        )
        warnings: tuple[str, ...] = ()
        if state is McpRegistrationState.FOREIGN_PRESENT:
            warnings = ("foreign_entry_present",)
        elif state is McpRegistrationState.FINISHUP_OWNED:
            # Codex 0.149.x exposes a name-based remove command, not a compare-and-remove token.
            # Apply narrows that host limitation with an immediate ownership recheck below and
            # the preview must surface the remaining non-atomic boundary to the operator.
            warnings = ("host_remove_not_compare_and_swap",)
        if (
            state is McpRegistrationState.FINISHUP_OWNED
            and current_command is not None
            and mcp_command_profile(current_command) is not None
        ):
            serve_command = current_command
            route_profile = cast(Literal["policy", "strict"], mcp_command_profile(current_command))
        else:
            # Never copy a foreign argv into the preview shape. The digest still
            # binds ``state_before``, so apply refuses the same-name entry.
            serve_command = self._serve_command
            route_profile = self._route_profile
        digest_input: dict[str, object] = {
            "action": action.value,
            "executable_path": binary.executable_path,
            "harness": binary.harness_id.value,
            "schema": "yoetz.mcp-unregistration-preview/1",
            "serve_command": list(serve_command),
            "server_name": MCP_SERVER_NAME,
            "state_before": state.value,
        }
        if current_root is not None:
            digest_input["schema"] = "yoetz.mcp-unregistration-preview/2"
            digest_input["isolated_root"] = current_root
        if serve_command[0] != "finishup":
            proof = installed_launcher()
            digest_input["schema"] = "yoetz.mcp-unregistration-preview/3"
            digest_input["launcher_digest"] = None if proof is None else proof[1]
        if self._codex_home is not None:
            digest_input["codex_home"] = str(self._codex_home)
            digest_input["schema"] = "yoetz.mcp-unregistration-preview/4"
        digest = canonical_digest(cast(JsonValue, digest_input))
        return McpRegistrationPreview(
            binary.harness_id,
            action,
            state,
            warnings,
            digest,
            serve_command,
            route_profile,
            current_root,
        )

    async def preview_unregistration(self, binary: HarnessBinary) -> McpRegistrationPreview:
        self._require_codex(binary)
        self._expected_isolated_root()
        state, current_command, current_root = self._observe_registration_state(binary)
        return self._unregistration_preview_for(binary, state, current_command, current_root)

    async def apply_unregistration(
        self,
        binary: HarnessBinary,
        command: McpRegistrationCommand,
    ) -> McpRegistrationResult:
        self._require_codex(binary)
        if type(command) is not McpRegistrationCommand:
            raise McpRegistrationError(McpRegistrationReason.CONFIRMATION_REQUIRED, {})
        if not command.explicitly_accepted:
            raise McpRegistrationError(McpRegistrationReason.CONFIRMATION_REQUIRED, {})
        preview = await self.preview_unregistration(binary)
        if command.preview_digest != preview.preview_digest:
            raise McpRegistrationError(McpRegistrationReason.PREVIEW_STALE, {})
        if preview.state_before is McpRegistrationState.FOREIGN_PRESENT:
            raise McpRegistrationError(McpRegistrationReason.FOREIGN_ENTRY_PRESENT, {})
        if preview.action is McpRegistrationAction.NOOP:
            return McpRegistrationResult(
                binary.harness_id,
                McpRegistrationAction.NOOP,
                preview.state_before,
                preview.state_before,
                preview.preview_digest,
            )
        state_before_remove, command_before_remove, root_before_remove = (
            self._observe_registration_state(binary)
        )
        if state_before_remove is McpRegistrationState.FOREIGN_PRESENT:
            raise McpRegistrationError(McpRegistrationReason.FOREIGN_ENTRY_PRESENT, {})
        if (
            state_before_remove is not McpRegistrationState.FINISHUP_OWNED
            or command_before_remove != preview.serve_command
            or root_before_remove != preview.isolated_root
        ):
            raise McpRegistrationError(McpRegistrationReason.PREVIEW_STALE, {})
        try:
            remove_output = self._run((binary.executable_path, "mcp", "remove", MCP_SERVER_NAME))
        except Exception as exc:
            # The name-based command may have mutated registration before a timeout or
            # harness failure surfaced. Its outcome is therefore unknown, never a
            # pre-mutation observation error.
            raise McpRegistrationError(McpRegistrationReason.REGISTRATION_FAILED, {}) from exc
        # A nonzero exit does not establish that the host left the entry present.
        # Reconcile once through the same bounded positive-absence probe as exit zero;
        # never retry the mutation or echo the host's output.
        details: dict[str, JsonValue] = (
            {"exit_code_class": "nonzero"} if remove_output.exit_code != 0 else {}
        )
        try:
            state_after, _command_after, _root_after = self._observe_registration_state(binary)
        except McpRegistrationError as exc:
            # The name-based remove command already ran. Any unreadable or
            # malformed verification is therefore an outcome-unknown mutation,
            # not the pre-mutation observation reason.
            raise McpRegistrationError(McpRegistrationReason.REGISTRATION_FAILED, details) from exc
        if state_after is not McpRegistrationState.ABSENT:
            raise McpRegistrationError(
                McpRegistrationReason.REGISTRATION_FAILED,
                {**details, "verified_state": state_after.value},
            )
        return McpRegistrationResult(
            binary.harness_id,
            McpRegistrationAction.UNREGISTER,
            preview.state_before,
            state_after,
            preview.preview_digest,
            ("host_remove_returned_nonzero",) if remove_output.exit_code != 0 else (),
        )
