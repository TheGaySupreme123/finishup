"""Codex adapter for the harness MCP registration port.

Automates exactly the runbook's manual check-then-add sequence:
``codex mcp get finishup --json`` first, a bounded ``codex mcp list --json``
that proves absence when ``get`` fails and reads the legacy ``yoetz`` key, and registration of
this runtime's proven absolute console script after absence is positively observed or an owned
re-registration is accepted. Bare and legacy entries remain recognizable. A foreign same-name
entry is never replaced.

Registrations written before the rename sit under the legacy ``yoetz`` key (ADR-048). An entry
there that is provably FinishUP's reads as owned but outdated; integrate migrates it in the same
preview and consent (write ``finishup``, then remove ``yoetz``), and remove takes both keys. An
entry under the legacy key that FinishUP cannot prove is its own is reported and never touched.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import Final, Literal, cast

from finishup.adapters.integrations.codex_launcher import installed_launcher
from finishup.adapters.integrations.launcher import invoking_launcher
from finishup.config.paths import (
    ISOLATED_ROOT_ENV,
    LEGACY_ISOLATED_ROOT_ENV,
    PathSafetyError,
    isolated_root,
)
from finishup.domain.values import JsonValue
from finishup.legacy_names import LAUNCHER_NAMES, LEGACY_LAUNCHER_NAME
from finishup.ports.harness_mcp import (
    LEGACY_UNREAD_REASONS,
    MCP_LEGACY_SERVER_NAME,
    MCP_SERVE_COMMAND,
    MCP_SERVER_NAME,
    MCP_STRICT_SERVE_COMMAND,
    HarnessBinary,
    LegacyRegistration,
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
    "codex_project_mcp_leftover",
    "codex_project_mcp_leftovers",
    "isolated_root_environment",
    "proven_serve_command",
    "LEGACY_UNREAD_REASONS",
    "PROJECT_CONFIG_UNREADABLE_REASONS",
    "LegacyRegistrationUse",
    "home_project_candidates",
    "legacy_registration_dependents",
    "project_config_unreadable_reason",
    "legacy_registration_shaped",
    "read_bounded_toml",
    "probe_project_config_load",
    "project_transport_dependence",
]

_COMMAND_TIMEOUT_SECONDS: Final = 10.0
# The user configuration is read with Codex's own bound (as the marketplace adapter reads it):
# trust rows for many projects can exceed the 64 KiB a project file is allowed (#1073 round 3).
_USER_CONFIG_LIMIT_BYTES: Final = 1_048_576
# Why one project's ``.codex/config.toml`` could not be read safely (closed tokens).
PROJECT_CONFIG_UNREADABLE_REASONS: Final = frozenset(
    {"symlink", "not_regular_file", "oversized", "unreadable", "not_valid_toml"}
)
_OUTPUT_LIMIT_BYTES: Final = 65_536
# Both spellings of the isolation root a registration may carry (ADR-048). New registrations
# write both with one value so an older bare ``yoetz`` launcher resolved through PATH still
# isolates; either one alone, or both equal, is read as the same binding.
_ISOLATED_ROOT_ENV_NAMES: Final = frozenset({ISOLATED_ROOT_ENV, LEGACY_ISOLATED_ROOT_ENV})


@dataclass(frozen=True, slots=True)
class _Entry:
    """One registration key's structural classification; never carries host bytes beyond argv."""

    state: McpRegistrationState
    command: tuple[str, ...] | None = None
    root: str | None = None
    # False when an owned isolated entry carries only one spelling of the root (ADR-048).
    env_current: bool = True


_ABSENT: Final = _Entry(McpRegistrationState.ABSENT)
_FOREIGN: Final = _Entry(McpRegistrationState.FOREIGN_PRESENT)


@dataclass(frozen=True, slots=True)
class _Registrations:
    """The entries under the ``finishup`` key and the legacy ``yoetz`` key (ADR-048)."""

    current: _Entry
    legacy: _Entry

    @property
    def effective(self) -> _Entry:
        """The entry the FinishUP registration reads as: the new key wins unless it is absent."""

        if (
            self.current.state is McpRegistrationState.ABSENT
            and self.legacy.state is McpRegistrationState.FINISHUP_OWNED
        ):
            return self.legacy
        return self.current

    @property
    def removable(self) -> _Entry:
        """Select an owned key independently of a foreign entry under the other name."""

        if self.current.state is McpRegistrationState.FINISHUP_OWNED:
            return self.current
        if self.legacy.state is McpRegistrationState.FINISHUP_OWNED:
            return self.legacy
        return self.effective

    @property
    def legacy_registration(self) -> LegacyRegistration:
        if self.legacy.state is McpRegistrationState.ABSENT:
            return "none"
        if self.legacy.state is McpRegistrationState.FOREIGN_PRESENT:
            return "foreign"
        if self.current.state is McpRegistrationState.FINISHUP_OWNED:
            return "duplicate"
        return "legacy_only"

    def legacy_warnings(self) -> tuple[str, ...]:
        if self.legacy.state is McpRegistrationState.FINISHUP_OWNED:
            return ("legacy_registration_owned",)
        if self.legacy.state is McpRegistrationState.FOREIGN_PRESENT:
            return ("legacy_registration_foreign",)
        return ()

    def bind_legacy(self, digest_input: dict[str, object]) -> None:
        """Bind a present legacy entry into a preview digest (schema ``/5``, ADR-048)."""

        if self.legacy.state is McpRegistrationState.ABSENT:
            return
        digest_input.update(
            schema=str(digest_input["schema"]).rsplit("/", 1)[0] + "/5",
            legacy_server_name=MCP_LEGACY_SERVER_NAME,
            legacy_state=self.legacy.state.value,
            legacy_command=None if self.legacy.command is None else list(self.legacy.command),
            legacy_root=self.legacy.root,
        )


@dataclass(frozen=True, slots=True)
class CommandOutput:
    """Bounded structural result of one harness subprocess invocation."""

    exit_code: int
    stdout: bytes
    stdout_truncated: bool = False


type CommandRunner = Callable[[tuple[str, ...]], CommandOutput]


def _selected_codex_home(codex_home: Path | None) -> Path:
    if codex_home is not None:
        return codex_home
    configured = os.environ.get("CODEX_HOME")
    return Path(configured) if configured else Path.home() / ".codex"


def _neutral_cwd(codex_home: Path | None) -> str | None:
    """Run user-scope registration commands outside any project layer.

    ``codex mcp add|get|list|remove`` act on ``$CODEX_HOME/config.toml``, but Codex also merges
    a trusted project's ``.codex/config.toml`` found from the working directory. Launching from
    the selected Codex home keeps an unrelated or broken project layer in the invoking shell's
    directory from changing or failing the user-scope observation.
    """

    home = _selected_codex_home(codex_home)
    return str(home) if home.is_dir() else None


def _default_runner(
    argv: tuple[str, ...], *, codex_home: Path | None = None, cwd: str | None = None
) -> CommandOutput:
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
                cwd=cwd if cwd is not None else _neutral_cwd(codex_home),
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


def _entry_isolated_root(entry: Mapping[str, object]) -> tuple[bool, str | None, bool]:
    """Read the only environment binding this owned registration may carry.

    The command tokens establish FinishUP ownership; this separate parser refuses to bless a
    same-command entry with any other environment key, inherited variable, or malformed root.
    A known but different absolute root remains readable for legacy bare-command repair;
    absolute-launcher classification additionally requires this runtime's exact root.

    The root may be spelled ``FINISHUP_ISOLATED_ROOT``, the legacy ``YOETZ_ISOLATED_ROOT``, or
    both with one value (ADR-048); two different values are not FinishUP's binding. The third
    element is False when an isolated entry lacks one of the two spellings a new render writes.
    """

    transport = entry.get("transport")
    source: Mapping[str, object] = entry
    if isinstance(transport, Mapping):
        nested = cast(Mapping[str, object], transport)
        if "command" in nested or "args" in nested:
            source = nested
    env_vars = source.get("env_vars")
    if env_vars not in (None, []):
        return False, None, True
    environment = source.get("env")
    if environment is None:
        return True, None, True
    if not isinstance(environment, Mapping):
        return False, None, True
    values = cast(Mapping[object, object], environment)
    if not values:
        return True, None, True
    names = {name for name in _ISOLATED_ROOT_ENV_NAMES if name in values}
    if len(names) != len(values):
        return False, None, True
    # Host-supplied values are type-checked before they are compared: a list or object value is
    # not FinishUP's binding, never an unhashable crash.
    if any(type(values[name]) is not str for name in names):
        return False, None, True
    roots = {cast(str, values[name]) for name in names}
    if len(roots) != 1:
        # Two spellings bound to different roots: ambiguous, so never FinishUP's (ADR-048).
        return False, None, True
    raw = roots.pop()
    if (
        not 1 <= len(raw) <= 4_096
        or not Path(raw).is_absolute()
        or any(ord(char) < 32 or ord(char) == 127 for char in raw)
    ):
        return False, None, True
    return True, raw, len(names) == len(_ISOLATED_ROOT_ENV_NAMES)


def proven_serve_command(serve_command: tuple[str, ...]) -> tuple[tuple[str, ...], str | None]:
    """The serve argv the external Codex registration writes. Never a ``PATH`` lookup.

    A console script this interpreter's installed RECORD still proves replaces the bare launcher.
    An installed CLI whose script cannot be proved raises ``launcher_unproven`` rather than
    falling back to ``PATH``. An embed with no invoking launcher keeps the historical bare command.
    """

    proof = installed_launcher()
    if proof is not None:
        return (proof[0], *serve_command[1:]), proof[1]
    if invoking_launcher() is not None:
        raise McpRegistrationError(
            McpRegistrationReason.HARNESS_UNAVAILABLE, {"detail": "launcher_unproven"}
        )
    return serve_command, None


def isolated_root_environment() -> dict[str, str] | None:
    """Both isolation-root spellings bound to this process's root, or ``None`` when ambient.

    The same pair the external registration passes to ``codex mcp add --env``. An unsafe root
    is ``isolation_invalid``, never a silent ambient binding.
    """

    try:
        root = isolated_root()
    except PathSafetyError as exc:
        raise McpRegistrationError(
            McpRegistrationReason.ISOLATION_INVALID,
            {"reason": exc.reason_code},
        ) from exc
    if root is None:
        return None
    text = str(root)
    return {ISOLATED_ROOT_ENV: text, LEGACY_ISOLATED_ROOT_ENV: text}


def _legacy_distribution_installed() -> bool:
    """Whether a ``yoetz`` distribution, whose RECORD owns the alias script, is installed.

    An unreadable distribution counts as installed, so its RECORD stays the only proof.
    """

    try:
        distribution(LEGACY_LAUNCHER_NAME)
    except PackageNotFoundError:
        return False
    except OSError, ValueError:
        return True
    return True


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

    def _classify_entry(self, entry: Mapping[str, object]) -> _Entry:
        tokens = _entry_command_tokens(entry)
        if tokens is None or mcp_command_profile(tokens) is None:
            # An unreadable or different command is preserved, never replaced.
            return _FOREIGN
        readable, root, env_current = _entry_isolated_root(entry)
        if not readable:
            return _FOREIGN
        if tokens[0] in LAUNCHER_NAMES:
            # A bare launcher under either spelling (ADR-048); the shape check above already
            # matched one of the four FinishUP serve templates exactly.
            return _Entry(McpRegistrationState.FINISHUP_OWNED, tokens, root, env_current)
        if (
            self._owned_absolute_launcher(tokens[0])
            and (root is None or root == self._expected_isolated_root())
            and self._unambiguous_absolute_entry(entry)
        ):
            return _Entry(McpRegistrationState.FINISHUP_OWNED, tokens, root, env_current)
        return _FOREIGN

    @staticmethod
    def _owned_absolute_launcher(launcher: str) -> bool:
        """Whether an absolute launcher is this runtime's proven script or its legacy alias.

        The deprecated ``yoetz`` alias (ADR-048) is proven the same way as ``finishup``: by the
        transitional ``yoetz`` distribution's installed RECORD, digest and all. While that
        distribution is installed, nothing else proves the alias: a script its RECORD rejects
        (modified, symlinked, or loosened) is never FinishUP's. Only when no ``yoetz``
        distribution is installed does the exact sibling path ``<proven scripts dir>/yoetz``
        still count, and likewise when the distribution is installed but nothing is at that
        path. That fallback trusts the location, an owner-only directory this runtime's proven
        ``finishup`` script lives in, and holds no bytes a RECORD rejected; it exists so the
        registration an earlier Yoetz install wrote for this same environment stays migratable
        and removable after the old script itself was uninstalled. Any other path is not
        FinishUP's.
        """

        proof = installed_launcher()
        if proof is not None and launcher == proof[0]:
            return True
        legacy_proof = installed_launcher(LEGACY_LAUNCHER_NAME)
        if legacy_proof is not None:
            return launcher == legacy_proof[0]
        if proof is None:
            return False
        sibling = Path(proof[0]).with_name(LEGACY_LAUNCHER_NAME)
        if launcher != str(sibling):
            return False
        return not _legacy_distribution_installed() or not os.path.lexists(sibling)

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
        # Embedded clients retain the historical bare command. An installed CLI with missing
        # or modified launcher evidence must never quietly fall back to PATH (issue #766).
        return proven_serve_command(self._serve_command)

    def _classify_get(self, output: CommandOutput) -> _Entry:
        if output.exit_code != 0:
            raise McpRegistrationError(McpRegistrationReason.HARNESS_UNAVAILABLE, {})
        try:
            parsed = _strict_json_loads(output)
        except (UnicodeDecodeError, ValueError) as exc:
            raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {}) from exc
        if not isinstance(parsed, Mapping):
            raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {})
        return self._classify_entry(cast(Mapping[str, object], parsed))

    @staticmethod
    def _listed_entries(output: CommandOutput) -> list[Mapping[str, object]]:
        if output.exit_code != 0:
            raise McpRegistrationError(McpRegistrationReason.HARNESS_UNAVAILABLE, {})
        try:
            parsed = _strict_json_loads(output)
        except (UnicodeDecodeError, ValueError) as exc:
            raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {}) from exc
        if not isinstance(parsed, list):
            raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {})
        entries: list[Mapping[str, object]] = []
        for item in cast(list[object], parsed):
            if not isinstance(item, Mapping):
                raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {})
            entry = cast(Mapping[str, object], item)
            if not isinstance(entry.get("name"), str):
                raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {})
            entries.append(entry)
        return entries

    def _classify_listed(self, entries: Sequence[Mapping[str, object]], name: str) -> _Entry:
        matches = [entry for entry in entries if entry.get("name") == name]
        if not matches:
            return _ABSENT
        if len(matches) != 1:
            # A same-name duplicate is not a trustworthy absence or ownership observation.
            raise McpRegistrationError(McpRegistrationReason.PARSE_FAILED, {})
        return self._classify_entry(matches[0])

    def _observe_registration_state(self, binary: HarnessBinary) -> _Registrations:
        output = self._run((binary.executable_path, "mcp", "get", MCP_SERVER_NAME, "--json"))
        current = self._classify_get(output) if output.exit_code == 0 else None
        # Codex reports both a missing name and host/config read failures as a nonzero ``get``.
        # Only a successful structural list may therefore establish positive absence; the same
        # list also reads the legacy ``yoetz`` key, so one probe covers both names (ADR-048).
        entries = self._listed_entries(self._run((binary.executable_path, "mcp", "list", "--json")))
        if current is None:
            current = self._classify_listed(entries, MCP_SERVER_NAME)
        return _Registrations(current, self._classify_listed(entries, MCP_LEGACY_SERVER_NAME))

    async def status_registration(self, binary: HarnessBinary) -> McpRegistrationState:
        self._require_codex(binary)
        self._expected_isolated_root()
        return self._observe_registration_state(binary).effective.state

    async def observe_registration(self, binary: HarnessBinary) -> McpRegistrationObservation:
        self._require_codex(binary)
        expected_root = self._expected_isolated_root()
        registrations = self._observe_registration_state(binary)
        effective = registrations.effective
        state, command, registered_root = effective.state, effective.command, effective.root
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
            registrations.legacy_registration,
        )

    @staticmethod
    def _expected_isolated_root() -> str | None:
        environment = isolated_root_environment()
        if environment is None:
            return None
        return environment[ISOLATED_ROOT_ENV]

    @staticmethod
    def _require_codex(binary: HarnessBinary) -> None:
        if type(binary) is not HarnessBinary or binary.harness_id is not HarnessId.CODEX:
            raise McpRegistrationError(McpRegistrationReason.HARNESS_UNAVAILABLE, {})

    @staticmethod
    def _current_is_desired(
        entry: _Entry, serve_command: tuple[str, ...], expected_root: str | None
    ) -> bool:
        return (
            entry.state is McpRegistrationState.FINISHUP_OWNED
            and entry.command == serve_command
            and entry.root == expected_root
            and entry.env_current
        )

    def _preview_for(
        self, binary: HarnessBinary, registrations: _Registrations
    ) -> McpRegistrationPreview:
        expected_root = self._expected_isolated_root()
        serve_command, launcher_digest = self._desired_command()
        effective = registrations.effective
        state, current_command, current_root = effective.state, effective.command, effective.root
        legacy_owned = registrations.legacy.state is McpRegistrationState.FINISHUP_OWNED
        # An owned legacy-key entry migrates unless a project's Codex configuration still names
        # the ``yoetz`` server without a transport of its own: removing it would stop Codex
        # loading there, so it stays beside ``finishup`` until those tables go (#1073).
        use = (
            legacy_registration_dependents(self._codex_home)
            if legacy_owned
            else LegacyRegistrationUse((), (), ())
        )
        kept_for, unchecked = use.kept_for, use.unchecked
        keep_legacy = use.keeps
        legacy_route = (
            mcp_command_profile(registrations.legacy.command)
            if keep_legacy and registrations.legacy.command is not None
            else None
        )
        if state is McpRegistrationState.ABSENT:
            action = McpRegistrationAction.REGISTER
        elif state is not McpRegistrationState.FINISHUP_OWNED:
            action = McpRegistrationAction.NOOP
        elif keep_legacy:
            # Only the ``finishup`` key is written; the kept entry is left as it is.
            action = (
                McpRegistrationAction.NOOP
                if self._current_is_desired(registrations.current, serve_command, expected_root)
                else McpRegistrationAction.REREGISTER
            )
        else:
            action = (
                McpRegistrationAction.REREGISTER
                # An owned legacy-key entry always migrates, even beside a current one.
                if legacy_owned
                or not self._current_is_desired(effective, serve_command, expected_root)
                else McpRegistrationAction.NOOP
            )
        warnings: list[str] = list(registrations.legacy_warnings())
        if state is McpRegistrationState.FOREIGN_PRESENT:
            warnings.append("foreign_entry_present")
        if keep_legacy:
            warnings.append("legacy_registration_kept")
            if legacy_route is not None and legacy_route != self._route_profile:
                # The kept entry serves every project of the home on its own review mode.
                warnings.append("legacy_registration_route_kept")
        digest_input: dict[str, object] = {
            "action": action.value,
            "executable_path": binary.executable_path,
            "harness": binary.harness_id.value,
            # Frozen legacy identifier (ADR-048): the preview tag family keeps its namespace.
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
        if not effective.env_current:
            digest_input["current_env_complete"] = False
        registrations.bind_legacy(digest_input)
        if keep_legacy:
            # The decision to keep the legacy entry, and for whom, is part of what is approved.
            digest_input.update(
                schema=str(digest_input["schema"]).rsplit("/", 1)[0] + "/6",
                legacy_kept_for=list(kept_for),
                legacy_kept_unchecked=unchecked,
                legacy_kept_unreadable=list(use.unreadable),
                legacy_kept_unread=list(use.unread),
            )
        digest = canonical_digest(cast(JsonValue, digest_input))
        return McpRegistrationPreview(
            binary.harness_id,
            action,
            state,
            tuple(sorted(warnings)),
            digest,
            serve_command,
            self._route_profile,
            expected_root,
            registrations.legacy_registration,
            None
            if state is not McpRegistrationState.FINISHUP_OWNED or current_command is None
            else mcp_command_profile(current_command),
            kept_for,
            unchecked,
            legacy_route,
            use.unreadable,
            use.unread,
        )

    async def preview_registration(self, binary: HarnessBinary) -> McpRegistrationPreview:
        self._require_codex(binary)
        return self._preview_for(binary, self._observe_registration_state(binary))

    def _remove_legacy_entry(self, binary: HarnessBinary, expected: _Entry) -> None:
        """Remove the owned legacy-key entry the accepted preview named (ADR-048).

        Codex removes by name only, so the entry is re-read immediately before the removal and
        any change since the preview stops the migration with the new-key entry already written.
        """

        before = self._observe_registration_state(binary).legacy
        if before != expected:
            raise McpRegistrationError(
                McpRegistrationReason.REGISTRATION_FAILED,
                {"legacy_state": before.state.value},
            )
        try:
            self._run((binary.executable_path, "mcp", "remove", MCP_LEGACY_SERVER_NAME))
        except Exception as exc:
            raise McpRegistrationError(
                McpRegistrationReason.REGISTRATION_FAILED, {"legacy_state": "unknown"}
            ) from exc

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
        registrations = self._observe_registration_state(binary)
        preview = self._preview_for(binary, registrations)
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
        if not self._current_is_desired(
            registrations.current, preview.serve_command, preview.isolated_root
        ):
            # New registrations bind both spellings of the root to one value (ADR-048).
            environment_args = (
                ()
                if preview.isolated_root is None
                else (
                    "--env",
                    f"{ISOLATED_ROOT_ENV}={preview.isolated_root}",
                    "--env",
                    f"{LEGACY_ISOLATED_ROOT_ENV}={preview.isolated_root}",
                )
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
        # A legacy entry another project's Codex configuration still needs stays (#1073).
        keep_legacy = bool(preview.legacy_kept_for) or preview.legacy_kept_unchecked
        if registrations.legacy.state is McpRegistrationState.FINISHUP_OWNED and not keep_legacy:
            # The new key is written first, so a failed removal leaves a working duplicate
            # rather than no registration at all.
            self._remove_legacy_entry(binary, registrations.legacy)
        # Verify by re-reading state rather than trusting the add exit code alone.
        after = self._observe_registration_state(binary)
        if not self._current_is_desired(
            after.current, preview.serve_command, preview.isolated_root
        ):
            raise McpRegistrationError(
                McpRegistrationReason.REGISTRATION_FAILED,
                {"verified_state": after.current.state.value},
            )
        if not keep_legacy and (
            after.legacy.state is McpRegistrationState.FINISHUP_OWNED
            or (
                registrations.legacy.state is McpRegistrationState.FINISHUP_OWNED
                and after.legacy.state is not McpRegistrationState.ABSENT
            )
        ):
            raise McpRegistrationError(
                McpRegistrationReason.REGISTRATION_FAILED,
                {"legacy_state": after.legacy.state.value},
            )
        return McpRegistrationResult(
            binary.harness_id,
            preview.action,
            preview.state_before,
            after.current.state,
            preview.preview_digest,
        )

    def _unregistration_preview_for(
        self, binary: HarnessBinary, registrations: _Registrations
    ) -> McpRegistrationPreview:
        effective = registrations.removable
        state, current_command, current_root = effective.state, effective.command, effective.root
        action = (
            McpRegistrationAction.NOOP
            if state is McpRegistrationState.ABSENT
            else McpRegistrationAction.UNREGISTER
        )
        warnings: list[str] = list(registrations.legacy_warnings())
        if registrations.current.state is McpRegistrationState.FOREIGN_PRESENT:
            warnings.append("foreign_entry_present")
        if state is McpRegistrationState.FINISHUP_OWNED:
            # Codex 0.149.x exposes a name-based remove command, not a compare-and-remove token.
            # Apply narrows that host limitation with an immediate ownership recheck below and
            # the preview must surface the remaining non-atomic boundary to the operator.
            warnings.append("host_remove_not_compare_and_swap")
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
            # Frozen legacy identifier (ADR-048): the preview tag family keeps its namespace.
            "schema": "yoetz.mcp-unregistration-preview/1",
            "serve_command": list(serve_command),
            "server_name": MCP_SERVER_NAME,
            "state_before": state.value,
        }
        if current_root is not None:
            digest_input["schema"] = "yoetz.mcp-unregistration-preview/2"
            digest_input["isolated_root"] = current_root
        if serve_command[0] not in LAUNCHER_NAMES:
            proof = installed_launcher()
            digest_input["schema"] = "yoetz.mcp-unregistration-preview/3"
            digest_input["launcher_digest"] = None if proof is None else proof[1]
        if self._codex_home is not None:
            digest_input["codex_home"] = str(self._codex_home)
            digest_input["schema"] = "yoetz.mcp-unregistration-preview/4"
        if registrations.current.state is not effective.state:
            # The effective entry is the legacy one; bind the new-key state it stands in for.
            digest_input["current_state"] = registrations.current.state.value
        registrations.bind_legacy(digest_input)
        digest = canonical_digest(cast(JsonValue, digest_input))
        return McpRegistrationPreview(
            binary.harness_id,
            action,
            state,
            tuple(sorted(warnings)),
            digest,
            serve_command,
            route_profile,
            current_root,
            registrations.legacy_registration,
        )

    async def preview_unregistration(self, binary: HarnessBinary) -> McpRegistrationPreview:
        self._require_codex(binary)
        self._expected_isolated_root()
        return self._unregistration_preview_for(binary, self._observe_registration_state(binary))

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
        self._expected_isolated_root()
        registrations = self._observe_registration_state(binary)
        preview = self._unregistration_preview_for(binary, registrations)
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
        before_remove = self._observe_registration_state(binary)
        if before_remove.removable.state is McpRegistrationState.FOREIGN_PRESENT:
            raise McpRegistrationError(McpRegistrationReason.FOREIGN_ENTRY_PRESENT, {})
        if before_remove != registrations:
            raise McpRegistrationError(McpRegistrationReason.PREVIEW_STALE, {})
        # Remove every owned entry: the new key, then the legacy key (ADR-048). A foreign entry
        # under either key is never removed.
        names = tuple(
            name
            for name, entry in (
                (MCP_SERVER_NAME, registrations.current),
                (MCP_LEGACY_SERVER_NAME, registrations.legacy),
            )
            if entry.state is McpRegistrationState.FINISHUP_OWNED
        )
        nonzero = False
        for index, name in enumerate(names):
            if index:
                # The first removal can run host code. Recheck the other key immediately
                # before its name-based removal so a replacement is never treated as ours.
                try:
                    latest = self._observe_registration_state(binary).legacy
                except McpRegistrationError as exc:
                    raise McpRegistrationError(
                        McpRegistrationReason.REGISTRATION_FAILED, {"legacy_state": "unknown"}
                    ) from exc
                if latest.state is McpRegistrationState.ABSENT:
                    continue
                if latest != registrations.legacy:
                    raise McpRegistrationError(
                        McpRegistrationReason.REGISTRATION_FAILED,
                        {"legacy_state": latest.state.value},
                    )
            try:
                remove_output = self._run((binary.executable_path, "mcp", "remove", name))
            except Exception as exc:
                # The name-based command may have mutated registration before a timeout or
                # harness failure surfaced. Its outcome is therefore unknown, never a
                # pre-mutation observation error.
                raise McpRegistrationError(McpRegistrationReason.REGISTRATION_FAILED, {}) from exc
            nonzero = nonzero or remove_output.exit_code != 0
        # A nonzero exit does not establish that the host left the entry present.
        # Reconcile once through the same bounded positive-absence probe as exit zero;
        # never retry the mutation or echo the host's output.
        details: dict[str, JsonValue] = {"exit_code_class": "nonzero"} if nonzero else {}
        try:
            after = self._observe_registration_state(binary)
        except McpRegistrationError as exc:
            # The name-based remove command already ran. Any unreadable or
            # malformed verification is therefore an outcome-unknown mutation,
            # not the pre-mutation observation reason.
            raise McpRegistrationError(McpRegistrationReason.REGISTRATION_FAILED, details) from exc
        if after.current.state is McpRegistrationState.FINISHUP_OWNED or (
            MCP_SERVER_NAME in names and after.current.state is not McpRegistrationState.ABSENT
        ):
            raise McpRegistrationError(
                McpRegistrationReason.REGISTRATION_FAILED,
                {**details, "verified_state": after.current.state.value},
            )
        if after.legacy.state is McpRegistrationState.FINISHUP_OWNED or (
            MCP_LEGACY_SERVER_NAME in names
            and after.legacy.state is not McpRegistrationState.ABSENT
        ):
            raise McpRegistrationError(
                McpRegistrationReason.REGISTRATION_FAILED,
                {**details, "legacy_state": after.legacy.state.value},
            )
        return McpRegistrationResult(
            binary.harness_id,
            McpRegistrationAction.UNREGISTER,
            preview.state_before,
            McpRegistrationState.ABSENT,
            preview.preview_digest,
            ("host_remove_returned_nonzero",) if nonzero else (),
        )


def probe_project_config_load(
    executable_path: str,
    codex_home: Path | None,
    project: Path,
    *,
    runner: Callable[[tuple[str, ...], str], CommandOutput] | None = None,
) -> Literal["loads", "fails", "unknown"]:
    """Ask Codex itself whether it loads configuration with ``project`` as working directory.

    ``codex mcp list --json`` merges the user layer with a trusted project's ``.codex`` layer
    exactly as a session there would; a nonzero exit means a session in that project cannot
    start. Output is never echoed. A probe that cannot run is ``unknown``, never ``loads``.
    """

    argv = (executable_path, "mcp", "list", "--json")
    try:
        output = (
            runner(argv, str(project))
            if runner is not None
            else _default_runner(argv, codex_home=codex_home, cwd=str(project))
        )
    except McpRegistrationError:
        return "unknown"
    return "loads" if output.exit_code == 0 else "fails"


def _has_transport(table: object) -> bool:
    if not isinstance(table, Mapping):
        return False
    entry = cast(Mapping[str, object], table)
    return entry.get("command") is not None or entry.get("url") is not None


def read_bounded_toml(path: Path) -> Mapping[str, object] | None:
    import tomllib

    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _OUTPUT_LIMIT_BYTES:
            return None
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError, UnicodeError, tomllib.TOMLDecodeError:
        return None


def project_transport_dependence(
    project: Path, *, after_sweep: bool, names: Sequence[str] = (MCP_SERVER_NAME,)
) -> Literal["none", "depends", "unknown"]:
    """Whether ``project``'s Codex layer needs the user-level ``mcp_servers.finishup`` transport.

    ``depends`` means ``<project>/.codex/config.toml`` declares ``mcp_servers.finishup`` (for
    example a ``tools.*`` approval table) without its own ``command`` or ``url``: Codex then
    refuses to load configuration in that project once the user-level registration is gone.
    ``after_sweep`` first removes the exact tables the admission sweep would remove, so the
    answer describes the project after a disconnect; the sweep never edits a foreign surface (an
    edited approval table, a server-wide default), so nothing is removed from one. ``unknown``
    is a file FinishUP cannot read safely (symlink, oversized, not UTF-8 TOML). ``names`` are
    the user-level server keys the caller is about to remove: a disconnect that also removes an
    owned entry under the earlier ``yoetz`` key passes both, so a project table that still needs
    that transport stops it too (ADR-048). The sweep removes the exact legacy approval tables as
    well.
    """

    from finishup.adapters.integrations.host_admission import (
        CODEX_EXTERNAL_ADMISSION_TABLE,
        CODEX_LEGACY_ADMISSION_TABLES,
        CODEX_PLUGIN_ADMISSION_TABLE,
        codex_sweep_edits,
    )
    from finishup.adapters.integrations.toml_tables import strip_exact_table

    raw, problem = _read_project_config(project)
    if problem is not None:
        return "unknown"
    if raw is None:
        return "none"
    if after_sweep and codex_sweep_edits(raw):
        for table in (
            CODEX_EXTERNAL_ADMISSION_TABLE,
            CODEX_PLUGIN_ADMISSION_TABLE,
            *CODEX_LEGACY_ADMISSION_TABLES,
        ):
            raw = strip_exact_table(raw, table)
    import tomllib

    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except UnicodeError, tomllib.TOMLDecodeError:
        return "unknown"
    servers = parsed.get("mcp_servers")
    if not isinstance(servers, Mapping):
        return "none"
    for name in names:
        entry = cast(Mapping[str, object], servers).get(name)
        if entry is not None and not _has_transport(entry):
            return "depends"
    return "none"


def _read_project_config(project: Path) -> tuple[bytes | None, str | None]:
    """The bytes of ``<project>/.codex/config.toml`` (``None`` when absent), or why not.

    The reason is a closed token: ``symlink``, ``not_regular_file``, ``oversized`` (over 64 KiB),
    ``unreadable``; parsing is the caller's (``not_valid_toml``).
    """

    path = project / ".codex" / "config.toml"
    try:
        if not os.path.lexists(path):
            return None, None
        if path.is_symlink():
            return None, "symlink"
        if not path.is_file():
            return None, "not_regular_file"
        if path.stat().st_size > _OUTPUT_LIMIT_BYTES:
            return None, "oversized"
        return path.read_bytes(), None
    except OSError:
        return None, "unreadable"


def project_config_unreadable_reason(project: Path) -> str | None:
    """Why ``<project>/.codex/config.toml`` cannot be read safely, or ``None`` when it can.

    One of ``PROJECT_CONFIG_UNREADABLE_REASONS``; an absent file is readable (nothing in it).
    """

    import tomllib

    raw, problem = _read_project_config(project)
    if problem is not None or raw is None:
        return problem
    try:
        tomllib.loads(raw.decode("utf-8"))
    except UnicodeError, tomllib.TOMLDecodeError:
        return "not_valid_toml"
    return None


def legacy_registration_shaped(config: Mapping[str, object]) -> bool:
    """Whether a user-level Codex config holds a FinishUP-shaped ``mcp_servers.yoetz`` entry.

    Static and conservative: the command matches one of the FinishUP serve templates under either
    launcher spelling. The adapter's ownership proof (the launcher itself) needs ``codex mcp``;
    callers use this where an unproven owned entry may only make them more careful (ADR-048).
    """

    servers = config.get("mcp_servers")
    if not isinstance(servers, Mapping):
        return False
    entry = cast(Mapping[str, object], servers).get(MCP_LEGACY_SERVER_NAME)
    if not isinstance(entry, Mapping):
        return False
    tokens = _entry_command_tokens(cast(Mapping[str, object], entry))
    return tokens is not None and mcp_command_profile(tokens) is not None


def _has_control_character(text: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in text)


def _read_user_config(path: Path) -> Mapping[str, object] | None:
    """The user ``config.toml`` within Codex's own bound, ``{}`` when absent, ``None`` when unsafe."""

    import tomllib

    try:
        if not os.path.lexists(path):
            return {}
        if path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size > _USER_CONFIG_LIMIT_BYTES:
            return None
        return tomllib.loads(path.read_bytes().decode("utf-8"))
    except OSError, UnicodeError, tomllib.TOMLDecodeError:
        return None


def home_project_candidates(codex_home: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The existing project directories this Codex home knows, and what could not be read.

    Candidates are the ``[projects."<path>"]`` rows of the user ``config.toml`` and the home's
    verified members (the FinishUP marketplace binding, the connected-projects record, and a
    Yoetz-era bound project, ADR-012). The second value lists, as closed tokens
    (``LEGACY_UNREAD_REASONS``), why the list may not be whole: the user configuration
    (``user_config_unreadable``) or the members (``connected_projects_unreadable``) could not be
    read, or a known path holds a control character (``project_path_unsafe``) and was neither
    read nor returned, so it never reaches text or a preview.
    """

    from finishup.adapters.integrations.codex_marketplace import connected_projects
    from finishup.ports.integrations import IntegrationError

    if not os.path.lexists(codex_home):
        # A home that does not exist knows no projects (and holds no registration).
        return (), ()
    unread: set[str] = set()
    config = _read_user_config(codex_home / "config.toml")
    if config is None:
        unread.add("user_config_unreadable")
    candidates: set[str] = set()
    projects = (config or {}).get("projects")
    if isinstance(projects, Mapping):
        candidates.update(str(key) for key in cast(Mapping[object, object], projects))
    try:
        candidates.update(connected_projects(codex_home))
    except IntegrationError:
        # The members are read from that configuration too: name the record only when the
        # configuration itself was readable, so the first fix named is the one that helps.
        if config is not None:
            unread.add("connected_projects_unreadable")
    if any(_has_control_character(candidate) for candidate in candidates):
        unread.add("project_path_unsafe")
    return (
        tuple(
            sorted(
                candidate
                for candidate in candidates
                if not _has_control_character(candidate)
                and Path(candidate).is_absolute()
                and Path(candidate).is_dir()
            )
        ),
        tuple(sorted(unread)),
    )


@dataclass(frozen=True, slots=True)
class LegacyRegistrationUse:
    """Why an owned ``yoetz`` entry must stay beside ``finishup`` (ADR-048, #1073).

    ``needed_by``: projects whose readable ``.codex/config.toml`` names ``mcp_servers.yoetz``
    without a transport of its own. ``unreadable``: projects whose ``.codex/config.toml`` cannot be
    read safely. ``unread``: closed tokens for what of the home itself could not be read.
    """

    needed_by: tuple[str, ...]
    unreadable: tuple[str, ...]
    unread: tuple[str, ...]

    @property
    def kept_for(self) -> tuple[str, ...]:
        return tuple(sorted({*self.needed_by, *self.unreadable}))

    @property
    def unchecked(self) -> bool:
        return bool(self.unread)

    @property
    def keeps(self) -> bool:
        return bool(self.needed_by or self.unreadable or self.unread)


def legacy_registration_dependents(codex_home: Path | None) -> LegacyRegistrationUse:
    """Which projects still need the user-level ``yoetz`` transport, read in full (ADR-048).

    Such a project's ``.codex/config.toml`` names ``mcp_servers.yoetz`` without a ``command`` or
    ``url`` of its own (the exact ``[mcp_servers.yoetz.tools.check]`` a Yoetz 0.2
    ``integrate codex admission grant`` wrote, for example), or cannot be read safely. Removing
    the owned ``yoetz`` entry would stop Codex loading configuration there (#1073). Every project
    the home knows is read: each read is a bounded small file (64 KiB), so there is no window to
    fall outside of; only an input that cannot be read leaves the answer unchecked.
    """

    candidates, unread = home_project_candidates(_selected_codex_home(codex_home))
    needed_by: list[str] = []
    unreadable: list[str] = []
    for candidate in candidates:
        dependence = project_transport_dependence(
            Path(candidate), after_sweep=False, names=(MCP_LEGACY_SERVER_NAME,)
        )
        if dependence == "depends":
            needed_by.append(candidate)
        elif dependence == "unknown":
            unreadable.append(candidate)
    return LegacyRegistrationUse(tuple(needed_by), tuple(unreadable), unread)


def codex_project_mcp_leftovers(
    codex_home: Path | None, project: Path
) -> tuple[tuple[str, Literal["tools_only", "retained_tables"]], ...]:
    """Each project ``mcp_servers.<name>`` table with no transport anywhere, by server key.

    Both keys are read: ``finishup``, and the earlier ``yoetz`` key whose approval tables Yoetz
    0.1-0.2 wrote and whose disconnects never removed (ADR-048). A key's table is left over when
    ``<project>/.codex/config.toml`` declares it (for example only its ``tools.check`` admission)
    while neither that layer nor the user layer supplies its ``command`` or ``url``; Codex then
    rejects the merged server as ``invalid transport`` and refuses to start in that project.
    ``tools_only``: only exact approval tables remain, which an admission revoke removes;
    ``retained_tables``: tables FinishUP did not write (or that were edited) remain.
    """

    project_config = read_bounded_toml(project / ".codex" / "config.toml")
    if project_config is None:
        return ()
    servers = project_config.get("mcp_servers")
    if not isinstance(servers, Mapping):
        return ()
    user_config = read_bounded_toml(_selected_codex_home(codex_home) / "config.toml") or {}
    user_servers = user_config.get("mcp_servers")
    found: list[tuple[str, Literal["tools_only", "retained_tables"]]] = []
    for name in (MCP_SERVER_NAME, MCP_LEGACY_SERVER_NAME):
        project_entry = cast(Mapping[str, object], servers).get(name)
        if project_entry is None or _has_transport(project_entry):
            continue
        user_entry = (
            cast(Mapping[str, object], user_servers).get(name)
            if isinstance(user_servers, Mapping)
            else None
        )
        if _has_transport(user_entry):
            continue
        # A revoke removes the exact tables of this key only from a surface it edits; anything
        # else naming the key is the owner's to edit (or, for ``finishup``, to register again).
        found.append(
            (
                name,
                "tools_only"
                if project_transport_dependence(project, after_sweep=True, names=(name,)) == "none"
                else "retained_tables",
            )
        )
    return tuple(found)


def codex_project_mcp_leftover(codex_home: Path | None, project: Path) -> str | None:
    """Name a project table that has no transport anywhere, statically, under either key.

    Returns ``"tools_only"`` when every such table is an exact approval table an admission
    revoke removes, ``"retained_tables"`` when any other table remains (see
    ``codex_project_mcp_leftovers``). ``None`` means no such leftover was read.
    """

    leftovers = codex_project_mcp_leftovers(codex_home, project)
    if not leftovers:
        return None
    return (
        "retained_tables"
        if any(kind == "retained_tables" for _name, kind in leftovers)
        else "tools_only"
    )
