"""Harness-neutral MCP server registration boundary, separate from skill install."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Final, Literal, Protocol, cast

from finishup.domain.values import JsonObject, JsonValue, validate_sha256_digest
from finishup.ports.integrations import HarnessId
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.errors import PROTOCOL_REASON_CODES, ProtocolValueError

__all__ = [
    "MCP_SERVE_COMMAND",
    "MCP_STRICT_SERVE_COMMAND",
    "MCP_SERVER_NAME",
    "HarnessBinary",
    "HarnessMcpPort",
    "McpRegistrationAction",
    "McpRegistrationCommand",
    "McpRegistrationError",
    "McpIsolationBinding",
    "McpRegistrationObservation",
    "McpRegistrationPreview",
    "McpRegistrationReason",
    "McpRegistrationResult",
    "McpRegistrationState",
]

MCP_SERVER_NAME: Final = "finishup"
MCP_SERVE_COMMAND: Final = ("finishup", "mcp", "serve", "--host", "codex")
MCP_STRICT_SERVE_COMMAND: Final = (*MCP_SERVE_COMMAND, "--semantic", "off")
# Registrations created before host identity became explicit remain recognizable for a bounded
# status/remove/reinstall transition. They are never emitted by a new preview or renderer.
MCP_LEGACY_SERVE_COMMAND: Final = ("finishup", "mcp", "serve")
MCP_LEGACY_STRICT_SERVE_COMMAND: Final = (*MCP_LEGACY_SERVE_COMMAND, "--semantic", "off")

_MAX_PATH_CHARS: Final = 4_096
_MAX_VERSION_CHARS: Final = 64
_MAX_WARNINGS: Final = 16
_TOKEN_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$", re.ASCII)

type Compatibility = Literal["supported", "untested"]
type McpIsolationBinding = Literal["ambient", "isolated_exact", "missing", "different"]


def mcp_command_profile(command: tuple[str, ...]) -> Literal["policy", "strict"] | None:
    """Validate command shape only; executable ownership belongs to the adapter."""

    if type(command) is not tuple or not command or any(type(x) is not str for x in command):
        return None
    launcher = command[0]
    if launcher != "finishup" and (
        not launcher.startswith("/")
        or len(launcher) > _MAX_PATH_CHARS
        or str(PurePosixPath(launcher)) != launcher
        or ".." in PurePosixPath(launcher).parts
        or any(ord(c) < 32 or ord(c) == 127 for c in launcher)
    ):
        return None
    for template, profile in (
        (MCP_SERVE_COMMAND, "policy"),
        (MCP_STRICT_SERVE_COMMAND, "strict"),
        (MCP_LEGACY_SERVE_COMMAND, "policy"),
        (MCP_LEGACY_STRICT_SERVE_COMMAND, "strict"),
    ):
        if command[1:] == template[1:]:
            return cast(Literal["policy", "strict"], profile)
    return None


def _port_error(reason: str) -> ProtocolValueError:
    if reason not in PROTOCOL_REASON_CODES:
        reason = "invalid_event_value_type"
    return ProtocolValueError(reason)


class McpRegistrationState(str, Enum):  # noqa: UP042 - exact wire-valued Enum is required
    ABSENT = "absent"
    FINISHUP_OWNED = "yoetz_owned"
    FOREIGN_PRESENT = "foreign_present"


class McpRegistrationAction(str, Enum):  # noqa: UP042 - exact wire-valued Enum is required
    REGISTER = "register"
    REREGISTER = "reregister"
    UNREGISTER = "unregister"
    NOOP = "noop"


class McpRegistrationReason(str, Enum):  # noqa: UP042 - exact wire-valued Enum is required
    CONFIRMATION_REQUIRED = "confirmation_required"
    PREVIEW_STALE = "preview_stale"
    HARNESS_UNAVAILABLE = "harness_unavailable"
    PARSE_FAILED = "parse_failed"
    TIMEOUT = "timeout"
    REGISTRATION_FAILED = "registration_failed"
    FOREIGN_ENTRY_PRESENT = "foreign_entry_present"
    ISOLATION_INVALID = "isolation_invalid"


@dataclass(frozen=True, slots=True, repr=False)
class HarnessBinary:
    """One discovered harness executable; the path is never echoed in repr."""

    harness_id: HarnessId
    executable_path: str
    reported_version: str | None
    compatibility: Compatibility

    def __post_init__(self) -> None:
        if type(self.harness_id) is not HarnessId:
            raise _port_error("integration_harness_invalid")
        if (
            type(self.executable_path) is not str
            or not 1 <= len(self.executable_path) <= _MAX_PATH_CHARS
            or any(ord(char) < 32 or ord(char) == 127 for char in self.executable_path)
        ):
            raise _port_error("integration_target_invalid")
        if self.reported_version is not None and (
            type(self.reported_version) is not str
            or not 1 <= len(self.reported_version) <= _MAX_VERSION_CHARS
            or not self.reported_version.isascii()
            or not self.reported_version.isprintable()
        ):
            raise _port_error("integration_value_invalid")
        if self.compatibility not in {"supported", "untested"}:
            raise _port_error("integration_compatibility_invalid")

    def __repr__(self) -> str:
        return (
            "HarnessBinary("
            f"harness_id={self.harness_id.value!r}, "
            f"reported_version={self.reported_version!r}, "
            f"compatibility={self.compatibility!r}, executable_path=<redacted>)"
        )

    __str__ = __repr__


@dataclass(frozen=True, slots=True)
class McpRegistrationPreview:
    harness_id: HarnessId
    action: McpRegistrationAction
    state_before: McpRegistrationState
    warnings: tuple[str, ...]
    preview_digest: str
    serve_command: tuple[str, ...] = MCP_SERVE_COMMAND
    route_profile: Literal["policy", "strict"] = "policy"
    isolated_root: str | None = None

    def __post_init__(self) -> None:
        if type(self.harness_id) is not HarnessId:
            raise _port_error("integration_harness_invalid")
        if type(self.action) is not McpRegistrationAction:
            raise _port_error("integration_action_invalid")
        if type(self.state_before) is not McpRegistrationState:
            raise _port_error("integration_state_invalid")
        if type(self.warnings) is not tuple or len(self.warnings) > _MAX_WARNINGS:
            raise _port_error("integration_value_invalid")
        previous: str | None = None
        for warning in self.warnings:
            if type(warning) is not str or not warning or not warning.isascii():
                raise _port_error("integration_value_invalid")
            if previous is not None and warning <= previous:
                raise _port_error("integration_value_invalid")
            previous = warning
        validate_sha256_digest(self.preview_digest)
        if self.route_profile not in {"policy", "strict"} or (
            mcp_command_profile(self.serve_command) != self.route_profile
        ):
            raise _port_error("integration_value_invalid")
        if self.isolated_root is not None and (
            type(self.isolated_root) is not str
            or not 1 <= len(self.isolated_root) <= _MAX_PATH_CHARS
            or not self.isolated_root.startswith("/")
            or any(ord(char) < 32 or ord(char) == 127 for char in self.isolated_root)
        ):
            raise _port_error("integration_target_invalid")


@dataclass(frozen=True, slots=True)
class McpRegistrationObservation:
    """One read-only registration probe, including *which* FinishUP route is registered.

    ``status_registration`` answers only "is this entry ours", which reads identically for a
    policy and a strict registration. Reporting a route posture requires the extra fact, so it
    is carried here rather than by widening the state enum. ``route_profile`` is non-null only
    when the entry is FinishUP-owned; a foreign or absent entry has no FinishUP route to describe.
    """

    harness_id: HarnessId
    state: McpRegistrationState
    route_profile: Literal["policy", "strict"] | None
    isolation_binding: McpIsolationBinding | None = None
    serve_command: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if type(self.harness_id) is not HarnessId:
            raise _port_error("integration_harness_invalid")
        if type(self.state) is not McpRegistrationState:
            raise _port_error("integration_state_invalid")
        if self.serve_command is not None and (
            self.state is not McpRegistrationState.FINISHUP_OWNED
            or self.route_profile is None
            or mcp_command_profile(self.serve_command) != self.route_profile
        ):
            raise _port_error("integration_value_invalid")
        if self.route_profile is None:
            if self.isolation_binding is not None:
                raise _port_error("integration_value_invalid")
            return
        if (
            self.route_profile not in {"policy", "strict"}
            or self.state is not McpRegistrationState.FINISHUP_OWNED
            or self.isolation_binding not in {"ambient", "isolated_exact", "missing", "different"}
        ):
            raise _port_error("integration_value_invalid")


@dataclass(frozen=True, slots=True)
class McpRegistrationCommand:
    preview_digest: str
    explicitly_accepted: bool

    def __post_init__(self) -> None:
        validate_sha256_digest(self.preview_digest)
        if type(self.explicitly_accepted) is not bool:
            raise _port_error("integration_action_invalid")


@dataclass(frozen=True, slots=True)
class McpRegistrationResult:
    harness_id: HarnessId
    action: McpRegistrationAction
    state_before: McpRegistrationState
    state_after: McpRegistrationState
    preview_digest: str
    warnings: tuple[Literal["host_remove_returned_nonzero"], ...] = ()

    def __post_init__(self) -> None:
        if type(self.harness_id) is not HarnessId:
            raise _port_error("integration_harness_invalid")
        if type(self.action) is not McpRegistrationAction:
            raise _port_error("integration_action_invalid")
        if (
            type(self.state_before) is not McpRegistrationState
            or type(self.state_after) is not McpRegistrationState
        ):
            raise _port_error("integration_state_invalid")
        validate_sha256_digest(self.preview_digest)
        if self.warnings not in ((), ("host_remove_returned_nonzero",)) or (
            self.warnings
            and (
                self.action is not McpRegistrationAction.UNREGISTER
                or self.state_after is not McpRegistrationState.ABSENT
            )
        ):
            raise _port_error("integration_value_invalid")


@dataclass(frozen=True, slots=True)
class McpRegistrationError(Exception):
    reason: McpRegistrationReason
    safe_details: Mapping[str, JsonValue]

    def __post_init__(self) -> None:
        if type(self.reason) is not McpRegistrationReason:
            raise _port_error("integration_reason_invalid")
        try:
            details = JsonObject(self.safe_details)
        except ProtocolValueError as exc:
            raise _port_error("integration_error_invalid") from exc
        if (
            len(details) > 16
            or len(canonical_encode(details)) > 4_096
            or any(_TOKEN_RE.fullmatch(key) is None for key in details)
        ):
            raise _port_error("integration_error_invalid")
        object.__setattr__(self, "safe_details", details)
        Exception.__init__(self, self.reason.value)


class HarnessMcpPort(Protocol):
    async def status_registration(self, binary: HarnessBinary) -> McpRegistrationState: ...

    async def observe_registration(self, binary: HarnessBinary) -> McpRegistrationObservation: ...

    async def preview_registration(self, binary: HarnessBinary) -> McpRegistrationPreview: ...

    async def apply_registration(
        self,
        binary: HarnessBinary,
        command: McpRegistrationCommand,
    ) -> McpRegistrationResult: ...

    async def preview_unregistration(self, binary: HarnessBinary) -> McpRegistrationPreview: ...

    async def apply_unregistration(
        self,
        binary: HarnessBinary,
        command: McpRegistrationCommand,
    ) -> McpRegistrationResult: ...
