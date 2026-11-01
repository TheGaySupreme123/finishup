"""Harness MCP registration preview, confirmation, and status service."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast

from finishup.application.applied_mcp_route import clear_applied_route, record_applied_route
from finishup.domain.values import validate_sha256_digest
from finishup.ports.harness_mcp import (
    MCP_SERVE_COMMAND,
    MCP_STRICT_SERVE_COMMAND,
    HarnessBinary,
    HarnessMcpPort,
    McpRegistrationCommand,
    McpRegistrationError,
    McpRegistrationObservation,
    McpRegistrationPreview,
    McpRegistrationReason,
    McpRegistrationResult,
    McpRegistrationState,
)
from finishup.ports.integrations import HarnessId
from finishup.protocol.canonical import JsonValue
from finishup.protocol.mcp_removal import CompletedMcpRemoval, UnverifiedMcpRemoval

__all__ = [
    "HarnessMcpDiagnosticSink",
    "HarnessMcpService",
    "McpRegistrationConfirmation",
    "McpRegistrationDiagnostic",
    "mcp_removal_report",
]

type ConfirmationChannel = Literal["interactive", "noninteractive_flag"]


def mcp_removal_report(
    result: McpRegistrationResult | McpRegistrationError,
) -> dict[str, JsonValue]:
    """Render only closed state and warning tokens, never host payloads."""

    report: CompletedMcpRemoval | UnverifiedMcpRemoval
    if isinstance(result, McpRegistrationResult):
        if result.state_after is not McpRegistrationState.ABSENT:
            raise ValueError("mcp_removal_not_absent")
        report = CompletedMcpRemoval(warnings=list(result.warnings))
    else:
        state = result.safe_details.get("verified_state")
        report = UnverifiedMcpRemoval(
            state_after=(
                "yoetz_owned"
                if state == "yoetz_owned"
                else "foreign_present"
                if state == "foreign_present"
                else None
            ),
            warnings=(
                ["host_remove_returned_nonzero"]
                if result.safe_details.get("exit_code_class") == "nonzero"
                else []
            ),
        )
    return cast(dict[str, JsonValue], report.model_dump(by_alias=True))


def _invalid(reason: str) -> ValueError:
    return ValueError(reason)


@dataclass(frozen=True, slots=True)
class McpRegistrationConfirmation:
    preview_digest: str
    explicitly_accepted: bool
    channel: ConfirmationChannel

    def __post_init__(self) -> None:
        validate_sha256_digest(self.preview_digest)
        if type(self.explicitly_accepted) is not bool:
            raise _invalid("integration_confirmation_invalid")
        if type(self.channel) is not str or self.channel not in {
            "interactive",
            "noninteractive_flag",
        }:
            raise _invalid("integration_confirmation_invalid")


@dataclass(frozen=True, slots=True)
class McpRegistrationDiagnostic:
    """Path-free structural observation for one MCP registration service call."""

    harness: HarnessId
    phase: Literal["preview", "status", "execute"]
    outcome: Literal["success", "failed"]
    state_before: McpRegistrationState | None
    state_after: McpRegistrationState | None
    preview_digest: str | None
    reason: McpRegistrationReason | None

    def __post_init__(self) -> None:
        if type(self.harness) is not HarnessId:
            raise _invalid("integration_diagnostic_invalid")
        if self.phase not in {"preview", "status", "execute"} or self.outcome not in {
            "success",
            "failed",
        }:
            raise _invalid("integration_diagnostic_invalid")
        if self.state_before is not None and type(self.state_before) is not McpRegistrationState:
            raise _invalid("integration_diagnostic_invalid")
        if self.state_after is not None and type(self.state_after) is not McpRegistrationState:
            raise _invalid("integration_diagnostic_invalid")
        if self.preview_digest is not None:
            validate_sha256_digest(self.preview_digest)
        if (self.outcome == "success") != (self.reason is None):
            raise _invalid("integration_diagnostic_invalid")
        if self.reason is not None and type(self.reason) is not McpRegistrationReason:
            raise _invalid("integration_diagnostic_invalid")


class HarnessMcpDiagnosticSink(Protocol):
    def record_mcp_registration(self, diagnostic: McpRegistrationDiagnostic) -> None: ...


class _NullSink:
    def record_mcp_registration(self, diagnostic: McpRegistrationDiagnostic) -> None:
        del diagnostic


class HarnessMcpService:
    """Bind every MCP registration mutation to an exact confirmed preview."""

    __slots__ = ("_diagnostics", "_port")

    def __init__(
        self,
        port: HarnessMcpPort,
        diagnostics: HarnessMcpDiagnosticSink | None = None,
    ) -> None:
        self._port = port
        self._diagnostics = _NullSink() if diagnostics is None else diagnostics

    async def status(self, binary: HarnessBinary) -> McpRegistrationState:
        if type(binary) is not HarnessBinary:
            raise _invalid("integration_request_invalid")
        try:
            state = await self._port.status_registration(binary)
        except McpRegistrationError as exc:
            self._diagnostics.record_mcp_registration(
                McpRegistrationDiagnostic(
                    binary.harness_id, "status", "failed", None, None, None, exc.reason
                )
            )
            raise
        self._diagnostics.record_mcp_registration(
            McpRegistrationDiagnostic(
                binary.harness_id, "status", "success", state, state, None, None
            )
        )
        return state

    async def observe(self, binary: HarnessBinary) -> McpRegistrationObservation:
        """Read registration state *and* the registered route profile in one probe.

        Shares the ``status`` phase because it reads exactly what ``status`` reads and mutates
        nothing; the diagnostic shape is unchanged.
        """

        if type(binary) is not HarnessBinary:
            raise _invalid("integration_request_invalid")
        try:
            observation = await self._port.observe_registration(binary)
        except McpRegistrationError as exc:
            self._diagnostics.record_mcp_registration(
                McpRegistrationDiagnostic(
                    binary.harness_id, "status", "failed", None, None, None, exc.reason
                )
            )
            raise
        self._diagnostics.record_mcp_registration(
            McpRegistrationDiagnostic(
                binary.harness_id,
                "status",
                "success",
                observation.state,
                observation.state,
                None,
                None,
            )
        )
        return observation

    async def preview(self, binary: HarnessBinary) -> McpRegistrationPreview:
        if type(binary) is not HarnessBinary:
            raise _invalid("integration_request_invalid")
        try:
            preview = await self._port.preview_registration(binary)
        except McpRegistrationError as exc:
            self._diagnostics.record_mcp_registration(
                McpRegistrationDiagnostic(
                    binary.harness_id, "preview", "failed", None, None, None, exc.reason
                )
            )
            raise
        self._diagnostics.record_mcp_registration(
            McpRegistrationDiagnostic(
                binary.harness_id,
                "preview",
                "success",
                preview.state_before,
                preview.state_before,
                preview.preview_digest,
                None,
            )
        )
        return preview

    async def register(
        self,
        binary: HarnessBinary,
        confirmation: McpRegistrationConfirmation,
        *,
        _state: Path | None = None,
    ) -> McpRegistrationResult:
        if type(binary) is not HarnessBinary:
            raise _invalid("integration_request_invalid")
        if type(confirmation) is not McpRegistrationConfirmation:
            raise _invalid("integration_confirmation_invalid")
        try:
            if not confirmation.explicitly_accepted:
                raise McpRegistrationError(McpRegistrationReason.CONFIRMATION_REQUIRED, {})
            result = await self._port.apply_registration(
                binary,
                McpRegistrationCommand(confirmation.preview_digest, True),
            )
        except McpRegistrationError as exc:
            self._diagnostics.record_mcp_registration(
                McpRegistrationDiagnostic(
                    binary.harness_id, "execute", "failed", None, None, None, exc.reason
                )
            )
            raise
        self._diagnostics.record_mcp_registration(
            McpRegistrationDiagnostic(
                binary.harness_id,
                "execute",
                "success",
                result.state_before,
                result.state_after,
                result.preview_digest,
                None,
            )
        )
        # A NOOP register is included on purpose: it still leaves the host on the route the
        # owner accepted, so the record has to agree with it rather than keep an earlier
        # entry that would then read as drift (issue #537).
        if result.state_after is McpRegistrationState.FINISHUP_OWNED:
            await self._remember_applied_route(binary, result.preview_digest, _state)
        return result

    async def preview_unregistration(self, binary: HarnessBinary) -> McpRegistrationPreview:
        if type(binary) is not HarnessBinary:
            raise _invalid("integration_request_invalid")
        try:
            preview = await self._port.preview_unregistration(binary)
        except McpRegistrationError as exc:
            self._diagnostics.record_mcp_registration(
                McpRegistrationDiagnostic(
                    binary.harness_id, "preview", "failed", None, None, None, exc.reason
                )
            )
            raise
        self._diagnostics.record_mcp_registration(
            McpRegistrationDiagnostic(
                binary.harness_id,
                "preview",
                "success",
                preview.state_before,
                preview.state_before,
                preview.preview_digest,
                None,
            )
        )
        return preview

    async def unregister(
        self,
        binary: HarnessBinary,
        confirmation: McpRegistrationConfirmation,
        *,
        _state: Path | None = None,
    ) -> McpRegistrationResult:
        if type(binary) is not HarnessBinary:
            raise _invalid("integration_request_invalid")
        if type(confirmation) is not McpRegistrationConfirmation:
            raise _invalid("integration_confirmation_invalid")
        try:
            if not confirmation.explicitly_accepted:
                raise McpRegistrationError(McpRegistrationReason.CONFIRMATION_REQUIRED, {})
            result = await self._port.apply_unregistration(
                binary,
                McpRegistrationCommand(confirmation.preview_digest, True),
            )
        except McpRegistrationError as exc:
            self._diagnostics.record_mcp_registration(
                McpRegistrationDiagnostic(
                    binary.harness_id, "execute", "failed", None, None, None, exc.reason
                )
            )
            raise
        self._diagnostics.record_mcp_registration(
            McpRegistrationDiagnostic(
                binary.harness_id,
                "execute",
                "success",
                result.state_before,
                result.state_after,
                result.preview_digest,
                None,
            )
        )
        if result.state_after is McpRegistrationState.ABSENT:
            try:
                clear_applied_route(_state=_state)
            except Exception:
                pass
        return result

    def reconcile_applied_route(
        self,
        binary: HarnessBinary,
        preview: McpRegistrationPreview,
        *,
        _state: Path | None = None,
    ) -> None:
        """Refresh the applied-route record for an accepted install that changed nothing.

        A ``NOOP`` registration preview is only reached when the host's own entry already
        equals the command the ceremony would have written, so the host is on
        ``preview.route_profile`` and no second host read is needed to say so. Recording it
        is what keeps a deliberate re-registration from leaving an earlier entry behind for
        every later status to report as drift (issue #537). Callers must first check that
        ``preview.state_before`` is ``FINISHUP_OWNED``: every other state reaches ``NOOP``
        through the fall-through branch and proves nothing about the route. Fail-soft like
        every other write on this path.
        """

        try:
            if binary.harness_id is not HarnessId.CODEX:
                return
            profile = preview.route_profile
            if profile != "policy" and profile != "strict":
                return
            serve_command = preview.serve_command
            record_applied_route(
                profile,
                list(serve_command),
                list(serve_command),
                preview.preview_digest,
                _state=_state,
            )
        except Exception:
            # An unrecordable route must read as no applied route, never as stale drift.
            try:
                clear_applied_route(_state=_state)
            except Exception:
                pass

    async def _remember_applied_route(
        self,
        binary: HarnessBinary,
        preview_digest: str,
        _state: Path | None,
    ) -> None:
        """Persist the verified post-write route; persistence never fails the install.

        Both command fields carry the same verified post-write command, because the
        record describes what the host serves after the ceremony, not what the caller
        asked for. A failed post-write verification clears any stale record fail-soft
        so a prior policy entry never survives a strict install it cannot describe.
        """

        def _clear_stale() -> None:
            try:
                clear_applied_route(_state=_state)
            except Exception:
                pass

        try:
            if binary.harness_id is not HarnessId.CODEX:
                return
            try:
                observation = await self._port.observe_registration(binary)
            except Exception:
                _clear_stale()
                return
            if observation.state is not McpRegistrationState.FINISHUP_OWNED:
                _clear_stale()
                return
            profile = observation.route_profile
            if profile is None:
                _clear_stale()
                return
            if profile != "policy" and profile != "strict":
                _clear_stale()
                return
            serve_command = observation.serve_command or (
                MCP_STRICT_SERVE_COMMAND if profile == "strict" else MCP_SERVE_COMMAND
            )
            try:
                record_applied_route(
                    profile,
                    list(serve_command),
                    list(serve_command),
                    preview_digest,
                    _state=_state,
                )
            except Exception:
                _clear_stale()
                return
        except Exception:
            _clear_stale()
            return
