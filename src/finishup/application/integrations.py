"""Harness-neutral integration preview, confirmation, status, and removal service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from finishup.domain.values import RequestId, validate_sha256_digest
from finishup.ports.integrations import (
    HarnessId,
    IntegrationAction,
    IntegrationError,
    IntegrationPreview,
    IntegrationReason,
    IntegrationResult,
    IntegrationScope,
    IntegrationsPort,
    IntegrationState,
    IntegrationStatus,
    IntegrationTarget,
    SkillApplyCommand,
    SkillPreviewCommand,
    SkillStatusCommand,
)

__all__ = [
    "IntegrationConfirmation",
    "IntegrationDiagnostic",
    "IntegrationDiagnosticSink",
    "IntegrationRequest",
    "IntegrationService",
    "IntegrationStatusRequest",
]

type ConfirmationChannel = Literal["interactive", "noninteractive_flag"]


def _invalid(reason: str) -> ValueError:
    return ValueError(reason)


def _require_harness(value: object) -> HarnessId:
    if type(value) is not HarnessId:
        raise _invalid("integration_harness_invalid")
    return value


def _target(harness: HarnessId, project_root: str) -> IntegrationTarget:
    _require_harness(harness)
    return IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, project_root)


@dataclass(frozen=True, slots=True, repr=False)
class IntegrationRequest:
    request_id: RequestId
    harness: HarnessId
    project_root: str
    action: IntegrationAction
    replace_modified: bool = False

    def __post_init__(self) -> None:
        _require_harness(self.harness)
        target = _target(self.harness, self.project_root)
        command = SkillPreviewCommand(
            self.request_id,
            target,
            self.action,
            self.replace_modified,
        )
        object.__setattr__(self, "request_id", command.request_id)
        if type(self.action) is not IntegrationAction or self.action is IntegrationAction.NOOP:
            raise _invalid("integration_action_invalid")

    def __repr__(self) -> str:
        return (
            "IntegrationRequest("
            f"request_id={self.request_id!r}, harness={self.harness.value!r}, "
            f"action={self.action.value!r}, replace_modified={self.replace_modified!r}, "
            "project_root=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class IntegrationStatusRequest:
    harness: HarnessId
    project_root: str

    def __post_init__(self) -> None:
        _target(self.harness, self.project_root)

    def __repr__(self) -> str:
        return f"IntegrationStatusRequest(harness={self.harness.value!r}, project_root=<redacted>)"


@dataclass(frozen=True, slots=True)
class IntegrationConfirmation:
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
class IntegrationDiagnostic:
    """Path-free structural observation for one integration service call."""

    harness: HarnessId
    action: IntegrationAction
    phase: Literal["preview", "status", "execute"]
    outcome: Literal["success", "failed"]
    state_before: IntegrationState | None
    state_after: IntegrationState | None
    compatibility: Literal["supported", "unsupported", "untested"] | None
    managed_file_count: int
    source_digest: str | None
    installed_digest: str | None
    preview_digest: str | None
    reason: IntegrationReason | None

    def __post_init__(self) -> None:
        if type(self.harness) is not HarnessId or type(self.action) is not IntegrationAction:
            raise _invalid("integration_diagnostic_invalid")
        if self.phase not in {"preview", "status", "execute"} or self.outcome not in {
            "success",
            "failed",
        }:
            raise _invalid("integration_diagnostic_invalid")
        if self.state_before is not None and type(self.state_before) is not IntegrationState:
            raise _invalid("integration_diagnostic_invalid")
        if self.state_after is not None and type(self.state_after) is not IntegrationState:
            raise _invalid("integration_diagnostic_invalid")
        if self.compatibility is not None and self.compatibility not in {
            "supported",
            "unsupported",
            "untested",
        }:
            raise _invalid("integration_diagnostic_invalid")
        if type(self.managed_file_count) is not int or not 0 <= self.managed_file_count <= 64:
            raise _invalid("integration_diagnostic_invalid")
        for digest in (self.source_digest, self.installed_digest, self.preview_digest):
            if digest is not None:
                validate_sha256_digest(digest)
        if (self.outcome == "success") != (self.reason is None):
            raise _invalid("integration_diagnostic_invalid")
        if self.reason is not None and type(self.reason) is not IntegrationReason:
            raise _invalid("integration_diagnostic_invalid")


class IntegrationDiagnosticSink(Protocol):
    def record_integration(self, diagnostic: IntegrationDiagnostic) -> None: ...


class IntegrationService:
    """Validate harness intent and bind every mutation to an exact preview."""

    __slots__ = ("_diagnostics", "_integrations")

    def __init__(
        self,
        integrations: IntegrationsPort,
        diagnostics: IntegrationDiagnosticSink,
    ) -> None:
        self._integrations = integrations
        self._diagnostics = diagnostics

    def _record_preview(
        self,
        harness: HarnessId,
        preview: IntegrationPreview,
        *,
        phase: Literal["preview", "execute"],
    ) -> None:
        self._diagnostics.record_integration(
            IntegrationDiagnostic(
                harness,
                preview.action,
                phase,
                "success",
                preview.state_before,
                preview.state_before,
                preview.compatibility,
                len(preview.file_changes),
                preview.source_digest,
                preview.installed_digest,
                preview.preview_digest,
                None,
            )
        )

    def _record_failure(
        self,
        request: IntegrationRequest,
        phase: Literal["preview", "execute"],
        reason: IntegrationReason,
        preview: IntegrationPreview | None = None,
    ) -> None:
        self._diagnostics.record_integration(
            IntegrationDiagnostic(
                request.harness,
                request.action,
                phase,
                "failed",
                None if preview is None else preview.state_before,
                None,
                None if preview is None else preview.compatibility,
                0 if preview is None else len(preview.file_changes),
                None if preview is None else preview.source_digest,
                None if preview is None else preview.installed_digest,
                None if preview is None else preview.preview_digest,
                reason,
            )
        )

    async def preview_skill(self, request: IntegrationRequest) -> IntegrationPreview:
        if type(request) is not IntegrationRequest:
            raise _invalid("integration_request_invalid")
        target = _target(request.harness, request.project_root)
        try:
            result = await self._integrations.preview_skill(
                request.harness,
                SkillPreviewCommand(
                    request.request_id,
                    target,
                    request.action,
                    request.replace_modified,
                ),
            )
        except IntegrationError as exc:
            self._record_failure(request, "preview", exc.reason)
            raise
        self._record_preview(request.harness, result, phase="preview")
        return result

    async def status_skill(self, request: IntegrationStatusRequest) -> IntegrationStatus:
        if type(request) is not IntegrationStatusRequest:
            raise _invalid("integration_request_invalid")
        harness = _require_harness(request.harness)
        try:
            result = await self._integrations.status_skill(
                harness,
                SkillStatusCommand(_target(harness, request.project_root)),
            )
        except IntegrationError as exc:
            self._diagnostics.record_integration(
                IntegrationDiagnostic(
                    harness,
                    IntegrationAction.NOOP,
                    "status",
                    "failed",
                    None,
                    None,
                    None,
                    0,
                    None,
                    None,
                    None,
                    exc.reason,
                )
            )
            raise
        self._diagnostics.record_integration(
            IntegrationDiagnostic(
                harness,
                IntegrationAction.NOOP,
                "status",
                "success",
                result.state,
                result.state,
                result.compatibility,
                len(result.file_states),
                result.source_digest,
                result.installed_digest,
                None,
                None,
            )
        )
        return result

    @staticmethod
    def _confirmed_apply(
        request: IntegrationRequest,
        confirmation: IntegrationConfirmation,
        preview: IntegrationPreview,
    ) -> SkillApplyCommand:
        if type(confirmation) is not IntegrationConfirmation:
            raise _invalid("integration_confirmation_invalid")
        if not confirmation.explicitly_accepted:
            raise IntegrationError(IntegrationReason.CONFIRMATION_REQUIRED, {})
        if confirmation.preview_digest != preview.preview_digest:
            raise IntegrationError(IntegrationReason.PREVIEW_STALE, {})
        if preview.compatibility == "unsupported":
            raise IntegrationError(IntegrationReason.VERSION_INCOMPATIBLE, {})
        if (
            preview.state_before is IntegrationState.MODIFIED
            and not request.replace_modified
            and "owned_skill_update" not in preview.warnings
        ):
            raise IntegrationError(IntegrationReason.MODIFIED_COPY, {})
        if preview.state_before is IntegrationState.PARTIAL and not request.replace_modified:
            raise IntegrationError(IntegrationReason.PARTIAL_INSTALL, {})
        return SkillApplyCommand(
            request.request_id,
            _target(request.harness, request.project_root),
            request.action,
            confirmation.preview_digest,
            True,
            request.replace_modified,
        )

    async def install_skill(
        self,
        request: IntegrationRequest,
        confirmation: IntegrationConfirmation,
    ) -> IntegrationResult:
        if type(request) is not IntegrationRequest or request.action not in {
            IntegrationAction.INSTALL,
            IntegrationAction.REPLACE,
        }:
            raise _invalid("integration_action_invalid")
        preview = await self.preview_skill(request)
        try:
            command = self._confirmed_apply(request, confirmation, preview)
            result = await self._integrations.install_skill(request.harness, command)
        except IntegrationError as exc:
            self._record_failure(request, "execute", exc.reason, preview)
            raise
        self._diagnostics.record_integration(
            IntegrationDiagnostic(
                request.harness,
                result.action,
                "execute",
                "success",
                result.state_before,
                result.state_after,
                preview.compatibility,
                len(result.changed_files),
                result.source_digest,
                result.installed_digest,
                result.preview_digest,
                None,
            )
        )
        return result

    async def remove_skill(
        self,
        request: IntegrationRequest,
        confirmation: IntegrationConfirmation,
    ) -> IntegrationResult:
        if (
            type(request) is not IntegrationRequest
            or request.action is not IntegrationAction.REMOVE
        ):
            raise _invalid("integration_action_invalid")
        preview = await self.preview_skill(request)
        try:
            if preview.state_before is not IntegrationState.INSTALLED_EXACT and not (
                preview.state_before is IntegrationState.MODIFIED
                and "owned_skill_update" in preview.warnings
            ):
                raise IntegrationError(IntegrationReason.REMOVE_REFUSED, {})
            command = self._confirmed_apply(request, confirmation, preview)
            result = await self._integrations.remove_skill(request.harness, command)
        except IntegrationError as exc:
            self._record_failure(request, "execute", exc.reason, preview)
            raise
        self._diagnostics.record_integration(
            IntegrationDiagnostic(
                request.harness,
                result.action,
                "execute",
                "success",
                result.state_before,
                result.state_after,
                preview.compatibility,
                len(result.changed_files),
                result.source_digest,
                result.installed_digest,
                result.preview_digest,
                None,
            )
        )
        return result
