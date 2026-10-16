"""Integration-service consent, harness, and privacy contract tests."""

from __future__ import annotations

from typing import cast

import pytest

from finishup.application.integrations import (
    IntegrationConfirmation,
    IntegrationDiagnostic,
    IntegrationDiagnosticSink,
    IntegrationRequest,
    IntegrationService,
    IntegrationStatusRequest,
)
from finishup.domain.values import JsonObject, request_id
from finishup.ports.integrations import (
    HarnessId,
    IntegrationAction,
    IntegrationError,
    IntegrationPreview,
    IntegrationReason,
    IntegrationResult,
    IntegrationsPort,
    IntegrationState,
    IntegrationStatus,
    SkillApplyCommand,
    SkillPreviewCommand,
    SkillStatusCommand,
)

_DIGEST_A = "sha256:" + "a" * 64
_DIGEST_B = "sha256:" + "b" * 64


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _preview(state: IntegrationState, *, action: IntegrationAction) -> IntegrationPreview:
    return IntegrationPreview(action, state, _DIGEST_A, None, "supported", (), (), _DIGEST_B)


class _Port:
    def __init__(self) -> None:
        self.preview = _preview(IntegrationState.ABSENT, action=IntegrationAction.INSTALL)
        self.calls: list[str] = []

    async def preview_skill(
        self, harness: HarnessId, command: SkillPreviewCommand
    ) -> IntegrationPreview:
        assert harness is HarnessId.CODEX
        self.calls.append("preview")
        return self.preview

    async def install_skill(
        self, harness: HarnessId, command: SkillApplyCommand
    ) -> IntegrationResult:
        assert harness is HarnessId.CODEX
        self.calls.append("install")
        return IntegrationResult(
            command.requested_action,
            self.preview.state_before,
            IntegrationState.INSTALLED_EXACT,
            _DIGEST_A,
            _DIGEST_A,
            ("SKILL.md",),
            command.preview_digest,
        )

    async def status_skill(
        self, harness: HarnessId, command: SkillStatusCommand
    ) -> IntegrationStatus:
        assert harness is HarnessId.CODEX
        self.calls.append("status")
        return IntegrationStatus(
            IntegrationState.ABSENT,
            _DIGEST_A,
            None,
            "supported",
            (JsonObject({"relative_path": "SKILL.md", "state": "absent"}),),
            False,
        )

    async def remove_skill(
        self, harness: HarnessId, command: SkillApplyCommand
    ) -> IntegrationResult:
        assert harness is HarnessId.CODEX
        self.calls.append("remove")
        return IntegrationResult(
            IntegrationAction.REMOVE,
            IntegrationState.INSTALLED_EXACT,
            IntegrationState.ABSENT,
            _DIGEST_A,
            None,
            ("SKILL.md",),
            command.preview_digest,
        )


class _Diagnostics:
    def __init__(self) -> None:
        self.records: list[IntegrationDiagnostic] = []

    def record_integration(self, diagnostic: IntegrationDiagnostic) -> None:
        self.records.append(diagnostic)


def _service(port: _Port, diagnostics: _Diagnostics) -> IntegrationService:
    return IntegrationService(
        cast(IntegrationsPort, port), cast(IntegrationDiagnosticSink, diagnostics)
    )


def _request(
    action: IntegrationAction = IntegrationAction.INSTALL,
    *,
    replace_modified: bool = False,
) -> IntegrationRequest:
    return IntegrationRequest(
        request_id("req_00000000-0000-4000-8000-000000000021"),
        HarnessId.CODEX,
        "/secret/project",
        action,
        replace_modified,
    )


def test_harness_is_explicit_and_rejected_before_any_port_call() -> None:
    port = _Port()
    with pytest.raises(ValueError, match="integration_harness_invalid"):
        IntegrationRequest(
            request_id("req_00000000-0000-4000-8000-000000000021"),
            cast(HarnessId, "codex"),
            "/secret/project",
            IntegrationAction.INSTALL,
        )
    assert port.calls == []
    assert "secret/project" not in repr(_request())


@pytest.mark.anyio
async def test_install_requires_exact_preview_and_explicit_consent() -> None:
    port = _Port()
    diagnostics = _Diagnostics()
    service = _service(port, diagnostics)
    with pytest.raises(IntegrationError) as declined:
        await service.install_skill(
            _request(), IntegrationConfirmation(_DIGEST_B, False, "interactive")
        )
    assert declined.value.reason is IntegrationReason.CONFIRMATION_REQUIRED
    assert port.calls == ["preview"]

    port.calls.clear()
    with pytest.raises(IntegrationError) as stale:
        await service.install_skill(
            _request(), IntegrationConfirmation(_DIGEST_A, True, "noninteractive_flag")
        )
    assert stale.value.reason is IntegrationReason.PREVIEW_STALE
    assert port.calls == ["preview"]


@pytest.mark.anyio
async def test_modified_replacement_requires_request_flag_bound_before_preview() -> None:
    port = _Port()
    port.preview = _preview(IntegrationState.MODIFIED, action=IntegrationAction.REPLACE)
    service = _service(port, _Diagnostics())
    with pytest.raises(IntegrationError) as refused:
        await service.install_skill(
            _request(IntegrationAction.REPLACE),
            IntegrationConfirmation(_DIGEST_B, True, "interactive"),
        )
    assert refused.value.reason is IntegrationReason.MODIFIED_COPY
    assert port.calls == ["preview"]

    port.calls.clear()
    result = await service.install_skill(
        _request(IntegrationAction.REPLACE, replace_modified=True),
        IntegrationConfirmation(_DIGEST_B, True, "interactive"),
    )
    assert result.state_after is IntegrationState.INSTALLED_EXACT
    assert port.calls == ["preview", "install"]


@pytest.mark.anyio
async def test_status_is_read_only_and_diagnostics_are_path_free() -> None:
    port = _Port()
    diagnostics = _Diagnostics()
    service = _service(port, diagnostics)
    result = await service.status_skill(
        IntegrationStatusRequest(HarnessId.CODEX, "/secret/project")
    )
    assert result.state is IntegrationState.ABSENT
    assert port.calls == ["status"]
    assert len(diagnostics.records) == 1
    assert "secret" not in repr(diagnostics.records[0])
    assert not hasattr(diagnostics.records[0], "project_root")


@pytest.mark.anyio
async def test_remove_preserves_nonexact_copy_without_port_mutation() -> None:
    port = _Port()
    port.preview = _preview(IntegrationState.MODIFIED, action=IntegrationAction.REMOVE)
    service = _service(port, _Diagnostics())
    with pytest.raises(IntegrationError) as refused:
        await service.remove_skill(
            _request(IntegrationAction.REMOVE),
            IntegrationConfirmation(_DIGEST_B, True, "interactive"),
        )
    assert refused.value.reason is IntegrationReason.REMOVE_REFUSED
    assert port.calls == ["preview"]


@pytest.mark.anyio
@pytest.mark.parametrize("action", [IntegrationAction.INSTALL, IntegrationAction.REMOVE])
async def test_pristine_prior_skill_keeps_exact_consent_without_overwrite_flag(
    action: IntegrationAction,
) -> None:
    import dataclasses

    port = _Port()
    port.preview = dataclasses.replace(
        _preview(IntegrationState.MODIFIED, action=action), warnings=("owned_skill_update",)
    )
    service = _service(port, _Diagnostics())
    execute = service.remove_skill if action is IntegrationAction.REMOVE else service.install_skill
    for confirmation, reason in (
        (
            IntegrationConfirmation(_DIGEST_B, False, "interactive"),
            IntegrationReason.CONFIRMATION_REQUIRED,
        ),
        (IntegrationConfirmation(_DIGEST_A, True, "interactive"), IntegrationReason.PREVIEW_STALE),
    ):
        with pytest.raises(IntegrationError) as caught:
            await execute(_request(action), confirmation)
        assert caught.value.reason is reason
        assert port.calls[-1] == "preview"
    port.calls.clear()
    await execute(_request(action), IntegrationConfirmation(_DIGEST_B, True, "interactive"))
    assert port.calls == ["preview", "remove" if action is IntegrationAction.REMOVE else "install"]


@pytest.mark.anyio
async def test_owned_update_warning_does_not_bypass_harness_compatibility() -> None:
    import dataclasses

    port = _Port()
    port.preview = dataclasses.replace(
        _preview(IntegrationState.MODIFIED, action=IntegrationAction.INSTALL),
        warnings=("owned_skill_update",),
        compatibility="unsupported",
    )
    with pytest.raises(IntegrationError) as caught:
        await _service(port, _Diagnostics()).install_skill(
            _request(), IntegrationConfirmation(_DIGEST_B, True, "interactive")
        )
    assert caught.value.reason is IntegrationReason.VERSION_INCOMPATIBLE
    assert port.calls == ["preview"]
