"""Harness MCP registration service: confirmation binding and diagnostics."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import anyio
import pytest

from finishup.application.applied_mcp_route import read_applied_route, record_applied_route
from finishup.application.harness_mcp import (
    HarnessMcpService,
    McpRegistrationConfirmation,
    McpRegistrationDiagnostic,
)
from finishup.ports.harness_mcp import (
    MCP_SERVE_COMMAND,
    HarnessBinary,
    McpRegistrationAction,
    McpRegistrationCommand,
    McpRegistrationError,
    McpRegistrationObservation,
    McpRegistrationPreview,
    McpRegistrationReason,
    McpRegistrationResult,
    McpRegistrationState,
)
from finishup.ports.integrations import HarnessId

_DIGEST = "sha256:" + "a" * 64
_BINARY = HarnessBinary(
    harness_id=HarnessId.CODEX,
    executable_path="/opt/harness/bin/codex",
    reported_version=None,
    compatibility="untested",
)


class _Sink:
    def __init__(self) -> None:
        self.records: list[McpRegistrationDiagnostic] = []

    def record_mcp_registration(self, diagnostic: McpRegistrationDiagnostic) -> None:
        self.records.append(diagnostic)


class _Port:
    def __init__(
        self,
        state: McpRegistrationState = McpRegistrationState.ABSENT,
        fail_with: McpRegistrationReason | None = None,
    ) -> None:
        self.state = state
        self.fail_with = fail_with
        self.applied: list[McpRegistrationCommand] = []

    async def status_registration(self, binary: HarnessBinary) -> McpRegistrationState:
        del binary
        if self.fail_with is not None:
            raise McpRegistrationError(self.fail_with, {})
        return self.state

    async def observe_registration(self, binary: HarnessBinary) -> McpRegistrationObservation:
        if self.fail_with is not None:
            raise McpRegistrationError(self.fail_with, {})
        route_profile: Literal["policy", "strict"] | None = (
            "strict" if self.state is McpRegistrationState.FINISHUP_OWNED else None
        )
        return McpRegistrationObservation(
            binary.harness_id,
            self.state,
            route_profile,
            "ambient" if route_profile is not None else None,
        )

    async def preview_registration(self, binary: HarnessBinary) -> McpRegistrationPreview:
        if self.fail_with is not None:
            raise McpRegistrationError(self.fail_with, {})
        action = (
            McpRegistrationAction.REGISTER
            if self.state is McpRegistrationState.ABSENT
            else McpRegistrationAction.NOOP
        )
        return McpRegistrationPreview(binary.harness_id, action, self.state, (), _DIGEST)

    async def apply_registration(
        self,
        binary: HarnessBinary,
        command: McpRegistrationCommand,
    ) -> McpRegistrationResult:
        self.applied.append(command)
        if self.fail_with is not None:
            raise McpRegistrationError(self.fail_with, {})
        return McpRegistrationResult(
            binary.harness_id,
            McpRegistrationAction.REGISTER,
            self.state,
            McpRegistrationState.FINISHUP_OWNED,
            command.preview_digest,
        )

    async def preview_unregistration(self, binary: HarnessBinary) -> McpRegistrationPreview:
        if self.fail_with is not None:
            raise McpRegistrationError(self.fail_with, {})
        action = (
            McpRegistrationAction.NOOP
            if self.state is McpRegistrationState.ABSENT
            else McpRegistrationAction.UNREGISTER
        )
        return McpRegistrationPreview(binary.harness_id, action, self.state, (), _DIGEST)

    async def apply_unregistration(
        self,
        binary: HarnessBinary,
        command: McpRegistrationCommand,
    ) -> McpRegistrationResult:
        self.applied.append(command)
        if self.fail_with is not None:
            raise McpRegistrationError(self.fail_with, {})
        return McpRegistrationResult(
            binary.harness_id,
            McpRegistrationAction.NOOP
            if self.state is McpRegistrationState.ABSENT
            else McpRegistrationAction.UNREGISTER,
            self.state,
            McpRegistrationState.ABSENT,
            command.preview_digest,
        )


def test_status_and_preview_record_success_diagnostics() -> None:
    sink = _Sink()
    service = HarnessMcpService(_Port(), sink)
    state = anyio.run(lambda: service.status(_BINARY))
    preview = anyio.run(lambda: service.preview(_BINARY))
    assert state is McpRegistrationState.ABSENT
    assert preview.preview_digest == _DIGEST
    assert [record.phase for record in sink.records] == ["status", "preview"]
    assert all(record.outcome == "success" for record in sink.records)


def test_observe_records_a_status_phase_diagnostic_and_carries_the_route() -> None:
    sink = _Sink()
    service = HarnessMcpService(_Port(McpRegistrationState.FINISHUP_OWNED), sink)
    observation = anyio.run(lambda: service.observe(_BINARY))
    assert observation.state is McpRegistrationState.FINISHUP_OWNED
    assert observation.route_profile == "strict"
    # Observing reads exactly what status reads, so it shares the phase; the diagnostic shape
    # is unchanged.
    assert sink.records[-1].phase == "status"
    assert sink.records[-1].outcome == "success"
    assert sink.records[-1].state_before is McpRegistrationState.FINISHUP_OWNED


def test_observe_failure_is_recorded_and_reraised() -> None:
    sink = _Sink()
    service = HarnessMcpService(_Port(fail_with=McpRegistrationReason.PARSE_FAILED), sink)
    with pytest.raises(McpRegistrationError):
        anyio.run(lambda: service.observe(_BINARY))
    assert sink.records[-1].phase == "status"
    assert sink.records[-1].outcome == "failed"
    assert sink.records[-1].reason is McpRegistrationReason.PARSE_FAILED


def test_observe_rejects_an_invalid_binary() -> None:
    service = HarnessMcpService(_Port())
    with pytest.raises(ValueError):
        anyio.run(lambda: service.observe(object()))  # type: ignore[arg-type]


def test_a_route_profile_is_only_meaningful_for_a_finishup_owned_entry() -> None:
    """A foreign or absent entry has no FinishUP route, so claiming one is a construction error."""

    with pytest.raises(ValueError):
        McpRegistrationObservation(
            HarnessId.CODEX, McpRegistrationState.ABSENT, "policy", "ambient"
        )
    with pytest.raises(ValueError):
        McpRegistrationObservation(
            HarnessId.CODEX, McpRegistrationState.FOREIGN_PRESENT, "strict", "ambient"
        )


def test_register_requires_explicit_acceptance() -> None:
    sink = _Sink()
    port = _Port()
    service = HarnessMcpService(port, sink)
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: service.register(
                _BINARY,
                McpRegistrationConfirmation(_DIGEST, False, "interactive"),
            )
        )
    assert caught.value.reason is McpRegistrationReason.CONFIRMATION_REQUIRED
    # The port was never asked to mutate anything.
    assert port.applied == []
    assert sink.records[-1].outcome == "failed"
    assert sink.records[-1].reason is McpRegistrationReason.CONFIRMATION_REQUIRED


def test_register_passes_exact_digest_and_records_result(tmp_path: Path) -> None:
    sink = _Sink()
    port = _Port()
    service = HarnessMcpService(port, sink)
    result = anyio.run(
        lambda: service.register(
            _BINARY,
            McpRegistrationConfirmation(_DIGEST, True, "noninteractive_flag"),
            _state=tmp_path,
        )
    )
    assert result.state_after is McpRegistrationState.FINISHUP_OWNED
    assert port.applied == [McpRegistrationCommand(_DIGEST, True)]
    assert sink.records[-1].phase == "execute"
    assert sink.records[-1].outcome == "success"
    assert sink.records[-1].preview_digest == _DIGEST
    # The static fake still observes absence after the write, so the unverified
    # route is never persisted.
    assert read_applied_route(_state=tmp_path) is None


def test_port_failure_is_recorded_and_reraised() -> None:
    sink = _Sink()
    service = HarnessMcpService(_Port(fail_with=McpRegistrationReason.FOREIGN_ENTRY_PRESENT), sink)
    with pytest.raises(McpRegistrationError):
        anyio.run(
            lambda: service.register(
                _BINARY,
                McpRegistrationConfirmation(_DIGEST, True, "interactive"),
            )
        )
    assert sink.records[-1].outcome == "failed"
    assert sink.records[-1].reason is McpRegistrationReason.FOREIGN_ENTRY_PRESENT


def test_confirmation_channel_is_closed() -> None:
    with pytest.raises(ValueError):
        McpRegistrationConfirmation(_DIGEST, True, "release_automation")  # type: ignore[arg-type]


def test_invalid_binary_rejected() -> None:
    service = HarnessMcpService(_Port())
    with pytest.raises(ValueError):
        anyio.run(lambda: service.status(object()))  # type: ignore[arg-type]


def test_unregister_requires_explicit_acceptance() -> None:
    sink = _Sink()
    port = _Port(McpRegistrationState.FINISHUP_OWNED)
    service = HarnessMcpService(port, sink)
    with pytest.raises(McpRegistrationError) as caught:
        anyio.run(
            lambda: service.unregister(
                _BINARY,
                McpRegistrationConfirmation(_DIGEST, False, "interactive"),
            )
        )
    assert caught.value.reason is McpRegistrationReason.CONFIRMATION_REQUIRED
    assert port.applied == []


@pytest.mark.parametrize(
    "state", [McpRegistrationState.FINISHUP_OWNED, McpRegistrationState.ABSENT]
)
def test_unregister_passes_exact_digest_and_records_result(
    tmp_path: Path, state: McpRegistrationState
) -> None:
    sink = _Sink()
    port = _Port(state)
    record_applied_route(
        "policy", list(MCP_SERVE_COMMAND), list(MCP_SERVE_COMMAND), _DIGEST, _state=tmp_path
    )
    assert read_applied_route(_state=tmp_path) is not None
    service = HarnessMcpService(port, sink)
    result = anyio.run(
        lambda: service.unregister(
            _BINARY,
            McpRegistrationConfirmation(_DIGEST, True, "noninteractive_flag"),
            _state=tmp_path,
        )
    )
    assert result.state_after is McpRegistrationState.ABSENT
    assert port.applied == [McpRegistrationCommand(_DIGEST, True)]
    assert sink.records[-1].phase == "execute"
    assert read_applied_route(_state=tmp_path) is None
