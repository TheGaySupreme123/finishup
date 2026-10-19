"""Runtime discovery must not treat discovery order as connection authority."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from builders.tui_runtime import CLI, DESKTOP
from finishup.adapters.workspace_binding import canonical_workspace_locator
from finishup.tui.models import HarnessOption
from finishup.tui.runtime import (
    FinishUpRuntime,
    _WorkSession,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.parametrize(
    ("host", "installed", "enabled", "configured", "expected"),
    [
        ("claude", False, False, True, "absent"),
        ("claude", True, False, True, "absent"),
        ("claude", True, True, True, "yoetz_owned"),
        ("cursor-cli", True, None, True, "yoetz_owned"),
        ("cursor-ide", False, None, True, "absent"),
        ("cursor-ide", True, None, False, "absent"),
    ],
)
async def test_host_ownership_requires_complete_configuration_off_event_loop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    host: str,
    installed: bool,
    enabled: bool | None,
    configured: bool,
    expected: str,
) -> None:
    import threading

    from finishup.cli import host_connection

    event_thread = threading.get_ident()

    def select(*_args: object) -> object:
        assert threading.get_ident() != event_thread
        return object()

    monkeypatch.setattr(host_connection, "select_installation", select)

    def prepare(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            status=lambda: {"installed": installed, "enabled": enabled, "configured": configured}
        )

    monkeypatch.setattr(host_connection, "prepare_selected", prepare)
    option = HarnessOption("/opt/agent", "1.0.0", "Agent", "", host=host)
    assert await FinishUpRuntime(cwd=tmp_path).mcp_state(option) == expected


@pytest.mark.parametrize("host", ["claude", "cursor-ide", "cursor-cli"])
async def test_non_codex_plugin_layers_use_selected_host_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, host: str
) -> None:
    from finishup.tui.models import LayerState

    seen: list[str] = []

    async def status(_self: FinishUpRuntime, option: HarnessOption) -> dict[str, object]:
        seen.append(option.host)
        return {"installed": True, "configured": True, "enabled": True}

    monkeypatch.setattr(FinishUpRuntime, "_host_connection_status", status)
    option = HarnessOption("/opt/agent", "1.0.0", "Selected agent", "", host=host)
    layers = await FinishUpRuntime(cwd=tmp_path)._host_plugin_layers(option)  # pyright: ignore[reportPrivateUsage]
    assert seen == [host]
    assert layers[0].state is LayerState.VERIFIED
    assert layers[0].detail == "Selected agent"
    assert layers[1].state is LayerState.UNPROVEN


async def test_detect_reports_connected_when_the_second_installation_is_owned(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime = FinishUpRuntime(cwd=tmp_path)

    def harnesses(_self: FinishUpRuntime) -> tuple[HarnessOption, ...]:
        return (DESKTOP, CLI)

    monkeypatch.setattr(
        FinishUpRuntime,
        "discover_harnesses",
        harnesses,
    )

    async def state(_self: FinishUpRuntime, option: HarnessOption) -> str:
        return "yoetz_owned" if option is CLI else "absent"

    monkeypatch.setattr(FinishUpRuntime, "mcp_state", state)

    detection = await runtime.detect()

    assert detection.already_connected is True


async def test_service_client_uses_ui_kind_and_runtime_cwd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import finishup.cli.app as cli_app
    from finishup.ports.control import ControlClientKind, ProjectionRenderMode, WorkspaceLocator

    observed: list[tuple[ControlClientKind, WorkspaceLocator]] = []

    class Client:
        async def close(self) -> None:
            return None

    async def build(
        client_kind: ControlClientKind,
        *,
        workspace_locator: WorkspaceLocator | None = None,
        projection_render_mode: ProjectionRenderMode = ProjectionRenderMode.MACHINE_READABLE,
        output_is_controlling_tty: bool = False,
    ) -> Client:
        assert workspace_locator is not None
        # Agent-facing by default (ADR-009 round 3): the TUI asserts no terminal authority.
        assert projection_render_mode is ProjectionRenderMode.MACHINE_READABLE
        assert not output_is_controlling_tty
        observed.append((client_kind, workspace_locator))
        return Client()

    monkeypatch.setattr(cli_app, "build_service_client", build)
    runtime = FinishUpRuntime(cwd=tmp_path)

    async with runtime._client():  # pyright: ignore[reportPrivateUsage]
        pass

    assert observed == [(ControlClientKind.UI, WorkspaceLocator(str(tmp_path)))]


async def test_provider_posture_reads_at_the_repository_root_not_the_launch_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """PR #478 review: host admission files live at the repository root, so a subdirectory
    launch must hand the resolved root, not the launch directory, to the status report."""

    from finishup.cli import provider_status

    (tmp_path / ".git").mkdir()
    subdirectory = tmp_path / "src" / "nested"
    subdirectory.mkdir(parents=True)
    observed: list[Path | None] = []

    async def report(*, workspace_locator: Path | None = None) -> dict[str, object]:
        observed.append(workspace_locator)
        return {}

    monkeypatch.setattr(provider_status, "provider_status_report", report)
    runtime = FinishUpRuntime(cwd=subdirectory)

    await runtime.provider_posture()

    assert observed == [tmp_path]


def test_work_detail_preserves_unknown_open_obligation_count(tmp_path: Path) -> None:
    runtime = FinishUpRuntime(cwd=tmp_path)
    session = _WorkSession(
        task_id="tsk_00000000-0000-4000-8000-000000000001",
        session_id="ses_00000000-0000-4000-8000-000000000002",
        writer_id="wri_00000000-0000-4000-8000-000000000003",
        frontier=SimpleNamespace(sequence="2"),
    )
    compact = SimpleNamespace(
        coverage=SimpleNamespace(known_gaps=("redacted_event",)),
        gaps=("readiness_unknown",),
        ledger_freshness="redacted_gap",
        open_obligation_count=None,
        unanswered_finding_count="0",
        receipt_blocking_finding_count="0",
    )

    detail = runtime._work_detail(  # pyright: ignore[reportPrivateUsage]
        "Unreadable plan scope", session, compact
    )

    assert detail.evidence_count is None
    assert detail.coverage == ("redacted_event",)


async def test_store_provider_credential_supplies_the_scoped_reauthentication_secret(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A Keychain-provisioned vault must not ask the TUI user for an unseen passphrase."""

    observed: list[tuple[object, object]] = []
    observed_workspaces: list[Path | None] = []

    def configuration(*_args: object) -> SimpleNamespace:
        return SimpleNamespace(
            provider=SimpleNamespace(
                provider_id="fireworks",
                model="accounts/fireworks/models/minimax-m3",
                endpoint_profile_id="fireworks-responses",
                endpoint_profile_version="1.0.0",
            )
        )

    async def snapshot(workspace_locator: Path | None = None) -> SimpleNamespace:
        observed_workspaces.append(workspace_locator)
        return SimpleNamespace(bound_scope={"workspace_ref_commitment": "hmac-sha256:" + "7" * 64})

    async def ceremony(
        _target: object,
        credential: bytearray | None = None,
        reauthentication: bytearray | None = None,
    ) -> SimpleNamespace:
        observed.append((credential, reauthentication))
        return SimpleNamespace(activation_status="stored")

    monkeypatch.setattr("finishup.config.load.load_config", configuration)
    monkeypatch.setattr("finishup.cli.privacy_setup.get_privacy_setup_snapshot", snapshot)
    monkeypatch.setattr("finishup.cli.unlock.set_provider_credential", ceremony)
    monkeypatch.setattr(
        "finishup.cli.unlock.load_auto_unlock_reauthentication",
        lambda: bytearray(b"scoped-reauth"),
    )

    status = await FinishUpRuntime(cwd=tmp_path).store_provider_credential()

    assert status == "stored"
    assert observed_workspaces == [tmp_path]
    assert len(observed) == 1
    credential, reauthentication = observed[0]
    assert credential is None
    assert reauthentication is not None
    assert bytes(cast(bytearray, reauthentication)) == b"scoped-reauth"


def test_every_reviewed_provider_preset_gets_a_friendly_picker_label(tmp_path: Path) -> None:
    """A preset missing from the label map either vanishes from ``/provider`` or
    shows its raw provider id; both regress silently, so the map is locked to
    the preset registry rather than to a hand-maintained list."""

    from finishup.config.write import PROVIDER_PRESETS

    options = {option.choice: option for option in FinishUpRuntime(cwd=tmp_path).provider_options()}

    missing = sorted(set(PROVIDER_PRESETS) - set(options))
    assert missing == [], f"presets without a picker entry: {missing}"
    for choice, preset in PROVIDER_PRESETS.items():
        option = options[choice]
        assert option.provider_id == preset.provider_id
        assert option.label.strip(), f"empty label for preset {choice}"
        assert option.label != preset.provider_id, (
            f"preset {choice} falls through to its raw provider id {preset.provider_id!r}"
        )
        assert option.label != choice, f"preset {choice} falls through to its choice key"
    assert options["grok"].label == "Grok (xAI)"


# ---------------------------------------------------------------------------
# Host facts are named once in /doctor and detection (issues #720, #721, #724)
# ---------------------------------------------------------------------------


def test_secure_storage_probe_names_the_reason_from_the_vault_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.adapters.keys import os_keyring
    from finishup.tui import runtime as runtime_module

    monkeypatch.setattr(
        os_keyring,
        "describe_vault_keyring_backend",
        lambda: os_keyring.KeyringBackendReport(
            "keyring.backends.null.Keyring", False, "backend_not_approved", "macOS Keychain"
        ),
    )

    available, reason = runtime_module._secure_storage_probe()  # pyright: ignore[reportPrivateUsage]

    assert available is False
    assert "keyring.backends.null.Keyring" in reason
    assert reason.endswith("FinishUP needs macOS Keychain")


def test_host_entries_report_platform_sandbox_and_storage_without_mutating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.version as version_module
    from finishup.adapters import check_sandbox
    from finishup.adapters.keys import os_keyring
    from finishup.ports.check_sandbox import CheckSandboxAvailability, CheckSandboxStatus
    from finishup.tui import runtime as runtime_module
    from finishup.tui.models import LayerState

    # The older-python CI lane runs this too; certify whichever interpreter is running so only
    # the patched OS/CPU decides the platform line (issue #1119).
    monkeypatch.setattr(
        version_module,
        "_CERTIFIED_PYTHON",
        (
            version_module.platform.python_implementation(),
            tuple(version_module.sys.version_info[:3]),
        ),
    )
    monkeypatch.setattr(version_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(version_module.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(
        check_sandbox,
        "default_check_sandbox",
        lambda: check_sandbox.LinuxCheckSandbox(bwrap="/nonexistent/bwrap", _probe=lambda _argv: 1),
    )
    monkeypatch.setattr(
        os_keyring,
        "describe_vault_keyring_backend",
        lambda: os_keyring.KeyringBackendReport("", False, "keyring_unavailable", "a store"),
    )

    entries = runtime_module._host_entries()  # pyright: ignore[reportPrivateUsage]

    by_key = {entry.key: entry for entry in entries}
    assert list(by_key) == ["platform_cell", "check_sandbox", "secure_storage"]
    assert by_key["platform_cell"].state is LayerState.UNPROVEN
    assert "aarch64" in by_key["platform_cell"].detail
    assert "macOS arm64 and Linux x86-64" in by_key["platform_cell"].remediation
    assert by_key["check_sandbox"].state is LayerState.NOT_CONFIGURED
    assert by_key["check_sandbox"].detail.startswith("bwrap_missing")
    assert "apt install bubblewrap" in by_key["check_sandbox"].remediation
    assert by_key["secure_storage"].state is LayerState.NOT_CONFIGURED
    assert (
        by_key["secure_storage"].detail == "no credential store is loaded; FinishUP needs a store"
    )
    assert "passphrase" in by_key["secure_storage"].remediation

    ready = CheckSandboxAvailability(CheckSandboxStatus.READY, "seatbelt", "ready", "")
    monkeypatch.setattr(check_sandbox, "probe_check_sandbox", lambda: ready)
    monkeypatch.setattr(version_module.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(version_module.platform, "libc_ver", lambda: ("glibc", "2.28"))
    monkeypatch.setattr(
        os_keyring,
        "describe_vault_keyring_backend",
        lambda: os_keyring.KeyringBackendReport("x", True, "approved", "a store"),
    )

    verified = {entry.key: entry for entry in runtime_module._host_entries()}  # pyright: ignore[reportPrivateUsage]
    assert all(entry.state is LayerState.VERIFIED for entry in verified.values())
    assert verified["platform_cell"].detail == "Linux x86_64 (manylinux_2_28_x86_64)"
    assert verified["check_sandbox"].detail == "seatbelt"
    assert all(entry.remediation == "" for entry in verified.values())


async def test_integration_preview_uses_activation_home_for_mcp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.adapters.integrations import codex_mcp
    from finishup.cli import setup
    from finishup.ports.harness_mcp import McpRegistrationError, McpRegistrationReason
    from finishup.tui.runtime import RuntimeError_

    selected = tmp_path / "selected"
    resolved = tmp_path / "resolved"
    seen: list[Path | None] = []

    def activation(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(codex_home=resolved)

    class StopAtPreview:
        def __init__(self, *, route_profile: str, codex_home: Path | None = None) -> None:
            assert route_profile == "strict"
            seen.append(codex_home)

        async def preview_registration(self, _binary: object) -> object:
            raise McpRegistrationError(McpRegistrationReason.TIMEOUT, {})

    monkeypatch.setattr(setup, "codex_activation_preview", activation)
    monkeypatch.setattr(codex_mcp, "CodexMcpAdapter", StopAtPreview)
    runtime = FinishUpRuntime(cwd=tmp_path)
    with pytest.raises(RuntimeError_):
        await runtime.integration_plan(CLI, selected, "strict")
    assert seen == [resolved]


async def test_the_codex_integration_preview_refuses_a_runtime_that_cannot_serve(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The first-run and ``/connect`` Codex path previews nothing for such a runtime."""

    from finishup.adapters import release_runtime
    from finishup.cli import setup
    from finishup.tui.runtime import RuntimeError_

    monkeypatch.setattr(
        release_runtime,
        "installed_runtime_refusal",
        lambda: release_runtime.ReleaseRuntimeError("release_runtime_not_owned"),
    )

    def no_preview(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("previewed a registration for a runtime that cannot serve")

    monkeypatch.setattr(setup, "codex_activation_preview", no_preview)
    runtime = FinishUpRuntime(cwd=tmp_path)
    with pytest.raises(RuntimeError_) as refused:
        await runtime.integration_plan(CLI, tmp_path / "codex-home", "strict")
    assert refused.value.reason == "release_runtime_not_owned"
    assert any(
        "must belong to the account running FinishUP" in line for line in refused.value.details
    )


def _isolated_observation_store(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[FinishUpRuntime, Path]:
    """Point the runtime's store at an isolated state root, never the live install."""

    from finishup.adapters.integrations import observation_local

    real_store = observation_local.LocalObservationStore
    state = tmp_path / "isolated"
    workspace = tmp_path / "workspace"
    (workspace / ".git").mkdir(parents=True)

    def isolated_store(*_args: object, **_kwargs: object) -> object:
        return real_store(_state=state)

    monkeypatch.setattr(observation_local, "LocalObservationStore", isolated_store)
    return FinishUpRuntime(cwd=workspace), state


async def test_capacity_preview_and_apply_persist_the_workspace_selection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The TUI changes the workspace selection only, through the owning preview/apply path."""

    from finishup.adapters.integrations.observation_local import LocalObservationStore
    from finishup.domain.observation_budget import CapacityRequest, ObservationCapacity

    runtime, state = _isolated_observation_store(monkeypatch, tmp_path)
    request = CapacityRequest.for_capacity(ObservationCapacity(1_024))

    preview = await runtime.preview_observation_selection(request)

    digest = preview["preview_digest"]
    assert isinstance(digest, str)
    disclosure = cast(dict[str, object], preview["disclosure"])
    assert disclosure["scope"] == "workspace"
    assert disclosure["change"] == "increase"
    requested = cast(dict[str, object], preview["requested_selection"])
    assert requested["queue_count"] == 1_024
    assert requested["detail"] == "focused"

    applied = await runtime.apply_observation_selection(request, digest)

    assert applied["applied"] is True
    selection = cast(dict[str, object], applied["selection"])
    assert selection["queue_count"] == 1_024
    assert selection["origin"] == "workspace"
    # The command line resolves the same workspace, so it reads the TUI's change.
    store = LocalObservationStore(_state=state)
    locator = canonical_workspace_locator(str(runtime.project_root()))
    assert locator is not None
    settings = store.selection_settings_for(store.workspace_commitment(locator))
    assert settings.workspace is not None
    assert settings.workspace.selection.capacity == ObservationCapacity(1_024)
    assert settings.sessions == ()
    status = await runtime.observation_selection_status()
    selected = cast(dict[str, object], status["selected"])
    assert selected["queue_count"] == 1_024


async def test_capacity_paths_refuse_a_workspace_the_command_line_refuses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A root the CLI's canonicalization rejects is refused here too, never hashed raw."""

    from finishup.domain.observation_budget import CapacityRequest, ObservationCapacity
    from finishup.tui.runtime import RuntimeError_

    runtime, _state = _isolated_observation_store(monkeypatch, tmp_path)
    runtime.project_root().chmod(0o777)
    request = CapacityRequest.for_capacity(ObservationCapacity(1_024))
    try:
        assert canonical_workspace_locator(str(runtime.project_root())) is None
        with pytest.raises(RuntimeError_) as status:
            await runtime.observation_selection_status()
        assert status.value.reason == "observation_status_unavailable"
        with pytest.raises(RuntimeError_) as preview:
            await runtime.preview_observation_selection(request)
        assert preview.value.reason == "observation_selection_preview_failed"
        with pytest.raises(RuntimeError_) as applied:
            await runtime.apply_observation_selection(request, "sha256:" + "0" * 64)
        assert applied.value.reason == "observation_selection_apply_failed"
    finally:
        runtime.project_root().chmod(0o755)


async def test_capacity_apply_refuses_a_stale_digest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.domain.observation_budget import CapacityRequest, ObservationCapacity
    from finishup.tui.runtime import RuntimeError_

    runtime, _state = _isolated_observation_store(monkeypatch, tmp_path)
    request = CapacityRequest.for_capacity(ObservationCapacity(2_048))

    with pytest.raises(RuntimeError_) as raised:
        await runtime.apply_observation_selection(request, "sha256:" + "0" * 64)

    assert raised.value.reason == "observation_selection_apply_failed"


async def test_capacity_no_cap_is_a_typed_outcome_that_changes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.adapters.integrations.observation_local import LocalObservationStore
    from finishup.domain.observation_budget import CapacityRequest
    from finishup.tui.runtime import ObservationCapacityUnavailable

    runtime, state = _isolated_observation_store(monkeypatch, tmp_path)

    with pytest.raises(ObservationCapacityUnavailable) as raised:
        await runtime.preview_observation_selection(CapacityRequest("no_cap", None))

    assert raised.value.reason == "capacity_no_cap_unsupported"
    assert raised.value.lines[0].startswith("No FinishUP cap is not available")
    assert "--capacity largest" in raised.value.alternative_command
    assert "--workspace <workspace>" in raised.value.alternative_command
    store = LocalObservationStore(_state=state)
    locator = canonical_workspace_locator(str(runtime.project_root()))
    assert locator is not None
    settings = store.selection_settings_for(store.workspace_commitment(locator))
    assert settings.workspace is None
