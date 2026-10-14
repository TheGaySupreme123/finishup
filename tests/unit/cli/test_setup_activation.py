"""Setup activation readiness and synthetic-probe isolation."""

from __future__ import annotations

from pathlib import Path

import pytest

from finishup.adapters.integrations.codex_marketplace import (
    ActivationInspection,
    ActivationState,
)
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import setup
from finishup.ports.harness_mcp import HarnessBinary
from finishup.ports.integrations import HarnessId


def _tree(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }


def test_observation_probe_reads_real_consent_but_writes_only_ephemeral_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live_state = tmp_path / "live-state"
    workspace = tmp_path / "project"
    workspace.mkdir()

    import finishup.adapters.integrations.observation_local as observation_local

    monkeypatch.setattr(observation_local, "state_dir", lambda: live_state)

    def hooks_installed(_root: Path | None = None) -> bool:
        return True

    monkeypatch.setattr(setup, "_installed_hooks_declare_workspace_binding", hooks_installed)

    import finishup.cli.observe_hooks as observe_hooks

    service_touches: list[str] = []

    async def forbidden_connect(*_args: object, **_kwargs: object) -> object:
        service_touches.append("connect_service")
        raise AssertionError("the readiness probe must never open a service connection")

    async def forbidden_auto_start(*_args: object, **_kwargs: object) -> object:
        service_touches.append("_try_auto_start")
        raise AssertionError("the readiness probe must never auto-attach a ledger task")

    monkeypatch.setattr(observe_hooks, "connect_service", forbidden_connect)
    monkeypatch.setattr(observe_hooks, "_try_auto_start", forbidden_auto_start)
    store = LocalObservationStore()
    commitment = store.workspace_commitment(str(workspace.resolve()))
    store.grant_consent(commitment)
    before = _tree(live_state)

    result = setup._observation_hook_probe(workspace=workspace)  # pyright: ignore[reportPrivateUsage]

    assert result == {"ok": True, "reason": "envelope_enqueued"}
    assert service_touches == []
    assert _tree(live_state) == before
    assert store.codex_sessions_for_workspace(commitment) == ()
    assert store.list_pending_outbox(commitment) == ()


def test_observation_readiness_requires_active_selected_codex_plugin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "project"
    workspace.mkdir()
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    binary = HarnessBinary(HarnessId.CODEX, "/bin/codex", "1.0.0", "untested")

    def inactive_activation(*_args: object, **_kwargs: object) -> ActivationInspection:
        return ActivationInspection(False, False, ActivationState.INSTALLED_NOT_ACTIVATED)

    monkeypatch.setattr(setup, "inspect_activation", inactive_activation)

    def probe(**_kwargs: object) -> dict[str, object]:
        raise AssertionError("inactive activation must prevent the synthetic probe")

    monkeypatch.setattr(setup, "_observation_hook_probe", probe)
    result = setup._readiness_layers(  # pyright: ignore[reportPrivateUsage]
        binary=binary,
        mcp_state="yoetz_owned",
        plugin_presence="installed",
        skill_presence="installed_exact",
        hooks={},
        consent_outcome="granted",
        service={"reachable": True, "state": "ready"},
        workspace=workspace,
        codex_home=codex_home,
    )

    assert result["plugin_activation"] == {
        "codex_home": str(codex_home),
        "config_path": str(codex_home / "config.toml"),
        "marketplace_registered": False,
        "plugin_enabled": False,
        "state": "installed_not_activated",
    }
    assert result["observation_ready"] is False
    assert result["observation_hook_probe"] == {"ok": False, "reason": "not_attempted"}
