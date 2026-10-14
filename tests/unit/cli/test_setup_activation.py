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
        "legacy_activation": False,
        "marketplace_registered": False,
        "plugin_enabled": False,
        "state": "installed_not_activated",
    }
    assert result["observation_ready"] is False
    assert result["observation_hook_probe"] == {"ok": False, "reason": "not_attempted"}


# --- legacy Yoetz surfaces (ADR-048) ----------------------------------------------------------


def test_readiness_surfaces_a_legacy_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "project"
    workspace.mkdir()
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    binary = HarnessBinary(HarnessId.CODEX, "/bin/codex", "1.0.0", "untested")

    def legacy_activation(*_args: object, **_kwargs: object) -> ActivationInspection:
        return ActivationInspection(
            False, False, ActivationState.INSTALLED_NOT_ACTIVATED, legacy_activation=True
        )

    monkeypatch.setattr(setup, "inspect_activation", legacy_activation)
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
    activation = result["plugin_activation"]
    assert isinstance(activation, dict) and activation["legacy_activation"] is True
    unread = setup._readiness_layers(  # pyright: ignore[reportPrivateUsage]
        binary=None,
        mcp_state=None,
        plugin_presence=None,
        skill_presence=None,
        hooks={},
        consent_outcome=None,
        service={},
    )
    unread_activation = unread["plugin_activation"]
    assert isinstance(unread_activation, dict) and unread_activation["legacy_activation"] is None


def _hooks(root: Path, directory: str) -> Path:
    path = root / ".agents" / "plugins" / directory / "hooks" / "hooks.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"command":"yoetz hooks observe --workspace . --event Stop"}\n')
    return path


def test_hooks_probe_falls_back_to_a_legacy_tree_only_when_finishup_hooks_are_missing(
    tmp_path: Path,
) -> None:
    _hooks(tmp_path, "yoetz")
    probe = setup._installed_hooks_declare_workspace_binding  # pyright: ignore[reportPrivateUsage]
    assert probe(tmp_path) is True
    # An unreadable (here: not a regular file) FinishUP hooks file never reads as bound.
    unreadable = tmp_path / ".agents" / "plugins" / "finishup" / "hooks" / "hooks.json"
    unreadable.mkdir(parents=True)
    assert probe(tmp_path) is False


def test_policy_preview_reports_an_ambiguous_policy_instead_of_absent(tmp_path: Path) -> None:
    for directory in (".finishup", ".yoetz"):
        (tmp_path / directory).mkdir()
        (tmp_path / directory / "checks.toml").write_text("", encoding="utf-8")

    preview = setup._check_policy_preview(tmp_path)  # pyright: ignore[reportPrivateUsage]

    assert preview == {
        "outcome": "ambiguous",
        "reason": "policy_ambiguous",
        "policy_digest": None,
        "check_ids": (),
    }
    (tmp_path / ".yoetz" / "checks.toml").unlink()
    assert setup._check_policy_preview(tmp_path)["outcome"] != "ambiguous"  # pyright: ignore[reportPrivateUsage]


def test_interactive_preview_names_the_legacy_plugin_tree(
    capsys: pytest.CaptureFixture[str],
) -> None:
    setup._emit_legacy_activation("", (), plugin_tree_planned=True)  # pyright: ignore[reportPrivateUsage]
    setup._emit_legacy_plugin_tree(  # pyright: ignore[reportPrivateUsage]
        ("legacy_plugin_tree_present",), removal_planned=False
    )
    setup._emit_legacy_plugin_tree(  # pyright: ignore[reportPrivateUsage]
        ("legacy_plugin_tree_retained",), removal_planned=False
    )
    setup._emit_legacy_plugin_tree(  # pyright: ignore[reportPrivateUsage]
        ("legacy_plugin_tree_present",), removal_planned=True
    )
    out = capsys.readouterr().out.splitlines()
    assert out == [
        "  Earlier Yoetz activation removed by this change:",
        "    plugin source tree: .agents/plugins/yoetz (FinishUP-managed; deleted last, "
        "once nothing activated here reads it)",
        "  Earlier Yoetz plugin sources (.agents/plugins/yoetz): kept; only an approved "
        "Codex plugin activation removes them",
        "  Earlier Yoetz plugin directory (.agents/plugins/yoetz): not provably FinishUP's; "
        "left unchanged",
    ]
