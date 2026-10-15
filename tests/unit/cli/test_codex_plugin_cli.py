"""CLI wiring for Codex plugin/marketplace removal."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from finishup.adapters.integrations.codex_marketplace import (
    ActivationInspection,
    ActivationState,
    RemovalOutcome,
    RemovalPreview,
    RemovalResult,
)
from finishup.cli.app import app
from finishup.ports.harness_mcp import HarnessBinary
from finishup.ports.integrations import HarnessId, IntegrationError, IntegrationReason

_RUNNER = CliRunner()
_DIGEST = "sha256:" + "a" * 64


def _preview(home: Path, executable: Path) -> RemovalPreview:
    return RemovalPreview(
        preview_digest=_DIGEST,
        inspection=ActivationInspection(True, True, ActivationState.ACTIVE),
        outcome=RemovalOutcome.REMOVE,
        purge_cache=False,
        plugin_remove_planned=True,
        marketplace_remove_planned=True,
        marketplace_json_planned=True,
        cache_versions=("0.1.0",),
        cache_digests=(("0.1.0", "sha256:" + "e" * 64),),
        skill_tree_state="absent",
        executable_path=executable,
        executable_digest="sha256:" + "b" * 64,
        codex_version="0.148.0-alpha.6",
        codex_home=home,
        probe_command=("--version",),
        inventory_command=("plugin", "list", "--marketplace", "finishup", "--json"),
        plugin_remove_command=("plugin", "remove", "finishup@finishup", "--json"),
        marketplace_remove_command=("plugin", "marketplace", "remove", "finishup", "--json"),
        probe_environment="temporary_owner_private_home",
        activation_environment=(("CODEX_HOME", str(home)), ("CODEX_TESTING_HOME", str(home))),
        marketplace_preimage_digest="sha256:" + "c" * 64,
        config_preimage_digest="sha256:" + "d" * 64,
        config_toml_block='[marketplaces.finishup]\nsource_type = "local"\n',
    )


def test_codex_plugin_cli_preserves_symlinked_project_root_for_adapter_rejection(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    project_link = tmp_path / "project-link"
    project_link.symlink_to(project, target_is_directory=True)
    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    executable = tmp_path / "codex"
    executable.write_text("#!/bin/sh\nprintf 'codex-cli 0.149.1\\n'\n", encoding="utf-8")
    executable.chmod(0o700)

    import finishup.cli.codex_plugin as module

    target = module._target(project_link)  # pyright: ignore[reportPrivateUsage]
    assert Path(target.project_root) == project_link.absolute()
    with pytest.raises(IntegrationError) as caught:
        module.preview_removal(target, executable_path=str(executable), codex_home=home)
    assert caught.value.reason is IntegrationReason.TARGET_UNTRUSTED


def test_codex_plugin_cli_preview_status_and_remove(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    executable = home / "codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    preview = _preview(home, executable)

    def fake_discover(*, _probe: object = None) -> tuple[HarnessBinary, ...]:
        return (HarnessBinary(HarnessId.CODEX, str(executable), "0.148.0-alpha.6", "untested"),)

    def fake_preview(*_args: object, **_kwargs: object) -> RemovalPreview:
        return preview

    def fake_inspection(*_args: object, **_kwargs: object) -> ActivationInspection:
        return preview.inspection

    def fake_apply(*_args: object, **_kwargs: object) -> RemovalResult:
        return RemovalResult(
            RemovalOutcome.REMOVE,
            ActivationInspection(True, False, ActivationState.INSTALLED_NOT_ACTIVATED),
            "absent",
            False,
        )

    import finishup.cli.codex_plugin as module

    monkeypatch.setattr(module, "discover_codex_binaries", fake_discover)
    monkeypatch.setattr(module, "preview_removal", fake_preview)
    monkeypatch.setattr(module, "inspect_activation", fake_inspection)
    monkeypatch.setattr(module, "apply_removal", fake_apply)

    status = _RUNNER.invoke(
        app,
        ["integrate", "codex", "plugin", "status", "--codex-home", str(home), "--json"],
    )
    assert status.exit_code == 0, status.output
    assert json.loads(status.stdout)["state"] == "active"

    shown = _RUNNER.invoke(
        app,
        ["integrate", "codex", "plugin", "preview", "--codex-home", str(home), "--json"],
    )
    assert shown.exit_code == 0, shown.output
    body = json.loads(shown.stdout)
    assert body["preview_digest"] == _DIGEST
    assert body["action"] == "remove"
    assert body["cache_preimages"] == [{"digest": "sha256:" + "e" * 64, "version": "0.1.0"}]

    removed = _RUNNER.invoke(
        app,
        [
            "integrate",
            "codex",
            "plugin",
            "remove",
            "--codex-home",
            str(home),
            "--accept",
            "--preview-digest",
            _DIGEST,
            "--json",
        ],
    )
    assert removed.exit_code == 0, removed.output
    assert json.loads(removed.stdout)["outcome"] == "remove"


def test_codex_plugin_cli_names_remove_refused_conflict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    executable = home / "codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)

    def fake_discover(*, _probe: object = None) -> tuple[HarnessBinary, ...]:
        return (HarnessBinary(HarnessId.CODEX, str(executable), "0.148.0-alpha.6", "untested"),)

    def refuse(*_args: object, **_kwargs: object) -> RemovalPreview:
        raise IntegrationError(IntegrationReason.REMOVE_REFUSED, {"conflict": "cache"})

    import finishup.cli.codex_plugin as module

    monkeypatch.setattr(module, "discover_codex_binaries", fake_discover)
    monkeypatch.setattr(module, "preview_removal", refuse)

    result = _RUNNER.invoke(
        app,
        ["integrate", "codex", "plugin", "preview", "--codex-home", str(home), "--json"],
    )
    assert result.exit_code == 2
    assert "codex_plugin_remove_refused:cache" in result.stderr


def test_codex_plugin_cli_status_reports_foreign_without_previewing_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    executable = home / "codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)

    def fake_discover(*, _probe: object = None) -> tuple[HarnessBinary, ...]:
        return (HarnessBinary(HarnessId.CODEX, str(executable), "0.148.0-alpha.6", "untested"),)

    def refuse(*_args: object, **_kwargs: object) -> RemovalPreview:
        raise IntegrationError(IntegrationReason.REMOVE_REFUSED, {"conflict": "cache"})

    def foreign_inspection(*_args: object, **_kwargs: object) -> ActivationInspection:
        return ActivationInspection(False, False, ActivationState.FOREIGN)

    def absent_skill(_target: object) -> str:
        return "absent"

    import finishup.cli.codex_plugin as module

    monkeypatch.setattr(module, "discover_codex_binaries", fake_discover)
    monkeypatch.setattr(module, "inspect_activation", foreign_inspection)
    monkeypatch.setattr(module, "preview_removal", refuse)
    monkeypatch.setattr(module, "skill_tree_state", absent_skill)

    result = _RUNNER.invoke(
        app,
        ["integrate", "codex", "plugin", "status", "--codex-home", str(home), "--json"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["state"] == "foreign"


def test_codex_plugin_cli_remove_requires_exact_preview_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    executable = home / "codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    preview = _preview(home, executable)

    def fake_discover(*, _probe: object = None) -> tuple[HarnessBinary, ...]:
        return (HarnessBinary(HarnessId.CODEX, str(executable), "0.148.0-alpha.6", "untested"),)

    def fake_preview(*_args: object, **_kwargs: object) -> RemovalPreview:
        return preview

    import finishup.cli.codex_plugin as module

    monkeypatch.setattr(module, "discover_codex_binaries", fake_discover)
    monkeypatch.setattr(module, "preview_removal", fake_preview)

    result = _RUNNER.invoke(
        app,
        ["integrate", "codex", "plugin", "remove", "--codex-home", str(home), "--json"],
    )
    assert result.exit_code == 3
    assert "codex_plugin_exact_preview_acceptance_required" in result.stderr
