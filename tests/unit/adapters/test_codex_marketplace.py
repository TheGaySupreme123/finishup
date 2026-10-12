"""Tests for consent-gated Codex marketplace activation."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from yoetz import __version__
from yoetz.adapters.integrations.codex_marketplace import (
    ActivationInspection,
    ActivationPreview,
    ActivationState,
    RemovalOutcome,
    RemovalPreview,
    RemovalResult,
    resolve_codex_home_for_binary,
)
from yoetz.adapters.integrations.codex_marketplace import (
    apply_activation as _apply_activation,
)
from yoetz.adapters.integrations.codex_marketplace import (
    apply_removal as _apply_removal,
)
from yoetz.adapters.integrations.codex_marketplace import (
    inspect_activation as _inspect_activation,
)
from yoetz.adapters.integrations.codex_marketplace import (
    preview_activation as _preview_activation,
)
from yoetz.adapters.integrations.codex_marketplace import (
    preview_removal as _preview_removal,
)
from yoetz.adapters.integrations.codex_plugin import (
    PluginHookPresence,
    inspect_plugin,
    install_plugin,
)
from yoetz.ports.integrations import (
    IntegrationError,
    IntegrationReason,
    IntegrationScope,
    IntegrationTarget,
)


def _target(tmp_path: Path) -> tuple[IntegrationTarget, Path, Path]:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    home = tmp_path / "codex"
    home.mkdir(mode=0o700)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(project))
    return target, project, home


def _install(target: IntegrationTarget, *, codex_version: str | None = "0.148.0-alpha.6") -> None:
    install_plugin(target, allow_untested=True, codex_version=codex_version)


class _FakeCodex:
    def __init__(
        self,
        target: IntegrationTarget,
        home: Path,
        *,
        codex_version: str = "0.148.0-alpha.6",
    ) -> None:
        self.project = Path(target.project_root)
        self.home = home
        self.executable = home / "codex"
        self.executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.executable.chmod(0o700)
        self.calls: list[tuple[str, ...]] = []
        self.environments: list[dict[str, str]] = []
        self.fail_add_after_copy = False
        self.conflict_after_marketplace_remove = False
        self.repository_marketplace_conflict_after_remove = False
        self.malformed_after_mutation: set[tuple[str, ...]] = set()
        self.error_after_mutation: Exception | None = None
        self.codex_version = codex_version

    def __call__(
        self, command: tuple[str, ...], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(command)
        environment_obj = kwargs.get("env")
        assert isinstance(environment_obj, dict)
        environment = cast(dict[str, str], environment_obj)
        self.environments.append(environment)
        args = tuple(command[1:])
        if args == ("--version",):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=f"codex-cli {self.codex_version}\n".encode("ascii"),
                stderr=b"",
            )
        elif args == ("plugin", "list", "--marketplace", "yoetz", "--json"):
            body: object
            config = self.home / "config.toml"
            cache = self.home / f"plugins/cache/yoetz/yoetz/{__version__}"
            if not config.exists() or "marketplaces.yoetz" not in config.read_text(
                encoding="utf-8"
            ):
                body = {"installed": [], "available": []}
            else:
                installed = cache.is_dir()
                row = {
                    "pluginId": "yoetz@yoetz",
                    "name": "yoetz",
                    "marketplaceName": "yoetz",
                    "version": __version__,
                    "installed": installed,
                    "enabled": True,
                    "source": {
                        "source": "local",
                        "path": str(self.project / ".agents/plugins/yoetz"),
                    },
                    "marketplaceSource": {
                        "sourceType": "local",
                        "source": str(self.project),
                    },
                }
                body = {"installed" if installed else "available": [row]}
                body["available" if installed else "installed"] = []
        elif args == ("plugin", "add", "yoetz@yoetz", "--json"):
            source = self.project / ".agents/plugins/yoetz"
            destination = self.home / f"plugins/cache/yoetz/yoetz/{__version__}"
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, destination)
            body = {
                "pluginId": "yoetz@yoetz",
                "name": "yoetz",
                "marketplaceName": "yoetz",
                "version": __version__,
                "installedPath": str(destination),
            }
        elif args == ("plugin", "remove", "yoetz@yoetz", "--json"):
            destination = self.home / f"plugins/cache/yoetz/yoetz/{__version__}"
            if destination.is_dir():
                shutil.rmtree(destination)
            body = {"pluginId": "yoetz@yoetz"}
        elif args == ("plugin", "marketplace", "remove", "yoetz", "--json"):
            config = self.home / "config.toml"
            if config.exists():
                text = config.read_text(encoding="utf-8")
                marker = "[marketplaces.yoetz]\n"
                start = text.find(marker)
                if start >= 0:
                    rest = text[start + len(marker) :]
                    next_table = rest.find("\n[")
                    end = start + len(marker) + (len(rest) if next_table < 0 else next_table + 1)
                    text = text[:start] + text[end:]
                    config.write_text(text, encoding="utf-8")
            if self.conflict_after_marketplace_remove and config.exists():
                text = config.read_text(encoding="utf-8").replace(
                    "enabled = true\n", "enabled = true\nowner_note = true\n"
                )
                config.write_text(text, encoding="utf-8")
            if self.repository_marketplace_conflict_after_remove:
                marketplace = self.project / ".agents/plugins/marketplace.json"
                marketplace.write_bytes(b'{"name":"foreign"}\n')
            body = {"name": "yoetz"}
        else:
            raise AssertionError(command)
        if self.error_after_mutation is not None and args in {
            ("plugin", "remove", "yoetz@yoetz", "--json"),
            ("plugin", "marketplace", "remove", "yoetz", "--json"),
        }:
            raise self.error_after_mutation
        if args in self.malformed_after_mutation:
            return subprocess.CompletedProcess(command, 0, stdout=b'{"truncated":', stderr=b"")
        return subprocess.CompletedProcess(
            command,
            1
            if self.fail_add_after_copy and args == ("plugin", "add", "yoetz@yoetz", "--json")
            else 0,
            stdout=json.dumps(body).encode(),
            stderr=b"failed after copy" if self.fail_add_after_copy else b"",
        )


def _selected_home(codex_home: Path | str | None) -> Path:
    if codex_home is not None:
        return Path(codex_home)
    return Path(os.environ["CODEX_HOME"])


def preview_activation(
    target: IntegrationTarget, *, codex_home: Path | str | None = None
) -> ActivationPreview:
    home = _selected_home(codex_home)
    runner = _FakeCodex(target, home)
    return _preview_activation(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        _run=runner,
    )


def inspect_activation(
    target: IntegrationTarget, *, codex_home: Path | str | None = None
) -> ActivationInspection:
    home = _selected_home(codex_home)
    runner = _FakeCodex(target, home)
    return _inspect_activation(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        _run=runner,
    )


def apply_activation(
    target: IntegrationTarget,
    *,
    approved_digest: str,
    codex_home: Path | str | None = None,
) -> ActivationInspection:
    home = _selected_home(codex_home)
    runner = _FakeCodex(target, home)
    return _apply_activation(
        target,
        executable_path=str(runner.executable),
        approved_digest=approved_digest,
        codex_home=home,
        _run=runner,
    )


def preview_removal(
    target: IntegrationTarget,
    *,
    codex_home: Path | str | None = None,
    purge_cache: bool = False,
) -> RemovalPreview:
    home = _selected_home(codex_home)
    runner = _FakeCodex(target, home)
    return _preview_removal(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        purge_cache=purge_cache,
        _run=runner,
    )


def apply_removal(
    target: IntegrationTarget,
    *,
    approved_digest: str,
    codex_home: Path | str | None = None,
    purge_cache: bool = False,
) -> RemovalResult:
    home = _selected_home(codex_home)
    runner = _FakeCodex(target, home)
    return _apply_removal(
        target,
        executable_path=str(runner.executable),
        approved_digest=approved_digest,
        codex_home=home,
        purge_cache=purge_cache,
        _run=runner,
    )


def test_inspect_preview_and_apply_activation(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    assert inspect_activation(target, codex_home=home).state is ActivationState.NOT_INSTALLED
    _install(target)
    assert (
        inspect_activation(target, codex_home=home).state is ActivationState.INSTALLED_NOT_ACTIVATED
    )

    preview = preview_activation(target, codex_home=home)
    document = json.loads(preview.marketplace_bytes)
    assert document["plugins"] == [
        {
            "name": "yoetz",
            "source": {"path": "./.agents/plugins/yoetz", "source": "local"},
        }
    ]
    assert f'source = "{project}"' in preview.config_toml_block
    assert '[plugins."yoetz@yoetz"]' in preview.config_toml_block
    assert preview.plugin_source_digest.startswith("sha256:")
    assert preview.codex_home == home
    assert preview.plugin_install_path == home / f"plugins/cache/yoetz/yoetz/{__version__}"
    assert preview.plugin_install_digest.startswith("sha256:")
    assert preview.probe_command == ("--version",)
    assert preview.inventory_command == ("plugin", "list", "--marketplace", "yoetz", "--json")
    assert preview.install_command == ("plugin", "add", "yoetz@yoetz", "--json")

    result = apply_activation(
        target,
        codex_home=home,
        approved_digest=preview.preview_digest,
    )
    assert result == inspect_activation(target, codex_home=home)
    assert result.state is ActivationState.ACTIVE
    config = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert config["marketplaces"]["yoetz"]["source"] == str(project)
    assert config["plugins"]["yoetz@yoetz"]["enabled"] is True


def test_stable_codex_activation_serves_required_hooks_synchronously(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    version = "0.147.0"
    _install(target, codex_version=version)
    runner = _FakeCodex(target, home, codex_version=version)

    preview = _preview_activation(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        _run=runner,
    )
    result = _apply_activation(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        approved_digest=preview.preview_digest,
        _run=runner,
    )

    assert result.state is ActivationState.ACTIVE
    installed_hooks = json.loads(
        (home / f"plugins/cache/yoetz/yoetz/{__version__}/hooks/hooks.json").read_bytes()
    )
    for event in (
        "PreToolUse",
        "PermissionRequest",
        "PreCompact",
        "PostCompact",
        "SubagentStart",
        "SubagentStop",
    ):
        groups = installed_hooks["hooks"][event]
        handler = groups[0]["hooks"][0]
        assert "async" not in handler
    assert (project / ".agents/plugins/marketplace.json").is_file()


def test_canonical_source_activates_on_async_host_and_seeds_host_rendered_cache(
    tmp_path: Path,
) -> None:
    """#387: the committed async-free source must activate on an async-capable host.

    The project tree deliberately carries the canonical (``codex_version=None``)
    render; the host-specific async hooks belong only to the activation cache.
    Activation must succeed without rewriting the project source, and the cache
    must end up byte-identical to the host-specific render.
    """

    target, project, home = _target(tmp_path)
    _install(target, codex_version=None)
    source_hooks = (project / ".agents/plugins/yoetz/hooks/hooks.json").read_bytes()
    source_tree_before = {
        path.relative_to(project).as_posix(): path.read_bytes()
        for path in (project / ".agents/plugins/yoetz").rglob("*")
        if path.is_file()
    }
    runner = _FakeCodex(target, home, codex_version="0.148.0-alpha.6")

    assert (
        _inspect_activation(
            target, executable_path=str(runner.executable), codex_home=home, _run=runner
        ).state
        is ActivationState.INSTALLED_NOT_ACTIVATED
    )
    preview = _preview_activation(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        _run=runner,
    )
    result = _apply_activation(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        approved_digest=preview.preview_digest,
        _run=runner,
    )

    assert result.state is ActivationState.ACTIVE
    # The committed source stays byte-stable in its canonical async-free form.
    source_tree_after = {
        path.relative_to(project).as_posix(): path.read_bytes()
        for path in (project / ".agents/plugins/yoetz").rglob("*")
        if path.is_file()
    }
    assert source_tree_after == source_tree_before
    assert b'"async":true' not in source_hooks
    # The cache carries the host-specific render: async ingress hooks present.
    cache_hooks = json.loads(
        (home / f"plugins/cache/yoetz/yoetz/{__version__}/hooks/hooks.json").read_bytes()
    )
    handler = cache_hooks["hooks"]["PermissionRequest"][0]["hooks"][0]
    assert handler.get("async") is True
    # PreToolUse stays synchronous so its pairing identity commits before PostToolUse (#974).
    assert "async" not in cache_hooks["hooks"]["PreToolUse"][0]["hooks"][0]


def test_plugin_source_installed_accepts_either_current_renderer_variant(tmp_path: Path) -> None:
    target, _project, home = _target(tmp_path)
    host = "0.148.0-alpha.6"
    _install(target, codex_version=None)
    assert inspect_plugin(target, codex_version=None).presence is PluginHookPresence.INSTALLED
    assert (
        inspect_plugin(target, codex_version=host).presence
        is PluginHookPresence.INSTALLED_UNTRUSTED_UNKNOWN
    )
    assert (
        inspect_activation(target, codex_home=home).state is ActivationState.INSTALLED_NOT_ACTIVATED
    )

    _install(target, codex_version=host)
    assert inspect_plugin(target, codex_version=host).presence is PluginHookPresence.INSTALLED
    assert (
        inspect_plugin(target, codex_version=None).presence
        is PluginHookPresence.INSTALLED_UNTRUSTED_UNKNOWN
    )
    runner = _FakeCodex(target, home, codex_version=host)
    assert (
        _inspect_activation(
            target, executable_path=str(runner.executable), codex_home=home, _run=runner
        ).state
        is ActivationState.INSTALLED_NOT_ACTIVATED
    )


def test_modified_plugin_source_is_installed_not_activated(tmp_path: Path) -> None:
    """#347: a byte-present modified tree is not classified as not_installed."""

    target, project, home = _target(tmp_path)
    _install(target, codex_version=None)
    hooks = project / ".agents/plugins/yoetz/hooks/hooks.json"
    hooks.write_bytes(hooks.read_bytes() + b"\n")

    inspection = inspect_activation(target, codex_home=home)

    assert (
        inspect_plugin(target, codex_version=None).presence
        is PluginHookPresence.INSTALLED_UNTRUSTED_UNKNOWN
    )
    assert inspection.state is ActivationState.INSTALLED_NOT_ACTIVATED
    assert inspection.plugin_cached is False


def test_inventory_enabled_modified_source_never_reads_active(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    _install(target, codex_version=None)
    (project / ".agents/plugins/yoetz/hooks/hooks.json").write_bytes(b"{}\n")
    (home / "config.toml").write_text(
        '[marketplaces.yoetz]\nsource_type = "local"\n'
        f'source = "{project}"\n\n[plugins."yoetz@yoetz"]\nenabled = true\n',
        encoding="utf-8",
    )
    (home / f"plugins/cache/yoetz/yoetz/{__version__}").mkdir(parents=True, mode=0o700)

    inspection = inspect_activation(target, codex_home=home)

    assert inspection.state is ActivationState.INSTALLED_NOT_ACTIVATED
    assert inspection.state is not ActivationState.ACTIVE
    assert inspection.state is not ActivationState.NOT_INSTALLED


def test_same_version_cache_refresh_replaces_prior_managed_render(tmp_path: Path) -> None:
    """#388: a marker-identified prior cache render is replaceable, not a conflict."""

    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    target, _project, home = _target(tmp_path)
    _install(target, codex_version=None)
    runner = _FakeCodex(target, home, codex_version="0.148.0-alpha.6")
    first = _preview_activation(
        target, executable_path=str(runner.executable), codex_home=home, _run=runner
    )
    _apply_activation(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        approved_digest=first.preview_digest,
        _run=runner,
    )
    cache = home / f"plugins/cache/yoetz/yoetz/{__version__}"
    # Simulate content drift since the prior activation: overwrite the cache with
    # the other renderer variant, which is exactly a prior yoetz-managed render.
    shutil.rmtree(cache)
    cache.mkdir(mode=0o700)
    for relative_path, payload in render_plugin_install_tree(codex_version=None).items():
        destination = cache / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)

    inspection = _inspect_activation(
        target, executable_path=str(runner.executable), codex_home=home, _run=runner
    )
    assert inspection.state is ActivationState.INSTALLED_NOT_ACTIVATED

    preview = _preview_activation(
        target, executable_path=str(runner.executable), codex_home=home, _run=runner
    )
    assert preview.cache_mutation_planned is True
    result = _apply_activation(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        approved_digest=preview.preview_digest,
        _run=runner,
    )
    assert result.state is ActivationState.ACTIVE
    refreshed = json.loads((cache / "hooks/hooks.json").read_bytes())
    assert refreshed["hooks"]["PermissionRequest"][0]["hooks"][0].get("async") is True


def test_cache_refresh_between_preview_and_apply_is_stale(tmp_path: Path) -> None:
    """A cache that changes after preview must still refuse as ``preview_stale``."""

    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    target, _project, home = _target(tmp_path)
    _install(target, codex_version=None)
    runner = _FakeCodex(target, home, codex_version="0.148.0-alpha.6")
    first = _preview_activation(
        target, executable_path=str(runner.executable), codex_home=home, _run=runner
    )
    _apply_activation(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        approved_digest=first.preview_digest,
        _run=runner,
    )
    cache = home / f"plugins/cache/yoetz/yoetz/{__version__}"
    shutil.rmtree(cache)
    cache.mkdir(mode=0o700)
    for relative_path, payload in render_plugin_install_tree(codex_version=None).items():
        destination = cache / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    preview = _preview_activation(
        target, executable_path=str(runner.executable), codex_home=home, _run=runner
    )
    # The cache moves again between preview and apply: back to the host render.
    shutil.rmtree(cache)
    cache.mkdir(mode=0o700)
    for relative_path, payload in render_plugin_install_tree(
        codex_version="0.148.0-alpha.6"
    ).items():
        destination = cache / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)

    with pytest.raises(IntegrationError) as caught:
        _apply_activation(
            target,
            executable_path=str(runner.executable),
            codex_home=home,
            approved_digest=preview.preview_digest,
            _run=runner,
        )
    assert caught.value.reason is IntegrationReason.PREVIEW_STALE


def test_modified_or_foreign_cache_stays_destination_conflict(tmp_path: Path) -> None:
    """#388 keeps ``destination_conflict`` for marker-inconsistent or foreign trees."""

    target, _project, home = _target(tmp_path)
    _install(target, codex_version=None)
    runner = _FakeCodex(target, home, codex_version="0.148.0-alpha.6")
    first = _preview_activation(
        target, executable_path=str(runner.executable), codex_home=home, _run=runner
    )
    _apply_activation(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        approved_digest=first.preview_digest,
        _run=runner,
    )
    cache = home / f"plugins/cache/yoetz/yoetz/{__version__}"
    hooks = cache / "hooks/hooks.json"
    hooks.write_bytes(hooks.read_bytes() + b"# modified\n")

    with pytest.raises(IntegrationError) as caught:
        _preview_activation(
            target, executable_path=str(runner.executable), codex_home=home, _run=runner
        )
    assert caught.value.reason is IntegrationReason.DESTINATION_CONFLICT


def test_stale_managed_source_render_is_previewed_but_fenced_until_source_refresh(
    tmp_path: Path,
) -> None:
    """An older marker-consistent source render previews, but apply requires a refresh."""

    from yoetz.adapters.integrations.codex_plugin import (
        _build_marker,  # pyright: ignore[reportPrivateUsage]
        render_plugin_tree,
    )

    target, project, home = _target(tmp_path)
    _install(target, codex_version=None)
    source = project / ".agents/plugins/yoetz"
    # Rebuild the source as an older-guidance managed render: one member changes
    # and the marker is regenerated so the tree stays marker-consistent.
    members = dict(render_plugin_tree(codex_version=None))
    members["skills/yoetz/SKILL.md"] = b"# an older guidance render\n"
    for relative_path, payload in members.items():
        (source / relative_path).write_bytes(payload)
    (source / ".yoetz-plugin-install.json").write_bytes(_build_marker(members))

    runner = _FakeCodex(target, home, codex_version="0.148.0-alpha.6")
    preview = _preview_activation(
        target, executable_path=str(runner.executable), codex_home=home, _run=runner
    )
    with pytest.raises(IntegrationError) as caught:
        _apply_activation(
            target,
            executable_path=str(runner.executable),
            codex_home=home,
            approved_digest=preview.preview_digest,
            _run=runner,
        )
    assert caught.value.reason is IntegrationReason.PARTIAL_INSTALL
    assert not (project / ".agents/plugins/marketplace.json").exists()
    assert not (home / "config.toml").exists()

    install_plugin(target, allow_untested=True, codex_version=None)
    result = _apply_activation(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        approved_digest=preview.preview_digest,
        _run=runner,
    )
    assert result.state is ActivationState.ACTIVE


def test_apply_preserves_foreign_marketplace_entries_and_config(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    marketplace = project / ".agents/plugins/marketplace.json"
    marketplace.write_text(
        json.dumps(
            {
                "name": "yoetz",
                "interface": {"displayName": "Local tools"},
                "plugins": [
                    {
                        "name": "other",
                        "source": {"source": "local", "path": "./plugins/other"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (home / "config.toml").write_text('model = "gpt-5"\n', encoding="utf-8")
    preview = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=preview.preview_digest)
    document = json.loads(marketplace.read_bytes())
    assert document["interface"] == {"displayName": "Local tools"}
    assert [row["name"] for row in document["plugins"]] == ["other", "yoetz"]
    assert (home / "config.toml").read_text(encoding="utf-8").startswith('model = "gpt-5"\n')


def test_foreign_same_name_entry_is_refused(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    marketplace = project / ".agents/plugins/marketplace.json"
    marketplace.write_text(
        json.dumps(
            {
                "name": "yoetz",
                "plugins": [
                    {
                        "name": "yoetz",
                        "source": {"source": "local", "path": "./somewhere-else"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert inspect_activation(target, codex_home=home).state is ActivationState.FOREIGN
    with pytest.raises(IntegrationError) as caught:
        preview_activation(target, codex_home=home)
    assert caught.value.reason is IntegrationReason.DESTINATION_CONFLICT


def test_foreign_config_source_is_refused(tmp_path: Path) -> None:
    target, _project, home = _target(tmp_path)
    _install(target)
    (home / "config.toml").write_text(
        '[marketplaces.yoetz]\nsource_type = "local"\nsource = "/some/other/project"\n',
        encoding="utf-8",
    )
    assert inspect_activation(target, codex_home=home).state is ActivationState.FOREIGN
    with pytest.raises(IntegrationError) as caught:
        preview_activation(target, codex_home=home)
    assert caught.value.reason is IntegrationReason.DESTINATION_CONFLICT


def test_symlinked_managed_ancestor_and_leaf_are_refused(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (project / ".agents").symlink_to(outside, target_is_directory=True)
    with pytest.raises(IntegrationError) as caught:
        inspect_activation(target, codex_home=home)
    assert caught.value.reason is IntegrationReason.TARGET_UNSAFE

    (project / ".agents").unlink()
    _install(target)
    config_target = tmp_path / "config-target.toml"
    config_target.write_text("", encoding="utf-8")
    (home / "config.toml").symlink_to(config_target)
    with pytest.raises(IntegrationError) as caught:
        preview_activation(target, codex_home=home)
    assert caught.value.reason is IntegrationReason.TARGET_UNSAFE


def test_activation_refuses_symlinked_cache_ancestor_before_host_mutation(tmp_path: Path) -> None:
    target, _project, home = _target(tmp_path)
    _install(target)
    outside = tmp_path / "outside-cache"
    outside.mkdir()
    (home / "plugins").symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrationError) as caught:
        preview_activation(target, codex_home=home)

    assert caught.value.reason is IntegrationReason.TARGET_UNSAFE
    assert list(outside.iterdir()) == []


def test_cache_replacement_refuses_ancestor_swap_after_validation(tmp_path: Path) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    home = tmp_path / "codex-home"
    cache = home / f"plugins/cache/yoetz/yoetz/{__version__}"
    cache.mkdir(parents=True)
    module._validate_descendant_ancestors(  # pyright: ignore[reportPrivateUsage]
        home,
        Path("plugins/cache/yoetz/yoetz"),
    )
    outside = tmp_path / "outside-cache"
    (home / "plugins").rename(outside)
    (home / "plugins").symlink_to(outside, target_is_directory=True)
    sentinel = outside / f"cache/yoetz/yoetz/{__version__}/sentinel.txt"
    sentinel.write_bytes(b"outside")

    with pytest.raises(IntegrationError) as caught:
        module._replace_cache_tree(  # pyright: ignore[reportPrivateUsage]
            home / f"plugins/cache/yoetz/yoetz/{__version__}",
            render_plugin_install_tree(codex_version="0.148.0-alpha.6"),
            anchor_root=home,
        )

    assert caught.value.reason is IntegrationReason.TARGET_UNSAFE
    assert sentinel.read_bytes() == b"outside"


def test_removal_preview_refuses_cache_ancestor_swap_after_validation(tmp_path: Path) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    home = tmp_path / "codex-home"
    cache_root = home / "plugins/cache/yoetz/yoetz"
    cache = cache_root / __version__
    cache.mkdir(parents=True)
    expected = render_plugin_install_tree(codex_version="0.148.0-alpha.6")
    for relative, payload in expected.items():
        member = cache / relative
        member.parent.mkdir(parents=True, exist_ok=True)
        member.write_bytes(payload)
    module._validate_descendant_ancestors(  # pyright: ignore[reportPrivateUsage]
        home,
        Path("plugins/cache/yoetz/yoetz"),
    )
    outside = tmp_path / "outside-cache"
    (home / "plugins").rename(outside)
    (home / "plugins").symlink_to(outside, target_is_directory=True)
    sentinel = outside / f"cache/yoetz/yoetz/{__version__}/sentinel.txt"
    sentinel.write_bytes(b"outside")

    with pytest.raises(IntegrationError) as caught:
        module._managed_cache_versions(  # pyright: ignore[reportPrivateUsage]
            cache_root,
            expected,
            include_all_managed=False,
            anchor_root=home,
        )

    assert caught.value.reason is IntegrationReason.TARGET_UNSAFE
    assert sentinel.read_bytes() == b"outside"


def test_stale_digest_refuses_without_writing(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    preview = preview_activation(target, codex_home=home)
    config = home / "config.toml"
    config.write_text('model = "changed"\n', encoding="utf-8")
    before = config.read_bytes()
    with pytest.raises(IntegrationError) as caught:
        apply_activation(target, codex_home=home, approved_digest=preview.preview_digest)
    assert caught.value.reason is IntegrationReason.PREVIEW_STALE
    assert config.read_bytes() == before
    assert not (project / ".agents/plugins/marketplace.json").exists()


def test_second_file_stale_fence_preserves_approved_partial_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    preview = preview_activation(target, codex_home=home)
    config = home / "config.toml"
    real_assert = __import__(
        "yoetz.adapters.integrations.codex_marketplace", fromlist=["_assert_snapshot"]
    )._assert_snapshot

    def race(path: Path, expected: bytes | None) -> None:
        if path == config:
            config.write_text('model = "concurrent"\n', encoding="utf-8")
        real_assert(path, expected)

    monkeypatch.setattr("yoetz.adapters.integrations.codex_marketplace._assert_snapshot", race)
    with pytest.raises(IntegrationError) as caught:
        apply_activation(target, codex_home=home, approved_digest=preview.preview_digest)
    assert caught.value.reason is IntegrationReason.PREVIEW_STALE
    assert (project / ".agents/plugins/marketplace.json").read_bytes() == preview.marketplace_bytes
    assert config.read_text(encoding="utf-8") == 'model = "concurrent"\n'


def test_apply_refuses_before_writing_when_plugin_is_not_installed(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    preview = preview_activation(target, codex_home=home)
    with pytest.raises(IntegrationError) as caught:
        apply_activation(target, codex_home=home, approved_digest=preview.preview_digest)
    assert caught.value.reason is IntegrationReason.PARTIAL_INSTALL
    assert not (project / ".agents/plugins/marketplace.json").exists()
    assert not (home / "config.toml").exists()


def test_apply_refuses_modified_plugin_source_before_activation(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    preview = preview_activation(target, codex_home=home)
    (project / ".agents/plugins/yoetz/hooks/hooks.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(IntegrationError) as caught:
        apply_activation(target, codex_home=home, approved_digest=preview.preview_digest)
    assert caught.value.reason is IntegrationReason.PARTIAL_INSTALL
    assert not (project / ".agents/plugins/marketplace.json").exists()
    assert not (home / "config.toml").exists()


def test_preview_refuses_extra_plugin_source_file_before_any_install_command(
    tmp_path: Path,
) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    (project / ".agents/plugins/yoetz/credential123").write_text("not managed", encoding="utf-8")
    runner = _FakeCodex(target, home)
    with pytest.raises(IntegrationError) as caught:
        _preview_activation(
            target,
            executable_path=str(runner.executable),
            codex_home=home,
            _run=runner,
        )
    assert caught.value.reason is IntegrationReason.DESTINATION_CONFLICT
    assert not any(call[1:3] == ("plugin", "add") for call in runner.calls)


def test_add_failure_after_copy_preserves_honest_partial_state_for_retry(
    tmp_path: Path,
) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    runner = _FakeCodex(target, home)
    preview = _preview_activation(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        _run=runner,
    )
    runner.fail_add_after_copy = True
    with pytest.raises(IntegrationError) as caught:
        _apply_activation(
            target,
            executable_path=str(runner.executable),
            codex_home=home,
            approved_digest=preview.preview_digest,
            _run=runner,
        )
    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert (home / f"plugins/cache/yoetz/yoetz/{__version__}").exists()
    assert (project / ".agents/plugins/marketplace.json").read_bytes() == preview.marketplace_bytes
    assert (home / "config.toml").is_file()


def test_exact_commands_force_approved_home_and_version_uses_temporary_home(
    tmp_path: Path,
) -> None:
    target, _project, home = _target(tmp_path)
    _install(target)
    runner = _FakeCodex(target, home)
    preview = _preview_activation(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        _run=runner,
    )
    assert runner.calls and all(command[1:] == ("--version",) for command in runner.calls)
    for probe_environment in runner.environments:
        assert probe_environment["CODEX_HOME"] == probe_environment["CODEX_TESTING_HOME"]
        assert Path(probe_environment["CODEX_HOME"]) != home
        assert not Path(probe_environment["CODEX_HOME"]).exists()
    _apply_activation(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        approved_digest=preview.preview_digest,
        _run=runner,
    )
    for command, environment in zip(runner.calls, runner.environments, strict=True):
        assert environment["CODEX_HOME"] == environment["CODEX_TESTING_HOME"]
        if command[1:] != ("--version",):
            assert environment["CODEX_HOME"] == str(home)


def test_final_plugin_fence_preserves_approved_partial_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    preview = preview_activation(target, codex_home=home)
    hook_path = project / ".agents/plugins/yoetz/hooks/hooks.json"
    module = __import__(
        "yoetz.adapters.integrations.codex_marketplace", fromlist=["_assert_plugin_source"]
    )
    real_assert = module._assert_plugin_source
    calls = 0

    def mutate_at_final_fence(
        checked_target: IntegrationTarget,
        expected_digest: str,
        expected_members: object,
        *,
        codex_version: str,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 4:
            hook_path.write_text("{}\n", encoding="utf-8")
        real_assert(
            checked_target,
            expected_digest,
            expected_members,
            codex_version=codex_version,
        )

    monkeypatch.setattr(
        "yoetz.adapters.integrations.codex_marketplace._assert_plugin_source",
        mutate_at_final_fence,
    )
    with pytest.raises(IntegrationError) as caught:
        apply_activation(target, codex_home=home, approved_digest=preview.preview_digest)
    assert caught.value.reason is IntegrationReason.PARTIAL_INSTALL
    assert (project / ".agents/plugins/marketplace.json").read_bytes() == preview.marketplace_bytes
    assert (home / "config.toml").is_file()


def test_codex_home_environment_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target, _project, home = _target(tmp_path)
    _install(target)
    monkeypatch.setenv("CODEX_HOME", str(home))
    preview = preview_activation(target)
    apply_activation(target, approved_digest=preview.preview_digest)
    assert (home / "config.toml").is_file()
    assert inspect_activation(target).state is ActivationState.ACTIVE


def test_resolve_explicit_codex_home_without_subprocess(tmp_path: Path) -> None:
    executable = tmp_path / "codex-testing"
    selected_home = tmp_path / "selected-home"
    selected_home.mkdir(mode=0o700)
    calls: list[tuple[str, ...]] = []

    def run(command: tuple[str, ...], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        raise AssertionError("home selection must not spawn")

    resolved = resolve_codex_home_for_binary(str(executable), codex_home=selected_home, _run=run)
    assert resolved == selected_home
    assert calls == []


def test_explicit_selected_home_never_mutates_ambient_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, _project, selected_home = _target(tmp_path)
    _install(target)
    ambient = tmp_path / "ambient"
    ambient.mkdir(mode=0o700)
    ambient_config = ambient / "config.toml"
    ambient_config.write_text('model = "do-not-touch"\n', encoding="utf-8")
    before = ambient_config.read_bytes()
    monkeypatch.setenv("CODEX_HOME", str(ambient))
    preview = preview_activation(target, codex_home=selected_home)
    apply_activation(target, codex_home=selected_home, approved_digest=preview.preview_digest)
    assert ambient_config.read_bytes() == before
    assert inspect_activation(target, codex_home=selected_home).state is ActivationState.ACTIVE


def test_missing_explicit_home_is_refused_without_touching_ambient_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, _project, selected_home = _target(tmp_path)
    _install(target)
    ambient = tmp_path / "ambient"
    ambient.mkdir(mode=0o700)
    ambient_config = ambient / "config.toml"
    ambient_config.write_text('model = "do-not-touch"\n', encoding="utf-8")
    before = ambient_config.read_bytes()
    monkeypatch.setenv("CODEX_HOME", str(ambient))
    monkeypatch.setenv("CODEX_TESTING_HOME", str(selected_home))
    runner = _FakeCodex(target, selected_home)
    testing_executable = runner.executable.with_name("codex-testing")
    runner.executable.rename(testing_executable)
    runner.executable = testing_executable
    with pytest.raises(IntegrationError) as caught:
        _preview_activation(
            target,
            executable_path=str(runner.executable),
            _run=runner,
        )
    assert caught.value.reason is IntegrationReason.TARGET_UNTRUSTED
    assert ambient_config.read_bytes() == before
    assert not (selected_home / "config.toml").is_file()


def test_approved_digest_is_bound_to_exact_codex_home(tmp_path: Path) -> None:
    target, project, first_home = _target(tmp_path)
    _install(target)
    second_home = tmp_path / "second-home"
    second_home.mkdir(mode=0o700)
    preview = preview_activation(target, codex_home=first_home)
    with pytest.raises(IntegrationError) as caught:
        apply_activation(target, codex_home=second_home, approved_digest=preview.preview_digest)
    assert caught.value.reason is IntegrationReason.PREVIEW_STALE
    assert not (project / ".agents/plugins/marketplace.json").exists()
    assert not (first_home / "config.toml").exists()
    assert not (second_home / "config.toml").exists()


def test_disabled_owner_authored_plugin_table_is_not_rewritten(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    (home / "config.toml").write_text(
        "[marketplaces.yoetz]\n"
        'source_type = "local"\n'
        f'source = "{project}"\n\n'
        '[plugins."yoetz@yoetz"]\n'
        "enabled = false # owner explicitly accepts re-enable\n",
        encoding="utf-8",
    )
    before = (home / "config.toml").read_bytes()
    with pytest.raises(IntegrationError) as caught:
        preview_activation(target, codex_home=home)
    assert caught.value.reason is IntegrationReason.DESTINATION_CONFLICT
    assert (home / "config.toml").read_bytes() == before


def test_unrelated_personal_marketplace_is_not_foreign(tmp_path: Path) -> None:
    target, _project, home = _target(tmp_path)
    _install(target)
    personal = home / ".agents/plugins/marketplace.json"
    personal.parent.mkdir(parents=True)
    personal.write_text(
        json.dumps(
            {
                "name": "personal",
                "plugins": [
                    {
                        "name": "other",
                        "source": {"source": "local", "path": "./plugins/other"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert (
        inspect_activation(target, codex_home=home).state is ActivationState.INSTALLED_NOT_ACTIVATED
    )


def test_owner_inline_tables_refuse_at_preview_without_writing(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    config = home / "config.toml"
    for owner_toml in (
        "marketplaces = {}\n",
        "plugins = {}\n",
        "marketplaces = {}\nplugins = {}\n",
    ):
        config.write_text(owner_toml, encoding="utf-8")
        before = config.read_bytes()
        with pytest.raises(IntegrationError) as caught:
            preview_activation(target, codex_home=home)
        assert caught.value.reason is IntegrationReason.DESTINATION_CONFLICT
        with pytest.raises(IntegrationError) as caught:
            apply_activation(target, codex_home=home, approved_digest="sha256:" + "0" * 64)
        assert caught.value.reason is IntegrationReason.DESTINATION_CONFLICT
        assert config.read_bytes() == before
        assert not (project / ".agents/plugins/marketplace.json").exists()


def test_non_bmp_project_path_activates_with_parseable_config(tmp_path: Path) -> None:
    project = tmp_path / "project-🦊"
    project.mkdir(mode=0o700)
    home = tmp_path / "codex"
    home.mkdir(mode=0o700)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(project))
    _install(target)
    preview = preview_activation(target, codex_home=home)
    assert "🦊" in preview.config_toml_block
    result = apply_activation(target, codex_home=home, approved_digest=preview.preview_digest)
    assert result.state is ActivationState.ACTIVE
    config = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert config["marketplaces"]["yoetz"]["source"] == str(project)
    assert config["plugins"]["yoetz@yoetz"]["enabled"] is True
    document = json.loads((project / ".agents/plugins/marketplace.json").read_bytes())
    assert document["name"] == "yoetz"


def test_applied_config_parses_as_toml(tmp_path: Path) -> None:
    target, _project, home = _target(tmp_path)
    _install(target)
    (home / "config.toml").write_text('model = "gpt-5"\n', encoding="utf-8")
    preview = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=preview.preview_digest)
    parsed = tomllib.loads((home / "config.toml").read_text(encoding="utf-8"))
    assert parsed["model"] == "gpt-5"
    assert parsed["plugins"]["yoetz@yoetz"]["enabled"] is True


def test_idempotent_reapply_keeps_exact_bytes(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    first = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=first.preview_digest)
    marketplace = project / ".agents/plugins/marketplace.json"
    config = home / "config.toml"
    before = (marketplace.read_bytes(), config.read_bytes())
    second = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=second.preview_digest)
    assert (marketplace.read_bytes(), config.read_bytes()) == before
    assert os.stat(config).st_mode & 0o777 == 0o600


def test_unreadable_cache_member_normalizes_to_integration_error(tmp_path: Path) -> None:
    from yoetz.adapters.integrations.codex_marketplace import (
        _installed_cache_digest,  # pyright: ignore[reportPrivateUsage]
    )

    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    member = cache / "plugin.json"
    member.write_bytes(b"{}")
    member.chmod(0o000)
    try:
        with pytest.raises(IntegrationError) as caught:
            _installed_cache_digest(cache, {"plugin.json": b"{}"})
    finally:
        member.chmod(0o600)
    assert caught.value.reason is IntegrationReason.TARGET_UNSAFE


def test_preview_and_apply_removal_of_managed_activation(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)
    assert inspect_activation(target, codex_home=home).state is ActivationState.ACTIVE

    preview = preview_removal(target, codex_home=home)
    assert preview.outcome is RemovalOutcome.REMOVE
    assert preview.plugin_remove_planned is True
    assert preview.marketplace_remove_planned is True
    assert preview.marketplace_json_planned is True
    assert preview.skill_tree_state == "absent"
    result = apply_removal(target, codex_home=home, approved_digest=preview.preview_digest)
    assert result.outcome is RemovalOutcome.REMOVE
    assert result.inspection.state is ActivationState.INSTALLED_NOT_ACTIVATED
    assert not (project / ".agents/plugins/marketplace.json").exists()
    config = home / "config.toml"
    parsed = tomllib.loads(config.read_text(encoding="utf-8") if config.exists() else "")
    assert "yoetz" not in parsed.get("marketplaces", {})
    assert "yoetz@yoetz" not in parsed.get("plugins", {})
    cache_root = home / "plugins/cache/yoetz/yoetz"
    assert not cache_root.exists() or not any(cache_root.iterdir())
    assert (
        inspect_activation(target, codex_home=home).state is ActivationState.INSTALLED_NOT_ACTIVATED
    )
    second = preview_removal(target, codex_home=home)
    assert second.outcome is RemovalOutcome.ALREADY_ABSENT
    replay = apply_removal(target, codex_home=home, approved_digest=second.preview_digest)
    assert replay.outcome is RemovalOutcome.ALREADY_ABSENT


def test_removal_preview_digest_binds_the_exact_project_root(tmp_path: Path) -> None:
    from yoetz.adapters.integrations.codex_marketplace import (
        _canonical_marketplace_bytes,  # pyright: ignore[reportPrivateUsage]
    )

    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    targets: list[IntegrationTarget] = []
    marketplace_paths: list[Path] = []
    for name in ("project-a", "project-b"):
        project = tmp_path / name
        project.mkdir(mode=0o700)
        target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(project))
        marketplace = project / ".agents/plugins/marketplace.json"
        marketplace.parent.mkdir(parents=True, mode=0o700)
        marketplace.write_bytes(_canonical_marketplace_bytes())
        targets.append(target)
        marketplace_paths.append(marketplace)

    preview_a = preview_removal(targets[0], codex_home=home)
    preview_b = preview_removal(targets[1], codex_home=home)
    assert preview_a.preview_digest != preview_b.preview_digest

    with pytest.raises(IntegrationError) as caught:
        apply_removal(
            targets[1],
            codex_home=home,
            approved_digest=preview_a.preview_digest,
        )

    assert caught.value.reason is IntegrationReason.PREVIEW_STALE
    assert marketplace_paths[1].is_file()


def test_post_host_mutation_config_conflict_is_write_failed(tmp_path: Path) -> None:
    target, _project, home = _target(tmp_path)
    _install(target)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)
    runner = _FakeCodex(target, home)
    preview = _preview_removal(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        _run=runner,
    )
    runner.conflict_after_marketplace_remove = True

    with pytest.raises(IntegrationError) as caught:
        _apply_removal(
            target,
            executable_path=str(runner.executable),
            approved_digest=preview.preview_digest,
            codex_home=home,
            _run=runner,
        )

    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert caught.value.safe_details["conflict"] == "config_plugin"
    assert not (home / f"plugins/cache/yoetz/yoetz/{__version__}").exists()


def test_post_host_mutation_marketplace_conflict_is_write_failed(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)
    runner = _FakeCodex(target, home)
    preview = _preview_removal(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        _run=runner,
    )
    runner.repository_marketplace_conflict_after_remove = True

    with pytest.raises(IntegrationError) as caught:
        _apply_removal(
            target,
            executable_path=str(runner.executable),
            approved_digest=preview.preview_digest,
            codex_home=home,
            _run=runner,
        )

    marketplace = project / ".agents/plugins/marketplace.json"
    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert caught.value.safe_details["conflict"] == "repository_marketplace"
    assert marketplace.read_bytes() == b'{"name":"foreign"}\n'
    assert not (home / f"plugins/cache/yoetz/yoetz/{__version__}").exists()


def test_post_host_mutation_config_read_error_is_write_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module

    target, _project, home = _target(tmp_path)
    _install(target)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)
    runner = _FakeCodex(target, home)
    preview = _preview_removal(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        _run=runner,
    )
    cache = home / f"plugins/cache/yoetz/yoetz/{__version__}"
    config = home / "config.toml"
    real_current_bytes = module._current_bytes  # pyright: ignore[reportPrivateUsage]

    def fail_after_remove(path: Path) -> bytes | None:
        if path == config and not cache.exists():
            raise module._error(  # pyright: ignore[reportPrivateUsage]
                IntegrationReason.TARGET_UNSAFE
            )
        return real_current_bytes(path)

    monkeypatch.setattr(module, "_current_bytes", fail_after_remove)
    with pytest.raises(IntegrationError) as caught:
        _apply_removal(
            target,
            executable_path=str(runner.executable),
            approved_digest=preview.preview_digest,
            codex_home=home,
            _run=runner,
        )

    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert not cache.exists()


def test_mutating_host_runner_error_is_write_failed(tmp_path: Path) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module

    target, _project, home = _target(tmp_path)
    _install(target)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)
    runner = _FakeCodex(target, home)
    preview = _preview_removal(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        _run=runner,
    )
    cache = home / f"plugins/cache/yoetz/yoetz/{__version__}"
    runner.error_after_mutation = module._error(  # pyright: ignore[reportPrivateUsage]
        IntegrationReason.TARGET_UNSAFE
    )

    with pytest.raises(IntegrationError) as caught:
        _apply_removal(
            target,
            executable_path=str(runner.executable),
            approved_digest=preview.preview_digest,
            codex_home=home,
            _run=runner,
        )

    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert not cache.exists()


@pytest.mark.parametrize("host_surface", ["plugin", "marketplace"])
def test_mutating_host_malformed_json_is_write_failed(
    tmp_path: Path,
    host_surface: str,
) -> None:
    target, _project, home = _target(tmp_path)
    _install(target)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)
    cache = home / f"plugins/cache/yoetz/yoetz/{__version__}"
    if host_surface == "marketplace":
        shutil.rmtree(cache)
    runner = _FakeCodex(target, home)
    preview = _preview_removal(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        _run=runner,
    )
    command = (
        ("plugin", "remove", "yoetz@yoetz", "--json")
        if host_surface == "plugin"
        else ("plugin", "marketplace", "remove", "yoetz", "--json")
    )
    runner.malformed_after_mutation.add(command)

    with pytest.raises(IntegrationError) as caught:
        _apply_removal(
            target,
            executable_path=str(runner.executable),
            approved_digest=preview.preview_digest,
            codex_home=home,
            _run=runner,
        )

    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    if host_surface == "plugin":
        assert not cache.exists()
    else:
        config = home / "config.toml"
        assert "marketplaces.yoetz" not in config.read_text(encoding="utf-8")


def test_repository_marketplace_replacement_during_quarantine_is_preserved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module

    target, project, home = _target(tmp_path)
    _install(target)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)
    runner = _FakeCodex(target, home)
    preview = _preview_removal(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        _run=runner,
    )
    marketplace = project / ".agents/plugins/marketplace.json"
    foreign = b'{"name":"foreign-race"}\n'
    original_rename = os.rename
    raced = False

    def replace_before_quarantine(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal raced
        if source == "marketplace.json" and not raced:
            raced = True
            replacement = marketplace.with_name("marketplace.foreign")
            replacement.write_bytes(foreign)
            os.replace(replacement, marketplace)
        original_rename(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    # Replacing ``os.rename`` changes function identity and would make the production primitive
    # capability probe fail before reaching the simulated supported-host race.
    monkeypatch.setattr(module, "_require_safe_cache_removal_primitives", lambda: None)
    monkeypatch.setattr(module, "_require_safe_file_removal_primitives", lambda: None)
    monkeypatch.setattr(os, "rename", replace_before_quarantine)

    with pytest.raises(IntegrationError) as caught:
        _apply_removal(
            target,
            executable_path=str(runner.executable),
            approved_digest=preview.preview_digest,
            codex_home=home,
            _run=runner,
        )

    assert raced is True
    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert caught.value.safe_details["conflict"] == "repository_marketplace"
    assert marketplace.read_bytes() == foreign


def test_repository_marketplace_restore_never_clobbers_new_foreign_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module

    target, project, home = _target(tmp_path)
    _install(target)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)
    runner = _FakeCodex(target, home)
    preview = _preview_removal(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        _run=runner,
    )
    marketplace = project / ".agents/plugins/marketplace.json"
    moved_foreign = b'{"name":"moved-foreign"}\n'
    new_foreign = b'{"name":"new-foreign"}\n'
    original_rename = os.rename
    original_link = os.link
    renamed = False
    linked = False

    def replace_before_quarantine(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal renamed
        if source == "marketplace.json" and not renamed:
            renamed = True
            replacement = marketplace.with_name("marketplace.moved")
            replacement.write_bytes(moved_foreign)
            os.replace(replacement, marketplace)
        original_rename(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    def create_before_restore_link(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal linked
        if destination == "marketplace.json" and not linked:
            linked = True
            marketplace.write_bytes(new_foreign)
        original_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(module, "_require_safe_cache_removal_primitives", lambda: None)
    monkeypatch.setattr(module, "_require_safe_file_removal_primitives", lambda: None)
    monkeypatch.setattr(os, "rename", replace_before_quarantine)
    monkeypatch.setattr(os, "link", create_before_restore_link)

    with pytest.raises(IntegrationError) as caught:
        _apply_removal(
            target,
            executable_path=str(runner.executable),
            approved_digest=preview.preview_digest,
            codex_home=home,
            _run=runner,
        )

    assert renamed is True
    assert linked is True
    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert marketplace.read_bytes() == new_foreign
    quarantines = tuple(marketplace.parent.glob(".yoetz-file-remove-*"))
    assert len(quarantines) == 1
    assert quarantines[0].read_bytes() == moved_foreign


def test_exact_empty_config_cleanup_preserves_a_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module

    parent = tmp_path / "codex"
    parent.mkdir(mode=0o700)
    config = parent / "config.toml"
    config.write_bytes(b"")
    foreign = b'owner = "foreign"\n'
    original_rename = os.rename
    raced = False

    def replace_before_quarantine(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal raced
        if source == "config.toml" and not raced:
            raced = True
            replacement = parent / "config.foreign"
            replacement.write_bytes(foreign)
            os.replace(replacement, config)
        original_rename(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(module, "_require_safe_file_removal_primitives", lambda: None)
    monkeypatch.setattr(os, "rename", replace_before_quarantine)

    with pytest.raises(IntegrationError) as caught:
        module._remove_exact_managed_file(  # pyright: ignore[reportPrivateUsage]
            config,
            b"",
            mismatch_reason=IntegrationReason.PREVIEW_STALE,
        )

    assert raced is True
    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert config.read_bytes() == foreign


def test_removal_preserves_unrelated_owner_blank_lines(tmp_path: Path) -> None:
    target, _project, home = _target(tmp_path)
    _install(target)
    owner = b'owner = "keep"\n\n\n\n[owner_table]\nvalue = true\n'
    config = home / "config.toml"
    config.write_bytes(owner)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)

    removal = preview_removal(target, codex_home=home)
    apply_removal(target, codex_home=home, approved_digest=removal.preview_digest)

    assert config.read_bytes() == owner
    assert tomllib.loads(config.read_text(encoding="utf-8")) == {
        "owner": "keep",
        "owner_table": {"value": True},
    }


def test_plugin_command_output_is_bounded_during_capture(tmp_path: Path) -> None:
    target, _project, home = _target(tmp_path)
    _install(target)
    executable = home / "flooding-codex"
    pid_path = home / "flooding-codex.pid"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import os\n"
        "import pathlib\n"
        "import sys\n"
        f"pid_path = pathlib.Path({str(pid_path)!r})\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('codex-cli 0.148.0-alpha.6')\n"
        "else:\n"
        "    pid_path.write_text(str(os.getpid()), encoding='ascii')\n"
        "    chunk = b'x' * 65536\n"
        "    while True:\n"
        "        os.write(2, chunk)\n"
        "        os.write(1, chunk)\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)

    with pytest.raises(IntegrationError) as caught:
        _inspect_activation(
            target,
            executable_path=str(executable),
            codex_home=home,
        )

    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    pid = int(pid_path.read_text(encoding="ascii"))
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_cache_only_removal_preserves_write_failed_for_final_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    target, project, home = _target(tmp_path)
    _install(target)
    cache = home / f"plugins/cache/yoetz/yoetz/{__version__}"
    expected = render_plugin_install_tree(codex_version="0.148.0-alpha.6")
    for relative, payload in expected.items():
        destination = cache / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    runner = _FakeCodex(target, home)
    preview = _preview_removal(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        _run=runner,
    )
    assert preview.cache_versions == (__version__,)
    assert preview.plugin_remove_planned is False
    assert preview.marketplace_remove_planned is False
    original_inventory = module._plugin_inventory  # pyright: ignore[reportPrivateUsage]

    def fail_inventory_after_cache_delete(
        binary: object,
        selected_project: Path,
        *,
        _run: object,
    ) -> tuple[bool, str | None]:
        if not cache.exists():
            raise IntegrationError(IntegrationReason.SOURCE_INVALID, {})
        return original_inventory(binary, selected_project, _run=_run)  # type: ignore[arg-type]

    monkeypatch.setattr(module, "_plugin_inventory", fail_inventory_after_cache_delete)

    with pytest.raises(IntegrationError) as caught:
        _apply_removal(
            target,
            executable_path=str(runner.executable),
            approved_digest=preview.preview_digest,
            codex_home=home,
            _run=runner,
        )

    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert not cache.exists()
    assert project.is_dir()


@pytest.mark.parametrize(
    "overflow",
    ["member_bytes", "file_count", "entry_count", "depth", "version_count"],
)
def test_removal_preview_bounds_cache_members(tmp_path: Path, overflow: str) -> None:
    from yoetz.adapters.integrations.codex_marketplace import (
        _MAX_MANAGED_CACHE_DEPTH,  # pyright: ignore[reportPrivateUsage]
        _MAX_MANAGED_CACHE_ENTRIES,  # pyright: ignore[reportPrivateUsage]
        _MAX_MANAGED_CACHE_FILES,  # pyright: ignore[reportPrivateUsage]
        _MAX_MANAGED_CACHE_MEMBER_BYTES,  # pyright: ignore[reportPrivateUsage]
    )

    target, _project, home = _target(tmp_path)
    _install(target)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)
    cache = home / f"plugins/cache/yoetz/yoetz/{__version__}"
    if overflow == "member_bytes":
        os.truncate(cache / "hooks/hooks.json", _MAX_MANAGED_CACHE_MEMBER_BYTES + 1)
    elif overflow == "file_count":
        overflow_dir = cache / "overflow"
        overflow_dir.mkdir()
        for index in range(_MAX_MANAGED_CACHE_FILES + 1):
            (overflow_dir / f"{index:02d}.txt").write_bytes(b"x")
    elif overflow == "entry_count":
        overflow_dir = cache / "overflow"
        overflow_dir.mkdir()
        for index in range(_MAX_MANAGED_CACHE_ENTRIES + 1):
            (overflow_dir / f"{index:03d}").mkdir()
    elif overflow == "depth":
        current = cache / "overflow"
        for index in range(_MAX_MANAGED_CACHE_DEPTH + 1):
            current /= f"d{index:02d}"
            current.mkdir(parents=True)
    else:
        cache_root = cache.parent
        for index in range(_MAX_MANAGED_CACHE_ENTRIES + 1):
            (cache_root / f"1.0.{index}").mkdir()

    with pytest.raises(IntegrationError) as caught:
        preview_removal(target, codex_home=home, purge_cache=True)

    assert caught.value.reason is IntegrationReason.PREVIEW_STALE
    assert cache.is_dir()


def test_removal_preview_rejects_unrepresented_empty_cache_directory(tmp_path: Path) -> None:
    target, _project, home = _target(tmp_path)
    _install(target)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)
    cache = home / f"plugins/cache/yoetz/yoetz/{__version__}"
    empty = cache / "owner-empty"
    empty.mkdir()

    with pytest.raises(IntegrationError) as caught:
        preview_removal(target, codex_home=home, purge_cache=True)

    assert caught.value.reason is IntegrationReason.REMOVE_REFUSED
    assert caught.value.safe_details == {"conflict": "cache"}
    assert empty.is_dir()


def test_removal_refuses_foreign_marketplace_and_names_conflict(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    marketplace = project / ".agents/plugins/marketplace.json"
    marketplace.parent.mkdir(parents=True, exist_ok=True)
    marketplace.write_text(
        '{"name":"other","plugins":[{"name":"yoetz","source":{"source":"local","path":"./"}}]}\n',
        encoding="utf-8",
    )
    with pytest.raises(IntegrationError) as caught:
        preview_removal(target, codex_home=home)
    assert caught.value.reason is IntegrationReason.REMOVE_REFUSED
    assert caught.value.safe_details["conflict"] == "repository_marketplace"
    assert marketplace.is_file()


def test_removal_refuses_modified_plugin_table(tmp_path: Path) -> None:
    target, _project, home = _target(tmp_path)
    _install(target)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)
    config = home / "config.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace("enabled = true", "enabled = false"),
        encoding="utf-8",
    )
    before = config.read_bytes()
    with pytest.raises(IntegrationError) as caught:
        preview_removal(target, codex_home=home)
    assert caught.value.reason is IntegrationReason.REMOVE_REFUSED
    assert caught.value.safe_details["conflict"] == "config_plugin"
    assert config.read_bytes() == before


def test_removal_refuses_plugin_table_with_additional_field(tmp_path: Path) -> None:
    target, _project, home = _target(tmp_path)
    _install(target)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)
    config = home / "config.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "enabled = true\n", "enabled = true\nowner_note = true\n"
        ),
        encoding="utf-8",
    )
    before = config.read_bytes()
    with pytest.raises(IntegrationError) as caught:
        preview_removal(target, codex_home=home)
    assert caught.value.reason is IntegrationReason.REMOVE_REFUSED
    assert caught.value.safe_details["conflict"] == "config_plugin"
    assert config.read_bytes() == before


def test_removal_refuses_marketplace_table_with_additional_field(tmp_path: Path) -> None:
    target, project, home = _target(tmp_path)
    _install(target)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)
    config = home / "config.toml"
    expected = f'source = "{project}"\n'
    config.write_text(
        config.read_text(encoding="utf-8").replace(expected, f"{expected}owner_note = true\n"),
        encoding="utf-8",
    )
    before = config.read_bytes()
    with pytest.raises(IntegrationError) as caught:
        preview_removal(target, codex_home=home)
    assert caught.value.reason is IntegrationReason.REMOVE_REFUSED
    assert caught.value.safe_details["conflict"] == "config_marketplace"
    assert config.read_bytes() == before


def test_cache_removal_revalidates_digest_immediately_before_delete(
    tmp_path: Path,
) -> None:
    from yoetz.adapters.integrations.codex_marketplace import (
        _delete_managed_cache_versions,  # pyright: ignore[reportPrivateUsage]
        _installed_cache_digest,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    root = tmp_path / "cache"
    version = root / "0.1.0"
    expected = render_plugin_install_tree(codex_version="0.148.0-alpha.6")
    for relative, payload in expected.items():
        destination = version / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    digest = _installed_cache_digest(version, expected)
    assert digest is not None
    hooks = version / "hooks/hooks.json"
    hooks.write_bytes(hooks.read_bytes() + b"\n")

    with pytest.raises(IntegrationError) as caught:
        _delete_managed_cache_versions(root, (("0.1.0", digest),), expected)
    assert caught.value.reason is IntegrationReason.PREVIEW_STALE
    assert hooks.exists()


def test_cache_removal_bounds_replaced_member_before_reading_to_eof(tmp_path: Path) -> None:
    from yoetz.adapters.integrations.codex_marketplace import (
        _MAX_MANAGED_CACHE_MEMBER_BYTES,  # pyright: ignore[reportPrivateUsage]
        _delete_managed_cache_versions,  # pyright: ignore[reportPrivateUsage]
        _installed_cache_digest,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    root = tmp_path / "cache"
    version = root / "0.1.0"
    expected = render_plugin_install_tree(codex_version="0.148.0-alpha.6")
    for relative, payload in expected.items():
        destination = version / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    digest = _installed_cache_digest(version, expected)
    assert digest is not None
    replaced = version / "hooks/hooks.json"
    os.truncate(replaced, _MAX_MANAGED_CACHE_MEMBER_BYTES + 1)

    with pytest.raises(IntegrationError) as caught:
        _delete_managed_cache_versions(root, (("0.1.0", digest),), expected)

    assert caught.value.reason is IntegrationReason.PREVIEW_STALE
    assert replaced.stat().st_size == _MAX_MANAGED_CACHE_MEMBER_BYTES + 1


def test_cache_removal_bounds_aggregate_revalidation_bytes(tmp_path: Path) -> None:
    from yoetz.adapters.integrations.codex_marketplace import (
        _MAX_MANAGED_CACHE_TREE_BYTES,  # pyright: ignore[reportPrivateUsage]
        _delete_managed_cache_versions,  # pyright: ignore[reportPrivateUsage]
        _installed_cache_digest,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    root = tmp_path / "cache"
    version = root / "0.1.0"
    expected = render_plugin_install_tree(codex_version="0.148.0-alpha.6")
    for relative, payload in expected.items():
        destination = version / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    digest = _installed_cache_digest(version, expected)
    assert digest is not None
    overflow = version / "overflow"
    overflow.mkdir()
    member_size = _MAX_MANAGED_CACHE_TREE_BYTES // 16
    for index in range(17):
        member = overflow / f"{index:02d}.bin"
        member.touch()
        os.truncate(member, member_size)

    with pytest.raises(IntegrationError) as caught:
        _delete_managed_cache_versions(root, (("0.1.0", digest),), expected)

    assert caught.value.reason is IntegrationReason.PREVIEW_STALE
    assert version.is_dir()


def test_cache_removal_does_not_reopen_replaced_quarantine_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    root = tmp_path / "cache"
    version = root / "0.1.0"
    expected = render_plugin_install_tree(codex_version="0.148.0-alpha.6")
    for relative, payload in expected.items():
        destination = version / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    digest = module._installed_cache_digest(version, expected)  # pyright: ignore[reportPrivateUsage]
    assert digest is not None
    original_remove = module._remove_validated_directory  # pyright: ignore[reportPrivateUsage]

    def replace_before_remove(
        root_fd: int,
        name: str,
        descriptor: int,
        approved_members: Mapping[str, bytes],
    ) -> None:
        moved = f"{name}-moved"
        os.rename(name, moved, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.mkdir(name, mode=0o700, dir_fd=root_fd)
        replacement_fd = os.open(name, module._directory_open_flags(), dir_fd=root_fd)  # pyright: ignore[reportPrivateUsage]
        try:
            sentinel_fd = os.open(
                "sentinel.txt",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=replacement_fd,
            )
            try:
                os.write(sentinel_fd, b"foreign")
            finally:
                os.close(sentinel_fd)
        finally:
            os.close(replacement_fd)
        original_remove(root_fd, name, descriptor, approved_members)

    monkeypatch.setattr(module, "_remove_validated_directory", replace_before_remove)

    with pytest.raises(IntegrationError) as caught:
        module._delete_managed_cache_versions(  # pyright: ignore[reportPrivateUsage]
            root, (("0.1.0", digest),), expected
        )

    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    replacements = [
        candidate
        for candidate in root.iterdir()
        if candidate.name.startswith(".yoetz-cache-remove-")
        and not candidate.name.endswith("-moved")
    ]
    assert len(replacements) == 1
    assert (replacements[0] / "sentinel.txt").read_bytes() == b"foreign"


@pytest.mark.parametrize("mutation", ["modify", "add", "empty_directory"])
def test_cache_removal_revalidates_exact_quarantine_contents_before_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    root = tmp_path / "cache"
    version = root / "0.1.0"
    expected = render_plugin_install_tree(codex_version="0.148.0-alpha.6")
    for relative, payload in expected.items():
        destination = version / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    digest = module._installed_cache_digest(version, expected)  # pyright: ignore[reportPrivateUsage]
    assert digest is not None
    original_remove = module._remove_validated_directory  # pyright: ignore[reportPrivateUsage]

    def mutate_before_remove(
        root_fd: int,
        name: str,
        descriptor: int,
        approved_members: Mapping[str, bytes],
    ) -> None:
        if mutation == "modify":
            member_fd = os.open(
                "hooks/hooks.json",
                os.O_WRONLY | os.O_TRUNC,
                dir_fd=descriptor,
            )
            try:
                os.write(member_fd, b"changed")
            finally:
                os.close(member_fd)
        elif mutation == "add":
            member_fd = os.open(
                "added.txt",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=descriptor,
            )
            try:
                os.write(member_fd, b"foreign")
            finally:
                os.close(member_fd)
        else:
            os.mkdir("empty", mode=0o700, dir_fd=descriptor)
        original_remove(root_fd, name, descriptor, approved_members)

    monkeypatch.setattr(module, "_remove_validated_directory", mutate_before_remove)

    with pytest.raises(IntegrationError) as caught:
        module._delete_managed_cache_versions(  # pyright: ignore[reportPrivateUsage]
            root,
            (("0.1.0", digest),),
            expected,
        )

    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert version.is_dir()
    if mutation == "modify":
        assert (version / "hooks/hooks.json").read_bytes() == b"changed"
    elif mutation == "add":
        assert (version / "added.txt").read_bytes() == b"foreign"
    else:
        assert (version / "empty").is_dir()


def test_cache_removal_restores_quarantine_on_race_before_first_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    root = tmp_path / "cache"
    version = root / "0.1.0"
    expected = render_plugin_install_tree(codex_version="0.148.0-alpha.6")
    for relative, payload in expected.items():
        destination = version / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    digest = module._installed_cache_digest(version, expected)  # pyright: ignore[reportPrivateUsage]
    assert digest is not None
    original_remove_contents = module._remove_managed_tree_contents_fd  # pyright: ignore[reportPrivateUsage]
    mutated = False

    def mutate_after_full_validation(
        directory_fd: int,
        approved_members: Mapping[str, bytes],
        *,
        prefix: str = "",
        mutation_state: list[bool],
    ) -> None:
        nonlocal mutated
        if not mutated:
            mutated = True
            member_fd = os.open(
                ".codex-plugin/plugin.json",
                os.O_WRONLY | os.O_TRUNC,
                dir_fd=directory_fd,
            )
            try:
                os.write(member_fd, b"changed-after-validation")
            finally:
                os.close(member_fd)
        original_remove_contents(
            directory_fd,
            approved_members,
            prefix=prefix,
            mutation_state=mutation_state,
        )

    monkeypatch.setattr(module, "_remove_managed_tree_contents_fd", mutate_after_full_validation)

    with pytest.raises(IntegrationError) as caught:
        module._delete_managed_cache_versions(  # pyright: ignore[reportPrivateUsage]
            root,
            (("0.1.0", digest),),
            expected,
        )

    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert (version / ".codex-plugin/plugin.json").read_bytes() == b"changed-after-validation"
    assert not any(path.name.startswith(".yoetz-cache-remove-") for path in root.iterdir())


def test_cache_removal_keeps_write_failed_across_multiple_versions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    root = tmp_path / "cache"
    expected = render_plugin_install_tree(codex_version="0.148.0-alpha.6")
    digests: list[tuple[str, str]] = []
    for version_name in ("0.1.0", "0.2.0"):
        version = root / version_name
        for relative, payload in expected.items():
            destination = version / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
        digest = module._installed_cache_digest(version, expected)  # pyright: ignore[reportPrivateUsage]
        assert digest is not None
        digests.append((version_name, digest))
    original_open = module._open_managed_cache_digest_at  # pyright: ignore[reportPrivateUsage]

    def drift_second_version(
        root_fd: int,
        name: str,
        expected_members: Mapping[str, bytes],
    ) -> tuple[int, str, Mapping[str, bytes]] | None:
        if name == "0.2.0":
            second_fd = os.open(name, module._directory_open_flags(), dir_fd=root_fd)  # pyright: ignore[reportPrivateUsage]
            try:
                member_fd = os.open(
                    "hooks/hooks.json",
                    os.O_WRONLY | os.O_TRUNC,
                    dir_fd=second_fd,
                )
                try:
                    os.write(member_fd, b"changed-after-first-version")
                finally:
                    os.close(member_fd)
            finally:
                os.close(second_fd)
        return original_open(root_fd, name, expected_members)

    monkeypatch.setattr(module, "_open_managed_cache_digest_at", drift_second_version)

    with pytest.raises(IntegrationError) as caught:
        module._delete_managed_cache_versions(  # pyright: ignore[reportPrivateUsage]
            root,
            tuple(digests),
            expected,
        )

    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert not (root / "0.1.0").exists()
    assert (root / "0.2.0/hooks/hooks.json").read_bytes() == b"changed-after-first-version"


def test_cache_removal_normalizes_missing_quarantine_after_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    root = tmp_path / "cache"
    version = root / "0.1.0"
    expected = render_plugin_install_tree(codex_version="0.148.0-alpha.6")
    for relative, payload in expected.items():
        destination = version / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    digest = module._installed_cache_digest(version, expected)  # pyright: ignore[reportPrivateUsage]
    assert digest is not None
    real_rename = module.os.rename
    moved_name: str | None = None

    def disappear_quarantine_after_rename(
        source: str,
        destination: str,
        **kwargs: object,
    ) -> None:
        nonlocal moved_name
        real_rename(source, destination, **kwargs)  # type: ignore[arg-type]
        if moved_name is None and destination.startswith(".yoetz-cache-remove-"):
            moved_name = f"{destination}-moved"
            real_rename(destination, moved_name, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(module, "_require_safe_cache_removal_primitives", lambda: None)
    monkeypatch.setattr(module.os, "rename", disappear_quarantine_after_rename)

    with pytest.raises(IntegrationError) as caught:
        module._delete_managed_cache_versions(  # pyright: ignore[reportPrivateUsage]
            root,
            (("0.1.0", digest),),
            expected,
        )

    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert moved_name is not None
    assert (root / moved_name / "hooks/hooks.json").exists()


def test_cache_removal_refuses_replaced_symlink_root(tmp_path: Path) -> None:
    from yoetz.adapters.integrations.codex_marketplace import (
        _delete_managed_cache_versions,  # pyright: ignore[reportPrivateUsage]
        _installed_cache_digest,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    root = tmp_path / "cache"
    version = root / "0.1.0"
    expected = render_plugin_install_tree(codex_version="0.148.0-alpha.6")
    for relative, payload in expected.items():
        destination = version / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    digest = _installed_cache_digest(version, expected)
    assert digest is not None
    outside = tmp_path / "outside"
    root.rename(outside)
    root.symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrationError) as caught:
        _delete_managed_cache_versions(root, (("0.1.0", digest),), expected)
    assert caught.value.reason is IntegrationReason.TARGET_UNSAFE
    assert (outside / "0.1.0/hooks/hooks.json").exists()


def test_cache_removal_refuses_symlinked_ancestor_beneath_selected_home(tmp_path: Path) -> None:
    from yoetz.adapters.integrations.codex_marketplace import (
        _delete_managed_cache_versions,  # pyright: ignore[reportPrivateUsage]
        _installed_cache_digest,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    root = outside / "cache/yoetz/yoetz"
    version = root / "0.1.0"
    expected = render_plugin_install_tree(codex_version="0.148.0-alpha.6")
    for relative, payload in expected.items():
        destination = version / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    digest = _installed_cache_digest(version, expected)
    assert digest is not None
    (home / "plugins").symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrationError) as caught:
        _delete_managed_cache_versions(
            home / "plugins/cache/yoetz/yoetz",
            (("0.1.0", digest),),
            expected,
            anchor_root=home,
        )

    assert caught.value.reason is IntegrationReason.TARGET_UNSAFE
    assert (version / "hooks/hooks.json").exists()


def test_cache_removal_accepts_host_removed_root_only_after_prior_mutation(tmp_path: Path) -> None:
    from yoetz.adapters.integrations.codex_marketplace import (
        _delete_managed_cache_versions,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    root = home / "plugins/cache/yoetz/yoetz"
    expected = render_plugin_install_tree(codex_version="0.148.0-alpha.6")
    assert _delete_managed_cache_versions(
        root,
        (("0.1.0", "sha256:" + "a" * 64),),
        expected,
        anchor_root=home,
        missing_ok_after_prior_mutation=True,
    )


def test_file_removal_refuses_symlinked_ancestor_beneath_selected_project(
    tmp_path: Path,
) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module

    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    plugins = outside / "plugins"
    plugins.mkdir(parents=True)
    marketplace = plugins / "marketplace.json"
    expected = b'{"name":"yoetz"}\n'
    marketplace.write_bytes(expected)
    (project / ".agents").symlink_to(outside, target_is_directory=True)

    with pytest.raises(IntegrationError) as caught:
        module._remove_exact_managed_file(  # pyright: ignore[reportPrivateUsage]
            project / ".agents/plugins/marketplace.json",
            expected,
            mismatch_reason=IntegrationReason.PREVIEW_STALE,
            anchor_root=project,
        )

    assert caught.value.reason is IntegrationReason.TARGET_UNSAFE
    assert marketplace.read_bytes() == expected


@pytest.mark.parametrize(
    "reason",
    [IntegrationReason.DESTINATION_CONFLICT, IntegrationReason.TARGET_UNSAFE],
)
def test_cache_removal_normalizes_every_post_quarantine_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reason: IntegrationReason,
) -> None:
    from yoetz.adapters.integrations import codex_marketplace as module
    from yoetz.adapters.integrations.codex_plugin import render_plugin_install_tree

    root = tmp_path / "cache"
    version = root / "0.1.0"
    expected = render_plugin_install_tree(codex_version="0.148.0-alpha.6")
    for relative, payload in expected.items():
        destination = version / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    digest = module._installed_cache_digest(version, expected)  # pyright: ignore[reportPrivateUsage]
    assert digest is not None

    def fail_after_quarantine(
        _root_fd: int,
        _name: str,
        _descriptor: int,
        _approved_members: Mapping[str, bytes],
    ) -> None:
        raise IntegrationError(reason, {})

    monkeypatch.setattr(module, "_remove_validated_directory", fail_after_quarantine)

    with pytest.raises(IntegrationError) as caught:
        module._delete_managed_cache_versions(  # pyright: ignore[reportPrivateUsage]
            root,
            (("0.1.0", digest),),
            expected,
        )

    assert caught.value.reason is IntegrationReason.WRITE_FAILED
    assert version.is_dir()
    assert not any(
        candidate.name.startswith(".yoetz-cache-remove-") for candidate in root.iterdir()
    )


def test_purge_cache_deletes_other_managed_versions(tmp_path: Path) -> None:
    target, _project, home = _target(tmp_path)
    _install(target)
    activation = preview_activation(target, codex_home=home)
    apply_activation(target, codex_home=home, approved_digest=activation.preview_digest)
    extra = home / "plugins/cache/yoetz/yoetz/0.0.1"
    shutil.copytree(home / f"plugins/cache/yoetz/yoetz/{__version__}", extra)
    with pytest.raises(IntegrationError) as caught:
        preview_removal(target, codex_home=home)
    assert caught.value.reason is IntegrationReason.REMOVE_REFUSED
    assert caught.value.safe_details["conflict"] == "cache"
    preview = preview_removal(target, codex_home=home, purge_cache=True)
    assert "0.0.1" in preview.cache_versions
    result = apply_removal(
        target,
        codex_home=home,
        approved_digest=preview.preview_digest,
        purge_cache=True,
    )
    assert result.outcome is RemovalOutcome.REMOVE
    assert not extra.exists()
    cache_root = home / "plugins/cache/yoetz/yoetz"
    assert not cache_root.exists() or not any(cache_root.iterdir())
