"""One Codex home serves several Yoetz-connected projects (issue #1058).

Codex keeps the Yoetz plugin, its cache, its enable table, and the ``[marketplaces.yoetz]``
binding once per home; the binding names one project's ``.agents/plugins`` manifest. Before
#1058, setup for a second project in the same home refused as ``destination_conflict`` because
the binding named the first project. These tests pin the multi-project model: B joins the shared
pieces, disconnecting A moves the binding to B, the last disconnect removes the shared pieces,
and only a genuine duplicate (one directory under two paths) is refused.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import cast

import pytest
from tests.unit.adapters.test_codex_marketplace import (
    _install,  # pyright: ignore[reportPrivateUsage]
    apply_activation,
    apply_removal,
    inspect_activation,
    preview_activation,
    preview_removal,
)

from yoetz import __version__
from yoetz.adapters.integrations.codex_marketplace import (
    ActivationState,
    RemovalOutcome,
    connected_projects,
    project_registered_elsewhere,
)
from yoetz.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE
from yoetz.ports.integrations import (
    IntegrationError,
    IntegrationReason,
    IntegrationScope,
    IntegrationTarget,
)


def _project(tmp_path: Path, name: str) -> tuple[IntegrationTarget, Path]:
    root = tmp_path / name
    root.mkdir(mode=0o700)
    return IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(root)), root


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "codex"
    home.mkdir(mode=0o700)
    return home


def _connect(target: IntegrationTarget, home: Path) -> None:
    _install(target)
    preview = preview_activation(target, codex_home=home)
    result = apply_activation(target, codex_home=home, approved_digest=preview.preview_digest)
    assert result.state is ActivationState.ACTIVE


def _disconnect(target: IntegrationTarget, home: Path) -> RemovalOutcome:
    preview = preview_removal(target, codex_home=home)
    result = apply_removal(target, codex_home=home, approved_digest=preview.preview_digest)
    return result.outcome


def _config(home: Path) -> dict[str, object]:
    path = home / "config.toml"
    return tomllib.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _binding(home: Path) -> str | None:
    marketplaces = cast(dict[str, object], _config(home).get("marketplaces", {}))
    entry = marketplaces.get("yoetz")
    if not isinstance(entry, dict):
        return None
    source = cast(dict[str, object], entry).get("source")
    return source if isinstance(source, str) else None


def _cache(home: Path) -> Path:
    return home / f"plugins/cache/yoetz/yoetz/{__version__}"


def test_second_project_connects_to_a_home_connected_for_another(tmp_path: Path) -> None:
    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    _connect(target_a, home)

    _connect(target_b, home)

    assert inspect_activation(target_a, codex_home=home).state is ActivationState.ACTIVE
    assert inspect_activation(target_b, codex_home=home).state is ActivationState.ACTIVE
    # One shared binding and enable table; B adds only its own manifest and the record entry.
    assert _binding(home) == str(root_a)
    raw = (home / "config.toml").read_text(encoding="utf-8")
    assert raw.count("[marketplaces.yoetz]") == 1
    assert raw.count('[plugins."yoetz@yoetz"]') == 1
    assert (root_b / ".agents/plugins/marketplace.json").is_file()
    assert connected_projects(home) == tuple(sorted((str(root_a), str(root_b))))
    assert (home / CONNECTED_PROJECTS_FILE).stat().st_mode & 0o777 == 0o600


def test_reconnecting_a_connected_project_changes_nothing(tmp_path: Path) -> None:
    home = _home(tmp_path)
    target_a, _root_a = _project(tmp_path, "a")
    target_b, _root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    _connect(target_b, home)
    config = (home / "config.toml").read_bytes()
    record = (home / CONNECTED_PROJECTS_FILE).read_bytes()

    _connect(target_b, home)
    _connect(target_a, home)

    assert (home / "config.toml").read_bytes() == config
    assert (home / CONNECTED_PROJECTS_FILE).read_bytes() == record


def test_unconnected_project_is_not_reported_connected_by_the_shared_plugin(
    tmp_path: Path,
) -> None:
    home = _home(tmp_path)
    target_a, _root_a = _project(tmp_path, "a")
    target_c, _root_c = _project(tmp_path, "c")
    _connect(target_a, home)
    # C carries Yoetz's committed plugin source and manifest but never ran setup here.
    _install(target_c)
    from yoetz.adapters.integrations.codex_marketplace import (
        _canonical_marketplace_bytes,  # pyright: ignore[reportPrivateUsage]
    )

    (Path(target_c.project_root) / ".agents/plugins/marketplace.json").write_bytes(
        _canonical_marketplace_bytes()
    )

    inspection = inspect_activation(target_c, codex_home=home)

    assert inspection.state is ActivationState.INSTALLED_NOT_ACTIVATED
    assert inspection.marketplace_registered is False


def test_disconnecting_the_first_project_keeps_the_second(tmp_path: Path) -> None:
    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    _connect(target_b, home)

    preview = preview_removal(target_a, codex_home=home)
    assert preview.outcome is RemovalOutcome.DETACH
    assert preview.shared_with == (str(root_b),)
    assert preview.rebind_to == str(root_b)
    assert preview.plugin_remove_planned is False
    assert preview.marketplace_remove_planned is False
    assert preview.cache_versions == ()
    result = apply_removal(target_a, codex_home=home, approved_digest=preview.preview_digest)

    assert result.outcome is RemovalOutcome.DETACH
    assert inspect_activation(target_b, codex_home=home).state is ActivationState.ACTIVE
    assert inspect_activation(target_a, codex_home=home).state is not ActivationState.ACTIVE
    assert _binding(home) == str(root_b)
    assert '[plugins."yoetz@yoetz"]' in (home / "config.toml").read_text(encoding="utf-8")
    assert _cache(home).is_dir()
    assert not (root_a / ".agents/plugins/marketplace.json").exists()
    assert connected_projects(home) == (str(root_b),)


def test_disconnecting_a_sharing_project_leaves_the_binding_alone(tmp_path: Path) -> None:
    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    _connect(target_b, home)
    config = (home / "config.toml").read_bytes()

    preview = preview_removal(target_b, codex_home=home)
    assert preview.outcome is RemovalOutcome.DETACH
    assert preview.rebind_to is None
    assert _disconnect(target_b, home) is RemovalOutcome.DETACH

    assert (home / "config.toml").read_bytes() == config
    assert inspect_activation(target_a, codex_home=home).state is ActivationState.ACTIVE
    assert not (root_b / ".agents/plugins/marketplace.json").exists()
    assert connected_projects(home) == (str(root_a),)


def test_disconnecting_the_last_project_removes_the_shared_pieces(tmp_path: Path) -> None:
    home = _home(tmp_path)
    target_a, _root_a = _project(tmp_path, "a")
    target_b, _root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    _connect(target_b, home)
    assert _disconnect(target_a, home) is RemovalOutcome.DETACH

    assert preview_removal(target_b, codex_home=home).outcome is RemovalOutcome.REMOVE
    assert _disconnect(target_b, home) is RemovalOutcome.REMOVE

    config = _config(home)
    assert "yoetz" not in config.get("marketplaces", {})  # type: ignore[operator]
    assert "yoetz@yoetz" not in config.get("plugins", {})  # type: ignore[operator]
    assert not _cache(home).exists()
    assert not (home / CONNECTED_PROJECTS_FILE).exists()
    assert connected_projects(home) == ()
    assert preview_removal(target_b, codex_home=home).outcome is RemovalOutcome.ALREADY_ABSENT


def test_a_deleted_project_does_not_hold_the_shared_pieces(tmp_path: Path) -> None:
    home = _home(tmp_path)
    target_a, _root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    _connect(target_b, home)
    for path in sorted(root_b.rglob("*"), reverse=True):
        path.unlink() if path.is_file() else path.rmdir()
    root_b.rmdir()

    assert preview_removal(target_a, codex_home=home).outcome is RemovalOutcome.REMOVE


def test_home_connected_before_the_record_existed_keeps_its_first_project(
    tmp_path: Path,
) -> None:
    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    # A home connected by an earlier release carries the binding but no record.
    (home / CONNECTED_PROJECTS_FILE).unlink()
    assert inspect_activation(target_a, codex_home=home).state is ActivationState.ACTIVE

    _connect(target_b, home)

    assert connected_projects(home) == tuple(sorted((str(root_a), str(root_b))))
    assert inspect_activation(target_a, codex_home=home).state is ActivationState.ACTIVE
    assert _disconnect(target_a, home) is RemovalOutcome.DETACH
    assert inspect_activation(target_b, codex_home=home).state is ActivationState.ACTIVE


def test_binding_to_a_vanished_project_is_moved_to_the_connecting_one(tmp_path: Path) -> None:
    home = _home(tmp_path)
    target_b, root_b = _project(tmp_path, "b")
    _install(target_b)
    gone = tmp_path / "gone"
    (home / "config.toml").write_text(
        f'[marketplaces.yoetz]\nsource_type = "local"\nsource = "{gone}"\n\n'
        '[plugins."yoetz@yoetz"]\nenabled = true\n',
        encoding="utf-8",
    )

    _connect(target_b, home)

    assert _binding(home) == str(root_b)
    assert (home / "config.toml").read_text(encoding="utf-8").count("[marketplaces.yoetz]") == 1


def test_same_project_under_a_symlinked_path_is_refused(tmp_path: Path) -> None:
    home = _home(tmp_path)
    target, root = _project(tmp_path, "real")
    _connect(target, home)
    # The project moved; its old path is now a symlink to the new one and the home's binding
    # and record still name the old path.
    moved = tmp_path / "moved"
    root.rename(moved)
    root.symlink_to(moved, target_is_directory=True)
    moved_target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(moved))

    with pytest.raises(IntegrationError) as caught:
        preview_activation(moved_target, codex_home=home)

    assert caught.value.reason is IntegrationReason.PROJECT_CONNECTED_VIA_OTHER_PATH
    assert project_registered_elsewhere(home, moved) == str(root)

    # The way out the refusal names: disconnecting this project clears the old-path entry.
    assert _disconnect(moved_target, home) is RemovalOutcome.REMOVE
    assert _binding(home) is None
    assert connected_projects(home) == ()
    _connect(moved_target, home)
    assert _binding(home) == str(moved)


def test_disconnecting_an_aliased_project_keeps_the_other_projects(tmp_path: Path) -> None:
    home = _home(tmp_path)
    target, root = _project(tmp_path, "real")
    target_b, root_b = _project(tmp_path, "b")
    _connect(target, home)
    _connect(target_b, home)
    moved = tmp_path / "moved"
    root.rename(moved)
    root.symlink_to(moved, target_is_directory=True)
    moved_target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(moved))

    assert _disconnect(moved_target, home) is RemovalOutcome.DETACH

    assert _binding(home) == str(root_b)
    assert connected_projects(home) == (str(root_b),)
    assert inspect_activation(target_b, codex_home=home).state is ActivationState.ACTIVE


def test_record_alias_of_the_same_directory_is_refused_without_a_binding(
    tmp_path: Path,
) -> None:
    home = _home(tmp_path)
    target, root = _project(tmp_path, "real")
    _install(target)
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)
    (home / CONNECTED_PROJECTS_FILE).write_text(f'{{"projects":["{alias}"]}}\n')
    (home / CONNECTED_PROJECTS_FILE).chmod(0o600)

    with pytest.raises(IntegrationError) as caught:
        preview_activation(target, codex_home=home)

    assert caught.value.reason is IntegrationReason.PROJECT_CONNECTED_VIA_OTHER_PATH


def test_case_variant_of_a_connected_project_is_refused(tmp_path: Path) -> None:
    home = _home(tmp_path)
    target, root = _project(tmp_path, "proj")
    variant = root.with_name("PROJ")
    if not os.path.exists(variant):
        pytest.skip("case-sensitive file system: case variants are different directories")
    _connect(target, home)
    variant_target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(variant))

    with pytest.raises(IntegrationError) as caught:
        preview_activation(variant_target, codex_home=home)

    assert caught.value.reason is IntegrationReason.PROJECT_CONNECTED_VIA_OTHER_PATH


def test_malformed_record_is_refused_not_overwritten(tmp_path: Path) -> None:
    home = _home(tmp_path)
    target, _root = _project(tmp_path, "a")
    _install(target)
    record = home / CONNECTED_PROJECTS_FILE
    record.write_text('{"projects": "not-a-list"}\n')
    record.chmod(0o600)

    with pytest.raises(IntegrationError) as caught:
        preview_activation(target, codex_home=home)

    assert caught.value.reason is IntegrationReason.SOURCE_INVALID
    assert record.read_text() == '{"projects": "not-a-list"}\n'
    assert inspect_activation(target, codex_home=home).state is ActivationState.FOREIGN
