"""One Codex home serves several FinishUP-connected projects (issue #1058).

Codex keeps the FinishUP plugin, its cache, its enable table, and the ``[marketplaces.finishup]``
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
from typing import Any, Literal, cast

import pytest
from tests.unit.adapters.test_codex_marketplace import (
    _install,  # pyright: ignore[reportPrivateUsage]
    apply_activation,
    apply_removal,
    inspect_activation,
    preview_activation,
    preview_removal,
)

from finishup import __version__
from finishup.adapters.integrations.codex_marketplace import (
    ActivationState,
    RemovalOutcome,
    connected_projects,
    possible_projects,
    project_registered_elsewhere,
)
from finishup.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE
from finishup.ports.integrations import (
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
    entry = marketplaces.get("finishup")
    if not isinstance(entry, dict):
        return None
    source = cast(dict[str, object], entry).get("source")
    return source if isinstance(source, str) else None


def _cache(home: Path) -> Path:
    return home / f"plugins/cache/finishup/finishup/{__version__}"


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
    assert raw.count("[marketplaces.finishup]") == 1
    assert raw.count('[plugins."finishup@finishup"]') == 1
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
    # C carries FinishUP's committed plugin source and manifest but never ran setup here.
    _install(target_c)
    from finishup.adapters.integrations.codex_marketplace import (
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
    assert '[plugins."finishup@finishup"]' in (home / "config.toml").read_text(encoding="utf-8")
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
    assert "finishup" not in config.get("marketplaces", {})  # type: ignore[operator]
    assert "finishup@finishup" not in config.get("plugins", {})  # type: ignore[operator]
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
        f'[marketplaces.finishup]\nsource_type = "local"\nsource = "{gone}"\n\n'
        '[plugins."finishup@finishup"]\nenabled = true\n',
        encoding="utf-8",
    )

    _connect(target_b, home)

    assert _binding(home) == str(root_b)
    assert (home / "config.toml").read_text(encoding="utf-8").count("[marketplaces.finishup]") == 1


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


def _trust(home: Path, *rows: tuple[Path, str]) -> None:
    with (home / "config.toml").open("a", encoding="utf-8") as handle:
        for root, level in rows:
            handle.write(f'\n[projects."{root}"]\ntrust_level = "{level}"\n')


def _clone(tmp_path: Path, name: str) -> tuple[IntegrationTarget, Path]:
    """A checkout carrying FinishUP's committed plugin files that never ran setup here."""

    from finishup.adapters.integrations.codex_marketplace import (
        _canonical_marketplace_bytes,  # pyright: ignore[reportPrivateUsage]
    )

    target, root = _project(tmp_path, name)
    _install(target, codex_version=None)
    (root / ".agents/plugins/marketplace.json").write_bytes(_canonical_marketplace_bytes())
    return target, root


def test_lost_record_with_only_unverified_users_refuses_and_reconnect_records_them(
    tmp_path: Path,
) -> None:
    """A lost record is not proof this is the last project, nor that a checkout connected."""

    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    _connect(target_b, home)
    (home / CONNECTED_PROJECTS_FILE).unlink()
    _trust(home, (root_a, "trusted"), (root_b, "trusted"))
    assert possible_projects(home) == (str(root_b),)

    with pytest.raises(IntegrationError) as caught:
        preview_removal(target_a, codex_home=home)
    assert caught.value.reason is IntegrationReason.REMOVE_REFUSED
    assert caught.value.safe_details.get("conflict") == "membership_unverified"

    # The recovery the refusal names: connecting B again records it as a verified member.
    _connect(target_b, home)
    assert set(connected_projects(home)) == {str(root_a), str(root_b)}
    assert _disconnect(target_a, home) is RemovalOutcome.DETACH
    assert _binding(home) == str(root_b)
    assert inspect_activation(target_b, codex_home=home).state is ActivationState.ACTIVE


def test_never_connected_clone_is_not_an_anchor_and_removing_it_keeps_b(tmp_path: Path) -> None:
    """CHECK_MULTIPROJ_R2 P2-R2-1: a trusted clone sorting first must not take the binding."""

    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "m-a")
    target_b, root_b = _project(tmp_path, "m-b")
    _connect(target_a, home)
    (home / CONNECTED_PROJECTS_FILE).unlink()  # an earlier single-project release
    _clone_target, root_f = _clone(tmp_path, "a-clone")
    _trust(home, (root_f, "trusted"))
    _connect(target_b, home)
    assert set(connected_projects(home)) == {str(root_a), str(root_b)}
    assert possible_projects(home) == (str(root_f),)

    preview = preview_removal(target_a, codex_home=home)
    assert preview.outcome is RemovalOutcome.DETACH
    assert preview.rebind_to == str(root_b)
    assert preview.possible_users == (str(root_f),)
    # `integrate codex plugin preview` shows them too (#1058 review P3).
    from finishup.cli.codex_plugin import _preview_body  # pyright: ignore[reportPrivateUsage]

    body = _preview_body(preview)
    assert body["possible_users"] == [str(root_f)] and body["membership_unknown"] is True
    assert _disconnect(target_a, home) is RemovalOutcome.DETACH
    assert _binding(home) == str(root_b)

    import shutil

    shutil.rmtree(root_f)
    assert inspect_activation(target_b, codex_home=home).state is ActivationState.ACTIVE


def test_untrusted_rows_and_invalid_descriptors_are_not_possible_users(tmp_path: Path) -> None:
    home = _home(tmp_path)
    target_a, _root_a = _project(tmp_path, "a")
    _connect(target_a, home)
    (home / CONNECTED_PROJECTS_FILE).unlink()
    _target_u, root_u = _clone(tmp_path, "untrusted")
    _target_i, root_i = _clone(tmp_path, "invalid")
    descriptor = next((root_i / ".agents/plugins/finishup").rglob("plugin.json"))
    descriptor.write_text("{not json")
    _trust(home, (root_u, "untrusted"), (root_i, "trusted"))

    assert possible_projects(home) == ()
    # With no verified or possible user left, the last disconnect removes the shared pieces.
    assert _disconnect(target_a, home) is RemovalOutcome.REMOVE


def test_trust_row_naming_a_verified_member_another_way_is_not_a_possible_user(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """On a case-insensitive filesystem Codex's trust row may spell a member's path differently.

    That row is the verified member itself, so it must neither be listed as a possible user nor
    keep membership unknown after every project was reconnected (#1058).
    """

    from finishup.adapters.integrations import codex_marketplace
    from finishup.adapters.integrations.host_projects import (
        encode_projects,
        load_connected_projects,
    )

    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    _connect(target_b, home)
    record = home / CONNECTED_PROJECTS_FILE
    record.write_bytes(encode_projects((str(root_a), str(root_b)), unknown_members=True))
    record.chmod(0o600)
    # Stand-in for a letter-case spelling of B: Linux test filesystems are case-sensitive.
    _alias_target, alias = _clone(tmp_path, "B-spelled")
    _trust(home, (root_a, "trusted"), (root_b, "trusted"), (alias, "trusted"))
    real = codex_marketplace.same_directory

    def same(left: Path, right: Path) -> bool:
        if {str(left), str(right)} == {str(alias), str(root_b)}:
            return True
        return real(left, right)

    monkeypatch.setattr(codex_marketplace, "same_directory", same)

    assert possible_projects(home) == ()
    preview = preview_removal(target_a, codex_home=home)
    assert preview.outcome is RemovalOutcome.DETACH and preview.possible_users == ()
    assert _disconnect(target_a, home) is RemovalOutcome.DETACH
    after = load_connected_projects(home)
    assert after.projects == (str(root_b),) and after.unknown_members is False


def _remove(
    target: IntegrationTarget, home: Path, *, remove_shared: bool = False
) -> RemovalOutcome:
    from tests.unit.adapters.test_codex_marketplace import (
        _FakeCodex,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.adapters.integrations.codex_marketplace import (
        apply_removal as raw_apply,
    )
    from finishup.adapters.integrations.codex_marketplace import (
        preview_removal as raw_preview,
    )

    runner = _FakeCodex(target, home)
    preview = raw_preview(
        target,
        executable_path=str(runner.executable),
        codex_home=home,
        remove_shared=remove_shared,
        _run=runner,
    )
    return raw_apply(
        target,
        executable_path=str(runner.executable),
        approved_digest=preview.preview_digest,
        codex_home=home,
        remove_shared=remove_shared,
        _run=runner,
    ).outcome


def _shared_gone(home: Path) -> None:
    config = _config(home)
    assert "finishup" not in cast(dict[str, object], config.get("marketplaces", {}))
    assert "finishup@finishup" not in cast(dict[str, object], config.get("plugins", {}))
    assert not _cache(home).exists()
    assert not (home / CONNECTED_PROJECTS_FILE).exists()


@pytest.mark.parametrize("remove_shared", [False, True])
def test_after_the_anchor_is_deleted_the_last_member_can_still_disconnect(
    tmp_path: Path, remove_shared: bool
) -> None:
    """#1058 review P2-2: a dangling binding no longer blocks the remaining member's disconnect."""

    import shutil

    from finishup.adapters.integrations.codex_marketplace import serving_projects

    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    _connect(target_b, home)
    assert _binding(home) == str(root_a)
    shutil.rmtree(root_a)
    # The deleted anchor is not reported as a connected project.
    assert serving_projects(home) == (str(root_b),)

    assert _remove(target_b, home, remove_shared=remove_shared) is RemovalOutcome.REMOVE
    _shared_gone(home)
    assert not (root_b / ".agents/plugins/marketplace.json").exists()


def test_an_anchor_without_its_manifest_hands_the_binding_to_a_remaining_member(
    tmp_path: Path,
) -> None:
    """#1058 review P2-2: e.g. `git clean` removed the anchor's marketplace.json."""

    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_b, _root_b = _project(tmp_path, "b")
    target_c, root_c = _project(tmp_path, "c")
    for target in (target_a, target_b, target_c):
        _connect(target, home)
    (root_a / ".agents/plugins/marketplace.json").unlink()

    preview = preview_removal(target_b, codex_home=home)
    assert preview.outcome is RemovalOutcome.DETACH
    assert preview.rebind_to == str(root_c)
    assert str(root_a) not in preview.shared_with
    assert _disconnect(target_b, home) is RemovalOutcome.DETACH
    assert _binding(home) == str(root_c)
    assert inspect_activation(target_c, codex_home=home).state is ActivationState.ACTIVE


def test_a_deleted_record_still_keeps_the_projects_this_installation_connected(
    tmp_path: Path,
) -> None:
    """#1058 review P2-4: deleting the record (as the old advice said) never silently removes
    what another connected project uses, even when Codex does not trust that project."""

    home = _home(tmp_path)
    target_a, _root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    _connect(target_b, home)
    (home / CONNECTED_PROJECTS_FILE).unlink()
    # No `[projects."<path>"]` trust rows at all: only FinishUP's own witness remembers B.
    assert "projects" not in _config(home)
    assert possible_projects(home) == (str(root_b),)

    with pytest.raises(IntegrationError) as caught:
        preview_removal(target_a, codex_home=home)
    assert caught.value.reason is IntegrationReason.REMOVE_REFUSED
    assert caught.value.safe_details.get("conflict") == "membership_unverified"

    # Reconnecting B records it; then A detaches and B keeps the shared pieces.
    _connect(target_b, home)
    assert _disconnect(target_a, home) is RemovalOutcome.DETACH
    assert _binding(home) == str(root_b)
    assert inspect_activation(target_b, codex_home=home).state is ActivationState.ACTIVE
    # The last disconnect removes everything and forgets the witness.
    assert _disconnect(target_b, home) is RemovalOutcome.REMOVE
    assert possible_projects(home) == ()


def test_a_review_mode_change_names_the_other_connected_projects(tmp_path: Path) -> None:
    """#1058 review P2-3: `[mcp_servers.finishup]` is user-level, shared by the whole home;
    round 2: projects that may use it (possible users) are named too."""

    import anyio

    from finishup.ports.harness_mcp import (
        McpRegistrationAction,
        McpRegistrationObservation,
        McpRegistrationPreview,
        McpRegistrationState,
    )
    from finishup.ports.integrations import HarnessId
    from finishup.tui import runtime

    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    _target_c, root_c = _project(tmp_path, "c")
    _connect(target_a, home)

    class Service:
        def __init__(self, route: str | None) -> None:
            self.route = route

        async def observe(self, _binary: object) -> McpRegistrationObservation:
            return McpRegistrationObservation(
                HarnessId.CODEX,
                McpRegistrationState.FINISHUP_OWNED,
                cast(Literal["policy", "strict"] | None, self.route),
                isolation_binding="ambient",
            )

    preview = McpRegistrationPreview(
        HarnessId.CODEX,
        McpRegistrationAction.REREGISTER,
        McpRegistrationState.FINISHUP_OWNED,
        (),
        "sha256:" + "a" * 64,
    )

    async def change(route: str | None, project: Path) -> object:
        return await runtime._shared_route_change(  # pyright: ignore[reportPrivateUsage]
            cast(Any, Service(route)), cast(Any, None), preview, "policy", home, project
        )

    assert anyio.run(change, "strict", root_b) == ("strict", (str(root_a),), ())
    # Same review mode, or connecting the only project: nothing to disclose for others.
    assert anyio.run(change, "policy", root_b) == (None, (), ())
    assert anyio.run(change, "strict", root_a) == (None, (), ())
    # After the record is lost, B is only a possible user, and is still named.
    _connect(target_b, home)
    (home / CONNECTED_PROJECTS_FILE).unlink()
    assert anyio.run(change, "strict", root_c) == ("strict", (str(root_a),), (str(root_b),))


def test_a_project_that_never_connected_cannot_remove_a_dangling_binding(
    tmp_path: Path,
) -> None:
    """#1058 review round 2 P3: A's manifest is only absent for now (branch switch, git clean,
    unmounted volume); disconnecting never-connected C must not remove A's shared pieces."""

    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_c, _root_c = _clone(tmp_path, "c")
    _connect(target_a, home)
    manifest = root_a / ".agents/plugins/marketplace.json"
    saved = manifest.read_bytes()
    manifest.unlink()
    config_before = (home / "config.toml").read_bytes()

    outcome = _remove(target_c, home)

    assert outcome in {RemovalOutcome.DETACH, RemovalOutcome.ALREADY_ABSENT}
    assert (home / "config.toml").read_bytes() == config_before
    assert _cache(home).exists()
    assert connected_projects(home) == (str(root_a),)
    # A comes back and is still connected.
    manifest.write_bytes(saved)
    assert inspect_activation(target_a, codex_home=home).state is ActivationState.ACTIVE


def test_removing_a_dangling_binding_names_members_without_their_plugin_files(
    tmp_path: Path,
) -> None:
    """#1058 review round 2 P3: B (a member) is the last serving project; A's directory exists
    but lost its manifest. B's disconnect removes the shared pieces and says A loses them."""

    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_b, _root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    _connect(target_b, home)
    (root_a / ".agents/plugins/marketplace.json").unlink()

    preview = preview_removal(target_b, codex_home=home)

    assert preview.outcome is RemovalOutcome.REMOVE
    assert preview.unserved_members == (str(root_a),)
    assert _disconnect(target_b, home) is RemovalOutcome.REMOVE
    _shared_gone(home)


@pytest.mark.parametrize("who", ["detached", "never-connected"])
def test_a_rerun_or_outsider_disconnect_keeps_pieces_for_a_member_without_its_files(
    tmp_path: Path, who: str
) -> None:
    """#1058 review round 3 T1: the removal plan itself reports that it keeps the shared pieces."""

    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_b, _root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    if who == "detached":
        _connect(target_b, home)
        assert _disconnect(target_b, home) is RemovalOutcome.DETACH
        target = target_b
    else:
        target, _root_c = _clone(tmp_path, "c")
    (root_a / ".agents/plugins/marketplace.json").unlink()
    config_before = (home / "config.toml").read_bytes()

    preview = preview_removal(target, codex_home=home)

    assert preview.keeps_shared is True
    assert preview.unserved_members == (str(root_a),)
    from finishup.cli.codex_plugin import _preview_body  # pyright: ignore[reportPrivateUsage]

    # `integrate codex plugin preview` names them too (bound into the digest).
    body = _preview_body(preview)
    assert body["members_not_serving"] == [str(root_a)] and body["keeps_shared"] is True
    _disconnect(target, home)
    assert (home / "config.toml").read_bytes() == config_before
    assert _cache(home).exists()
    assert connected_projects(home) == (str(root_a),)


def test_without_a_binding_a_member_detaches_and_keeps_the_others_pieces(
    tmp_path: Path,
) -> None:
    """#1058 review round 3 P3: the binding table was removed by hand; B's disconnect must not
    remove the plugin table, cache and record A still uses."""

    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_b, _root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    _connect(target_b, home)
    config = home / "config.toml"
    text = config.read_text(encoding="utf-8")
    table = f'[marketplaces.finishup]\nsource_type = "local"\nsource = "{root_a}"\n'
    assert table in text
    config.write_text(text.replace(table, ""), encoding="utf-8")

    preview = preview_removal(target_b, codex_home=home)

    assert preview.outcome is RemovalOutcome.DETACH and preview.keeps_shared is True
    assert _disconnect(target_b, home) is RemovalOutcome.DETACH
    assert '[plugins."finishup@finishup"]' in config.read_text(encoding="utf-8")
    assert _cache(home).exists()
    assert connected_projects(home) == (str(root_a),)


def test_a_never_connected_disconnect_names_a_member_whose_directory_is_missing(
    tmp_path: Path,
) -> None:
    """#1058 triage: only A connected and its directory moved away (an unmounted volume).

    C's disconnect keeps the shared pieces for A's dangling binding; the plan names A as a
    project whose directory is missing right now, so the kept pieces have an owner.
    """

    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    _connect(target_a, home)
    root_a.rename(tmp_path / "a-away")
    target_c, _root_c = _clone(tmp_path, "c")
    config_before = (home / "config.toml").read_bytes()

    preview = preview_removal(target_c, codex_home=home)

    assert preview.keeps_shared is True
    assert preview.missing_members == (str(root_a),)
    assert preview.unserved_members == ()
    _disconnect(target_c, home)
    assert (home / "config.toml").read_bytes() == config_before
    assert _cache(home).exists()


def test_a_yoetz_era_project_detaches_its_own_legacy_activation_only(tmp_path: Path) -> None:
    """ADR-048 x #1058: B's Yoetz 0.2 activation is B's own, not a shared piece. Disconnecting B
    while A uses the home's FinishUP pieces deactivates B's legacy tables, document and cache
    in the same detach and leaves A's binding, plugin, cache and record alone."""

    from tests.unit.adapters.test_codex_marketplace import (
        _legacy_tables,  # pyright: ignore[reportPrivateUsage]
        _write_legacy_activation,  # pyright: ignore[reportPrivateUsage]
    )

    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    shared = (home / "config.toml").read_text(encoding="utf-8")
    legacy_cache = _write_legacy_activation(root_b, home)
    (home / "config.toml").write_text(shared + "\n" + _legacy_tables(root_b), encoding="utf-8")

    assert inspect_activation(target_b, codex_home=home).legacy_activation is True
    preview = preview_removal(target_b, codex_home=home)
    assert preview.outcome is RemovalOutcome.DETACH
    assert preview.keeps_shared is True
    assert preview.shared_with == (str(root_a),)
    assert preview.legacy_removed_block == _legacy_tables(root_b)
    assert preview.legacy_cache_versions == ("0.2.5",)
    assert preview.legacy_marketplace_json_planned is True

    result = apply_removal(target_b, codex_home=home, approved_digest=preview.preview_digest)

    assert result.outcome is RemovalOutcome.DETACH
    assert result.inspection.legacy_activation is False
    assert (home / "config.toml").read_text(encoding="utf-8").rstrip("\n") == shared.rstrip("\n")
    assert not (root_b / ".agents/plugins/marketplace.json").exists()
    assert not legacy_cache.exists()
    assert _binding(home) == str(root_a)
    assert _cache(home).is_dir()
    assert connected_projects(home) == (str(root_a),)
    assert inspect_activation(target_a, codex_home=home).state is ActivationState.ACTIVE


def test_a_member_detach_also_strips_its_own_legacy_tables(tmp_path: Path) -> None:
    """The binding moves to B while A's exact Yoetz-era tables leave in the same config write."""

    from tests.unit.adapters.test_codex_marketplace import (
        _legacy_tables,  # pyright: ignore[reportPrivateUsage]
    )

    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    _connect(target_a, home)
    _connect(target_b, home)
    config = home / "config.toml"
    config.write_text(
        config.read_text(encoding="utf-8") + "\n" + _legacy_tables(root_a), encoding="utf-8"
    )

    preview = preview_removal(target_a, codex_home=home)
    assert preview.outcome is RemovalOutcome.DETACH
    assert preview.rebind_to == str(root_b)
    assert preview.legacy_removed_block == _legacy_tables(root_a)
    apply_removal(target_a, codex_home=home, approved_digest=preview.preview_digest)

    parsed = _config(home)
    assert set(cast(dict[str, object], parsed["marketplaces"])) == {"finishup"}
    assert set(cast(dict[str, object], parsed["plugins"])) == {"finishup@finishup"}
    assert _binding(home) == str(root_b)
    assert inspect_activation(target_b, codex_home=home).state is ActivationState.ACTIVE


def test_a_yoetz_era_bound_project_is_a_member_of_the_shared_registration(
    tmp_path: Path,
) -> None:
    """ADR-048 x #1058: Yoetz 0.2 bound A with `[marketplaces.yoetz]` and registered the
    user-level server every project in the home uses, but kept no record. B's connect migrates
    that registration; A, still holding its own Yoetz-era activation, is recorded with B and
    keeps using the registration after B's disconnect. A never anchors the FinishUP binding: it
    does not serve FinishUP's manifest, so B (the anchor) removes the FinishUP plugin pieces
    nobody else can carry, and A's Yoetz-era activation stays untouched."""

    from tests.unit.adapters.test_codex_marketplace import (
        _legacy_tables,  # pyright: ignore[reportPrivateUsage]
        _write_legacy_activation,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.adapters.integrations.codex_marketplace import other_members, serving_projects
    from finishup.adapters.integrations.host_projects import load_connected_projects

    home = _home(tmp_path)
    _target_a, root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    legacy_cache = _write_legacy_activation(root_a, home)
    # Before any record exists, the project the exact legacy binding names is the home's member.
    assert connected_projects(home) == (str(root_a),)
    assert serving_projects(home) == (str(root_a),)

    _connect(target_b, home)

    record = load_connected_projects(home)
    assert record.projects == tuple(sorted((str(root_a), str(root_b))))
    assert not record.unknown_members
    assert other_members(home, root_b) == ((str(root_a),), ())
    assert _binding(home) == str(root_b)
    preview = preview_removal(target_b, codex_home=home)
    assert preview.outcome is RemovalOutcome.REMOVE
    assert preview.rebind_to is None
    # A serves its own Yoetz-era activation; it is not a member whose plugin files are missing.
    assert preview.unserved_members == ()

    result = apply_removal(target_b, codex_home=home, approved_digest=preview.preview_digest)

    assert result.outcome is RemovalOutcome.REMOVE
    assert _binding(home) is None
    assert _legacy_tables(root_a) in (home / "config.toml").read_text(encoding="utf-8")
    assert legacy_cache.is_dir()
    assert (root_a / ".agents/plugins/marketplace.json").is_file()
    # A still uses the user-level registration, so another disconnect keeps it for A.
    assert other_members(home, root_b) == ((str(root_a),), ())


def test_a_yoetz_era_project_that_lost_its_activation_is_no_member(tmp_path: Path) -> None:
    """Only a project still holding its exact Yoetz-era activation counts: an edited legacy
    table, or a project whose legacy marketplace document is gone, does not."""

    from tests.unit.adapters.test_codex_marketplace import (
        _write_legacy_activation,  # pyright: ignore[reportPrivateUsage]
    )

    home = _home(tmp_path)
    _target_a, root_a = _project(tmp_path, "a")
    _write_legacy_activation(root_a, home, cache=False)
    assert connected_projects(home) == (str(root_a),)

    (root_a / ".agents/plugins/marketplace.json").unlink()
    assert connected_projects(home) == ()

    _write_legacy_activation(root_a, home, cache=False)
    config = home / "config.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            'source_type = "local"\n', 'source_type = "local"\n# edited\n'
        ),
        encoding="utf-8",
    )
    assert connected_projects(home) == ()


def test_an_upgraded_yoetz_era_home_keeps_a_trusted_checkout_uncertain(tmp_path: Path) -> None:
    """ADR-012's earlier-release rule for the real earlier release: shared pieces found without a
    record make membership uncertain, so a trusted checkout serving FinishUP's manifest is a
    possible user, the migrating connect records `unknown_members`, and A's removal, with no
    verified member to carry the binding, refuses as `membership_unverified`."""

    from tests.unit.adapters.test_codex_marketplace import (
        _write_legacy_activation,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.adapters.integrations.host_projects import load_connected_projects

    home = _home(tmp_path)
    target_a, root_a = _project(tmp_path, "a")
    _install(target_a)
    _write_legacy_activation(root_a, home, cache=False)
    _clone_target, root_c = _clone(tmp_path, "c")
    _trust(home, (root_c, "trusted"))
    # Status already says so before anything is recorded.
    assert possible_projects(home) == (str(root_c),)

    _connect(target_a, home)

    record = load_connected_projects(home)
    assert record.projects == (str(root_a),)
    assert record.unknown_members
    with pytest.raises(IntegrationError) as caught:
        preview_removal(target_a, codex_home=home)
    assert caught.value.reason is IntegrationReason.REMOVE_REFUSED
    assert caught.value.safe_details.get("conflict") == "membership_unverified"


def test_an_owned_yoetz_era_registration_without_a_record_is_uncertain(tmp_path: Path) -> None:
    """A Yoetz 0.2 home with only its user-level `[mcp_servers.yoetz]` registration (every
    project in the home uses it) is uncertain too, the same as legacy tables."""

    from finishup.adapters.integrations.host_projects import load_connected_projects

    home = _home(tmp_path)
    target_b, _root_b = _project(tmp_path, "b")
    (home / "config.toml").write_text(
        '[mcp_servers.yoetz]\ncommand = "yoetz"\nargs = ["mcp", "serve", "--host", "codex"]\n',
        encoding="utf-8",
    )
    _clone_target, root_c = _clone(tmp_path, "c")
    _trust(home, (root_c, "trusted"))
    assert possible_projects(home) == (str(root_c),)

    _connect(target_b, home)

    assert load_connected_projects(home).unknown_members

