"""Focused tests for Cursor's explicit project-scoped MCP registration."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from finishup.adapters.integrations.cursor_project_mcp import (
    CursorProjectMcpError,
    CursorProjectMcpTarget,
    apply_cursor_project_mcp,
    preview_cursor_project_mcp,
    status_cursor_project_mcp,
)

LAUNCHER = ("/opt/finishup-test/bin/finishup", "--runtime")
OTHER_LAUNCHER = ("/opt/other-finishup/bin/finishup", "--runtime")


def _secure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _target(tmp_path: Path) -> CursorProjectMcpTarget:
    return CursorProjectMcpTarget(
        _secure_directory(tmp_path / "project"),
        _secure_directory(tmp_path / "cursor-config"),
    )


def _isolation_root(tmp_path: Path, name: str = "isolated") -> str:
    return str(_secure_directory(tmp_path / name))


def _project_config(target: CursorProjectMcpTarget) -> Path:
    return target.project_root / ".cursor" / "mcp.json"


def _user_config(target: CursorProjectMcpTarget) -> Path:
    return target.cursor_config_root / "mcp.json"


def _plugin_config(target: CursorProjectMcpTarget) -> Path:
    return target.cursor_config_root / "plugins" / "local" / "finishup" / "mcp.json"


def _write_json(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _entry(
    launcher: tuple[str, ...] = LAUNCHER,
    *,
    route: str = "policy",
    isolation_root: str | None = None,
    project_root: Path | None = None,
) -> dict[str, Any]:
    args = [
        *launcher[1:],
        "mcp",
        "serve",
        "--host",
        "cursor",
        "--project-root",
        "${workspaceFolder}" if project_root is None else str(project_root),
    ]
    if route == "strict":
        args.extend(("--semantic", "off"))
    result: dict[str, Any] = {
        "type": "stdio",
        "command": launcher[0],
        "args": args,
    }
    if isolation_root is not None:
        # Both spellings with one value while the deprecated alias ships (ADR-048).
        result["env"] = {
            "FINISHUP_ISOLATED_ROOT": isolation_root,
            "YOETZ_ISOLATED_ROOT": isolation_root,
        }
    return result


def _legacy_entry(
    launcher: tuple[str, ...] = LAUNCHER,
    *,
    route: str = "policy",
    isolation_root: str | None = None,
) -> dict[str, Any]:
    result = _entry(launcher, route=route, isolation_root=isolation_root)
    result["args"] = [*launcher[1:], "mcp", "serve", "--host", "cursor"]
    if route == "strict":
        result["args"].extend(("--semantic", "off"))
    return result


def _install(
    target: CursorProjectMcpTarget,
    *,
    launcher: tuple[str, ...] = LAUNCHER,
    route_profile: str | None = "policy",
    isolation_root: str | None = None,
) -> dict[str, Any]:
    preview = preview_cursor_project_mcp(
        target,
        action="install",
        launcher=launcher,
        route_profile=route_profile,  # type: ignore[arg-type]
        isolation_root=isolation_root,
    )
    return apply_cursor_project_mcp(
        target,
        action="install",
        launcher=launcher,
        route_profile=route_profile,  # type: ignore[arg-type]
        isolation_root=isolation_root,
        preview_digest=str(preview["preview_digest"]),
        accept=True,
    )


def _assert_fixed_reason(operation: Any) -> None:
    with pytest.raises(CursorProjectMcpError) as raised:
        operation()
    error = raised.value
    assert error.reason.startswith("cursor_project_mcp_")
    assert error.reason == str(error)
    assert " " not in error.reason


def test_install_preserves_unrelated_project_json_and_binds_exact_launcher_and_root(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    project = _project_config(target)
    unrelated = {
        "version": 1,
        "mcpServers": {"other": {"type": "stdio", "command": "other", "args": ["--keep"]}},
        "cursor": {"enabled": True, "nested": [1, "keep"]},
    }
    _write_json(project, unrelated)

    preview = preview_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile="policy",
        isolation_root=root,
    )

    assert preview["action"] == "register"
    assert preview["operation"] == "install"
    assert preview["state_before"] == "absent"
    assert preview["source"] == "none"
    assert isinstance(preview["preview_digest"], str)
    assert isinstance(preview["config_digest_before"], str)
    assert isinstance(preview["config_digest_after"], str)
    assert preview["config_digest_before"] != preview["config_digest_after"]
    assert preview["launcher"] == list(LAUNCHER)
    assert preview["isolated_root"] == root

    applied = apply_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile="policy",
        isolation_root=root,
        preview_digest=str(preview["preview_digest"]),
        accept=True,
    )

    assert applied["state_after"] == "yoetz_owned"
    document = _read_json(project)
    assert document["version"] == unrelated["version"]
    assert document["cursor"] == unrelated["cursor"]
    servers = document["mcpServers"]
    assert isinstance(servers, dict)
    unrelated_servers = unrelated["mcpServers"]
    assert isinstance(unrelated_servers, dict)
    assert servers["other"] == unrelated_servers["other"]
    assert servers["finishup"] == _entry(isolation_root=root, project_root=target.project_root)
    assert applied["config_digest_after"] == (
        "sha256:" + hashlib.sha256(project.read_bytes()).hexdigest()
    )

    status = status_cursor_project_mcp(target, launcher=LAUNCHER, isolation_root=root)
    assert status["source"] == "project"
    assert status["state"] == "yoetz_owned"
    assert status["route_profile"] == "policy"
    assert status["runtime_binding"] == "unobserved"


def test_strict_route_is_preserved_when_route_is_none_and_can_be_changed_explicitly(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    _install(target, route_profile="strict", isolation_root=root)
    project = _project_config(target)
    strict_bytes = project.read_bytes()

    preserved = preview_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile=None,
        isolation_root=root,
    )
    assert preserved["action"] == "noop"
    assert preserved["state_before"] == "yoetz_owned"
    assert preserved["route_profile"] == "strict"

    applied = apply_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile=None,
        isolation_root=root,
        preview_digest=str(preserved["preview_digest"]),
        accept=True,
    )
    assert applied["state_after"] == "yoetz_owned"
    assert project.read_bytes() == strict_bytes

    changed = preview_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile="policy",
        isolation_root=root,
    )
    assert changed["action"] == "reregister"
    assert changed["state_before"] == "yoetz_owned"
    _ = apply_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile="policy",
        isolation_root=root,
        preview_digest=str(changed["preview_digest"]),
        accept=True,
    )
    assert _read_json(project)["mcpServers"]["finishup"] == _entry(
        isolation_root=root, project_root=target.project_root
    )


def test_legacy_project_entry_is_owned_for_upgrade_and_emits_the_selector(tmp_path: Path) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    project = _project_config(target)
    _write_json(project, {"mcpServers": {"finishup": _legacy_entry(isolation_root=root)}})

    status = status_cursor_project_mcp(target, launcher=LAUNCHER, isolation_root=root)
    assert status["source"] == "project"
    assert status["state"] == "yoetz_owned"
    assert status["route_profile"] == "policy"

    preview = preview_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile=None,
        isolation_root=root,
    )
    assert preview["action"] == "reregister"
    assert preview["route_profile"] == "policy"
    applied = apply_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile=None,
        isolation_root=root,
        preview_digest=str(preview["preview_digest"]),
        accept=True,
    )
    assert applied["state_after"] == "yoetz_owned"
    assert _read_json(project)["mcpServers"]["finishup"] == _entry(
        isolation_root=root, project_root=target.project_root
    )


def test_changed_launcher_or_isolation_root_is_not_treated_as_owned(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path, "first-root")
    other_root = _isolation_root(tmp_path, "second-root")
    _install(target, isolation_root=root)

    status = status_cursor_project_mcp(
        target,
        launcher=OTHER_LAUNCHER,
        isolation_root=other_root,
    )
    assert status["source"] == "project"
    assert status["state"] == "foreign_present"

    _assert_fixed_reason(
        lambda: preview_cursor_project_mcp(
            target,
            action="install",
            launcher=OTHER_LAUNCHER,
            route_profile="policy",
            isolation_root=other_root,
        )
    )


def test_remove_unregisters_only_finishup_and_repeating_remove_is_noop(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    _install(target, isolation_root=root)
    project = _project_config(target)
    document = _read_json(project)

    remove = preview_cursor_project_mcp(
        target,
        action="remove",
        launcher=LAUNCHER,
        route_profile=None,
        isolation_root=root,
    )
    assert remove["action"] == "unregister"
    assert remove["state_before"] == "yoetz_owned"
    assert remove["operation"] == "remove"
    removed = apply_cursor_project_mcp(
        target,
        action="remove",
        launcher=LAUNCHER,
        route_profile=None,
        isolation_root=root,
        preview_digest=str(remove["preview_digest"]),
        accept=True,
    )
    assert removed["state_after"] == "absent"
    after_remove = _read_json(project)
    assert after_remove["mcpServers"] == {
        key: value for key, value in document["mcpServers"].items() if key != "finishup"
    }
    assert status_cursor_project_mcp(target, launcher=LAUNCHER, isolation_root=root)["state"] == (
        "absent"
    )

    no_op = preview_cursor_project_mcp(
        target,
        action="remove",
        launcher=LAUNCHER,
        route_profile=None,
        isolation_root=root,
    )
    assert no_op["action"] == "noop"
    assert no_op["state_before"] == "absent"
    bytes_before_noop = project.read_bytes()
    applied_no_op = apply_cursor_project_mcp(
        target,
        action="remove",
        launcher=LAUNCHER,
        route_profile=None,
        isolation_root=root,
        preview_digest=str(no_op["preview_digest"]),
        accept=True,
    )
    assert applied_no_op["state_after"] == "absent"
    assert project.read_bytes() == bytes_before_noop


def test_stale_preview_refuses_without_mutating_a_changed_project_file(tmp_path: Path) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    project = _project_config(target)
    _write_json(project, {"mcpServers": {"other": {"command": "one"}}})
    preview = preview_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile="policy",
        isolation_root=root,
    )
    _write_json(project, {"mcpServers": {"other": {"command": "changed"}}})
    changed_bytes = project.read_bytes()

    _assert_fixed_reason(
        lambda: apply_cursor_project_mcp(
            target,
            action="install",
            launcher=LAUNCHER,
            route_profile="policy",
            isolation_root=root,
            preview_digest=str(preview["preview_digest"]),
            accept=True,
        )
    )
    assert project.read_bytes() == changed_bytes


def test_same_bytes_recreated_after_preview_are_stale_by_file_identity(tmp_path: Path) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    project = _project_config(target)
    original = {"mcpServers": {"other": {"command": "one"}}}
    _write_json(project, original)
    preview = preview_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile="policy",
        isolation_root=root,
    )
    before = project.read_bytes()
    # Keep the previewed file's inode allocated. A freed inode number is handed straight back to
    # the next file (297 of 300 recreates on the CI-equivalent box), and on kernels before 6.13
    # timestamps tick once per jiffy (1 ms there), so an unpinned recreate lands on the same
    # (device, inode, size, mtime, ctime) as the original. The bytes are the same too, so FinishUP has
    # nothing to distinguish; pinning the old inode makes "recreated" a fact instead of a race.
    held = tmp_path / "previewed-inode"
    os.link(project, held)
    project.unlink()
    _write_json(project, original)
    assert project.read_bytes() == before
    assert os.stat(project).st_ino != os.stat(held).st_ino

    _assert_fixed_reason(
        lambda: apply_cursor_project_mcp(
            target,
            action="install",
            launcher=LAUNCHER,
            route_profile="policy",
            isolation_root=root,
            preview_digest=str(preview["preview_digest"]),
            accept=True,
        )
    )
    assert project.read_bytes() == before


def test_same_bytes_rewritten_in_place_after_preview_are_stale_by_timestamp(
    tmp_path: Path,
) -> None:
    """The file identity also holds the modification time: a rewrite of the same bytes in place
    (same inode, same size) is stale once the timestamp differs. The timestamp is set outright,
    so the result does not depend on the filesystem's clock granularity."""

    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    project = _project_config(target)
    _write_json(project, {"mcpServers": {"other": {"command": "one"}}})
    preview = preview_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile="policy",
        isolation_root=root,
    )
    before = project.read_bytes()
    inode = os.stat(project).st_ino
    project.write_bytes(before)
    os.utime(project, ns=(1, 1))
    assert os.stat(project).st_ino == inode and project.read_bytes() == before

    _assert_fixed_reason(
        lambda: apply_cursor_project_mcp(
            target,
            action="install",
            launcher=LAUNCHER,
            route_profile="policy",
            isolation_root=root,
            preview_digest=str(preview["preview_digest"]),
            accept=True,
        )
    )
    assert project.read_bytes() == before


def test_absent_project_config_directory_replacement_is_stale_by_directory_identity(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    project = _project_config(target)
    _secure_directory(project.parent)
    preview = preview_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile="policy",
        isolation_root=root,
    )

    project.parent.rename(tmp_path / "old-cursor-config")
    _secure_directory(project.parent)
    _assert_fixed_reason(
        lambda: apply_cursor_project_mcp(
            target,
            action="install",
            launcher=LAUNCHER,
            route_profile="policy",
            isolation_root=root,
            preview_digest=str(preview["preview_digest"]),
            accept=True,
        )
    )
    assert not project.exists()


def test_refuses_unrelated_user_plugin_and_dual_sources(tmp_path: Path) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    user_entry = _entry(isolation_root=root)

    _write_json(_user_config(target), {"mcpServers": {"finishup": user_entry}})
    _assert_fixed_reason(
        lambda: preview_cursor_project_mcp(
            target,
            action="install",
            launcher=LAUNCHER,
            route_profile="policy",
            isolation_root=root,
        )
    )
    assert status_cursor_project_mcp(target, launcher=LAUNCHER, isolation_root=root)["source"] == (
        "user"
    )

    _user_config(target).unlink()
    _write_json(_plugin_config(target), {"mcpServers": {"finishup": user_entry}})
    _assert_fixed_reason(
        lambda: preview_cursor_project_mcp(
            target,
            action="install",
            launcher=LAUNCHER,
            route_profile="policy",
            isolation_root=root,
        )
    )
    assert status_cursor_project_mcp(target, launcher=LAUNCHER, isolation_root=root)["source"] == (
        "plugin"
    )

    _write_json(_project_config(target), {"mcpServers": {"finishup": _entry(isolation_root=root)}})
    status = status_cursor_project_mcp(target, launcher=LAUNCHER, isolation_root=root)
    assert status["source"] == "none"
    assert status["state"] == "multiple_sources"
    _assert_fixed_reason(
        lambda: preview_cursor_project_mcp(
            target,
            action="install",
            launcher=LAUNCHER,
            route_profile="policy",
            isolation_root=root,
        )
    )


def test_foreign_project_entry_is_refused_instead_of_overwritten(tmp_path: Path) -> None:
    target = _target(tmp_path)
    project = _project_config(target)
    _write_json(
        project,
        {
            "settings": {"keep": True},
            "mcpServers": {
                "finishup": {"type": "stdio", "command": "foreign", "args": ["--owned"]}
            },
        },
    )
    before = project.read_bytes()

    _assert_fixed_reason(
        lambda: preview_cursor_project_mcp(
            target,
            action="install",
            launcher=LAUNCHER,
            route_profile="policy",
            isolation_root=None,
        )
    )
    assert project.read_bytes() == before


def test_symlink_hardlink_and_malformed_configs_are_rejected(tmp_path: Path) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    project = _project_config(target)
    outside = tmp_path / "outside.json"
    _write_json(outside, {"mcpServers": {"finishup": {"command": "foreign"}}})
    project.parent.mkdir(parents=True, exist_ok=True)
    project.parent.chmod(0o700)
    project.symlink_to(outside)

    _assert_fixed_reason(
        lambda: preview_cursor_project_mcp(
            target,
            action="install",
            launcher=LAUNCHER,
            route_profile="policy",
            isolation_root=root,
        )
    )

    project.unlink()
    os.link(outside, project)
    _assert_fixed_reason(
        lambda: status_cursor_project_mcp(target, launcher=LAUNCHER, isolation_root=root)
    )

    project.unlink()
    project.write_text("{ malformed", encoding="utf-8")
    project.chmod(0o600)
    _assert_fixed_reason(
        lambda: preview_cursor_project_mcp(
            target,
            action="install",
            launcher=LAUNCHER,
            route_profile="policy",
            isolation_root=root,
        )
    )


def test_rejects_unsafe_target_root_and_invalid_launcher_without_leaking_os_errors(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    symlinked_project = tmp_path / "project-link"
    symlinked_project.symlink_to(target.project_root, target_is_directory=True)
    unsafe_target = CursorProjectMcpTarget(symlinked_project, target.cursor_config_root)

    _assert_fixed_reason(
        lambda: status_cursor_project_mcp(
            unsafe_target,
            launcher=LAUNCHER,
            isolation_root=root,
        )
    )
    _assert_fixed_reason(
        lambda: preview_cursor_project_mcp(
            target,
            action="install",
            launcher=("relative-finishup",),
            route_profile="policy",
            isolation_root=root,
        )
    )


def test_apply_rejects_a_project_replaced_after_atomic_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    project = _project_config(target)
    preview = preview_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile="policy",
        isolation_root=root,
    )

    from finishup.adapters.integrations import cursor_project_mcp as adapter

    original_write = getattr(adapter, "_write")

    def clobber_after_write(
        write_target: CursorProjectMcpTarget,
        before: bytes | None,
        after: bytes,
        **kwargs: Any,
    ) -> None:
        original_write(write_target, before, after, **kwargs)
        _write_json(project, {"mcpServers": {"other": {"command": "foreign"}}})

    monkeypatch.setattr(adapter, "_write", clobber_after_write)
    with pytest.raises(CursorProjectMcpError) as raised:
        apply_cursor_project_mcp(
            target,
            action="install",
            launcher=LAUNCHER,
            route_profile="policy",
            isolation_root=root,
            preview_digest=str(preview["preview_digest"]),
            accept=True,
        )
    assert raised.value.reason == "cursor_project_mcp_write_failed"
    assert _read_json(project) == {"mcpServers": {"other": {"command": "foreign"}}}


def test_apply_rejects_project_replacement_between_precheck_and_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    project = _project_config(target)
    preview = preview_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile="policy",
        isolation_root=root,
    )

    from finishup.adapters.integrations import cursor_project_mcp as adapter

    original_write = getattr(adapter, "_write")

    def replace_before_write(
        write_target: CursorProjectMcpTarget,
        before: bytes | None,
        after: bytes,
        **kwargs: Any,
    ) -> None:
        write_target.project_root.rename(tmp_path / "old-project")
        _secure_directory(write_target.project_root)
        original_write(write_target, before, after, **kwargs)

    monkeypatch.setattr(adapter, "_write", replace_before_write)
    _assert_fixed_reason(
        lambda: apply_cursor_project_mcp(
            target,
            action="install",
            launcher=LAUNCHER,
            route_profile="policy",
            isolation_root=root,
            preview_digest=str(preview["preview_digest"]),
            accept=True,
        )
    )
    assert not project.exists()
    assert not (target.project_root / ".cursor").exists()


def test_apply_rejects_project_config_directory_replacement_between_precheck_and_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    project = _project_config(target)
    _secure_directory(project.parent)
    preview = preview_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile="policy",
        isolation_root=root,
    )

    from finishup.adapters.integrations import cursor_project_mcp as adapter

    original_write = getattr(adapter, "_write")

    def replace_config_directory_before_write(
        write_target: CursorProjectMcpTarget,
        before: bytes | None,
        after: bytes,
        **kwargs: Any,
    ) -> None:
        config_directory = write_target.project_root / ".cursor"
        config_directory.rename(tmp_path / "old-cursor-config")
        _secure_directory(config_directory)
        original_write(write_target, before, after, **kwargs)

    monkeypatch.setattr(adapter, "_write", replace_config_directory_before_write)
    _assert_fixed_reason(
        lambda: apply_cursor_project_mcp(
            target,
            action="install",
            launcher=LAUNCHER,
            route_profile="policy",
            isolation_root=root,
            preview_digest=str(preview["preview_digest"]),
            accept=True,
        )
    )
    assert not project.exists()


def test_apply_rejects_a_user_source_appearing_after_project_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    project = _project_config(target)
    preview = preview_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile="policy",
        isolation_root=root,
    )

    from finishup.adapters.integrations import cursor_project_mcp as adapter

    original_write = getattr(adapter, "_write")

    def add_external_source(
        write_target: CursorProjectMcpTarget,
        before: bytes | None,
        after: bytes,
        **kwargs: Any,
    ) -> None:
        original_write(write_target, before, after, **kwargs)
        _write_json(_user_config(write_target), {"mcpServers": {"finishup": _entry()}})

    monkeypatch.setattr(adapter, "_write", add_external_source)
    with pytest.raises(CursorProjectMcpError) as raised:
        apply_cursor_project_mcp(
            target,
            action="install",
            launcher=LAUNCHER,
            route_profile="policy",
            isolation_root=root,
            preview_digest=str(preview["preview_digest"]),
            accept=True,
        )
    assert raised.value.reason == "cursor_project_mcp_write_failed"
    assert _read_json(project)["mcpServers"]["finishup"] == _entry(
        isolation_root=root, project_root=target.project_root
    )
    assert _read_json(_user_config(target))["mcpServers"]["finishup"] == _entry()


def test_placeholder_registration_upgrades_to_exact_project_and_remains_runtime_verifiable(
    tmp_path: Path,
) -> None:
    from finishup.adapters.integrations.cursor_project_mcp import inspect_project_mcp_registration

    target = _target(tmp_path)
    root = _isolation_root(tmp_path)
    config = _project_config(target)
    _write_json(config, {"mcpServers": {"finishup": _entry(isolation_root=root)}})
    # Existing IDE registrations remain valid until an explicitly accepted upgrade.
    inspect_project_mcp_registration(
        target.project_root, launcher=LAUNCHER, route_profile="policy", isolation_root=root
    )
    preview = preview_cursor_project_mcp(
        target, action="install", launcher=LAUNCHER, route_profile="policy", isolation_root=root
    )
    assert preview["action"] == "reregister"
    apply_cursor_project_mcp(
        target,
        action="install",
        launcher=LAUNCHER,
        route_profile="policy",
        isolation_root=root,
        preview_digest=str(preview["preview_digest"]),
        accept=True,
    )
    actual = _read_json(config)["mcpServers"]["finishup"]
    assert "${workspaceFolder}" not in actual["args"]
    assert str(target.project_root) in actual["args"]
    inspect_project_mcp_registration(
        target.project_root, launcher=LAUNCHER, route_profile="policy", isolation_root=root
    )
    # An absolute selector for another directory cannot establish this registration's authority.
    actual["args"] = [
        str(tmp_path) if arg == str(target.project_root) else arg for arg in actual["args"]
    ]
    _write_json(config, {"mcpServers": {"finishup": actual}})
    with pytest.raises(CursorProjectMcpError, match="foreign_present"):
        inspect_project_mcp_registration(
            target.project_root, launcher=LAUNCHER, route_profile="policy", isolation_root=root
        )
