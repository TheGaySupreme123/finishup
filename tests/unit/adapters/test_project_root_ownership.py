"""Every host's project-root check admits a root-owned project root for a non-root user (container
``/app``) exactly as ``project_root_admitted`` decides, and still refuses another user's directory.

The runner cannot create a root-owned directory, so the runner's own uid plays the superuser and the
process pretends to run as another account. Files Yoetz writes inside the project are still checked
against the running user; only the project root itself is judged by the project rule.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from yoetz.adapters.integrations import (
    claude_code_integration,
    codex_marketplace,
    codex_plugin,
    codex_skill,
    cursor_project_mcp,
    portable_plugin,
)
from yoetz.config import foreign_write
from yoetz.ports.integrations import IntegrationScope, IntegrationTarget
from yoetz.ports.plugin_artifacts import ArtifactTarget

pytestmark = pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX ownership")


def _codex_skill(root: Path) -> None:
    codex_skill._validated_project(  # pyright: ignore[reportPrivateUsage]
        IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(root))
    )
    codex_skill._skill_parent_identity(root)  # pyright: ignore[reportPrivateUsage]


def _codex_plugin(root: Path) -> None:
    codex_plugin._validated_project(  # pyright: ignore[reportPrivateUsage]
        IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(root))
    )


def _codex_marketplace(root: Path) -> None:
    codex_marketplace._validated_project(  # pyright: ignore[reportPrivateUsage]
        IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(root))
    )


def _portable(root: Path) -> None:
    portable_plugin._validate_project(ArtifactTarget(str(root)))  # pyright: ignore[reportPrivateUsage]


def _cursor(root: Path) -> None:
    with cursor_project_mcp._directory(root, project=True):  # pyright: ignore[reportPrivateUsage]
        pass


def _claude(root: Path) -> None:
    claude_code_integration._safe_existing_ancestor(  # pyright: ignore[reportPrivateUsage]
        root, project=True
    )


CHECKS: dict[str, Callable[[Path], None]] = {
    "codex_skill": _codex_skill,
    "codex_plugin": _codex_plugin,
    "codex_marketplace": _codex_marketplace,
    "portable_plugin": _portable,
    "cursor_project_mcp": _cursor,
    "claude_code": _claude,
}


def _project(tmp_path: Path, mode: int) -> Path:
    root = tmp_path.resolve() / "app"
    root.mkdir()
    root.chmod(mode)
    return root


@pytest.mark.parametrize("name", sorted(CHECKS))
@pytest.mark.parametrize("mode", [0o755, 0o1777])
def test_superuser_owned_project_root_is_admitted_for_a_non_root_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, mode: int
) -> None:
    root = _project(tmp_path, mode)
    real = os.geteuid()
    monkeypatch.setattr(foreign_write, "_SUPERUSER_UID", real)
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)

    CHECKS[name](root)


@pytest.mark.parametrize("name", sorted(CHECKS))
@pytest.mark.parametrize(("mode", "owner"), [(0o755, "other"), (0o777, "superuser")])
def test_other_owner_or_shared_project_root_is_still_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, mode: int, owner: str
) -> None:
    root = _project(tmp_path, mode)
    real = os.geteuid()
    monkeypatch.setattr(foreign_write, "_SUPERUSER_UID", real if owner == "superuser" else real + 7)
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)

    with pytest.raises(Exception) as caught:  # noqa: PT011 - each host raises its own typed error
        CHECKS[name](root)
    assert "target_unsafe" in repr(caught.value) or "TARGET_UNSAFE" in repr(caught.value)


# --- Public paths in a root-owned project (independent review of #1071) ---------------------
#
# Each lifecycle runs through the adapter's public status/preview/apply functions, and its way
# out as well as its way in. Ownership is simulated by ``tests.builders.ownership`` so these run
# on a non-root runner too: the runner is the user, ``/app`` is reported as the superuser's.

_LAUNCHER = ("/opt/yoetz-test/bin/yoetz", "--runtime")


@pytest.mark.parametrize("mode", [0o755, 0o1777], ids=["0755", "1777"])
def test_cursor_project_mcp_install_and_remove_in_a_root_owned_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    """Status, preview and apply judged the project root by the owner rule (target_unsafe)."""

    from tests.builders.ownership import root_owned_project

    from yoetz.adapters.integrations.cursor_project_mcp import (
        CursorProjectMcpTarget,
        apply_cursor_project_mcp,
        preview_cursor_project_mcp,
        status_cursor_project_mcp,
    )

    # In a 0755 root-owned /app only root can create .cursor, so root made it for the user.
    project = root_owned_project(
        monkeypatch, tmp_path, mode=mode, made_for_user=(".cursor",) if mode == 0o755 else ()
    )
    config = tmp_path / "cursor-config"
    config.mkdir(mode=0o700)
    target = CursorProjectMcpTarget(project, config)

    def status() -> object:
        return status_cursor_project_mcp(target, launcher=_LAUNCHER, isolation_root=None)["state"]

    def change(action: str) -> None:
        preview = preview_cursor_project_mcp(
            target, action=action, launcher=_LAUNCHER, route_profile="policy", isolation_root=None
        )
        apply_cursor_project_mcp(
            target,
            action=action,
            launcher=_LAUNCHER,
            route_profile="policy",
            isolation_root=None,
            preview_digest=str(preview["preview_digest"]),
            accept=True,
        )

    assert status() == "absent"
    change("install")
    assert status() == "yoetz_owned"
    change("remove")
    assert status() == "absent"


@pytest.mark.parametrize("mode", [0o755, 0o777], ids=["0755", "0777"])
def test_cursor_project_mcp_refuses_a_cursor_directory_another_account_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    from tests.builders.ownership import root_owned_project

    from yoetz.adapters.integrations.cursor_project_mcp import (
        CursorProjectMcpError,
        CursorProjectMcpTarget,
        preview_cursor_project_mcp,
    )

    project = root_owned_project(monkeypatch, tmp_path, mode=0o1777, other_owned={".cursor": mode})
    config = tmp_path / "cursor-config"
    config.mkdir(mode=0o700)
    with pytest.raises(CursorProjectMcpError, match="target_unsafe"):
        preview_cursor_project_mcp(
            CursorProjectMcpTarget(project, config),
            action="install",
            launcher=_LAUNCHER,
            route_profile="policy",
            isolation_root=None,
        )
    assert list((project / ".cursor").iterdir()) == []


@pytest.mark.parametrize("host", ["cursor-ide", "cursor-cli"])
def test_cursor_connect_disconnect_reconnect_in_a_root_owned_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    """The setup composition (application/host_connection) reaches the same adapter checks."""

    from typing import cast

    from tests.builders.ownership import root_owned_project

    from yoetz.adapters.integrations.host_discovery import HostInstallation, SetupHost
    from yoetz.application.host_connection import (
        ConnectionAction,
        ConnectionPlan,
        apply_connection,
        prepare_connection,
    )
    from yoetz.domain.values import request_id
    from yoetz.ports.plugin_artifacts import ArtifactAuthority

    project = root_owned_project(monkeypatch, tmp_path, mode=0o1777)
    config = tmp_path / "cursor"
    config.mkdir(mode=0o700)
    launcher = tmp_path / "yoetz"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    installation = HostInstallation(cast(SetupHost, host), launcher, "2026.09.19", config, "Cursor")
    request = request_id("req_65c9c29d-7e67-4a52-88a9-a68c3c570ebb")

    class Review:
        def consume_artifact_review(
            self, authority: ArtifactAuthority, preview_digest: str
        ) -> None:
            assert authority.target_digest == preview_digest

        def consume_setup_authority(
            self, authority: ArtifactAuthority, preview_digest: str
        ) -> None:
            raise AssertionError("only the complete connection is reviewed")

    for action in ("connect", "disconnect", "connect"):

        def prepare(action: str = action) -> ConnectionPlan:
            return prepare_connection(
                request,
                installation,
                project,
                action=cast(ConnectionAction, action),
                route="strict",
                launcher=(str(launcher),),
            )

        plan = prepare()
        result = apply_connection(
            plan,
            accepted_digest=plan.digest,
            refresh=prepare,
            authority=ArtifactAuthority("review_only", plan.digest, "test"),
            review=Review(),
        )
        assert result["configured"] is (action == "connect")


_HOST_FOLDERS = [
    ("claude", ".claude", "plugin"),
    ("codex", ".codex", "external"),
    ("cursor", ".cursor", "plugin"),
]


@pytest.mark.parametrize(("host", "directory", "owner"), _HOST_FOLDERS)
@pytest.mark.parametrize("squat_mode", [0o755, 0o777], ids=["0755", "0777"])
def test_host_admission_never_reads_or_writes_a_folder_another_account_made(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    host: str,
    directory: str,
    owner: str,
    squat_mode: int,
) -> None:
    """A sticky root-owned /app lets any account create .claude first; it is not the user's.

    Status reports it ``unknown`` (``folder_not_owned``) rather than this user's admission,
    and both grant and revoke refuse it before anything is written.
    """

    from tests.builders.ownership import root_owned_project

    from yoetz.adapters.integrations.host_admission import (
        HostAdmissionAction,
        HostAdmissionError,
        HostAdmissionReason,
        HostAdmissionState,
        observe_host_admission,
        preview_host_admission,
    )

    project = root_owned_project(
        monkeypatch, tmp_path, mode=0o1777, other_owned={directory: squat_mode}
    )
    observation = observe_host_admission(host, project, owner=owner)  # type: ignore[arg-type]
    assert observation.state is HostAdmissionState.UNKNOWN
    assert {entry.detail for entry in observation.entries} == {"folder_not_owned"}
    for action in (HostAdmissionAction.GRANT, HostAdmissionAction.REVOKE):
        with pytest.raises(HostAdmissionError) as refused:
            preview_host_admission(
                host,  # type: ignore[arg-type]
                project,
                action,
                route_profile="policy",
                grant_permits=True,
                owner=owner,  # type: ignore[arg-type]
            )
        assert refused.value.reason is HostAdmissionReason.ENTRY_UNREADABLE
    assert list((project / directory).iterdir()) == []


@pytest.mark.parametrize("swap", ["symlink", "other_account_folder"])
def test_host_admission_write_is_pinned_to_the_folder_it_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap: str
) -> None:
    """The folder is swapped after the fresh preview, just before the write: the descriptor-
    pinned write refuses instead of following a link into the user's other project, or writing
    into a folder the squatter owns."""

    import json

    from tests.builders.ownership import OTHER, SUPERUSER, present_owners

    import yoetz.adapters.integrations.host_admission as module
    from yoetz.adapters.integrations.host_admission import (
        HostAdmissionAction,
        HostAdmissionError,
        HostAdmissionReason,
        apply_host_admission,
        preview_host_admission,
    )

    project = tmp_path.resolve() / "app"
    project.mkdir()
    project.chmod(0o1777)
    victim = tmp_path.resolve() / "other-project" / ".claude"
    victim.mkdir(parents=True, mode=0o700)
    original = json.dumps({"permissions": {"deny": ["Bash(curl:*)"]}}).encode()
    (victim / "settings.local.json").write_bytes(original)
    squat = tmp_path.resolve() / "squat"
    squat.mkdir()
    present_owners(monkeypatch, {project: SUPERUSER, squat: OTHER})
    preview = preview_host_admission(
        "claude",
        project,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        owner="plugin",
    )
    real_mutator = module._delete_or_write  # pyright: ignore[reportPrivateUsage]

    def swapped_first(path: Path, payload: bytes, *, expected_digest: str | None) -> None:
        if swap == "symlink":
            (project / ".claude").symlink_to(victim, target_is_directory=True)
        else:
            squat.rename(project / ".claude")
        real_mutator(path, payload, expected_digest=expected_digest)

    monkeypatch.setattr(module, "_delete_or_write", swapped_first)
    with pytest.raises(HostAdmissionError) as refused:
        apply_host_admission(preview, project, accepted_preview_digest=preview.preview_digest)

    assert refused.value.reason is HostAdmissionReason.TARGET_UNSAFE
    assert (victim / "settings.local.json").read_bytes() == original
    assert sorted(path.name for path in victim.iterdir()) == ["settings.local.json"]
    if swap == "other_account_folder":
        assert list((project / ".claude").iterdir()) == []


@pytest.mark.parametrize(("host", "directory", "owner"), _HOST_FOLDERS)
def test_reverse_sweeps_stay_absent_beside_host_folders_root_committed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    host: str,
    directory: str,
    owner: str,
) -> None:
    """``COPY . /app`` with a committed root-owned .claude/.codex/.cursor: nothing to remove.

    Before, every reverse transition (privacy ceremony, Codex disconnect, plugin removal)
    reported write_failed and suggested a revoke that then failed target_unsafe.
    """

    from types import SimpleNamespace
    from typing import cast

    from tests.builders.ownership import SUPERUSER, present_owners, root_owned_project

    from yoetz.adapters.integrations.host_admission import (
        HostAdmissionAction,
        HostAdmissionError,
        HostAdmissionReason,
        preview_host_admission,
    )
    from yoetz.cli.host_admission import admission_cleanup_preview, reverse_sweep
    from yoetz.cli.privacy_setup import (
        _reconcile_host_admission,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.domain.privacy import PrivacyPolicy

    project = root_owned_project(monkeypatch, tmp_path, mode=0o755)
    committed = project / directory
    committed.mkdir(mode=0o755)
    (committed / "settings.json").write_text("{}\n", encoding="utf-8")
    committed.chmod(0o755)
    present_owners(monkeypatch, {committed: SUPERUSER})

    assert admission_cleanup_preview(host, project)["state"] == "absent"  # type: ignore[arg-type]
    assert reverse_sweep(host, project)["outcome"] == "absent"  # type: ignore[arg-type]
    policy = cast(
        PrivacyPolicy, SimpleNamespace(network_egress_permitted=False, channel_policies=())
    )
    _reconcile_host_admission(policy, project)
    assert "Could not remove" not in capsys.readouterr().out
    # A grant would have to write into root's folder, which the user cannot: refused up front.
    with pytest.raises(HostAdmissionError) as refused:
        preview_host_admission(
            host,  # type: ignore[arg-type]
            project,
            HostAdmissionAction.GRANT,
            route_profile="policy",
            grant_permits=True,
            owner=owner,  # type: ignore[arg-type]
        )
    assert refused.value.reason is HostAdmissionReason.TARGET_UNSAFE


@pytest.mark.parametrize("mode", [0o755, 0o1777], ids=["0755", "1777"])
def test_host_admission_grant_and_revoke_in_a_root_owned_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    from tests.builders.ownership import root_owned_project

    from yoetz.adapters.integrations.host_admission import (
        HostAdmissionAction,
        HostAdmissionState,
        apply_host_admission,
        observe_host_admission,
        preview_host_admission,
    )

    project = root_owned_project(
        monkeypatch, tmp_path, mode=mode, made_for_user=(".claude",) if mode == 0o755 else ()
    )
    for action, expected in (
        (HostAdmissionAction.GRANT, HostAdmissionState.PRESENT),
        (HostAdmissionAction.REVOKE, HostAdmissionState.ABSENT),
    ):
        preview = preview_host_admission(
            "claude",
            project,
            action,
            route_profile="policy",
            grant_permits=True,
            owner="plugin",
        )
        apply_host_admission(preview, project, accepted_preview_digest=preview.preview_digest)
        assert observe_host_admission("claude", project, owner="plugin").state is expected


@pytest.mark.parametrize(
    ("mode", "owner"), [(0o755, "other"), (0o777, "superuser")], ids=["other_0755", "root_0777"]
)
def test_host_admission_refuses_a_project_root_the_rule_does_not_admit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int, owner: str
) -> None:
    from tests.builders.ownership import OTHER, SUPERUSER, present_owners

    from yoetz.adapters.integrations.host_admission import (
        HostAdmissionError,
        HostAdmissionReason,
        observe_host_admission,
    )

    project = tmp_path.resolve() / "app"
    project.mkdir()
    project.chmod(mode)
    present_owners(monkeypatch, {project: OTHER if owner == "other" else SUPERUSER})
    with pytest.raises(HostAdmissionError) as refused:
        observe_host_admission("claude", project, owner="plugin")
    assert refused.value.reason is HostAdmissionReason.TARGET_UNSAFE
