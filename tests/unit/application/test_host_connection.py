"""Connection composition against real isolated adapter state, without a live host."""

from pathlib import Path
from typing import cast

import pytest

from yoetz.adapters.integrations.host_discovery import HostInstallation
from yoetz.application.host_connection import ConnectionError, apply_connection, prepare_connection
from yoetz.domain.values import request_id
from yoetz.ports.plugin_artifacts import ArtifactAuthority

REQUEST = request_id("req_65c9c29d-7e67-4a52-88a9-a68c3c570ebb")


class Review:
    def __init__(self) -> None:
        self.digests: list[str] = []

    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        assert authority.target_digest == preview_digest
        self.digests.append(preview_digest)

    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        raise AssertionError("only the complete connection is reviewed")


@pytest.mark.parametrize("host", ["cursor-ide", "cursor-cli"])
@pytest.mark.parametrize("config_exists", [False, True])
def test_cursor_connect_disconnect_reconnect(
    tmp_path: Path, host: str, config_exists: bool
) -> None:
    from typing import cast

    from yoetz.adapters.integrations.host_discovery import SetupHost

    project = tmp_path / "project"
    config = tmp_path / "cursor"
    project.mkdir(mode=0o700)
    if config_exists:
        config.mkdir(mode=0o700)
    launcher = tmp_path / "yoetz"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    installation = HostInstallation(cast(SetupHost, host), launcher, "2026.09.19", config, "Cursor")
    review = Review()
    for step, action in enumerate(("connect", "disconnect", "connect"), 1):
        from yoetz.application.host_connection import ConnectionAction

        def prepare():
            return prepare_connection(
                REQUEST,
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
            review=review,
        )
        assert result["configured"] is (action == "connect")
        assert result["installed"] is (action == "connect")
        assert result["connection_observed"] is False
        assert len(review.digests) == step
    assert len(review.digests) == 3

    def prepare_again():
        return prepare_connection(
            REQUEST,
            installation,
            project,
            action="connect",
            route="strict",
            launcher=(str(launcher),),
        )

    plan = prepare_again()
    assert plan.unchanged
    apply_connection(
        plan, accepted_digest=plan.digest, refresh=prepare_again, authority=None, review=review
    )
    assert len(review.digests) == 3


def test_cursor_stale_project_config_refuses_before_review(tmp_path: Path) -> None:
    project, config = tmp_path / "project", tmp_path / "cursor"
    project.mkdir(mode=0o700)
    config.mkdir(mode=0o700)
    installation = HostInstallation("cursor-cli", Path("/bin/echo"), "2026.09.19", config, "Cursor")

    def prepare():
        return prepare_connection(
            REQUEST,
            installation,
            project,
            action="connect",
            route="strict",
            launcher=("/bin/echo",),
        )

    plan = prepare()
    (project / ".cursor").mkdir(mode=0o700)
    (project / ".cursor" / "mcp.json").write_text(
        '{"mcpServers":{"unrelated":{"command":"other"}}}'
    )
    review = Review()
    with pytest.raises(ConnectionError, match="connection_preview_stale"):
        apply_connection(
            plan,
            accepted_digest=plan.digest,
            refresh=prepare,
            authority=ArtifactAuthority("review_only", plan.digest, "test"),
            review=review,
        )
    assert review.digests == []
    assert not (config / "plugins").exists()


def test_denied_connection_does_not_create_the_missing_config_root(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    config = tmp_path / "cursor"
    installation = HostInstallation("cursor-cli", Path("/bin/echo"), "2026.09.19", config, "Cursor")

    def prepare():
        return prepare_connection(
            REQUEST,
            installation,
            project,
            action="connect",
            route="strict",
            launcher=("/bin/echo",),
        )

    class Denied(Review):
        def consume_artifact_review(
            self, authority: ArtifactAuthority, preview_digest: str
        ) -> None:
            raise PermissionError("denied")

    plan = prepare()
    with pytest.raises(PermissionError):
        apply_connection(
            plan,
            accepted_digest=plan.digest,
            refresh=prepare,
            authority=ArtifactAuthority("review_only", plan.digest, "test"),
            review=Denied(),
        )
    assert not config.exists()
    assert list(project.iterdir()) == []


def test_partial_cursor_connection_resumes_only_remaining_mcp_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from yoetz.adapters.integrations import cursor_project_mcp as mcp

    project, config = tmp_path / "project", tmp_path / "cursor"
    project.mkdir(mode=0o700)
    config.mkdir(mode=0o700)
    installation = HostInstallation("cursor-cli", Path("/bin/echo"), "2026.09.19", config, "Cursor")

    def prepare():
        return prepare_connection(
            REQUEST,
            installation,
            project,
            action="connect",
            route="strict",
            launcher=("/bin/echo",),
        )

    plan = prepare()
    original = mcp.apply_cursor_project_mcp

    def fail(*_args: object, **_kwargs: object):
        raise mcp.CursorProjectMcpError("cursor_project_mcp_write_failed")

    monkeypatch.setattr(mcp, "apply_cursor_project_mcp", fail)
    with pytest.raises(mcp.CursorProjectMcpError):
        apply_connection(
            plan,
            accepted_digest=plan.digest,
            refresh=prepare,
            authority=ArtifactAuthority("review_only", plan.digest, "test"),
            review=Review(),
        )
    assert (config / "plugins/local/yoetz").is_dir()
    monkeypatch.setattr(mcp, "apply_cursor_project_mcp", original)
    remaining = prepare()
    # The interrupted connect never recorded the project (#1058), so resuming records it too.
    assert remaining.body["changes"] == ["register_project_mcp", "record_connected_project"]
    result = apply_connection(
        remaining,
        accepted_digest=remaining.digest,
        refresh=prepare,
        authority=ArtifactAuthority("review_only", remaining.digest, "test"),
        review=Review(),
    )
    assert result["configured"] is True


def _cursor_step(
    installation: HostInstallation, project: Path, action: str, launcher: Path, review: Review
) -> dict[str, object]:
    from typing import cast

    from yoetz.application.host_connection import ConnectionAction

    def prepare():
        return prepare_connection(
            REQUEST,
            installation,
            project,
            action=cast(ConnectionAction, action),
            route="strict",
            launcher=(str(launcher),),
        )

    plan = prepare()
    return dict(
        apply_connection(
            plan,
            accepted_digest=plan.digest,
            refresh=prepare,
            authority=ArtifactAuthority("review_only", plan.digest, "test"),
            review=review,
        )
    )


def test_cursor_projects_share_the_user_plugin_until_the_last_disconnect(tmp_path: Path) -> None:
    """#1058: disconnecting one project keeps the user plugin another connected project uses."""

    from typing import cast

    from yoetz.adapters.integrations.host_discovery import SetupHost
    from yoetz.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE

    project_a, project_b = tmp_path / "a", tmp_path / "b"
    project_a.mkdir(mode=0o700)
    project_b.mkdir(mode=0o700)
    config = tmp_path / "cursor"
    launcher = tmp_path / "yoetz"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    installation = HostInstallation(
        cast(SetupHost, "cursor-cli"), launcher, "2026.09.19", config, "Cursor"
    )
    review = Review()

    _cursor_step(installation, project_a, "connect", launcher, review)
    connected_b = _cursor_step(installation, project_b, "connect", launcher, review)
    assert connected_b["installed"] is True and connected_b["configured"] is True
    assert connected_b["connected_projects"] == sorted([str(project_a), str(project_b)])

    left_a = _cursor_step(installation, project_a, "disconnect", launcher, review)
    assert left_a["configured"] is False
    # The shared plugin stays installed for B; only A's project MCP entry went.
    assert left_a["installed"] is True
    assert left_a["connected_projects"] == [str(project_b)]

    left_b = _cursor_step(installation, project_b, "disconnect", launcher, review)
    assert left_b["installed"] is False and left_b["configured"] is False
    assert not (config / CONNECTED_PROJECTS_FILE).exists()


def test_cursor_second_path_to_a_connected_project_is_refused(tmp_path: Path) -> None:
    from typing import cast

    from yoetz.adapters.integrations.host_discovery import SetupHost

    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    config = tmp_path / "cursor"
    launcher = tmp_path / "yoetz"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    installation = HostInstallation(
        cast(SetupHost, "cursor-ide"), launcher, "2026.09.19", config, "Cursor"
    )
    review = Review()
    _cursor_step(installation, project, "connect", launcher, review)
    moved = tmp_path / "moved"
    project.rename(moved)
    project.symlink_to(moved, target_is_directory=True)

    with pytest.raises(ConnectionError, match="project_connected_via_other_path"):
        prepare_connection(
            REQUEST,
            installation,
            moved,
            action="connect",
            route="strict",
            launcher=(str(launcher),),
        )
    # Cursor's project MCP entry still names the old path, so it is not Yoetz's for the new one:
    # the owner removes it (the refusal says so), then a disconnect under the current path
    # clears the old-path record entry, after which the project connects.
    (moved / ".cursor" / "mcp.json").unlink()
    _cursor_step(installation, moved, "disconnect", launcher, review)
    assert _cursor_step(installation, moved, "connect", launcher, review)["configured"] is True


def _cursor_install(tmp_path: Path, host: str) -> tuple[HostInstallation, Path]:
    from typing import cast

    from yoetz.adapters.integrations.host_discovery import SetupHost

    launcher = tmp_path / "yoetz"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    return (
        HostInstallation(
            cast(SetupHost, host), launcher, "2026.09.19", tmp_path / "cursor", "Cursor"
        ),
        launcher,
    )


@pytest.mark.parametrize("host", ["cursor-ide", "cursor-cli"])
def test_cursor_upgrade_without_record_keeps_the_older_projects_plugin(
    tmp_path: Path, host: str
) -> None:
    """CHECK_MULTIPROJ_R1 P2-1: a missing record is unknown membership, not an empty one."""

    from yoetz.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE

    installation, launcher = _cursor_install(tmp_path, host)
    project_a, project_b = tmp_path / "a", tmp_path / "b"
    project_a.mkdir(mode=0o700)
    project_b.mkdir(mode=0o700)
    review = Review()
    _cursor_step(installation, project_b, "connect", launcher, review)
    # B was connected by an earlier release (or the record was lost).
    (installation.config_root / CONNECTED_PROJECTS_FILE).unlink()

    preview_a = prepare_connection(
        REQUEST,
        installation,
        project_a,
        action="connect",
        route="strict",
        launcher=(str(launcher),),
    )
    assert preview_a.disclosure["membership_unknown"] is True
    _cursor_step(installation, project_a, "connect", launcher, review)

    plan = prepare_connection(
        REQUEST,
        installation,
        project_a,
        action="disconnect",
        route="strict",
        launcher=(str(launcher),),
    )
    assert "remove_plugin" not in cast(list[str], plan.body["changes"])
    assert plan.disclosure["membership_unknown"] is True
    _cursor_step(installation, project_a, "disconnect", launcher, review)

    status_b = prepare_connection(
        REQUEST,
        installation,
        project_b,
        action="connect",
        route="strict",
        launcher=(str(launcher),),
    ).status()
    assert status_b["installed"] is True and status_b["configured"] is True
    assert status_b["membership_unknown"] is True

    # Only the explicit home-wide disconnect removes the shared plugin, with disclosure.
    def prepare_shared():
        return prepare_connection(
            REQUEST,
            installation,
            project_b,
            action="disconnect",
            route="strict",
            launcher=(str(launcher),),
            remove_shared=True,
        )

    shared = prepare_shared()
    assert "remove_plugin" in cast(list[str], shared.body["changes"])
    assert shared.disclosure["remove_shared"] is True
    result = apply_connection(
        shared,
        accepted_digest=shared.digest,
        refresh=prepare_shared,
        authority=ArtifactAuthority("review_only", shared.digest, "test"),
        review=review,
    )
    assert result["installed"] is False
    assert not (installation.config_root / CONNECTED_PROJECTS_FILE).exists()


def test_concurrent_cursor_connects_never_lose_a_member(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CHECK_MULTIPROJ_R1 P2-2: the second apply waits, then is stale; its retry joins."""

    import threading

    from yoetz.adapters.integrations import host_projects
    from yoetz.adapters.integrations.host_projects import load_connected_projects
    from yoetz.application import host_connection as composition

    installation, launcher = _cursor_install(tmp_path, "cursor-cli")
    project_a, project_b, project_c = tmp_path / "a", tmp_path / "b", tmp_path / "c"
    for root in (project_a, project_b, project_c):
        root.mkdir(mode=0o700)
    review = Review()
    _cursor_step(installation, project_c, "connect", launcher, review)

    def prepare(project: Path):
        return lambda: prepare_connection(
            REQUEST,
            installation,
            project,
            action="connect",
            route="strict",
            launcher=(str(launcher),),
        )

    plans = {name: prepare(root)() for name, root in (("a", project_a), ("b", project_b))}
    a_inside = threading.Event()
    b_waiting = threading.Event()
    real_lock = host_projects.host_config_lock
    from contextlib import contextmanager

    @contextmanager
    def observed_lock(root: Path):
        name = threading.current_thread().name
        if name == "b":
            b_waiting.set()  # B is about to block on the lock A holds.
        with real_lock(root):
            if name == "a":
                a_inside.set()
                assert b_waiting.wait(timeout=30)
            yield

    monkeypatch.setattr(composition, "host_config_lock", observed_lock)
    outcomes: dict[str, object] = {}

    def run(name: str, project: Path) -> None:
        if name == "b":
            assert a_inside.wait(timeout=30)
        plan = plans[name]
        try:
            outcomes[name] = apply_connection(
                plan,
                accepted_digest=plan.digest,
                refresh=prepare(project),
                authority=ArtifactAuthority("review_only", plan.digest, "test"),
                review=review,
            )
        except ConnectionError as error:
            outcomes[name] = str(error)

    threads = [
        threading.Thread(target=run, args=("a", project_a), name="a"),
        threading.Thread(target=run, args=("b", project_b), name="b"),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert isinstance(outcomes["a"], dict)
    # B's preview predates A's record change: refused before any change, never a lost member.
    assert outcomes["b"] == "connection_preview_stale"
    assert not (project_b / ".cursor" / "mcp.json").exists()
    _cursor_step(installation, project_b, "connect", launcher, review)
    assert load_connected_projects(installation.config_root).projects == tuple(
        sorted(str(root) for root in (project_a, project_b, project_c))
    )


@pytest.mark.parametrize("host", ["cursor-ide", "cursor-cli"])
def test_first_cursor_setup_into_an_absent_nested_config_root(tmp_path: Path, host: str) -> None:
    """CHECK_MULTIPROJ_R2 P2-R2-2: no manual mkdir before the first connect."""

    from typing import cast as typed

    from yoetz.adapters.integrations.host_discovery import SetupHost

    launcher = tmp_path / "yoetz"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    scratch_home = tmp_path / "home"
    scratch_home.mkdir(mode=0o700)
    config = scratch_home / host / "config"
    installation = HostInstallation(
        typed(SetupHost, host), launcher, "2026.09.19", config, "Cursor"
    )
    project = tmp_path / "project"
    project.mkdir(mode=0o700)

    result = _cursor_step(installation, project, "connect", launcher, Review())

    assert result["installed"] is True and result["configured"] is True


def test_lock_failure_is_reported_before_any_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import errno
    import fcntl

    installation, launcher = _cursor_install(tmp_path, "cursor-cli")
    project = tmp_path / "project"
    project.mkdir(mode=0o700)

    def refuse(_descriptor: int, _operation: int) -> None:
        raise OSError(errno.ENOLCK, "no locks")

    monkeypatch.setattr(fcntl, "flock", refuse)
    with pytest.raises(ConnectionError, match="connection_lock_unavailable"):
        _cursor_step(installation, project, "connect", launcher, Review())
    assert not installation.config_root.exists()
    assert not (project / ".cursor").exists()


def test_status_shows_unknown_membership_before_any_record_exists(tmp_path: Path) -> None:
    """CHECK_MULTIPROJ_R2 P3: status, not only a preview, names unknown membership."""

    from yoetz.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE

    installation, launcher = _cursor_install(tmp_path, "cursor-cli")
    project_b, project_c = tmp_path / "b", tmp_path / "c"
    project_b.mkdir(mode=0o700)
    project_c.mkdir(mode=0o700)
    _cursor_step(installation, project_b, "connect", launcher, Review())
    (installation.config_root / CONNECTED_PROJECTS_FILE).unlink()

    status = prepare_connection(
        REQUEST,
        installation,
        project_c,
        action="connect",
        route="strict",
        launcher=(str(launcher),),
    ).status()

    assert status["membership_unknown"] is True
    assert not (installation.config_root / CONNECTED_PROJECTS_FILE).exists()


def test_status_step_gives_the_exact_remove_shared_preview(tmp_path: Path) -> None:
    from yoetz.cli import host_connection as cli

    installation, _launcher = _cursor_install(tmp_path, "cursor-ide")
    step = cli._membership_status_step(  # pyright: ignore[reportPrivateUsage]
        {"membership_unknown": True}, installation, tmp_path / "p"
    )
    assert step is not None
    assert "setup disconnect --host cursor-ide" in step and step.rstrip().endswith(
        "--remove-shared"
    )
    assert "--accept" not in step
