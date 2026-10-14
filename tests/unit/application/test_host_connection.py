"""Connection composition against real isolated adapter state, without a live host."""

from pathlib import Path

import pytest

from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.application.host_connection import (
    ConnectionError,
    apply_connection,
    prepare_connection,
)
from finishup.domain.values import request_id
from finishup.ports.plugin_artifacts import ArtifactAuthority

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

    from finishup.adapters.integrations.host_discovery import SetupHost

    project = tmp_path / "project"
    config = tmp_path / "cursor"
    project.mkdir(mode=0o700)
    if config_exists:
        config.mkdir(mode=0o700)
    launcher = tmp_path / "finishup"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    installation = HostInstallation(cast(SetupHost, host), launcher, "2026.09.19", config, "Cursor")
    review = Review()
    for step, action in enumerate(("connect", "disconnect", "connect"), 1):
        from finishup.application.host_connection import ConnectionAction

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
    from finishup.adapters.integrations import cursor_project_mcp as mcp

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
    assert (config / "plugins/local/finishup").is_dir()
    monkeypatch.setattr(mcp, "apply_cursor_project_mcp", original)
    remaining = prepare()
    assert remaining.body["changes"] == ["register_project_mcp"]
    result = apply_connection(
        remaining,
        accepted_digest=remaining.digest,
        refresh=prepare,
        authority=ArtifactAuthority("review_only", remaining.digest, "test"),
        review=Review(),
    )
    assert result["configured"] is True
