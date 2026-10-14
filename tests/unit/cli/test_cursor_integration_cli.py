from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

from finishup.adapters.integrations.artifact_presence import describe_artifact_presence
from finishup.adapters.integrations.portable_plugin import prepare_portable_artifact_review
from finishup.cli.app import app
from finishup.cli.cursor_integration import run_cursor_plugin_command
from finishup.ports.plugin_artifacts import ArtifactAuthority
from finishup.protocol.canonical import JsonValue, canonical_encode


class _Presence:
    """Stand in for the action-bound presence cell the packaged runtime does not ship."""

    def __init__(self) -> None:
        self.seen: list[ArtifactAuthority] = []

    def verify_artifact_review(self, authority: ArtifactAuthority) -> None:
        self.seen.append(authority)


def _mutate(
    command: str,
    config: Path,
    project: Path,
    *,
    request_value: str,
    preview_digest: str,
    state: Path | None,
    presence: _Presence | None,
    requested_action: str | None = None,
) -> int:
    return run_cursor_plugin_command(
        command,
        harness="cursor",
        cursor_config_root=config,
        project_root=project,
        format_name="native",
        ownership_name="plugin-managed",
        route_profile="strict",
        requested_action=requested_action,
        request_value=request_value,
        preview_digest=preview_digest,
        accept=True,
        json_output=True,
        _state=state,
        _presence=presence,
    )


def _args(config: Path, project: Path, command: str, *extra: str) -> list[str]:
    return [
        "integrate",
        "cursor",
        "plugin",
        command,
        "--cursor-config-root",
        str(config),
        "--project-root",
        str(project),
        "--format",
        "native",
        "--mcp-ownership",
        "plugin-managed",
        "--route-profile",
        "strict",
        "--json",
        *extra,
    ]


def test_cursor_plugin_cli_binds_preview_install_status_and_remove(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # This scripted CLI lifecycle represents a legacy ambient install. Mock
    # only the adapter lookup; the process still runs with its isolated root.
    monkeypatch.setattr(
        "finishup.adapters.integrations.cursor_integration.isolated_root", lambda: None
    )
    runner = CliRunner()
    config = tmp_path / "cursor-testing-home" / ".cursor"
    project = tmp_path / "project"
    project.mkdir()
    regular = tmp_path / "regular-cursor"
    regular.mkdir()
    sentinel = regular / "sentinel"
    sentinel.write_text("untouched\n", encoding="utf-8")

    preview_result = runner.invoke(app, _args(config, project, "preview"))
    assert preview_result.exit_code == 0, preview_result.output
    preview = json.loads(preview_result.stdout)
    assert (
        preview_result.stdout.encode("utf-8") == canonical_encode(cast(JsonValue, preview)) + b"\n"
    )
    assert preview["state_before"] == "absent"
    assert preview["authorization"] == {
        "operation": "plugin_artifact_apply",
        "prepare_command": [
            "finishup",
            "consent",
            "prepare",
            "plugin_artifact_apply",
            "--target-digest",
            preview["preview_digest"],
        ],
        "human_presence": describe_artifact_presence(),
        "requires_os_authenticated_prompt": True,
    }

    state = tmp_path / "private-state"
    presence = _Presence()
    prepare_portable_artifact_review(preview["preview_digest"], _state=state)
    assert (
        _mutate(
            "install",
            config,
            project,
            request_value=preview["request_id"],
            preview_digest=preview["preview_digest"],
            state=state,
            presence=presence,
        )
        == 0
    )
    installed_body = json.loads(capsys.readouterr().out)
    assert installed_body["installed_digest"] is not None
    assert installed_body["installed_startup_mode"] == "optional"
    assert len(presence.seen) == 1

    status = runner.invoke(app, _args(config, project, "status"))
    assert status.exit_code == 0, status.output
    status_body = json.loads(status.stdout)
    assert status_body["state"] == "native_managed"
    assert status_body["isolation_binding"] == "ambient"
    assert status_body["mcp"]["ownership_state"] == "plugin"
    # Issue #468: the CLI status exposes the bound launcher, its MCP binding, and the identity
    # probed from that exact executable (this venv's own console script here).
    launcher = status_body["launcher"]
    assert launcher["installed"] == launcher["artifact"]
    assert Path(launcher["installed"][0]).is_absolute()
    assert launcher["executable"] == "matched"
    assert launcher["mcp_binding"] == "exact_launcher"
    assert launcher["identity"]["observed"] is True
    assert launcher["identity"]["matched"] is True
    assert launcher["identity"]["control_schema_version"] is not None
    assert "executable_activation" in status_body["mcp"]["runtime"]

    replace_preview_result = runner.invoke(
        app,
        _args(
            config,
            project,
            "preview",
            "--action",
            "replace",
            "--request-id",
            "req_10000000-0000-4000-8000-000000000009",
        ),
    )
    assert replace_preview_result.exit_code == 0
    replace_preview = json.loads(replace_preview_result.stdout)
    prepare_portable_artifact_review(replace_preview["preview_digest"], _state=state)
    assert (
        _mutate(
            "install",
            config,
            project,
            request_value=replace_preview["request_id"],
            preview_digest=replace_preview["preview_digest"],
            state=state,
            presence=presence,
            requested_action="replace",
        )
        == 0
    )
    capsys.readouterr()
    assert len(presence.seen) == 2

    remove_preview_result = runner.invoke(
        app,
        _args(
            config,
            project,
            "preview",
            "--action",
            "remove",
            "--request-id",
            "req_10000000-0000-4000-8000-000000000010",
        ),
    )
    assert remove_preview_result.exit_code == 0
    remove_preview = json.loads(remove_preview_result.stdout)
    prepare_portable_artifact_review(remove_preview["preview_digest"], _state=state)
    assert (
        _mutate(
            "remove",
            config,
            project,
            request_value=remove_preview["request_id"],
            preview_digest=remove_preview["preview_digest"],
            state=state,
            presence=presence,
        )
        == 0
    )
    removed_body = json.loads(capsys.readouterr().out)
    assert removed_body["installed_digest"] is None
    assert removed_body["installed_startup_mode"] is None
    assert len(presence.seen) == 3
    assert not (config / "plugins" / "local" / "finishup").exists()
    assert sentinel.read_text("utf-8") == "untouched\n"

    # Each review is single-shot: the pending is gone and a replay cannot reuse it.
    assert (
        _mutate(
            "install",
            config,
            project,
            request_value=preview["request_id"],
            preview_digest=preview["preview_digest"],
            state=state,
            presence=presence,
            requested_action="install",
        )
        == 1
    )
    assert len(presence.seen) == 3


def test_cursor_plugin_cli_preview_surfaces_isolated_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "isolated-root"
    monkeypatch.setattr(
        "finishup.adapters.integrations.cursor_integration.isolated_root", lambda: root
    )
    runner = CliRunner()
    preview_result = runner.invoke(
        app,
        _args(
            tmp_path / "cursor-config",
            tmp_path / "project",
            "preview",
        ),
    )
    assert preview_result.exit_code == 0, preview_result.output
    preview = json.loads(preview_result.stdout)
    assert preview["isolation_root"] == str(root)


def test_cursor_plugin_cli_rejects_unknown_action_with_bounded_reason(tmp_path: Path) -> None:
    runner = CliRunner()
    config = tmp_path / "cursor-testing-home" / ".cursor"
    project = tmp_path / "project"
    project.mkdir()

    result = runner.invoke(app, _args(config, project, "preview", "--action", "bogus"))

    assert result.exit_code == 1
    assert result.stderr == "cursor_plugin_action_invalid\n"


def test_accept_without_a_prepared_review_cannot_mutate_through_the_typer_surface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--accept`` is operator acceptance of an exact digest, never human authority."""

    monkeypatch.setattr(
        "finishup.service.elevated_bootstrap.state_dir", lambda: tmp_path / "private-state"
    )
    runner = CliRunner()
    config = tmp_path / "cursor-testing-home" / ".cursor"
    project = tmp_path / "project"
    project.mkdir()

    preview_result = runner.invoke(app, _args(config, project, "preview"))
    assert preview_result.exit_code == 0, preview_result.output
    preview = json.loads(preview_result.stdout)

    installed = runner.invoke(
        app,
        [
            *_args(config, project, "install"),
            "--request-id",
            preview["request_id"],
            "--preview-digest",
            preview["preview_digest"],
            "--accept",
        ],
    )

    assert installed.exit_code == 1
    assert installed.stderr == "authority_required\n"
    assert not (config / "plugins" / "local" / "finishup").exists()


def test_prepared_review_denied_by_os_presence_fails_closed_before_any_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "cursor-testing-home" / ".cursor"
    project = tmp_path / "project"
    project.mkdir()
    state = tmp_path / "private-state"
    runner = CliRunner()

    preview = json.loads(runner.invoke(app, _args(config, project, "preview")).stdout)
    prepare_portable_artifact_review(preview["preview_digest"], _state=state)

    def deny_presence(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 0, b"denied\n", b"")

    monkeypatch.setattr(
        "finishup.adapters.integrations.macos_artifact_presence.subprocess.run",
        deny_presence,
    )

    # No presence override uses the packaged macOS adapter. A denied/cancelled OS prompt cannot
    # consume the pending or move any target bytes.
    assert (
        _mutate(
            "install",
            config,
            project,
            request_value=preview["request_id"],
            preview_digest=preview["preview_digest"],
            state=state,
            presence=None,
        )
        == 1
    )
    assert not (config / "plugins" / "local" / "finishup").exists()


def test_wedged_install_replay_reconciles_through_the_cli_without_a_second_review(
    tmp_path: Path,
) -> None:
    config = tmp_path / "cursor-testing-home" / ".cursor"
    project = tmp_path / "project"
    project.mkdir()
    state = tmp_path / "private-state"
    runner = CliRunner()

    preview = json.loads(runner.invoke(app, _args(config, project, "preview")).stdout)
    prepare_portable_artifact_review(preview["preview_digest"], _state=state)
    assert (
        _mutate(
            "install",
            config,
            project,
            request_value=preview["request_id"],
            preview_digest=preview["preview_digest"],
            state=state,
            presence=_Presence(),
        )
        == 0
    )

    # The single-shot review is spent and the result was lost. Replaying the same request must
    # reconcile at the committed state rather than demand a second review.
    assert (
        _mutate(
            "install",
            config,
            project,
            request_value=preview["request_id"],
            preview_digest=preview["preview_digest"],
            state=state,
            presence=None,
            requested_action="install",
        )
        == 0
    )


def test_invoking_launcher_preserves_module_entrypoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup
    from finishup.cli import cursor_integration as cli_module

    package_main = str(Path(finishup.__file__).parent / "__main__.py")
    monkeypatch.setattr(cli_module.sys, "argv", [package_main])
    assert cli_module._invoking_launcher() == (  # pyright: ignore[reportPrivateUsage]
        cli_module.sys.executable,
        "-m",
        "finishup",
    )

    monkeypatch.setattr(cli_module.sys, "argv", ["/opt/tools/finishup"])
    assert cli_module._invoking_launcher() == (  # pyright: ignore[reportPrivateUsage]
        "/opt/tools/finishup"
    )

    monkeypatch.setattr(cli_module.sys, "argv", ["/usr/bin/unrelated"])
    assert cli_module._invoking_launcher() is None  # pyright: ignore[reportPrivateUsage]


def test_a_strict_preview_discloses_the_project_host_admission_it_would_revoke(
    tmp_path: Path,
) -> None:
    """A strict route and a removal are reverse transitions for host admission (issue #467)."""

    config = tmp_path / "cursor-testing-home" / ".cursor"
    project = tmp_path / "project"
    (project / ".cursor").mkdir(parents=True)
    (project / ".cursor" / "permissions.json").write_text(
        json.dumps({"mcpAllowlist": ["finishup:check"]}), encoding="utf-8"
    )
    (project / ".cursor" / "cli.json").write_text(
        json.dumps({"permissions": {"allow": ["Mcp(plugin-finishup-finishup:check)"]}}),
        encoding="utf-8",
    )
    runner = CliRunner()
    preview_result = runner.invoke(app, _args(config, project, "preview"))
    assert preview_result.exit_code == 0, preview_result.output
    preview = json.loads(preview_result.stdout)
    assert preview["mcp_route_profile"] == "strict"
    assert preview["admission_cleanup"] == {
        "host": "cursor",
        "state": "present",
        "surfaces": [".cursor/cli.json", ".cursor/permissions.json"],
    }
    # Disclosure only; nothing is removed by a preview.
    assert (project / ".cursor" / "permissions.json").exists()

    policy_args = [
        item if item != "strict" else "policy" for item in _args(config, project, "preview")
    ]
    policy = runner.invoke(app, policy_args)
    assert policy.exit_code == 0, policy.output
    assert json.loads(policy.stdout)["admission_cleanup"] is None


@pytest.mark.parametrize(
    ("platform", "expected"),
    [("darwin", ["macos"]), ("linux", ["linux"]), ("win32", [])],
)
def test_default_presence_cell_follows_the_platform_and_fails_closed_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str, expected: list[str]
) -> None:
    from types import SimpleNamespace

    from finishup.adapters.integrations import artifact_presence
    from finishup.adapters.integrations.artifact_presence import describe_artifact_presence
    from finishup.adapters.integrations.linux_artifact_presence import LinuxArtifactUserPresence
    from finishup.adapters.integrations.macos_artifact_presence import MacOSArtifactUserPresence

    config = tmp_path / "cursor-testing-home" / ".cursor"
    project = tmp_path / "project"
    project.mkdir()
    state = tmp_path / "private-state"
    runner = CliRunner()
    monkeypatch.setattr(artifact_presence, "sys", SimpleNamespace(platform=platform))

    preview = json.loads(runner.invoke(app, _args(config, project, "preview")).stdout)
    assert preview["authorization"]["human_presence"] == describe_artifact_presence(platform)
    assert preview["authorization"]["human_presence"]["supported"] is bool(expected)
    prepare_portable_artifact_review(preview["preview_digest"], _state=state)

    called: list[str] = []

    def macos(_self: object, _authority: ArtifactAuthority) -> None:
        called.append("macos")
        raise RuntimeError("human_authority_unavailable")

    def linux(_self: object, _authority: ArtifactAuthority) -> None:
        called.append("linux")
        raise RuntimeError("human_authority_unavailable")

    monkeypatch.setattr(MacOSArtifactUserPresence, "verify_artifact_review", macos)
    monkeypatch.setattr(LinuxArtifactUserPresence, "verify_artifact_review", linux)

    assert (
        _mutate(
            "install",
            config,
            project,
            request_value=preview["request_id"],
            preview_digest=preview["preview_digest"],
            state=state,
            presence=None,
        )
        == 1
    )
    assert called == expected
    assert not (config / "plugins" / "local" / "finishup").exists()
