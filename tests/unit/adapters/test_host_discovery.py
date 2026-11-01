from pathlib import Path

import pytest

from finishup.adapters.integrations import host_discovery as discovery


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_executable_discovery_keeps_cursor_surfaces_distinct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    monkeypatch.setattr(discovery.sys, "platform", platform)
    for key in ("CURSOR_CONFIG_DIR", "XDG_CONFIG_HOME", "CLAUDE_CONFIG_DIR"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(discovery, "discover_codex_binaries", lambda: ())
    names = {"claude": "2.1.241", "cursor": "2.6.0", "cursor-agent": "2026.09.19"}
    for name in names:
        path = tmp_path / name
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o700)
    rows = discovery.discover_hosts(
        which=lambda name: str(tmp_path / name) if name in names else None,
        version_probe=lambda path: names[path.name],
        home=tmp_path,
    )
    assert [row.host for row in rows] == ["claude", "cursor-ide", "cursor-cli"]
    assert rows[1].config_root == rows[2].config_root == tmp_path / ".cursor"
    assert all(row.support == "untested" for row in rows)


def test_leftover_directories_and_failed_versions_are_not_installations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(discovery, "discover_codex_binaries", lambda: ())
    monkeypatch.setattr(discovery.sys, "platform", "linux")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".cursor").mkdir()
    assert discovery.discover_hosts(which=lambda _name: None, home=tmp_path) == ()
    binary = tmp_path / "claude"
    binary.write_text("#!/bin/sh\nexit 1\n")
    binary.chmod(0o700)
    assert (
        discovery.discover_hosts(
            which=lambda name: str(binary) if name == "claude" else None,
            version_probe=lambda _path: None,
            home=tmp_path,
        )
        == ()
    )


def test_configuration_overrides_do_not_mix_host_profiles(tmp_path: Path) -> None:
    environment = {
        "CLAUDE_CONFIG_DIR": str(tmp_path / "claude-custom"),
        "CODEX_HOME": str(tmp_path / "codex-custom"),
    }
    assert (
        discovery.host_config_root("claude", home=tmp_path, environ=environment)
        == tmp_path / "claude-custom"
    )
    assert (
        discovery.host_config_root("codex", home=tmp_path, environ=environment)
        == tmp_path / "codex-custom"
    )
    assert (
        discovery.host_config_root("cursor-ide", home=tmp_path, environ=environment)
        == tmp_path / ".cursor"
    )
