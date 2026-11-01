"""Codex PATH discovery: dedupe, bounds, version parsing, and zero mutation."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import finishup.adapters.integrations.codex_discovery as discovery_module
from finishup.adapters.integrations.codex_discovery import discover_codex_binaries
from finishup.ports.integrations import HarnessId


class _Probe:
    def __init__(self, entries: tuple[str, ...], versions: dict[str, str | None]) -> None:
        self._entries = entries
        self.versions = versions
        self.probed: list[str] = []

    def path_entries(self) -> tuple[str, ...]:
        return self._entries

    def run_version(self, executable: str) -> str | None:
        self.probed.append(executable)
        return self.versions.get(executable)


def _make_codex(
    directory: Path,
    *,
    executable: bool = True,
    executable_name: str = "codex",
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / executable_name
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    mode = 0o755 if executable else 0o644
    os.chmod(binary, mode)
    return binary


def test_no_entries_yields_empty(tmp_path: Path) -> None:
    probe = _Probe((str(tmp_path / "missing"),), {})
    assert discover_codex_binaries(_probe=probe) == ()


def test_single_candidate_reports_untested_and_parsed_version(tmp_path: Path) -> None:
    binary = _make_codex(tmp_path / "bin")
    probe = _Probe((str(binary.parent),), {str(binary): "codex-cli 0.144.5"})
    result = discover_codex_binaries(_probe=probe)
    assert len(result) == 1
    found = result[0]
    assert found.harness_id is HarnessId.CODEX
    assert found.executable_path == str(binary)
    assert found.reported_version == "0.144.5"
    # E-002: discovery alone never claims capability support.
    assert found.compatibility == "untested"


def test_unparsable_or_failed_version_probe_yields_none(tmp_path: Path) -> None:
    binary = _make_codex(tmp_path / "bin")
    for output in (None, "no digits here", ""):
        probe = _Probe((str(binary.parent),), {str(binary): output})
        result = discover_codex_binaries(_probe=probe)
        assert result[0].reported_version is None


def test_symlinked_duplicate_is_deduplicated_but_path_visible_name_kept(tmp_path: Path) -> None:
    real = _make_codex(tmp_path / "real")
    alias_dir = tmp_path / "alias"
    alias_dir.mkdir()
    (alias_dir / "codex").symlink_to(real)
    probe = _Probe((str(alias_dir), str(real.parent)), {})
    result = discover_codex_binaries(_probe=probe)
    # One entry per resolved target; the first PATH-visible name wins.
    assert len(result) == 1
    assert result[0].executable_path == str(alias_dir / "codex")


def test_two_distinct_installs_are_both_reported_sorted(tmp_path: Path) -> None:
    first = _make_codex(tmp_path / "a")
    second = _make_codex(tmp_path / "b")
    probe = _Probe((str(second.parent), str(first.parent)), {})
    result = discover_codex_binaries(_probe=probe)
    assert [entry.executable_path for entry in result] == sorted([str(first), str(second)])


def test_exact_testing_wrapper_is_discovered_but_prefix_neighbors_are_not(tmp_path: Path) -> None:
    directory = tmp_path / "bin"
    testing = _make_codex(directory, executable_name="codex-testing")
    _make_codex(directory, executable_name="codex-testing-update")
    probe = _Probe((str(directory),), {str(testing): "codex-cli 0.146.0-alpha.2"})

    result = discover_codex_binaries(_probe=probe)

    assert [entry.executable_path for entry in result] == [str(testing)]
    assert result[0].reported_version == "0.146.0-alpha.2"
    assert probe.probed == [str(testing)]


def test_prerelease_and_build_suffix_are_preserved_exactly(tmp_path: Path) -> None:
    binary = _make_codex(tmp_path / "bin")
    probe = _Probe(
        (str(binary.parent),),
        {str(binary): "codex-cli 1.2.3-beta.1+exp.sha.5114f85"},
    )
    result = discover_codex_binaries(_probe=probe)
    assert result[0].reported_version == "1.2.3-beta.1+exp.sha.5114f85"


def test_default_probe_adds_standard_macos_desktop_location(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path_directory = tmp_path / "path-bin"
    desktop_directory = tmp_path / "desktop"
    npm_codex = _make_codex(path_directory)
    testing_codex = _make_codex(path_directory, executable_name="codex-testing")
    desktop_codex = _make_codex(desktop_directory)
    monkeypatch.setenv("PATH", str(path_directory))
    monkeypatch.setattr(discovery_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        discovery_module,
        "_MACOS_CODEX_DIRECTORIES",
        (str(desktop_directory),),
    )

    result = discover_codex_binaries()

    assert [entry.executable_path for entry in result] == sorted(
        [str(npm_codex), str(testing_codex), str(desktop_codex)]
    )


def test_windows_discovers_store_app_cli_and_one_form_per_path_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path_directory = tmp_path / "windows-path"
    app_resources = tmp_path / "windows-app" / "resources"
    cli_exe = _make_codex(path_directory, executable_name="codex.exe")
    _make_codex(path_directory, executable_name="codex.cmd")
    testing_cmd = _make_codex(path_directory, executable_name="codex-testing.cmd")
    app_cli = _make_codex(app_resources, executable_name="codex.exe")
    monkeypatch.setenv("PATH", str(path_directory))
    monkeypatch.setattr(discovery_module.sys, "platform", "win32")
    monkeypatch.setattr(
        discovery_module,
        "_windows_codex_app_directories",
        lambda: (str(app_resources),),
    )

    result = discover_codex_binaries()

    assert [entry.executable_path for entry in result] == sorted(
        [str(cli_exe), str(testing_cmd), str(app_cli)]
    )


def test_linux_discovers_cli_and_testing_wrapper_with_same_selection_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path_directory = tmp_path / "linux-path"
    cli = _make_codex(path_directory)
    testing = _make_codex(path_directory, executable_name="codex-testing")
    monkeypatch.setenv("PATH", str(path_directory))
    monkeypatch.setattr(discovery_module.sys, "platform", "linux")

    result = discover_codex_binaries()

    assert [entry.executable_path for entry in result] == sorted([str(cli), str(testing)])


def test_non_executable_candidate_is_skipped(tmp_path: Path) -> None:
    binary = _make_codex(tmp_path / "bin", executable=False)
    probe = _Probe((str(binary.parent),), {})
    assert discover_codex_binaries(_probe=probe) == ()


def test_discovery_never_mutates_the_candidate(tmp_path: Path) -> None:
    binary = _make_codex(tmp_path / "bin")
    before = binary.read_bytes(), stat.S_IMODE(binary.stat().st_mode)
    probe = _Probe((str(binary.parent),), {})
    discover_codex_binaries(_probe=probe)
    assert (binary.read_bytes(), stat.S_IMODE(binary.stat().st_mode)) == before


def test_default_codex_home_prefers_codex_home_then_the_dotfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    explicit = tmp_path / "explicit-codex"
    explicit.mkdir()

    def fake_home(cls: type[Path]) -> Path:
        return home

    monkeypatch.setattr(Path, "home", classmethod(fake_home))

    assert discovery_module.default_codex_home({"CODEX_HOME": str(explicit)}) == explicit
    assert discovery_module.default_codex_home({}) == home / ".codex"


def test_default_codex_home_is_only_ever_an_existing_owner_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()

    def fake_home(cls: type[Path]) -> Path:
        return home

    monkeypatch.setattr(Path, "home", classmethod(fake_home))

    # Nothing exists: the caller asks instead of inventing a home.
    assert discovery_module.default_codex_home({}) is None
    # A CODEX_HOME that does not exist falls through to the dotfile, not to a guess.
    (home / ".codex").mkdir()
    assert discovery_module.default_codex_home({"CODEX_HOME": str(tmp_path / "missing")}) == (
        home / ".codex"
    )
    # A symlinked home is never offered.
    link = tmp_path / "link"
    link.symlink_to(home / ".codex")
    assert discovery_module.default_codex_home({"CODEX_HOME": str(link)}) == home / ".codex"


def test_default_codex_home_treats_an_unresolvable_home_as_no_offer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_home(cls: type[Path]) -> Path:
        raise RuntimeError("Could not determine home directory.")

    def no_expansion(self: Path) -> Path:
        if str(self).startswith("~"):
            raise RuntimeError("Could not determine home directory.")
        return self

    monkeypatch.setattr(Path, "home", classmethod(no_home))
    monkeypatch.setattr(Path, "expanduser", no_expansion)
    explicit = tmp_path / "explicit-codex"
    explicit.mkdir()

    assert discovery_module.default_codex_home({}) is None
    assert discovery_module.default_codex_home({"CODEX_HOME": "~/.codex"}) is None
    # An absolute CODEX_HOME still wins even when the home directory cannot be resolved.
    assert discovery_module.default_codex_home({"CODEX_HOME": str(explicit)}) == explicit
