"""Launcher resolution recognizes the deprecated ``yoetz`` spellings (ADR-048)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import finishup
from finishup.adapters.integrations import codex_launcher
from finishup.adapters.integrations import launcher as launcher_module
from finishup.adapters.integrations.launcher import (
    invoked_through_legacy_alias,
    invoking_launcher,
    resolve_finishup_launcher,
)


def _script(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def _site_packages() -> Path:
    return Path(finishup.__file__).resolve().parent.parent


def test_finishup_console_script_binds_itself(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["/opt/bin/finishup", "integrate"])
    assert invoking_launcher() == "/opt/bin/finishup"


def test_alias_binds_the_finishup_script_of_the_same_installation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    alias = _script(tmp_path / "tool/bin/yoetz")
    sibling = _script(tmp_path / "tool/bin/finishup")
    monkeypatch.setattr(sys, "argv", [str(alias), "integrate"])

    assert invoking_launcher() == str(sibling.resolve())


def test_alias_reached_through_the_uv_bin_symlink_binds_the_tool_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    alias = _script(tmp_path / "tools/yoetz/bin/yoetz")
    sibling = _script(tmp_path / "tools/yoetz/bin/finishup")
    linked = tmp_path / "local-bin/yoetz"
    linked.parent.mkdir()
    linked.symlink_to(alias)
    monkeypatch.setattr(sys, "argv", [str(linked), "integrate"])

    assert invoking_launcher() == str(sibling.resolve())


def test_alias_without_a_finishup_script_beside_it_binds_the_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    alias = _script(tmp_path / "bin/yoetz")
    (tmp_path / "bin/finishup").write_text("not executable", encoding="utf-8")
    (tmp_path / "bin/finishup").chmod(0o600)
    monkeypatch.setattr(sys, "argv", [str(alias), "integrate"])

    assert invoking_launcher() == str(alias)


def test_legacy_module_beside_this_package_binds_python_m_finishup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy_main = _site_packages() / "yoetz" / "__main__.py"
    monkeypatch.setattr(sys, "argv", [str(legacy_main), "integrate"])

    assert invoking_launcher() == (sys.executable, "-m", "finishup")


def test_unrelated_legacy_looking_module_binds_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "argv", [str(tmp_path / "other/yoetz/__main__.py"), "integrate"])

    assert invoking_launcher() is None


@pytest.mark.parametrize(
    ("argv0", "legacy"),
    [
        ("/opt/bin/yoetz", True),
        ("yoetz", True),
        ("/opt/site-packages/yoetz/__main__.py", True),
        ("/opt/bin/finishup", False),
        ("/opt/site-packages/finishup/__main__.py", False),
        ("/opt/bin/yoetz-helper", False),
    ],
)
def test_alias_recognition_is_by_spelling(argv0: str, legacy: bool) -> None:
    assert invoked_through_legacy_alias(argv0) is legacy


def test_path_lookup_prefers_finishup_over_the_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finishup_script = _script(tmp_path / "a/finishup")
    alias = _script(tmp_path / "b/yoetz")
    found = {"finishup": str(finishup_script), "yoetz": str(alias)}
    monkeypatch.setattr(launcher_module.shutil, "which", found.get)

    assert resolve_finishup_launcher() == (str(finishup_script.resolve()),)


def _prove(monkeypatch: pytest.MonkeyPatch, *, alias: Path | None, launcher: Path | None) -> None:
    """Stand in for the RECORD proofs of this runtime's ``yoetz`` and ``finishup`` scripts."""

    proofs = {"yoetz": alias, "finishup": launcher}

    def installed_launcher(name: str = "finishup") -> tuple[str, str] | None:
        proven = proofs.get(name)
        return None if proven is None else (str(proven), "sha256:" + "0" * 64)

    monkeypatch.setattr(codex_launcher, "installed_launcher", installed_launcher)


def test_path_lookup_with_only_this_runtimes_alias_binds_its_finishup_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    alias = _script(tmp_path / "tool/bin/yoetz")
    sibling = _script(tmp_path / "tool/bin/finishup")
    _prove(monkeypatch, alias=alias, launcher=sibling)
    found = {"yoetz": str(alias)}
    monkeypatch.setattr(launcher_module.shutil, "which", found.get)

    assert resolve_finishup_launcher() == (str(sibling.resolve()),)


def test_path_lookup_through_the_uv_bin_symlink_binds_this_runtimes_finishup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    alias = _script(tmp_path / "tools/yoetz/bin/yoetz")
    sibling = _script(tmp_path / "tools/yoetz/bin/finishup")
    linked = tmp_path / "local-bin/yoetz"
    linked.parent.mkdir()
    linked.symlink_to(alias)
    _prove(monkeypatch, alias=alias, launcher=sibling)
    found = {"yoetz": str(linked)}
    monkeypatch.setattr(launcher_module.shutil, "which", found.get)

    assert resolve_finishup_launcher() == (str(sibling.resolve()),)


def test_path_lookup_never_binds_a_pre_rename_yoetz(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 0.1-0.2.5 ``yoetz`` tool has no ``finishup`` beside it and is not this runtime."""

    old = _script(tmp_path / "old-tool/bin/yoetz")
    _prove(monkeypatch, alias=None, launcher=None)
    found = {"yoetz": str(old)}
    monkeypatch.setattr(launcher_module.shutil, "which", found.get)

    with pytest.raises(ValueError, match="finishup_executable_unavailable"):
        resolve_finishup_launcher()


def test_path_lookup_never_binds_another_environments_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A transitional alias of a different environment is not this runtime's, sibling or not."""

    other = _script(tmp_path / "other/bin/yoetz")
    _script(tmp_path / "other/bin/finishup")
    alias = _script(tmp_path / "tool/bin/yoetz")
    sibling = _script(tmp_path / "tool/bin/finishup")
    _prove(monkeypatch, alias=alias, launcher=sibling)
    found = {"yoetz": str(other)}
    monkeypatch.setattr(launcher_module.shutil, "which", found.get)

    with pytest.raises(ValueError, match="finishup_executable_unavailable"):
        resolve_finishup_launcher()


@pytest.mark.parametrize("missing", ["alias", "launcher", "split"])
def test_path_lookup_needs_both_record_proofs_in_one_scripts_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    alias = _script(tmp_path / "tool/bin/yoetz")
    sibling = _script(tmp_path / "tool/bin/finishup")
    elsewhere = _script(tmp_path / "elsewhere/bin/finishup")
    proofs = {
        "alias": {"alias": None, "launcher": sibling},
        "launcher": {"alias": alias, "launcher": None},
        "split": {"alias": alias, "launcher": elsewhere},
    }[missing]
    _prove(monkeypatch, **proofs)
    found = {"yoetz": str(alias)}
    monkeypatch.setattr(launcher_module.shutil, "which", found.get)

    with pytest.raises(ValueError, match="finishup_executable_unavailable"):
        resolve_finishup_launcher()


def test_path_lookup_without_an_installed_alias_record_stays_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unmocked: this checkout installs no transitional ``yoetz`` distribution, so no proof."""

    alias = _script(tmp_path / "bin/yoetz")
    _script(tmp_path / "bin/finishup")
    found = {"yoetz": str(alias)}
    monkeypatch.setattr(launcher_module.shutil, "which", found.get)

    with pytest.raises(ValueError, match="finishup_executable_unavailable"):
        resolve_finishup_launcher()


def test_path_lookup_with_neither_name_stays_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    found: dict[str, str] = {}
    monkeypatch.setattr(launcher_module.shutil, "which", found.get)

    with pytest.raises(ValueError, match="finishup_executable_unavailable"):
        resolve_finishup_launcher()


def test_explicit_legacy_module_invocation_is_kept_verbatim(tmp_path: Path) -> None:
    python = _script(tmp_path / "bin/python")

    assert resolve_finishup_launcher((str(python), "-m", "yoetz")) == (
        str(python.resolve()),
        "-m",
        "yoetz",
    )
