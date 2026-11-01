"""A declared test file is refused in HOME's private state and system trees by identity (#1220).

PR #1221 review (P1): the HOME guard compared spellings, so on a case-insensitive volume
``/Users/<ALICE>/Library/report.txt`` (HOME ``/Users/<alice>``) skipped it. The read now finds HOME
and the system directories among the path's ancestors by device and inode. Another spelling of
the same directory is simulated with a link the guard resolves (HOME, a system directory), since
the test volume may be case-sensitive; the real alternate-case spelling runs where it is not.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import finishup.adapters.task_input_read as task_input_read
from finishup.adapters.home_project_reads import home_private_location
from finishup.adapters.task_input_read import read_declared_test

_TEXT = "assert expected() == 4\n"


def _file(path: Path, text: str = _TEXT) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(text)
    path.chmod(0o600)
    return path


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    real = tmp_path.resolve() / "Alice"
    real.mkdir(mode=0o700)
    # HOME names the same directory by another spelling than the one the read uses.
    alias = tmp_path.resolve() / "alice-alias"
    alias.symlink_to(real)
    monkeypatch.setenv("HOME", str(alias))
    assert Path.home() == alias
    return real


def test_a_private_tree_under_another_spelling_of_home_is_refused(home: Path) -> None:
    report = _file(home / "Library" / "report.txt")
    # Before the fix the spelling did not start with HOME, so the private-tree rule never ran.
    assert not str(report).startswith(str(Path.home()) + "/")
    assert home_private_location(str(report))
    assert read_declared_test(str(report), excluded=()) is None


def test_an_ordinary_project_file_under_home_is_still_readable(home: Path) -> None:
    test = _file(home / "project" / "tests" / "test_x.py")
    assert not home_private_location(str(test))
    assert read_declared_test(str(test), excluded=()) == _TEXT.encode()


def test_a_link_into_a_private_tree_is_never_followed(home: Path, tmp_path: Path) -> None:
    _file(home / "Library" / "report.txt")
    link = tmp_path.resolve() / "scratch"
    link.symlink_to(home / "Library")
    assert read_declared_test(str(link / "report.txt"), excluded=()) is None


def _case_insensitive(directory: Path) -> bool:
    probe = directory / "CaseProbe"
    probe.mkdir()
    try:
        return (directory / "caseprobe").exists()
    finally:
        probe.rmdir()


def test_an_alternate_case_home_spelling_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = tmp_path.resolve()
    if not _case_insensitive(base):
        pytest.skip("needs a case-insensitive volume; the alias test covers the identity rule")
    home = base / "alice"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    _file(home / "Library" / "report.txt")
    _file(home / "backup" / "Library" / "keys.txt")
    upper = base / "ALICE" / "Library" / "report.txt"
    assert read_declared_test(str(upper), excluded=()) is None
    # A copied private tree below the top, spelled in another case, is the same directory.
    folded = base / "ALICE" / "backup" / "library" / "keys.txt"
    assert home_private_location(str(folded))
    assert read_declared_test(str(folded), excluded=()) is None


def test_a_system_directory_under_another_spelling_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = tmp_path.resolve() / "system"
    data = _file(real / "hosts.txt")
    alias = tmp_path.resolve() / "SYSTEM-alias"
    alias.symlink_to(real)
    # The refused directory is named by a spelling the read never uses; identity still matches.
    monkeypatch.setattr(task_input_read, "SYSTEM_DIRECTORY_PREFIXES", (str(alias),))
    assert read_declared_test(str(data), excluded=()) is None
    monkeypatch.setattr(task_input_read, "SYSTEM_DIRECTORY_PREFIXES", ())
    assert read_declared_test(str(data), excluded=()) == _TEXT.encode()


def test_an_unexaminable_ancestor_refuses(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    test = _file(home / "project" / "test_x.py")
    original = os.lstat
    above_home = str(tmp_path.resolve())  # an ancestor above HOME

    def refusing(path: str | os.PathLike[str], *args: object, **kwargs: object) -> os.stat_result:
        if str(path) == above_home:
            raise PermissionError("denied")
        return original(path, *args, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(os, "lstat", refusing)
    assert home_private_location(str(test))
