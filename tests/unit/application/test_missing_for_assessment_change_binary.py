"""Suffix-less binaries read from a real check-time change capture (tb4n2 A11)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from yoetz.adapters.git_change_capture import GitChangeCaptureAdapter
from yoetz.application.missing_for_assessment import check_change_binary_paths


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        (
            "git",
            "-c",
            "user.name=Yoetz Test",
            "-c",
            "user.email=yoetz@example.invalid",
            *arguments,
        ),
        cwd=repository,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        env={
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": os.fspath(repository),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
        },
    )


@pytest.fixture(autouse=True)
def isolated_global_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)


def test_git_marked_binaries_without_a_suffix_are_found_in_a_real_capture(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    (repository / "bin").mkdir()
    (repository / "bin" / "firmware").write_bytes(b"\x7fFW\0\0\x01")
    (repository / "notes.txt").write_text("baseline\n", encoding="utf-8")
    _git(repository, "add", "--", "bin/firmware", "notes.txt")
    _git(repository, "commit", "--quiet", "-m", "baseline")
    (repository / "bin" / "firmware").write_bytes(b"\x7fFW\0\0\x02")
    (repository / "notes.txt").write_text("changed\n", encoding="utf-8")
    (repository / "solver").write_bytes(b"\x7fELF\x02\x01\x01\0\0\0\0\0")
    (repository / "Makefile").write_text("all:\n\tcc -o solver solver.c\n", encoding="utf-8")

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    assert check_change_binary_paths(capture) == frozenset({"bin/firmware", "solver"})


def test_git_quoted_non_ascii_binaries_are_decoded(tmp_path: Path) -> None:
    """Codex review round 1: ``core.quotePath=true`` quotes ``résumé``; it is still binary."""

    repository = tmp_path / "repo"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    (repository / "tracked é").write_bytes(b"\x7fELF\0\x01")
    _git(repository, "add", "--", "tracked é")
    _git(repository, "commit", "--quiet", "-m", "baseline")
    (repository / "tracked é").write_bytes(b"\x7fELF\0\x02")
    (repository / "résumé").write_bytes(b"\x7fELF\x02\x01\x01\0\0\0")

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    assert b'"r\\303\\251sum\\303\\251"' in capture.text
    assert check_change_binary_paths(capture) == frozenset({"résumé", "tracked é"})


@pytest.mark.parametrize(
    ("operands", "expected"),
    [
        ('/dev/null and "b/r\\303\\251sum\\303\\251"', ("résumé",)),
        ('"a/x\\ty" and "b/x\\ty"', ("x\ty", "x\ty")),
        ('"a/broken\\9" and "b/broken"', ()),
        ('"a/bad\\377" and /dev/null', ()),
    ],
)
def test_quoted_binary_line_operands(operands: str, expected: tuple[str, ...]) -> None:
    from yoetz.application import missing_for_assessment

    parse = getattr(missing_for_assessment, "_binary_line_paths")
    assert parse(operands) == expected
