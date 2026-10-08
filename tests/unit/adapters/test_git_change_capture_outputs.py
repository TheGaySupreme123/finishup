"""Declared deliverables are rendered first in the check-time change (tb4n2 R7, P1-11, #1016)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

import yoetz.adapters.git_change_capture as capture_module
from yoetz.adapters.git_change_capture import GitChangeCaptureAdapter
from yoetz.ports.change_capture import CheckChangeCapture


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", *arguments),
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
    return completed.stdout.decode("utf-8")


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    (repository / "selectors.ts").write_text("export const base = 1;\n", encoding="utf-8")
    _git(repository, "add", "--", "selectors.ts")
    _git(
        repository,
        "-c",
        "user.name=Yoetz Test",
        "-c",
        "user.email=yoetz@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "baseline",
    )
    return repository


@pytest.fixture(autouse=True)
def isolated_global_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)


def _text(capture: CheckChangeCapture) -> str:
    return capture.text.decode("utf-8")


def test_declared_deliverables_and_small_files_are_rendered_before_scratch(
    tmp_path: Path,
) -> None:
    # tb4n2 interleaved-vigenere S (L457): a 12-byte requirements.txt and the cracker were clipped
    # behind scratch files. Declared deliverables come first, then small files, then the rest.
    repository = _repository(tmp_path)
    for index in range(40):
        (repository / f"a_scratch_{index:02d}.txt").write_text(
            "".join(f"scratch {index} row {row}\n" for row in range(400)), encoding="utf-8"
        )
    (repository / "requirements.txt").write_text("numpy==2.1\n", encoding="utf-8")
    (repository / "solution").mkdir()
    (repository / "solution" / "cracker.py").write_text(
        "".join(f"KEY_{row} = {row}\n" for row in range(600)), encoding="utf-8"
    )

    plain = GitChangeCaptureAdapter(_max_text_bytes=64 * 1024).capture(os.fspath(repository), None)
    ordered = GitChangeCaptureAdapter(_max_text_bytes=64 * 1024).capture(
        os.fspath(repository),
        None,
        priority_paths=(os.fspath(repository / "solution"), "/output/elsewhere.json"),
    )

    # Without a declaration the small file still precedes the large scratch files.
    assert "+numpy==2.1" in _text(plain)
    assert "+KEY_599 = 599" not in _text(plain)
    text = _text(ordered)
    assert ordered.truncated
    assert "+KEY_599 = 599" in text and "+numpy==2.1" in text
    body = text.split("End of header. The unified diff follows.\n", 1)[1]
    assert (
        body.index("b/solution/cracker.py")
        < body.index("b/requirements.txt")
        < body.index("b/a_scratch_00.txt")
    )


def test_declared_deliverable_is_read_ahead_of_the_untracked_file_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    for index in range(10):
        (repository / f"a_{index}.txt").write_text(f"row {index}\n", encoding="utf-8")
    (repository / "z_deliverable.py").write_text("print('deliver')\n", encoding="utf-8")
    monkeypatch.setattr(capture_module, "_MAX_UNTRACKED_FILES", 3)

    capture = GitChangeCaptureAdapter().capture(
        os.fspath(repository), None, priority_paths=("z_deliverable.py",)
    )

    text = _text(capture)
    assert "+print('deliver')" in text
    assert capture.untracked_files == 11


def test_priority_paths_outside_the_root_or_the_root_itself_order_nothing(tmp_path: Path) -> None:
    priority_paths: Any = getattr(capture_module, "_priority_paths")
    prioritised: Any = getattr(capture_module, "_prioritised")
    root = tmp_path / "repo"
    assert priority_paths(root, (os.fspath(root), "/output/x.json", "../up")) == ()
    assert priority_paths(root, ("b/c.py", os.fspath(root / "a"), "b/c.py")) == (
        b"a",
        b"b/c.py",
    )
    assert prioritised(b"a/x.py", (b"a",))
    assert not prioritised(b"ab/x.py", (b"a",))
