"""Task inputs as text or FinishUP's own summary, and the admitted outside-workspace read (#1082)."""

from __future__ import annotations

import os
import struct
import subprocess
from pathlib import Path

import pytest

from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.adapters.task_input_read import (
    MAX_TASK_INPUT_READ_BYTES,
    read_outside_inputs,
    task_input_from_bytes,
    task_input_from_ends,
)
from finishup.ports.change_capture import (
    MAX_TASK_INPUT_TEXT_BYTES,
    decode_check_change,
    encode_check_change,
)

_PNG = (
    b"\x89PNG\r\n\x1a\n"
    + struct.pack(">I", 13)
    + b"IHDR"
    + struct.pack(">IIBBBBB", 640, 480, 8, 2, 0, 0, 0)
    + b"\x00\x00\x00\x00"
)


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", os.fspath(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    ).stdout


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "test@example.invalid")
    _git(repository, "config", "user.name", "Test")
    (repository / "README.md").write_text("readme\n", encoding="utf-8")
    _git(repository, "add", "--", "README.md")
    _git(repository, "commit", "-q", "-m", "init")
    return repository


def test_binary_bytes_become_a_summary_and_text_stays_text() -> None:
    image = task_input_from_bytes("figures/plot.png", _PNG)
    assert image is not None and image.summary and image.origin == "task"
    assert image.size == len(_PNG)
    assert b"format: PNG image" in image.text and b"dimensions: 640x480" in image.text
    assert _PNG not in image.text

    text = task_input_from_bytes("DESIGN.md", b"# Design\n")
    assert text is not None and not text.summary and text.text == b"# Design\n"


def test_a_file_too_large_to_read_whole_keeps_its_two_ends_or_a_summary() -> None:
    size = MAX_TASK_INPUT_READ_BYTES * 3
    head = b"id,value\n" + b"1,2\n" * 1000
    tail = b"9999,LAST_ROW_MARKER\n"
    rows = task_input_from_ends("data/big.csv", head, tail, size)
    assert rows is not None and not rows.summary
    assert rows.size == size and len(rows.text) <= MAX_TASK_INPUT_TEXT_BYTES
    assert rows.text.startswith(b"id,value\n") and rows.text.endswith(b"LAST_ROW_MARKER\n")
    assert b"bytes elided here; head and tail kept]" in rows.text

    blob = task_input_from_ends("data/big.bin", b"\x00\x01" * 100, b"", size)
    assert blob is not None and blob.summary and f"size: {size} bytes".encode() in blob.text


def test_the_repository_read_summarizes_a_binary_and_a_large_untracked_input(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    (repository / "figures").mkdir()
    (repository / "figures" / "plot.png").write_bytes(_PNG)
    _git(repository, "add", "--", "figures/plot.png")
    _git(repository, "commit", "-q", "-m", "figure")
    big = b"id,value\n" + b"1,2\n" * (MAX_TASK_INPUT_READ_BYTES // 4 + 10) + b"END_MARKER\n"
    (repository / "big.csv").write_bytes(big)
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    (repository / "solution.py").write_text("print(1)\n", encoding="utf-8")

    capture = adapter.capture(
        os.fspath(repository), base, input_paths=("figures/plot.png", "big.csv")
    )

    plot, rows = capture.inputs
    assert plot.path == "figures/plot.png" and plot.summary
    assert b"dimensions: 640x480" in plot.text
    assert rows.path == "big.csv" and not rows.summary and rows.size == len(big)
    assert rows.text.endswith(b"END_MARKER\n")
    assert decode_check_change(encode_check_change(capture)) == capture


@pytest.fixture
def shared(tmp_path: Path) -> Path:
    root = (tmp_path / "shared").resolve()
    (root / "legacy_app" / "forms").mkdir(parents=True)
    (root / "legacy_app" / "Module1.bas").write_text("Sub Main()\nEnd Sub\n", encoding="utf-8")
    (root / "legacy_app" / "forms" / "Form1.frm").write_text("FORM_MARKER\n", encoding="utf-8")
    (root / "legacy_app" / ".env").write_text("TOKEN=hidden\n", encoding="utf-8")
    (root / "legacy_app" / "secrets.pem").write_text("not a key\n", encoding="utf-8")
    (root / "spec.md").write_text("SPEC_MARKER\n", encoding="utf-8")
    (root / "scan.png").write_bytes(_PNG)
    return root


def test_outside_inputs_are_read_only_beneath_an_admitted_root(
    shared: Path, tmp_path: Path
) -> None:
    other = tmp_path / "other.md"
    other.write_text("OUTSIDE_ROOT_MARKER\n", encoding="utf-8")
    root = os.fspath(shared)

    inputs = read_outside_inputs(
        (root,),
        (
            f"{root}/spec.md",
            os.fspath(other),  # not beneath an admitted root
            f"{root}/../other.md",  # normalizes outside the root
            f"{root}/legacy_app/.env",  # hidden
            f"{root}/legacy_app/secrets.pem",  # credential-named
            f"{root}/missing.md",
            f"{root}/scan.png",
        ),
        limit=4,
    )

    assert [item.path for item in inputs] == [f"{root}/spec.md", f"{root}/scan.png"]
    spec, scan = inputs
    assert spec.origin == "outside_workspace" and spec.text == b"SPEC_MARKER\n"
    assert scan.summary and b"format: PNG image" in scan.text
    joined = b"".join(item.text for item in inputs)
    assert b"OUTSIDE_ROOT_MARKER" not in joined and b"hidden" not in joined


def test_a_named_directory_offers_its_visible_files_in_order(shared: Path) -> None:
    root = os.fspath(shared)

    inputs = read_outside_inputs((root,), (f"{root}/legacy_app/",), limit=4)

    assert [item.path for item in inputs] == [
        f"{root}/legacy_app/Module1.bas",
        f"{root}/legacy_app/forms/Form1.frm",
    ]
    assert read_outside_inputs((root,), (f"{root}/legacy_app/",), limit=1)[0].path.endswith(
        "Module1.bas"
    )


def test_links_and_unsafe_roots_admit_nothing(shared: Path, tmp_path: Path) -> None:
    root = os.fspath(shared)
    target = tmp_path / "target.md"
    target.write_text("LINK_TARGET_MARKER\n", encoding="utf-8")
    (shared / "link.md").symlink_to(target)
    (shared / "linked_dir").symlink_to(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(shared)
    writable = shared / "writable.md"
    writable.write_text("WRITABLE_MARKER\n", encoding="utf-8")
    writable.chmod(0o666)

    assert read_outside_inputs((root,), (f"{root}/link.md",)) == ()
    assert read_outside_inputs((root,), (f"{root}/linked_dir/target.md",)) == ()
    assert read_outside_inputs((root,), (f"{root}/writable.md",)) == ()
    # A root reached through a link, or one the domain refuses, admits nothing.
    assert read_outside_inputs((os.fspath(alias),), (f"{alias}/spec.md",)) == ()
    assert read_outside_inputs(("/etc",), ("/etc/hosts",)) == ()
    assert read_outside_inputs((), (f"{root}/spec.md",)) == ()
