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
    priority_tier: Any = getattr(capture_module, "_priority_tier")
    root = tmp_path / "repo"
    assert priority_paths(root, (os.fspath(root), "/output/x.json", "../up")) == ()
    assert priority_paths(root, ("b/c.py", os.fspath(root / "a"), "b/c.py")) == (b"b/c.py", b"a")
    assert priority_tier(b"a/x.py", (b"b", b"a")) == 1
    assert priority_tier(b"ab/x.py", (b"a",)) is None


def test_explicit_outputs_outrank_role_less_requested_files(tmp_path: Path) -> None:
    """Codex review round 1: an unroled ``a_legacy.txt`` must not take an output's budget."""

    repository = _repository(tmp_path)
    (repository / "a_legacy.txt").write_text("legacy\n" * 9_000, encoding="utf-8")
    (repository / "z_result.py").write_text("RESULT = 1\n" * 6_000, encoding="utf-8")

    capture = GitChangeCaptureAdapter(_max_text_bytes=96 * 1024).capture(
        os.fspath(repository), None, priority_paths=("z_result.py", "a_legacy.txt")
    )

    text = _text(capture)
    body = text.split("End of header. The unified diff follows.\n", 1)[1]
    assert body.startswith("diff --git a/z_result.py b/z_result.py")


def test_small_untracked_files_are_read_ahead_of_the_untracked_file_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Codex review round 1: size ranking must govern which untracked files are read at all."""

    repository = _repository(tmp_path)
    for index in range(6):
        (repository / f"a_scratch_{index}.txt").write_text("x" * 9_000 + "\n", encoding="utf-8")
    (repository / "requirements.txt").write_text("numpy==2.1\n", encoding="utf-8")
    monkeypatch.setattr(capture_module, "_MAX_UNTRACKED_FILES", 3)

    text = _text(GitChangeCaptureAdapter().capture(os.fspath(repository), None))

    assert "+numpy==2.1" in text


def _commit_all(repository: Path) -> None:
    _git(repository, "add", "-A")
    _git(
        repository,
        "-c",
        "user.name=Yoetz Test",
        "-c",
        "user.email=yoetz@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "base",
    )


def test_small_tracked_files_take_the_per_file_read_budget_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Codex review round 2: the per-file fallback reads small files before large scratch."""

    repository = _repository(tmp_path)
    for index in range(4):
        (repository / f"a_scratch_{index}.txt").write_text("base\n", encoding="utf-8")
    (repository / "requirements.txt").write_text("numpy==2.0\n", encoding="utf-8")
    _commit_all(repository)
    for index in range(4):
        (repository / f"a_scratch_{index}.txt").write_text(
            "".join(f"row {row}\n" for row in range(500)), encoding="utf-8"
        )
    (repository / "requirements.txt").write_text("numpy==2.1\n", encoding="utf-8")
    monkeypatch.setattr(capture_module, "_WHOLE_DIFF_LIMIT", 1_024)
    monkeypatch.setattr(capture_module, "_MAX_PER_FILE_DIFFS", 2)

    text = _text(GitChangeCaptureAdapter().capture(os.fspath(repository), None))

    assert "+numpy==2.1" in text


def test_object_verification_budget_never_withholds_a_declared_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Codex review round 2: large scratch blobs must not spend a deliverable's verification."""

    repository = _repository(tmp_path)
    for index in range(4):
        (repository / f"a_scratch_{index}.txt").write_text(
            f"{index}\n" + "x" * 12_497 + "\n", encoding="utf-8"
        )
    (repository / "z_output.py").write_text("RESULT = 0\n", encoding="utf-8")
    _commit_all(repository)
    for index in range(4):
        (repository / f"a_scratch_{index}.txt").write_text(
            f"{index} changed\n" + "x" * 12_497 + "\n", encoding="utf-8"
        )
    (repository / "z_output.py").write_text("RESULT = 1\n", encoding="utf-8")
    # Four 12,500-byte scratch base blobs spend the whole budget in path order.
    monkeypatch.setattr(capture_module, "_MAX_TOTAL_VERIFIED_OBJECT_BYTES", 50_000)

    text = _text(
        GitChangeCaptureAdapter().capture(
            os.fspath(repository), None, priority_paths=("z_output.py",)
        )
    )

    assert "+RESULT = 1" in text


# --- Generated, build and minified output ranks last (tb4n5 react-lead-form) ------------------


def _bundle(size: int, lines: int = 46) -> str:
    """Minified build output: ``size`` bytes in ``lines`` very long lines, like a Vite bundle."""

    row = (size // lines) - 1
    return "".join(f"var b{index}=" + "x" * (row - 8) + ";\n" for index in range(lines))


def _source(name: str, size: int) -> str:
    """Ordinary hand-written source: short lines that sum to about ``size`` bytes."""

    return "".join(f"export const {name}_{row} = {row};\n" for row in range(size // 32))


def _body(capture: CheckChangeCapture) -> str:
    return _text(capture).split("End of header. The unified diff follows.\n", 1)[1]


def test_a_built_bundle_ranks_after_the_source_it_was_built_from(tmp_path: Path) -> None:
    """tb4n5 react-lead-form: ``dist/assets/index-*.js`` (145 KB) sorted path-first ahead of
    ``src/lib/leadStore.ts``; the packet carried the bundle's head and never the ledger code."""

    repository = _repository(tmp_path)
    (repository / "dist" / "assets").mkdir(parents=True)
    (repository / "dist" / "assets" / "index-Bxb0DgZR.js").write_text(
        _bundle(145_000), encoding="utf-8"
    )
    (repository / "src" / "lib").mkdir(parents=True)
    (repository / "src" / "lib" / "leadStore.ts").write_text(
        _source("lead", 9_800), encoding="utf-8"
    )
    (repository / "src" / "components").mkdir(parents=True)
    (repository / "src" / "components" / "LeadForm.tsx").write_text(
        _source("form", 4_400), encoding="utf-8"
    )
    (repository / "README.md").write_text("# Leads\n", encoding="utf-8")

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    body = _body(capture)
    # Small files first, then the larger sources smallest first, then the bundle.
    assert (
        body.index("b/README.md")
        < body.index("b/src/components/LeadForm.tsx")
        < body.index("b/src/lib/leadStore.ts")
        < body.index("b/dist/assets/index-Bxb0DgZR.js")
    )
    # Never dropped for being generated: shown, listed and noted in the header.
    header = _text(capture).split("End of header.", 1)[0]
    (listed,) = [line for line in header.split("\n") if "dist/assets/index-Bxb0DgZR.js" in line]
    assert listed.endswith(
        "untracked; generated, build or minified output, placed after the other files"
    )
    assert "src/lib/leadStore.ts" in header
    assert "placed after" not in next(
        line for line in header.split("\n") if "src/lib/leadStore.ts" in line
    )
    assert not capture.truncated


def test_a_declared_build_output_keeps_its_first_place(tmp_path: Path) -> None:
    """A requested output under ``dist/`` is the work under review, not incidental output."""

    repository = _repository(tmp_path)
    (repository / "dist").mkdir()
    (repository / "dist" / "bundle.min.js").write_text(_bundle(40_000), encoding="utf-8")
    (repository / "src").mkdir()
    (repository / "src" / "core.ts").write_text(_source("core", 10_000), encoding="utf-8")

    capture = GitChangeCaptureAdapter().capture(
        os.fspath(repository), None, priority_paths=("dist/bundle.min.js",)
    )

    body = _body(capture)
    assert body.startswith("diff --git a/dist/bundle.min.js b/dist/bundle.min.js")
    assert body.index("b/dist/bundle.min.js") < body.index("b/src/core.ts")
    assert "placed after the other files" not in _text(capture)


def test_minified_text_outside_a_build_directory_still_ranks_last(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (repository / "a_vendor.js").write_text(_bundle(50_000, lines=3), encoding="utf-8")
    (repository / "z_core.ts").write_text(_source("core", 10_000), encoding="utf-8")

    body = _body(GitChangeCaptureAdapter().capture(os.fspath(repository), None))

    assert body.index("b/z_core.ts") < body.index("b/a_vendor.js")


def test_larger_files_rank_by_size_so_several_sources_fit_ahead_of_one_large_file(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    (repository / "a_big.py").write_text(_source("big", 60_000), encoding="utf-8")
    (repository / "m_mid.py").write_text(_source("mid", 12_000), encoding="utf-8")
    (repository / "z_small.py").write_text(_source("small", 6_000), encoding="utf-8")

    body = _body(GitChangeCaptureAdapter().capture(os.fspath(repository), None))

    assert body.index("b/z_small.py") < body.index("b/m_mid.py") < body.index("b/a_big.py")


@pytest.mark.parametrize("whole_diff_limit", [None, 1_024])
def test_a_lockfile_change_ranks_after_source_in_both_read_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, whole_diff_limit: int | None
) -> None:
    """Tracked files: the whole diff, and the per-file fallback that reads in rank order."""

    repository = _repository(tmp_path)
    (repository / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")
    (repository / "src").mkdir()
    (repository / "src" / "app.ts").write_text("export const app = 0;\n", encoding="utf-8")
    _commit_all(repository)
    (repository / "package-lock.json").write_text(
        "".join(f'  "node_modules/pkg-{row}": {{"version": "1.0.{row}"}},\n' for row in range(900)),
        encoding="utf-8",
    )
    (repository / "src" / "app.ts").write_text(_source("app", 12_000), encoding="utf-8")
    if whole_diff_limit is not None:
        monkeypatch.setattr(capture_module, "_WHOLE_DIFF_LIMIT", whole_diff_limit)
        # The per-file read budget reaches the source first and the lockfile not at all.
        monkeypatch.setattr(capture_module, "_MAX_PER_FILE_DIFFS", 1)

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    text = _text(capture)
    assert "+export const app_1 = 1;" in text
    header = text.split("End of header.", 1)[0]
    assert "package-lock.json" in header
    if whole_diff_limit is None:
        body = _body(capture)
        assert body.index("b/src/app.ts") < body.index("b/package-lock.json")
    else:
        assert "b/package-lock.json" not in _body(capture)
        assert capture.truncated


def test_generated_output_is_read_after_source_under_the_untracked_file_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "build").mkdir()
    for index in range(4):
        (repository / "build" / f"chunk_{index}.js").write_text("x();\n", encoding="utf-8")
    (repository / "src").mkdir()
    (repository / "src" / "main.py").write_text(_source("main", 9_000), encoding="utf-8")
    monkeypatch.setattr(capture_module, "_MAX_UNTRACKED_FILES", 2)

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    assert "+export const main_1 = 1;" in _text(capture)
    assert capture.untracked_files == 5


def test_generated_path_rules_match_whole_components_and_exact_names() -> None:
    generated: Any = getattr(capture_module, "_generated_path")
    for path in (
        b"dist/assets/index.js",
        b"api/build/x.py",
        b"web/node_modules/a/index.js",
        b"app.min.js",
        b"styles/site.min.css",
        b"app.js.map",
        b"package-lock.json",
        b"sub/uv.lock",
        b"dist/",
    ):
        assert generated(path), path
    for path in (
        b"src/distance.ts",
        b"builder/x.py",
        b"src/build.ts",
        b"docs/roadmap.md",
        b"src/lib/leadStore.ts",
        b"locks/package-lock.json.txt",
    ):
        assert not generated(path), path
