"""Check-time change capture from a real local Git workspace (ADR-031, issue #883)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

import yoetz.adapters.git_change_capture as capture_module
from yoetz.adapters.git_change_capture import GitChangeCaptureAdapter
from yoetz.kernel.test_edit_visibility import preexisting_test_edits
from yoetz.ports.change_capture import (
    ChangeCaptureUnavailable,
    CheckChangeCapture,
    CheckChangeMetadata,
    TaskChangeBase,
    decode_check_change,
    decode_task_change_base,
    encode_check_change,
    encode_task_change_base,
    metadata_path_representable,
)

_EMPTY_SHA1_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


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


def _commit(repository: Path, message: str) -> None:
    _git(
        repository,
        "-c",
        "user.name=Yoetz Test",
        "-c",
        "user.email=yoetz@example.invalid",
        "commit",
        "--quiet",
        "-am",
        message,
    )


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    (repository / "selectors.ts").write_text(
        "export function key(value: number | string) {\n  return String(value);\n}\n",
        encoding="utf-8",
    )
    (repository / ".gitignore").write_text("local.env\nbuild/\n", encoding="utf-8")
    _git(repository, "add", "--", "selectors.ts", ".gitignore")
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
    # The capture honours the owner's global ignore file; keep the test runner's own out of it.
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)


def _text(capture: CheckChangeCapture) -> str:
    return capture.text.decode("utf-8")


def test_script_rewrite_without_any_edit_tool_is_captured_against_the_task_base(
    tmp_path: Path,
) -> None:
    """kea shape: a shell Python rewrite and a commit, no ``apply_patch`` anywhere."""

    repository = _repository(tmp_path)
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    assert base.object_format == "sha1"

    target = repository / "selectors.ts"
    target.write_text(
        target.read_text(encoding="utf-8").replace(
            "return String(value);", "return typeof value + ':' + String(value);"
        ),
        encoding="utf-8",
    )
    _commit(repository, "agent commit")
    (repository / "notes.md").write_text("follow-up\n", encoding="utf-8")

    capture = adapter.capture(os.fspath(repository), base)

    assert capture.base == "task_start"
    assert (capture.tracked_files, capture.untracked_files, capture.omitted_files) == (1, 1, 0)
    assert not capture.truncated
    text = _text(capture)
    assert text.startswith("Yoetz check-time change: captured by the Yoetz service")
    assert "Base: the commit HEAD named when this task started." in text
    assert "-  return String(value);" in text
    assert "+  return typeof value + ':' + String(value);" in text
    assert "diff --git a/notes.md b/notes.md" in text and "+follow-up" in text
    assert "  M selectors.ts (+1 -1)" in text
    assert "  A notes.md (+1 -0) untracked" in text


def test_real_capture_reduces_a_preexisting_test_edit_to_structural_counts(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    tests_dir = repository / "tests"
    tests_dir.mkdir()
    test_file = tests_dir / "test_existing.py"
    test_file.write_text("def test_existing():\n    assert 1 == 1\n", encoding="utf-8")
    _git(repository, "add", "--", "tests/test_existing.py")
    _commit(repository, "add existing test")
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    test_file.write_text("def test_existing():\n    assert 1 == 2\n", encoding="utf-8")

    capture = adapter.capture(os.fspath(repository), base)
    facts = preexisting_test_edits(capture)

    assert facts.modified == 1
    assert facts.renamed == facts.deleted == facts.skipped == 0
    assert facts.gaps == ("preexisting_test_modified",)


def test_metadata_capture_lists_test_paths_without_reading_file_content(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    tests_dir = repository / "tests"
    tests_dir.mkdir()
    test_file = tests_dir / "test_existing.py"
    test_file.write_text("def test_existing():\n    assert 1 == 1\n", encoding="utf-8")
    _git(repository, "add", "--", "tests/test_existing.py")
    _commit(repository, "add existing test")
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    test_file.write_text("SECRET_METADATA_CANARY\n", encoding="utf-8")

    metadata = adapter.capture_metadata(os.fspath(repository), base)

    assert type(metadata) is CheckChangeMetadata
    assert metadata.base == "task_start"
    assert [(entry.status, entry.path) for entry in metadata.entries] == [
        ("M", "tests/test_existing.py")
    ]
    assert "SECRET_METADATA_CANARY" not in repr(metadata)


def test_real_capture_handles_a_test_path_containing_git_header_delimiter_bytes(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    test_file = repository / "tests" / "foo b"
    test_file.mkdir(parents=True)
    test_file = test_file / "test.js"
    test_file.write_text("it('works', fn)\n", encoding="utf-8")
    _git(repository, "add", "--", "tests/foo b/test.js")
    _commit(repository, "add existing js test")
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    test_file.write_text("it.skip('works', fn)\n", encoding="utf-8")

    capture = adapter.capture(os.fspath(repository), base)
    facts = preexisting_test_edits(capture)

    assert "  M tests/foo b/test.js" in _text(capture)
    assert facts.modified == 1
    assert facts.skipped == 1


def test_real_capture_marks_a_git_rename_for_structural_test_accounting(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    tests_dir = repository / "tests"
    tests_dir.mkdir()
    old_file = tests_dir / "test_existing.py"
    old_file.write_text("def test_existing():\n    assert 1 == 1\n", encoding="utf-8")
    _git(repository, "add", "--", "tests/test_existing.py")
    _commit(repository, "add existing test")
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    _git(repository, "mv", "--", "tests/test_existing.py", "tests/test_renamed.py")

    capture = adapter.capture(os.fspath(repository), base)
    facts = preexisting_test_edits(capture)
    metadata = adapter.capture_metadata(os.fspath(repository), base)

    assert "  R tests/test_renamed.py" in _text(capture)
    assert facts.renamed == 1
    assert facts.modified == facts.deleted == facts.skipped == 0
    assert [(entry.status, entry.original_path, entry.path) for entry in metadata.entries] == [
        ("R", "tests/test_existing.py", "tests/test_renamed.py")
    ]


def test_without_a_recorded_base_the_change_is_against_head_and_says_so(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    adapter = GitChangeCaptureAdapter()
    target = repository / "selectors.ts"
    target.write_text("export const committed = 1;\n", encoding="utf-8")
    _commit(repository, "agent commit")
    target.write_text("export const committed = 2;\n", encoding="utf-8")

    capture = adapter.capture(os.fspath(repository), None)

    assert capture.base == "head"
    text = _text(capture)
    assert "commits made during the task may be missing" in text
    assert "-export const committed = 1;" in text
    assert "+export const committed = 2;" in text
    assert "return String(value)" not in text


def test_unresolvable_base_falls_back_to_head(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    missing = TaskChangeBase("sha1", "0" * 40)

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), missing)

    assert capture.base == "head"
    assert "Changed files: none. The working tree matches the base." in _text(capture)


def test_ignored_and_globally_ignored_files_are_never_read(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (repository / "local.env").write_text("API_TOKEN=repo-ignored-canary\n", encoding="utf-8")
    (repository / "build").mkdir()
    (repository / "build" / "out.js").write_text("build-canary\n", encoding="utf-8")
    global_ignore = Path(os.environ["HOME"]) / ".config" / "git" / "ignore"
    global_ignore.parent.mkdir(parents=True)
    global_ignore.write_text("*.secret\n", encoding="utf-8")
    (repository / "owner.secret").write_text("global-ignore-canary\n", encoding="utf-8")
    (repository / "kept.txt").write_text("kept\n", encoding="utf-8")

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    text = _text(capture)
    assert "+kept" in text
    for canary in ("repo-ignored-canary", "build-canary", "global-ignore-canary"):
        assert canary not in text
    assert "local.env" not in text and "owner.secret" not in text
    assert capture.untracked_files == 1


def test_links_are_named_but_never_followed(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("outside-canary\n", encoding="utf-8")
    os.symlink(outside / "private.txt", repository / "link.txt")
    os.link(outside / "private.txt", repository / "hardlink.txt")

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    text = _text(capture)
    assert "outside-canary" not in text
    assert "  A link.txt untracked; not shown: links, special files" in text
    assert "  A hardlink.txt untracked; not shown: links, special files" in text
    assert capture.omitted_files == 2 and capture.truncated


def test_oversized_files_are_left_out_whole_and_the_rest_is_still_shown(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    # Over the per-file read bound (232 KiB since issue #983), so it is named, never read.
    (repository / "a_generated.txt").write_text("x" * 300_000 + "\n", encoding="utf-8")
    (repository / "big.lock").write_text(
        "".join(f"line {index}\n" for index in range(40_000)), encoding="utf-8"
    )
    _git(repository, "add", "--", "big.lock")
    (repository / "z_small.py").write_text("print('kept')\n", encoding="utf-8")

    capture = GitChangeCaptureAdapter(_max_text_bytes=64 * 1024).capture(
        os.fspath(repository), None
    )

    text = _text(capture)
    assert capture.truncated and capture.omitted_files == 2
    assert len(capture.text) <= 64 * 1024
    assert "+print('kept')" in text
    assert "  A a_generated.txt untracked; not shown: too large for this capture" in text
    assert "  A big.lock (+40000 -0) not shown: the capture reached its size" in text
    assert "line 39999" not in text


def test_a_large_new_source_file_is_shown_whole(tmp_path: Path) -> None:
    # Issue #983: a ~140 KiB untracked deliverable was named only above the old 64 KiB read bound.
    repository = _repository(tmp_path)
    source = "".join(f"TABLE_{index} = [{', '.join(['1234'] * 20)}]\n" for index in range(1_100))
    assert 128 * 1024 < len(source) < 160 * 1024
    (repository / "cracker.py").write_text(source, encoding="utf-8")

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    text = _text(capture)
    assert not capture.truncated and capture.omitted_files == 0
    assert "+TABLE_1099 = [" in text
    assert "not shown" not in text


def test_binary_untracked_file_is_described_not_embedded(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (repository / "image.bin").write_bytes(b"\x89PNG\0\0binary-canary")

    text = _text(GitChangeCaptureAdapter().capture(os.fspath(repository), None))

    assert "Binary files /dev/null and b/image.bin differ" in text
    assert "binary-canary" not in text


def test_unborn_repository_starts_from_the_empty_tree(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    adapter = GitChangeCaptureAdapter()

    base = adapter.read_task_base(os.fspath(repository))
    # The task-start snapshot (#1045) holds no untracked file and is complete.
    assert base == TaskChangeBase("sha1", _EMPTY_SHA1_TREE, untracked_complete=True)
    (repository / "first.py").write_text("print(1)\n", encoding="utf-8")
    _git(repository, "add", "--", "first.py")
    _commit(repository, "first commit")
    (repository / "second.py").write_text("print(2)\n", encoding="utf-8")

    capture = adapter.capture(os.fspath(repository), base)

    assert capture.base == "task_start"
    text = _text(capture)
    assert "+print(1)" in text and "+print(2)" in text


def test_subdirectory_locator_captures_the_whole_repository(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    nested = repository / "pkg"
    nested.mkdir()
    (repository / "selectors.ts").write_text("export const root = true;\n", encoding="utf-8")

    capture = GitChangeCaptureAdapter().capture(os.fspath(nested), None)

    assert "+export const root = true;" in _text(capture)


def test_partial_clone_is_refused_rather_than_fetched(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    _git(repository, "config", "remote.origin.promisor", "true")

    with pytest.raises(ChangeCaptureUnavailable) as caught:
        GitChangeCaptureAdapter().capture(os.fspath(repository), None)
    assert caught.value.reason == "unsupported_repository"


def test_plain_directory_is_not_git(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir(mode=0o700)

    with pytest.raises(ChangeCaptureUnavailable) as caught:
        GitChangeCaptureAdapter().capture(os.fspath(plain), None)
    assert caught.value.reason == "not_git"


def test_capture_round_trips_through_its_object_encoding(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (repository / "selectors.ts").write_text("export const é = 'ü';\n", encoding="utf-8")
    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    assert decode_check_change(encode_check_change(capture)) == capture


@pytest.mark.parametrize("placement", ["worktree_config", "two_sections_one_line", "include"])
def test_filter_driver_hidden_from_the_lexical_fence_is_refused_and_never_run(
    tmp_path: Path, placement: str
) -> None:
    repository = _repository(tmp_path)
    (repository / ".gitattributes").write_text("*.ts filter=probe\n", encoding="utf-8")
    marker = tmp_path / "filter-ran"
    driver = f'[filter "probe"]\n\tclean = "touch {marker}; cat"\n'
    config = repository / ".git" / "config"
    if placement == "worktree_config":
        _git(repository, "config", "extensions.worktreeConfig", "true")
        (repository / ".git" / "config.worktree").write_text(driver, encoding="utf-8")
    elif placement == "two_sections_one_line":
        with config.open("a", encoding="utf-8") as handle:
            handle.write("[core]" + driver)
    else:
        included = tmp_path / "included.cfg"
        included.write_text(driver, encoding="utf-8")
        _git(repository, "config", "extensions.worktreeConfig", "true")
        (repository / ".git" / "config.worktree").write_text(
            f"[include]\n\tpath = {included}\n", encoding="utf-8"
        )
    (repository / "selectors.ts").write_text("export const changed = 1;\n", encoding="utf-8")

    with pytest.raises(ChangeCaptureUnavailable) as raised:
        GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    assert raised.value.reason in {"unsupported_repository", "unsafe_root"}
    assert not marker.exists()


def test_repository_excludes_file_and_included_global_ignore_are_honoured(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    local_ignore = repository / ".git" / "local-ignore"
    local_ignore.write_text("owner-notes.txt\n", encoding="utf-8")
    _git(repository, "config", "core.excludesFile", os.fspath(local_ignore))
    (repository / "owner-notes.txt").write_text("repository-ignored words\n", encoding="utf-8")

    home = Path(os.environ["HOME"])
    (home / "global-ignore").write_text("personal.txt\n", encoding="utf-8")
    (home / "extra.gitconfig").write_text(
        f"[core]\n\texcludesFile = {home / 'global-ignore'}\n", encoding="utf-8"
    )
    (home / ".gitconfig").write_text(
        f"[include]\n\tpath = {home / 'extra.gitconfig'}\n", encoding="utf-8"
    )
    (tmp_path / "other").mkdir()
    other = _repository(tmp_path / "other")
    (other / "personal.txt").write_text("globally ignored words\n", encoding="utf-8")

    first = _text(GitChangeCaptureAdapter().capture(os.fspath(repository), None))
    second = _text(GitChangeCaptureAdapter().capture(os.fspath(other), None))

    assert "owner-notes.txt" not in first and "repository-ignored words" not in first
    assert "personal.txt" not in second and "globally ignored words" not in second


_NAME_ONLY = "not shown: listed by name only, as for every file named like this"


def test_untracked_credential_files_are_named_but_never_read(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (repository / ".env").write_text("DB_PASS=hunter2hunter2\n", encoding="utf-8")
    (repository / "deploy.pem").write_text("not a marker but still a key\n", encoding="utf-8")

    text = _text(GitChangeCaptureAdapter().capture(os.fspath(repository), None))

    assert "hunter2hunter2" not in text and "still a key" not in text
    assert f".env untracked; {_NAME_ONLY}" in text
    assert f"deploy.pem untracked; {_NAME_ONLY}" in text


def test_tracked_credential_files_are_named_but_their_change_is_never_shown(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    (repository / ".env.production").write_text("DB_PASS=before-before\n", encoding="utf-8")
    _git(repository, "add", "--", ".env.production")
    _commit(repository, "track an env file")
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))

    (repository / ".env.production").write_text("DB_PASS=after-after-after\n", encoding="utf-8")
    (repository / "service.key").write_text("committed key material\n", encoding="utf-8")
    _git(repository, "add", "--", "service.key")
    _commit(repository, "agent commits a key")
    (repository / "selectors.ts").write_text("export const shown = 1;\n", encoding="utf-8")

    capture = adapter.capture(os.fspath(repository), base)
    text = _text(capture)

    for secret in ("before-before", "after-after-after", "committed key material"):
        assert secret not in text
    assert f"M .env.production (+1 -1) {_NAME_ONLY}" in text
    assert f"A service.key (+1 -0) {_NAME_ONLY}" in text
    assert "export const shown = 1;" in text
    assert capture.omitted_files == 2 and capture.truncated


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def monotonic(self) -> float:
        return self.now


def _slow_git(
    monkeypatch: pytest.MonkeyPatch,
    *,
    seconds_per_call: float,
    slow_from_call: int = 0,
    slow_marker: str | None = None,
    seconds_before: float = 0.0,
) -> tuple[_FakeClock, list[float]]:
    """Git calls from ``slow_from_call`` on take ``seconds_per_call`` of a fake clock.

    Earlier calls take ``seconds_before``. With ``slow_marker``, only the calls whose argv holds
    it are slow and every other call takes ``seconds_before``.
    A call whose granted timeout is shorter than that ends the way the hardened runner ends a
    timed-out Git: the clock advances by the timeout and the call fails. Nothing sleeps.
    """

    clock = _FakeClock()
    timeouts: list[float] = []
    real = capture_module.run_read_only_git

    def run(*args: Any, **kwargs: Any) -> tuple[int, bytes]:
        timeout = float(kwargs["timeout_seconds"])
        timeouts.append(timeout)
        if slow_marker is not None:
            slow = slow_marker in args[1]
        else:
            slow = len(timeouts) > slow_from_call
        seconds = seconds_per_call if slow else seconds_before
        if timeout < seconds:
            clock.now += timeout
            raise ValueError("git_failed")
        clock.now += seconds
        return real(*args, **kwargs)

    monkeypatch.setattr(capture_module, "time", clock)
    monkeypatch.setattr(capture_module, "run_read_only_git", run)
    return clock, timeouts


def test_slow_git_makes_the_capture_unavailable_within_its_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "selectors.ts").write_text("export const changed = 1;\n", encoding="utf-8")
    clock, timeouts = _slow_git(monkeypatch, seconds_per_call=6.0)
    started = clock.now

    with pytest.raises(ChangeCaptureUnavailable) as raised:
        GitChangeCaptureAdapter(_deadline_seconds=20.0).capture(os.fspath(repository), None)

    assert raised.value.reason == "git_failed"
    # Each call got at most 10 s and never more than what was left of the assembly share of the
    # 20 s deadline (the rest is kept for the closing stability check).
    assert timeouts[0] == 10.0 and all(timeout <= 10.0 for timeout in timeouts)
    assert timeouts[-1] < 6.0
    assert clock.now - started == pytest.approx(20.0 * getattr(capture_module, "_ASSEMBLY_SHARE"))


def test_deadline_inside_the_diff_lists_every_file_and_shows_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "selectors.ts").write_text("export const changed = 1;\n", encoding="utf-8")
    (repository / "notes.txt").write_text("untracked words\n", encoding="utf-8")
    # Every call before the patch takes 2 s (location check, config, object format, HEAD, the
    # raw list and numstat: 12 s); the patch never ends.
    clock, timeouts = _slow_git(
        monkeypatch, seconds_per_call=60.0, slow_marker="--unified=3", seconds_before=2.0
    )
    started = clock.now

    capture = GitChangeCaptureAdapter(_deadline_seconds=20.0).capture(os.fspath(repository), None)
    text = _text(capture)

    # The patch (the seventh call) got only what was left of the 15 s assembly share; the
    # closing stability check then ran inside the 5 s kept for it.
    assert timeouts[6] == pytest.approx(3.0)
    assert 15.0 < clock.now - started <= 20.0
    assert capture.truncated
    assert (
        "selectors.ts (+1 -3) not shown: the capture reached its size, time or file limit" in text
    )
    assert "export const changed" not in text
    assert "untracked words" not in text and "the untracked count above is a lower bound" in text


def test_git_without_show_scope_fails_closed_before_any_diff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Git older than 2.26 rejects ``--show-scope``; the filter check is never skipped."""

    repository = _repository(tmp_path)
    (repository / "selectors.ts").write_text("export const changed = 1;\n", encoding="utf-8")
    calls: list[tuple[str, ...]] = []
    real = capture_module.run_read_only_git

    def run(handle: Any, arguments: tuple[str, ...], **kwargs: Any) -> tuple[int, bytes]:
        calls.append(arguments)
        if "--show-scope" in arguments:
            raise ValueError("git_failed")  # exit 129: unknown option
        return real(handle, arguments, **kwargs)

    monkeypatch.setattr(capture_module, "run_read_only_git", run)

    with pytest.raises(ChangeCaptureUnavailable) as raised:
        GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    assert raised.value.reason == "git_failed"
    assert not any("diff" in arguments for arguments in calls)


def test_untracked_listing_over_its_limit_lists_what_fits_and_discloses_the_rest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "selectors.ts").write_text("export const changed = 1;\n", encoding="utf-8")
    for index in range(40):
        (repository / f"generated-{index:02d}.txt").write_text(f"row {index}\n", encoding="utf-8")
    monkeypatch.setattr(capture_module, "_LIST_LIMIT", 256)

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)
    text = _text(capture)

    assert capture.truncated
    assert 0 < capture.untracked_files < 40
    assert "export const changed = 1;" in text  # the tracked change is not lost
    assert "+row 0" in text and "generated-39.txt" not in text
    assert "the untracked count above is a lower bound" in text


def test_global_ignore_read_past_the_deadline_makes_the_capture_unavailable() -> None:
    global_excludes_file = getattr(capture_module, "_global_excludes_file")

    with pytest.raises(ChangeCaptureUnavailable) as raised:
        global_excludes_file(0.0)

    assert raised.value.reason == "git_failed"


def test_long_file_listing_never_overruns_the_object_bound(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    deep = repository / ("a" * 60) / ("b" * 60) / ("c" * 60)
    deep.mkdir(parents=True)
    for index in range(100):
        (deep / f"link{index:03d}{'q' * 20}").symlink_to("/dev/null")
    filler = repository / "zz"
    filler.mkdir()
    for index in range(399):
        (filler / f"s{index:03d}").write_text("y" * 700 + "\n", encoding="utf-8")

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)
    text = _text(capture)

    assert capture.truncated
    assert "more changed files are not listed" in text


def test_first_check_base_is_labelled_with_its_commit_and_round_trips(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    adapter = GitChangeCaptureAdapter()
    head = adapter.read_task_base(os.fspath(repository))
    pinned = TaskChangeBase(head.object_format, head.commit, origin="first_check")
    assert decode_task_change_base(encode_task_change_base(pinned)) == pinned
    (repository / "selectors.ts").write_text("export const pinned = 1;\n", encoding="utf-8")
    _commit(repository, "committed after the pin")

    capture = adapter.capture(os.fspath(repository), pinned)
    text = _text(capture)

    assert capture.base == "first_check" and capture.base_commit == head.commit
    assert f"Base: {head.commit[:12]}, the state at this task's first check" in text
    assert "export const pinned = 1;" in text  # committed after the pin, still in the change


# --- R945-03/04/05: a coherent snapshot of the validated repository, with no link read -------


def _loose_object_path(repository: Path, oid: str) -> Path:
    return repository / ".git" / "objects" / oid[:2] / oid[2:]


def _outside_blob(tmp_path: Path, content: str) -> Path:
    """A loose object in a separate repository, holding bytes that are not in the workspace."""

    outside = tmp_path / "outside-repo"
    outside.mkdir(mode=0o700)
    _git(outside, "init", "--quiet")
    (outside / "secret.txt").write_text(content, encoding="utf-8")
    oid = _git(outside, "hash-object", "-w", "--", "secret.txt").strip()
    return _loose_object_path(outside, oid)


def test_tracked_file_replaced_by_a_hard_link_is_named_but_never_shown(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (repository / "tracked.txt").write_text("tracked base\n", encoding="utf-8")
    _git(repository, "add", "--", "tracked.txt")
    _commit(repository, "track a file")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("OUTSIDE HARDLINK SECRET\n", encoding="utf-8")
    (repository / "tracked.txt").unlink()
    os.link(outside / "private.txt", repository / "tracked.txt")
    (repository / "selectors.ts").write_text("export const shown = 1;\n", encoding="utf-8")

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)
    text = _text(capture)

    assert "OUTSIDE HARDLINK SECRET" not in text
    assert "  M tracked.txt not shown: links, special files and multiply linked" in text
    assert "export const shown = 1;" in text
    assert capture.omitted_files == 1 and capture.truncated


def test_tracked_file_replaced_by_a_symlink_is_named_but_never_shown(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("outside-canary\n", encoding="utf-8")
    (repository / "selectors.ts").unlink()
    os.symlink(outside / "private.txt", repository / "selectors.ts")

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)
    text = _text(capture)

    assert "outside-canary" not in text and os.fspath(outside) not in text
    assert "selectors.ts not shown: links, special files and multiply linked" in text


@pytest.mark.parametrize("link", ("symlink", "hardlink"))
def test_base_object_substituted_through_a_link_is_never_shown(tmp_path: Path, link: str) -> None:
    repository = _repository(tmp_path)
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(repository))
    oid = _git(repository, "rev-parse", "HEAD:selectors.ts").strip()
    target = _loose_object_path(repository, oid)
    outside_object = _outside_blob(tmp_path, "secret-outside\n")
    target.unlink()
    if link == "symlink":
        os.symlink(outside_object, target)
    else:
        os.link(outside_object, target)
    (repository / "selectors.ts").write_text("export const shown = 2;\n", encoding="utf-8")

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), base)
    text = _text(capture)

    assert "secret-outside" not in text
    assert "selectors.ts" in text and "export const shown = 2;" not in text
    assert capture.omitted_files == 1 and capture.truncated


def test_object_store_reached_through_a_symlink_is_refused(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (repository / "selectors.ts").write_text("export const shown = 3;\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere-objects"
    (repository / ".git" / "objects").rename(elsewhere)
    os.symlink(elsewhere, repository / ".git" / "objects")

    with pytest.raises(ChangeCaptureUnavailable) as raised:
        GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    assert raised.value.reason == "unsafe_root"


def test_git_directory_sharing_another_common_directory_is_refused(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    _git(other, "init", "--quiet")
    (repository / ".git" / "commondir").write_text(
        os.fspath(other / ".git") + "\n", encoding="utf-8"
    )
    (repository / "selectors.ts").write_text("export const shown = 4;\n", encoding="utf-8")

    with pytest.raises(ChangeCaptureUnavailable) as raised:
        GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    assert raised.value.reason in {"unsupported_repository", "unsafe_root", "not_git"}


def test_validated_root_replaced_by_another_repository_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    (repository / "selectors.ts").write_text("export const original = 1;\n", encoding="utf-8")
    # A clone of the same base, so the task base resolves in it too.
    replacement = tmp_path / "replacement"
    _git(tmp_path, "clone", "--quiet", "--no-hardlinks", os.fspath(repository), "replacement")
    replacement.chmod(0o700)
    (replacement / "selectors.ts").write_text("REPLACEMENT CONTENT\n", encoding="utf-8")
    real = capture_module.run_read_only_git
    swapped: list[bool] = []

    def run(handle: Any, arguments: tuple[str, ...], **kwargs: Any) -> tuple[int, bytes]:
        if "diff" in arguments and not swapped:
            # A same-user process renames the validated directory away and puts another
            # repository at its path after the capture validated it.
            repository.rename(tmp_path / "moved-away")
            replacement.rename(repository)
            swapped.append(True)
        return real(handle, arguments, **kwargs)

    monkeypatch.setattr(capture_module, "run_read_only_git", run)

    with pytest.raises(ChangeCaptureUnavailable) as raised:
        adapter.capture(os.fspath(repository), base)

    assert swapped and raised.value.reason == "unsafe_root"


def _mutate_on(
    monkeypatch: pytest.MonkeyPatch, marker: str, mutate: Any, *, times: int
) -> list[tuple[str, ...]]:
    """Run ``mutate`` just before the first ``times`` Git calls whose argv contains ``marker``."""

    calls: list[tuple[str, ...]] = []
    real = capture_module.run_read_only_git

    def run(handle: Any, arguments: tuple[str, ...], **kwargs: Any) -> tuple[int, bytes]:
        if marker in arguments:
            calls.append(arguments)
            if len(calls) <= times:
                mutate(len(calls))
        return real(handle, arguments, **kwargs)

    monkeypatch.setattr(capture_module, "run_read_only_git", run)
    return calls


def test_tracked_edit_between_git_reads_is_retried_into_one_coherent_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    target = repository / "selectors.ts"
    target.write_text("export const first = 1;\n", encoding="utf-8")

    def mutate(_: int) -> None:
        # A formatter rewrites the file after its counts were read, before its patch.
        target.write_text(
            "export const first = 1;\nexport const second = 2;\nexport const third = 3;\n",
            encoding="utf-8",
        )

    calls = _mutate_on(monkeypatch, "--unified=3", mutate, times=1)

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)
    text = _text(capture)

    assert len(calls) == 2  # the first attempt saw the change and was taken again
    assert "+export const third = 3;" in text
    assert "  M selectors.ts (+3 -3)" in text


def test_working_tree_that_never_holds_still_makes_the_capture_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    target = repository / "selectors.ts"
    target.write_text("export const churn = 0;\n", encoding="utf-8")

    def mutate(count: int) -> None:
        target.write_text(f"export const churn = {count};\n" * count, encoding="utf-8")

    calls = _mutate_on(monkeypatch, "--unified=3", mutate, times=100)

    with pytest.raises(ChangeCaptureUnavailable) as raised:
        GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    assert raised.value.reason == "changed_during_capture"
    assert 1 < len(calls) <= 3


def test_untracked_file_created_during_the_capture_is_retried_into_one_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "a.txt").write_text("first untracked\n", encoding="utf-8")

    def mutate(_: int) -> None:
        (repository / "b.txt").write_text("second untracked\n", encoding="utf-8")

    real = capture_module.run_read_only_git
    listed: list[int] = []

    def run(handle: Any, arguments: tuple[str, ...], **kwargs: Any) -> tuple[int, bytes]:
        result = real(handle, arguments, **kwargs)
        if "--others" in arguments:
            listed.append(1)
            if len(listed) == 1:
                # A new file appears just after the first listing was taken.
                mutate(1)
        return result

    monkeypatch.setattr(capture_module, "run_read_only_git", run)

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)
    text = _text(capture)

    assert len(listed) >= 3  # first attempt listed twice and differed; the retry agreed
    assert capture.untracked_files == 2
    assert "+second untracked" in text and "+first untracked" in text


def test_untracked_file_rewritten_while_it_is_read_is_never_a_mix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    target = repository / "notes.txt"
    target.write_text("old-" * 10_000 + "\n", encoding="utf-8")
    inode = target.stat().st_ino
    real_read = os.read
    rewrites: list[int] = []

    def read(descriptor: int, size: int) -> bytes:
        chunk = real_read(descriptor, size)
        if not rewrites and os.fstat(descriptor).st_ino == inode:
            # Another process rewrites the file in place after its first chunk was read.
            rewrites.append(1)
            with open(target, "r+b") as handle:
                handle.write(b"new-" * 10_000 + b"\n")
        return chunk

    monkeypatch.setattr(os, "read", read)

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)
    text = _text(capture)

    assert rewrites
    assert "old-" not in text or "new-" not in text
    assert "+" + "new-" * 20 in text


# --- Adversarial follow-up: redirection, shared packs, swaps inside one Git read -------------


def _other_worktree(tmp_path: Path) -> Path:
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    _git(other, "init", "--quiet")
    (other / "selectors.ts").write_text("OUTSIDE WORKTREE SECRET\n", encoding="utf-8")
    _git(other, "add", "--", "selectors.ts")
    return other


def test_core_worktree_naming_another_repository_is_refused_at_discovery(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    other = _other_worktree(tmp_path)
    _git(repository, "config", "core.worktree", os.fspath(other))

    with pytest.raises(ChangeCaptureUnavailable) as raised:
        GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    assert raised.value.reason in {"unsafe_root", "unsupported_repository"}


def test_core_worktree_written_after_discovery_never_redirects_the_diff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    other = _other_worktree(tmp_path)
    (repository / "selectors.ts").write_text("export const mine = 1;\n", encoding="utf-8")

    def mutate(_: int) -> None:
        _git(repository, "config", "core.worktree", os.fspath(other))

    _mutate_on(monkeypatch, "--raw", mutate, times=1)

    try:
        capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)
    except ChangeCaptureUnavailable as exc:
        assert exc.reason in {"unsafe_root", "unsupported_repository", "changed_during_capture"}
        return
    text = _text(capture)
    assert "OUTSIDE WORKTREE SECRET" not in text
    assert "export const mine = 1;" in text


def test_pack_hard_linked_from_another_repository_is_shown_once_every_blob_verifies(
    tmp_path: Path,
) -> None:
    """A second name is not a leak: the blob hashes to the name the task base gives it."""

    repository = _repository(tmp_path)
    outside = tmp_path / "outside-repo"
    outside.mkdir(mode=0o700)
    _git(outside, "init", "--quiet")
    (outside / "shared.txt").write_text("shared packed content\n", encoding="utf-8")
    oid = _git(outside, "hash-object", "-w", "--", "shared.txt").strip()
    _git(outside, "add", "--", "shared.txt")
    _commit(outside, "outside")
    _git(outside, "repack", "-a", "-d", "--quiet")
    pack_directory = outside / ".git" / "objects" / "pack"
    for entry in pack_directory.iterdir():
        os.link(entry, repository / ".git" / "objects" / "pack" / entry.name)
    # The task base names the blob, which the repository reaches only through that pack.
    _git(repository, "update-index", "--add", "--cacheinfo", f"100644,{oid},shared.txt")
    _git(
        repository,
        "-c",
        "user.name=Yoetz Test",
        "-c",
        "user.email=yoetz@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "reference the shared blob",
    )
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(repository))
    (repository / "shared.txt").write_text("replaced\n", encoding="utf-8")

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), base)
    text = _text(capture)

    assert "-shared packed content" in text and "+replaced" in text
    assert "  M shared.txt (+1 -1)" in text
    assert capture.omitted_files == 0 and not capture.truncated


def test_local_clone_with_hard_linked_loose_objects_captures_normally(tmp_path: Path) -> None:
    source = _repository(tmp_path)
    _git(tmp_path, "clone", "--quiet", "--local", os.fspath(source), "clone")
    clone = tmp_path / "clone"
    clone.chmod(0o700)
    oid = _git(clone, "rev-parse", "HEAD:selectors.ts").strip()
    assert _loose_object_path(clone, oid).stat().st_nlink > 1  # the clone shares its objects
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(clone))
    (clone / "selectors.ts").write_text("export const cloned = 1;\n", encoding="utf-8")

    capture = GitChangeCaptureAdapter().capture(os.fspath(clone), base)
    text = _text(capture)

    assert "-  return String(value);" in text and "+export const cloned = 1;" in text
    assert capture.omitted_files == 0 and not capture.truncated


def test_loose_object_swapped_only_during_the_diff_is_never_shown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(repository))
    oid = _git(repository, "rev-parse", "HEAD:selectors.ts").strip()
    target = _loose_object_path(repository, oid)
    aside = target.with_name(target.name + ".aside")
    outside_object = _outside_blob(tmp_path, "secret-outside\n")
    (repository / "selectors.ts").write_text("export const shown = 5;\n", encoding="utf-8")
    real = capture_module.run_read_only_git
    swaps: list[int] = []

    def run(handle: Any, arguments: tuple[str, ...], **kwargs: Any) -> tuple[int, bytes]:
        if "--unified=3" not in arguments or swaps:
            return real(handle, arguments, **kwargs)
        swaps.append(1)
        target.rename(aside)
        os.symlink(outside_object, target)
        try:
            return real(handle, arguments, **kwargs)
        finally:
            target.unlink()
            aside.rename(target)

    monkeypatch.setattr(capture_module, "run_read_only_git", run)

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), base)
    text = _text(capture)

    assert swaps
    assert "secret-outside" not in text
    assert "export const shown = 5;" in text  # the retaken capture is the real change


def test_hard_link_swapped_in_only_while_counting_never_reaches_the_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "tracked.txt").write_text("base\n", encoding="utf-8")
    _git(repository, "add", "--", "tracked.txt")
    _commit(repository, "track a file")
    (repository / "tracked.txt").write_text("changed\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("".join(f"x{n}\n" for n in range(7)), encoding="utf-8")
    target = repository / "tracked.txt"
    aside = repository / "tracked.aside"

    def mutate(_: int) -> None:
        target.rename(aside)
        os.link(outside / "private.txt", target)

    real = capture_module.run_read_only_git
    swaps: list[int] = []

    def run(handle: Any, arguments: tuple[str, ...], **kwargs: Any) -> tuple[int, bytes]:
        if "--numstat" not in arguments or swaps:
            return real(handle, arguments, **kwargs)
        swaps.append(1)
        mutate(1)
        try:
            return real(handle, arguments, **kwargs)
        finally:
            target.unlink()
            aside.rename(target)

    monkeypatch.setattr(capture_module, "run_read_only_git", run)

    capture = GitChangeCaptureAdapter().capture(os.fspath(repository), None)
    text = _text(capture)

    assert swaps
    assert "(+7 " not in text and "x6" not in text
    assert "  M tracked.txt (+1 -1)" in text


def test_alternates_are_unsafe_root_whether_static_or_written_during_the_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path)
    (repository / "selectors.ts").write_text("export const shown = 7;\n", encoding="utf-8")
    alternates = repository / ".git" / "objects" / "info" / "alternates"
    alternates.parent.mkdir(exist_ok=True)
    alternates.write_text(os.fspath(tmp_path / "elsewhere") + "\n", encoding="utf-8")

    with pytest.raises(ChangeCaptureUnavailable) as static:
        GitChangeCaptureAdapter().capture(os.fspath(repository), None)
    alternates.unlink()

    def mutate(_: int) -> None:
        alternates.write_text(os.fspath(tmp_path / "elsewhere") + "\n", encoding="utf-8")

    _mutate_on(monkeypatch, "--raw", mutate, times=1)
    with pytest.raises(ChangeCaptureUnavailable) as written:
        GitChangeCaptureAdapter().capture(os.fspath(repository), None)

    assert static.value.reason == written.value.reason == "unsafe_root"


def test_submodule_checkout_opened_as_the_root_is_unsafe_root(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    checkout = tmp_path / "checkout"
    checkout.mkdir(mode=0o700)
    (checkout / ".git").write_text(
        "gitdir: " + os.fspath(repository / ".git") + "\n", encoding="utf-8"
    )

    with pytest.raises(ChangeCaptureUnavailable) as raised:
        GitChangeCaptureAdapter().capture(os.fspath(checkout), None)

    assert raised.value.reason == "unsafe_root"


def test_metadata_capture_skips_and_counts_a_line_break_file_name(tmp_path: Path) -> None:
    """#1019: a CR or LF in a name is skipped and counted, never a failed capture or a path."""

    repository = _repository(tmp_path)
    tracked = repository / "tracked\nname.txt"
    tracked.write_text("one\n", encoding="utf-8")
    _git(repository, "add", "--", "tracked\nname.txt")
    _commit(repository, "add odd tracked name")
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    tracked.write_text("two\n", encoding="utf-8")
    (repository / "a\nb").write_bytes(b"x\n")
    (repository / "c\rd").write_bytes(b"x\n")
    (repository / "selectors.ts").write_text("export const changed = 1;\n", encoding="utf-8")
    (repository / "out.txt").write_text("result\n", encoding="utf-8")

    metadata = adapter.capture_metadata(os.fspath(repository), base)

    assert [(entry.status, entry.path, entry.untracked) for entry in metadata.entries] == [
        ("M", "selectors.ts", False),
        ("A", "out.txt", True),
    ]
    assert metadata.unrepresentable_files == 3
    assert metadata.tracked_files == 2
    assert metadata.untracked_files == 3
    assert metadata.omitted_files == 3
    assert metadata.truncated is True
    assert "a\nb" not in repr(metadata) and "c\rd" not in repr(metadata)


def test_metadata_capture_skips_a_rename_from_a_line_break_name(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    odd = repository / "old\nname.txt"
    odd.write_text("same content\n", encoding="utf-8")
    _git(repository, "add", "--", "old\nname.txt")
    _commit(repository, "add odd name")
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    _git(repository, "mv", "--", "old\nname.txt", "plain.txt")

    metadata = adapter.capture_metadata(os.fspath(repository), base)

    assert metadata.entries == ()
    assert metadata.unrepresentable_files == 1
    assert metadata.omitted_files == 1 and metadata.truncated is True


def test_metadata_counter_invariants() -> None:
    """The skipped-path count is part of ``omitted_files``, which implies ``truncated``."""

    with pytest.raises(ValueError):
        CheckChangeMetadata(
            base="head",
            entries=(),
            tracked_files=1,
            untracked_files=0,
            omitted_files=0,
            truncated=False,
            unrepresentable_files=1,
        )
    with pytest.raises(ValueError):
        CheckChangeMetadata(
            base="head",
            entries=(),
            tracked_files=1,
            untracked_files=0,
            omitted_files=1,
            truncated=True,
            unrepresentable_files=True,
        )
    assert not metadata_path_representable("a\nb")
    assert not metadata_path_representable("a\rb")
    assert not metadata_path_representable("a\x00b")
    assert metadata_path_representable("a\tb")


# --- Issue #1045: packet completeness within the existing budget ---------------------------------


def _nested_repository(parent: Path, name: str = "api") -> Path:
    """An embedded Git repository inside ``parent``, with one committed file."""

    nested = parent / name
    nested.mkdir(mode=0o700)
    _git(nested, "init", "--quiet")
    (nested / "server.py").write_text("def handler():\n    return 'v1'\n", encoding="utf-8")
    _git(nested, "add", "--", "server.py")
    _git(
        nested,
        "-c",
        "user.name=Yoetz Test",
        "-c",
        "user.email=yoetz@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "nested baseline",
    )
    return nested


def test_untracked_files_present_at_task_start_are_baseline_not_additions(
    tmp_path: Path,
) -> None:
    """pretrain shape: a pre-existing untracked ``index.json`` was shown to the reviewer as added."""

    repository = _repository(tmp_path)
    (repository / "index.json").write_text('{"shards": 4}\n', encoding="utf-8")
    (repository / "notes.txt").write_text("before the task\n", encoding="utf-8")
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    assert base.untracked_complete is True
    assert {item.path for item in base.untracked} == {"index.json", "notes.txt"}
    assert decode_task_change_base(encode_task_change_base(base)) == base

    (repository / "notes.txt").write_text("before the task\nand during it\n", encoding="utf-8")
    (repository / "train.py").write_text("print('train')\n", encoding="utf-8")

    capture = adapter.capture(os.fspath(repository), base)
    text = _text(capture)
    assert "index.json" not in text
    assert (
        "Untracked files that already existed when the task started and are unchanged since: 1."
        in text
    )
    assert "  A train.py (+1 -0) untracked\n" in text
    assert (
        "  M notes.txt (+2 -0) untracked; existed when the task started; its earlier content "
        "was not recorded, so it is shown whole\n"
    ) in text
    assert capture.untracked_files == 2

    metadata = adapter.capture_metadata(os.fspath(repository), base)
    entries = {entry.path: entry for entry in metadata.entries}
    assert "index.json" not in entries
    assert entries["notes.txt"].status == "M" and not entries["notes.txt"].untracked
    assert entries["train.py"].status == "A" and entries["train.py"].untracked
    assert metadata.untracked_files == 2 and not metadata.truncated


def test_a_base_without_a_snapshot_keeps_every_untracked_file_as_before(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (repository / "index.json").write_text('{"shards": 4}\n', encoding="utf-8")
    adapter = GitChangeCaptureAdapter()
    recorded = adapter.read_task_base(os.fspath(repository))
    legacy = TaskChangeBase(recorded.object_format, recorded.commit)
    # A base written before the snapshot existed keeps its exact bytes and reads back as one.
    assert set(strict_json_keys(encode_task_change_base(legacy))) == {
        "commit",
        "object_format",
        "origin",
        "schema",
    }

    text = _text(adapter.capture(os.fspath(repository), legacy))
    assert "  A index.json (+1 -0) untracked\n" in text
    assert "existed when the task started" not in text


def test_first_check_base_cannot_carry_a_task_start_snapshot() -> None:
    from yoetz.ports.change_capture import UntrackedBaselineFile

    with pytest.raises(ValueError):
        TaskChangeBase(
            "sha1",
            "a" * 40,
            "first_check",
            (UntrackedBaselineFile("x.txt", "sha256:" + "0" * 64),),
            True,
        )


def test_nested_repository_change_is_captured_under_its_directory(tmp_path: Path) -> None:
    """live-database-cutover shape: the implementation lived in a nested ``/app/api`` repository."""

    repository = _repository(tmp_path)
    nested = _nested_repository(repository)
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    assert [path for path, _ in base.nested] == ["api"]

    (nested / "server.py").write_text("def handler():\n    return 'v2'\n", encoding="utf-8")
    _git(
        nested,
        "-c",
        "user.name=Yoetz Test",
        "-c",
        "user.email=yoetz@example.invalid",
        "commit",
        "--quiet",
        "-am",
        "cut over",
    )
    (nested / "server.py").write_text("def handler():\n    return 'v3'\n", encoding="utf-8")
    (nested / "migrate.py").write_text("print('migrate')\n", encoding="utf-8")

    capture = adapter.capture(os.fspath(repository), base)
    text = _text(capture)
    assert (
        "Nested repository api/: its own change is shown under that directory, from the commit "
        "it held when the task started." in text
    )
    # The committed and the uncommitted work inside the nested repository, against its start.
    assert "diff --git a/api/server.py b/api/server.py" in text
    assert "-    return 'v1'" in text and "+    return 'v3'" in text
    assert "  A api/migrate.py (+1 -0) untracked\n" in text
    assert "  M api/server.py (+1 -1)\n" in text
    # The directory's one-line placeholder gave way to its files.
    assert "  A api/ untracked" not in text
    assert capture.tracked_files == 1 and capture.untracked_files == 1
    assert capture.omitted_files == 0 and not capture.truncated


def test_gitlink_repository_diff_starts_at_the_commit_the_base_tree_records(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    nested = _nested_repository(repository)
    _git(repository, "add", "--", "api")
    _commit(repository, "track api as a gitlink")
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    assert base.nested == ()  # tracked: the base tree records its commit

    (nested / "server.py").write_text("def handler():\n    return 'v2'\n", encoding="utf-8")

    text = _text(adapter.capture(os.fspath(repository), base))
    assert "-Subproject commit" in text  # the outer gitlink line still stands
    assert "Nested repository api/: its own change is shown under that directory" in text
    assert "diff --git a/api/server.py b/api/server.py" in text
    assert "+    return 'v2'" in text


def test_nested_repository_that_fails_a_fence_is_named_and_not_read(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    nested = _nested_repository(repository)
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    (nested / "server.py").write_text("NESTED_CANARY = 1\n", encoding="utf-8")
    nested.chmod(0o777)  # group- and world-writable: the ADR-011 root fence refuses it
    try:
        capture = adapter.capture(os.fspath(repository), base)
    finally:
        nested.chmod(0o700)

    text = _text(capture)
    assert "NESTED_CANARY" not in text
    assert "Nested repository api/: its own change is not shown (it failed a safety check)." in text
    assert (
        "  A api/ untracked; not shown: a nested Git repository whose own change was not read"
        in text
    )
    assert capture.truncated


def _nested_commit(nested: Path, content: str, message: str) -> None:
    (nested / "server.py").write_text(content, encoding="utf-8")
    _git(
        nested,
        "-c",
        "user.name=Yoetz Test",
        "-c",
        "user.email=yoetz@example.invalid",
        "commit",
        "--quiet",
        "-am",
        message,
    )


def test_changed_gitlink_whose_repository_is_not_read_counts_as_not_shown(
    tmp_path: Path,
) -> None:
    """Review of #1045: a submodule checkout (its ``.git`` is a file) is never opened, so its own
    change is not shown; the gitlink's commit-id lines alone must not read as a complete change."""

    repository = _repository(tmp_path)
    nested = repository / "api"
    nested.mkdir(mode=0o700)
    _git(nested, "init", "--quiet", f"--separate-git-dir={tmp_path / 'api.git'}")
    (nested / "server.py").write_text("def handler():\n    return 'v1'\n", encoding="utf-8")
    _git(nested, "add", "--", "server.py")
    _nested_commit(nested, "def handler():\n    return 'v1'\n", "nested baseline")
    _git(repository, "add", "--", "api")
    _commit(repository, "track api as a gitlink")
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    _nested_commit(nested, "SUBMODULE_CANARY = 1\n", "work inside the submodule")

    capture = adapter.capture(os.fspath(repository), base)

    text = _text(capture)
    assert "SUBMODULE_CANARY" not in text
    assert "+Subproject commit" in text  # the outer gitlink lines still stand
    assert (
        "Nested repository api/: its own change is not shown (its Git configuration or layout is "
        "not supported)." in text
    )
    assert "  M api (+1 -1) not shown: a nested Git repository whose own change was not read" in (
        text
    )
    assert "Changed files: 1 tracked, 0 untracked. Not shown: 1." in text
    assert capture.omitted_files == 1 and capture.truncated


def test_gitlink_added_over_an_untracked_repository_starts_at_its_task_start_head(
    tmp_path: Path,
) -> None:
    """Review of #1045: untracked at task start, staged as a new gitlink later. The new gitlink's
    source commit is Git's null id, which must not hide the snapshot's starting commit."""

    repository = _repository(tmp_path)
    nested = _nested_repository(repository)
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    assert [path for path, _ in base.nested] == ["api"]
    _nested_commit(nested, "def handler():\n    return 'COMMITTED_IN_TASK'\n", "cut over")
    _git(repository, "add", "--", "api")

    text = _text(adapter.capture(os.fspath(repository), base))

    assert (
        "Nested repository api/: its own change is shown under that directory, from the commit "
        "it held when the task started." in text
    )
    assert "diff --git a/api/server.py b/api/server.py" in text
    assert "-    return 'v1'" in text and "+    return 'COMMITTED_IN_TASK'" in text


def test_nested_repository_borrowing_another_store_is_refused_at_task_start(
    tmp_path: Path,
) -> None:
    """Review of #1045: a ``commondir`` naming another repository is refused before its HEAD is
    read, so that repository's commit never becomes the task's starting state."""

    repository = _repository(tmp_path)
    other = _nested_repository(tmp_path, "other")
    _nested_commit(other, "OTHER_REPOSITORY = 1\n", "another repository's work")
    other_head = _git(other, "rev-parse", "HEAD").strip()
    nested = _nested_repository(repository)
    assert _git(nested, "rev-parse", "HEAD").strip() != other_head
    (nested / ".git" / "commondir").write_text(os.fspath(other / ".git") + "\n", "utf-8")
    adapter = GitChangeCaptureAdapter()

    base = adapter.read_task_base(os.fspath(repository))

    assert base.origin == "task_start"
    assert base.nested == ()
    assert other_head not in encode_task_change_base(base).decode("utf-8")
    # Check time refuses the same repository for the same reason.
    text = _text(adapter.capture(os.fspath(repository), base))
    assert (
        "Nested repository api/: its own change is not shown (its Git configuration or layout is "
        "not supported)." in text
    )


def test_gitlink_inside_a_nested_repository_counts_as_not_shown(tmp_path: Path) -> None:
    """Review of #1045: a repository nested inside a nested one is never read, so its changed
    gitlink counts as not shown, as an untracked repository at that depth already does."""

    repository = _repository(tmp_path)
    api = _nested_repository(repository)
    lib = _nested_repository(api, "lib")
    _git(api, "add", "--", "lib")
    _commit(api, "track lib as a gitlink")
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    _nested_commit(lib, "INNER_CANARY = 1\n", "work inside the inner repository")

    capture = adapter.capture(os.fspath(repository), base)

    text = _text(capture)
    assert "INNER_CANARY" not in text
    assert "Nested repository api/: its own change is shown under that directory" in text
    assert "+Subproject commit" in text  # the inner gitlink's commit-id lines still stand
    assert (
        "  M api/lib (+1 -1) not shown: a nested Git repository whose own change was not read"
        in text
    )
    assert "Not shown: 1." in text
    assert capture.omitted_files == 1 and capture.truncated


def test_task_input_files_the_statement_names_are_read_only_when_unchanged(
    tmp_path: Path,
) -> None:
    """vba-userform-port shape: the VBA source to port never reached the reviewer."""

    repository = _repository(tmp_path)
    (repository / "vba").mkdir()
    (repository / "vba" / "UserForm1.frm").write_text(
        'Private Sub CommandButton1_Click()\n    MsgBox "hi"\nEnd Sub\n', encoding="utf-8"
    )
    (repository / "DESIGN.md").write_text("# Design\n" + "rule line\n" * 4000, encoding="utf-8")
    (repository / "secrets.pem").write_text("not a real key\n", encoding="utf-8")
    _git(repository, "add", "--", "vba/UserForm1.frm", "DESIGN.md", "secrets.pem")
    _commit(repository, "inputs")
    (repository / "local.env").write_text("IGNORED_CANARY=1\n", encoding="utf-8")
    (repository / "brief.txt").write_text("UNTRACKED_BRIEF_MARKER\n", encoding="utf-8")
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    (repository / "form.py").write_text("def click():\n    print('hi')\n", encoding="utf-8")
    (repository / "notes.md").write_text("AGENT_NOTES_MARKER\n", encoding="utf-8")

    capture = adapter.capture(
        os.fspath(repository),
        base,
        input_paths=(
            os.fspath(repository / "vba" / "UserForm1.frm"),
            "DESIGN.md",
            "form.py",  # the agent's own work: part of the change, never an input
            "secrets.pem",  # credential-named
            "local.env",  # ignored
            "/etc/hostname",  # outside the repository
            "missing.md",
            "notes.md",  # created by the agent: untracked and not in the task-start snapshot
            "brief.txt",  # untracked before the task started and unchanged since
        ),
    )

    assert [item.path for item in capture.inputs] == [
        "vba/UserForm1.frm",
        "DESIGN.md",
        "brief.txt",
    ]
    form, design, brief = capture.inputs
    assert brief.text == b"UNTRACKED_BRIEF_MARKER\n"
    assert b"MsgBox" in form.text and form.size == len(form.text)
    # A large input keeps its head and tail with the cut marked, within the per-input bound.
    assert design.size > len(design.text) and len(design.text) <= 16_384
    assert design.text.startswith(b"# Design\n")
    assert b"bytes elided here; head and tail kept]" in design.text
    joined = b"".join(item.text for item in capture.inputs)
    assert b"IGNORED_CANARY" not in joined and b"AGENT_NOTES_MARKER" not in joined
    # Inputs never enter the change text, and they round-trip with the stored object.
    assert b"MsgBox" not in capture.text
    assert decode_check_change(encode_check_change(capture)) == capture


def strict_json_keys(data: bytes) -> list[str]:
    import json

    return list(json.loads(data))
