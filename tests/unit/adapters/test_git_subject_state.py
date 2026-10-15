"""Bounded, content-withholding Git subject-state adapter coverage."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from finishup.adapters import git_subject_state as git_subject_state_module
from finishup.adapters.git_subject_state import GitSubjectStateAdapter, open_local_workspace
from finishup.ports.subject_state import (
    SubjectStateBound,
    SubjectStateCaptureCommand,
    SubjectStateCaptureResult,
    SubjectStateFormat,
    SubjectStateLimitation,
    SubjectStateLimitDetail,
    SubjectStateStatus,
)
from finishup.protocol.errors import ProtocolValueError


def test_limit_detail_requires_an_actual_overflow() -> None:
    with pytest.raises(ProtocolValueError, match="invalid_subject_state"):
        SubjectStateLimitDetail(SubjectStateBound.UNTRACKED_FILE_COUNT, 4, 4)


def test_capture_result_rejects_limit_detail_without_limit_limitation() -> None:
    with pytest.raises(ProtocolValueError, match="invalid_subject_state"):
        SubjectStateCaptureResult(
            status=SubjectStateStatus.STATE_NOT_OBSERVED,
            subject_state=None,
            format=SubjectStateFormat.GIT_STRUCTURAL_V1,
            limitations=(SubjectStateLimitation.NOT_GIT,),
            bytes_hashed=0,
            files_hashed=0,
            limit_detail=(SubjectStateLimitDetail(SubjectStateBound.UNTRACKED_FILE_COUNT, 5, 4),),
        )


def _git(repository: Path, *arguments: str) -> bytes:
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
    return completed.stdout


def _repository(tmp_path: Path, *, committed: bool = True) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    if committed:
        (repository / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        _git(repository, "add", "--", "tracked.txt")
        _git(
            repository,
            "-c",
            "user.name=FinishUP Test",
            "-c",
            "user.email=finishup@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "baseline",
        )
    return repository


def _command(repository: Path) -> SubjectStateCaptureCommand:
    return SubjectStateCaptureCommand(
        open_local_workspace(repository), SubjectStateFormat.GIT_STRUCTURAL_V1
    )


def _captured(adapter: GitSubjectStateAdapter, command: SubjectStateCaptureCommand) -> str:
    result = adapter.capture(command)
    assert result.status is SubjectStateStatus.CAPTURED
    assert result.subject_state is not None
    assert result.subject_state.tree_digest is not None
    assert result.subject_state.diff_digest is not None
    assert result.limitations == ()
    return result.subject_state.tree_digest


def test_clean_dirty_staged_untracked_and_ignored_states_are_comparable(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    command = _command(repository)
    adapter = GitSubjectStateAdapter()
    clean = adapter.capture(command)
    assert clean.status is SubjectStateStatus.CAPTURED
    assert clean.bytes_hashed == 0
    assert clean.files_hashed == 0
    assert clean.subject_state is not None

    (repository / "tracked.txt").write_text("dirty source canary\n", encoding="utf-8")
    dirty = adapter.capture(command)
    assert dirty.status is SubjectStateStatus.CAPTURED
    assert dirty.subject_state != clean.subject_state

    _git(repository, "add", "--", "tracked.txt")
    staged = adapter.capture(command)
    assert staged.status is SubjectStateStatus.CAPTURED
    assert staged.subject_state != dirty.subject_state

    (repository / "untracked-secret-name.txt").write_text(
        "untracked content canary\n", encoding="utf-8"
    )
    untracked = adapter.capture(command)
    assert untracked.status is SubjectStateStatus.CAPTURED
    assert untracked.subject_state != staged.subject_state
    assert untracked.files_hashed == 1
    assert untracked.bytes_hashed > staged.bytes_hashed
    public_rendering = repr(untracked)
    assert "untracked-secret-name" not in public_rendering
    assert "untracked content canary" not in public_rendering
    assert "dirty source canary" not in public_rendering
    assert os.fspath(repository) not in public_rendering

    (repository / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    _git(repository, "add", "--", ".gitignore")
    _git(
        repository,
        "-c",
        "user.name=FinishUP Test",
        "-c",
        "user.email=finishup@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "state",
    )
    before_ignored = _captured(adapter, command)
    (repository / "ignored.txt").write_text("ignored canary\n", encoding="utf-8")
    assert _captured(adapter, command) == before_ignored


def test_unborn_head_is_stable_and_material_state_changes_digest(tmp_path: Path) -> None:
    repository = _repository(tmp_path, committed=False)
    command = _command(repository)
    adapter = GitSubjectStateAdapter()
    empty = _captured(adapter, command)
    (repository / "new.txt").write_text("new\n", encoding="utf-8")
    untracked = _captured(adapter, command)
    assert untracked != empty
    _git(repository, "add", "--", "new.txt")
    assert _captured(adapter, command) != untracked


def test_submodule_symlink_special_file_and_linked_worktree_fail_closed(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    adapter = GitSubjectStateAdapter()
    command = _command(repository)
    head = _git(repository, "rev-parse", "HEAD").decode("ascii").strip()
    _git(repository, "update-index", "--add", "--cacheinfo", f"160000,{head},nested")
    submodule = adapter.capture(command)
    assert submodule.status is SubjectStateStatus.UNSUPPORTED
    assert submodule.subject_state is None
    assert submodule.limitations == (SubjectStateLimitation.SUBMODULE_PRESENT,)

    _git(repository, "reset", "--quiet", "HEAD", "--", "nested")
    (repository / "link").symlink_to("tracked.txt")
    _git(repository, "add", "--", "link")
    symlink = adapter.capture(command)
    assert symlink.status is SubjectStateStatus.UNSUPPORTED
    assert symlink.limitations == (SubjectStateLimitation.SYMLINK_UNSUPPORTED,)

    _git(repository, "reset", "--quiet", "HEAD", "--", "link")
    (repository / "link").unlink()
    fifo = repository / "pipe"
    os.mkfifo(fifo)
    try:
        special = adapter.capture(command)
        assert special.status is SubjectStateStatus.UNSUPPORTED
        assert special.limitations == (SubjectStateLimitation.SYMLINK_UNSUPPORTED,)
    finally:
        fifo.unlink()

    linked = tmp_path / "linked"
    _git(repository, "worktree", "add", "--quiet", "-b", "linked-test", os.fspath(linked))
    with pytest.raises(ValueError, match="unsafe_root"):
        open_local_workspace(linked)


def test_file_and_byte_caps_discard_all_candidate_digests(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    command = _command(repository)
    (repository / "one.txt").write_text("one", encoding="utf-8")
    (repository / "two.txt").write_text("two", encoding="utf-8")
    file_limited = GitSubjectStateAdapter(_max_files=1).capture(command)
    assert file_limited.status is SubjectStateStatus.UNSUPPORTED
    assert file_limited.subject_state is None
    assert file_limited.bytes_hashed == 0
    assert file_limited.files_hashed == 0
    assert file_limited.limitations == (SubjectStateLimitation.FILE_LIMIT_EXCEEDED,)
    assert file_limited.limit_detail == (
        SubjectStateLimitDetail(SubjectStateBound.UNSAFE_TREE_ENTRIES, 2, 1),
    )

    byte_limited = GitSubjectStateAdapter(_max_hash_bytes=5).capture(command)
    assert byte_limited.status is SubjectStateStatus.UNSUPPORTED
    assert byte_limited.subject_state is None
    assert byte_limited.bytes_hashed == 0
    assert byte_limited.files_hashed == 0
    assert byte_limited.limitations == (SubjectStateLimitation.READ_LIMIT_EXCEEDED,)


def test_input_change_cancellation_and_timeout_map_to_closed_results(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    command = _command(repository)

    def mutate() -> None:
        (repository / "tracked.txt").write_text("changed between snapshots\n", encoding="utf-8")

    changed = GitSubjectStateAdapter(_before_second_capture=mutate).capture(command)
    assert changed.status is SubjectStateStatus.CHANGED_DURING_CAPTURE
    assert changed.subject_state is None
    assert changed.limitations == (SubjectStateLimitation.INPUT_CHANGED,)

    def cancel() -> None:
        raise KeyboardInterrupt

    cancelled = GitSubjectStateAdapter(_before_second_capture=cancel).capture(command)
    assert cancelled.status is SubjectStateStatus.STATE_NOT_OBSERVED
    assert cancelled.subject_state is None
    assert cancelled.limitations == (SubjectStateLimitation.GIT_FAILED,)

    sleeper = tmp_path / "sleeping-git"
    sleeper.write_text("#!/bin/sh\nsleep 2\n", encoding="utf-8")
    sleeper.chmod(0o700)
    timed_out = GitSubjectStateAdapter(_git_executable=sleeper, _timeout_seconds=0.01).capture(
        command
    )
    assert timed_out.status is SubjectStateStatus.STATE_NOT_OBSERVED
    assert timed_out.subject_state is None
    assert timed_out.limitations == (SubjectStateLimitation.GIT_FAILED,)


def test_path_safety_malicious_config_and_capture_are_read_only(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    command = _command(repository)
    adapter = GitSubjectStateAdapter()
    before_index = (repository / ".git" / "index").read_bytes()
    before_head = (repository / ".git" / "HEAD").read_bytes()

    canary = tmp_path / "external-diff-ran"
    external = tmp_path / "external-diff"
    external.write_text(
        f"#!/bin/sh\nprintf ran > {canary!s}\nexit 99\n",
        encoding="utf-8",
    )
    external.chmod(0o700)
    _git(repository, "config", "diff.external", os.fspath(external))
    (repository / "tracked.txt").write_text("dirty\n", encoding="utf-8")
    expected_status = _git(repository, "status", "--porcelain=v2", "-z")
    result = adapter.capture(command)
    assert result.status is SubjectStateStatus.CAPTURED
    assert not canary.exists()
    assert (repository / ".git" / "index").read_bytes() == before_index
    assert (repository / ".git" / "HEAD").read_bytes() == before_head
    assert _git(repository, "status", "--porcelain=v2", "-z") == expected_status

    hidden_metadata = repository / ".git-hidden"
    (repository / ".git").rename(hidden_metadata)
    try:
        missing = adapter.capture(command)
        assert missing.status is SubjectStateStatus.STATE_NOT_OBSERVED
        assert missing.subject_state is None
        assert missing.limitations == (SubjectStateLimitation.NOT_GIT,)
        assert missing.bytes_hashed == 0
        assert missing.files_hashed == 0
    finally:
        hidden_metadata.rename(repository / ".git")

    repository.chmod(0o777)
    try:
        unsafe = adapter.capture(command)
        assert unsafe.status is SubjectStateStatus.STATE_NOT_OBSERVED
        assert unsafe.subject_state is None
        assert unsafe.limitations == (SubjectStateLimitation.UNSAFE_ROOT,)
    finally:
        repository.chmod(0o700)

    symlink = tmp_path / "repo-link"
    symlink.symlink_to(repository, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe_root"):
        open_local_workspace(symlink)
    with pytest.raises(ValueError, match="unsafe_root"):
        open_local_workspace(Path.home())

    filter_parent = tmp_path / "filter-case"
    filter_parent.mkdir(mode=0o700)
    filter_repository = _repository(filter_parent)
    filter_command = _command(filter_repository)
    (filter_repository / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
    _git(filter_repository, "add", "--", ".gitattributes")
    _git(
        filter_repository,
        "-c",
        "user.name=FinishUP Test",
        "-c",
        "user.email=finishup@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "attributes",
    )
    filter_canary = tmp_path / "filter-ran"
    filter_executable = tmp_path / "evil-filter"
    filter_executable.write_text(
        f"#!/bin/sh\nprintf ran > {filter_canary!s}\ncat\n", encoding="utf-8"
    )
    filter_executable.chmod(0o700)
    _git(
        filter_repository,
        "config",
        "filter.evil.clean",
        os.fspath(filter_executable),
    )
    (filter_repository / "tracked.txt").write_text("filter bait\n", encoding="utf-8")
    filtered = adapter.capture(filter_command)
    assert filtered.status is SubjectStateStatus.STATE_NOT_OBSERVED
    assert filtered.subject_state is None
    assert filtered.limitations == (SubjectStateLimitation.UNSAFE_ROOT,)
    assert not filter_canary.exists()


def test_git_config_scan_has_its_own_practical_bound(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    config = repository / ".git" / "config"
    config.write_bytes(config.read_bytes() + b"# branch history\n" * 1_100)
    assert config.stat().st_size > 16_384

    captured = GitSubjectStateAdapter().capture(_command(repository))
    assert captured.status is SubjectStateStatus.CAPTURED
    assert captured.limitations == ()

    config.write_bytes(config.read_bytes() + b"# bounded padding\n" * 70_000)
    with pytest.raises(ValueError, match="^git_config_limit_exceeded$"):
        open_local_workspace(repository)


def test_unsafe_tree_walk_skips_gitignored_trees_but_still_scans_partially_tracked_ones(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    command = _command(repository)
    (repository / ".gitignore").write_text("big_ignored/\nmixed/\n", encoding="utf-8")
    big_ignored = repository / "big_ignored"
    big_ignored.mkdir()
    for index in range(50):
        (big_ignored / f"junk-{index}.txt").write_text("junk", encoding="utf-8")

    # A fully-ignored 50-file subtree is collapsed to one prune-set entry, never
    # walked, so the tight file limit only ever sees the four root-level entries.
    pruned = GitSubjectStateAdapter(_max_files=5).capture(command)
    assert pruned.status is SubjectStateStatus.CAPTURED

    mixed = repository / "mixed"
    mixed.mkdir()
    (mixed / "keep.txt").write_text("kept\n", encoding="utf-8")
    _git(repository, "add", "--force", "--", "mixed/keep.txt")
    os.mkfifo(mixed / "pipe")
    try:
        # A tracked file inside "mixed/" stops git from collapsing it, so the walk
        # still descends and still rejects the untracked FIFO sitting alongside it.
        partially_tracked = GitSubjectStateAdapter().capture(command)
        assert partially_tracked.status is SubjectStateStatus.UNSUPPORTED
        assert partially_tracked.limitations == (SubjectStateLimitation.SYMLINK_UNSUPPORTED,)
    finally:
        (mixed / "pipe").unlink()


def test_unsafe_tree_walk_skips_root_git_internals_but_still_rejects_nested_git(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    command = _command(repository)
    canary = repository / ".git" / "canary"
    canary.mkdir()
    for index in range(10):
        (canary / f"junk-{index}.txt").write_text("junk", encoding="utf-8")

    # Root .git internals are never descended into, so a tight file limit that would
    # trip on ten extra entries under .git/canary sees only the two root entries.
    bounded = GitSubjectStateAdapter(_max_files=5).capture(command)
    assert bounded.status is SubjectStateStatus.CAPTURED

    nested_git = repository / "nested" / ".git"
    nested_git.mkdir(parents=True)
    # A .git anywhere other than the root is still rejected: pruning is confined to
    # the root's own metadata directory, not to every directory named ".git".
    nested = GitSubjectStateAdapter().capture(command)
    assert nested.status is SubjectStateStatus.STATE_NOT_OBSERVED
    assert nested.limitations == (SubjectStateLimitation.UNSAFE_ROOT,)


def test_a_nested_git_inside_a_fully_ignored_subtree_is_deliberately_not_rejected(
    tmp_path: Path,
) -> None:
    """A nested `.git` under a gitignore-excluded subtree does not make the root unsafe.

    Pruning fully-ignored subtrees (issue #243) means the walk never sees what is inside one, so
    the `.venv/lib/pkg/.git` of a vendored dependency no longer trips UNSAFE_ROOT. That is
    deliberate and safe rather than a lost check: the nested-`.git` rule exists so capture never
    reads or hashes a foreign repository's contents, and a fully-ignored subtree is already
    outside everything capture touches — `git ls-files` never lists a path under a collapsed
    ignored directory, and the walk never opens a file there. The narrower non-ignored case is
    still rejected; see the nested-`.git` assertion above.
    """

    repository = _repository(tmp_path)
    command = _command(repository)
    (repository / ".gitignore").write_text("vendored/\n", encoding="utf-8")
    _git(repository, "add", "--", ".gitignore")
    _git(
        repository,
        "-c",
        "user.name=FinishUP Test",
        "-c",
        "user.email=finishup@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "ignore vendored",
    )
    foreign = repository / "vendored" / "lib" / "pkg"
    (foreign / ".git").mkdir(parents=True)
    (foreign / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (foreign / "module.py").write_text("vendored source\n", encoding="utf-8")

    result = GitSubjectStateAdapter().capture(command)

    assert result.status is SubjectStateStatus.CAPTURED
    assert result.limitations == ()
    # Nothing inside the ignored subtree was read: the digest is unchanged by its contents.
    (foreign / "module.py").write_text("vendored source, edited\n", encoding="utf-8")
    assert GitSubjectStateAdapter().capture(command).subject_state == result.subject_state


def test_file_limit_trip_reports_bound_observed_and_limit(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    command = _command(repository)
    (repository / "one.txt").write_text("one", encoding="utf-8")
    (repository / "two.txt").write_text("two", encoding="utf-8")

    # Root scandir order is .git, one.txt, tracked.txt, two.txt: .git is entry 1
    # (allowed and skipped without descent), one.txt is entry 2, which trips 2 > 1.
    result = GitSubjectStateAdapter(_max_files=1).capture(command)
    assert result.status is SubjectStateStatus.UNSUPPORTED
    assert result.limitations == (SubjectStateLimitation.FILE_LIMIT_EXCEEDED,)
    assert result.limit_detail == (
        SubjectStateLimitDetail(SubjectStateBound.UNSAFE_TREE_ENTRIES, 2, 1),
    )


def test_hash_untracked_file_limit_reports_bound_observed_and_limit(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (repository / "one.txt").write_text("one", encoding="utf-8")
    (repository / "two.txt").write_text("two", encoding="utf-8")
    handle = open_local_workspace(repository)
    # _hash_untracked's own FILE_LIMIT_EXCEEDED check is unreachable through the public
    # capture() path: _reject_unsafe_tree_entries runs first against the same
    # self._max_files and always trips sooner (it also counts .git and directories).
    # This white-box call exercises the detail-labeling at that site directly.
    workspace = git_subject_state_module._workspace_payload(  # pyright: ignore[reportPrivateUsage]
        handle
    )
    adapter = GitSubjectStateAdapter(_max_files=1)
    with pytest.raises(git_subject_state_module._CaptureFailure) as excinfo:  # pyright: ignore[reportPrivateUsage]
        adapter._hash_untracked(workspace, 0)  # pyright: ignore[reportPrivateUsage]
    assert excinfo.value.detail == SubjectStateLimitDetail(
        SubjectStateBound.UNTRACKED_FILE_COUNT, 2, 1
    )


@pytest.mark.parametrize("private", [True, False], ids=["user-private-group", "shared-group"])
def test_umask_0002_repository_is_captured_only_for_a_user_private_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, private: bool
) -> None:
    """A repository made under Ubuntu's default umask is g+w throughout (#n5 umask)."""

    from finishup.config import foreign_write

    monkeypatch.setattr(foreign_write, "owner_private_group", _private_group_is(private))
    previous = os.umask(0o002)
    try:
        repository = _repository(tmp_path)
        repository.chmod(0o775)
        (repository / "tracked.txt").write_text("dirty\n", encoding="utf-8")
    finally:
        os.umask(previous)
    if not private:
        with pytest.raises(ValueError, match="unsafe_root"):
            open_local_workspace(repository)
        return
    result = GitSubjectStateAdapter().capture(_command(repository))
    assert result.status is SubjectStateStatus.CAPTURED


def _private_group_is(value: bool) -> Callable[[int, int], bool]:
    def answer(_uid: int, _gid: int) -> bool:
        return value

    return answer
