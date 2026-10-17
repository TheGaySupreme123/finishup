"""The before/after workspace fingerprint the hook takes around one call (PR #1080 round 5)."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from finishup.adapters import workspace_fingerprint as fingerprint
from finishup.adapters.workspace_fingerprint import WorkspaceFingerprintStore

_KEY = b"w" * 32


def _store(tmp_path: Path) -> WorkspaceFingerprintStore:
    return WorkspaceFingerprintStore(tmp_path / "state" / "fp", _KEY)


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    (root / "src").mkdir(parents=True)
    (root / "src" / "module.py").write_text("print('reviewed')\n")
    (root / "README.md").write_text("reviewed\n")
    return root


def _around(store: WorkspaceFingerprintStore, root: Path, change: object = None) -> str:
    assert store.capture_before(str(root), "call", deadline=time.monotonic() + 10) is None
    if callable(change):
        change()
    reading = store.effect_after(
        str(root), "call", deadline=time.monotonic() + 10, call_complete=True
    )
    assert reading.reason is None or reading.effect == "unavailable"
    return reading.effect


def test_nothing_done_is_unchanged_and_a_write_is_changed(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    store = _store(tmp_path)
    assert _around(store, root) == "unchanged"
    assert _around(store, root, lambda: (root / "src" / "module.py").write_text("x\n")) == "changed"
    assert _around(store, root, lambda: (root / "new.txt").write_text("")) == "changed"
    assert _around(store, root, lambda: (root / "new.txt").unlink()) == "changed"
    assert _around(store, root, lambda: (root / "empty").mkdir()) == "changed"
    assert _around(store, root, lambda: (root / "README.md").chmod(0o700)) == "changed"


def test_a_write_that_restores_size_and_mtime_is_still_seen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _workspace(tmp_path)
    target = root / "README.md"
    old = target.stat()
    # No entry is racy: the stat path alone must catch the rewrite through the change time.
    monkeypatch.setattr(fingerprint, "RACY_WINDOW_NS", -(10**18))
    store = _store(tmp_path)

    def rewrite() -> None:
        target.write_text("tampered\n")
        os.utime(target, ns=(old.st_atime_ns, old.st_mtime_ns))

    assert len("tampered\n") == len("reviewed\n")
    assert _around(store, root, rewrite) == "changed"


def test_identical_bytes_rewritten_are_unchanged_once_their_digest_is_known(
    tmp_path: Path,
) -> None:
    root = _workspace(tmp_path)
    target = root / "README.md"
    store = _store(tmp_path)
    # Freshly written files are racy, so their bytes are hashed before the call.
    assert _around(store, root, lambda: target.write_text("reviewed\n")) == "unchanged"
    assert _around(store, root, lambda: os.utime(target)) == "unchanged"
    assert _around(store, root, lambda: target.write_text("changed!\n")) == "changed"


def test_a_metadata_move_without_a_known_digest_is_conservatively_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _workspace(tmp_path)
    monkeypatch.setattr(fingerprint, "RACY_WINDOW_NS", -(10**18))
    store = _store(tmp_path)
    # Cold cache, nothing racy: no digest was taken, so a touch cannot be told from a write.
    assert _around(store, root, lambda: os.utime(root / "README.md")) == "changed"
    # The post snapshot hashed the moved entry, so the next touch is recognised as metadata only.
    assert _around(store, root, lambda: os.utime(root / "README.md")) == "unchanged"


def test_vcs_internal_churn_is_skipped_but_vcs_configuration_is_compared(tmp_path: Path) -> None:
    """Round 6: ``.git`` is walked except its exact internals (review finding 3)."""

    root = _workspace(tmp_path)
    git = root / ".git"
    for directory in ("objects/ab", "refs/heads", "logs/refs/heads", "hooks", "info", "lfs"):
        (git / directory).mkdir(parents=True)
    for name, text in {
        "objects/ab/cdef": "blob",
        "refs/heads/main": "1" * 40,
        "logs/HEAD": "entry\n",
        "index": "index-v1",
        "HEAD": "ref: refs/heads/main\n",
        "packed-refs": "",
        "config": "[core]\n",
        "hooks/pre-commit.sample": "#!/bin/sh\n",
        "info/exclude": "",
    }.items():
        (git / name).write_text(text)
    store = _store(tmp_path)
    quiet = {
        "index refresh": lambda: (git / "index").write_text("index-v2"),
        "index lock": lambda: (git / "index.lock").write_text("x"),
        "lock removed": lambda: (git / "index.lock").unlink(),
        "object": lambda: (git / "objects" / "ab" / "0123").write_text("blob"),
        "ref": lambda: (git / "refs" / "heads" / "main").write_text("2" * 40),
        "reflog": lambda: (git / "logs" / "HEAD").write_text("entry\nentry\n"),
        "head": lambda: (git / "HEAD").write_text("ref: refs/heads/other\n"),
        "packed refs": lambda: (git / "packed-refs").write_text("x"),
        "fetch head": lambda: (git / "FETCH_HEAD").write_text("x"),
        "commit message": lambda: (git / "COMMIT_EDITMSG").write_text("msg"),
        "split index": lambda: (git / "sharedindex.0123").write_text("x"),
        "tool index copy": lambda: (git / "t3-checkpoint-index-0001").write_text("x"),
    }
    for label, change in quiet.items():
        assert _around(store, root, change) == "unchanged", label
    loud = {
        "config": lambda: (git / "config").write_text("[core]\n\tfsmonitor = ./hook\n"),
        "new hook": lambda: (git / "hooks" / "post-checkout").write_text("#!/bin/sh\n"),
        "attributes": lambda: (git / "info" / "attributes").write_text("* filter=x\n"),
        "other file": lambda: (git / "answer.txt").write_text("UNREVIEWED"),
        # The index-name rule covers the metadata root only, never a hook script.
        "hook named like an index": lambda: (git / "hooks" / "reindex").write_text("#!/bin/sh\n"),
    }
    for label, change in loud.items():
        assert _around(store, root, change) == "changed", label


@pytest.mark.parametrize(
    "name",
    ["node_modules", ".venv", "venv", ".tox", ".pytest_cache", ".mypy_cache", ".ruff_cache"],
)
def test_dependency_and_tool_cache_directories_compare_their_first_level(
    tmp_path: Path, name: str
) -> None:
    """A file directly inside one is compared (review finding 3); deeper trees by identity."""

    root = _workspace(tmp_path)
    shallow = root / name
    (shallow / "pkg" / "lib").mkdir(parents=True)
    (shallow / "answer.txt").write_text("reviewed")
    (shallow / "pkg" / "lib" / "deep.py").write_text("x = 1\n")
    store = _store(tmp_path)
    assert _around(store, root) == "unchanged"
    assert _around(store, root, lambda: (shallow / "answer.txt").write_text("UNREVIEWED")) == (
        "changed"
    )
    assert _around(store, root, lambda: (shallow / "new.txt").write_text("")) == "changed"
    assert _around(store, root, lambda: (shallow / "newpkg").mkdir()) == "changed"
    # Below the first level only identity is kept: a deep in-place rewrite is not seen. A task that
    # declares a delivery there gets no ``unchanged`` from the kernel instead.
    assert (
        _around(store, root, lambda: (shallow / "pkg" / "lib" / "deep.py").write_text("x = 2\n"))
        == "unchanged"
    )
    assert _around(store, root, lambda: os.rename(shallow / "pkg", shallow / "moved")) == "changed"


def test_bytecode_caches_hide_only_bytecode(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    cache = root / "src" / "__pycache__"
    store = _store(tmp_path)

    def compile_module() -> None:
        cache.mkdir()
        (cache / "module.cpython-312.pyc").write_bytes(b"\x00pyc")
        (cache / "module.cpython-312.pyc.4372823").write_bytes(b"\x00tmp")

    # An import creating the cache and its bytecode is not a workspace change.
    assert _around(store, root, compile_module) == "unchanged"
    assert (
        _around(store, root, lambda: (cache / "module.cpython-312.pyc").write_bytes(b"\x01"))
        == "unchanged"
    )
    # Anything else written there is (review finding 3).
    assert _around(store, root, lambda: (cache / "answer.txt").write_text("UNREVIEWED")) == (
        "changed"
    )
    assert _around(store, root, lambda: (cache / "answer.txt").write_text("again")) == "changed"


def test_finishup_receipts_and_owned_state_are_not_the_workspace(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    (root / ".state").mkdir()
    store = _store(tmp_path)
    assert (
        store.capture_before(
            str(root), "call", deadline=time.monotonic() + 10, excluded=(".state",)
        )
        is None
    )
    (root / "finishup_receipt.md").write_text("receipt")
    (root / "output").mkdir()
    (root / "output" / "yoetz_receipt.json").write_text("{}")
    (root / ".state" / "ledger.sqlite").write_text("rows")
    reading = store.effect_after(
        str(root),
        "call",
        deadline=time.monotonic() + 10,
        call_complete=True,
        excluded=(".state",),
    )
    # ``output/`` itself is a new directory: creating it is a workspace change.
    assert reading.effect == "changed"
    (root / "output" / "yoetz_receipt.json").unlink()
    (root / "output").rmdir()
    assert (
        store.capture_before(
            str(root), "call", deadline=time.monotonic() + 10, excluded=(".state",)
        )
        is None
    )
    (root / "finishup_receipt.md").write_text("receipt again")
    (root / ".state" / "ledger.sqlite").write_text("more rows")
    reading = store.effect_after(
        str(root),
        "call",
        deadline=time.monotonic() + 10,
        call_complete=True,
        excluded=(".state",),
    )
    assert reading.effect == "unchanged"


def test_links_are_compared_by_target_and_never_followed(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "data.txt").write_text("a")
    (root / "link").symlink_to(outside)
    store = _store(tmp_path)
    # A write behind a directory link is outside the workspace and is not walked.
    assert _around(store, root, lambda: (outside / "data.txt").write_text("b")) == "unchanged"

    def retarget() -> None:
        (root / "link").unlink()
        (root / "link").symlink_to(tmp_path)

    assert _around(store, root, retarget) == "changed"


def test_a_replaced_root_is_changed(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    store = _store(tmp_path)
    assert store.capture_before(str(root), "call", deadline=time.monotonic() + 10) is None
    os.rename(root, tmp_path / "moved")
    _workspace(tmp_path)
    for path in (tmp_path / "moved").rglob("*"):
        if path.is_file():
            (root / path.relative_to(tmp_path / "moved")).write_bytes(path.read_bytes())
    reading = store.effect_after(
        str(root), "call", deadline=time.monotonic() + 10, call_complete=True
    )
    assert reading.effect == "changed"


@pytest.mark.parametrize(
    "setup,reason",
    [
        ("missing_pre", "no_pre_snapshot"),
        ("incomplete", "call_incomplete"),
        ("tampered", "no_pre_snapshot"),
        ("other_key", "no_pre_snapshot"),
    ],
)
def test_unestablished_comparisons_are_unavailable(tmp_path: Path, setup: str, reason: str) -> None:
    root = _workspace(tmp_path)
    store = _store(tmp_path)
    if setup != "missing_pre":
        assert store.capture_before(str(root), "call", deadline=time.monotonic() + 10) is None
    if setup == "tampered":
        (pending,) = (tmp_path / "state" / "fp" / "pending").iterdir()
        data = bytearray(pending.read_bytes())
        data[40] ^= 1
        pending.write_bytes(bytes(data))
    if setup == "other_key":
        store = WorkspaceFingerprintStore(tmp_path / "state" / "fp", b"v" * 32)
    reading = store.effect_after(
        str(root),
        "call",
        deadline=time.monotonic() + 10,
        call_complete=setup != "incomplete",
    )
    assert (reading.effect, reading.reason) == ("unavailable", reason)
    # The pending snapshot is consumed either way: a replayed post cannot reuse it.
    again = store.effect_after(
        str(root), "call", deadline=time.monotonic() + 10, call_complete=True
    )
    assert (again.effect, again.reason) == ("unavailable", "no_pre_snapshot")


def test_walk_bounds_make_the_comparison_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _workspace(tmp_path)
    for index in range(40):
        (root / f"f{index}.txt").write_text(str(index))
    store = _store(tmp_path)
    monkeypatch.setattr(fingerprint, "MAX_ENTRIES", 10)
    assert store.capture_before(str(root), "call", deadline=time.monotonic() + 10) == "too_large"
    reading = store.effect_after(
        str(root), "call", deadline=time.monotonic() + 10, call_complete=True
    )
    assert (reading.effect, reading.reason) == ("unavailable", "too_large")
    # A workspace that just exceeded the bound is not walked again on every call.
    monkeypatch.setattr(fingerprint, "MAX_ENTRIES", 60_000)
    walked: list[str] = []
    real_walk = WorkspaceFingerprintStore._walk  # pyright: ignore[reportPrivateUsage]

    def counting_walk(self: WorkspaceFingerprintStore, *args: object, **kwargs: object) -> object:
        walked.append("walk")
        return real_walk(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(WorkspaceFingerprintStore, "_walk", counting_walk)
    assert store.capture_before(str(root), "call", deadline=time.monotonic() + 10) == "too_large"
    reading = store.effect_after(
        str(root), "call", deadline=time.monotonic() + 10, call_complete=True
    )
    assert (reading.effect, reading.reason) == ("unavailable", "too_large")
    assert walked == []
    # Once the back-off has passed, the next call walks and compares normally again.
    marker = tmp_path / "state" / "fp" / "bounded"
    os.utime(marker, (time.time() - 3600, time.time() - 3600))
    assert store.capture_before(str(root), "call", deadline=time.monotonic() + 10) is None
    reading = store.effect_after(
        str(root), "call", deadline=time.monotonic() - 1, call_complete=True
    )
    assert (reading.effect, reading.reason) == ("unavailable", "timeout")


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every directory")
def test_an_unreadable_directory_makes_the_comparison_unavailable(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    locked = root / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        store = _store(tmp_path)
        assert store.capture_before(str(root), "call", deadline=time.monotonic() + 10) == (
            "unreadable"
        )
    finally:
        locked.chmod(0o700)


def test_snapshots_hold_no_path_or_content_and_revoke_removes_them(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    secret = "zq1080canary"
    (root / f"{secret}.txt").write_text(secret)
    store = _store(tmp_path)
    assert _around(store, root) == "unchanged"
    stored = b"".join(
        path.read_bytes() for path in (tmp_path / "state").rglob("*") if path.is_file()
    )
    assert secret.encode() not in stored
    assert b"module.py" not in stored
    store.discard()
    assert not (tmp_path / "state" / "fp").exists()


def test_a_realistic_tree_fits_the_bound(tmp_path: Path) -> None:
    """A 5,000-entry tree is fingerprinted twice well inside one snapshot's time bound."""

    root = tmp_path / "workspace"
    for package in range(50):
        directory = root / "src" / f"package_{package}"
        directory.mkdir(parents=True)
        for module in range(99):
            (directory / f"module_{module}.py").write_text(f"VALUE = {module}\n")
    store = _store(tmp_path)
    started = time.monotonic()
    assert store.capture_before(str(root), "call", deadline=time.monotonic() + 10) is None
    (root / "src" / "package_7" / "module_3.py").write_text("VALUE = -1\n")
    reading = store.effect_after(
        str(root), "call", deadline=time.monotonic() + 10, call_complete=True
    )
    elapsed = time.monotonic() - started
    assert reading.effect == "changed"
    assert elapsed < 2 * fingerprint.SNAPSHOT_SECONDS * 4, elapsed


# --- PR #1080 round 6: quiescence, host window and the whole-pass budget ---------------------


_LAUNCHER = """import subprocess, sys
fds = tuple(int(value) for value in sys.argv[1:])
subprocess.Popen(
    [sys.executable, "worker.py", *sys.argv[1:]],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    pass_fds=fds, start_new_session=True,
)
"""
_WORKER = """import os, sys
from pathlib import Path
os.read(int(sys.argv[1]), 1)
Path("deliverable.txt").write_text("LATE UNREVIEWED")
os.write(int(sys.argv[2]), b"D")
"""


def _process_table_readable() -> bool:
    from finishup.adapters.process_lifetime import lingering_process, process_clock_ns

    window = process_clock_ns()
    return window is not None and lingering_process(window, "/nonexistent-fp-root") is False


def launch_lingering_worker(cwd: Path) -> tuple[int, int]:
    """Run a launcher that exits 0 while its new-session child waits on a pipe.

    Returns the write end that releases the child and the read end it signals completion on.
    The caller must release and await it with a bounded wait (never a sleep).
    """

    import subprocess
    import sys

    (cwd / "launch.py").write_text(_LAUNCHER)
    (cwd / "worker.py").write_text(_WORKER)
    release_read, release_write = os.pipe()
    done_read, done_write = os.pipe()
    subprocess.run(
        [sys.executable, "launch.py", str(release_read), str(done_write)],
        cwd=cwd,
        pass_fds=(release_read, done_write),
        check=True,
    )
    os.close(release_read)
    os.close(done_write)
    return release_write, done_read


def release_worker(release_write: int, done_read: int) -> None:
    import select

    try:
        os.write(release_write, b"G")
        ready, _write, _error = select.select([done_read], [], [], 30)
        assert ready, "the released child did not finish within the bound"
        assert os.read(done_read, 1) == b"D"
    finally:
        os.close(release_write)
        os.close(done_read)


@pytest.mark.skipif(not _process_table_readable(), reason="no readable process table here")
def test_a_child_left_running_in_the_workspace_makes_the_comparison_unavailable(
    tmp_path: Path,
) -> None:
    """Review finding 2: a foreground exit does not prove the workspace quiescent."""

    root = _workspace(tmp_path)
    (root / "deliverable.txt").write_text("reviewed")
    store = _store(tmp_path)
    assert store.capture_before(str(root), "call", deadline=time.monotonic() + 10) is None
    release_write, done_read = launch_lingering_worker(root)
    try:
        reading = store.effect_after(
            str(root), "call", deadline=time.monotonic() + 10, call_complete=True
        )
    finally:
        release_worker(release_write, done_read)
    assert (reading.effect, reading.reason) == ("unavailable", "call_incomplete")
    # The child really did write after the post-call pass: "unchanged" would have been false.
    assert (root / "deliverable.txt").read_text() == "LATE UNREVIEWED"


@pytest.mark.skipif(not _process_table_readable(), reason="no readable process table here")
def test_a_child_left_running_elsewhere_does_not_block_the_comparison(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    store = _store(tmp_path)
    assert store.capture_before(str(root), "call", deadline=time.monotonic() + 10) is None
    release_write, done_read = launch_lingering_worker(elsewhere)
    try:
        reading = store.effect_after(
            str(root), "call", deadline=time.monotonic() + 10, call_complete=True
        )
    finally:
        release_worker(release_write, done_read)
    assert reading.effect == "unchanged"


@pytest.mark.parametrize("answer", [True, None])
def test_a_lingering_or_unknowable_process_table_is_unavailable(
    tmp_path: Path, answer: bool | None
) -> None:
    root = _workspace(tmp_path)
    seen: list[tuple[int, str]] = []

    def probe(window: int, workspace: str) -> bool | None:
        seen.append((window, workspace))
        return answer

    store = WorkspaceFingerprintStore(tmp_path / "state" / "fp", _KEY, lingering=probe)
    readings: list[fingerprint.WorkspaceEffectReading] = []
    for call in ("a", "b"):
        assert store.capture_before(str(root), call, deadline=time.monotonic() + 10) is None
        readings.append(
            store.effect_after(str(root), call, deadline=time.monotonic() + 10, call_complete=True)
        )
    reason = "call_incomplete" if answer else "process_table_unreadable"
    assert [(r.effect, r.reason) for r in readings] == [("unavailable", reason)] * 2
    # A lingering process is a per-call fact; an unreadable table is a standing condition that
    # is named once, then stays quiet in diagnostics while it lasts.
    assert [r.fresh for r in readings] == ([True, True] if answer else [True, False])
    # The window handed to the probe is the authenticated pre-call start, never zero.
    assert len(seen) == 2 and seen[0][0] > 0 and seen[0][1] == str(root)


@pytest.mark.parametrize("change", ["create", "remove"])
def test_a_directory_written_during_the_post_walk_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """The review's walk race: an entry created after the listing finished is not missed."""

    root = _workspace(tmp_path)
    (root / "old.txt").write_text("reviewed")
    store = _store(tmp_path)
    future = time.time_ns() + 3_000_000_000
    monkeypatch.setattr(fingerprint.time, "time_ns", lambda: future)
    assert store.capture_before(str(root), "call", deadline=time.monotonic() + 10) is None
    real_scandir = os.scandir
    done: list[bool] = []

    class _Iterator:
        def __init__(self, path: str) -> None:
            self._iterator = real_scandir(path)

        def __enter__(self) -> _Iterator:
            self._iterator.__enter__()
            return self

        def __exit__(self, *args: object) -> None:
            self._iterator.__exit__(*args)  # type: ignore[arg-type]

        def __iter__(self) -> _Iterator:
            return self

        def __next__(self) -> os.DirEntry[str]:
            try:
                return next(self._iterator)
            except StopIteration:
                if not done:
                    done.append(True)
                    if change == "create":
                        (root / "new-answer.txt").write_text("unreviewed")
                    else:
                        (root / "old.txt").unlink()
                raise

    monkeypatch.setattr(fingerprint.os, "scandir", _Iterator)
    reading = store.effect_after(
        str(root), "call", deadline=time.monotonic() + 10, call_complete=True
    )
    assert reading.effect == "unavailable", reading


@pytest.mark.parametrize("writer_started_in_call", [False, True])
def test_an_in_place_rewrite_during_the_post_walk_is_judged_by_who_wrote_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, writer_started_in_call: bool
) -> None:
    """The review's walk-race rewrite: the explicitly narrower guarantee of round 6 (ADR-033).

    A process the call started and that still runs in the workspace is caught before the walk,
    so its rewrite cannot slip in. A process that predates the call (here, this test process,
    acting like an editor or another agent) rewriting an already compared file in place after
    the walk passed it is outside the fact: the comparison is not an atomic filesystem snapshot.
    """

    root = _workspace(tmp_path)
    target = root / "answer.txt"
    target.write_text("reviewed")
    store = WorkspaceFingerprintStore(
        tmp_path / "state" / "fp", _KEY, lingering=lambda _window, _root: writer_started_in_call
    )
    future = time.time_ns() + 3_000_000_000
    monkeypatch.setattr(fingerprint.time, "time_ns", lambda: future)
    assert store.capture_before(str(root), "call", deadline=time.monotonic() + 10) is None
    real_scandir = os.scandir
    done: list[bool] = []

    class _Iterator:
        def __init__(self, path: str) -> None:
            self._iterator = real_scandir(path)

        def __enter__(self) -> _Iterator:
            self._iterator.__enter__()
            return self

        def __exit__(self, *args: object) -> None:
            self._iterator.__exit__(*args)  # type: ignore[arg-type]

        def __iter__(self) -> _Iterator:
            return self

        def __next__(self) -> os.DirEntry[str]:
            try:
                return next(self._iterator)
            except StopIteration:
                if not done:
                    done.append(True)
                    target.write_text("UNREVIEWED")
                raise

    monkeypatch.setattr(fingerprint.os, "scandir", _Iterator)
    reading = store.effect_after(
        str(root), "call", deadline=time.monotonic() + 10, call_complete=True
    )
    if writer_started_in_call:
        assert (reading.effect, reading.reason) == ("unavailable", "call_incomplete")
        assert not done  # never reached: the lingering writer stopped the pass before the walk
    else:
        assert done and target.read_text() == "UNREVIEWED"
        assert reading.effect == "unchanged"


def test_a_capture_finished_after_the_host_window_is_never_published(tmp_path: Path) -> None:
    """Review finding 4: nothing late is stored, so nothing late can be consumed."""

    root = _workspace(tmp_path)
    store = _store(tmp_path)
    stored: list[str] = []
    real_store = WorkspaceFingerprintStore._store  # pyright: ignore[reportPrivateUsage]

    def recording_store(self: WorkspaceFingerprintStore, path: Path, snapshot: object) -> None:
        stored.append(path.parent.name)
        real_store(self, path, snapshot)  # type: ignore[arg-type]

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(WorkspaceFingerprintStore, "_store", recording_store)
        reason = store.capture_before(
            str(root),
            "call",
            deadline=time.monotonic() + 10,
            host_deadline=time.monotonic() - 1,
        )
    assert reason == "timeout"
    assert "pending" not in stored
    assert not list((tmp_path / "state" / "fp" / "pending").glob("*.bin"))
    reading = store.effect_after(
        str(root), "call", deadline=time.monotonic() + 10, call_complete=True
    )
    assert (reading.effect, reading.reason) == ("unavailable", "timeout")


def test_a_record_whose_capture_missed_its_host_deadline_is_not_trusted(tmp_path: Path) -> None:
    """The authenticated record carries its capture time; the post-call pass re-checks it."""

    root = _workspace(tmp_path)
    store = _store(tmp_path)
    assert (
        store.capture_before(
            str(root), "call", deadline=time.monotonic() + 10, host_deadline=time.monotonic() + 30
        )
        is None
    )
    pending = store._pending_path("call")  # pyright: ignore[reportPrivateUsage]
    snapshot = store._load(pending, delete=False)  # pyright: ignore[reportPrivateUsage]
    assert snapshot is not None and 0 < snapshot.captured_ns <= snapshot.host_deadline_ns
    snapshot.paths = {}
    snapshot.host_deadline_ns = snapshot.captured_ns - 1
    store._store(pending, snapshot)  # pyright: ignore[reportPrivateUsage]
    reading = store.effect_after(
        str(root), "call", deadline=time.monotonic() + 10, call_complete=True
    )
    assert (reading.effect, reading.reason) == ("unavailable", "timeout")


@pytest.mark.parametrize("phase", ["pre", "post"])
def test_a_slow_read_overruns_into_a_timeout_never_a_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    """Review finding 5: the deadline bounds hashing as well as the walk."""

    root = _workspace(tmp_path)
    target = root / "large.bin"
    target.write_bytes(b"x" * (2 * 1024 * 1024))
    store = _store(tmp_path)
    clock = [time.monotonic()]
    real_monotonic = time.monotonic

    def fake_monotonic() -> float:
        return max(real_monotonic(), clock[0])

    real_read = os.read

    def slow_read(descriptor: int, size: int) -> bytes:
        # Deterministic fault injection: every content read advances the observed clock 120 ms.
        clock[0] = fake_monotonic() + 0.12
        return real_read(descriptor, size)

    if phase == "post":
        assert store.capture_before(str(root), "call", deadline=real_monotonic() + 10) is None
        target.write_bytes(b"y" * (2 * 1024 * 1024))
    monkeypatch.setattr(fingerprint.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(fingerprint.os, "read", slow_read)
    started = fake_monotonic()
    if phase == "pre":
        reason = store.capture_before(str(root), "call", deadline=started + 0.75)
        assert reason == "timeout"
    else:
        reading = store.effect_after(str(root), "call", deadline=started + 0.75, call_complete=True)
        assert reading.effect in {"unavailable", "changed"}
        assert reading.reason == "timeout" or reading.effect == "changed"
    # The deadline stopped the read loop within one chunk of the bound.
    assert fake_monotonic() - started < 0.75 + 0.25
    # A hashing overrun does not start the walk back-off.
    assert not (tmp_path / "state" / "fp" / "bounded").exists()


def test_an_unchanged_comparison_past_its_budget_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _workspace(tmp_path)
    store = _store(tmp_path)
    assert store.capture_before(str(root), "call", deadline=time.monotonic() + 10) is None
    real_settled = WorkspaceFingerprintStore._settled  # pyright: ignore[reportPrivateUsage]
    deadline = time.monotonic() + 10
    clock = [0.0]
    real_monotonic = time.monotonic

    def settled(directories: tuple[tuple[str, int], ...]) -> bool:
        clock[0] = deadline + 1  # the re-read itself ran past the budget
        return real_settled(directories)

    monkeypatch.setattr(WorkspaceFingerprintStore, "_settled", staticmethod(settled))
    monkeypatch.setattr(fingerprint.time, "monotonic", lambda: max(real_monotonic(), clock[0]))
    reading = store.effect_after(str(root), "call", deadline=deadline, call_complete=True)
    assert (reading.effect, reading.reason) == ("unavailable", "timeout")


@pytest.mark.skipif(__import__("shutil").which("git") is None, reason="git is not installed")
def test_real_git_bookkeeping_is_quiet_and_a_config_change_is_not(tmp_path: Path) -> None:
    """Round 6 narrowed ``.git``: status, commit and branch traffic stay quiet; config does not."""

    import subprocess

    root = _workspace(tmp_path)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp_path),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=root, env=env, check=True, capture_output=True)

    git("init", "-q")
    git("add", "-A")
    git("commit", "-q", "-m", "base")
    store = _store(tmp_path)
    assert _around(store, root, lambda: git("status", "--short")) == "unchanged"
    assert _around(store, root, lambda: git("commit", "-q", "--allow-empty", "-m", "x")) == (
        "unchanged"
    )
    assert _around(store, root, lambda: git("branch", "side")) == "unchanged"
    assert _around(store, root, lambda: git("log", "--oneline")) == "unchanged"
    assert _around(store, root, lambda: git("config", "core.fsmonitor", "./x")) == "changed"
