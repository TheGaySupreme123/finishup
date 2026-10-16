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


def test_opaque_directories_count_by_identity_only(tmp_path: Path) -> None:
    root = _workspace(tmp_path)
    for name in (".git", "node_modules", "__pycache__", ".venv"):
        (root / name).mkdir()
        (root / name / "inner").write_text("a")
    store = _store(tmp_path)
    for name in (".git", "node_modules", "__pycache__", ".venv"):
        assert (
            _around(store, root, lambda name=name: (root / name / "inner").write_text("b"))
            == "unchanged"
        ), name
    assert _around(store, root, lambda: (root / ".pytest_cache").mkdir()) == "changed"
    assert _around(store, root, lambda: os.rename(root / "node_modules", root / "nm")) == "changed"


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
