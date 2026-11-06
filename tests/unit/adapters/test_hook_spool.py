from __future__ import annotations

import fcntl
import os
import threading
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest

from finishup.adapters.integrations.hook_spool import HookSpool
from finishup.protocol.canonical import canonical_encode


def _spool(tmp_path: Path) -> tuple[HookSpool, str, str]:
    observation = tmp_path / "observation"
    observation.mkdir()
    (observation / "key-material.bin").write_bytes(b"k" * 32)
    workspace = str(tmp_path)
    spool = HookSpool(_state=tmp_path)
    return spool, workspace, spool.workspace_commitment(workspace)


def _append(spool: HookSpool, workspace: str, event_name: str) -> None:
    assert spool.append(
        workspace=workspace,
        event_name=event_name,
        payload={"session_id": "session-1", "tool_name": event_name},
    )


def test_claim_advances_a_durable_cursor_across_large_file_batches(tmp_path: Path) -> None:
    spool, workspace, commitment = _spool(tmp_path)
    for ordinal in range(5):
        _append(spool, workspace, f"Event{ordinal}")

    seen: list[str] = []
    for expected in (("Event0", "Event1"), ("Event2", "Event3"), ("Event4",)):
        with spool.claim(commitment, limit=2) as records:
            current = tuple(record.event_name for record in records)
            seen.extend(current)
            assert current == expected
        if expected != ("Event4",):
            assert spool.pending_workspaces() == (commitment,)

    assert seen == ["Event0", "Event1", "Event2", "Event3", "Event4"]
    assert spool.pending_workspaces() == ()


def _spool_files(tmp_path: Path) -> dict[str, int]:
    return {path.name: path.stat().st_size for path in (tmp_path / "hook-spool").iterdir()}


@contextmanager
def _hook_holds_lock(tmp_path: Path, commitment: str) -> Generator[None]:
    """Hold the workspace's spool lock as a hook does, through its own open file description."""

    digest = commitment.removeprefix("hmac-sha256:")
    descriptor = os.open(tmp_path / "hook-spool" / f"{digest}.lock", os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        # Closing the descriptor releases the lock.
        os.close(descriptor)


class _ObservedStop(threading.Event):
    """A stop flag that reports when a claim first waits on it."""

    def __init__(self) -> None:
        super().__init__()
        self.waited_on = threading.Event()

    def wait(self, timeout: float | None = None) -> bool:
        self.waited_on.set()
        return super().wait(timeout)


def _claim_in_thread(
    spool: HookSpool, commitment: str, stop: threading.Event
) -> tuple[threading.Thread, list[tuple[str, ...]]]:
    claimed: list[tuple[str, ...]] = []

    def claim() -> None:
        with spool.claim(commitment, stop=stop) as records:
            claimed.append(tuple(record.event_name for record in records))

    # Daemon, so a claim that never returns fails its test without holding the run open.
    worker = threading.Thread(target=claim, daemon=True)
    worker.start()
    return worker, claimed


def test_claim_told_to_stop_leaves_the_spool_as_it_was(tmp_path: Path) -> None:
    spool, workspace, commitment = _spool(tmp_path)
    _append(spool, workspace, "Event0")
    spooled = _spool_files(tmp_path)
    stop = threading.Event()
    stop.set()

    with spool.claim(commitment, stop=stop) as records:
        assert records == ()

    assert _spool_files(tmp_path) == spooled
    with spool.claim(commitment) as records:
        assert tuple(record.event_name for record in records) == ("Event0",)
    assert spool.pending_workspaces() == ()


def test_claim_waiting_for_a_hooks_lock_returns_at_once_when_told_to_stop(
    tmp_path: Path,
) -> None:
    """A hook that keeps its spool lock cannot keep a stopped claim's thread waiting."""

    spool, workspace, commitment = _spool(tmp_path)
    _append(spool, workspace, "Event0")
    spooled = _spool_files(tmp_path)
    stop = _ObservedStop()

    with _hook_holds_lock(tmp_path, commitment):
        worker, claimed = _claim_in_thread(spool, commitment, stop)
        # The claim has found the lock busy and is waiting for it.
        assert stop.waited_on.wait(5.0)
        stop.set()
        worker.join(5.0)
        # Still inside the hook's hold: the claim gave up the wait rather than outlasting it.
        assert not worker.is_alive()
        assert claimed == [()]
        assert _spool_files(tmp_path) == spooled

    assert _spool_files(tmp_path) == spooled
    with spool.claim(commitment) as records:
        assert tuple(record.event_name for record in records) == ("Event0",)


def test_claim_waiting_for_a_hooks_lock_claims_once_the_hook_lets_go(tmp_path: Path) -> None:
    spool, workspace, commitment = _spool(tmp_path)
    _append(spool, workspace, "Event0")
    stop = _ObservedStop()

    with _hook_holds_lock(tmp_path, commitment):
        worker, claimed = _claim_in_thread(spool, commitment, stop)
        assert stop.waited_on.wait(5.0)
        # Waiting with a stop flag that is not set keeps waiting while the hook holds the lock.
        assert worker.is_alive()
        assert claimed == []

    worker.join(5.0)
    assert not worker.is_alive()
    assert claimed == [("Event0",)]
    assert spool.pending_workspaces() == ()


def test_append_during_claim_is_ordered_after_the_claimed_batch(tmp_path: Path) -> None:
    spool, workspace, commitment = _spool(tmp_path)
    _append(spool, workspace, "Event0")
    _append(spool, workspace, "Event1")

    with spool.claim(commitment, limit=1) as records:
        assert tuple(record.event_name for record in records) == ("Event0",)
        _append(spool, workspace, "Event2")

    with spool.claim(commitment, limit=10) as records:
        assert tuple(record.event_name for record in records) == ("Event1", "Event2")
    assert spool.pending_workspaces() == ()


def test_failed_claim_keeps_the_batch_for_at_least_once_replay(tmp_path: Path) -> None:
    spool, workspace, commitment = _spool(tmp_path)
    _append(spool, workspace, "Event0")

    with pytest.raises(RuntimeError, match="stop_before_commit"):
        with spool.claim(commitment, limit=1) as records:
            assert tuple(record.event_name for record in records) == ("Event0",)
            raise RuntimeError("stop_before_commit")

    with spool.claim(commitment, limit=1) as records:
        assert tuple(record.event_name for record in records) == ("Event0",)


def test_stale_offset_is_cleared_before_a_new_pending_file_is_claimed(tmp_path: Path) -> None:
    spool, workspace, commitment = _spool(tmp_path)
    _append(spool, workspace, "Old0")
    _append(spool, workspace, "Old1")
    with spool.claim(commitment, limit=1) as records:
        assert tuple(record.event_name for record in records) == ("Old0",)

    digest = commitment.removeprefix("hmac-sha256:")
    draining = tmp_path / "hook-spool" / f"{digest}.draining"
    offset = tmp_path / "hook-spool" / f"{digest}.offset"
    assert draining.exists()
    assert offset.exists()
    # Model a crash after the draining inode was removed but before its cursor cleanup.
    draining.unlink()
    _append(spool, workspace, "New0")
    _append(spool, workspace, "New1")

    with spool.claim(commitment, limit=10) as records:
        assert tuple(record.event_name for record in records) == ("New0", "New1")
    assert not offset.exists()


def test_oversized_line_fragments_are_skipped_until_the_next_newline(tmp_path: Path) -> None:
    spool, workspace, commitment = _spool(tmp_path)
    digest = commitment.removeprefix("hmac-sha256:")
    spool_root = tmp_path / "hook-spool"
    spool_root.mkdir(exist_ok=True)
    path = spool_root / f"{digest}.jsonl"
    valid_tail = canonical_encode(
        {
            "event": "LooksValidButIsPartOfGarbage",
            "payload": {"session_id": "session-1"},
            "workspace_commitment": commitment,
        }
    )
    path.write_bytes(b"x" * 9_000 + valid_tail + b"\n")
    path.chmod(0o600)
    _append(spool, workspace, "LegitimateAfterGarbage")

    with spool.claim(commitment, limit=64) as records:
        assert tuple(record.event_name for record in records) == ("LegitimateAfterGarbage",)


def test_old_claim_cannot_commit_against_a_replaced_draining_inode(tmp_path: Path) -> None:
    spool, workspace, commitment = _spool(tmp_path)
    _append(spool, workspace, "Old")

    old_claim = spool.claim(commitment, limit=1)
    assert tuple(record.event_name for record in old_claim.__enter__()) == ("Old",)
    old_closed = False
    try:
        # A later generation consumes and removes the old inode while the first worker is still
        # handling its snapshot.
        with spool.claim(commitment, limit=1) as records:
            assert tuple(record.event_name for record in records) == ("Old",)
        _append(spool, workspace, "New")
        new_claim = spool.claim(commitment, limit=1)
        try:
            assert tuple(record.event_name for record in new_claim.__enter__()) == ("New",)
            old_claim.__exit__(None, None, None)
            old_closed = True
            draining = (
                tmp_path / "hook-spool" / (f"{commitment.removeprefix('hmac-sha256:')}.draining")
            )
            assert draining.exists()
        finally:
            new_claim.__exit__(None, None, None)
    finally:
        if not old_closed:
            old_claim.__exit__(None, None, None)


def test_claim_limit_must_be_positive(tmp_path: Path) -> None:
    spool, _workspace, commitment = _spool(tmp_path)
    for invalid in (0, -1, True, 1.0):
        with pytest.raises(ValueError, match="hook_spool_claim_limit_invalid"):
            with spool.claim(commitment, limit=invalid):  # type: ignore[arg-type]
                pass
