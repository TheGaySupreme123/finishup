from __future__ import annotations

import os
from pathlib import Path

import pytest

import finishup.adapters.integrations.observation_local as local


@pytest.mark.skipif(local.fcntl is None, reason="POSIX flock is unavailable")
def test_interprocess_store_lock_wait_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock_path = tmp_path / "store.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    assert local.fcntl is not None
    local.fcntl.flock(descriptor, local.fcntl.LOCK_EX | local.fcntl.LOCK_NB)
    monkeypatch.setattr(local, "_STORE_LOCK_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(local, "_STORE_LOCK_POLL_SECONDS", 0.005)
    try:
        with pytest.raises(TimeoutError, match="observation_store_lock_timeout"):
            with local._InterprocessStoreLock(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
                lock_path
            ):
                pytest.fail("the contended lock must not be entered")
    finally:
        local.fcntl.flock(descriptor, local.fcntl.LOCK_UN)
        os.close(descriptor)


@pytest.mark.skipif(local.fcntl is None, reason="POSIX flock is unavailable")
def test_contended_wait_is_attributed_even_when_it_times_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#310/#311: queueing was charged to the pass but named by no stage."""

    lock_path = tmp_path / "store.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    assert local.fcntl is not None
    local.fcntl.flock(descriptor, local.fcntl.LOCK_EX | local.fcntl.LOCK_NB)
    monkeypatch.setattr(local, "_STORE_LOCK_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(local, "_STORE_LOCK_POLL_SECONDS", 0.005)
    waits: dict[str, float] = {"lock_wait": 0.0}
    try:
        with pytest.raises(TimeoutError, match="observation_store_lock_timeout"):
            with local._InterprocessStoreLock(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
                lock_path, waits_ms=waits
            ):
                pytest.fail("the contended lock must not be entered")
    finally:
        local.fcntl.flock(descriptor, local.fcntl.LOCK_UN)
        os.close(descriptor)
    # A pass that waited out the ceiling and then failed still spent that time.
    assert waits["lock_wait"] >= 50.0
