"""Restart-safe passphrase throttle contract coverage."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from finishup.service.unlock import (
    UnlockError,
    UnlockThrottleRecord,
    UnlockThrottleStore,
    passphrase_delay_seconds,
)

INSTALLATION_ID = "ins_10000000-0000-4000-8000-000000000001"
SERVICE_ID = "svc_10000000-0000-4000-8000-000000000002"
SUCCESSOR_SERVICE_ID = "svc_10000000-0000-4000-8000-000000000003"


@dataclass
class _Clock:
    monotonic: float = 100.0
    utc: datetime = datetime(2026, 7, 19, 12, 0, 0, tzinfo=UTC)

    def now_utc(self) -> datetime:
        return self.utc

    def monotonic_seconds(self) -> float:
        return self.monotonic


def _private_directory(path: Path) -> Path:
    path.chmod(0o700)
    return path


def _store(path: Path, clock: _Clock) -> UnlockThrottleStore:
    return UnlockThrottleStore(
        path,
        installation_id=INSTALLATION_ID,
        writer_instance_id=SERVICE_ID,
        clock=clock,
    )


def test_record_digest_and_canonical_lf_vector() -> None:
    record = UnlockThrottleRecord.create(
        installation_id=INSTALLATION_ID,
        record_generation=1,
        consecutive_failures=0,
        attempt_in_progress=False,
        last_failure_utc=None,
        last_writer_instance_id=SERVICE_ID,
    )
    assert record.record_digest == (
        "sha256:1fda9b379a5dca9cd3155dab77ff5807e4932d4fcc2fe0bd023044214843ef80"
    )
    encoded = record.encode()
    assert encoded.endswith(b"}\n")
    assert not encoded.endswith(b"\n\n")
    assert UnlockThrottleRecord.decode(encoded) == record


@pytest.mark.parametrize(
    ("failures", "delay"),
    [(0, 0), (1, 0), (2, 0), (3, 30), (4, 60), (5, 120), (6, 240), (7, 300), (63, 300)],
)
def test_exact_delay_table(failures: int, delay: int) -> None:
    assert passphrase_delay_seconds(failures) == delay


def test_atomic_owner_only_record_and_success_reset(tmp_path: Path) -> None:
    directory = _private_directory(tmp_path)
    path = directory / "unlock-throttle.json"
    clock = _Clock()
    store = _store(path, clock)
    initial = store.stage_initial_record()
    assert initial.record_generation == 1
    facts = path.lstat()
    assert stat.S_ISREG(facts.st_mode)
    assert stat.S_IMODE(facts.st_mode) == 0o600
    assert facts.st_nlink == 1
    assert facts.st_uid == os.geteuid()
    assert not tuple(directory.glob("*.tmp"))

    reserved = store.reserve_attempt()
    assert reserved.attempt_in_progress
    assert reserved.record_generation == 2
    reset = store.reset_success()
    assert reset.consecutive_failures == 0
    assert not reset.attempt_in_progress
    assert reset.last_failure_utc is None
    assert reset.record_generation == 3


def test_successor_adopts_only_exact_provisional_initial_record(tmp_path: Path) -> None:
    path = _private_directory(tmp_path) / "unlock-throttle.json"
    clock = _Clock()
    staged = _store(path, clock).stage_initial_record()
    staged_bytes = path.read_bytes()
    successor = UnlockThrottleStore(
        path,
        installation_id=INSTALLATION_ID,
        writer_instance_id=SUCCESSOR_SERVICE_ID,
        clock=clock,
    )

    adopted = successor.stage_or_adopt_initial_record()

    assert adopted == staged
    assert adopted.last_writer_instance_id == SERVICE_ID
    assert path.read_bytes() == staged_bytes
    successor.reserve_attempt()
    with pytest.raises(UnlockError, match="throttle_record_exists"):
        UnlockThrottleStore(
            path,
            installation_id=INSTALLATION_ID,
            writer_instance_id=SUCCESSOR_SERVICE_ID,
            clock=clock,
        ).stage_or_adopt_initial_record()


def test_failure_is_charged_before_delay_and_restart_rearms_full_delay(tmp_path: Path) -> None:
    path = _private_directory(tmp_path) / "unlock-throttle.json"
    clock = _Clock()
    store = _store(path, clock)
    store.stage_initial_record()
    for expected in (1, 2, 3):
        store.reserve_attempt()
        record = store.charge_failure()
        assert record.consecutive_failures == expected
        if expected < 3:
            assert store.remaining_delay() == 0.0

    assert store.remaining_delay() == 30.0
    restarted_clock = _Clock(monotonic=900.0, utc=clock.utc)
    restarted = _store(path, restarted_clock)
    restarted.open_for_restart()
    assert restarted.remaining_delay() == 30.0
    restarted_clock.monotonic = 929.999
    assert restarted.remaining_delay() == pytest.approx(0.001)
    restarted_clock.monotonic = 930.0
    assert restarted.remaining_delay() == 0.0


def test_in_progress_crash_is_charged_before_restart_admission(tmp_path: Path) -> None:
    path = _private_directory(tmp_path) / "unlock-throttle.json"
    clock = _Clock()
    store = _store(path, clock)
    store.stage_initial_record()
    store.reserve_attempt()

    restarted = _store(path, _Clock(monotonic=500.0, utc=clock.utc))
    recovered = restarted.open_for_restart()
    assert recovered.consecutive_failures == 1
    assert not recovered.attempt_in_progress
    assert recovered.last_failure_utc == "2026-07-19T12:00:00.000Z"
    assert recovered.record_generation == 3


def test_wall_rollback_arms_maximum_and_requires_repair(tmp_path: Path) -> None:
    path = _private_directory(tmp_path) / "unlock-throttle.json"
    first_clock = _Clock(utc=datetime(2026, 7, 19, 13, 0, 0, tzinfo=UTC))
    first = _store(path, first_clock)
    first.stage_initial_record()
    first.reserve_attempt()
    first.charge_failure()

    rolled_back = _store(
        path,
        _Clock(monotonic=50.0, utc=datetime(2026, 7, 19, 12, 0, 0, tzinfo=UTC)),
    )
    rolled_back.open_for_restart()
    assert rolled_back.repair_required
    assert rolled_back.remaining_delay() == 300.0
    with pytest.raises(UnlockError, match="throttle_repair_required"):
        rolled_back.reserve_attempt()


def test_corrupt_or_unsafe_record_never_opens_an_immediate_attempt(tmp_path: Path) -> None:
    path = _private_directory(tmp_path) / "unlock-throttle.json"
    clock = _Clock(monotonic=7.0)
    store = _store(path, clock)
    store.stage_initial_record()
    path.write_bytes(path.read_bytes().replace(b'"record_generation":1', b'"record_generation":2'))
    path.chmod(0o600)

    restarted = _store(path, clock)
    with pytest.raises(UnlockError, match="throttle_record_tampered"):
        restarted.open_for_restart()
    assert restarted.repair_required
    clock.monotonic = 8.0
    assert restarted.remaining_delay() == 299.0

    path.chmod(0o644)
    unsafe = _store(path, _Clock())
    with pytest.raises(UnlockError, match="throttle_record_unsafe"):
        unsafe.open_for_restart()
    assert unsafe.repair_required
