"""The bounded per-(host, event, path) timing aggregate over every hook pass (issue #915)."""

from __future__ import annotations

import fcntl
import json
import os
import random
import threading
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from finishup.cli import hook_timing, observe_hooks
from finishup.cli.hook_diagnostics import hook_diagnostic_summary, record_hook_diagnostic
from finishup.cli.hook_timing import (
    BUCKET_UPPER_BOUNDS_MS,
    HookPassTiming,
    hook_pass_timing_summary,
    hook_pass_timing_text,
    record_hook_pass_timing,
)
from finishup.config.paths import PathSafetyError
from finishup.domain.values import JsonObject

_NOW = datetime(2026, 9, 29, 16, 52, 45, 737000, tzinfo=UTC)


def _entries(state: Path, *, now: datetime = _NOW) -> list[Mapping[str, object]]:
    summary = hook_pass_timing_summary(_state=state, _now=now)
    return [
        cast(Mapping[str, object], entry) for entry in cast(tuple[object, ...], summary["entries"])
    ]


def _nearest_rank(samples: Sequence[int], percent: int) -> int:
    ordered = sorted(samples)
    return ordered[max(1, (percent * len(ordered) + 99) // 100) - 1]


def _bucket_edges(value: int, maximum: int) -> tuple[int, int]:
    """Return the (exclusive lower, inclusive upper) histogram edges that contain *value*."""

    lower = 0
    for bound in BUCKET_UPPER_BOUNDS_MS:
        if value <= bound:
            return lower, min(bound, maximum)
        lower = bound
    return lower, maximum


def test_every_pass_counts_with_exact_count_sum_mean_and_max(tmp_path: Path) -> None:
    samples = [8, 140, 150, 151, 480, 760, 910, 2_200]
    for index, sample in enumerate(samples):
        assert record_hook_pass_timing(
            "codex",
            "PostToolUse",
            "observe",
            "ingested" if index else "not_ingested",
            ms=sample,
            _state=tmp_path,
            _now=_NOW + timedelta(seconds=index),
        )

    (entry,) = _entries(tmp_path, now=_NOW + timedelta(seconds=10))
    assert entry["host"] == "codex"
    assert entry["event"] == "PostToolUse"
    assert entry["path"] == "observe"
    assert entry["count"] == len(samples)
    assert entry["sum_ms"] == sum(samples)
    assert entry["mean_ms"] == sum(samples) // len(samples)
    assert entry["max_ms"] == 2_200
    assert entry["max_ts"] == "2026-09-29T16:52:52.737000Z"
    assert entry["first_seen"] == "2026-09-29T16:52:45.737000Z"
    assert entry["last_seen"] == "2026-09-29T16:52:52.737000Z"
    assert entry["outcomes"] == {
        "ingested": 7,
        "followup_deferred": 0,
        "not_ingested": 1,
        "failed": 0,
    }
    buckets = cast(tuple[int, ...], entry["bucket_counts"])
    assert len(buckets) == len(BUCKET_UPPER_BOUNDS_MS) + 1
    assert sum(buckets) == len(samples)
    # 150 ms is an exact bucket edge, so the share within the Codex per-call goal is exact.
    within_goal = sum(buckets[: BUCKET_UPPER_BOUNDS_MS.index(150) + 1])
    assert within_goal == sum(sample <= 150 for sample in samples) == 3
    # Nearest-rank p50 is 151 ms and p95 is 2200 ms; reported as their bucket upper bounds.
    assert entry["p50_ms_at_most"] == 200
    assert entry["p95_ms_at_most"] == 2_200


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_percentiles_are_honest_bucket_bounds_over_every_sample(tmp_path: Path, seed: int) -> None:
    generator = random.Random(seed)
    samples = [
        int(generator.lognormvariate(6.4, 0.7)) if index % 7 else generator.randrange(0, 20_000)
        for index in range(301)
    ]
    for sample in samples:
        record_hook_pass_timing(
            "cursor", "postToolUse", "ordinary", "ingested", ms=sample, _state=tmp_path, _now=_NOW
        )

    (entry,) = _entries(tmp_path)
    maximum = max(samples)
    assert entry["count"] == len(samples)
    assert entry["max_ms"] == maximum
    for percent, key in ((50, "p50_ms_at_most"), (95, "p95_ms_at_most")):
        exact = _nearest_rank(samples, percent)
        lower, upper = _bucket_edges(exact, maximum)
        # The reported value is an upper bound of the exact percentile, and no looser than the
        # bucket that holds it.
        assert lower < exact <= cast(int, entry[key]) == upper


def test_a_drain_pass_that_delivered_nothing_keeps_one_tally_across_its_rename(
    tmp_path: Path,
) -> None:
    """tb4n5: ``drain_budget_exhausted`` is read back as ``drain_pass_delivered_nothing``.

    The owner kept the 0.2 s hook drain budget and renamed the counter to say what it counts: one
    hook pass that delivered no row within the budget. Rows written under the old name before an
    upgrade join the new tally instead of splitting the history in two.
    """

    record_hook_diagnostic("drain_pass_delivered_nothing", "PostToolUse", _state=tmp_path)
    diagnostics = tmp_path / "observation" / "hook-diagnostics.jsonl"
    stamp = json.loads(diagnostics.read_text().splitlines()[0])["ts"]
    with diagnostics.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps({"event": "PreToolUse", "reason": "drain_budget_exhausted", "ts": stamp})
            + "\n"
        )
    # The old name is no longer written.
    record_hook_diagnostic("drain_budget_exhausted", "Stop", _state=tmp_path)

    summary = hook_diagnostic_summary(_state=tmp_path)
    reasons = cast(Mapping[str, Mapping[str, object]], summary["reasons"])
    assert reasons["drain_pass_delivered_nothing"]["count"] == 2
    assert "drain_budget_exhausted" not in reasons
    assert reasons["unknown_reason"]["count"] == 1


def test_ten_thousand_in_budget_passes_do_not_evict_failure_reason_history(
    tmp_path: Path,
) -> None:
    for reason in ("service_unavailable", "drain_pass_delivered_nothing", "mapping_missing"):
        record_hook_diagnostic(reason, "PostToolUse", _state=tmp_path)
    diagnostics = tmp_path / "observation" / "hook-diagnostics.jsonl"
    before = diagnostics.read_bytes()

    # Each pass ends the way a real observe pass ends: the budget/boundary row recorder, then the
    # host entry's aggregate sample. In budget and off a session boundary, only the latter writes.
    for index in range(10_000):
        started = float(index)
        observe_hooks._record_pass_timing(  # pyright: ignore[reportPrivateUsage]
            "PostToolUse",
            entry_started=started,
            stages={"import": 40, "store": 50, "drain": 30},
            monotonic=lambda started=started: started + 0.125,
            _state=tmp_path,
        )
        timing = HookPassTiming("codex", "PostToolUse", "observe", started, outcome="ingested")
        observe_hooks._finish_hook_pass(  # pyright: ignore[reportPrivateUsage]
            timing, monotonic=lambda started=started: started + 0.125, _state=tmp_path
        )

    # Not one byte was added to the failure-reason window, and it never rotated.
    assert diagnostics.read_bytes() == before
    assert not (tmp_path / "observation" / "hook-diagnostics.jsonl.1").exists()
    summary = hook_diagnostic_summary(_state=tmp_path)
    reasons = cast(Mapping[str, Mapping[str, object]], summary["reasons"])
    assert {name: reasons[name]["count"] for name in reasons} == {
        "drain_pass_delivered_nothing": 1,
        "mapping_missing": 1,
        "service_unavailable": 1,
    }
    assert cast(Mapping[str, object], summary["timings"])["count"] == 0
    pass_timings = cast(Mapping[str, object], summary["pass_timings"])
    (entry,) = cast(tuple[Mapping[str, object], ...], pass_timings["entries"])
    assert entry["count"] == 10_000
    assert entry["p50_ms_at_most"] == entry["p95_ms_at_most"] == entry["max_ms"] == 125
    assert entry["outcomes"] == {
        "ingested": 10_000,
        "followup_deferred": 0,
        "not_ingested": 0,
        "failed": 0,
    }
    # The aggregate itself is fixed-size: it does not grow with the number of passes.
    assert (tmp_path / "observation" / "hook-pass-timing.json").stat().st_size < 4_096


def test_hosts_events_and_paths_stay_separate_and_ordered(tmp_path: Path) -> None:
    for host, event, path in (
        ("cursor", "afterMCPExecution", "structural"),
        ("codex", "PostToolUse", "observe"),
        ("claude", "PostToolUse", "ordinary"),
        ("claude", "PostToolUse", "structural"),
        ("codex", "PostToolUse", "sync_fallback_spool"),
        ("codex", "PreToolUse", "observe"),
    ):
        assert record_hook_pass_timing(host, event, path, "ingested", ms=10, _state=tmp_path)

    assert [(e["host"], e["event"], e["path"]) for e in _entries(tmp_path)] == [
        ("claude", "PostToolUse", "ordinary"),
        ("claude", "PostToolUse", "structural"),
        ("codex", "PostToolUse", "observe"),
        ("codex", "PostToolUse", "sync_fallback_spool"),
        ("codex", "PreToolUse", "observe"),
        ("cursor", "afterMCPExecution", "structural"),
    ]


def test_recent_covers_the_current_and_previous_clock_hour_only(tmp_path: Path) -> None:
    hour = _NOW.replace(minute=0, second=0, microsecond=0)
    for offset, sample in (
        (timedelta(hours=-3), 4_000),
        (timedelta(hours=-1), 300),
        (timedelta(0), 90),
    ):
        record_hook_pass_timing(
            "claude",
            "PreToolUse",
            "ordinary",
            "ingested",
            ms=sample,
            _state=tmp_path,
            _now=hour + offset,
        )

    (entry,) = _entries(tmp_path, now=hour + timedelta(minutes=5))
    assert entry["count"] == 3
    assert entry["max_ms"] == 4_000
    assert entry["recent"] == {
        "since": "2026-09-29T15:00:00Z",
        "count": 2,
        "p50_ms_at_most": 100,
        "p95_ms_at_most": 300,
        "max_ms": 300,
    }
    # An hour later the older slot has aged out; nothing is called recent that is not.
    (later,) = _entries(tmp_path, now=hour + timedelta(hours=1, minutes=5))
    assert cast(Mapping[str, object], later["recent"])["count"] == 1
    (stale,) = _entries(tmp_path, now=hour + timedelta(hours=3))
    assert stale["recent"] == {
        "since": None,
        "count": 0,
        "p50_ms_at_most": None,
        "p95_ms_at_most": None,
        "max_ms": None,
    }
    assert stale["count"] == 3


def test_legacy_spool_entry_reads_its_target_and_cap_against_every_pass(tmp_path: Path) -> None:
    for sample in (40, 60, 240, 499, 500, 501, 900):
        record_hook_pass_timing(
            "codex", "PreToolUse", "sync_fallback_spool", "ingested", ms=sample, _state=tmp_path
        )

    (entry,) = _entries(tmp_path)
    assert entry["p95_target_ms"] == 250
    assert entry["hard_cap_ms"] == 500
    assert entry["hard_cap_breach_count"] == 2


def test_unknown_tokens_are_closed_and_an_unknown_event_is_named_as_such(tmp_path: Path) -> None:
    assert not record_hook_pass_timing(
        "other", "PostToolUse", "observe", "ingested", ms=1, _state=tmp_path
    )
    assert not record_hook_pass_timing(
        "codex", "PostToolUse", "custom", "ingested", ms=1, _state=tmp_path
    )
    assert not record_hook_pass_timing(
        "codex", "PostToolUse", "observe", "maybe", ms=1, _state=tmp_path
    )
    assert record_hook_pass_timing(
        "codex", "/private/path PostToolUse", "observe", "ingested", ms=-5, _state=tmp_path
    )

    (entry,) = _entries(tmp_path)
    assert entry["event"] == "unknown_event"
    assert entry["max_ms"] == 0
    raw = (tmp_path / "observation" / "hook-pass-timing.json").read_text()
    assert "/private/path" not in raw


def test_the_aggregate_file_is_owner_only_and_a_tampered_one_restarts(tmp_path: Path) -> None:
    record_hook_pass_timing(
        "codex", "Stop", "observe", "ingested", ms=12, _state=tmp_path, _now=_NOW
    )
    target = tmp_path / "observation" / "hook-pass-timing.json"
    assert target.stat().st_mode & 0o777 == 0o600

    document = json.loads(target.read_text())
    document["entries"][0]["all"]["count"] = 99
    target.write_text(json.dumps(document))
    summary = hook_pass_timing_summary(_state=tmp_path, _now=_NOW)
    assert summary["status"] == "unreadable"
    assert summary["entries"] == ()
    assert hook_pass_timing_text(summary) == "unreadable; restarts on next hook"

    later = _NOW + timedelta(minutes=1)
    assert record_hook_pass_timing(
        "codex", "Stop", "observe", "ingested", ms=7, _state=tmp_path, _now=later
    )
    restarted = hook_pass_timing_summary(_state=tmp_path, _now=later)
    assert restarted["status"] == "retained"
    assert restarted["since"] == "2026-09-29T16:53:45.737000Z"
    assert [entry["count"] for entry in _entries(tmp_path, now=later)] == [1]

    os.chmod(target, 0o644)
    assert hook_pass_timing_summary(_state=tmp_path)["status"] == "unreadable"


def _mutate(entry: dict[str, Any], mutation: str) -> None:
    if mutation == "container_host":
        entry["host"] = ["codex"]
    elif mutation == "container_event":
        entry["event"] = {"PostToolUse": 1}
    elif mutation == "boolean_outcome":
        entry["outcomes"]["ingested"] = True
    elif mutation == "max_outside_its_bucket":
        entry["all"]["max_ms"] = 1
    elif mutation == "duplicate_slot":
        entry["slots"].append(dict(entry["slots"][0]))
    else:
        entry["extra"] = "/private/path"


@pytest.mark.parametrize(
    "mutation",
    [
        "container_host",
        "container_event",
        "boolean_outcome",
        "max_outside_its_bucket",
        "duplicate_slot",
        "unknown_field",
    ],
)
def test_container_or_inconsistent_fields_fail_closed_without_raising(
    tmp_path: Path, mutation: str
) -> None:
    record_hook_pass_timing("codex", "PostToolUse", "observe", "ingested", ms=640, _state=tmp_path)
    target = tmp_path / "observation" / "hook-pass-timing.json"
    document = cast(dict[str, Any], json.loads(target.read_text()))
    _mutate(cast(list[dict[str, Any]], document["entries"])[0], mutation)
    target.write_text(json.dumps(document))

    assert hook_pass_timing_summary(_state=tmp_path)["status"] == "unreadable"
    assert record_hook_pass_timing(
        "codex", "PostToolUse", "observe", "ingested", ms=1, _state=tmp_path
    )
    assert [entry["count"] for entry in _entries(tmp_path, now=datetime.now(UTC))] == [1]


def test_a_symlinked_aggregate_is_neither_read_nor_replaced(tmp_path: Path) -> None:
    directory = tmp_path / "observation"
    directory.mkdir(mode=0o700)
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    (directory / "hook-pass-timing.json").symlink_to(outside)

    assert not record_hook_pass_timing(
        "codex", "Stop", "observe", "ingested", ms=1, _state=tmp_path
    )
    assert outside.read_text() == "{}"
    assert hook_pass_timing_summary(_state=tmp_path)["status"] == "unreadable"


def test_the_entry_cap_evicts_the_stalest_key_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hook_timing, "_MAX_ENTRIES", 3)
    for index, event in enumerate(("PreToolUse", "PostToolUse", "Stop", "SessionEnd")):
        record_hook_pass_timing(
            "codex",
            event,
            "observe",
            "ingested",
            ms=1,
            _state=tmp_path,
            _now=_NOW + timedelta(seconds=index),
        )

    summary = hook_pass_timing_summary(_state=tmp_path, _now=_NOW)
    assert summary["evicted_entry_count"] == 1
    assert sorted(cast(str, entry["event"]) for entry in _entries(tmp_path)) == [
        "PostToolUse",
        "SessionEnd",
        "Stop",
    ]


def test_an_absent_aggregate_summarizes_to_an_empty_labelled_shape(tmp_path: Path) -> None:
    summary = hook_pass_timing_summary(_state=tmp_path)

    assert summary == {
        "status": "absent",
        "measured_from": "console_entry",
        "excludes": ("interpreter_start", "process_exit"),
        "quantile_method": "nearest_rank_bucket_upper_bound",
        "bucket_upper_bounds_ms": BUCKET_UPPER_BOUNDS_MS,
        "since": None,
        "recent_window": "current_and_previous_clock_hour",
        "evicted_entry_count": 0,
        "dropped_sample_count": 0,
        "entries": (),
    }
    assert hook_pass_timing_text(summary) == "none recorded"


def test_text_rendering_names_the_measurement_and_its_bounds(tmp_path: Path) -> None:
    for sample in (90, 700, 800):
        record_hook_pass_timing(
            "codex", "PostToolUse", "observe", "ingested", ms=sample, _state=tmp_path, _now=_NOW
        )

    text = hook_pass_timing_text(hook_pass_timing_summary(_state=tmp_path, _now=_NOW))
    assert text == (
        "in-process from console entry since 2026-09-29T16:52:45.737000Z; "
        "percentiles are histogram bucket bounds; codex PostToolUse observe: n=3 "
        "p50<=700ms p95<=800ms max=800ms (recent n=3 p50<=700ms p95<=800ms)"
    )


def test_an_unresolvable_state_directory_is_a_lost_sample_not_a_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def invalid_root() -> Path:
        raise PathSafetyError("isolation_root_invalid")

    monkeypatch.setattr(hook_timing, "state_dir", invalid_root)

    assert not record_hook_pass_timing("codex", "PostToolUse", "observe", "ingested", ms=5)
    assert hook_pass_timing_summary()["status"] == "unreadable"


def test_a_held_timing_lock_drops_the_sample_promptly_and_counts_it(tmp_path: Path) -> None:
    """A stalled holder must never hold a hook past its host timeout (#915 review)."""

    assert record_hook_pass_timing(
        "codex", "PostToolUse", "observe", "ingested", ms=10, _state=tmp_path
    )
    holder = os.open(tmp_path / "observation" / ".hook-pass-timing.lock", os.O_RDWR)
    fcntl.flock(holder, fcntl.LOCK_EX)
    results: list[bool] = []
    worker = threading.Thread(
        target=lambda: results.append(
            record_hook_pass_timing(
                "codex", "PostToolUse", "observe", "ingested", ms=20, _state=tmp_path
            )
        ),
        daemon=True,
    )
    try:
        started = time.monotonic()
        worker.start()
        worker.join(timeout=5)
        assert not worker.is_alive(), "the recorder waited on a held lock without a deadline"
        assert time.monotonic() - started < 2
        assert results == [False]
        # The reader does not wait on the stalled holder either; the drop is counted.
        summary = hook_pass_timing_summary(_state=tmp_path)
        assert summary["status"] == "retained"
        assert summary["dropped_sample_count"] == 1
        assert [entry["count"] for entry in _entries(tmp_path, now=datetime.now(UTC))] == [1]
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)
        worker.join(timeout=5)

    assert record_hook_pass_timing(
        "codex", "PostToolUse", "observe", "ingested", ms=30, _state=tmp_path
    )
    summary = hook_pass_timing_summary(_state=tmp_path)
    assert summary["dropped_sample_count"] == 1
    assert [entry["count"] for entry in _entries(tmp_path, now=datetime.now(UTC))] == [2]
    assert "1 sample(s) dropped under lock contention" in hook_pass_timing_text(summary)


@pytest.mark.parametrize(
    "field", ["since_ms", "first_ms", "last_ms", "max_at_ms", "slot_max_at_ms"]
)
def test_an_unrenderable_timestamp_reads_as_unreadable_not_a_fault(
    tmp_path: Path, field: str
) -> None:
    record_hook_pass_timing("codex", "PostToolUse", "observe", "ingested", ms=12, _state=tmp_path)
    target = tmp_path / "observation" / "hook-pass-timing.json"
    document = cast(dict[str, Any], json.loads(target.read_text()))
    entry = cast(list[dict[str, Any]], document["entries"])[0]
    beyond_year_9999 = 2**53 - 1
    if field == "since_ms":
        document["since_ms"] = beyond_year_9999
    elif field == "slot_max_at_ms":
        entry["slots"][0]["max_at_ms"] = beyond_year_9999
    elif field == "max_at_ms":
        entry["all"]["max_at_ms"] = beyond_year_9999
    else:
        entry[field] = beyond_year_9999
    target.write_text(json.dumps(document))

    summary = hook_pass_timing_summary(_state=tmp_path)

    assert summary["status"] == "unreadable"
    assert summary["entries"] == ()


def _tree(root: Path) -> list[str]:
    return sorted(str(path.relative_to(root)) for path in root.rglob("*"))


def test_status_reads_on_a_fresh_state_directory_create_nothing(tmp_path: Path) -> None:
    """A status read is a read: no directory, lock or aggregate appears (#915 review 932-RISK-1)."""

    state = tmp_path / "state"
    state.mkdir(mode=0o700)

    assert hook_pass_timing_summary(_state=state, _now=_NOW)["status"] == "absent"
    diagnostics = hook_diagnostic_summary(_state=state, _now=_NOW)
    assert cast(Mapping[str, object], diagnostics["pass_timings"])["status"] == "absent"
    assert _tree(state) == []


def test_reading_a_retained_aggregate_never_creates_its_lock(tmp_path: Path) -> None:
    assert record_hook_pass_timing(
        "codex", "PostToolUse", "observe", "ingested", ms=10, _state=tmp_path, _now=_NOW
    )
    directory = tmp_path / "observation"
    (directory / ".hook-pass-timing.lock").unlink()
    before = _tree(tmp_path)

    summary = hook_pass_timing_summary(_state=tmp_path, _now=_NOW)
    hook_diagnostic_summary(_state=tmp_path, _now=_NOW)

    assert summary["status"] == "retained"
    assert [entry["count"] for entry in _entries(tmp_path)] == [1]
    assert _tree(tmp_path) == before


def test_a_status_read_during_an_update_sees_the_last_complete_aggregate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reader landing mid-update never surfaces a torn document (#915 review 932-RISK-1)."""

    assert record_hook_pass_timing(
        "codex", "PostToolUse", "observe", "ingested", ms=10, _state=tmp_path, _now=_NOW
    )
    seen: list[JsonObject] = []
    real_write = os.write
    real_pwrite = os.pwrite

    def read_mid_update() -> None:
        if not seen:
            seen.append(hook_pass_timing_summary(_state=tmp_path, _now=_NOW))

    def write_then_read(descriptor: int, data: bytes) -> int:
        if seen or len(data) < 2:
            return real_write(descriptor, data)
        written = real_write(descriptor, data[: len(data) // 2])
        read_mid_update()
        return written

    def pwrite_then_read(descriptor: int, data: bytes, offset: int) -> int:
        if seen or len(data) < 2:
            return real_pwrite(descriptor, data, offset)
        written = real_pwrite(descriptor, data[: len(data) // 2], offset)
        read_mid_update()
        return written

    monkeypatch.setattr(os, "write", write_then_read)
    monkeypatch.setattr(os, "pwrite", pwrite_then_read)
    assert record_hook_pass_timing(
        "codex", "PostToolUse", "observe", "ingested", ms=20, _state=tmp_path, _now=_NOW
    )
    monkeypatch.undo()

    (mid_update,) = seen
    assert mid_update["status"] == "retained"
    (entry,) = cast(tuple[Mapping[str, object], ...], mid_update["entries"])
    assert entry["count"] == 1
    assert [entry["count"] for entry in _entries(tmp_path)] == [2]


def test_an_update_interrupted_mid_write_leaves_the_last_complete_aggregate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert record_hook_pass_timing(
        "codex", "PostToolUse", "observe", "ingested", ms=10, _state=tmp_path, _now=_NOW
    )
    real_write = os.write
    real_pwrite = os.pwrite

    def torn_write(descriptor: int, data: bytes) -> int:
        real_write(descriptor, data[: len(data) // 2])
        raise OSError("disk full")

    def torn_pwrite(descriptor: int, data: bytes, offset: int) -> int:
        real_pwrite(descriptor, data[: len(data) // 2], offset)
        raise OSError("disk full")

    monkeypatch.setattr(os, "write", torn_write)
    monkeypatch.setattr(os, "pwrite", torn_pwrite)
    assert not record_hook_pass_timing(
        "codex", "PostToolUse", "observe", "ingested", ms=20, _state=tmp_path, _now=_NOW
    )
    monkeypatch.undo()

    summary = hook_pass_timing_summary(_state=tmp_path, _now=_NOW)
    assert summary["status"] == "retained"
    assert [entry["count"] for entry in _entries(tmp_path)] == [1]
    # No partial update is left beside the aggregate, and the next pass folds in normally.
    assert sorted(path.name for path in (tmp_path / "observation").iterdir()) == [
        ".hook-pass-timing.lock",
        "hook-pass-timing.json",
    ]
    assert record_hook_pass_timing(
        "codex", "PostToolUse", "observe", "ingested", ms=30, _state=tmp_path, _now=_NOW
    )
    assert [entry["count"] for entry in _entries(tmp_path)] == [2]
