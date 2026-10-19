"""Bounded, payload-free timing totals for every observation hook pass (issue #915).

The failure-reason file (``hook-diagnostics.jsonl``) keeps timing rows only for over-budget passes
and session boundaries, because a row per pass would evict its 64 KiB failure-reason history. The
typical cost of a hook was therefore never recorded. This module keeps a separate, fixed-size
aggregate per ``(host, event, path)``: exact count, sum and maximum, a fixed-bucket histogram, and the
same histogram for the current and previous clock hour. Nothing grows with the number of passes,
and nothing here is ever written to ``hook-diagnostics.jsonl``.

A sample is the in-process time from the console entry (sampled when ``finishup.cli.entry`` loads,
before the hook handler's imports; a hook reached through the typer fallback starts at its host
entry function instead) to the end of the pass, after the host's stdout was written. Interpreter
start, folding the sample into this aggregate and process exit are outside it, as they are for the
existing timing rows. Percentiles are read from the histogram, so
they are reported as the bucket bound a nearest-rank percentile falls at or below, never as an
interpolated value.
"""

from __future__ import annotations

import json
import os
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Final, cast

from finishup.config.paths import (
    PathSafetyError,
    ensure_owner_only_dir,
    existing_owner_only_dir,
    state_dir,
)
from finishup.domain.values import JsonObject, JsonValue

try:
    import fcntl
except ImportError:  # pragma: no cover - supported hook hosts are POSIX
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "BUCKET_UPPER_BOUNDS_MS",
    "HookPassTiming",
    "hook_pass_timing_summary",
    "hook_pass_timing_text",
    "record_hook_pass_timing",
]

_FILE_NAME: Final = "hook-pass-timing.json"
# Writers build the next document here and rename it over the aggregate, so the aggregate path
# only ever names a complete document and a reader needs neither the lock nor a retry.
_STAGING_NAME: Final = ".hook-pass-timing.json.next"
_LOCK_NAME: Final = ".hook-pass-timing.lock"
# One byte per sample dropped under lock contention, appended without the lock (an O_APPEND write is
# atomic), so counting a drop never waits on the holder it is reporting.
_DROP_NAME: Final = ".hook-pass-timing.dropped"
_MAX_DROP_BYTES: Final = 64 * 1024
# A writer keeps the lock for one small staged rewrite and rename. One that stalls (suspended, or on
# a hung filesystem) must not hold a hook past its 3, 5 or 10 s host timeout, so every acquisition
# is bounded and a sample that cannot take the lock in time is dropped and counted instead.
_LOCK_WAIT_SECONDS: Final = 0.1
_LOCK_POLL_SECONDS: Final = 0.002
_FORMAT: Final = "yoetz.hook-pass-timing/1"
# One entry is well under 1 KiB, and the closed vocabularies keep a real install to a few dozen
# entries, so the cap only guards a tampered or pathological file.
_MAX_FILE_BYTES: Final = 64 * 1024
_MAX_ENTRIES: Final = 48
_MAX_MS: Final = 3_600_000
_MAX_SAFE: Final = 2**53 - 1
_HOUR_MS: Final = 3_600_000
# 9999-12-31T23:59:59.999Z, the last moment ``datetime`` can render. A larger stamp in the mutable
# file would pass the integer checks and then fail rendering, so it is rejected as unreadable.
_MAX_EPOCH_MS: Final = 253_402_300_799_999
# Inclusive upper bounds. The bounds that carry a documented meaning are exact edges: 150 ms is the
# Codex per-call goal (#915), 250 ms and 500 ms the legacy spool p95 target and hard cap (#362),
# and 3, 5 and 10 s the rendered host timeouts. Everything above the last bound shares one bucket
# whose upper edge is the exact recorded maximum.
BUCKET_UPPER_BOUNDS_MS: Final = (
    5,
    10,
    25,
    50,
    75,
    100,
    125,
    150,
    200,
    250,
    300,
    400,
    500,
    600,
    700,
    800,
    900,
    1_000,
    1_250,
    1_500,
    2_000,
    2_500,
    3_000,
    4_000,
    5_000,
    7_500,
    10_000,
)
_BUCKETS: Final = len(BUCKET_UPPER_BOUNDS_MS) + 1
_SPOOL_PATH: Final = "sync_fallback_spool"
_SPOOL_P95_TARGET_MS: Final = 250
_SPOOL_HARD_CAP_MS: Final = 500
_SPOOL_HARD_CAP_BUCKET: Final = BUCKET_UPPER_BOUNDS_MS.index(_SPOOL_HARD_CAP_MS)
_HOSTS: Final = frozenset({"codex", "claude", "cursor"})
# Raw host hook names as each host fires them: Codex and Claude Code spell them in PascalCase,
# Cursor in camelCase. The raw name is kept so each registered hook reads as its own cost.
_EVENTS: Final = frozenset(
    {
        "PermissionDenied",
        "PermissionRequest",
        "PostCompact",
        "PostToolUse",
        "PostToolUseFailure",
        "PreCompact",
        "PreToolUse",
        "SessionEnd",
        "SessionStart",
        "Stop",
        "StopFailure",
        "SubagentStart",
        "SubagentStop",
        "UserPromptSubmit",
        "afterFileEdit",
        "afterMCPExecution",
        "postToolUse",
        "postToolUseFailure",
        "preToolUse",
        "sessionEnd",
        "sessionStart",
        "stop",
    }
)
_UNKNOWN_EVENT: Final = "unknown_event"
# ``observe``: the Codex observe command. ``sync_fallback_spool``: the Codex legacy spool writer.
# ``structural`` / ``ordinary``: the Claude Code or Cursor observation profile the hook rendered;
# ``invalid_profile`` is a profile argument the ingress refused.
_PATHS: Final = frozenset({"observe", _SPOOL_PATH, "structural", "ordinary", "invalid_profile"})
# ``ingested``: the event was durably captured and the pass ran its follow-up work.
# ``followup_deferred``: captured, but the pass yielded its follow-up after spending its local
# allowance. ``not_ingested``: the pass ended before capturing anything (no consent, paused,
# disabled, filtered by profile, invalid or oversized input). ``failed``: an unexpected fault
# reached the fail-open handler.
_OUTCOMES: Final = ("ingested", "followup_deferred", "not_ingested", "failed")
_OUTCOME_SET: Final = frozenset(_OUTCOMES)
_DOCUMENT_KEYS: Final = frozenset({"format", "since_ms", "evicted_entry_count", "entries"})
_ENTRY_KEYS: Final = frozenset(
    {"host", "event", "path", "first_ms", "last_ms", "outcomes", "all", "slots"}
)
_HISTOGRAM_KEYS: Final = frozenset({"count", "sum_ms", "max_ms", "max_at_ms", "buckets"})
_SLOT_KEYS: Final = _HISTOGRAM_KEYS | {"hour"}
_thread_lock = Lock()


@dataclass(slots=True)
class HookPassTiming:
    """One host hook process's sample, owned by the outermost ingress entry.

    The entry that the host invoked creates it and records it once; the shared observe pass only
    reports how far the pass got. Nested and service-side replays of the observe pass never own a
    sample, so they cannot be mistaken for host-visible cost.
    """

    host: str
    event: str
    path: str
    started: float
    outcome: str = "not_ingested"


def _bounded(value: int) -> int:
    return max(0, min(value, _MAX_SAFE))


def _render(epoch_ms: int) -> str:
    moment = datetime.fromtimestamp(epoch_ms / 1000, UTC)
    return moment.replace(microsecond=(epoch_ms % 1000) * 1000).isoformat().replace("+00:00", "Z")


def _now_ms(now: datetime | None) -> int:
    moment = datetime.now(UTC) if now is None else now.astimezone(UTC)
    return int(moment.timestamp() * 1000)


def _bucket(ms: int) -> int:
    for index, bound in enumerate(BUCKET_UPPER_BOUNDS_MS):
        if ms <= bound:
            return index
    return _BUCKETS - 1


def _is_count(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_SAFE


def _is_moment(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_EPOCH_MS


def _valid_histogram(raw: object, keys: frozenset[str]) -> dict[str, object] | None:
    if type(raw) is not dict:
        return None
    histogram = cast(dict[str, object], raw)
    if frozenset(histogram) != keys:
        return None
    buckets = histogram["buckets"]
    count = histogram["count"]
    if (
        not _is_count(count)
        or not _is_count(histogram["sum_ms"])
        or type(buckets) is not list
        or len(cast(list[object], buckets)) != _BUCKETS
        or not all(_is_count(item) for item in cast(list[object], buckets))
        or sum(cast(list[int], buckets)) != count
    ):
        return None
    maximum = histogram["max_ms"]
    moment = histogram["max_at_ms"]
    if count == 0:
        if maximum is not None or moment is not None:
            return None
    elif (
        type(maximum) is not int
        or not 0 <= maximum <= _MAX_MS
        or not _is_moment(moment)
        or _bucket(maximum) != max(i for i, item in enumerate(cast(list[int], buckets)) if item)
    ):
        return None
    if "hour" in keys and not (
        _is_count(histogram["hour"]) and cast(int, histogram["hour"]) <= _MAX_EPOCH_MS // _HOUR_MS
    ):
        return None
    return histogram


def _valid_entry(raw: object) -> dict[str, object] | None:
    if type(raw) is not dict:
        return None
    entry = cast(dict[str, object], raw)
    if frozenset(entry) != _ENTRY_KEYS:
        return None
    # The file is mutable local input: reject containers before any set membership lookup.
    if any(type(entry[key]) is not str for key in ("host", "event", "path")):
        return None
    if (
        entry["host"] not in _HOSTS
        or (entry["event"] not in _EVENTS and entry["event"] != _UNKNOWN_EVENT)
        or entry["path"] not in _PATHS
        or not _is_moment(entry["first_ms"])
        or not _is_moment(entry["last_ms"])
    ):
        return None
    total = _valid_histogram(entry["all"], _HISTOGRAM_KEYS)
    outcomes = entry["outcomes"]
    slots = entry["slots"]
    if (
        total is None
        or type(outcomes) is not dict
        or not set(cast(dict[str, object], outcomes)) <= _OUTCOME_SET
        or not all(_is_count(item) for item in cast(dict[str, object], outcomes).values())
        or sum(cast(dict[str, int], outcomes).values()) != total["count"]
        or type(slots) is not list
        or len(cast(list[object], slots)) > 2
        or any(_valid_histogram(slot, _SLOT_KEYS) is None for slot in cast(list[object], slots))
    ):
        return None
    hours = [cast(dict[str, int], slot)["hour"] for slot in cast(list[object], slots)]
    if len(set(hours)) != len(hours):
        return None
    return entry


def _valid_document(raw: object) -> dict[str, object] | None:
    if type(raw) is not dict:
        return None
    document = cast(dict[str, object], raw)
    if frozenset(document) != _DOCUMENT_KEYS or type(document["format"]) is not str:
        return None
    if document["format"] != _FORMAT:
        return None
    entries = document["entries"]
    if (
        not _is_moment(document["since_ms"])
        or not _is_count(document["evicted_entry_count"])
        or type(entries) is not list
        or len(cast(list[object], entries)) > _MAX_ENTRIES
    ):
        return None
    keys: set[tuple[object, object, object]] = set()
    for item in cast(list[object], entries):
        entry = _valid_entry(item)
        if entry is None:
            return None
        key = (entry["host"], entry["event"], entry["path"])
        if key in keys:
            return None
        keys.add(key)
    return document


def _open_flags(*, write: bool) -> int:
    base = os.O_RDWR | os.O_CREAT if write else os.O_RDONLY
    return base | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _read_descriptor(descriptor: int) -> dict[str, object] | None:
    """Return the validated document behind an open owner-only descriptor, or None."""

    facts = os.fstat(descriptor)
    if (
        not stat.S_ISREG(facts.st_mode)
        or facts.st_uid != os.geteuid()
        or facts.st_mode & 0o077
        or facts.st_size > _MAX_FILE_BYTES
    ):
        return None
    raw = os.pread(descriptor, _MAX_FILE_BYTES + 1, 0)
    if not raw:
        return None
    try:
        parsed: object = json.loads(raw)
    except (UnicodeError, ValueError):
        return None
    return _valid_document(parsed)


def _acquire(descriptor: int, operation: int) -> bool:
    """Take the file lock within ``_LOCK_WAIT_SECONDS``, or report that it is held."""

    if fcntl is None:
        return True
    deadline = time.monotonic() + _LOCK_WAIT_SECONDS
    while True:
        try:
            fcntl.flock(descriptor, operation | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(_LOCK_POLL_SECONDS)


def _count_dropped_sample(directory: Path) -> None:
    """Record one sample dropped under contention without taking the lock. Never raises."""

    try:
        descriptor = os.open(
            directory / _DROP_NAME,
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError:
        return
    try:
        facts = os.fstat(descriptor)
        if (
            stat.S_ISREG(facts.st_mode)
            and facts.st_uid == os.geteuid()
            and facts.st_size < _MAX_DROP_BYTES
        ):
            os.write(descriptor, b".")
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _reset_dropped_samples(directory: Path) -> None:
    """Empty the drop count when the aggregate restarts; the caller holds the lock."""

    try:
        descriptor = os.open(
            directory / _DROP_NAME,
            os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        return
    try:
        if os.fstat(descriptor).st_uid == os.geteuid():
            os.ftruncate(descriptor, 0)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _dropped_sample_count(directory: Path) -> int:
    """Samples dropped under contention since ``since``: a lower bound, saturating at 64 Ki."""

    try:
        descriptor = os.open(directory / _DROP_NAME, _open_flags(write=False))
    except OSError:
        return 0
    try:
        facts = os.fstat(descriptor)
    except OSError:
        return 0
    finally:
        os.close(descriptor)
    if not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid() or facts.st_mode & 0o077:
        return 0
    return min(facts.st_size, _MAX_DROP_BYTES)


def _read_document(directory: Path) -> tuple[str, dict[str, object] | None]:
    """Return ``absent``, ``unreadable`` or ``retained`` plus the validated document.

    Writers never modify the aggregate in place: they rename a complete staged document over it.
    An open descriptor therefore pins one complete document, and a single read of it is a
    consistent snapshot without taking (or creating) the writers' lock, so a status read neither
    waits on a writer nor makes one drop its sample.
    """

    try:
        descriptor = os.open(directory / _FILE_NAME, _open_flags(write=False))
    except FileNotFoundError:
        return "absent", None
    except OSError:
        return "unreadable", None
    try:
        document = _read_descriptor(descriptor)
    except OSError:
        return "unreadable", None
    finally:
        os.close(descriptor)
    return ("retained", document) if document is not None else ("unreadable", None)


def _empty_histogram() -> dict[str, object]:
    return {"count": 0, "sum_ms": 0, "max_ms": None, "max_at_ms": None, "buckets": [0] * _BUCKETS}


def _observe(histogram: dict[str, object], ms: int, at_ms: int) -> None:
    buckets = cast(list[int], histogram["buckets"])
    buckets[_bucket(ms)] += 1
    histogram["count"] = _bounded(cast(int, histogram["count"]) + 1)
    histogram["sum_ms"] = _bounded(cast(int, histogram["sum_ms"]) + ms)
    maximum = histogram["max_ms"]
    if maximum is None or ms > cast(int, maximum):
        histogram["max_ms"] = ms
        histogram["max_at_ms"] = at_ms


def record_hook_pass_timing(
    host: str,
    event: str,
    path: str,
    outcome: str,
    *,
    ms: int,
    _state: Path | None = None,
    _now: datetime | None = None,
) -> bool:
    """Fold one hook pass into its bounded ``(host, event, path)`` aggregate.

    Never raises, never writes a diagnostics row, and never waits longer than the bounded lock
    acquisition: a sample that cannot take the lock in time is dropped and counted. A document
    that fails validation is replaced by a fresh one whose ``since`` names the restart, rather than
    being trusted.
    """

    if host not in _HOSTS or path not in _PATHS or outcome not in _OUTCOME_SET:
        return False
    event_token = event if event in _EVENTS else _UNKNOWN_EVENT
    sample = max(0, min(int(ms), _MAX_MS))
    now_ms = _now_ms(_now)
    try:
        # An invalid isolation root makes ``state_dir()`` raise; that is a lost sample, not a
        # hook fault.
        root = state_dir() if _state is None else _state
        directory = root / "observation"
        ensure_owner_only_dir(directory)
        if not _thread_lock.acquire(timeout=_LOCK_WAIT_SECONDS):
            _count_dropped_sample(directory)
            return False
        try:
            lock_descriptor = os.open(directory / _LOCK_NAME, _open_flags(write=True), 0o600)
            try:
                os.fchmod(lock_descriptor, 0o600)
                if fcntl is not None and not _acquire(lock_descriptor, fcntl.LOCK_EX):
                    _count_dropped_sample(directory)
                    return False
                replaceable, current = _current_document(directory)
                if not replaceable:
                    return False
                encoded, restarted = _updated_document(
                    current, host, event_token, path, outcome, sample, now_ms
                )
                if encoded is None:
                    return False
                _replace_document(directory, encoded)
                if restarted:
                    # Drops are counted for the period ``since`` names; a restart starts both.
                    _reset_dropped_samples(directory)
            finally:
                os.close(lock_descriptor)
        finally:
            _thread_lock.release()
    except (OSError, PathSafetyError, ValueError):
        return False
    return True


def _updated_document(
    document: dict[str, object] | None,
    host: str,
    event_token: str,
    path: str,
    outcome: str,
    sample: int,
    now_ms: int,
) -> tuple[bytes | None, bool]:
    """Fold one sample into *document* and encode it; the caller holds the lock.

    Returns the encoded document (None when it would exceed the size cap) and whether the
    aggregate restarted, so the caller can restart the drop count with it.
    """

    hour = now_ms // _HOUR_MS
    restarted = document is None
    if document is None:
        fresh_entries: list[dict[str, object]] = []
        document = {
            "format": _FORMAT,
            "since_ms": now_ms,
            "evicted_entry_count": 0,
            "entries": fresh_entries,
        }
    entries = cast(list[dict[str, object]], document["entries"])
    entry: dict[str, object] | None = next(
        (
            item
            for item in entries
            if (item["host"], item["event"], item["path"]) == (host, event_token, path)
        ),
        None,
    )
    if entry is None:
        if len(entries) >= _MAX_ENTRIES:
            stalest = min(entries, key=lambda item: cast(int, item["last_ms"]))
            entries.remove(stalest)
            document["evicted_entry_count"] = _bounded(
                cast(int, document["evicted_entry_count"]) + 1
            )
        fresh_outcomes: dict[str, int] = {}
        fresh_slots: list[dict[str, object]] = []
        entry = {
            "host": host,
            "event": event_token,
            "path": path,
            "first_ms": now_ms,
            "last_ms": now_ms,
            "outcomes": fresh_outcomes,
            "all": _empty_histogram(),
            "slots": fresh_slots,
        }
        entries.append(entry)
    entry["first_ms"] = min(cast(int, entry["first_ms"]), now_ms)
    entry["last_ms"] = max(cast(int, entry["last_ms"]), now_ms)
    outcomes = cast(dict[str, int], entry["outcomes"])
    outcomes[outcome] = _bounded(outcomes.get(outcome, 0) + 1)
    _observe(cast(dict[str, object], entry["all"]), sample, now_ms)
    # Keep only this clock hour and the one before it; a slot from the future (a clock
    # stepped back) is dropped rather than trusted.
    slots = [
        slot
        for slot in cast(list[dict[str, object]], entry["slots"])
        if hour - 1 <= cast(int, slot["hour"]) <= hour
    ]
    current = next((slot for slot in slots if slot["hour"] == hour), None)
    if current is None:
        current = {"hour": hour, **_empty_histogram()}
        slots.append(current)
    _observe(current, sample, now_ms)
    entry["slots"] = sorted(slots, key=lambda slot: cast(int, slot["hour"]))
    encoded = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    if len(encoded) > _MAX_FILE_BYTES:
        return None, restarted
    return encoded, restarted


def _current_document(directory: Path) -> tuple[bool, dict[str, object] | None]:
    """Return whether the aggregate may be replaced, and its document (None restarts it).

    The caller holds the lock. ``O_NOFOLLOW`` refuses a symlinked aggregate outright, and a file
    another user owns is never replaced. An owner-only mode is restored before reading, so a
    widened mode alone does not restart the totals.
    """

    try:
        descriptor = os.open(directory / _FILE_NAME, _open_flags(write=False))
    except FileNotFoundError:
        return True, None
    except OSError:
        return False, None
    try:
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid():
            return False, None
        os.fchmod(descriptor, 0o600)
        return True, _read_descriptor(descriptor)
    finally:
        os.close(descriptor)


def _replace_document(directory: Path, encoded: bytes) -> None:
    """Stage *encoded* beside the aggregate and rename it into place; the caller holds the lock.

    Best-effort diagnostics, so nothing is fsynced: a crash can at worst lose the aggregate, and
    the next pass finds it missing or invalid and restarts it with a new ``since``. A write that
    fails part-way leaves the previous complete document in place and removes the staged bytes.
    """

    staging = directory / _STAGING_NAME
    # Only a writer holding the lock touches the staging name, so anything there is a leftover
    # from a writer that died mid-update. Unlinking removes a planted symlink, never its target.
    try:
        os.unlink(staging)
    except FileNotFoundError:
        pass
    descriptor = os.open(
        staging,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        try:
            os.fchmod(descriptor, 0o600)
            written = 0
            while written < len(encoded):
                written += os.write(descriptor, encoded[written:])
        finally:
            os.close(descriptor)
        os.replace(staging, directory / _FILE_NAME)
    except BaseException:
        try:
            os.unlink(staging)
        except OSError:
            pass
        raise


def _quantile_at_most(histogram: Mapping[str, object], numerator: int) -> int | None:
    """Return the bound a nearest-rank percentile falls at or below, or None when empty."""

    count = cast(int, histogram["count"])
    if count == 0:
        return None
    maximum = cast(int, histogram["max_ms"])
    rank = max(1, (numerator * count + 99) // 100)
    cumulative = 0
    for index, bucket_count in enumerate(cast(list[int], histogram["buckets"])):
        cumulative += bucket_count
        if cumulative >= rank:
            bound = (
                BUCKET_UPPER_BOUNDS_MS[index] if index < len(BUCKET_UPPER_BOUNDS_MS) else maximum
            )
            # Every sample is at most the exact maximum, so it is also a valid upper bound.
            return min(bound, maximum)
    return maximum


def _merge(histograms: list[Mapping[str, object]]) -> dict[str, object]:
    merged = _empty_histogram()
    buckets = cast(list[int], merged["buckets"])
    for histogram in histograms:
        for index, bucket_count in enumerate(cast(list[int], histogram["buckets"])):
            buckets[index] = _bounded(buckets[index] + bucket_count)
        merged["count"] = _bounded(cast(int, merged["count"]) + cast(int, histogram["count"]))
        merged["sum_ms"] = _bounded(cast(int, merged["sum_ms"]) + cast(int, histogram["sum_ms"]))
        maximum = histogram["max_ms"]
        if maximum is not None and (
            merged["max_ms"] is None or cast(int, maximum) > cast(int, merged["max_ms"])
        ):
            merged["max_ms"] = maximum
            merged["max_at_ms"] = histogram["max_at_ms"]
    return merged


def _entry_json(entry: Mapping[str, object], *, hour: int) -> JsonObject:
    total = cast(Mapping[str, object], entry["all"])
    count = cast(int, total["count"])
    recent_slots = [
        slot
        for slot in cast(list[Mapping[str, object]], entry["slots"])
        if hour - 1 <= cast(int, slot["hour"]) <= hour
    ]
    recent = _merge(list(recent_slots))
    recent_since = (
        None
        if not recent_slots
        else _render(min(cast(int, slot["hour"]) for slot in recent_slots) * _HOUR_MS)
    )
    outcomes = cast(Mapping[str, int], entry["outcomes"])
    body: dict[str, JsonValue] = {
        "host": cast(str, entry["host"]),
        "event": cast(str, entry["event"]),
        "path": cast(str, entry["path"]),
        "count": count,
        "sum_ms": cast(int, total["sum_ms"]),
        "mean_ms": cast(int, total["sum_ms"]) // count if count else None,
        "p50_ms_at_most": _quantile_at_most(total, 50),
        "p95_ms_at_most": _quantile_at_most(total, 95),
        "max_ms": cast(int | None, total["max_ms"]),
        "max_ts": None if total["max_at_ms"] is None else _render(cast(int, total["max_at_ms"])),
        "first_seen": _render(cast(int, entry["first_ms"])),
        "last_seen": _render(cast(int, entry["last_ms"])),
        "outcomes": JsonObject({name: outcomes.get(name, 0) for name in _OUTCOMES}),
        "bucket_counts": tuple(cast(list[int], total["buckets"])),
        "recent": JsonObject(
            {
                "since": recent_since,
                "count": cast(int, recent["count"]),
                "p50_ms_at_most": _quantile_at_most(recent, 50),
                "p95_ms_at_most": _quantile_at_most(recent, 95),
                "max_ms": cast(int | None, recent["max_ms"]),
            }
        ),
    }
    if entry["path"] == _SPOOL_PATH:
        # The legacy spool's proposed contract (#362) is read against every pass, not only
        # against the breaches that also leave a diagnostics row.
        body["p95_target_ms"] = _SPOOL_P95_TARGET_MS
        body["hard_cap_ms"] = _SPOOL_HARD_CAP_MS
        body["hard_cap_breach_count"] = sum(
            cast(list[int], total["buckets"])[_SPOOL_HARD_CAP_BUCKET + 1 :]
        )
    return JsonObject(body)


def hook_pass_timing_summary(
    *,
    _state: Path | None = None,
    _now: datetime | None = None,
) -> JsonObject:
    """Return the retained per-``(host, event, path)`` totals in a stable order."""

    status = "unreadable"
    document: dict[str, object] | None = None
    dropped = 0
    try:
        root = state_dir() if _state is None else _state
        directory = root / "observation"
        # A status read never creates the directory, the lock or the aggregate it reports on.
        if existing_owner_only_dir(directory):
            status, document = _read_document(directory)
            dropped = _dropped_sample_count(directory)
        else:
            status = "absent"
    except (OSError, PathSafetyError):
        status, document = "unreadable", None
    hour = _now_ms(_now) // _HOUR_MS
    entries = [] if document is None else cast(list[Mapping[str, object]], document["entries"])
    return JsonObject(
        {
            "status": status,
            "measured_from": "console_entry",
            "excludes": ("interpreter_start", "process_exit"),
            "quantile_method": "nearest_rank_bucket_upper_bound",
            "bucket_upper_bounds_ms": BUCKET_UPPER_BOUNDS_MS,
            "since": None if document is None else _render(cast(int, document["since_ms"])),
            "recent_window": "current_and_previous_clock_hour",
            "evicted_entry_count": 0
            if document is None
            else cast(int, document["evicted_entry_count"]),
            # Passes that could not take the lock within the bounded wait: a lower bound.
            "dropped_sample_count": dropped,
            "entries": tuple(
                _entry_json(entry, hour=hour)
                for entry in sorted(
                    entries,
                    key=lambda item: (
                        cast(str, item["host"]),
                        cast(str, item["event"]),
                        cast(str, item["path"]),
                    ),
                )
            ),
        }
    )


def hook_pass_timing_text(summary: Mapping[str, JsonValue]) -> str:
    """Render the summary as one bounded human line for ``observe status``."""

    status = summary.get("status")
    entries = cast(tuple[Mapping[str, JsonValue], ...], summary.get("entries") or ())
    dropped = summary.get("dropped_sample_count")
    dropped_note = (
        f"; {dropped} sample(s) dropped under lock contention"
        if type(dropped) is int and dropped
        else ""
    )
    if status != "retained" or not entries:
        return (
            "none recorded" if status != "unreadable" else "unreadable; restarts on next hook"
        ) + dropped_note
    parts: list[str] = []
    for entry in entries:
        recent = cast(Mapping[str, JsonValue], entry["recent"])
        part = (
            f"{entry['host']} {entry['event']} {entry['path']}: n={entry['count']} "
            f"p50<={entry['p50_ms_at_most']}ms p95<={entry['p95_ms_at_most']}ms "
            f"max={entry['max_ms']}ms"
        )
        if recent["count"]:
            part += (
                f" (recent n={recent['count']} p50<={recent['p50_ms_at_most']}ms "
                f"p95<={recent['p95_ms_at_most']}ms)"
            )
        parts.append(part)
    return (
        f"in-process from console entry since {summary.get('since')}; "
        "percentiles are histogram bucket bounds; " + "; ".join(parts) + dropped_note
    )
