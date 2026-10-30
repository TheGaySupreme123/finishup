"""Tests for bounded, payload-free hook diagnostics."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from finishup.cli.hook_diagnostics import (
    hook_diagnostic_summary,
    record_hook_diagnostic,
    record_hook_timing,
)


def test_record_is_structural_and_owner_only(tmp_path: Path) -> None:
    record_hook_diagnostic("service_unavailable", "PostToolUse", _state=tmp_path)
    path = tmp_path / "observation/hook-diagnostics.jsonl"
    row = json.loads(path.read_text(encoding="utf-8"))
    assert set(row) == {"event", "reason", "ts"}
    assert row["event"] == "PostToolUse"
    assert row["reason"] == "service_unavailable"
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("candidate_count", [2, 1_000_000])
def test_ambiguous_binding_diagnostic_exposes_only_bounded_count(
    tmp_path: Path, candidate_count: int
) -> None:
    record_hook_diagnostic(
        "auto_attach_binding_ambiguous",
        "SessionStart",
        candidate_count=candidate_count,
        _state=tmp_path,
    )
    row = json.loads((tmp_path / "observation/hook-diagnostics.jsonl").read_text())
    assert set(row) == {"event", "reason", "ts", "candidate_count"}
    assert row["reason"] == "auto_attach_binding_ambiguous"
    assert row["candidate_count"] == candidate_count
    summary = hook_diagnostic_summary(_state=tmp_path)
    assert summary["count"] == 1
    assert summary["last_reason"] == "auto_attach_binding_ambiguous"
    assert "auto_attach_binding_ambiguous" in cast(dict[str, object], summary["reasons"])


@pytest.mark.parametrize(
    ("reason", "advice_set", "kept"),
    [
        ("closure_gate_advice_asked", "advice:0123456789abcdef", True),
        ("closure_gate_advice_asked", "advice:private-note-text", False),
        ("closure_gate_advice_asked", None, False),
        ("closure_gate_continued", "advice:0123456789abcdef", False),
    ],
)
def test_advice_ask_diagnostic_keeps_only_its_set_key(
    tmp_path: Path, reason: str, advice_set: str | None, kept: bool
) -> None:
    """#1240 D2: an advice ask names its set key (a digest), so an export tells asks apart."""

    record_hook_diagnostic(reason, "Stop", advice_set=advice_set, _state=tmp_path)
    row = json.loads((tmp_path / "observation/hook-diagnostics.jsonl").read_text())
    assert ("advice_set" in row) is kept
    assert "private-note-text" not in json.dumps(row)
    summary = hook_diagnostic_summary(_state=tmp_path)
    assert summary["count"] == 1
    assert summary["last_reason"] == reason


def test_summary_rejects_an_advice_set_on_another_reason(tmp_path: Path) -> None:
    _seed(
        tmp_path / "observation",
        [
            {
                "event": "Stop",
                "reason": "closure_gate_continued",
                "ts": "2026-10-30T00:00:00.000Z",
                "advice_set": "advice:0123456789abcdef",
            },
            {
                "event": "Stop",
                "reason": "closure_gate_advice_asked",
                "ts": "2026-10-30T00:00:00.000Z",
                "advice_set": "advice:not-a-digest",
            },
        ],
    )
    assert hook_diagnostic_summary(_state=tmp_path)["count"] == 0


@pytest.mark.parametrize("candidate_count", [None, True, 1, 1_000_001, "private-task"])
def test_ambiguous_binding_diagnostic_drops_invalid_counts(
    tmp_path: Path, candidate_count: object
) -> None:
    record_hook_diagnostic(
        "auto_attach_binding_ambiguous",
        "SessionStart",
        candidate_count=cast(int | None, candidate_count),
        _state=tmp_path,
    )
    row = json.loads((tmp_path / "observation/hook-diagnostics.jsonl").read_text())
    assert set(row) == {"event", "reason", "ts"}
    assert "private-task" not in json.dumps(row)


def test_workspace_binding_reasons_are_distinct_closed_tokens(tmp_path: Path) -> None:
    for reason in ("workspace_unresolvable", "workspace_unconsented"):
        record_hook_diagnostic(reason, "SessionStart", _state=tmp_path)

    rows = [
        json.loads(line)
        for line in (tmp_path / "observation/hook-diagnostics.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [row["reason"] for row in rows] == [
        "workspace_unresolvable",
        "workspace_unconsented",
    ]


@pytest.mark.parametrize("candidate_count", [None, True, 1, 1_000_001, "private-task"])
def test_summary_rejects_malformed_ambiguity_rows(tmp_path: Path, candidate_count: object) -> None:
    _seed(
        tmp_path / "observation",
        [
            {
                "event": "SessionStart",
                "reason": "auto_attach_binding_ambiguous",
                "ts": "2026-09-23T00:00:00Z",
                "candidate_count": candidate_count,
            }
        ],
    )
    assert hook_diagnostic_summary(_state=tmp_path)["count"] == 0


def test_summary_rejects_counts_on_unrelated_reasons(tmp_path: Path) -> None:
    _seed(
        tmp_path / "observation",
        [
            {
                "event": "SessionStart",
                "reason": "service_unavailable",
                "ts": "2026-09-23T00:00:00Z",
                "candidate_count": 2,
            }
        ],
    )
    assert hook_diagnostic_summary(_state=tmp_path)["count"] == 0


def test_invalid_plaintext_is_not_persisted(tmp_path: Path) -> None:
    record_hook_diagnostic("customer private repository", "payload\ntext", _state=tmp_path)
    row = json.loads((tmp_path / "observation/hook-diagnostics.jsonl").read_text(encoding="utf-8"))
    assert row["event"] == "unknown_event"
    assert row["reason"] == "unknown_reason"
    assert "customer" not in json.dumps(row)


def test_sensitive_looking_legal_tokens_are_not_persisted(tmp_path: Path) -> None:
    record_hook_diagnostic("sk_live_ABC123", "BearerTokenABC123", _state=tmp_path)
    row = json.loads((tmp_path / "observation/hook-diagnostics.jsonl").read_text(encoding="utf-8"))
    assert row["event"] == "unknown_event"
    assert row["reason"] == "unknown_reason"
    assert "ABC123" not in json.dumps(row)


def test_rotates_at_64_kib_and_keeps_one_backup(tmp_path: Path) -> None:
    directory = tmp_path / "observation"
    directory.mkdir(mode=0o700)
    path = directory / "hook-diagnostics.jsonl"
    path.write_bytes(b"x" * (64 * 1024 - 1))
    record_hook_diagnostic("service_unavailable", "SessionStart", _state=tmp_path)
    rotated = directory / "hook-diagnostics.jsonl.1"
    assert rotated.stat().st_size == 64 * 1024 - 1
    assert path.stat().st_size < 1024

    path.write_bytes(b"y" * (64 * 1024 - 1))
    record_hook_diagnostic("timeout", "Stop", _state=tmp_path)
    assert rotated.read_bytes().startswith(b"y")
    assert len(list(directory.glob("hook-diagnostics.jsonl.*"))) == 1


def test_discards_an_externally_oversized_active_file(tmp_path: Path) -> None:
    directory = tmp_path / "observation"
    directory.mkdir(mode=0o700)
    path = directory / "hook-diagnostics.jsonl"
    path.write_bytes(b"x" * (64 * 1024 + 1))
    record_hook_diagnostic("timeout", "Stop", _state=tmp_path)
    assert path.stat().st_size < 1024
    assert not (directory / "hook-diagnostics.jsonl.1").exists()


def test_concurrent_processes_preserve_bound_and_json_lines(tmp_path: Path) -> None:
    script = (
        "from pathlib import Path; "
        "from finishup.cli.hook_diagnostics import record_hook_diagnostic; "
        f"root=Path({str(tmp_path)!r}); "
        "[record_hook_diagnostic('service_unavailable','PostToolUse',_state=root) "
        "for _ in range(180)]"
    )
    processes = [subprocess.Popen((sys.executable, "-c", script)) for _ in range(4)]
    for process in processes:
        assert process.wait(timeout=15) == 0
    directory = tmp_path / "observation"
    files = [directory / "hook-diagnostics.jsonl", directory / "hook-diagnostics.jsonl.1"]
    for path in files:
        if not path.exists():
            continue
        assert path.stat().st_size <= 64 * 1024
        for line in path.read_text(encoding="utf-8").splitlines():
            assert set(json.loads(line)) == {"event", "reason", "ts"}
    assert len(list(directory.glob("hook-diagnostics.jsonl.*"))) <= 1


def test_timing_rows_round_trip_and_reason_counts_are_unpolluted(tmp_path: Path) -> None:
    """Two row shapes share one file; neither may be counted as the other."""

    record_hook_diagnostic("hook_budget_exceeded", "PostToolUse", _state=tmp_path)
    record_hook_timing(
        "SessionEnd",
        ms=1_842,
        stages={"import": 42, "store": 900, "advice": 8, "drain": 150, "bogus": 5},
        _state=tmp_path,
    )
    path = tmp_path / "observation/hook-diagnostics.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert set(rows[0]) == {"event", "reason", "ts"}
    assert set(rows[1]) == {"event", "kind", "ms", "stages", "ts"}
    assert rows[1]["kind"] == "timing"
    assert rows[1]["ms"] == 1_842
    # Unknown stage names are dropped rather than persisted verbatim.
    assert set(rows[1]["stages"]) == {"import", "store", "advice", "drain"}

    summary = hook_diagnostic_summary(_state=tmp_path)
    assert summary["count"] == 1
    assert summary["recent_count"] == 1
    assert summary["last_reason"] == "hook_budget_exceeded"
    reasons = dict(cast(Mapping[str, object], summary["reasons"]))
    assert set(reasons) == {"hook_budget_exceeded"}
    budget = dict(cast(Mapping[str, object], reasons["hook_budget_exceeded"]))
    assert budget["count"] == 1
    assert budget["recent"] == 1
    assert budget["first_seen"] == budget["last_seen"] == summary["last_seen"]
    timings = dict(cast(Mapping[str, object], summary["timings"]))
    assert timings["count"] == 1
    assert timings["recent_count"] == 1
    assert timings["last_ms"] == timings["max_ms"] == timings["recent_max_ms"] == 1_842
    assert timings["recent_p95_ms"] == 1_842
    assert timings["paths"] == {}
    assert timings["max_ts"] is not None


def _seed(directory: Path, rows: list[dict[str, object]]) -> None:
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / "hook-diagnostics.jsonl"
    path.write_text(
        "".join(f"{json.dumps(row, sort_keys=True)}\n" for row in rows), encoding="utf-8"
    )
    path.chmod(0o600)


def test_fixed_and_gone_failures_are_dated_rather_than_reported_as_live(tmp_path: Path) -> None:
    """#310: an all-time tally read a two-day-old, since-fixed failure as live."""

    _seed(
        tmp_path / "observation",
        [
            {"event": "PreToolUse", "reason": "runtime_gate_unsafe", "ts": "2026-08-15T18:49:51Z"},
            {"event": "Stop", "reason": "runtime_gate_unsafe", "ts": "2026-08-15T19:00:00Z"},
            {
                "event": "Stop",
                "kind": "timing",
                "ms": 60_001,
                "stages": {"store": 59_780},
                "ts": "2026-08-15T22:29:17Z",
            },
            {
                "event": "Stop",
                "kind": "timing",
                "ms": 789,
                "stages": {"store": 247},
                "ts": "2026-08-17T12:00:00Z",
            },
        ],
    )
    summary = hook_diagnostic_summary(
        _state=tmp_path, _now=datetime(2026, 8, 17, 12, 30, tzinfo=UTC)
    )

    assert summary["count"] == 2
    assert summary["recent_count"] == 0
    assert summary["first_seen"] == "2026-08-15T18:49:51Z"
    assert summary["last_seen"] == "2026-08-15T19:00:00Z"
    assert summary["window_seconds"] == 3_600
    reasons = dict(cast(Mapping[str, object], summary["reasons"]))
    assert dict(cast(Mapping[str, object], reasons["runtime_gate_unsafe"])) == {
        "count": 2,
        "first_seen": "2026-08-15T18:49:51Z",
        "last_seen": "2026-08-15T19:00:00Z",
        "recent": 0,
    }
    # The all-time extreme is retained, but dated, and the live window has its own.
    timings = dict(cast(Mapping[str, object], summary["timings"]))
    assert timings == {
        "count": 2,
        "last_ms": 789,
        "max_ms": 60_001,
        "max_ts": "2026-08-15T22:29:17Z",
        "recent_count": 1,
        "recent_max_ms": 789,
        "recent_p95_ms": 789,
        "paths": {},
    }


def test_a_live_failure_is_still_counted_as_recent(tmp_path: Path) -> None:
    _seed(
        tmp_path / "observation",
        [
            {"event": "PreToolUse", "reason": "runtime_gate_unsafe", "ts": "2026-08-15T18:49:51Z"},
            {"event": "PostToolUse", "reason": "service_unavailable", "ts": "2026-08-17T12:25:00Z"},
        ],
    )
    summary = hook_diagnostic_summary(
        _state=tmp_path, _now=datetime(2026, 8, 17, 12, 30, tzinfo=UTC)
    )
    assert summary["count"] == 2
    assert summary["recent_count"] == 1
    reasons = dict(cast(Mapping[str, object], summary["reasons"]))
    assert dict(cast(Mapping[str, object], reasons["service_unavailable"]))["recent"] == 1
    assert dict(cast(Mapping[str, object], reasons["runtime_gate_unsafe"]))["recent"] == 0


def test_a_future_diagnostic_is_retained_but_not_called_recent(tmp_path: Path) -> None:
    """Clock-skewed rows must not remain live until their future timestamp arrives."""

    _seed(
        tmp_path / "observation",
        [{"event": "Stop", "reason": "timeout", "ts": "2026-08-18T12:30:00+02:00"}],
    )
    summary = hook_diagnostic_summary(
        _state=tmp_path, _now=datetime(2026, 8, 17, 12, 30, tzinfo=UTC)
    )
    assert summary["count"] == 1
    assert summary["recent_count"] == 0
    # Dated fields are normalized to the same UTC wire form as writer-created rows.
    assert summary["last_seen"] == "2026-08-18T10:30:00Z"


def test_an_undatable_row_is_counted_but_never_called_recent(tmp_path: Path) -> None:
    """An unreadable stamp is exactly what must stop being presented as live."""

    _seed(
        tmp_path / "observation",
        [
            {"event": "Stop", "reason": "timeout", "ts": "not-a-timestamp"},
            {
                "event": "Stop",
                "kind": "timing",
                "ms": 4_000,
                "stages": {"store": 1},
                "ts": "not-a-timestamp",
            },
        ],
    )
    summary = hook_diagnostic_summary(
        _state=tmp_path, _now=datetime(2026, 8, 17, 12, 30, tzinfo=UTC)
    )
    assert summary["count"] == 1
    assert summary["recent_count"] == 0
    assert summary["first_seen"] is None
    assert summary["last_seen"] is None
    assert summary["last_reason"] == "timeout"
    reasons = dict(cast(Mapping[str, object], summary["reasons"]))
    assert dict(cast(Mapping[str, object], reasons["timeout"])) == {
        "count": 1,
        "first_seen": None,
        "last_seen": None,
        "recent": 0,
    }
    timings = dict(cast(Mapping[str, object], summary["timings"]))
    assert timings["count"] == 1
    assert timings["max_ms"] == 4_000
    assert timings["max_ts"] is None
    assert timings["recent_count"] == 0
    assert timings["recent_max_ms"] is None
    assert timings["recent_p95_ms"] is None
    assert timings["paths"] == {}


def test_an_absent_diagnostics_file_summarizes_to_an_empty_dated_shape(tmp_path: Path) -> None:
    summary = hook_diagnostic_summary(_state=tmp_path)
    assert summary["count"] == 0
    assert summary["recent_count"] == 0
    assert summary["first_seen"] is None
    assert summary["last_seen"] is None
    assert summary["last_event"] is None
    assert summary["last_reason"] is None
    assert dict(cast(Mapping[str, object], summary["reasons"])) == {}
    assert dict(cast(Mapping[str, object], summary["timings"])) == {
        "count": 0,
        "last_ms": None,
        "max_ms": None,
        "max_ts": None,
        "recent_count": 0,
        "recent_max_ms": None,
        "recent_p95_ms": None,
        "paths": {},
    }


def test_budget_reason_is_an_admitted_token_and_unknown_reasons_are_closed(
    tmp_path: Path,
) -> None:
    for reason in ("hook_budget_exceeded", "async_hook_downgraded"):
        record_hook_diagnostic(reason, "PostToolUse", _state=tmp_path)
    rows = [
        json.loads(line)
        for line in (tmp_path / "observation/hook-diagnostics.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    # The async-downgrade detector was removed: its predicate flagged compliant
    # async hosts, so its token is no longer admitted and closes to the
    # unknown-reason fallback.
    assert [row["reason"] for row in rows] == ["hook_budget_exceeded", "unknown_reason"]


def test_storage_outcome_reasons_are_closed_tokens_shared_with_the_advisory(
    tmp_path: Path,
) -> None:
    """`storage_unsafe` / `storage_corrupt` are the hook-side spelling of the public codes (#338)."""

    for reason in ("storage_unsafe", "storage_corrupt", "STORAGE_CORRUPT"):
        record_hook_diagnostic(reason, "SessionStart", _state=tmp_path)
    rows = [
        json.loads(line)
        for line in (tmp_path / "observation/hook-diagnostics.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [row["reason"] for row in rows] == [
        "storage_unsafe",
        "storage_corrupt",
        "unknown_reason",
    ]
    summary = hook_diagnostic_summary(_state=tmp_path)
    reasons = cast(Mapping[str, object], summary["reasons"])
    assert set(reasons) == {"storage_unsafe", "storage_corrupt", "unknown_reason"}


def test_host_denial_reasons_are_admitted_tokens_on_the_permission_denied_event(
    tmp_path: Path,
) -> None:
    """Claude Code's PermissionDenied hook lands here as a closed token (issue #467)."""

    for reason in ("host_auto_review_denied", "host_permission_rule_denied"):
        record_hook_diagnostic(reason, "PermissionDenied", _state=tmp_path)
    rows = [
        json.loads(line)
        for line in (tmp_path / "observation/hook-diagnostics.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [(row["reason"], row["event"]) for row in rows] == [
        ("host_auto_review_denied", "PermissionDenied"),
        ("host_permission_rule_denied", "PermissionDenied"),
    ]


def test_host_hold_advisory_outcomes_are_admitted_tokens_on_the_permission_denied_event(
    tmp_path: Path,
) -> None:
    """What the hook then said about the hold is recorded beside the hold itself (issue #857)."""

    outcomes = (
        "host_denial_retry_offered",
        "host_denial_retry_exhausted",
        "host_denial_retry_unrecorded",
        "host_denial_grant_unconfirmed",
    )
    for reason in outcomes:
        record_hook_diagnostic(reason, "PermissionDenied", _state=tmp_path)
    rows = [
        json.loads(line)
        for line in (tmp_path / "observation/hook-diagnostics.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [row["reason"] for row in rows] == list(outcomes)
    assert {row["event"] for row in rows} == {"PermissionDenied"}


def test_drain_diagnostics_keep_cause_without_payload_and_report_rotation(tmp_path: Path) -> None:
    from finishup.adapters.integrations.observation_local import LocalObservationStore
    from finishup.application.observation_drain import observation_control_failure
    from finishup.cli.hook_diagnostics import record_drain_failure
    from finishup.cli.observe_hooks import map_hook_payload_to_envelope
    from finishup.ports.control import ControlError

    store = LocalObservationStore(_state=tmp_path)
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "session_id": "private-session",
            "tool_name": "shell",
            "correlation_id": "private-call",
            "exit_status": 1,
        },
        session_commitment=store.session_commitment("private-session"),
        event_ordinal=1,
        key_material=store.key_material(),
    )
    failure = observation_control_failure(ControlError("frame_invalid"))
    for _ in range(150):
        assert record_drain_failure(failure, envelope, "retry", _state=tmp_path)
    summary = hook_diagnostic_summary(_state=tmp_path)
    attempts = cast(tuple[Mapping[str, object], ...], summary["drain_failures"])
    assert len(attempts) == 32
    assert summary["drain_failure_history_complete"] is False
    assert (tmp_path / "observation/hook-diagnostics.jsonl.1").exists()
    for attempt in attempts:
        assert attempt["control_reason"] == "frame_invalid"
        assert attempt["stage"] == "control"
        assert attempt["correlation_id"] is None
        assert attempt["control_retryable"] is False
    raw = (tmp_path / "observation/hook-diagnostics.jsonl").read_text()
    assert "private-session" not in raw and "private-call" not in raw


def test_drain_diagnostic_write_failure_is_explicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.adapters.integrations.observation_local import LocalObservationStore
    from finishup.application.observation_drain import observation_control_failure
    from finishup.cli import hook_diagnostics
    from finishup.cli.observe_hooks import map_hook_payload_to_envelope
    from finishup.ports.control import ControlError

    store = LocalObservationStore(_state=tmp_path)
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {"session_id": "test", "tool_name": "shell", "exit_status": 1},
        session_commitment=store.session_commitment("test"),
        event_ordinal=1,
        key_material=store.key_material(),
    )

    def unavailable(*args: object, **kwargs: object) -> int:
        raise OSError("unavailable")

    monkeypatch.setattr(hook_diagnostics.os, "open", unavailable)
    assert not hook_diagnostics.record_drain_failure(
        observation_control_failure(ControlError("frame_invalid")),
        envelope,
        "retry",
        _state=tmp_path,
    )


@pytest.mark.parametrize("reason", ["invalid_request", "frame_invalid", "request_timeout"])
def test_control_reason_survives_diagnostic_roundtrip(tmp_path: Path, reason: str) -> None:
    from finishup.adapters.integrations.observation_local import LocalObservationStore
    from finishup.application.observation_drain import observation_control_failure
    from finishup.cli.hook_diagnostics import record_drain_failure
    from finishup.cli.observe_hooks import map_hook_payload_to_envelope
    from finishup.ports.control import ControlError

    store = LocalObservationStore(_state=tmp_path)
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {"session_id": "test", "tool_name": "shell", "exit_status": 1},
        session_commitment=store.session_commitment("test"),
        event_ordinal=1,
        key_material=store.key_material(),
    )
    assert record_drain_failure(
        observation_control_failure(ControlError(reason)), envelope, "quarantine", _state=tmp_path
    )
    rows = cast(
        tuple[Mapping[str, object], ...], hook_diagnostic_summary(_state=tmp_path)["drain_failures"]
    )
    assert len(rows) == 1
    assert rows[0]["control_reason"] == reason
    assert rows[0]["reason"] == "control_" + reason


def _lock_timeout_event(**overrides: object) -> object:
    from finishup.adapters.integrations.observation_local import (
        ObservationStoreLockEvent,
        ObservationStoreLockTimeout,
    )

    facts: dict[str, object] = {
        "scope": "process",
        "waited_ms": 1_931,
        "holder_role": "sweep",
        "holder_phase": "bump_outbox_row_attempt",
        "holder_held_ms": 1_204,
        "holder_waiting": False,
    }
    facts.update(overrides)
    return ObservationStoreLockEvent(
        kind="timeout",
        role="hook",
        phase="handle_observe",
        timeout=ObservationStoreLockTimeout(**facts),  # type: ignore[arg-type]
    )


def test_store_lock_rows_name_the_holder_and_count_as_reasons(tmp_path: Path) -> None:
    """#689: a lock timeout is named with its holder, never folded into `observe`."""

    from finishup.adapters.integrations.observation_local import ObservationStoreLockEvent
    from finishup.cli.hook_diagnostics import record_store_lock_event

    assert record_store_lock_event("PreToolUse", _lock_timeout_event(), _state=tmp_path)
    assert record_store_lock_event(
        "PostToolUse",
        ObservationStoreLockEvent(
            kind="long_hold", role="hook", phase="handle_observe", held_ms=1_500
        ),
        _state=tmp_path,
    )
    rows = [
        json.loads(line)
        for line in (tmp_path / "observation/hook-diagnostics.jsonl").read_text().splitlines()
    ]
    assert rows[0]["kind"] == "store_lock"
    assert {key: rows[0][key] for key in rows[0] if key != "ts"} == {
        "event": "PreToolUse",
        "holder_held_ms": 1_204,
        "holder_phase": "bump_outbox_row_attempt",
        "holder_role": "sweep",
        "holder_waiting": False,
        "kind": "store_lock",
        "phase": "handle_observe",
        "reason": "store_lock_timeout",
        "role": "hook",
        "scope": "process",
        "waited_ms": 1_931,
    }
    summary = hook_diagnostic_summary(_state=tmp_path)
    reasons = cast(Mapping[str, Mapping[str, object]], summary["reasons"])
    assert reasons["store_lock_timeout"]["count"] == 1
    assert reasons["store_lock_long_hold"]["count"] == 1
    events = cast(tuple[Mapping[str, object], ...], summary["store_lock_events"])
    assert [event["reason"] for event in events] == ["store_lock_timeout", "store_lock_long_hold"]
    assert events[1]["holder_held_ms"] == 1_500 and events[1]["scope"] is None


@pytest.mark.parametrize(
    "overrides",
    (
        {"holder_role": "/example/private"},
        {"holder_role": []},
        {"holder_phase": "rm -rf"},
        {"holder_phase": "A" * 65},
        {"scope": "network"},
        {"scope": {}},
        {"holder_waiting": "no"},
    ),
)
def test_store_lock_rows_refuse_open_values(tmp_path: Path, overrides: dict[str, object]) -> None:
    from finishup.cli.hook_diagnostics import record_store_lock_event

    assert not record_store_lock_event(
        "PreToolUse", _lock_timeout_event(**overrides), _state=tmp_path
    )
    assert not (tmp_path / "observation/hook-diagnostics.jsonl").exists()


def test_tampered_store_lock_rows_are_dropped_on_read(tmp_path: Path) -> None:
    from finishup.cli.hook_diagnostics import record_store_lock_event

    assert record_store_lock_event("PreToolUse", _lock_timeout_event(), _state=tmp_path)
    path = tmp_path / "observation/hook-diagnostics.jsonl"
    row = json.loads(path.read_text())
    tampered = [
        {**row, "holder_phase": "../secret"},
        {**row, "extra": "payload"},
        {**row, "reason": "store_lock_long_hold"},
        {**row, "waited_ms": -1},
    ]
    invalid_values: tuple[object, ...] = ([], {})
    tampered.extend(
        {**row, field: value}
        for field in ("reason", "event", "role", "holder_role", "scope")
        for value in invalid_values
    )
    with path.open("a", encoding="utf-8") as handle:
        for item in tampered:
            handle.write(json.dumps(item) + "\n")
    summary = hook_diagnostic_summary(_state=tmp_path)
    assert len(cast(tuple[object, ...], summary["store_lock_events"])) == 1
    reasons = cast(Mapping[str, Mapping[str, object]], summary["reasons"])
    assert reasons["store_lock_timeout"]["count"] == 1
