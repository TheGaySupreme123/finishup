"""Unit tests for observation health lifecycle thresholds."""

from __future__ import annotations

from yoetz.application.observation_health import (
    ObservationHealthSignals,
    ObservationHealthThresholds,
    compute_observation_lifecycle,
)
from yoetz.domain.observation import ObservationLifecycle, ObservationSource


def _signals(**overrides: object) -> ObservationHealthSignals:
    values: dict[str, object] = {
        "consent_active": True,
        "mapping_available": True,
        "source_coverage": {ObservationSource.CODEX_HOOK: True},
        "pending_outbox_count": 0,
        "lag_events": 0,
        "gaps": (),
        "unsupported_events": (),
        "advice_frontier": "frontier-1",
        "last_hook_receipt_monotonic": 100.0,
        "last_stream_advancement_monotonic": None,
        "last_successful_drain_monotonic": 100.0,
        "session_ended": False,
    }
    values.update(overrides)
    return ObservationHealthSignals(**values)  # type: ignore[arg-type]


def test_active_when_mapped_draining_and_fresh() -> None:
    lifecycle = compute_observation_lifecycle(
        _signals(),
        now_monotonic=110.0,
        thresholds=ObservationHealthThresholds(freshness_seconds=60.0, lag_event_cap=8),
    )
    assert lifecycle is ObservationLifecycle.ACTIVE


def test_stale_when_progress_exceeds_threshold() -> None:
    lifecycle = compute_observation_lifecycle(
        _signals(last_hook_receipt_monotonic=1.0, last_successful_drain_monotonic=1.0),
        now_monotonic=400.0,
        thresholds=ObservationHealthThresholds(freshness_seconds=60.0, lag_event_cap=8),
    )
    assert lifecycle is ObservationLifecycle.STALE


def test_single_historical_event_does_not_stay_active() -> None:
    lifecycle = compute_observation_lifecycle(
        _signals(last_hook_receipt_monotonic=10.0, last_successful_drain_monotonic=10.0),
        now_monotonic=10.0 + 301.0,
        thresholds=ObservationHealthThresholds(freshness_seconds=300.0, lag_event_cap=32),
    )
    assert lifecycle is ObservationLifecycle.STALE


def test_stopped_without_consent() -> None:
    lifecycle = compute_observation_lifecycle(
        _signals(consent_active=False),
        now_monotonic=110.0,
    )
    assert lifecycle is ObservationLifecycle.STOPPED


def test_degraded_with_pending_outbox_or_gap() -> None:
    pending = compute_observation_lifecycle(
        _signals(pending_outbox_count=2, last_successful_drain_monotonic=None),
        now_monotonic=110.0,
    )
    assert pending is ObservationLifecycle.DEGRADED
    gap = compute_observation_lifecycle(
        _signals(gaps=("service_unavailable",)),
        now_monotonic=110.0,
    )
    assert gap is ObservationLifecycle.DEGRADED


def test_recent_pending_outbox_does_not_degrade_healthy_observation() -> None:
    """A non-empty queue is healthy while its drain is recent (#974)."""

    lifecycle = compute_observation_lifecycle(
        _signals(pending_outbox_count=1, last_successful_drain_monotonic=109.0),
        now_monotonic=110.0,
    )
    assert lifecycle is ObservationLifecycle.ACTIVE


def test_standing_unpaired_record_is_not_degraded_health() -> None:
    """#917: a sticky orphan record is disclosed coverage, not current acquisition health."""

    thresholds = ObservationHealthThresholds(freshness_seconds=60.0, lag_event_cap=8)
    assert (
        compute_observation_lifecycle(
            _signals(gaps=("unpaired_event",)), now_monotonic=110.0, thresholds=thresholds
        )
        is ObservationLifecycle.ACTIVE
    )
    for standing in (
        "truncated_payload",
        "content_capture_unavailable",
        "pending_attempt_expired",
        "content_unselected",
    ):
        assert (
            compute_observation_lifecycle(
                _signals(gaps=(standing,)), now_monotonic=110.0, thresholds=thresholds
            )
            is ObservationLifecycle.ACTIVE
        ), standing
    # Transient acquisition conditions still degrade the lifecycle beside it.
    for transient in ("source_lag", "cursor_stale", "service_unavailable", "vault_locked"):
        assert (
            compute_observation_lifecycle(
                _signals(gaps=("unpaired_event", transient)),
                now_monotonic=110.0,
                thresholds=thresholds,
            )
            is ObservationLifecycle.DEGRADED
        ), transient
