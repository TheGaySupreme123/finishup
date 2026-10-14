"""Truthful observation lifecycle from real acquisition/drain/mapping signals."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from yoetz.domain.observation import (
    MATERIAL_OBSERVATION_GAPS,
    ObservationLifecycle,
    ObservationSource,
)

__all__ = [
    "DEFAULT_OBSERVATION_HEALTH_THRESHOLDS",
    "ObservationHealthSignals",
    "ObservationHealthThresholds",
    "compute_observation_lifecycle",
    "qualifying_progress_monotonic",
]


@dataclass(frozen=True, slots=True)
class ObservationHealthThresholds:
    """Monotonic thresholds owned by the observation subsystem."""

    freshness_seconds: float = 300.0
    lag_event_cap: int = 32
    drain_freshness_seconds: float = 120.0

    def __post_init__(self) -> None:
        if (
            type(self.freshness_seconds) is not float
            or self.freshness_seconds <= 0.0
            or type(self.lag_event_cap) is not int
            or self.lag_event_cap < 1
            or type(self.drain_freshness_seconds) is not float
            or self.drain_freshness_seconds <= 0.0
        ):
            raise ValueError("observation_health_invalid")


DEFAULT_OBSERVATION_HEALTH_THRESHOLDS: Final = ObservationHealthThresholds()


@dataclass(frozen=True, slots=True)
class ObservationHealthSignals:
    """Real observation state used to compute lifecycle (tests inject the clock)."""

    consent_active: bool
    mapping_available: bool
    source_coverage: Mapping[ObservationSource, bool]
    pending_outbox_count: int
    lag_events: int
    gaps: tuple[str, ...]
    unsupported_events: tuple[str, ...]
    advice_frontier: str | None
    last_hook_receipt_monotonic: float | None = None
    last_stream_advancement_monotonic: float | None = None
    last_successful_drain_monotonic: float | None = None
    session_ended: bool = False


def qualifying_progress_monotonic(signals: ObservationHealthSignals) -> float | None:
    """Latest monotonic sample that counts as observation progress."""

    samples = [
        signals.last_hook_receipt_monotonic,
        signals.last_stream_advancement_monotonic,
        signals.last_successful_drain_monotonic,
    ]
    present = [item for item in samples if item is not None]
    if not present:
        return None
    return max(present)


def compute_observation_lifecycle(
    signals: ObservationHealthSignals,
    *,
    now_monotonic: float,
    thresholds: ObservationHealthThresholds = DEFAULT_OBSERVATION_HEALTH_THRESHOLDS,
) -> ObservationLifecycle:
    """Derive ACTIVE/DEGRADED/STALE/STOPPED from real signals and injected clock."""

    if type(signals) is not ObservationHealthSignals:
        raise ValueError("observation_health_invalid")
    if type(now_monotonic) is not float or now_monotonic < 0.0:
        raise ValueError("observation_health_invalid")
    if type(thresholds) is not ObservationHealthThresholds:
        raise ValueError("observation_health_invalid")

    if not signals.consent_active or signals.session_ended:
        return ObservationLifecycle.STOPPED

    if signals.lag_events > thresholds.lag_event_cap:
        return ObservationLifecycle.STALE
    if signals.pending_outbox_count > thresholds.lag_event_cap:
        return ObservationLifecycle.STALE

    progress = qualifying_progress_monotonic(signals)
    if progress is None:
        # Consent alone / empty history is never ACTIVE indefinitely.
        return ObservationLifecycle.DEGRADED
    age = now_monotonic - progress
    if age < 0.0:
        raise ValueError("observation_health_invalid")
    if age > thresholds.freshness_seconds:
        return ObservationLifecycle.STALE

    has_source = any(signals.source_coverage.values())
    material_gap = any(gap in MATERIAL_OBSERVATION_GAPS for gap in signals.gaps) or bool(
        signals.unsupported_events
    )
    drain_stale = False
    if signals.pending_outbox_count > 0:
        drain = signals.last_successful_drain_monotonic
        if drain is None or (now_monotonic - drain) > thresholds.drain_freshness_seconds:
            drain_stale = True

    if not signals.mapping_available or not has_source or material_gap or drain_stale:
        return ObservationLifecycle.DEGRADED

    return ObservationLifecycle.ACTIVE
