"""Production SystemClock must emit whole-millisecond UTC timestamps."""

from __future__ import annotations

from finishup.domain.values import format_rfc3339_millis
from finishup.service import daemon as daemon_module


def test_system_clock_now_utc_is_whole_millisecond() -> None:
    clock = daemon_module._SystemClock()  # pyright: ignore[reportPrivateUsage]
    now = clock.now_utc()
    assert now.tzinfo is not None
    assert now.utcoffset() is not None
    assert now.microsecond % 1000 == 0
    # Must be formatable for throttle wall-anomaly checks.
    assert format_rfc3339_millis(now).endswith("Z")
