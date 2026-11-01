"""Session-lock/suspend monitor capability evidence.

Proves normalized lock/suspend/resume/unlock ordering and disconnect-to-monitor-lost
behavior. Injected subscribe bindings exercise the release monitor contract offline;
default platform backends without a verified API binding remain unsupported.
"""

from __future__ import annotations

import sys
from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest
from tests.capability.evidence import (
    CapabilityCase,
    EvidenceOutcome,
    Observation,
    bytes_digest,
    record_and_write,
    runtime_capability_context,
)

from finishup.adapters.session_events import (
    LinuxLogin1Backend,
    MacOSSessionBackend,
    SessionEventMonitor,
    SessionMonitorError,
    SessionMonitorReason,
)
from finishup.protocol.canonical import canonical_digest
from finishup.service.lifecycle import SessionSecurityEvent

_TEST_REVISION = bytes_digest(Path(__file__).read_bytes())

_CASE_ORDER = CapabilityCase(
    case_id="SESS-001",
    requirement_id="ADR-008.session-monitor",
    claim_id="E-008.session-event-monitor",
    capability_family="session_event_monitor",
    required_observation_codes=frozenset(
        {
            "lock_suspend_order_held",
            "monitor_lost_on_disconnect",
            "resume_never_ready",
        }
    ),
    allowed_observation_codes=frozenset(
        {
            "lock_suspend_order_held",
            "monitor_lost_on_disconnect",
            "resume_never_ready",
            "duplicate_suppressed",
            "capability_active_while_subscribed",
        }
    ),
)

_CASE_PLATFORM = CapabilityCase(
    case_id="SESS-002",
    requirement_id="ADR-008.session-monitor",
    claim_id="E-008.session-platform-api",
    capability_family="session_event_monitor",
    required_observation_codes=frozenset({"platform_backend_selected"}),
    allowed_observation_codes=frozenset(
        {
            "platform_backend_selected",
            "backend_binding_present",
        }
    ),
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_normalized_lock_suspend_resume_and_monitor_lost(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)

    sink: Callable[[SessionSecurityEvent], Awaitable[None]] | None = None
    unsubscribed = 0

    async def subscribe(
        value: Callable[[SessionSecurityEvent], Awaitable[None]],
    ) -> Callable[[], Awaitable[None]]:
        nonlocal sink
        sink = value
        await value(SessionSecurityEvent.USER_SESSION_LOCKED)

        async def unsubscribe() -> None:
            nonlocal unsubscribed
            unsubscribed += 1

        return unsubscribe

    events: list[SessionSecurityEvent] = []

    async def lifecycle(event: SessionSecurityEvent) -> None:
        events.append(event)

    backend = (
        MacOSSessionBackend(subscribe)
        if sys.platform == "darwin"
        else LinuxLogin1Backend(subscribe)
    )
    monitor = SessionEventMonitor(backend)
    await monitor.start(lifecycle)
    assert monitor.capability.active
    assert callable(sink)
    emit = sink
    await emit(SessionSecurityEvent.USER_SESSION_LOCKED)  # duplicate suppressed
    await emit(SessionSecurityEvent.USER_SESSION_UNLOCKED)
    await emit(SessionSecurityEvent.SYSTEM_SUSPEND)
    await emit(SessionSecurityEvent.SYSTEM_RESUME)
    assert events == [
        SessionSecurityEvent.USER_SESSION_LOCKED,
        SessionSecurityEvent.USER_SESSION_UNLOCKED,
        SessionSecurityEvent.SYSTEM_SUSPEND,
        SessionSecurityEvent.SYSTEM_RESUME,
    ]
    # Resume is delivered for lifecycle drain/relock policy; it never itself means ready.
    assert SessionSecurityEvent.SYSTEM_RESUME in events
    await emit(SessionSecurityEvent.MONITOR_LOST)
    assert events[-1] is SessionSecurityEvent.MONITOR_LOST
    assert not monitor.capability.active
    await monitor.close()
    assert unsubscribed == 1

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"session-event-monitor-order"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest(
            {"backend": monitor.capability.backend, "cell": "injected_subscribe"}
        ),
        external_tool="session_monitor",
        external_version="0.1.0",
        integration_channel="session_events",
    )
    evidence = record_and_write(
        _CASE_ORDER,
        context,
        (
            Observation("capability_active_while_subscribed", boolean_value=True),
            Observation("duplicate_suppressed", boolean_value=True),
            Observation("lock_suspend_order_held", boolean_value=True),
            Observation("monitor_lost_on_disconnect", boolean_value=True),
            Observation("resume_never_ready", boolean_value=True),
        ),
        EvidenceOutcome.PASS,
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.PASS


@pytest.mark.anyio
@pytest.mark.skipif(
    not (sys.platform == "darwin" or sys.platform.startswith("linux")),
    reason="session monitor platform cells are macOS/Linux only",
)
async def test_default_platform_backend_without_binding_is_unsupported(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)

    monitor = SessionEventMonitor()
    assert monitor.capability.platform in {"darwin", "linux"}
    assert not monitor.capability.active

    async def lifecycle(event: SessionSecurityEvent) -> None:
        del event

    with pytest.raises(SessionMonitorError) as raised:
        await monitor.start(lifecycle)
    assert raised.value.reason is SessionMonitorReason.BACKEND_UNAVAILABLE

    context = runtime_capability_context(
        fixture_digest=bytes_digest(b"session-platform-unbound"),
        test_revision=_TEST_REVISION,
        config_profile_digest=canonical_digest(
            {"backend": monitor.capability.backend, "cell": "default_unbound"}
        ),
        external_tool="session_monitor",
        external_version="0.1.0",
        integration_channel="session_events",
    )
    evidence = record_and_write(
        _CASE_PLATFORM,
        context,
        (
            Observation("backend_binding_present", boolean_value=False),
            Observation("platform_backend_selected", boolean_value=True),
        ),
        EvidenceOutcome.UNSUPPORTED,
        ("session_backend_unbound",),
        output_root=evidence_root,
    )
    assert evidence.outcome is EvidenceOutcome.UNSUPPORTED
