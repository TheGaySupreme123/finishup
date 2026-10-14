from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import pytest

from finishup.ports.control import ServiceState
from finishup.ports.secret_memory import HumanAuthorizationProof
from finishup.protocol.canonical import canonical_encode
from finishup.service.lifecycle import (
    IDLE_STOP_SECONDS,
    IdleRelockPolicy,
    LifecycleError,
    ServiceLifecycle,
    SessionSecurityEvent,
    probe_singleton_holder,
    probe_singleton_holder_identity,
    probe_singleton_holder_lock,
)

_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000001"
_COMMITMENT = "sha256:" + "a" * 64


class _EndpointRecoveryAuthority(Protocol):
    def assert_held(self) -> None: ...


@dataclass(slots=True)
class _Clock:
    monotonic: float = 10.0

    def monotonic_seconds(self) -> float:
        return self.monotonic

    def now_utc(self) -> object:
        raise AssertionError("wall clock forbidden")


@dataclass(slots=True)
class _GenerationStore:
    generation: int = 0

    def advance(self, instance_id: str) -> int:
        assert instance_id == _INSTANCE_ID
        self.generation += 1
        return self.generation


def _lifecycle(clock: _Clock, **callbacks: object) -> ServiceLifecycle:
    return ServiceLifecycle(
        clock,  # pyright: ignore[reportArgumentType] - wall clock is intentionally unavailable
        generation_store=_GenerationStore(),
        process_start_identity_commitment=_COMMITMENT,
        instance_id=_INSTANCE_ID,
        **callbacks,  # pyright: ignore[reportArgumentType]
    )


@pytest.mark.anyio
async def test_endpoint_recovery_runs_under_singleton_before_publication(tmp_path: Path) -> None:
    calls: list[str] = []
    captured: list[_EndpointRecoveryAuthority] = []

    async def recover(authority: _EndpointRecoveryAuthority) -> None:
        authority.assert_held()
        captured.append(authority)
        calls.append("recover")

    async def publish(_instance: object) -> None:
        assert calls == ["recover"]
        calls.append("publish")

    lifecycle = _lifecycle(
        _Clock(),
        singleton_lock_path=tmp_path / "service.lock",
        endpoint_recovery=recover,
        endpoint_publisher=publish,
    )
    await lifecycle.acquire_singleton()
    await lifecycle.publish_endpoint()
    assert calls == ["recover", "publish"]

    await lifecycle.transition(ServiceState.LOCKED)
    await lifecycle.close()
    with pytest.raises(LifecycleError, match="invalid_transition"):
        captured[0].assert_held()


@pytest.mark.anyio
async def test_ready_requires_positive_vault_generation_and_relock_clears_it() -> None:
    lifecycle = _lifecycle(_Clock())
    await lifecycle.acquire_singleton()
    with pytest.raises(LifecycleError, match="vault_locked"):
        await lifecycle.transition(ServiceState.READY)
    instance = await lifecycle.transition(ServiceState.READY, vault_generation=3)
    assert instance.state is ServiceState.READY
    assert lifecycle.current_vault_generation == 3
    await lifecycle.request_lock()
    assert lifecycle.state is ServiceState.LOCKED
    assert lifecycle.current_vault_generation is None


@pytest.mark.anyio
async def test_transition_table_rejects_every_unlisted_edge() -> None:
    lifecycle = _lifecycle(_Clock())
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    with pytest.raises(LifecycleError, match="invalid_transition"):
        await lifecycle.transition(ServiceState.READY, vault_generation=1)
    await lifecycle.transition(ServiceState.UNLOCKING)
    await lifecycle.transition(ServiceState.READY, vault_generation=1)
    with pytest.raises(LifecycleError, match="invalid_transition"):
        await lifecycle.transition(ServiceState.UNLOCKING)


@pytest.mark.anyio
async def test_admission_blocks_drain_until_released() -> None:
    closed = asyncio.Event()

    async def close_ready() -> None:
        closed.set()

    lifecycle = _lifecycle(_Clock(), close_ready_composition=close_ready)
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.READY, vault_generation=1)
    admission = await lifecycle.admit(
        "write",
        secret_use_class="secret_consumer",
        provider_call=True,
        shielded_commit=True,
    )
    draining = asyncio.create_task(lifecycle.request_lock())
    await asyncio.sleep(0)
    assert lifecycle.state is ServiceState.DRAINING
    assert not closed.is_set()
    with pytest.raises(LifecycleError, match="service_draining"):
        await lifecycle.admit("late")
    await lifecycle.release(admission)
    await draining
    assert closed.is_set()
    assert lifecycle.state is ServiceState.LOCKED


@pytest.mark.anyio
async def test_close_after_completed_stop_does_not_repeat_ready_cleanup() -> None:
    cleanup_calls = 0

    async def close_ready() -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1

    lifecycle = _lifecycle(_Clock(), close_ready_composition=close_ready)
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.READY, vault_generation=1)

    await lifecycle.request_stop()
    assert lifecycle.state is ServiceState.DRAINING
    assert cleanup_calls == 1

    await lifecycle.close()
    await lifecycle.close()
    assert cleanup_calls == 1


@pytest.mark.anyio
async def test_idle_policy_requires_exact_generation_bound_proof() -> None:
    clock = _Clock()
    lifecycle = _lifecycle(clock)
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.READY, vault_generation=9)
    proposed = IdleRelockPolicy(None)
    target = lifecycle.idle_relock_target_digest(lifecycle.idle_relock_policy, proposed)
    proof = HumanAuthorizationProof(
        "proof-idle",
        "idle_relock_policy_change",
        target,
        lifecycle.instance.generation,
        9,
        None,
        9.0,
        20.0,
    )
    assert await lifecycle.change_idle_relock_policy(proposed, proof) == proposed
    with pytest.raises(LifecycleError, match="human_authorization_stale"):
        await lifecycle.change_idle_relock_policy(IdleRelockPolicy(60), proof)


@pytest.mark.anyio
async def test_session_lock_and_monitor_loss_relock_but_wake_never_readies() -> None:
    lifecycle = _lifecycle(_Clock())
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.READY, vault_generation=1)
    await lifecycle.on_session_event(SessionSecurityEvent.USER_SESSION_LOCKED)
    assert lifecycle.state is ServiceState.LOCKED
    await lifecycle.on_session_event(SessionSecurityEvent.USER_SESSION_UNLOCKED)
    await lifecycle.on_session_event(SessionSecurityEvent.SYSTEM_RESUME)
    assert lifecycle.state is ServiceState.LOCKED


@pytest.mark.anyio
async def test_drain_deadline_fails_instead_of_claiming_locked() -> None:
    terminated = asyncio.Event()

    async def terminate() -> None:
        terminated.set()

    lifecycle = _lifecycle(_Clock(), terminate_on_deadline=terminate, lock_drain_seconds=0.01)
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.READY, vault_generation=1)
    await lifecycle.admit("stuck", secret_use_class="secret_consumer")
    with pytest.raises(LifecycleError, match="service_draining"):
        await lifecycle.request_lock()
    assert terminated.is_set()
    assert lifecycle.state is ServiceState.FAILED


def test_idle_policy_is_closed_and_restart_default_is_safe() -> None:
    assert IDLE_STOP_SECONDS == 7_200
    # Relock must stay strictly below the process-idle stop so the cheap in-process soft lock
    # is always the first containment reached (#291).
    default_seconds = IdleRelockPolicy().seconds
    assert default_seconds == 3_600
    assert default_seconds is not None and default_seconds < IDLE_STOP_SECONDS
    assert IdleRelockPolicy(None).canonical_value() == {"mode": "disabled"}
    with pytest.raises(ValueError, match="idle_relock_policy_invalid"):
        IdleRelockPolicy(59)


@pytest.mark.anyio
async def test_idle_stop_waits_for_client_disconnect_then_stops_after_two_hours() -> None:
    clock = _Clock()
    lifecycle = _lifecycle(clock)
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.LOCKED)
    await lifecycle.client_connected()
    clock.monotonic += 8_000.0
    monitor = asyncio.create_task(lifecycle.run_idle_monitor(poll_seconds=0.001))
    await asyncio.sleep(0.01)
    assert not monitor.done()

    await lifecycle.client_disconnected()
    clock.monotonic += 7_201.0
    await asyncio.wait_for(monitor, timeout=1.0)
    assert lifecycle.state is ServiceState.DRAINING


@pytest.mark.anyio
async def test_note_activity_renews_the_idle_window_indefinitely() -> None:
    """Quiescent activity evidence (e.g. resolved observation rows) defers relock forever,
    while its absence still relocks one full window later (#291)."""

    clock = _Clock()
    lifecycle = _lifecycle(clock)
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.READY, vault_generation=1)
    monitor = asyncio.create_task(lifecycle.run_idle_monitor(poll_seconds=0.001))
    for _ in range(4):
        clock.monotonic += 3_599.0
        await lifecycle.note_activity()
        await asyncio.sleep(0.005)
        assert lifecycle.state is ServiceState.READY

    clock.monotonic += 3_601.0
    for _ in range(200):
        await asyncio.sleep(0.005)
        if lifecycle.state is ServiceState.LOCKED:
            break
    assert lifecycle.state is ServiceState.LOCKED
    monitor.cancel()
    with pytest.raises(asyncio.CancelledError):
        await monitor


@pytest.mark.anyio
async def test_note_activity_also_holds_the_process_idle_lease() -> None:
    """Quiescent activity evidence must defer the process stop, not only the relock.

    The relock check is skipped entirely once the process-idle deadline passes, so if activity
    renewed only the relock clock a live hook-fed workspace would still lose its daemon at
    ``IDLE_STOP_SECONDS`` — trading the cheap soft lock that re-readies on the next ordinary call
    for a full respawn, which is the containment ordering #291 exists to preserve.
    """

    clock = _Clock()
    lifecycle = _lifecycle(clock, idle_stop_seconds=5.0)
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.READY, vault_generation=1)
    monitor = asyncio.create_task(lifecycle.run_idle_monitor(poll_seconds=0.001))
    # Four sub-deadline steps total far more than the 5 s stop: only a renewed process clock
    # can keep the daemon alive across them.
    for _ in range(4):
        clock.monotonic += 4.0
        await lifecycle.note_activity()
        await asyncio.sleep(0.005)
        assert lifecycle.state is ServiceState.READY
        assert not monitor.done()

    clock.monotonic += 6.0
    await asyncio.wait_for(monitor, timeout=1.0)
    assert lifecycle.state is ServiceState.DRAINING


@pytest.mark.anyio
async def test_connected_client_prevents_idle_relock() -> None:
    clock = _Clock()
    lifecycle = _lifecycle(clock)
    await lifecycle.acquire_singleton()
    await lifecycle.transition(ServiceState.READY, vault_generation=1)
    await lifecycle.client_connected()
    clock.monotonic += 3_601.0
    monitor = asyncio.create_task(lifecycle.run_idle_monitor(poll_seconds=0.001))
    await asyncio.sleep(0.01)
    assert lifecycle.state is ServiceState.READY
    monitor.cancel()
    with pytest.raises(asyncio.CancelledError):
        await monitor


@pytest.mark.anyio
async def test_singleton_lock_records_a_probeable_holder_pid(tmp_path: Path) -> None:
    """A refused start can only name the process it lost to if the holder left its identity."""

    path = tmp_path / "service.lock"
    lifecycle = _lifecycle(_Clock(), singleton_lock_path=path)
    await lifecycle.acquire_singleton()

    assert probe_singleton_holder(path) == os.getpid()

    await lifecycle.transition(ServiceState.LOCKED)
    await lifecycle.close()

    assert probe_singleton_holder(path) is None


def test_holder_probe_answers_nothing_for_a_body_it_cannot_trust(tmp_path: Path) -> None:
    assert probe_singleton_holder(tmp_path / "absent.lock") is None

    path = tmp_path / "service.lock"
    path.write_bytes(b"")
    assert probe_singleton_holder(path) is None
    path.write_bytes(b"not json at all\n")
    assert probe_singleton_holder(path) is None
    path.write_bytes(b'{"instance_id":"svc","pid":0}\n')
    assert probe_singleton_holder(path) is None
    path.write_bytes(b'{"instance_id":"svc","pid":"' + b"9" * 300 + b'"}\n')
    assert probe_singleton_holder(path) is None


def test_holder_probe_refuses_a_stamp_anyone_else_could_have_written(tmp_path: Path) -> None:
    """A stamp only trusted when nobody but the owner could have placed it there."""

    live = canonical_encode({"instance_id": "svc", "pid": os.getpid()}) + b"\n"
    path = tmp_path / "service.lock"
    path.write_bytes(live)
    path.chmod(0o600)
    assert probe_singleton_holder(path) == os.getpid()

    path.chmod(0o644)
    assert probe_singleton_holder(path) is None
    path.chmod(0o610)
    assert probe_singleton_holder(path) is None

    path.chmod(0o600)
    link = tmp_path / "service.lock.link"
    link.symlink_to(path)
    assert probe_singleton_holder(link) is None


@pytest.mark.anyio
async def test_singleton_stamp_names_the_holder_installation_identity(tmp_path: Path) -> None:
    """A client whose hello the holder rejects can still learn what it is talking to."""

    from finishup import __version__
    from finishup.protocol.schemas import schema_manifest_digest

    path = tmp_path / "service.lock"
    lifecycle = _lifecycle(_Clock(), singleton_lock_path=path)
    await lifecycle.acquire_singleton()
    try:
        assert probe_singleton_holder_lock(path) is True
        holder = probe_singleton_holder_identity(path)
        assert holder is not None
        assert holder.pid == os.getpid()
        assert holder.schema_manifest_digest == schema_manifest_digest()
        assert holder.service_version == __version__
        assert holder.instance_id is not None
    finally:
        await lifecycle.transition(ServiceState.LOCKED)
        await lifecycle.close()
    assert probe_singleton_holder_lock(path) is False
    assert probe_singleton_holder_identity(path) is None


@pytest.mark.anyio
async def test_singleton_stamp_carries_the_instance_lifecycle_and_source_ref(
    tmp_path: Path,
) -> None:
    """A refused client, or ``finishup instance status``, can name what kind of instance holds
    the singleton (issue #604); only the closed fields ride in the stamp."""

    path = tmp_path / "service.lock"
    source_ref = "c3d553611c998df32a72c64337d1e8231560a37d"
    lifecycle = _lifecycle(
        _Clock(),
        singleton_lock_path=path,
        holder_identity={"instance_lifecycle": "disposable", "source_ref": source_ref},
    )
    await lifecycle.acquire_singleton()
    try:
        holder = probe_singleton_holder_identity(path)
        assert holder is not None
        assert holder.instance_lifecycle == "disposable"
        assert holder.source_ref == source_ref
    finally:
        await lifecycle.transition(ServiceState.LOCKED)
        await lifecycle.close()

    with pytest.raises(ValueError, match="holder_identity_invalid"):
        _lifecycle(_Clock(), singleton_lock_path=path, holder_identity={"instance_lifecycle": "x"})
    with pytest.raises(ValueError, match="holder_identity_invalid"):
        _lifecycle(_Clock(), singleton_lock_path=path, holder_identity={"other": "value"})


def test_holder_probe_drops_malformed_instance_identity_fields(tmp_path: Path) -> None:
    path = tmp_path / "service.lock"
    path.write_bytes(
        canonical_encode(
            {
                "instance_id": "svc_legacy",
                "pid": os.getpid(),
                "instance_lifecycle": "permanent",
                "source_ref": "HEAD",
            }
        )
        + b"\n"
    )
    path.chmod(0o600)
    holder = probe_singleton_holder_identity(path)
    assert holder is not None
    assert holder.instance_lifecycle is None
    assert holder.source_ref is None


def test_holder_identity_probe_tolerates_legacy_and_malformed_identity_fields(
    tmp_path: Path,
) -> None:
    path = tmp_path / "service.lock"
    legacy = canonical_encode({"instance_id": "svc_legacy", "pid": os.getpid()}) + b"\n"
    path.write_bytes(legacy)
    path.chmod(0o600)
    holder = probe_singleton_holder_identity(path)
    assert holder is not None
    assert (holder.pid, holder.instance_id) == (os.getpid(), "svc_legacy")
    assert holder.schema_manifest_digest is None
    assert holder.service_version is None

    path.write_bytes(
        canonical_encode(
            {
                "instance_id": "svc_bad",
                "pid": os.getpid(),
                "schema_manifest_digest": "not-a-digest",
                "service_version": "",
            }
        )
        + b"\n"
    )
    holder = probe_singleton_holder_identity(path)
    assert holder is not None
    assert holder.schema_manifest_digest is None
    assert holder.service_version is None
