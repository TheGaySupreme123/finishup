"""Per-user service lifecycle, admission fencing, draining, and idle relock."""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import hashlib
import hmac
import math
import os
import re
import stat
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Final, Literal, Protocol, cast

from yoetz import __version__
from yoetz.domain.values import validate_sha256_digest
from yoetz.ports.clock import ClockPort
from yoetz.ports.control import ServiceState
from yoetz.ports.secret_memory import HumanAuthorizationProof, SecretMemoryError
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_encode,
    strict_json_parse,
)
from yoetz.protocol.ids import IdKind, new_id, validate_id

__all__ = [
    "IDLE_STOP_SECONDS",
    "LOCK_DRAIN_SECONDS",
    "SINGLETON_LOCK_NAME",
    "STOP_DRAIN_SECONDS",
    "Admission",
    "IdleRelockPolicy",
    "LifecycleError",
    "ServiceInstance",
    "ServiceLifecycle",
    "SessionSecurityEvent",
    "SingletonHolder",
    "probe_singleton_holder",
    "probe_singleton_holder_identity",
    "probe_singleton_holder_lock",
]

LOCK_DRAIN_SECONDS: Final = 5
STOP_DRAIN_SECONDS: Final = 30
# Soft relock (default 3,600 s) must come before process stop: the in-process soft lock re-readies
# on the next ordinary call, while a stopped process needs an on-demand relaunch. Keeping
# relock < stop makes the cheap containment the first one reached.
IDLE_STOP_SECONDS: Final = 7_200
# One name for the per-user singleton lock file, so the daemon that takes it and the CLI that
# reports on its holder can never disagree about which file that is.
SINGLETON_LOCK_NAME: Final = "service.lock"
# pid + instance id + service version + schema-manifest digest + instance lifecycle + source
# ref, canonical JSON, one line.
_MAX_SINGLETON_HOLDER_BYTES: Final = 512
_HOLDER_LIFECYCLES: Final = frozenset({"persistent", "disposable"})
_HOLDER_SOURCE_REF: Final = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$", re.ASCII)
_DEFAULT_IDLE_SECONDS: Final = 3_600
_IDLE_POLICY_DOMAIN: Final = "yoetz/idle-relock-policy-change/v1\x00"
_LIFECYCLE_REASONS: Final = frozenset(
    {
        "service_already_running",
        "invalid_transition",
        "vault_locked",
        "service_draining",
        "session_monitor_unavailable",
        "human_authorization_required",
        "human_authorization_stale",
    }
)
_ALLOWED_TRANSITIONS: Final[dict[ServiceState, frozenset[ServiceState]]] = {
    ServiceState.STARTING: frozenset(
        {ServiceState.LOCKED, ServiceState.READY, ServiceState.FAILED}
    ),
    ServiceState.LOCKED: frozenset(
        {ServiceState.UNLOCKING, ServiceState.DRAINING, ServiceState.FAILED}
    ),
    ServiceState.UNLOCKING: frozenset(
        {ServiceState.READY, ServiceState.LOCKED, ServiceState.FAILED}
    ),
    ServiceState.READY: frozenset({ServiceState.DRAINING, ServiceState.FAILED}),
    ServiceState.DRAINING: frozenset({ServiceState.LOCKED, ServiceState.FAILED}),
    ServiceState.FAILED: frozenset({ServiceState.DRAINING}),
}


class LifecycleError(Exception):
    """Bounded lifecycle failure."""

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _LIFECYCLE_REASONS:
            raise TypeError("lifecycle_reason_invalid")
        self.reason = reason
        super().__init__(reason)


class SessionSecurityEvent(str, Enum):  # noqa: UP042 - frozen internal vocabulary
    USER_SESSION_LOCKED = "user_session_locked"
    SYSTEM_SUSPEND = "system_suspend"
    USER_SESSION_UNLOCKED = "user_session_unlocked"
    SYSTEM_RESUME = "system_resume"
    MONITOR_LOST = "monitor_lost"


@dataclass(frozen=True, slots=True)
class IdleRelockPolicy:
    seconds: int | None = _DEFAULT_IDLE_SECONDS

    def __post_init__(self) -> None:
        if self.seconds is not None and (
            type(self.seconds) is not int or not 60 <= self.seconds <= 86_400
        ):
            raise ValueError("idle_relock_policy_invalid")

    def canonical_value(self) -> dict[str, JsonValue]:
        if self.seconds is None:
            return {"mode": "disabled"}
        return {"mode": "finite", "seconds": self.seconds}


@dataclass(frozen=True, slots=True)
class ServiceInstance:
    instance_id: str
    generation: int
    process_start_identity_commitment: str
    state: ServiceState

    def __post_init__(self) -> None:
        validate_id(IdKind.SERVICE_INSTANCE, self.instance_id)
        if type(self.generation) is not int or self.generation <= 0:
            raise ValueError("service_generation_invalid")
        validate_sha256_digest(self.process_start_identity_commitment)
        if type(self.state) is not ServiceState:
            raise ValueError("service_state_invalid")


type SecretUseClass = Literal["none", "secret_consumer"]
type CommitSectionState = Literal["none", "shielded"]


@dataclass(slots=True, repr=False)
class Admission:
    method: str
    secret_use_class: SecretUseClass
    commit_section_state: CommitSectionState
    provider_call: bool
    writer_queued: bool
    lease_held: bool
    _owner_token: object = field(repr=False)
    _released: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if type(self.method) is not str or not self.method:
            raise ValueError("admission_method_invalid")
        if self.secret_use_class not in {"none", "secret_consumer"}:
            raise ValueError("admission_secret_use_invalid")
        if self.commit_section_state not in {"none", "shielded"}:
            raise ValueError("admission_commit_state_invalid")
        if any(
            type(value) is not bool
            for value in (self.provider_call, self.writer_queued, self.lease_held)
        ):
            raise ValueError("admission_counter_invalid")

    def __repr__(self) -> str:
        return f"Admission(method={self.method!r}, released={self._released})"

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("admission_not_serializable")

    def belongs_to(self, owner_token: object) -> bool:
        return self._owner_token is owner_token and not self._released

    def mark_released(self) -> None:
        if self._released:
            raise LifecycleError("invalid_transition")
        self._released = True


class _GenerationStorePort(Protocol):
    def advance(self, instance_id: str) -> int: ...


class _SingletonEndpointAuthority:
    """Nonserializable proof that this lifecycle still owns its singleton descriptor."""

    __slots__ = ("_assertion",)

    def __init__(self, assertion: Callable[[], None]) -> None:
        self._assertion = assertion

    def assert_held(self) -> None:
        self._assertion()

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("singleton_endpoint_authority_not_serializable")


class ServiceLifecycle:
    """Own exactly one service instance and all ready admission."""

    def __init__(
        self,
        clock: ClockPort,
        *,
        generation_store: _GenerationStorePort,
        process_start_identity_commitment: str,
        instance_id: str | None = None,
        singleton_lock_path: Path | None = None,
        endpoint_recovery: Callable[[_SingletonEndpointAuthority], Awaitable[None]] | None = None,
        endpoint_publisher: Callable[[ServiceInstance], Awaitable[None]] | None = None,
        endpoint_cleanup: Callable[[ServiceInstance], Awaitable[None]] | None = None,
        cancel_ready_work: Callable[[], Awaitable[None]] | None = None,
        close_ready_composition: Callable[[], Awaitable[None]] | None = None,
        terminate_on_deadline: Callable[[], Awaitable[None]] | None = None,
        lock_drain_seconds: float = float(LOCK_DRAIN_SECONDS),
        stop_drain_seconds: float = float(STOP_DRAIN_SECONDS),
        idle_stop_seconds: float = float(IDLE_STOP_SECONDS),
        holder_identity: Mapping[str, str] | None = None,
    ) -> None:
        validate_sha256_digest(process_start_identity_commitment)
        # Only the closed instance-identity fields may ride in the lock stamp (issue #604); the
        # stamp names what holds the singleton, it never carries content.
        stamped: dict[str, str] = {}
        for name, value in (holder_identity or {}).items():
            if name == "instance_lifecycle" and value in _HOLDER_LIFECYCLES:
                stamped[name] = value
            elif name == "source_ref" and _HOLDER_SOURCE_REF.match(value):
                stamped[name] = value
            else:
                raise ValueError("holder_identity_invalid")
        self._holder_identity = stamped
        if instance_id is not None:
            validate_id(IdKind.SERVICE_INSTANCE, instance_id)
        for value in (lock_drain_seconds, stop_drain_seconds, idle_stop_seconds):
            if type(value) is not float or not math.isfinite(value) or value <= 0.0:
                raise ValueError("drain_timeout_invalid")
        self._clock = clock
        self._generation_store = generation_store
        self._process_commitment = process_start_identity_commitment
        self._instance_id = instance_id or new_id(IdKind.SERVICE_INSTANCE)
        self._singleton_lock_path = singleton_lock_path
        self._endpoint_recovery = endpoint_recovery
        self._endpoint_publisher = endpoint_publisher or _noop_instance
        self._endpoint_cleanup = endpoint_cleanup or _noop_instance
        self._cancel_ready_work = cancel_ready_work or _noop
        self._close_ready_composition = close_ready_composition or _noop
        self._terminate_on_deadline = terminate_on_deadline or _noop
        self._lock_drain_seconds = lock_drain_seconds
        self._stop_drain_seconds = stop_drain_seconds
        self._idle_stop_seconds = idle_stop_seconds
        self._instance: ServiceInstance | None = None
        self._vault_generation: int | None = None
        self._policy = IdleRelockPolicy()
        self._last_quiescent_activity: float | None = None
        self._last_process_activity: float | None = None
        self._connected_clients = 0
        self._admissions: dict[int, Admission] = {}
        self._owner_token = object()
        self._mutex = asyncio.Lock()
        self._condition = asyncio.Condition(self._mutex)
        self._drain_task: asyncio.Task[None] | None = None
        self._idle_stop = asyncio.Event()
        self._singleton_fd: int | None = None
        self._singleton_authority: _SingletonEndpointAuthority | None = None
        self._endpoint_published = False
        self._closed = False

    @property
    def instance(self) -> ServiceInstance:
        instance = self._instance
        if instance is None:
            raise LifecycleError("invalid_transition")
        return instance

    @property
    def state(self) -> ServiceState:
        return self.instance.state

    @property
    def current_vault_generation(self) -> int | None:
        return self._vault_generation

    def assert_singleton_held(self) -> None:
        """Assert that this generation still owns the process singleton.

        Startup maintenance uses this narrow, non-serializable fence immediately before and
        after touching a task bundle.  The lock descriptor remains the authority; exposing the
        assertion through the lifecycle keeps callers from reaching into its private descriptor
        state or mistaking the advisory lock-file stamp for ownership.
        """

        authority = self._singleton_authority
        if authority is None:
            raise LifecycleError("invalid_transition")
        authority.assert_held()

    @property
    def idle_relock_policy(self) -> IdleRelockPolicy:
        return self._policy

    @staticmethod
    def generation_store(path: Path, installation_id: str) -> _GenerationStorePort:
        """Construct the private fixed-path durable generation source for composition."""

        return _ServiceGenerationStore(path, installation_id)

    async def acquire_singleton(self) -> ServiceInstance:
        async with self._mutex:
            if self._instance is not None:
                return self._instance
            if self._closed:
                raise LifecycleError("invalid_transition")
            path = self._singleton_lock_path
            if path is not None:
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    os.close(descriptor)
                    raise LifecycleError("service_already_running") from exc
                self._singleton_fd = descriptor
                self._stamp_singleton_holder(descriptor)
                self._singleton_authority = _SingletonEndpointAuthority(
                    lambda: self._assert_singleton_descriptor_held(descriptor)
                )
            try:
                generation = self._generation_store.advance(self._instance_id)
            except Exception:
                self._release_singleton()
                raise
            self._instance = ServiceInstance(
                self._instance_id,
                generation,
                self._process_commitment,
                ServiceState.STARTING,
            )
            self._last_process_activity = self._sample_monotonic()
            return self._instance

    async def publish_endpoint(self) -> None:
        async with self._mutex:
            if self._instance is None or self._endpoint_published or self._closed:
                raise LifecycleError("invalid_transition")
            instance = self._instance
            recovery = self._endpoint_recovery
            if recovery is not None:
                authority = self._singleton_authority
                if authority is None:
                    raise LifecycleError("invalid_transition")
                authority.assert_held()
                await recovery(authority)
                authority.assert_held()
            await self._endpoint_publisher(instance)
            self._endpoint_published = True

    async def transition(
        self,
        target: ServiceState,
        *,
        vault_generation: int | None = None,
    ) -> ServiceInstance:
        if type(target) is not ServiceState:
            raise LifecycleError("invalid_transition")
        async with self._mutex:
            current = self.instance.state
            if target not in _ALLOWED_TRANSITIONS[current]:
                raise LifecycleError("invalid_transition")
            if target is ServiceState.READY:
                if type(vault_generation) is not int or vault_generation <= 0:
                    raise LifecycleError("vault_locked")
                self._vault_generation = vault_generation
                now = self._sample_monotonic()
                self._last_quiescent_activity = (
                    now if not self._admissions and not self._connected_clients else None
                )
            else:
                if vault_generation is not None:
                    raise LifecycleError("invalid_transition")
                if current is ServiceState.READY or target in {
                    ServiceState.DRAINING,
                    ServiceState.LOCKED,
                    ServiceState.FAILED,
                }:
                    self._vault_generation = None
                    self._last_quiescent_activity = None
            self._instance = replace(self.instance, state=target)
            return self._instance

    async def client_connected(self) -> None:
        """Hold process-idle shutdown while one authenticated local connection is active."""

        async with self._mutex:
            if self._closed or self.state in {ServiceState.DRAINING, ServiceState.FAILED}:
                raise LifecycleError("service_draining")
            self._connected_clients += 1
            self._last_process_activity = None
            self._last_quiescent_activity = None

    async def client_disconnected(self) -> None:
        async with self._mutex:
            if self._connected_clients <= 0:
                raise LifecycleError("invalid_transition")
            self._connected_clients -= 1
            if not self._connected_clients and not self._admissions:
                now = self._sample_monotonic()
                self._last_process_activity = now
                if self.state is ServiceState.READY:
                    self._last_quiescent_activity = now

    async def admit(
        self,
        method: str,
        *,
        secret_use_class: SecretUseClass = "none",
        provider_call: bool = False,
        writer_queued: bool = False,
        lease_held: bool = False,
        shielded_commit: bool = False,
    ) -> Admission:
        async with self._condition:
            if self.state is ServiceState.DRAINING:
                raise LifecycleError("service_draining")
            if self.state is not ServiceState.READY:
                raise LifecycleError("vault_locked")
            admission = Admission(
                method,
                secret_use_class,
                "shielded" if shielded_commit else "none",
                provider_call,
                writer_queued,
                lease_held,
                self._owner_token,
            )
            self._admissions[id(admission)] = admission
            self._last_quiescent_activity = None
            self._last_process_activity = None
            return admission

    async def release(self, admission: Admission) -> None:
        async with self._condition:
            if (
                not admission.belongs_to(self._owner_token)
                or self._admissions.pop(id(admission), None) is not admission
            ):
                raise LifecycleError("invalid_transition")
            admission.mark_released()
            if not self._admissions and not self._connected_clients:
                now = self._sample_monotonic()
                self._last_process_activity = now
                if self.state is ServiceState.READY:
                    self._last_quiescent_activity = now
            self._condition.notify_all()

    async def note_activity(self) -> None:
        async with self._mutex:
            if self.state is not ServiceState.READY:
                return
            if not self._admissions and not self._connected_clients:
                now = self._sample_monotonic()
                self._last_quiescent_activity = now
                self._last_process_activity = now

    async def request_lock(self, reason: str = "explicit") -> None:
        del reason  # state publication owns bounded reasons outside this internal coordinator
        task = await self._coalesced_drain(stop=False)
        await task

    async def request_stop(self, reason: str = "explicit") -> None:
        del reason
        task = await self._coalesced_drain(stop=True)
        await task

    async def on_session_event(self, event: SessionSecurityEvent) -> None:
        if type(event) is not SessionSecurityEvent:
            raise LifecycleError("session_monitor_unavailable")
        if event in {
            SessionSecurityEvent.USER_SESSION_LOCKED,
            SessionSecurityEvent.SYSTEM_SUSPEND,
            SessionSecurityEvent.MONITOR_LOST,
        }:
            if self.state is ServiceState.READY:
                await self.request_lock(event.value)
            return
        # Unlock/resume are deliberately state preserving.

    async def run_idle_monitor(self, *, poll_seconds: float = 1.0) -> None:
        if type(poll_seconds) is not float or not math.isfinite(poll_seconds) or poll_seconds <= 0:
            raise ValueError("idle_poll_invalid")
        while not self._idle_stop.is_set():
            await asyncio.sleep(poll_seconds)
            should_lock = False
            should_stop = False
            async with self._mutex:
                if self._admissions or self._connected_clients:
                    continue
                process_started = self._last_process_activity
                if process_started is not None:
                    should_stop = (
                        self._sample_monotonic() - process_started >= self._idle_stop_seconds
                    )
                if should_stop:
                    pass
                elif self.state is not ServiceState.READY:
                    continue
                else:
                    seconds = self._policy.seconds
                    started = self._last_quiescent_activity
                    if seconds is None or started is None:
                        continue
                    should_lock = self._sample_monotonic() - started >= seconds
            if should_stop:
                await self.request_stop("idle_shutdown")
                return
            if should_lock:
                await self.request_lock("idle_expired")

    async def change_idle_relock_policy(
        self,
        proposed: IdleRelockPolicy,
        proof: HumanAuthorizationProof,
    ) -> IdleRelockPolicy:
        if type(proposed) is not IdleRelockPolicy:
            raise LifecycleError("human_authorization_required")
        async with self._mutex:
            if self.state is not ServiceState.READY:
                raise LifecycleError("human_authorization_stale")
            vault_generation = self._vault_generation
            if vault_generation is None:
                raise LifecycleError("human_authorization_stale")
            target_digest = self.idle_relock_target_digest(self._policy, proposed)
            now = self._sample_monotonic()
            try:
                proof.consume(
                    "idle_relock_policy_change",
                    target_digest,
                    self.instance.generation,
                    vault_generation,
                    None,
                    now,
                )
            except SecretMemoryError as exc:
                raise LifecycleError("human_authorization_stale") from exc
            self._policy = proposed
            self._last_quiescent_activity = (
                now if not self._admissions and not self._connected_clients else None
            )
            return self._policy

    def idle_relock_target_digest(
        self,
        current: IdleRelockPolicy,
        proposed: IdleRelockPolicy,
    ) -> str:
        value: dict[str, JsonValue] = {
            "current": current.canonical_value(),
            "proposed": proposed.canonical_value(),
            "service_generation": self.instance.generation,
        }
        return _domain_digest(_IDLE_POLICY_DOMAIN, cast(JsonValue, value))

    async def close(self) -> None:
        if self._closed:
            return
        if self._instance is not None and self.state not in {
            ServiceState.LOCKED,
            ServiceState.DRAINING,
            ServiceState.FAILED,
        }:
            await self.request_stop("close")
        async with self._mutex:
            if self._closed:
                return
            if self._endpoint_published:
                await self._endpoint_cleanup(self.instance)
                self._endpoint_published = False
            self._closed = True
            self._idle_stop.set()
            self._release_singleton()

    async def _coalesced_drain(self, *, stop: bool) -> asyncio.Task[None]:
        async with self._mutex:
            existing = self._drain_task
            if existing is not None and not existing.done():
                return existing
            state = self.state
            if not stop and state is ServiceState.LOCKED:
                return asyncio.create_task(_noop())
            if stop and state in {ServiceState.LOCKED, ServiceState.FAILED}:
                self._instance = replace(self.instance, state=ServiceState.DRAINING)
            elif state is ServiceState.READY:
                self._vault_generation = None
                self._last_quiescent_activity = None
                self._instance = replace(self.instance, state=ServiceState.DRAINING)
            elif state is not ServiceState.DRAINING:
                raise LifecycleError("invalid_transition")
            task = asyncio.create_task(self._drain(stop=stop))
            self._drain_task = task
            return task

    async def _drain(self, *, stop: bool) -> None:
        await self._cancel_ready_work()
        timeout = self._stop_drain_seconds if stop else self._lock_drain_seconds
        try:
            async with asyncio.timeout(timeout):
                async with self._condition:
                    await self._condition.wait_for(lambda: not self._admissions)
        except TimeoutError as exc:
            await self._terminate_on_deadline()
            async with self._mutex:
                self._instance = replace(self.instance, state=ServiceState.FAILED)
                self._vault_generation = None
            raise LifecycleError("service_draining") from exc
        await self._close_ready_composition()
        async with self._mutex:
            self._vault_generation = None
            self._last_quiescent_activity = None
            self._instance = replace(
                self.instance,
                state=ServiceState.DRAINING if stop else ServiceState.LOCKED,
            )
        if stop:
            async with self._mutex:
                if self._endpoint_published:
                    await self._endpoint_cleanup(self.instance)
                    self._endpoint_published = False

    def _sample_monotonic(self) -> float:
        value = self._clock.monotonic_seconds()
        if type(value) is not float or not math.isfinite(value) or value < 0.0:
            raise LifecycleError("invalid_transition")
        return value

    def _assert_singleton_descriptor_held(self, descriptor: int) -> None:
        if (
            self._closed
            or self._instance is None
            or self._singleton_fd != descriptor
            or self._singleton_authority is None
        ):
            raise LifecycleError("invalid_transition")
        try:
            os.fstat(descriptor)
        except OSError as exc:
            raise LifecycleError("invalid_transition") from exc

    def _stamp_singleton_holder(self, descriptor: int) -> None:
        """Record advisory holder identity in the lock file the flock already owns.

        The flock stays the sole mutual-exclusion authority; this content exists only so a
        refused start can name the process it lost to instead of reporting a generic failure.
        Every write is best effort and every reader degrades to "no pid".
        """

        body: dict[str, JsonValue] = {"instance_id": self._instance_id, "pid": os.getpid()}
        body.update(self._holder_identity)
        # Version and schema-manifest identity let a client whose hello this service will
        # reject (an upgraded installation talking to a stale process) name what it found and
        # decide whether the holder is a supersede candidate, without a compatible channel.
        # The version is always written, outside the best-effort digest lookup: a stamp with
        # neither identity key reads as a pre-0.2 installation that may be replaced, and a
        # current service must never write one, even when its manifest cannot be read (#1040).
        body["service_version"] = __version__
        with contextlib.suppress(Exception):
            from yoetz.protocol.schemas import schema_manifest_digest

            body["schema_manifest_digest"] = schema_manifest_digest()
        with contextlib.suppress(OSError):
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.write(descriptor, canonical_encode(cast(JsonValue, body)) + b"\n")

    def _release_singleton(self) -> None:
        descriptor = self._singleton_fd
        self._singleton_authority = None
        self._singleton_fd = None
        if descriptor is not None:
            try:
                with contextlib.suppress(OSError):
                    os.ftruncate(descriptor, 0)
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


@dataclass(frozen=True, slots=True)
class SingletonHolder:
    """Advisory identity of the live process stamped in the singleton lock file.

    ``schema_manifest_digest`` and ``service_version`` are None when the stamp lacks them or holds
    a value that does not validate; they are never inferred. ``identity_fields_absent`` tells the
    first case apart: neither key is in the stamp at all, which is how installations that predate
    the identity fields (Yoetz 0.1.x stamped only ``pid`` and ``instance_id``) wrote it. A current
    writer always writes ``service_version`` (``_stamp_singleton_holder``), so it never produces
    that shape. A key that is present but unreadable leaves it False, so missing information is
    never mistaken for an older installation. ``instance_lifecycle`` and ``source_ref`` name the holder's instance
    identity (issue #604) and are absent for the everyday (permanent) install and for holders
    stamped before that contract.
    """

    pid: int
    instance_id: str | None
    schema_manifest_digest: str | None
    service_version: str | None
    instance_lifecycle: str | None = None
    source_ref: str | None = None
    identity_fields_absent: bool = False


def probe_singleton_holder(path: Path) -> int | None:
    """Return the live pid stamped in a singleton lock file, or ``None`` when unknown."""

    holder = probe_singleton_holder_identity(path)
    return None if holder is None else holder.pid


def probe_singleton_holder_identity(path: Path) -> SingletonHolder | None:
    """Return the live holder identity stamped in a singleton lock file, or ``None``.

    Reading the file never disturbs the lock: taking even a shared flock would conflict with a
    daemon that is still acquiring its exclusive one, so a diagnostic could make a legitimate
    start fail. An absent, oversized, malformed, or dead-pid stamp is simply no answer, and so is
    one that is a symlink, owned by another uid, or readable past the owner.

    A pid can be reused after the stamped process exits, which ``kill(pid, 0)`` cannot tell apart.
    The stamp is never a fence -- the flock is -- and callers that use the stamp to make a
    startup decision must corroborate it with a lock probe.
    """

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid() or facts.st_mode & 0o077:
            return None
        data = os.read(descriptor, _MAX_SINGLETON_HOLDER_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    if not data or len(data) > _MAX_SINGLETON_HOLDER_BYTES or not data.endswith(b"\n"):
        return None
    try:
        parsed = strict_json_parse(data[:-1])
    except Exception:
        return None
    if type(parsed) is not dict:
        return None
    stamp = cast(dict[str, JsonValue], parsed)
    pid = stamp.get("pid")
    if type(pid) is not int or not 1 <= pid < 2**31:
        return None
    try:
        os.kill(pid, 0)
    except OSError:
        return None
    instance_id = stamp.get("instance_id")
    digest = stamp.get("schema_manifest_digest")
    version = stamp.get("service_version")
    if type(digest) is str:
        try:
            validate_sha256_digest(digest)
        except Exception:
            digest = None
    lifecycle = stamp.get("instance_lifecycle")
    source_ref = stamp.get("source_ref")
    return SingletonHolder(
        pid,
        instance_id if type(instance_id) is str and len(instance_id) <= 64 else None,
        digest if type(digest) is str else None,
        version if type(version) is str and 0 < len(version) <= 128 else None,
        lifecycle if type(lifecycle) is str and lifecycle in _HOLDER_LIFECYCLES else None,
        source_ref if type(source_ref) is str and _HOLDER_SOURCE_REF.match(source_ref) else None,
        identity_fields_absent=(
            "schema_manifest_digest" not in stamp and "service_version" not in stamp
        ),
    )


def probe_singleton_holder_lock(path: Path) -> bool | None:
    """Probe whether the owner-only singleton lock is held without changing its authority.

    ``True`` means another process currently holds the exclusive flock, ``False`` means the
    safely opened lock file was available, and ``None`` means the lock could not be inspected.
    The probe never treats the stamp contents or a pid as proof of liveness.
    """

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        facts = os.fstat(descriptor)
        if not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid() or facts.st_mode & 0o077:
            return None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        except OSError:
            return None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            return None
        return False
    finally:
        os.close(descriptor)


class _ServiceGenerationStore:
    """Owner-only canonical service generation metadata.

    The path is fixed by composition; this class never derives it from caller content.
    """

    def __init__(self, path: Path, installation_id: str) -> None:
        self._path = path
        self._installation_id = validate_id(IdKind.INSTALLATION, installation_id)

    def advance(self, instance_id: str) -> int:
        validate_id(IdKind.SERVICE_INSTANCE, instance_id)
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _verify_private_directory(self._path.parent)
        generation = 1
        if self._path.exists():
            value = self._read()
            generation = _required_generation(value["generation"]) + 1
        value: dict[str, JsonValue] = {
            "generation": str(generation),
            "installation_id": self._installation_id,
            "last_instance_id": instance_id,
            "schema_version": "1",
        }
        digest = _domain_digest("yoetz/service-generation/v1\x00", cast(JsonValue, value))
        value["record_digest"] = digest
        data = canonical_encode(value) + b"\n"
        temporary = self._path.with_name(f".{self._path.name}.{os.urandom(12).hex()}.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self._path)
        directory = os.open(self._path.parent, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return generation

    def _read(self) -> dict[str, JsonValue]:
        metadata = self._path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise LifecycleError("invalid_transition")
        data = self._path.read_bytes()
        if not data.endswith(b"\n") or data.endswith(b"\n\n"):
            raise LifecycleError("invalid_transition")
        parsed = strict_json_parse(data[:-1])
        if type(parsed) is not dict:
            raise LifecycleError("invalid_transition")
        value = cast(dict[str, JsonValue], parsed)
        if set(value) != {
            "generation",
            "installation_id",
            "last_instance_id",
            "record_digest",
            "schema_version",
        }:
            raise LifecycleError("invalid_transition")
        if value["installation_id"] != self._installation_id or value["schema_version"] != "1":
            raise LifecycleError("invalid_transition")
        validate_id(IdKind.SERVICE_INSTANCE, value["last_instance_id"])
        record_digest = value["record_digest"]
        if type(record_digest) is not str:
            raise LifecycleError("invalid_transition")
        body = dict(value)
        del body["record_digest"]
        expected = _domain_digest("yoetz/service-generation/v1\x00", cast(JsonValue, body))
        if not hmac_compare(record_digest, expected):
            raise LifecycleError("invalid_transition")
        return value


def _required_generation(value: JsonValue) -> int:
    if type(value) is not str or not value.isascii() or not value.isdecimal():
        raise LifecycleError("invalid_transition")
    if value != str(int(value)) or int(value) <= 0:
        raise LifecycleError("invalid_transition")
    return int(value)


def _verify_private_directory(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise LifecycleError("invalid_transition")


def hmac_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))


def _domain_digest(domain: str, value: JsonValue) -> str:
    return f"sha256:{hashlib.sha256(domain.encode('ascii') + canonical_encode(value)).hexdigest()}"


async def _noop() -> None:
    return None


async def _noop_instance(_instance: ServiceInstance) -> None:
    return None
