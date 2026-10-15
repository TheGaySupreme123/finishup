"""Vault-unlock coordination and the durable passphrase throttle."""

from __future__ import annotations

import hashlib
import math
import os
import secrets
import stat
from asyncio import CancelledError
from asyncio import Lock as AsyncLock
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Final, Literal, Protocol, cast

from finishup.adapters.keys.installation_recovery import InstallationRecoveryArtifact
from finishup.domain.values import (
    format_rfc3339_millis,
    parse_rfc3339_millis,
    validate_sha256_digest,
)
from finishup.ports.clock import ClockPort
from finishup.ports.control import ServiceState
from finishup.ports.secret_memory import (
    HumanAuthorizationProof,
    SecretHandle,
    SecretPurpose,
    UserPresenceAttestation,
    UserPresenceCapability,
    UserPresenceChallenge,
)
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, validate_id
from finishup.service.confidential_protocol import CEREMONY_EXPIRY_SECONDS

__all__ = [
    "UnlockChallenge",
    "UnlockCoordinator",
    "UnlockError",
    "UnlockResult",
    "UnlockThrottleRecord",
    "UnlockThrottleStore",
    "passphrase_delay_seconds",
]

_THROTTLE_DIGEST_DOMAIN: Final = b"yoetz/unlock-throttle/v1\0"
_MAX_CANONICAL_INTEGER: Final = 2**53 - 1
_MAX_FAILURES: Final = 63
_MAX_DELAY_SECONDS: Final = 300
_HEX_64: Final = frozenset("0123456789abcdef")

_UNLOCK_REASONS: Final = frozenset(
    {
        "attempt_active",
        "binding_expired",
        "cancelled",
        "challenge_mismatch",
        "closed",
        "confidential_endpoint_unavailable",
        "human_authority_unavailable",
        "initialization_ambiguous",
        "initialization_forbidden",
        "invalid_state",
        "keyring_locked",
        "keyring_unavailable",
        "record_binding_mismatch",
        "record_missing",
        "reauthentication_unavailable",
        "secret_purpose_mismatch",
        "stale_generation",
        "throttle_persistence_failed",
        "throttle_repair_required",
        "throttle_record_exists",
        "throttle_record_missing",
        "throttle_record_tampered",
        "throttle_record_unsafe",
        "unlock_rate_limited",
        "unlock_failed",
        "unlock_wrong",
        "vault_locked",
        "vault_uninitialized",
        "vault_tampered",
    }
)


class UnlockError(Exception):
    """A bounded coordinator failure that carries no secret-derived detail."""

    __slots__ = ("reason",)

    reason: str

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _UNLOCK_REASONS:
            raise TypeError("unlock_reason_invalid")
        self.reason = reason
        super().__init__(reason)


def passphrase_delay_seconds(consecutive_failures: int) -> int:
    """Return the exact bounded delay for a durable failure count."""

    if type(consecutive_failures) is not int or not 0 <= consecutive_failures <= _MAX_FAILURES:
        raise ValueError("consecutive_failures_invalid")
    if consecutive_failures <= 2:
        return 0
    return min(_MAX_DELAY_SECONDS, 30 * 2 ** (consecutive_failures - 3))


def _record_preimage(
    *,
    installation_id: str,
    record_generation: int,
    consecutive_failures: int,
    attempt_in_progress: bool,
    last_failure_utc: str | None,
    last_writer_instance_id: str,
) -> dict[str, JsonValue]:
    return {
        "schema_version": "1",
        "installation_id": installation_id,
        "vault_mode": "passphrase",
        "record_generation": record_generation,
        "consecutive_failures": consecutive_failures,
        "attempt_in_progress": attempt_in_progress,
        "last_failure_utc": last_failure_utc,
        "last_writer_instance_id": last_writer_instance_id,
    }


def _record_digest(preimage: dict[str, JsonValue]) -> str:
    return (
        f"sha256:{hashlib.sha256(_THROTTLE_DIGEST_DOMAIN + canonical_encode(preimage)).hexdigest()}"
    )


@dataclass(frozen=True, slots=True)
class UnlockThrottleRecord:
    """Exact nonsecret restart-safe passphrase-throttle record."""

    schema_version: Literal["1"]
    installation_id: str
    vault_mode: Literal["passphrase"]
    record_generation: int
    consecutive_failures: int
    attempt_in_progress: bool
    last_failure_utc: str | None
    last_writer_instance_id: str
    record_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != "1" or self.vault_mode != "passphrase":
            raise ValueError("throttle_record_version_invalid")
        validate_id(IdKind.INSTALLATION, self.installation_id)
        validate_id(IdKind.SERVICE_INSTANCE, self.last_writer_instance_id)
        if (
            type(self.record_generation) is not int
            or not 1 <= self.record_generation <= _MAX_CANONICAL_INTEGER
        ):
            raise ValueError("throttle_generation_invalid")
        if (
            type(self.consecutive_failures) is not int
            or not 0 <= self.consecutive_failures <= _MAX_FAILURES
        ):
            raise ValueError("consecutive_failures_invalid")
        if type(self.attempt_in_progress) is not bool:
            raise ValueError("attempt_in_progress_invalid")
        if self.last_failure_utc is not None:
            parse_rfc3339_millis(self.last_failure_utc)
        validate_sha256_digest(self.record_digest)
        if self.record_digest != _record_digest(self.preimage()):
            raise ValueError("throttle_record_digest_mismatch")

    @classmethod
    def create(
        cls,
        *,
        installation_id: str,
        record_generation: int,
        consecutive_failures: int,
        attempt_in_progress: bool,
        last_failure_utc: str | None,
        last_writer_instance_id: str,
    ) -> UnlockThrottleRecord:
        preimage = _record_preimage(
            installation_id=installation_id,
            record_generation=record_generation,
            consecutive_failures=consecutive_failures,
            attempt_in_progress=attempt_in_progress,
            last_failure_utc=last_failure_utc,
            last_writer_instance_id=last_writer_instance_id,
        )
        record = cls(
            schema_version="1",
            installation_id=installation_id,
            vault_mode="passphrase",
            record_generation=record_generation,
            consecutive_failures=consecutive_failures,
            attempt_in_progress=attempt_in_progress,
            last_failure_utc=last_failure_utc,
            last_writer_instance_id=last_writer_instance_id,
            record_digest=_record_digest(preimage),
        )
        return record

    @classmethod
    def decode(cls, encoded: bytes) -> UnlockThrottleRecord:
        if not encoded.endswith(b"\n") or encoded.endswith(b"\n\n"):
            raise ValueError("throttle_record_encoding_invalid")
        value = strict_json_parse(encoded[:-1])
        if type(value) is not dict:
            raise ValueError("throttle_record_shape_invalid")
        source = cast(dict[str, object], value)
        if set(source) != {
            "schema_version",
            "installation_id",
            "vault_mode",
            "record_generation",
            "consecutive_failures",
            "attempt_in_progress",
            "last_failure_utc",
            "last_writer_instance_id",
            "record_digest",
        }:
            raise ValueError("throttle_record_shape_invalid")
        if (
            source["schema_version"] != "1"
            or type(source["installation_id"]) is not str
            or source["vault_mode"] != "passphrase"
            or type(source["record_generation"]) is not int
            or type(source["consecutive_failures"]) is not int
            or type(source["attempt_in_progress"]) is not bool
            or (
                source["last_failure_utc"] is not None
                and type(source["last_failure_utc"]) is not str
            )
            or type(source["last_writer_instance_id"]) is not str
            or type(source["record_digest"]) is not str
        ):
            raise ValueError("throttle_record_shape_invalid")
        record = cls(
            schema_version="1",
            installation_id=source["installation_id"],
            vault_mode="passphrase",
            record_generation=source["record_generation"],
            consecutive_failures=source["consecutive_failures"],
            attempt_in_progress=source["attempt_in_progress"],
            last_failure_utc=source["last_failure_utc"],
            last_writer_instance_id=source["last_writer_instance_id"],
            record_digest=source["record_digest"],
        )
        if record.encode() != encoded:
            raise ValueError("throttle_record_encoding_invalid")
        return record

    def preimage(self) -> dict[str, JsonValue]:
        return _record_preimage(
            installation_id=self.installation_id,
            record_generation=self.record_generation,
            consecutive_failures=self.consecutive_failures,
            attempt_in_progress=self.attempt_in_progress,
            last_failure_utc=self.last_failure_utc,
            last_writer_instance_id=self.last_writer_instance_id,
        )

    def encode(self) -> bytes:
        body = self.preimage()
        body["record_digest"] = self.record_digest
        return canonical_encode(body) + b"\n"


class UnlockThrottleStore:
    """Sole crash-safe owner of the locked-state throttle record."""

    def __init__(
        self,
        path: Path,
        *,
        installation_id: str,
        writer_instance_id: str,
        clock: ClockPort,
    ) -> None:
        validate_id(IdKind.INSTALLATION, installation_id)
        validate_id(IdKind.SERVICE_INSTANCE, writer_instance_id)
        self._path = path
        self._installation_id = installation_id
        self._writer_instance_id = writer_instance_id
        self._clock = clock
        self._record: UnlockThrottleRecord | None = None
        self._deadline = 0.0
        self._repair_required = False
        self._last_monotonic: float | None = None
        self._lock = RLock()

    @property
    def record(self) -> UnlockThrottleRecord:
        with self._lock:
            if self._record is None:
                raise UnlockError("throttle_record_missing")
            return self._record

    @property
    def repair_required(self) -> bool:
        with self._lock:
            return self._repair_required

    def stage_initial_record(self) -> UnlockThrottleRecord:
        """Create generation one exactly once for passphrase initialization."""

        with self._lock:
            if self._path.exists():
                raise UnlockError("throttle_record_exists")
            record = UnlockThrottleRecord.create(
                installation_id=self._installation_id,
                record_generation=1,
                consecutive_failures=0,
                attempt_in_progress=False,
                last_failure_utc=None,
                last_writer_instance_id=self._writer_instance_id,
            )
            self._write(record, replace_existing=False)
            self._record = record
            self._deadline = 0.0
            self._repair_required = False
            return record

    def stage_or_adopt_initial_record(self) -> UnlockThrottleRecord:
        """Create or adopt only the exact provisional pre-publication record."""

        with self._lock:
            if not self._path.exists():
                return self.stage_initial_record()
            try:
                record = self._read()
            except UnlockError:
                raise
            except (OSError, TypeError, ValueError) as exc:
                raise UnlockError("throttle_record_tampered") from exc
            if (
                record.installation_id != self._installation_id
                or record.record_generation != 1
                or record.consecutive_failures != 0
                or record.attempt_in_progress
                or record.last_failure_utc is not None
            ):
                raise UnlockError("throttle_record_exists")
            self._record = record
            self._deadline = 0.0
            self._repair_required = False
            return record

    def open_for_restart(self) -> UnlockThrottleRecord:
        """Load, charge an interrupted attempt, and arm a fresh monotonic delay."""

        with self._lock:
            now_monotonic = self._sample_monotonic()
            now_utc = self._clock.now_utc()
            try:
                record = self._read()
                if record.installation_id != self._installation_id:
                    raise ValueError("throttle_installation_mismatch")
                wall_anomaly = self._wall_anomaly(record, now_utc)
                if record.attempt_in_progress:
                    record = self._advance(
                        record=record,
                        consecutive_failures=min(_MAX_FAILURES, record.consecutive_failures + 1),
                        attempt_in_progress=False,
                        last_failure_utc=format_rfc3339_millis(now_utc),
                    )
                    self._write(record, replace_existing=True)
                self._record = record
                delay = (
                    _MAX_DELAY_SECONDS
                    if wall_anomaly
                    else passphrase_delay_seconds(record.consecutive_failures)
                )
                self._deadline = now_monotonic + delay
                self._repair_required = wall_anomaly
                return record
            except UnlockError:
                self._deadline = now_monotonic + _MAX_DELAY_SECONDS
                self._repair_required = True
                raise
            except (OSError, ValueError, TypeError) as exc:
                self._deadline = now_monotonic + _MAX_DELAY_SECONDS
                self._repair_required = True
                raise UnlockError("throttle_record_tampered") from exc

    def remaining_delay(self) -> float:
        with self._lock:
            now = self._sample_monotonic()
            return max(0.0, self._deadline - now)

    def reserve_attempt(self) -> UnlockThrottleRecord:
        """Persist an in-progress reservation before any passphrase KDF work."""

        with self._lock:
            if self._repair_required:
                raise UnlockError("throttle_repair_required")
            current = self.record
            if current.attempt_in_progress:
                raise UnlockError("attempt_active")
            if self.remaining_delay() > 0.0:
                raise UnlockError("unlock_rate_limited")
            updated = self._advance(
                record=current,
                consecutive_failures=current.consecutive_failures,
                attempt_in_progress=True,
                last_failure_utc=current.last_failure_utc,
            )
            self._write(updated, replace_existing=True)
            self._record = updated
            return updated

    def charge_failure(self) -> UnlockThrottleRecord:
        """Charge a failed, cancelled, or ambiguous reserved verification."""

        with self._lock:
            current = self.record
            if not current.attempt_in_progress:
                raise UnlockError("attempt_active")
            now_monotonic = self._sample_monotonic()
            last_failure = format_rfc3339_millis(self._clock.now_utc())
            updated = self._advance(
                record=current,
                consecutive_failures=min(_MAX_FAILURES, current.consecutive_failures + 1),
                attempt_in_progress=False,
                last_failure_utc=last_failure,
            )
            self._write(updated, replace_existing=True)
            self._record = updated
            self._deadline = now_monotonic + passphrase_delay_seconds(updated.consecutive_failures)
            return updated

    def reset_success(self) -> UnlockThrottleRecord:
        """Persist success before ready state or authorization-proof publication."""

        with self._lock:
            current = self.record
            if not current.attempt_in_progress:
                raise UnlockError("attempt_active")
            updated = self._advance(
                record=current,
                consecutive_failures=0,
                attempt_in_progress=False,
                last_failure_utc=None,
            )
            self._write(updated, replace_existing=True)
            self._record = updated
            self._deadline = 0.0
            return updated

    def stage_recovery_record(self) -> UnlockThrottleRecord:
        """Install a clean passphrase throttle generation before a recovery marker switch.

        Recovery authenticates with its own provisioned secret, so it must not consume or bypass a
        pending vault-passphrase attempt.  The replacement record advances the durable generation
        when one exists and is safe to orphan: the pre-recovery marker can still use it after a
        crash because restart admission never binds to the frozen initial digest.
        """

        with self._lock:
            current: UnlockThrottleRecord | None
            try:
                current = self._read()
            except UnlockError as exc:
                if exc.reason != "throttle_record_missing":
                    raise
                current = None
            if current is not None and current.installation_id != self._installation_id:
                raise UnlockError("throttle_record_tampered")
            generation = 1 if current is None else current.record_generation + 1
            if generation > _MAX_CANONICAL_INTEGER:
                raise UnlockError("throttle_record_tampered")
            recovered = UnlockThrottleRecord.create(
                installation_id=self._installation_id,
                record_generation=generation,
                consecutive_failures=0,
                attempt_in_progress=False,
                last_failure_utc=None,
                last_writer_instance_id=self._writer_instance_id,
            )
            self._write(recovered, replace_existing=current is not None)
            self._record = recovered
            self._deadline = 0.0
            self._repair_required = False
            return recovered

    def prepare_recovery_record(self) -> UnlockThrottleRecord:
        """Compute, without persisting, the clean generation a successful recovery installs.

        The digest of this record is sealed into the recovered vault, so it has to exist before
        verification runs.  Writing it there too would zero the passphrase failure counters before
        anything was proven, which is how an attacker could clear an accumulated delay simply by
        starting a recovery they cannot finish.  Persist it only once recovery actually
        authenticated -- see `commit_recovery_record`.
        """

        with self._lock:
            current = self.record
            if current.record_generation >= _MAX_CANONICAL_INTEGER:
                raise UnlockError("throttle_record_tampered")
            return UnlockThrottleRecord.create(
                installation_id=self._installation_id,
                record_generation=current.record_generation + 1,
                consecutive_failures=0,
                attempt_in_progress=False,
                last_failure_utc=None,
                last_writer_instance_id=self._writer_instance_id,
            )

    def commit_recovery_record(self, record: UnlockThrottleRecord) -> UnlockThrottleRecord:
        """Install a prepared clean generation, only after recovery verified its own secret."""

        with self._lock:
            if (
                type(record) is not UnlockThrottleRecord
                or record.installation_id != self._installation_id
            ):
                raise UnlockError("throttle_record_tampered")
            self._write(record, replace_existing=True)
            self._record = record
            self._deadline = 0.0
            self._repair_required = False
            return record

    def _advance(
        self,
        *,
        record: UnlockThrottleRecord,
        consecutive_failures: int,
        attempt_in_progress: bool,
        last_failure_utc: str | None,
    ) -> UnlockThrottleRecord:
        if record.record_generation >= _MAX_CANONICAL_INTEGER:
            raise UnlockError("throttle_record_tampered")
        return UnlockThrottleRecord.create(
            installation_id=record.installation_id,
            record_generation=record.record_generation + 1,
            consecutive_failures=consecutive_failures,
            attempt_in_progress=attempt_in_progress,
            last_failure_utc=last_failure_utc,
            last_writer_instance_id=self._writer_instance_id,
        )

    def _sample_monotonic(self) -> float:
        sample = self._clock.monotonic_seconds()
        if type(sample) is not float or not math.isfinite(sample) or sample < 0.0:
            raise UnlockError("throttle_record_tampered")
        if self._last_monotonic is not None and sample < self._last_monotonic:
            raise UnlockError("throttle_record_tampered")
        self._last_monotonic = sample
        return sample

    @staticmethod
    def _wall_anomaly(record: UnlockThrottleRecord, now_utc: datetime) -> bool:
        try:
            now_text = format_rfc3339_millis(now_utc)
        except ValueError:
            return True
        if record.last_failure_utc is None:
            return False
        # Any persisted failure that appears later than the current wall clock is
        # conservatively treated as rollback/future evidence.
        return parse_rfc3339_millis(record.last_failure_utc) > parse_rfc3339_millis(now_text)

    def _read(self) -> UnlockThrottleRecord:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self._path, flags)
        except FileNotFoundError as exc:
            raise UnlockError("throttle_record_missing") from exc
        except OSError as exc:
            raise UnlockError("throttle_record_unsafe") from exc
        try:
            facts = os.fstat(descriptor)
            self._verify_facts(facts)
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                encoded = stream.read(16_385)
            if len(encoded) > 16_384:
                raise UnlockError("throttle_record_tampered")
            return UnlockThrottleRecord.decode(encoded)
        except UnlockError:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise UnlockError("throttle_record_tampered") from exc
        finally:
            os.close(descriptor)

    def _write(self, record: UnlockThrottleRecord, *, replace_existing: bool) -> None:
        parent = self._path.parent
        self._verify_directory(parent)
        encoded = record.encode()
        temp = parent / f".{self._path.name}.{secrets.token_hex(16)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = -1
        try:
            descriptor = os.open(temp, flags, 0o600)
            remaining = memoryview(encoded)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("throttle_write_incomplete")
                remaining = remaining[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            if not replace_existing and self._path.exists():
                raise UnlockError("throttle_record_exists")
            if replace_existing:
                os.replace(temp, self._path)
            else:
                try:
                    os.link(temp, self._path, follow_symlinks=False)
                except FileExistsError as exc:
                    raise UnlockError("throttle_record_exists") from exc
                temp.unlink()
            directory_descriptor = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
            self._verify_path()
        except UnlockError:
            raise
        except OSError as exc:
            raise UnlockError("throttle_persistence_failed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temp.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def _verify_path(self) -> None:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self._path, flags)
        try:
            self._verify_facts(os.fstat(descriptor))
        finally:
            os.close(descriptor)

    @staticmethod
    def _verify_directory(path: Path) -> None:
        facts = path.lstat()
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if (
            not stat.S_ISDIR(facts.st_mode)
            or facts.st_uid != expected_uid
            or stat.S_IMODE(facts.st_mode) & 0o077
        ):
            raise UnlockError("throttle_record_unsafe")

    @staticmethod
    def _verify_facts(facts: os.stat_result) -> None:
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != expected_uid
            or stat.S_IMODE(facts.st_mode) != 0o600
            or facts.st_nlink != 1
        ):
            raise UnlockError("throttle_record_unsafe")


@dataclass(frozen=True, slots=True)
class UnlockChallenge:
    """One-use structural binding for confidential secret ingress."""

    challenge: str
    purpose: str
    secret_purpose: SecretPurpose | None
    service_generation: int
    vault_generation: int
    policy_generation: int | None
    target_digest: str
    expires_at_monotonic: float

    def __post_init__(self) -> None:
        if (
            type(self.challenge) is not str
            or len(self.challenge) != 64
            or not set(self.challenge) <= _HEX_64
        ):
            raise ValueError("unlock_challenge_invalid")
        if type(self.purpose) is not str or not self.purpose:
            raise ValueError("unlock_purpose_invalid")
        if self.secret_purpose is not None and self.secret_purpose not in {
            SecretPurpose.VAULT_INITIALIZE,
            SecretPurpose.VAULT_UNLOCK,
            SecretPurpose.PROVIDER_REAUTHENTICATION,
            SecretPurpose.PRIVACY_REAUTHENTICATION,
            SecretPurpose.SECURITY_REAUTHENTICATION,
            SecretPurpose.INSTALLATION_RECOVERY,
        }:
            raise ValueError("unlock_purpose_invalid")
        if type(self.service_generation) is not int or self.service_generation <= 0:
            raise ValueError("service_generation_invalid")
        if type(self.vault_generation) is not int or self.vault_generation < 0:
            raise ValueError("vault_generation_invalid")
        if self.policy_generation is not None and (
            type(self.policy_generation) is not int or self.policy_generation <= 0
        ):
            raise ValueError("policy_generation_invalid")
        validate_sha256_digest(self.target_digest)
        if (
            type(self.expires_at_monotonic) is not float
            or not math.isfinite(self.expires_at_monotonic)
            or self.expires_at_monotonic < 0.0
        ):
            raise ValueError("unlock_expiry_invalid")


@dataclass(frozen=True, slots=True)
class UnlockResult:
    state: Literal["locked", "ready"]
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.state not in {"locked", "ready"}:
            raise ValueError("unlock_result_state_invalid")
        if self.reason is not None and self.reason not in _UNLOCK_REASONS:
            raise ValueError("unlock_result_reason_invalid")


class _LifecycleInstance(Protocol):
    @property
    def generation(self) -> int: ...


class _Lifecycle(Protocol):
    @property
    def instance(self) -> _LifecycleInstance: ...

    @property
    def state(self) -> ServiceState: ...

    async def transition(
        self, target: ServiceState, *, vault_generation: int | None = None
    ) -> object: ...


class _Vault(Protocol):
    @property
    def mode(self) -> object: ...

    @property
    def state(self) -> object: ...

    @property
    def generation(self) -> int: ...

    @property
    def ready(self) -> bool: ...

    async def retry_keyring(
        self, user_presence_capability: UserPresenceCapability | None
    ) -> object: ...

    async def initialize_passphrase(
        self, handle: SecretHandle, throttle_record_digest: str
    ) -> object: ...

    async def unlock(self, handle: SecretHandle) -> object: ...

    async def lock(self) -> object: ...

    async def mint_human_authorization(
        self,
        source: UserPresenceAttestation | SecretHandle,
        challenge: UserPresenceChallenge,
    ) -> HumanAuthorizationProof: ...


class _RecoveryVault(Protocol):
    async def recover_passphrase(
        self,
        artifact: InstallationRecoveryArtifact,
        recovery_secret: SecretHandle,
        rewrap_secret: SecretHandle,
        *,
        throttle_record_digest: str,
    ) -> object: ...


class UnlockCoordinator:
    """Serialize challenges and keep the throttle/proof ownership boundary explicit.

    Vault and lifecycle effects are supplied by the service composition.  This class
    deliberately owns only one live challenge and never constructs an authorization
    proof; completion callbacks must return the exact proof minted by the vault.
    """

    def __init__(
        self,
        *,
        clock: ClockPort,
        throttle: UnlockThrottleStore,
        vault: _Vault,
        lifecycle: _Lifecycle,
        activate_ready: Callable[[int, int], Awaitable[None]],
    ) -> None:
        if not callable(activate_ready):
            raise TypeError("ready_activation_invalid")
        self._clock = clock
        self._throttle = throttle
        self._vault = vault
        self._lifecycle = lifecycle
        self._activate_ready = activate_ready
        self._active: UnlockChallenge | None = None
        self._presence_challenge: UserPresenceChallenge | None = None
        self._closed = False
        self._mutex = AsyncLock()

    async def retry_keyring(self, capability: UserPresenceCapability | None) -> UnlockResult:
        async with self._mutex:
            self._require_open_idle()
            if self._lifecycle.state is not ServiceState.LOCKED:
                raise UnlockError("invalid_state")
            await self._lifecycle.transition(ServiceState.UNLOCKING)
            try:
                await self._vault.retry_keyring(capability)
                if self._vault.ready:
                    return await self._activate_fresh_ready()
                await self._lifecycle.transition(ServiceState.LOCKED)
                return UnlockResult("locked", self._vault_reason())
            except Exception as exc:
                await self._lifecycle.transition(ServiceState.LOCKED)
                return UnlockResult("locked", self._bounded_effect_reason(exc))

    async def begin_passphrase_initialization(self, *, target_digest: str) -> UnlockChallenge:
        async with self._mutex:
            validate_sha256_digest(target_digest)
            self._require_open_idle()
            if (
                self._lifecycle.state is not ServiceState.LOCKED
                or self._vault_mode() != "uninitialized"
            ):
                raise UnlockError("invalid_state")
            await self._lifecycle.transition(ServiceState.UNLOCKING)
            return self._new_challenge(
                purpose="vault_initialize",
                secret_purpose=SecretPurpose.VAULT_INITIALIZE,
                target_digest=target_digest,
                policy_generation=None,
            )

    async def complete_passphrase_initialization(
        self, challenge: UnlockChallenge, secret: SecretHandle
    ) -> UnlockResult:
        async with self._mutex:
            self._require_active(challenge)
            if secret.purpose is not SecretPurpose.VAULT_INITIALIZE:
                self._active = None
                await self._lifecycle.transition(ServiceState.LOCKED)
                raise UnlockError("secret_purpose_mismatch")
            try:
                record = self._throttle.stage_or_adopt_initial_record()
                await self._vault.initialize_passphrase(secret, record.record_digest)
                self._active = None
                if self._vault.ready:
                    return await self._activate_fresh_ready()
                await self._lifecycle.transition(ServiceState.LOCKED)
                return UnlockResult("locked", self._vault_reason())
            except Exception as exc:
                self._active = None
                await self._lifecycle.transition(ServiceState.LOCKED)
                return UnlockResult("locked", self._bounded_effect_reason(exc))

    async def begin_passphrase_unlock(self, *, target_digest: str) -> UnlockChallenge:
        async with self._mutex:
            validate_sha256_digest(target_digest)
            self._require_open_idle()
            if (
                self._lifecycle.state is not ServiceState.LOCKED
                or self._vault_mode() != "passphrase"
            ):
                raise UnlockError("invalid_state")
            if self._throttle.remaining_delay() > 0.0:
                raise UnlockError("unlock_rate_limited")
            await self._lifecycle.transition(ServiceState.UNLOCKING)
            return self._new_challenge(
                purpose="vault_unlock",
                secret_purpose=SecretPurpose.VAULT_UNLOCK,
                target_digest=target_digest,
                policy_generation=None,
            )

    async def complete_passphrase_unlock(
        self, challenge: UnlockChallenge, secret: SecretHandle
    ) -> UnlockResult:
        async with self._mutex:
            self._require_active(challenge)
            if secret.purpose is not SecretPurpose.VAULT_UNLOCK:
                self._active = None
                await self._lifecycle.transition(ServiceState.LOCKED)
                raise UnlockError("secret_purpose_mismatch")
            try:
                self._throttle.reserve_attempt()
                await self._vault.unlock(secret)
                if not self._vault.ready:
                    raise UnlockError(self._vault_reason())
                self._throttle.reset_success()
                self._active = None
                return await self._activate_fresh_ready()
            except Exception as exc:
                if self._attempt_reserved():
                    self._throttle.charge_failure()
                self._active = None
                await self._lifecycle.transition(ServiceState.LOCKED)
                return UnlockResult("locked", self._bounded_effect_reason(exc))

    async def begin_reauthentication(
        self,
        *,
        purpose: str,
        target_digest: str,
        secret_purpose: SecretPurpose,
        policy_generation: int | None = None,
    ) -> UnlockChallenge:
        async with self._mutex:
            validate_sha256_digest(target_digest)
            self._require_open_idle()
            if self._lifecycle.state is not ServiceState.READY or not self._vault.ready:
                raise UnlockError("invalid_state")
            allowed = {
                "provider_credential_set": SecretPurpose.PROVIDER_REAUTHENTICATION,
                "provider_credential_rotate": SecretPurpose.PROVIDER_REAUTHENTICATION,
                "privacy_policy_widen": SecretPurpose.PRIVACY_REAUTHENTICATION,
                "owner_receipt_view": SecretPurpose.PRIVACY_REAUTHENTICATION,
                "idle_relock_policy_change": SecretPurpose.SECURITY_REAUTHENTICATION,
                "installation_recovery_change": SecretPurpose.SECURITY_REAUTHENTICATION,
                "vault_passphrase_rotate": SecretPurpose.SECURITY_REAUTHENTICATION,
            }
            if allowed.get(purpose) is not secret_purpose:
                raise UnlockError("secret_purpose_mismatch")
            return self._new_challenge(
                purpose=purpose,
                secret_purpose=secret_purpose,
                target_digest=target_digest,
                policy_generation=policy_generation,
            )

    async def begin_installation_recovery(self, *, target_digest: str) -> UnlockChallenge:
        """Bind one recovery attempt without accepting an artifact or secret on control."""

        async with self._mutex:
            validate_sha256_digest(target_digest)
            self._require_open_idle()
            if (
                self._lifecycle.state is not ServiceState.LOCKED
                or self._vault_mode() == "uninitialized"
            ):
                raise UnlockError("invalid_state")
            # Recovery verifies a secret exactly like passphrase unlock does, so it is subject to
            # the same accumulated delay. Without this it is an unthrottled guessing oracle.
            if self._throttle.remaining_delay() > 0.0:
                raise UnlockError("unlock_rate_limited")
            await self._lifecycle.transition(ServiceState.UNLOCKING)
            return self._new_challenge(
                purpose="installation_recovery",
                secret_purpose=SecretPurpose.INSTALLATION_RECOVERY,
                target_digest=target_digest,
                policy_generation=None,
            )

    async def complete_installation_recovery(
        self,
        challenge: UnlockChallenge,
        artifact: InstallationRecoveryArtifact,
        recovery_secret: SecretHandle,
        rewrap_secret: SecretHandle,
    ) -> UnlockResult:
        """Verify a provisioned root and activate one newly wrapped passphrase envelope."""

        async with self._mutex:
            self._require_active(challenge)
            if (
                recovery_secret.purpose is not SecretPurpose.INSTALLATION_RECOVERY
                or rewrap_secret.purpose is not SecretPurpose.VAULT_REWRAP
            ):
                self._active = None
                await self._lifecycle.transition(ServiceState.LOCKED)
                raise UnlockError("secret_purpose_mismatch")
            try:
                # Reserve first, so the attempt is charged against the live counters, and only
                # then compute the clean generation this recovery would install. Nothing about
                # the existing delay is cleared until `recover_passphrase` has actually verified
                # the recovery secret.
                self._throttle.reserve_attempt()
                record = self._throttle.prepare_recovery_record()
                await cast(_RecoveryVault, self._vault).recover_passphrase(
                    artifact,
                    recovery_secret,
                    rewrap_secret,
                    throttle_record_digest=record.record_digest,
                )
                if not self._vault.ready:
                    raise UnlockError(self._vault_reason())
                self._throttle.commit_recovery_record(record)
                self._active = None
                return await self._activate_fresh_ready()
            except Exception as exc:
                if self._attempt_reserved():
                    self._throttle.charge_failure()
                self._active = None
                await self._lifecycle.transition(ServiceState.LOCKED)
                return UnlockResult("locked", self._bounded_effect_reason(exc))

    async def stage_root_rotation_throttle(self) -> str:
        """Prepare a clean throttle generation for an authorized ready-vault rotation."""

        async with self._mutex:
            self._require_open_idle()
            if self._lifecycle.state is not ServiceState.READY or not self._vault.ready:
                raise UnlockError("invalid_state")
            return self._throttle.stage_recovery_record().record_digest

    async def complete_reauthentication(
        self,
        challenge: UnlockChallenge,
        source: UserPresenceAttestation | SecretHandle,
    ) -> HumanAuthorizationProof:
        async with self._mutex:
            self._require_active(challenge)
            is_secret = hasattr(source, "purpose")
            if is_secret:
                secret = cast(SecretHandle, source)
                if secret.purpose is not challenge.secret_purpose:
                    self._active = None
                    raise UnlockError("secret_purpose_mismatch")
                if self._vault_mode() != "passphrase":
                    self._active = None
                    raise UnlockError("reauthentication_unavailable")
                self._throttle.reserve_attempt()
            user_challenge = self.user_presence_challenge(challenge)
            try:
                proof = await self._vault.mint_human_authorization(source, user_challenge)
                if is_secret:
                    self._throttle.reset_success()
                self._active = None
                self._presence_challenge = None
                return proof
            except Exception as exc:
                if is_secret and self._attempt_reserved():
                    self._throttle.charge_failure()
                self._active = None
                self._presence_challenge = None
                raise UnlockError(self._bounded_effect_reason(exc)) from exc

    def user_presence_challenge(self, challenge: UnlockChallenge) -> UserPresenceChallenge:
        """Expose the exact bound OS-presence challenge, never generic authority."""

        self._require_active(challenge)
        if self._presence_challenge is None:
            self._presence_challenge = UserPresenceChallenge(
                purpose=challenge.purpose,
                ceremony_digest=f"sha256:{challenge.challenge}",
                target_digest=challenge.target_digest,
                display_summary_digest=challenge.target_digest,
                service_generation=challenge.service_generation,
                vault_generation=challenge.vault_generation,
                policy_generation=challenge.policy_generation,
                expires_at_monotonic=challenge.expires_at_monotonic,
            )
        return self._presence_challenge

    async def cancel(self) -> None:
        async with self._mutex:
            active = self._active
            if self._active is not None and self._attempt_reserved():
                self._throttle.charge_failure()
            self._active = None
            self._presence_challenge = None
            if active is not None and active.purpose in {
                "installation_recovery",
                "vault_initialize",
                "vault_unlock",
            }:
                await self._release_unlocking()

    async def close(self) -> None:
        async with self._mutex:
            active = self._active
            if self._active is not None and self._attempt_reserved():
                self._throttle.charge_failure()
            self._active = None
            self._presence_challenge = None
            if active is not None and active.purpose in {
                "installation_recovery",
                "vault_initialize",
                "vault_unlock",
            }:
                await self._release_unlocking()
            self._closed = True

    def _new_challenge(
        self,
        *,
        purpose: str,
        secret_purpose: SecretPurpose,
        target_digest: str,
        policy_generation: int | None,
    ) -> UnlockChallenge:
        now = self._clock.monotonic_seconds()
        if type(now) is not float or not math.isfinite(now) or now < 0.0:
            raise UnlockError("stale_generation")
        challenge = UnlockChallenge(
            challenge=secrets.token_hex(32),
            purpose=purpose,
            secret_purpose=secret_purpose,
            service_generation=self._lifecycle.instance.generation,
            vault_generation=self._vault.generation,
            policy_generation=policy_generation,
            target_digest=target_digest,
            expires_at_monotonic=now + CEREMONY_EXPIRY_SECONDS,
        )
        self._active = challenge
        self._presence_challenge = None
        return challenge

    async def _activate_fresh_ready(self) -> UnlockResult:
        """Delegate one generation-bound ready build/install before publishing success."""

        service_generation = self._lifecycle.instance.generation
        vault_generation = self._vault.generation
        if self._lifecycle_state() is not ServiceState.UNLOCKING or not self._vault.ready:
            await self._rollback_ready_failure()
            return UnlockResult("locked", "unlock_failed")
        try:
            await self._activate_ready(service_generation, vault_generation)
        except CancelledError:
            await self._rollback_ready_failure()
            raise
        except Exception:
            await self._rollback_ready_failure()
            return UnlockResult("locked", "unlock_failed")
        if (
            self._lifecycle_state() is not ServiceState.READY
            or self._lifecycle.instance.generation != service_generation
            or self._vault.generation != vault_generation
            or not self._vault.ready
        ):
            await self._rollback_ready_failure()
            return UnlockResult("locked", "unlock_failed")
        return UnlockResult("ready")

    async def _rollback_ready_failure(self) -> None:
        """Best-effort reverse-order rollback after a failed outer ready gate."""

        try:
            await self._vault.lock()
        finally:
            if self._lifecycle_state() is ServiceState.UNLOCKING:
                await self._lifecycle.transition(ServiceState.LOCKED)

    def _lifecycle_state(self) -> ServiceState:
        return self._lifecycle.state

    async def _release_unlocking(self) -> None:
        """Return UNLOCKING to LOCKED; never reverse an in-flight drain or failure."""

        if self._lifecycle_state() is ServiceState.UNLOCKING:
            await self._lifecycle.transition(ServiceState.LOCKED)

    def _require_open_idle(self) -> None:
        if self._closed:
            raise UnlockError("closed")
        if self._active is not None:
            raise UnlockError("attempt_active")

    def _require_active(
        self, challenge: UnlockChallenge, *, check_expiry: bool = True
    ) -> UnlockChallenge:
        if self._closed:
            raise UnlockError("closed")
        if self._active is not challenge:
            raise UnlockError("challenge_mismatch")
        if check_expiry:
            now = self._clock.monotonic_seconds()
            if type(now) is not float or not math.isfinite(now) or now < 0.0:
                raise UnlockError("binding_expired")
            if now >= challenge.expires_at_monotonic:
                if self._throttle.record.attempt_in_progress:
                    self._throttle.charge_failure()
                raise UnlockError("binding_expired")
        return challenge

    def _attempt_reserved(self) -> bool:
        try:
            return self._throttle.record.attempt_in_progress
        except UnlockError:
            return False

    def _vault_mode(self) -> str:
        value = self._vault.mode
        return cast(str, getattr(value, "value", value))

    def _vault_reason(self) -> str:
        status = getattr(self._vault, "status", None)
        reason = getattr(status, "reason", None)
        return reason if reason in _UNLOCK_REASONS else "vault_tampered"

    @staticmethod
    def _bounded_effect_reason(exc: Exception) -> str:
        reason = getattr(exc, "reason", None)
        if reason in _UNLOCK_REASONS:
            return cast(str, reason)
        return "vault_tampered"
