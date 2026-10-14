"""Verified OS-keyring source for the installation vault-root key."""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import hmac
import os
import subprocess
import sys
from collections.abc import Callable, Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import Final, Protocol, cast

import keyring

from finishup.adapters.keys.vault_passphrase import VaultPassphraseError, validate_passphrase_view
from finishup.config.paths import PathSafetyError, ensure_owner_only_dir
from finishup.domain.values import validate_sha256_digest
from finishup.ports.secret_memory import (
    SecretConsumer,
    SecretHandle,
    SecretMemoryPort,
    SecretPurpose,
    UserPresenceCapability,
)
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "AutoUnlockPassphraseStore",
    "FirstInstallKeyringAuthority",
    "KeyringBackendReport",
    "KeyringInitializationBinding",
    "OSKeyringError",
    "OSKeyringProbe",
    "OSKeyringState",
    "OSVaultRootKeySource",
    "describe_vault_keyring_backend",
]

_SERVICE_NAME: Final = "yoetz.vault-root.v1"
_AUTO_UNLOCK_SERVICE_NAME: Final = "yoetz.auto-unlock.v1"
_AUTO_UNLOCK_BACKENDS: Final = frozenset(
    {
        "keyring.backends.SecretService.Keyring",
        "keyring.backends.Windows.WinVaultKeyring",
        "keyring.backends.kwallet.DBusKeyring",
        "keyring.backends.libsecret.Keyring",
        "keyring.backends.macOS.Keyring",
    }
)
_APPROVED_BACKENDS: Final = frozenset(
    {"keyring.backends.macOS.Keyring", "keyring.backends.SecretService.Keyring"}
)
_ERRORS: Final = frozenset(
    {
        "locked",
        "ambiguous_write",
        "missing",
        "readback_failed",
        "unsupported",
        "unverified",
        "human_authority_unavailable",
        "authority_mismatch",
        "entry_exists",
        "staged_entry_exists",
        "initialization_in_progress",
        "entry_invalid",
        "correlation_mismatch",
        "migration_not_proven",
        "bundle_parent_missing",
        "bundle_permission_denied",
        "bundle_unsafe",
        "guard_unavailable",
    }
)
_GUARD_UNSAFE_ERRNOS: Final = frozenset({errno.ELOOP, errno.EMLINK, errno.ENOTDIR})
_GUARD_PERMISSION_ERRNOS: Final = frozenset({errno.EACCES, errno.EPERM, errno.EROFS})


def _guard_os_reason(exc: OSError) -> str:
    """Map one guard filesystem failure to its distinct bounded reason (issue #565).

    ``unsupported`` is reserved for a platform that genuinely lacks the mechanism; a missing
    parent, a permission failure, and a symlink rejection are separate, actionable outcomes.
    """

    if exc.errno == errno.ENOENT:
        return "bundle_parent_missing"
    if exc.errno in _GUARD_UNSAFE_ERRNOS:
        return "bundle_unsafe"
    if exc.errno in _GUARD_PERMISSION_ERRNOS:
        return "bundle_permission_denied"
    return "guard_unavailable"


# Fixed, platform-keyed statements of what the vault-root store needs (issue #721). The text
# names the mechanism, never a path, a username, or anything read from the backend.
_KEYRING_REQUIREMENTS: Final[Mapping[str, str]] = {
    "Darwin": "macOS Keychain",
    "Linux": (
        "a running Freedesktop Secret Service (GNOME Keyring, or KWallet through its Secret "
        "Service bridge) on the session D-Bus; headless Linux and WSL 2 normally have none, so "
        "the vault passphrase is the supported route there"
    ),
}
_KEYRING_REQUIREMENT_DEFAULT: Final = "macOS Keychain or a Freedesktop Secret Service"


def _backend_id_of(backend: object) -> str:
    return f"{type(backend).__module__}.{type(backend).__qualname__}"


@dataclass(frozen=True, slots=True)
class KeyringBackendReport:
    """Why the system credential store is, or is not, usable for the vault root.

    ``approved`` mirrors the vault-root allowlist exactly; auto-unlock accepts a wider set, but
    an installation whose root key cannot live in an approved backend is a passphrase install.
    """

    backend_id: str
    approved: bool
    reason: str
    requirement: str

    def as_json(self) -> dict[str, JsonValue]:
        return {
            "approved": self.approved,
            "backend_id": self.backend_id,
            "reason": self.reason,
            "requirement": self.requirement,
        }


def _secret_service_available() -> bool:
    """Probe only backend availability, without reading keys or unlocking a collection.

    Keyring's priority probe checks the session bus and service name. Isolate it so an
    unresponsive D-Bus cannot hold setup indefinitely; discard all backend output.
    Isolated Python excludes workspace and PYTHONPATH modules from this trusted probe.
    """

    try:
        result = subprocess.run(  # noqa: S603 - fixed interpreter and probe, no shell
            [
                sys.executable,
                "-I",
                "-c",
                "from keyring.backends.SecretService import Keyring; "
                "raise SystemExit(0 if Keyring.priority > 0 else 1)",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except OSError, subprocess.SubprocessError:
        return False
    return result.returncode == 0


def describe_vault_keyring_backend(
    *, backend: object | None = None, system: str | None = None
) -> KeyringBackendReport:
    """Report the loaded keyring backend against the vault-root allowlist, with the reason."""

    import platform

    requirement = _KEYRING_REQUIREMENTS.get(
        platform.system() if system is None else system, _KEYRING_REQUIREMENT_DEFAULT
    )
    if backend is None:
        try:
            backend = keyring.get_keyring()
        except Exception:
            return KeyringBackendReport("", False, "keyring_unavailable", requirement)
    backend_id = _backend_id_of(backend)
    if backend_id == "keyring.backends.fail.Keyring":
        return KeyringBackendReport(backend_id, False, "keyring_unavailable", requirement)
    if backend_id not in _APPROVED_BACKENDS:
        return KeyringBackendReport(backend_id, False, "backend_not_approved", requirement)
    if backend_id == "keyring.backends.SecretService.Keyring" and not _secret_service_available():
        return KeyringBackendReport(backend_id, False, "keyring_unavailable", requirement)
    return KeyringBackendReport(backend_id, True, "approved", requirement)


class OSKeyringState(str, Enum):  # noqa: UP042
    AVAILABLE = "available"
    LOCKED = "locked"
    MISSING = "missing"
    UNSUPPORTED = "unsupported"
    UNVERIFIED = "unverified"


class OSKeyringError(Exception):
    __slots__ = ("reason",)
    reason: str

    def __init__(self, reason: str) -> None:
        if type(reason) is not str or reason not in _ERRORS:
            raise TypeError("os_keyring_reason_invalid")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class OSKeyringProbe:
    installation_id: str
    state: OSKeyringState
    backend_id: str
    create_if_absent: bool
    round_trip_load: bool
    probe_digest: str

    def __post_init__(self) -> None:
        validate_id(IdKind.INSTALLATION, self.installation_id)
        if type(self.state) is not OSKeyringState or type(self.backend_id) is not str:
            raise ValueError("keyring_probe_invalid")
        if type(self.create_if_absent) is not bool or type(self.round_trip_load) is not bool:
            raise ValueError("keyring_probe_invalid")
        validate_sha256_digest(self.probe_digest)


@dataclass(frozen=True, slots=True)
class KeyringInitializationBinding:
    version: int
    installation_id: str
    correlation_commitment: str
    ivk_handle: SecretHandle = field(repr=False)
    correlation_handle: SecretHandle = field(repr=False)

    def __post_init__(self) -> None:
        if self.version != 1:
            raise ValueError("keyring_binding_version_invalid")
        validate_id(IdKind.INSTALLATION, self.installation_id)
        validate_sha256_digest(self.correlation_commitment)
        if self.ivk_handle.purpose is not SecretPurpose.VAULT_ROOT_KEY:
            raise ValueError("keyring_ivk_purpose_invalid")
        if self.correlation_handle.purpose is not SecretPurpose.VAULT_ROOT_KEY:
            raise ValueError("keyring_correlation_purpose_invalid")


class _AtomicBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...
    def set_password_if_absent(self, service: str, username: str, password: str) -> bool: ...
    def delete_password(self, service: str, username: str) -> None: ...


@dataclass(slots=True)
class FirstInstallKeyringAuthority:
    service_generation: int
    pristine_state_digest: str
    probe_digest: str
    candidate_artifact_digest: str
    release_cell: str
    presence_evidence_digest: str
    _token: object = field(repr=False)
    _used: bool = field(default=False, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if self._token is not _AUTHORITY_TOKEN:
            raise TypeError("first_install_authority_opaque")
        if type(self.service_generation) is not int or self.service_generation <= 0:
            raise ValueError("service_generation_invalid")
        validate_sha256_digest(self.pristine_state_digest)
        validate_sha256_digest(self.probe_digest)
        validate_sha256_digest(self.candidate_artifact_digest)
        validate_sha256_digest(self.presence_evidence_digest)
        if type(self.release_cell) is not str or not self.release_cell:
            raise ValueError("release_cell_invalid")

    def _consume(self) -> None:
        with self._lock:
            if self._used:
                raise OSKeyringError("authority_mismatch")
            self._used = True

    def __copy__(self) -> FirstInstallKeyringAuthority:
        raise TypeError("first_install_authority_not_copyable")

    def __deepcopy__(self, memo: Mapping[int, object]) -> FirstInstallKeyringAuthority:
        del memo
        raise TypeError("first_install_authority_not_copyable")

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("first_install_authority_not_serializable")


_AUTHORITY_TOKEN: Final = object()


def _overwrite(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


class AutoUnlockPassphraseStore:
    """Platform-credential-store persistence for one FinishUP vault passphrase.

    The keyring username is a digest of the absolute service bundle path, so independent FinishUP
    data roots never share an auto-unlock secret and the filesystem path is not disclosed to the
    credential-store label. Fresh setup generates the value into a staged-initialization slot and
    promotes it only after the vault ceremony proves success; trusted-TTY repair may store an
    existing passphrase only after the caller proves it unlocks the current vault envelope.
    """

    __slots__ = (
        "_backend",
        "_backend_id",
        "_guard_path",
        "_staged_init_username",
        "_staged_username",
        "_username",
    )

    def __init__(self, bundle_path: object, *, backend: object | None = None) -> None:
        if not isinstance(bundle_path, Path) or not bundle_path.is_absolute():
            raise ValueError("auto_unlock_scope_invalid")
        self._backend = backend if backend is not None else keyring.get_keyring()
        self._backend_id = f"{type(self._backend).__module__}.{type(self._backend).__qualname__}"
        encoded = os.fsencode(os.path.abspath(bundle_path))
        self._username = "bundle-" + hashlib.sha256(encoded).hexdigest()
        self._staged_username = self._username + "-staged-rotation"
        self._staged_init_username = self._username + "-staged-initialization"
        self._guard_path = Path(os.path.abspath(bundle_path)) / "auto-unlock-init.lock"

    @contextmanager
    def staged_initialization_guard(self) -> Generator[None]:
        """Serialize local staging, promotion, and proof-based discard of the staged slot.

        A bundle-scoped advisory lock. The initializing process holds it across its whole
        stage -> ceremony -> promote/cleanup span, so a concurrent repair or retry can never
        delete the staged entry between a stale ``uninitialized`` status read and the vault
        envelope commit; discard-only callers re-prove the vault state while holding it. The
        lock releases automatically if its holder dies, and a held lock fails fast rather than
        blocking behind a ceremony.
        """

        try:
            import fcntl
        except ImportError:
            raise OSKeyringError("unsupported") from None
        self._ensure_bundle_root()
        try:
            fd = os.open(
                self._guard_path,
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
        except OSError as exc:
            raise OSKeyringError(_guard_os_reason(exc)) from None
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise OSKeyringError("initialization_in_progress") from None
            yield
        finally:
            os.close(fd)

    def _ensure_bundle_root(self) -> None:
        """Create and verify exactly the scoped bundle root before the guard opens (#565).

        Trusted initialization may legitimately run before any service start has created the
        bundle root, and the credential store is keyed by that path rather than its existence.
        Only the bundle root itself is created, owner-only, and only when its parent already
        exists; the whole path is then verified symlink-free, owned, and owner-only with the
        same helper the service uses. Nothing outside the exact selected bundle is ever
        created, and each failure keeps a distinct reason instead of collapsing to a keyring
        ``unsupported`` verdict.
        """

        bundle = self._guard_path.parent
        try:
            bundle.lstat()
        except FileNotFoundError:
            try:
                os.mkdir(bundle, 0o700)
            except FileExistsError:
                pass
            except OSError as exc:
                raise OSKeyringError(_guard_os_reason(exc)) from None
        except OSError as exc:
            raise OSKeyringError(_guard_os_reason(exc)) from None
        try:
            ensure_owner_only_dir(bundle)
        except PathSafetyError:
            raise OSKeyringError("bundle_unsafe") from None

    @property
    def entry_identity(self) -> tuple[str, str]:
        """Return the (service, account) this store is scoped to, for operator messages.

        Both halves are bounded structural values — a constant service name and a digest of the
        bundle path — and neither reveals the secret. Setup surfaces them so an operator asked to
        clear a blocking entry can actually find it in the platform credential store.
        """

        return _AUTO_UNLOCK_SERVICE_NAME, self._username

    @property
    def available(self) -> bool:
        return self._backend_id in _AUTO_UNLOCK_BACKENDS and all(
            callable(getattr(self._backend, name, None))
            for name in ("get_password", "set_password")
        )

    def load(self) -> bytearray | None:
        value, _reason = self.load_with_reason()
        return value

    def load_with_reason(self) -> tuple[bytearray | None, str]:
        """Load the secret and return only a bounded structural failure reason."""

        if not self.available:
            return None, "auto_unlock_backend_unavailable"
        return self._load_username(self._username)

    def load_candidates_with_reason(
        self,
    ) -> tuple[tuple[tuple[bytearray, str], ...], str]:
        """Load active then crash-recovery staged candidates without exposing any value.

        Each candidate is tagged with its slot (``active``, ``staged_rotation``, or
        ``staged_initialization``) so restart reconciliation can promote or discard exactly the
        entry that cryptographic proof selected. Staged values identical to an earlier candidate
        are dropped from the result but never deleted here.
        """

        if not self.available:
            return (), "auto_unlock_backend_unavailable"
        candidates: list[tuple[bytearray, str]] = []
        reasons: list[str] = []
        for username, slot in (
            (self._username, "active"),
            (self._staged_username, "staged_rotation"),
            (self._staged_init_username, "staged_initialization"),
        ):
            value, reason = self._load_username(username)
            reasons.append(reason)
            if value is None:
                continue
            if any(hmac.compare_digest(existing, value) for existing, _slot in candidates):
                _overwrite(value)
                continue
            candidates.append((value, slot))
        if candidates:
            return tuple(candidates), "none"
        if "auto_unlock_rejected" in reasons:
            return (), "auto_unlock_rejected"
        return (), reasons[0]

    def _load_username(self, username: str) -> tuple[bytearray | None, str]:
        try:
            encoded = cast(AnyKeyringBackend, self._backend).get_password(
                _AUTO_UNLOCK_SERVICE_NAME, username
            )
        except Exception:
            return None, "auto_unlock_rejected"
        if encoded is None:
            return None, "auto_unlock_absent"
        try:
            value = bytearray(
                base64.b64decode(
                    encoded + "=" * (-len(encoded) % 4),
                    altchars=b"-_",
                    validate=True,
                )
            )
        except binascii.Error, TypeError, ValueError:
            return None, "auto_unlock_rejected"
        canonical = base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
        if encoded != canonical:
            _overwrite(value)
            return None, "auto_unlock_rejected"
        try:
            validate_passphrase_view(memoryview(value))
        except VaultPassphraseError:
            _overwrite(value)
            return None, "auto_unlock_rejected"
        return value, "none"

    def load_or_create(self) -> bytearray:
        existing, load_reason = self.load_with_reason()
        if existing is not None:
            return existing
        return self._create_after_absent(load_reason)

    def stage_for_initialization(self) -> bytearray:
        """Create a fresh secret in the staged-initialization slot; never adopt an entry.

        The active slot refuses any pre-existing entry (``entry_exists``): adopting one would
        make an already known value the vault root passphrase. A leftover staged-initialization
        entry (``staged_entry_exists``) belongs to an earlier authorized attempt whose outcome is
        not yet reconciled; the caller must discard it with proof or let restart reconciliation
        resolve it before staging again.
        """

        if not callable(getattr(self._backend, "delete_password", None)):
            raise OSKeyringError("unsupported")
        active, active_reason = self.load_with_reason()
        if active is not None:
            _overwrite(active)
            raise OSKeyringError("entry_exists")
        if active_reason == "auto_unlock_backend_unavailable":
            raise OSKeyringError("unsupported")
        if active_reason != "auto_unlock_absent":
            raise OSKeyringError("entry_invalid")
        staged, staged_reason = self._load_username(self._staged_init_username)
        if staged is not None:
            _overwrite(staged)
            raise OSKeyringError("staged_entry_exists")
        return self._create_at(self._staged_init_username, staged_reason)

    def promote_staged_initialization(self) -> None:
        """Publish the proven staged-initialization secret as active, then clear the slot."""

        value, reason = self._load_username(self._staged_init_username)
        if value is None:
            raise OSKeyringError("missing" if reason == "auto_unlock_absent" else "entry_invalid")
        try:
            self._save_at(self._username, value)
            self._discard_slot(self._staged_init_username)
        finally:
            _overwrite(value)

    def discard_staged_initialization(self) -> None:
        """Remove a staged-initialization entry after proof that no vault envelope needs it."""

        self._discard_slot(self._staged_init_username)

    def slot_report(self) -> dict[str, str]:
        """Report each slot as present/absent/invalid without exposing credential material."""

        if not self.available:
            return {
                "active": "unavailable",
                "staged_initialization": "unavailable",
                "staged_rotation": "unavailable",
            }
        report: dict[str, str] = {}
        for username, slot in (
            (self._username, "active"),
            (self._staged_init_username, "staged_initialization"),
            (self._staged_username, "staged_rotation"),
        ):
            value, reason = self._load_username(username)
            if value is not None:
                _overwrite(value)
                report[slot] = "present"
            else:
                report[slot] = "absent" if reason == "auto_unlock_absent" else "invalid"
        return report

    def _create_after_absent(self, load_reason: str) -> bytearray:
        return self._create_at(self._username, load_reason)

    def stage_for_rotation(self) -> bytearray:
        """Persist one distinct candidate before the vault envelope switches to it."""

        if not callable(getattr(self._backend, "delete_password", None)):
            raise OSKeyringError("unsupported")
        active, active_reason = self.load_with_reason()
        if active is None:
            raise OSKeyringError(
                "missing" if active_reason == "auto_unlock_absent" else "entry_invalid"
            )
        _overwrite(active)
        staged, staged_reason = self._load_username(self._staged_username)
        if staged is not None:
            _overwrite(staged)
            raise OSKeyringError("entry_exists")
        return self._create_at(self._staged_username, staged_reason)

    def stage_value_for_rotation(self, value: bytearray) -> None:
        """Persist a user-selected replacement before the vault envelope switches to it."""

        if not callable(getattr(self._backend, "delete_password", None)):
            raise OSKeyringError("unsupported")
        active, active_reason = self.load_with_reason()
        if active is None:
            raise OSKeyringError(
                "missing" if active_reason == "auto_unlock_absent" else "entry_invalid"
            )
        _overwrite(active)
        staged, staged_reason = self._load_username(self._staged_username)
        if staged is not None:
            _overwrite(staged)
            raise OSKeyringError("entry_exists")
        if staged_reason != "auto_unlock_absent":
            raise OSKeyringError("entry_invalid")
        self._save_at(self._staged_username, value)

    def promote_staged_rotation(self) -> None:
        """Publish a proven staged secret as active, then remove the recovery slot."""

        value, reason = self._load_username(self._staged_username)
        if value is None:
            raise OSKeyringError("missing" if reason == "auto_unlock_absent" else "entry_invalid")
        try:
            self._save_at(self._username, value)
            self._discard_slot(self._staged_username)
        finally:
            _overwrite(value)

    def discard_staged_rotation(self) -> None:
        """Remove a staged candidate after the vault proved it did not switch."""

        self._discard_slot(self._staged_username)

    def _discard_slot(self, username: str) -> None:
        if not callable(getattr(self._backend, "delete_password", None)):
            raise OSKeyringError("unsupported")
        existing, reason = self._load_username(username)
        if existing is not None:
            _overwrite(existing)
        elif reason == "auto_unlock_absent":
            return
        else:
            raise OSKeyringError("entry_invalid")
        try:
            cast(AnyKeyringBackend, self._backend).delete_password(
                _AUTO_UNLOCK_SERVICE_NAME, username
            )
        except Exception:
            raise OSKeyringError("ambiguous_write") from None
        remaining, remaining_reason = self._load_username(username)
        if remaining is not None:
            _overwrite(remaining)
            raise OSKeyringError("unverified")
        if remaining_reason != "auto_unlock_absent":
            raise OSKeyringError("readback_failed")

    def _create_at(self, username: str, load_reason: str) -> bytearray:
        if load_reason == "auto_unlock_backend_unavailable":
            raise OSKeyringError("unsupported")
        if load_reason != "auto_unlock_absent":
            raise OSKeyringError("entry_invalid")
        generated = bytearray(base64.urlsafe_b64encode(os.urandom(48)).rstrip(b"="))
        encoded = base64.urlsafe_b64encode(generated).rstrip(b"=").decode("ascii")
        try:
            backend = cast(AnyKeyringBackend, self._backend)
            backend.set_password(_AUTO_UNLOCK_SERVICE_NAME, username, encoded)
        except Exception:
            _overwrite(generated)
            # A backend exception cannot prove whether the write committed.
            raise OSKeyringError("ambiguous_write") from None
        try:
            verified = backend.get_password(_AUTO_UNLOCK_SERVICE_NAME, username)
        except Exception:
            _overwrite(generated)
            raise OSKeyringError("readback_failed") from None
        if verified != encoded:
            _overwrite(generated)
            raise OSKeyringError("unverified")
        return generated

    def save(self, value: bytearray) -> None:
        """Replace the scoped entry after the caller proved the same secret unlocks the vault."""

        self._save_at(self._username, value)

    def _save_at(self, username: str, value: bytearray) -> None:
        if not self.available:
            raise OSKeyringError("unsupported")
        try:
            validate_passphrase_view(memoryview(value))
        except VaultPassphraseError:
            raise OSKeyringError("entry_invalid")
        encoded = base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
        try:
            backend = cast(AnyKeyringBackend, self._backend)
            backend.set_password(_AUTO_UNLOCK_SERVICE_NAME, username, encoded)
        except Exception:
            raise OSKeyringError("ambiguous_write") from None
        try:
            verified = backend.get_password(_AUTO_UNLOCK_SERVICE_NAME, username)
        except Exception:
            raise OSKeyringError("readback_failed") from None
        if verified != encoded:
            raise OSKeyringError("unverified")


class AnyKeyringBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


class OSVaultRootKeySource:
    def __init__(
        self,
        secret_memory: SecretMemoryPort,
        *,
        backend: object | None = None,
    ) -> None:
        self._secret_memory = secret_memory
        self._backend = backend if backend is not None else keyring.get_keyring()
        self._backend_id = f"{type(self._backend).__module__}.{type(self._backend).__qualname__}"

    async def probe(self, installation_id: str) -> OSKeyringProbe:
        validate_id(IdKind.INSTALLATION, installation_id)
        state = OSKeyringState.UNSUPPORTED
        atomic = callable(getattr(self._backend, "set_password_if_absent", None))
        if self._backend_id not in _APPROVED_BACKENDS:
            state = OSKeyringState.UNSUPPORTED
        else:
            try:
                existing = cast(_AtomicBackend, self._backend).get_password(
                    _SERVICE_NAME, installation_id
                )
                state = OSKeyringState.MISSING if existing is None else OSKeyringState.AVAILABLE
            except Exception:
                state = OSKeyringState.LOCKED
        value: dict[str, JsonValue] = {
            "backend_id": self._backend_id,
            "create_if_absent": atomic,
            "installation_id": installation_id,
            "round_trip_load": state in {OSKeyringState.AVAILABLE, OSKeyringState.MISSING},
            "state": state.value,
        }
        return OSKeyringProbe(
            installation_id,
            state,
            self._backend_id,
            atomic,
            state in {OSKeyringState.AVAILABLE, OSKeyringState.MISSING},
            canonical_digest(value),
        )

    async def authorize_first_install(
        self,
        probe: OSKeyringProbe,
        user_presence: UserPresenceCapability | None,
        runtime_support: Mapping[str, JsonValue],
        *,
        service_generation: int,
        pristine_state_digest: str,
    ) -> FirstInstallKeyringAuthority:
        current = await self.probe(probe.installation_id)
        if (
            probe.state is not OSKeyringState.MISSING
            or not probe.create_if_absent
            or not probe.round_trip_load
            or current.probe_digest != probe.probe_digest
            or user_presence is None
            or not _presence_allowed(user_presence, runtime_support)
        ):
            raise OSKeyringError("human_authority_unavailable")
        return FirstInstallKeyringAuthority(
            service_generation,
            pristine_state_digest,
            probe.probe_digest,
            user_presence.candidate_artifact_digest,
            user_presence.release_cell,
            user_presence.capability_evidence_digest,
            _AUTHORITY_TOKEN,
        )

    async def load(self, installation_id: str) -> KeyringInitializationBinding:
        validate_id(IdKind.INSTALLATION, installation_id)
        if self._backend_id not in _APPROVED_BACKENDS:
            raise OSKeyringError("unsupported")
        try:
            encoded = cast(_AtomicBackend, self._backend).get_password(
                _SERVICE_NAME, installation_id
            )
        except Exception:
            raise OSKeyringError("locked") from None
        if encoded is None:
            raise OSKeyringError("missing")
        return self._decode_entry(encoded, installation_id)

    async def create_and_verify(
        self,
        authority: FirstInstallKeyringAuthority,
        binding: KeyringInitializationBinding,
        *,
        service_generation: int,
        pristine_state_digest: str,
        staged_sentinel_verifier: Callable[[memoryview, str], None],
    ) -> KeyringInitializationBinding:
        authority._consume()  # pyright: ignore[reportPrivateUsage]
        if (
            authority.service_generation != service_generation
            or authority.pristine_state_digest != pristine_state_digest
            or self._backend_id not in _APPROVED_BACKENDS
        ):
            raise OSKeyringError("authority_mismatch")
        payload = _encode_binding_payload(binding)
        backend = cast(_AtomicBackend, self._backend)
        try:
            if not backend.set_password_if_absent(_SERVICE_NAME, binding.installation_id, payload):
                raise OSKeyringError("entry_exists")
        except OSKeyringError:
            raise
        except Exception:
            raise OSKeyringError("unsupported") from None
        loaded = await self.load(binding.installation_id)

        def _verify(view: memoryview) -> None:
            staged_sentinel_verifier(view, loaded.correlation_commitment)

        loaded.ivk_handle.consume(SecretConsumer.VAULT_ROOT, _verify)
        return await self.load(binding.installation_id)

    async def delete_after_proven_migration(
        self,
        installation_id: str,
        migration_verifier: Callable[[KeyringInitializationBinding], None],
    ) -> None:
        loaded = await self.load(installation_id)
        try:
            migration_verifier(loaded)
        except Exception:
            raise OSKeyringError("migration_not_proven") from None
        try:
            cast(_AtomicBackend, self._backend).delete_password(_SERVICE_NAME, installation_id)
        except Exception:
            raise OSKeyringError("locked") from None

    def _decode_entry(
        self, encoded: str, expected_installation_id: str
    ) -> KeyringInitializationBinding:
        try:
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            value = strict_json_parse(raw)
            if canonical_encode(value) != raw or type(value) is not dict:
                raise ValueError
            source = cast(dict[str, JsonValue], value)
            if set(source) != {"correlation", "format", "installation_id", "ivk"}:
                raise ValueError
            if (
                source["format"] != "yoetz-keyring-vault-root/1"
                or source["installation_id"] != expected_installation_id
            ):
                raise ValueError
            ivk = bytearray(base64.urlsafe_b64decode(cast(str, source["ivk"]) + "=="))
            correlation = bytearray(
                base64.urlsafe_b64decode(cast(str, source["correlation"]) + "==")
            )
            if len(ivk) != 32 or len(correlation) != 32:
                raise ValueError
        except (ValueError, TypeError, ProtocolValueError) as exc:
            raise OSKeyringError("entry_invalid") from exc
        commitment = f"sha256:{hashlib.sha256(correlation).hexdigest()}"
        return KeyringInitializationBinding(
            1,
            expected_installation_id,
            commitment,
            self._secret_memory.capture(SecretPurpose.VAULT_ROOT_KEY, ivk),
            self._secret_memory.capture(SecretPurpose.VAULT_ROOT_KEY, correlation),
        )


def _encode_binding_payload(binding: KeyringInitializationBinding) -> str:
    def _with_ivk(ivk: memoryview) -> str:
        def _with_correlation(correlation: memoryview) -> str:
            if len(ivk) != 32 or len(correlation) != 32:
                raise OSKeyringError("entry_invalid")
            commitment = f"sha256:{hashlib.sha256(correlation).hexdigest()}"
            if not hmac.compare_digest(commitment, binding.correlation_commitment):
                raise OSKeyringError("correlation_mismatch")
            value: dict[str, JsonValue] = {
                "correlation": base64.urlsafe_b64encode(correlation).rstrip(b"=").decode("ascii"),
                "format": "yoetz-keyring-vault-root/1",
                "installation_id": binding.installation_id,
                "ivk": base64.urlsafe_b64encode(ivk).rstrip(b"=").decode("ascii"),
            }
            return base64.urlsafe_b64encode(canonical_encode(value)).rstrip(b"=").decode("ascii")

        return binding.correlation_handle.consume(SecretConsumer.VAULT_ROOT, _with_correlation)

    return binding.ivk_handle.consume(SecretConsumer.VAULT_ROOT, _with_ivk)


def _presence_allowed(
    capability: UserPresenceCapability, manifest: Mapping[str, JsonValue]
) -> bool:
    if any(
        state != "active"
        for state in (
            capability.os_authenticated_prompt,
            capability.trusted_action_binding,
            capability.one_use_attestation,
            capability.available,
        )
    ):
        return False
    rows = manifest.get("user_presence_cells")
    if type(rows) is not list:
        return False
    for row_value in rows:
        if type(row_value) is not dict:
            continue
        row = cast(dict[str, JsonValue], row_value)
        if (
            row.get("candidate_artifact_digest") == capability.candidate_artifact_digest
            and row.get("release_cell") == capability.release_cell
            and row.get("adapter_id") == capability.adapter_id
            and row.get("profile_id") == capability.profile_id
            and row.get("capability_evidence_digest") == capability.capability_evidence_digest
            and all(
                row.get(name) == "active"
                for name in (
                    "os_authenticated_prompt",
                    "trusted_action_binding",
                    "one_use_attestation",
                    "available",
                )
            )
        ):
            return True
    return False
