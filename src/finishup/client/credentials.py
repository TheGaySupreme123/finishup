"""Server-target credentials: where a target's API key lives on this client (ADR-051, section 6).

``CredentialSource`` is the pluggable interface; an OAuth source can implement it later.
``KeyringOrFileCredential`` keeps one target's key in the platform credential store under the
fixed service ``yoetz.server-credential.v1`` with the target id as the account, or — where no
platform store is usable (WSL 2, headless Linux) — in an owner-only file beneath
``<target root>/config/credential/``. ``target.json`` records only which of the two holds it.

The key never appears in argv, the environment, ``target.json``, logs, or JSON output, and no
error carries it: every failure is a closed ``CredentialError`` reason. Same-user software can
still read the platform store or the file, as it can read today's auto-unlock secret; the claim
is interface parity — no surface an agent reaches reveals or switches the key.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Final, Protocol, cast

from finishup.client.targets import CredentialLocation

__all__ = [
    "SERVER_CREDENTIAL_SERVICE",
    "CredentialError",
    "CredentialSource",
    "KeyringOrFileCredential",
    "read_key_file",
    "validate_secret",
]

# ADR-048 tag namespace; a frozen identifier once released.
SERVER_CREDENTIAL_SERVICE: Final = "yoetz.server-credential.v1"
# Platform stores this client accepts for a target key (the auto-unlock allowlist without the
# owner file, which is the explicit fallback below).
_PLATFORM_BACKENDS: Final = frozenset(
    {
        "keyring.backends.SecretService.Keyring",
        "keyring.backends.Windows.WinVaultKeyring",
        "keyring.backends.kwallet.DBusKeyring",
        "keyring.backends.libsecret.Keyring",
        "keyring.backends.macOS.Keyring",
    }
)
_FILE_DIRECTORY: Final = Path("config") / "credential"
_ACCOUNT: Final = re.compile(r"^t_[0-9a-f]{8}$", re.ASCII)
# Printable ASCII without whitespace, bounded: covers ``fuk_<id>_<secret>`` keys and bearer
# tokens without ever echoing a rejected value.
_SECRET: Final = re.compile(r"^[\x21-\x7e]{16,512}$", re.ASCII)
_MAX_KEY_FILE_BYTES: Final = 1_024
_REASONS: Final = frozenset(
    {"credential_invalid", "credential_unavailable", "credential_store_unavailable"}
)


class CredentialError(Exception):
    """A bounded credential failure; ``reason`` is a closed token and never holds the secret."""

    reason: str

    def __init__(self, reason: str) -> None:
        if reason not in _REASONS:
            raise ValueError("credential_reason_invalid")
        self.reason = reason
        super().__init__(reason)


class CredentialSource(Protocol):
    """Where one server target's credential comes from."""

    @property
    def target_id(self) -> str: ...

    def location(self) -> CredentialLocation | None:
        """Which store holds the credential now, or ``None`` when none does."""
        ...

    def read(self) -> str:
        """Return the credential for the one process that dials; ``credential_unavailable``."""
        ...

    def store(self, secret: str) -> CredentialLocation:
        """Store (or replace) the credential and return where it went."""
        ...

    def delete(self) -> bool:
        """Remove the credential from every store; return whether one was removed."""
        ...


class _Backend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


def validate_secret(secret: str) -> str:
    """Return ``secret`` when it has a key's shape; ``credential_invalid`` otherwise."""

    if type(secret) is not str or not _SECRET.match(secret):
        raise CredentialError("credential_invalid")
    return secret


def read_key_file(path: Path) -> str:
    """Read a key file once: a regular, owner-owned, owner-only (0600) file of one key line."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise CredentialError("credential_unavailable") from None
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
            or facts.st_size > _MAX_KEY_FILE_BYTES
        ):
            raise CredentialError("credential_invalid")
        data = os.read(descriptor, _MAX_KEY_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > _MAX_KEY_FILE_BYTES:
        raise CredentialError("credential_invalid")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise CredentialError("credential_invalid") from None
    if text.endswith("\n"):
        text = text[:-1]
    if text.endswith("\r"):
        text = text[:-1]
    return validate_secret(text)


def _platform_backend() -> _Backend | None:
    """The first allowlisted platform credential store, or ``None`` when none is usable."""

    try:
        import keyring
        from keyring.backends.chainer import ChainerBackend

        loaded: object = keyring.get_keyring()
    except Exception:
        return None
    candidates: tuple[object, ...] = (
        tuple(loaded.backends) if isinstance(loaded, ChainerBackend) else (loaded,)
    )
    for candidate in candidates:
        backend_id = f"{type(candidate).__module__}.{type(candidate).__qualname__}"
        if backend_id in _PLATFORM_BACKENDS:
            return cast(_Backend, candidate)
    return None


class KeyringOrFileCredential:
    """One target's API key in the platform store, or in an owner-only file beneath its root."""

    __slots__ = ("_platform", "_recorded", "_root", "_target_id")

    _platform: _Backend | None | bool
    _recorded: CredentialLocation | None
    _root: Path
    _target_id: str

    def __init__(
        self,
        target_id: str,
        target_root: Path,
        *,
        recorded: CredentialLocation | None,
        platform: _Backend | None | bool = True,
    ) -> None:
        """``recorded`` is ``target.json``'s ``credential``. ``platform=True`` discovers the
        platform store; tests pass a backend, or ``None`` for a machine without one."""

        if not _ACCOUNT.match(target_id) or not target_root.is_absolute():
            raise CredentialError("credential_invalid")
        self._target_id = target_id
        self._root = target_root
        self._recorded = recorded
        self._platform = platform

    @property
    def target_id(self) -> str:
        return self._target_id

    def _platform_store(self) -> _Backend | None:
        if self._platform is True:
            self._platform = _platform_backend()
        platform = self._platform
        return None if isinstance(platform, bool) else platform

    def _file_store(self) -> _Backend:
        from finishup.adapters.keys.owner_file_store import OwnerOnlyFileCredentialStore

        return OwnerOnlyFileCredentialStore(
            self._root / _FILE_DIRECTORY,
            service=SERVER_CREDENTIAL_SERVICE,
            account_pattern=_ACCOUNT,
        )

    def _store_for(self, location: CredentialLocation) -> _Backend:
        if location == "file":
            return self._file_store()
        backend = self._platform_store()
        if backend is None:
            raise CredentialError("credential_store_unavailable")
        return backend

    def location(self) -> CredentialLocation | None:
        return self._recorded

    def read(self) -> str:
        if self._recorded is None:
            raise CredentialError("credential_unavailable")
        try:
            value = self._store_for(self._recorded).get_password(
                SERVER_CREDENTIAL_SERVICE, self._target_id
            )
        except CredentialError:
            raise
        except Exception:
            raise CredentialError("credential_store_unavailable") from None
        if value is None:
            raise CredentialError("credential_unavailable")
        return validate_secret(value)

    def store(self, secret: str) -> CredentialLocation:
        validate_secret(secret)
        location: CredentialLocation = "keyring" if self._platform_store() is not None else "file"
        try:
            self._store_for(location).set_password(
                SERVER_CREDENTIAL_SERVICE, self._target_id, secret
            )
        except CredentialError:
            raise
        except Exception:
            raise CredentialError("credential_store_unavailable") from None
        other: CredentialLocation = "file" if location == "keyring" else "keyring"
        if self._recorded == other:
            self._delete_from(other)
        self._recorded = location
        return location

    def _delete_from(self, location: CredentialLocation) -> bool:
        try:
            store = self._store_for(location)
            if store.get_password(SERVER_CREDENTIAL_SERVICE, self._target_id) is None:
                return False
            store.delete_password(SERVER_CREDENTIAL_SERVICE, self._target_id)
        except CredentialError:
            return False
        except Exception:
            raise CredentialError("credential_store_unavailable") from None
        return True

    def delete(self) -> bool:
        removed = False
        locations: tuple[CredentialLocation, ...] = ("keyring", "file")
        for location in locations:
            if location == "keyring" and self._platform_store() is None:
                continue
            removed = self._delete_from(location) or removed
        self._recorded = None
        return removed
