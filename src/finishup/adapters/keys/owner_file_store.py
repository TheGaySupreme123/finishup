"""Owner-only file custody for the scoped auto-unlock secret (issue #1119, ADR-008 amendment).

Where no platform credential store is usable (WSL 2, headless Linux), first-run setup keeps the
generated vault passphrase in a file only the owning account can read, instead of asking the
user to invent one. This protects the vault against other accounts on the machine. It does not
protect it against software running as the same user, which can read the file; the platform
store is preferred wherever one is usable, and a human passphrase remains an explicit choice.

The class exposes exactly the three ``keyring``-backend methods ``AutoUnlockPassphraseStore``
uses, so every staging, rotation and proof-based recovery rule applies unchanged. Each entry is
one file named by its account; the account is always a hex digest chosen by the store, never
user-controlled text. Reads refuse anything that is not a regular, owner-owned, owner-only file;
writes are atomic (temp file, fsync, rename, directory fsync).
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Final

from finishup.config.paths import PathSafetyError, ensure_owner_only_dir, existing_owner_only_dir

__all__ = ["OWNER_FILE_BACKEND_ID", "OwnerOnlyFileCredentialStore"]

OWNER_FILE_BACKEND_ID: Final = (
    "finishup.adapters.keys.owner_file_store.OwnerOnlyFileCredentialStore"
)
# Frozen legacy identifier (ADR-048): the only service name the auto-unlock store writes.
_SERVICE_NAME: Final = "yoetz.auto-unlock.v1"
_ACCOUNT_PATTERN: Final = re.compile(r"^bundle-[0-9a-f]{64}(-staged-(rotation|initialization))?$")
_MAX_ENTRY_BYTES: Final = 4096


class OwnerOnlyFileCredentialStore:
    """A ``keyring``-shaped backend over one owner-only directory."""

    __slots__ = ("_directory",)

    def __init__(self, directory: Path) -> None:
        if not directory.is_absolute():
            raise ValueError("owner_file_store_path_invalid")
        self._directory = directory

    @property
    def directory(self) -> Path:
        return self._directory

    def has_entries(self) -> bool:
        """True when any entry file exists; never creates the directory."""

        try:
            if not existing_owner_only_dir(self._directory):
                return False
            return any(
                _ACCOUNT_PATTERN.fullmatch(entry.name) is not None
                for entry in os.scandir(self._directory)
            )
        except (OSError, PathSafetyError):
            # An unreadable or unsafe directory is still this installation's custody: report it
            # as present so the store reads it and fails closed instead of silently switching.
            return self._directory.exists()

    def get_password(self, service: str, username: str) -> str | None:
        path = self._entry(service, username)
        if not existing_owner_only_dir(self._directory):
            return None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_size > _MAX_ENTRY_BYTES
            ):
                raise PermissionError("owner_file_entry_unsafe")
            data = os.read(fd, _MAX_ENTRY_BYTES + 1)
        finally:
            os.close(fd)
        if len(data) > _MAX_ENTRY_BYTES:
            raise PermissionError("owner_file_entry_unsafe")
        return data.decode("ascii")

    def set_password(self, service: str, username: str, password: str) -> None:
        path = self._entry(service, username)
        # Only the custody directory itself is ever created, inside an existing bundle root.
        if not self._directory.parent.is_dir():
            raise FileNotFoundError("owner_file_store_parent_missing")
        ensure_owner_only_dir(self._directory)
        encoded = password.encode("ascii")
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            try:
                os.write(fd, encoded)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(temporary, path)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        self._sync_directory()

    def delete_password(self, service: str, username: str) -> None:
        path = self._entry(service, username)
        os.unlink(path)
        self._sync_directory()

    def _entry(self, service: str, username: str) -> Path:
        if service != _SERVICE_NAME or _ACCOUNT_PATTERN.fullmatch(username) is None:
            raise ValueError("owner_file_entry_name_invalid")
        return self._directory / username

    def _sync_directory(self) -> None:
        fd = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
