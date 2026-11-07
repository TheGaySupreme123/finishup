"""Server-target credentials: platform store first, owner-only file otherwise, never echoed."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from builders.server_targets import ambient_home
from finishup.client.credentials import (
    SERVER_CREDENTIAL_SERVICE,
    CredentialError,
    KeyringOrFileCredential,
    read_key_file,
    validate_secret,
)

_KEY = "fuk_0123456789ab_" + "B" * 43
_TARGET = "t_0a1b2c3d"


class _Keyring:
    def __init__(self) -> None:
        self.entries: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.entries.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.entries[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        del self.entries[(service, username)]


@pytest.fixture
def root(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as home:
        target = home / _TARGET
        (target / "config").mkdir(parents=True, mode=0o700)
        target.chmod(0o700)
        yield target


def test_the_file_fallback_is_owner_only_and_reversible(root: Path) -> None:
    credential = KeyringOrFileCredential(_TARGET, root, recorded=None, platform=None)
    assert credential.store(_KEY) == "file"
    entry = root / "config" / "credential" / _TARGET
    assert entry.read_text(encoding="ascii") == _KEY
    assert entry.stat().st_mode & 0o777 == 0o600
    assert (root / "config" / "credential").stat().st_mode & 0o777 == 0o700
    assert credential.read() == _KEY
    assert credential.delete() is True
    assert not entry.exists()
    assert credential.location() is None
    assert credential.delete() is False


def test_the_platform_store_is_preferred_and_the_old_file_is_removed(root: Path) -> None:
    file_only = KeyringOrFileCredential(_TARGET, root, recorded=None, platform=None)
    assert file_only.store(_KEY) == "file"
    keyring = _Keyring()
    moved = KeyringOrFileCredential(_TARGET, root, recorded="file", platform=keyring)
    assert moved.store(_KEY) == "keyring"
    assert keyring.entries == {(SERVER_CREDENTIAL_SERVICE, _TARGET): _KEY}
    assert not (root / "config" / "credential" / _TARGET).exists()
    assert moved.read() == _KEY


def test_a_missing_credential_is_a_closed_reason(root: Path) -> None:
    credential = KeyringOrFileCredential(_TARGET, root, recorded=None, platform=None)
    with pytest.raises(CredentialError) as raised:
        credential.read()
    assert raised.value.reason == "credential_unavailable"
    recorded_keyring = KeyringOrFileCredential(_TARGET, root, recorded="keyring", platform=None)
    with pytest.raises(CredentialError) as unavailable:
        recorded_keyring.read()
    assert unavailable.value.reason == "credential_store_unavailable"


@pytest.mark.parametrize("secret", ["", "short", "has space in it here", "x" * 513, "é" * 20])
def test_secret_shape_is_checked_without_echo(secret: str) -> None:
    with pytest.raises(CredentialError) as raised:
        validate_secret(secret)
    assert raised.value.reason == "credential_invalid"
    assert secret not in str(raised.value) or not secret


def test_key_files_must_be_owner_only_regular_files(root: Path) -> None:
    key = root / "key"
    key.write_text(_KEY + "\n", encoding="ascii")
    key.chmod(0o600)
    assert read_key_file(key) == _KEY
    key.chmod(0o640)
    with pytest.raises(CredentialError) as raised:
        read_key_file(key)
    assert raised.value.reason == "credential_invalid"
    key.chmod(0o600)
    link = root / "link"
    os.symlink(key, link)
    with pytest.raises(CredentialError):
        read_key_file(link)
    with pytest.raises(CredentialError) as missing:
        read_key_file(root / "absent")
    assert missing.value.reason == "credential_unavailable"


def test_account_names_are_target_ids_only(root: Path) -> None:
    with pytest.raises(CredentialError):
        KeyringOrFileCredential("lab", root, recorded=None, platform=None)
    with pytest.raises(CredentialError):
        KeyringOrFileCredential(_TARGET, Path("relative"), recorded=None, platform=None)


def test_the_owner_file_store_keeps_its_auto_unlock_defaults() -> None:
    from finishup.adapters.keys.owner_file_store import OwnerOnlyFileCredentialStore

    store = OwnerOnlyFileCredentialStore(Path("/nonexistent/auto-unlock"))
    with pytest.raises(ValueError):
        store.set_password(SERVER_CREDENTIAL_SERVICE, "bundle-" + "0" * 64, "x")
