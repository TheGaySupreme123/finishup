"""Where no platform store is usable, the auto-unlock secret lives in owner-only files (#1119)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from keyring.backends.fail import Keyring as FailKeyring
from keyring.backends.macOS import Keyring as MacOSKeyring

from finishup.adapters.keys import os_keyring
from finishup.adapters.keys.os_keyring import AutoUnlockPassphraseStore
from finishup.adapters.keys.owner_file_store import OwnerOnlyFileCredentialStore

_SERVICE = "yoetz.auto-unlock.v1"
_ACCOUNT = "bundle-" + "a" * 64


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    root = tmp_path.resolve() / "bundle"
    root.mkdir(mode=0o700)
    return root


def _store(bundle: Path) -> OwnerOnlyFileCredentialStore:
    return OwnerOnlyFileCredentialStore(bundle / "auto-unlock")


def test_round_trip_is_owner_only(bundle: Path) -> None:
    store = _store(bundle)

    assert store.get_password(_SERVICE, _ACCOUNT) is None
    assert store.has_entries() is False
    store.set_password(_SERVICE, _ACCOUNT, "secret-value")

    assert store.get_password(_SERVICE, _ACCOUNT) == "secret-value"
    assert store.has_entries() is True
    assert stat.S_IMODE((bundle / "auto-unlock").stat().st_mode) == 0o700
    assert stat.S_IMODE((bundle / "auto-unlock" / _ACCOUNT).stat().st_mode) == 0o600
    assert [entry.name for entry in (bundle / "auto-unlock").iterdir()] == [_ACCOUNT]

    store.delete_password(_SERVICE, _ACCOUNT)
    assert store.get_password(_SERVICE, _ACCOUNT) is None
    assert store.has_entries() is False


def test_an_entry_others_can_read_is_refused(bundle: Path) -> None:
    store = _store(bundle)
    store.set_password(_SERVICE, _ACCOUNT, "secret-value")
    os.chmod(bundle / "auto-unlock" / _ACCOUNT, 0o644)

    with pytest.raises(PermissionError):
        store.get_password(_SERVICE, _ACCOUNT)


def test_a_symlinked_entry_is_refused(bundle: Path, tmp_path: Path) -> None:
    store = _store(bundle)
    store.set_password(_SERVICE, _ACCOUNT, "secret-value")
    elsewhere = tmp_path.resolve() / "planted"
    elsewhere.write_text("planted-value")
    os.chmod(elsewhere, 0o600)
    entry = bundle / "auto-unlock" / _ACCOUNT
    entry.unlink()
    entry.symlink_to(elsewhere)

    with pytest.raises(OSError):
        store.get_password(_SERVICE, _ACCOUNT)


@pytest.mark.parametrize(
    ("service", "account"),
    [
        ("other.service", _ACCOUNT),
        (_SERVICE, "../escape"),
        (_SERVICE, "bundle-short"),
    ],
)
def test_only_the_store_names_are_accepted(bundle: Path, service: str, account: str) -> None:
    with pytest.raises(ValueError):
        _store(bundle).set_password(service, account, "value")


def test_nothing_above_the_bundle_is_created(tmp_path: Path) -> None:
    store = OwnerOnlyFileCredentialStore(tmp_path.resolve() / "missing-bundle" / "auto-unlock")

    with pytest.raises(FileNotFoundError):
        store.set_password(_SERVICE, _ACCOUNT, "value")
    assert not (tmp_path / "missing-bundle").exists()


def test_without_a_usable_platform_store_custody_is_the_owner_file(
    monkeypatch: pytest.MonkeyPatch, bundle: Path
) -> None:
    monkeypatch.setattr(os_keyring.keyring, "get_keyring", lambda: FailKeyring())

    store = AutoUnlockPassphraseStore(bundle)

    assert store.custody == "owner_file"
    assert store.available is True
    with store.staged_initialization_guard():
        generated = store.stage_for_initialization()
        store.promote_staged_initialization()
    loaded = store.load()
    assert loaded == generated
    assert store.slot_report() == {
        "active": "present",
        "staged_initialization": "absent",
        "staged_rotation": "absent",
    }


def test_a_usable_platform_store_is_preferred(
    monkeypatch: pytest.MonkeyPatch, bundle: Path
) -> None:
    monkeypatch.setattr(os_keyring.keyring, "get_keyring", lambda: MacOSKeyring())

    assert AutoUnlockPassphraseStore(bundle).custody == "platform_store"


def test_existing_owner_file_custody_survives_a_platform_store_appearing(
    monkeypatch: pytest.MonkeyPatch, bundle: Path
) -> None:
    monkeypatch.setattr(os_keyring.keyring, "get_keyring", lambda: FailKeyring())
    first = AutoUnlockPassphraseStore(bundle)
    with first.staged_initialization_guard():
        first.stage_for_initialization()
        first.promote_staged_initialization()

    monkeypatch.setattr(os_keyring.keyring, "get_keyring", lambda: MacOSKeyring())
    later = AutoUnlockPassphraseStore(bundle)

    assert later.custody == "owner_file"
    assert later.load() is not None


def test_a_hard_linked_entry_is_refused(bundle: Path, tmp_path: Path) -> None:
    store = _store(bundle)
    store.set_password(_SERVICE, _ACCOUNT, "secret-value")
    os.link(bundle / "auto-unlock" / _ACCOUNT, tmp_path.resolve() / "second-name")

    with pytest.raises(PermissionError):
        store.get_password(_SERVICE, _ACCOUNT)


def test_a_short_write_is_completed_before_the_entry_is_published(
    monkeypatch: pytest.MonkeyPatch, bundle: Path
) -> None:
    real_write = os.write

    def one_byte_at_a_time(fd: int, data: bytes | memoryview) -> int:
        return real_write(fd, bytes(data[:1]))

    monkeypatch.setattr(os, "write", one_byte_at_a_time)
    store = _store(bundle)
    store.set_password(_SERVICE, _ACCOUNT, "secret-value")
    monkeypatch.undo()

    assert store.get_password(_SERVICE, _ACCOUNT) == "secret-value"
    assert [entry.name for entry in (bundle / "auto-unlock").iterdir()] == [_ACCOUNT]


def test_a_chained_platform_store_is_used_instead_of_the_file(
    monkeypatch: pytest.MonkeyPatch, bundle: Path
) -> None:
    from keyring.backends.chainer import ChainerBackend
    from keyring.backends.SecretService import Keyring as SecretServiceKeyring

    chained = SecretServiceKeyring()
    chainer = ChainerBackend()
    monkeypatch.setattr(
        ChainerBackend, "backends", property(lambda _self: [FailKeyring(), chained])
    )
    monkeypatch.setattr(os_keyring.keyring, "get_keyring", lambda: chainer)

    store = AutoUnlockPassphraseStore(bundle)

    assert store.custody == "platform_store"
    assert store._backend is chained  # pyright: ignore[reportPrivateUsage]
