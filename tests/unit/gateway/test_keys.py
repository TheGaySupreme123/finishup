"""Gateway API keys: shown once, stored hashed, revocable, expiring, re-read on change (ADR-051)."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from builders.server_targets import ambient_home
from finishup.gateway.keys import (
    GatewayKeyError,
    KeyRing,
    create_key,
    list_keys,
    record_use,
    revoke_key,
)
from finishup.protocol.rest_binding import API_KEY_PATTERN, KeyScope

_NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


@pytest.fixture
def directory(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root / "gateway"


def test_a_key_is_shown_once_and_stored_only_as_a_salted_hash(directory: Path) -> None:
    record, key = create_key(directory, label="laptop", scope="agent", now=_NOW)
    assert API_KEY_PATTERN.match(key)
    assert key.startswith(f"fuk_{record.key_id}_")
    # The whole secret: base64url may itself contain "_", so never split on the last one.
    secret = key.removeprefix(f"fuk_{record.key_id}_")
    stored = (directory / "keys.json").read_bytes()
    assert secret.encode() not in stored and key.encode() not in stored
    document = json.loads(stored)
    assert document["schema"] == "yoetz.gateway-keys/1"
    (entry,) = document["keys"]
    assert entry["digest"].startswith("sha256:") and entry["label"] == "laptop"
    assert entry["principal"] == "owner" and entry["scope"] == "agent"
    assert stat.S_IMODE((directory / "keys.json").stat().st_mode) == 0o600
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


def test_authentication_is_exact_and_names_closed_reasons(directory: Path) -> None:
    record, key = create_key(directory, label="ci", scope="operator", now=_NOW)
    ring = KeyRing(directory)
    authenticated = ring.authenticate(key, _NOW)
    assert not isinstance(authenticated, str) and authenticated.key_id == record.key_id
    wrong_secret = key[:-1] + ("A" if key[-1] != "A" else "B")
    assert ring.authenticate(wrong_secret, _NOW) == "api_key_invalid"
    assert ring.authenticate("fuk_000000000000_" + "A" * 43, _NOW) == "api_key_invalid"
    assert ring.authenticate("not-a-key", _NOW) == "api_key_invalid"


def test_revocation_is_seen_by_a_running_ring_and_is_idempotent(directory: Path) -> None:
    record, key = create_key(directory, label="ci", scope="agent", now=_NOW)
    ring = KeyRing(directory)
    assert not isinstance(ring.authenticate(key, _NOW), str)
    revoked = revoke_key(directory, record.key_id, now=_NOW + timedelta(minutes=1))
    assert revoked.revoked_at is not None
    assert ring.authenticate(key, _NOW) == "api_key_revoked"
    assert ring.revoked_ids(_NOW) == frozenset({record.key_id})
    again = revoke_key(directory, record.key_id, now=_NOW + timedelta(hours=1))
    assert again.revoked_at == revoked.revoked_at
    with pytest.raises(GatewayKeyError) as unknown:
        revoke_key(directory, "0" * 12)
    assert unknown.value.reason == "gateway_key_unknown"


def test_an_expired_key_stops_authenticating(directory: Path) -> None:
    _record, key = create_key(directory, label="tmp", scope="agent", expires_in_days=1, now=_NOW)
    ring = KeyRing(directory)
    assert not isinstance(ring.authenticate(key, _NOW + timedelta(hours=23)), str)
    assert ring.authenticate(key, _NOW + timedelta(days=1)) == "api_key_expired"
    with pytest.raises(GatewayKeyError) as invalid:
        create_key(directory, label="tmp", scope="agent", expires_in_days=0)
    assert invalid.value.reason == "gateway_key_expiry_invalid"


def test_rotation_copies_label_and_scope_and_keeps_the_old_key_until_revoked(
    directory: Path,
) -> None:
    old, old_key = create_key(directory, label="laptop", scope="operator", now=_NOW)
    new, new_key = create_key(directory, label=None, scope=None, rotate=old.key_id, now=_NOW)
    assert (new.label, new.scope) == ("laptop", "operator")
    assert new.key_id != old.key_id and new_key != old_key
    ring = KeyRing(directory)
    assert not isinstance(ring.authenticate(old_key, _NOW), str)
    assert not isinstance(ring.authenticate(new_key, _NOW), str)
    assert {key.key_id for key in list_keys(directory)} == {old.key_id, new.key_id}


def test_labels_are_bounded_and_never_echoed(directory: Path) -> None:
    for label in ("", "a" * 65, "two\nlines", "../etc"):
        with pytest.raises(GatewayKeyError) as invalid:
            create_key(directory, label=label, scope="agent")
        assert invalid.value.reason == "gateway_key_label_invalid"
        assert label not in str(invalid.value) or label == ""


def test_last_use_is_recorded_without_touching_the_secret(directory: Path) -> None:
    record, _key = create_key(directory, label="ci", scope="agent", now=_NOW)
    record_use(directory, record.key_id, now=_NOW + timedelta(minutes=5))
    (stored,) = list_keys(directory)
    assert stored.last_used_at == "2026-11-05T12:05:00.000Z"
    assert stored.digest == record.digest


def test_a_damaged_or_shared_file_fails_closed(directory: Path) -> None:
    _record, key = create_key(directory, label="ci", scope="agent", now=_NOW)
    path = directory / "keys.json"
    ring = KeyRing(directory)
    path.chmod(0o644)
    with pytest.raises(GatewayKeyError) as unsafe:
        list_keys(directory)
    assert unsafe.value.reason == "gateway_keys_unsafe"
    assert ring.authenticate(key, _NOW) == "api_key_invalid"
    path.chmod(0o600)
    os.truncate(path, 10)
    with pytest.raises(GatewayKeyError) as damaged:
        list_keys(directory)
    assert damaged.value.reason == "gateway_keys_invalid"
    assert KeyRing(directory).authenticate(key, _NOW) == "api_key_invalid"


def test_an_unsupported_scope_is_its_own_reason_not_a_damaged_file(directory: Path) -> None:
    with pytest.raises(GatewayKeyError) as invalid:
        create_key(directory, label="ci", scope=cast(KeyScope, "admin"))
    assert invalid.value.reason == "gateway_key_scope_invalid"
    assert list_keys(directory) == ()
