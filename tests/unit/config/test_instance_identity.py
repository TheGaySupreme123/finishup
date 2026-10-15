"""Instance identity marker and runtime-pinned root resolution (issue #604).

A persistent development instance or a disposable test snapshot carries a sealed identity in its
state directory and may pin its own runtime to its root. Resolution must prefer the environment,
fall back to the pin, refuse a conflict, leave ambient untouched, and fail closed on anything
malformed — never selecting the everyday install by accident.
"""

from __future__ import annotations

import errno
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from platformdirs import PlatformDirs

from finishup.config.installation import (
    INSTANCE_IDENTITY_SCHEMA,
    InstanceIdentity,
    InstanceIdentityError,
    format_rfc3339_ms,
    instance_identity_path,
    is_expired,
    new_instance_identity,
    parse_rfc3339_ms,
    read_instance_identity,
    remove_runtime_pin,
    verify_instance_binding,
    write_instance_identity,
    write_runtime_pin,
)
from finishup.config.paths import (
    ISOLATED_ROOT_ENV,
    RUNTIME_PIN_NAME,
    PathSafetyError,
    RuntimePin,
    _PathProbe,  # pyright: ignore[reportPrivateUsage]
    isolated_root,
    isolation_binding,
    read_runtime_pin,
    state_dir,
)

_NOW = datetime(2026, 9, 5, 15, 0, 0, tzinfo=UTC)
_SOURCE_REF = "c3d553611c998df32a72c64337d1e8231560a37d"


def _probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, prefix: Path) -> _PathProbe:  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))
    private_temp = tmp_path / "private-temp"
    private_temp.mkdir(mode=0o700, exist_ok=True)
    return _PathProbe(  # pyright: ignore[reportPrivateUsage]
        platform="linux",
        effective_uid=os.geteuid(),
        home=tmp_path,
        shared_temp=private_temp,
        fixed_shared_temps=(),
        platform_dirs=PlatformDirs(appname="finishup", appauthor=False, roaming=False),
        mount_table=lambda: "rootfs / ext4 rw 0 0",
        macos_fstype=lambda _path: None,
        diagnostic=lambda _reason: None,
        runtime_prefix=prefix,
    )


def _identity(lifecycle: str = "disposable", **overrides: object) -> InstanceIdentity:
    return new_instance_identity(
        lifecycle,  # pyright: ignore[reportArgumentType]
        now=_NOW,
        package_version="0.1.0",
        runtime_prefix=Path("/prefix"),
        source_ref=_SOURCE_REF,
        source_state="clean",
        package_digest="sha256:" + "ab" * 32,
        **overrides,  # pyright: ignore[reportArgumentType]
    )


# ---------------------------------------------------------------------------
# Marker
# ---------------------------------------------------------------------------


def test_marker_round_trips_sealed_and_owner_only(tmp_path: Path) -> None:
    state = tmp_path / "state"
    identity = _identity(expires_at=_NOW + timedelta(hours=2))

    path = write_instance_identity(state, identity)

    assert path == instance_identity_path(state)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert read_instance_identity(state) == identity
    body = json.loads(path.read_bytes())
    assert body["schema"] == INSTANCE_IDENTITY_SCHEMA
    assert body["lifecycle"] == "disposable"
    assert body["source_ref"] == _SOURCE_REF
    assert body["record_digest"].startswith("sha256:")
    # Digest-only runtime identity: the prefix path itself is never recorded.
    assert "/prefix" not in path.read_text()


def test_marker_absent_is_none_and_never_overwritten(tmp_path: Path) -> None:
    state = tmp_path / "state"
    assert read_instance_identity(state) is None
    write_instance_identity(state, _identity())
    with pytest.raises(InstanceIdentityError) as caught:
        write_instance_identity(state, _identity())
    assert caught.value.reason == "instance_exists"


def _set_lifecycle(body: dict[str, object]) -> None:
    body["lifecycle"] = "permanent"


def _set_source_ref(body: dict[str, object]) -> None:
    body["source_ref"] = "not-a-revision"


def _set_record_digest(body: dict[str, object]) -> None:
    body["record_digest"] = "sha256:" + "0" * 64


def _drop_package_digest(body: dict[str, object]) -> None:
    body.pop("package_digest")


def _add_extra(body: dict[str, object]) -> None:
    body["extra"] = True


@pytest.mark.parametrize(
    "mutate",
    [_set_lifecycle, _set_source_ref, _set_record_digest, _drop_package_digest, _add_extra],
)
def test_tampered_marker_fails_closed(
    tmp_path: Path, mutate: Callable[[dict[str, object]], None]
) -> None:
    state = tmp_path / "state"
    path = write_instance_identity(state, _identity())
    body = cast(dict[str, object], json.loads(path.read_bytes()))
    mutate(body)
    path.write_bytes(json.dumps(body, sort_keys=True, separators=(",", ":")).encode() + b"\n")

    with pytest.raises(InstanceIdentityError) as caught:
        read_instance_identity(state)
    assert caught.value.reason == "instance_identity_invalid"


def test_broad_permissions_on_marker_fail_closed(tmp_path: Path) -> None:
    state = tmp_path / "state"
    path = write_instance_identity(state, _identity())
    path.chmod(0o644)
    with pytest.raises(InstanceIdentityError) as caught:
        read_instance_identity(state)
    assert caught.value.reason == "instance_identity_invalid"


def test_expiry_is_bounded_to_disposable_and_thirty_days() -> None:
    with pytest.raises(InstanceIdentityError) as persistent:
        _identity("persistent", expires_at=_NOW + timedelta(hours=1))
    assert persistent.value.reason == "instance_expiry_invalid"
    with pytest.raises(InstanceIdentityError) as too_long:
        _identity(expires_at=_NOW + timedelta(days=31))
    assert too_long.value.reason == "instance_expiry_invalid"
    with pytest.raises(InstanceIdentityError) as past:
        _identity(expires_at=_NOW - timedelta(seconds=1))
    assert past.value.reason == "instance_expiry_invalid"

    bounded = _identity(expires_at=_NOW + timedelta(days=30))
    assert not is_expired(bounded, _NOW + timedelta(days=29))
    assert is_expired(bounded, _NOW + timedelta(days=30))
    assert not is_expired(_identity("persistent"), _NOW + timedelta(days=400))


def test_rfc3339_millisecond_form_round_trips() -> None:
    rendered = format_rfc3339_ms(_NOW.replace(microsecond=123_456))
    assert rendered == "2026-09-05T15:00:00.123Z"
    assert parse_rfc3339_ms(rendered) == _NOW.replace(microsecond=123_000)
    with pytest.raises(ValueError):
        parse_rfc3339_ms("2026-09-05T15:00:00Z")


# ---------------------------------------------------------------------------
# Runtime pin
# ---------------------------------------------------------------------------


def test_pin_writes_reads_and_removes_only_its_own_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ISOLATED_ROOT_ENV, raising=False)
    prefix = tmp_path / "venv"
    prefix.mkdir(mode=0o755)
    root = tmp_path / "iso"
    root.mkdir(mode=0o700)
    identity = _identity()
    probe = _probe(tmp_path, monkeypatch, prefix=prefix)

    assert read_runtime_pin(_probe=probe) is None
    write_runtime_pin(prefix, root, identity.installation_id)
    assert read_runtime_pin(_probe=probe) == RuntimePin(root, identity.installation_id)
    # Re-pinning to the same root is idempotent; another root is a conflict.
    write_runtime_pin(prefix, root, identity.installation_id)
    with pytest.raises(InstanceIdentityError) as caught:
        write_runtime_pin(prefix, tmp_path / "other", identity.installation_id)
    assert caught.value.reason == "runtime_pin_conflict"

    assert remove_runtime_pin(prefix, tmp_path / "other") is False
    assert (prefix / RUNTIME_PIN_NAME).is_file()
    assert remove_runtime_pin(prefix, root) is True
    assert remove_runtime_pin(prefix, root) is False


@pytest.mark.parametrize("failing", ["open", "write", "replace"])
def test_a_pin_that_cannot_be_written_is_a_typed_refusal_with_nothing_left(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failing: str
) -> None:
    """EACCES/ENOSPC/EROFS at any step: ``runtime_pin_unwritable``, no temp file, no pin."""

    prefix = tmp_path / "venv"
    prefix.mkdir(mode=0o755)
    identity = _identity()
    code = {"open": errno.EACCES, "write": errno.ENOSPC, "replace": errno.EROFS}[failing]
    real = cast(Callable[..., object], getattr(os, failing))

    def refuse(*args: object, **kwargs: object) -> object:
        first = args[0]
        beneath = isinstance(first, str | Path) and Path(first).parent == prefix
        if failing == "write" or beneath:
            raise OSError(code, os.strerror(code))
        return real(*args, **kwargs)

    monkeypatch.setattr(os, failing, refuse)
    with pytest.raises(InstanceIdentityError) as caught:
        write_runtime_pin(prefix, tmp_path / "iso", identity.installation_id)
    monkeypatch.undo()

    assert caught.value.reason == "runtime_pin_unwritable"
    assert list(prefix.iterdir()) == []


def test_a_marker_whose_write_fails_leaves_no_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed seal leaves the state directory empty, so a create can roll it back."""

    state = tmp_path / "state"
    state.mkdir(mode=0o700)

    def no_space(_descriptor: int, _data: object) -> int:
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(os, "write", no_space)
    with pytest.raises(OSError):
        write_instance_identity(state, _identity())
    monkeypatch.undo()

    assert list(state.iterdir()) == []


@pytest.mark.parametrize(
    ("payload", "mode"),
    [
        (b"not json\n", 0o600),
        (
            b'{"schema":"yoetz.runtime-instance-pin/1","isolated_root":"relative","installation_id":"ins_00000000-0000-4000-8000-000000000000"}\n',
            0o600,
        ),
        (
            b'{"schema":"other","isolated_root":"/x","installation_id":"ins_00000000-0000-4000-8000-000000000000"}\n',
            0o600,
        ),
        (
            b'{"schema":"yoetz.runtime-instance-pin/1","isolated_root":"/x","installation_id":"ins_00000000-0000-4000-8000-000000000000"}\n',
            0o666,
        ),
    ],
)
def test_malformed_or_writable_pin_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: bytes, mode: int
) -> None:
    monkeypatch.delenv(ISOLATED_ROOT_ENV, raising=False)
    prefix = tmp_path / "venv"
    prefix.mkdir(mode=0o755)
    (prefix / RUNTIME_PIN_NAME).write_bytes(payload)
    (prefix / RUNTIME_PIN_NAME).chmod(mode)
    probe = _probe(tmp_path, monkeypatch, prefix=prefix)

    with pytest.raises(PathSafetyError) as caught:
        isolated_root(_probe=probe)
    assert caught.value.reason_code == "runtime_pin_invalid"


# ---------------------------------------------------------------------------
# Resolution precedence
# ---------------------------------------------------------------------------


def test_ambient_stays_ambient_without_variable_or_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ISOLATED_ROOT_ENV, raising=False)
    prefix = tmp_path / "venv"
    prefix.mkdir(mode=0o755)
    probe = _probe(tmp_path, monkeypatch, prefix=prefix)

    assert isolated_root(_probe=probe) is None
    assert isolation_binding(_probe=probe) == "ambient"
    assert state_dir(_probe=probe) == Path(probe.platform_dirs.user_state_dir)


def test_pin_alone_selects_the_pinned_root_never_ambient(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ISOLATED_ROOT_ENV, raising=False)
    prefix = tmp_path / "venv"
    prefix.mkdir(mode=0o755)
    root = tmp_path / "iso"
    root.mkdir(mode=0o700)
    write_runtime_pin(prefix, root, _identity().installation_id)
    probe = _probe(tmp_path, monkeypatch, prefix=prefix)

    assert isolated_root(_probe=probe) == root
    assert isolation_binding(_probe=probe) == "runtime_pin"
    assert state_dir(_probe=probe) == root / "state"


def test_environment_and_matching_pin_agree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = tmp_path / "venv"
    prefix.mkdir(mode=0o755)
    root = tmp_path / "iso"
    root.mkdir(mode=0o700)
    write_runtime_pin(prefix, root, _identity().installation_id)
    monkeypatch.setenv(ISOLATED_ROOT_ENV, str(root))
    probe = _probe(tmp_path, monkeypatch, prefix=prefix)

    assert isolated_root(_probe=probe) == root
    assert isolation_binding(_probe=probe) == "environment_and_pin"


def test_environment_and_different_pin_is_a_conflict_not_a_choice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = tmp_path / "venv"
    prefix.mkdir(mode=0o755)
    pinned = tmp_path / "pinned"
    pinned.mkdir(mode=0o700)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    write_runtime_pin(prefix, pinned, _identity().installation_id)
    monkeypatch.setenv(ISOLATED_ROOT_ENV, str(other))
    probe = _probe(tmp_path, monkeypatch, prefix=prefix)

    with pytest.raises(PathSafetyError) as caught:
        state_dir(_probe=probe)
    assert caught.value.reason_code == "isolation_root_conflict"


def test_pinned_root_that_was_disposed_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A runtime whose root is gone must not quietly become the everyday install."""

    monkeypatch.delenv(ISOLATED_ROOT_ENV, raising=False)
    prefix = tmp_path / "venv"
    prefix.mkdir(mode=0o755)
    write_runtime_pin(prefix, tmp_path / "gone", _identity().installation_id)
    probe = _probe(tmp_path, monkeypatch, prefix=prefix)

    with pytest.raises(PathSafetyError) as caught:
        isolated_root(_probe=probe)
    assert caught.value.reason_code == "isolation_root_invalid"


# ---------------------------------------------------------------------------
# Service-start binding gate
# ---------------------------------------------------------------------------


def test_binding_gate_refuses_expired_mismatched_and_ambient_labeled_instances() -> None:
    identity = _identity(expires_at=_NOW + timedelta(hours=1))
    pin = RuntimePin(Path("/iso"), identity.installation_id)

    verify_instance_binding(None, isolated=False, pin=None, now=_NOW)
    verify_instance_binding(None, isolated=True, pin=None, now=_NOW)
    verify_instance_binding(identity, isolated=True, pin=None, now=_NOW)
    verify_instance_binding(identity, isolated=True, pin=pin, now=_NOW)

    with pytest.raises(InstanceIdentityError) as orphan_pin:
        verify_instance_binding(None, isolated=True, pin=pin, now=_NOW)
    assert orphan_pin.value.reason == "installation_identity_mismatch"

    foreign = RuntimePin(Path("/iso"), _identity().installation_id)
    with pytest.raises(InstanceIdentityError) as mismatch:
        verify_instance_binding(identity, isolated=True, pin=foreign, now=_NOW)
    assert mismatch.value.reason == "installation_identity_mismatch"

    with pytest.raises(InstanceIdentityError) as ambient:
        verify_instance_binding(identity, isolated=False, pin=None, now=_NOW)
    assert ambient.value.reason == "instance_lifecycle_requires_isolated_root"

    with pytest.raises(InstanceIdentityError) as expired:
        verify_instance_binding(identity, isolated=True, pin=pin, now=_NOW + timedelta(hours=1))
    assert expired.value.reason == "instance_expired"
