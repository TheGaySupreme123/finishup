"""What this computer's everyday FinishUP last reported about network use (ADR-051 decision 8).

Maintainer decision of 2026-11-07, "remember". The marker is an owner-only file beside the server
registry in this computer's everyday state folder, outside the vault: whether the last report was
zero-network, and when. It is written only for the everyday installation, read the same way, and
a marker that cannot be read counts as no record. The connection check refuses every remote
target while it says zero-network, whatever the process's selection memo says.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

import finishup.client.everyday_policy as everyday_policy
from builders.server_targets import ambient_home
from finishup.client import targets
from finishup.client.everyday_policy import (
    ReportedPolicy,
    last_reported_zero_network,
    marker_path,
    read_marker,
    record_reported_policy,
    remove_marker,
)
from finishup.config.paths import reset_selection_memo

_AT = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
_STAMP = "2026-11-07T09:30:00.000Z"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """An owner-only ambient home; the marker at its real place beneath it."""

    with ambient_home(monkeypatch) as root:
        monkeypatch.setattr(
            everyday_policy,
            "_location",
            everyday_policy._ambient_marker_path,  # pyright: ignore[reportPrivateUsage]
        )
        yield root


def test_the_marker_is_owner_only_client_state_beside_the_server_registry(home: Path) -> None:
    assert record_reported_policy(zero_network=True, now=_AT) is True

    path = marker_path()
    assert path == home / "state" / "finishup" / "servers" / "everyday-policy.json"
    assert path.parent == targets.servers_dir()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    # Only the closed facts: no path, name or policy content.
    assert json.loads(path.read_bytes()) == {
        "schema": "yoetz.everyday-network-policy/1",
        "reported_at": _STAMP,
        "zero_network": True,
    }
    assert read_marker() == ReportedPolicy(True, _STAMP)
    assert last_reported_zero_network() == ReportedPolicy(True, _STAMP)
    # No leftover temporary file beside it.
    assert sorted(entry.name for entry in path.parent.iterdir()) == ["everyday-policy.json"]


def test_the_latest_report_replaces_the_one_before(home: Path) -> None:
    record_reported_policy(zero_network=True, now=_AT)
    later = datetime(2026, 11, 7, 10, 0, 0, 123_456, tzinfo=UTC)

    assert record_reported_policy(zero_network=False, now=later) is True

    assert read_marker() == ReportedPolicy(False, "2026-11-07T10:00:00.123Z")
    assert last_reported_zero_network() is None


def test_no_marker_is_no_record(home: Path) -> None:
    assert read_marker() == "absent"
    assert last_reported_zero_network() is None
    assert remove_marker() is False


def _damage(path: Path, how: str) -> Path | None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    body = {
        "schema": "yoetz.everyday-network-policy/1",
        "reported_at": _STAMP,
        "zero_network": True,
    }
    if how == "not_json":
        path.write_bytes(b"{zero")
    elif how == "extra_field":
        path.write_text(json.dumps({**body, "path": "/srv/shared"}))
    elif how == "other_schema":
        path.write_text(json.dumps({**body, "schema": "yoetz.everyday-network-policy/2"}))
    elif how == "not_a_boolean":
        path.write_text(json.dumps({**body, "zero_network": "yes"}))
    elif how == "bad_time":
        path.write_text(json.dumps({**body, "reported_at": "yesterday"}))
    elif how == "too_large":
        path.write_bytes(b" " * 600 + json.dumps(body).encode())
    elif how == "group_readable":
        path.write_text(json.dumps(body))
        path.chmod(0o640)
        return None
    elif how == "symlink":
        # A well-formed record behind a link: still never followed.
        target = path.parent / "elsewhere.json"
        target.write_text(
            json.dumps({**body, "zero_network": False, "reported_at": "2026-01-01T00:00:00.000Z"})
        )
        target.chmod(0o600)
        path.symlink_to(target)
        return target
    path.chmod(0o600)
    return None


@pytest.mark.parametrize(
    "how",
    [
        "not_json",
        "extra_field",
        "other_schema",
        "not_a_boolean",
        "bad_time",
        "too_large",
        "group_readable",
        "symlink",
    ],
)
def test_a_marker_that_cannot_be_read_counts_as_no_record_and_the_next_report_replaces_it(
    home: Path, how: str
) -> None:
    path = marker_path()
    linked = _damage(path, how)

    assert read_marker() == "unreadable"
    # No surface claims zero-network from it, and no connection is refused on it.
    assert last_reported_zero_network() is None

    assert record_reported_policy(zero_network=True, now=_AT) is True
    assert read_marker() == ReportedPolicy(True, _STAMP)
    assert not path.is_symlink()
    if linked is not None:
        # The link itself was replaced; what it named was never written through it.
        assert json.loads(linked.read_bytes())["reported_at"] == "2026-01-01T00:00:00.000Z"


def test_removing_the_marker_removes_a_link_never_what_it_names(home: Path) -> None:
    path = marker_path()
    linked = _damage(path, "symlink")
    assert linked is not None

    assert remove_marker() is True

    assert not path.exists() and not path.is_symlink()
    assert linked.exists()
    assert read_marker() == "absent"


def test_a_folder_in_its_place_is_left_alone(home: Path) -> None:
    path = marker_path()
    path.mkdir(mode=0o700, parents=True)

    assert read_marker() == "unreadable"
    assert record_reported_policy(zero_network=True, now=_AT) is False
    assert remove_marker() is False
    assert path.is_dir()


def test_an_isolation_root_neither_records_nor_reads_the_everyday_marker(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record_reported_policy(zero_network=True, now=_AT)
    before = marker_path().read_bytes()
    isolated = home / "isolated"
    isolated.mkdir(mode=0o700)
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", str(isolated))
    reset_selection_memo()

    assert record_reported_policy(zero_network=False, now=_AT) is False
    assert read_marker() == "absent"
    assert last_reported_zero_network() is None

    monkeypatch.delenv("FINISHUP_ISOLATED_ROOT")
    reset_selection_memo()
    assert marker_path().read_bytes() == before


# --- the connection check: the last line of defence ---------------------------------------------


def _remote(kind: str = "ssh") -> targets.ServerTarget:
    fields: dict[str, object]
    if kind == "ssh":
        fields = {"user": "owner", "host": "lab.example", "port": 22}
    else:
        fields = {"base_url": "https://lab.example:8443", "tls_pin": "sha256:" + "a" * 64}
    with targets.registry_lock():
        record, _root = targets.new_remote_target("lab", kind, **fields)  # pyright: ignore[reportArgumentType]
    return record


@pytest.mark.parametrize("kind", ["ssh", "https"])
def test_every_connection_to_a_remote_target_is_refused_while_the_last_report_is_zero_network(
    home: Path, kind: str
) -> None:
    record = _remote(kind)
    targets.require_current_authorization(record)

    record_reported_policy(zero_network=True, now=_AT)

    with pytest.raises(targets.TargetError) as refused:
        targets.require_current_authorization(record)
    assert refused.value.reason == "zero_network_remote_selected"


def test_the_zero_network_refusal_comes_before_an_older_disclosure(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _remote()
    monkeypatch.setattr(targets, "DISCLOSURE_VERSION", targets.DISCLOSURE_VERSION + 1)
    with pytest.raises(targets.TargetError) as stale:
        targets.require_current_authorization(record)
    assert stale.value.reason == "target_reauthorization_required"

    record_reported_policy(zero_network=True, now=_AT)

    with pytest.raises(targets.TargetError) as refused:
        targets.require_current_authorization(record)
    # 'server use NAME' would be refused too: the one way out is 'server use local'.
    assert refused.value.reason == "zero_network_remote_selected"


@pytest.mark.parametrize("marker", ["permitted", "absent", "unreadable"])
def test_a_report_that_permits_network_or_none_refuses_nothing(home: Path, marker: str) -> None:
    record = _remote()
    if marker == "permitted":
        record_reported_policy(zero_network=False, now=_AT)
    elif marker == "unreadable":
        _damage(marker_path(), "not_json")

    targets.require_current_authorization(record)


def test_a_local_target_and_the_everyday_server_are_never_refused(home: Path) -> None:
    record_reported_policy(zero_network=True, now=_AT)
    with targets.registry_lock():
        local, _root = targets.new_local_target("work")

    targets.require_current_authorization(local)
    targets.require_current_authorization(None)


def test_an_isolation_root_keeps_its_own_policy_and_is_not_refused_here(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _remote()
    record_reported_policy(zero_network=True, now=_AT)
    isolated = home / "isolated"
    isolated.mkdir(mode=0o700)
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", str(isolated))
    reset_selection_memo()

    targets.require_current_authorization(record)


def test_the_connection_check_reads_a_file_and_never_asks_a_service(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _remote()
    record_reported_policy(zero_network=True, now=_AT)

    def never(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the connection check never asks a service")

    monkeypatch.setattr("finishup.service.client.connect_service", never)
    with pytest.raises(targets.TargetError):
        targets.require_current_authorization(record)
    assert os.path.exists(marker_path())
