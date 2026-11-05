"""The connector's owner-only records: status generations, the stamped lock, the scrubbed env."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from builders.server_targets import ambient_home
from finishup.client.connector_status import (
    ConnectorLock,
    ConnectorLockBusy,
    ConnectorStatus,
    connector_environment,
    connector_holder,
    new_status,
    read_connector_status,
    stop_connector,
    write_connector_status,
)

_STARTED = "2026-11-05T12:00:00.000Z"
_DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def root(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as home:
        target = home / "t_0000000a"
        (target / "state").mkdir(mode=0o700, parents=True)
        yield target


def test_status_round_trips_and_moves_its_generation_only_on_a_change(root: Path) -> None:
    first = new_status(None, "starting", None, started_at=_STARTED)
    assert first.generation == 1
    write_connector_status(root, first)
    assert read_connector_status(root) == first
    same = new_status(first, "starting", None, started_at=_STARTED)
    assert same.generation == 1
    ready = new_status(first, "ready", None, started_at=_STARTED)
    down = new_status(ready, "unavailable", "remote_unreachable", started_at=_STARTED)
    again = new_status(down, "unavailable", "remote_unreachable", started_at=_STARTED)
    repaired = new_status(again, "ready", None, started_at=_STARTED)
    assert [ready.generation, down.generation, again.generation, repaired.generation] == [
        2,
        3,
        3,
        4,
    ]
    stamped = (root / "state" / "connector-status.json").stat()
    assert stamped.st_mode & 0o777 == 0o600


def test_a_new_process_continues_the_roots_sequence(root: Path) -> None:
    previous = ConnectorStatus(7, "stopped", "idle_timeout", None, 1, _STARTED)
    assert previous.pid != os.getpid()
    assert new_status(previous, "starting", None, started_at=_STARTED).generation == 8


@pytest.mark.parametrize(
    ("phase", "reason"),
    [
        ("ready", "remote_unreachable"),
        ("unavailable", None),
        ("unavailable", "lab.example unreachable"),
        ("stopped", "remote_unreachable"),
        ("listening", None),
    ],
)
def test_status_holds_closed_tokens_only(phase: str, reason: str | None) -> None:
    with pytest.raises(ValueError, match="connector_status_invalid"):
        ConnectorStatus(1, phase, reason, None, os.getpid(), _STARTED)  # type: ignore[arg-type]


def test_an_unsafe_or_damaged_status_reads_as_none(root: Path) -> None:
    write_connector_status(root, new_status(None, "ready", None, started_at=_STARTED))
    path = root / "state" / "connector-status.json"
    path.chmod(0o644)
    assert read_connector_status(root) is None
    path.chmod(0o600)
    path.write_bytes(b'{"schema":"yoetz.connector-status/1"}\n')
    assert read_connector_status(root) is None
    path.unlink()
    assert read_connector_status(root) is None


def test_the_lock_is_a_stamped_singleton(root: Path) -> None:
    lock = ConnectorLock(root)
    lock.acquire(version="0.1.0", schema_manifest_digest=_DIGEST)
    try:
        holder = connector_holder(root)
        assert holder is not None
        assert (holder.pid, holder.version, holder.schema_manifest_digest) == (
            os.getpid(),
            "0.1.0",
            _DIGEST,
        )
        with pytest.raises(ConnectorLockBusy):
            ConnectorLock(root).acquire(version="0.1.0", schema_manifest_digest=_DIGEST)
        lock.assert_held()
    finally:
        lock.release()
    assert connector_holder(root) is None
    with pytest.raises(RuntimeError):
        lock.assert_held()
    assert stop_connector(root) is True


def test_the_environment_carries_no_product_variable_or_secret(
    monkeypatch: pytest.MonkeyPatch, root: Path
) -> None:
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", "/elsewhere")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/run/agent.sock")
    environment = connector_environment(root)
    assert environment.get("SSH_AUTH_SOCK") == "/run/agent.sock"
    assert "FINISHUP_ISOLATED_ROOT" not in environment
    assert "OPENAI_API_KEY" not in environment
    assert set(environment) <= {
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "PATH",
        "SSH_AUTH_SOCK",
        "TMPDIR",
        "USER",
    }
