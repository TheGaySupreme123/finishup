"""``finishup instance create|status|dispose`` (issue #604).

Disposal must touch exactly one marked root, stop only the service that holds that root's
singleton, never remove the everyday install or an unlabeled ADR-026 root, and be safe to repeat.
"""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

import finishup.cli.app as cli
from finishup.cli.exits import INSTANCE_PUBLIC_CODES, exit_code_for
from finishup.cli.instance import (
    create_instance,
    dispose_instance,
    instance_status,
    parse_expiry,
)
from finishup.config.installation import (
    InstanceIdentityError,
    new_instance_identity,
    read_instance_identity,
    write_instance_identity,
)
from finishup.config.paths import (
    ISOLATED_ROOT_ENV,
    LEGACY_ISOLATED_ROOT_ENV,
    RUNTIME_PIN_NAME,
    read_runtime_pin,
)
from finishup.protocol.canonical import canonical_encode
from finishup.service.lifecycle import SINGLETON_LOCK_NAME

_NOW = datetime(2026, 9, 5, 15, 0, 0, tzinfo=UTC)
_SOURCE_REF = "c3d553611c998df32a72c64337d1e8231560a37d"


@pytest.fixture
def cell() -> Iterator[Path]:
    """A short, owner-private, symlink-free cell under the real home (socket-path safe)."""

    import secrets
    import shutil

    base = Path.home() / ".yz-unit-inst"
    base.mkdir(mode=0o700, exist_ok=True)
    root = base / secrets.token_hex(3)
    root.mkdir(mode=0o700)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def prefix(cell: Path) -> Path:
    venv = cell / "venv"
    venv.mkdir(mode=0o755)
    return venv


def _ambient_state_dir(cell: Path) -> Callable[..., Path]:
    def state_dir(**_kwargs: object) -> Path:
        return cell / "ambient-state"

    return state_dir


def _scrub(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in [name for name in os.environ if name.startswith(("FINISHUP_", "YOETZ_"))]:
        monkeypatch.delenv(name, raising=False)


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


def test_create_seals_identity_creates_root_and_binds_runtime(
    cell: Path, prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scrub(monkeypatch)
    root = cell / "state"

    result = create_instance(
        root=root,
        lifecycle="disposable",
        now=_NOW,
        expires_at=_NOW + timedelta(hours=8),
        source_ref=_SOURCE_REF,
        source_state="clean",
        package_digest="sha256:" + "cd" * 32,
        bind_runtime=True,
        runtime_prefix=prefix,
    )

    assert result["created"] is True
    assert result["isolated_root"] == str(root)
    # Both spellings with one root (ADR-048): an older launcher on PATH stays isolated too.
    assert result["environment_export"] == (
        f"{ISOLATED_ROOT_ENV}={root} {LEGACY_ISOLATED_ROOT_ENV}={root}"
    )
    assert result["runtime_pin"] == "bound"
    assert result["lifecycle"] == "disposable"
    assert result["expires_at"] == "2026-09-05T23:00:00.000Z"
    assert oct(root.stat().st_mode & 0o777) == "0o700"
    identity = read_instance_identity(root / "state")
    assert identity is not None
    assert identity.installation_id == result["installation_id"]
    pin = json.loads((prefix / RUNTIME_PIN_NAME).read_bytes())
    assert pin == {
        "installation_id": identity.installation_id,
        "isolated_root": str(root),
        "schema": "yoetz.runtime-instance-pin/1",
    }


def test_create_refuses_existing_marked_nonempty_or_overlong_roots(
    cell: Path, prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scrub(monkeypatch)
    root = cell / "state"
    create_instance(root=root, lifecycle="persistent", now=_NOW, runtime_prefix=prefix)

    with pytest.raises(InstanceIdentityError) as exists:
        create_instance(root=root, lifecycle="persistent", now=_NOW, runtime_prefix=prefix)
    assert exists.value.reason == "instance_exists"

    busy = cell / "busy"
    busy.mkdir(mode=0o700)
    (busy / "stray").touch()
    with pytest.raises(InstanceIdentityError) as nonempty:
        create_instance(root=busy, lifecycle="persistent", now=_NOW, runtime_prefix=prefix)
    assert nonempty.value.reason == "instance_root_invalid"

    with pytest.raises(InstanceIdentityError) as missing_parent:
        create_instance(
            root=cell / "no-such-parent" / "state",
            lifecycle="persistent",
            now=_NOW,
            runtime_prefix=prefix,
        )
    assert missing_parent.value.reason == "instance_root_invalid"

    with pytest.raises(InstanceIdentityError) as too_long:
        create_instance(
            root=cell / ("x" * 120), lifecycle="persistent", now=_NOW, runtime_prefix=prefix
        )
    assert too_long.value.reason == "instance_root_too_long"

    with pytest.raises(InstanceIdentityError) as relative:
        create_instance(
            root=Path("relative"), lifecycle="persistent", now=_NOW, runtime_prefix=prefix
        )
    assert relative.value.reason == "instance_root_invalid"


def test_create_refuses_to_repin_a_runtime_bound_elsewhere(
    cell: Path, prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scrub(monkeypatch)
    monkeypatch.setattr(sys, "prefix", str(prefix))
    first = cell / "first"
    create_instance(
        root=first, lifecycle="persistent", now=_NOW, bind_runtime=True, runtime_prefix=prefix
    )

    with pytest.raises(InstanceIdentityError) as caught:
        create_instance(
            root=cell / "second",
            lifecycle="persistent",
            now=_NOW,
            bind_runtime=True,
            runtime_prefix=prefix,
        )
    assert caught.value.reason == "runtime_pin_conflict"
    assert not (cell / "second").exists()


def test_parse_expiry_accepts_exactly_one_spelling() -> None:
    assert parse_expiry(now=_NOW, expires_in_hours=None, expires_at=None) is None
    assert parse_expiry(now=_NOW, expires_in_hours=2, expires_at=None) == _NOW + timedelta(hours=2)
    assert parse_expiry(
        now=_NOW, expires_in_hours=None, expires_at="2026-09-06T00:00:00.000Z"
    ) == datetime(2026, 9, 6, tzinfo=UTC)
    for arguments in ((1, "2026-09-06T00:00:00.000Z"), (0, None), (None, "tomorrow")):
        with pytest.raises(InstanceIdentityError) as caught:
            parse_expiry(now=_NOW, expires_in_hours=arguments[0], expires_at=arguments[1])
        assert caught.value.reason == "instance_expiry_invalid"


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def test_status_reports_pinned_instance_digest_only(
    cell: Path, prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scrub(monkeypatch)
    root = cell / "state"
    created = create_instance(
        root=root,
        lifecycle="disposable",
        now=_NOW,
        expires_at=_NOW + timedelta(hours=1),
        source_ref=_SOURCE_REF,
        bind_runtime=True,
        runtime_prefix=prefix,
    )
    monkeypatch.setattr(sys, "prefix", str(prefix))
    monkeypatch.setenv("FINISHUP_CONFIG", str(cell / "missing.toml"))

    status = instance_status(now=_NOW + timedelta(minutes=5))

    assert status["mode"] == "isolated"
    assert status["binding"] == "runtime_pin"
    assert status["lifecycle"] == "disposable"
    assert status["installation_id"] == created["installation_id"]
    assert status["source_ref"] == _SOURCE_REF
    assert status["expired"] is False
    assert status["runtime_provenance"] == "matched"
    assert status["runtime_pin"] == "bound"
    assert status["service_holder"] is None
    # Path-identity digests are named as such; the ambiguous 0.2 ``identity`` block is gone.
    assert "identity" not in status
    assert set(cast(dict[str, str], status["path_identity"])) == {
        "state_path_digest",
        "endpoint_path_digest",
        "storage_path_digest",
        "config_path_digest",
        "executable_path_digest",
    }
    assert str(root) not in json.dumps(status)

    expired = instance_status(now=_NOW + timedelta(hours=2))
    assert expired["expired"] is True


def test_status_reports_the_everyday_install_as_permanent(
    cell: Path, prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scrub(monkeypatch)
    monkeypatch.setattr(sys, "prefix", str(prefix))
    monkeypatch.setenv("FINISHUP_CONFIG", str(cell / "missing.toml"))
    import finishup.config.paths as paths

    monkeypatch.setattr(paths, "state_dir", _ambient_state_dir(cell))

    status = instance_status(now=_NOW)

    assert status["mode"] == "ambient"
    assert status["binding"] == "ambient"
    assert status["lifecycle"] == "permanent"
    assert status["runtime_provenance"] == "unrecorded"
    assert status["runtime_pin"] == "none"


# ---------------------------------------------------------------------------
# dispose
# ---------------------------------------------------------------------------


def test_dispose_removes_only_a_marked_root_and_is_idempotent(
    cell: Path, prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scrub(monkeypatch)
    root = cell / "state"
    created = create_instance(
        root=root, lifecycle="disposable", now=_NOW, bind_runtime=True, runtime_prefix=prefix
    )
    (root / "log").mkdir(mode=0o700)
    (root / "log" / "service.stderr.jsonl").write_bytes(b'{"kept":true}\n')
    (root / "log" / "link").symlink_to(root / "log" / "service.stderr.jsonl")
    retain = cell / "retained"

    result = dispose_instance(root=root, retain_logs=retain, runtime_prefix=prefix)

    assert result == {
        "disposed": True,
        "state": "removed",
        "installation_id": created["installation_id"],
        "lifecycle": "disposable",
        "service_stopped": False,
        "logs_retained": True,
        "runtime_pin_removed": True,
    }
    assert not root.exists()
    kept = retain / str(created["installation_id"])
    assert (kept / "service.stderr.jsonl").read_bytes() == b'{"kept":true}\n'
    assert not (kept / "link").exists()
    assert read_runtime_pin() is None or not (prefix / RUNTIME_PIN_NAME).exists()

    again = dispose_instance(root=root, runtime_prefix=prefix)
    assert again == {"disposed": False, "state": "absent", "runtime_pin_removed": False}


def test_dispose_refuses_unlabeled_permanent_and_unsafe_targets(
    cell: Path, prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scrub(monkeypatch)
    unlabeled = cell / "legacy-root"
    unlabeled.mkdir(mode=0o700)
    (unlabeled / "state").mkdir(mode=0o700)
    (unlabeled / "state" / "service-generation.json").write_bytes(b"{}\n")

    with pytest.raises(InstanceIdentityError) as legacy:
        dispose_instance(root=unlabeled, runtime_prefix=prefix)
    assert legacy.value.reason == "instance_not_disposable"
    assert (unlabeled / "state" / "service-generation.json").exists()

    with pytest.raises(InstanceIdentityError) as home:
        dispose_instance(root=Path.home(), runtime_prefix=prefix)
    assert home.value.reason == "instance_root_invalid"

    with pytest.raises(InstanceIdentityError) as ancestor_of_runtime:
        dispose_instance(root=cell, runtime_prefix=prefix)
    assert ancestor_of_runtime.value.reason == "instance_root_invalid"

    with pytest.raises(InstanceIdentityError) as relative:
        dispose_instance(root=Path("relative"), runtime_prefix=prefix)
    assert relative.value.reason == "instance_root_invalid"


def test_dispose_stops_only_the_holder_of_that_roots_lock(
    cell: Path, prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A child holding the root's flock with a stamped pid is signalled; nothing else is."""

    _scrub(monkeypatch)
    root = cell / "state"
    create_instance(root=root, lifecycle="disposable", now=_NOW, runtime_prefix=prefix)
    lock = root / "state" / SINGLETON_LOCK_NAME
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import fcntl, os, signal, sys\n"
            "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
            "os.write(fd, sys.argv[2].encode())\n"
            # Block SIGTERM before announcing the lock, then wait for it synchronously: a
            # handler plus time.sleep loses a SIGTERM that lands before the sleep starts.
            # sigwait is POSIX (sigtimedwait is absent on macOS); the alarm's default action
            # bounds an orphaned holder to 60 seconds.
            "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})\n"
            "signal.alarm(60)\n"
            "print('held', flush=True)\n"
            "signal.sigwait({signal.SIGTERM})\n",
            str(lock),
            "PLACEHOLDER",
        ],
        stdout=subprocess.PIPE,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == b"held"
        # The stamp is written by the holder after it took the lock; rewrite it with its pid.
        stamp = canonical_encode({"instance_id": "svc_test", "pid": holder.pid}) + b"\n"
        fd = os.open(lock, os.O_WRONLY)
        try:
            os.ftruncate(fd, 0)
            os.write(fd, stamp)
        finally:
            os.close(fd)

        with pytest.raises(InstanceIdentityError) as refused:
            dispose_instance(root=root, stop_service=False, runtime_prefix=prefix)
        assert refused.value.reason == "instance_service_running"
        assert holder.poll() is None
        assert root.exists()

        result = dispose_instance(root=root, runtime_prefix=prefix, wait_seconds=10.0)
        assert result["service_stopped"] is True
        assert holder.wait(timeout=10) == 0
        assert not root.exists()
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.wait(timeout=5)


def test_dispose_bounded_wait_leaves_root_when_holder_ignores_the_stop(
    cell: Path, prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scrub(monkeypatch)
    root = cell / "state"
    create_instance(root=root, lifecycle="disposable", now=_NOW, runtime_prefix=prefix)
    lock = root / "state" / SINGLETON_LOCK_NAME
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.write(fd, canonical_encode({"instance_id": "svc_self", "pid": os.getpid()}) + b"\n")
    calls: list[tuple[int, int]] = []

    def record_kill(pid: int, sig: int) -> None:
        calls.append((pid, sig))

    monkeypatch.setattr(os, "kill", record_kill)
    try:
        started = time.monotonic()
        with pytest.raises(InstanceIdentityError) as caught:
            dispose_instance(root=root, runtime_prefix=prefix, wait_seconds=0.3)
        assert caught.value.reason == "instance_service_running"
        assert time.monotonic() - started < 5.0
        assert [(pid, int(sig)) for pid, sig in calls if int(sig) != 0] == [(os.getpid(), 15)]
        assert root.exists()
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Typer surface
# ---------------------------------------------------------------------------


def test_cli_create_status_dispose_round_trip(
    cell: Path, prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _scrub(monkeypatch)
    monkeypatch.setattr(sys, "prefix", str(prefix))
    monkeypatch.setenv("FINISHUP_CONFIG", str(cell / "missing.toml"))
    root = cell / "state"
    runner = CliRunner()

    created = runner.invoke(
        cli.app,
        [
            "instance",
            "create",
            "--root",
            str(root),
            "--lifecycle",
            "disposable",
            "--expires-in",
            "4",
            "--source-ref",
            _SOURCE_REF,
            "--source-state",
            "clean",
            "--bind-runtime",
            "--json",
        ],
    )
    assert created.exit_code == 0, created.stderr
    body = json.loads(created.stdout)
    assert body["runtime_pin"] == "bound"

    status = runner.invoke(cli.app, ["instance", "status", "--json"])
    assert status.exit_code == 0, status.stderr
    assert json.loads(status.stdout)["binding"] == "runtime_pin"

    duplicate = runner.invoke(
        cli.app, ["instance", "create", "--root", str(root), "--lifecycle", "disposable"]
    )
    assert duplicate.exit_code == exit_code_for(INSTANCE_PUBLIC_CODES["instance_exists"]) == 2
    assert duplicate.stderr.startswith("instance_exists:")

    disposed = runner.invoke(cli.app, ["instance", "dispose", "--root", str(root), "--json"])
    assert disposed.exit_code == 0, disposed.stderr
    assert json.loads(disposed.stdout)["state"] == "removed"
    assert not (prefix / RUNTIME_PIN_NAME).exists()

    again = runner.invoke(cli.app, ["instance", "dispose", "--root", str(root), "--json"])
    assert again.exit_code == 0
    assert json.loads(again.stdout)["state"] == "absent"


def test_cli_service_run_names_an_instance_refusal(
    cell: Path, prefix: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.config.paths as paths
    import finishup.service.daemon as daemon_module

    monkeypatch.setattr(paths, "state_dir", _ambient_state_dir(cell))

    def refuse(**_kwargs: object) -> None:
        raise InstanceIdentityError("instance_expired")

    monkeypatch.setattr(daemon_module, "main", refuse)
    result = CliRunner().invoke(cli.app, ["service", "run"])

    assert result.exit_code == exit_code_for(INSTANCE_PUBLIC_CODES["instance_expired"]) == 20
    assert result.stderr.startswith("instance_expired:")
    assert "finishup instance dispose" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_service_run_names_a_pin_conflict(cell: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import finishup.config.paths as paths
    import finishup.service.daemon as daemon_module
    from finishup.config.paths import PathSafetyError

    monkeypatch.setattr(paths, "state_dir", _ambient_state_dir(cell))

    def refuse(**_kwargs: object) -> None:
        raise PathSafetyError("isolation_root_conflict")

    monkeypatch.setattr(daemon_module, "main", refuse)
    result = CliRunner().invoke(cli.app, ["service", "run"])

    assert result.exit_code == 20
    assert result.stderr.startswith("isolation_root_conflict:")


def test_marker_helpers_are_reachable_for_reporting(cell: Path) -> None:
    identity = new_instance_identity(
        "persistent", now=_NOW, package_version="0.1.0", runtime_prefix=cell
    )
    write_instance_identity(cell / "state", identity)
    assert read_instance_identity(cell / "state") == identity
