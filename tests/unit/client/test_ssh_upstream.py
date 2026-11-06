"""OpenSSH for SSH targets: the exact secret-free argv, path bounds, closed failure reasons."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from builders.control_relay import write_fake_ssh
from builders.server_targets import ambient_home
from finishup.client import targets
from finishup.client.ssh_upstream import (
    SshMaster,
    UpstreamUnavailable,
    classify_ssh_failure,
    control_argv,
    master_argv,
    remote_argv,
    remote_command_line,
    ssh_root_fits,
)


@pytest.fixture
def target(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[targets.ServerTarget, Path, Path]]:
    with ambient_home(monkeypatch) as home:
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "lab",
                "ssh",
                user="owner",
                host="lab.example",
                port=2222,
                remote_root="/srv/finishup",
                remote_launcher="/opt/finishup/bin/finishup",
            )
        yield record, root, home


def test_the_master_argv_is_exactly_the_designed_one(
    target: tuple[targets.ServerTarget, Path, Path],
) -> None:
    record, root, _home = target
    assert master_argv("/usr/bin/ssh", root, record) == (
        "/usr/bin/ssh",
        "-M",
        "-S",
        f"{root}/run/m",
        "-N",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "StreamLocalBindMask=0177",
        "-o",
        "StreamLocalBindUnlink=yes",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-p",
        "2222",
        "-L",
        f"{root}/run/upstream.sock:/srv/finishup/run/control.sock",
        "owner@lab.example",
    )
    joined = " ".join(master_argv("/usr/bin/ssh", root, record))
    assert record.claim_salt is not None and record.claim_salt not in joined


def test_control_and_remote_commands_use_the_master_and_the_recorded_launcher(
    target: tuple[targets.ServerTarget, Path, Path],
) -> None:
    record, root, _home = target
    assert control_argv("/usr/bin/ssh", root, record, "exit") == (
        "/usr/bin/ssh",
        "-S",
        f"{root}/run/m",
        "-O",
        "exit",
        "-p",
        "2222",
        "owner@lab.example",
    )
    remote = remote_argv("/usr/bin/ssh", root, record, "service", "start")
    assert remote[-1] == (
        "env FINISHUP_ISOLATED_ROOT=/srv/finishup /opt/finishup/bin/finishup service start"
    )
    assert remote_command_line("/opt/my finishup/finishup", None, "service", "start") == (
        "'/opt/my finishup/finishup' service start"
    )
    with pytest.raises(ValueError):
        control_argv("/usr/bin/ssh", root, record, "stop")


def test_a_remote_endpoint_that_cannot_be_forwarded_is_refused(
    target: tuple[targets.ServerTarget, Path, Path],
) -> None:
    record, root, _home = target
    with pytest.raises(UpstreamUnavailable):
        master_argv("/usr/bin/ssh", root, replace(record, remote_endpoint="/srv/a:b/control.sock"))
    with pytest.raises(UpstreamUnavailable):
        master_argv("/usr/bin/ssh", root, replace(record, remote_endpoint=None))


def test_socket_paths_include_openssh_s_temporary_suffix() -> None:
    assert ssh_root_fits(Path("/srv/owner/.local/state/finishup/servers/t_01234567"))
    deep = Path("/" + "d" * 80)
    assert len(str(deep / "run" / "m")) <= 103 < len(str(deep / "run" / "m")) + 17
    assert not ssh_root_fits(deep)


@pytest.mark.parametrize(
    ("stderr", "reason"),
    [
        (b"owner@lab.example: Permission denied (publickey).", "remote_auth_failed"),
        (b"Host key verification failed.", "remote_identity_changed"),
        (b"@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@", "remote_identity_changed"),
        (b"ssh: connect to host lab.example port 2222: Connection refused", "remote_unreachable"),
        (b"", "remote_unreachable"),
    ],
)
def test_openssh_failures_map_to_closed_reasons(stderr: bytes, reason: str) -> None:
    assert classify_ssh_failure(stderr) == reason


def test_a_master_that_fails_authentication_reports_only_the_closed_reason(
    target: tuple[targets.ServerTarget, Path, Path],
) -> None:
    record, root, home = target
    refusing = home / "refusing-ssh"
    refusing.write_text(
        "#!/bin/sh\necho 'owner@lab.example: Permission denied (publickey).' >&2\nexit 255\n",
        encoding="utf-8",
    )
    refusing.chmod(0o700)

    async def exercise() -> None:
        master = SshMaster(root, record, ssh=str(refusing))
        with pytest.raises(UpstreamUnavailable) as failed:
            await master.ensure()
        assert failed.value.reason == "remote_auth_failed"
        assert "lab.example" not in str(failed.value)

    asyncio.run(exercise())


def test_a_master_forwards_the_upstream_socket_and_exits_through_its_control_socket(
    target: tuple[targets.ServerTarget, Path, Path],
) -> None:
    record, root, home = target
    ssh = write_fake_ssh(home / "bin")

    async def exercise() -> None:
        master = SshMaster(
            root, replace(record, remote_endpoint=str(home / "absent.sock")), ssh=str(ssh)
        )
        await master.ensure()
        upstream = root / "run" / "upstream.sock"
        assert upstream.exists()
        assert upstream.stat().st_mode & 0o777 == 0o600
        await master.ensure()  # already up: nothing restarted
        await master.close()
        assert not upstream.exists()

    asyncio.run(exercise())


def _stale_socket(path: Path) -> None:
    """A socket file nothing listens on: what a master whose connection dropped leaves behind."""

    import socket

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    stale = socket.socket(socket.AF_UNIX)
    stale.bind(str(path))
    stale.close()


def _connectable(path: Path) -> bool:
    import socket

    probe = socket.socket(socket.AF_UNIX)
    try:
        probe.connect(str(path))
    except OSError:
        return False
    finally:
        probe.close()
    return True


def test_a_new_master_binds_afresh_over_a_dropped_masters_stale_sockets(
    target: tuple[targets.ServerTarget, Path, Path],
) -> None:
    """Found in the real-environment run: after sshd came back the target stayed unreachable.

    The start used to stop waiting as soon as ``upstream.sock`` existed, so a stale one sent every
    connection to a socket nothing listened on, and the new master was stopped before it bound.
    """

    record, root, home = target
    ssh = write_fake_ssh(home / "bin")
    upstream = root / "run" / "upstream.sock"
    _stale_socket(upstream)
    _stale_socket(root / "run" / "m")
    assert not _connectable(upstream)

    async def exercise() -> None:
        master = SshMaster(
            root, replace(record, remote_endpoint=str(home / "absent.sock")), ssh=str(ssh)
        )
        await master.ensure()
        assert _connectable(upstream)
        await master.close()
        assert not upstream.exists()

    asyncio.run(exercise())


def test_a_master_that_outlived_its_connector_is_asked_to_exit_first(
    target: tuple[targets.ServerTarget, Path, Path],
) -> None:
    import subprocess
    import time

    record, root, home = target
    ssh = write_fake_ssh(home / "bin")
    forwarded = replace(record, remote_endpoint=str(home / "absent.sock"))
    upstream = root / "run" / "upstream.sock"
    (root / "run").mkdir(mode=0o700, parents=True, exist_ok=True)
    orphan = subprocess.Popen(  # noqa: S603 - the fixed argv of the stand-in
        list(master_argv(str(ssh), root, forwarded)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 10
        while not _connectable(upstream):
            assert time.monotonic() < deadline and orphan.poll() is None
            time.sleep(0.02)

        async def exercise() -> None:
            master = SshMaster(root, forwarded, ssh=str(ssh))
            await master.ensure()
            assert orphan.wait(timeout=10) == 0  # it left through its own control socket
            assert _connectable(upstream)
            await master.close()

        asyncio.run(exercise())
    finally:
        if orphan.poll() is None:
            orphan.kill()
            orphan.wait()


def test_only_an_owner_owned_socket_is_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    from finishup.client.ssh_upstream import remove_owned_socket

    # A short owner-only directory: pytest's tmp_path beneath CI's job temp is too long for the
    # AF_UNIX paths (``sun_path``) the stale sockets below are bound at.
    with ambient_home(monkeypatch) as home:
        base = home / "sockets"
        socket_path = base / "s.sock"
        _stale_socket(socket_path)
        regular = base / "regular"
        regular.write_bytes(b"")
        linked = base / "linked.sock"
        target_socket = base / "target.sock"
        _stale_socket(target_socket)
        linked.symlink_to(target_socket)

        remove_owned_socket(socket_path)
        remove_owned_socket(regular)
        remove_owned_socket(linked)
        remove_owned_socket(base / "absent.sock")

        assert not socket_path.exists()
        assert regular.exists()
        assert linked.is_symlink() and target_socket.exists()


def test_a_stopped_master_leaves_no_forward_behind(
    target: tuple[targets.ServerTarget, Path, Path],
) -> None:
    """OpenSSH leaves ``-L`` stream-local sockets behind when a master exits (as the stand-in
    does); the connector removes the forward itself, so no reader takes it for a live one."""

    record, root, home = target
    ssh = write_fake_ssh(home / "bin")
    upstream = root / "run" / "upstream.sock"

    async def exercise() -> None:
        master = SshMaster(
            root, replace(record, remote_endpoint=str(home / "absent.sock")), ssh=str(ssh)
        )
        for _lifecycle in range(2):
            await master.ensure()
            assert _connectable(upstream)
            await master.close()
            assert not upstream.exists()
            assert not (root / "run" / "m").exists()

    asyncio.run(exercise())


def test_readiness_is_a_new_forward_never_a_path_that_already_existed(
    target: tuple[targets.ServerTarget, Path, Path],
) -> None:
    """A stale forward the connector could not remove never counts as the new master's bind."""

    record, root, home = target
    upstream = root / "run" / "upstream.sock"
    _stale_socket(upstream)
    # A master that authenticates slowly and never binds before it is stopped.
    slow = home / "slow-ssh"
    slow.write_text("#!/bin/sh\nexec sleep 30\n", encoding="utf-8")
    slow.chmod(0o700)

    async def exercise() -> None:
        import finishup.client.ssh_upstream as ssh_upstream

        def keep(path: Path) -> None:
            del path

        master = SshMaster(root, record, ssh=str(slow))
        with pytest.MonkeyPatch.context() as patch:
            # Keep the stale socket in place (as if it could not be removed), and wait briefly.
            patch.setattr(ssh_upstream, "remove_owned_socket", keep)
            patch.setattr(ssh_upstream, "_MASTER_START_SECONDS", 0.5)
            with pytest.raises(UpstreamUnavailable) as failed:
                await master.ensure()
        assert failed.value.reason == "remote_unreachable"

    asyncio.run(exercise())


def test_disconnect_removes_the_forward_a_hard_killed_connector_left(
    target: tuple[targets.ServerTarget, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client.connector_runtime import ConnectorTargetRuntime

    _record, root, home = target
    write_fake_ssh(home / "bin")
    monkeypatch.setenv("PATH", f"{home / 'bin'}:/usr/bin:/bin")
    upstream = root / "run" / "upstream.sock"
    _stale_socket(upstream)
    _stale_socket(root / "run" / "m")

    ConnectorTargetRuntime().stop(root)

    assert not upstream.exists()
