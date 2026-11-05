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
    assert ssh_root_fits(Path("/home/owner/.local/state/finishup/servers/t_01234567"))
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
