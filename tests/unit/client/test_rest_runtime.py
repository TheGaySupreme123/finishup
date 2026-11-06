"""Remote target runtimes of the server-native API (ADR-051): the SSH master and HTTPS endpoints.

No ssh runs here: ``_run`` is replaced by a recorder. The master's argv is fixed and secret-free
and forwards a Unix socket to the server's owner-only API socket; ``server add`` learns that
socket (and the launcher) from ``service endpoint --json``; ssh failures become closed reasons;
``disconnect`` stops the master through its control socket and the agent by its stamped pid.
"""

from __future__ import annotations

import base64
import json
import socket
import subprocess
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from builders.server_targets import ambient_home
from finishup.client import rest_runtime, targets
from finishup.client.rest_client import RestEndpoint, rest_endpoint_for
from finishup.client.rest_runtime import (
    SshTargetRuntime,
    discover_ssh_endpoint,
    ssh_master_argv,
)
from finishup.client.target_runtime import TargetRuntimeError
from finishup.client.targets import ServerTarget
from finishup.ports.control import ControlError

_SALT = base64.b64encode(b"\x02" * 32).decode("ascii")


def _ssh_record(**overrides: object) -> ServerTarget:
    values: dict[str, object] = {
        "user": "owner",
        "host": "lab.example",
        "port": 2222,
        "remote_endpoint": "/srv/finishup/run/api.sock",
        "remote_launcher": "/home/owner/.local/bin/finishup",
        "remote_root": None,
    }
    values.update(overrides)
    return ServerTarget(
        "t_0a1b2c3d",
        "lab",
        "ssh",
        "2026-11-05T00:00:00.000Z",
        claim_salt=_SALT,
        authorized_at="2026-11-05T00:00:00.000Z",
        disclosure_version=1,
        **values,  # type: ignore[arg-type]
    )


class _Recorder:
    def __init__(self, *results: tuple[int, bytes, bytes]) -> None:
        self.calls: list[tuple[list[str], bool]] = []
        self._results = list(results)

    def __call__(
        self, argv: list[str], *, timeout: float, detaches: bool = False
    ) -> subprocess.CompletedProcess[bytes]:
        del timeout
        self.calls.append((argv, detaches))
        code, stdout, stderr = self._results.pop(0) if self._results else (0, b"", b"")
        return subprocess.CompletedProcess(argv, code, stdout, stderr)


def test_the_master_argv_is_fixed_and_forwards_the_api_socket() -> None:
    root = Path("/state/servers/t_0a1b2c3d")
    assert ssh_master_argv(_ssh_record(), root) == [
        "ssh",
        "-f",
        "-N",
        "-M",
        "-S",
        "/state/servers/t_0a1b2c3d/run/m",
        "-o",
        "ControlPersist=900",
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
        "/state/servers/t_0a1b2c3d/run/api.sock:/srv/finishup/run/api.sock",
        "--",
        "owner@lab.example",
    ]
    for endpoint in (None, "/srv/with:colon/api.sock", "/srv/with space/api.sock"):
        with pytest.raises(TargetRuntimeError):
            ssh_master_argv(_ssh_record(remote_endpoint=endpoint), root)


def test_discovery_reads_the_api_socket_and_the_launcher_that_answered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report: dict[str, object] = {
        "schema": "yoetz.service-endpoint/1",
        "endpoint": "/run/user/1000/finishup/control.sock",
        "network": {"api_socket": "/run/user/1000/finishup/api.sock", "listen": [], "tls": False},
    }
    recorder = _Recorder(
        (0, b"/home/owner/.local/bin/finishup\n" + json.dumps(report).encode(), b"")
    )
    monkeypatch.setattr(rest_runtime, "_run", recorder)
    found = discover_ssh_endpoint(
        user=None, host="lab.example", port=22, remote_root="/srv/x y", remote_launcher=None
    )
    assert (found.api_socket, found.launcher) == (
        "/run/user/1000/finishup/api.sock",
        "/home/owner/.local/bin/finishup",
    )
    ((argv, detaches),) = recorder.calls
    assert not detaches
    assert argv[:9] == [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-p",
        "22",
        "--",
        "lab.example",
    ]
    command = argv[9]
    # Never a bare ``finishup`` from the remote PATH; the isolated root is pinned and quoted.
    assert "exec env FINISHUP_ISOLATED_ROOT='/srv/x y' \"$p\" service endpoint --json" in command
    assert command.endswith("exit 127")


@pytest.mark.parametrize(
    ("result", "reason", "phase"),
    [
        ((255, b"", b"owner@lab: Permission denied (publickey)."), "remote_auth_failed", None),
        ((255, b"", b"Host key verification failed."), "remote_identity_changed", None),
        (
            (255, b"", b"ssh: connect to host lab port 22: Connection refused"),
            "remote_unreachable",
            None,
        ),
        ((127, b"", b""), "remote_incompatible", "launcher_not_found"),
        (
            (0, b'{"schema":"yoetz.service-endpoint/1"}', b""),
            "remote_incompatible",
            "api_socket_unconfigured",
        ),
        ((0, b"not json", b""), "remote_incompatible", "endpoint_report_invalid"),
    ],
)
def test_discovery_failures_are_closed_reasons(
    monkeypatch: pytest.MonkeyPatch,
    result: tuple[int, bytes, bytes],
    reason: str,
    phase: str | None,
) -> None:
    monkeypatch.setattr(rest_runtime, "_run", _Recorder(result))
    with pytest.raises(TargetRuntimeError) as raised:
        discover_ssh_endpoint(
            user="owner",
            host="lab.example",
            port=22,
            remote_root=None,
            remote_launcher="/opt/finishup/bin/finishup",
        )
    assert raised.value.reason == reason
    if phase is not None:
        assert raised.value.phase == phase
    assert "lab" not in str(raised.value)


@pytest.fixture
def ssh_root(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[ServerTarget, Path]]:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "lab",
                "ssh",
                user="owner",
                host="lab.example",
                port=2222,
                remote_launcher="/home/owner/.local/bin/finishup",
            )
        record = replace(record, remote_endpoint="/srv/finishup/run/api.sock")
        targets.write_target(root, record)
        yield record, root


def test_the_master_starts_once_and_stops_through_its_control_socket(
    ssh_root: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = ssh_root
    recorder = _Recorder((0, b"", b""))
    monkeypatch.setattr(rest_runtime, "_run", recorder)
    runtime = SshTargetRuntime()
    runtime.ensure_master(record, root)
    ((argv, detaches),) = recorder.calls
    assert detaches and argv == ssh_master_argv(record, root)

    # The master is up and its forward is in place: nothing new is started.
    (root / "run" / "m").touch()
    forwarded = socket.socket(socket.AF_UNIX)
    forwarded.bind(str(root / "run" / "api.sock"))
    forwarded.close()
    runtime.ensure_master(record, root)
    assert recorder.calls[-1][0][-4:] == ["-O", "check", "--", "owner@lab.example"]
    assert len(recorder.calls) == 2

    stopped: list[Path] = []

    def stop_agent(path: Path) -> bool:
        stopped.append(path)
        return True

    monkeypatch.setattr("finishup.client.agent.stop_agent", stop_agent)
    runtime.stop(root)
    assert stopped == [root]
    assert recorder.calls[-1][0][-4:] == ["-O", "exit", "--", "owner@lab.example"]
    assert not (root / "run" / "api.sock").exists()


def test_a_master_that_cannot_start_names_why(
    ssh_root: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = ssh_root
    monkeypatch.setattr(
        rest_runtime, "_run", _Recorder((255, b"", b"Host key verification failed."))
    )
    with pytest.raises(TargetRuntimeError) as raised:
        SshTargetRuntime().ensure_master(record, root)
    assert raised.value.reason == "remote_identity_changed"
    probe = SshTargetRuntime()
    monkeypatch.setattr(rest_runtime, "_run", _Recorder((255, b"", b"Permission denied")))
    result = probe.probe(root)
    assert (result.outcome, result.reason) == ("unavailable", "remote_auth_failed")


def test_an_idle_stopped_remote_service_is_started_with_its_launcher(
    ssh_root: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = ssh_root
    recorder = _Recorder((0, b"", b""))
    monkeypatch.setattr(rest_runtime, "_run", recorder)
    SshTargetRuntime().start_remote_service(record, root)
    ((argv, _detaches),) = recorder.calls
    assert argv[-2:] == ["owner@lab.example", "/home/owner/.local/bin/finishup service start"]
    assert argv[:3] == ["ssh", "-S", str(root / "run" / "m")]


def test_rest_endpoints_follow_the_record(
    ssh_root: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = ssh_root
    endpoint = rest_endpoint_for(record, root)
    assert (endpoint.kind, endpoint.credential) == ("ssh", None)
    assert isinstance(endpoint, RestEndpoint)
    with targets.registry_lock():
        https, https_root = targets.new_remote_target(
            "web", "https", base_url="https://fu.example", tls_pin="sha256:" + "a" * 64
        )
    # No stored key: the remote refuses this client before any request.
    with pytest.raises(ControlError) as raised:
        rest_endpoint_for(https, https_root)
    assert raised.value.phase == "remote_auth_failed"

    def stored_key(_self: object) -> str:
        return "k" * 32

    monkeypatch.setattr("finishup.client.credentials.KeyringOrFileCredential.read", stored_key)
    pinned = rest_endpoint_for(https, https_root)
    assert pinned.pin_mismatch is not None and pinned.credential == "k" * 32
    assert "k" * 32 not in repr(pinned)


def test_the_probe_samples_round_trips_after_the_first_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The first call of a process also loads its protocol validators (a local connection does
    # that in its hello). Sampled, it alone pushed a 20 ms target's p95 past the 200 ms warning.
    from finishup.client.target_runtime import PROBE_SAMPLES
    from finishup.ports.control import ServiceState, ServiceStatus

    clock = [100.0]
    calls: list[int] = []

    class _Client:
        async def service_status(self) -> ServiceStatus:
            calls.append(len(calls))
            clock[0] += 0.4 if len(calls) == 1 else 0.02
            return ServiceStatus(
                "1.0",
                "0.3.0",
                "svc_00000000-0000-4000-8000-000000000051",
                "1",
                ServiceState.READY,
                "none",
                "passphrase",
                (),
                "unavailable",
            )

        async def close(self) -> None:
            return None

    async def connect(*_args: object, **_kwargs: object) -> _Client:
        return _Client()

    monkeypatch.setattr("finishup.client.rest_client.connect_rest_service", connect)
    monkeypatch.setattr(rest_runtime.time, "monotonic", lambda: clock[0])
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            _record, root = targets.new_remote_target(
                "web", "https", base_url="https://fu.example", tls_pin="sha256:" + "a" * 64
            )
        result = rest_runtime.RestTargetRuntime().probe(root)
    assert result.outcome == "ready"
    assert len(calls) == PROBE_SAMPLES + 1
    assert (result.samples, result.round_trip_p95_ms) == (PROBE_SAMPLES, 20)
