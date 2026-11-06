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
        "remote_launcher": "/srv/owner/.local/bin/finishup",
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
        self.timeouts: list[float] = []
        self._results = list(results)

    def __call__(
        self, argv: list[str], *, timeout: float, detaches: bool = False
    ) -> subprocess.CompletedProcess[bytes]:
        self.timeouts.append(timeout)
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
        "ConnectTimeout=10",
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
        (0, b"/srv/owner/.local/bin/finishup\n" + json.dumps(report).encode(), b"")
    )
    monkeypatch.setattr(rest_runtime, "_run", recorder)
    found = discover_ssh_endpoint(
        user=None, host="lab.example", port=22, remote_root="/srv/x y", remote_launcher=None
    )
    assert (found.api_socket, found.launcher) == (
        "/run/user/1000/finishup/api.sock",
        "/srv/owner/.local/bin/finishup",
    )
    ((argv, detaches),) = recorder.calls
    assert not detaches
    assert argv[:11] == [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=10",
        "-p",
        "22",
        "--",
        "lab.example",
    ]
    command = argv[11]
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
        (
            (0, b'{"network":"config_invalid","schema":"yoetz.service-endpoint/1"}', b""),
            "remote_incompatible",
            "server_config_invalid",
        ),
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
                remote_launcher="/srv/owner/.local/bin/finishup",
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
    assert argv[-2:] == ["owner@lab.example", "/srv/owner/.local/bin/finishup service start"]
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


def _bind(path: Path) -> None:
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(path))
    listener.close()


def _check(argv: list[str]) -> bool:
    return argv[-4:-2] == ["-O", "check"]


def test_concurrent_clients_start_one_master_and_never_a_second_one(
    ssh_root: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A second ``ssh -M`` that finds the control socket would run on as a plain session that no
    # ``-O exit`` reaches. Under the target's lock the second client finds the first's master.
    import threading

    record, root = ssh_root
    calls: list[list[str]] = []
    entered = threading.Event()
    release = threading.Event()

    def fake_run(
        argv: list[str], *, timeout: float, detaches: bool = False
    ) -> subprocess.CompletedProcess[bytes]:
        del timeout
        calls.append(argv)
        if detaches:
            entered.set()
            assert release.wait(10)
            _bind(root / "run" / "m")
            _bind(root / "run" / "api.sock")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(rest_runtime, "_run", fake_run)
    first = threading.Thread(target=SshTargetRuntime().ensure_master, args=(record, root))
    first.start()
    assert entered.wait(10)
    second = threading.Thread(target=SshTargetRuntime().ensure_master, args=(record, root))
    second.start()
    release.set()
    first.join(10)
    second.join(10)
    masters = [argv for argv in calls if "-M" in argv]
    assert len(masters) == 1
    assert _check(calls[-1])


def test_a_live_master_that_lost_its_forward_gets_it_back_without_a_second_master(
    ssh_root: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = ssh_root
    _bind(root / "run" / "m")
    recorder = _Recorder((0, b"", b""), (0, b"", b""))
    monkeypatch.setattr(rest_runtime, "_run", recorder)
    SshTargetRuntime().ensure_master(record, root)
    (check, _), (forward, detaches) = recorder.calls
    assert _check(check)
    assert not detaches and "-M" not in forward
    assert forward[forward.index("-O") : forward.index("-O") + 4] == [
        "-O",
        "forward",
        "-L",
        f"{root / 'run' / 'api.sock'}:/srv/finishup/run/api.sock",
    ]


def test_a_stale_control_socket_is_removed_only_after_its_master_stopped_answering(
    ssh_root: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = ssh_root
    _bind(root / "run" / "m")
    recorder = _Recorder((255, b"", b"Control socket connect: Connection refused"), (0, b"", b""))
    removed_before_start: list[bool] = []

    def run(
        argv: list[str], *, timeout: float, detaches: bool = False
    ) -> subprocess.CompletedProcess[bytes]:
        if detaches:
            removed_before_start.append(not (root / "run" / "m").exists())
        return recorder(argv, timeout=timeout, detaches=detaches)

    monkeypatch.setattr(rest_runtime, "_run", run)
    SshTargetRuntime().ensure_master(record, root)
    assert [_check(argv) for argv, _ in recorder.calls] == [True, False]
    assert removed_before_start == [True]
    # Something that is not this user's socket is never removed, and no master is started.
    (root / "run" / "m").write_bytes(b"")
    monkeypatch.setattr(rest_runtime, "_run", _Recorder((255, b"", b"")))
    with pytest.raises(TargetRuntimeError) as raised:
        SshTargetRuntime().ensure_master(record, root)
    assert (raised.value.reason, raised.value.phase) == ("remote_unreachable", "target_root_unsafe")
    assert (root / "run" / "m").exists()


def test_the_master_runs_within_the_callers_budget(
    ssh_root: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = ssh_root
    recorder = _Recorder((0, b"", b""))
    monkeypatch.setattr(rest_runtime, "_run", recorder)
    SshTargetRuntime().ensure_master(record, root, timeout=3.5)
    ((argv, _),) = recorder.calls
    assert "ConnectTimeout=3" in argv
    assert recorder.timeouts[0] <= 3.5
    with pytest.raises(TargetRuntimeError) as raised:
        SshTargetRuntime().start_remote_service(record, root, timeout=0.0)
    assert (raised.value.reason, raised.value.phase) == ("remote_unreachable", "ssh_timeout")


def test_an_unreachable_server_fails_the_next_connections_at_once(
    ssh_root: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = ssh_root
    monkeypatch.setattr(
        rest_runtime, "_run", _Recorder((255, b"", b"connect to host: Connection timed out"))
    )
    with pytest.raises(TargetRuntimeError) as first:
        SshTargetRuntime().ensure_master(record, root)
    assert (first.value.reason, first.value.phase) == ("remote_unreachable", "ssh_connect")
    remembered = (root / "run" / "m.failed").read_text(encoding="ascii")
    assert remembered == "remote_unreachable:ssh_connect\n"
    quiet = _Recorder()
    monkeypatch.setattr(rest_runtime, "_run", quiet)
    with pytest.raises(TargetRuntimeError) as again:
        SshTargetRuntime().ensure_master(record, root)
    assert (again.value.reason, again.value.phase) == ("remote_unreachable", "ssh_connect")
    assert quiet.calls == []
    # The owner asking now (``server connect``/``test``) is never answered from memory, and a
    # master that starts clears it.
    SshTargetRuntime().ensure_master(record, root, honor_recent_failure=False)
    assert len(quiet.calls) == 1
    assert not (root / "run" / "m.failed").exists()
    # An authentication refusal is not remembered: the owner may load a key and retry at once.
    monkeypatch.setattr(rest_runtime, "_run", _Recorder((255, b"", b"Permission denied")))
    with pytest.raises(TargetRuntimeError):
        SshTargetRuntime().ensure_master(record, root)
    assert not (root / "run" / "m.failed").exists()


def test_restoring_the_transport_is_for_ssh_targets_only(
    ssh_root: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    record, root = ssh_root
    recorder = _Recorder((0, b"", b""))
    monkeypatch.setattr(rest_runtime, "_run", recorder)
    https = ServerTarget(
        record.target_id,
        "lab",
        "https",
        record.created_at,
        base_url="https://lab.example",
        claim_salt=_SALT,
        authorized_at=record.created_at,
        disclosure_version=1,
    )
    asyncio.run(rest_runtime.restore_ssh_transport(https, root))
    assert recorder.calls == []
    asyncio.run(rest_runtime.restore_ssh_transport(record, root))
    assert recorder.calls[0][0] == ssh_master_argv(record, root)


def test_a_connection_gives_the_ssh_steps_only_what_is_left_of_its_budget(
    ssh_root: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    from finishup.config.paths import reset_selection_memo
    from finishup.ports.control import ControlClientKind
    from finishup.service import client as client_module

    record, _root = ssh_root
    with targets.registry_lock():
        targets.write_selection(record)
    reset_selection_memo()
    budgets: list[tuple[str, float]] = []

    async def unreachable(*_args: object, **_options: object) -> object:
        raise ControlError("service_unavailable", retryable=True, phase="remote_unreachable")

    def master(_self: object, _record: object, _root: object, *, timeout: float) -> None:
        budgets.append(("master", timeout))

    def start(_self: object, _record: object, _root: object, *, timeout: float) -> None:
        budgets.append(("start", timeout))

    def no_spawn() -> object:
        raise AssertionError("a remote target never spawns a local service")

    monkeypatch.setattr("finishup.client.rest_client.connect_rest_service", unreachable)
    monkeypatch.setattr(SshTargetRuntime, "ensure_master", master)
    monkeypatch.setattr(SshTargetRuntime, "start_remote_service", start)
    monkeypatch.setattr(client_module, "_spawn_service_process", no_spawn)
    with pytest.raises(ControlError) as raised:
        asyncio.run(
            client_module.connect_service_on_demand(
                ControlClientKind.CLI, workspace_locator=None, timeout_seconds=2.0
            )
        )
    assert raised.value.phase == "remote_unreachable"
    assert [step for step, _ in budgets] == ["master", "start"]
    assert all(0 < budget <= 2.0 for _, budget in budgets)
