"""Remote target runtimes of the direct-dial topology, and ``server add`` endpoint discovery.

SSH: ``ensure_ready`` starts the target's own master with the fixed argv, ``stop`` asks that
master by its control path (never anything found by pattern), and every OpenSSH failure is a
closed phase. HTTPS: ``ensure_ready`` asks the gateway with the stored key; nothing runs on the
client, so ``stop`` has nothing to stop. ``discover_ssh_endpoint`` asks the server's own
``service endpoint --json`` through a recorded or found launcher and refuses another release.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from builders.server_targets import ambient_home
from finishup.client import direct_runtime, targets
from finishup.client.direct_runtime import (
    HttpsTargetRuntime,
    SshTargetRuntime,
    discover_ssh_endpoint,
)
from finishup.client.target_runtime import ProbeResult, TargetRuntimeError
from finishup.client.targets import ServerTarget
from finishup.client.transports import TransportError, ssh_control_argv, ssh_master_argv
from finishup.protocol.schemas import schema_manifest_digest


class _Runner:
    """Records each argv and answers from a script of ``(code, stdout, stderr)``."""

    def __init__(self, *answers: tuple[int, bytes, bytes]) -> None:
        self.answers = list(answers)
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert kwargs["stdin"] is subprocess.DEVNULL and kwargs["check"] is False
        assert "FINISHUP_ISOLATED_ROOT" not in kwargs["env"]
        self.calls.append(list(argv))
        code, stdout, stderr = self.answers.pop(0)
        return subprocess.CompletedProcess(argv, code, stdout, stderr)


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
                remote_root="/srv/fu",
                remote_launcher="/opt/fu/bin/finishup",
            )
        yield record, root


def test_ensure_ready_starts_this_targets_master_then_its_service(
    ssh_root: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    record, root = ssh_root
    started: list[Path] = []
    monkeypatch.setattr(direct_runtime, "_ensure_service", started.append)
    runner = _Runner((0, b"", b""))
    SshTargetRuntime(runner=runner).ensure_ready(root)
    assert runner.calls == [list(ssh_master_argv(record, root))]
    assert started == [root]


def test_a_refused_master_is_a_closed_phase(
    ssh_root: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _record, root = ssh_root

    def skip(_root: Path) -> None:
        return None

    monkeypatch.setattr(direct_runtime, "_ensure_service", skip)
    runner = _Runner((255, b"", b"owner@lab.example: Permission denied (publickey).\r\n"))
    with pytest.raises(TargetRuntimeError) as raised:
        SshTargetRuntime(runner=runner).ensure_ready(root)
    assert (raised.value.reason, raised.value.phase) == (
        "service_unavailable",
        "remote_auth_failed",
    )
    assert "lab.example" not in str(raised.value)


def test_stop_asks_only_this_roots_master(ssh_root: tuple[ServerTarget, Path]) -> None:
    record, root = ssh_root
    runner = _Runner()
    SshTargetRuntime(runner=runner).stop(root)
    assert runner.calls == []  # no master was ever started here: nothing to stop
    (root / "run" / "m").touch()
    runner = _Runner((0, b"", b"Exit request sent.\r\n"))
    SshTargetRuntime(runner=runner).stop(root)
    assert runner.calls == [list(ssh_control_argv(record, root, "exit"))]
    gone = _Runner((255, b"", b"Control socket connect(...): No such file or directory\r\n"))
    SshTargetRuntime(runner=gone).stop(root)


def test_probe_times_the_real_transport(
    ssh_root: tuple[ServerTarget, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _record, root = ssh_root
    seen: list[Path | None] = []

    def probe(target_root: Path | None) -> ProbeResult:
        seen.append(target_root)
        return ProbeResult("ready", samples=10, round_trip_p95_ms=4)

    monkeypatch.setattr(direct_runtime, "probe_service", probe)
    assert SshTargetRuntime().probe(root).outcome == "ready"
    assert seen == [root]


def test_a_runtime_refuses_a_root_of_another_kind(
    ssh_root: tuple[ServerTarget, Path],
) -> None:
    _record, root = ssh_root
    with pytest.raises(TargetRuntimeError) as raised:
        HttpsTargetRuntime().stop(root)
    assert raised.value.reason == "target_record_invalid"
    with pytest.raises(TargetRuntimeError):
        SshTargetRuntime().probe(None)


def test_https_ensure_ready_needs_a_stored_key_and_asks_the_gateway(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, root = targets.new_remote_target("gw", "https", base_url="https://fu.example")
        with pytest.raises(TargetRuntimeError) as raised:
            HttpsTargetRuntime().ensure_ready(root)
        assert raised.value.phase == "remote_auth_failed"

        monkeypatch.setattr("finishup.client.credentials._platform_backend", lambda: None)
        from finishup.client.credentials import KeyringOrFileCredential

        key = "fuk_0123456789ab_" + "D" * 43
        location = KeyringOrFileCredential(record.target_id, root, recorded=None).store(key)
        targets.write_target(root, replace(record, credential=location))
        asked: list[str] = []

        async def info(_target: ServerTarget, secret: str) -> None:
            asked.append(secret)

        monkeypatch.setattr("finishup.client.https_binding.fetch_server_info", info)
        HttpsTargetRuntime().ensure_ready(root)
        assert asked == [key]

        async def refused(_target: ServerTarget, _secret: str) -> None:
            raise TransportError("remote_incompatible")

        monkeypatch.setattr("finishup.client.https_binding.fetch_server_info", refused)
        with pytest.raises(TargetRuntimeError) as raised:
            HttpsTargetRuntime().ensure_ready(root)
        assert raised.value.phase == "remote_incompatible"
        HttpsTargetRuntime().stop(root)


def _report(**overrides: object) -> bytes:
    report: dict[str, object] = {
        "schema": "yoetz.service-endpoint/1",
        "endpoint": "/run/user/1001/finishup/control.sock",
        "launcher": ["/opt/fu/bin/finishup"],
        "release": "0.3.0",
        "schema_manifest_digest": schema_manifest_digest(),
        "runtime_dir_session_bound": False,
        "linger": "enabled",
    }
    report.update(overrides)
    return json.dumps(report).encode()


def _discover(runner: _Runner, **arguments: Any) -> direct_runtime.SshEndpoint:
    values: dict[str, Any] = {
        "user": "owner",
        "host": "lab.example",
        "port": 2222,
        "remote_root": None,
        "remote_launcher": "/opt/fu/bin/finishup",
    }
    values.update(arguments)
    return discover_ssh_endpoint(runner=runner, **values)


def test_discovery_asks_the_servers_own_endpoint_report() -> None:
    runner = _Runner((0, _report(), b""))
    found = _discover(runner, remote_root="/srv/my fu")
    assert (found.endpoint, found.launcher, found.session_bound) == (
        "/run/user/1001/finishup/control.sock",
        "/opt/fu/bin/finishup",
        False,
    )
    (argv,) = runner.calls
    assert argv[:-1] == [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-T",
        "-p",
        "2222",
        "owner@lab.example",
        "--",
    ]
    assert argv[-1] == (
        "env 'FINISHUP_ISOLATED_ROOT=/srv/my fu' /opt/fu/bin/finishup service endpoint --json"
    )


def test_a_session_bound_endpoint_without_linger_is_flagged() -> None:
    runner = _Runner((0, _report(runtime_dir_session_bound=True, linger="disabled"), b""))
    assert _discover(runner).session_bound is True


def test_a_launcher_is_found_at_a_fixed_install_path_never_on_path() -> None:
    runner = _Runner((0, b"/home/owner/.local/bin/finishup\n", b""), (0, _report(), b""))
    found = _discover(runner, remote_launcher=None)
    assert found.launcher == "/home/owner/.local/bin/finishup"
    probe, ask = runner.calls
    assert probe[-1].startswith('for candidate in "$HOME/.local/bin/finishup"')
    assert "command -v" not in probe[-1] and "which" not in probe[-1]
    assert ask[-1] == "/home/owner/.local/bin/finishup service endpoint --json"


def test_no_launcher_falls_back_to_the_recorded_root_or_refuses() -> None:
    runner = _Runner((3, b"", b""))
    found = _discover(runner, remote_launcher=None, remote_root="/srv/fu")
    assert (found.endpoint, found.launcher) == ("/srv/fu/run/control.sock", None)
    assert len(runner.calls) == 1
    with pytest.raises(TargetRuntimeError) as raised:
        _discover(_Runner((3, b"", b"")), remote_launcher=None)
    assert raised.value.phase == "remote_service_not_running"


@pytest.mark.parametrize(
    ("answer", "phase"),
    [
        ((0, _report(schema_manifest_digest="sha256:" + "0" * 64), b""), "remote_incompatible"),
        ((0, b"not json", b""), "remote_incompatible"),
        ((0, _report(endpoint="relative/control.sock"), b""), "remote_incompatible"),
        ((127, b"", b"sh: 1: /opt/fu/bin/finishup: not found\n"), "remote_incompatible"),
        ((255, b"", b"Host key verification failed.\r\n"), "remote_identity_changed"),
        (
            (255, b"", b"ssh: connect to host lab.example port 2222: Connection refused\r\n"),
            "remote_unreachable",
        ),
    ],
)
def test_discovery_failures_are_closed_phases(answer: tuple[int, bytes, bytes], phase: str) -> None:
    with pytest.raises(TargetRuntimeError) as raised:
        _discover(_Runner(answer))
    assert (raised.value.reason, raised.value.phase) == ("service_unavailable", phase)
