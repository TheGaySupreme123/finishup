"""``server add`` asks an SSH server for its endpoint; ``server login`` checks an HTTPS key first.

ADR-051, approach A. The SSH probe is one interactive ``ssh`` (OpenSSH itself asks to confirm a new
host key) running the server's own ``finishup service endpoint --json``; the record keeps the
reported endpoint and an absolute launcher (never a bare ``finishup``), and a release mismatch
or a missing launcher writes nothing. ``server login`` stores a key only after ``GET /v1/server``
accepted it.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner, Result

from builders.control_relay import ScriptedDaemon, memory_pair, write_fake_ssh
from builders.server_targets import ambient_home
from finishup import __version__
from finishup.cli import app as cli
from finishup.cli import server as server_cli
from finishup.client import targets
from finishup.config.paths import reset_selection_memo
from finishup.gateway.app import build_gateway_app
from finishup.gateway.keys import create_key
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import schema_manifest_digest

_RUNNER = CliRunner()


def _confirmed(_name: str, _kind: str) -> None:
    return None


class _Audit:
    def write(self, record: dict[str, JsonValue]) -> None:
        del record


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        monkeypatch.setattr(server_cli, "_zero_network_in_force", lambda: False)
        monkeypatch.setattr(server_cli, "_confirm_on_trusted_console", _confirmed)
        yield root


def _invoke(*arguments: str) -> Result:
    reset_selection_memo()
    return _RUNNER.invoke(cli.app, ["server", *arguments])


def _launcher(path: Path, *, digest: str, launcher: list[JsonValue]) -> Path:
    report: dict[str, JsonValue] = {
        "schema": "yoetz.service-endpoint/1",
        "endpoint": "/run/user/1000/finishup/control.sock",
        "launcher": launcher,
        "release": "9.9.9",
        "schema_manifest_digest": digest,
        "runtime_dir_session_bound": False,
        "linger": "enabled",
    }
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\ncat <<'EOF'\n{json.dumps(report)}\nEOF\n", encoding="utf-8")
    path.chmod(0o700)
    return path


@pytest.fixture
def fake_ssh(home: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bin_dir = home / "bin"
    write_fake_ssh(bin_dir)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    log = home / "ssh.log"
    monkeypatch.setenv("FAKE_SSH_LOG", str(log))
    return log


def test_an_ssh_add_records_the_servers_own_endpoint(home: Path, fake_ssh: Path) -> None:
    launcher = _launcher(
        home / "srv" / "finishup", digest=schema_manifest_digest(), launcher=["/ignored"]
    )
    result = _invoke(
        "add", "lab", "ssh://owner@lab.example:2222", "--remote-launcher", str(launcher)
    )
    assert result.exit_code == 0, result.output
    (record,) = targets.list_targets()
    assert record.remote_endpoint == "/run/user/1000/finishup/control.sock"
    assert record.remote_launcher == str(launcher)
    (probe,) = fake_ssh.read_text(encoding="utf-8").splitlines()
    assert "StrictHostKeyChecking=ask" in probe and "BatchMode" not in probe
    assert probe.endswith(f"{launcher} service endpoint --json")


def test_without_a_launcher_the_servers_reported_absolute_launcher_is_kept(
    home: Path, fake_ssh: Path
) -> None:
    _launcher(
        home / "bin" / "finishup",
        digest=schema_manifest_digest(),
        launcher=["/opt/finishup/bin/finishup"],
    )
    result = _invoke("add", "lab", "ssh://lab.example")
    assert result.exit_code == 0, result.output
    (record,) = targets.list_targets()
    assert record.remote_launcher == "/opt/finishup/bin/finishup"


def test_a_server_of_another_release_is_refused_and_nothing_is_written(
    home: Path, fake_ssh: Path
) -> None:
    launcher = _launcher(home / "srv" / "finishup", digest="sha256:" + "0" * 64, launcher=[])
    result = _invoke("add", "lab", "ssh://owner@lab.example", "--remote-launcher", str(launcher))
    assert result.exit_code == 20
    assert result.stderr.startswith("remote_incompatible:")
    assert f"client {__version__}, server 9.9.9" in result.stderr
    assert "lab.example" not in result.stderr and "owner" not in result.stderr
    assert targets.list_targets() == ()


def test_an_unknown_launcher_asks_for_an_absolute_one(home: Path, fake_ssh: Path) -> None:
    result = _invoke("add", "lab", "ssh://lab.example")
    assert result.exit_code == 2
    assert result.stderr.startswith("remote_launcher_unknown:")
    assert targets.list_targets() == ()
    relative = _launcher(
        home / "bin" / "finishup", digest=schema_manifest_digest(), launcher=["python", "-m"]
    )
    del relative
    again = _invoke("add", "lab", "ssh://lab.example")
    assert again.stderr.startswith("remote_launcher_unknown:")


def test_login_stores_a_key_only_after_the_gateway_accepted_it(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("finishup.client.credentials._platform_backend", lambda: None)
    keys = home / "gateway"
    _record, key = create_key(keys, label="laptop", scope="agent")

    async def connect_upstream() -> object:
        client, server = memory_pair()
        asyncio.get_running_loop().create_task(ScriptedDaemon().serve(server))
        return client

    _state, app = build_gateway_app(
        keys_directory=keys,
        connect_upstream=connect_upstream,  # type: ignore[arg-type]
        audit=_Audit(),
    )

    def in_process(_record: targets.ServerTarget) -> httpx.AsyncBaseTransport:
        return httpx.ASGITransport(app=app)

    monkeypatch.setattr("finishup.client.https_upstream._transport_for", in_process)
    assert _invoke("add", "fu", "https://fu.example").exit_code == 0
    wrong = home / "wrong"
    wrong.write_text("fuk_000000000000_" + "A" * 43, encoding="ascii")
    wrong.chmod(0o600)
    refused = _invoke("login", "fu", "--key-file", str(wrong))
    assert refused.exit_code == 20
    assert refused.stderr.startswith("remote_auth_failed:")
    assert targets.list_targets()[0].credential is None
    good = home / "good"
    good.write_text(key, encoding="ascii")
    good.chmod(0o600)
    accepted = _invoke("login", "fu", "--key-file", str(good))
    assert accepted.exit_code == 0, accepted.output
    assert targets.list_targets()[0].credential == "file"
    assert key not in accepted.output
