"""``finishup service api-key`` and ``service endpoint --json`` for the network API (ADR-051).

The key commands edit the service's own key file on the server host: ``create`` shows the key
once (or writes a new owner-only file), ``list`` never shows a key, ``revoke`` is the reverse.
They are ``server_host`` commands, refused on a remote target. ``service endpoint --json`` reports
the configured API socket only when ``[network]`` asks for one.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

from builders.server_targets import ambient_home
from finishup.cli import app as cli
from finishup.config.paths import config_file_path, runtime_dir
from finishup.service.api_keys import default_api_key_store
from finishup.service.network_protocol import parse_api_key

_RUNNER = CliRunner()


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def test_create_list_and_revoke_keys(home: Path) -> None:
    created = _RUNNER.invoke(
        cli.app, ["service", "api-key", "create", "--label", "laptop", "--scope", "agent"]
    )
    assert created.exit_code == 0, created.output
    lines = created.stdout.splitlines()
    token = lines[1]
    parsed = parse_api_key(token)
    assert parsed is not None and parsed.key_id in lines[0]
    assert token.encode() not in default_api_key_store().path.read_bytes()

    listed = _RUNNER.invoke(cli.app, ["service", "api-key", "list", "--json"])
    assert listed.exit_code == 0, listed.output
    document = cast(dict[str, object], json.loads(listed.stdout))
    (row,) = cast(list[dict[str, object]], document["keys"])
    assert (row["key_id"], row["label"], row["scope"], row["state"]) == (
        parsed.key_id,
        "laptop",
        "agent",
        "active",
    )
    assert token not in listed.stdout

    revoked = _RUNNER.invoke(cli.app, ["service", "api-key", "revoke", parsed.key_id])
    assert revoked.exit_code == 0
    again = _RUNNER.invoke(cli.app, ["service", "api-key", "revoke", parsed.key_id])
    assert "already revoked" in again.stdout
    unknown = _RUNNER.invoke(cli.app, ["service", "api-key", "revoke", "not-a-key-id"])
    assert unknown.exit_code == 2
    assert unknown.stderr.startswith("api_key_unknown:")
    assert "not-a-key-id" not in unknown.stderr


def test_a_key_can_be_written_once_to_a_new_owner_only_file(home: Path) -> None:
    target = home / "operator.key"
    created = _RUNNER.invoke(
        cli.app,
        [
            "service",
            "api-key",
            "create",
            "--label",
            "ops",
            "--scope",
            "operator",
            "--output-file",
            str(target),
        ],
    )
    assert created.exit_code == 0, created.output
    assert target.stat().st_mode & 0o777 == 0o600
    token = target.read_text(encoding="ascii").strip()
    assert parse_api_key(token) is not None and token not in created.stdout
    refused = _RUNNER.invoke(
        cli.app,
        [
            "service",
            "api-key",
            "create",
            "--label",
            "ops2",
            "--scope",
            "operator",
            "--output-file",
            str(target),
        ],
    )
    assert refused.exit_code == 2
    assert refused.stderr.startswith("output_file_unavailable:")


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        (["--label", "x", "--scope", "root"], "api_key_scope_invalid"),
        (["--label", "bad\tlabel", "--scope", "agent"], "api_key_label_invalid"),
        (["--label", "x", "--scope", "agent", "--expires-in-days", "0"], "api_key_expiry_invalid"),
        (["--label", "x", "--scope", "agent", "--rotate", "ffffffffffff"], "api_key_unknown"),
    ],
)
def test_create_refusals_are_closed_reasons(home: Path, arguments: list[str], reason: str) -> None:
    result = _RUNNER.invoke(cli.app, ["service", "api-key", "create", *arguments])
    assert result.exit_code == 2
    assert result.stderr.startswith(f"{reason}:")
    assert "bad\tlabel" not in result.stderr and "ffffffffffff" not in result.stderr


def test_key_commands_belong_to_the_server_host(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client.targets import ServerTarget

    record = ServerTarget(
        "t_0a1b2c3d",
        "lab",
        "https",
        "2026-11-05T00:00:00.000Z",
        base_url="https://lab.example",
        claim_salt="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        authorized_at="2026-11-05T00:00:00.000Z",
        disclosure_version=1,
    )
    monkeypatch.setattr(
        "finishup.client.targets.active_root_record", lambda: (Path("/r/t_0a1b2c3d"), record)
    )
    result = _RUNNER.invoke(cli.app, ["service", "api-key", "list"])
    assert result.exit_code == 2
    assert "requires_server_host" in result.stderr
    assert "lab.example" not in result.stderr


def test_endpoint_reports_the_api_socket_only_when_configured(home: Path) -> None:
    plain = _RUNNER.invoke(cli.app, ["service", "endpoint", "--json"])
    assert plain.exit_code == 0, plain.output
    assert "network" not in json.loads(plain.stdout)
    path = config_file_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text("[network]\napi_socket = true\n", encoding="utf-8")
    configured = _RUNNER.invoke(cli.app, ["service", "endpoint", "--json"])
    assert configured.exit_code == 0, configured.output
    network = json.loads(configured.stdout)["network"]
    assert network == {
        "api_socket": str(runtime_dir() / "api.sock"),
        "listen": [],
        "tls": False,
    }
    path.write_text('[network]\nlisten = ["10.0.0.1:443"]\n', encoding="utf-8")
    broken = _RUNNER.invoke(cli.app, ["service", "endpoint", "--json"])
    assert broken.exit_code == 2
    assert broken.stderr.startswith("config_invalid: network_tls_required")
