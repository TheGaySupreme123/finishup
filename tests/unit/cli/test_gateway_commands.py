"""``finishup service gateway`` and ``finishup connector`` on the command line (ADR-051, approach A).

A key is shown once on the trusted console or written to a new owner-only file, never echoed
otherwise; ``key list`` never shows a secret; ``key revoke`` is the reverse of ``key create``. The
gateway refuses plain HTTP off loopback before anything listens. Both gateway commands are
``server_host`` (refused while a remote target is selected); ``connector run`` refuses a root that
is not a remote target's own with a fixed line.
"""

from __future__ import annotations

import errno
import json
import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from builders.server_targets import ambient_home
from finishup.cli import app as cli
from finishup.cli import gateway as gateway_cli
from finishup.client import targets
from finishup.config.paths import reset_selection_memo
from finishup.gateway.keys import KeyRing
from finishup.protocol.rest_binding import API_KEY_PATTERN

_RUNNER = CliRunner()


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def _invoke(*arguments: str) -> Result:
    reset_selection_memo()
    return _RUNNER.invoke(cli.app, list(arguments))


def _keys(home: Path) -> Path:
    return home / "state" / "finishup" / "gateway"


def test_a_key_is_written_once_to_a_new_owner_only_file(home: Path) -> None:
    output = home / "laptop.key"
    created = _invoke(
        "service", "gateway", "key", "create", "--label", "laptop", "--scope", "agent",
        "--output-file", str(output),
    )  # fmt: skip
    assert created.exit_code == 0, created.output
    key = output.read_text(encoding="ascii").strip()
    assert API_KEY_PATTERN.match(key)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert key not in created.output and key.split("_")[2] not in created.output
    assert not isinstance(KeyRing(_keys(home)).authenticate(key), str)

    again = _invoke(
        "service", "gateway", "key", "create", "--label", "other", "--scope", "agent",
        "--output-file", str(output),
    )  # fmt: skip
    assert again.exit_code == 2
    assert again.stderr.startswith("gateway_key_output_exists:")
    # Refused before a key was made: nothing exists whose secret was never delivered.

    listed = _invoke("service", "gateway", "key", "list", "--json")
    assert listed.exit_code == 0
    (row,) = json.loads(listed.stdout)["keys"]
    assert row["label"] == "laptop" and row["revoked_at"] is None
    assert key.split("_")[2] not in listed.output

    revoked = _invoke("service", "gateway", "key", "revoke", row["key_id"])
    assert revoked.exit_code == 0
    assert KeyRing(_keys(home)).authenticate(key) == "api_key_revoked"


def test_without_an_output_file_a_key_needs_the_trusted_console(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shown: list[str] = []
    monkeypatch.setattr(gateway_cli, "_show_on_console", shown.append)
    monkeypatch.setattr(gateway_cli, "_stdin_is_terminal", lambda: True)
    created = _invoke("service", "gateway", "key", "create", "--label", "ci", "--scope", "operator")
    assert created.exit_code == 0, created.output
    (key,) = shown
    assert key not in created.output
    monkeypatch.setattr(gateway_cli, "_stdin_is_terminal", lambda: False)
    refused = _invoke("service", "gateway", "key", "create", "--label", "ci", "--scope", "agent")
    assert refused.exit_code == 2
    assert refused.stderr.startswith("trusted_console_required:")


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        (("--listen", "0.0.0.0:8443"), "gateway_tls_required"),
        (("--listen", "0.0.0.0:8443", "--behind-proxy"), "gateway_proxy_not_loopback"),
        (("--listen", "gateway.example:8443", "--behind-proxy"), "gateway_listen_invalid"),
        (("--listen", "127.0.0.1:0", "--behind-proxy"), "gateway_listen_invalid"),
    ],
)
def test_the_gateway_refuses_plain_http_off_loopback_before_listening(
    home: Path, arguments: tuple[str, ...], reason: str
) -> None:
    result = _invoke("service", "gateway", "run", *arguments)
    assert result.exit_code == 2
    assert result.stderr.startswith(f"{reason}:")


def test_gateway_commands_belong_to_the_server_host(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with targets.registry_lock():
        record, _root = targets.new_remote_target("gw", "https", base_url="https://gw.example")
        targets.write_selection(record)
    for arguments in (
        ("service", "gateway", "key", "list"),
        ("service", "gateway", "run", "--listen", "127.0.0.1:8443", "--behind-proxy"),
    ):
        result = _invoke(*arguments)
        assert result.exit_code != 0
        assert result.stderr.startswith("requires_server_host:")
        assert "gw.example" not in result.stderr


def test_connector_run_refuses_a_root_that_is_not_a_remote_targets_own(home: Path) -> None:
    result = _invoke("connector", "run", "--root", str(home))
    assert result.exit_code == 2
    assert result.stderr.startswith("connector_root_invalid:")
    assert str(home) not in result.stderr


def test_key_list_shows_an_expired_key_as_expired(home: Path) -> None:
    """The gateway refuses an expired key (``api_key_expired``); the list must not call it
    active."""

    from datetime import UTC, datetime, timedelta

    from finishup.gateway.keys import create_key, revoke_key

    directory = _keys(home)
    expired, _secret = create_key(
        directory,
        label="old-laptop",
        scope="agent",
        expires_in_days=1,
        now=datetime.now(UTC) - timedelta(days=2),
    )
    active, _secret = create_key(directory, label="laptop", scope="agent", expires_in_days=30)
    revoked, _secret = create_key(directory, label="lost", scope="operator")
    revoke_key(directory, revoked.key_id)

    listed = _invoke("service", "gateway", "key", "list")
    assert listed.exit_code == 0, listed.output
    states = {line.split()[0]: line.split()[2] for line in listed.stdout.splitlines()}
    assert states == {
        expired.key_id: "expired",
        active.key_id: "active",
        revoked.key_id: "revoked",
    }


def test_an_unsupported_scope_is_a_usage_error_not_a_damaged_key_file(home: Path) -> None:
    """``--scope admin`` is the operator's typo: it must not send them to repair a healthy key
    file (``gateway_keys_invalid``, exit 20), and nothing is created."""

    created = _invoke(
        "service", "gateway", "key", "create", "--label", "ci", "--scope", "agent",
        "--output-file", str(home / "ci.key"),
    )  # fmt: skip
    assert created.exit_code == 0, created.output
    before = (_keys(home) / "keys.json").read_bytes()
    output = home / "admin.key"
    refused = _invoke(
        "service", "gateway", "key", "create", "--label", "admin", "--scope", "admin",
        "--output-file", str(output),
    )  # fmt: skip
    assert refused.exit_code == 2
    assert refused.stderr.startswith("gateway_key_scope_invalid:")
    assert "admin" not in refused.stderr.split(":", 1)[1]
    assert "damaged" not in refused.stderr
    assert not output.exists()
    assert (_keys(home) / "keys.json").read_bytes() == before


class _ConsoleNotOurs:
    """A terminal on stdin that is not this process's foreground console: nothing is shown."""

    def __enter__(self) -> _ConsoleNotOurs:
        from finishup.cli.trusted_console import TrustedConsoleError

        raise TrustedConsoleError("trusted_console_required")

    def __exit__(self, *_exc: object) -> None:
        return None


class _FullDisk:
    """The CLI's ``os`` with a disk that fills up as the key file is flushed."""

    def __getattr__(self, name: str) -> object:
        return getattr(os, name)

    @staticmethod
    def fsync(_descriptor: int) -> None:
        raise OSError(errno.ENOSPC, "no space left on device")


def _rows(home: Path) -> dict[str, dict[str, object]]:
    listed = _invoke("service", "gateway", "key", "list", "--json")
    assert listed.exit_code == 0, listed.output
    return {row["key_id"]: row for row in json.loads(listed.stdout)["keys"]}


@pytest.mark.parametrize("rotate", [False, True])
def test_a_key_whose_secret_was_never_shown_is_revoked(
    home: Path, monkeypatch: pytest.MonkeyPatch, rotate: bool
) -> None:
    """stdin is a terminal, but the trusted console refuses after the key was created; nobody
    holds the new key, so it must not stay active. A rotated key is left exactly as it was."""

    from finishup.cli import trusted_console
    from finishup.gateway.keys import create_key

    old, old_key = create_key(_keys(home), label="laptop", scope="operator")
    monkeypatch.setattr(gateway_cli, "_stdin_is_terminal", lambda: True)
    monkeypatch.setattr(trusted_console, "TrustedForegroundConsole", _ConsoleNotOurs)
    arguments = ("--rotate", old.key_id) if rotate else ("--label", "ci", "--scope", "agent")
    refused = _invoke("service", "gateway", "key", "create", *arguments)
    assert refused.exit_code == 2
    assert refused.stderr.startswith("gateway_key_not_shown:")
    assert "Created key" not in refused.stdout
    rows = _rows(home)
    (new_id,) = set(rows) - {old.key_id}
    assert rows[new_id]["revoked_at"] is not None
    assert rows[old.key_id]["revoked_at"] is None
    assert not isinstance(KeyRing(_keys(home)).authenticate(old_key), str)


def test_a_key_that_could_not_be_written_is_revoked_and_its_file_removed(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = home / "laptop.key"
    monkeypatch.setattr(gateway_cli, "os", _FullDisk())
    refused = _invoke(
        "service", "gateway", "key", "create", "--label", "laptop", "--scope", "agent",
        "--output-file", str(output),
    )  # fmt: skip
    assert refused.exit_code == 20
    assert refused.stderr.startswith("gateway_key_output_failed:")
    assert not output.exists()
    (row,) = _rows(home).values()
    assert row["revoked_at"] is not None


def test_a_failed_revoke_of_an_undelivered_key_names_the_key_and_its_revoke(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.gateway import keys as gateway_keys
    from finishup.gateway.keys import GatewayKeyError

    def refuse(_directory: Path, _key_id: str) -> object:
        raise GatewayKeyError("gateway_keys_unsafe")

    monkeypatch.setattr(gateway_cli, "os", _FullDisk())
    monkeypatch.setattr(gateway_keys, "revoke_key", refuse)
    refused = _invoke(
        "service", "gateway", "key", "create", "--label", "laptop", "--scope", "agent",
        "--output-file", str(home / "laptop.key"),
    )  # fmt: skip
    assert refused.exit_code == 20
    (row,) = _rows(home).values()
    assert row["revoked_at"] is None
    key_id = row["key_id"]
    assert refused.stderr == (
        f"gateway_key_output_failed: key {key_id} could not be revoked; "
        f"run 'finishup service gateway key revoke {key_id}'\n"
    )
