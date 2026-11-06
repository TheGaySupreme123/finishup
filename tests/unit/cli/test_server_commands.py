"""``finishup server``: every way in has its way out, refusals are bounded, and hosts never move.

ADR-051 (design sections 5 and 6): ``add``/``remove``, ``use NAME``/``use local``,
``login``/``logout`` and ``connect``/``disconnect`` are reverse pairs; ``status --json`` is the
generated ``server-target-status`` 1.0.0 contract; remote kinds need the typed confirmation on the
trusted console and are refused in the zero-network state; names and hosts appear only in owner
displays; an isolation root or pin refuses selection changes; a selection is never stamped into a
host registration, and ``upgrade`` still runs with one.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner, Result

from builders.server_targets import ambient_home
from finishup.cli import app as cli
from finishup.cli import server as server_cli
from finishup.client import targets
from finishup.client.credentials import SERVER_CREDENTIAL_SERVICE
from finishup.config.paths import ISOLATED_ROOT_ENV_NAMES, active_root, reset_selection_memo
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import validate_schema_instance

_RUNNER = CliRunner()
_KEY = "fuk_0123456789ab_" + "A" * 43


class _MemoryKeyring:
    """An allowlisted-looking platform store held in memory."""

    def __init__(self) -> None:
        self.entries: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.entries.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.entries[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        del self.entries[(service, username)]


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def authorized(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Record trusted-console confirmations instead of opening /dev/tty."""

    confirmations: list[tuple[str, str]] = []

    def confirm(name: str, kind: str) -> None:
        confirmations.append((name, kind))

    def ssh_endpoint(
        _user: str | None,
        _host: str,
        _port: int,
        remote_root: str | None,
        remote_launcher: str | None,
    ) -> tuple[str, str]:
        # The server's own ``service endpoint --json`` answer, without an ssh round trip.
        endpoint = (
            f"{remote_root}/run/control.sock"
            if remote_root is not None
            else "/run/user/1000/finishup/control.sock"
        )
        return remote_launcher or "/opt/finishup/bin/finishup", endpoint

    def unreachable(_self: object, _root: Path | None) -> object:
        from finishup.client.target_runtime import ProbeResult

        return ProbeResult("unavailable", reason="remote_unreachable")

    monkeypatch.setattr(server_cli, "_zero_network_in_force", lambda: False)
    monkeypatch.setattr(server_cli, "_confirm_on_trusted_console", confirm)
    monkeypatch.setattr(server_cli, "_probe_ssh_endpoint", ssh_endpoint)

    def key_accepted(_record: targets.ServerTarget, _secret: str) -> None:
        return None

    monkeypatch.setattr(server_cli, "_check_https_key", key_accepted)
    # Approach A: a remote target's probe goes through its connector; no connector is started.
    monkeypatch.setattr(
        "finishup.client.connector_runtime.ConnectorTargetRuntime.probe", unreachable
    )
    return confirmations


@pytest.fixture
def no_platform_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("finishup.client.credentials._platform_backend", lambda: None)


def _invoke(*arguments: str) -> Result:
    reset_selection_memo()
    return _RUNNER.invoke(cli.app, ["server", *arguments])


def _status_json(*arguments: str) -> dict[str, JsonValue]:
    result = _invoke("status", *arguments, "--json")
    assert result.exit_code == 0, result.output
    document = cast(dict[str, JsonValue], json.loads(result.stdout))
    validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, document))
    return document


def _not_running(_self: object, _root: Path | None) -> object:
    from finishup.client.target_runtime import ProbeResult

    return ProbeResult("not_running", reason="service_unavailable")


@pytest.fixture
def quiet_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Probe without a service: the local runtime reports ``not_running`` without connecting."""

    monkeypatch.setattr("finishup.client.target_runtime.LocalTargetRuntime.probe", _not_running)


@pytest.mark.parametrize(
    "arguments",
    [(), *(((command.name or ""),) for command in server_cli.server_app.registered_commands)],
    ids=lambda arguments: "-".join(arguments) or "server",
)
def test_every_server_command_renders_its_help(home: Path, arguments: tuple[str, ...]) -> None:
    # Help renders as Rich markup: a bracketed address part such as ``[/base]`` once parsed as a
    # closing tag and turned ``server add --help`` into internal_error.
    result = _invoke(*arguments, "--help")
    assert result.exit_code == 0, result.output
    assert result.exception is None
    assert "internal_error" not in result.output


def test_add_help_names_both_remote_address_forms(home: Path) -> None:
    result = _invoke("add", "--help")
    assert result.exit_code == 0, result.output
    assert "ssh://user@host:port" in result.stdout
    assert "https://host:port/base" in result.stdout


def test_add_use_and_their_reverses_for_a_named_local_server(home: Path, quiet_probe: None) -> None:
    added = _invoke("add", "work", "--local")
    assert added.exit_code == 0, added.output
    (record,) = targets.list_targets()
    root = targets.target_root(record.target_id)
    assert (root / "state" / "instance-identity.json").is_file()

    listed = _invoke("list")
    assert listed.exit_code == 0
    assert listed.stdout.splitlines()[0].startswith("* local")
    assert "work" in listed.stdout and record.target_id in listed.stdout

    used = _invoke("use", "work")
    assert used.exit_code == 0, used.output
    assert "Restart open agent sessions" in used.stdout
    reset_selection_memo()
    assert active_root() == root
    status = _status_json()
    assert status["source"] == "selection"
    target = cast(dict[str, JsonValue], status["target"])
    assert (target["name"], target["target_id"], target["kind"]) == (
        "work",
        record.target_id,
        "local",
    )
    assert cast(dict[str, JsonValue], status["probe"])["outcome"] == "not_running"

    refused = _invoke("remove", "work")
    assert refused.exit_code == 2
    assert refused.stderr.startswith("target_selected:")

    back = _invoke("use", "local")
    assert back.exit_code == 0
    reset_selection_memo()
    assert active_root() is None
    assert _status_json()["source"] == "ambient"

    removed = _invoke("remove", "work")
    assert removed.exit_code == 0, removed.output
    assert not root.exists()
    assert targets.list_targets() == ()


def test_remove_select_local_switches_back_first(home: Path) -> None:
    assert _invoke("add", "work", "--local").exit_code == 0
    assert _invoke("use", "work").exit_code == 0
    removed = _invoke("remove", "work", "--select-local")
    assert removed.exit_code == 0, removed.output
    reset_selection_memo()
    assert active_root() is None
    assert not targets.selection_path().exists()


def test_status_of_the_everyday_server_and_a_named_one(home: Path, quiet_probe: None) -> None:
    assert _invoke("add", "work", "--local").exit_code == 0
    everyday = _status_json()
    target = cast(dict[str, JsonValue], everyday["target"])
    assert (target["name"], target["target_id"], target["credential"]) == (
        "local",
        None,
        "not_applicable",
    )
    named = _status_json("work")
    assert cast(dict[str, JsonValue], named["target"])["name"] == "work"
    assert named["source"] == "ambient"  # status NAME never changes the selection


def test_remote_add_requires_the_trusted_console(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(server_cli, "_zero_network_in_force", lambda: False)
    result = _invoke("add", "lab", "ssh://owner@lab.example")
    assert result.exit_code == 2
    assert result.stderr.startswith("trusted_console_required:")
    assert targets.list_targets() == ()
    assert "lab.example" not in result.stderr and "owner" not in result.stderr


def test_remote_add_is_refused_in_the_zero_network_state(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(server_cli, "_zero_network_in_force", lambda: True)
    for address in ("ssh://owner@lab.example", "https://fu.example"):
        result = _invoke("add", "lab", address)
        assert result.exit_code == 2
        assert result.stderr.startswith("zero_network_in_force:")
    assert targets.list_targets() == ()


def test_a_loopback_port_target_is_a_network_hop_too(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-051 section 3: every kind but ``local`` is refused in the zero-network state."""

    monkeypatch.setattr(server_cli, "_zero_network_in_force", lambda: True)
    for arguments in (
        ("--port", "9443"),
        ("https://127.0.0.1:9443",),
        ("https://[::1]:9443",),
    ):
        result = _invoke("add", "gw", *arguments)
        assert result.exit_code == 2, (arguments, result.output)
        assert result.stderr.startswith("zero_network_in_force:")
    assert targets.list_targets() == ()


@pytest.mark.parametrize(
    ("arguments", "kind", "base_url"),
    [
        (("--port", "9443"), "local_port", "https://127.0.0.1:9443"),
        (("https://127.0.0.1:9443",), "local_port", "https://127.0.0.1:9443"),
        (("https://[0:0:0:0:0:0:0:1]:9443/fu/",), "local_port", "https://[::1]:9443/fu"),
        # Only a literal loopback origin with an explicit port is this computer's port.
        (("https://127.0.0.1",), "https", "https://127.0.0.1"),
        (("https://localhost:9443",), "https", "https://localhost:9443"),
    ],
)
def test_a_loopback_address_is_the_local_port_kind(
    home: Path,
    authorized: list[tuple[str, str]],
    arguments: tuple[str, ...],
    kind: str,
    base_url: str,
) -> None:
    result = _invoke("add", "gw", *arguments)
    assert result.exit_code == 0, result.output
    (record,) = targets.list_targets()
    assert (record.kind, record.base_url) == (kind, base_url)
    assert f"({record.target_id}, {kind})" in result.stdout
    assert authorized == [("gw", kind)]


class _PolicyClient:
    """A control client whose ``privacy_get_setup`` answers like the wire: a ``JsonObject``."""

    def __init__(self, reply: object) -> None:
        self.reply = reply
        self.closed = False

    async def privacy_get_setup(self, _request: object) -> object:
        if isinstance(self.reply, BaseException):
            raise self.reply
        return self.reply

    async def close(self) -> None:
        self.closed = True


def _everyday_installation(home: Path) -> None:
    """The marker the everyday vault's initialization writes, in the ambient data folder."""

    bundle = home / "data" / "finishup"
    bundle.mkdir(mode=0o700, parents=True, exist_ok=True)
    (bundle / "installation-state.json").write_bytes(b"{}\n")


def _serve_policy(monkeypatch: pytest.MonkeyPatch, reply: object) -> list[_PolicyClient]:
    from finishup.ports.control import ControlError

    clients: list[_PolicyClient] = []

    async def connect(_kind: object, *, workspace_locator: object = None) -> _PolicyClient:
        assert workspace_locator is None
        if isinstance(reply, ControlError) and reply.reason == "service_unavailable":
            raise reply
        client = _PolicyClient(reply)
        clients.append(client)
        return client

    monkeypatch.setattr("finishup.service.client.connect_service", connect)
    return clients


def _policy(egress: bool) -> object:
    from finishup.domain.values import JsonObject

    return JsonObject(
        {"composed_policy": {"network_egress_permitted": egress, "schema_version": "1.0.0"}}
    )


@pytest.mark.parametrize(("egress", "refused"), [(False, True), (True, False)])
def test_the_everyday_policy_decides_the_zero_network_state(
    home: Path, monkeypatch: pytest.MonkeyPatch, egress: bool, refused: bool
) -> None:
    _everyday_installation(home)
    clients = _serve_policy(monkeypatch, _policy(egress))
    assert server_cli._zero_network_in_force() is refused  # pyright: ignore[reportPrivateUsage]
    (client,) = clients
    assert client.closed


@pytest.mark.parametrize("failure", ["service_unavailable", "vault_locked"])
def test_an_unreadable_everyday_policy_refuses_the_hop(
    home: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    from finishup.ports.control import ControlError

    _everyday_installation(home)
    _serve_policy(monkeypatch, ControlError(failure, retryable=True))
    with pytest.raises(server_cli.ServerCommandRefused) as refused:
        server_cli._zero_network_in_force()  # pyright: ignore[reportPrivateUsage]
    assert refused.value.reason == "network_policy_unreadable"

    def confirm(_name: str, _kind: str) -> None:
        raise AssertionError("refused before the confirmation")

    monkeypatch.setattr(server_cli, "_confirm_on_trusted_console", confirm)
    result = _invoke("add", "lab", "ssh://owner@lab.example")
    assert result.exit_code == 20
    assert result.stderr.startswith("network_policy_unreadable:")
    assert "lab.example" not in result.stderr
    assert targets.list_targets() == ()


def test_a_computer_never_set_up_has_no_policy_of_its_own(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def never(_kind: object, **_kwargs: object) -> object:
        raise AssertionError("no everyday installation: nothing to ask")

    monkeypatch.setattr("finishup.service.client.connect_service", never)
    assert server_cli._zero_network_in_force() is False  # pyright: ignore[reportPrivateUsage]


def test_remote_add_and_use_record_the_owner_authorization(
    home: Path, authorized: list[tuple[str, str]], quiet_probe: None
) -> None:
    added = _invoke(
        "add",
        "lab",
        "ssh://owner@lab.example:2222",
        "--remote-root",
        "/srv/finishup",
        "--remote-launcher",
        "/opt/finishup/bin/finishup",
    )
    assert added.exit_code == 0, added.output
    (record,) = targets.list_targets()
    assert (record.kind, record.user, record.host, record.port) == (
        "ssh",
        "owner",
        "lab.example",
        2222,
    )
    assert record.remote_endpoint == "/srv/finishup/run/control.sock"
    assert record.disclosure_version == targets.DISCLOSURE_VERSION
    assert authorized == [("lab", "ssh")]

    used = _invoke("use", "lab")
    assert used.exit_code == 0, used.output
    assert authorized == [("lab", "ssh"), ("lab", "ssh")]
    status = _status_json()
    target = cast(dict[str, JsonValue], status["target"])
    assert target["location"] == "ssh://owner@lab.example:2222"
    authorization = cast(dict[str, JsonValue], target["authorization"])
    assert authorization["current"] is True
    probe = cast(dict[str, JsonValue], status["probe"])
    # The connector runtime's probe: a closed token, never a local fallback.
    assert (probe["outcome"], probe["reason"], probe["phase"]) == (
        "unavailable",
        "remote_unreachable",
        None,
    )
    assert "claim_salt" not in json.dumps(status)


def test_declined_confirmation_changes_nothing(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server_cli, "_zero_network_in_force", lambda: False)

    def decline(_name: str, _kind: str) -> None:
        raise server_cli.ServerCommandRefused("authorization_declined")

    monkeypatch.setattr(server_cli, "_confirm_on_trusted_console", decline)
    result = _invoke("add", "lab", "https://fu.example")
    assert result.exit_code == 2
    assert result.stderr.startswith("authorization_declined:")
    assert targets.list_targets() == ()


@pytest.mark.parametrize(
    ("arguments", "reason"),
    [
        (("add", "lab"), "usage"),
        (("add", "lab", "--local", "--port", "9443"), "usage"),
        (("add", "lab", "http://fu.example"), "target_url_invalid"),
        (("add", "lab", "https://user@fu.example"), "target_url_invalid"),
        (("add", "local", "--local"), "target_name_reserved"),
        (("add", "Bad_Name", "--local"), "target_name_invalid"),
        (("add", "lab", "--local", "--remote-root", "/srv"), "usage"),
        (
            ("add", "lab", "ssh://lab.example", "--tls-pin", "sha256:" + "a" * 64),
            "target_tls_invalid",
        ),
        (("use", "nowhere"), "target_unknown"),
        (("remove", "nowhere"), "target_unknown"),
        (("login", "nowhere"), "target_unknown"),
    ],
)
def test_refusals_are_closed_tokens_without_owner_text(
    home: Path, arguments: tuple[str, ...], reason: str
) -> None:
    result = _invoke(*arguments)
    assert result.exit_code == 2, result.output
    assert result.stderr.startswith(f"{reason}:")
    for owner_text in ("nowhere", "Bad_Name", "fu.example", "https://user@"):
        assert owner_text not in result.stderr


def test_a_name_already_taken_is_refused_before_any_confirmation(
    home: Path, authorized: list[tuple[str, str]]
) -> None:
    assert _invoke("add", "lab", "--local").exit_code == 0
    result = _invoke("add", "lab", "https://fu.example")
    assert result.exit_code == 2
    assert result.stderr.startswith("target_name_taken:")
    assert authorized == []


def test_login_and_logout_with_an_owner_only_key_file(
    home: Path, authorized: list[tuple[str, str]], no_platform_store: None
) -> None:
    assert _invoke("add", "fu", "https://fu.example/base").exit_code == 0
    (record,) = targets.list_targets()
    root = targets.target_root(record.target_id)
    key_file = home / "key"
    key_file.write_text(_KEY + "\n", encoding="ascii")
    key_file.chmod(0o600)

    login = _invoke("login", "fu", "--key-file", str(key_file))
    assert login.exit_code == 0, login.output
    assert "owner-only file" in login.stdout
    stored = root / "config" / "credential" / record.target_id
    assert stored.read_text(encoding="ascii") == _KEY
    assert stored.stat().st_mode & 0o777 == 0o600
    (after,) = targets.list_targets()
    assert after.credential == "file"
    assert _KEY not in (root / "target.json").read_text(encoding="utf-8")
    assert _KEY not in login.output
    status = _invoke("status", "fu", "--json")
    assert _KEY not in status.output

    logout = _invoke("logout", "fu")
    assert logout.exit_code == 0, logout.output
    assert "Deleted the API key" in logout.stdout
    assert not stored.exists()
    (cleared,) = targets.list_targets()
    assert cleared.credential is None
    again = _invoke("logout", "fu")
    assert again.exit_code == 0 and "No API key was stored" in again.stdout


def test_remove_never_deletes_a_target_whose_connection_did_not_stop(
    home: Path, authorized: list[tuple[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client.connector_runtime import ConnectorTargetRuntime
    from finishup.client.target_runtime import TargetRuntimeError

    assert _invoke("add", "fu", "https://fu.example").exit_code == 0
    root = targets.target_root(targets.list_targets()[0].target_id)
    stops: list[Path | None] = []

    def stuck(_self: ConnectorTargetRuntime, target: Path | None) -> None:
        stops.append(target)
        raise TargetRuntimeError("service_unavailable", phase="connector_stop")

    monkeypatch.setattr(ConnectorTargetRuntime, "stop", stuck)
    refused = _invoke("remove", "fu")
    assert refused.exit_code != 0
    assert refused.stderr.startswith("target_still_connected:")
    assert root.is_dir() and [record.name for record in targets.list_targets()] == ["fu"]

    def stopped(_self: ConnectorTargetRuntime, target: Path | None) -> None:
        stops.append(target)

    monkeypatch.setattr(ConnectorTargetRuntime, "stop", stopped)
    assert _invoke("remove", "fu").exit_code == 0
    assert not root.exists() and not targets.list_targets()
    assert stops == [root, root]


def test_login_prefers_the_platform_store(
    home: Path, authorized: list[tuple[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    keyring = _MemoryKeyring()
    monkeypatch.setattr("finishup.client.credentials._platform_backend", lambda: keyring)
    assert _invoke("add", "fu", "https://fu.example").exit_code == 0
    (record,) = targets.list_targets()
    key_file = home / "key"
    key_file.write_text(_KEY, encoding="ascii")
    key_file.chmod(0o600)

    assert _invoke("login", "fu", "--key-file", str(key_file)).exit_code == 0
    assert keyring.entries == {(SERVER_CREDENTIAL_SERVICE, record.target_id): _KEY}
    assert targets.list_targets()[0].credential == "keyring"
    assert _invoke("remove", "fu").exit_code == 0
    assert keyring.entries == {}


def test_a_shared_key_file_is_refused(
    home: Path, authorized: list[tuple[str, str]], no_platform_store: None
) -> None:
    assert _invoke("add", "fu", "https://fu.example").exit_code == 0
    key_file = home / "key"
    key_file.write_text(_KEY, encoding="ascii")
    key_file.chmod(0o644)
    result = _invoke("login", "fu", "--key-file", str(key_file))
    assert result.exit_code == 2
    assert result.stderr.startswith("credential_invalid:")
    assert _KEY not in result.output


def test_ssh_targets_take_no_api_key(home: Path, authorized: list[tuple[str, str]]) -> None:
    assert _invoke("add", "lab", "ssh://lab.example").exit_code == 0
    assert _invoke("login", "lab").stderr.startswith("credential_not_applicable:")
    assert _invoke("logout", "lab").stderr.startswith("credential_not_applicable:")


def test_remote_connect_and_disconnect_dispatch_to_the_connector_runtime(
    home: Path, authorized: list[tuple[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, Path | None]] = []

    def ensure_ready(_self: object, root: Path | None) -> None:
        calls.append(("ensure_ready", root))

    def stop(_self: object, root: Path | None) -> None:
        calls.append(("stop", root))

    runtime = "finishup.client.connector_runtime.ConnectorTargetRuntime"
    monkeypatch.setattr(f"{runtime}.ensure_ready", ensure_ready)
    monkeypatch.setattr(f"{runtime}.stop", stop)
    assert _invoke("add", "lab", "ssh://lab.example").exit_code == 0
    (record,) = targets.list_targets()
    assert record.remote_endpoint == "/run/user/1000/finishup/control.sock"
    assert record.remote_launcher == "/opt/finishup/bin/finishup"
    root = targets.target_root(record.target_id)
    assert _invoke("connect", "lab").exit_code == 0
    assert _invoke("disconnect", "lab").exit_code == 0
    assert calls == [("ensure_ready", root), ("stop", root)]


def test_a_remote_kind_without_a_runtime_is_a_typed_refusal(
    home: Path, authorized: list[tuple[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client import target_runtime

    loaders = dict(target_runtime._RUNTIME_LOADERS)  # pyright: ignore[reportPrivateUsage]
    del loaders["ssh"]
    monkeypatch.setattr(target_runtime, "_RUNTIME_LOADERS", loaders)
    assert _invoke("add", "lab", "ssh://lab.example").exit_code == 0
    for command in ("connect", "disconnect"):
        result = _invoke(command, "lab")
        assert result.exit_code == 20
        assert result.stderr.startswith("runtime_unavailable:")
        assert "remote_unreachable, phase runtime_unavailable" in result.stderr


def test_a_connector_refusal_names_the_remote_phase_only(
    home: Path, authorized: list[tuple[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.client.target_runtime import TargetRuntimeError

    def refuse(_self: object, _root: Path | None) -> None:
        raise TargetRuntimeError("remote_auth_failed")

    monkeypatch.setattr(
        "finishup.client.connector_runtime.ConnectorTargetRuntime.ensure_ready", refuse
    )
    assert _invoke("add", "lab", "ssh://owner@lab.example").exit_code == 0
    result = _invoke("connect", "lab")
    assert result.exit_code == 20
    assert result.stderr.startswith("remote_auth_failed:")
    assert "lab.example" not in result.stderr and "owner" not in result.stderr


def test_connect_and_disconnect_dispatch_to_the_local_runtime(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, Path | None]] = []

    def ensure_ready(_self: object, root: Path | None) -> None:
        calls.append(("ensure_ready", root))

    def stop(_self: object, root: Path | None) -> None:
        calls.append(("stop", root))

    monkeypatch.setattr(
        "finishup.client.target_runtime.LocalTargetRuntime.ensure_ready", ensure_ready
    )
    monkeypatch.setattr("finishup.client.target_runtime.LocalTargetRuntime.stop", stop)
    assert _invoke("add", "work", "--local").exit_code == 0
    (record,) = targets.list_targets()
    root = targets.target_root(record.target_id)
    assert _invoke("connect", "work").exit_code == 0
    assert _invoke("disconnect", "work").exit_code == 0
    assert _invoke("connect").exit_code == 0  # the everyday server, with nothing selected
    assert calls == [("ensure_ready", root), ("stop", root), ("ensure_ready", None)]


def test_the_everyday_server_starts_while_another_is_selected(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``connect local`` starts the everyday server: its spawn reads no selection (ADR-051)."""

    calls: list[Path | None] = []

    def ensure_ready(_self: object, root: Path | None) -> None:
        calls.append(root)

    monkeypatch.setattr(
        "finishup.client.target_runtime.LocalTargetRuntime.ensure_ready", ensure_ready
    )
    assert _invoke("add", "work", "--local").exit_code == 0
    assert _invoke("use", "work").exit_code == 0
    result = _invoke("connect", "local")
    assert result.exit_code == 0, result.output
    assert calls == [None]
    assert "this computer's everyday server" in result.stdout


def _dangling_selection(home: Path) -> None:
    """Select a named local server, then delete its folder behind the selection's back."""

    assert _invoke("add", "work", "--local").exit_code == 0
    assert _invoke("use", "work").exit_code == 0
    shutil.rmtree(targets.target_root(targets.find_target("work").target_id))


def _malformed_selection(home: Path) -> None:
    path = targets.selection_path()
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.write_bytes(b"{not json")
    path.chmod(0o600)


def _symlinked_selection(home: Path) -> None:
    elsewhere = home / "elsewhere.json"
    elsewhere.write_bytes(b'{"schema":"yoetz.server-selection/1","target_id":"t_0a1b2c3d"}\n')
    elsewhere.chmod(0o600)
    targets.selection_path().parent.mkdir(mode=0o700, exist_ok=True)
    targets.selection_path().symlink_to(elsewhere)


@pytest.mark.parametrize(
    "break_selection", [_dangling_selection, _malformed_selection, _symlinked_selection]
)
def test_use_local_is_the_way_back_from_a_broken_selection(
    home: Path, quiet_probe: None, break_selection: Callable[[Path], None]
) -> None:
    """A damaged or dangling selection fails closed, and the remedy it names actually works."""

    break_selection(home)
    for arguments in (("list",), ("status", "--json"), ("use", "work")):
        refused = _invoke(*arguments)
        assert refused.exit_code == 20, (arguments, refused.output)
        assert refused.stderr.startswith("selection_invalid:")
        assert "'finishup server use local' clears it" in refused.stderr

    back = _invoke("use", "local")
    assert back.exit_code == 0, back.output
    assert not targets.selection_path().is_symlink()
    assert not targets.selection_path().exists()
    if break_selection is _symlinked_selection:
        assert (home / "elsewhere.json").is_file()  # the link is removed, never what it names
    reset_selection_memo()
    assert active_root() is None
    listed = _invoke("list")
    assert listed.exit_code == 0, listed.output
    assert listed.stdout.splitlines()[0].startswith("* local")


def test_remove_select_local_clears_a_selection_that_cannot_be_read(home: Path) -> None:
    assert _invoke("add", "work", "--local").exit_code == 0
    _malformed_selection(home)
    refused = _invoke("remove", "work")
    assert refused.exit_code == 20
    assert refused.stderr.startswith("selection_invalid:")
    assert targets.list_targets() != ()

    removed = _invoke("remove", "work", "--select-local")
    assert removed.exit_code == 0, removed.output
    assert not targets.selection_path().exists()
    assert targets.list_targets() == ()
    reset_selection_memo()
    assert active_root() is None


def test_another_target_can_be_removed_while_the_selection_dangles(home: Path) -> None:
    assert _invoke("add", "spare", "--local").exit_code == 0
    _dangling_selection(home)
    removed = _invoke("remove", "spare")
    assert removed.exit_code == 0, removed.output
    assert targets.selection_path().exists()  # not this target's; 'use local' clears it


def test_an_isolation_root_still_refuses_the_way_back(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _malformed_selection(home)
    explicit = home / "explicit"
    explicit.mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], str(explicit))
    result = _invoke("use", "local")
    assert result.exit_code == 2
    assert result.stderr.startswith("selection_overridden:")
    assert targets.selection_path().exists()


def test_an_isolation_root_overrides_the_selection(
    home: Path, monkeypatch: pytest.MonkeyPatch, quiet_probe: None
) -> None:
    assert _invoke("add", "work", "--local").exit_code == 0
    assert _invoke("use", "work").exit_code == 0
    explicit = home / "explicit"
    explicit.mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], str(explicit))

    for arguments in (("use", "local"), ("add", "lab", "--local"), ("remove", "work")):
        result = _invoke(*arguments)
        assert result.exit_code == 2
        assert result.stderr.startswith("selection_overridden:")
    status = _status_json()
    assert status["source"] == "environment"
    assert status["selection_overridden"] is True
    assert cast(dict[str, JsonValue], status["target"])["target_id"] is None


def test_remote_use_refreshes_the_recorded_authorization(
    home: Path, authorized: list[tuple[str, str]]
) -> None:
    assert _invoke("add", "fu", "https://fu.example").exit_code == 0
    (record,) = targets.list_targets()
    root = targets.target_root(record.target_id)
    targets.write_target(root, replace(record, authorized_at="2026-01-01T00:00:00.000Z"))
    assert _invoke("use", "fu").exit_code == 0
    (after,) = targets.list_targets()
    assert after.authorized_at != "2026-01-01T00:00:00.000Z"
    assert after.disclosure_version == targets.DISCLOSURE_VERSION
    assert authorized == [("fu", "https"), ("fu", "https")]


def test_a_stale_disclosure_is_refused_by_connect_and_renewed_by_use(
    home: Path,
    authorized: list[tuple[str, str]],
    quiet_probe: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``connect`` sends nothing to a target confirmed under an older disclosure; ``use`` renews."""

    assert _invoke("add", "lab", "ssh://lab.example").exit_code == 0
    # A later release shows a newer disclosure than the one the owner confirmed.
    monkeypatch.setattr(targets, "DISCLOSURE_VERSION", targets.DISCLOSURE_VERSION + 1)

    refused = _invoke("connect", "lab")
    assert refused.exit_code == 2
    assert refused.stderr.startswith("target_reauthorization_required:")
    assert "lab.example" not in refused.stderr
    # Seeing, stopping and removing a stale target stay possible.
    status = _status_json("lab")
    authorization = cast(
        dict[str, JsonValue], cast(dict[str, JsonValue], status["target"])["authorization"]
    )
    assert authorization["current"] is False
    # Approach A: disconnect stops this machine's connector for it and sends nothing.
    disconnected = _invoke("disconnect", "lab")
    assert disconnected.exit_code == 0 and disconnected.stderr == ""

    assert _invoke("use", "lab").exit_code == 0
    (renewed,) = targets.list_targets()
    assert not renewed.needs_reauthorization
    assert authorized == [("lab", "ssh"), ("lab", "ssh")]


# -- registrations and upgrade with a selection ---------------------------------------------


def _registration_bytes(launcher: Path) -> dict[str, bytes]:
    from finishup.adapters.integrations.claude_code_integration import render_claude_code_plugin
    from finishup.adapters.integrations.codex_mcp import isolated_root_environment
    from finishup.adapters.integrations.cursor_integration import render_cursor_plugin
    from finishup.ports.plugin_artifacts import PluginFormatProfile
    from finishup.protocol.canonical import canonical_encode

    claude = render_claude_code_plugin(finishup_launcher=launcher)
    cursor = render_cursor_plugin(
        PluginFormatProfile.CURSOR_PLUGIN_NATIVE, finishup_launcher=launcher
    )
    members = {f"claude/{name}": data for name, data in claude.members.items()}
    members.update({f"cursor/{name}": data for name, data in cursor.members.items()})
    members["codex/env"] = canonical_encode(cast(JsonValue, isolated_root_environment()))
    return members


def test_a_selection_is_never_stamped_into_a_host_registration(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher = home / "finishup"
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    launcher.chmod(0o700)
    before = _registration_bytes(launcher)

    assert _invoke("add", "work", "--local").exit_code == 0
    assert _invoke("use", "work").exit_code == 0
    reset_selection_memo()
    assert active_root() is not None
    after = _registration_bytes(launcher)
    assert after == before
    (record,) = targets.list_targets()
    assert not any(record.target_id.encode() in data for data in after.values())

    # The same renderers do stamp an explicit isolation root, so the comparison can see one.
    explicit = home / "explicit"
    explicit.mkdir(mode=0o700)
    monkeypatch.setenv(ISOLATED_ROOT_ENV_NAMES[0], str(explicit))
    stamped = _registration_bytes(launcher)
    assert stamped != before
    assert any(str(explicit).encode() in data for data in stamped.values())


def test_upgrade_is_not_refused_while_a_target_is_selected(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.adapters import package_upgrade

    assert _invoke("add", "work", "--local").exit_code == 0
    assert _invoke("use", "work").exit_code == 0
    reset_selection_memo()
    monkeypatch.setattr(package_upgrade, "installation_prefix", lambda: home / "source")

    def run(argv: tuple[str, ...], **_kwargs: object) -> object:
        from types import SimpleNamespace

        assert argv == ("uv", "tool", "dir")
        return SimpleNamespace(returncode=0, stdout=str(home / "tools").encode())

    monkeypatch.setattr(package_upgrade.subprocess, "run", run)
    # Past the isolation guard: the ordinary uv-tool check decides, never the selection.
    assert package_upgrade.execute_package_upgrade() == "refused_non_uv_tool_runtime"


# -- service start (the reverse of service stop) ---------------------------------------------


def test_service_start_is_an_on_demand_start_plus_status(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.ports.control import ControlClientKind, ServiceState, ServiceStatus

    status = ServiceStatus(
        protocol_version="1.0",
        service_version="0.3.0",
        service_instance_id="svc_00000000-0000-4000-8000-000000000001",
        service_generation="1",
        state=ServiceState.LOCKED,
        state_reason="vault_uninitialized",
        vault_mode="uninitialized",
        capabilities=(),
        session_monitor="unavailable",
    )
    calls: list[tuple[ControlClientKind, object]] = []

    class _Client:
        async def service_status(self) -> ServiceStatus:
            return status

        async def close(self) -> None:
            return None

    async def on_demand(kind: ControlClientKind, *, workspace_locator: object = None) -> _Client:
        calls.append((kind, workspace_locator))
        return _Client()

    monkeypatch.setattr("finishup.service.client.connect_service_on_demand", on_demand)
    result = _RUNNER.invoke(cli.app, ["service", "start", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["service_instance_id"] == status.service_instance_id
    assert calls == [(ControlClientKind.CLI, None)]


def test_ambiguous_everyday_folders_are_a_bounded_refusal(home: Path) -> None:
    for app_name in ("finishup", "yoetz"):
        folder = home / "config" / app_name
        folder.mkdir(mode=0o700)
        (folder / "config.toml").write_text("", encoding="utf-8")
    for arguments in (("list",), ("add", "work", "--local")):
        result = _invoke(*arguments)
        assert result.exit_code == 20, result.output
        assert result.stderr.startswith("installation_root_ambiguous:")
        assert "Traceback" not in result.output
