"""This computer's zero-network policy and a server elsewhere are never in force together (ADR-051).

Maintainer decision of 2026-11-07 (decision 8), replacing the 2026-11-06 choice to keep such a
server: "Remember but also make it so if user uses remote server it can't be zero network."

* Remember: every report of this computer's everyday policy to a client command is recorded;
  while the live policy cannot be read, the surfaces fall back to that record and say "this
  computer last reported".
* A change that would make this computer zero-network while a remote server is selected offers
  exactly two choices on the trusted console (switch to this computer's everyday FinishUP and
  make the change, or cancel it and keep the server; Enter, end of input and Ctrl-C cancel) and
  is refused before it is applied without that console. ``server add|use`` of a remote kind stay
  refused, live or last reported.
* Every surface shows the item while it lasts; every line names the target by its generated id
  and closed kind, never by the name the owner typed.
"""

from __future__ import annotations

import asyncio
import json
import os
import pty
import select
import signal
import sys
import textwrap
import threading
import time
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner, Result

import finishup.cli.zero_network_selection as zero_network
import finishup.client.everyday_policy as everyday_policy
from builders.privacy_policies import local_only_policy, minimal_external_policy
from builders.server_targets import ambient_home
from finishup.cli import app as cli
from finishup.cli import server as server_cli
from finishup.client import targets
from finishup.client.everyday_policy import ReportedPolicy, read_marker, record_reported_policy
from finishup.config.paths import active_root, reset_selection_memo
from finishup.domain.privacy import ConversationReview, CredentialHeuristic, PrivacyPolicy
from finishup.domain.values import JsonObject
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import validate_schema_instance

_RUNNER = CliRunner()
_NAME = "lab"
_AT = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
_STAMP = "2026-11-07T09:30:00.000Z"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """An owner-only ambient home whose selection and marker the checks really read."""

    with ambient_home(monkeypatch) as root:
        monkeypatch.setattr(zero_network, "_selection_on_disk", zero_network.read_selection_on_disk)
        monkeypatch.setattr(
            everyday_policy,
            "_location",
            everyday_policy._ambient_marker_path,  # pyright: ignore[reportPrivateUsage]
        )
        yield root


def _policy(monkeypatch: pytest.MonkeyPatch, state: str) -> list[int]:
    """This computer's everyday policy, as ``everyday_network_state`` reports it; counts reads."""

    reads: list[int] = []

    def read() -> str:
        reads.append(1)
        return state

    monkeypatch.setattr(zero_network, "everyday_network_state", read)
    return reads


def _remote(kind: str = "ssh", *, select: bool = True) -> targets.ServerTarget:
    fields: dict[str, object]
    if kind == "ssh":
        fields = {"user": "owner", "host": "lab.example", "port": 22}
    elif kind == "https":
        fields = {"base_url": "https://lab.example:8443", "tls_pin": "sha256:" + "a" * 64}
    else:
        fields = {"base_url": "https://127.0.0.1:8443", "tls_pin": "sha256:" + "a" * 64}
    with targets.registry_lock():
        record, _root = targets.new_remote_target(_NAME, kind, **fields)  # pyright: ignore[reportArgumentType]
        if select:
            targets.write_selection(record)
    return record


def _select_elsewhere(record: targets.ServerTarget, monkeypatch: pytest.MonkeyPatch) -> None:
    """'finishup server use lab' in another terminal: this process keeps the root it resolved.

    The other process writes the owner-only selection file and resets only its own memo.
    """

    with monkeypatch.context() as other_process, targets.registry_lock():
        other_process.setattr(targets, "reset_selection_memo", lambda: None)
        targets.write_selection(record)


class _Console:
    """The trusted foreground console: records what it shows and gives one scripted answer."""

    instances: list[_Console] = []
    answer: bytes | str = b"2"
    unavailable: bool = False

    def __init__(self) -> None:
        self.written: list[str] = []
        self.prompts: list[str] = []
        _Console.instances.append(self)

    def __enter__(self) -> _Console:
        from finishup.cli.trusted_console import TrustedConsoleError

        if _Console.unavailable:
            raise TrustedConsoleError("trusted_console_required")
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def write(self, value: str) -> None:
        self.written.append(value)

    def read_choice(self, prompt: str, allowed: tuple[bytes, ...]) -> bytes:
        from finishup.cli.trusted_console import TrustedConsoleError

        self.prompts.append(prompt)
        assert allowed == (b"1", b"2")
        if isinstance(_Console.answer, str):
            raise TrustedConsoleError(_Console.answer)
        return _Console.answer


@pytest.fixture
def console(monkeypatch: pytest.MonkeyPatch) -> type[_Console]:
    _Console.instances = []
    _Console.answer = b"2"
    _Console.unavailable = False
    monkeypatch.setattr("finishup.cli.trusted_console.TrustedForegroundConsole", _Console)
    return _Console


def _shown(console: type[_Console]) -> str:
    return "".join(text for instance in console.instances for text in instance.written)


def _invoke(*arguments: str) -> Result:
    reset_selection_memo()
    return _RUNNER.invoke(cli.app, list(arguments))


_MACHINE_SCOPE = JsonObject({"scope": {"kind": "machine"}})


def _everyday_service(
    home: Path, monkeypatch: pytest.MonkeyPatch, *, egress: bool | None
) -> list[object]:
    """This computer's set-up everyday installation and its running service; records each read.

    Only the control connection is a stand-in: ``everyday_network_state`` itself runs. ``egress``
    ``None`` is a service that cannot be asked (stopped or locked).
    """

    from finishup.ports.control import ControlError

    bundle = home / "data" / "finishup"
    bundle.mkdir(mode=0o700, parents=True, exist_ok=True)
    (bundle / "installation-state.json").write_bytes(b"{}\n")
    requests: list[object] = []

    class Client:
        async def privacy_get_effective(self, request: object) -> object:
            requests.append(request)
            return JsonObject({"policy": {"network_egress_permitted": egress}})

        async def close(self) -> None:
            return None

    async def connect(_kind: object, *, workspace_locator: object = None) -> Client:
        assert workspace_locator is None
        if egress is None:
            raise ControlError("service_unavailable", retryable=True)
        return Client()

    monkeypatch.setattr("finishup.service.client.connect_service", connect)
    monkeypatch.setattr(
        "finishup.cli.provider_status.machine_scope_request", lambda: _MACHINE_SCOPE
    )
    return requests


# --- remember ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("egress", "state"), [(False, "zero_network"), (True, "network_permitted")]
)
def test_the_everyday_machine_scope_policy_decides_and_is_remembered(
    home: Path, monkeypatch: pytest.MonkeyPatch, egress: bool, state: str
) -> None:
    requests = _everyday_service(home, monkeypatch, egress=egress)

    assert zero_network.everyday_network_state() == state

    assert requests == [_MACHINE_SCOPE]
    reading = read_marker()
    assert isinstance(reading, ReportedPolicy) and reading.zero_network is (not egress)


def test_a_policy_that_cannot_be_read_leaves_the_last_report_as_it_was(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record_reported_policy(zero_network=True, now=_AT)
    _everyday_service(home, monkeypatch, egress=None)

    assert zero_network.everyday_network_state() == "unreadable"

    assert read_marker() == ReportedPolicy(True, _STAMP)


def test_a_computer_never_set_up_has_no_policy_and_keeps_no_report(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The way out of the marker besides deleting the state folder (uninstalling): once this
    computer's everyday installation no longer exists, what it reported is removed."""

    record_reported_policy(zero_network=True, now=_AT)

    def never(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("nothing to ask")

    monkeypatch.setattr("finishup.service.client.connect_service", never)
    assert zero_network.everyday_network_state() == "no_policy"
    assert read_marker() == "absent"


def test_an_isolation_root_reads_its_own_policy_and_leaves_the_everyday_report(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record_reported_policy(zero_network=True, now=_AT)
    isolated = home / "isolated"
    isolated.mkdir(mode=0o700)
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", str(isolated))
    reset_selection_memo()

    assert zero_network.everyday_network_state() == "no_policy"

    monkeypatch.delenv("FINISHUP_ISOLATED_ROOT")
    reset_selection_memo()
    assert read_marker() == ReportedPolicy(True, _STAMP)


def _effective(*, egress: bool, scope: str = "machine") -> JsonObject:
    return JsonObject(
        {
            "policy": {
                "network_egress_permitted": egress,
                "effective_scope": {"kind": scope, "installation_id": "ins_1"},
            }
        }
    )


@pytest.mark.parametrize("egress", [False, True])
def test_privacy_show_on_this_computer_remembers_its_machine_policy(
    home: Path, monkeypatch: pytest.MonkeyPatch, egress: bool
) -> None:
    class Client:
        async def privacy_get_effective(self, _request: object, **_kwargs: object) -> object:
            return _effective(egress=egress)

        async def close(self) -> None:
            return None

    async def build(*_args: object, **_kwargs: object) -> Client:
        return Client()

    monkeypatch.setattr(cli, "build_service_client", build)
    monkeypatch.setattr(cli, "_machine_scope_request_or_none", lambda: _MACHINE_SCOPE)

    result = _invoke("privacy", "show", "--json")

    assert result.exit_code == 0, result.output
    reading = read_marker()
    assert isinstance(reading, ReportedPolicy) and reading.zero_network is (not egress)


def test_only_this_computers_own_machine_policy_is_remembered(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A repository's policy narrows that repository, not this computer.
    assert (
        zero_network.remember_reported_policy(_effective(egress=False, scope="workspace")) is False
    )
    assert read_marker() == "absent"

    # A process on a remote server's root reads that server's policy, not this computer's.
    _remote()
    reset_selection_memo()
    assert active_root() is not None
    assert zero_network.remember_reported_policy(_effective(egress=False)) is False
    assert read_marker() == "absent"

    with targets.registry_lock():
        targets.clear_selection()
    assert zero_network.remember_reported_policy(_effective(egress=False)) is True
    assert read_marker() == ReportedPolicy(True, cast(ReportedPolicy, read_marker()).reported_at)


def test_a_change_on_this_computer_reads_the_policy_again_and_remembers_it(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        zero_network,
        "_after_change_state",
        zero_network._read_after_change,  # pyright: ignore[reportPrivateUsage]
    )
    requests = _everyday_service(home, monkeypatch, egress=False)

    asyncio.run(zero_network.after_policy_change_async())

    assert requests == [_MACHINE_SCOPE]
    assert cast(ReportedPolicy, read_marker()).zero_network is True
    assert capsys.readouterr() == ("", "")


def test_a_change_made_on_a_remote_server_reads_nothing_here(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        zero_network,
        "_after_change_state",
        zero_network._read_after_change,  # pyright: ignore[reportPrivateUsage]
    )
    requests = _everyday_service(home, monkeypatch, egress=False)
    _remote()
    reset_selection_memo()

    zero_network.after_policy_change()

    assert requests == []
    assert read_marker() == "absent"


def test_a_remote_selected_while_a_change_was_made_is_said(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``server use`` ran in another terminal between the check and the change: connections to
    that server are refused now, and the owner is told so and the way out."""

    monkeypatch.setattr(zero_network, "_after_change_state", lambda: "zero_network")
    record = _remote(select=False)
    reset_selection_memo()
    assert active_root() is None
    _select_elsewhere(record, monkeypatch)

    zero_network.after_policy_change()

    err = capsys.readouterr().err
    assert err.startswith("zero_network_remote_selected: ")
    assert f"{record.target_id} (ssh)" in err
    assert "refused before anything is sent" in err
    assert "'finishup server use local'" in err


# --- the item, live and last reported -----------------------------------------------------------


@pytest.mark.parametrize("kind", ["ssh", "https", "local_port"])
def test_a_remote_selection_under_zero_network_is_the_item(
    home: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    record = _remote(kind)
    _policy(monkeypatch, "zero_network")

    item = zero_network.find_zero_network_selection()

    assert item is not None
    assert item == zero_network.ZeroNetworkSelection(
        zero_network.REMOTE_SELECTED, record.target_id, kind
    )
    text = " ".join(item.lines())
    assert text.startswith("This computer's privacy policy forbids all network use")
    assert f"{record.target_id} ({kind})" in text
    assert "refused before anything is sent" in text
    assert "'finishup server use local', then restart open agent sessions" in text
    assert item.indicator() == f"{kind} {record.target_id} · refused: zero-network here"
    for line in (*item.lines(), item.line(), item.indicator(), item.next_step(), item.heading()):
        assert _NAME not in line.replace(record.target_id, "")
        assert "lab.example" not in line and "127.0.0.1" not in line
    assert item.line().startswith("zero_network_remote_selected: ")
    assert item.fact() == {
        "reason": "zero_network_remote_selected",
        "target_id": record.target_id,
        "kind": kind,
        "detail": None,
        "policy_read": "live",
        "last_reported_at": None,
    }


def test_an_unreadable_policy_falls_back_to_this_computers_last_report(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The normal case while a remote server is used: this computer's service is stopped or
    locked. What it last reported decides, and the item says so, with when."""

    record = _remote()
    record_reported_policy(zero_network=True, now=_AT)
    _policy(monkeypatch, "unreadable")

    item = zero_network.find_zero_network_selection()

    assert item == zero_network.ZeroNetworkSelection(
        zero_network.REMOTE_SELECTED,
        record.target_id,
        "ssh",
        policy_read="last_reported",
        last_reported_at=_STAMP,
    )
    assert item is not None
    text = " ".join(item.lines())
    assert text.startswith(f"This computer last reported, at {_STAMP}, that its privacy policy")
    assert "cannot be asked now" in text
    assert "'finishup server use local'" in text
    assert item.indicator() == f"ssh {record.target_id} · refused: last reported zero-network here"
    assert "last reported" in item.heading() and "last reported" in item.next_step()
    assert item.fact()["policy_read"] == "last_reported"
    assert item.fact()["last_reported_at"] == _STAMP


def test_the_fallback_reads_the_real_policy_path_when_the_service_cannot_be_asked(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _remote()
    record_reported_policy(zero_network=True, now=_AT)
    _everyday_service(home, monkeypatch, egress=None)

    item = zero_network.find_zero_network_selection()

    assert item is not None and (item.target_id, item.policy_read) == (
        record.target_id,
        "last_reported",
    )


@pytest.mark.parametrize("marker", ["permitted", "absent", "unreadable"])
def test_an_unreadable_policy_without_a_zero_network_report_says_nothing(
    home: Path, monkeypatch: pytest.MonkeyPatch, marker: str
) -> None:
    _remote()
    if marker == "permitted":
        record_reported_policy(zero_network=False, now=_AT)
    elif marker == "unreadable":
        path = everyday_policy.marker_path()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(b"{zero")
        path.chmod(0o600)
    _policy(monkeypatch, "unreadable")

    assert zero_network.find_zero_network_selection() is None


@pytest.mark.parametrize("state", ["network_permitted", "no_policy"])
def test_a_live_answer_outranks_the_last_report(
    home: Path, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    _remote()
    record_reported_policy(zero_network=True, now=_AT)
    reads = _policy(monkeypatch, state)

    assert zero_network.find_zero_network_selection() is None
    assert reads == [1]


def test_no_selection_or_a_local_one_asks_no_service(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record_reported_policy(zero_network=True, now=_AT)
    reads = _policy(monkeypatch, "zero_network")
    assert zero_network.find_zero_network_selection() is None

    with targets.registry_lock():
        record, _root = targets.new_local_target("work")
        targets.write_selection(record)
    assert zero_network.find_zero_network_selection() is None
    assert reads == []


def test_an_unreadable_selection_is_said_with_its_closed_reason(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _policy(monkeypatch, "zero_network")
    path = targets.selection_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(b"{not json\n")
    path.chmod(0o600)

    item = zero_network.find_zero_network_selection()

    assert item is not None
    assert (item.reason, item.detail, item.target_id) == (
        zero_network.SELECTION_UNREADABLE,
        "selection_invalid",
        None,
    )
    text = item.line()
    assert text.startswith("zero_network_selection_unreadable: ")
    assert "cannot tell whether a server on another machine is selected" in text
    assert "'finishup server use local' clears it" in text
    # Never reported as "no server": it says the selection could not be read.
    assert "could not be read (selection_invalid)" in text


def test_a_selection_naming_a_missing_folder_is_unreadable_too(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import shutil

    record = _remote()
    shutil.rmtree(targets.target_root(record.target_id))
    _policy(monkeypatch, "zero_network")

    item = zero_network.find_zero_network_selection()

    assert item is not None and item.reason == zero_network.SELECTION_UNREADABLE
    assert item.detail == "selection_invalid"


def test_an_isolation_root_decides_its_own_process_tree(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _remote()
    record_reported_policy(zero_network=True, now=_AT)
    reads = _policy(monkeypatch, "zero_network")
    isolated = home / "isolated"
    isolated.mkdir(mode=0o700)
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", str(isolated))
    reset_selection_memo()

    assert zero_network.find_zero_network_selection() is None
    assert reads == []


def test_the_policy_read_works_from_a_cli_commands_event_loop(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every CLI command runs under ``anyio.run``; the read runs in a worker thread from there.

    ``asyncio.to_thread`` copies the caller's context, which names the running async library, so
    the read's own event loop must start from a fresh context or it refuses to start at all.
    """

    import anyio

    record = _remote()
    requests = _everyday_service(home, monkeypatch, egress=False)

    item = anyio.run(zero_network.find_zero_network_selection_async)

    assert item == zero_network.ZeroNetworkSelection(
        zero_network.REMOTE_SELECTED, record.target_id, "ssh"
    )
    assert requests == [_MACHINE_SCOPE]


# --- server add and use: refused, live or last reported -----------------------------------------


def test_remote_use_stays_refused_under_zero_network(
    home: Path, monkeypatch: pytest.MonkeyPatch, console: type[_Console]
) -> None:
    record = _remote(select=False)
    _policy(monkeypatch, "zero_network")

    result = _invoke("server", "use", _NAME)

    assert result.exit_code == 2
    assert result.stderr.startswith("zero_network_in_force:")
    assert console.instances == []
    assert targets.read_selected_target_id() is None
    assert record.target_id not in result.stderr


@pytest.mark.parametrize("command", ["use", "add"])
def test_remote_add_and_use_are_refused_when_this_computer_last_reported_zero_network(
    home: Path, monkeypatch: pytest.MonkeyPatch, console: type[_Console], command: str
) -> None:
    if command == "use":
        _remote(select=False)
        arguments = ("server", "use", _NAME)
    else:
        arguments = ("server", "add", "lab2", "ssh://owner@lab.example:22")
    record_reported_policy(zero_network=True, now=_AT)
    _policy(monkeypatch, "unreadable")

    result = _invoke(*arguments)

    assert result.exit_code == 2, result.output
    assert result.stderr.startswith("zero_network_in_force: ")
    assert f"last reported, at {_STAMP}, that it makes no network connections" in result.stderr
    assert "change the privacy policy on this computer first" in result.stderr
    assert console.instances == []
    assert targets.read_selected_target_id() is None
    assert len(targets.list_targets()) == (1 if command == "use" else 0)


@pytest.mark.parametrize("marker", ["permitted", "absent"])
def test_an_unreadable_policy_without_a_zero_network_report_stays_refused_as_unreadable(
    home: Path, monkeypatch: pytest.MonkeyPatch, console: type[_Console], marker: str
) -> None:
    """Fail closed: only a live answer allows a hop; the last report never does."""

    _remote(select=False)
    if marker == "permitted":
        record_reported_policy(zero_network=False, now=_AT)
    _policy(monkeypatch, "unreadable")

    result = _invoke("server", "use", _NAME)

    assert result.exit_code == 20
    assert result.stderr.startswith("network_policy_unreadable:")
    assert console.instances == []


def test_server_login_sends_no_key_check_while_this_computer_last_reported_zero_network(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _remote("https", select=False)
    record_reported_policy(zero_network=True, now=_AT)

    def never(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("nothing is read or sent")

    monkeypatch.setattr(server_cli, "_check_https_key", never)
    monkeypatch.setattr(server_cli, "_read_secret_on_console", never)

    result = _invoke("server", "login", _NAME)

    assert result.exit_code == 2
    assert result.stderr.startswith("zero_network_remote_selected: ")
    assert "'finishup server use local'" in result.stderr


# --- a change that would make this computer zero-network: two choices, or refused --------------


def _guard(*, interactive: bool = True, forbids: bool = True) -> str:
    return zero_network.guard_policy_change(forbids_network=forbids, interactive=interactive)


def test_choosing_1_switches_to_the_everyday_server_then_the_change_goes_ahead(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    capsys: pytest.CaptureFixture[str],
) -> None:
    from finishup.client.connector_runtime import ConnectorTargetRuntime

    record = _stale_process_with_a_remote_selected(monkeypatch)
    console.answer = b"1"
    stops: list[Path | None] = []

    def stop(_self: object, target: Path | None) -> None:
        stops.append(target)

    monkeypatch.setattr(ConnectorTargetRuntime, "stop", stop)

    assert _guard() == "switched"

    assert targets.read_selected_target_id() is None
    # Switching stops the traffic it names: what this client ran for that server (approach A:
    # its connector and the background workspace agents answering the server's reads) stopped.
    assert stops == [targets.target_root(record.target_id)]
    shown = _shown(console)
    assert f"the selected FinishUP server {record.target_id} (ssh)" in shown
    assert "make no network connections" in shown
    assert "both cannot stay" in shown
    assert "1  Switch to this computer's everyday FinishUP and make this change" in shown
    assert f"2  Cancel this change and keep using the server {record.target_id} (ssh)" in shown
    assert console.instances[0].prompts == ["Choose 1 or 2 (Enter cancels the change): "]
    assert _NAME not in shown.replace(record.target_id, "")
    out = capsys.readouterr().out
    assert "Using this computer's everyday FinishUP server." in out
    assert f"Closed this computer's connection to the server {record.target_id} (ssh)" in out
    assert "Restart open agent sessions" in out


def _stale_process_with_a_remote_selected(monkeypatch: pytest.MonkeyPatch) -> targets.ServerTarget:
    """This process resolved this computer's server; another terminal then selected a remote one."""

    record = _remote(select=False)
    reset_selection_memo()
    assert active_root() is None
    _select_elsewhere(record, monkeypatch)
    return record


def test_choosing_2_cancels_the_change_and_keeps_the_server(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    capsys: pytest.CaptureFixture[str],
) -> None:
    from finishup.client.connector_runtime import ConnectorTargetRuntime

    def never(_self: object, _target: Path | None) -> None:
        raise AssertionError("keeping the server stops nothing")

    record = _stale_process_with_a_remote_selected(monkeypatch)
    console.answer = b"2"
    monkeypatch.setattr(ConnectorTargetRuntime, "stop", never)

    with pytest.raises(zero_network.ZeroNetworkChangeStopped) as stopped:
        _guard()

    assert (stopped.value.reason, stopped.value.cancelled) == (zero_network.REMOTE_SELECTED, True)
    assert targets.read_selected_target_id() == record.target_id
    out = capsys.readouterr().out
    assert "Cancelled: nothing was changed." in out
    assert f"the server {record.target_id} (ssh) stays selected" in out


@pytest.mark.parametrize(
    "answer", ["empty_input", "eof", "cancelled", "interrupted", "input_invalid"]
)
def test_enter_end_of_input_ctrl_c_or_any_other_answer_cancels(
    home: Path, monkeypatch: pytest.MonkeyPatch, console: type[_Console], answer: str
) -> None:
    record = _stale_process_with_a_remote_selected(monkeypatch)
    console.answer = answer

    with pytest.raises(zero_network.ZeroNetworkChangeStopped) as stopped:
        _guard()

    assert stopped.value.cancelled is True
    assert targets.read_selected_target_id() == record.target_id
    # Ctrl-C ("cancelled") and Ctrl-D echo no newline, so the prompt's line is ended for them.
    last = console.instances[0].written[-1]
    if answer in {"eof", "cancelled", "interrupted"}:
        assert last == "\n"
    else:
        assert last.endswith("(ssh)\n")


def test_the_choice_is_read_on_the_loop_thread_where_ctrl_c_reaches_it(
    home: Path, monkeypatch: pytest.MonkeyPatch, console: type[_Console]
) -> None:
    """Every caller is a coroutine: the read runs on its thread, with Ctrl-C raising there.

    An event loop's runner turns the first SIGINT into a task cancellation and returns, so a read
    blocked in a worker thread, or under that handler, waits for another line and a later "1"
    still switches. The read must run on the loop's (main) thread under Python's default handler,
    and the runner's handler must be back afterwards.
    """

    _stale_process_with_a_remote_selected(monkeypatch)
    seen: list[tuple[bool, bool]] = []

    class Reading(_Console):
        def read_choice(self, prompt: str, allowed: tuple[bytes, ...]) -> bytes:
            seen.append(
                (
                    threading.current_thread() is threading.main_thread(),
                    signal.getsignal(signal.SIGINT) is signal.default_int_handler,
                )
            )
            return super().read_choice(prompt, allowed)

    monkeypatch.setattr("finishup.cli.trusted_console.TrustedForegroundConsole", Reading)

    def runner_handler(_signum: int, _frame: object) -> None:
        """Stands in for the handler ``asyncio.Runner`` installs: it does not raise."""

    async def run() -> tuple[bool, bool]:
        previous = signal.signal(signal.SIGINT, runner_handler)
        try:
            try:
                _guard()
            except zero_network.ZeroNetworkChangeStopped as stopped:
                return stopped.cancelled, signal.getsignal(signal.SIGINT) is runner_handler
            return False, False
        finally:
            signal.signal(signal.SIGINT, previous)

    cancelled, restored = asyncio.run(run())

    assert cancelled
    assert seen == [(True, True)]
    assert restored


def test_ctrl_c_before_the_read_begins_cancels(
    home: Path, monkeypatch: pytest.MonkeyPatch, console: type[_Console]
) -> None:
    record = _stale_process_with_a_remote_selected(monkeypatch)

    class Interrupted(_Console):
        def write(self, value: str) -> None:
            raise KeyboardInterrupt

    monkeypatch.setattr("finishup.cli.trusted_console.TrustedForegroundConsole", Interrupted)

    try:
        with pytest.raises(zero_network.ZeroNetworkChangeStopped) as stopped:
            _guard()
    except KeyboardInterrupt:
        pytest.fail("the interrupt escaped the prompt instead of cancelling the change")
    assert stopped.value.cancelled is True
    assert targets.read_selected_target_id() == record.target_id


_PTY_CHILD = textwrap.dedent(
    """
    import signal
    from types import SimpleNamespace

    # A fresh terminal process: SIGINT deliverable and Python's own handler, whatever the test
    # process's signal state was when it forked.
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})
    signal.signal(signal.SIGINT, signal.default_int_handler)

    import anyio
    import finishup.cli.zero_network_selection as zero_network

    # Only the process root, the selection and the switch are stand-ins: nothing reads or
    # changes real state.
    zero_network._on_everyday_root = lambda: True
    zero_network._remote_on_disk = lambda: SimpleNamespace(
        target_id="t_1a2b3c4d", kind="ssh", is_remote=True
    )

    def switch():
        print("SWITCHED", flush=True)
        return True

    zero_network._switch_to_local = switch

    async def main():
        try:
            return zero_network.guard_policy_change(forbids_network=True, interactive=True)
        except zero_network.ZeroNetworkChangeStopped as stopped:
            return "cancelled" if stopped.cancelled else "refused"

    print("OUTCOME " + anyio.run(main), flush=True)
    """
)


def _read_pty(fd: int, output: bytearray, until: bytes | None, seconds: float) -> bool:
    """Read the child's terminal until ``until`` appears (or, for ``None``, until it closes).

    False when the deadline passes first: the bounded wait observes the child's real output.
    """

    deadline = time.monotonic() + seconds
    while until is None or until not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            return until is None
        if not chunk:
            return until is None
        output.extend(chunk)
    return True


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX pseudo-terminals only")
def test_ctrl_c_at_a_real_console_prompt_cancels_the_change_and_exits() -> None:
    """A real pseudo-terminal, the production coroutine path, and ``anyio.run``'s SIGINT handler.

    Ctrl-C at the prompt must cancel the change, keep the server and let the command finish at
    once: never wait for another line, never switch.
    """

    pid, fd = pty.fork()
    if pid == 0:  # pragma: no cover - child process
        try:
            os.execv(sys.executable, [sys.executable, "-c", _PTY_CHILD])
        finally:
            os._exit(127)
    output = bytearray()
    finished = False
    try:
        assert _read_pty(fd, output, b"Enter cancels the change", 60), output.decode(
            "utf-8", "replace"
        )
        os.write(fd, b"\x03")
        finished = _read_pty(fd, output, None, 30)
    finally:
        if not finished:
            os.kill(pid, signal.SIGKILL)
        os.close(fd)
        _, status = os.waitpid(pid, 0)
    text = output.decode("utf-8", "replace")
    assert finished, text
    assert os.waitstatus_to_exitcode(status) == 0, text
    assert "Cancelled: nothing was changed." in text
    assert "the server t_1a2b3c4d (ssh) stays selected" in text
    assert "OUTCOME cancelled" in text
    assert "SWITCHED" not in text


def test_without_a_trusted_console_the_change_is_refused_before_it_is_applied(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = _stale_process_with_a_remote_selected(monkeypatch)
    console.unavailable = True

    with pytest.raises(zero_network.ZeroNetworkChangeStopped) as stopped:
        _guard()

    assert (stopped.value.reason, stopped.value.cancelled) == (zero_network.REMOTE_SELECTED, False)
    assert targets.read_selected_target_id() == record.target_id
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("zero_network_remote_selected: ")
    assert f"server {record.target_id} (ssh) is on another machine, a port or the web" in (
        captured.err
    )
    assert "nothing was changed" in captured.err
    assert "Run 'finishup server use local' in your own terminal, then make the change again" in (
        captured.err
    )


def test_non_interactive_and_machine_readable_never_prompt(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = _stale_process_with_a_remote_selected(monkeypatch)

    with pytest.raises(zero_network.ZeroNetworkChangeStopped):
        _guard(interactive=False)
    with (
        zero_network.machine_readable_answer(),
        pytest.raises(zero_network.ZeroNetworkChangeStopped),
    ):
        _guard(interactive=True)

    assert console.instances == []
    assert targets.read_selected_target_id() == record.target_id
    err = capsys.readouterr().err
    assert err.count("zero_network_remote_selected: ") == 2
    assert "lab.example" not in err


def test_an_unreadable_selection_offers_the_same_two_choices_or_is_refused(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = targets.selection_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with monkeypatch.context() as patched:
        patched.setattr(zero_network, "_on_everyday_root", lambda: True)
        path.write_bytes(b"[]\n")
        path.chmod(0o600)

        with pytest.raises(zero_network.ZeroNetworkChangeStopped) as refused:
            _guard(interactive=False)
        assert refused.value.reason == zero_network.SELECTION_UNREADABLE
        assert capsys.readouterr().err.startswith("zero_network_selection_unreadable: ")

        console.answer = b"1"
        assert _guard() == "switched"
    # 'server use local' clears a damaged selection: the change may then go ahead.
    assert not path.exists()
    assert "may still be selected" in _shown(console)


@pytest.mark.parametrize(
    "case", ["keeps_network", "nothing_selected", "local_selected", "on_remote_root", "isolated"]
)
def test_nothing_is_asked_or_refused_when_both_would_not_be_in_force(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    capsys: pytest.CaptureFixture[str],
    case: str,
) -> None:
    forbids = case != "keeps_network"
    if case == "keeps_network":
        _stale_process_with_a_remote_selected(monkeypatch)
    elif case == "local_selected":
        with targets.registry_lock():
            local, _root = targets.new_local_target("work")
        _select_elsewhere(local, monkeypatch)
    elif case == "on_remote_root":
        # A process on the remote server's root changes that server's own policy (D1b).
        _remote()
        reset_selection_memo()
        assert active_root() is not None
    elif case == "isolated":
        _remote()
        isolated = home / "isolated"
        isolated.mkdir(mode=0o700)
        monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", str(isolated))
        reset_selection_memo()

    assert _guard(forbids=forbids) == "clear"
    assert console.instances == []
    assert capsys.readouterr() == ("", "")


def test_which_candidates_would_make_this_computer_zero_network() -> None:
    from finishup.adapters.privacy.catalog import encode_privacy_policy_json
    from finishup.domain.privacy import AuthorizationScope, AuthorizationScopeKind

    machine_zero = local_only_policy()
    assert zero_network.candidate_forbids_network(machine_zero) is True
    assert zero_network.candidate_forbids_network(minimal_external_policy()) is False
    repository = replace(
        machine_zero,
        effective_scope=AuthorizationScope(
            AuthorizationScopeKind.WORKSPACE,
            machine_zero.effective_scope.installation_id,
            workspace_ref_commitment="hmac-sha256:" + "a" * 64,
        ),
    )
    assert zero_network.candidate_forbids_network(repository) is False
    wire = encode_privacy_policy_json(machine_zero)
    assert zero_network.candidate_forbids_network(wire) is True
    assert zero_network.candidate_forbids_network(encode_privacy_policy_json(repository)) is False
    assert zero_network.candidate_forbids_network({"network_egress_permitted": False}) is False
    assert zero_network.candidate_forbids_network(None) is False


# --- every path that changes this computer's policy ---------------------------------------------


class _PolicyClient:
    sent: list[str] = []

    def __init__(self, outcome: str) -> None:
        self.outcome = outcome

    def _result(self, schema_version: str | None = None) -> JsonObject:
        body: dict[str, JsonValue] = {"outcome": self.outcome}
        if schema_version is not None:
            body["schema_version"] = schema_version
        if self.outcome == "decision_required":
            body["proposal_id"] = "ppr_10000000-0000-4000-8000-000000000009"
        return JsonObject(body)

    async def privacy_propose_policy(self, request: JsonObject, **_kwargs: object) -> JsonObject:
        _PolicyClient.sent.append("propose")
        return self._result(cast(str | None, request.get("schema_version")))

    async def privacy_tighten_policy(self, _request: JsonObject, **_kwargs: object) -> JsonObject:
        _PolicyClient.sent.append("tighten")
        return self._result()

    async def close(self) -> None:
        return None


def _serve(monkeypatch: pytest.MonkeyPatch, outcome: str) -> list[str]:
    _PolicyClient.sent = []

    async def build(*_args: object, **_kwargs: object) -> _PolicyClient:
        return _PolicyClient(outcome)

    monkeypatch.setattr(cli, "build_service_client", build)
    return _PolicyClient.sent


def _record_steps(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, object]]:
    """Record the guard before each change (with its two facts) and the read after it."""

    steps: list[tuple[str, object]] = []

    def guard(*, forbids_network: bool, interactive: bool) -> str:
        steps.append(("guard", (forbids_network, interactive)))
        return "clear"

    async def after() -> None:
        steps.append(("after", None))

    monkeypatch.setattr(zero_network, "guard_policy_change", guard)
    monkeypatch.setattr(zero_network, "after_policy_change_async", after)
    return steps


@pytest.mark.parametrize(
    ("outcome", "applied"), [("tightening_applied", True), ("decision_required", False)]
)
@pytest.mark.parametrize("terminal", [True, False])
def test_a_repository_policy_change_is_guarded_before_and_remembered_once_it_applies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, outcome: str, applied: bool, terminal: bool
) -> None:
    import finishup.cli.privacy_setup as privacy_setup

    steps = _record_steps(monkeypatch)
    _serve(monkeypatch, outcome)
    monkeypatch.setattr(privacy_setup, "_interactive_terminal", lambda: terminal)

    asyncio.run(
        privacy_setup._propose(  # pyright: ignore[reportPrivateUsage]
            local_only_policy(), "sha256:" + "d" * 64, workspace_locator=tmp_path
        )
    )

    assert steps == [("guard", (True, terminal)), *([("after", None)] if applied else [])]


def test_a_relayed_proposal_is_refused_never_offered(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """The elevated bootstrap relays an agent chat's approval: no console, nothing sent."""

    import finishup.cli.privacy_setup as privacy_setup

    record = _stale_process_with_a_remote_selected(monkeypatch)
    sent = _serve(monkeypatch, "tightening_applied")
    monkeypatch.setattr(privacy_setup, "_interactive_terminal", lambda: True)

    with pytest.raises(zero_network.ZeroNetworkChangeStopped) as refused:
        asyncio.run(
            privacy_setup.propose_privacy_candidate(
                local_only_policy(), "sha256:" + "d" * 64, workspace_locator=tmp_path
            )
        )

    assert refused.value.cancelled is False
    assert sent == []
    assert console.instances == []
    assert targets.read_selected_target_id() == record.target_id
    assert capsys.readouterr().err.startswith("zero_network_remote_selected: ")


@pytest.mark.parametrize(
    ("outcome", "applied"), [("tightening_applied", True), ("decision_required", False)]
)
def test_a_machine_policy_change_is_guarded_before_and_remembered_once_it_applies(
    monkeypatch: pytest.MonkeyPatch, outcome: str, applied: bool
) -> None:
    import finishup.cli.privacy_setup as privacy_setup

    steps = _record_steps(monkeypatch)
    _serve(monkeypatch, outcome)
    monkeypatch.setattr(privacy_setup, "_interactive_terminal", lambda: True)

    asyncio.run(
        privacy_setup._propose_machine(  # pyright: ignore[reportPrivateUsage]
            minimal_external_policy(), "sha256:" + "2" * 64
        )
    )
    assert steps == [("guard", (False, True)), *([("after", None)] if applied else [])]

    if outcome == "tightening_applied":
        steps.clear()
        asyncio.run(
            privacy_setup._tighten_machine(  # pyright: ignore[reportPrivateUsage]
                local_only_policy(), "sha256:" + "2" * 64
            )
        )
        assert steps == [("guard", (True, True)), ("after", None)]


def _decision(status: str) -> object:
    from finishup.service.confidential_protocol import PrivacyDecisionResult

    return PrivacyDecisionResult(status, "sha256:" + "c" * 64)  # pyright: ignore[reportArgumentType]


class _NoStoredPassphrase:
    def __init__(self, _root: object) -> None:
        return None

    def load(self) -> None:
        return None


@pytest.mark.parametrize(("status", "applied"), [("committed", True), ("denied", False)])
def test_a_trusted_decision_is_remembered_only_when_it_commits(
    home: Path, monkeypatch: pytest.MonkeyPatch, status: str, applied: bool
) -> None:
    import finishup.cli.privacy_setup as privacy_setup

    steps = _record_steps(monkeypatch)
    monkeypatch.setattr(privacy_setup, "_interactive_terminal", lambda: False)
    monkeypatch.setattr(
        "finishup.adapters.keys.os_keyring.AutoUnlockPassphraseStore", _NoStoredPassphrase
    )

    async def decide(_proposal_id: str) -> object:
        return _decision(status)

    monkeypatch.setattr("finishup.cli.privacy_control.decide_policy", decide)

    decision = asyncio.run(privacy_setup._decide("ppr_1"))  # pyright: ignore[reportPrivateUsage]

    assert getattr(decision, "status", None) == status
    assert steps == ([("after", None)] if applied else [])


def _request(policy: PrivacyPolicy) -> str:
    from finishup.adapters.privacy.catalog import encode_privacy_policy_json

    return json.dumps(
        {
            "expected_policy_digest": "sha256:" + "2" * 64,
            "candidate_policy": cast(object, encode_privacy_policy_json(policy)),
        }
    )


@pytest.mark.parametrize("command", ["tighten", "propose"])
def test_the_privacy_commands_refuse_a_zero_network_change_with_json_and_send_nothing(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    command: str,
) -> None:
    record = _remote(select=False)
    sent = _serve(monkeypatch, "tightening_applied")
    monkeypatch.setattr(zero_network, "interactive_terminal", lambda: True)
    # This process resolved this computer's server before another terminal chose the remote one.
    monkeypatch.setattr(zero_network, "_on_everyday_root", lambda: True)
    with targets.registry_lock():
        targets.write_selection(record)

    result = _invoke("privacy", command, "--request", _request(local_only_policy()), "--json")

    assert result.exit_code == 2, result.output
    assert sent == []
    assert result.stdout == ""
    assert result.stderr.startswith("zero_network_remote_selected: ")
    assert "'finishup server use local'" in result.stderr
    assert console.instances == []
    assert targets.read_selected_target_id() == record.target_id


@pytest.mark.parametrize(("answer", "switched"), [(b"1", True), (b"2", False)])
def test_the_privacy_commands_offer_the_two_choices_on_the_owners_terminal(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    answer: bytes,
    switched: bool,
) -> None:
    steps: list[str] = []

    async def after() -> None:
        steps.append("after")

    record = _remote(select=False)
    sent = _serve(monkeypatch, "tightening_applied")
    monkeypatch.setattr(zero_network, "interactive_terminal", lambda: True)
    monkeypatch.setattr(zero_network, "_on_everyday_root", lambda: True)
    monkeypatch.setattr(zero_network, "after_policy_change_async", after)
    with targets.registry_lock():
        targets.write_selection(record)
    console.answer = answer

    result = _invoke("privacy", "tighten", "--request", _request(local_only_policy()))

    assert len(console.instances) == 1
    if switched:
        assert result.exit_code == 0, result.output
        assert sent == ["tighten"] and steps == ["after"]
        assert targets.read_selected_target_id() is None
        assert "Using this computer's everyday FinishUP server." in result.stdout
    else:
        assert result.exit_code == 2, result.output
        assert sent == [] and steps == []
        assert targets.read_selected_target_id() == record.target_id
        assert "Cancelled: nothing was changed." in result.stdout


def test_a_change_that_keeps_network_use_is_sent_without_a_question(
    home: Path, monkeypatch: pytest.MonkeyPatch, console: type[_Console]
) -> None:
    record = _remote()
    sent = _serve(monkeypatch, "tightening_applied")
    monkeypatch.setattr(zero_network, "_on_everyday_root", lambda: True)

    result = _invoke(
        "privacy", "tighten", "--request", _request(minimal_external_policy()), "--json"
    )

    assert result.exit_code == 0, result.output
    assert sent == ["tighten"]
    assert console.instances == []
    assert targets.read_selected_target_id() == record.target_id


def test_a_proposal_that_needs_a_decision_reads_nothing_yet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    steps = _record_steps(monkeypatch)
    _serve(monkeypatch, "decision_required")

    result = _invoke("privacy", "propose", "--request", "{}", "--json")

    assert result.exit_code == 0, result.output
    assert steps == [("guard", (False, False))]


_SETTING_COMMANDS = (
    (("privacy", "credential-heuristic", "enable"), "run_credential_heuristic_change"),
    (("privacy", "conversations", "local-only"), "run_conversation_review_change"),
    (("privacy", "input-roots", "remove", "/srv/shared"), "run_input_root_change"),
)


@pytest.mark.parametrize(("arguments", "function"), _SETTING_COMMANDS)
@pytest.mark.parametrize("json_output", [False, True])
def test_the_setting_commands_offer_the_choice_only_without_json(
    monkeypatch: pytest.MonkeyPatch, arguments: tuple[str, ...], function: str, json_output: bool
) -> None:
    import finishup.cli.privacy_setup as privacy_setup

    machine_readable: list[bool] = []

    async def change(*_args: object, **_kwargs: object) -> object:
        machine_readable.append(zero_network.machine_readable_requested())
        return privacy_setup.PrivacySetupReport("configured", "local_only")

    monkeypatch.setattr(privacy_setup, function, change)

    result = _invoke(*arguments, *(["--json"] if json_output else []))

    assert result.exit_code == 0, result.output
    # A JSON answer keeps stdout to the document: no console choice, the refusal on stderr.
    assert machine_readable == [json_output]
    assert zero_network.machine_readable_requested() is False


def _granted(policy: PrivacyPolicy) -> object:
    import finishup.cli.privacy_setup as privacy_setup

    snapshot = privacy_setup.PrivacySetupSnapshot(
        policy,
        JsonObject({"kind": "machine", "installation_id": "ins_1"}),
        "sha256:" + "d" * 64,
        "granted",
        "not_applicable",
    )

    async def read(_locator: object = None) -> object:
        return snapshot

    return read


@pytest.mark.parametrize("change", ["credential_heuristic", "conversations", "input_roots"])
@pytest.mark.parametrize("json_output", [False, True])
def test_a_json_answer_reaches_every_policy_change_beneath_the_command(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    change: str,
    json_output: bool,
) -> None:
    """The real setting changes and the real guard; only the services and console are fakes.

    Each change leaves this computer's machine policy zero-network while a remote server is
    selected: a JSON answer is refused before anything is sent; the owner's terminal asks.
    """

    import finishup.cli.privacy_setup as privacy_setup

    record = _stale_process_with_a_remote_selected(monkeypatch)
    sent = _serve(monkeypatch, "tightening_applied")
    monkeypatch.setattr(privacy_setup, "_interactive_terminal", lambda: True)
    console.answer = b"2"

    async def run() -> object:
        with zero_network.machine_readable_answer(json_output):
            if change == "credential_heuristic":
                machine = replace(
                    local_only_policy(), credential_heuristic=CredentialHeuristic.DISABLED
                )

                async def machine_policy() -> PrivacyPolicy:
                    return machine

                monkeypatch.setattr(privacy_setup, "_machine_effective_policy", machine_policy)
                return await privacy_setup.run_credential_heuristic_change(
                    CredentialHeuristic.ENFORCED, machine_default=True
                )
            if change == "conversations":
                current = replace(
                    local_only_policy(), conversation_review=ConversationReview.AI_POWERED
                )
                monkeypatch.setattr(privacy_setup, "get_privacy_setup_snapshot", _granted(current))
                return await privacy_setup.run_conversation_review_change(
                    ConversationReview.LOCAL_ONLY, workspace_locator=tmp_path
                )
            root = str(tmp_path.resolve())
            current = replace(local_only_policy(), admitted_input_roots=(root,))
            monkeypatch.setattr(privacy_setup, "get_privacy_setup_snapshot", _granted(current))
            return await privacy_setup.run_input_root_change(
                "remove", root, workspace_locator=tmp_path
            )

    with pytest.raises(zero_network.ZeroNetworkChangeStopped) as stopped:
        asyncio.run(run())

    assert sent == []
    assert targets.read_selected_target_id() == record.target_id
    captured = capsys.readouterr()
    if json_output:
        assert stopped.value.cancelled is False
        assert console.instances == []
        assert captured.out == ""
        assert captured.err.startswith("zero_network_remote_selected: ")
    else:
        assert stopped.value.cancelled is True
        assert len(console.instances) == 1
        assert "Cancelled: nothing was changed." in captured.out


def test_the_questionnaire_reports_a_cancelled_change_with_its_reason(
    home: Path, monkeypatch: pytest.MonkeyPatch, console: type[_Console], tmp_path: Path
) -> None:
    import finishup.cli.privacy_setup as privacy_setup

    _stale_process_with_a_remote_selected(monkeypatch)
    sent = _serve(monkeypatch, "tightening_applied")
    monkeypatch.setattr(privacy_setup, "_interactive_terminal", lambda: True)
    current = minimal_external_policy()
    monkeypatch.setattr(privacy_setup, "get_privacy_setup_snapshot", _granted(current))

    def quiet(_snapshot: object) -> None:
        return None

    def chosen(*_args: object, **_kwargs: object) -> PrivacyPolicy:
        return local_only_policy()

    monkeypatch.setattr(privacy_setup, "_render_repository_authority", quiet)
    monkeypatch.setattr(privacy_setup, "_configured_bindings", lambda: (None, None))
    monkeypatch.setattr(privacy_setup, "_configured_fallback_binding", lambda: None)
    monkeypatch.setattr(privacy_setup, "_choose_candidate", chosen)
    console.answer = "empty_input"

    report = asyncio.run(
        privacy_setup._privacy_setup_questionnaire(  # pyright: ignore[reportPrivateUsage]
            recipe_hint="private",
            offer_recommended=False,
            credential_probe_authorized=False,
            update_checks_override=None,
            workspace_locator=tmp_path,
            credential_heuristic=None,
            conversation_review=None,
            ai_review_add_on=False,
            ai_review_add_on_when_hybrid=False,
            decide_here=True,
        )
    )

    assert (report.outcome, report.reason) == ("cancelled", "zero_network_remote_selected")
    assert sent == []


@pytest.mark.parametrize("json_output", [False, True])
def test_a_process_on_this_computers_server_with_a_remote_selected_meanwhile(
    home: Path, monkeypatch: pytest.MonkeyPatch, console: type[_Console], json_output: bool
) -> None:
    """End to end through a real command, the one way this computer's policy changes then.

    While a remote server is selected, a fresh command cannot set this computer's policy: its
    privacy ceremonies are refused (``requires_server_host``) and ``privacy tighten|propose``
    reach the selected server. A FinishUP process that resolved this computer's server first
    can: here ``privacy credential-heuristic enable --machine-default`` passes its server-host
    check on the everyday root, another terminal then selects the remote server, and the change
    would leave this computer zero-network with it selected. With ``--json`` it is refused before
    anything is sent; on the owner's terminal "1" switches, the change is made, and this
    computer's policy is read again and remembered. The selection, the guard, the switch and the
    policy read are the real code; only the two services and the console are stand-ins.
    """

    import finishup.cli.privacy_setup as privacy_setup

    monkeypatch.setattr(
        zero_network,
        "_after_change_state",
        zero_network._read_after_change,  # pyright: ignore[reportPrivateUsage]
    )
    record = _remote(select=False)
    policy_reads = _everyday_service(home, monkeypatch, egress=False)
    console.answer = b"1"
    monkeypatch.setattr(privacy_setup, "_interactive_terminal", lambda: True)
    roots: list[Path | None] = []
    machine = replace(local_only_policy(), credential_heuristic=CredentialHeuristic.DISABLED)

    async def machine_policy() -> PrivacyPolicy:
        roots.append(active_root())
        _select_elsewhere(record, monkeypatch)
        return machine

    sent: list[str] = []

    async def build(*_args: object, **_kwargs: object) -> _PolicyClient:
        roots.append(active_root())
        _PolicyClient.sent = sent
        return _PolicyClient("tightening_applied")

    monkeypatch.setattr(privacy_setup, "_machine_effective_policy", machine_policy)
    monkeypatch.setattr(cli, "build_service_client", build)

    result = _invoke(
        "privacy",
        "credential-heuristic",
        "enable",
        "--machine-default",
        *(["--json"] if json_output else []),
    )

    if json_output:
        assert result.exit_code == 20, result.output
        assert sent == [] and policy_reads == []
        assert console.instances == []
        assert targets.read_selected_target_id() == record.target_id
        assert result.stderr.startswith("zero_network_remote_selected: ")
        assert read_marker() == "absent"
    else:
        assert result.exit_code == 0, result.output
        assert roots == [None, None]
        assert sent == ["tighten"]
        assert f"2  Cancel this change and keep using the server {record.target_id} (ssh)" in (
            _shown(console)
        )
        assert targets.read_selected_target_id() is None
        assert "Using this computer's everyday FinishUP server." in result.stdout
        # The real stop of what this client ran for it (no connector was running here).
        assert (
            f"Closed this computer's connection to the server {record.target_id} (ssh)"
        ) in result.stdout
        # The change was made on this computer: its policy is read again and remembered.
        assert policy_reads == [_MACHINE_SCOPE]
        assert cast(ReportedPolicy, read_marker()).zero_network is True


@pytest.mark.parametrize(("status", "applied"), [("committed", True), ("stale", False)])
def test_decide_policy_remembers_after_a_committed_decision(
    monkeypatch: pytest.MonkeyPatch, status: str, applied: bool
) -> None:
    steps = _record_steps(monkeypatch)
    monkeypatch.setattr(cli, "_auto_unlock_store", lambda: _NoStoredPassphrase(None))

    async def decide(_pending_id: str) -> object:
        return _decision(status)

    monkeypatch.setattr("finishup.cli.privacy_control.decide_policy", decide)

    result = _invoke("privacy", "decide-policy", "ppr_1", "--json")

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["status"] == status
    assert steps == ([("after", None)] if applied else [])


# --- visible while it lasts -------------------------------------------------------------------


def _unreachable(_self: object, _root: Path | None) -> object:
    from finishup.client.target_runtime import ProbeResult

    return ProbeResult("unavailable", reason="remote_unreachable")


def test_server_status_and_list_show_the_item(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    record = _remote()
    _policy(monkeypatch, "zero_network")
    monkeypatch.setattr(
        "finishup.client.connector_runtime.ConnectorTargetRuntime.probe", _unreachable
    )

    status = _invoke("server", "status", "--json")
    assert status.exit_code == 0, status.output
    document = cast(JsonValue, json.loads(status.stdout))
    validate_schema_instance("server-target-status", "1.0.0", document)
    assert status.stderr.startswith("zero_network_remote_selected: ")
    assert "finishup server use local" in status.stderr

    listed = _invoke("server", "list")
    assert listed.exit_code == 0, listed.output
    first = listed.stdout.splitlines()[0]
    assert first.startswith("This computer's privacy policy forbids all network use")
    assert f"{record.target_id} (ssh)" in first

    server_cli._show_zero_network_item(machine_readable=False)  # pyright: ignore[reportPrivateUsage]
    out = capsys.readouterr().out
    assert "To keep working, run 'finishup server use local'" in out


def test_server_status_text_and_json_say_this_computer_last_reported_it(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _remote("https")
    record_reported_policy(zero_network=True, now=_AT)
    _policy(monkeypatch, "unreadable")
    monkeypatch.setattr(
        "finishup.client.connector_runtime.ConnectorTargetRuntime.probe", _unreachable
    )

    document, stderr = _status_document()

    assert document["zero_network_selection"] == {
        "reason": "zero_network_remote_selected",
        "target_id": record.target_id,
        "kind": "https",
        "detail": None,
        "policy_read": "last_reported",
        "last_reported_at": _STAMP,
    }
    assert stderr.startswith(
        f"zero_network_remote_selected: This computer last reported, at {_STAMP}"
    )

    listed = _invoke("server", "list")
    assert listed.stdout.startswith(f"This computer last reported, at {_STAMP}")


def test_server_status_is_unchanged_without_the_item(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _remote()
    _policy(monkeypatch, "network_permitted")
    monkeypatch.setattr(
        "finishup.client.connector_runtime.ConnectorTargetRuntime.probe", _unreachable
    )

    status = _invoke("server", "status", "--json")

    assert status.exit_code == 0, status.output
    assert status.stderr == ""
    assert json.loads(status.stdout)["zero_network_selection"] is None


def _status_document(*arguments: str) -> tuple[dict[str, JsonValue], str]:
    status = _invoke("server", "status", *arguments, "--json")
    assert status.exit_code == 0, status.output
    document = cast(dict[str, JsonValue], json.loads(status.stdout))
    validate_schema_instance("server-target-status", "1.0.0", cast(JsonValue, document))
    return document, status.stderr


def test_server_status_json_carries_the_remote_selected_item(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The document's ``zero_network_selection`` is the item the owner sees on stderr beside it,
    by generated id and closed kind, and this computer's policy is asked once for both."""

    record = _remote("https")
    reads = _policy(monkeypatch, "zero_network")
    monkeypatch.setattr(
        "finishup.client.connector_runtime.ConnectorTargetRuntime.probe", _unreachable
    )

    document, stderr = _status_document()

    assert document["zero_network_selection"] == {
        "reason": "zero_network_remote_selected",
        "target_id": record.target_id,
        "kind": "https",
        "detail": None,
        "policy_read": "live",
        "last_reported_at": None,
    }
    assert stderr.startswith("zero_network_remote_selected: ")
    assert reads == [1]
    assert _NAME not in json.dumps(document["zero_network_selection"])


def test_server_status_json_carries_an_unreadable_selection_with_its_reason(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A selected target whose record cannot be read is the unreadable item, with its closed
    reason and no server named; ``server status local`` still answers its document."""

    record = _remote()
    marker = targets.target_root(record.target_id) / "target.json"
    marker.write_bytes(b"{not json\n")
    _policy(monkeypatch, "zero_network")

    document, stderr = _status_document("local")

    assert document["zero_network_selection"] == {
        "reason": "zero_network_selection_unreadable",
        "target_id": None,
        "kind": None,
        "detail": "target_record_invalid",
        "policy_read": "live",
        "last_reported_at": None,
    }
    assert stderr.startswith("zero_network_selection_unreadable: ")


@pytest.mark.parametrize("state", ["network_permitted", "no_policy", "unreadable"])
def test_server_status_json_says_nothing_when_there_is_nothing_to_say(
    home: Path, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    """Null, never a guess: no selection asks no service; a remote selection under a policy that
    permits network use, was never set up, or cannot be read with no zero-network report is not
    the item."""

    reads = _policy(monkeypatch, state)
    document, stderr = _status_document()
    assert (document["zero_network_selection"], stderr, reads) == (None, "", [])

    _remote()
    monkeypatch.setattr(
        "finishup.client.connector_runtime.ConnectorTargetRuntime.probe", _unreachable
    )
    document, stderr = _status_document()
    assert (document["zero_network_selection"], stderr, reads) == (None, "", [1])


def test_the_status_document_reads_the_item_itself_when_not_given_one(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller that has not read the item (``server status`` and the terminal interface pass
    the one they showed) gets the document's own read of the check."""

    record = _remote("local_port")
    _policy(monkeypatch, "zero_network")
    monkeypatch.setattr(
        "finishup.client.connector_runtime.ConnectorTargetRuntime.probe", _unreachable
    )
    reset_selection_memo()

    document = server_cli.build_status_document(None)

    assert document["zero_network_selection"] == {
        "reason": "zero_network_remote_selected",
        "target_id": record.target_id,
        "kind": "local_port",
        "detail": None,
        "policy_read": "live",
        "last_reported_at": None,
    }


def test_server_test_never_asks_this_computers_policy(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``server test`` shows the probe only, never the item, so it asks no service for it."""

    _remote()
    reads = _policy(monkeypatch, "zero_network")
    monkeypatch.setattr(
        "finishup.client.connector_runtime.ConnectorTargetRuntime.probe", _unreachable
    )

    result = _invoke("server", "test")

    assert "State: unavailable (remote_unreachable)" in result.stdout
    assert reads == []


@pytest.mark.parametrize("policy_read", ["live", "last_reported"])
def test_setup_readiness_names_the_item_with_its_continuation(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    policy_read: str,
) -> None:
    from finishup.cli import setup_readiness

    record = _remote()
    if policy_read == "live":
        _policy(monkeypatch, "zero_network")
    else:
        record_reported_policy(zero_network=True, now=_AT)
        _policy(monkeypatch, "unreadable")

    def readiness(json_output: bool) -> str:
        code = setup_readiness._setup_next(  # pyright: ignore[reportPrivateUsage]
            operation="connection",
            host=None,
            executable=None,
            config_root=None,
            project=home,
            route=None,
            json_output=json_output,
        )
        assert code == 0
        return capsys.readouterr().out

    report = json.loads(readiness(True))
    fact = report["facts"]["server_selection"]
    assert {
        key: fact[key]
        for key in ("reason", "target_id", "kind", "detail", "policy_read", "last_reported_at")
    } == {
        "reason": "zero_network_remote_selected",
        "target_id": record.target_id,
        "kind": "ssh",
        "detail": None,
        "policy_read": policy_read,
        "last_reported_at": None if policy_read == "live" else _STAMP,
    }
    assert fact["next_command"].endswith("server use local")

    human = readiness(False)
    line = next(line for line in human.splitlines() if line.startswith("Server: "))
    assert f"refuses the selected server {record.target_id} (ssh)" in line
    assert "server use local, then restart open agent sessions" in line
    if policy_read == "last_reported":
        assert f"last reported, at {_STAMP}" in line


def test_setup_status_puts_the_item_on_stderr(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import finishup.cli.host_connection as host_connection
    from finishup.cli import setup

    _remote()
    _policy(monkeypatch, "zero_network")

    async def observed() -> tuple[dict[str, object], None]:
        return {"reachable": False}, None

    def no_layers(*_args: object) -> dict[str, object]:
        return {}

    monkeypatch.setattr(setup, "discover_codex_binaries", tuple)
    monkeypatch.setattr(setup, "_service_reachability_observed", observed)
    monkeypatch.setattr(setup, "_integration_layers", no_layers)
    monkeypatch.setattr(setup, "_platform_diagnostics", dict)
    monkeypatch.setattr(host_connection, "installation_rows", list)

    assert asyncio.run(setup.setup_status(json_output=True)) == 0

    captured = capsys.readouterr()
    assert json.loads(captured.out)["schema"] == "yoetz.setup-status/2"
    assert captured.err.startswith("zero_network_remote_selected: ")


@pytest.mark.parametrize("policy_read", ["live", "last_reported"])
def test_the_menu_home_shows_the_item(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], policy_read: str
) -> None:
    from finishup.cli import menu

    item = zero_network.ZeroNetworkSelection(
        zero_network.REMOTE_SELECTED,
        "t_1a2b3c4d",
        "ssh",
        policy_read=cast(zero_network.PolicyRead, policy_read),
        last_reported_at=None if policy_read == "live" else _STAMP,
    )

    async def service() -> str:
        return "reachable"

    async def harness() -> tuple[str, ...]:
        return ()

    monkeypatch.setattr(menu, "_service_summary", service)
    monkeypatch.setattr(menu, "_harness_summary", harness)
    monkeypatch.setattr("finishup.cli.setup.setup_marker_present", lambda: True)
    monkeypatch.setattr(zero_network, "find_zero_network_selection", lambda: item)

    menu._print_home(menu._gather_overview())  # pyright: ignore[reportPrivateUsage]

    lines = [line for line in capsys.readouterr().out.splitlines() if "Server" in line]
    assert lines and all(line.startswith("  Server     ") for line in lines)
    assert any("t_1a2b3c4d (ssh)" in line for line in lines)
    assert any("finishup server use local" in line for line in lines)
    if policy_read == "last_reported":
        assert any(f"last reported, at {_STAMP}" in line for line in lines)


def test_the_menu_privacy_view_remembers_this_computers_policy(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.cli import menu

    class Client:
        async def privacy_get_effective(self, _request: object) -> object:
            return _effective(egress=False)

        async def close(self) -> None:
            return None

    async def build(*_args: object, **_kwargs: object) -> Client:
        return Client()

    monkeypatch.setattr(cli, "build_service_client", build)
    monkeypatch.setattr(
        "finishup.cli.provider_status.machine_scope_request", lambda: _MACHINE_SCOPE
    )

    def shown(_result: object) -> None:
        return None

    monkeypatch.setattr(menu, "_show", shown)

    asyncio.run(menu._privacy_show("privacy_get_effective"))  # pyright: ignore[reportPrivateUsage]

    assert cast(ReportedPolicy, read_marker()).zero_network is True


def test_setup_reading_the_update_policy_remembers_this_computers_policy(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.cli import setup

    class Client:
        async def privacy_get_effective(self, _request: object) -> object:
            return _effective(egress=True)

        async def close(self) -> None:
            return None

    async def build(*_args: object, **_kwargs: object) -> Client:
        return Client()

    monkeypatch.setattr(cli, "build_service_client", build)
    monkeypatch.setattr(
        "finishup.cli.provider_status.machine_scope_request", lambda: _MACHINE_SCOPE
    )

    network, _enabled = asyncio.run(
        setup._effective_update_policy_bits()  # pyright: ignore[reportPrivateUsage]
    )

    assert network is True
    assert cast(ReportedPolicy, read_marker()).zero_network is False
