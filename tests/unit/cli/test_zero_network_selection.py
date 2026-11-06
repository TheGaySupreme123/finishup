"""A remote server still selected when this computer's policy forbids network use (ADR-051).

Maintainer decision of 2026-11-06 (decision 8): whenever this computer's privacy policy is set to
the zero-network state while the selection names a server on another machine, a port or the web,
FinishUP tells the owner and lets them decide. On the trusted console the owner chooses to switch
to this computer's everyday FinishUP or keep the server, and anything but "1" keeps it; without a
console the facts and ``finishup server use local`` go to stderr and nothing switches. The same
item shows afterwards on ``server status``/``list``, ``setup status [--next]``, the setup wizard
and the menu. An unreadable selection is said with its closed reason, never as "no server". Every
line names the target by its generated id and closed kind, never by the name the owner typed.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner, Result

import finishup.cli.zero_network_selection as zero_network
from builders.privacy_policies import local_only_policy
from builders.server_targets import ambient_home
from finishup.cli import app as cli
from finishup.cli import server as server_cli
from finishup.client import targets
from finishup.config.paths import reset_selection_memo
from finishup.domain.values import JsonObject
from finishup.protocol.canonical import JsonValue
from finishup.protocol.schemas import validate_schema_instance

_RUNNER = CliRunner()
_NAME = "lab"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """An owner-only ambient home whose selection the checks really read."""

    with ambient_home(monkeypatch) as root:
        monkeypatch.setattr(zero_network, "_selection_on_disk", zero_network.read_selection_on_disk)
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


# --- the item ---------------------------------------------------------------------------------


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
    assert f"{record.target_id} ({kind})" in text
    assert "does not stop traffic" in text
    assert "'finishup server use local', then restart open agent sessions" in text
    for line in (*item.lines(), item.line(), item.indicator(), item.next_step()):
        assert _NAME not in line.replace(record.target_id, "")
        assert "lab.example" not in line and "127.0.0.1" not in line
    assert item.line().startswith("zero_network_remote_selected: ")


@pytest.mark.parametrize("state", ["network_permitted", "no_policy", "unreadable"])
def test_nothing_is_claimed_unless_the_policy_is_zero_network(
    home: Path, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    _remote()
    reads = _policy(monkeypatch, state)

    assert zero_network.find_zero_network_selection() is None
    assert reads == [1]


def test_no_selection_or_a_local_one_asks_no_service(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    assert "cannot tell whether a server on another machine is still selected" in text
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
    reads = _policy(monkeypatch, "zero_network")
    isolated = home / "isolated"
    isolated.mkdir(mode=0o700)
    monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", str(isolated))
    reset_selection_memo()

    assert zero_network.find_zero_network_selection() is None
    assert reads == []


@pytest.mark.parametrize(
    ("egress", "state"), [(False, "zero_network"), (True, "network_permitted")]
)
def test_the_everyday_machine_scope_policy_decides(
    home: Path, monkeypatch: pytest.MonkeyPatch, egress: bool, state: str
) -> None:
    bundle = home / "data" / "finishup"
    bundle.mkdir(mode=0o700, parents=True)
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
        return Client()

    scope = JsonObject({"scope": {"kind": "machine"}})
    monkeypatch.setattr("finishup.service.client.connect_service", connect)
    monkeypatch.setattr("finishup.cli.provider_status.machine_scope_request", lambda: scope)

    assert zero_network.everyday_network_state() == state
    assert requests == [scope]


def test_a_computer_never_set_up_has_no_policy_of_its_own(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def never(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("nothing to ask")

    monkeypatch.setattr("finishup.service.client.connect_service", never)
    assert zero_network.everyday_network_state() == "no_policy"


# --- the owner's choice -----------------------------------------------------------------------


def test_choosing_1_switches_to_the_everyday_server(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = _remote()
    _policy(monkeypatch, "zero_network")
    console.answer = b"1"

    assert zero_network.surface_after_policy_change(interactive=True) == "switched"

    assert targets.read_selected_target_id() is None
    shown = _shown(console)
    assert f"{record.target_id} (ssh)" in shown
    assert "does not stop traffic" in shown
    assert "1  Switch to this computer's everyday FinishUP now" in shown
    assert f"2  Keep using the server {record.target_id} (ssh)" in shown
    assert console.instances[0].prompts == ["Choose 1 or 2 (Enter keeps the server): "]
    assert _NAME not in shown.replace(record.target_id, "")
    out = capsys.readouterr().out
    assert "Using this computer's everyday FinishUP server." in out
    assert "Restart open agent sessions" in out


def test_choosing_2_keeps_the_server(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = _remote()
    _policy(monkeypatch, "zero_network")
    console.answer = b"2"

    assert zero_network.surface_after_policy_change(interactive=True) == "kept"

    assert targets.read_selected_target_id() == record.target_id
    out = capsys.readouterr().out
    assert f"Kept the server {record.target_id} (ssh). Traffic to it continues" in out
    assert "'finishup server use local', then restart open agent sessions" in out


@pytest.mark.parametrize("answer", ["empty_input", "eof", "interrupted", "input_invalid"])
def test_enter_end_of_input_or_any_other_answer_keeps_the_server(
    home: Path, monkeypatch: pytest.MonkeyPatch, console: type[_Console], answer: str
) -> None:
    record = _remote()
    _policy(monkeypatch, "zero_network")
    console.answer = answer

    assert zero_network.surface_after_policy_change(interactive=True) == "kept"
    assert targets.read_selected_target_id() == record.target_id


def test_without_a_trusted_console_the_facts_go_to_stderr(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = _remote()
    _policy(monkeypatch, "zero_network")
    console.unavailable = True

    assert zero_network.surface_after_policy_change(interactive=True) == "warned"

    assert targets.read_selected_target_id() == record.target_id
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("zero_network_remote_selected: ")
    assert "'finishup server use local', then restart open agent sessions" in captured.err
    assert "FinishUP did not switch servers." in captured.err


def test_non_interactive_never_prompts_and_never_switches(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = _remote("https")
    _policy(monkeypatch, "zero_network")

    assert zero_network.surface_after_policy_change(interactive=False) == "warned"

    assert console.instances == []
    assert targets.read_selected_target_id() == record.target_id
    err = capsys.readouterr().err
    assert f"{record.target_id} (https)" in err
    assert "finishup server use local" in err
    assert "lab.example" not in err


def test_an_unreadable_selection_is_reported_not_offered(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    capsys: pytest.CaptureFixture[str],
) -> None:
    _policy(monkeypatch, "zero_network")
    path = targets.selection_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(b"[]\n")
    path.chmod(0o600)

    assert zero_network.surface_after_policy_change(interactive=True) == "warned"

    assert console.instances == []
    assert capsys.readouterr().err.startswith("zero_network_selection_unreadable: ")


def test_nothing_to_say_shows_nothing(
    home: Path,
    monkeypatch: pytest.MonkeyPatch,
    console: type[_Console],
    capsys: pytest.CaptureFixture[str],
) -> None:
    _remote()
    _policy(monkeypatch, "network_permitted")

    assert zero_network.surface_after_policy_change(interactive=True) == "clear"
    assert console.instances == []
    assert capsys.readouterr() == ("", "")


# --- every path that sets the policy ----------------------------------------------------------


def _record_surfacing(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    calls: list[bool] = []

    def surface(*, interactive: bool) -> str:
        calls.append(interactive)
        return "clear"

    monkeypatch.setattr(zero_network, "surface_after_policy_change", surface)
    return calls


class _PolicyClient:
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
        return self._result(cast(str | None, request.get("schema_version")))

    async def privacy_tighten_policy(self, _request: JsonObject, **_kwargs: object) -> JsonObject:
        return self._result()

    async def close(self) -> None:
        return None


def _serve(monkeypatch: pytest.MonkeyPatch, outcome: str) -> None:
    async def build(*_args: object, **_kwargs: object) -> _PolicyClient:
        return _PolicyClient(outcome)

    monkeypatch.setattr(cli, "build_service_client", build)


@pytest.mark.parametrize(
    ("outcome", "surfaced"), [("tightening_applied", True), ("decision_required", False)]
)
@pytest.mark.parametrize("terminal", [True, False])
def test_a_repository_policy_change_surfaces_once_it_applies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, outcome: str, surfaced: bool, terminal: bool
) -> None:
    import finishup.cli.privacy_setup as privacy_setup

    calls = _record_surfacing(monkeypatch)
    _serve(monkeypatch, outcome)
    monkeypatch.setattr(privacy_setup, "_interactive_terminal", lambda: terminal)

    asyncio.run(
        privacy_setup._propose(  # pyright: ignore[reportPrivateUsage]
            local_only_policy(), "sha256:" + "d" * 64, workspace_locator=tmp_path
        )
    )

    assert calls == ([terminal] if surfaced else [])


def test_a_relayed_proposal_never_prompts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import finishup.cli.privacy_setup as privacy_setup

    calls = _record_surfacing(monkeypatch)
    _serve(monkeypatch, "tightening_applied")
    monkeypatch.setattr(privacy_setup, "_interactive_terminal", lambda: True)

    asyncio.run(
        privacy_setup.propose_privacy_candidate(
            local_only_policy(), "sha256:" + "d" * 64, workspace_locator=tmp_path
        )
    )

    # The elevated bootstrap relays an agent chat's approval: stderr only, never a console.
    assert calls == [False]


@pytest.mark.parametrize(
    ("outcome", "surfaced"), [("tightening_applied", True), ("decision_required", False)]
)
def test_a_machine_policy_change_surfaces_once_it_applies(
    monkeypatch: pytest.MonkeyPatch, outcome: str, surfaced: bool
) -> None:
    import finishup.cli.privacy_setup as privacy_setup

    calls = _record_surfacing(monkeypatch)
    _serve(monkeypatch, outcome)
    monkeypatch.setattr(privacy_setup, "_interactive_terminal", lambda: True)

    asyncio.run(
        privacy_setup._propose_machine(  # pyright: ignore[reportPrivateUsage]
            local_only_policy(), "sha256:" + "2" * 64
        )
    )
    assert calls == ([True] if surfaced else [])

    if outcome == "tightening_applied":
        asyncio.run(
            privacy_setup._tighten_machine(  # pyright: ignore[reportPrivateUsage]
                local_only_policy(), "sha256:" + "2" * 64
            )
        )
        assert calls == [True, True]


def _decision(status: str) -> object:
    from finishup.service.confidential_protocol import PrivacyDecisionResult

    return PrivacyDecisionResult(status, "sha256:" + "c" * 64)  # pyright: ignore[reportArgumentType]


class _NoStoredPassphrase:
    def __init__(self, _root: object) -> None:
        return None

    def load(self) -> None:
        return None


@pytest.mark.parametrize(("status", "surfaced"), [("committed", True), ("denied", False)])
def test_a_trusted_decision_surfaces_only_when_it_commits(
    home: Path, monkeypatch: pytest.MonkeyPatch, status: str, surfaced: bool
) -> None:
    import finishup.cli.privacy_setup as privacy_setup

    calls = _record_surfacing(monkeypatch)
    monkeypatch.setattr(privacy_setup, "_interactive_terminal", lambda: False)
    monkeypatch.setattr(
        "finishup.adapters.keys.os_keyring.AutoUnlockPassphraseStore", _NoStoredPassphrase
    )

    async def decide(_proposal_id: str) -> object:
        return _decision(status)

    monkeypatch.setattr("finishup.cli.privacy_control.decide_policy", decide)

    decision = asyncio.run(privacy_setup._decide("ppr_1"))  # pyright: ignore[reportPrivateUsage]

    assert getattr(decision, "status", None) == status
    assert calls == ([False] if surfaced else [])


def _invoke(*arguments: str) -> Result:
    reset_selection_memo()
    return _RUNNER.invoke(cli.app, list(arguments))


@pytest.mark.parametrize("command", ["tighten", "propose"])
@pytest.mark.parametrize("json_output", [False, True])
def test_the_privacy_commands_surface_after_an_applied_tightening(
    monkeypatch: pytest.MonkeyPatch, command: str, json_output: bool
) -> None:
    calls = _record_surfacing(monkeypatch)
    _serve(monkeypatch, "tightening_applied")
    monkeypatch.setattr(zero_network, "interactive_terminal", lambda: True)

    arguments = ["privacy", command, "--request", "{}"]
    result = _invoke(*arguments, *(["--json"] if json_output else []))

    assert result.exit_code == 0, result.output
    # A machine-readable answer never prompts; a human terminal may.
    assert calls == [not json_output]


def test_a_proposal_that_needs_a_decision_surfaces_nothing_yet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _record_surfacing(monkeypatch)
    _serve(monkeypatch, "decision_required")

    result = _invoke("privacy", "propose", "--request", "{}", "--json")

    assert result.exit_code == 0, result.output
    assert calls == []


@pytest.mark.parametrize(("status", "surfaced"), [("committed", True), ("stale", False)])
def test_decide_policy_surfaces_after_a_committed_decision(
    monkeypatch: pytest.MonkeyPatch, status: str, surfaced: bool
) -> None:
    calls = _record_surfacing(monkeypatch)
    monkeypatch.setattr(zero_network, "interactive_terminal", lambda: True)
    monkeypatch.setattr(cli, "_auto_unlock_store", lambda: _NoStoredPassphrase(None))

    async def decide(_pending_id: str) -> object:
        return _decision(status)

    monkeypatch.setattr("finishup.cli.privacy_control.decide_policy", decide)

    result = _invoke("privacy", "decide-policy", "ppr_1", "--json")

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["status"] == status
    assert calls == ([False] if surfaced else [])


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


# --- visible afterwards ------------------------------------------------------------------------


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
    # The released contract keeps its shape; the item rides on stderr beside it.
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
    assert "To stop, run 'finishup server use local'" in out


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


def test_setup_readiness_names_the_item_with_its_continuation(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from finishup.cli import setup_readiness

    record = _remote()
    _policy(monkeypatch, "zero_network")

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
    assert {key: fact[key] for key in ("reason", "target_id", "kind", "detail")} == {
        "reason": "zero_network_remote_selected",
        "target_id": record.target_id,
        "kind": "ssh",
        "detail": None,
    }
    assert fact["next_command"].endswith("server use local")

    human = readiness(False)
    line = next(line for line in human.splitlines() if line.startswith("Server: "))
    assert f"{record.target_id} (ssh)" in line
    assert "server use local, then restart open agent sessions" in line


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


def test_the_menu_home_shows_the_item(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from finishup.cli import menu

    item = zero_network.ZeroNetworkSelection(zero_network.REMOTE_SELECTED, "t_1a2b3c4d", "ssh")

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
