"""Which FinishUP server's privacy policy a command changes (ADR-051 decision 8).

With a server on another machine, a port or the web selected, ``privacy tighten``, ``privacy
propose`` and the privacy step of ``setup run`` change that server's policy, not this computer's
everyday FinishUP's, and ``privacy decide-policy`` is refused here because a trusted decision runs
only on the server host. Following the maintainer's principle "be clear on what happened", each
says before the change and in its result which server it is, by generated id and closed kind,
never by the name the owner typed. Released output keeps its shape: the result document of
``tighten|propose`` is unchanged and the lines go to stderr, the same in text and JSON.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from typer.testing import CliRunner, Result

import finishup.cli.privacy_setup as privacy_setup
from builders.privacy_policies import local_only_policy
from builders.server_targets import ambient_home
from builders.tui_runtime import FakeRuntime
from finishup.cli import app as cli
from finishup.cli import setup as setup_cli
from finishup.cli.exits import exit_code_for
from finishup.cli.policy_server import PolicyServer, selected_policy_server
from finishup.client import targets
from finishup.config.paths import reset_selection_memo
from finishup.domain.privacy import PrivacyPolicy
from finishup.domain.values import JsonObject
from finishup.ports.control import ControlError
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PublicErrorCode
from finishup.tui.app import FinishUpTui
from finishup.tui.symbols import Level

_RUNNER = CliRunner()
# A name the owner typed: it must never appear in anything these paths print.
_NAME = "owner-typed-lab"
_REMOTE_KINDS = ("ssh", "https", "local_port")
_PROPOSAL = "ppr_10000000-0000-4000-8000-000000000009"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def _remote(kind: str = "ssh") -> targets.ServerTarget:
    fields: dict[str, object]
    if kind == "ssh":
        fields = {"user": "owner", "host": "lab.example", "port": 22}
    elif kind == "https":
        fields = {"base_url": "https://lab.example:8443", "tls_pin": "sha256:" + "a" * 64}
    else:
        fields = {"base_url": "https://127.0.0.1:8443", "tls_pin": "sha256:" + "a" * 64}
    with targets.registry_lock():
        record, _root = targets.new_remote_target(_NAME, kind, **fields)  # pyright: ignore[reportArgumentType]
        targets.write_selection(record)
    reset_selection_memo()
    return record


def _server(record: targets.ServerTarget) -> str:
    return f"{record.target_id} ({record.kind})"


# --- which server ------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", _REMOTE_KINDS)
def test_a_selected_remote_server_is_the_policy_server(home: Path, kind: str) -> None:
    record = _remote(kind)

    assert selected_policy_server() == PolicyServer(record.target_id, kind)


def test_this_computers_server_and_a_named_local_one_are_not_named(home: Path) -> None:
    assert selected_policy_server() is None

    with targets.registry_lock():
        record, _root = targets.new_local_target(_NAME)
        targets.write_selection(record)
    reset_selection_memo()

    # A named server on this computer is this computer's own server host (decision 11).
    assert selected_policy_server() is None


def test_an_unreadable_record_is_left_to_the_connection_that_refuses_it(home: Path) -> None:
    record = _remote()
    (targets.target_root(record.target_id) / "target.json").write_text("{}")

    assert selected_policy_server() is None


def test_every_line_names_the_server_by_id_and_kind_only() -> None:
    server = PolicyServer("t_1a2b3c4d", "ssh")
    lines = (
        server.before_line(),
        server.applied_line(),
        server.pending_line(),
        server.unchanged_line(),
        server.unconfirmed_line(),
        server.summary_suffix(),
    )

    assert all("t_1a2b3c4d (ssh)" in line for line in lines)
    assert "selected FinishUP server t_1a2b3c4d (ssh)" in server.before_line()
    assert "this computer's everyday FinishUP" in server.before_line()
    assert "'finishup privacy decide-policy' on that server host" in server.pending_line()
    assert "'finishup privacy show'" in server.unconfirmed_line()
    assert server.outcome_line("tightening_applied") == server.applied_line()
    assert server.outcome_line("decision_required") == server.pending_line()
    assert server.outcome_line("something_else") == server.unconfirmed_line()
    assert server.report_line("configured") == server.applied_line()
    assert server.report_line("cancelled", "requires_server_host") == server.pending_line()
    for outcome in ("unchanged", "cancelled", "failed"):
        assert server.report_line(outcome, "privacy_decision_not_approved") == (
            server.unchanged_line()
        )
    assert server.report_line(None) == server.unconfirmed_line()


# --- privacy tighten | propose -----------------------------------------------------------------


class _PolicyClient:
    def __init__(self, outcome: str | None, events: list[str]) -> None:
        self.outcome = outcome
        self.events = events

    def _result(self) -> JsonObject:
        if self.outcome is None:
            raise ControlError("service_unavailable", retryable=True)
        body: dict[str, JsonValue] = {"schema_version": "1.0.0", "outcome": self.outcome}
        if self.outcome == "decision_required":
            body["proposal_id"] = _PROPOSAL
        return JsonObject(body)

    async def privacy_propose_policy(self, _request: JsonObject, **_kwargs: object) -> JsonObject:
        self.events.append("request")
        return self._result()

    async def privacy_tighten_policy(self, _request: JsonObject, **_kwargs: object) -> JsonObject:
        self.events.append("request")
        return self._result()

    async def close(self) -> None:
        return None


def _serve(monkeypatch: pytest.MonkeyPatch, outcome: str | None) -> list[str]:
    """A stand-in service; ``events`` interleaves each request with every stderr line."""

    events: list[str] = []

    async def build(*_args: object, **_kwargs: object) -> _PolicyClient:
        return _PolicyClient(outcome, events)

    original = cli._stderr  # pyright: ignore[reportPrivateUsage]

    def stderr(message: str) -> None:
        events.append(message)
        original(message)

    monkeypatch.setattr(cli, "build_service_client", build)
    monkeypatch.setattr(cli, "_stderr", stderr)
    return events


def _invoke(*arguments: str) -> Result:
    reset_selection_memo()
    return _RUNNER.invoke(cli.app, list(arguments))


@pytest.mark.parametrize("kind", _REMOTE_KINDS)
@pytest.mark.parametrize("command", ["tighten", "propose"])
@pytest.mark.parametrize("json_output", [False, True])
def test_an_applied_tightening_names_the_server_before_and_after(
    home: Path, monkeypatch: pytest.MonkeyPatch, kind: str, command: str, json_output: bool
) -> None:
    record = _remote(kind)
    server = PolicyServer(record.target_id, kind)
    events = _serve(monkeypatch, "tightening_applied")

    result = _invoke("privacy", command, "--request", "{}", *(["--json"] if json_output else []))

    assert result.exit_code == 0, result.output
    # Before anything is sent, and in the result; the same lines with and without --json.
    assert events == [server.before_line(), "request", server.applied_line()]
    assert result.stderr == f"{server.before_line()}\n{server.applied_line()}\n"
    # The released result document keeps its exact shape: no field was added to stdout.
    assert json.loads(result.stdout) == {"outcome": "tightening_applied", "schema_version": "1.0.0"}
    assert _NAME not in result.output


@pytest.mark.parametrize("json_output", [False, True])
def test_a_proposal_waiting_for_a_decision_says_where_it_waits(
    home: Path, monkeypatch: pytest.MonkeyPatch, json_output: bool
) -> None:
    record = _remote("https")
    server = PolicyServer(record.target_id, "https")
    events = _serve(monkeypatch, "decision_required")

    result = _invoke("privacy", "propose", "--request", "{}", *(["--json"] if json_output else []))

    assert result.exit_code == 0, result.output
    assert events == [server.before_line(), "request", server.pending_line()]
    assert json.loads(result.stdout)["proposal_id"] == _PROPOSAL
    assert f"decision on the FinishUP server {_server(record)}" in result.stderr


@pytest.mark.parametrize("command", ["tighten", "propose"])
def test_a_failed_request_says_no_change_was_confirmed(
    home: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    record = _remote()
    server = PolicyServer(record.target_id, "ssh")
    events = _serve(monkeypatch, None)

    result = _invoke("privacy", command, "--request", "{}", "--json")

    # The bounded control failure still decides the exit, after the line naming the server.
    assert result.exit_code == exit_code_for(PublicErrorCode.SERVICE_UNAVAILABLE)
    assert events[:3] == [server.before_line(), "request", server.unconfirmed_line()]
    assert result.stdout == ""


@pytest.mark.parametrize("command", ["tighten", "propose"])
def test_this_computers_own_server_keeps_its_exact_output(
    home: Path, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    events = _serve(monkeypatch, "tightening_applied")

    result = _invoke("privacy", command, "--request", "{}", "--json")

    assert result.exit_code == 0, result.output
    assert events == ["request"]
    assert result.stderr == ""


@pytest.mark.parametrize("kind", _REMOTE_KINDS)
def test_decide_policy_is_refused_here_and_names_the_server(
    home: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    record = _remote(kind)
    decided: list[str] = []

    async def decide(pending_id: str) -> object:
        decided.append(pending_id)
        return SimpleNamespace(status="committed")

    monkeypatch.setattr("finishup.cli.privacy_control.decide_policy", decide)

    result = _invoke("privacy", "decide-policy", _PROPOSAL)

    assert result.exit_code != 0
    assert decided == []
    assert result.stderr.startswith("requires_server_host: ")
    assert f"selected server target {_server(record)} is not this machine" in result.stderr
    assert _NAME not in result.output


# --- the privacy step of setup run (the trusted questionnaire) -----------------------------------


def _questionnaire(
    monkeypatch: pytest.MonkeyPatch, *, proposal: str | None, snapshot_error: bool = False
) -> tuple[list[str], list[str]]:
    """Stub the questionnaire's I/O edges; returns the printed lines and the decisions opened."""

    printed: list[str] = []
    decided: list[str] = []
    current = local_only_policy()

    async def snapshot(_locator: object = None) -> object:
        printed.append("<snapshot read>")
        if snapshot_error:
            raise ControlError("service_unavailable", retryable=True)
        return privacy_setup.PrivacySetupSnapshot(
            current,
            JsonObject({"kind": "workspace"}),
            "sha256:" + "d" * 64,
            "missing",
            "not_applicable",
        )

    def choose(_current: PrivacyPolicy, *_args: object, **_kwargs: object) -> PrivacyPolicy:
        return current

    async def propose(*_args: object, **_kwargs: object) -> str | None:
        printed.append("<proposed>")
        return proposal

    async def decide(proposal_id: str) -> object:
        decided.append(proposal_id)
        return SimpleNamespace(status="committed")

    async def nothing(*_args: object) -> None:
        return None

    def ignore(*_args: object) -> None:
        return None

    def echo(message: str = "", *_args: object, **_kwargs: object) -> None:
        printed.append(message)

    monkeypatch.setattr(privacy_setup, "_interactive_terminal", lambda: True)
    monkeypatch.setattr(privacy_setup, "get_privacy_setup_snapshot", snapshot)
    monkeypatch.setattr(privacy_setup, "_render_repository_authority", ignore)
    monkeypatch.setattr(privacy_setup, "_configured_bindings", lambda: (None, None))
    monkeypatch.setattr(privacy_setup, "_configured_fallback_binding", lambda: None)
    monkeypatch.setattr(privacy_setup, "_choose_candidate", choose)
    monkeypatch.setattr(privacy_setup, "_propose", propose)
    monkeypatch.setattr(privacy_setup, "_decide", decide)
    monkeypatch.setattr(privacy_setup, "_warn_if_agent_route_cannot_dispatch", nothing)
    monkeypatch.setattr(privacy_setup, "_reconcile_host_admission", ignore)
    monkeypatch.setattr(privacy_setup.typer, "echo", echo)
    return printed, decided


@pytest.mark.parametrize("kind", _REMOTE_KINDS)
def test_the_setup_privacy_step_names_the_server_it_changes(
    home: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    record = _remote(kind)
    server = PolicyServer(record.target_id, kind)
    printed, _decided = _questionnaire(monkeypatch, proposal=None)

    report = asyncio.run(privacy_setup.run_privacy_setup(recipe_hint="private"))

    assert report.outcome == "configured"
    # Named before anything is read or sent, and again once the server applied it.
    assert printed == [server.before_line(), "<snapshot read>", "<proposed>", server.applied_line()]
    assert all(_NAME not in line for line in printed)


def test_a_widening_on_a_remote_server_waits_there_instead_of_opening_a_ceremony_here(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _remote()
    server = PolicyServer(record.target_id, "ssh")
    printed, decided = _questionnaire(monkeypatch, proposal=_PROPOSAL)

    report = asyncio.run(privacy_setup.run_privacy_setup(recipe_hint="private"))

    # The trusted decision runs only on the server host: no ceremony is opened on this computer.
    assert decided == []
    assert (report.outcome, report.proposal_id, report.reason) == (
        "cancelled",
        _PROPOSAL,
        "requires_server_host",
    )
    assert printed[-1] == server.pending_line()
    assert "Final widening decision (trusted local ceremony)" not in printed


def test_a_questionnaire_that_fails_says_no_change_was_confirmed(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _remote()
    server = PolicyServer(record.target_id, "ssh")
    printed, _decided = _questionnaire(monkeypatch, proposal=None, snapshot_error=True)

    with pytest.raises(ControlError):
        asyncio.run(privacy_setup.run_privacy_setup(recipe_hint="private"))

    assert printed == [server.before_line(), "<snapshot read>", server.unconfirmed_line()]


def test_on_this_computers_server_the_questionnaire_is_unchanged(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    printed, decided = _questionnaire(monkeypatch, proposal=_PROPOSAL)

    report = asyncio.run(privacy_setup.run_privacy_setup(recipe_hint="private"))

    assert report.outcome == "configured"
    assert decided == [_PROPOSAL]
    assert not any("FinishUP server" in line for line in printed)


def test_the_setup_summary_names_the_server_on_its_privacy_lines(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    privacy: dict[str, JsonValue] = {
        "outcome": "configured",
        "profile": "local_only",
        "grant_state": "granted",
        "reason": None,
    }
    report: dict[str, JsonValue] = {
        "registration": {"outcome": "registered"},
        "service": {"reachable": True, "state": "ready"},
        "provider": {"binding": "skipped", "credential": "skipped"},
        "privacy": cast(JsonValue, privacy),
        "integration": {},
        "readiness": None,
        "next_steps": [],
    }
    emit = setup_cli._emit_human_report  # pyright: ignore[reportPrivateUsage]

    emit(report)
    setup_cli._emit_provider_setup_layer_report(privacy_outcome="configured")  # pyright: ignore[reportPrivateUsage]
    everyday = capsys.readouterr().out
    assert "  Privacy: configured (local_only); repository grant: granted\n" in everyday
    assert "  Privacy policy: configured\n" in everyday

    record = _remote("https")
    emit(report)
    setup_cli._emit_provider_setup_layer_report(privacy_outcome="configured")  # pyright: ignore[reportPrivateUsage]
    setup_cli._emit_codex_subscription_layer_report(privacy_outcome="configured")  # pyright: ignore[reportPrivateUsage]
    setup_cli._emit_privacy_incomplete(  # pyright: ignore[reportPrivateUsage]
        reason="requires_server_host", privacy_outcome="cancelled", api_key_unstored=False
    )
    remote = capsys.readouterr().out
    suffix = f" (on the FinishUP server {_server(record)})"
    assert f"  Privacy: configured (local_only); repository grant: granted{suffix}\n" in remote
    assert remote.count(f"  Privacy policy: configured{suffix}\n") == 2
    assert f"Privacy policy: cancelled{suffix}\n" in remote
    assert _NAME not in remote


# --- the terminal interface --------------------------------------------------------------------


class _Said:
    def __init__(self, app: FinishUpTui) -> None:
        self.lines: list[tuple[Level, str, tuple[str, ...]]] = []

        def say(level: Level, title: str, body: tuple[str, ...] = (), **_kwargs: object) -> None:
            self.lines.append((level, title, tuple(body)))

        async def handover(operation: object) -> object:
            return await operation()  # pyright: ignore[reportUnknownVariableType, reportCallIssue]

        async def refresh() -> None:
            return None

        app.say = say  # pyright: ignore[reportAttributeAccessIssue]
        app.hand_over_terminal = handover  # pyright: ignore[reportAttributeAccessIssue]
        app._refresh_header = refresh  # pyright: ignore[reportAttributeAccessIssue, reportPrivateUsage]


@pytest.mark.anyio
async def test_the_terminal_interface_names_the_server_after_each_questionnaire() -> None:
    server = PolicyServer("t_1a2b3c4d", "ssh")
    runtime = FakeRuntime(policy_server=server)
    app = FinishUpTui(runtime)  # pyright: ignore[reportArgumentType]
    said = _Said(app)

    await app._hand_privacy_to_trusted_terminal("private")  # pyright: ignore[reportPrivateUsage]
    assert await app._record_local_only()  # pyright: ignore[reportPrivateUsage]

    named = [body for _level, title, body in said.lines if "FinishUP server" in title]
    assert named == [(server.applied_line(),), (server.applied_line(),)]
    assert len(runtime.policy_server_reports) == 2


@pytest.mark.anyio
async def test_the_terminal_interface_says_nothing_more_for_this_computers_server() -> None:
    runtime = FakeRuntime()
    app = FinishUpTui(runtime)  # pyright: ignore[reportArgumentType]
    said = _Said(app)

    await app._hand_privacy_to_trusted_terminal("private")  # pyright: ignore[reportPrivateUsage]

    assert not any("FinishUP server" in title for _level, title, _body in said.lines)


def test_the_runtime_names_the_selected_remote_server(home: Path) -> None:
    from finishup.tui.runtime import FinishUpRuntime

    runtime = FinishUpRuntime(cwd=home)
    assert runtime.policy_server_line(SimpleNamespace(outcome="configured")) is None

    record = _remote("local_port")
    server = PolicyServer(record.target_id, "local_port")
    assert runtime.policy_server_line(SimpleNamespace(outcome="configured")) == (
        server.applied_line()
    )
    assert runtime.policy_server_line(None) == server.unconfirmed_line()
