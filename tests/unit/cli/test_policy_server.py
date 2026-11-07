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
from collections.abc import Awaitable, Callable, Iterator
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
from finishup.cli.policy_server import PendingProposal, PolicyServer, selected_policy_server
from finishup.client import targets
from finishup.config.paths import reset_selection_memo
from finishup.domain.privacy import PrivacyPolicy
from finishup.domain.values import JsonObject
from finishup.ports.control import ControlError
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PublicErrorCode
from finishup.tui.app import FinishUpTui
from finishup.tui.runtime import RuntimeError_
from finishup.tui.symbols import Level
from finishup.tui.widgets.views import ApprovalView, SelectionView, TextEntryView

_RUNNER = CliRunner()
# A name the owner typed: it must never appear in anything these paths print.
_NAME = "owner-typed-lab"
_REMOTE_KINDS = ("ssh", "https", "local_port")
_PROPOSAL = "ppr_10000000-0000-4000-8000-000000000009"
# The server's expiry of that proposal; it is named rounded down to the minute, in UTC.
_EXPIRES = "2026-11-06T22:40:30.000Z"
_DEADLINE = "before 2026-11-06 22:40 UTC"
_WAITING = PendingProposal(_PROPOSAL, _EXPIRES)


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
        server.pending_line(_WAITING),
        server.pending_line(),
        server.unchanged_line(),
        server.unconfirmed_line(),
        server.summary_suffix(),
        server.privacy_next_step(_WAITING),
        server.privacy_next_step(),
        server.credential_next_step(),
    )

    assert all("t_1a2b3c4d (ssh)" in line for line in lines)
    assert "selected FinishUP server t_1a2b3c4d (ssh)" in server.before_line()
    assert "this computer's everyday FinishUP" in server.before_line()
    assert "'finishup privacy show'" in server.unconfirmed_line()
    waiting = SimpleNamespace(
        outcome="cancelled",
        reason="requires_server_host",
        proposal_id=_PROPOSAL,
        expires_at=_EXPIRES,
    )
    assert server.answer_line({"outcome": "tightening_applied"}) == server.applied_line()
    assert server.answer_line(
        {"outcome": "decision_required", "proposal_id": _PROPOSAL, "expires_at": _EXPIRES}
    ) == server.pending_line(_WAITING)
    assert server.answer_line({"outcome": "something_else"}) == server.unconfirmed_line()
    assert server.result_line(SimpleNamespace(outcome="configured")) == server.applied_line()
    assert server.result_line(waiting) == server.pending_line(_WAITING)
    for outcome in ("unchanged", "cancelled", "failed"):
        declined = SimpleNamespace(outcome=outcome, reason="privacy_decision_not_approved")
        assert server.result_line(declined) == server.unchanged_line()
    assert server.result_line(None) == server.unconfirmed_line()


def test_a_waiting_proposal_is_named_with_its_id_its_expiry_and_the_retry() -> None:
    """What happened, why, and that a retry helps: the id to decide, until when, and after."""

    server = PolicyServer("t_1a2b3c4d", "ssh")

    line = server.pending_line(_WAITING)
    assert "its policy has not changed yet" in line
    assert "a trusted decision runs only on that server host" in line
    assert f"Run 'finishup privacy decide-policy {_PROPOSAL}' on that host {_DEADLINE}" in line
    assert "after that it expires unchanged" in line
    assert "making the change again here proposes it anew" in line
    # The expiry may be unknown; the id is still named, and so is the retry.
    assert f"decide-policy {_PROPOSAL}' on that host before it expires" in server.pending_line(
        PendingProposal(_PROPOSAL)
    )
    # Setup's next step names the same continuation, never 'finishup --privacy'.
    step = server.privacy_next_step(_WAITING)
    assert f"'finishup privacy decide-policy {_PROPOSAL}' on that server host {_DEADLINE}" in step
    assert "rerun 'finishup setup run' here to propose it again" in step
    assert "finishup --privacy" not in step
    retry = server.privacy_next_step()
    assert retry.startswith("rerun 'finishup setup run' here to choose the privacy policy")
    assert "'finishup --privacy' runs only on that server host" in retry
    assert "on the host of the FinishUP server t_1a2b3c4d (ssh)" in server.credential_next_step()


def test_a_server_answer_of_another_shape_is_never_printed() -> None:
    server = PolicyServer("t_1a2b3c4d", "ssh")
    hostile = PendingProposal("ppr_$(touch /tmp/x)", "tomorrow; rm -rf ~")

    for line in (server.pending_line(hostile), server.privacy_next_step(hostile)):
        assert "touch" not in line
        assert "tomorrow" not in line
    assert server.pending_line(hostile).endswith("Make the change again here to propose it anew.")
    assert PendingProposal(_PROPOSAL, "tomorrow").deadline() == "before it expires"
    assert PendingProposal.of(None, _EXPIRES) is None
    assert PendingProposal.of(_PROPOSAL, 5) == PendingProposal(_PROPOSAL)


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
            body["expires_at"] = _EXPIRES
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
    assert events == [server.before_line(), "request", server.pending_line(_WAITING)]
    assert json.loads(result.stdout)["proposal_id"] == _PROPOSAL
    assert f"decision on the FinishUP server {_server(record)}" in result.stderr
    # The owner can act on it: the exact id to decide on the server host, and until when.
    assert f"'finishup privacy decide-policy {_PROPOSAL}' on that host {_DEADLINE}" in (
        result.stderr
    )


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

    async def propose(*_args: object, **_kwargs: object) -> PendingProposal | None:
        printed.append("<proposed>")
        return None if proposal is None else PendingProposal(proposal, _EXPIRES)

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
    monkeypatch.setattr(privacy_setup, "_propose_pending", propose)
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
    assert (report.outcome, report.proposal_id, report.reason, report.expires_at) == (
        "cancelled",
        _PROPOSAL,
        "requires_server_host",
        _EXPIRES,
    )
    # The result names the proposal to decide there and until when.
    assert printed[-1] == server.pending_line(_WAITING)
    assert _PROPOSAL in printed[-1]
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
    layers = setup_cli._emit_provider_setup_layer_report  # pyright: ignore[reportPrivateUsage]
    codex_layers = setup_cli._emit_codex_subscription_layer_report  # pyright: ignore[reportPrivateUsage]
    incomplete = setup_cli._emit_privacy_incomplete  # pyright: ignore[reportPrivateUsage]

    emit(report)
    layers(privacy_outcome="configured")
    incomplete(
        reason="privacy_decision_not_approved", privacy_outcome="cancelled", api_key_unstored=True
    )
    everyday = capsys.readouterr().out
    assert "  Privacy: configured (local_only); repository grant: granted\n" in everyday
    assert "  Privacy policy: configured\n" in everyday
    assert "finishup --privacy" in everyday
    assert "rerun 'finishup --set'" in everyday

    # The server the privacy step changed is passed in, never read again here.
    server = PolicyServer("t_1a2b3c4d", "https")
    emit(report, policy_server=server)
    layers(privacy_outcome="configured", policy_server=server)
    codex_layers(privacy_outcome="configured", policy_server=server)
    incomplete(
        reason="requires_server_host",
        privacy_outcome="cancelled",
        api_key_unstored=True,
        policy_server=server,
        pending=_WAITING,
    )
    remote = capsys.readouterr().out
    suffix = " (on the FinishUP server t_1a2b3c4d (https))"
    assert f"  Privacy: configured (local_only); repository grant: granted{suffix}\n" in remote
    assert remote.count(f"  Privacy policy: configured{suffix}\n") == 2
    assert f"Privacy policy: cancelled{suffix}\n" in remote
    # A proposal waiting on that server's host: decided there with its id, or setup runs again.
    assert f"Next: {server.privacy_next_step(_WAITING)}; the provider binding is kept.\n" in remote
    assert f"{server.credential_next_step()}\n" in remote
    assert "run 'finishup --privacy'" not in remote
    assert "rerun 'finishup --set'" not in remote


# --- setup end to end: the server read once, the waiting proposal named -------------------------


def _setup_home(monkeypatch: pytest.MonkeyPatch, home: Path) -> tuple[Path, Path]:
    """A HOME and a scratch folder under the isolated root (targets live under its XDG dirs)."""

    from finishup.cli import zero_network_selection

    user_home = home / "home"
    user_home.mkdir(mode=0o700)
    scratch = home / "scratch"
    scratch.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(user_home))
    # This computer's own policy is not part of these cases: never ask a service about it.
    monkeypatch.setattr(zero_network_selection, "find_zero_network_selection", lambda: None)
    return user_home, scratch


async def _waiting_report(**_kwargs: object) -> privacy_setup.PrivacySetupReport:
    return privacy_setup.PrivacySetupReport(
        "cancelled",
        "local_only",
        _PROPOSAL,
        "requires_server_host",
        "missing",
        "not_applicable",
        _EXPIRES,
    )


async def _declined_report(**_kwargs: object) -> privacy_setup.PrivacySetupReport:
    return privacy_setup.PrivacySetupReport(
        "cancelled", "local_only", None, "privacy_decision_not_approved"
    )


async def _switching_report(**_kwargs: object) -> privacy_setup.PrivacySetupReport:
    """The owner answers the zero-network choice with "switch" during the privacy step."""

    from finishup.cli.server import use_target

    use_target("local")
    reset_selection_memo()
    assert selected_policy_server() is None
    return privacy_setup.PrivacySetupReport(
        "configured", "minimal_external", grant_state="granted", migration_state="not_applicable"
    )


def _setup_run(
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    privacy: Callable[..., Awaitable[object]],
    *,
    semantic_ready: bool,
) -> int:
    """``finishup setup run`` through its real provider and summary steps (Codex sign-in)."""

    from tests.unit.cli import test_setup_wizard_smoothness as smoothness

    user_home, scratch = _setup_home(monkeypatch, home)
    smoothness._codex_wizard_with_codex_sign_in(  # pyright: ignore[reportPrivateUsage]
        monkeypatch,
        user_home,
        scratch,
        privacy,
        semantic_ready=semantic_ready,
    )
    monkeypatch.setattr(setup_cli, "_emit_human_report", _REAL_HUMAN_REPORT)
    return smoothness._codex_wizard()  # pyright: ignore[reportPrivateUsage]


_REAL_HUMAN_REPORT = setup_cli._emit_human_report  # pyright: ignore[reportPrivateUsage]


def _provider_setup(
    monkeypatch: pytest.MonkeyPatch, home: Path, privacy: Callable[..., Awaitable[object]]
) -> int:
    """The provider step ``setup run --host`` runs (``run_provider_setup``), Codex sign-in."""

    import anyio
    from tests.unit.cli import test_setup_wizard_smoothness as smoothness

    _setup_home(monkeypatch, home)
    smoothness._codex_provider_run(monkeypatch, privacy)  # pyright: ignore[reportPrivateUsage]
    return anyio.run(setup_cli.run_provider_setup)


def test_setup_names_the_waiting_proposal_and_where_to_decide_it(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    record = _remote()
    server = PolicyServer(record.target_id, "ssh")

    assert _setup_run(monkeypatch, home, _waiting_report, semantic_ready=False) == 20

    out = capsys.readouterr().out
    assert f"Privacy policy: cancelled (on the FinishUP server {_server(record)})" in out
    assert f"Next: {server.privacy_next_step(_WAITING)}; the provider binding is kept." in out
    assert f"'finishup privacy decide-policy {_PROPOSAL}' on that server host {_DEADLINE}" in out
    # Nothing points at a command that runs only on that server's host.
    assert "finishup --privacy" not in out
    assert "finishup --set" not in out
    assert _NAME not in out


def test_setup_on_a_remote_server_retries_here_instead_of_finishup_privacy(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    record = _remote()
    server = PolicyServer(record.target_id, "ssh")

    assert _setup_run(monkeypatch, home, _declined_report, semantic_ready=False) == 20

    out = capsys.readouterr().out
    assert f"Next: {server.privacy_next_step()}; the provider binding is kept." in out
    assert "run 'finishup --privacy'" not in out


def test_setup_keeps_naming_the_server_when_the_owner_switches_during_the_privacy_step(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    record = _remote()
    suffix = f" (on the FinishUP server {_server(record)})"

    assert _setup_run(monkeypatch, home, _switching_report, semantic_ready=True) == 0

    out = capsys.readouterr().out
    # The remote server's policy changed, so the summary still says whose, though the owner
    # switched to this computer's everyday FinishUP during the step.
    assert f"  Privacy: configured (minimal_external); repository grant: granted{suffix}" in out
    assert f"  Privacy policy: configured{suffix}" in out


def test_setup_next_steps_on_a_remote_server_never_point_at_finishup_privacy(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from tests.unit.cli import test_setup_wizard_smoothness as smoothness

    user_home, scratch = _setup_home(monkeypatch, home)
    smoothness._codex_only(monkeypatch, user_home, scratch, "ai_powered")  # pyright: ignore[reportPrivateUsage]
    project = scratch / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    monkeypatch.setattr(setup_cli, "_is_interactive_terminal", lambda: False)
    next_privacy = setup_cli._NEXT_PRIVACY  # pyright: ignore[reportPrivateUsage]

    def next_steps() -> list[str]:
        assert smoothness._codex_wizard(json_output=True, non_interactive=True) == 0  # pyright: ignore[reportPrivateUsage]
        return cast(list[str], json.loads(capsys.readouterr().out)["next_steps"])

    # This computer's everyday FinishUP keeps its released next step.
    assert next_privacy in next_steps()

    record = _remote()
    steps = next_steps()
    # 'finishup --privacy' runs only on that server's host: setup names the retry here instead.
    assert PolicyServer(record.target_id, "ssh").privacy_next_step() in steps
    assert next_privacy not in steps
    assert _NAME not in json.dumps(steps)


def test_provider_setup_names_the_waiting_proposal_and_where_to_decide_it(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    record = _remote()
    server = PolicyServer(record.target_id, "ssh")

    assert _provider_setup(monkeypatch, home, _waiting_report) == 20

    out = capsys.readouterr().out
    assert f"Privacy policy: cancelled (on the FinishUP server {_server(record)})" in out
    assert f"Next: {server.privacy_next_step(_WAITING)}; the provider binding is kept." in out
    assert "finishup --privacy" not in out


def test_provider_setup_keeps_naming_the_server_when_the_owner_switches_during_it(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    record = _remote()

    assert _provider_setup(monkeypatch, home, _switching_report) == 0

    out = capsys.readouterr().out
    assert f"  Privacy policy: configured (on the FinishUP server {_server(record)})" in out


# --- the terminal interface --------------------------------------------------------------------


_HAND_OVERS = ("privacy", "local_only", "codex_subscription", "provider_binding")


class _Said:
    def __init__(self, app: FinishUpTui) -> None:
        self.lines: list[tuple[Level, str, tuple[str, ...]]] = []

        def say(level: Level, title: str, body: tuple[str, ...] = (), **_kwargs: object) -> None:
            self.lines.append((level, title, tuple(body)))

        async def handover(operation: object) -> object:
            return await operation()  # pyright: ignore[reportUnknownVariableType, reportCallIssue]

        async def refresh() -> None:
            return None

        async def ask(view: object) -> str | None:
            """Approve, pick an API provider or the first option, keep every typed default."""

            name = getattr(view, "name", "")
            if isinstance(view, TextEntryView):
                return "entered"
            if isinstance(view, ApprovalView):
                return None if name == "confidential" else "approve"
            keys = [option.key for option in cast(SelectionView, view).options]
            return "api_key" if "api_key" in keys else keys[0]

        app.say = say  # pyright: ignore[reportAttributeAccessIssue]
        app.ask = ask  # pyright: ignore[reportAttributeAccessIssue]
        app.hand_over_terminal = handover  # pyright: ignore[reportAttributeAccessIssue]
        app._refresh_header = refresh  # pyright: ignore[reportAttributeAccessIssue, reportPrivateUsage]

    def named(self) -> list[tuple[str, ...]]:
        return [body for _level, title, body in self.lines if "FinishUP server" in title]


async def _hand_over(app: FinishUpTui, which: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Drive one of the four places the interface hands its terminal to the questionnaire."""

    import finishup.tui.app as app_module

    def rendered(*_args: object) -> tuple[str, ...]:
        return ()

    monkeypatch.setattr(app_module, "render_provider_stored", rendered)
    if which == "privacy":
        await app._hand_privacy_to_trusted_terminal("private")  # pyright: ignore[reportPrivateUsage]
    elif which == "local_only":
        await app._record_local_only()  # pyright: ignore[reportPrivateUsage]
    elif which == "codex_subscription":
        await app._command_codex_subscription()  # pyright: ignore[reportPrivateUsage]
    else:
        await app.command_provider()


@pytest.mark.anyio
@pytest.mark.parametrize("which", _HAND_OVERS)
@pytest.mark.parametrize("outcome", ["applied", "waiting", "raised"])
async def test_each_hand_over_names_the_server_after_the_questionnaire(
    monkeypatch: pytest.MonkeyPatch, which: str, outcome: str
) -> None:
    server = PolicyServer("t_1a2b3c4d", "ssh")
    runtime = FakeRuntime(policy_server=server)
    expected = server.applied_line()
    if outcome == "waiting":
        runtime.privacy_report = await _waiting_report()
        expected = server.pending_line(_WAITING)
    elif outcome == "raised":
        runtime.privacy_error = RuntimeError_("privacy_setup_failed", "the ceremony failed")
        expected = server.unconfirmed_line()
    app = FinishUpTui(runtime)  # pyright: ignore[reportArgumentType]
    said = _Said(app)

    await _hand_over(app, which, monkeypatch)

    assert said.named() == [(expected,)]
    assert runtime.policy_server_reads == 1
    if outcome == "waiting":
        assert _PROPOSAL in expected


@pytest.mark.anyio
@pytest.mark.parametrize("which", _HAND_OVERS)
async def test_each_hand_over_keeps_the_server_when_the_owner_switches_during_it(
    monkeypatch: pytest.MonkeyPatch, which: str
) -> None:
    server = PolicyServer("t_1a2b3c4d", "ssh")
    runtime = FakeRuntime(policy_server=server, switch_servers_during_privacy=True)
    app = FinishUpTui(runtime)  # pyright: ignore[reportArgumentType]
    said = _Said(app)

    await _hand_over(app, which, monkeypatch)

    # The selection reads as this computer's server afterwards; the change was the remote one's.
    assert runtime.selected_policy_server() is None
    assert said.named() == [(server.applied_line(),)]


@pytest.mark.anyio
@pytest.mark.parametrize("which", _HAND_OVERS)
async def test_the_terminal_interface_says_nothing_more_for_this_computers_server(
    monkeypatch: pytest.MonkeyPatch, which: str
) -> None:
    runtime = FakeRuntime()
    app = FinishUpTui(runtime)  # pyright: ignore[reportArgumentType]
    said = _Said(app)

    await _hand_over(app, which, monkeypatch)

    assert said.named() == []
    assert runtime.policy_server_reads == 1


def test_the_runtime_reads_the_server_of_its_resolved_root(home: Path) -> None:
    from finishup.cli.server import use_target
    from finishup.tui.runtime import FinishUpRuntime

    runtime = FinishUpRuntime(cwd=home)
    assert runtime.selected_policy_server() is None

    record = _remote("local_port")
    assert runtime.selected_policy_server() == PolicyServer(record.target_id, "local_port")

    use_target("local")
    reset_selection_memo()
    assert runtime.selected_policy_server() is None
