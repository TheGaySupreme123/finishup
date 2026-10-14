"""The Stop-time closure gate (issue #977): decision, memory and per-host delivery."""

from __future__ import annotations

import io
import json
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from builders.gate_readiness import (
    acceptance_recheck,
    ack_recheck,
    blocker_recheck,
    premise_recheck,
)
from finishup.adapters.integrations.codex_lifecycle import mapping_from_start_ids, store_mapping
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import closure_gate as gate_module
from finishup.cli import observe_hooks
from finishup.cli.closure_gate import (
    closure_gate_already_delivered,
    closure_gate_from_readiness,
    record_closure_gate_delivered,
)
from finishup.domain.observation import (
    ObservationIngestDisposition,
    ObservationIngestResult,
    observation_ingest_result_to_json,
)
from finishup.kernel.task_facts import STOP_GATE_TOKENS
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.ids import IdKind, new_id

_DIGEST = "sha256:" + "d" * 64


def _readiness(
    state: str = "action_required", actionable: tuple[str, ...] = ("obligations_open",)
) -> Any:
    return SimpleNamespace(
        state=state,
        agent_actionable=actionable,
        open_obligation_count="2",
        receipt_blocking_finding_count="1",
    )


def _gate(readiness: object, *, pending: bool = False) -> Any:
    return closure_gate_from_readiness(
        readiness, frontier_sequence="7", frontier_digest=_DIGEST, observation_pending=pending
    )


# --- pure decision -------------------------------------------------------------------------


@pytest.mark.parametrize("token", STOP_GATE_TOKENS)
def test_every_stop_gate_token_fires(token: str) -> None:
    gate = _gate(_readiness(actionable=(token,)))
    assert gate is not None
    assert gate.items == (token,)
    assert gate.identity == f"7:{_DIGEST}"
    # The blocker exit is offered only for open obligations (F1, #984).
    offers_blocker = token in {"obligations_open", gate_module.BLOCKER_UNCONFIRMED_TOKEN}
    assert ("finishup-blocker:<" in gate.text) is offers_blocker
    assert "A FinishUP limit is never a `finishup-blocker`" in gate.text
    assert len(gate.text) <= 2000
    assert "/" not in gate.text.replace("<authority|consent|credential|dependency_unavailable>", "")


@pytest.mark.parametrize("state", ["ready", "ready_with_limitations"])
def test_ready_states_do_not_gate(state: str) -> None:
    assert _gate(_readiness(state=state)) is None


@pytest.mark.parametrize(
    "token", ["findings_unanswered", "check_not_applicable", "no_plan_published"]
)
def test_non_gate_actionable_items_do_not_gate(token: str) -> None:
    assert token not in STOP_GATE_TOKENS
    assert _gate(_readiness(actionable=(token,))) is None


def test_observation_pending_drops_only_observation_dependent_items() -> None:
    dependent = tuple(token for token in STOP_GATE_TOKENS if token.startswith("planned_verif"))
    assert dependent
    assert _gate(_readiness(actionable=dependent), pending=True) is None
    mixed = _gate(_readiness(actionable=(*dependent, "obligations_open")), pending=True)
    assert mixed is not None
    assert mixed.items == ("obligations_open",)
    assert "draining" in mixed.text


def test_edited_after_last_verification_gates_with_a_rerun_repair() -> None:
    """tb4n2 P1-4b (ADR-042): verification not re-run after the last edit stops the agent once."""

    token = "edited_after_last_verification"
    assert token in STOP_GATE_TOKENS
    gate = _gate(_readiness(actionable=(token,)))
    assert gate is not None
    assert gate.items == (token,)
    assert "after your last verification run" in gate.text
    assert "Run each planned verification after your last edit" in gate.text
    # It depends on observed runs, so it is never used while observations are still draining.
    assert _gate(_readiness(actionable=(token,)), pending=True) is None


def test_malformed_readiness_does_not_gate() -> None:
    assert _gate(None) is None
    assert (
        _gate(SimpleNamespace(state="action_required", agent_actionable="obligations_open")) is None
    )


# --- once-per-frontier memory ----------------------------------------------------------------


def test_memory_round_trip_and_session_isolation(tmp_path: Path) -> None:
    assert not closure_gate_already_delivered("ses_a", "1:x", _state=tmp_path)
    assert record_closure_gate_delivered("ses_a", "1:x", _state=tmp_path)
    assert closure_gate_already_delivered("ses_a", "1:x", _state=tmp_path)
    assert not closure_gate_already_delivered("ses_a", "2:x", _state=tmp_path)
    assert not closure_gate_already_delivered("ses_b", "1:x", _state=tmp_path)
    assert record_closure_gate_delivered("ses_b", "2:y", _state=tmp_path)
    assert closure_gate_already_delivered("ses_a", "1:x", _state=tmp_path)
    assert closure_gate_already_delivered("ses_b", "2:y", _state=tmp_path)


def test_memory_is_bounded(tmp_path: Path) -> None:
    limit = gate_module._MAX_SESSIONS  # pyright: ignore[reportPrivateUsage]
    for index in range(limit + 10):
        assert record_closure_gate_delivered(f"s{index}", f"{index}:d", _state=tmp_path)
    stored = json.loads((tmp_path / "observation" / "closure-gate.json").read_text())
    assert len(stored) == limit
    assert not closure_gate_already_delivered("s0", "0:d", _state=tmp_path)
    assert closure_gate_already_delivered(f"s{limit + 9}", f"{limit + 9}:d", _state=tmp_path)


@pytest.mark.parametrize("content", ["{not json", "[1, 2]", '{"a": 1}', ""])
def test_corrupt_memory_is_tolerated(tmp_path: Path, content: str) -> None:
    directory = tmp_path / "observation"
    directory.mkdir(mode=0o700)
    (directory / "closure-gate.json").write_text(content)
    assert not closure_gate_already_delivered("ses_a", "1:x", _state=tmp_path)
    assert record_closure_gate_delivered("ses_a", "1:x", _state=tmp_path)
    assert closure_gate_already_delivered("ses_a", "1:x", _state=tmp_path)


# --- hook level, per host --------------------------------------------------------------------


def _status_branch(readiness: object, sequence: str) -> object:
    return SimpleNamespace(
        head_frontier=SimpleNamespace(sequence=sequence, head_digest=_DIGEST),
        closure_readiness=readiness,
        task_id=new_id(IdKind.TASK),
    )


class _Harness:
    def __init__(self, tmp_path: Path, host_key: str) -> None:
        self.state = tmp_path
        self.store = LocalObservationStore(_state=tmp_path)
        commitment = self.store.workspace_commitment(str(tmp_path.resolve()))
        self.store.grant_consent(commitment)
        self.session_id = new_id(IdKind.SESSION)
        store_mapping(
            mapping_from_start_ids(
                codex_session_id=host_key,
                yoetz_task_id=new_id(IdKind.TASK),
                yoetz_session_id=self.session_id,
                yoetz_writer_id=new_id(IdKind.WRITER),
                last_frontier="0:genesis",
            ),
            _state=tmp_path,
        )
        self.readiness: Any = _readiness()
        self.sequence = "5"
        self.status_calls = 0
        # #1050: the resolved obligations an ``obligations`` view read returns (None: it fails).
        self.obligation_rows: tuple[Any, ...] | None = ()
        self.views: list[str] = []
        harness = self

        class _Client:
            async def status(self, request: object, *, deadline_ms: int | None = None) -> object:
                del deadline_ms
                harness.status_calls += 1
                view = getattr(request, "view", "compact")
                harness.views.append(view)
                if view == "obligations":
                    if harness.obligation_rows is None:
                        raise RuntimeError("obligations view unavailable")
                    page = SimpleNamespace(items=harness.obligation_rows, next_cursor=None)
                    return SimpleNamespace(root=SimpleNamespace(page=page))
                return SimpleNamespace(root=_status_branch(harness.readiness, harness.sequence))

            async def observation_ingest(self, body: object, *, deadline_ms: int) -> object:
                del body, deadline_ms
                return observation_ingest_result_to_json(
                    ObservationIngestResult(ObservationIngestDisposition.DUPLICATE, None, None)
                )

            async def close(self) -> None:
                return None

        async def connect(_kind: object) -> _Client:
            return _Client()

        self.connect: Any = connect

    def reasons(self) -> list[str]:
        path = self.state / "observation" / "hook-diagnostics.jsonl"
        if not path.exists():
            return []
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        return [row["reason"] for row in rows if str(row.get("reason", "")).startswith("closure_")]

    def run(self, handler: Any, event: str, body: dict[str, JsonValue]) -> Mapping[str, Any]:
        stdout = io.BytesIO()
        code = handler(
            event_name=event,
            stdin_bytes=canonical_encode({"hook_event_name": event, **body}),
            stdout=stdout,
            workspace=str(self.state),
            _state=self.state,
            connect=self.connect,
        )
        assert code == 0
        return cast(Mapping[str, Any], json.loads(stdout.getvalue().decode() or "{}"))


class _Host:
    def __init__(self, name: str) -> None:
        self.name = name

    def key(self, session: str) -> str:
        return session if self.name == "codex" else f"{self.name}:{session}"

    def handler(self) -> Any:
        return {
            "codex": observe_hooks.handle_observe,
            "claude": observe_hooks.handle_claude_observe,
            "cursor": observe_hooks.handle_cursor_observe,
        }[self.name]

    def event(self) -> str:
        return "stop" if self.name == "cursor" else "Stop"

    def body(self, session: str, *, guarded: bool = False) -> dict[str, JsonValue]:
        if self.name == "cursor":
            return {
                "conversation_id": session,
                "cursor_version": "3.17.8",
                "status": "completed",
                "loop_count": 1 if guarded else 0,
            }
        return {"session_id": session, "stop_hook_active": guarded}

    def assert_gate(self, output: Mapping[str, Any]) -> str:
        if self.name == "codex":
            assert output["decision"] == "block"
            text = output["reason"]
        elif self.name == "claude":
            assert set(output) == {"hookSpecificOutput"}
            specific = output["hookSpecificOutput"]
            assert specific["hookEventName"] == "Stop"
            text = specific["additionalContext"]
        else:
            assert set(output) == {"followup_message"}
            text = output["followup_message"]
        assert "FinishUP closure gate" in text
        assert "open obligation" in text
        return cast(str, text)


@pytest.fixture(params=["codex", "claude", "cursor"])
def host(request: pytest.FixtureRequest) -> _Host:
    return _Host(cast(str, request.param))


def _stop(h: _Harness, host: _Host, session: str, *, guarded: bool = False) -> Mapping[str, Any]:
    return h.run(host.handler(), host.event(), host.body(session, guarded=guarded))


def test_stop_continues_once_per_frontier(tmp_path: Path, host: _Host) -> None:
    session = "gate-host"
    h = _Harness(tmp_path, host.key(session))
    first = _stop(h, host, session)
    host.assert_gate(first)
    assert h.reasons() == ["closure_gate_continued"]
    assert closure_gate_already_delivered(h.session_id, f"5:{_DIGEST}", _state=tmp_path)

    second = _stop(h, host, session)
    assert "closure gate" not in json.dumps(second)
    assert h.reasons() == ["closure_gate_continued", "closure_gate_repeat_suppressed"]

    h.sequence = "6"  # the ledger moved: a new frontier may be gated once more
    third = _stop(h, host, session)
    host.assert_gate(third)


def test_active_stop_never_continues_for_ordinary_items(tmp_path: Path, host: _Host) -> None:
    session = "gate-guard"
    h = _Harness(tmp_path, host.key(session))
    output = _stop(h, host, session, guarded=True)
    assert "closure gate" not in json.dumps(output)
    # The active Stop reads status for a new blocker (#985) but open obligations alone never
    # continue it; only the loop guard is recorded.
    assert h.status_calls == 1
    assert h.reasons() == ["closure_gate_turn_end_after_continue"]
    assert not closure_gate_already_delivered(h.session_id, f"5:{_DIGEST}", _state=tmp_path)


def test_ready_status_does_not_gate(tmp_path: Path, host: _Host) -> None:
    session = "gate-ready"
    h = _Harness(tmp_path, host.key(session))
    h.readiness = _readiness(state="ready", actionable=())
    output = _stop(h, host, session)
    assert "closure gate" not in json.dumps(output)
    assert h.reasons() == ["closure_gate_not_required"]


def test_unreachable_status_lets_the_agent_stop(tmp_path: Path, host: _Host) -> None:
    session = "gate-down"
    h = _Harness(tmp_path, host.key(session))

    async def broken(_kind: object) -> object:
        raise OSError("service down")

    h.connect = broken
    output = _stop(h, host, session)
    assert "closure gate" not in json.dumps(output)
    # A status read that failed is recorded as unavailable, never as "nothing left to do".
    assert h.reasons() == ["closure_gate_unavailable"]


def test_closing_review_requirement_continues_with_the_final_review_repair() -> None:
    from types import SimpleNamespace

    from finishup.cli.closure_gate import closure_gate_from_readiness

    gate = closure_gate_from_readiness(
        SimpleNamespace(
            state="action_required",
            agent_actionable=("closing_review_required",),
            open_obligation_count="0",
            receipt_blocking_finding_count="0",
        ),
        frontier_sequence="9",
        frontier_digest="sha256:" + "a" * 64,
        observation_pending=False,
    )
    assert gate is not None
    assert gate.items == ("closing_review_required",)
    assert "`final_review: true`" in gate.text


# --- blocker re-check (#977 follow-up) -------------------------------------------------------

_OBL = "obl_97700000-0000-4000-8000-000000000001"
_EVT = "evt_97700000-0000-4000-8000-000000000002"


def _blocked(kind: str = "dependency_unavailable", obligation: str = _OBL) -> Any:
    """The blocker re-check status announces for one claimed blocker (tb4n3 RC-8)."""

    return blocker_recheck(obligation, kind)


def _blocked_readiness(
    *rows: Any, state: str = "ready_with_limitations", actionable: tuple[str, ...] = ()
) -> Any:
    readiness = _readiness(state=state, actionable=actionable)
    readiness.rechecks = rows or (_blocked(),)
    return readiness


def test_a_recorded_blocker_is_rechecked_once_naming_the_obligation_and_kind() -> None:
    gate = _gate(_blocked_readiness())
    assert gate is not None
    assert gate.items == (gate_module.BLOCKER_RECHECK_ITEM,)
    assert gate.blocker_keys == (f"{_OBL}:dependency_unavailable",)
    assert f"{_OBL} (dependency_unavailable)" in gate.text
    assert "authority or consent you do not have" in gate.text
    assert "the task says is recoverable" in gate.text
    assert "a failing test" in gate.text
    assert "continue the work" in gate.text
    # Once re-asked, the same (obligation, kind) is honoured whatever the frontier.
    assert (
        closure_gate_from_readiness(
            _blocked_readiness(),
            frontier_sequence="99",
            frontier_digest=_DIGEST,
            observation_pending=False,
            reasked_blockers=frozenset(gate.blocker_keys),
        )
        is None
    )


def test_a_changed_blocker_kind_is_a_new_claim_and_rechecked_once() -> None:
    reasked = frozenset({f"{_OBL}:dependency_unavailable"})
    gate = closure_gate_from_readiness(
        _blocked_readiness(_blocked("credential")),
        frontier_sequence="8",
        frontier_digest=_DIGEST,
        observation_pending=False,
        reasked_blockers=reasked,
    )
    assert gate is not None
    assert gate.blocker_keys == (f"{_OBL}:credential",)


def test_blocker_recheck_joins_other_remaining_work() -> None:
    gate = _gate(
        _blocked_readiness(state="action_required", actionable=("closing_review_required",))
    )
    assert gate is not None
    assert gate.items == ("closing_review_required", gate_module.BLOCKER_RECHECK_ITEM)
    assert "`final_review: true`" in gate.text
    assert f"{_OBL} (dependency_unavailable)" in gate.text


@pytest.mark.parametrize(
    "row",
    [
        SimpleNamespace(kind="blocker", key=f"blocker:{_OBL}:data_missing", subjects=()),
        SimpleNamespace(kind="blocker", key="blocker:not-an-id:consent", subjects=()),
        SimpleNamespace(kind="blocker", key=f"{_OBL}:consent", subjects=()),
        SimpleNamespace(kind="unknown_kind", key=f"blocker:{_OBL}:consent", subjects=()),
        "blocker:obl_x:consent",
        None,
    ],
)
def test_malformed_recheck_entries_never_gate(row: object) -> None:
    assert _gate(_blocked_readiness(row)) is None


def test_a_readiness_without_the_recheck_list_announces_none() -> None:
    """A service older than the gate sends no ``rechecks``: the gate asks none, never invents one."""

    readiness = _readiness(state="ready_with_limitations", actionable=())
    readiness.blocked_obligations = (
        SimpleNamespace(obligation_id=_OBL, blocker_kind="consent", confirmation="claimed"),
    )
    readiness.acknowledged_not_done = (_OBL,)
    readiness.acknowledged_obligation_count = "1"
    readiness.standing_limitations = ("finding_premise_disputed",)
    assert not hasattr(readiness, "rechecks")
    assert _gate(readiness) is None


def test_blocker_memory_round_trip_is_per_session_and_bounded(tmp_path: Path) -> None:
    assert gate_module.closure_gate_reasked_blockers("ses_a", _state=tmp_path) == frozenset()
    keys = tuple(f"obl_{index:04d}:consent" for index in range(80))
    assert record_closure_gate_delivered("ses_a", "1:x", blocker_keys=keys, _state=tmp_path)
    remembered = gate_module.closure_gate_reasked_blockers("ses_a", _state=tmp_path)
    assert len(remembered) == 64
    assert keys[-1] in remembered
    assert gate_module.closure_gate_reasked_blockers("ses_b", _state=tmp_path) == frozenset()
    # A plain frontier record keeps the session's blocker memory.
    assert record_closure_gate_delivered("ses_a", "2:y", _state=tmp_path)
    assert keys[-1] in gate_module.closure_gate_reasked_blockers("ses_a", _state=tmp_path)


def test_stop_rechecks_a_blocker_once_then_honours_it(tmp_path: Path, host: _Host) -> None:
    session = "gate-blocker"
    h = _Harness(tmp_path, host.key(session))
    h.readiness = _blocked_readiness()

    first = _stop(h, host, session)
    if host.name == "codex":
        text = first["reason"]
    elif host.name == "claude":
        text = first["hookSpecificOutput"]["additionalContext"]
    else:
        text = first["followup_message"]
    assert "Blocker re-check (asked once)" in text
    assert f"{_OBL} (dependency_unavailable)" in text
    assert h.reasons() == ["closure_gate_continued", "closure_gate_blocker_rechecked"]

    # The agent stops again without changing anything: the blocker is honoured.
    second = _stop(h, host, session)
    assert "closure gate" not in json.dumps(second)
    # It re-records the same blocker (the frontier moves): still honoured, never a loop.
    h.sequence = "6"
    third = _stop(h, host, session)
    assert "closure gate" not in json.dumps(third)
    assert h.reasons()[-2:] == ["closure_gate_not_required", "closure_gate_not_required"]


def _text(host: _Host, output: Mapping[str, Any]) -> str:
    if host.name == "codex":
        assert output["decision"] == "block"
        return cast(str, output["reason"])
    if host.name == "claude":
        return cast(str, output["hookSpecificOutput"]["additionalContext"])
    assert set(output) == {"followup_message"}
    return cast(str, output["followup_message"])


def test_blocker_published_after_the_gate_is_reasked_once_on_the_active_stop(
    tmp_path: Path, host: _Host
) -> None:
    """tb4n1 pretrain det: gate at the first Stop, blocker 17 min later, loop-guarded Stop (#985)."""

    session = "gate-late-blocker"
    h = _Harness(tmp_path, host.key(session))
    first = _stop(h, host, session)
    host.assert_gate(first)
    assert h.reasons() == ["closure_gate_continued"]

    # The agent publishes a blocker and stops again; the host marks the Stop active.
    h.readiness = _blocked_readiness(state="action_required", actionable=("obligations_open",))
    h.sequence = "6"
    second = _stop(h, host, session, guarded=True)
    text = _text(host, second)
    assert text.startswith("FinishUP closure gate (shown once for these blockers)")
    assert f"{_OBL} (dependency_unavailable)" in text
    # Ordinary items never ride an active Stop.
    assert "open obligation(s)" not in text
    assert h.reasons()[1:] == [
        "closure_gate_continued",
        "closure_gate_blocker_rechecked",
        "closure_gate_active_stop_rechecked",
    ]
    assert gate_module.closure_gate_turn_blocks(h.session_id, _state=tmp_path) == 2

    # The same blocker on the next active Stop is not asked again.
    h.sequence = "7"
    third = _stop(h, host, session, guarded=True)
    assert "closure gate" not in json.dumps(third)
    assert h.reasons()[-1] == "closure_gate_turn_end_after_continue"


def test_active_stop_is_capped_at_two_gate_blocks_per_turn(tmp_path: Path, host: _Host) -> None:
    session = "gate-turn-cap"
    h = _Harness(tmp_path, host.key(session))
    host.assert_gate(_stop(h, host, session))
    h.readiness = _blocked_readiness()
    h.sequence = "6"
    assert "Blocker re-check" in _text(host, _stop(h, host, session, guarded=True))
    # A second, different blocker in the same turn: the per-turn cap (2) lets the agent stop
    # without even reading status.
    other = "obl_97700000-0000-4000-8000-000000000003"
    h.readiness = _blocked_readiness(_blocked(), _blocked("consent", other))
    h.sequence = "7"
    calls = h.status_calls
    assert "closure gate" not in json.dumps(_stop(h, host, session, guarded=True))
    assert h.status_calls == calls
    assert h.reasons()[-1] == "closure_gate_turn_end_after_continue"
    # A new turn (a Stop the host did not continue) resets the cap; the unasked blocker is
    # re-asked once there.
    h.sequence = "8"
    fresh = _text(host, _stop(h, host, session))
    assert f"{other} (consent)" in fresh
    assert f"{_OBL} (dependency_unavailable)" not in fresh


def test_active_stop_fails_open_when_status_fails(tmp_path: Path, host: _Host) -> None:
    session = "gate-active-down"
    h = _Harness(tmp_path, host.key(session))

    async def broken(_kind: object) -> object:
        raise OSError("service down")

    h.connect = broken
    output = _stop(h, host, session, guarded=True)
    assert "closure gate" not in json.dumps(output)
    assert h.reasons() == ["closure_gate_turn_end_after_continue"]


def test_active_stop_fails_open_when_memory_is_unwritable(
    tmp_path: Path, host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = "gate-active-unwritable"
    h = _Harness(tmp_path, host.key(session))
    h.readiness = _blocked_readiness()

    def unwritable(*args: object, **kwargs: object) -> bool:
        del args, kwargs
        return False

    monkeypatch.setattr(observe_hooks, "record_closure_gate_delivered", unwritable)
    # Without durable once-per-key memory nothing bounds an active Stop, so it is not emitted.
    for _ in range(3):
        output = _stop(h, host, session, guarded=True)
        assert "closure gate" not in json.dumps(output)
    assert set(h.reasons()) == {"closure_gate_turn_end_after_continue"}


def test_a_blocker_status_no_longer_announces_is_not_asked() -> None:
    """Confirmation is decided by the service: a confirmed blocker is simply not announced."""

    assert _gate(_readiness(state="ready_with_limitations", actionable=())) is None
    gate = _gate(_blocked_readiness(_blocked("consent")))
    assert gate is not None
    assert gate.blocker_keys == (f"{_OBL}:consent",)


def test_unconfirmed_blocker_token_gates_and_confirms_only_in_the_recheck() -> None:
    gate = _gate(
        _blocked_readiness(
            state="action_required", actionable=(gate_module.BLOCKER_UNCONFIRMED_TOKEN,)
        )
    )
    assert gate is not None
    assert gate.items == (gate_module.BLOCKER_UNCONFIRMED_TOKEN, gate_module.BLOCKER_RECHECK_ITEM)
    # The confirm instruction appears once, inside the re-check that challenges the blocker.
    recheck = gate.text.index("Blocker re-check (asked once)")
    assert gate.text.count("same finishup-blocker line again") == 1
    assert gate.text.index("same finishup-blocker line again") > recheck
    # An obligation is never `self_verified`: the re-check says to finish it and disclose.
    assert "self_verified" not in gate.text[recheck:]
    assert "finish the obligation and disclose any limit in your final answer" in gate.text


def test_unconfirmed_blocker_already_rechecked_says_how_to_confirm() -> None:
    gate = closure_gate_from_readiness(
        _blocked_readiness(
            state="action_required", actionable=(gate_module.BLOCKER_UNCONFIRMED_TOKEN,)
        ),
        frontier_sequence="9",
        frontier_digest=_DIGEST,
        observation_pending=False,
        reasked_blockers=frozenset({f"{_OBL}:dependency_unavailable"}),
    )
    assert gate is not None
    assert gate.items == (gate_module.BLOCKER_UNCONFIRMED_TOKEN,)
    assert "You were already asked about your recorded blocker" in gate.text
    assert "same finishup-blocker line again" in gate.text


def test_full_recheck_never_offers_self_verified_for_an_obligation() -> None:
    gate = _gate(_blocked_readiness())
    assert gate is not None
    assert "self_verified" not in gate.text
    assert "finish the obligation and disclose any limit in your final answer" in gate.text


@pytest.mark.parametrize("content", ["{not json", "[1, 2]", ""])
def test_a_corrupt_turn_counter_counts_as_the_cap(tmp_path: Path, content: str) -> None:
    directory = tmp_path / "observation"
    directory.mkdir(mode=0o700)
    (directory / "closure-gate-turns.json").write_text(content)
    assert (
        gate_module.closure_gate_turn_blocks("ses_a", _state=tmp_path)
        == gate_module.MAX_GATE_BLOCKS_PER_TURN
    )
    # The next turn replaces the corrupt counter instead of capping every later turn.
    gate_module.reset_closure_gate_turn("ses_a", _state=tmp_path)
    assert gate_module.closure_gate_turn_blocks("ses_a", _state=tmp_path) == 0


def test_a_non_active_stop_resets_the_turn_even_when_the_gate_is_not_evaluated(
    tmp_path: Path, host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = "gate-reset"
    h = _Harness(tmp_path, host.key(session))
    assert record_closure_gate_delivered(h.session_id, "1:x", _state=tmp_path)
    assert gate_module.closure_gate_turn_blocks(h.session_id, _state=tmp_path) == 1

    def not_evaluated(*args: object, **kwargs: object) -> None:
        del args, kwargs
        return None

    monkeypatch.setattr(observe_hooks, "_decide_closure_gate", not_evaluated)
    _stop(h, host, session)
    assert gate_module.closure_gate_turn_blocks(h.session_id, _state=tmp_path) == 0


def test_active_stop_decision_ignores_ordinary_items() -> None:
    readiness = _blocked_readiness(
        state="action_required", actionable=("obligations_open", "receipt_findings_unresolved")
    )
    gate = closure_gate_from_readiness(
        readiness,
        frontier_sequence="9",
        frontier_digest=_DIGEST,
        observation_pending=False,
        active_stop=True,
    )
    assert gate is not None
    assert gate.items == (gate_module.BLOCKER_RECHECK_ITEM,)
    assert (
        closure_gate_from_readiness(
            _readiness(actionable=("obligations_open",)),
            frontier_sequence="9",
            frontier_digest=_DIGEST,
            observation_pending=False,
            active_stop=True,
        )
        is None
    )


def test_a_blocker_recheck_is_not_held_back_by_draining_observations() -> None:
    readiness = _blocked_readiness(
        state="action_required", actionable=("planned_verification_not_observed",)
    )
    gate = _gate(readiness, pending=True)
    assert gate is not None
    assert gate.items == (gate_module.BLOCKER_RECHECK_ITEM,)


def test_an_unwritable_memory_is_a_visible_diagnostic(
    tmp_path: Path, host: _Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = "gate-blocker-unwritable"
    h = _Harness(tmp_path, host.key(session))
    h.readiness = _blocked_readiness()

    def unwritable(*args: object, **kwargs: object) -> bool:
        del args, kwargs
        return False

    monkeypatch.setattr(observe_hooks, "record_closure_gate_delivered", unwritable)
    _stop(h, host, session)
    assert "closure_gate_memory_unwritten" in h.reasons()
    # The active Stop still ends the turn: without memory it never re-asks (fail open).
    guarded = _stop(h, host, session, guarded=True)
    assert "closure gate" not in json.dumps(guarded)


# --- tb4n3 RC-8: announced re-checks and the withdrawn deliverable, per host -----------------


def test_stop_asks_the_announced_acceptance_reread_once_and_does_not_challenge_its_answer(
    tmp_path: Path, host: _Host
) -> None:
    """cargo D (tb4n3): resolved obligations, no gate token. The re-read is announced by status,
    asked once at the first Stop, and an acknowledgement published after it is not re-challenged."""

    session = "gate-acceptance"
    h = _Harness(tmp_path, host.key(session))
    invite = acceptance_recheck()
    h.readiness = _readiness(state="ready_with_limitations", actionable=())
    h.readiness.rechecks = (invite,)
    first = _stop(h, host, session)
    text = _text(host, first)
    assert "acceptance_criteria" in text
    assert h.reasons() == ["closure_gate_continued", "closure_gate_acceptance_rechecked"]
    assert gate_module.closure_gate_reasked_blockers(h.session_id, _state=tmp_path) == frozenset(
        {f"{invite.key}@5"}
    )

    # The agent answers the invite by acknowledging an obligation (later frontier), then stops
    # again. Status announces the acknowledgement, but it answers the invite: no second gate.
    h.sequence = "9"
    h.readiness.rechecks = (invite, ack_recheck(_OBL, since=8))
    second = _stop(h, host, session, guarded=True)
    assert "closure gate" not in json.dumps(second)
    assert h.reasons()[-1] == "closure_gate_turn_end_after_continue"
    third = _stop(h, host, session)
    assert "closure gate" not in json.dumps(third)
    assert h.reasons()[-1] == "closure_gate_not_required"


def test_stop_never_gates_a_readiness_that_announces_nothing(tmp_path: Path, host: _Host) -> None:
    session = "gate-silent"
    h = _Harness(tmp_path, host.key(session))
    h.readiness = _readiness(state="ready_with_limitations", actionable=())
    h.readiness.acknowledged_not_done = (_OBL,)
    h.readiness.acknowledged_obligation_count = "1"
    h.readiness.rechecks = ()
    for guarded in (False, True):
        output = _stop(h, host, session, guarded=guarded)
        assert "closure gate" not in json.dumps(output)


def test_withdrawn_deliverable_is_voiced_on_the_active_stop_once(
    tmp_path: Path, host: _Host
) -> None:
    """formal-crypto S (tb4n3): the first Stop's gate named other work; the solver was emptied
    afterwards; every later Stop was active, so the emptied text was never shown."""

    session = "gate-withdrawn"
    h = _Harness(tmp_path, host.key(session))
    # The first Stop re-checks a premise dispute and an acknowledged obligation (formal S 09:11):
    # the push to work now also says to keep the working deliverable.
    h.readiness.rechecks = (premise_recheck(1), ack_recheck(_OBL))
    first = _text(host, _stop(h, host, session))
    assert "Do that work unless it is genuinely impossible" in first
    assert "keep the working deliverable; acknowledgement never requires withdrawing" in first
    h.readiness = _readiness(actionable=(gate_module.DECLARED_OUTPUT_EMPTIED_GAP,))
    h.readiness.fact_lineage = (
        SimpleNamespace(
            code=gate_module.DECLARED_OUTPUT_EMPTIED_GAP,
            rule="deliverable_path_history",
            state="emptied",
            obligation_id=_OBL,
            item_index="0",
            basis="verified",
        ),
    )
    h.sequence = "9"
    second = _stop(h, host, session, guarded=True)
    text = _text(host, second)
    assert "You withdrew a deliverable that passed your verification run" in text
    assert _OBL in text
    assert h.reasons()[1:] == ["closure_gate_continued", "closure_gate_active_stop_rechecked"]
    assert gate_module.closure_gate_turn_blocks(h.session_id, _state=tmp_path) == 2
    # The per-turn cap (2) holds: the next active Stop ends the turn without reading status.
    h.sequence = "10"
    third = _stop(h, host, session, guarded=True)
    assert "closure gate" not in json.dumps(third)
    assert h.reasons()[-1] == "closure_gate_turn_end_after_continue"


# --- tb4n4 (#1044): a delivered file that loads an undeclared file ---------------------------

_UNDECLARED = "deliverable_references_undeclared_file"
_OBL_REF = "obl_97700000-0000-4000-8000-000000000444"


def _undeclared_readiness(*paths: object, total: str = "2", **extra: Any) -> Any:
    readiness = _readiness(actionable=(_UNDECLARED,))
    readiness.undeclared_references = (
        SimpleNamespace(obligation_id=_OBL_REF, item_index="0", paths=paths, total=total),
    )
    for name, value in extra.items():
        setattr(readiness, name, value)
    return readiness


def test_an_undeclared_dependency_gates_and_names_the_files_never_disclosure() -> None:
    gate = _gate(_undeclared_readiness("artifacts/english_ngrams.npz", 'odd "name".npz', total="3"))
    assert gate is not None
    assert gate.items == (_UNDECLARED,)
    assert (
        f'Undeclared files: {_OBL_REF} item 0 names "artifacts/english_ngrams.npz",'
        " \"odd 'name'.npz\" and 1 more." in gate.text
    )
    assert "embed its content in the deliverable, rebuild it at run time" in gate.text
    assert "disclosing the dependency does not clear this" in gate.text
    # No path is remembered: the gate memory holds no key for it.
    assert gate.blocker_keys == ()


def test_a_withheld_path_reads_withheld_and_an_older_service_still_gets_the_repair() -> None:
    withheld = SimpleNamespace(omitted=True, category="repository_excerpt", reason="x")
    gate = _gate(_undeclared_readiness(withheld, total="1"))
    assert gate is not None
    assert f"{_OBL_REF} item 0 names (path withheld)." in gate.text
    older = _readiness(actionable=(_UNDECLARED,))
    gate = _gate(older)
    assert gate is not None and gate.items == (_UNDECLARED,)
    assert "Undeclared files" not in gate.text
    assert "declare it as a delivered output" in gate.text


def test_the_acceptance_invitation_waits_beside_an_undeclared_dependency() -> None:
    gate = _gate(_undeclared_readiness("a.npz", total="1", rechecks=(acceptance_recheck(),)))
    assert gate is not None
    assert "acceptance_criteria" not in gate.text
    assert not any(key.startswith("accept:") for key in gate.blocker_keys)


# --- tb4n4 (#1050): the acceptance re-read only for what the final message does not address --

_RESOLVED_A = "obl_97700000-0000-4000-8000-000000000200"
_RESOLVED_B = "obl_97700000-0000-4000-8000-000000000201"
_CRITERIA_A = "The cracker prints the decrypted plaintext for each ciphertext within 60 seconds."
_CRITERIA_B = "Recovered keys match the reference keys for every sample in tests/keys."


def _resolved_row(obligation: str, criteria: object, description: str = "Deliver it") -> Any:
    return SimpleNamespace(
        obligation_id=obligation,
        status="resolved",
        closure_basis="resolved",
        acceptance_criteria=criteria,
        description=description,
    )


def test_the_addressed_rule_is_deterministic_and_conservative() -> None:
    rows = ((_RESOLVED_A, _CRITERIA_A), (_RESOLVED_B, _CRITERIA_B))
    # A message that restates the criteria with its result addresses it.
    message = (
        "The cracker prints the decrypted plaintext for each ciphertext; the slowest took"
        " 12 seconds, well within 60 seconds."
    )
    assert gate_module.uncovered_acceptance(message, rows) == (_RESOLVED_B,)
    # Citing the obligation id covers it whatever else the message says.
    assert gate_module.uncovered_acceptance(f"{_RESOLVED_B}: done.", rows) == (_RESOLVED_A,)
    # "Done." addresses nothing; a third of the terms is not enough.
    assert gate_module.uncovered_acceptance("Done. All tests pass.", rows) == rows_ids(rows)
    assert gate_module.uncovered_acceptance("The cracker works.", rows) == rows_ids(rows)
    # A withheld text, or one with no term, is covered only by its id.
    withheld = ((_RESOLVED_A, None), (_RESOLVED_B, "It is ok."))
    assert gate_module.uncovered_acceptance("ok it is", withheld) == rows_ids(withheld)
    assert gate_module.uncovered_acceptance(f"{_RESOLVED_A} {_RESOLVED_B}", withheld) == ()


def rows_ids(rows: tuple[tuple[str, object], ...]) -> tuple[str, ...]:
    return tuple(row[0] for row in rows)


def test_the_reread_names_the_uncovered_obligations_and_ends_on_a_pure_confirmation() -> None:
    announced = _readiness(state="ready_with_limitations", actionable=())
    announced.rechecks = (acceptance_recheck((_RESOLVED_A, _RESOLVED_B)),)
    named = closure_gate_from_readiness(
        announced,
        frontier_sequence="7",
        frontier_digest=_DIGEST,
        observation_pending=False,
        acceptance_uncovered=(_RESOLVED_B,),
    )
    assert named is not None
    assert named.items == (gate_module.ACCEPTANCE_RECHECK_ITEM,)
    assert f"acceptance criteria of resolved obligation(s) {_RESOLVED_B}." in named.text
    assert _RESOLVED_A not in named.text
    # The downgrade path is unchanged (#1050 item 3) ...
    assert "republish that obligation as `acknowledged_not_done`" in named.text
    assert "`finishup-verification-limit:<obligation id>`" in named.text
    # ... and a pure confirmation is the end of it (item 2): no new record, check or receipt.
    assert "that confirmation alone needs no new record, check or receipt" in named.text
    # Every resolved obligation addressed: nothing to ask, the agent stops.
    assert (
        closure_gate_from_readiness(
            announced,
            frontier_sequence="7",
            frontier_digest=_DIGEST,
            observation_pending=False,
            acceptance_uncovered=(),
        )
        is None
    )
    # Without a final message the re-read is asked as before, for every resolved obligation.
    today = _gate(announced)
    assert today is not None
    assert "read each resolved obligation's acceptance_criteria" in today.text
    assert "that confirmation alone needs no new record" in today.text


def test_beside_an_item_that_needs_a_check_the_named_reread_promises_no_shortcut() -> None:
    announced = _readiness(actionable=("closing_review_required",))
    announced.rechecks = (acceptance_recheck((_RESOLVED_A, _RESOLVED_B)),)
    gate = closure_gate_from_readiness(
        announced,
        frontier_sequence="7",
        frontier_digest=_DIGEST,
        observation_pending=False,
        acceptance_uncovered=(_RESOLVED_A,),
    )
    assert gate is not None
    assert gate.items == ("closing_review_required", gate_module.ACCEPTANCE_RECHECK_ITEM)
    assert f"resolved obligation(s) {_RESOLVED_A}." in gate.text
    assert "needs no new record, check or receipt" not in gate.text
    covered = closure_gate_from_readiness(
        announced,
        frontier_sequence="7",
        frontier_digest=_DIGEST,
        observation_pending=False,
        acceptance_uncovered=(),
    )
    assert covered is not None and covered.items == ("closing_review_required",)


def _acceptance_harness(tmp_path: Path, host: _Host, session: str) -> tuple[_Harness, Any]:
    h = _Harness(tmp_path, host.key(session))
    invite = acceptance_recheck((_RESOLVED_A, _RESOLVED_B))
    h.readiness = _readiness(state="ready_with_limitations", actionable=())
    h.readiness.rechecks = (invite,)
    h.obligation_rows = (
        _resolved_row(_RESOLVED_A, _CRITERIA_A),
        _resolved_row(_RESOLVED_B, _CRITERIA_B),
    )
    return h, invite


def _final_stop(
    h: _Harness, host: _Host, session: str, message: str, *, guarded: bool = False
) -> Mapping[str, Any]:
    body = host.body(session, guarded=guarded)
    if host.name != "cursor":
        body["last_assistant_message"] = message
    return h.run(host.handler(), host.event(), body)


_ADDRESSED_BOTH = (
    "The cracker prints the decrypted plaintext for each ciphertext within 60 seconds"
    f" (slowest 12 seconds). {_RESOLVED_B}: recovered keys match the reference keys."
)


def test_a_final_message_that_addresses_every_criterion_skips_the_reread(
    tmp_path: Path, host: _Host
) -> None:
    """60 of 60 tb4n4 deterministic attempts were asked; 41 then only did FinishUP bookkeeping.

    Codex and Claude Code pass the final message: an addressed set is not asked and the gate
    records ``closure_gate_acceptance_covered``. Cursor's ``stop`` carries none, so it keeps the
    re-read as before (per-host decision in the runbooks).
    """

    session = "gate-acceptance-covered"
    h, invite = _acceptance_harness(tmp_path, host, session)
    output = _final_stop(h, host, session, _ADDRESSED_BOTH)
    if host.name == "cursor":
        text = _text(host, output)
        assert "read each resolved obligation's acceptance_criteria" in text
        assert "obligations" not in h.views  # no second read without a final message
        assert h.reasons() == ["closure_gate_continued", "closure_gate_acceptance_rechecked"]
        return
    assert "closure gate" not in json.dumps(output)
    assert h.views == ["compact", "obligations"]
    assert h.reasons() == ["closure_gate_acceptance_covered", "closure_gate_not_required"]
    # Nothing was asked, so nothing is remembered: a later message that drops it is asked.
    assert gate_module.closure_gate_reasked_blockers(h.session_id, _state=tmp_path) == frozenset()
    h.sequence = "6"
    later = _final_stop(h, host, session, "Done.")
    text = _text(host, later)
    assert f"{_RESOLVED_A}, {_RESOLVED_B}." in text
    assert gate_module.closure_gate_reasked_blockers(h.session_id, _state=tmp_path) == frozenset(
        {f"{invite.key}@6"}
    )


def test_the_reread_names_only_what_the_message_missed_and_the_downgrade_still_counts(
    tmp_path: Path, host: _Host
) -> None:
    """#1050 items 1 and 3: the uncovered obligation is named; the agent's acknowledgement answers
    the invite (the acknowledgement re-check does not challenge it); a pure confirmation needs no
    second round: the next Stop at the same frontier passes."""

    if host.name == "cursor":
        pytest.skip("Cursor's stop carries no final message (asked as before, test above)")
    session = "gate-acceptance-named"
    h, invite = _acceptance_harness(tmp_path, host, session)
    message = "The cracker prints the decrypted plaintext for each ciphertext within 60 seconds."
    text = _text(host, _final_stop(h, host, session, message))
    assert f"resolved obligation(s) {_RESOLVED_B}." in text
    assert _RESOLVED_A not in text
    assert h.reasons() == ["closure_gate_continued", "closure_gate_acceptance_rechecked"]

    # A pure "criteria confirmed" answer records nothing: the same frontier passes, and the
    # already-continued Stop asks nothing more.
    confirmed = _final_stop(h, host, session, f"{_RESOLVED_B}: confirmed met.", guarded=True)
    assert "closure gate" not in json.dumps(confirmed)
    assert h.reasons()[-1] == "closure_gate_turn_end_after_continue"

    # The downgrade path: the agent republishes the unmet obligation acknowledged_not_done after
    # the invite; status announces the acknowledgement, and it is not challenged.
    h.sequence = "9"
    h.readiness.rechecks = (invite, ack_recheck(_RESOLVED_B, since=8))
    after = _final_stop(h, host, session, "Acknowledged as not done.")
    assert "closure gate" not in json.dumps(after)


def test_an_unreadable_obligations_view_keeps_the_reread(tmp_path: Path, host: _Host) -> None:
    if host.name == "cursor":
        pytest.skip("Cursor's stop carries no final message")
    session = "gate-acceptance-unreadable"
    h, _invite = _acceptance_harness(tmp_path, host, session)
    h.obligation_rows = None  # the second read fails
    text = _text(host, _final_stop(h, host, session, _ADDRESSED_BOTH))
    assert "read each resolved obligation's acceptance_criteria" in text
    # A page whose resolved set is not the one the key names (a later frontier) is not trusted.
    h2, _ = _acceptance_harness(tmp_path / "other", host, session + "-2")
    h2.obligation_rows = (_resolved_row(_RESOLVED_A, _CRITERIA_A),)
    text = _text(host, _final_stop(h2, host, session + "-2", _ADDRESSED_BOTH))
    assert "read each resolved obligation's acceptance_criteria" in text
