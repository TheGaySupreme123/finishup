"""Terminal workflows must reach the service through valid public requests."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from builders.readiness import with_checklist
from finishup.cli.render import render_human_status
from finishup.protocol.models import (
    CheckAwaitingHumanModel,
    CheckRequestModel,
    ReceiptRequestModel,
    StartRequestModel,
    StatusClosureReadinessModel,
    StatusRequestModel,
    StatusResultModel,
    StatusSuccessModel,
)
from finishup.tui.app import FinishUpTui
from finishup.tui.models import CheckMode
from finishup.tui.runtime import FinishUpRuntime, RuntimeError_
from fixture_loader import load_fixture_json

pytestmark = pytest.mark.anyio
_SESSION = "ses_52000000-0000-4000-8000-000000000001"
_SUCCESSOR = "ses_52000000-0000-4000-8000-000000000002"
_TASK = "tsk_52000000-0000-4000-8000-000000000001"
_WRITER = "wri_52000000-0000-4000-8000-000000000001"
_LINEAGE_TASK = "tsk_52000000-0000-4000-8000-000000000010"
_LINEAGE_CHILD = "tsk_52000000-0000-4000-8000-000000000011"
_LINEAGE_REQUEST = "req_52000000-0000-4000-8000-000000000012"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Client:
    def __init__(self, status_result: StatusResultModel | None = None) -> None:
        self.requests: list[
            StartRequestModel | CheckRequestModel | ReceiptRequestModel | StatusRequestModel
        ] = []
        self.status_result = status_result

    async def start(self, request: StartRequestModel) -> object:
        self.requests.append(request)
        return SimpleNamespace(
            root=SimpleNamespace(
                ok=True,
                task_id=_TASK,
                session_id=_SUCCESSOR,
                writer_id=_WRITER,
                frontier=SimpleNamespace(sequence="7", head_digest="sha256:" + "a" * 64),
                compact=SimpleNamespace(),
            )
        )

    async def check(self, request: CheckRequestModel) -> object:
        self.requests.append(request)
        return self._refused()

    async def receipt(self, request: ReceiptRequestModel) -> object:
        self.requests.append(request)
        return self._refused()

    async def status(self, request: StatusRequestModel) -> object:
        self.requests.append(request)
        return self.status_result or _lineage_status_result()

    @staticmethod
    def _refused() -> object:
        return SimpleNamespace(
            root=SimpleNamespace(
                ok=False,
                error=SimpleNamespace(code="BUNDLE_BUSY", message="The task is busy."),
            )
        )


def _lineage_status_result() -> StatusResultModel:
    digest = "sha256:" + "a" * 64
    return StatusResultModel.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": _LINEAGE_REQUEST,
            "ok": True,
            "task_id": _LINEAGE_TASK,
            "session_id": _SUCCESSOR,
            "writer_id": _WRITER,
            "view": "lineage",
            "requested_frontier": {"sequence": "7", "head_digest": digest},
            "head_frontier": {"sequence": "8", "head_digest": digest},
            "subject_frontier": {"sequence": "8", "head_digest": digest},
            "result_frontier": {"sequence": "8", "head_digest": digest},
            "projection_lag": "0",
            "projection_version": "0.1.0",
            "rebuild_state": "current",
            "page": {
                "parent_task_id": None,
                "children": [
                    {
                        "task_id": _LINEAGE_CHILD,
                        "parent_task_id": _LINEAGE_TASK,
                        "origin": "parent_minted",
                        "acceptance": "accepted",
                        "work_state": "open",
                        "session_health": "active",
                        "depth": "1",
                        "rollup_state": "open_gap",
                        "blocking_conditions": ["lineage_child_incomplete"],
                    }
                ],
                "annotations": [
                    {
                        "correlation_id": "claude-child-1",
                        "subagent_id": "claude-child-1",
                        "parent_tool_call_id": None,
                        "origin": "host_observed",
                        "acceptance": "pending",
                    }
                ],
                "next_cursor": None,
            },
            "coverage": {
                "publication_channels": ["cooperative_mcp"],
                "authorship_assurance": "self_asserted",
                "artifact_observation": "published_only",
                "evidence_immutability": "content_digest",
                "ledger_freshness": "current",
                "check_types": ["none"],
                "known_gaps": [],
            },
            "gaps": [],
            "import_status": {
                "pending_count": "0",
                "terminal_count": "0",
                "phase": None,
                "report_evidence_id": None,
                "source_identity_digest": None,
            },
            "closure_readiness": with_checklist(
                {
                    "declared_obligation_count": "0",
                    "no_obligations_reason": None,
                    "open_obligation_count": "0",
                    "unanswered_finding_count": "0",
                    "receipt_blocking_finding_count": "0",
                    "blocking_conditions": ["no_obligations_declared"],
                }
            ),
            "privacy_projection": {
                "sink": "local_human_view",
                "local_disclosure_receipt_id": "egr_52000000-0000-4000-8000-000000000013",
                "policy_id": "pvy_52000000-0000-4000-8000-000000000014",
                "policy_version": "1",
                "policy_digest": digest,
                "included_categories": [],
                "blocked_categories": [],
                "omitted_pointers": [],
                "projection_commitment": "hmac-sha256:" + "b" * 64,
            },
        }
    )


async def test_exact_selector_and_returned_frontier_reach_check_and_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _Client()

    @asynccontextmanager
    async def connect(_runtime: FinishUpRuntime) -> AsyncGenerator[_Client]:
        yield client

    monkeypatch.setattr(FinishUpRuntime, "_client", connect)
    runtime = FinishUpRuntime(cwd=tmp_path)
    detail = await runtime.open_task(_SESSION)
    assert detail.item.subject_id == _TASK
    start = client.requests[0]
    assert isinstance(start, StartRequestModel)
    assert start.session_id == _SESSION
    assert start.mode == "attach"
    # The opened panel reads the service's closure checklist for the returned session (#913) and
    # renders the same lines as `finishup status`; nothing in it reads as verified.
    readiness = client.requests[1]
    assert isinstance(readiness, StatusRequestModel)
    assert readiness.view == "compact"
    assert readiness.session_id == _SUCCESSOR
    assert detail.closure_state == "action_required"
    assert detail.closure[0] == "Closure: action_required"
    with pytest.raises(RuntimeError_, match="The task is busy"):
        await runtime.run_check(_SESSION, CheckMode.DETERMINISTIC_ONLY)
    with pytest.raises(RuntimeError_, match="The task is busy"):
        await runtime.build_receipt(_SESSION, "markdown")
    for request in client.requests[2:]:
        assert isinstance(request, (CheckRequestModel, ReceiptRequestModel))
        assert request.session_id == _SUCCESSOR
        assert request.writer_id == _WRITER
        assert request.expected_frontier.sequence == "7"
        assert request.expected_frontier.head_digest == "sha256:" + "a" * 64
        assert request.actor.actor_id == "yoetz:tui"
    receipt = client.requests[-1]
    assert isinstance(receipt, ReceiptRequestModel)
    assert receipt.task_id == _TASK
    assert receipt.redaction_profile.value == "default_local_export"


async def test_coverage_slash_command_dispatches_to_the_task_coverage_view(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tui = FinishUpTui(cwd=tmp_path)
    requested: list[str] = []

    async def task_view(view: str) -> None:
        requested.append(view)

    monkeypatch.setattr(tui, "_command_task_view", task_view)
    await tui._dispatch("coverage")  # pyright: ignore[reportPrivateUsage]
    assert requested == ["coverage"]


async def test_coverage_view_uses_the_service_witnesses_and_shared_renderer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = cast(
        dict[str, Any], load_fixture_json("canonical/verification-coverage-1.4.0.case.json")
    )
    wire = _lineage_status_wire()
    wire["view"] = "coverage"
    wire["page"] = fixture["input"]["status_result"]["page"]
    result = StatusResultModel.model_validate(wire)
    client = _Client(result)

    @asynccontextmanager
    async def connect(_runtime: FinishUpRuntime) -> AsyncGenerator[_Client]:
        yield client

    monkeypatch.setattr(FinishUpRuntime, "_client", connect)
    runtime = FinishUpRuntime(cwd=tmp_path)
    await runtime.open_task(_SESSION)
    rendered = await runtime.task_status(_SESSION, "coverage")
    assert isinstance(result.root, StatusSuccessModel)
    assert rendered.lines == tuple(render_human_status(result.root).splitlines())
    assert any("6/100 failing" in line for line in rendered.lines)
    request = client.requests[-1]
    assert isinstance(request, StatusRequestModel) and request.view == "coverage"


async def test_notes_slash_command_dispatches_to_the_reviewer_notes_view(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tui = FinishUpTui(cwd=tmp_path)
    requested: list[str] = []

    async def task_view(view: str) -> None:
        requested.append(view)

    monkeypatch.setattr(tui, "_command_task_view", task_view)
    await tui._dispatch("notes")  # pyright: ignore[reportPrivateUsage]
    assert requested == ["notes"]


async def test_notes_view_reads_recorded_checks_through_the_history_view(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # #1240: reviewer notes and their answers ride on each recorded check's history row, so the
    # TUI reads the same history page the CLI and MCP read, filtered to recorded checks.
    wire = _lineage_status_wire()
    wire["view"] = "history"
    wire["page"] = {"items": [], "next_cursor": None}
    result = StatusResultModel.model_validate(wire)
    client = _Client(result)

    @asynccontextmanager
    async def connect(_runtime: FinishUpRuntime) -> AsyncGenerator[_Client]:
        yield client

    monkeypatch.setattr(FinishUpRuntime, "_client", connect)
    runtime = FinishUpRuntime(cwd=tmp_path)
    await runtime.open_task(_SESSION)
    rendered = await runtime.task_status(_SESSION, "notes")
    assert isinstance(result.root, StatusSuccessModel)
    assert rendered.lines == tuple(render_human_status(result.root).splitlines())
    request = client.requests[-1]
    assert isinstance(request, StatusRequestModel) and request.view == "history"
    assert request.filter is not None
    assert request.filter.model_dump(exclude_none=True) == {"schema_name": "check_recorded"}


async def test_notes_view_names_every_answer_in_the_receipt_s_words(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1240/#1190: /notes and the CLI history say how each note was answered, as the receipt does.

    A withheld answer recognised from its envelope (``response_unavailable``) is an answer, so it
    never reads like a missing one.
    """

    check = "evt_52000000-0000-4000-8000-000000000051"
    notes: list[dict[str, Any]] = [
        {
            "summary": f"Concern {ordinal}.",
            "detail": f"Detail {ordinal}.",
            "subject_refs": [check],
            "advisory_id": f"{check}:{ordinal}",
            "disposition": disposition,
        }
        for ordinal, disposition in enumerate(
            ("kept_choice", "response_unavailable", "no_recorded_response"), 1
        )
    ]
    notes[0] |= {
        "reason": "The task fixes it.",
        "response_event_id": "evt_52000000-0000-4000-8000-000000000052",
        "evidence_refs": [],
    }
    wire = _lineage_status_wire()
    wire["view"] = "history"
    wire["page"] = {
        "items": [
            {
                "event_id": check,
                "schema_name": "check_recorded",
                "schema_version": "1.6.0",
                "actor_id": "harness:test",
                "publication_channel": "cooperative_mcp",
                "ingestion_sequence": "3",
                "occurred_at": "2026-10-16T00:00:00.000Z",
                "accepted_at": "2026-10-16T00:00:00.000Z",
                "occurred_at_consistency": "within_forward_skew_allowance",
                "projection_status": "projected",
                "summary_code": "check_recorded",
                "correctness_advisories": notes,
                "advisory_subject_frontier": {"sequence": "2", "head_digest": "sha256:" + "a" * 64},
            }
        ],
        "next_cursor": None,
    }
    result = StatusResultModel.model_validate(wire)
    client = _Client(result)

    @asynccontextmanager
    async def connect(_runtime: FinishUpRuntime) -> AsyncGenerator[_Client]:
        yield client

    monkeypatch.setattr(FinishUpRuntime, "_client", connect)
    runtime = FinishUpRuntime(cwd=tmp_path)
    await runtime.open_task(_SESSION)
    lines = (await runtime.task_status(_SESSION, "notes")).lines
    kept = f"Correctness advisory {check}:1: checked, kept my choice (agent-reported, with reason)"
    assert kept in lines
    withheld = "answered (response withheld; disposition and reason unreadable)"
    assert f"Correctness advisory {check}:2: {withheld}" in lines
    assert f"Correctness advisory {check}:3: no recorded response" in lines


async def test_lineage_view_reuses_cli_renderer_and_preserves_child_facts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _Client()

    @asynccontextmanager
    async def connect(_runtime: FinishUpRuntime) -> AsyncGenerator[_Client]:
        yield client

    monkeypatch.setattr(FinishUpRuntime, "_client", connect)
    runtime = FinishUpRuntime(cwd=tmp_path)
    await runtime.open_task(_SESSION)

    rendered = await runtime.task_status(_SESSION, "lineage")
    result = _lineage_status_result().root
    assert isinstance(result, StatusSuccessModel)
    expected = tuple(render_human_status(result).splitlines())

    assert rendered.lines == expected
    assert (
        f"- {_LINEAGE_CHILD}: parent_minted, accepted; work open, session active; rollup open_gap"
    ) in rendered.lines
    assert "  Completion gaps: lineage_child_incomplete" in rendered.lines
    assert "- Observed subagent claude-child-1: pending child binding" in rendered.lines

    status_request = client.requests[-1]
    assert isinstance(status_request, StatusRequestModel)
    assert status_request.session_id == _SUCCESSOR
    assert status_request.writer_id == _WRITER
    assert status_request.view == "lineage"
    assert status_request.limit == "50"
    assert status_request.cursor is None


_FINDING_STATES = (
    "open",
    "verified_resolved",
    "acknowledged_not_done",
    "rejection_accepted",
    "self_verified",
)


def _finding_row(number: int, todo_state: str) -> dict[str, object]:
    digest = "sha256:" + "a" * 64
    responded = {
        "acknowledged_not_done": "acknowledged_not_done",
        "rejection_accepted": "rejected",
        "self_verified": "self_verified",
    }.get(todo_state)
    return {
        "finding_id": f"fnd_52000000-0000-4000-8000-00000000002{number}",
        "kind": "claim_without_admissible_evidence",
        "origin": "deterministic",
        "priority": 2,
        "summary": "A structural finding.",
        "detail": "A structural finding detail.",
        "subject_refs": [f"clm_52000000-0000-4000-8000-00000000003{number}"],
        "policy_id": "work-integrity",
        "policy_version": "0.1.0",
        "subject_frontier": {"sequence": "7", "head_digest": digest},
        "coverage": _lineage_status_result().model_dump(mode="json")["coverage"],
        "provenance": None,
        "disposition": responded or "none",
        "resolved": todo_state == "verified_resolved",
        "response_event_id": (
            None if responded is None else f"evt_52000000-0000-4000-8000-00000000004{number}"
        ),
        "reason": None if responded is None else "A recorded reason.",
        "waiver_scope": None,
        "waiver_expiry": None,
        "todo_state": todo_state,
        "review_rounds": "2" if todo_state == "open" else "0",
    }


def _lineage_status_wire() -> dict[str, Any]:
    """The lineage status as wire JSON: optional non-null fields absent, never ``null`` (F3)."""

    wire = _lineage_status_result().model_dump(mode="json")
    # An unset optional field dumps as null here; the public wire omits it (issues #982, ADR-049).
    for optional in ("agent_status_line", "credential_heuristic", "review_mode"):
        if wire.get(optional) is None:
            wire.pop(optional, None)
    readiness = wire.get("closure_readiness")
    if isinstance(readiness, dict):
        typed = cast(dict[str, object], readiness)
        for key in [key for key, value in typed.items() if value is None]:
            if key in StatusClosureReadinessModel.optional_non_null_fields:
                del typed[key]
    return wire


def _findings_status_result() -> StatusResultModel:
    wire = _lineage_status_wire()
    wire["view"] = "findings"
    wire["page"] = {
        "items": [_finding_row(index, state) for index, state in enumerate(_FINDING_STATES)],
        "next_cursor": None,
        "attempt_budget": "5",
    }
    return StatusResultModel.model_validate(wire)


async def test_findings_view_shows_a_linked_duplicate_through_the_cli_renderer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #996: the terminal interface names the earlier finding a duplicate is linked to."""

    earlier = _finding_row(0, "open")
    duplicate = {
        **_finding_row(1, "open"),
        "disposition": "duplicate_of",
        "response_event_id": "evt_52000000-0000-4000-8000-000000000041",
        "duplicate_of_finding_id": earlier["finding_id"],
    }
    wire = _lineage_status_wire()
    wire["view"] = "findings"
    wire["page"] = {"items": [earlier, duplicate], "next_cursor": None, "attempt_budget": "5"}
    status = StatusResultModel.model_validate(wire)
    client = _Client(status)

    @asynccontextmanager
    async def connect(_runtime: FinishUpRuntime) -> AsyncGenerator[_Client]:
        yield client

    monkeypatch.setattr(FinishUpRuntime, "_client", connect)
    runtime = FinishUpRuntime(cwd=tmp_path)
    await runtime.open_task(_SESSION)

    rendered = await runtime.task_status(_SESSION, "findings")
    assert f"  duplicate of: {earlier['finding_id']}" in rendered.lines
    assert f"[ ] F-2 {duplicate['finding_id']} open (2/5)" in rendered.lines


async def test_findings_view_shows_each_items_final_state_through_the_cli_renderer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PR #943 review CG-1: the terminal interface lists every item with its one to-do state."""

    client = _Client(_findings_status_result())

    @asynccontextmanager
    async def connect(_runtime: FinishUpRuntime) -> AsyncGenerator[_Client]:
        yield client

    monkeypatch.setattr(FinishUpRuntime, "_client", connect)
    runtime = FinishUpRuntime(cwd=tmp_path)
    await runtime.open_task(_SESSION)

    rendered = await runtime.task_status(_SESSION, "findings")
    result = _findings_status_result().root
    assert isinstance(result, StatusSuccessModel)
    assert rendered.lines == tuple(render_human_status(result).splitlines())
    rows = [_finding_row(index, state) for index, state in enumerate(_FINDING_STATES)]
    expected = (
        f"[ ] F-1 {rows[0]['finding_id']} open (2/5)",
        f"[x] F-2 {rows[1]['finding_id']} verified_resolved",
        f"[~] F-3 {rows[2]['finding_id']} acknowledged_not_done",
        f"[-] F-4 {rows[3]['finding_id']} rejection_accepted",
        # Issue #984: final, disclosed, never rendered as resolved.
        f"[s] F-5 {rows[4]['finding_id']} self_verified",
    )
    for line in expected:
        assert line in rendered.lines

    status_request = client.requests[-1]
    assert isinstance(status_request, StatusRequestModel)
    assert status_request.view == "findings"
    assert status_request.session_id == _SUCCESSOR
    # Verified items are part of the to-do list, so the view asks for them explicitly.
    assert status_request.filter is not None
    assert status_request.filter.model_dump(exclude_none=True) == {"include_resolved": True}


async def test_title_cannot_select_another_task(tmp_path: Path) -> None:
    runtime = FinishUpRuntime(cwd=tmp_path)
    with pytest.raises(RuntimeError_, match="session ID"):
        await runtime.open_task("An unrelated task title")


async def test_awaiting_human_replays_the_exact_request_even_if_picker_mode_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class AwaitingClient(_Client):
        async def check(self, request: CheckRequestModel) -> object:
            self.requests.append(request)
            if sum(isinstance(item, CheckRequestModel) for item in self.requests) > 1:
                return self._refused()
            frontier = request.expected_frontier.model_dump(mode="json")
            return SimpleNamespace(
                root=CheckAwaitingHumanModel.model_validate(
                    {
                        "protocol_version": "0.1",
                        "schema_version": "1.0.0",
                        "request_id": request.request_id,
                        "ok": True,
                        "state": "awaiting_human",
                        "task_id": _TASK,
                        "session_id": _SUCCESSOR,
                        "writer_id": _WRITER,
                        "subject_frontier": frontier,
                        "result_frontier": frontier,
                        "semantic_status": "awaiting_human",
                        "semantic_reason": "human_approval_required",
                        "continuation": {
                            "kind": "repository_privacy_setup",
                            "command": ["finishup", "--privacy"],
                            "replay_request_id": request.request_id,
                            "instruction": "Complete the trusted review, then replay this request.",
                        },
                        "privacy_projection": {
                            "sink": "local_human_view",
                            "local_disclosure_receipt_id": "egr_52000000-0000-4000-8000-000000000001",
                            "policy_id": "pvy_52000000-0000-4000-8000-000000000001",
                            "policy_version": "1",
                            "policy_digest": "sha256:" + "b" * 64,
                            "included_categories": [],
                            "blocked_categories": [],
                            "omitted_pointers": [],
                            "projection_commitment": "hmac-sha256:" + "c" * 64,
                        },
                        "versions": {
                            "protocol_version": "0.1",
                            "engine_version": "0.1.0",
                            "projection_version": "yoetz/0.1.0",
                            "policy_packs": ["research-evidence/0.2.0", "work-integrity/0.3.0"],
                        },
                    }
                )
            )

    client = AwaitingClient()

    @asynccontextmanager
    async def connect(_runtime: FinishUpRuntime) -> AsyncGenerator[AwaitingClient]:
        yield client

    monkeypatch.setattr(FinishUpRuntime, "_client", connect)
    runtime = FinishUpRuntime(cwd=tmp_path)
    await runtime.open_task(_SESSION)
    state, lines = await runtime.run_check(_SESSION, CheckMode.SEMANTIC_REQUIRED)
    assert state == "awaiting_human"
    assert "finishup --privacy" in "\n".join(lines)
    assert "No verdict yet" in "\n".join(lines)
    with pytest.raises(RuntimeError_, match="The task is busy"):
        await runtime.run_check(_SESSION, CheckMode.DETERMINISTIC_ONLY)
    # The opened panel's closure read is a status request; the check replay follows it.
    requests = [item for item in client.requests if not isinstance(item, StatusRequestModel)]
    assert requests[1] is requests[2]
    assert isinstance(requests[1], CheckRequestModel)
    assert requests[1].mode == "semantic_required"
