"""The read-only ``mode: inspect`` check over the real application facade (issue #1048, ADR-047).

Built from the shape the issue reports: an agent resolves a latency obligation with evidence from
a harness command that never touched the declared supervisor entry point or configuration (the
payments-pipeline-fix D attempt), leaves a second obligation unattempted, and keeps working after
its last check. One inspection must say what is left (and whose move each gap is), what the hooks
observed since that check, and that the cited evidence has no recorded link to the declared
setup - while recording nothing, minting nothing and passing the daemon's real privacy projection.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import Any, cast

import pytest

from builders.projection_workflow import (
    ProjectionCase,
    build_projection_application,
    frontier_json,
    project_case,
    request_base,
)
from builders.start_application import protocol_id, start_request
from yoetz.application.check_inspection import CheckInspection, check_inspection_json
from yoetz.application.observation_materialize import observation_author
from yoetz.application.service import Application
from yoetz.application.start import StartInternalResult
from yoetz.cli.render import render_human_inspection
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EventDraft,
    EventPayload,
    EventSchema,
    ResultOutcome,
    ResultRecordedPayload,
    encode_payload,
    media_type_for,
)
from yoetz.domain.values import Frontier, action_id, event_id, result_id, timestamp_from_datetime
from yoetz.kernel.observed_failures import observed_action_description
from yoetz.kernel.task_facts import requested_command_identity
from yoetz.mcp.summaries import render_safe_compact_summary
from yoetz.ports.control import ControlMethod
from yoetz.ports.ledger import AppendCommand, AppendEntry, CheckCommitResult, OperationKind
from yoetz.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
from yoetz.protocol.canonical import canonical_encode
from yoetz.protocol.coverage import PublicationChannel, coverage_for_channel
from yoetz.protocol.models import (
    CheckInspectionModel,
    CheckRequest,
    CheckResult,
    PublishWorkRequest,
    classify_result_leaf,
    public_model_to_wire,
)

pytestmark = pytest.mark.anyio

_LATENCY = protocol_id("obl_", 7101)
_TESTS = protocol_id("obl_", 7102)
_HARNESS_ACTION = protocol_id("act_", 7103)
_HARNESS_RESULT = protocol_id("res_", 7104)
_SUPERVISED_ACTION = protocol_id("act_", 7105)
_SUPERVISED_RESULT = protocol_id("res_", 7106)
_DIGEST = "sha256:" + "4" * 64


class _Drafts:
    def __init__(self, start: int) -> None:
        self.number = start

    def __call__(self, name: str, payload: dict[str, Any], version: str = "1.0.0") -> Any:
        self.number += 1
        return {
            "event_id": protocol_id("evt_", self.number),
            "schema": {"name": name, "version": version},
            "occurred_at": "2026-10-12T12:00:00.000Z",
            "causal_parents": [],
            "artifact_refs": [],
            "evidence_refs": [],
            "payload": payload,
        }


def _latency_obligation(status: str, evidence: tuple[str, ...] = ()) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "obligation_id": _LATENCY,
        "description": "p99 latency of the payments service as deployed",
        "evidence_expectation": "A latency run against the supervised service",
        "status": status,
        "requested_items": [
            {"item_kind": "file", "value": "deploy/supervisord.conf", "role": "output"},
            {"item_kind": "command", "value": "supervisorctl start payments"},
        ],
    }
    if evidence:
        payload["resolution_evidence_refs"] = list(evidence)
    return payload


async def _publish(
    app: Application, started: StartInternalResult, frontier: Any, drafts: list[Any], seed: int
) -> Frontier:
    result = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier_json(frontier),
                "event_drafts": drafts,
            }
        )
    )
    return cast(Frontier, result.result_frontier)


async def _append_observed(
    app: Application,
    started: StartInternalResult,
    items: tuple[tuple[str, EventPayload], ...],
    *,
    seed: int,
    expected_frontier: int,
) -> Frontier:
    runtime = cast(Any, app.runtime)
    ledger, objects = next(iter(runtime.resources.values()))
    now = app.clock.now_utc()
    entries: list[AppendEntry] = []
    for offset, (schema_name, payload) in enumerate(items):
        encoded = canonical_encode(encode_payload(payload))
        metadata = ObjectMetadata(
            ObjectKind.EVENT_PAYLOAD, media_type_for(schema_name), started.task_id, now
        )
        staged = await objects.stage(
            ObjectSource(data=encoded, declared_size=len(encoded)), metadata
        )
        payload_ref = await objects.finalize(staged)
        entries.append(
            AppendEntry(
                EventDraft(
                    event_id(protocol_id("evt_", seed + offset)),
                    EventSchema(schema_name, "1.0.0"),
                    timestamp_from_datetime(now),
                    (),
                    payload,
                    (),
                    (),
                ),
                observation_author(),
                payload_ref,
                payload_ref.commitment,
                metadata.media_type,
                payload_ref.plaintext_size,
                PublicationChannel.HOOK_OBSERVED,
                coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
                "projected",
            )
        )
    appended = await ledger.append_batch(
        AppendCommand(
            started.task_id,
            started.session_id,
            started.writer_id,
            protocol_id("req_", seed + 90),
            OperationKind.PUBLISH_WORK,
            _DIGEST,
            expected_frontier,
            tuple(entries),
            None,
        )
    )
    return cast(Frontier, appended.result_frontier)


def _observed_action(
    seed: int, kind: ActionKind, tool: str, **runtime: Any
) -> tuple[str, EventPayload]:
    return (
        "action_recorded",
        ActionRecordedPayload(
            action_id(protocol_id("act_", seed)),
            kind,
            observed_action_description(
                f"Observed {kind.value} via Claude Code hook", tool, None, **runtime
            ),
            command="omitted:structural" if kind is ActionKind.COMMAND else None,
        ),
    )


def _observed_result(seed: int, action_seed: int, outcome: ResultOutcome, exit_status: int) -> Any:
    return (
        "result_recorded",
        ResultRecordedPayload(
            result_id(protocol_id("res_", seed)),
            action_id(protocol_id("act_", action_seed)),
            outcome,
            exit_status=exit_status,
            summary=f"Observed result status={outcome.value}",
        ),
    )


async def _inspect(
    app: Application, started: StartInternalResult, frontier: Frontier, seed: int, **extra: Any
) -> tuple[CheckInspection, dict[str, Any]]:
    wire: dict[str, Any] = {
        **request_base(protocol_id("req_", seed)),
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(frontier),
        "mode": "inspect",
        **extra,
    }
    internal = await app.check(CheckRequest.model_validate(wire))
    assert type(internal) is CheckInspection
    projected = await project_case(
        app, ProjectionCase("check-inspect", ControlMethod.CHECK, wire, internal), seed + 1
    )
    return internal, dict(projected)


async def _ledger_head(app: Application, started: StartInternalResult) -> int:
    runtime = cast(Any, app.runtime)
    ledger, _objects = next(iter(runtime.resources.values()))
    return len([record async for record in ledger.load_events(started.session_id)])


async def test_inspection_answers_what_is_left_what_hooks_saw_and_where_evidence_came_from() -> (
    None
):
    app, _policy = await build_projection_application(seed=7000)
    started = await app.start(start_request(7000, title="Payments latency"))
    draft = _Drafts(7200)
    frontier = await _publish(
        app,
        started,
        started.frontier,
        [
            draft(
                "plan_published",
                {
                    "plan_version": 1,
                    "summary": "Measure and fix",
                    "obligation_refs": [_LATENCY, _TESTS],
                },
            ),
            draft("obligation_published", _latency_obligation("open"), "1.1.0"),
            draft(
                "obligation_published",
                {
                    "obligation_id": _TESTS,
                    "description": "The test suite passes",
                    "evidence_expectation": "An observed test run",
                    "status": "open",
                    "requested_items": [{"item_kind": "command", "value": "make test"}],
                },
            ),
        ],
        7300,
    )
    # The latency evidence comes from a harness that bypasses the supervisor: its action names
    # neither the declared configuration nor the requested supervisor command.
    frontier = await _publish(
        app,
        started,
        frontier,
        [
            draft(
                "action_recorded",
                {
                    "action_id": _HARNESS_ACTION,
                    "action_kind": "command",
                    "command": "python bench/latency.py --direct",
                    "description": "Latency harness run",
                    "obligation_refs": [_LATENCY],
                },
            ),
            draft(
                "result_recorded",
                {"result_id": _HARNESS_RESULT, "action_id": _HARNESS_ACTION, "outcome": "success"},
            ),
            draft(
                "obligation_published",
                _latency_obligation("resolved", (_HARNESS_RESULT,)),
                "1.1.0",
            ),
        ],
        7310,
    )
    checked = await app.check(
        CheckRequest.model_validate(
            {
                **request_base(protocol_id("req_", 7320)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier_json(frontier),
                "mode": "deterministic_only",
                "max_findings": "3",
            }
        )
    )
    assert type(checked) is CheckCommitResult
    checked_frontier = checked.result_frontier
    # After the check: a failing observed command, an observed workspace edit, and Yoetz's own
    # status call (never listed: it cannot change the work).
    frontier = await _append_observed(
        app,
        started,
        (
            _observed_action(7400, ActionKind.COMMAND, "Bash", write_scope="workspace"),
            _observed_result(7401, 7400, ResultOutcome.FAILURE, 1),
            _observed_action(7402, ActionKind.EDIT, "Edit", write_scope="workspace"),
            _observed_action(7403, ActionKind.OTHER, "mcp__yoetz__status"),
        ),
        seed=7400,
        expected_frontier=checked_frontier.sequence,
    )

    head_before = await _ledger_head(app, started)
    internal, projected = await _inspect(app, started, frontier, 7500)
    # A read: nothing appended, nothing minted.
    assert await _ledger_head(app, started) == head_before
    assert internal.frontier == frontier

    result = CheckResult.model_validate(projected)
    assert type(result.root) is CheckInspectionModel
    assert projected["state"] == "inspected"
    for forbidden in ("verdict", "findings", "coverage", "semantic_status", "result_frontier"):
        assert forbidden not in projected

    remaining = projected["remaining"]
    assert remaining["readiness"] == "action_required"
    assert remaining["obligation_count"] == "1"
    (tests_row,) = remaining["obligations"]
    assert tests_row["obligation_id"] == _TESTS
    assert (tests_row["closure_class"], tests_row["closure_basis"]) == ("agent_work", "open")
    assert tests_row["missing"] == [
        {"kind": "requested_item_not_attempted", "owner": "agent", "item_indexes": ["0"]},
        {"kind": "resolution_evidence_not_cited", "owner": "agent"},
    ]

    observed = projected["observed_since_check"]
    assert observed["last_check_frontier"] == str(checked.subject_frontier.sequence)
    assert observed["action_count"] == "2"
    command, edit = observed["actions"]
    assert command["action_kind"] == "command"
    assert command["tool_name"] == "Bash"
    assert command["outcome"] == "failure" and command["exit_status"] == 1
    assert command["write_scope"] == "workspace"
    assert edit["action_kind"] == "edit"
    assert edit["material_class"] == "edit_or_write"
    assert edit["write_scope"] == "workspace"
    assert all(row.get("tool_name") != "mcp__yoetz__status" for row in observed["actions"])

    alignment = projected["evidence_alignment"]
    assert alignment["basis"] == "recorded_links"
    (latency,) = alignment["obligations"]
    assert latency["obligation_id"] == _LATENCY
    assert latency["alignment"] == "evidence_off_declared_items"
    assert latency["declared_items"] == [
        {"index": "0", "item_kind": "file"},
        {"index": "1", "item_kind": "command"},
    ]
    (source,) = latency["sources"]
    expected_source: dict[str, Any] = {
        "ref": _HARNESS_RESULT,
        "origin": "asserted",
        "named_item_indexes": [],
        "outcome": "success",
    }
    # The keyed identity a hook would record for the asserted command, when this process holds
    # the installation key; never the command text.
    commitment = requested_command_identity("python bench/latency.py --direct")
    if commitment is not None:
        expected_source["command_commitment"] = commitment
    assert source == expected_source

    # Every leaf of the branch is structural under the daemon's own classification.
    wire = public_model_to_wire(result)

    def leaves(value: object, pointer: str = "") -> list[str]:
        if isinstance(value, dict):
            mapping = cast(dict[str, object], value)
            return [
                leaf for key, item in mapping.items() for leaf in leaves(item, f"{pointer}/{key}")
            ]
        if isinstance(value, list):
            rows = cast(list[object], value)
            return [
                leaf
                for index, item in enumerate(rows)
                for leaf in leaves(item, f"{pointer}/{index}")
            ]
        return [pointer]

    for pointer in leaves(wire):
        if pointer.startswith("/privacy_projection"):
            continue
        assert classify_result_leaf("check", wire, pointer) == "public_structural", pointer

    # The CLI and the MCP text print the same lead; the flagged evidence is named.
    assert isinstance(result.root, CheckInspectionModel)
    cli = render_human_inspection(result.root)
    mcp = render_safe_compact_summary(wire)
    for text in (cli, mcp):
        assert "read only; nothing was recorded" in text
        assert "What is left: readiness action_required" in text
        assert "1 cite evidence with no recorded link" in text
    assert f"{_LATENCY} evidence_off_declared_items" in cli
    assert "requested items not attempted (#0) [you]" in cli


async def test_evidence_that_names_the_declared_setup_is_not_flagged() -> None:
    app, _policy = await build_projection_application(seed=7600)
    started = await app.start(start_request(7600, title="Payments latency, supervised"))
    draft = _Drafts(7700)
    frontier = await _publish(
        app,
        started,
        started.frontier,
        [
            draft(
                "plan_published",
                {"plan_version": 1, "summary": "Measure", "obligation_refs": [_LATENCY]},
            ),
            draft("obligation_published", _latency_obligation("open"), "1.1.0"),
            draft(
                "action_recorded",
                {
                    "action_id": _SUPERVISED_ACTION,
                    "action_kind": "command",
                    "command": "supervisorctl start payments",
                    "description": "Started the service under its supervisor and measured",
                    "obligation_refs": [_LATENCY],
                    "attempted_items": ["deploy/supervisord.conf", "supervisorctl start payments"],
                },
            ),
            draft(
                "result_recorded",
                {
                    "result_id": _SUPERVISED_RESULT,
                    "action_id": _SUPERVISED_ACTION,
                    "outcome": "success",
                },
            ),
            draft(
                "obligation_published",
                _latency_obligation("resolved", (_SUPERVISED_RESULT,)),
                "1.1.0",
            ),
        ],
        7800,
    )
    head_before = await _ledger_head(app, started)
    _internal, projected = await _inspect(app, started, frontier, 7900, await_observations=True)
    assert await _ledger_head(app, started) == head_before
    (latency,) = projected["evidence_alignment"]["obligations"]
    assert latency["alignment"] == "evidence_names_declared_item"
    (source,) = latency["sources"]
    assert source["origin"] == "asserted"
    assert source["named_item_indexes"] == ["0", "1"]
    # No check yet: nothing to compare the hook observations against, and it says so.
    observed = projected["observed_since_check"]
    assert "last_check_frontier" not in observed
    assert projected["remaining"]["obligations"] == []


@pytest.mark.parametrize(
    "extra",
    (
        {"final_review": True},
        {"max_findings": "3"},
        {"policy_packs": ["work-integrity/0.3.0"]},
        {"scope": {"claim_ids": [], "obligation_ids": []}},
    ),
)
def test_inspect_refuses_the_options_that_only_a_minting_check_has(extra: dict[str, Any]) -> None:
    from pydantic import ValidationError

    wire = {
        **request_base(protocol_id("req_", 8000)),
        "session_id": protocol_id("ses_", 8001),
        "writer_id": protocol_id("wri_", 8002),
        "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
        "mode": "inspect",
    }
    CheckRequest.model_validate(wire)
    CheckRequest.model_validate({**wire, "await_observations": True})
    with pytest.raises(ValidationError):
        CheckRequest.model_validate({**wire, **extra})
    # The same option stays legal on a minting check.
    CheckRequest.model_validate({**wire, "mode": "deterministic_only", **extra})


def test_inspection_json_carries_only_a_supplied_wait() -> None:
    from yoetz.ports.ledger import CheckObservationsAwaited

    base = CheckInspection(
        protocol_id("req_", 8100),
        protocol_id("tsk_", 8101),
        protocol_id("ses_", 8102),
        protocol_id("wri_", 8103),
        Frontier.genesis(),
        {},
        {},
        {},
    )
    assert "observations_awaited" not in check_inspection_json(base)
    from dataclasses import replace

    awaited = check_inspection_json(
        replace(base, observations_awaited=CheckObservationsAwaited("bounded_timeout", 2))
    )
    assert awaited["observations_awaited"] == {"state": "bounded_timeout", "pending_count": "2"}


async def test_evidence_items_trace_through_their_recorded_links_or_say_they_cannot() -> None:
    """An evidence item cites its action through ``causal_parents``; a bare one is unattributed."""

    from yoetz.domain.events import EVIDENCE_SCHEMA_VERSION

    app, _policy = await build_projection_application(seed=8200)
    started = await app.start(start_request(8200, title="Evidence links"))
    draft = _Drafts(8300)
    linked_evidence = protocol_id("evd_", 8201)
    bare_evidence = protocol_id("evd_", 8202)
    bare_obligation = protocol_id("obl_", 8203)
    action_draft = draft(
        "action_recorded",
        {
            "action_id": _SUPERVISED_ACTION,
            "action_kind": "edit",
            "description": "Configured the supervisor",
            "obligation_refs": [_LATENCY],
            "attempted_items": ["deploy/supervisord.conf"],
        },
    )

    def evidence(evidence_id: str, parents: list[str]) -> Any:
        row = draft(
            "evidence_recorded",
            {
                "evidence_id": evidence_id,
                "evidence_kind": "other",
                "strength": "metadata_only",
                "observed_at": "2026-10-12T12:00:00.000Z",
                "description": "Configuration evidence",
            },
            EVIDENCE_SCHEMA_VERSION,
        )
        row["causal_parents"] = parents
        return row

    frontier = await _publish(
        app,
        started,
        started.frontier,
        [
            draft(
                "plan_published",
                {
                    "plan_version": 1,
                    "summary": "Configure",
                    "obligation_refs": sorted([_LATENCY, bare_obligation]),
                },
            ),
            draft("obligation_published", _latency_obligation("open"), "1.1.0"),
            draft(
                "obligation_published",
                {
                    "obligation_id": bare_obligation,
                    "description": "Write the runbook",
                    "evidence_expectation": "The runbook file",
                    "status": "open",
                    "requested_items": [
                        {"item_kind": "file", "value": "docs/runbook.md", "role": "output"}
                    ],
                },
                "1.1.0",
            ),
            action_draft,
            evidence(linked_evidence, [action_draft["event_id"]]),
            evidence(bare_evidence, []),
        ],
        8400,
    )
    frontier = await _publish(
        app,
        started,
        frontier,
        [
            draft(
                "obligation_published",
                _latency_obligation("resolved", (linked_evidence,)),
                "1.1.0",
            ),
            draft(
                "obligation_published",
                {
                    "obligation_id": bare_obligation,
                    "description": "Write the runbook",
                    "evidence_expectation": "The runbook file",
                    "status": "resolved",
                    "requested_items": [
                        {"item_kind": "file", "value": "docs/runbook.md", "role": "output"}
                    ],
                    "resolution_evidence_refs": [bare_evidence],
                },
                "1.1.0",
            ),
        ],
        8410,
    )
    _internal, projected = await _inspect(app, started, frontier, 8500)
    rows = {row["obligation_id"]: row for row in projected["evidence_alignment"]["obligations"]}
    linked = rows[_LATENCY]
    assert linked["alignment"] == "evidence_names_declared_item"
    assert linked["sources"] == [
        {"ref": linked_evidence, "origin": "asserted", "named_item_indexes": ["0"]}
    ]
    bare = rows[bare_obligation]
    assert bare["alignment"] == "evidence_unattributed"
    assert bare["sources"] == [
        {"ref": bare_evidence, "origin": "unattributed", "named_item_indexes": []}
    ]


@pytest.mark.parametrize(
    ("observed_command", "alignment", "named"),
    (
        # The run Yoetz's hook observed was the requested supervisor command.
        ("supervisorctl start payments", "evidence_names_declared_item", ["1"]),
        # tb4n4 payments D: the latency run bypassed the supervisor the service is deployed under.
        ("python bench/latency.py --direct", "evidence_off_declared_items", []),
    ),
)
async def test_an_observed_run_is_compared_with_the_requested_command_by_keyed_identity(
    observed_command: str, alignment: str, named: list[str]
) -> None:
    from builders.observed_runs import INSTALLATION_KEY, command_identity_for
    from yoetz.kernel.observed_failures import command_identity
    from yoetz.kernel.task_facts import register_command_identity_key

    register_command_identity_key(INSTALLATION_KEY)
    try:
        app, _policy = await build_projection_application(seed=8600)
        started = await app.start(start_request(8600, title="Observed latency run"))
        draft = _Drafts(8700)
        frontier = await _publish(
            app,
            started,
            started.frontier,
            [
                draft(
                    "plan_published",
                    {"plan_version": 1, "summary": "Measure", "obligation_refs": [_LATENCY]},
                ),
                draft("obligation_published", _latency_obligation("open"), "1.1.0"),
            ],
            8800,
        )
        field = command_identity_for(observed_command)
        observed_action = ActionRecordedPayload(
            action_id(protocol_id("act_", 8810)),
            ActionKind.COMMAND,
            observed_action_description("Observed command via Claude Code hook", "Bash", None),
            command=field,
        )
        frontier = await _append_observed(
            app,
            started,
            (
                ("action_recorded", observed_action),
                _observed_result(8811, 8810, ResultOutcome.SUCCESS, 0),
            ),
            seed=8810,
            expected_frontier=frontier.sequence,
        )
        observed_result = protocol_id("res_", 8811)
        frontier = await _publish(
            app,
            started,
            frontier,
            [
                draft(
                    "obligation_published",
                    _latency_obligation("resolved", (observed_result,)),
                    "1.1.0",
                )
            ],
            8820,
        )
        _internal, projected = await _inspect(app, started, frontier, 8900)
    finally:
        register_command_identity_key(None)
    (row,) = projected["evidence_alignment"]["obligations"]
    assert row["alignment"] == alignment
    assert row["sources"] == [
        {
            "ref": observed_result,
            "origin": "observed",
            "command_commitment": command_identity(field),
            "outcome": "success",
            "named_item_indexes": named,
        }
    ]


async def test_alignment_beyond_the_bound_is_counted_and_never_drops_a_flag() -> None:
    """A revised plan can carry more than 64 obligations; every one citing evidence is counted.

    Sixty-four obligations declare nothing and cite evidence; the sixty-fifth, carried in by a
    plan revision and last by id, declares a deliverable its evidence never names. It is the only
    flagged row, so it must be listed and counted, never the row the bound drops.
    """

    app, _policy = await build_projection_application(seed=9000)
    started = await app.start(start_request(9000, title="Expanded plan"))
    draft = _Drafts(9100)
    plain = [protocol_id("obl_", 9300 + index) for index in range(64)]
    carried = protocol_id("obl_", 9400)
    action = protocol_id("act_", 9401)
    result = protocol_id("res_", 9402)

    def obligation(obligation_id: str, status: str, declared: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "obligation_id": obligation_id,
            "description": "One measured part of the work",
            "evidence_expectation": "A recorded run",
            "status": status,
        }
        if declared:
            payload["requested_items"] = [
                {"item_kind": "file", "value": "deploy/supervisord.conf", "role": "output"}
            ]
        if status == "resolved":
            payload["resolution_evidence_refs"] = [result]
        return payload

    frontier = await _publish(
        app,
        started,
        started.frontier,
        [
            draft(
                "plan_published",
                {"plan_version": 1, "summary": "Measure", "obligation_refs": plain},
            ),
            *(
                draft("obligation_published", obligation(item, "open", False), "1.1.0")
                for item in plain
            ),
        ],
        9500,
    )
    frontier = await _publish(
        app,
        started,
        frontier,
        [
            draft(
                "plan_revised",
                {
                    "plan_version": 2,
                    "supersedes_plan_version": 1,
                    "reason": "The scope expanded.",
                    "summary": "One more obligation applies.",
                    "obligation_changes": [{"obligation_id": carried, "change": "carried"}],
                },
            ),
            draft("obligation_published", obligation(carried, "open", True), "1.1.0"),
            draft(
                "action_recorded",
                {
                    "action_id": action,
                    "action_kind": "command",
                    "command": "python bench/latency.py --direct",
                    "description": "Latency harness run",
                },
            ),
            draft(
                "result_recorded",
                {"result_id": result, "action_id": action, "outcome": "success"},
            ),
        ],
        9510,
    )
    frontier = await _publish(
        app,
        started,
        frontier,
        [
            draft("obligation_published", obligation(item, "resolved", item == carried), "1.1.0")
            for item in (*plain, carried)
        ],
        9520,
    )
    _internal, projected = await _inspect(app, started, frontier, 9600)
    result_model = CheckResult.model_validate(projected)
    assert type(result_model.root) is CheckInspectionModel

    alignment = projected["evidence_alignment"]
    rows = alignment["obligations"]
    assert len(rows) == 64
    flagged = [row for row in rows if row["alignment"] == "evidence_off_declared_items"]
    assert [row["obligation_id"] for row in flagged] == [carried]
    assert rows[0]["obligation_id"] == carried
    assert alignment["obligation_count"] == "65"
    assert alignment["off_declared_count"] == "1"

    wire = public_model_to_wire(result_model)
    cli = render_human_inspection(result_model.root)
    mcp = render_safe_compact_summary(wire)
    for text in (cli, mcp):
        assert "65 obligation(s) cite resolution evidence, 64 listed" in text
        assert "1 cite evidence with no recorded link" in text
