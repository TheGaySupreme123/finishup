"""The agent-transcribed task statement through the real start and publish paths (issue #908).

``start`` records the user's request on the lifecycle event it appends, a same-request retry
replays it, a different statement under the same request id conflicts, and a plan revision records
a newer statement while the ledger keeps the earlier one. The frozen check case then carries the
newest statement as a citable source for the AI-powered review packet.
"""

from __future__ import annotations

from typing import Literal, NoReturn, cast

import pytest

from builders.ledger_adapters import ownership_fence
from builders.start_application import MemoryStartRuntime, protocol_id, start_composition
from yoetz.application.egress import PrivacyCoordinator
from yoetz.application.semantic_case import build_semantic_case
from yoetz.application.service import Application, VerificationPolicy
from yoetz.domain.events import (
    AcceptedEvent,
    PlanRevisedPayload,
    RuntimeProfile,
    SessionOpenedPayload,
)
from yoetz.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from yoetz.domain.task_statement import TaskStatementSource, current_task_statement
from yoetz.domain.values import Frontier
from yoetz.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    build_deterministic_case,
    deterministic_case_from_json,
    deterministic_case_to_json,
)
from yoetz.kernel.reducers import replay
from yoetz.ports.diagnostics import RuntimeCapability
from yoetz.ports.importer import ImporterPort, ImportStatusSnapshot
from yoetz.ports.publish_response_catalog import PublishResponseCatalogPort
from yoetz.ports.runtime import BundleRuntimePort, RouteCommand, TaskRuntime
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.models import FrontierModel, PublishWorkRequest, StartRequest

pytestmark = pytest.mark.anyio

_REQUEST = (
    "Add Style.Truncate(int, TruncateOptions) string. Under Ascii, Style.Truncate returns plain "
    "text without tail; Output.Truncate returns text with tail; no ANSI emitted."
)
_AMENDED = _REQUEST + " Also keep U+200B at width 0."


class _IdleImporter:
    async def status(self, session: str) -> ImportStatusSnapshot:
        from yoetz.domain.values import session_id

        return ImportStatusSnapshot(session_id(session), 0, 0, (), ())


class _WorkflowRuntime(MemoryStartRuntime):
    async def route(self, command: RouteCommand) -> TaskRuntime:
        assert command.writer_id is not None
        task_id, resources = next(iter(self.resources.items()))
        ledger, objects = resources
        capabilities = frozenset(
            {
                RuntimeCapability.WRITE,
                RuntimeCapability.STRUCTURAL_READ,
                RuntimeCapability.PAYLOAD_READ,
            }
        )
        return TaskRuntime(
            task_id,
            command.session_id,
            command.writer_id,
            capabilities,
            ledger,
            objects,
            cast(ImporterPort, _IdleImporter()),
            "0.1.0",
            "0.1.0",
            "0.1",
            "1.0.0",
            ownership_fence(),
        )


def _base(request_id: str) -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "actor": {"actor_id": "harness:test", "actor_type": "harness"},
        "client": {"kind": "test_client", "version": "0.1.0", "integration": "local_cli"},
    }


def _start(seed: int, statement: str | None, *, mode: str = "create_or_attach") -> StartRequest:
    wire: dict[str, JsonValue] = {
        **_base(protocol_id("req_", seed)),
        "mode": mode,
        "task_title": "termenv truncation",
        "requested_view": "compact",
        "workspace_ref": "workspace-A",
        "external_ref": "external-A",
    }
    if statement is not None:
        wire["task_statement"] = statement
    return StartRequest.model_validate(wire)


def _frontier(value: Frontier | FrontierModel) -> JsonValue:
    if isinstance(value, Frontier):
        return cast(JsonValue, dict(value.as_wire().items()))
    return cast(JsonValue, value.model_dump(mode="json"))


def _app() -> tuple[Application, _WorkflowRuntime]:
    start_app, start_runtime, clock, catalog = start_composition()
    runtime = _WorkflowRuntime(clock, start_runtime.ids)

    async def semantic_disabled(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        require_complete_specification: bool = False,
    ) -> object:
        del frozen, findings, runtime, lineage_evaluation
        raise AssertionError("semantic_evaluator_called")

    def unused(*_: object) -> NoReturn:
        raise AssertionError("unused")

    app = Application(
        start_catalog=catalog.delegate,
        publish_responses=cast(PublishResponseCatalogPort, catalog.delegate),
        runtime=cast(BundleRuntimePort, runtime),
        clock=clock,
        ids=start_runtime.ids,
        verification_policy=VerificationPolicy(semantic="disabled", max_findings=3),
        privacy=cast(PrivacyCoordinator, object()),
        status_cursor_key=b"task-statement-status-cursor-key",
        waiver_policy_digest="sha256:" + "7" * 64,
        semantic_evaluator=semantic_disabled,
        disclosure_scope_for=unused,
        receipt_version_resolver=unused,
        waiver_authorizer=lambda _: False,
        import_publication_authorizer=lambda _: False,
        profile=RuntimeProfile.TEST_FAKE,
        policy_packs=("research-evidence/0.2.0", "work-integrity/0.3.0"),
        version_manifest=start_app.version_manifest,
        enforce_repository_identity=False,
    )
    return app, runtime


async def test_start_records_the_statement_and_same_request_retry_is_idempotent() -> None:
    app, runtime = _app()
    request = _start(9080, _REQUEST)

    created = await app.start(request)
    replayed = await app.start(request)

    assert replayed == created
    ledger, _ = runtime.resources[created.task_id]
    records = ledger._state.records  # pyright: ignore[reportPrivateUsage]
    assert len(records) == 1
    opened = records[0]
    assert type(opened) is AcceptedEvent
    assert (opened.schema.name, opened.schema.version) == ("session_opened", "1.2.0")
    assert type(opened.payload) is SessionOpenedPayload
    assert opened.payload.task_statement == _REQUEST

    # The statement is request identity: the same request id with other words conflicts.
    with pytest.raises(PublicOperationError) as conflict:
        await app.start(_start(9080, _AMENDED))
    assert conflict.value.code in {
        PublicErrorCode.IDEMPOTENCY_CONFLICT,
        PublicErrorCode.REQUEST_IDENTITY_CONFLICT,
    }
    assert len(ledger._state.records) == 1  # pyright: ignore[reportPrivateUsage]


async def test_start_without_a_statement_keeps_the_frozen_session_schema() -> None:
    app, runtime = _app()
    created = await app.start(_start(9081, None))
    ledger, _ = runtime.resources[created.task_id]
    opened = ledger._state.records[0]  # pyright: ignore[reportPrivateUsage]
    assert opened.schema.version == "1.1.0"


async def test_revision_is_newest_history_is_kept_and_the_case_cites_it() -> None:
    app, runtime = _app()
    started = await app.start(_start(9082, _REQUEST))
    plan_event = protocol_id("evt_", 9083)
    revision_event = protocol_id("evt_", 9084)
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_base(protocol_id("req_", 9085)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": (
                    {
                        "event_id": plan_event,
                        "schema": {"name": "plan_published", "version": "1.0.0"},
                        "occurred_at": "2026-09-30T12:00:00.000Z",
                        "causal_parents": (),
                        "payload": {
                            "plan_version": 1,
                            "summary": "Implement ANSI-safe truncation.",
                            "obligation_refs": (),
                            "no_obligations_reason": "single_atomic_change",
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                    {
                        "event_id": revision_event,
                        "schema": {"name": "plan_revised", "version": "1.1.0"},
                        "occurred_at": "2026-09-30T12:00:01.000Z",
                        "causal_parents": (plan_event,),
                        "payload": {
                            "plan_version": 2,
                            "supersedes_plan_version": 1,
                            "reason": "The user amended the request.",
                            "summary": "Implement ANSI-safe truncation and zero-width runes.",
                            "obligation_changes": (),
                            "no_obligations_reason": "single_atomic_change",
                            "task_statement": _AMENDED,
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    assert published.ok is True

    ledger, _ = runtime.resources[started.task_id]
    records = tuple(ledger._state.records)  # pyright: ignore[reportPrivateUsage]
    statements = [
        getattr(record.payload, "task_statement", None)
        for record in records
        if type(record) is AcceptedEvent
    ]
    assert _REQUEST in statements and _AMENDED in statements
    current = current_task_statement(records)
    assert current is not None
    assert current.text == _AMENDED
    assert str(current.source_event_id) == revision_event
    assert current.source is TaskStatementSource.AGENT_TRANSCRIBED
    revision = next(record for record in records if str(record.event_id) == revision_event)
    assert type(revision.payload) is PlanRevisedPayload

    projection = replay(records)
    case = build_deterministic_case(projection, records, CaseAvailabilityFacts())
    assert case.task_statement == current
    assert case.task_title == "termenv truncation"
    assert current.source_event_id in case.allowed_ids
    assert deterministic_case_from_json(deterministic_case_to_json(case)) == case

    semantic = build_semantic_case(
        case_id="cas_90800000-0000-4000-8000-000000000009",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.GOAL_AWARE,
        review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE),
        policy_id="pvy_90800000-0000-4000-8000-000000000009",
        policy_version="1",
    )
    statement_item = next(item for item in semantic.items if item.section == "task_statement")
    assert statement_item.source_ref == revision_event
    assert _AMENDED.encode() in statement_item.content
    goal = next(item for item in semantic.items if item.section == "goal")
    assert b"task_statement" not in goal.content


async def test_reattach_with_a_statement_records_it_on_the_resumed_session() -> None:
    app, runtime = _app()
    created = await app.start(_start(9086, _REQUEST))
    attached = await app.start(_start(9087, _AMENDED))
    assert attached.task_id == created.task_id
    ledger, _ = runtime.resources[created.task_id]
    records = tuple(ledger._state.records)  # pyright: ignore[reportPrivateUsage]
    resumed = records[-1]
    assert (resumed.schema.name, resumed.schema.version) == ("session_resumed", "1.2.0")
    current = current_task_statement(records)
    assert current is not None and current.text == _AMENDED


async def test_a_repeated_unchanged_statement_keeps_the_earlier_event_current() -> None:
    """Pilot blocker D2: a re-attach repeating the statement does not move its event."""

    app, runtime = _app()
    created = await app.start(_start(9088, _REQUEST))
    attached = await app.start(_start(9089, _REQUEST))
    assert attached.task_id == created.task_id
    ledger, _ = runtime.resources[created.task_id]
    records = tuple(ledger._state.records)  # pyright: ignore[reportPrivateUsage]
    opened, resumed = records[0], records[-1]
    assert (resumed.schema.name, resumed.schema.version) == ("session_resumed", "1.2.0")
    current = current_task_statement(records)
    assert current is not None
    assert current.source_event_id == opened.event_id
    assert current.source_family == "session_opened"
    assert set(current.equivalent_event_ids) == {opened.event_id, resumed.event_id}

    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    assert case.task_statement == current
    encoded = deterministic_case_to_json(case)
    assert "equivalent_event_ids" in canonical_encode(encoded).decode()
    assert deterministic_case_from_json(encoded) == case


@pytest.mark.parametrize("preset_version", ["1.1.0", "1.2.0"])
@pytest.mark.parametrize(
    "profile",
    [
        ReviewContextProfile.GOAL_AWARE,
        ReviewContextProfile.ASSISTED,
        ReviewContextProfile.EXPANDED,
        ReviewContextProfile.STRUCTURAL,
    ],
)
async def test_frozen_history_rows_never_carry_a_revised_statement(
    profile: ReviewContextProfile, preset_version: str
) -> None:
    """Criterion 7 (issue #908) over real frozen history, not only the projection fallback.

    Plan events that carry a statement are timeline rows too. Under an approval without the
    section no copy leaves in any item; with it, only the ``task-statement`` item carries it.
    """

    app, runtime = _app()
    started = await app.start(_start(9090, _REQUEST))
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_base(protocol_id("req_", 9091)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": _frontier(started.frontier),
                "event_drafts": (
                    {
                        "event_id": protocol_id("evt_", 9092),
                        "schema": {"name": "plan_published", "version": "1.1.0"},
                        "occurred_at": "2026-09-30T12:00:00.000Z",
                        "causal_parents": (),
                        "payload": {
                            "plan_version": 1,
                            "summary": "Implement ANSI-safe truncation.",
                            "obligation_refs": (),
                            "no_obligations_reason": "single_atomic_change",
                            "task_statement": _AMENDED,
                        },
                        "artifact_refs": (),
                        "evidence_refs": (),
                    },
                ),
            }
        )
    )
    assert published.ok is True
    ledger, _ = runtime.resources[started.task_id]
    records = tuple(ledger._state.records)  # pyright: ignore[reportPrivateUsage]
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    assert case.history_availability == "available"
    assert any(item.schema_name == "plan_published" for item in case.history)
    selection = ReviewSelectionPolicy.for_profile(
        profile, preset_version=cast(Literal["1.1.0", "1.2.0"], preset_version)
    )
    semantic = build_semantic_case(
        case_id="cas_90800000-0000-4000-8000-000000000010",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=profile,
        review_selection=selection,
        policy_id="pvy_90800000-0000-4000-8000-000000000010",
        policy_version="1",
    )
    assert any(item.section == "timeline" for item in semantic.items)
    marker = b"Output.Truncate returns text with tail"
    carriers = [item.item_id for item in semantic.items if marker in item.content]
    expected = ["task-statement"] if "task_statement" in selection.sections else []
    assert carriers == expected


@pytest.mark.parametrize("preset_version", ["1.1.0", "1.2.0"])
async def test_a_withheld_statement_is_not_a_reduced_reference_scope(preset_version: str) -> None:
    """Issue #908: the statement's lifecycle event joins the frozen case only to be citable.

    When the approved policy withholds the statement, its own gaps disclose that; the event must
    not also count as an omitted reference (``semantic_reference_scope_reduced``), which would
    ride on every check an existing approval runs.
    """

    app, runtime = _app()
    started = await app.start(_start(9095, _REQUEST))
    ledger, _ = runtime.resources[started.task_id]
    records = tuple(ledger._state.records)  # pyright: ignore[reportPrivateUsage]
    case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
    profile = ReviewContextProfile.ASSISTED
    semantic = build_semantic_case(
        case_id="cas_90800000-0000-4000-8000-000000000011",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=profile,
        review_selection=ReviewSelectionPolicy.for_profile(
            profile, preset_version=cast(Literal["1.1.0", "1.2.0"], preset_version)
        ),
        policy_id="pvy_90800000-0000-4000-8000-000000000011",
        policy_version="1",
    )
    assert semantic.omitted_reference_count == 0
    assert "semantic_reference_scope_reduced" not in semantic.packet.coverage.known_gaps
