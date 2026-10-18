"""A failed command, then its passing rerun, through the real coordinator to status and receipt.

#1104 round 1 (the design's ``test_failed_command_then_pass_then_receipt_is_not_blocked``). The
Claude Code hook handler records a ``PostToolUseFailure`` and a later passing ``PostToolUse`` of the
same command into a real local observation store. Every stored envelope is materialized and
appended as a hook observation, and the real ``ObservationCoordinator`` runs the real advice rule
over the stored envelopes (``build_observation_advice_snapshot``, as ``_run_advice`` does) and
records its own ``failed_command_unresolved`` finding (``_materialize_advice_findings``). Status (the
findings view, validated against the generated ``status-result`` model) and the receipt then read
the finding as retired by the passing run, not blocking.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import io
from pathlib import Path
from typing import Any, cast

import pytest

import integration.application.test_respond_status_receipt as workflow
from builders.ledger_adapters import MemoryObjects
from builders.start_application import start_request
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application import status as status_module
from finishup.application.observation_advice import (
    ObservationAdviceBuildInput,
    build_observation_advice_snapshot,
)
from finishup.application.observation_coordinator import ObservationCoordinator
from finishup.application.observation_materialize import (
    materialize_observation_envelope,
    observation_author,
)
from finishup.cli import observe_hooks
from finishup.domain.events import AcceptedEvent, ResultRecordedPayload, media_type_for
from finishup.domain.findings import Finding
from finishup.domain.observation import AdviceSnapshot, ObservationEnvelope, ObservationLifecycle
from finishup.domain.observation_profiles import CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
from finishup.domain.values import Frontier
from finishup.kernel.task_facts import register_command_identity_key
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.ledger import (
    AppendCommand,
    AppendEntry,
    LedgerPort,
    OperationKind,
    ProjectionView,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
from finishup.ports.runtime import (
    BundleRuntimePort,
    RouteAccess,
    RouteCommand,
    TaskObservationPort,
    TaskRuntime,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import StatusRequest
from integration.application.test_closure_readiness_checklist import _Session, public_status

pytestmark = pytest.mark.anyio

_COMMAND = "pytest -q tests/test_retire_1104.py"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Host:
    """A Claude Code ordinary-profile hook writing into one isolated local store."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.state = root / "state"
        self.store = LocalObservationStore(_state=self.state)
        self.workspace = self.store.workspace_commitment(str(root.resolve()))
        self.store.grant_consent(self.workspace)
        self.appended: set[str] = set()

    def emit(self, event: str, payload: dict[str, JsonValue]) -> None:
        assert (
            observe_hooks.handle_claude_observe(
                event_name=event,
                stdin_bytes=canonical_encode(payload),
                stdout=io.BytesIO(),
                workspace=str(self.root),
                _state=self.state,
                skip_service=True,
                observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )

    def bash(self, call: str, *, failed: bool, command: str = _COMMAND) -> None:
        session: dict[str, JsonValue] = {
            "session_id": "claude-1104",
            "tool_name": "Bash",
            "tool_use_id": call,
        }
        tool_input: dict[str, JsonValue] = {"command": command, "description": "Run tests"}
        self.emit(
            "PreToolUse", {**session, "hook_event_name": "PreToolUse", "tool_input": tool_input}
        )
        if failed:
            self.emit(
                "PostToolUseFailure",
                {
                    **session,
                    "hook_event_name": "PostToolUseFailure",
                    "tool_input": tool_input,
                    "error": "Exit code 1\n1 failed",
                },
            )
        else:
            self.emit(
                "PostToolUse",
                {
                    **session,
                    "hook_event_name": "PostToolUse",
                    "tool_input": tool_input,
                    "tool_response": {"stdout": "1 passed", "stderr": "", "interrupted": False},
                },
            )

    def new_envelopes(self) -> list[ObservationEnvelope]:
        fresh = [
            envelope
            for envelope in self.store.list_envelopes(self.workspace)
            if envelope.source_identity not in self.appended
        ]
        self.appended.update(envelope.source_identity for envelope in fresh)
        return fresh


def _ledger(session: _Session) -> tuple[LedgerPort, MemoryObjects]:
    resources = cast(
        dict[str, tuple[LedgerPort, MemoryObjects]], cast(Any, session.runtime).resources
    )
    return next(iter(resources.values()))


async def _head(session: _Session) -> Frontier:
    ledger, _objects = _ledger(session)
    projection = await ledger.load_projection(session.started.session_id, ProjectionView.COMPACT)
    assert projection is not None
    return projection.frontier


async def _append_observed(session: _Session, envelopes: list[ObservationEnvelope]) -> None:
    """Append what the production mapping materializes for each envelope, as the coordinator does."""

    ledger, objects = _ledger(session)
    now = session.app.clock.now_utc()
    entries: list[AppendEntry] = []
    # A call's pre and post materialize the same action; the coordinator appends it once.
    seen = {str(record.event_id) for record in await _records(session)}
    for envelope in envelopes:
        batch = materialize_observation_envelope(envelope, task_id=session.started.task_id)
        for item in batch.drafts:
            if str(item.draft.event_id) in seen:
                continue
            seen.add(str(item.draft.event_id))
            metadata = ObjectMetadata(
                ObjectKind.EVENT_PAYLOAD,
                media_type_for(item.draft.schema.name),
                session.started.task_id,
                now,
            )
            staged = await objects.stage(
                ObjectSource(data=item.payload_bytes, declared_size=len(item.payload_bytes)),
                metadata,
            )
            ref = await objects.finalize(staged)
            entries.append(
                AppendEntry(
                    item.draft,
                    observation_author(),
                    ref,
                    ref.commitment,
                    metadata.media_type,
                    ref.plaintext_size,
                    batch.channel,
                    batch.coverage,
                    item.projection_status,
                )
            )
    if not entries:
        return
    appended = await ledger.append_batch(
        AppendCommand(
            session.started.task_id,
            session.started.session_id,
            session.started.writer_id,
            session.next("req_"),
            OperationKind.PUBLISH_WORK,
            "sha256:" + "7" * 64,
            int(session.frontier.sequence),
            tuple(entries),
            None,
        )
    )
    session.frontier = appended.result_frontier


async def _records(session: _Session) -> list[AcceptedEvent]:
    ledger, _objects = _ledger(session)
    return [
        record
        async for record in ledger.load_events(session.started.session_id)
        if type(record) is AcceptedEvent
    ]


async def _findings_view(session: _Session) -> list[dict[str, Any]]:
    request = StatusRequest.model_validate(
        {
            **workflow._request_base(session.next("req_")),
            "session_id": session.started.session_id,
            "writer_id": session.started.writer_id,
            "view": "findings",
            "limit": "10",
            "filter": {"include_resolved": True},
        }
    )
    status = await session.app.status(request)
    wire = status.as_json()
    # The generated status-result model admits the new closure basis tokens (#1104).
    public_status(status)
    return cast(list[dict[str, Any]], cast(dict[str, Any], wire)["page"]["items"])


async def test_failed_command_then_pass_then_receipt_is_not_blocked(tmp_path: Path) -> None:
    app, runtime, _ = workflow._build_app(seed_offset=1104)
    started = await app.start(start_request(1_104_500, title="Retire a fixed failure"))
    session = _Session(app, runtime, started)
    host = _Host(tmp_path)

    host.bash("toolu-red", failed=True)
    red = host.new_envelopes()
    await _append_observed(session, red)

    task_runtime = await runtime.route(
        RouteCommand(
            started.session_id,
            started.writer_id,
            RouteAccess.WRITE,
            frozenset({RuntimeCapability.WRITE}),
        )
    )
    coordinator = ObservationCoordinator(
        runtime=cast(BundleRuntimePort, runtime),
        local=host.store,
        clock=app.clock,
        ids=app.ids,
        state_root=host.state,
    )
    # The real advice rule over the stored envelopes, then the coordinator's own materialization.
    envelopes = host.store.list_envelopes(host.workspace)
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    assert any(item.rule_code == "failed_command_unresolved" for item in snapshot.ranked_items)
    await coordinator._materialize_advice_findings(
        task_runtime, envelopes, snapshot, store=cast(TaskObservationPort, host.store)
    )
    records = await _records(session)
    findings = [
        record
        for record in records
        if record.schema.name == "finding_recorded"
        and type(record.payload) is Finding
        and record.payload.policy_id == "work-integrity"
    ]
    assert len(findings) == 1, [record.schema.name for record in records]
    finding = cast(Finding, findings[0].payload)
    # The coordinator named the failed call's own action and result events, not the session's
    # lifecycle fallback: that is what lets a later pass find the failed run.
    failed_result = next(
        record
        for record in records
        if type(record.payload) is ResultRecordedPayload
        and record.payload.exit_status is None
        and record.payload.outcome.value == "failure"
    )
    failed_action = next(
        record
        for record in records
        if record.schema.name == "action_recorded"
        and getattr(record.payload, "action_id", None)
        == cast(ResultRecordedPayload, failed_result.payload).action_id
    )
    assert {str(ref) for ref in finding.subject_refs} == {
        str(failed_action.event_id),
        str(failed_result.event_id),
    }
    session.frontier = await _head(session)
    (open_item,) = [
        item
        for item in await _findings_view(session)
        if item["finding_id"] == str(finding.finding_id)
    ]
    assert open_item["closure_basis"] == "open_unanswered"
    assert await session.receipt() == "unresolved_findings_remain"

    host.bash("toolu-green", failed=False)
    await _append_observed(session, host.new_envelopes())
    (retired,) = [
        item
        for item in await _findings_view(session)
        if item["finding_id"] == str(finding.finding_id)
    ]
    assert retired["closure_basis"] == "retired_by_passing_run"
    assert retired["resolved"] is True
    assert await session.receipt() != "unresolved_findings_remain"


async def _advice_finding(
    session: _Session, runtime: Any, host: _Host
) -> tuple[TaskRuntime, AdviceSnapshot, Finding]:
    """Run the real advice rule and the coordinator's materialization; the one finding."""

    task_runtime = await runtime.route(
        RouteCommand(
            session.started.session_id,
            session.started.writer_id,
            RouteAccess.WRITE,
            frozenset({RuntimeCapability.WRITE}),
        )
    )
    coordinator = ObservationCoordinator(
        runtime=cast(BundleRuntimePort, runtime),
        local=host.store,
        clock=session.app.clock,
        ids=session.app.ids,
        state_root=host.state,
    )
    envelopes = host.store.list_envelopes(host.workspace)
    snapshot = build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )
    assert snapshot is not None
    await coordinator._materialize_advice_findings(
        task_runtime, envelopes, snapshot, store=cast(TaskObservationPort, host.store)
    )
    findings = [
        record.payload
        for record in await _records(session)
        if record.schema.name == "finding_recorded"
        and type(record.payload) is Finding
        and record.payload.policy_id == "work-integrity"
    ]
    assert len(findings) == 1
    return cast(TaskRuntime, task_runtime), snapshot, findings[0]


def _failed_command_items(snapshot: AdviceSnapshot) -> list[str]:
    return [
        str(item.finding_id)
        for item in snapshot.ranked_items
        if item.rule_code == "failed_command_unresolved"
    ]


async def test_failed_install_then_planned_verification_pass_retires_it(tmp_path: Path) -> None:
    """Owner decision 2026-10-18 through the application: the plan requests the test command, an
    install fails, the coordinator records its finding, and the planned test command passes.
    Status (findings view, validated against the generated model) names the planned kind, the
    advice view drops the retired item, and the receipt is no longer blocked by it; the
    completion-claim duty to name the failure is unchanged (ADR-025)."""

    app, runtime, _ = workflow._build_app(seed_offset=1105)
    started = await app.start(start_request(1_104_600, title="Retire by a planned check"))
    session = _Session(app, runtime, started)
    host = _Host(tmp_path)
    # The service registers the installation key the hooks commit with (ready composition).
    register_command_identity_key(host.store.key_material())
    try:
        obligation = session.next("obl_")
        await session.publish(
            session.draft(
                "plan_published",
                {"plan_version": 1, "summary": "Tests", "obligation_refs": [obligation]},
            ),
            session.draft(
                "obligation_published",
                {
                    "obligation_id": obligation,
                    "description": "Make the suite pass.",
                    "evidence_expectation": "The planned test run passes.",
                    "status": "open",
                    "requested_items": [{"item_kind": "command", "value": _COMMAND}],
                },
            ),
        )
        host.bash("toolu-install", failed=True, command="pip install -e .")
        await _append_observed(session, host.new_envelopes())
        task_runtime, snapshot, finding = await _advice_finding(session, runtime, host)
        session.frontier = await _head(session)
        (open_item,) = [
            item
            for item in await _findings_view(session)
            if item["finding_id"] == str(finding.finding_id)
        ]
        assert open_item["closure_basis"] == "open_unanswered"
        assert await session.receipt() == "unresolved_findings_remain"
        kept = await status_module._without_retired_failed_commands(task_runtime, snapshot)
        assert _failed_command_items(kept) == [str(finding.finding_id)]

        host.bash("toolu-tests", failed=False)
        await _append_observed(session, host.new_envelopes())
        (retired,) = [
            item
            for item in await _findings_view(session)
            if item["finding_id"] == str(finding.finding_id)
        ]
        assert retired["closure_basis"] == "retired_by_planned_verification"
        assert retired["resolved"] is True
        assert await session.receipt() != "unresolved_findings_remain"
        # The advice rule still sees no pass of the install itself; the advice view reads the
        # ledger's retirement and drops the item, so both views agree about the finding.
        assert _failed_command_items(snapshot) == [str(finding.finding_id)]
        dropped = await status_module._without_retired_failed_commands(task_runtime, snapshot)
        assert _failed_command_items(dropped) == []
    finally:
        register_command_identity_key(None)
