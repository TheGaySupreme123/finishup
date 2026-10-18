"""A failed command, then its passing rerun, through the real coordinator to status and receipt.

#1104 round 1 (the design's ``test_failed_command_then_pass_then_receipt_is_not_blocked``). The
Codex, Claude Code and Cursor hook handlers record a failure and a later passing rerun of the
same command into a real local observation store. Every stored envelope is materialized and
appended as a hook observation, and the real ``ObservationCoordinator`` runs the real advice rule
over the stored envelopes (``build_observation_advice_snapshot``, as ``_run_advice`` does) and
records its own ``failed_command_unresolved`` finding (``_materialize_advice_findings``). Status (the
findings view, validated against the generated ``status-result`` model) and the receipt then read
the finding as retired by the passing run, not blocking.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import apsw
import pytest

import integration.application.test_respond_status_receipt as workflow
from builders.ledger_adapters import MemoryObjects
from builders.start_application import start_request
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.observation import SqliteObservationStore
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
from finishup.cli.render import render_human_status
from finishup.domain.events import AcceptedEvent, ResultRecordedPayload, media_type_for
from finishup.domain.findings import Finding
from finishup.domain.observation import AdviceSnapshot, ObservationEnvelope, ObservationLifecycle
from finishup.domain.values import Frontier, timestamp_from_datetime
from finishup.kernel.task_facts import register_command_identity_key
from finishup.mcp.summaries import summary_for_status
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
from finishup.protocol.models import StatusRequest, StatusSuccessModel
from integration.application.test_closure_readiness_checklist import _Session, public_status
from integration.observation.test_failure_supersession_hosts import _host, _run_on

pytestmark = pytest.mark.anyio

_COMMAND = "pytest -q tests/test_retire_1104.py"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Host:
    """One host's normalized hook payloads writing into an isolated local store."""

    def __init__(self, root: Path, host_name: str = "claude") -> None:
        self.root = root
        self.host_name = host_name
        self.emit, _ = _host(root, host_name)
        self.state = root / "state"
        self.store = LocalObservationStore(_state=self.state)
        self.workspace = self.store.workspace_commitment(str(root.resolve()))
        self.store.grant_consent(self.workspace)
        self.appended: set[str] = set()

    def bash(self, call: str, *, failed: bool, command: str = _COMMAND) -> None:
        _run_on(self.host_name, self.emit, call, command, int(failed))

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


async def _assert_unanswered_status(session: _Session, count: int) -> None:
    status = await session.status()
    public = public_status(status).root
    assert type(public) is StatusSuccessModel
    assert public.closure_readiness.unanswered_finding_count == str(count)
    assert ("findings_unanswered" in public.closure_readiness.blocking_conditions) == bool(count)
    assert f"Unanswered findings: {count}" in render_human_status(public)
    assert ("findings_unanswered" in summary_for_status(status.as_json())) == bool(count)


async def _mirror_advice(session: _Session, task_runtime: TaskRuntime, host: _Host) -> None:
    """Use the production build/materialize/persist/mirror path, with private SQL."""

    path = host.root / "advice.sqlite"
    fresh = not path.exists()
    db = apsw.Connection(str(path))
    try:
        if fresh:
            initialize_bundle(db, {"task_id": task_runtime.task_id, "owner_generation": "1"})
        store = SqliteObservationStore(db)
        store.grant_consent(host.workspace, timestamp_from_datetime(session.app.clock.now_utc()))
        for envelope in host.store.list_envelopes(host.workspace):
            store.bind_session(host.workspace, envelope.session_commitment)
            await store.ingest(envelope)
        coordinator = ObservationCoordinator(
            runtime=cast(BundleRuntimePort, session.runtime),
            local=host.store,
            clock=session.app.clock,
            ids=session.app.ids,
            state_root=host.state,
        )
        await coordinator._run_advice(host.workspace, task_runtime, store)
        assert store.load_advice_snapshot(host.workspace) is not None
    finally:
        db.close()


def _assert_hook_failure(host: _Host, session: _Session, expected: bool) -> None:
    delivery = host.store.peek_advice_for_delivery(
        host.workspace, yoetz_session_id=session.started.session_id, allow_standing=False
    )
    assert bool(delivery and "resolve_failed_command" in delivery.text) == expected


@pytest.mark.parametrize("host_name", ["claude", "cursor", "codex"])
async def test_failed_command_then_pass_then_receipt_is_not_blocked(
    tmp_path: Path, host_name: str
) -> None:
    app, runtime, _ = workflow._build_app(seed_offset=1104)
    started = await app.start(start_request(1_104_500, title="Retire a fixed failure"))
    session = _Session(app, runtime, started)
    host = _Host(tmp_path, host_name)

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
    await _mirror_advice(session, task_runtime, host)
    _assert_hook_failure(host, session, True)

    host.bash("toolu-green", failed=False)
    await _append_observed(session, host.new_envelopes())
    (retired,) = [
        item
        for item in await _findings_view(session)
        if item["finding_id"] == str(finding.finding_id)
    ]
    assert retired["closure_basis"] == "retired_by_passing_run"
    assert retired["resolved"] is True
    await _assert_unanswered_status(session, 0)
    assert await session.receipt() != "unresolved_findings_remain"
    await _mirror_advice(session, task_runtime, host)
    _assert_hook_failure(host, session, False)

    # The retained observation still contains the pass, but the ledger has lost its proof.
    # Rebuilding the mirror must restore the failed-command item from the retained candidate.
    passing = next(
        record
        for record in await _records(session)
        if type(record.payload) is ResultRecordedPayload
        and record.payload.outcome.value == "success"
    )
    await workflow._append_local_redaction(
        app,
        runtime,
        started,
        seed=1_104_950,
        expected_frontier=int(session.frontier.sequence),
        target=str(passing.event_id),
    )
    session.frontier = await _head(session)
    await _assert_unanswered_status(session, 1)
    assert await session.receipt() == "unresolved_findings_remain"
    await _mirror_advice(session, task_runtime, host)
    _assert_hook_failure(host, session, True)


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


@pytest.mark.parametrize("host_name", ["claude", "cursor", "codex"])
@pytest.mark.parametrize("reversal", ["waive", "redact"])
async def test_failed_install_then_planned_verification_pass_retires_it(
    tmp_path: Path, host_name: str, reversal: str
) -> None:
    """Owner decision 2026-10-18 through the application: the plan requests the test command, an
    install fails, the coordinator records its finding, and the planned test command passes.
    Status (findings view, validated against the generated model) names the planned kind, the
    advice view drops the retired item, and the receipt is no longer blocked by it; the
    completion-claim duty to name the failure is unchanged (ADR-025)."""

    app, runtime, _ = workflow._build_app(seed_offset=1105)
    started = await app.start(start_request(1_104_600, title="Retire by a planned check"))
    session = _Session(app, runtime, started)
    host = _Host(tmp_path, host_name)
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
        await _mirror_advice(session, task_runtime, host)
        _assert_hook_failure(host, session, True)

        host.bash("toolu-tests", failed=False)
        await _append_observed(session, host.new_envelopes())
        (retired,) = [
            item
            for item in await _findings_view(session)
            if item["finding_id"] == str(finding.finding_id)
        ]
        assert retired["closure_basis"] == "retired_by_planned_verification"
        assert retired["resolved"] is True
        await _assert_unanswered_status(session, 0)
        assert await session.receipt() != "unresolved_findings_remain"
        # The advice rule still sees no pass of the install itself; the advice view reads the
        # ledger's retirement and drops the item, so both views agree about the finding.
        assert _failed_command_items(snapshot) == [str(finding.finding_id)]
        dropped = await status_module._without_retired_failed_commands(task_runtime, snapshot)
        assert _failed_command_items(dropped) == []
        await _mirror_advice(session, task_runtime, host)
        _assert_hook_failure(host, session, False)

        # Reverse state uses the same ledger projection: a waiver or unreadable proof restores
        # the unanswered work and the actual hook-local selection on the next advice build.
        session.frontier = await _head(session)
        if reversal == "waive":
            await session.publish(
                session.draft(
                    "plan_revised",
                    {
                        "plan_version": 2,
                        "supersedes_plan_version": 1,
                        "reason": "The planned check is out of scope.",
                        "summary": "Waive the check.",
                        "obligation_changes": [
                            {
                                "obligation_id": obligation,
                                "change": "waived",
                                "reason": "Out of scope.",
                            }
                        ],
                    },
                )
            )
        else:
            passing = next(
                record
                for record in await _records(session)
                if type(record.payload) is ResultRecordedPayload
                and record.payload.outcome.value == "success"
            )
            await workflow._append_local_redaction(
                app,
                runtime,
                started,
                seed=1_104_900,
                expected_frontier=int(session.frontier.sequence),
                target=str(passing.event_id),
            )
            session.frontier = await _head(session)
        await _assert_unanswered_status(session, 1)
        (reopened,) = [
            item
            for item in await _findings_view(session)
            if item["finding_id"] == str(finding.finding_id)
        ]
        assert reopened["resolved"] is False
        assert await session.receipt() == "unresolved_findings_remain"
        await _mirror_advice(session, task_runtime, host)
        _assert_hook_failure(host, session, True)
    finally:
        register_command_identity_key(None)
