"""Issue #841: a Codex multi-agent v2 child binds to exactly one accepted child task.

Codex 0.153.4 with ``multi_agent_version=v2`` gives every thread of one delegation tree the root
``session_id``. A delegated child's own callbacks therefore arrive under the parent's session, and
its rollout is named by the child's thread, which is never a host session. Before #841 the child's
attach callback could not publish a child lane, the parent's provisional host annotation stayed
unbound, the child's command evidence landed on the parent lane, and ``observe reconcile`` of the
child's rollout failed ``mapping_missing``.

These rows drive the production service and encrypted task bundles with the exact IMP-015 v2
parent and child rollout records. The child's callback shape (root session, no host child alias,
``transcript_path`` naming its own rollout) is the shape the v2 header implies; it is not a
native capture, and nothing here certifies a Codex profile.
"""

from __future__ import annotations

import base64
import io
import json
import subprocess
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from builders.codex_rollout import encode_lines, function_call, function_call_output
from builders.multi_agent import MultiAgentService, multi_agent_service
from fixture_loader import build_fixture_loader
from yoetz.adapters.integrations.codex_lifecycle import load_mapping, scoped_child_session_id
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.application.publish_work import PublishWorkInternalResult
from yoetz.application.start import StartInternalResult
from yoetz.cli import observe as observe_cli
from yoetz.cli.hooks import bind_start_mapping_outcome, with_transcript_child_identity
from yoetz.cli.observe_hooks import handle_observe
from yoetz.domain.host_lineage import host_lineage_from_payload
from yoetz.domain.observation import (
    ObservationIngestRequest,
    observation_ingest_request_to_json,
    observation_ingest_result_from_json,
)
from yoetz.ports.control import RepositoryPrivacyContext
from yoetz.ports.ledger import CheckCommitResult
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.ids import IdKind, new_id
from yoetz.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    StartRequest,
    StatusLineagePageModel,
    StatusRequest,
)

pytestmark = pytest.mark.anyio

_REPOSITORY = RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")
_IMP_015 = "imports/codex/rollout-multi-agent-v2-0.153.4.case.json"
# The IMP-015 canary threads: the root/parent session and the one delegated child.
_PARENT_THREAD = "019f8b27-b98e-7061-bbb5-d0b897594de6"
_CHILD_THREAD = "019f8b27-b98e-7061-bbb5-d0b897594de7"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _identity() -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": new_id(IdKind.REQUEST),
        "actor": {"actor_id": "harness:codex-v2-child", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _imp_015(variant: str) -> bytes:
    case = cast(dict[str, object], build_fixture_loader().load_json(_IMP_015))
    variants = cast(dict[str, object], cast(dict[str, object], case["input"])["variants"])
    source = cast(dict[str, object], cast(dict[str, object], variants[variant])["source"])
    return base64.b64decode(cast(str, source["bytes_base64"]))


@dataclass
class _Scenario:
    service: MultiAgentService
    workspace: Path
    state: Path
    local: LocalObservationStore
    workspace_commitment: str
    parent: StartInternalResult
    parent_rollout: Path
    child_rollout: Path

    async def deliver(self) -> tuple[tuple[str, str], ...]:
        """Deliver every pending row through the public ingest route; return its lanes."""

        delivered: list[tuple[str, str]] = []
        for row in self.local.list_pending_outbox_rows(self.workspace_commitment):
            result = observation_ingest_result_from_json(
                await self.service.app.observation_ingest(
                    observation_ingest_request_to_json(
                        ObservationIngestRequest(
                            codex_session_id=row.codex_session_id,
                            envelope=row.envelope,
                        )
                    )
                )
            )
            assert result.disposition.value in {"accepted", "duplicate"}, result
            assert self.local.acknowledge_outbox_row(self.workspace_commitment, row)
            delivered.append((row.codex_session_id, row.envelope.event_kind))
        return tuple(delivered)

    def hook(self, payload: Mapping[str, object]) -> None:
        output = io.BytesIO()
        assert (
            handle_observe(
                event_name=None,
                stdin_bytes=json.dumps(payload).encode(),
                stdout=output,
                workspace=str(self.workspace),
                _state=self.state,
                skip_service=True,
            )
            == 0
        )

    async def status(self, task: StartInternalResult, view: str = "compact") -> object:
        return await self.service.app.status(
            StatusRequest.model_validate(
                {
                    **_identity(),
                    "session_id": task.session_id,
                    "writer_id": task.writer_id,
                    "view": view,
                    "limit": "10",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )


@asynccontextmanager
async def _scenario(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncGenerator[_Scenario]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    subprocess.run(["git", "init", "--quiet", str(workspace)], check=True, capture_output=True)
    workspace = workspace.resolve()
    async with multi_agent_service(tmp_path / "state") as service:
        monkeypatch.setenv("YOETZ_ISOLATED_ROOT", str(service.root))
        codex_home = service.root / "codex-home"
        sessions = codex_home / "sessions" / "2026" / "08" / "22"
        sessions.mkdir(parents=True)
        monkeypatch.setenv("CODEX_HOME", str(codex_home))
        # Hook and stream rows are stamped from the wall clock, and local admission measures
        # their age against it. Start the deterministic service clock at the same instant.
        behind = int((datetime.now(UTC) - service.clock.now_utc()).total_seconds())
        if behind > 0:
            service.clock.advance(seconds=behind)
        # Exact IMP-015 v2 records: the parent's spawn and the child's own header. The child's
        # own work follows its header, as it does in a real child rollout.
        parent_rollout = sessions / f"rollout-2026-08-22T12-00-00-{_PARENT_THREAD}.jsonl"
        parent_rollout.write_bytes(_imp_015("parent"))
        child_rollout = sessions / f"rollout-2026-08-22T12-00-01-{_CHILD_THREAD}.jsonl"
        child_rollout.write_bytes(
            _imp_015("child")
            + encode_lines(
                function_call(name="shell", call_id="child-shell", arguments='{"command":"ls"}'),
                function_call_output(call_id="child-shell", output="ok", exit_code=0),
            )
        )
        state = service.root / "state"
        parent = await service.app.start(
            StartRequest.model_validate(
                {
                    **_identity(),
                    "mode": "create",
                    "task_title": "v2 parent",
                    "workspace_ref": str(workspace),
                    "external_ref": f"codex-session:{_PARENT_THREAD}",
                    "requested_view": "compact",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        assert (
            bind_start_mapping_outcome(
                {
                    "session_id": _PARENT_THREAD,
                    "tool_name": "mcp__yoetz__start",
                    "tool_response": {"structuredContent": parent.as_wire()},
                },
                _state=state,
            )
            == "bound"
        )
        local = LocalObservationStore(_state=state)
        workspace_commitment = local.workspace_commitment(str(workspace))
        local.grant_consent(workspace_commitment)
        yield _Scenario(
            service,
            workspace,
            state,
            local,
            workspace_commitment,
            parent,
            parent_rollout,
            child_rollout,
        )


async def _delegate_and_attach(scenario: _Scenario) -> StartInternalResult:
    app = scenario.service.app
    delegated = await app.start(
        StartRequest.model_validate(
            {
                **_identity(),
                "mode": "delegate",
                "task_title": "v2 child",
                "session_id": scenario.parent.session_id,
                "requested_view": "compact",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert delegated.attach_handle is not None
    return await app.start(
        StartRequest.model_validate(
            {
                **_identity(),
                "mode": "attach",
                "task_title": "v2 child",
                "attach_handle": delegated.as_wire()["attach_handle"],
                "requested_view": "compact",
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )


async def _observe_parent_spawn(scenario: _Scenario) -> None:
    """The parent's own callback reconciles its rollout, whose spawn opens the annotation."""

    scenario.hook(
        {
            "hook_event_name": "Stop",
            "session_id": _PARENT_THREAD,
            "transcript_path": str(scenario.parent_rollout),
        }
    )
    lanes = {lane for lane, _kind in await scenario.deliver()}
    assert lanes == {_PARENT_THREAD}
    registry = scenario.service.app.host_lineage_registry
    assert registry is not None
    (annotation,) = await registry.list_provisional_annotations(scenario.parent.task_id)
    assert annotation.bound_child_task_id is None


def _child_attach_callback(
    attached: StartInternalResult, *, alias: bool, transcript: Path | None
) -> dict[str, object]:
    callback: dict[str, object] = {
        "hook_event_name": "PostToolUse",
        # v2 child callbacks carry the root session, never the child's own thread.
        "session_id": _PARENT_THREAD,
        "tool_use_id": "child-attach-call",
        "tool_name": "mcp__yoetz__start",
        "tool_response": {"structuredContent": attached.as_wire()},
    }
    if alias:
        callback["agent_id"] = _CHILD_THREAD
    if transcript is not None:
        callback["transcript_path"] = str(transcript)
    return callback


async def _publish(
    scenario: _Scenario, task: StartInternalResult, name: str, payload: Mapping[str, object]
) -> PublishWorkInternalResult:
    status = await scenario.status(task)
    head = getattr(status, "head_frontier")
    result = await scenario.service.app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": dict(head.as_wire().items()),
                "event_drafts": [
                    {
                        "event_id": new_id(IdKind.EVENT),
                        "schema": {"name": name, "version": "1.0.0"},
                        "occurred_at": "2026-09-05T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": dict(payload),
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, PublishWorkInternalResult)
    return result


async def _check(scenario: _Scenario, task: StartInternalResult) -> CheckCommitResult:
    status = await scenario.status(task)
    head = getattr(status, "head_frontier")
    result = await scenario.service.app.check(
        CheckRequest.model_validate(
            {
                **_identity(),
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": dict(head.as_wire().items()),
                "mode": "deterministic_only",
                "max_findings": "10",
                "policy_packs": ["work-integrity/0.3.0"],
            }
        ),
        repository_privacy_context=_REPOSITORY,
    )
    assert isinstance(result, CheckCommitResult)
    return result


@pytest.mark.parametrize(
    ("alias", "transcript"),
    [
        # The v2 shape: root session, no host child alias, the child's own transcript.
        (False, True),
        # A host alias and the transcript agree.
        (True, True),
        # A host alias alone still reaches the child's rollout by its thread filename.
        (True, False),
    ],
    ids=["transcript_only", "alias_and_transcript", "alias_only"],
)
async def test_v2_child_binds_one_accepted_child_and_reconciles_its_own_rollout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    alias: bool,
    transcript: bool,
) -> None:
    async with _scenario(tmp_path, monkeypatch) as scenario:
        app = scenario.service.app
        registry = app.host_lineage_registry
        assert registry is not None
        await _observe_parent_spawn(scenario)
        attached = await _delegate_and_attach(scenario)
        parent_mapping = load_mapping(_PARENT_THREAD, _state=scenario.state)
        assert (
            parent_mapping is not None and parent_mapping.yoetz_task_id == scenario.parent.task_id
        )

        callback = _child_attach_callback(
            attached, alias=alias, transcript=scenario.child_rollout if transcript else None
        )
        # ``yoetz hooks post-tool-use`` resolves the transcript identity before binding.
        bind_payload, conflict = with_transcript_child_identity(
            cast(Mapping[str, JsonValue], callback), event_name="PostToolUse"
        )
        assert conflict is None
        assert bind_start_mapping_outcome(bind_payload, _state=scenario.state) == "bound"
        child_lane = scoped_child_session_id(
            _PARENT_THREAD, host="codex", identity=_CHILD_THREAD, identity_kind="host"
        )
        child_mapping = load_mapping(child_lane, _state=scenario.state)
        assert child_mapping is not None
        assert (child_mapping.yoetz_task_id, child_mapping.yoetz_session_id) == (
            attached.task_id,
            attached.session_id,
        )
        # The shared root session keeps its parent route.
        assert load_mapping(_PARENT_THREAD, _state=scenario.state) == parent_mapping

        # The attach callback lands on the child lane and reconciles the child's own rollout,
        # whose v2 header is the child-observed delegation signal.
        scenario.hook(callback)
        delivered = await scenario.deliver()
        assert delivered, "the child attach produced no deliverable rows"
        assert {lane for lane, _kind in delivered} == {child_lane}
        # The child's own header arrives as its SubagentStart, on the child lane only.
        assert "SubagentStart" in {kind for _lane, kind in delivered}

        # Exactly one accepted child, bound to the one host observation; nothing provisional.
        assert await app.start_catalog.list_child_task_ids(scenario.parent.task_id) == (
            attached.task_id,
        )
        assert await registry.list_provisional_annotations(scenario.parent.task_id) == ()
        signal = host_lineage_from_payload("codex", "SubagentStart", {"subagent_id": _CHILD_THREAD})
        assert signal is not None
        annotation = await registry.find_host_lineage_observation(scenario.parent.task_id, signal)
        assert annotation is not None
        assert annotation.bound_child_task_id == attached.task_id
        lineage = await scenario.status(scenario.parent, "lineage")
        page = getattr(lineage, "page")
        assert isinstance(page, StatusLineagePageModel)
        assert page.annotations == ()
        (child_row,) = page.children
        assert (child_row.task_id, child_row.origin, child_row.acceptance) == (
            attached.task_id,
            "parent_minted",
            "accepted",
        )

        # The child's own command evidence stays on the child lane and in the child's ledger.
        child_before = await scenario.status(attached)
        for event_name in ("PreToolUse", "PostToolUse"):
            payload: dict[str, object] = {
                "hook_event_name": event_name,
                "session_id": _PARENT_THREAD,
                "tool_name": "shell",
                "tool_use_id": "child-shell-hook",
                "exit_status": 0,
            }
            if alias:
                payload["agent_id"] = _CHILD_THREAD
            if transcript:
                payload["transcript_path"] = str(scenario.child_rollout)
            scenario.hook(payload)
        assert {lane for lane, _kind in await scenario.deliver()} == {child_lane}
        parent_after = await scenario.status(scenario.parent)
        child_after = await scenario.status(attached)
        assert getattr(parent_after, "task_id") == scenario.parent.task_id
        assert getattr(parent_after, "result_frontier") == getattr(parent_after, "subject_frontier")
        assert int(getattr(child_after, "result_frontier").sequence) > int(
            getattr(child_before, "result_frontier").sequence
        )

        # The supported operator recovery is idempotent and resolves the same child lane.
        for _attempt in range(2):
            assert (
                observe_cli.reconcile_session_stream(
                    session_file=str(scenario.child_rollout),
                    workspace=str(scenario.workspace),
                    json_output=True,
                    _state=scenario.state,
                )
                == 0
            )
            emitted = json.loads(capsys.readouterr().out)
            assert emitted["mode"] == "recovery_child_lane"
            assert emitted["accepted"] == 0
            assert await scenario.deliver() == ()
        assert await registry.list_provisional_annotations(scenario.parent.task_id) == ()
        assert await app.start_catalog.list_child_task_ids(scenario.parent.task_id) == (
            attached.task_id,
        )

        # The parent consumes the child's outcome through its recorded rollup manifest.
        await _publish(scenario, attached, "work_closed", {})
        await _check(scenario, attached)
        sweep = app.observation_sweep
        if sweep is not None:
            await sweep()
        parent_check = await _check(scenario, scenario.parent)
        assert parent_check.children is not None
        (preview,) = parent_check.children.items
        assert (preview.child_task_id, preview.work_state) == (attached.task_id, "closed")
        receipt = await app.receipt(
            ReceiptRequest.model_validate(
                {
                    **_identity(),
                    "task_id": scenario.parent.task_id,
                    "session_id": scenario.parent.session_id,
                    "writer_id": scenario.parent.writer_id,
                    "expected_frontier": dict(parent_check.result_frontier.as_wire().items()),
                    "format": "json",
                    "include": "standard",
                    "redaction_profile": "default_local_export",
                }
            ),
            repository_privacy_context=_REPOSITORY,
        )
        document = cast(Mapping[str, object], receipt.document)
        children = cast(Mapping[str, object], document["children"])["children"]
        (receipt_child,) = cast(list[Mapping[str, object]], children)
        assert receipt_child["child_task_id"] == attached.task_id
        assert receipt_child["tested_manifest_ref"] is not None


async def test_v2_child_without_any_identity_stays_provisional_and_refuses_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """With neither a host alias nor its own transcript, nothing is inferred for the child."""

    async with _scenario(tmp_path, monkeypatch) as scenario:
        registry = scenario.service.app.host_lineage_registry
        assert registry is not None
        await _observe_parent_spawn(scenario)
        attached = await _delegate_and_attach(scenario)
        callback = _child_attach_callback(attached, alias=False, transcript=None)
        bind_payload, conflict = with_transcript_child_identity(
            cast(Mapping[str, JsonValue], callback), event_name="PostToolUse"
        )
        assert conflict is None and bind_payload == callback
        assert (
            bind_start_mapping_outcome(bind_payload, _state=scenario.state)
            == "start_bind_child_lane_unbound"
        )
        assert (
            observe_cli.reconcile_session_stream(
                session_file=str(scenario.child_rollout),
                workspace=str(scenario.workspace),
                json_output=True,
                _state=scenario.state,
            )
            == 20
        )
        assert "observation_reconcile_failed:child_route_missing" in capsys.readouterr().err
        # Workspace-wide stream state and the one pending annotation never stand in for a route.
        (annotation,) = await registry.list_provisional_annotations(scenario.parent.task_id)
        assert annotation.bound_child_task_id is None
        assert scenario.local.list_pending_outbox_rows(scenario.workspace_commitment) == ()
