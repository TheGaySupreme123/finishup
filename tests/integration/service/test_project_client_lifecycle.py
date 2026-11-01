"""Production project lifecycle through the authenticated service client."""

from __future__ import annotations

import asyncio
import io
import os
import subprocess
from collections.abc import Buffer, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from builders.multi_agent import INSTANCE_ID, multi_agent_service
from finishup.adapters.control.unix_socket import AuthenticatedUnixStream
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.adapters.repository_identity import resolve_repository_privacy_context
from finishup.application.coordination import CoordinationRuntime
from finishup.application.start import StartInternalResult
from finishup.cli.hooks import bind_start_mapping_outcome
from finishup.cli.observe_hooks import handle_claude_observe, handle_cursor_observe
from finishup.domain.observation import (
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationSource,
    observation_ingest_request_to_json,
    observation_ingest_result_from_json,
)
from finishup.domain.values import JsonObject
from finishup.ports.control import (
    ControlClientKind,
    ProjectionRenderMode,
    RepositoryPrivacyContext,
    WorkspaceLocator,
)
from finishup.ports.keys import MacKeyPurpose
from finishup.ports.ledger import CheckCommitResult
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.ids import IdKind, new_id
from finishup.protocol.models import CheckRequest, StartRequest, StatusRequest
from finishup.service.client import (
    _connected_client,  # pyright: ignore[reportPrivateUsage]
    prepare_project_request,
)
from finishup.service.control_protocol import client_handshake
from finishup.service.daemon import ServiceComposition, ServiceDaemon
from finishup.service.elevated_bootstrap import (
    load_pending,
    record_project_coordination_authorization,
)
from finishup.service.lifecycle import ServiceLifecycle

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class _Clock:
    instant: datetime = datetime(2026, 9, 6, tzinfo=UTC)

    def now_utc(self) -> datetime:
        return self.instant

    def monotonic_seconds(self) -> float:
        return self.instant.timestamp()


class _Generations:
    def advance(self, instance_id: str) -> int:
        assert instance_id == INSTANCE_ID
        return 1


class _Listener:
    def __init__(self) -> None:
        self._closed = asyncio.Event()

    async def accept(self) -> object:
        await self._closed.wait()
        raise RuntimeError("closed")

    async def aclose(self) -> None:
        self._closed.set()


class _Monitor:
    class _Capability:
        active = False

    capability = _Capability()

    async def start(self, callback: object) -> None:
        del callback

    async def close(self) -> None:
        return None


class _Stream:
    def __init__(self, peer_identity: object) -> None:
        self.peer_identity = peer_identity
        self.other: _Stream | None = None
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._buffer = bytearray()

    async def receive(self, max_bytes: int) -> bytes:
        while not self._buffer:
            self._buffer.extend(await self._queue.get())
        chunk = bytes(self._buffer[:max_bytes])
        del self._buffer[:max_bytes]
        return chunk

    async def send_all(self, data: Buffer) -> None:
        assert self.other is not None
        await self.other._queue.put(bytes(data))

    async def aclose(self) -> None:
        return None


def _pair() -> tuple[_Stream, _Stream]:
    client = _Stream(object())
    server = _Stream(object())
    client.other = server
    server.other = client
    return client, server


def _start_request(workspace: Path, index: int) -> StartRequest:
    return StartRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": new_id(IdKind.REQUEST),
            "mode": "create",
            "task_title": f"Project client task {index}",
            "workspace_ref": str(workspace),
            "external_ref": f"project-client-{index}",
            "actor": {"actor_id": "harness:project-client", "actor_type": "harness"},
            "client": {
                "kind": "cooperative_agent",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
            "requested_view": "compact",
        }
    )


def _wire_rows(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, (list, tuple)):
        raise AssertionError("wire_rows_invalid")
    rows: list[dict[str, object]] = []
    for item in cast(list[object] | tuple[object, ...], value):
        if not isinstance(item, dict):
            raise AssertionError("wire_row_invalid")
        rows.append(cast(dict[str, object], item))
    return tuple(rows)


def _frontier(value: object) -> dict[str, object]:
    as_wire = getattr(value, "as_wire", None)
    if not callable(as_wire):
        raise AssertionError("frontier_not_serializable")
    return dict(cast(dict[str, object], as_wire()))


def _project_request(values: Mapping[str, object], *, request_id: str | None = None) -> JsonObject:
    """Build one project body with a retained identity for exact retries."""

    return prepare_project_request(JsonObject(values), request_id=request_id).body


async def _check_current(
    service: object,
    task: StartInternalResult,
    repository: RepositoryPrivacyContext,
) -> CheckCommitResult:
    app = getattr(service, "app")
    status = await app.status(
        StatusRequest.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": new_id(IdKind.REQUEST),
                "actor": {"actor_id": "harness:project-client", "actor_type": "harness"},
                "client": {
                    "kind": "cooperative_agent",
                    "version": "0.3.0",
                    "integration": "cooperative_mcp",
                },
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "view": "compact",
                "limit": "1",
            }
        ),
        repository_privacy_context=repository,
    )
    result = await app.check(
        CheckRequest.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": new_id(IdKind.REQUEST),
                "actor": {"actor_id": "harness:project-client", "actor_type": "harness"},
                "client": {
                    "kind": "cooperative_agent",
                    "version": "0.3.0",
                    "integration": "cooperative_mcp",
                },
                "session_id": task.session_id,
                "writer_id": task.writer_id,
                "expected_frontier": _frontier(status.head_frontier),
                "mode": "deterministic_only",
                "max_findings": "10",
            }
        ),
        repository_privacy_context=repository,
    )
    assert isinstance(result, CheckCommitResult)
    return result


async def _approve_pending(state: Path) -> str:
    pending = load_pending(_state=state)
    assert pending is not None
    binding = pending.coordination_binding
    assert binding is not None
    audit_record_id = binding["audit_record_id"]
    assert isinstance(audit_record_id, str)
    record_project_coordination_authorization(pending, _state=state)
    return audit_record_id


async def test_project_lifecycle_uses_real_ready_client_and_exact_grant_retries(
    tmp_path: Path,
) -> None:
    workspace_a = (tmp_path / "workspace-a").resolve()
    workspace_b = (tmp_path / "workspace-b").resolve()
    workspace_a.mkdir()
    git_environment = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}
    for arguments in (
        ("init",),
        ("commit", "--allow-empty", "-m", "initial"),
        ("worktree", "add", "--detach", str(workspace_b), "HEAD"),
    ):
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=FinishUP Test",
                "-c",
                "user.email=test@finishup.invalid",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
                "-C",
                str(workspace_a),
                *arguments,
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=git_environment,
        )
    async with multi_agent_service(tmp_path / "state") as service:
        lookup = service.vault.installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP)
        repository = await resolve_repository_privacy_context(
            WorkspaceLocator(str(workspace_a)), lookup
        )
        repository_b = await resolve_repository_privacy_context(
            WorkspaceLocator(str(workspace_b)), lookup
        )
        assert repository.commitment == repository_b.commitment
        local = LocalObservationStore(_state=service.root / "state")
        assert local.workspace_commitment(str(workspace_a)) != local.workspace_commitment(
            str(workspace_b)
        )
        local.grant_consent(local.workspace_commitment(str(workspace_a)))
        local.grant_consent(local.workspace_commitment(str(workspace_b)))
        started: list[StartInternalResult] = []
        for index, (workspace, repository_context) in enumerate(
            ((workspace_a, repository), (workspace_b, repository_b))
        ):
            started.append(
                await service.app.start(
                    _start_request(workspace, index),
                    repository_privacy_context=repository_context,
                )
            )
        first, second = started
        assert first.task_id is not None and second.task_id is not None
        daemon_clock = _Clock()
        lifecycle = ServiceLifecycle(
            daemon_clock,
            generation_store=_Generations(),
            process_start_identity_commitment="sha256:" + "e" * 64,
            instance_id=INSTANCE_ID,
            singleton_lock_path=tmp_path / "daemon.lock",
        )
        daemon = ServiceDaemon(
            _composition=ServiceComposition(
                lifecycle=lifecycle,
                control_listener=_Listener(),  # pyright: ignore[reportArgumentType]
                secret_ingress_listener=None,
                human_control_listener=None,
                human_control_service=None,
                session_monitor=_Monitor(),  # pyright: ignore[reportArgumentType]
                vault=service.vault,  # pyright: ignore[reportArgumentType]
                application=cast(Any, service.app),
            )
        )
        await daemon.start()
        client_stream, server_stream = _pair()
        server_task = asyncio.create_task(daemon._serve_control_connection(server_stream))  # pyright: ignore[reportPrivateUsage]
        server_task_b: asyncio.Task[object] | None = None
        client = None
        client_b = None
        try:
            from finishup.service.control_protocol import client_handshake

            session = await client_handshake(
                client_stream,
                ControlClientKind.CLI,
                "0.3.0",
                workspace_locator=WorkspaceLocator(str(workspace_a)),
                projection_render_mode=ProjectionRenderMode.HUMAN_READABLE,
                output_is_controlling_tty=True,
            )
            client = _connected_client(
                cast(AuthenticatedUnixStream, client_stream), session, ControlClientKind.CLI
            )
            client_stream_b, server_stream_b = _pair()
            server_task_b = asyncio.create_task(daemon._serve_control_connection(server_stream_b))  # pyright: ignore[reportPrivateUsage]
            session_b = await client_handshake(
                client_stream_b,
                ControlClientKind.CLI,
                "0.3.0",
                workspace_locator=WorkspaceLocator(str(workspace_b)),
                projection_render_mode=ProjectionRenderMode.MACHINE_READABLE,
                output_is_controlling_tty=False,
            )
            client_b = _connected_client(
                cast(AuthenticatedUnixStream, client_stream_b), session_b, ControlClientKind.CLI
            )

            checked = await client.check(
                CheckRequest.model_validate(
                    {
                        "protocol_version": "0.1",
                        "schema_version": "1.0.0",
                        "request_id": new_id(IdKind.REQUEST),
                        "actor": {
                            "actor_id": "harness:project-client",
                            "actor_type": "harness",
                        },
                        "client": {
                            "kind": "cooperative_agent",
                            "version": "0.3.0",
                            "integration": "cooperative_mcp",
                        },
                        "session_id": first.session_id,
                        "writer_id": first.writer_id,
                        "expected_frontier": first.frontier.model_dump(mode="json"),
                        "mode": "deterministic_only",
                        "policy_packs": ["coordination/0.1.0"],
                    }
                )
            )
            assert checked.root.ok is True
            assert checked.root.state == "complete"
            assert checked.root.versions.policy_packs == ("coordination/0.1.0",)

            created = await client.project(
                _project_request(
                    {
                        "schema_version": "1.0.0",
                        "operation": "create",
                        "title": "Client lifecycle project",
                        "description": "Encrypted project description",
                        "owner_task_id": first.task_id,
                    }
                )
            )
            project_id = created["project_id"]
            assert isinstance(project_id, str)

            first_grant = _project_request(
                {
                    "schema_version": "1.0.0",
                    "operation": "grant",
                    "project_id": project_id,
                    "membership_generation": 1,
                }
            )
            with pytest.raises(Exception):
                await client.project(first_grant)
            await _approve_pending(service.root / "state")
            granted = await client.project(first_grant)
            assert granted["state"] == "active"
            first_provenance = await service.app.start_catalog.task_source_provenance(first.task_id)
            assert first_provenance is not None
            link_body = _project_request(
                {
                    "schema_version": "1.0.0",
                    "operation": "link",
                    "project_id": project_id,
                    "member_kind": "task",
                    "member_commitment_or_id": first.task_id,
                    "source_workspace_commitment": first_provenance.workspace_ref_commitment,
                }
            )
            linked = await client.project(link_body)
            assert linked["member_commitment_or_id"] == first.task_id

            second_grant = _project_request(
                {
                    "schema_version": "1.0.0",
                    "operation": "grant",
                    "project_id": project_id,
                    "membership_generation": 2,
                }
            )
            with pytest.raises(Exception):
                await client.project(second_grant)
            await _approve_pending(service.root / "state")
            granted = await client.project(second_grant)
            assert granted["state"] == "active"

            status_body: dict[str, object] = {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": new_id(IdKind.REQUEST),
                "actor": {"actor_id": "harness:project-client", "actor_type": "harness"},
                "client": {
                    "kind": "yoetz_cli",
                    "version": "0.3.0",
                    "integration": "local_cli",
                },
                "session_id": first.session_id,
                "writer_id": first.writer_id,
                "view": "project",
                "limit": "100",
                "project_id": project_id,
            }
            status_body["request_id"] = new_id(IdKind.REQUEST)
            status = await client.status(StatusRequest.model_validate(status_body))
            status_wire = status.model_dump(mode="json", by_alias=True, exclude_none=False)
            assert status_wire["view"] == "project"
            assert "memberships" not in status_wire
            page = status_wire["page"]
            assert isinstance(page, dict)
            assert page["project_id"] == project_id

            amended = await client.project(
                _project_request(
                    {
                        "schema_version": "1.0.0",
                        "operation": "amend",
                        "project_id": project_id,
                        "owner_task_id": first.task_id,
                        "title": "Amended client project",
                    }
                )
            )
            assert amended["project_id"] == project_id

            second_provenance = await service.app.start_catalog.task_source_provenance(
                second.task_id
            )
            assert second_provenance is not None
            second_link = _project_request(
                {
                    "schema_version": "1.0.0",
                    "operation": "link",
                    "project_id": project_id,
                    "member_kind": "task",
                    "member_commitment_or_id": second.task_id,
                    "source_workspace_commitment": second_provenance.workspace_ref_commitment,
                }
            )
            linked_second = await client.project(second_link)
            assert linked_second["member_commitment_or_id"] == second.task_id

            third_grant = _project_request(
                {
                    "schema_version": "1.0.0",
                    "operation": "grant",
                    "project_id": project_id,
                    "membership_generation": 3,
                }
            )
            with pytest.raises(Exception):
                await client.project(third_grant)
            await _approve_pending(service.root / "state")
            granted = await client.project(third_grant)
            assert granted["state"] == "active"

            project_application = service.app.project_application
            assert project_application is not None
            coordination_runtime = cast(
                CoordinationRuntime, getattr(project_application, "coordination_runtime")
            )
            first_input = await coordination_runtime.inputs.input_for(
                first.task_id, project_id, resources=("src/shared.py",)
            )
            second_input = await coordination_runtime.inputs.input_for(
                second.task_id, project_id, resources=("src/shared.py",)
            )
            assert first_input is not None and second_input is not None
            delivered = await coordination_runtime.sweep(
                project_id_value=project_id,
                inputs={first.task_id: first_input, second.task_id: second_input},
            )
            assert {item.target_task_id for item in delivered} == {first.task_id, second.task_id}

            checked_with_advice = await _check_current(service, first, repository)
            project_notes = tuple(
                note for note in checked_with_advice.advisory_notes if note.project_id == project_id
            )
            assert len(project_notes) == 1
            assert all(
                note.kind == "live_member_present"
                and note.task_ids == (second.task_id,)
                and note.count == 1
                for note in project_notes
            )
            # These real worktrees also share an independently admitted implicit project.
            # Revoking the general project's grant must not revoke that separate authority.
            independent_notes = tuple(
                note for note in checked_with_advice.advisory_notes if note.project_id != project_id
            )
            assert len(independent_notes) == 1
            assert independent_notes[0].kind == "live_member_present"
            assert independent_notes[0].task_ids == (second.task_id,)

            advice_body = {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": new_id(IdKind.REQUEST),
                "actor": {"actor_id": "harness:project-client", "actor_type": "harness"},
                "client": {
                    "kind": "yoetz_cli",
                    "version": "0.3.0",
                    "integration": "local_cli",
                },
                "session_id": first.session_id,
                "writer_id": first.writer_id,
                "view": "advice",
                "limit": "64",
            }
            advice_first = await client.status(StatusRequest.model_validate(advice_body))
            advice_first_wire = advice_first.model_dump(
                mode="json", by_alias=True, exclude_none=False
            )
            advice_first_page = advice_first_wire["page"]
            assert isinstance(advice_first_page, dict)
            advice_first_items = _wire_rows(cast(object, advice_first_page["items"]))
            assert len(advice_first_items) == 1
            # ADR-009 round 3: a human-readable render on a controlling terminal is a
            # presentation fact an agent's pseudo-terminal reproduces, so it no longer selects
            # the owner's view. Both clients get the agent-facing projection.
            assert advice_first_items[0]["coordination_resource_paths"] == {
                "omitted": True,
                "category": "repository_excerpt",
                "reason": "local_disclosure_not_authorized",
            }
            advice_second_body = {
                **advice_body,
                "request_id": new_id(IdKind.REQUEST),
                "session_id": second.session_id,
                "writer_id": second.writer_id,
            }
            advice_second = await client_b.status(StatusRequest.model_validate(advice_second_body))
            advice_second_wire = advice_second.model_dump(
                mode="json", by_alias=True, exclude_none=False
            )
            advice_second_page = advice_second_wire["page"]
            assert isinstance(advice_second_page, dict)
            advice_second_items = _wire_rows(cast(object, advice_second_page["items"]))
            assert len(advice_second_items) == 1
            assert advice_second_items[0]["coordination_resource_paths"] == {
                "omitted": True,
                "category": "repository_excerpt",
                "reason": "local_disclosure_not_authorized",
            }
            assert advice_first_items[0]["finding_id"] == advice_second_items[0]["finding_id"]

            denied_status_body = {
                **status_body,
                "request_id": new_id(IdKind.REQUEST),
                "session_id": second.session_id,
                "writer_id": second.writer_id,
            }
            status = await client_b.status(StatusRequest.model_validate(denied_status_body))
            status_wire = status.model_dump(mode="json", by_alias=True, exclude_none=False)
            page = status_wire["page"]
            assert isinstance(page, dict)
            members = _wire_rows(cast(object, page["members"]))
            assert {item["task_id"] for item in members} == {first.task_id, second.task_id}
            detections = _wire_rows(cast(object, page["detections"]))
            assert len(detections) == 1
            assert detections[0]["resource_paths"] == {
                "omitted": True,
                "category": "repository_excerpt",
                "reason": "local_disclosure_not_authorized",
            }

            unlinked = await client.project(
                _project_request(
                    {
                        "schema_version": "1.0.0",
                        "operation": "unlink",
                        "project_id": project_id,
                        "member_kind": "task",
                        "member_commitment_or_id": second.task_id,
                        "expected_generation": 3,
                    }
                )
            )
            assert unlinked["member_commitment_or_id"] == second.task_id

            fourth_grant = _project_request(
                {
                    "schema_version": "1.0.0",
                    "operation": "grant",
                    "project_id": project_id,
                    "membership_generation": 4,
                }
            )
            with pytest.raises(Exception):
                await client.project(fourth_grant)
            await _approve_pending(service.root / "state")
            granted = await client.project(fourth_grant)
            assert granted["state"] == "active"
            revoke_body = _project_request(
                {
                    "schema_version": "1.0.0",
                    "operation": "revoke",
                    "project_id": project_id,
                    "membership_generation": 4,
                }
            )
            revoked = await client.project(revoke_body)
            assert revoked["state"] == "revoked"
            assert revoked["membership_generation"] == "4"
            assert (
                await project_application.coordination_advice_for(first.task_id, project=project_id)
                == ()
            )
            assert await coordination_runtime.sweep(project_id_value=project_id) == ()
            checked_after_revoke = await _check_current(service, first, repository)
            assert checked_after_revoke.advisory_notes == independent_notes

            opt_out = await client.project(
                _project_request(
                    {
                        "schema_version": "1.0.0",
                        "operation": "opt_out",
                        "repository_commitment": repository.commitment,
                    }
                )
            )
            assert opt_out["auto_grouping"] is False
            opt_in = await client.project(
                _project_request(
                    {
                        "schema_version": "1.0.0",
                        "operation": "opt_in",
                        "repository_commitment": repository.commitment,
                    }
                )
            )
            assert opt_in["auto_grouping"] is True

            dissolved = await client.project(
                _project_request(
                    {
                        "schema_version": "1.0.0",
                        "operation": "dissolve",
                        "project_id": project_id,
                        "expected_generation": 5,
                    }
                )
            )
            assert dissolved["project_id"] == project_id
            assert dissolved["dissolved_at"] is not None
        finally:
            if client is not None:
                await client.close()
            if client_b is not None:
                await client_b.close()
            server_task.cancel()
            await asyncio.gather(server_task, return_exceptions=True)
            if server_task_b is not None:
                server_task_b.cancel()
                await asyncio.gather(server_task_b, return_exceptions=True)
            await daemon.close()


async def test_ready_service_client_admits_claude_and_cursor_observation_wire(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Current host observation frames reach one real READY task through the client."""

    workspace = (tmp_path / "observation-workspace").resolve()
    workspace.mkdir()
    git_environment = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=FinishUP Test",
            "-c",
            "user.email=test@finishup.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-C",
            str(workspace),
            "init",
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=git_environment,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=FinishUP Test",
            "-c",
            "user.email=test@finishup.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-C",
            str(workspace),
            "commit",
            "--allow-empty",
            "-m",
            "initial",
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=git_environment,
    )

    async with multi_agent_service(tmp_path / "state") as service:
        # READY composition stores its synthetic installation under ``service.root`` while
        # lifecycle mapping resolution follows the isolated-root contract.
        monkeypatch.setenv("FINISHUP_ISOLATED_ROOT", str(service.root))
        lookup = service.vault.installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP)
        repository = await resolve_repository_privacy_context(
            WorkspaceLocator(str(workspace)), lookup
        )
        local = LocalObservationStore(_state=service.root / "state")
        workspace_commitment = local.workspace_commitment(str(workspace))
        local.grant_consent(workspace_commitment)
        task = await service.app.start(
            _start_request(workspace, 0),
            repository_privacy_context=repository,
        )
        lifecycle_state = service.root / "state"
        claude_session = "claude:ready-observation"
        cursor_session = "cursor:ready-observation"
        assert (
            bind_start_mapping_outcome(
                {
                    "session_id": claude_session,
                    "tool_name": "mcp__finishup__start",
                    "tool_response": {"structuredContent": task.as_wire()},
                },
                _state=lifecycle_state,
                host="claude",
            )
            == "bound"
        )
        assert (
            bind_start_mapping_outcome(
                {
                    "session_id": cursor_session,
                    "tool_name": "mcp__finishup__start",
                    "tool_response": {"structuredContent": task.as_wire()},
                },
                _state=lifecycle_state,
                host="cursor",
            )
            == "bound"
        )

        daemon_clock = _Clock()
        lifecycle = ServiceLifecycle(
            daemon_clock,
            generation_store=_Generations(),
            process_start_identity_commitment="sha256:" + "e" * 64,
            instance_id=INSTANCE_ID,
            singleton_lock_path=tmp_path / "observation-daemon.lock",
        )
        daemon = ServiceDaemon(
            _composition=ServiceComposition(
                lifecycle=lifecycle,
                control_listener=_Listener(),  # pyright: ignore[reportArgumentType]
                secret_ingress_listener=None,
                human_control_listener=None,
                human_control_service=None,
                session_monitor=_Monitor(),  # pyright: ignore[reportArgumentType]
                vault=service.vault,  # pyright: ignore[reportArgumentType]
                application=cast(Any, service.app),
            )
        )
        await daemon.start()
        # This test drives the two newly queued rows through the authenticated client itself.
        # The daemon's independent READY maintenance loop may otherwise ingest one between the
        # hook and this client's call, turning a deterministic wire assertion into a timing-based
        # ACCEPTED versus DUPLICATE race.  Maintenance delivery has its own lifecycle coverage;
        # keep this client-boundary case focused on the exact request/result pair.
        await daemon._cancel_ready_maintenance()  # pyright: ignore[reportPrivateUsage]
        client_stream, server_stream = _pair()
        server_task = asyncio.create_task(daemon._serve_control_connection(server_stream))  # pyright: ignore[reportPrivateUsage]
        client = None
        try:
            session = await client_handshake(
                client_stream,
                ControlClientKind.CLI,
                "0.3.0",
                workspace_locator=WorkspaceLocator(str(workspace)),
                projection_render_mode=ProjectionRenderMode.MACHINE_READABLE,
                output_is_controlling_tty=False,
            )
            client = _connected_client(
                cast(AuthenticatedUnixStream, client_stream), session, ControlClientKind.CLI
            )

            assert (
                handle_claude_observe(
                    event_name="PostToolUse",
                    stdin_bytes=canonical_encode(
                        {
                            "hook_event_name": "PostToolUse",
                            "session_id": "ready-observation",
                            "claude_code_version": "2.1.241",
                            "tool_name": "mcp__plugin_finishup_finishup__check",
                            "tool_use_id": "claude-observation-call",
                        }
                    ),
                    stdout=io.BytesIO(),
                    workspace=str(workspace),
                    _state=lifecycle_state,
                    skip_service=True,
                )
                == 0
            )
            assert (
                handle_cursor_observe(
                    event_name="afterMCPExecution",
                    stdin_bytes=canonical_encode(
                        {
                            "hook_event_name": "afterMCPExecution",
                            "conversation_id": "ready-observation",
                            "cursor_version": "3.17.8",
                            "generation_id": "cursor-generation-1",
                            "tool_name": "mcp__finishup__respond",
                            "tool_call_id": "cursor-observation-call",
                        }
                    ),
                    stdout=io.BytesIO(),
                    workspace=str(workspace),
                    _state=lifecycle_state,
                    skip_service=True,
                )
                == 0
            )

            rows = local.list_pending_outbox_rows(workspace_commitment)
            assert {row.envelope.source for row in rows} == {
                ObservationSource.CLAUDE_HOOK,
                ObservationSource.CURSOR_HOOK,
            }
            assert len(rows) == 2
            by_source = {row.envelope.source: row for row in rows}
            claude_envelope = by_source[ObservationSource.CLAUDE_HOOK].envelope
            cursor_envelope = by_source[ObservationSource.CURSOR_HOOK].envelope
            assert claude_envelope.structural_payload["pairing_mode"] == "post_only"
            assert claude_envelope.structural_payload["correlation_kind"] == "tool_call_id"
            assert cursor_envelope.structural_payload["pairing_mode"] == "post_only"
            assert cursor_envelope.structural_payload["correlation_kind"] == "generation_id"
            assert cursor_envelope.structural_payload["correlation_id"] == "cursor-generation-1"

            for row in rows:
                raw = await client.observation_ingest(
                    observation_ingest_request_to_json(
                        ObservationIngestRequest(
                            codex_session_id=row.codex_session_id,
                            envelope=row.envelope,
                        )
                    ),
                    deadline_ms=3_000,
                )
                result = observation_ingest_result_from_json(raw)
                assert result.disposition is ObservationIngestDisposition.ACCEPTED
                assert result.advanced_cursor == row.envelope.cursor
                assert local.acknowledge_outbox_row(workspace_commitment, row)

            status_request_id = new_id(IdKind.REQUEST)
            observation_status = await client.observation_status(
                JsonObject(
                    {
                        "schema_version": "1.0.0",
                        "request_id": status_request_id,
                        "query": {"workspace_commitment": workspace_commitment},
                    }
                ),
                deadline_ms=3_000,
            )
            assert observation_status["schema_version"] == "1.0.0"
            assert observation_status["request_id"] == status_request_id
            observation_status_body = cast(JsonObject, observation_status["status"])
            assert observation_status_body["source_coverage"] == {
                "claude_hook": True,
                "codex_hook": False,
                "codex_session_stream": False,
                "cursor_hook": True,
            }
            assert observation_status_body["last_observation_receipt_time"] is not None

            pause_request_id = new_id(IdKind.REQUEST)
            paused = await client.observation_pause(
                JsonObject(
                    {
                        "schema_version": "1.0.0",
                        "request_id": pause_request_id,
                        "command": {"workspace_commitment": workspace_commitment},
                    }
                ),
                deadline_ms=3_000,
            )
            assert paused["schema_version"] == "1.0.0"
            assert paused["request_id"] == pause_request_id
            paused_body = cast(JsonObject, paused["status"])
            assert paused_body["lifecycle"] == "stopped"
            resume_request_id = new_id(IdKind.REQUEST)
            resumed = await client.observation_resume(
                JsonObject(
                    {
                        "schema_version": "1.0.0",
                        "request_id": resume_request_id,
                        "command": {"workspace_commitment": workspace_commitment},
                    }
                ),
                deadline_ms=3_000,
            )
            assert resumed["schema_version"] == "1.0.0"
            assert resumed["request_id"] == resume_request_id
            resumed_body = cast(JsonObject, resumed["status"])
            assert resumed_body["lifecycle"] in {"active", "degraded"}
            revoke_request_id = new_id(IdKind.REQUEST)
            revoked = await client.observation_revoke(
                JsonObject(
                    {
                        "schema_version": "1.0.0",
                        "request_id": revoke_request_id,
                        "command": {
                            "workspace_commitment": workspace_commitment,
                            "retain_evidence": True,
                        },
                    }
                ),
                deadline_ms=3_000,
            )
            assert revoked["schema_version"] == "1.0.0"
            assert revoked["request_id"] == revoke_request_id
            revoked_body = cast(JsonObject, revoked["status"])
            assert revoked_body["lifecycle"] == "stopped"

            status = await client.status(
                StatusRequest.model_validate(
                    {
                        "protocol_version": "0.1",
                        "schema_version": "1.0.0",
                        "request_id": new_id(IdKind.REQUEST),
                        "actor": {"actor_id": "harness:ready-observation", "actor_type": "harness"},
                        "client": {
                            "kind": "cooperative_agent",
                            "version": "0.3.0",
                            "integration": "cooperative_mcp",
                        },
                        "session_id": task.session_id,
                        "writer_id": task.writer_id,
                        "view": "compact",
                        "limit": "10",
                    }
                )
            )
            assert status.root.ok is True
            assert int(status.root.result_frontier.sequence) > int(task.frontier.sequence)
        finally:
            if client is not None:
                await client.close()
            server_task.cancel()
            await asyncio.gather(server_task, return_exceptions=True)
            await daemon.close()
