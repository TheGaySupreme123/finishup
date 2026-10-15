"""Real service/socket start-admission composition for same-workspace reattachment.

The isolated service fixture keeps this regression at the public MCP boundary: the test exercises
the daemon, Unix socket, SQLite start catalog, bundle runtime, lifecycle ledger, and response
replay together.  It does not provide native host acceptance evidence.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal, cast

import pytest

import finishup.mcp.server as bridge
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.service import Application
from finishup.cli import observe_hooks
from finishup.ports.control import ControlClientKind, WorkspaceLocator
from finishup.ports.start_catalog import StartIdentityInput
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import StartRequest, StartSuccessModel
from finishup.service.client import ServiceClient, connect_service
from integration.service.test_start_contention_composition import (
    _body,  # pyright: ignore[reportPrivateUsage]
    _logical_result,  # pyright: ignore[reportPrivateUsage]
    _structured,  # pyright: ignore[reportPrivateUsage]
    ready,  # noqa: F401  # pyright: ignore[reportUnusedImport]
    runtime_directory,  # noqa: F401  # pyright: ignore[reportUnusedImport]
)

pytestmark = pytest.mark.anyio


class _HookServiceClient:
    """Adapt the hook's object protocol to the typed real control client."""

    def __init__(self, client: ServiceClient) -> None:
        self.client = client

    async def start(self, request: object, *, deadline_ms: int | None = None) -> object:
        assert isinstance(request, StartRequest)
        return await self.client.start(request, deadline_ms=deadline_ms)

    async def close(self) -> None:
        await self.client.close()


def _admission_body(
    seed: int,
    *,
    workspace_ref: str,
    external_ref: str,
    mode: str = "create_or_attach",
    session_id: str | None = None,
) -> dict[str, JsonValue]:
    body = dict(_body(seed, session_id))
    body["mode"] = mode
    body["workspace_ref"] = workspace_ref
    body["external_ref"] = external_ref
    return body


async def test_same_workspace_admission_reattaches_exact_pair_and_replays(
    ready: tuple[Application, bridge.BridgeRuntime],  # noqa: F811
) -> None:
    """A new pair creates a sibling while its exact pair remains an attach selector.

    This is the smallest service-level reproduction of the 0.3 admission change.  A workspace
    may have several independently named tasks, but a repeated exact pair must never create a
    second task and replaying its request id must return the committed attachment unchanged.
    """

    _application, transport = ready
    workspace = "workspace-810"
    first = _structured(
        await bridge.dispatch_start(
            _admission_body(
                8100,
                workspace_ref=workspace,
                external_ref="external-A",
                mode="create",
            ),
            transport,
        )
    )
    assert first["ok"] is True
    assert first["outcome"] == "created"

    drifted_request = _admission_body(
        8101,
        workspace_ref=workspace,
        external_ref="external-B",
    )
    sibling = _structured(await bridge.dispatch_start(drifted_request, transport))
    assert sibling["ok"] is True
    assert sibling["outcome"] == "created"
    assert sibling["task_id"] != first["task_id"]

    exact_request = _admission_body(
        8102,
        workspace_ref=workspace,
        external_ref="external-A",
    )
    attached = _structured(await bridge.dispatch_start(exact_request, transport))
    assert attached["ok"] is True
    assert attached["outcome"] == "attached"
    assert attached["task_id"] == first["task_id"]
    assert attached["session_id"] != first["session_id"]

    replayed = _structured(await bridge.dispatch_start(exact_request, transport))
    assert _logical_result(replayed) == _logical_result(attached)


async def test_start_admission_rejects_cross_workspace_selector(
    ready: tuple[Application, bridge.BridgeRuntime],  # noqa: F811
) -> None:
    """A selector never crosses its workspace boundary or creates a hidden third task."""

    application, transport = ready
    first = _structured(
        await bridge.dispatch_start(
            _admission_body(
                8110,
                workspace_ref="workspace-811-A",
                external_ref="external-A",
                mode="create",
            ),
            transport,
        )
    )
    unrelated = _structured(
        await bridge.dispatch_start(
            _admission_body(
                8111,
                workspace_ref="workspace-811-B",
                external_ref="external-B",
            ),
            transport,
        )
    )
    assert unrelated["ok"] is True
    assert unrelated["outcome"] == "created"
    identity = await application.start_catalog.commit_identity(
        StartIdentityInput(
            "Synthetic start contention",
            "workspace-811-B",
            "external-B",
        )
    )
    workspace_tasks_before = await application.start_catalog.list_workspace_task_ids(
        cast(str, identity.workspace_ref_commitment)
    )
    assert workspace_tasks_before == (cast(str, unrelated["task_id"]),)
    request = _admission_body(
        8112,
        workspace_ref="workspace-811-B",
        external_ref="external-C",
        mode="attach",
        session_id=cast(str, first["session_id"]),
    )
    result = _structured(await bridge.dispatch_start(request, transport))
    error = cast(dict[str, object], result["error"])
    assert error["code"] == "SESSION_CONFLICT"
    assert (
        await application.start_catalog.list_workspace_task_ids(
            cast(str, identity.workspace_ref_commitment)
        )
        == workspace_tasks_before
    )


async def test_exact_same_workspace_selector_recovers_beside_independent_task(
    ready: tuple[Application, bridge.BridgeRuntime],  # noqa: F811
) -> None:
    """An exact session selects the task; another root is not selector ambiguity."""

    application, transport = ready
    workspace = "workspace-812"
    first = _structured(
        await bridge.dispatch_start(
            _admission_body(
                8120,
                workspace_ref=workspace,
                external_ref="external-A",
                mode="create",
            ),
            transport,
        )
    )
    sibling = _structured(
        await bridge.dispatch_start(
            _admission_body(
                8121,
                workspace_ref=workspace,
                external_ref="external-B",
            ),
            transport,
        )
    )
    assert first["ok"] is True
    assert sibling["ok"] is True
    assert first["task_id"] != sibling["task_id"]

    identity = await application.start_catalog.commit_identity(
        StartIdentityInput("Synthetic start contention", workspace, "external-A")
    )
    workspace_tasks_before = await application.start_catalog.list_workspace_task_ids(
        cast(str, identity.workspace_ref_commitment)
    )
    assert len(workspace_tasks_before) == 2
    assert set(workspace_tasks_before) == {
        cast(str, first["task_id"]),
        cast(str, sibling["task_id"]),
    }

    third_pair = _admission_body(
        8122,
        workspace_ref=workspace,
        external_ref="external-C",
        mode="attach",
        session_id=cast(str, first["session_id"]),
    )
    sibling_route = await application.start_catalog.resolve_route(cast(str, sibling["session_id"]))
    recovered = _structured(await bridge.dispatch_start(third_pair, transport))
    assert recovered["ok"] is True
    assert recovered["outcome"] == "attached"
    assert recovered["task_id"] == first["task_id"]
    assert recovered["session_id"] != first["session_id"]
    replayed = _structured(await bridge.dispatch_start(third_pair, transport))
    assert _logical_result(replayed) == _logical_result(recovered)
    assert (
        await application.start_catalog.resolve_route(cast(str, sibling["session_id"]))
        == sibling_route
    )
    assert (
        await application.start_catalog.list_workspace_task_ids(
            cast(str, identity.workspace_ref_commitment)
        )
        == workspace_tasks_before
    )

    session_only = _structured(
        await bridge.dispatch_start(_body(8123, cast(str, first["session_id"])), transport)
    )
    assert session_only["ok"] is True
    assert session_only["outcome"] == "attached"
    assert session_only["task_id"] == first["task_id"]
    assert session_only["session_id"] != first["session_id"]


@pytest.mark.parametrize("harness", ["codex", "claude", "cursor"])
async def test_ended_host_predecessor_automatically_recovers_with_unrelated_workspace_task(
    ready: tuple[Application, bridge.BridgeRuntime],  # noqa: F811
    tmp_path: Path,
    harness: Literal["codex", "claude", "cursor"],
) -> None:
    """Exercise the native shared recovery selector against the real service/catalog.

    Only one ended host mapping identifies a predecessor, even though the service
    has two independent root tasks. No operator-supplied recovery selector or
    scripted success replaces the hook's persisted mapping selection.
    """

    application, _transport = ready
    workspace_directory = tmp_path / "workspace"
    workspace_directory.mkdir(mode=0o700)
    workspace = str(workspace_directory)

    async def bound_connector(kind: ControlClientKind) -> _HookServiceClient:
        return _HookServiceClient(
            await connect_service(kind, workspace_locator=WorkspaceLocator(workspace))
        )

    state = tmp_path / "hook-state"
    store = LocalObservationStore(_state=state)
    commitment = store.workspace_commitment(workspace)
    store.grant_consent(commitment)
    prefix = "" if harness == "codex" else f"{harness}:"
    predecessor = f"{prefix}predecessor-814"
    successor = f"{prefix}successor-814"
    first = await observe_hooks._try_auto_start(  # pyright: ignore[reportPrivateUsage]
        predecessor,
        _state=state,
        harness_id=harness,
        workspace_locator=workspace,
        connect=bound_connector,
    )
    assert first.mapping is not None, first.reason
    predecessor_commitment = store.bind_codex_session(commitment, predecessor)
    store.note_session_end(commitment, predecessor_commitment)
    sibling_client = await connect_service(
        ControlClientKind.CLI, workspace_locator=WorkspaceLocator(workspace)
    )
    try:
        sibling_result = await sibling_client.start(
            StartRequest.model_validate(
                _admission_body(8140, workspace_ref=workspace, external_ref="independent-work")
            )
        )
    finally:
        await sibling_client.close()
    sibling = sibling_result.root
    assert isinstance(sibling, StartSuccessModel)
    assert sibling.task_id != first.mapping.yoetz_task_id
    sibling_route = await application.start_catalog.resolve_route(sibling.session_id)
    store.bind_codex_session(commitment, successor)

    recovered = await observe_hooks._try_workspace_auto_start(  # pyright: ignore[reportPrivateUsage]
        successor,
        store=store,
        workspace_commitment=commitment,
        workspace_locator=workspace,
        harness_id=harness,
        _state=state,
        connect=bound_connector,
    )

    assert recovered.mapping is not None, recovered.reason
    assert recovered.recovered
    assert recovered.mapping.yoetz_task_id == first.mapping.yoetz_task_id
    assert recovered.mapping.yoetz_session_id != first.mapping.yoetz_session_id
    assert await application.start_catalog.resolve_route(sibling.session_id) == sibling_route
