"""The service facade binds the check-time change only to the check's own connection (ADR-031)."""

from __future__ import annotations

import os
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Literal, cast

import pytest

import finishup.application.check as check_module
import finishup.application.service as service_module
from builders.ledger_adapters import FixedClock, MemoryObjects, append_command, memory_adapter
from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.adapters.memory.ledger import MemoryLedgerAdapter
from finishup.application.service import Application
from finishup.application.start import StartInternalResult
from finishup.ports.change_capture import (
    TASK_CHANGE_BASE_MEDIA_TYPE,
    CheckWorkspaceSource,
    current_check_workspace_source,
    decode_task_change_base,
)
from finishup.ports.control import RepositoryPrivacyContext, WorkspaceLocator
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.importer import ImporterPort
from finishup.ports.objects import ObjectKind, ObjectStorePort
from finishup.ports.runtime import BundleRuntimePort, RouteCommand, TaskRuntime
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import CheckRequest
from unit.application.test_service_facade import (
    _SESSION,  # pyright: ignore[reportPrivateUsage]
    _TASK,  # pyright: ignore[reportPrivateUsage]
    _WRITER,  # pyright: ignore[reportPrivateUsage]
    _application,  # pyright: ignore[reportPrivateUsage]
    _Catalog,  # pyright: ignore[reportPrivateUsage]
    _route,  # pyright: ignore[reportPrivateUsage]
)

_COMMITMENT = "hmac-sha256:" + "a" * 64


class _Port:
    def read_task_base(self, workspace: str) -> object:
        raise AssertionError(f"not used: {workspace}")

    def capture(self, workspace: str, base: object) -> object:
        raise AssertionError(f"not used: {workspace} {base}")


def _context(path: str | None) -> RepositoryPrivacyContext:
    return RepositoryPrivacyContext(
        _COMMITMENT,
        "git_common_root",
        None if path is None else WorkspaceLocator(path),
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("with_port", "path", "expected"),
    (
        (True, "/work/kea", CheckWorkspaceSource("/work/kea", _COMMITMENT)),
        (False, "/work/kea", None),
        (True, None, None),
    ),
)
async def test_check_binds_its_own_connection_workspace_only_for_its_duration(
    monkeypatch: pytest.MonkeyPatch,
    with_port: bool,
    path: str | None,
    expected: CheckWorkspaceSource | None,
) -> None:
    seen: list[CheckWorkspaceSource | None] = []

    async def execute_check(app: object, request: object, **kwargs: object) -> str:
        del app, request, kwargs
        seen.append(current_check_workspace_source())
        return "checked"

    monkeypatch.setattr(check_module, "execute_check", execute_check)
    app = _application(
        _Catalog(_route(repository_privacy_commitment=_COMMITMENT)),
        enforce_repository_identity=True,
    )
    if with_port:
        app = replace(app, change_capture=_Port())  # pyright: ignore[reportArgumentType]
    request = CheckRequest.model_construct(
        session_id=_SESSION, task_id=_TASK, writer_id=_WRITER, mode="deterministic_only"
    )

    result = await app.check(request, repository_privacy_context=_context(path))

    assert result == "checked"
    assert seen == [expected]
    assert current_check_workspace_source() is None


def test_repository_context_keeps_its_locator_out_of_equality_and_repr() -> None:
    first = _context("/work/private-repository-name")
    second = _context("/work/other")

    assert first == second
    assert "private-repository-name" not in repr(first)
    assert first.workspace_locator == WorkspaceLocator("/work/private-repository-name")


class _Router:
    def __init__(self, runtime: TaskRuntime) -> None:
        self.runtime = runtime
        self.routes: list[RouteCommand] = []

    async def route(self, command: RouteCommand) -> TaskRuntime:
        self.routes.append(command)
        return self.runtime

    async def release(self, runtime: TaskRuntime) -> None:
        assert runtime is self.runtime


def _start_result(
    outcome: Literal["attached", "created", "replayed", "delegated"], runtime: TaskRuntime
) -> StartInternalResult:
    # Only the fields the post-start hook reads; a full result needs frontier and view models.
    return cast(
        StartInternalResult,
        SimpleNamespace(
            outcome=outcome,
            session_id=runtime.session_id,
            writer_id=runtime.writer_id,
            request_id="req_00000000-0000-4000-8000-000000000031",
        ),
    )


def _runtime() -> tuple[TaskRuntime, MemoryLedgerAdapter]:
    command = append_command()
    adapter = memory_adapter(command)
    runtime = TaskRuntime(
        command.task_id,
        command.session_id,
        command.writer_id,
        frozenset({RuntimeCapability.WRITE}),
        adapter,
        cast(ObjectStorePort, getattr(adapter, "_objects")),
        cast(ImporterPort, object()),
        "0.1.0",
        "0.1.0",
        "0.1",
        "1.0.0",
        getattr(adapter, "_fence"),
    )
    return runtime, adapter


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("outcome", "recorded"),
    (("created", True), ("delegated", True), ("attached", False), ("replayed", False)),
)
async def test_only_a_creating_start_records_the_task_base(
    tmp_path: Path,
    outcome: Literal["attached", "created", "replayed", "delegated"],
    recorded: bool,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir(mode=0o700)
    environment = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "PATH": os.defpath}
    subprocess.run(("git", "init", "--quiet"), cwd=repository, check=True, env=environment)
    runtime, adapter = _runtime()
    router = _Router(runtime)
    app = replace(
        _application(_Catalog(_route())),
        runtime=cast(BundleRuntimePort, router),
        clock=FixedClock(),  # pyright: ignore[reportArgumentType]
        change_capture=GitChangeCaptureAdapter(),
    )
    record = getattr(Application, "_record_task_change_base")

    await record(app, _start_result(outcome, runtime), _context(os.fspath(repository)))

    base = await adapter.load_task_change_base()
    assert (base is not None) is recorded
    assert len(router.routes) == (1 if recorded else 0)
    if base is not None:
        assert base.metadata.kind is ObjectKind.CHANGE_CAPTURE
        assert base.metadata.media_type == TASK_CHANGE_BASE_MEDIA_TYPE
        objects = cast(MemoryObjects, getattr(adapter, "_objects"))
        data = b"".join([chunk async for chunk in objects.open_verified(base)])
        # An empty repository starts from the empty tree.
        assert decode_task_change_base(data).commit == "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


class _RefusingRouter:
    async def route(self, command: RouteCommand) -> TaskRuntime:
        del command
        raise PublicOperationError(PublicErrorCode.BUNDLE_BUSY, "busy", True)


@pytest.mark.anyio
async def test_a_base_that_cannot_be_recorded_never_fails_the_start(tmp_path: Path) -> None:
    runtime, adapter = _runtime()
    app = replace(
        _application(_Catalog(_route())),
        runtime=cast(BundleRuntimePort, _RefusingRouter()),
        clock=FixedClock(),  # pyright: ignore[reportArgumentType]
        change_capture=GitChangeCaptureAdapter(),
    )
    record = getattr(Application, "_record_task_change_base")

    await record(app, _start_result("created", runtime), _context(os.fspath(tmp_path)))

    assert await adapter.load_task_change_base() is None


@pytest.mark.anyio
@pytest.mark.parametrize("admitted", [True, False])
async def test_a_start_keeps_its_named_outside_input_only_where_the_scope_allows(
    tmp_path: Path, admitted: bool
) -> None:
    """#1118 unit 1: the creating start keeps a ``task_start`` copy before it returns; with no
    admitted root (or no review), it reads nothing and routes no runtime."""

    from finishup.adapters.task_input_read import snapshot_outside_inputs  # noqa: PLC0415
    from finishup.application.input_snapshot import (  # noqa: PLC0415
        InputSnapshotScope,
        load_input_snapshots,
    )

    shared = (tmp_path / "shared").resolve()
    shared.mkdir()
    (shared / "spec.md").write_text("ORIGINAL\n", encoding="utf-8")
    runtime, _adapter = _runtime()
    router = _Router(runtime)
    scopes: list[str] = []

    async def scope(context: RepositoryPrivacyContext, task_id: str) -> InputSnapshotScope | None:
        scopes.append(task_id)
        if not admitted:
            return None
        return InputSnapshotScope(
            (os.fspath(shared),), (os.fspath(tmp_path / "repo"),), snapshot_outside_inputs
        )

    app = replace(
        _application(_Catalog(_route())),
        runtime=cast(BundleRuntimePort, router),
        clock=FixedClock(),  # pyright: ignore[reportArgumentType]
        input_snapshot_scope=scope,
    )
    record = getattr(Application, "_record_input_snapshot")

    await record(
        app,
        runtime.task_id,
        runtime.session_id,
        runtime.writer_id,
        (os.fspath(shared / "spec.md"),),
        "task_start",
        _context(os.fspath(tmp_path / "repo")),
        None,
    )

    kept = await load_input_snapshots(runtime, None)
    assert scopes == [runtime.task_id]
    assert len(router.routes) == (1 if admitted else 0)
    assert [s.boundary for s in kept] == (["task_start"] if admitted else [])


def test_a_publish_batch_names_only_its_role_input_files_and_directories() -> None:
    declared = getattr(service_module, "_declared_input_paths")
    obligation = {
        "schema": {"name": "obligation_published", "version": "1.1.0"},
        "payload": {
            "obligation_id": "obl_00000000-0000-4000-8000-000000000001",
            "description": "Port the form.",
            "evidence_expectation": "A test run.",
            "status": "open",
            "requested_items": [
                {"item_kind": "file", "value": "/shared/spec.md", "role": "input"},
                {"item_kind": "directory", "value": "/shared/forms/", "role": "input"},
                {"item_kind": "file", "value": "/app/out.md", "role": "output"},
                {"item_kind": "command", "value": "pytest -q"},
            ],
        },
    }
    other = {"schema": {"name": "plan_published", "version": "1.0.0"}, "payload": {}}

    request = SimpleNamespace(event_drafts=[other, obligation])

    assert declared(request) == ("/shared/spec.md", "/shared/forms/")
