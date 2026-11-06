"""The terminal interface's status and receipt views name a claim-bound connection's producer.

Through ``FinishUpRuntime`` only (ADR-017): a claim-bound connection's views end with the fixed
workspace-evidence line and the producing service; a local connection's lines are unchanged
(ADR-051).
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from tests.unit.protocol.test_models_and_schemas import _receipt_result_wire
from tests.unit.tui.test_workflow_contract import _SESSION, _Client

from finishup.cli.render import render_human_status
from finishup.domain.receipts import CLIENT_ATTESTED_WORKSPACE_LINE
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.models import (
    ReceiptRequestModel,
    ReceiptResultModel,
    ReceiptSuccessModel,
    StatusSuccessModel,
)
from finishup.tui.runtime import FinishUpRuntime

pytestmark = pytest.mark.anyio
_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000084"
_REACHED = f"This client reached FinishUP service {_SERVICE_ID} (transport: connector)."


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _BoundClient(_Client):
    def __init__(self, binding: str) -> None:
        super().__init__()
        self.workspace_binding = binding
        self.service_instance_id = _SERVICE_ID
        self.transport = "connector"

    async def receipt(self, request: ReceiptRequestModel) -> object:
        self.requests.append(request)
        return ReceiptResultModel.model_validate(_receipt_result_wire())


def _document_lines() -> tuple[str, ...]:
    document = ReceiptSuccessModel.model_validate(_receipt_result_wire()).document
    return tuple(canonical_encode(document).decode("utf-8").splitlines())


def _status_of(result: object) -> StatusSuccessModel:
    success = getattr(result, "root", None)
    assert type(success) is StatusSuccessModel
    return success


async def _runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, binding: str
) -> tuple[FinishUpRuntime, _BoundClient]:
    client = _BoundClient(binding)

    @asynccontextmanager
    async def connect(_runtime: FinishUpRuntime) -> AsyncGenerator[_BoundClient]:
        yield client

    monkeypatch.setattr(FinishUpRuntime, "_client", connect)
    runtime = FinishUpRuntime(cwd=tmp_path)
    await runtime.open_task(_SESSION)
    return runtime, client


async def test_a_claim_bound_task_view_names_its_producer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime, client = await _runtime(monkeypatch, tmp_path, "client_claim")
    rendered = await runtime.task_status(_SESSION, "lineage")
    success = _status_of(await client.status(client.requests[-1]))  # pyright: ignore[reportArgumentType]
    assert rendered.lines == (
        *render_human_status(success).splitlines(),
        CLIENT_ATTESTED_WORKSPACE_LINE,
        _REACHED,
    )


async def test_a_local_task_view_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime, client = await _runtime(monkeypatch, tmp_path, "local_path")
    rendered = await runtime.task_status(_SESSION, "lineage")
    success = _status_of(await client.status(client.requests[-1]))  # pyright: ignore[reportArgumentType]
    assert rendered.lines == tuple(render_human_status(success).splitlines())


async def test_a_claim_bound_receipt_names_its_producer_after_the_document(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime, _client = await _runtime(monkeypatch, tmp_path, "client_claim")
    summary = await runtime.build_receipt(_SESSION, "json")
    assert summary.rendered_lines == (*_document_lines(), CLIENT_ATTESTED_WORKSPACE_LINE, _REACHED)


async def test_a_local_receipt_is_the_document_alone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime, _client = await _runtime(monkeypatch, tmp_path, "local_path")
    summary = await runtime.build_receipt(_SESSION, "json")
    assert summary.rendered_lines == _document_lines()
