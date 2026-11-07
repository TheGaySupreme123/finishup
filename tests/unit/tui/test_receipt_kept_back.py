"""The terminal interface's receipt says how many files listed mode kept back (ADR-051).

Maintainer decision 2026-11-07 ("add the count now"), through ``FinishUpRuntime`` only (ADR-017):
a JSON receipt shows the receipt document, whose live ``outside_reads_not_listed`` gap carries
the count line in its ``detail`` and the bounded ``kept_back``; a text or markdown receipt shows
the service's own text, which carries the same line. Counts only, never which file.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from tests.unit.protocol.test_receipt_kept_back_counts import _COUNT_LINE, kept_back_receipt_result
from tests.unit.tui.test_workflow_contract import _SESSION, _Client

from finishup.protocol.models import ReceiptRequestModel, ReceiptResultModel
from finishup.tui.runtime import FinishUpRuntime

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _KeptBackClient(_Client):
    async def receipt(self, request: ReceiptRequestModel) -> object:
        self.requests.append(request)
        return ReceiptResultModel.model_validate(kept_back_receipt_result(request.format.value))


async def _runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FinishUpRuntime:
    client = _KeptBackClient()

    @asynccontextmanager
    async def connect(_runtime: FinishUpRuntime) -> AsyncGenerator[_KeptBackClient]:
        yield client

    monkeypatch.setattr(FinishUpRuntime, "_client", connect)
    runtime = FinishUpRuntime(cwd=tmp_path)
    await runtime.open_task(_SESSION)
    return runtime


@pytest.mark.parametrize("output_format", ["json", "markdown", "text"])
async def test_the_receipt_view_says_how_many_in_every_format(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, output_format: str
) -> None:
    runtime = await _runtime(monkeypatch, tmp_path)
    summary = await runtime.build_receipt(_SESSION, output_format)
    shown = "\n".join(summary.rendered_lines)
    assert _COUNT_LINE in shown
    # Then the owner's two ways out, with their full arguments and where to run them.
    assert "`finishup server folders add NAME FOLDER`" in shown
    assert "`finishup server folders mode NAME local`" in shown
    if output_format == "json":
        # The document itself: the bounded counts beside their closed code, and no file.
        assert '"kept_back":{"declared_tests":1,"task_inputs":3}' in shown
    assert summary.limitations == ("outside_reads_not_listed",)
