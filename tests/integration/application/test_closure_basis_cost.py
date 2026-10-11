"""What the predicted receipt conclusion costs on a long ledger (tb4n3 RC-3, ADR-046).

Status now builds the receipt's own context (the deterministic case over every accepted record)
so it can print the conclusion the receipt will carry. ``closure_prepare`` reads about twenty status
pages at one frontier, and formal-crypto S ran past 1,400 events, so the derivation is memoized per
``(session, frontier)`` and reused only while the adapter's projection object is unchanged.

The tests never compare wall-clock time with a fixed threshold. They count the work (how many times
the deterministic case is built) and print the timings with ``-s`` for the record:

    uv run pytest tests/integration/application/test_closure_basis_cost.py -s
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, Final

import pytest

import yoetz.application.closure_basis as closure_basis
import yoetz.application.status as status_module
from builders.status_render_cost import CodexStatusLedger, build_codex_status_ledger
from yoetz.application.closure_basis import clear_closure_basis_memo
from yoetz.cli.closure import Selection, prepare_closure
from yoetz.protocol.models import StatusRequest, StatusResult, public_model_to_wire

pytestmark = pytest.mark.anyio

_REPEATS: Final = 20


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def _compact(ledger: CodexStatusLedger, seed: int) -> Any:
    body = ledger.status_body("compact", seed, limit="10")
    return await ledger.app.status(StatusRequest.model_validate(body))


def _count_cases(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = [0]
    original: Callable[..., Any] = closure_basis.build_deterministic_case

    def counted(*args: Any, **kwargs: Any) -> Any:
        calls[0] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(closure_basis, "build_deterministic_case", counted)
    return calls


async def test_one_frontier_builds_the_case_once_however_often_status_is_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = await build_codex_status_ledger()
    clear_closure_basis_memo()
    calls = _count_cases(monkeypatch)

    started = time.perf_counter()
    first = await _compact(ledger, 910_000)
    cold = time.perf_counter() - started
    assert first.closure_readiness.predicted_receipt is not None

    started = time.perf_counter()
    for index in range(_REPEATS):
        again = await _compact(ledger, 910_100 + index)
        assert (
            again.closure_readiness.predicted_receipt == first.closure_readiness.predicted_receipt
        )
    warm = (time.perf_counter() - started) / _REPEATS

    print(
        f"\n[closure basis cost] ledger head {ledger.head.sequence} events: "
        f"status cold {cold * 1000:.0f} ms, warm {warm * 1000:.0f} ms (mean of {_REPEATS})"
    )
    assert calls[0] == 1  # the deterministic case is built once for the frontier


async def test_the_prediction_costs_one_case_derivation_and_nothing_per_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = await build_codex_status_ledger()

    async def without(*_args: Any, **_kwargs: Any) -> None:
        return None

    clear_closure_basis_memo()
    with monkeypatch.context() as patch:
        patch.setattr(status_module, "_closure_basis_or_none", without)
        started = time.perf_counter()
        bare = await _compact(ledger, 911_000)
        baseline = time.perf_counter() - started
    assert bare.closure_readiness.predicted_receipt is None

    clear_closure_basis_memo()
    started = time.perf_counter()
    predicted = await _compact(ledger, 911_100)
    cold = time.perf_counter() - started
    started = time.perf_counter()
    await _compact(ledger, 911_200)
    warm = time.perf_counter() - started
    assert predicted.closure_readiness.predicted_receipt is not None

    print(
        f"\n[closure basis cost] status without the prediction {baseline * 1000:.0f} ms, "
        f"with it (cold) {cold * 1000:.0f} ms, with it (memo hit) {warm * 1000:.0f} ms; "
        f"derivation {max(cold - baseline, 0) * 1000:.0f} ms"
    )


async def test_closure_prepare_derives_the_basis_once_for_its_status_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = await build_codex_status_ledger()
    clear_closure_basis_memo()
    calls = _count_cases(monkeypatch)
    pages: list[str] = []

    async def status(request: StatusRequest) -> StatusResult:
        pages.append(request.view)
        seed = 912_000 + len(pages) * 10
        return await ledger.project_status(public_model_to_wire(request), seed)

    started = time.perf_counter()
    prepared = await prepare_closure(
        status, ledger.started.session_id, ledger.started.writer_id, Selection()
    )
    elapsed = time.perf_counter() - started
    assert prepared["closure_readiness"] is not None
    print(
        f"\n[closure basis cost] closure_prepare: {len(pages)} status pages, "
        f"{elapsed * 1000:.0f} ms, deterministic case built {calls[0]} time(s)"
    )
    assert calls[0] <= 1
