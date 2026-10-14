"""Lineage status preserves the difference between identity and recorded verification."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, call

import pytest

from finishup.application.status import (
    Application,
    _lineage_readiness_gaps,  # pyright: ignore[reportPrivateUsage]
)
from finishup.application.status_faults import StatusFault, StatusFaultStage, classify_status_fault
from finishup.application.task_views import lineage_status_page
from finishup.domain.coordination import LineageAcceptance, LineageOrigin, SessionHealth, WorkState
from finishup.domain.values import Frontier, Timestamp
from finishup.ports.host_lineage import HostLineageAnnotation, HostLineageRegistryPort
from finishup.ports.runtime import TaskRuntime
from finishup.ports.start_catalog import SessionState, StartCatalogPort, TaskLineage
from finishup.protocol.errors import PublicErrorCode

pytestmark = pytest.mark.anyio
_PARENT = "tsk_53000000-0000-4000-8000-000000000001"
_CHILD = "tsk_53000000-0000-4000-8000-000000000002"
_SESSION = "ses_53000000-0000-4000-8000-000000000001"
_SESSION_COMMITMENT = "hmac-sha256:" + ("c" * 64)
_DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def _no_records(*_args: object, **_kwargs: object) -> AsyncIterator[object]:
    for record in ():
        yield record


@pytest.mark.parametrize(
    ("acceptance", "state", "blockers"),
    [
        (LineageAcceptance.ACCEPTED, "unavailable", ("lineage_manifest_not_recorded",)),
        (LineageAcceptance.PENDING, "annotation", ()),
        (LineageAcceptance.REJECTED, "annotation", ()),
    ],
)
async def test_catalog_child_without_a_manifest_is_never_verified(
    acceptance: LineageAcceptance, state: str, blockers: tuple[str, ...]
) -> None:
    parent = TaskLineage(_PARENT, None, 0, _DIGEST, None, None, WorkState.OPEN)
    child = TaskLineage(
        _CHILD, _PARENT, 1, _DIGEST, LineageOrigin.SELF_REGISTERED, acceptance, WorkState.CLOSED
    )
    catalog = AsyncMock(spec=StartCatalogPort)
    catalog.task_lineage.side_effect = [parent, child]
    catalog.list_child_task_ids.return_value = (_CHILD,)
    catalog.task_session_states.return_value = (
        SessionState(_CHILD, _SESSION, SessionHealth.ENDED, datetime(2026, 9, 5, tzinfo=UTC)),
    )
    runtime = cast(
        TaskRuntime,
        SimpleNamespace(
            task_id=_PARENT,
            session_id=_SESSION,
            ledger=SimpleNamespace(load_events=_no_records),
        ),
    )

    page = await lineage_status_page(
        cast(StartCatalogPort, catalog), runtime, Frontier(0, "genesis")
    )

    assert page.parent_task_id is None
    (item,) = page.children
    assert item.task_id == _CHILD
    assert item.origin.value == "self_registered"
    assert item.rollup_state.value == state
    assert item.blocking_conditions == blockers
    catalog.task_lineage.side_effect = [parent, child]
    assert await _lineage_readiness_gaps(
        cast(Application, SimpleNamespace(start_catalog=catalog)),
        runtime,
        Frontier(0, "genesis"),
        "req_53000000-0000-4000-8000-000000000001",
    ) == (blockers, False)
    assert item.self_verified_finding_count is None


@pytest.mark.parametrize("count", [1, 101, 200])
async def test_lineage_status_reads_every_provisional_host_annotation(count: int) -> None:
    parent = TaskLineage(_PARENT, None, 0, _DIGEST, None, None, WorkState.OPEN)
    catalog = AsyncMock(spec=StartCatalogPort)
    catalog.task_lineage.return_value = parent
    catalog.list_child_task_ids.return_value = ()
    runtime = cast(
        TaskRuntime,
        SimpleNamespace(
            task_id=_PARENT,
            session_id=_SESSION,
            ledger=SimpleNamespace(load_events=_no_records),
        ),
    )
    commitment = "hmac-sha256:" + ("b" * 64)
    annotation = HostLineageAnnotation(
        parent_task_id=_PARENT,
        host_profile="codex",
        correlation_id=commitment,
        subagent_id=commitment,
        parent_tool_call_id=commitment,
        parent_conversation_id=None,
        conversation_id=None,
        origin="host_observed",
        acceptance="pending",
        observed_phases=("start",),
        source_mask=1,
        last_session_commitment=_SESSION_COMMITMENT,
        first_observed_at=Timestamp("2026-09-05T00:00:00.000Z"),
        last_observed_at=Timestamp("2026-09-05T00:00:00.000Z"),
    )
    annotations = tuple(
        replace(annotation, correlation_id=f"hmac-sha256:{index:064x}") for index in range(count)
    )
    batches = [annotations[index : index + 100] for index in range(0, count, 100)]
    if count % 100 == 0:
        batches.append(())
    registry = SimpleNamespace(list_provisional_annotations=AsyncMock(side_effect=batches))

    page = await lineage_status_page(
        cast(StartCatalogPort, catalog),
        runtime,
        Frontier(0, "genesis"),
        host_lineage_registry=cast(HostLineageRegistryPort, registry),
    )

    registry.list_provisional_annotations.assert_has_awaits(
        [
            call(
                _PARENT,
                limit=100,
                correlation_id=None,
                after_correlation_id=None if index == 0 else annotations[index - 1].correlation_id,
            )
            for index in range(0, count + (1 if count % 100 == 0 else 0), 100)
        ]
    )
    assert tuple(item.correlation_id for item in page.annotations) == tuple(
        item.correlation_id for item in annotations
    )
    assert page.annotations[0].origin == "host_observed"
    assert page.annotations[0].acceptance == "pending"

    # A registry cannot expand the exact selector to a different observed child. The view tags
    # the invalid stored rows; the status boundary classifies them with a joinable diagnostic.
    registry.list_provisional_annotations = AsyncMock(return_value=(annotation,))
    with pytest.raises(StatusFault) as exc_info:
        await lineage_status_page(
            cast(StartCatalogPort, catalog),
            runtime,
            Frontier(0, "genesis"),
            host_lineage_registry=cast(HostLineageRegistryPort, registry),
            correlation_id="hmac-sha256:" + "d" * 64,
        )
    assert exc_info.value.stage is StatusFaultStage.REPLAY
    classified = classify_status_fault(exc_info.value, view="lineage", request_id=None)
    assert classified.code is PublicErrorCode.STORAGE_CORRUPT
    assert classified.message == "Host lineage status is inconsistent."


@pytest.mark.parametrize(("acceptance", "expected"), (("accepted", True), ("pending", False)))
async def test_readiness_reports_an_accepted_child_with_self_verified_findings(
    monkeypatch: pytest.MonkeyPatch, acceptance: str, expected: bool
) -> None:
    """Issue #984/#996 (S2): the lineage row's count drives the standing status note."""

    from finishup.application import task_views
    from finishup.protocol.models import StatusLineageChildModel

    child = StatusLineageChildModel.model_validate(
        {
            "task_id": _CHILD,
            "parent_task_id": _PARENT,
            "origin": "self_registered",
            "acceptance": acceptance,
            "work_state": "closed",
            "session_health": "ended",
            "depth": "1",
            "rollup_state": "annotation",
            "blocking_conditions": (),
            "self_verified_finding_count": "2",
        }
    )

    async def page(*_args: object, **_kwargs: object) -> object:
        return SimpleNamespace(children=(child,))

    monkeypatch.setattr(task_views, "lineage_status_page", page)
    catalog = AsyncMock(spec=StartCatalogPort)
    catalog.list_child_task_ids.return_value = (_CHILD,)
    runtime = cast(TaskRuntime, SimpleNamespace(task_id=_PARENT, session_id=_SESSION))
    assert await _lineage_readiness_gaps(
        cast(Application, SimpleNamespace(start_catalog=catalog)),
        runtime,
        Frontier(0, "genesis"),
        "req_53000000-0000-4000-8000-000000000002",
    ) == ((), expected)
