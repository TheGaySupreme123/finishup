"""Receipts never claim background AI-powered advice is pending when it cannot run (#923).

In the DeepSWE v2 arm B (review required, no provider bound, local-only privacy) every receipt
said ``advice_semantic_pending``: work that could never happen. The receipt reaches advice
coverage through the advice findings it retains, so this drives the real advice builder and
scheduler, materializes the findings into the task ledger through the observation coordinator,
and reads the gap codes back from real JSON and markdown receipts.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import apsw
import pytest

from builders.ledger_adapters import FixedClock, FixedIds
from builders.projection_workflow import (
    build_projection_application,
    frontier_json,
    request_base,
)
from builders.start_application import protocol_id, start_request
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.observation_advice_semantic import (
    SqliteObservationAdviceSemanticRepository,
)
from finishup.application.observation_advice import (
    ADVICE_SEMANTIC_PENDING_GAP,
    ADVICE_SEMANTIC_UNAVAILABLE_GAP,
    ObservationAdviceContextBuilder,
)
from finishup.application.observation_advice_semantic import ObservationAdviceSemanticScheduler
from finishup.application.observation_coordinator import ObservationCoordinator
from finishup.domain.observation import (
    ObservationCursor,
    ObservationEnvelope,
    ObservationLifecycle,
    ObservationSource,
    ObservationStatus,
    ObservationStatusQuery,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.ledger import ProjectionView
from finishup.ports.runtime import BundleRuntimePort, RouteAccess, RouteCommand, TaskRuntime
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import ReceiptRequest

pytestmark = pytest.mark.anyio

_WORKSPACE = "hmac-sha256:" + "9" * 64
_TIME = Timestamp("2026-09-29T08:42:37.000Z")


class _Store:
    """A busy session: several unresolved failed commands, each a distinct advice candidate."""

    def __init__(self, repository: SqliteObservationAdviceSemanticRepository) -> None:
        self.repository = repository

    def list_envelopes(self, workspace: str) -> tuple[ObservationEnvelope, ...]:
        assert workspace == _WORKSPACE
        return tuple(
            ObservationEnvelope(
                session_commitment=_WORKSPACE,
                event_kind="PostToolUse",
                source_identity=f"hook:fail-{index}",
                source=ObservationSource.CODEX_HOOK,
                cursor=ObservationCursor(
                    source_generation=1,
                    byte_position=(index + 1) * 8,
                    event_position=index + 1,
                    last_source_commitment=_WORKSPACE,
                    mapping_version="codex-obs-hook/1.0.0",
                ),
                receipt_time=_TIME,
                structural_payload=JsonObject(
                    {
                        "tool_name": "shell",
                        "exit_status": 1,
                        "correlation_id": f"hook:fail-{index}",
                    }
                ),
                content_object_refs=(),
                gap_codes=(),
            )
            for index in range(4)
        )

    async def status(self, query: ObservationStatusQuery) -> ObservationStatus:
        assert query.workspace_commitment == _WORKSPACE
        return ObservationStatus(
            ObservationLifecycle.ACTIVE, _WORKSPACE, {}, _TIME, 0, (), (), None
        )

    def load_advice_snapshot(self, workspace: str) -> None:
        return None

    def advice_semantic_repository(self) -> SqliteObservationAdviceSemanticRepository:
        return self.repository


async def _receipt_gaps(
    tmp_path: Path, *, provider_ready: bool, seed: int
) -> tuple[tuple[str, ...], str, int]:
    """Return (JSON receipt gap codes, markdown receipt text, advice rows written)."""

    app, _policy = await build_projection_application(seed=seed)
    started = await app.start(start_request(seed + 1, title="Advice availability receipt"))
    runtime = await app.runtime.route(
        RouteCommand(
            started.session_id,
            started.writer_id,
            RouteAccess.WRITE,
            frozenset({RuntimeCapability.WRITE}),
        )
    )
    assert type(runtime) is TaskRuntime

    db = apsw.Connection(":memory:")
    initialize_bundle(db, {"task_id": "tsk_advice", "owner_generation": "1"})
    repository = SqliteObservationAdviceSemanticRepository(db)
    store = _Store(repository)

    async def readiness() -> bool:
        return provider_ready

    builder = ObservationAdviceContextBuilder(
        semantic_scheduler=ObservationAdviceSemanticScheduler(
            now=lambda: _TIME.wire, provider_ready=readiness
        )
    )
    snapshot = await builder.build(
        _WORKSPACE,
        store,  # type: ignore[arg-type]
        yoetz_session_id=started.session_id,
    )
    assert snapshot is not None and snapshot.ranked_items
    count = db.execute("SELECT COUNT(*) FROM observation_advice_semantic_attempts").fetchone()
    assert count is not None
    written = int(cast(int, count[0]))
    db.close()

    coordinator = ObservationCoordinator(
        runtime=cast(BundleRuntimePort, object()),
        local=LocalObservationStore(_state=tmp_path),
        clock=FixedClock(),
        ids=FixedIds(),
        state_root=tmp_path,
    )
    await coordinator._materialize_advice_findings(  # pyright: ignore[reportPrivateUsage]
        runtime, store.list_envelopes(_WORKSPACE), snapshot
    )
    projection = await runtime.ledger.load_projection(started.session_id, ProjectionView.COMPACT)
    assert projection is not None

    wire: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed + 2)),
        "task_id": started.task_id,
        "session_id": started.session_id,
        "writer_id": started.writer_id,
        "expected_frontier": frontier_json(projection.frontier),
        "format": "json",
        "include": "standard",
        "redaction_profile": "full_local",
    }
    document = await app.receipt(ReceiptRequest.model_validate(wire))
    text = await app.receipt(
        ReceiptRequest.model_validate(
            {
                **wire,
                "request_id": protocol_id("req_", seed + 3),
                "expected_frontier": frontier_json(document.result_frontier),
                "format": "markdown",
            }
        )
    )
    assert text.human_text is not None
    return document.coverage.known_gaps, text.human_text, written


async def test_receipt_reports_unavailable_not_pending_when_no_provider_can_run(
    tmp_path: Path,
) -> None:
    gaps, human_text, written = await _receipt_gaps(tmp_path, provider_ready=False, seed=9230)

    assert written == 0
    assert ADVICE_SEMANTIC_PENDING_GAP not in gaps
    assert gaps.count(ADVICE_SEMANTIC_UNAVAILABLE_GAP) == 1
    assert ADVICE_SEMANTIC_PENDING_GAP not in human_text
    assert ADVICE_SEMANTIC_UNAVAILABLE_GAP in human_text


async def test_receipt_reports_pending_only_for_a_queued_provider_attempt(
    tmp_path: Path,
) -> None:
    gaps, human_text, written = await _receipt_gaps(tmp_path, provider_ready=True, seed=9240)

    assert written == 1
    assert ADVICE_SEMANTIC_PENDING_GAP in gaps
    assert ADVICE_SEMANTIC_UNAVAILABLE_GAP not in gaps
    assert ADVICE_SEMANTIC_PENDING_GAP in human_text
