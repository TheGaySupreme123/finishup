"""Issue #836: a structural delivery never leaves its own capture handoff behind.

Only the structural row a handoff was staged for can consume it. These tests
drive the production coordinator, SQLite ledger, and encrypted object store with
real Claude Code hook requests and check each transition that used to acknowledge
or quarantine the row while its ticket stayed ``pending``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest

from integration.application.test_native_capture_pipeline import (
    _capture_claude_post_requests,  # pyright: ignore[reportPrivateUsage]
    _claude_hook_runner,  # pyright: ignore[reportPrivateUsage]
    _pipeline,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.adapters.sqlite.observation import SqliteObservationStore
from yoetz.application.observation_coordinator import ObservationCoordinator
from yoetz.application.observation_materialize import observation_content_identity
from yoetz.domain.observation import (
    OBSERVATION_CONTENT_CAPTURE_PENDING_REASON,
    ObservationCaptureTicket,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestRequest,
)
from yoetz.domain.observation_profiles import CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError

_PROFILE = CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
_HOST_SESSION = "claude:handoff-ingest"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class _Lane:
    workspace: str
    local: LocalObservationStore
    observation: SqliteObservationStore
    coordinator: ObservationCoordinator
    capture: ObservationIngestRequest
    structural: ObservationIngestRequest
    ledger: Any = None
    runtime: Any = None

    def ticket(self) -> ObservationCaptureTicket | None:
        return self.observation.load_capture_ticket(
            workspace=self.workspace,
            logical_identity=observation_content_identity(self.structural.envelope),
        )

    def reservations(self) -> int:
        return cast(int, self.local.capture_backlog(self.workspace)["reservation_count"])

    def retirements(self) -> tuple[Mapping[str, object], ...]:
        account = self.local.capture_handoff_retirements(self.workspace)
        return cast(tuple[Mapping[str, object], ...], account["recent"])

    def acknowledge_structural_row(self) -> None:
        (row,) = (
            row
            for row in self.local.list_pending_outbox_rows(
                self.workspace, codex_session_id=_HOST_SESSION
            )
            if row.envelope.source_identity == self.structural.envelope.source_identity
        )
        assert self.local.acknowledge_outbox_row(self.workspace, row)

    async def stage(self) -> ObservationCaptureTicket:
        staged = await self.coordinator.ingest_request(self.capture)
        assert staged.reason == OBSERVATION_CONTENT_CAPTURE_PENDING_REASON
        ticket = self.ticket()
        assert ticket is not None and ticket.state == "pending"
        assert self.reservations() == 1
        return ticket


async def _lane(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _Lane:
    (
        project,
        workspace,
        _session_commitment,
        local,
        observation,
        ledger,
        runtime,
        coordinator,
        client,
        connect,
    ) = await _pipeline(tmp_path, codex_session_id=_HOST_SESSION, profile=_PROFILE)
    run_hook = _claude_hook_runner(
        project=project, state=tmp_path / "state", connect=connect, profile=_PROFILE
    )
    assert (
        await asyncio.to_thread(
            run_hook,
            "PreToolUse",
            {
                "hook_event_name": "PreToolUse",
                "session_id": "handoff-ingest",
                "tool_name": "Bash",
                "tool_use_id": "handoff-ingest-tool",
            },
        )
        == 0
    )
    captured = await _capture_claude_post_requests(
        client=client,
        monkeypatch=monkeypatch,
        run_hook=run_hook,
        session_id="handoff-ingest",
        tool_use_id="handoff-ingest-tool",
        marker=b"handoff-ingest-marker",
    )
    capture = next(item for item in captured if item.capture_only)
    structural = next(item for item in captured if not item.capture_only)
    # The hook left its structural row queued, as a real interrupted drain does.
    assert any(
        row.envelope.source_identity == structural.envelope.source_identity
        for row in local.list_pending_outbox_rows(workspace, codex_session_id=_HOST_SESSION)
    )
    return _Lane(
        workspace,
        local,
        observation,
        coordinator,
        capture,
        structural,
        ledger,
        runtime,
    )


@pytest.mark.anyio
async def test_commit_without_consuming_a_matched_handoff_retires_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Content fenced at delivery: the row commits and nothing can consume the ticket."""

    lane = await _lane(tmp_path, monkeypatch)
    await lane.stage()

    def fenced(*_args: object, **_kwargs: object) -> bool:
        return False

    monkeypatch.setattr(lane.local, "content_capture_authority_is_current", fenced)
    result = await lane.coordinator.ingest_request(lane.structural)
    assert result.disposition is ObservationIngestDisposition.ACCEPTED

    retired = lane.ticket()
    assert retired is not None and retired.state == "revoked"
    assert lane.reservations() == 0
    (entry,) = lane.retirements()
    assert entry["stage"] == "structural_committed"
    assert entry["reason"] == "content_not_admitted"
    assert entry["ticket_state"] == "pending"
    lane.coordinator.close()


@pytest.mark.anyio
async def test_terminal_refusal_after_matching_retires_the_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ledger refusal quarantines the row, so its ticket must not survive it."""

    lane = await _lane(tmp_path, monkeypatch)
    await lane.stage()

    async def refused(*_args: object, **_kwargs: object) -> object:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST, "synthetic terminal refusal", retryable=False
        )

    monkeypatch.setattr(lane.coordinator, "_append_materialized", refused)
    result = await lane.coordinator.ingest_request(lane.structural)
    assert result.reason == ObservationGapCode.LEDGER_REJECTED.value

    retired = lane.ticket()
    assert retired is not None and retired.state == "revoked"
    assert lane.reservations() == 0
    (entry,) = lane.retirements()
    assert (entry["stage"], entry["reason"]) == ("structural_refused", "terminal_refusal")
    lane.coordinator.close()


@pytest.mark.anyio
async def test_retryable_refusal_keeps_the_handoff_for_the_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lane = await _lane(tmp_path, monkeypatch)
    await lane.stage()
    original = lane.coordinator._append_materialized  # pyright: ignore[reportPrivateUsage]
    unavailable = True

    async def flaky(*args: object, **kwargs: object) -> object:
        if unavailable:
            raise PublicOperationError(
                PublicErrorCode.SERVICE_UNAVAILABLE, "synthetic outage", retryable=True
            )
        return await original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(lane.coordinator, "_append_materialized", flaky)
    first = await lane.coordinator.ingest_request(lane.structural)
    assert first.reason == ObservationGapCode.SERVICE_UNAVAILABLE.value
    kept = lane.ticket()
    assert kept is not None and kept.state == "pending"
    assert lane.retirements() == ()

    unavailable = False
    retried = await lane.coordinator.ingest_request(lane.structural)
    assert retried.disposition in {
        ObservationIngestDisposition.ACCEPTED,
        ObservationIngestDisposition.DUPLICATE,
    }
    assert lane.ticket() is None  # consumed by its own row
    assert lane.reservations() == 0
    assert lane.retirements() == ()
    lane.coordinator.close()


@pytest.mark.anyio
async def test_capture_after_an_acknowledged_row_stages_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lease-free drain delivered the row first: no unconsumable ticket is minted."""

    lane = await _lane(tmp_path, monkeypatch)
    delivered = await lane.coordinator.ingest_request(lane.structural)
    assert delivered.disposition is ObservationIngestDisposition.ACCEPTED
    lane.acknowledge_structural_row()

    late = await lane.coordinator.ingest_request(lane.capture)
    assert late.disposition is ObservationIngestDisposition.REJECTED
    assert late.reason == ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
    assert lane.ticket() is None
    assert lane.reservations() == 0
    lane.coordinator.close()


@pytest.mark.anyio
async def test_capture_staged_while_its_row_is_in_flight_is_retired_at_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The row passed its capture fence before the late capture staged a ticket."""

    lane = await _lane(tmp_path, monkeypatch)
    original = lane.coordinator._append_materialized  # pyright: ignore[reportPrivateUsage]
    entered = asyncio.Event()
    release = asyncio.Event()

    async def held(*args: object, **kwargs: object) -> object:
        entered.set()
        await release.wait()
        return await original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(lane.coordinator, "_append_materialized", held)
    structural = asyncio.create_task(lane.coordinator.ingest_request(lane.structural))
    try:
        await asyncio.wait_for(entered.wait(), timeout=2.0)
        # The row is still queued, so an interrupted delivery could still
        # consume a new handoff: staging is allowed.
        await lane.stage()
        release.set()
        result = await asyncio.wait_for(structural, timeout=5.0)
        assert result.disposition is ObservationIngestDisposition.ACCEPTED
    finally:
        release.set()
        if not structural.done():
            structural.cancel()
    retired = lane.ticket()
    assert retired is not None and retired.state == "revoked"
    assert lane.reservations() == 0
    (entry,) = lane.retirements()
    assert entry["stage"] == "structural_committed"
    lane.coordinator.close()


async def _case_gaps(lane: _Lane, seed: int) -> tuple[str, ...]:
    from integration.application.test_native_capture_pipeline import (
        _ZERO_DIGEST,  # pyright: ignore[reportPrivateUsage]
        _ids,  # pyright: ignore[reportPrivateUsage]
    )
    from yoetz.kernel.deterministic_checks import case_coverage
    from yoetz.ports.ledger import FrozenCase
    from yoetz.protocol.ids import IdKind

    frontier = await lane.ledger.load_frontier()
    frozen = await lane.ledger.freeze_case(
        lane.runtime.session_id,
        lane.runtime.writer_id,
        frontier.sequence,
        _ids(IdKind.REQUEST, seed),
        _ZERO_DIGEST,
    )
    assert isinstance(frozen, FrozenCase)
    return case_coverage(frozen.case).known_gaps


@pytest.mark.anyio
async def test_a_retired_handoff_puts_its_disclosure_on_its_own_task(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#1019 (tb4n2 N-4): a retirement is no longer visible only in a workspace ring buffer.

    The retiring task's coverage carries ``capture_handoff_retired`` once, through one marker
    keyed by the ticket; a replay of the same row adds no second marker, and another task's
    runtime never receives it.
    """

    from yoetz.domain.observation import CaptureHandoffRetirementReason

    lane = await _lane(tmp_path, monkeypatch)
    ticket = await lane.stage()

    def fenced(*_args: object, **_kwargs: object) -> bool:
        return False

    monkeypatch.setattr(lane.local, "content_capture_authority_is_current", fenced)
    result = await lane.coordinator.ingest_request(lane.structural)
    assert result.disposition is ObservationIngestDisposition.ACCEPTED
    assert len(lane.retirements()) == 1

    assert "capture_handoff_retired" in await _case_gaps(lane, 41)
    frontier = (await lane.ledger.load_frontier()).sequence
    await lane.coordinator._publish_capture_handoff_retirement(  # pyright: ignore[reportPrivateUsage]
        lane.runtime, ticket, CaptureHandoffRetirementReason.CONTENT_NOT_ADMITTED
    )
    assert (await lane.ledger.load_frontier()).sequence == frontier

    class _OtherTask:
        task_id = "tsk_00000000-0000-4000-8000-0000000010ff"

        def __getattr__(self, name: str) -> object:
            raise AssertionError("another task's runtime must not be written: " + name)

    await lane.coordinator._publish_capture_handoff_retirement(  # pyright: ignore[reportPrivateUsage]
        cast(Any, _OtherTask()), ticket, CaptureHandoffRetirementReason.CONTENT_NOT_ADMITTED
    )
    assert (await lane.ledger.load_frontier()).sequence == frontier
    lane.coordinator.close()


@pytest.mark.anyio
async def test_a_consumed_handoff_leaves_no_retirement_disclosure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A task whose handoff was attached normally carries no ``capture_handoff_retired``."""

    lane = await _lane(tmp_path, monkeypatch)
    await lane.stage()
    result = await lane.coordinator.ingest_request(lane.structural)
    assert result.disposition is ObservationIngestDisposition.ACCEPTED
    assert lane.retirements() == ()
    assert "capture_handoff_retired" not in await _case_gaps(lane, 42)
    lane.coordinator.close()
