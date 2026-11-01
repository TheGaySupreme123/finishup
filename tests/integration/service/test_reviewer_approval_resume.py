"""#1118 R2: an approval wait resumes in the first turn it reserved, once, by its pending id.

Through the real composition over a durable SQLite step store; the privacy coordinator's
evaluate/resume entry points are scripted to wait, so the test sees exactly which identity the
resumed exchange names, its media type, and that no turn is added or refilled. A job holding more
than that one uncaptured turn is not resumed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from finishup.application.egress import PrivacyCoordinator, SemanticEgressAwaitingHuman
from finishup.protocol.models import SemanticStatus
from finishup.service import ready_composition as rc
from integration.service import test_reviewer_conversation_composition as c

pytestmark = pytest.mark.anyio

_PENDING = "ppr_53000000-0000-4000-8000-000000000001"


async def _wait_then_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, extra_step: bool
) -> tuple[Any, list[tuple[str, str]], Any]:
    """Run a job to its approval wait, then run its conversation again for that pending id."""

    from finishup.application.reviewer_run import run_reviewer

    runs: list[tuple[Any, dict[str, Any]]] = []
    resumed: list[tuple[str, str]] = []

    async def waiting(self: PrivacyCoordinator, candidate: Any, deadline: Any, **_: Any) -> object:
        return SemanticEgressAwaitingHuman(
            candidate.request_id,
            _PENDING,
            candidate.subject_digest,
            datetime(2030, 1, 1, tzinfo=UTC),
        )

    async def resume(
        self: PrivacyCoordinator, request_id: str, pending_id: str, deadline: Any, **kwargs: Any
    ) -> object:
        resumed.append((request_id, pending_id))
        # The resumed exchange keeps the reviewer frame: its media type, never one-shot dispatch.
        assert kwargs["exchange"].media_type == "application/vnd.finishup.reviewer-turn+json"
        return SemanticEgressAwaitingHuman(
            request_id, pending_id, "sha256:" + "5" * 64, datetime(2030, 1, 1, tzinfo=UTC)
        )

    async def recording(privacy: Any, **kwargs: Any) -> Any:
        runs.append((privacy, kwargs))
        return await run_reviewer(privacy, **kwargs)

    monkeypatch.setattr(PrivacyCoordinator, "evaluate_semantic", waiting)
    monkeypatch.setattr(PrivacyCoordinator, "resume_reviewer_exchange", resume)
    monkeypatch.setattr(rc, "run_reviewer", recording)
    result, gateway, _ = await c._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        c._FINAL,  # pyright: ignore[reportPrivateUsage]
    )
    assert result.status is SemanticStatus.AWAITING_HUMAN and gateway.exchanges == []
    privacy, kwargs = runs[0]
    steps = kwargs["steps"]
    assert await steps.usage() == (1, 1)  # the first turn is reserved; nothing was captured
    if extra_step:  # e.g. an earlier run that got further: not provably unconsumed
        await steps.reserve("repair", 1, b"x")
    rerun: dict[str, Any] = {**kwargs, "resume_pending": _PENDING}
    again = await run_reviewer(privacy, **rerun)
    return again, resumed, steps


async def test_an_approval_wait_resumes_once_in_its_reserved_turn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    again, resumed, steps = await _wait_then_rerun(tmp_path, monkeypatch, extra_step=False)
    assert len(resumed) == 1 and resumed[0][1] == _PENDING
    assert type(again.result) is SemanticEgressAwaitingHuman
    assert await steps.usage() == (1, 1)  # the same reservation: nothing added or refilled


async def test_a_job_with_more_than_its_waiting_turn_is_not_resumed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    again, resumed, _ = await _wait_then_rerun(tmp_path, monkeypatch, extra_step=True)
    assert resumed == []
    assert again.record.ended == "uncaptured_step"
