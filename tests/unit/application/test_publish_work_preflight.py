"""Dry-run publish feasibility parity for observation-authored batches."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

from finishup.application.publish_work import (  # pyright: ignore[reportPrivateUsage]
    PreparedPublication,
    _preflight_dry_run_feasibility,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.values import Actor, ActorType, Frontier, actor_id
from finishup.ports.runtime import TaskRuntime
from finishup.protocol.coverage import (
    AuthorshipAssurance,
    PublicationChannel,
    coverage_for_channel,
)
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import PublishWorkRequestModel


@pytest.mark.anyio
async def test_observation_dry_run_rejects_active_frozen_check_like_append() -> None:
    class _Ledger:
        async def load_frontier(self) -> Frontier:
            return Frontier(1, "sha256:" + "a" * 64)

        async def has_active_frozen_case(self, session_id: str) -> bool:
            assert session_id == "ses_00000000-0000-4000-8000-000000000001"
            return True

    runtime = cast(
        TaskRuntime,
        SimpleNamespace(
            session_id="ses_00000000-0000-4000-8000-000000000001",
            ledger=_Ledger(),
        ),
    )
    prepared = PreparedPublication(
        PublicationChannel.HOOK_OBSERVED,
        Actor(
            actor_id("yoetz:observation-coordinator"),
            ActorType.HARNESS,
            AuthorshipAssurance.HARNESS_OBSERVED,
        ),
        coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
        (),
    )

    with pytest.raises(PublicOperationError) as caught:
        await _preflight_dry_run_feasibility(
            runtime,
            cast(PublishWorkRequestModel, object()),
            prepared,
        )

    assert caught.value.code is PublicErrorCode.OPERATION_PENDING
