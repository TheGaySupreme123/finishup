"""Task-lane scheduling for the ready verification supervisor."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import pytest

from finishup.application.observation_verification import (
    ObservationVerificationSupervisor,
    VerificationDrainHandle,
)


@dataclass
class _Worker:
    service_generation: int = 1
    calls: list[str] = field(default_factory=lambda: list[str]())
    lane: str = ""
    remaining: int = 2
    active: list[int] = field(default_factory=lambda: [0, 0])
    shared_active: list[int] | None = None
    release: asyncio.Event | None = None

    async def run_once(self) -> object | None:
        self.calls.append(self.lane)
        active = self.shared_active if self.shared_active is not None else self.active
        active[0] += 1
        active[1] = max(active[1], active[0])
        try:
            if self.release is not None:
                await self.release.wait()
            if self.remaining == 0:
                return None
            self.remaining -= 1
            return object()
        finally:
            active[0] -= 1


def _handle(workspace: str, task_id: str, worker: _Worker) -> VerificationDrainHandle:
    return VerificationDrainHandle(
        workspace_commitment=workspace,
        worker=worker,  # type: ignore[arg-type]
        task_id=task_id,
    )


@pytest.mark.anyio
async def test_same_workspace_task_lanes_run_in_one_fair_concurrent_round() -> None:
    workspace = "hmac-sha256:" + "a" * 64
    supervisor = ObservationVerificationSupervisor(service_generation=1)
    all_started = asyncio.Event()
    release = asyncio.Event()
    shared_active = [0, 0]
    workers = tuple(
        _Worker(
            lane=task,
            release=release,
            shared_active=shared_active,
        )
        for task in ("task-a", "task-b", "task-c")
    )

    # The first worker signals once it has started; the other workers do so through the shared
    # count below.  A callback-free worker is enough to prove the supervisor's lane scheduling.
    started_count = 0
    for worker in workers:
        original: Callable[[], Awaitable[object | None]] = worker.run_once

        async def wrapped(
            original: Callable[[], Awaitable[object | None]] = original,
        ) -> object | None:
            nonlocal started_count
            started_count += 1
            if started_count == len(workers):
                all_started.set()
            return await original()

        worker.run_once = wrapped  # type: ignore[method-assign]

    assert all(
        supervisor.register(_handle(workspace, task, worker))
        for task, worker in zip(("task-a", "task-b", "task-c"), workers, strict=True)
    )
    assert supervisor.has_handle(workspace, "task-a")
    assert supervisor.has_handle(workspace, "task-b")
    assert supervisor.has_handle(workspace, "task-c")
    assert len(supervisor._handles) == 3  # pyright: ignore[reportPrivateUsage]

    first_round = asyncio.create_task(supervisor._drain_once())  # pyright: ignore[reportPrivateUsage]
    await all_started.wait()
    release.set()
    assert await first_round is True
    assert [worker.calls for worker in workers] == [["task-a"], ["task-b"], ["task-c"]]
    assert shared_active[1] == 3

    # A busy lane cannot consume the whole queue before its siblings get their next turn.
    assert await supervisor._drain_once() is True  # pyright: ignore[reportPrivateUsage]
    assert [worker.calls for worker in workers] == [
        ["task-a", "task-a"],
        ["task-b", "task-b"],
        ["task-c", "task-c"],
    ]

    assert await supervisor._drain_once() is False  # pyright: ignore[reportPrivateUsage]
    assert len(supervisor._handles) == 0  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
async def test_duplicate_task_lane_is_rejected_without_blocking_a_sibling() -> None:
    workspace = "hmac-sha256:" + "b" * 64
    supervisor = ObservationVerificationSupervisor(service_generation=1)
    first = _Worker(lane="task-a")
    duplicate = _Worker(lane="task-a")
    sibling = _Worker(lane="task-b")

    assert supervisor.register(_handle(workspace, "task-a", first))
    assert not supervisor.register(_handle(workspace, "task-a", duplicate))
    assert supervisor.register(_handle(workspace, "task-b", sibling))
    assert supervisor.has_handle(workspace, "task-a")
    assert supervisor.has_handle(workspace, "task-b")
    assert len(supervisor._handles) == 2  # pyright: ignore[reportPrivateUsage]

    assert await supervisor._drain_once() is True  # pyright: ignore[reportPrivateUsage]
    assert first.calls == ["task-a"]
    assert duplicate.calls == []
    assert sibling.calls == ["task-b"]
