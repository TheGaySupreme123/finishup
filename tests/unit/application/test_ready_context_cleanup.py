from __future__ import annotations

import asyncio

import pytest

from finishup.application.service import (
    Application,
    ServiceReadyContext,
    _close_ready_context,  # pyright: ignore[reportPrivateUsage]
)


class _Closer:
    def __init__(self, name: str, calls: list[str]) -> None:
        self.name = name
        self.calls = calls

    async def close(self) -> None:
        self.calls.append(self.name)


class _Supervisor:
    def __init__(self, calls: list[str], name: str = "supervisor") -> None:
        self.calls = calls
        self.name = name

    async def stop(self) -> None:
        self.calls.append(self.name)


@pytest.mark.anyio
async def test_ready_context_cleanup_continues_after_sweeper_close_failure() -> None:
    calls: list[str] = []
    context = object.__new__(ServiceReadyContext)

    def fail_sweeper() -> None:
        calls.append("sweeper")
        raise RuntimeError("sweeper failed")

    async def wait_for_sweeper() -> None:
        calls.append("sweeper_wait_closed")

    object.__setattr__(context, "observation_sweep_close", fail_sweeper)
    object.__setattr__(context, "observation_sweep_wait_closed", wait_for_sweeper)
    object.__setattr__(context, "verification_supervisor", _Supervisor(calls))
    object.__setattr__(context, "privacy", _Closer("privacy", calls))
    object.__setattr__(context, "runtime", _Closer("runtime", calls))

    with pytest.raises(RuntimeError, match="sweeper failed"):
        await _close_ready_context(context)

    # The stop request comes first and the wait for the hook-spool pass last.
    assert calls == ["sweeper", "supervisor", "privacy", "runtime", "sweeper_wait_closed"]


@pytest.mark.anyio
async def test_application_close_waits_for_the_spool_pass_after_every_other_closer() -> None:
    # A pass parked on a hook's spool lock must not hold the supervisors, privacy or runtime.
    calls: list[str] = []
    application = object.__new__(Application)

    def stop_sweeper() -> None:
        calls.append("sweeper")

    async def wait_for_sweeper() -> None:
        calls.append("sweeper_wait_closed")

    for name, value in (
        ("_close_lock", asyncio.Lock()),
        ("_close_task", None),
        ("observation_sweep_close", stop_sweeper),
        ("observation_sweep_wait_closed", wait_for_sweeper),
        ("verification_supervisor", _Supervisor(calls)),
        ("advice_semantic_supervisor", _Supervisor(calls, "advice_supervisor")),
        ("privacy", _Closer("privacy", calls)),
        ("runtime", _Closer("runtime", calls)),
    ):
        object.__setattr__(application, name, value)

    await application.close()

    assert calls == [
        "sweeper",
        "supervisor",
        "advice_supervisor",
        "privacy",
        "runtime",
        "sweeper_wait_closed",
    ]
