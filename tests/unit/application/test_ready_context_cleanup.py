from __future__ import annotations

import pytest

from finishup.application.service import (
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
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    async def stop(self) -> None:
        self.calls.append("supervisor")


@pytest.mark.anyio
async def test_ready_context_cleanup_continues_after_sweeper_close_failure() -> None:
    calls: list[str] = []
    context = object.__new__(ServiceReadyContext)

    def fail_sweeper() -> None:
        calls.append("sweeper")
        raise RuntimeError("sweeper failed")

    object.__setattr__(context, "observation_sweep_close", fail_sweeper)
    object.__setattr__(context, "verification_supervisor", _Supervisor(calls))
    object.__setattr__(context, "privacy", _Closer("privacy", calls))
    object.__setattr__(context, "runtime", _Closer("runtime", calls))

    with pytest.raises(RuntimeError, match="sweeper failed"):
        await _close_ready_context(context)

    assert calls == ["sweeper", "supervisor", "privacy", "runtime"]
