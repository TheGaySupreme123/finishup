"""#1073: the terminal interface's "Your full receipt" path through the real runtime."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import yoetz.cli.unlock as unlock
from yoetz.service.confidential_client import ConfidentialClientError
from yoetz.service.owner_view import owner_receipt_view_target
from yoetz.tui.runtime import RuntimeError_, YoetzRuntime, _WorkSession

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def test_the_owner_path_asks_first_and_maps_every_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    class _Client:
        def owner_receipt_view_target(self, request: Any) -> Any:
            calls.append(f"target:{request.include.value}:{request.redaction_profile.value}")
            return owner_receipt_view_target(request, "e" * 64)

        async def receipt(self, request: Any) -> Any:
            del request
            calls.append("receipt")
            raise RuntimeError_("stop_here", "the test stops before rendering")

    @asynccontextmanager
    async def connect(_runtime: Any) -> AsyncGenerator[_Client]:
        yield _Client()

    monkeypatch.setattr(YoetzRuntime, "_client", connect)
    runtime = YoetzRuntime(cwd=tmp_path)
    runtime._sessions["t"] = _WorkSession(
        "tsk_00000000-0000-4000-8000-0000000000e1",
        "ses_00000000-0000-4000-8000-0000000000e2",
        "wri_00000000-0000-4000-8000-0000000000e4",
        SimpleNamespace(sequence="3", head_digest="sha256:" + "1" * 64),
    )
    for reason, expected in (
        ("presence_refused", "owner_view_refused"),
        ("presence_timeout", "owner_view_refused"),
        ("presence_unavailable", "owner_view_unavailable"),
        ("reauthentication_unavailable", "owner_view_unavailable"),
        ("ceremony_busy", "owner_view_busy"),
        ("reauthentication_rate_limited", "owner_view_refused"),
        ("passphrase_in_credential_store", "owner_view_unavailable"),
    ):

        async def refuse(target: Any, reason: str = reason, **_kwargs: Any) -> Any:
            del target
            if reason == "passphrase_in_credential_store":
                raise unlock.HumanCeremonyCliError(reason)
            raise ConfidentialClientError(reason)

        monkeypatch.setattr(unlock, "authorize_owner_receipt_view", refuse)
        calls.clear()
        with pytest.raises(RuntimeError_) as raised:
            await runtime.build_receipt("t", "markdown", owner_view=True)
        assert raised.value.reason == expected, reason
        # Refused before any receipt call: nothing was fetched, let alone shown.
        assert calls == ["target:full:full_local"], reason

    async def grant(target: Any, **_kwargs: Any) -> Any:
        del target

    monkeypatch.setattr(unlock, "authorize_owner_receipt_view", grant)
    calls.clear()
    with pytest.raises(RuntimeError_, match="stops before rendering"):
        await runtime.build_receipt("t", "markdown", owner_view=True)
    assert calls == ["target:full:full_local", "receipt"]
