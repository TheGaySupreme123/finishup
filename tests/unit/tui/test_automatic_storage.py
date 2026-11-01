"""The first-run storage step asks nothing and names the custody actually used (issue #1119)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any

import pytest

from finishup.tui.app import FinishUpTui
from finishup.tui.models import Detection


def _app(
    monkeypatch: pytest.MonkeyPatch,
    outcome: tuple[bool, str | None, str],
    *,
    reachable: bool = True,
    vault_mode: str | None = "uninitialized",
    ready: bool = False,
) -> tuple[FinishUpTui, list[tuple[object, str, tuple[str, ...]]]]:
    app = FinishUpTui()
    said: list[tuple[object, str, tuple[str, ...]]] = []

    async def posture() -> SimpleNamespace:
        return SimpleNamespace(reachable=reachable, vault_mode=vault_mode, ready=ready)

    async def automatic() -> tuple[bool, str | None, str]:
        return outcome

    async def hand_over(operation: Callable[[], Awaitable[Any]]) -> Any:
        return await operation()

    async def never_ask(_view: object) -> str:
        raise AssertionError("the storage step must not ask a question")

    monkeypatch.setattr(app.runtime, "vault_posture", posture)
    monkeypatch.setattr(app.runtime, "set_up_storage_automatically", automatic)
    monkeypatch.setattr(app, "hand_over_terminal", hand_over)
    monkeypatch.setattr(app, "ask", never_ask)

    def say(level: object, title: str, body: tuple[str, ...] = ()) -> None:
        said.append((level, title, tuple(body)))

    monkeypatch.setattr(app, "say", say)
    return app, said


@pytest.mark.anyio
async def test_owner_file_custody_is_named_even_when_a_keychain_is_detected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, said = _app(monkeypatch, (True, None, "owner_file"))

    await app._choose_storage(Detection(None, None, False, False, secure_storage_available=True))  # pyright: ignore[reportPrivateUsage]

    assert said[-1][1] == "Secure storage is set up"
    assert "a file only your account can read" in said[-1][2][0]
    assert "programs running as you can" in said[-1][2][1]


@pytest.mark.anyio
async def test_a_vault_that_is_not_ready_says_so_and_names_the_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, said = _app(monkeypatch, (False, "auto_unlock_entry_exists", "unknown"))

    await app._choose_storage(Detection(None, None, False, False))  # pyright: ignore[reportPrivateUsage]

    assert said[-1][1] == "Secure storage was not set up"
    assert "auto_unlock_entry_exists" in said[-1][2]
    assert "Run 'finishup setup vault' to try again." in said[-1][2]


@pytest.mark.anyio
async def test_a_stopped_service_still_gets_storage_set_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The automatic helper starts the service, so a stopped one is not an early return."""

    app, said = _app(monkeypatch, (True, None, "platform_store"), reachable=False, vault_mode=None)

    await app._choose_storage(Detection(None, None, False, False))  # pyright: ignore[reportPrivateUsage]

    assert said[-1][1] == "Secure storage is set up"


@pytest.mark.anyio
async def test_a_locked_existing_vault_is_unlocked_rather_than_reported_set_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, said = _app(monkeypatch, (True, None, "owner_file"), vault_mode="passphrase")

    await app._choose_storage(Detection(None, None, False, False))  # pyright: ignore[reportPrivateUsage]

    assert said[-1][1] == "Secure storage is set up"


@pytest.mark.anyio
async def test_a_ready_vault_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    async def never_called() -> tuple[bool, str | None, str]:
        raise AssertionError("a ready vault needs no setup")

    app, said = _app(monkeypatch, (True, None, "owner_file"), vault_mode="os_keyring", ready=True)
    monkeypatch.setattr(app.runtime, "set_up_storage_automatically", never_called)

    await app._choose_storage(Detection(None, None, False, False))  # pyright: ignore[reportPrivateUsage]

    assert said[-1][1] == "Secure storage is already set up"
