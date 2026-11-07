"""A refused ``finishup service unlock`` must not exit 0 (issue #1323).

The unlock ceremony reports a wrong passphrase or a refused keyring as a locked result document,
not an exception, and the command used to render that document and exit 0. A script or agent that
reads the exit status took the refusal for an unlock. The document is still printed unchanged;
the exit status and one fixed stderr line now say the vault is still locked.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any

import pytest

import finishup.cli.app as module
import finishup.cli.unlock as unlock_module
from finishup.cli.exits import exit_code_for
from finishup.protocol.errors import PublicErrorCode
from finishup.service.confidential_protocol import KeyringRetryResult, VaultStateResult

pytestmark = pytest.mark.anyio


class _Client:
    def __init__(self, vault_mode: str) -> None:
        self._status = SimpleNamespace(
            state=SimpleNamespace(value="locked"),
            state_reason="passphrase_required",
            vault_mode=vault_mode,
        )
        self.closed = False

    async def service_status(self) -> Any:
        return self._status

    async def close(self) -> None:
        self.closed = True


def _service(monkeypatch: pytest.MonkeyPatch, vault_mode: str) -> _Client:
    client = _Client(vault_mode)

    async def build() -> _Client:
        return client

    monkeypatch.setattr(module, "build_service_client", build)
    return client


def _ceremony(
    monkeypatch: pytest.MonkeyPatch, name: str, result: object
) -> Callable[[], Awaitable[object]]:
    """Replace one unlock ceremony; nothing here reaches a service or a terminal."""

    async def ceremony(*_args: object, **_kwargs: object) -> object:
        return result

    monkeypatch.setattr(unlock_module, name, ceremony)
    return ceremony


@pytest.mark.parametrize("json_output", [True, False])
async def test_a_wrong_passphrase_still_prints_the_document_and_exits_vault_locked(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], json_output: bool
) -> None:
    refused = VaultStateResult("locked", "unlock_wrong")
    ceremony = _ceremony(monkeypatch, "unlock_vault", refused)
    # What the command printed before the fix, rendered by the unchanged shared path.
    assert await module._trusted_call(ceremony, json_output) == 0
    before = capsys.readouterr().out
    client = _service(monkeypatch, "passphrase")

    code = await module._service_unlock(json_output)

    captured = capsys.readouterr()
    assert code == exit_code_for(PublicErrorCode.VAULT_LOCKED)
    assert code != 0
    assert captured.out == before
    assert captured.err == "vault_locked: the vault is still locked (unlock_wrong)\n"
    assert client.closed


async def test_the_json_document_is_the_one_the_ceremony_returned(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _service(monkeypatch, "passphrase")
    _ceremony(monkeypatch, "unlock_vault", VaultStateResult("locked", "unlock_wrong"))

    code = await module._service_unlock(True)

    assert code == exit_code_for(PublicErrorCode.VAULT_LOCKED)
    assert json.loads(capsys.readouterr().out) == {
        "kind": "vault_state",
        "reason": "unlock_wrong",
        "state": "locked",
    }


async def test_a_ready_vault_exits_zero_with_nothing_on_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _service(monkeypatch, "passphrase")
    _ceremony(monkeypatch, "unlock_vault", VaultStateResult("ready", "succeeded"))

    code = await module._service_unlock(True)

    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["state"] == "ready"
    assert captured.err == ""


async def test_a_keyring_retry_that_stays_locked_exits_non_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _service(monkeypatch, "os_keyring")
    _ceremony(monkeypatch, "retry_keyring", KeyringRetryResult("locked", "keyring_locked"))

    code = await module._service_unlock(True)

    captured = capsys.readouterr()
    assert code == exit_code_for(PublicErrorCode.VAULT_LOCKED)
    assert code != 0
    assert json.loads(captured.out) == {
        "kind": "keyring_retry",
        "reason": "keyring_locked",
        "state": "locked",
    }
    assert captured.err == "vault_locked: the vault is still locked (keyring_locked)\n"


async def test_a_ready_keyring_retry_exits_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _service(monkeypatch, "os_keyring")
    _ceremony(monkeypatch, "retry_keyring", KeyringRetryResult("ready", "succeeded"))

    assert await module._service_unlock(False) == 0
    assert capsys.readouterr().err == ""


async def test_a_reason_outside_the_named_set_gets_the_fixed_generic_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _service(monkeypatch, "passphrase")
    _ceremony(monkeypatch, "unlock_vault", VaultStateResult("locked", "challenge_mismatch"))

    code = await module._service_unlock(True)

    assert code == exit_code_for(PublicErrorCode.VAULT_LOCKED)
    assert capsys.readouterr().err == "vault_locked: the vault is still locked\n"


async def test_a_ceremony_failure_keeps_its_existing_outcome(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Only a returned locked result changes; a raised ceremony error maps as it did before."""

    _service(monkeypatch, "passphrase")

    async def cancelled(*_args: object, **_kwargs: object) -> object:
        raise unlock_module.HumanCeremonyCliError("cancelled")

    monkeypatch.setattr(unlock_module, "unlock_vault", cancelled)

    code = await module._service_unlock(True)

    captured = capsys.readouterr()
    assert code == exit_code_for("cancelled")
    assert captured.out == ""
    assert captured.err == "cancelled\n"
