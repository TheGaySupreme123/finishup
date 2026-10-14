"""#1073 2.C: the owner-view command with a service-side OS presence check.

The CLI never decides presence: it names the source the service offered, prints the same
confirmation code the system dialog shows, and turns each bounded service refusal into a plain
continuation that shows nothing.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

import yoetz.cli.app as cli_app
import yoetz.cli.unlock as unlock
from yoetz.ports.secret_memory import presence_confirmation_code
from yoetz.service.confidential_client import ConfidentialClientError
from yoetz.service.confidential_protocol import (
    AuthorizationRequiredPhase,
    HumanCeremonyKind,
    OwnerReceiptViewPreview,
    OwnerReceiptViewResult,
    SelectAuthorizationSourceAction,
)
from yoetz.service.owner_view import owner_receipt_view_target

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "5e7a90c1" + "4" * 56
_REQUEST = SimpleNamespace(
    task_id="tsk_00000000-0000-4000-8000-0000000000e1",
    session_id="ses_00000000-0000-4000-8000-0000000000e2",
    request_id="req_00000000-0000-4000-8000-0000000000e3",
    format="markdown",
    include="full",
    redaction_profile="full_local",
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Terminal:
    def __init__(self) -> None:
        self.text: list[str] = []

    def write(self, value: str) -> None:
        self.text.append(value)

    def write_secret(self, value: bytearray) -> None:
        raise AssertionError("no secret is shown")

    def read_choice(self, prompt: str, allowed: tuple[bytes, ...]) -> bytes:
        raise AssertionError("no choice is asked")

    def read_secret(self, prompt: str, maximum: int) -> bytearray:
        raise AssertionError("Touch ID needs no passphrase prompt")


class _Session:
    def __init__(self) -> None:
        self.opened = SimpleNamespace(binding=SimpleNamespace(target_digest=_DIGEST))
        self.actions: list[object] = []

    async def send_action(self, action: object) -> None:
        self.actions.append(action)

    async def wait_phase_or_result(self) -> object:
        return OwnerReceiptViewResult("authorized", _DIGEST, 60)


def test_the_code_is_derived_from_the_target_digest_only() -> None:
    assert presence_confirmation_code(_DIGEST) == "5e7a-90c1"
    # The preview itself names no code: a passphrase-only ceremony has no dialog to match.
    terminal = _Terminal()
    unlock._render_preview(
        terminal,
        OwnerReceiptViewPreview(
            task_id=_REQUEST.task_id,
            format="markdown",
            redaction_profile="full_local",
            grant_seconds=60,
            target_digest=_DIGEST,
        ),
    )
    assert "5e7a-90c1" not in "".join(terminal.text)


async def test_presence_is_requested_from_the_service_never_asserted_by_the_cli() -> None:
    terminal = _Terminal()
    session = _Session()
    target = owner_receipt_view_target(_REQUEST, "e" * 64)

    result, decision = await unlock._drive_session(
        session,  # pyright: ignore[reportArgumentType]
        terminal,
        HumanCeremonyKind.OWNER_RECEIPT_VIEW,
        target,
        AuthorizationRequiredPhase(("os_user_presence",)),
    )

    assert result == OwnerReceiptViewResult("authorized", _DIGEST, 60)
    assert decision is None
    # The only thing the CLI sends is the name of the source; the check runs in the service.
    assert session.actions == [SelectAuthorizationSourceAction("os_user_presence")]
    shown = "".join(terminal.text)
    assert "Touch ID or your login password" in shown
    assert "confirmation code 5e7a-90c1" in shown


@pytest.mark.parametrize(
    ("reason", "prefix", "detail"),
    [
        ("presence_refused", "owner_view_refused", "cancelled or did not confirm"),
        ("presence_timeout", "owner_view_refused", "not answered within a minute"),
        ("presence_unavailable", "owner_view_unavailable", "Touch ID or your login password"),
        ("reauthentication_unavailable", "owner_view_unavailable", "Linux and WSL have none"),
    ],
)
async def test_each_presence_refusal_shows_nothing_and_says_what_to_do(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    reason: str,
    prefix: str,
    detail: str,
) -> None:
    class _Client:
        def owner_receipt_view_target(self, request: Any) -> Any:
            return owner_receipt_view_target(request, "e" * 64)

    async def refuse(target: Any) -> Any:
        del target
        raise ConfidentialClientError(reason)

    monkeypatch.setattr(unlock, "authorize_owner_receipt_view", refuse)
    code = await cli_app._authorize_owner_receipt_view(_Client(), _REQUEST)  # pyright: ignore[reportArgumentType]

    assert code is not None and code != 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith(prefix + ":")
    assert detail in captured.err
    assert "Nothing" in captured.err or "nothing changed" in captured.err


def _fake_ceremonies(
    monkeypatch: pytest.MonkeyPatch, outcomes: list[object], offered: tuple[str, ...]
) -> list[str]:
    asked: list[str] = []

    async def run(kind: object, target: object, **kwargs: Any) -> object:
        del kind, target
        choice = kwargs["authorization"]
        asked.append(choice.prefer)
        choice.offered = offered
        outcome = outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(unlock, "run_human_ceremony", run)
    return asked


_GRANTED = OwnerReceiptViewResult("authorized", _DIGEST, 60)
_BOTH = ("os_user_presence", "secret_reauthentication")


async def test_no_dialog_here_falls_back_once_to_an_offered_passphrase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked = _fake_ceremonies(
        monkeypatch, [ConfidentialClientError("presence_unavailable"), _GRANTED], _BOTH
    )
    target = owner_receipt_view_target(_REQUEST, "e" * 64)
    assert await unlock.authorize_owner_receipt_view(target) == _GRANTED
    assert asked == ["os_user_presence", "secret_reauthentication"]


@pytest.mark.parametrize(
    ("reason", "offered"),
    [
        ("presence_unavailable", ("os_user_presence",)),
        ("presence_refused", _BOTH),
        ("presence_timeout", _BOTH),
        ("secret_rejected", _BOTH),
    ],
)
async def test_a_refusal_or_a_vault_without_a_passphrase_is_not_retried(
    monkeypatch: pytest.MonkeyPatch, reason: str, offered: tuple[str, ...]
) -> None:
    asked = _fake_ceremonies(monkeypatch, [ConfidentialClientError(reason), _GRANTED], offered)
    target = owner_receipt_view_target(_REQUEST, "e" * 64)
    with pytest.raises(ConfidentialClientError) as raised:
        await unlock.authorize_owner_receipt_view(target)
    assert raised.value.reason == reason
    assert asked == ["os_user_presence"]


async def test_the_passphrase_fallback_names_the_passphrase_source() -> None:
    terminal = _Terminal()
    session = _Session()
    choice = unlock._AuthorizationChoice(
        prefer="secret_reauthentication", after_unavailable_dialog=True
    )
    target = owner_receipt_view_target(_REQUEST, "e" * 64)

    await unlock._drive_session(
        session,  # pyright: ignore[reportArgumentType]
        terminal,
        HumanCeremonyKind.OWNER_RECEIPT_VIEW,
        target,
        AuthorizationRequiredPhase(_BOTH),
        authorization=choice,
    )

    assert session.actions == [SelectAuthorizationSourceAction("secret_reauthentication")]
    assert choice.offered == _BOTH
    assert "No system confirmation dialog can be shown from here" in "".join(terminal.text)
