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
        ("passphrase_in_credential_store", "owner_view_unavailable", "--use-passphrase"),
        ("passphrase_unavailable", "owner_view_unavailable", "no passphrase"),
        ("ceremony_busy", "owner_view_busy", "it is not for this command"),
        ("reauthentication_rate_limited", "owner_view_refused", "waits before asking again"),
        ("trusted_console_required", "owner_view_requires_terminal", "Touch ID"),
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

    async def refuse(target: Any, **_kwargs: Any) -> Any:
        del target
        if reason in {
            "passphrase_in_credential_store",
            "passphrase_unavailable",
            "trusted_console_required",
        }:
            raise unlock.HumanCeremonyCliError(reason)
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


async def test_a_busy_service_names_this_commands_code_not_a_locked_vault(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """#1073 review P2-2: an agent's open ceremony must not read as a locked vault."""

    target = owner_receipt_view_target(_REQUEST, "e" * 64)

    class _Client:
        def owner_receipt_view_target(self, request: Any) -> Any:
            del request
            return target

    async def busy(target: Any, **_kwargs: Any) -> Any:
        del target
        raise ConfidentialClientError("ceremony_busy")

    monkeypatch.setattr(unlock, "authorize_owner_receipt_view", busy)
    await cli_app._authorize_owner_receipt_view(_Client(), _REQUEST)  # pyright: ignore[reportArgumentType]
    err = capsys.readouterr().err
    assert "locked" not in err and "service unlock" not in err
    assert f"would be {unlock.owner_view_confirmation_code(target)}." in err


async def test_on_macos_the_code_is_printed_before_anything_opens(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = owner_receipt_view_target(_REQUEST, "e" * 64)
    seen_before_open: list[str] = []

    async def run(kind: object, target_: object, **kwargs: Any) -> object:
        del kind, target_, kwargs
        seen_before_open.append(capsys.readouterr().err)
        return _GRANTED

    monkeypatch.setattr(unlock, "run_human_ceremony", run)
    monkeypatch.setattr(unlock.sys, "platform", "darwin")
    await unlock.authorize_owner_receipt_view(target)
    code = unlock.owner_view_confirmation_code(target)
    assert seen_before_open == [f"Confirmation code for this request: {code}\n"]


async def test_a_credential_store_passphrase_is_never_prompted_for() -> None:
    """#1073 review P2-3: setup's system-keychain passphrase was never shown to its owner."""

    terminal = _Terminal()  # read_secret would fail the test
    session = _Session()
    target = owner_receipt_view_target(_REQUEST, "e" * 64)
    choice = unlock._AuthorizationChoice(passphrase_allowed=lambda: False)
    with pytest.raises(unlock.HumanCeremonyCliError) as raised:
        await unlock._drive_session(
            session,  # pyright: ignore[reportArgumentType]
            terminal,
            HumanCeremonyKind.OWNER_RECEIPT_VIEW,
            target,
            AuthorizationRequiredPhase(("secret_reauthentication",)),
            authorization=choice,
        )
    assert raised.value.reason == "passphrase_in_credential_store"
    assert session.actions == []
    # Asked for explicitly, the passphrase is the only source used, never the dialog.
    explicit = unlock._AuthorizationChoice(
        prefer="secret_reauthentication", passphrase_only=True, passphrase_allowed=lambda: False
    )
    await unlock._drive_session(
        session,  # pyright: ignore[reportArgumentType]
        terminal,
        HumanCeremonyKind.OWNER_RECEIPT_VIEW,
        target,
        AuthorizationRequiredPhase(_BOTH),
        authorization=explicit,
    )
    assert session.actions == [SelectAuthorizationSourceAction("secret_reauthentication")]
    session.actions.clear()
    with pytest.raises(unlock.HumanCeremonyCliError) as unavailable:
        await unlock._drive_session(
            session,  # pyright: ignore[reportArgumentType]
            terminal,
            HumanCeremonyKind.OWNER_RECEIPT_VIEW,
            target,
            AuthorizationRequiredPhase(("os_user_presence",)),
            authorization=explicit,
        )
    assert unavailable.value.reason == "passphrase_unavailable"


async def test_use_passphrase_runs_one_passphrase_only_ceremony(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    choices: list[Any] = []

    async def run(kind: object, target: object, **kwargs: Any) -> object:
        del kind, target
        choices.append(kwargs["authorization"])
        return _GRANTED

    monkeypatch.setattr(unlock, "run_human_ceremony", run)
    target = owner_receipt_view_target(_REQUEST, "e" * 64)
    assert await unlock.authorize_owner_receipt_view(target, use_passphrase=True) == _GRANTED
    (choice,) = choices
    assert choice.passphrase_only and choice.prefer == "secret_reauthentication"


async def test_the_dialog_fallback_keeps_the_credential_store_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    choices: list[Any] = []
    outcomes: list[object] = [ConfidentialClientError("presence_unavailable"), _GRANTED]

    async def run(kind: object, target: object, **kwargs: Any) -> object:
        del kind, target
        choice = kwargs["authorization"]
        choice.offered = _BOTH
        choices.append(choice)
        outcome = outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(unlock, "run_human_ceremony", run)
    monkeypatch.setattr(unlock, "vault_passphrase_held_by_credential_store", lambda: True)
    target = owner_receipt_view_target(_REQUEST, "e" * 64)
    await unlock.authorize_owner_receipt_view(target)
    first, second = choices
    assert first.passphrase_allowed is not None and first.passphrase_allowed() is False
    assert second.prefer == "secret_reauthentication"
    assert second.passphrase_allowed is first.passphrase_allowed


def test_the_credential_store_check_reads_one_slot_and_wipes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.adapters.keys import os_keyring

    loaded: list[bytearray] = []

    def present(self: object) -> tuple[bytearray | None, str]:
        del self
        value = bytearray(b"generated-passphrase-value")
        loaded.append(value)
        return value, "ok"

    monkeypatch.setattr(os_keyring.AutoUnlockPassphraseStore, "load_with_reason", present)
    assert unlock.vault_passphrase_held_by_credential_store() is True
    assert loaded and loaded[0] == bytearray(len(loaded[0]))  # overwritten

    def absent(self: object) -> tuple[bytearray | None, str]:
        del self
        return None, "auto_unlock_absent"

    monkeypatch.setattr(os_keyring.AutoUnlockPassphraseStore, "load_with_reason", absent)
    assert unlock.vault_passphrase_held_by_credential_store() is False

    def broken(self: object) -> tuple[bytearray | None, str]:
        del self
        raise RuntimeError("backend")

    # #1073 review round 2: a store that cannot be asked, or refuses, may hold a passphrase
    # its owner never saw, so it fails closed.
    monkeypatch.setattr(os_keyring.AutoUnlockPassphraseStore, "load_with_reason", broken)
    assert unlock.vault_passphrase_held_by_credential_store() is True

    def rejected(self: object) -> tuple[bytearray | None, str]:
        del self
        return None, "auto_unlock_rejected"

    monkeypatch.setattr(os_keyring.AutoUnlockPassphraseStore, "load_with_reason", rejected)
    assert unlock.vault_passphrase_held_by_credential_store() is True

    def no_store(self: object) -> tuple[bytearray | None, str]:
        del self
        return None, "auto_unlock_backend_unavailable"

    monkeypatch.setattr(os_keyring.AutoUnlockPassphraseStore, "load_with_reason", no_store)
    assert unlock.vault_passphrase_held_by_credential_store() is False


async def test_a_passphrase_the_owner_typed_is_still_asked_for() -> None:
    """The other vault kind: no credential-store entry, so the passphrase source is used."""

    session = _Session()
    target = owner_receipt_view_target(_REQUEST, "e" * 64)
    asked: list[bool] = []

    def allowed() -> bool:
        asked.append(True)
        return True

    await unlock._drive_session(
        session,  # pyright: ignore[reportArgumentType]
        _Terminal(),
        HumanCeremonyKind.OWNER_RECEIPT_VIEW,
        target,
        AuthorizationRequiredPhase(("secret_reauthentication",)),
        authorization=unlock._AuthorizationChoice(passphrase_allowed=allowed),
    )
    assert asked == [True]
    assert session.actions == [SelectAuthorizationSourceAction("secret_reauthentication")]


def test_busy_and_throttled_directives_never_ask_for_approval() -> None:
    """#1073 review round 2, P2-2: the directives must agree with the refusal text."""

    from yoetz.cli.exits import ceremony_refusal_message
    from yoetz.protocol.recovery import RECOVERY_DIRECTIVES, continuation_for_local_reason

    busy = continuation_for_local_reason("ceremony_busy")
    throttled = continuation_for_local_reason("reauthentication_rate_limited")
    assert busy == "ceremony_in_progress"
    assert throttled == "ceremony_retry_after_wait"
    busy_text = RECOVERY_DIRECTIVES["ceremony_in_progress"].directive
    # Agents cannot see the screen: they report and let the owner decide (#1073 round 3).
    assert "let the owner decide" in busy_text and "Do not approve" in busy_text
    assert "Authorize" not in busy_text and "service restart" not in busy_text
    wait_text = RECOVERY_DIRECTIVES["ceremony_retry_after_wait"].directive
    assert "five minutes" in wait_text and "policy" not in wait_text
    assert "five minutes" in (ceremony_refusal_message("reauthentication_rate_limited") or "")
    assert "yoetz service restart" in (ceremony_refusal_message("ceremony_busy") or "")


async def test_a_passphrase_throttle_is_not_described_as_the_dialog_backoff(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """#1073 review round 3, T2: on Linux, or with --use-passphrase, the wait is the durable
    passphrase throttle: a restart does not clear it and --use-passphrase is not a way out."""

    async def run(kind: object, target: object, **kwargs: Any) -> object:
        del kind, target
        choice = kwargs["authorization"]
        choice.offered = ("secret_reauthentication",)
        choice.selected = "secret_reauthentication"
        raise ConfidentialClientError("reauthentication_rate_limited")

    monkeypatch.setattr(unlock, "run_human_ceremony", run)
    target = owner_receipt_view_target(_REQUEST, "e" * 64)
    for use_passphrase in (True, False):
        with pytest.raises(unlock.HumanCeremonyCliError) as raised:
            await unlock.authorize_owner_receipt_view(target, use_passphrase=use_passphrase)
        assert raised.value.reason == "passphrase_rate_limited"

    class _Client:
        def owner_receipt_view_target(self, request: Any) -> Any:
            del request
            return target

    code = await cli_app._authorize_owner_receipt_view(  # pyright: ignore[reportPrivateUsage]
        _Client(),
        _REQUEST,  # pyright: ignore[reportArgumentType]
        use_passphrase=True,
    )
    assert code is not None and code != 0
    err = capsys.readouterr().err
    assert "wrong passphrases" in err and "does not clear" in err
    assert "--use-passphrase" not in err and "clears the wait" not in err


async def test_a_dialog_backoff_keeps_its_own_remedies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run(kind: object, target: object, **kwargs: Any) -> object:
        del kind, target
        choice = kwargs["authorization"]
        choice.offered = ("os_user_presence",)
        choice.selected = "os_user_presence"
        raise ConfidentialClientError("reauthentication_rate_limited")

    monkeypatch.setattr(unlock, "run_human_ceremony", run)
    target = owner_receipt_view_target(_REQUEST, "e" * 64)
    with pytest.raises(ConfidentialClientError) as raised:
        await unlock.authorize_owner_receipt_view(target)
    assert raised.value.reason == "reauthentication_rate_limited"
    assert "service restart" in cli_app._OWNER_VIEW_REFUSALS["reauthentication_rate_limited"]  # pyright: ignore[reportPrivateUsage]


def test_the_credential_store_refusal_does_not_claim_more_than_it_knows() -> None:
    """#1073 review round 3: the check also fails closed when the store cannot be read, so the
    refusal says the passphrase may be kept there, not that it is."""

    refusals = cli_app._OWNER_VIEW_REFUSALS  # pyright: ignore[reportPrivateUsage]
    cli_text = refusals["passphrase_in_credential_store"]
    assert "may be kept in the system credential store" in cli_text
    assert "could not be read" in cli_text
    assert "is kept in the system credential store" not in cli_text
