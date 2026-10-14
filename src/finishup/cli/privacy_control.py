"""Trusted foreground privacy preview and decision helper."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

from finishup.cli.unlock import (
    HumanCeremonyCliError,
    _cancel_quietly,  # pyright: ignore[reportPrivateUsage]
    _drive_session,  # pyright: ignore[reportPrivateUsage]
    _ForegroundTerminal,  # pyright: ignore[reportPrivateUsage]
    _render_preview,  # pyright: ignore[reportPrivateUsage]
    _SuppliedSecretTerminal,  # pyright: ignore[reportPrivateUsage]
    _verify_preview,  # pyright: ignore[reportPrivateUsage]
    overwrite_secret_buffer,
)
from finishup.service.confidential_client import (
    ConfidentialClientError,
    ConfidentialResultUnconfirmed,
    HumanControlClient,
)
from finishup.service.confidential_protocol import (
    DecisionAction,
    DecisionRequiredPhase,
    HumanCeremonyKind,
    PrivacyDecisionResult,
    PrivacyDisclosureDecisionPreview,
    PrivacyPendingTarget,
    PrivacyPolicyDecisionPreview,
)

__all__ = [
    "PrivacyLocalEditResult",
    "PrivacyDecisionUnconfirmed",
    "decide_disclosure",
    "decide_policy",
    "decide_policy_with_local_reauthentication",
]


class PrivacyDecisionUnconfirmed(ConfidentialClientError):
    """A privacy decision was attempted but no authoritative result was received."""


_UNCONFIRMED_AFTER_DECISION_REASONS = frozenset(
    {"ambiguous", "correlation_mismatch", "protocol_error", "service_unavailable", "timeout"}
)


@dataclass(frozen=True, slots=True)
class PrivacyLocalEditResult:
    outcome: Literal["edit"] = "edit"

    def __post_init__(self) -> None:
        if self.outcome != "edit":
            raise ValueError("privacy_local_edit_result_invalid")


async def _decide(
    decision_kind: Literal["policy", "disclosure"],
    pending_id: str,
    *,
    passphrase: bytearray | None = None,
) -> PrivacyDecisionResult | PrivacyLocalEditResult:
    target = PrivacyPendingTarget(decision_kind, pending_id)
    kind = (
        HumanCeremonyKind.PRIVACY_POLICY_DECISION
        if decision_kind == "policy"
        else HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION
    )
    client = HumanControlClient()
    with _ForegroundTerminal() as terminal:
        try:
            session = await client.open(kind, target)
            async with session:
                try:
                    preview = _verify_preview(kind, target, session)
                    if decision_kind == "policy":
                        if type(preview) is not PrivacyPolicyDecisionPreview:
                            raise HumanCeremonyCliError("preview_invalid")
                    elif (
                        type(preview) is not PrivacyDisclosureDecisionPreview
                        or preview.authorization_change != "none"
                    ):
                        raise HumanCeremonyCliError("preview_invalid")
                    _render_preview(terminal, preview)
                    selected = terminal.read_choice(
                        "Decision [approve/deny/edit]: ",
                        (b"approve", b"deny", b"edit"),
                    )
                    if selected == b"edit":
                        await session.cancel()
                        terminal.write(
                            "No decision was sent. Edit locally and create a new proposal.\n"
                        )
                        return PrivacyLocalEditResult()
                    decision: Literal["approve", "deny"] = (
                        "approve" if selected == b"approve" else "deny"
                    )
                    await session.send_action(DecisionAction(decision))
                    current = await session.wait_phase_or_result()
                    if decision_kind == "disclosure":
                        if type(current) is not PrivacyDecisionResult:
                            raise HumanCeremonyCliError("result_invalid")
                        return current
                    result, observed_decision = await _drive_session(
                        session,
                        terminal,
                        kind,
                        target,
                        current,
                        passphrase=passphrase,
                    )
                    if observed_decision is not None:
                        raise HumanCeremonyCliError("result_invalid")
                    return cast(PrivacyDecisionResult, result)
                except BaseException:
                    await _cancel_quietly(session)
                    raise
        finally:
            await client.close()


async def decide_policy(
    pending_id: str,
    *,
    decision: Literal["approve", "deny"] | None = None,
    passphrase: bytearray | None = None,
) -> PrivacyDecisionResult | PrivacyLocalEditResult:
    """Decide one exact pending durable-policy proposal on the controlling TTY.

    When ``decision`` and ``passphrase`` are both supplied, the ceremony runs without
    prompting (same trust boundary as ``unlock_vault(passphrase=...)``).
    """

    if (decision is None) != (passphrase is None):
        if passphrase is not None:
            overwrite_secret_buffer(passphrase)
        raise ValueError("privacy_decision_supplied_pair_invalid")
    if decision is not None and passphrase is not None:
        return await _decide_policy_supplied(pending_id, decision, passphrase)
    return await _decide("policy", pending_id)


async def decide_policy_with_local_reauthentication(
    pending_id: str,
    passphrase: bytearray,
) -> PrivacyDecisionResult | PrivacyLocalEditResult:
    """Keep policy approval explicit while using a provisioned local unlock secret.

    The caller obtains the secret from the same per-installation platform store
    used for restart auto-unlock.  The policy preview and approve/deny decision
    still happen on the controlling terminal; only the subsequent
    reauthentication secret is supplied without asking a user to know a
    generated value.
    """

    try:
        return await _decide("policy", pending_id, passphrase=passphrase)
    finally:
        overwrite_secret_buffer(passphrase)


async def _decide_policy_supplied(
    pending_id: str,
    decision: Literal["approve", "deny"],
    passphrase: bytearray,
) -> PrivacyDecisionResult:
    target = PrivacyPendingTarget("policy", pending_id)
    kind = HumanCeremonyKind.PRIVACY_POLICY_DECISION
    client = HumanControlClient()
    terminal = _SuppliedSecretTerminal()
    session = None
    try:
        session = await client.open(kind, target)
        async with session:
            try:
                preview = _verify_preview(kind, target, session)
                if type(preview) is not PrivacyPolicyDecisionPreview:
                    raise HumanCeremonyCliError("preview_invalid")
                current = session.opened.phase
                if type(current) is DecisionRequiredPhase:
                    await session.send_action(DecisionAction(decision))
                    current = await session.wait_phase_or_result()
                result, _observed = await _drive_session(
                    session,
                    _DecisionTerminal(terminal, decision),
                    kind,
                    target,
                    current,
                    passphrase=passphrase,
                )
                return cast(PrivacyDecisionResult, result)
            except ConfidentialResultUnconfirmed:
                await _cancel_quietly(session)
                raise
            except ConfidentialClientError as exc:
                await _cancel_quietly(session)
                if session.decision_attempted and exc.reason in _UNCONFIRMED_AFTER_DECISION_REASONS:
                    raise PrivacyDecisionUnconfirmed("ambiguous") from exc
                raise
            except BaseException:
                await _cancel_quietly(session)
                raise
    finally:
        await client.close()
        overwrite_secret_buffer(passphrase)


class _DecisionTerminal:
    """Supplied-secret terminal that answers one exact approve/deny choice.

    Every prompt other than the decision stays non-prompting: the wrapped supplied-secret
    terminal refuses to read, so a ceremony that asks for anything unsupplied fails closed.
    """

    __slots__ = ("_decision", "_inner")

    def __init__(
        self, inner: _SuppliedSecretTerminal, decision: Literal["approve", "deny"]
    ) -> None:
        self._inner = inner
        self._decision = decision.encode("ascii")

    def write(self, value: str) -> None:
        self._inner.write(value)

    def write_secret(self, value: bytearray) -> None:
        self._inner.write_secret(value)

    def read_secret(self, prompt: str, maximum: int) -> bytearray:
        return self._inner.read_secret(prompt, maximum)

    def read_choice(self, prompt: str, allowed: tuple[bytes, ...]) -> bytes:
        del prompt
        if self._decision not in allowed:
            raise HumanCeremonyCliError("input_invalid")
        return self._decision


async def decide_disclosure(
    pending_id: str,
) -> PrivacyDecisionResult | PrivacyLocalEditResult:
    """Decide one exact within-policy disclosure on the controlling TTY."""

    return await _decide("disclosure", pending_id)
