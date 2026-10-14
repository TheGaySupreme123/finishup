"""The owner's conversation setting at the egress gate (ADR-049).

An agent's switch is a request. Under ``local_agent_opt_in`` the owner's setup answer is the
standing permission, so an approved review dispatches on the baseline policy; under
``local_owner_approval`` every review waits for the owner's per-request decision, exactly like
per-request confirmation. Neither setting widens what may be sent.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from typing import Any, cast

import pytest
from tests.unit.application.test_data_use_evidence_runtime_guard import (
    _NOW,  # pyright: ignore[reportPrivateUsage]
    _SUBJECT,  # pyright: ignore[reportPrivateUsage]
    _candidate,  # pyright: ignore[reportPrivateUsage]
    _Classifier,  # pyright: ignore[reportPrivateUsage]
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _deadline,  # pyright: ignore[reportPrivateUsage]
    _Gateway,  # pyright: ignore[reportPrivateUsage]
    _human_authority,  # pyright: ignore[reportPrivateUsage]
    _Ids,  # pyright: ignore[reportPrivateUsage]
    _Store,  # pyright: ignore[reportPrivateUsage]
)

from builders.privacy_policies import minimal_external_policy
from builders.privacy_widenings import llm_channel
from finishup.application.egress import (
    PrivacyCoordinator,
    SemanticEgressAwaitingHuman,
)
from finishup.domain.privacy import ConsentSource, ConversationReview, PrivacyPolicy
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.privacy import (
    OutboundGatewayPort,
    PrivacyAuditPort,
    PrivacyClassifierPort,
    PrivacyPolicyStorePort,
)

_PROPOSAL = "ppr_80000000-0000-4000-8000-0000000000aa"


class _PreparingAudit:
    """Prepares one proposal and records the wait, so the gate decision is observable."""

    def __init__(self) -> None:
        self.awaiting: list[str] = []

    async def reserve(self, subject: object) -> object:
        del subject
        return SimpleNamespace(subject_digest=_SUBJECT)

    async def complete_decision(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    async def prepare_disclosure_proposal(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        return SimpleNamespace(
            proposal=SimpleNamespace(
                privacy_proposal_id=_PROPOSAL, expires_at=_NOW + timedelta(minutes=1)
            ),
            reservation=SimpleNamespace(subject_digest=_SUBJECT),
        )

    async def mark_awaiting_human(self, proposal_id: str) -> None:
        self.awaiting.append(proposal_id)


def _policy(setting: ConversationReview | None) -> PrivacyPolicy:
    return replace(minimal_external_policy(), conversation_review=setting)


async def _evaluate(
    monkeypatch: pytest.MonkeyPatch, setting: ConversationReview | None
) -> tuple[object, list[Any], list[str]]:
    policy = _policy(setting)
    binding = llm_channel(policy).provider_binding
    assert binding is not None
    assert not llm_channel(policy).preview_required
    audit = _PreparingAudit()
    coordinator = PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, _Store(policy)),
        cast(PrivacyClassifierPort, _Classifier()),
        cast(PrivacyAuditPort, audit),
        cast(OutboundGatewayPort, _Gateway()),
        cast(ClockPort, _Clock()),
        cast(IdPort, _Ids()),
        human_authority=_human_authority(),
    )
    dispatched: list[Any] = []

    async def dispatch(_self: object, *args: object, **kwargs: object) -> object:
        # (candidate, effective, proposal, minimized, consent source, deadline)
        dispatched.append(args[4])
        del kwargs
        return "dispatched"

    monkeypatch.setattr(PrivacyCoordinator, "_dispatch_approved", dispatch)
    result = await coordinator.evaluate_semantic(_candidate(binding), _deadline())
    return result, dispatched, audit.awaiting


@pytest.mark.anyio
@pytest.mark.parametrize(
    "setting", [ConversationReview.LOCAL_AGENT_OPT_IN, ConversationReview.AI_POWERED, None]
)
async def test_a_preauthorised_review_dispatches_on_the_baseline_policy(
    monkeypatch: pytest.MonkeyPatch, setting: ConversationReview | None
) -> None:
    result, dispatched, awaiting = await _evaluate(monkeypatch, setting)
    assert result == "dispatched"
    assert dispatched == [ConsentSource.BASELINE_POLICY]
    assert awaiting == []


@pytest.mark.anyio
async def test_owner_approval_makes_every_review_wait_for_the_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, dispatched, awaiting = await _evaluate(
        monkeypatch, ConversationReview.LOCAL_OWNER_APPROVAL
    )
    assert isinstance(result, SemanticEgressAwaitingHuman)
    assert result.privacy_proposal_id == _PROPOSAL
    assert dispatched == []
    assert awaiting == [_PROPOSAL]
