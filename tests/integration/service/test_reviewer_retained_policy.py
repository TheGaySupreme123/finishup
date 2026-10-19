"""#1118 R1: read results a conversation retains answer to the policy they were admitted under.

Through the real composition and privacy coordinator (only the provider is scripted): once a read
result is held, a withdrawn category, or an exchange under another policy generation, ends the
conversation honestly incomplete, and the retained bytes are never sent again.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from finishup.application.egress import PrivacyCoordinator
from finishup.domain.privacy import EgressChannel
from finishup.ports.privacy import EffectivePrivacyPolicy
from finishup.protocol.models import DataCategory, SemanticStatus
from integration.service import test_reviewer_conversation_composition as c

pytestmark = pytest.mark.anyio


def _narrowed(old: EffectivePrivacyPolicy, category: DataCategory) -> EffectivePrivacyPolicy:
    channels = tuple(
        replace(ch, allowed_categories=tuple(x for x in ch.allowed_categories if x is not category))
        if ch.channel is EgressChannel.LLM_INFERENCE
        else ch
        for ch in old.policy.channel_policies
    )
    narrowed = replace(
        old.policy,
        channel_policies=channels,
        version=old.policy.version + 1,
        policy_digest="sha256:" + "7" * 64,
    )
    return EffectivePrivacyPolicy(narrowed, old.generation + 1, narrowed.policy_digest)


async def test_a_retained_read_is_not_resent_after_its_category_is_withdrawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admit = PrivacyCoordinator.admit_reviewer_read

    async def admit_then_narrow(self: PrivacyCoordinator, *args: Any, **kwargs: Any) -> object:
        reason = await admit(self, *args, **kwargs)
        assert reason is None
        store: Any = self._policies  # pyright: ignore[reportPrivateUsage]
        store._effective = _narrowed(store._effective, DataCategory.REPOSITORY_EXCERPT)
        return reason

    monkeypatch.setattr(PrivacyCoordinator, "admit_reviewer_read", admit_then_narrow)
    result, gateway, _ = await c._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        c._read_file("calc.py"),  # pyright: ignore[reportPrivateUsage]
        c._FINAL,  # pyright: ignore[reportPrivateUsage]
    )
    # Only the first exchange left; the admitted read result never did.
    assert len(gateway.exchanges) == 1
    assert result.status is SemanticStatus.BLOCKED_BY_POLICY and result.judgment is None
    assert result.reviewer is not None and result.reviewer.ended == "authorization_changed"
    assert result.reviewer.reads[0].disclosure is None


async def test_an_exchange_under_another_policy_generation_is_refused_once_reads_are_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exchange admission itself refuses, even when the turn's own recheck has passed."""

    admit = PrivacyCoordinator.admit_reviewer_read
    current = PrivacyCoordinator.reviewer_history_current

    async def admit_then_bump(self: PrivacyCoordinator, *args: Any, **kwargs: Any) -> object:
        reason = await admit(self, *args, **kwargs)
        store: Any = self._policies  # pyright: ignore[reportPrivateUsage]
        old = store._effective
        # Same rules, a new generation and digest: the conversation's binding no longer holds.
        bumped = replace(
            old.policy, version=old.policy.version + 1, policy_digest="sha256:" + "6" * 64
        )
        store._effective = EffectivePrivacyPolicy(bumped, old.generation + 1, bumped.policy_digest)
        return reason

    async def always_current(self: PrivacyCoordinator, *args: Any, **kwargs: Any) -> bool:
        await current(self, *args, **kwargs)
        return True

    monkeypatch.setattr(PrivacyCoordinator, "admit_reviewer_read", admit_then_bump)
    monkeypatch.setattr(PrivacyCoordinator, "reviewer_history_current", always_current)
    result, gateway, _ = await c._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        c._read_file("calc.py"),  # pyright: ignore[reportPrivateUsage]
        c._FINAL,  # pyright: ignore[reportPrivateUsage]
    )
    assert len(gateway.exchanges) == 1
    assert result.status is SemanticStatus.BLOCKED_BY_POLICY
    assert result.reviewer is not None and result.reviewer.ended == "reviewer_exchange_not_sent"
    assert result.reviewer.exchanges == 2 and result.reviewer.reads[0].disclosure is None
