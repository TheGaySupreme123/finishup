"""How a privacy draft carries the owner's conversation setting (ADR-049)."""

from __future__ import annotations

from typing import cast

import pytest
from tests.unit.cli.test_privacy_setup import (
    _answers,  # pyright: ignore[reportPrivateUsage]
    _install_setup_stubs,  # pyright: ignore[reportPrivateUsage]
)

import finishup.cli.privacy_setup as module
from builders.privacy_policies import local_only_policy, minimal_external_policy
from finishup.domain.privacy import ConversationReview, PrivacyPolicy, ProviderBinding


def _capture(monkeypatch: pytest.MonkeyPatch) -> list[PrivacyPolicy]:
    proposed: list[PrivacyPolicy] = []

    async def propose(candidate: PrivacyPolicy, _digest: str, **_: object) -> str:
        proposed.append(candidate)
        return "pvp_1"

    monkeypatch.setattr(module, "_propose", propose)
    return proposed


def _external() -> ProviderBinding:
    return cast(ProviderBinding, _answers().external_provider)


@pytest.mark.anyio
async def test_a_first_ai_grant_asks_once_and_recommends_the_hybrid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conversations: list[ConversationReview] = []
    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=[],
        external=_external(),
        conversations=conversations,
    )
    proposed = _capture(monkeypatch)
    report = await module.run_privacy_setup(recipe_hint="assisted_review")
    assert report.outcome == "configured"
    assert conversations == [ConversationReview.LOCAL_AGENT_OPT_IN]
    assert [policy.conversation_review for policy in proposed] == [
        ConversationReview.LOCAL_AGENT_OPT_IN
    ]


@pytest.mark.anyio
async def test_declining_the_recommendation_does_not_ask_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conversations: list[ConversationReview] = []
    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((False, True)),
        prompts=[],
        external=_external(),
        conversations=conversations,
    )

    def recommended(*_args: object, **_kwargs: object) -> str:
        return "assisted_review"

    def choice(_hint: object) -> str:
        return "expanded_review"

    monkeypatch.setattr(module, "recommended_privacy_recipe", recommended)
    monkeypatch.setattr(module, "_recipe_choice", choice)
    proposed = _capture(monkeypatch)
    await module.run_privacy_setup(offer_recommended=True)
    assert conversations == [ConversationReview.LOCAL_AGENT_OPT_IN]
    assert proposed[-1].conversation_review is ConversationReview.LOCAL_AGENT_OPT_IN


@pytest.mark.anyio
async def test_reapproving_a_policy_that_already_sends_work_keeps_its_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An existing AI-powered review policy is not asked, and its setting stays unset."""

    conversations: list[ConversationReview] = []
    current = minimal_external_policy()
    _install_setup_stubs(
        monkeypatch,
        current=current,
        confirmations=iter((True,)),
        prompts=[],
        external=_external(),
        conversations=conversations,
    )
    proposed = _capture(monkeypatch)
    await module.run_privacy_setup(recipe_hint="assisted_review")
    assert conversations == []
    assert all(policy.conversation_review is None for policy in proposed)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("recipe", "setting"),
    [
        ("assisted_review", ConversationReview.LOCAL_AGENT_OPT_IN),
        ("assisted_review", ConversationReview.AI_POWERED),
        ("private", ConversationReview.LOCAL_ONLY),
    ],
)
async def test_a_setup_answer_is_drafted_without_asking_again(
    monkeypatch: pytest.MonkeyPatch, recipe: str, setting: ConversationReview
) -> None:
    conversations: list[ConversationReview] = []
    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=[],
        external=_external(),
        conversations=conversations,
    )
    proposed = _capture(monkeypatch)
    await module.run_privacy_setup(
        recipe_hint=cast(module.PrivacyRecipe, recipe), conversation_review=setting
    )
    assert conversations == []
    assert [policy.conversation_review for policy in proposed] == [setting]


def test_the_review_screen_names_the_setting_in_task_words(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from dataclasses import replace

    render = getattr(module, "_render_review")
    render(replace(minimal_external_policy(), conversation_review=ConversationReview.LOCAL_ONLY))
    out = capsys.readouterr().out
    assert "Tasks and AI-powered review: local checks only; agents may not turn on" in out
