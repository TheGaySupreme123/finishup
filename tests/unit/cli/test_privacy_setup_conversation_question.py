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
        grant_state="granted",
        conversations=conversations,
    )
    proposed = _capture(monkeypatch)
    await module.run_privacy_setup(recipe_hint="assisted_review")
    assert conversations == []
    assert all(policy.conversation_review is None for policy in proposed)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("inherited", "default"),
    [
        (None, ConversationReview.LOCAL_AGENT_OPT_IN),
        (ConversationReview.AI_POWERED, ConversationReview.LOCAL_AGENT_OPT_IN),
        (ConversationReview.LOCAL_ONLY, ConversationReview.LOCAL_ONLY),
    ],
)
async def test_a_first_repository_grant_asks_even_where_the_installation_already_sends_work(
    monkeypatch: pytest.MonkeyPatch,
    inherited: ConversationReview | None,
    default: ConversationReview,
) -> None:
    """Review round 1 (P2-7): a new repository is asked, whatever the installation row says.

    Its composed policy is the installation row (inference on). The question starts on the
    recommended answer, or on the installation's own explicit setting where that is narrower.
    """

    from dataclasses import replace

    conversations: list[ConversationReview] = []
    _install_setup_stubs(
        monkeypatch,
        current=replace(minimal_external_policy(), conversation_review=inherited),
        confirmations=iter((True,)),
        prompts=[],
        external=_external(),
        grant_state="missing",
        conversations=conversations,
    )
    proposed = _capture(monkeypatch)
    await module.run_privacy_setup(recipe_hint="assisted_review")
    assert conversations == [default]
    assert [policy.conversation_review for policy in proposed] == [default]


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


@pytest.mark.anyio
async def test_choosing_private_while_adding_ai_review_warns_that_opt_in_stays_local(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review round 1 (P2-3): Private stays selectable but says what it means for agents."""

    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=[],
        external=_external(),
    )

    def choice(hint: object) -> str:
        # The add-on list starts on Assisted review; the owner picks Private instead.
        assert hint == "assisted_review"
        return "private"

    monkeypatch.setattr(module, "_recipe_choice", choice)
    _capture(monkeypatch)
    await module.run_privacy_setup(
        ai_review_add_on=True, conversation_review=ConversationReview.LOCAL_AGENT_OPT_IN
    )
    assert module.PRIVATE_ADD_ON_WARNING in capsys.readouterr().out


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("setting", "expected_default"),
    [(ConversationReview.LOCAL_ONLY, True), (None, False)],
)
async def test_the_local_only_answer_applies_on_enter(
    monkeypatch: pytest.MonkeyPatch,
    setting: ConversationReview | None,
    expected_default: bool,
) -> None:
    """Review round 1 (P3): the explicit local-only answer is a narrowing the owner chose.

    Its Private confirmation defaults to Yes, so pressing Enter cannot leave an existing grant
    reviewing every task; a plain Private draft keeps its released default (No).
    """

    _install_setup_stubs(
        monkeypatch,
        current=minimal_external_policy(),
        confirmations=iter(()),
        prompts=[],
        external=_external(),
        grant_state="granted",
    )
    defaults: list[bool] = []

    def confirm(_prompt: str, *, default: bool = False) -> bool:
        defaults.append(default)
        return default

    monkeypatch.setattr(module.typer, "confirm", confirm)
    _capture(monkeypatch)
    await module.run_privacy_setup(recipe_hint="private", conversation_review=setting)
    assert defaults == [expected_default]


@pytest.mark.parametrize(
    ("inherited", "first_grant", "expected"),
    [
        (ConversationReview.AI_POWERED, True, ConversationReview.LOCAL_AGENT_OPT_IN),
        (None, True, ConversationReview.LOCAL_AGENT_OPT_IN),
        (ConversationReview.LOCAL_ONLY, True, ConversationReview.LOCAL_ONLY),
        (ConversationReview.AI_POWERED, False, ConversationReview.AI_POWERED),
        (None, False, None),
    ],
)
def test_a_candidate_for_a_first_grant_starts_on_the_first_grant_default(
    inherited: ConversationReview | None,
    first_grant: bool,
    expected: ConversationReview | None,
) -> None:
    """ADR-049 review round 2: the chat grant path asks no question, so the candidate decides."""

    from dataclasses import replace
    from datetime import UTC, datetime

    current = replace(minimal_external_policy(), conversation_review=inherited)
    answers = module.recipe_answers("assisted_review", current, _external())
    candidate = module.build_candidate_policy(
        current, answers, now=datetime(2026, 10, 15, tzinfo=UTC), first_grant=first_grant
    )
    assert candidate.conversation_review is expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("current_setting", "grant_state", "bound", "add_on"),
    [
        # A first grant here, with a reviewer bound: the AI-powered review listing.
        (None, "missing", True, True),
        (ConversationReview.LOCAL_AGENT_OPT_IN, "missing", True, True),
        # The hybrid (or owner approval) with a grant: agent opt-in needs a reviewing recipe.
        (ConversationReview.LOCAL_AGENT_OPT_IN, "granted", True, True),
        (ConversationReview.LOCAL_OWNER_APPROVAL, "granted", True, True),
        # Released behaviour: an unset setting with a grant, or no reviewer bound.
        (None, "granted", True, False),
        (ConversationReview.LOCAL_AGENT_OPT_IN, "missing", False, False),
    ],
)
async def test_finishup_privacy_lists_the_ai_recipes_where_agent_opt_in_needs_them(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    current_setting: ConversationReview | None,
    grant_state: str,
    bound: bool,
    add_on: bool,
) -> None:
    """Review round 3 (P2-B): `finishup --privacy` no longer grants Private on Enter there.

    Status sends an owner whose agent's opt-in stays local to `finishup --privacy`. With a
    reviewer bound, on a first grant here or under the hybrid or owner approval, it lists the
    AI-powered review recipes (Assisted review by default, no recommendation for an unreviewed
    route, the Private warning); otherwise it keeps its released recommendation.
    """

    from dataclasses import replace

    _install_setup_stubs(
        monkeypatch,
        current=replace(local_only_policy(), conversation_review=current_setting),
        confirmations=iter((True, True)),
        prompts=[],
        external=_external() if bound else None,
        grant_state=grant_state,  # pyright: ignore[reportArgumentType]
    )
    hints: list[object] = []

    def choice(hint: object) -> str:
        hints.append(hint)
        return "private"

    monkeypatch.setattr(module, "_recipe_choice", choice)
    _capture(monkeypatch)
    await module.run_privacy_setup(
        recipe_hint="assisted_review", offer_recommended=True, ai_review_add_on_when_hybrid=True
    )
    out = capsys.readouterr().out
    assert ("Add AI-powered review" in out) is add_on
    assert ("Recommended policy:" in out) is (not add_on)
    if add_on:
        assert hints == ["assisted_review"]
        assert module.PRIVATE_ADD_ON_WARNING in out


def test_the_privacy_command_asks_for_the_ai_listing_where_it_applies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from typer.testing import CliRunner

    from finishup.cli.app import app

    seen: list[dict[str, object]] = []

    async def run_setup(**kwargs: object) -> module.PrivacySetupReport:
        seen.append(kwargs)
        return module.PrivacySetupReport("unchanged", "local_only")

    monkeypatch.setattr(module, "run_privacy_setup", run_setup)
    result = CliRunner().invoke(app, ["--privacy"])
    assert result.exit_code == 0, result.output
    assert seen and seen[0].get("ai_review_add_on_when_hybrid") is True


def test_a_first_private_grant_inherits_no_hybrid() -> None:
    """Review round 3 (P3): a grant that sends nothing records no setting on a first grant."""

    from dataclasses import replace
    from datetime import UTC, datetime

    inherited = replace(
        local_only_policy(), conversation_review=ConversationReview.LOCAL_AGENT_OPT_IN
    )
    answers = module.recipe_answers("private", inherited, _external())
    candidate = module.build_candidate_policy(
        inherited, answers, now=datetime(2026, 10, 15, tzinfo=UTC), first_grant=True
    )
    assert candidate.conversation_review is None
    assert candidate.effective_conversation_review is ConversationReview.LOCAL_ONLY


@pytest.mark.anyio
async def test_the_terminal_path_tells_the_candidate_it_is_a_first_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The terminal confirmation builds the same candidate the chat path does."""

    from dataclasses import replace

    _install_setup_stubs(
        monkeypatch,
        current=replace(
            local_only_policy(), conversation_review=ConversationReview.LOCAL_AGENT_OPT_IN
        ),
        confirmations=iter((True,)),
        prompts=[],
        external=_external(),
        grant_state="missing",
    )
    proposed = _capture(monkeypatch)
    await module.run_privacy_setup(recipe_hint="private")
    assert [policy.conversation_review for policy in proposed] == [None]
