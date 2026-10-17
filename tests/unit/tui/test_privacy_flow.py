"""``/privacy`` selects a policy; it never authorizes one.

The interface used to take its own approval for a widening and then hand over to a second,
differently worded approval in the trusted terminal. Only the second one gated anything, so the
first taught users that clicking "yes" in an untrusted surface is what changes privacy. These
tests pin the replacement: one recommendation, a plain selection, and a handoff — with the exact
``before → after`` diff and the actual authorization living in the trusted terminal ceremony.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from finishup.tui.app import FinishUpTui
from finishup.tui.models import PrivacyPosture, PrivacyRecommendation
from finishup.tui.symbols import Level
from finishup.tui.widgets.views import BaseView, SelectionView


class _Runtime:
    """Only the two privacy questions ``command_privacy`` asks."""

    def __init__(self, posture: PrivacyPosture, recommendation: PrivacyRecommendation) -> None:
        self._posture = posture
        self._recommendation = recommendation

    async def privacy_posture(self) -> PrivacyPosture:
        return self._posture

    def privacy_recommendation(
        self, _posture: PrivacyPosture | None = None
    ) -> PrivacyRecommendation:
        return self._recommendation

    def project_root(self) -> str:
        return "/srv/finishup"


class _Harness:
    """A ``FinishUpTui`` with the mounted-widget surfaces replaced by recording stubs."""

    def __init__(self, posture: PrivacyPosture, recommendation: PrivacyRecommendation) -> None:
        runtime = _Runtime(posture, recommendation)
        self.app = FinishUpTui(runtime)  # pyright: ignore[reportArgumentType]
        self.said: list[tuple[Level, str, tuple[str, ...]]] = []
        self.views: list[SelectionView] = []
        self.answers: list[str | None] = []
        self.handed: list[str] = []

        def say(
            level: Level,
            title: str,
            body: Sequence[str] = (),
            *,
            details: Sequence[str] = (),
        ) -> None:
            del details
            self.said.append((level, title, tuple(body)))

        async def ask(view: BaseView) -> str | None:
            assert type(view) is SelectionView
            self.views.append(view)
            return self.answers.pop(0)

        async def hand_over(recipe: str) -> None:
            self.handed.append(recipe)

        self.app.say = say  # pyright: ignore[reportAttributeAccessIssue]
        self.app.ask = ask  # pyright: ignore[reportAttributeAccessIssue]
        self.app._hand_privacy_to_trusted_terminal = hand_over  # pyright: ignore[reportAttributeAccessIssue, reportPrivateUsage]

    def choices(self, index: int) -> list[str]:
        return [option.key for option in self.views[index].options]

    @property
    def transcript(self) -> str:
        return "\n".join(f"{title}\n" + "\n".join(body) for _level, title, body in self.said)


def _posture(
    profile: str | None = "minimal_external",
    *,
    grant_state: str | None = None,
    migration_state: str | None = None,
) -> PrivacyPosture:
    return PrivacyPosture(
        profile=profile,
        llm_inference_enabled=True,
        readable=True,
        repository_grant_state=grant_state,  # pyright: ignore[reportArgumentType]
        repository_migration_state=migration_state,
    )


def _recommendation(recipe: str = "metadata_only") -> PrivacyRecommendation:
    return PrivacyRecommendation(recipe, "Because it discloses the least.", "It costs detail.")


@pytest.mark.anyio
async def test_privacy_leads_with_the_current_posture_and_the_recommendation() -> None:
    harness = _Harness(_posture(), _recommendation())
    harness.answers = [None]

    await harness.app.command_privacy()

    assert "Currently: minimal external review" in harness.transcript
    assert "Recommended: Metadata only" in harness.transcript
    assert "Because it discloses the least." in harness.transcript
    # A recommendation without its cost is advice, not a choice.
    assert "It costs detail." in harness.transcript
    assert harness.choices(0) == ["keep", "recommended", "other"]


@pytest.mark.anyio
async def test_privacy_names_repository_grant_and_automatic_migration_without_identity() -> None:
    harness = _Harness(
        _posture(grant_state="granted", migration_state="consumed"),
        _recommendation(),
    )
    harness.answers = [None]

    await harness.app.command_privacy()

    assert "Repository grant: granted for this repository" in harness.transcript
    assert "carried forward and narrowed" in harness.transcript
    assert "sha256:" not in harness.transcript
    assert "/srv/finishup" not in harness.transcript


@pytest.mark.anyio
async def test_no_configured_provider_recommends_private() -> None:
    harness = _Harness(_posture("local_only"), _recommendation("private"))
    harness.answers = [None]

    await harness.app.command_privacy()

    assert "Recommended: Private" in harness.transcript


@pytest.mark.anyio
async def test_selecting_the_recommendation_hands_it_straight_to_the_trusted_terminal() -> None:
    harness = _Harness(_posture(), _recommendation())
    harness.answers = ["recommended"]

    await harness.app.command_privacy()

    # Exactly one selection view and no approval view: the interface never takes a consent.
    assert len(harness.views) == 1
    assert harness.handed == ["metadata_only"]


@pytest.mark.anyio
async def test_a_policy_already_matching_the_recommendation_is_not_offered_as_a_change() -> None:
    harness = _Harness(_posture("confirm_every_request"), _recommendation())
    harness.answers = [None]

    await harness.app.command_privacy()

    assert "already on the recommended privacy policy" in harness.transcript
    assert harness.choices(0) == ["keep", "other"]


@pytest.mark.anyio
async def test_an_earlier_version_of_the_recommended_recipe_offers_the_newer_one() -> None:
    """Issue #907 Phase 1b: an Expanded 1.1.0 approval is not "already recommended"."""

    from dataclasses import replace

    harness = _Harness(
        replace(_posture("confirm_every_request"), recipe_outdated=True), _recommendation()
    )
    harness.answers = [None]

    await harness.app.command_privacy()

    assert "already on the recommended privacy policy" not in harness.transcript
    assert "A newer version of your recipe is available" in harness.transcript
    assert harness.choices(0) == ["keep", "recommended", "other"]


def test_the_runtime_reads_an_earlier_expanded_preset_as_outdated() -> None:
    from typing import cast

    from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
    from finishup.tui.runtime import _review_recipe_outdated  # pyright: ignore[reportPrivateUsage]

    def row(selection: ReviewSelectionPolicy) -> dict[str, object]:
        fields = ReviewSelectionPolicy.__dataclass_fields__
        return {
            "review_context_profile": "expanded",
            "review_selection": {
                name: list(cast("tuple[object, ...]", value)) if isinstance(value, tuple) else value
                for name, value in (
                    (name, cast(object, getattr(selection, name))) for name in fields
                )
            },
        }

    legacy = ReviewSelectionPolicy.for_profile(
        ReviewContextProfile.EXPANDED, preset_version="1.1.0"
    )
    current = ReviewSelectionPolicy.for_profile(ReviewContextProfile.EXPANDED)
    assert _review_recipe_outdated(row(legacy)) is True
    assert _review_recipe_outdated(row(current)) is False
    assert _review_recipe_outdated({"review_context_profile": "custom"}) is False
    assert _review_recipe_outdated({}) is False


@pytest.mark.anyio
@pytest.mark.parametrize("answer", [None, "keep"])
async def test_cancelling_or_keeping_changes_nothing(answer: str | None) -> None:
    harness = _Harness(_posture(), _recommendation())
    harness.answers = [answer]

    await harness.app.command_privacy()

    assert harness.handed == []
    assert "Privacy was left unchanged." in harness.transcript


@pytest.mark.anyio
async def test_other_options_offer_the_command_line_recipe_names() -> None:
    harness = _Harness(_posture(), _recommendation())
    harness.answers = ["other", "expanded_review"]

    await harness.app.command_privacy()

    assert harness.choices(1) == [
        "private",
        "metadata_only",
        "assisted_review",
        "expanded_review",
        "custom",
    ]
    assert harness.handed == ["expanded_review"]


@pytest.mark.anyio
async def test_backing_out_of_the_other_options_list_changes_nothing() -> None:
    harness = _Harness(_posture(), _recommendation())
    harness.answers = ["other", None]

    await harness.app.command_privacy()

    assert harness.handed == []
    assert "Privacy was left unchanged." in harness.transcript


def test_the_fake_runtime_carries_the_production_recommendation_text_verbatim() -> None:
    """A fake that paraphrases lets tests assert wording the product does not say.

    The recommendation's benefit and cost are the whole basis on which a user accepts it, so
    the driven-interface tests must be pinned to the real strings, not to a summary of them.
    """

    from unittest.mock import patch

    from builders.tui_runtime import RECOMMEND_METADATA_ONLY, RECOMMEND_PRIVATE
    from finishup.tui.runtime import FinishUpRuntime

    runtime = FinishUpRuntime()
    for recipe, expected in (
        ("metadata_only", RECOMMEND_METADATA_ONLY),
        ("private", RECOMMEND_PRIVATE),
    ):
        with patch("finishup.cli.privacy_setup.recommended_privacy_recipe", return_value=recipe):
            assert runtime.privacy_recommendation() == expected


def test_an_unreadable_configuration_recommends_the_closed_posture() -> None:
    """Never recommend enabling egress on the strength of a config that could not be read.

    Reading the configured provider binding loads configuration, which raises `ConfigError`
    on any unrecognized `FINISHUP_*` variable. `ConfigError` is not a `ValueError`, so it used to
    escape every handler between here and the top of `/privacy`.
    """

    from unittest.mock import patch

    from finishup.config.models import ConfigError
    from finishup.tui.runtime import FinishUpRuntime

    with patch(
        "finishup.cli.privacy_setup.recommended_privacy_recipe",
        side_effect=ConfigError("unknown_config_env_var"),
    ):
        assert FinishUpRuntime().privacy_recommendation().recipe == "private"


def test_the_privacy_screen_names_admitted_outside_workspace_roots() -> None:
    """Issue #1082: the way in has a way to see it on every owner surface."""

    from finishup.tui.models import PrivacyPosture

    none = PrivacyPosture(profile="assisted_review", llm_inference_enabled=True, readable=True)
    assert none.admitted_input_roots_summary is None
    some = PrivacyPosture(
        profile="assisted_review",
        llm_inference_enabled=True,
        readable=True,
        admitted_input_roots=("/data", "/shared/legacy_app"),
    )
    summary = some.admitted_input_roots_summary
    assert summary is not None
    assert "/data, /shared/legacy_app" in summary
    assert "finishup privacy input-roots" in summary
