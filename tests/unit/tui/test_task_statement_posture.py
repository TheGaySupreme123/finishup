"""The terminal interface says whether the task statement reaches the reviewer (issue #908).

Review 942-G3: without this, a policy that withholds the user's request and one that sends it look
the same in routine status. The words are the ones ``finishup privacy show`` prints, read from the
same composed policy document, so the two surfaces cannot disagree.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import replace
from typing import cast

import pytest

from builders.privacy_policies import minimal_external_policy
from finishup.adapters.privacy.catalog import encode_privacy_policy_json
from finishup.cli.app import (
    _effective_task_statement_line,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.privacy import PrivacyPolicy, ReviewSelectionPolicy
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import DataCategory
from finishup.tui.models import LayerState, PrivacyPosture, ProviderPosture
from finishup.tui.runtime import FinishUpRuntime


def _legacy(policy: PrivacyPolicy) -> PrivacyPolicy:
    return replace(
        policy,
        review_selection=ReviewSelectionPolicy.for_profile(
            policy.review_context_profile, preset_version="1.1.0"
        ),
    )


def _blocked(policy: PrivacyPolicy) -> PrivacyPolicy:
    """The review channel no longer allows ``task_description``."""

    return replace(
        policy,
        channel_policies=tuple(
            replace(
                channel,
                allowed_categories=tuple(
                    item
                    for item in channel.allowed_categories
                    if item is not DataCategory.TASK_DESCRIPTION
                ),
            )
            for channel in policy.channel_policies
        ),
    )


async def _posture(monkeypatch: pytest.MonkeyPatch, composed: JsonValue | None) -> PrivacyPosture:
    class _Client:
        async def privacy_get_setup(self, _body: object) -> object:
            return {} if composed is None else {"composed_policy": composed}

    @asynccontextmanager
    async def connect(_self: FinishUpRuntime) -> AsyncGenerator[_Client]:
        yield _Client()

    monkeypatch.setattr(FinishUpRuntime, "_client", connect)
    return await FinishUpRuntime().privacy_posture()


def _layer(privacy: PrivacyPosture) -> tuple[LayerState, str]:
    provider = ProviderPosture(
        endpoint_bound=True,
        provider_id="openai",
        model="gpt-5",
        endpoint_profile_id="openai-responses",
        credential_connected=True,
        llm_inference_enabled=True,
        semantic_enabled=True,
        semantic_ready=True,
        readiness_determinable=True,
    )
    layers = FinishUpRuntime()._provider_layers(provider, privacy)  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    layer = next(layer for layer in layers if layer.key == "task_statement_review")
    return layer.state, layer.detail


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("variant", "state", "opening"),
    [
        ("current", LayerState.VERIFIED, "sent."),
        ("legacy", LayerState.NOT_CONFIGURED, "not sent. This policy was approved before"),
        ("blocked", LayerState.NOT_CONFIGURED, "not sent. The task_statement section is selected"),
    ],
)
async def test_status_names_whether_the_statement_is_sent_in_privacy_show_words(
    monkeypatch: pytest.MonkeyPatch, variant: str, state: LayerState, opening: str
) -> None:
    current = minimal_external_policy()
    policy = {
        "current": current,
        "legacy": _legacy(current),
        "blocked": _blocked(current),
    }[variant]
    document = cast(JsonValue, encode_privacy_policy_json(policy))

    posture = await _posture(monkeypatch, document)
    layer_state, detail = _layer(posture)

    assert posture.task_statement_disclosure is not None
    assert posture.task_statement_disclosure.startswith(opening)
    assert layer_state is state
    assert detail == posture.task_statement_disclosure
    assert "host-captured user prompt is never used" in detail
    # The same words `finishup privacy show` prints for the same document.
    line = _effective_task_statement_line(cast(JsonValue, {"policy": document}))
    assert line == "Task statement: " + posture.task_statement_disclosure


@pytest.mark.anyio
async def test_an_unreadable_policy_is_unknown_never_a_guess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unreadable = await _posture(monkeypatch, None)
    assert unreadable.task_statement_disclosure is None
    assert _layer(unreadable)[0] is LayerState.UNKNOWN

    malformed = await _posture(monkeypatch, cast(JsonValue, {"profile": "assisted_review"}))
    assert malformed.readable is True
    assert malformed.task_statement_disclosure is None
    assert _layer(malformed)[0] is LayerState.UNKNOWN


@pytest.mark.anyio
async def test_the_privacy_screen_states_the_task_statement_line() -> None:
    from collections.abc import Sequence

    from finishup.tui.app import FinishUpTui
    from finishup.tui.models import PrivacyRecommendation
    from finishup.tui.symbols import Level
    from finishup.tui.widgets.views import BaseView

    posture = PrivacyPosture(
        profile="assisted_review",
        llm_inference_enabled=True,
        readable=True,
        task_statement_disclosure="sent. The agent's transcription goes to the reviewer.",
    )

    class _Runtime:
        async def privacy_posture(self) -> PrivacyPosture:
            return posture

        def privacy_recommendation(self, _posture: object = None) -> PrivacyRecommendation:
            return PrivacyRecommendation("metadata_only", "Least.", "Costs detail.")

        def project_root(self) -> str:
            return "/srv/finishup"

    app = FinishUpTui(_Runtime())  # pyright: ignore[reportArgumentType]
    said: list[str] = []

    def say(level: Level, title: str, body: Sequence[str] = (), *, details: object = ()) -> None:
        del level, details
        said.append("\n".join((title, *body)))

    async def ask(view: BaseView) -> None:
        del view

    app.say = say  # pyright: ignore[reportAttributeAccessIssue]
    app.ask = ask  # pyright: ignore[reportAttributeAccessIssue]
    await app.command_privacy()

    assert "Task statement: sent. The agent's transcription goes to the reviewer." in "\n".join(
        said
    )
