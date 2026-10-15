"""The first-run review-mode question: what it recommends, and what it does not decide (ADR-049)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

import finishup.cli.setup as cli_setup
from finishup.domain.privacy import ConversationReview


def _choose() -> str:
    """Call the private prompt through one seam, so the ignore lives in a single place."""

    return cli_setup._choose_review_mode()  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001


def _script_prompt(monkeypatch: pytest.MonkeyPatch, replies: list[str]) -> list[str]:
    """Script ``typer.prompt`` so the default is exercised as the user would meet it."""

    seen: list[str] = []

    def fake_prompt(text: str, default: str | None = None) -> str:
        seen.append(f"{text}|{default}")
        reply = replies.pop(0)
        # An empty reply is what pressing enter does: typer returns the default.
        return default if reply == "" and default is not None else reply

    monkeypatch.setattr(cli_setup.typer, "prompt", fake_prompt)
    return seen


@pytest.fixture(autouse=True)
def quiet_echo(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep the prompt's option list out of captured output."""

    def silent(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(cli_setup.typer, "echo", silent)
    yield


def _echo_lines(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    lines: list[str] = []

    def record(message: object = "", *_args: object, **_kwargs: object) -> None:
        lines.append(str(message))

    monkeypatch.setattr(cli_setup.typer, "echo", record)
    return lines


def test_pressing_enter_chooses_the_recommended_hybrid(monkeypatch: pytest.MonkeyPatch) -> None:
    """The recommended answer is the one an unmodified enter selects: FinishUP with agent opt-in."""

    seen = _script_prompt(monkeypatch, [""])
    assert _choose() == "agent_opt_in"
    assert seen == ["Review mode|1"]


def test_the_three_answers_are_worded_for_the_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    """The exact owner-facing options; no stale provider/API-key or update-check wording."""

    lines = _echo_lines(monkeypatch)
    _script_prompt(monkeypatch, ["1"])
    _choose()
    text = "\n".join(lines)
    assert (
        "  1. FinishUP (recommended): local checks; your agent can turn on AI-powered review for "
        "a task when it helps"
    ) in lines
    assert "  2. FinishUP, local only (agents may not opt in)" in lines
    assert "  3. AI-powered review on every task" in lines
    assert "AI-powered review (recommended)" not in text
    assert "API key" not in text
    assert "next prompt separately decides" not in text
    assert "deterministic" not in text.lower()


@pytest.mark.parametrize(
    ("reply", "choice", "setting"),
    [
        ("1", "agent_opt_in", ConversationReview.LOCAL_AGENT_OPT_IN),
        ("2", "local_only", ConversationReview.LOCAL_ONLY),
        ("3", "ai_powered", ConversationReview.AI_POWERED),
    ],
)
def test_each_answer_maps_to_one_conversation_setting(
    monkeypatch: pytest.MonkeyPatch,
    reply: str,
    choice: cli_setup.ReviewChoice,
    setting: ConversationReview,
) -> None:
    _script_prompt(monkeypatch, [reply])
    chosen = _choose()
    assert chosen == choice
    assert cli_setup.review_choice_conversation_setting(choice) is setting


def test_local_only_stays_reachable_as_the_second_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _script_prompt(monkeypatch, ["2"])
    assert _choose() == "local_only"


def test_an_unrecognized_answer_reasks_rather_than_assuming(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A posture question must never resolve a typo into an egress-capable branch."""

    _script_prompt(monkeypatch, ["yes", "4", "2"])
    assert _choose() == "local_only"


def test_choosing_ai_review_configures_nothing_by_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The answer selects a wizard branch; it is not consent and binds nothing.

    Reaching egress still needs a provider binding, a stored credential, and the separately
    reauthenticated policy commit, none of which this call performs.
    """

    _script_prompt(monkeypatch, [""])
    calls: list[str] = []

    def record(name: str) -> object:
        def stub(*_args: object, **_kwargs: object) -> None:
            calls.append(name)

        return stub

    for attribute in ("apply_provider_endpoint_choice", "run_privacy_setup"):
        monkeypatch.setattr(cli_setup, attribute, record(attribute), raising=False)

    assert _choose() == "agent_opt_in"
    assert calls == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("answer", "add_on"),
    [
        (ConversationReview.LOCAL_AGENT_OPT_IN, True),
        (ConversationReview.AI_POWERED, True),
        (None, False),
    ],
)
async def test_the_host_path_lists_the_ai_review_recipes_for_an_add_on_answer(
    monkeypatch: pytest.MonkeyPatch, answer: ConversationReview | None, add_on: bool
) -> None:
    """Review round 1 (P2-3): Claude Code and Cursor reach the same AI recipe list as Codex.

    An answer that adds AI-powered review never meets the released Private recommendation a
    subscription reviewer (or any reviewer without reviewed data-use evidence) would get; a
    plain ``finishup --set`` keeps its released recommendation.
    """

    import finishup.cli.privacy_setup as privacy_setup_module

    calls: list[dict[str, object]] = []

    async def reachable(*, start_if_absent: bool = False) -> dict[str, object]:
        del start_if_absent
        return {"reachable": True, "state": "ready"}

    async def privacy_setup(**kwargs: object) -> object:
        calls.append(kwargs)
        return type("Report", (), {"outcome": "configured", "reason": None})()

    async def provider_setup(
        service: dict[str, object], *, before_credential: object = None, **_: object
    ) -> tuple[dict[str, object], dict[str, object]]:
        assert callable(before_credential)
        assert await before_credential() is None  # type: ignore[misc]
        return service, {"binding": "skipped", "credential": "skipped"}

    monkeypatch.setattr(cli_setup, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(cli_setup, "_service_reachability", reachable)
    monkeypatch.setattr(cli_setup, "_prompt_credential_probe_authorization", lambda: False)
    monkeypatch.setattr(cli_setup, "_interactive_provider_setup", provider_setup)
    monkeypatch.setattr(privacy_setup_module, "run_privacy_setup", privacy_setup)

    await cli_setup.run_provider_setup(conversation_review=answer)
    assert len(calls) == 1
    call = calls[0]
    assert call["ai_review_add_on"] is add_on
    assert call["offer_recommended"] is (not add_on)
    assert call["conversation_review"] is answer
