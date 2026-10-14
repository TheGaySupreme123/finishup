"""The first-run review-mode question: what it recommends, and what it does not decide."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

import finishup.cli.setup as cli_setup


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


def test_pressing_enter_chooses_semantic_review(monkeypatch: pytest.MonkeyPatch) -> None:
    """The recommended answer is the one an unmodified enter selects."""

    seen = _script_prompt(monkeypatch, [""])
    assert _choose() == "semantic"
    assert seen == ["Review mode|1"]


def test_local_only_stays_reachable_as_the_second_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _script_prompt(monkeypatch, ["2"])
    assert _choose() == "local_only"


def test_an_unrecognized_answer_reasks_rather_than_assuming(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A posture question must never resolve a typo into an egress-capable branch."""

    _script_prompt(monkeypatch, ["yes", "3", "2"])
    assert _choose() == "local_only"


def test_choosing_semantic_review_configures_nothing_by_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The answer selects a wizard branch; it is not consent and binds nothing.

    This is what keeps the seeded-``local_only`` claim true while the prompt recommends
    AI-powered review: reaching egress still needs a provider binding, a stored credential, and
    the separately reauthenticated policy commit, none of which this call performs.
    """

    _script_prompt(monkeypatch, [""])
    calls: list[str] = []

    def record(name: str) -> object:
        def stub(*_args: object, **_kwargs: object) -> None:
            calls.append(name)

        return stub

    for attribute in ("apply_provider_endpoint_choice", "run_privacy_setup"):
        monkeypatch.setattr(cli_setup, attribute, record(attribute), raising=False)

    assert _choose() == "semantic"
    assert calls == []
