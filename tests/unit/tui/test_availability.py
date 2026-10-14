"""The gate that decides whether a terminal UI may open at all.

Getting this wrong is the one way a presentation layer can break automation, so
each condition is asserted on its own rather than as one combined predicate.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from finishup.tui import tui_available, tui_supported


class _Stream:
    """The only part of a stream this gate ever reads."""

    def __init__(self, tty: bool) -> None:
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


class _Streams:
    def __init__(self, stdin: bool, stdout: bool) -> None:
        self._stdin = stdin
        self._stdout = stdout

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys

        monkeypatch.setattr(sys, "stdin", _Stream(self._stdin))
        monkeypatch.setattr(sys, "stdout", _Stream(self._stdout))


TTY = {"TERM": "xterm-256color"}


def terminal(monkeypatch: pytest.MonkeyPatch, *, stdin: bool = True, stdout: bool = True) -> None:
    _Streams(stdin, stdout).install(monkeypatch)


def test_a_real_interactive_terminal_may_open_the_interface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminal(monkeypatch)
    assert tui_available(TTY) is True


@pytest.mark.parametrize(
    ("stdin", "stdout"),
    [(False, True), (True, False), (False, False)],
)
def test_a_pipe_or_redirect_on_either_stream_keeps_the_historical_behaviour(
    monkeypatch: pytest.MonkeyPatch, stdin: bool, stdout: bool
) -> None:
    terminal(monkeypatch, stdin=stdin, stdout=stdout)
    assert tui_available(TTY) is False


@pytest.mark.parametrize(
    "marker",
    [
        "CI",
        "CONTINUOUS_INTEGRATION",
        "BUILD_NUMBER",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "TEAMCITY_VERSION",
    ],
)
def test_every_ci_marker_keeps_the_deterministic_output(
    monkeypatch: pytest.MonkeyPatch, marker: str
) -> None:
    terminal(monkeypatch)
    assert tui_available({**TTY, marker: "1"}) is False


def test_a_dumb_or_absent_term_is_treated_as_automation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminal(monkeypatch)
    assert tui_available({"TERM": "dumb"}) is False
    assert tui_available({}) is False


@pytest.mark.parametrize(
    ("variables", "available"),
    [
        ({"YOETZ_TUI": "0"}, False),
        ({"YOETZ_TUI": "1"}, True),
        ({"FINISHUP_TUI": "0", "YOETZ_TUI": "0"}, False),
        ({"FINISHUP_TUI": "1", "YOETZ_TUI": "1"}, True),
        # Two spellings that disagree keep the prompt loop rather than choosing (ADR-048).
        ({"FINISHUP_TUI": "1", "YOETZ_TUI": "0"}, False),
    ],
)
def test_the_legacy_opt_out_spelling_is_honoured(
    monkeypatch: pytest.MonkeyPatch, variables: Mapping[str, str], available: bool
) -> None:
    terminal(monkeypatch)
    assert tui_available({**TTY, **variables}) is available


def test_the_environment_opt_out_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    terminal(monkeypatch)
    assert tui_available({**TTY, "FINISHUP_TUI": "0"}) is False
    # Any other value is not an opt-out.
    assert tui_available({**TTY, "FINISHUP_TUI": "1"}) is True


def test_an_unreadable_stream_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    class Broken:
        def isatty(self) -> bool:
            raise OSError("stream is gone")

    monkeypatch.setattr(sys, "stdin", Broken())
    assert tui_available(TTY) is False


def test_support_reports_whether_the_rendering_dependency_is_installed() -> None:
    # Textual is a declared runtime dependency of this distribution.
    assert tui_supported() is True


def test_the_gate_reads_the_supplied_mapping_rather_than_the_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminal(monkeypatch)
    monkeypatch.setenv("CI", "1")
    supplied: Mapping[str, str] = TTY
    # An explicit mapping wins, which is what makes this testable at all.
    assert tui_available(supplied) is True
