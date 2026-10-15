"""The deprecated ``yoetz`` alias notice (ADR-048): interactive stderr only, never machine output."""

from __future__ import annotations

import io
import sys

import pytest

import finishup
import finishup.cli.entry as entry

_ALIAS = "/opt/tools/yoetz/bin/yoetz"
_LAUNCHER = "/opt/tools/finishup/bin/finishup"
_LEGACY_MODULE = "/opt/venv/lib/python3.14/site-packages/yoetz/__main__.py"


class _Stream(io.StringIO):
    def __init__(self, *, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def _stderr(monkeypatch: pytest.MonkeyPatch, *, tty: bool) -> _Stream:
    stream = _Stream(tty=tty)
    monkeypatch.setattr(sys, "stderr", stream)
    return stream


@pytest.mark.parametrize("argv0", [_ALIAS, "yoetz", _LEGACY_MODULE])
def test_alias_on_an_interactive_terminal_prints_one_notice_line(
    monkeypatch: pytest.MonkeyPatch, argv0: str
) -> None:
    stream = _stderr(monkeypatch, tty=True)
    monkeypatch.setattr(sys, "argv", [argv0, "status"])

    entry._legacy_alias_notice(["status"])  # pyright: ignore[reportPrivateUsage]

    assert stream.getvalue() == entry.LEGACY_ALIAS_NOTICE + "\n"
    assert "\n" not in entry.LEGACY_ALIAS_NOTICE
    assert "'finishup'" in entry.LEGACY_ALIAS_NOTICE


@pytest.mark.parametrize(
    "argv0", [_LAUNCHER, "finishup", "/opt/venv/lib/python3.14/site-packages/finishup/__main__.py"]
)
def test_the_finishup_spellings_never_print_the_notice(
    monkeypatch: pytest.MonkeyPatch, argv0: str
) -> None:
    stream = _stderr(monkeypatch, tty=True)
    monkeypatch.setattr(sys, "argv", [argv0, "status"])

    entry._legacy_alias_notice(["status"])  # pyright: ignore[reportPrivateUsage]

    assert stream.getvalue() == ""


def test_a_non_interactive_stderr_never_gets_the_notice(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = _stderr(monkeypatch, tty=False)
    monkeypatch.setattr(sys, "argv", [_ALIAS, "status"])

    entry._legacy_alias_notice(["status"])  # pyright: ignore[reportPrivateUsage]

    assert stream.getvalue() == ""


@pytest.mark.parametrize(
    "arguments",
    [
        ["--version"],
        ["version", "--json"],
        ["status", "--json"],
        ["service", "status", "--json"],
        ["hooks", "observe", "--event", "Stop"],
        ["hooks", "startup-gate", "--host", "claude", "--event", "SessionStart"],
        ["mcp", "serve"],
        ["mcp", "serve", "--host", "codex"],
        ["service", "run"],
    ],
)
def test_machine_facing_invocations_stay_silent_on_a_terminal(
    monkeypatch: pytest.MonkeyPatch, arguments: list[str]
) -> None:
    stream = _stderr(monkeypatch, tty=True)
    monkeypatch.setattr(sys, "argv", [_ALIAS, *arguments])

    entry._legacy_alias_notice(arguments)  # pyright: ignore[reportPrivateUsage]

    assert stream.getvalue() == ""


def test_a_closed_stderr_never_fails_the_command(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Closed(_Stream):
        def write(self, s: str) -> int:
            raise OSError("closed")

    monkeypatch.setattr(sys, "stderr", _Closed(tty=True))
    monkeypatch.setattr(sys, "argv", [_ALIAS, "status"])

    entry._legacy_alias_notice(["status"])  # pyright: ignore[reportPrivateUsage]


def test_main_prints_the_notice_once_before_dispatching_the_full_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = _stderr(monkeypatch, tty=True)
    monkeypatch.setattr(sys, "argv", [_ALIAS, "privacy", "show"])
    monkeypatch.setattr(entry.os, "name", "posix")
    calls: list[str] = []
    monkeypatch.setattr(entry, "_run_full_cli", lambda: calls.append(stream.getvalue()))

    entry.main()

    assert calls == [entry.LEGACY_ALIAS_NOTICE + "\n"]


def test_alias_version_prints_only_the_bare_version_for_released_upgrade_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Released ``yoetz upgrade`` parses ``<tool>/bin/yoetz --version`` stdout as a version."""

    stream = _stderr(monkeypatch, tty=True)
    monkeypatch.setattr(sys, "argv", [_ALIAS, "--version"])
    monkeypatch.setattr(entry.os, "name", "posix")

    with pytest.raises(SystemExit) as exited:
        entry.main()

    assert exited.value.code in (0, None)
    assert capsys.readouterr().out == finishup.__version__ + "\n"
    assert stream.getvalue() == ""


def test_the_notice_names_the_upgrade_guide_anchor() -> None:
    assert entry.LEGACY_ALIAS_NOTICE.endswith("docs/usage/upgrading.md#upgrading-from-yoetz")


def test_the_notice_tells_a_transitional_user_the_alias_still_runs_every_command() -> None:
    # A transitional 'yoetz' distribution puts only 'yoetz' on PATH, so the notice must not read
    # as if the user has to switch launchers before anything works.
    notice = entry.LEGACY_ALIAS_NOTICE
    assert "\n" not in notice
    assert "'finishup'" in notice
    assert "any finishup command also works as 'yoetz'" in notice
    assert "'yoetz upgrade'" in notice
    assert "removed in a later release" in notice
    assert notice.endswith(
        "https://github.com/TheGaySupreme123/finishup/blob/main/docs/usage/upgrading.md"
        "#upgrading-from-yoetz"
    )
