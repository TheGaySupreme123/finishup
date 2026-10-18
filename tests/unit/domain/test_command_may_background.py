"""Shell-grammar background detection for the workspace fingerprint (n7 RC1, #1089 item 1)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

import pytest

from finishup.cli.workspace_effect_hook import command_may_outlive_call
from finishup.domain.command_segments import command_may_background
from finishup.domain.values import JsonValue


def _outlives(text: str) -> bool:
    return command_may_outlive_call(
        cast(Mapping[str, JsonValue], {"tool_input": {"command": text}})
    )


@pytest.mark.parametrize(
    "text",
    [
        "curl 'h?a=1&b=2'",
        'curl "https://example.invalid/?a=1&b=2"',
        "sed 's/x/&/' f",
        "grep -n '&&' f",
        "sed -n 's|a|&b|gp' f",
        "printf 'a&b\\n' | grep -c '&'",
        "cd src && rg -n 'a&b' .",
        "bash -lc 'curl \"h?a=1&b=2\"'",
        "rg -n 'a&b' src",
    ],
)
def test_text_that_does_not_background(text: str) -> None:
    assert command_may_background(text) is False
    assert _outlives(text) is False


@pytest.mark.parametrize("text", ["echo a && b", "cmd >&2", "cmd &>log", "cmd 2>&1 | tee out.log"])
def test_an_ampersand_that_is_not_a_background_operator(text: str) -> None:
    # ``cmd`` is not a known program, so the grammar leaves it undecided; the pattern agrees.
    assert command_may_background(text) is not True
    assert _outlives(text) is False


@pytest.mark.parametrize(
    "text",
    [
        "cmd &",
        "npm run dev & sleep 1",
        "(./server &)",
        "bash -c 'x &'",
        "sh -lc 'nohup ./worker'",
        "nohup x",
        "env A=1 setsid x",
        "timeout 5 nohup x",
        "x & disown",
        "cat <<EOF\nx &\nEOF\n",
    ],
)
def test_text_that_backgrounds(text: str) -> None:
    assert command_may_background(text) is True
    assert _outlives(text) is True


@pytest.mark.parametrize(
    "text",
    [
        # A program that hands an argument to a shell or an interpreter.
        'eval "x &"',
        "ssh host 'x &'",
        "env -S 'x &'",
        r"find . -exec sh -c 'x &' \;",
        "python -c 'import os; os.system(\"x &\")'",
        "awk 'BEGIN{system(\"(sleep 5; echo x > f) &\")}'",
        "git -c core.pager='less &' log",
        "git log --format='%h&%s'",
        "fish -c 'x &'",
        "lua -e 'os.execute(\"x &\")'",
        "Rscript -e 'system(\"x &\")'",
        "trap 'sleep 9 &' EXIT",
        'trap "sleep 9 &" EXIT',
        # A privilege wrapper: its daemon is invisible to the same-user process probe.
        "sudo setsid -f x",
        "sudo daemonize x",
        "sudo daemonize /usr/bin/srv",
        "sudo nohup x",
        "doas setsid x",
        "sudo -E env X=1 setsid w",
        "sudo -u app setsid -f srv",
        "sudo start-stop-daemon --start --background --exec /usr/bin/srv",
        "sudo setsid -f sh -c 'sleep 5; echo x > deliverable.txt'",
        # A shell or interpreter reading its script from stdin or a here-document.
        "echo 'sleep 9 &' | sh",
        "printf './writer &\\n' | bash",
        "bash <<'EOF'\nsetsid -f ./writer\nEOF\n",
        "sh -s <<EOF\nnohup w\nEOF\n",
        "bash <<< 'sleep 9 &'",
        # A ``sed`` that runs its pattern space, or reads its script from a file.
        "sed 's/x/sleep 9 \\&/e' f",
        "sed -e 's/^/sleep 9 /' -e 's/$/ \\&/' -e e f",
        "sed -f s.sed 'a&b'",
        # The agent's own program under a known name.
        "./curl 'a&b'",
        # ANSI-C quoting: ``$'\''`` is an escaped quote, so the ``&`` after it is top level.
        "echo $'\\'' & (sleep 2; echo late > deliverable.txt) & echo \\'",
        # A wrapper or assignment that changes what runs in front of a known program.
        "env -S 'sh -c \"sleep 2; echo late > deliverable.txt &\"' curl -s x",
        "env --split-string='sh -c \"(sleep 2; touch f) &\"' cat f",
        "env -S 'sh -c \"(sleep 5; echo x > deliverable.txt) & echo\"' true",
        "env --split-string='sh -c \"x &\"' true",
        "LD_PRELOAD=./bg.so curl 'h?a=1&b=2'",
        "PATH=.:$PATH grep 'a&b' f",
        "env -i PATH=. grep 'a&b'",
        "BASH_ENV=./bg.sh bash -c 'curl \"h?a=1&b=2\"'",
        # A known program in a form that starts or runs another process.
        "wget -b -q 'https://example.com/a?x=1&y=2'",
        "wget --background 'https://example.com/a?x=1&y=2' -O out.html",
        "wget --use-askpass=./bg.sh 'h?a&b'",
        "rg --pre=sh 'a&b' .",
        "rg --pre ./bg.sh 'a&b' .",
        "rg --pre setsid -e x .",
    ],
)
def test_text_the_grammar_leaves_to_the_conservative_reading(text: str) -> None:
    # Never a quieter answer than the pattern: the grammar does not clear these.
    assert command_may_background(text) is not False
    assert _outlives(text) is True


@pytest.mark.parametrize("text", ["echo 'unterminated &", "$(x &)", "echo `x &`"])
def test_unsplittable_or_substituted_text_keeps_the_conservative_reading(text: str) -> None:
    assert command_may_background(text) is None
    # The fallback pattern still sees the ``&``: never a quieter answer than before.
    assert _outlives(text) is True


def test_a_claude_background_launch_flag_is_a_background_launch() -> None:
    from finishup.cli.workspace_effect_hook import HOST_CALL_ENDED_KEY, host_call_incomplete_reason

    def reason(payload: dict[str, object]) -> str | None:
        return host_call_incomplete_reason(cast(Mapping[str, JsonValue], payload))

    assert (
        reason(
            {"tool_input": {"command": "npm run dev", "run_in_background": True}, "success": True}
        )
        == "background_launch"
    )
    assert reason({"tool_input": {"command": "date"}}) == "call_incomplete"
    assert reason({"tool_input": {"command": "date"}, HOST_CALL_ENDED_KEY: True}) is None
    # The ended marker never overrides a background launch.
    assert (
        reason({"tool_input": {"command": "x &"}, HOST_CALL_ENDED_KEY: True}) == "background_launch"
    )
