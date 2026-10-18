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
        "echo a && b",
        "cmd >&2",
        "cmd &>log",
        "cmd 2>&1 | tee out.log",
        "git log --format='%h&%s'",
        "bash -lc 'curl \"h?a=1&b=2\"'",
        "rg -n 'a&b' src",
    ],
)
def test_text_that_does_not_background(text: str) -> None:
    assert command_may_background(text) is False
    assert _outlives(text) is False


@pytest.mark.parametrize(
    "text",
    [
        "cmd &",
        "npm run dev & sleep 1",
        "(./server &)",
        "bash -c 'x &'",
        "sh -lc 'nohup ./worker'",
        'eval "x &"',
        "ssh host 'x &'",
        "env -S 'x &'",
        r"find . -exec sh -c 'x &' \;",
        "python -c 'import os; os.system(\"x &\")'",
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
