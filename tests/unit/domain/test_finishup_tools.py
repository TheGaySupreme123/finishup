"""FinishUP's own tool names are recognised under the current and the legacy server name (ADR-048).

Recorded observations from 0.1-0.2.5 name the tools ``mcp__yoetz__<tool>`` and friends, and
replay reclassifies them, so the legacy spellings stay recognised permanently. The current
spellings come first in every derived tuple, so a renderer reading the first entry emits them.
"""

from __future__ import annotations

import pytest

from finishup.domain.finishup_tools import (
    FINISHUP_MCP_TOOL_NAMES,
    FINISHUP_PREFIXED_TOOL_PREFIXES,
    FINISHUP_SCOPED_TOOL_PREFIXES,
    FINISHUP_SKILL_NAMES,
    FINISHUP_TOOL_SERVER_NAMES,
    FINISHUP_WORKFLOW_TOOL_NAMES,
    finishup_scoped_tool_basename,
    finishup_tool_spelling,
)

_NEW_SCOPED = ("mcp__finishup__{name}", "mcp__plugin_finishup_finishup__{name}")
_LEGACY_SCOPED = ("mcp__yoetz__{name}", "mcp__plugin_yoetz_yoetz__{name}")
_NEW_PREFIXED = ("finishup:{name}", "plugin-finishup-finishup:{name}")
_LEGACY_PREFIXED = ("yoetz:{name}", "plugin-yoetz-yoetz:{name}")


def test_server_names_put_the_current_spelling_first() -> None:
    assert FINISHUP_TOOL_SERVER_NAMES == ("finishup", "yoetz")
    assert FINISHUP_SCOPED_TOOL_PREFIXES == (
        "mcp__finishup__",
        "mcp__plugin_finishup_finishup__",
        "mcp__yoetz__",
        "mcp__plugin_yoetz_yoetz__",
    )
    assert FINISHUP_PREFIXED_TOOL_PREFIXES == (
        "finishup:",
        "plugin-finishup-finishup:",
        "yoetz:",
        "plugin-yoetz-yoetz:",
    )
    assert FINISHUP_SKILL_NAMES == ("finishup", "finishup:finishup", "yoetz", "yoetz:yoetz")


@pytest.mark.parametrize("name", FINISHUP_MCP_TOOL_NAMES)
@pytest.mark.parametrize("spelling", (*_NEW_SCOPED, *_LEGACY_SCOPED))
def test_scoped_spellings_of_either_server_are_finishup_own(spelling: str, name: str) -> None:
    assert finishup_tool_spelling(spelling.format(name=name)) == "server_scoped"
    # Hosts record the case they were given; matching is case-insensitive.
    assert finishup_tool_spelling(spelling.format(name=name).upper()) == "server_scoped"


@pytest.mark.parametrize("name", FINISHUP_MCP_TOOL_NAMES)
@pytest.mark.parametrize("spelling", (*_NEW_PREFIXED, *_LEGACY_PREFIXED))
def test_cursor_prefixed_spellings_of_either_server_are_finishup_own(
    spelling: str, name: str
) -> None:
    assert finishup_tool_spelling(spelling.format(name=name)) == "server_prefixed"


@pytest.mark.parametrize("server", ["yoetz", "plugin_yoetz_yoetz", "finishup", "x_yoetz_y"])
def test_any_tool_of_a_server_keyed_by_either_name_is_finishup_own(server: str) -> None:
    """A tool added later is FinishUP's without a registry edit, under the legacy key too."""

    assert finishup_tool_spelling(f"mcp__{server}__future_tool") == "server_scoped"


@pytest.mark.parametrize(
    "other",
    [
        "mcp__yoetzx__status",
        "mcp__notyoetz__status",
        "mcp__finishupx__status",
        "mcp__yoetz__",
        "mcp__yoetz",
        "yoetz:rm_rf",
        "yoetz:",
        "plugin-yoetz-yoetz:statusx",
        "plugin-yoetz-finishup:status",
        "yoetz",
        "yoetz:yoetz",
    ],
)
def test_near_miss_legacy_spellings_are_not_finishup_own(other: str) -> None:
    assert finishup_tool_spelling(other) is None


@pytest.mark.parametrize("name", FINISHUP_WORKFLOW_TOOL_NAMES)
@pytest.mark.parametrize("spelling", (*_NEW_SCOPED, *_LEGACY_SCOPED))
def test_scoped_basename_reads_both_server_names(spelling: str, name: str) -> None:
    assert finishup_scoped_tool_basename(spelling.format(name=name)) == name


@pytest.mark.parametrize(
    "other",
    [
        "start",
        "yoetz:start",
        "finishup:start",
        "MCP__YOETZ__start",
        "mcp__yoetz__closure_prepare",
        "mcp__other__start",
        "mcp__yoetz__startx",
        None,
        7,
    ],
)
def test_scoped_basename_is_exact_and_closed(other: object) -> None:
    assert finishup_scoped_tool_basename(other) is None
