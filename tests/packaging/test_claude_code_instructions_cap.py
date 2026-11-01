"""Packaging gate: the Claude-host initialize instructions fit the observed Claude Code cap.

The cap is an observed host fact (issue #789), recorded in
``docs/runbooks/claude-code-integration.md``, not a documented Claude limit: the desktop app keeps
the first 2,048 characters of the block and appends ``… [truncated]``. This test fails the build
when the packaged Claude text, its route tail, and the longest admissible destination disclosure
can no longer fit together, so the fix cannot regress silently as the guidance grows.
"""

from __future__ import annotations

from finishup.mcp.descriptors import (
    CLAUDE_CODE_INITIALIZE_INSTRUCTIONS,
    CLAUDE_CODE_INSTRUCTIONS_BUDGET,
    McpRouteProfile,
    server_instructions,
)
from finishup.mcp.semantic_destination import (
    DISCLOSURE_PREFIX,
    MAX_DISCLOSURE_ENCODED_BYTES,
    SemanticDestinationDisclosure,
)

OBSERVED_CLAUDE_CODE_CAP_CHARS = 2_048


def test_claude_host_instructions_never_exceed_the_recorded_cap() -> None:
    assert CLAUDE_CODE_INSTRUCTIONS_BUDGET["observed_host_cap_chars"] == (
        OBSERVED_CLAUDE_CODE_CAP_CHARS
    )
    padding = MAX_DISCLOSURE_ENCODED_BYTES - len(DISCLOSURE_PREFIX.encode("utf-8")) - 1
    ceiling = SemanticDestinationDisclosure("unknown", DISCLOSURE_PREFIX + "x" * padding + ".")
    cases: tuple[tuple[McpRouteProfile, SemanticDestinationDisclosure | None], ...] = (
        ("policy", None),
        ("policy", ceiling),
        ("strict", None),
    )
    for profile, disclosure in cases:
        rendered = server_instructions(
            profile, host_profile="claude", semantic_destination=disclosure
        )
        assert rendered.isascii()
        assert len(rendered) <= OBSERVED_CLAUDE_CODE_CAP_CHARS, (profile, len(rendered))
        assert rendered.startswith(CLAUDE_CODE_INITIALIZE_INSTRUCTIONS)
