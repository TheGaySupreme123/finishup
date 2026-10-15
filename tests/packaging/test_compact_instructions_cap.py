"""Packaging gate: the Codex and Cursor initialize instructions keep their stated byte cap (#918).

Codex code mode builds every advertised tool's description from the initialize instructions, the
tool description and a generated declaration, so the instructions are charged once per tool. Issue
#918 states a 2,048-byte cap for the packaged compact body those hosts receive, recorded in
``docs/runbooks/codex-integration.md``. The route tail and the longest admissible destination
disclosure (#479) ride on top and are never trimmed to fit. This test fails the build when the
packaged body, or any rendering of it, outgrows that cap, so the saving cannot regress silently as
the text is edited. It sits next to the Claude cap gate (#789).
"""

from __future__ import annotations

from finishup.mcp.descriptors import (
    COMPACT_INITIALIZE_INSTRUCTIONS,
    COMPACT_INSTRUCTIONS_BUDGET,
    McpRouteProfile,
    server_instructions,
)
from finishup.mcp.semantic_destination import (
    DISCLOSURE_PREFIX,
    MAX_DISCLOSURE_ENCODED_BYTES,
    SemanticDestinationDisclosure,
)
from finishup.ports.control import McpHostProfile

STATED_COMPACT_BODY_CAP_BYTES = 2_048
COMPACT_HOSTS: tuple[McpHostProfile, ...] = ("codex", "cursor")


def test_codex_and_cursor_instructions_never_exceed_the_stated_cap() -> None:
    assert COMPACT_INSTRUCTIONS_BUDGET["packaged_max_encoded_bytes"] == (
        STATED_COMPACT_BODY_CAP_BYTES
    )
    assert COMPACT_INITIALIZE_INSTRUCTIONS.isascii()
    assert len(COMPACT_INITIALIZE_INSTRUCTIONS.encode("utf-8")) <= STATED_COMPACT_BODY_CAP_BYTES
    padding = MAX_DISCLOSURE_ENCODED_BYTES - len(DISCLOSURE_PREFIX.encode("utf-8")) - 1
    ceiling = SemanticDestinationDisclosure("unknown", DISCLOSURE_PREFIX + "x" * padding + ".")
    cases: tuple[tuple[McpRouteProfile, SemanticDestinationDisclosure | None], ...] = (
        ("policy", None),
        ("policy", ceiling),
        ("strict", None),
    )
    for host in COMPACT_HOSTS:
        for profile, disclosure in cases:
            rendered = server_instructions(
                profile, host_profile=host, semantic_destination=disclosure
            )
            encoded = len(rendered.encode("utf-8"))
            assert rendered.isascii()
            assert rendered.startswith(COMPACT_INITIALIZE_INSTRUCTIONS)
            assert encoded <= COMPACT_INSTRUCTIONS_BUDGET["max_encoded_bytes"], (host, profile)
            if disclosure is not None:
                # The privacy disclosure is carried whole, never cut to fit the cap.
                assert rendered.rstrip("\n").endswith(disclosure.sentence)
