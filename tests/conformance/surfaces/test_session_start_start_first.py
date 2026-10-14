"""Host entrypoints must name start-first and failed-start intro recovery.

Issue #692's instruction-delivery slice (not a PreToolUse deny gate): Codex, Claude Code, and
Cursor catalog descriptions and skill bodies, plus SessionStart inactive context, tell a new
session to call `start` before substantive work and to follow recovery before asking for intro and guidance if startup
remains blocked. Wording is not enforcement.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest

from yoetz.cli.hooks import INACTIVE_CONTEXT
from yoetz.mcp.descriptors import descriptor_for

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_PACKAGED_ROOT: Final = _REPO_ROOT / "src" / "yoetz" / "resources"

_HOST_SKILLS: Final = (
    ("codex", "skills/codex/yoetz/SKILL.md"),
    ("claude-code", "skills/claude-code/yoetz/SKILL.md"),
    ("cursor", "skills/cursor/yoetz/SKILL.md"),
    ("portable", "skills/portable/yoetz/SKILL.md"),
)

_START_FIRST = "read guidance and discover schemas, then call start before substantive work"
_FAIL_INTRO = "follow recovery on failure and ask for intro and guidance if startup remains blocked"
_BODY_START_FIRST = "first workflow operation is `start`"
# tb4n5 (P10): the body sentence names what "This" is, so it cannot read as "start includes
# read_guidance".
_BODY_DISCOVERY = (
    "The first workflow operation is `start`, after a discovery step that reads guidance and "
    "discovers schemas. This includes `read_guidance` and commands."
)
_BODY_FAIL = "ask the user for intro and guidance"
# tb4n5 (P5): the description is the trigger hosts select skills by, so it also names closure, where
# agents met findings and Stop messages with the skill no longer in context.
_CLOSURE_TRIGGER = "Also use when a Yoetz finding, Stop message or receipt needs an answer."


def _frontmatter_description(text: str) -> str:
    assert text.startswith("---\n"), "skill is missing YAML frontmatter"
    closing = text.find("\n---\n", 4)
    assert closing != -1, "skill frontmatter is not closed"
    block = text[4:closing]
    for line in block.splitlines():
        if line.startswith("description:"):
            return line.removeprefix("description:").strip()
    raise AssertionError("skill frontmatter has no description")


@pytest.mark.parametrize(("host", "relative"), _HOST_SKILLS, ids=[item[0] for item in _HOST_SKILLS])
def test_host_skill_description_names_start_first_and_failed_start_intro(
    host: str, relative: str
) -> None:
    source = (_REPO_ROOT / relative).read_text(encoding="utf-8")
    packaged = (_PACKAGED_ROOT / relative).read_text(encoding="utf-8")
    assert packaged == source, f"{host} packaged skill drifted from source"
    description = _frontmatter_description(source)
    collapsed = " ".join(source.split())
    assert _START_FIRST in description, host
    assert _FAIL_INTRO in description, host
    assert description.endswith(_CLOSURE_TRIGGER), host
    assert _BODY_START_FIRST in collapsed, host
    assert _BODY_DISCOVERY in collapsed, host
    # tb4n5 startup dedup (ADR-047): the skill states failed-start recovery once, in the catalog
    # description pinned above. The initialize body and the operating card own the rest of it.
    body = collapsed.partition(" --- ")[2]
    assert _BODY_FAIL not in body, host
    assert "same-request recovery first" not in body, host


def test_failed_start_recovery_is_stated_by_initialize_and_the_operating_card() -> None:
    """The copies the skills dropped (tb4n5) are still on every host's mandatory surface."""

    from yoetz.mcp.descriptors import (
        CLAUDE_CODE_INITIALIZE_INSTRUCTIONS,
        COMPACT_INITIALIZE_INSTRUCTIONS,
    )

    card = " ".join((_REPO_ROOT / "guidance/agent-instructions.md").read_text("utf-8").split())
    assert (
        "If startup fails, follow recovery first; if still blocked, ask for intro and guidance"
        in (card)
    )
    assert "Skip trivial questions or edits; never invent a ledger task." in card
    for initialize in (CLAUDE_CODE_INITIALIZE_INSTRUCTIONS, COMPACT_INITIALIZE_INSTRUCTIONS):
        text = " ".join(initialize.split())
        assert "then ask; do not work without a task." in text
        assert "Read-only questions skip it." in text


def test_session_start_inactive_context_names_start_and_intro_recovery() -> None:
    assert "call start before substantive material work" in INACTIVE_CONTEXT
    assert "Guidance reads, tool/schema discovery" in INACTIVE_CONTEXT
    assert (
        "If start fails, follow exact continuations and same-request recovery first"
        in INACTIVE_CONTEXT
    )
    assert "ask the user for intro and guidance" in INACTIVE_CONTEXT
    assert "do not invent a workflow or continue without a ledger task" in INACTIVE_CONTEXT


def test_start_tool_description_names_new_session_and_failed_start_intro() -> None:
    description = descriptor_for("start").description
    assert "A new session's first workflow operation is this call" in description
    assert "read_guidance and discovery commands" in description
    assert "for intro and guidance" in description
    assert description.index("same-request recovery") < description.index("for intro and guidance")
    assert "continue without a task" in description


@pytest.mark.parametrize("relative", ["guidance/workflow.md", "guidance/coverage-and-receipts.md"])
def test_first_start_failure_is_not_the_general_outage_fallback(relative: str) -> None:
    """The same terminal startup error must not select both stop and continue rows."""
    text = " ".join((_REPO_ROOT / relative).read_text(encoding="utf-8").split())
    assert "A first non-retryable `start` failure alone does not qualify" in text
    assert "no write or approval remains pending" in text
    assert "or returns a non-retryable error | Continue" not in text
    assert "same-request recovery first, including a named one-time repair" in text


def test_startup_recovery_keeps_unknown_writes_and_denied_consent_out_of_fallback() -> None:
    text = (_REPO_ROOT / "guidance/coverage-and-receipts.md").read_text(encoding="utf-8")
    rules = " ".join(text.split("### Startup failure precedence", 1)[1].split())
    assert "Retain and report any remaining pending, quarantined, or unknown outcome" in rules
    assert "denied/expired initialization decision" in rules
    assert "One bounded diagnostic read does not satisfy the repair exception" in rules
    assert "then continue without Yoetz" not in rules
    assert "state the boundary and continue without Yoetz" not in rules
