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

from finishup.cli.hooks import INACTIVE_CONTEXT
from finishup.mcp.descriptors import descriptor_for

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_PACKAGED_ROOT: Final = _REPO_ROOT / "src" / "finishup" / "resources"

_HOST_SKILLS: Final = (
    ("codex", "skills/codex/finishup/SKILL.md"),
    ("claude-code", "skills/claude-code/finishup/SKILL.md"),
    ("cursor", "skills/cursor/finishup/SKILL.md"),
    ("portable", "skills/portable/finishup/SKILL.md"),
)

_START_FIRST = "read guidance and discover schemas, then call start before substantive work"
_FAIL_INTRO = "follow recovery on failure and ask for intro and guidance if startup remains blocked"
_BODY_START_FIRST = "first workflow operation is `start`"
_BODY_FAIL = "ask the user for intro and guidance"


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
    assert _BODY_START_FIRST in collapsed, host
    assert _BODY_FAIL in collapsed, host
    assert "This includes `read_guidance` and commands" in collapsed, host
    assert collapsed.index("same-request recovery first") < collapsed.index(_BODY_FAIL), host


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
    assert "then continue without FinishUP" not in rules
    assert "state the boundary and continue without FinishUP" not in rules
