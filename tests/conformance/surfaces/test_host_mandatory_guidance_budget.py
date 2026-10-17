"""The host-injected initialize block and skill stay within the startup context budget."""

from __future__ import annotations

from pathlib import Path
from typing import Final

from finishup.mcp.descriptors import (
    CLAUDE_CODE_INITIALIZE_INSTRUCTIONS,
    COMPACT_INITIALIZE_INSTRUCTIONS,
    McpHostProfile,
    server_instructions,
)

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_BUDGET_BYTES: Final = 8_192
_MANDATORY_CORE: Final = _REPO_ROOT / "guidance/agent-instructions.md"
_HOST_SKILLS: Final = {
    "claude-code": (_REPO_ROOT / "skills/claude-code/finishup/SKILL.md", "claude"),
    "codex": (_REPO_ROOT / "skills/codex/finishup/SKILL.md", "compact"),
    "cursor": (_REPO_ROOT / "skills/cursor/finishup/SKILL.md", "compact"),
    "portable": (_REPO_ROOT / "skills/portable/finishup/SKILL.md", "compact"),
}


def test_initialize_plus_host_skill_fits_the_mandatory_8kib_budget() -> None:
    """Initialize, skill, and the one required pre-start core fit the host budget."""

    initialize_bytes = {
        "claude": len(CLAUDE_CODE_INITIALIZE_INSTRUCTIONS.encode("utf-8")),
        "compact": len(COMPACT_INITIALIZE_INSTRUCTIONS.encode("utf-8")),
    }
    for host, (skill_path, initialize_kind) in _HOST_SKILLS.items():
        skill_bytes = len(skill_path.read_bytes())
        core_bytes = len(_MANDATORY_CORE.read_bytes())
        total = skill_bytes + core_bytes + initialize_bytes[initialize_kind]
        assert total <= _BUDGET_BYTES, (
            f"{host} mandatory host surface is {total} bytes; budget is {_BUDGET_BYTES} bytes"
        )


# The host profile whose initialize block each skill is served beside. The portable skill rides the
# compact block the Codex and Cursor profiles share.
_SERVED_PROFILE: Final[dict[str, McpHostProfile]] = {
    "claude-code": "claude",
    "codex": "codex",
    "cursor": "cursor",
    "portable": "codex",
}


def test_the_served_startup_surface_with_its_route_tail_fits_the_budget() -> None:
    """Review R8 of PR #1088: count the initialize block exactly as it is served.

    ``server_instructions`` appends a mandatory route line to the packaged body on every route,
    and the strict route's line is the longer one. The budget holds for both routes on every host,
    without the optional AI-powered-review destination disclosure, which keeps its own separate
    allowance (ADR-043).
    """

    core_bytes = len(_MANDATORY_CORE.read_bytes())
    for host, (skill_path, _kind) in _HOST_SKILLS.items():
        skill_bytes = len(skill_path.read_bytes())
        for route in ("policy", "strict"):
            served = server_instructions(route, host_profile=_SERVED_PROFILE[host])
            total = core_bytes + skill_bytes + len(served.encode("utf-8"))
            assert total <= _BUDGET_BYTES, (
                f"{host} {route} served startup surface is {total} bytes; "
                f"budget is {_BUDGET_BYTES} bytes"
            )


def test_only_the_compact_core_is_mandatory_before_start() -> None:
    """Procedure topics remain addressable without becoming startup context."""

    for skill_path, _ in _HOST_SKILLS.values():
        text = skill_path.read_text(encoding="utf-8")
        assert "finishup://guidance/agent-instructions.md" in text
        assert "After start" in text
    for initialize in (CLAUDE_CODE_INITIALIZE_INSTRUCTIONS, COMPACT_INITIALIZE_INSTRUCTIONS):
        before_start, separator, after_start = initialize.partition("After `start`")
        assert separator
        assert "finishup://guidance/agent-instructions.md" in before_start
        assert "finishup://guidance/workflow.md" not in before_start
        assert "startup.md" not in before_start
        assert "read workflow" in after_start
