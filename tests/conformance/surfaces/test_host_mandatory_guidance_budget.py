"""The host-injected initialize block and skill stay within the startup context budget."""

from __future__ import annotations

from pathlib import Path
from typing import Final

from yoetz.mcp.descriptors import (
    CLAUDE_CODE_INITIALIZE_INSTRUCTIONS,
    COMPACT_INITIALIZE_INSTRUCTIONS,
)

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_BUDGET_BYTES: Final = 8_192
_MANDATORY_CORE: Final = _REPO_ROOT / "guidance/agent-instructions.md"
_HOST_SKILLS: Final = {
    "claude-code": (_REPO_ROOT / "skills/claude-code/yoetz/SKILL.md", "claude"),
    "codex": (_REPO_ROOT / "skills/codex/yoetz/SKILL.md", "compact"),
    "cursor": (_REPO_ROOT / "skills/cursor/yoetz/SKILL.md", "compact"),
    "portable": (_REPO_ROOT / "skills/portable/yoetz/SKILL.md", "compact"),
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


def test_only_the_compact_core_is_mandatory_before_start() -> None:
    """Procedure topics remain addressable without becoming startup context."""

    for skill_path, _ in _HOST_SKILLS.values():
        text = skill_path.read_text(encoding="utf-8")
        assert "yoetz://guidance/agent-instructions.md" in text
        assert "After start" in text
    for initialize in (CLAUDE_CODE_INITIALIZE_INSTRUCTIONS, COMPACT_INITIALIZE_INSTRUCTIONS):
        before_start, separator, after_start = initialize.partition("After `start`")
        assert separator
        assert "yoetz://guidance/agent-instructions.md" in before_start
        assert "yoetz://guidance/workflow.md" not in before_start
        assert "startup.md" not in before_start
        assert "read workflow" in after_start
