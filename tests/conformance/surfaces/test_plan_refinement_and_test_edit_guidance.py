"""Guidance keeps plans current and pre-existing test edits attributable (#970/#973)."""

from __future__ import annotations

from pathlib import Path
from typing import Final

_ROOT: Final = Path(__file__).resolve().parents[3]
_PLAN_RULE: Final = "before the first material edit"
_SKILLS: Final = tuple(
    _ROOT / "skills" / host / "yoetz" / "SKILL.md"
    for host in ("codex", "claude-code", "cursor", "portable")
)


def _collapsed(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def test_core_startup_and_publication_describe_plan_refinement() -> None:
    for relative in (
        "guidance/agent-instructions.md",
        "guidance/startup.md",
        "guidance/publication.md",
    ):
        text = _collapsed(_ROOT / relative)
        assert _PLAN_RULE in text
        assert "bounded exploration" in text
        assert "plan_revised" in text
        assert "testable obligation" in text
    for skill in _SKILLS:
        assert "yoetz://guidance/agent-instructions.md" in _collapsed(skill)


def test_publication_topic_requires_the_closed_test_change_marker() -> None:
    text = _collapsed(_ROOT / "guidance/publication.md")
    assert "Do not change an existing test's assertion or expectation" in text
    assert "yoetz:test-change:<action_id>:sha256:<path_digest>" in text
    assert "lowercase SHA-256 of the captured path's UTF-8 spelling" in text
    assert "generic prose does not clear the structural edit finding" in text


def test_guidance_requires_statement_sourced_obligations() -> None:
    """TB4 pilot: agents must cite the task-statement event so the mapping is checkable."""

    core = _collapsed(_ROOT / "guidance/agent-instructions.md")
    assert "`source_refs` cite the `start` event (`status view=history`)" in core
    startup = _collapsed(_ROOT / "guidance/startup.md")
    assert "Decompose the user's request yourself" in startup
    assert "`task_requirement_unmet` finding" in startup
    templates = _collapsed(_ROOT / "guidance/request-templates.md")
    assert '"source_refs": ["evt_00000000-0000-4000-8000-000000000000"]' in templates
    policy = _collapsed(_ROOT / "guidance/publication-policy.md")
    assert "You decompose the request; Yoetz checks the link." in policy


def test_publication_topic_names_the_requested_file_justification() -> None:
    text = _collapsed(_ROOT / "guidance/publication.md")
    assert "list that path as a `requested_items` entry with `item_kind` `file`" in text
    assert "hook-observed verification run made after your last observed edit" in text


def test_core_and_every_skill_carry_milestone_check_cadence() -> None:
    core = _collapsed(_ROOT / "guidance/agent-instructions.md")
    assert "`check` after the plan and each milestone" in core
    assert "an unchanged recheck returns it" in core
    workflow = _collapsed(_ROOT / "guidance/workflow.md")
    assert "a recheck with no new events returns the same finding" in workflow
    for skill in _SKILLS:
        text = _collapsed(skill)
        assert "`check` after the plan and each milestone" in text
        assert "not just recheck" in text
