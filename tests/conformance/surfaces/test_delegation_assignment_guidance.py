"""Delegation guidance tells the parent what a child's assignment carries (issue #509).

A native helper sees host skill listings and initialize instructions that say to call `start`,
but nothing there says it is a child. In the #509 qualification run a delegated child reported
that every child duty it followed came from the parent's prompt, and an unregistered helper noted
that the initialize trigger, read literally, applied to its own file edits. These tests pin the
assignment contents, the child's own closure sequence, and the no-selector rule in the workflow
procedure and every host skill.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_AGENT_INSTRUCTIONS: Final = _REPO_ROOT / "guidance" / "agent-instructions.md"
_WORKFLOW: Final = _REPO_ROOT / "guidance" / "workflow.md"
_SKILLS: Final = tuple(
    _REPO_ROOT / "skills" / host / "yoetz" / "SKILL.md"
    for host in ("claude-code", "codex", "cursor", "portable")
)
_CHILD_SECTION: Final = "#### Child assignment and child closure"


def _collapsed(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def _section(path: Path, heading: str) -> str:
    text = path.read_text(encoding="utf-8")
    level = heading.split(" ", 1)[0]
    start = text.index(f"\n{heading}\n")
    rest = text[start + len(heading) + 2 :]
    pattern = re.compile(rf"^#{{1,{len(level)}}} ", re.MULTILINE)
    ends = [m.start() for m in pattern.finditer(rest)]
    return " ".join(rest[: ends[0] if ends else len(rest)].split())


def test_workflow_lists_what_a_child_assignment_carries() -> None:
    section = _section(_WORKFLOW, _CHILD_SECTION)
    for phrase in (
        "A native helper learns its Yoetz role only from its assignment",
        "the complete `attach_handle`, to use before its `expires_at` and before other work",
        "the parent `session_id` for `parent_session_id` plus a stable child-specific "
        "`workspace_ref` + `external_ref` pair (the canonical root the child works in; never the "
        "parent's pair)",
        "a distinct child actor id, the bounded scope and write policy, and, after a "
        "`terminal_unavailable` result, the `yoetz_availability` block",
    ):
        assert phrase in section, phrase


def test_workflow_gives_the_child_its_own_closure_sequence_ending_in_work_closed() -> None:
    section = _section(_WORKFLOW, _CHILD_SECTION)
    sequence = (
        "publish its plan and obligations, results and evidence, and completion claim; `check`; "
        "`respond` to each finding it returns, repairing and rechecking where the finding "
        "requires it; `receipt`; then `work_closed`, because a receipt never closes work"
    )
    assert sequence in section
    assert "reports its task and receipt ids and limits back to the parent" in section
    assert (
        "the parent publishes `child_accepted` or `child_rejected` after the child reports its "
        "task id" in section
    )


def test_workflow_makes_the_no_selector_rule_a_parent_duty_covered_by_the_parent_task() -> None:
    section = _section(_WORKFLOW, _CHILD_SECTION)
    for phrase in (
        "A helper that gets neither selector does no Yoetz work of its own",
        "its work is the parent's to account for: the parent's own obligations cover "
        "incorporating and verifying it, and the parent discloses what the helper did that the "
        "ledger does not show",
        "This is not the startup fallback in startup failure precedence",
        "Tell it so in the assignment in plain words",
        "because its initialize instructions otherwise tell it to call `start`",
        "It does not create a root task for delegated work",
    ):
        assert phrase in section, phrase


def test_workflow_limits_parent_publication_about_a_child_to_its_own_decisions() -> None:
    section = _section(_WORKFLOW, _CHILD_SECTION)
    assert (
        "The parent never publishes a child's plan, results, evidence, claim, or closure as if it "
        "were the child's" in section
    )
    assert (
        "(`child_accepted`, `child_rejected`, `delegation_cancelled`, `child_written_off`)"
        in section
    )
    assert "A child's text report is a claim, not its receipt" in section


def test_the_child_subsection_does_not_absorb_the_parent_level_delegation_rules() -> None:
    section = _section(_WORKFLOW, _CHILD_SECTION)
    assert "Parent checks use the latest dependency manifest" not in section
    assert "Work state, session health, and receipt history are separate" not in section
    delegation = _section(_WORKFLOW, "### Delegation and project coordination")
    assert "Parent checks use the latest dependency manifest" in delegation


def test_safety_floor_routes_delegation_to_the_workflow_rules() -> None:
    # The MCP-initialize safety floor has no headroom under the replicated advertised-surface
    # budget (the strict profile is within a few characters), so, like the #828 capacity rule, the
    # child-assignment rules live in the workflow procedure and every skill, which it points to.
    section = _section(_AGENT_INSTRUCTIONS, "# Multi-agent work")
    assert "read the multi-agent sections of `yoetz://guidance/workflow.md`" in section


@pytest.mark.parametrize("skill", _SKILLS, ids=lambda path: path.parts[-3])
def test_every_skill_names_the_assignment_and_child_closure(skill: Path) -> None:
    text = _collapsed(skill)
    assert "yoetz://guidance/workflow.md#start-and-resume" in text
    assert "delegation" in text
    assert "closure" in text
