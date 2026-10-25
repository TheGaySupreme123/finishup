"""Guidance, skills and every rendering agree on the closure stop signal (issue #913, ADR-032).

After ``closure_readiness.state`` reads ``ready_with_limitations`` nothing is left to do, and no
shipped surface may send the agent back to recheck unchanged state. These tests pin the phrases
agents rely on in the workflow's Completion section, the coverage guide, the receipt template and
every host skill, and check that the frozen directive every renderer shares is the owner-approved
stop sentence, instructs no further check, and never claims the work was verified.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest

from finishup.mcp.summaries import MAX_SUMMARY_BYTES
from finishup.protocol.canonical import JsonValue
from finishup.protocol.readiness_text import READINESS_STATES, readiness_directive

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_GUIDANCE: Final = _REPO_ROOT / "guidance"
_SKILLS: Final = tuple(
    _REPO_ROOT / "skills" / host / "finishup" / "SKILL.md"
    for host in ("codex", "claude-code", "cursor", "portable")
)
_APPROVED: Final = (
    "Nothing further to do. 4 standing limitation(s) and 1 acknowledged item(s) will be "
    "disclosed on the receipt. Request the receipt."
)
_UNQUALIFIED_CLAIM: Final = re.compile(r"\b(?:verified|passed|clean|no issue)\b", re.IGNORECASE)


def _collapsed(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def _section(path: Path, heading: str) -> str:
    text = path.read_text(encoding="utf-8")
    level = heading.split(" ", 1)[0]
    start = text.index(f"\n{heading}\n")
    rest = text[start + len(heading) + 2 :]
    pattern = re.compile(rf"^#{{1,{len(level)}}} ", re.MULTILINE)
    ends = [match.start() for match in pattern.finditer(rest)]
    return " ".join(rest[: ends[0] if ends else len(rest)].split())


def test_the_shared_directive_is_the_owner_approved_stop_sentence() -> None:
    assert readiness_directive("ready_with_limitations", standing=4, acknowledged="1") == _APPROVED
    for state in READINESS_STATES:
        text = readiness_directive(state, standing=4, acknowledged=1)
        # A readiness state is an instruction, never a correctness claim.
        assert _UNQUALIFIED_CLAIM.search(text) is None, state
    for state in ("ready", "ready_with_limitations"):
        # Done means done: the stop states ask for the receipt, never another check.
        text = readiness_directive(state, standing=4, acknowledged=1)
        assert "Request the receipt." in text
        assert "check" not in text.lower()


def test_workflow_completion_is_a_checklist_with_a_stop_state() -> None:
    section = _section(_GUIDANCE / "workflow.md", "## Completion")
    for phrase in (
        "Closure is a checklist. `closure_readiness.state` names the next move",
        "`action_required`: do each item in `agent_actionable`",
        "`check_not_recorded` or `check_not_applicable` (run a check after the material change)",
        "`ready_with_limitations`: nothing further to do.",
        "Request the receipt now; do not recheck unchanged state.",
        "its verdict stays coverage-bounded (a local-only check stays `insufficient_coverage`)",
        "`coverage_gaps_declared` there is a disclosure, not a task",
        "never describe an acknowledged item as done",
    ):
        assert phrase in section, phrase


def test_coverage_guide_explains_the_three_groups_and_the_closed_table() -> None:
    text = _collapsed(_GUIDANCE / "coverage-and-receipts.md")
    for phrase in (
        "## Closure readiness: actionable, standing, acknowledged",
        "A closed, versioned table (`gap_classification_version`) assigns every gap code",
        "`semantic_review_not_requested` is standing on a route where AI-powered review is "
        "optional or off",
        "`unclassified_gap:<code>` in `agent_actionable`",
        "Classification never removes a gap from `known_gaps`, never changes a verdict",
        "When `closure_readiness.state` is `ready_with_limitations`, request the receipt without "
        "another check.",
    ):
        assert phrase in text, phrase


def test_receipt_template_stops_at_ready_with_limitations() -> None:
    section = _section(_GUIDANCE / "request-templates.md", "## `receipt`")
    assert (
        "At `state: ready_with_limitations` fix, or decline with a reason, each `fix_or_decline` "
        "item (receipt.md step 7); otherwise nothing further is to do: request the receipt without "
        "another check" in section
    )


@pytest.mark.parametrize("skill", _SKILLS, ids=lambda path: path.parts[-3])
def test_every_host_skill_names_the_stop_signal(skill: Path) -> None:
    text = _collapsed(skill)
    assert "ready_with_limitations" in text
    assert "nothing further is to do" in text
    assert "request the receipt without another check" in text
    # Issue #1209: the fix-or-decline step precedes the receipt on every host.
    assert "fix or decline with a reason each `fix_or_decline` item; then nothing further" in text
    assert "`standing_limitations` are disclosed, never tasks" in text


@pytest.mark.parametrize(
    "path",
    (
        _GUIDANCE / "workflow.md",
        _GUIDANCE / "coverage-and-receipts.md",
        _GUIDANCE / "request-templates.md",
        *_SKILLS,
    ),
    ids=lambda path: "/".join(path.parts[-3:]),
)
def test_no_shipped_sentence_recommends_rechecking_after_the_stop_state(path: Path) -> None:
    text = _collapsed(path)
    for sentence in re.split(r"(?<=[.;:])\s+", text):
        if "ready_with_limitations" not in sentence:
            continue
        lowered = sentence.lower()
        if "check" in lowered.replace("checklist", ""):
            assert any(
                negation in lowered
                for negation in ("without another check", "do not recheck", "not recheck")
            ), sentence


@pytest.mark.parametrize("view", ("advice", "lineage", "project", "compact"))
def test_every_status_view_summary_names_the_closure_state(view: str) -> None:
    """The checklist rides on every view, so every view's text names it (Greptile P2)."""

    from finishup.mcp.summaries import summary_for_status

    readiness: dict[str, JsonValue] = {
        "declared_obligation_count": "1",
        "no_obligations_reason": None,
        "open_obligation_count": "0",
        "unanswered_finding_count": "0",
        "receipt_blocking_finding_count": "0",
        "blocking_conditions": ["coverage_gaps_declared"],
        "state": "ready_with_limitations",
        "gap_classification_version": "1",
        "agent_actionable": [],
        "standing_limitations": ["host_outcome_unavailable", "unpaired_event"],
        "acknowledged_not_done": [],
        "acknowledged_not_done_count": "0",
    }
    page: dict[str, JsonValue] = {"items": [], "next_cursor": None}
    if view == "lineage":
        page = {"parent_task_id": None, "children": [], "annotations": [], "next_cursor": None}
    elif view == "project":
        page = {
            "project_id": None,
            "lineage": {"children": [], "annotations": []},
            "next_cursor": None,
        }
    envelope: dict[str, JsonValue] = {
        "ok": True,
        "view": view,
        "result_frontier": {"sequence": "9", "head_digest": "sha256:" + "a" * 64},
        "page": page,
        "coverage": {"ledger_freshness": "current", "known_gaps": []},
        "gaps": ["host_outcome_unavailable", "unpaired_event"],
        "closure_readiness": readiness,
    }
    summary = summary_for_status(envelope)
    assert "Closure: ready_with_limitations. Nothing further to do." in summary
    assert summary.endswith("Request the receipt.") or "Standing limitations:" in summary
    if view != "project":
        # The project page's long prefix leaves room only for the bounded short form.
        assert (
            "Nothing further to do. 2 standing limitation(s) and 0 acknowledged item(s) will be "
            "disclosed on the receipt. Request the receipt." in summary
        )
    assert len(summary.encode("ascii")) <= MAX_SUMMARY_BYTES
