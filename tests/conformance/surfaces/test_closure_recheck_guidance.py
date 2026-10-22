"""Closure guidance never sends an agent on a frontier hunt or into a recheck that cannot matter.

Issue #911 (DeepSWE 2026-09 post-mortem): agents probed historical frontiers to answer a finding
because the guidance said to use "the result frontier of the check that returned it"; they
rechecked after `work_closed`, after answering the check's own findings, and after answering the
observation advisory; and they ran a `deterministic_only` "fallback" after `insufficient_packet`.
Every one of those rechecks returned the identical result. These cases pin the corrected closure
order in the shared guidance and every host skill, while keeping the productive recheck after a
recorded repair.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_GUIDANCE: Final = _REPO_ROOT / "guidance"
_SKILLS: Final = tuple(
    _REPO_ROOT / "skills" / host / "finishup" / "SKILL.md"
    for host in ("claude-code", "codex", "cursor", "portable")
)


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


def test_repair_then_finish_orders_findings_check_receipt_then_work_closed() -> None:
    section = _section(_GUIDANCE / "coverage-and-receipts.md", "## Repair then finish")
    before = section.index("Before the final check, read `status view=findings`")
    after = section.index(
        "After the final check, respond only to the findings it returned that are still unanswered"
    )
    closing = section.index("Request `receipt`, then publish `work_closed`")
    assert before < after < closing
    for phrase in (
        "Responses to the check's own findings, an acknowledgement of an observation-authored "
        "non-actionable finding, and `work_closed` need no recheck.",
        # The convergence guard: removing futile rechecks never removes the productive one.
        "a recorded repair (it always gets at least one re-check)",
        "`work_closed` never requires another check",
    ):
        assert phrase in section, phrase


def test_lifecycle_closure_and_limitation_acknowledgements_are_not_material() -> None:
    attribution = _section(_GUIDANCE / "coverage-and-receipts.md", "## Coverage attribution")
    assert "acknowledgements of observation-authored non-actionable findings" in attribution
    assert "`work_closed` (and the other work-state and delegation lifecycle events) never " in (
        attribution
    )
    # Productive rechecks stay: any other answer to a finding the check did not return is
    # material, including a rejection of an observation-authored finding.
    assert "any other response to a finding the check did not return" in attribution
    assert "a rejection of an observation-authored finding included" in attribution


def test_observation_limitation_findings_never_block_and_need_no_wait() -> None:
    findings = _section(_GUIDANCE / "coverage-and-receipts.md", "## Findings and responses")
    for phrase in (
        "Observation-authored findings that are not actionable (priority 3",
        "They never block the receipt and never count in `unanswered_finding_count` or "
        "`findings_unanswered`, so they need no response.",
        "To note the disclosure, answer one once `acknowledged` with a short reason",
        "never resolves the finding",
        "a standing gap such as `unpaired_event` does not recover within the session",
    ):
        assert phrase in findings, phrase
    workflow = _collapsed(_GUIDANCE / "workflow.md")
    assert "wait for drain to recover" not in workflow
    assert "wait only while it reports lag or a drain backlog" in workflow


@pytest.mark.parametrize(
    "name",
    (
        "coverage-and-receipts.md",
        "workflow.md",
        "request-templates.md",
        "publication-policy.md",
        # The mandatory core defers the closure order to the focused receipt topic (#961).
        "receipt.md",
    ),
)
def test_no_guidance_requires_the_exact_check_result_frontier(name: str) -> None:
    text = _collapsed(_GUIDANCE / name)
    assert "Use `finding_frontier` = the result frontier" not in text
    assert "at the result frontier of the check that returned it" not in text
    assert "The response frontier is the result frontier" not in text
    assert "current status frontier" in text


def test_the_mandatory_core_never_sends_an_agent_on_a_frontier_hunt() -> None:
    text = _collapsed(_GUIDANCE / "agent-instructions.md")
    assert "result frontier" not in text
    assert "`receipt.md`" in text


def test_respond_template_names_the_frontier_to_use() -> None:
    text = _collapsed(_GUIDANCE / "request-templates.md")
    assert (
        "Use `finding_frontier` = any frontier at or after the finding's own record: the item's "
        "`finding_frontier` from `status view=findings` when it carries one, otherwise the "
        "current status frontier"
    ) in text
    assert "No historical frontier search is needed." in text


_SUPPLY_LIMIT: Final = (
    # 83abdad0d (#1100 DOC fixes): an item may name no target, so the link is to "any named" one.
    "If `missing_for_assessment` names an `agent_suppliable` item you can supply, publish exactly "
    "that item once, linked to any named target, then `check` again. If it is already supplied, or it "
    "is a packet, type or authority limit, go to the receipt and state that specific limit."
)
_OBSERVED_OUTPUT: Final = (
    "Observed test, build, lint, or typecheck output reaches the reviewer only when a repository "
    "excerpt would be sent."
)
# W6 (#1107, ADR-006 amendment): a re-run FinishUP observed counts only once its output reaches
# the reviewer; a respond counts only for a finding target, a description never.
_OBSERVED_RERUN: Final = "counts only once it reaches the reviewer"
_RESPOND_RULE: Final = "a respond counts only when the target is a finding"


@pytest.mark.parametrize(
    "name", ("coverage-and-receipts.md", "workflow.md", "agent-instructions.md", "receipt.md")
)
def test_insufficient_packet_goes_to_the_receipt_not_a_deterministic_fallback(name: str) -> None:
    text = _collapsed(_GUIDANCE / name)
    assert "insufficient_packet" in text
    assert "go to the receipt" in text
    if name != "workflow.md":
        assert _SUPPLY_LIMIT in text
    if name in {"agent-instructions.md", "receipt.md"}:
        assert _OBSERVED_OUTPUT in text
        assert "never counts as agent-supplied" not in text
    if name == "receipt.md":
        assert _OBSERVED_RERUN in text
        assert _RESPOND_RULE in text
    # The workflow page keeps the explicit local-only ban; the other three share one sentence.
    assert any(
        phrase in text
        for phrase in (
            "deterministic_only` fallback",
            "never use `deterministic_only` merely to shorten closure",
            "go to the receipt rather than a local-only fallback",
            "state that specific limit",
        )
    )


def test_the_initialize_safety_floor_carries_the_closure_order() -> None:
    core = _collapsed(_GUIDANCE / "agent-instructions.md")
    assert "Publish claim/evidence before the final check; answer findings, check, and " in core
    assert "Recheck only after repair/material record." in core
    # The full closure order lives in the focused receipt topic the core names (#961).
    text = _collapsed(_GUIDANCE / "receipt.md")
    assert "Answer each finding once; its `finding_frontier` may be the current status" in text
    assert "answer each unanswered finding" in text
    assert "answer only the findings it returned that remain unanswered" in text
    assert "a material repair needs a qualifying recheck" in text
    assert "and `work_closed` do not need a recheck" in text
    assert "Non-actionable observation-authored findings need no answer." in text


@pytest.mark.parametrize("path", _SKILLS, ids=lambda path: path.parent.parent.name)
def test_every_host_skill_carries_the_same_closure_order(path: Path) -> None:
    text = _collapsed(path)
    assert "at its result frontier" not in text
    assert "at the result frontier" not in text
    # The budgeted skills (8 KiB with the core) keep the stop signal and the finding rules; the
    # closure order is stated once, in the operating card (tb4n5 startup dedup, ADR-047), and the
    # frontier and no-answer rules ride in the receipt topic every host carries (#961).
    assert "publish evidence before `check`" not in text
    assert "A `respond` does not clear a finding." in text
    card = _collapsed(_GUIDANCE / "agent-instructions.md")
    assert "Publish claim/evidence before the final check; answer findings, check, and " in card
    assert "Cadence: `start` once, `publish_work` per material transition; `receipt` last." in card


def test_close_guidance_states_the_work_closed_rule_the_service_enforces() -> None:
    """Review of #1169: no surface waits for a close permission that nothing advertises.

    The service admits `work_closed` from the task's active session while work is `open`, and
    refuses a task that already ended (for example abandoned after lost contact) as
    `lineage_work_transition` (`tests/conformance/observation/test_lineage_recovery_public_workflow.py`).
    No result advertises a lifecycle continuation that permits closing, so an agent told to wait
    for one leaves open work open, and one told to "read lineage once" retries a terminal task.
    """

    surfaces = [*sorted(_GUIDANCE.glob("*.md")), *_SKILLS]
    for path in surfaces:
        text = _collapsed(path)
        assert "lifecycle continuation" not in text, path.name
        assert "close continuation" not in text, path.name
    card = _collapsed(_GUIDANCE / "agent-instructions.md")
    assert "Then publish `work_closed` if the work is complete; a receipt never closes it." in card
    assert "`lineage_work_transition` means the task already ended: report it." in card
    closing = _section(_GUIDANCE / "receipt.md", "## Closing sequence")
    assert "publish `work_closed` from the task's active session; it needs no recheck." in closing
    assert "Only `open` work closes: `lineage_work_transition` means the task already ended" in (
        closing
    )
    assert "Do not retry the close or open a new task for it" in closing
