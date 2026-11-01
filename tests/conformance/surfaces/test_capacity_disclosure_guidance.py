"""Agent guidance, skills, and the shared renderer say the same thing about capacity (issue #828).

A larger or uncapped observation capacity is a local-hardware and cost decision that belongs to
the owner. The guidance tells agents to run the preview, relay its disclosure, apply only after
acceptance, and relay the typed no-cap outcome verbatim. These tests pin the phrases agents rely
on in every shipped guidance source and check that the one human renderer used by the CLI and the
terminal interface actually emits the sentences the guidance and user documentation promise.

The MCP-initialize safety floor (`agent-instructions.md`) carries no capacity section: with its
unrelated passages intact it already fills the replicated advertised-surface budget, so the rule
lives in the workflow procedure. Since tb4n5 (P4) every skill keeps only the one-line consent
floor and names that procedure's catalogued topic, `workflow.md#change-local-retention-capacity`;
the commands, the lower/pause/resume path and the no-cap outcome are pinned once, there.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest

from finishup.domain.observation_budget import ObservationCapacity, parse_capacity_request
from finishup.domain.observation_capacity_policy import (
    capacity_change_disclosure,
    render_capacity_disclosure_lines,
)
from finishup.mcp.resources import read_resource
from finishup.protocol.guidance_uris import GUIDANCE_TOPIC_URIS

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_AGENT_INSTRUCTIONS: Final = _REPO_ROOT / "guidance" / "agent-instructions.md"
_WORKFLOW: Final = _REPO_ROOT / "guidance" / "workflow.md"
_USAGE: Final = _REPO_ROOT / "docs" / "usage" / "observation-selection.md"
_SKILLS: Final = tuple(
    _REPO_ROOT / "skills" / host / "finishup" / "SKILL.md"
    for host in ("codex", "claude-code", "cursor", "portable")
)
_SECTION_TITLE: Final = "Capacity and cost changes need a disclosed choice"
_CAPACITY_TOPIC: Final = "finishup://guidance/workflow.md#change-local-retention-capacity"
_NO_CAP_TOKEN: Final = "capacity_no_cap_unsupported"


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


def test_workflow_carries_the_complete_disclosed_choice_rules() -> None:
    section = _section(_WORKFLOW, "### Change local retention capacity")
    for phrase in (
        f"{_SECTION_TITLE}.",
        "Never choose a larger or uncapped local capacity for an ordinary task",
        "task permission, a busy queue, or a pressure notice never authorizes it",
        "the exact scope",
        "current and requested values",
        "disk use, memory use, CPU work, possible slowdown of FinishUP or other apps",
        "what stays limited, and how to lower, pause, and resume",
        "Repeat the scope and the remaining limits exactly as the preview states them",
        "The shared workspace queue follows the largest active selection, so an increase can raise "
        "the queue and state-document bounds for every session in that workspace",
        "use `<workspace>` and `<session-id>` placeholders",
        "never call a larger setting safe without evidence or faster",
        "never describe unknown cost as free",
        "never imply provider limits vanished",
        "Only after the user explicitly accepts that exact preview",
        "Explain how to lower or pause before and after applying",
    ):
        assert phrase in section, phrase


def test_workflow_gives_the_preview_accept_apply_commands_and_the_no_cap_outcome() -> None:
    section = _section(_WORKFLOW, "### Change local retention capacity")
    for phrase in (
        "finishup observe selection-status --workspace /exact/project",
        "finishup observe selection-preview --workspace /exact/project",
        "--capacity custom --queue-count 1024",
        "finishup observe selection-apply --workspace /exact/project",
        "--accept --preview-digest <preview-digest>",
        "`custom` with `--queue-count` from 64 to 8,192",
        "finishup observe pause --workspace /exact/project",
        "finishup observe resume --workspace /exact/project",
        "accepted records drain and are not deleted",
        f"return `{_NO_CAP_TOKEN}` and change nothing",
        "16 MiB safety ceiling",
        "8,192 rows",
        "Relay that outcome as given, with its alternative command",
        "do not describe any setting as unlimited",
    ):
        assert phrase in section, phrase


def test_agent_instructions_keep_the_safety_floor_within_budget() -> None:
    text = _collapsed(_AGENT_INSTRUCTIONS)
    for phrase in (
        "Never publish hidden reasoning or chain-of-thought,",
        "full prompts, transcripts, conversation history, credentials, secrets, whole files/repositories,",
        "Select `semantic_required` when the user, effective policy, or named acceptance criterion",
        # Issue #1048 (ADR-047): no mandatory status read before a write; citation stays bounded.
        "Cite IDs you published; find native captures",
    ):
        assert phrase in text, phrase


@pytest.mark.parametrize("skill", _SKILLS, ids=lambda path: path.parents[1].name)
def test_every_skill_keeps_the_consent_floor_and_names_the_capacity_topic(skill: Path) -> None:
    text = _collapsed(skill)
    for phrase in (
        f"{_SECTION_TITLE}: never choose a larger or uncapped local observation capacity for an "
        "ordinary task",
        f"change it only on request, after the user accepts the preview in `{_CAPACITY_TOPIC}`",
    ):
        assert phrase in text, phrase
    # The procedure is stated once, in the topic, not repeated in four budgeted skills (tb4n5 P4).
    for procedure in ("selection-preview", _NO_CAP_TOKEN, "lower/pause/resume"):
        assert procedure not in text, procedure
    assert _CAPACITY_TOPIC in GUIDANCE_TOPIC_URIS
    topic = " ".join(read_resource(_CAPACITY_TOPIC).decode("utf-8").split())
    assert topic.startswith("### Change local retention capacity")
    assert f"{_SECTION_TITLE}." in topic
    assert "finishup observe selection-preview --workspace /exact/project" in topic
    assert f"return `{_NO_CAP_TOKEN}` and change nothing" in topic


def test_renderer_emits_the_increase_consequences_the_guidance_names() -> None:
    disclosure = capacity_change_disclosure(
        current=ObservationCapacity(512),
        current_origin="default",
        requested=parse_capacity_request("custom", queue_count=1024),
        scope="session",
    )
    assert disclosure["change"] == "increase"
    lines = render_capacity_disclosure_lines(disclosure)
    assert lines[0] == (
        "Larger local retention can increase disk use, memory use and CPU work, "
        "and may slow FinishUP or other apps."
    )
    rendered = " ".join(lines)
    assert (
        "Still limited: 256 pending pairs, 512 capture tickets / 128 MiB, 16 MiB state document"
        in (rendered)
    )
    assert (
        "Lower it later with: finishup observe selection-preview --workspace <workspace>"
        in rendered
    )
    assert "Pause new observation ingest with: finishup observe pause --workspace <workspace>" in (
        rendered
    )
    assert "Resume with: finishup observe resume --workspace <workspace>" in rendered
    assert "Performance validation is provisional (not_validated)." in rendered
    consequences = disclosure["consequences"]
    assert isinstance(consequences, (list, tuple))
    assert "workspace_aggregate_raised" in consequences
    assert disclosure["resume_command"] == "finishup observe resume --workspace <workspace>"
    aggregate = (
        "The shared workspace queue follows the largest active selection, so this can raise the "
        "queue and state-document bounds for every session in the workspace."
    )
    assert aggregate in lines
    usage = _collapsed(_USAGE)
    assert " ".join(lines[0].split()) in usage
    assert aggregate in usage


def test_renderer_emits_the_no_cap_outcome_the_guidance_says_to_relay() -> None:
    request = parse_capacity_request("none")
    assert request.kind == "no_cap"
    disclosure = capacity_change_disclosure(
        current=ObservationCapacity(512),
        current_origin="default",
        requested=request,
        scope="workspace",
    )
    assert disclosure["change"] == "unsupported"
    lines = render_capacity_disclosure_lines(disclosure)
    assert lines == (
        "No FinishUP cap is not available for the structural queue in this revision: the local "
        "state document has a 16 MiB safety ceiling. The largest supported finite capacity is "
        "8,192 rows (--capacity largest or --capacity custom --queue-count 8192).",
    )
    assert lines[0] in _collapsed(_USAGE)
