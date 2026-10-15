"""Evidence discovery guidance asks only for what the agent can see (issue #914).

The shipped guidance used to tell agents to read every page of `status view=evidence` and match
items on their bounded description before publishing evidence or claiming completion. Under the
default `agent_context` ceiling every other writer's and every host-observed description projects
as omitted (`local_disclosure_not_authorized`), so the walk could never match: in the DeepSWE v2
run agents paged 90,668 blanked rows across 1,037 pages and reused a walked ID once in 58
attempts. These tests keep the old procedure out of every shipped surface and pin the replacement:
cite the IDs you published, find native captures with a filter, relate them only through a
structural link, and read an omitted description as a privacy setting rather than absence.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest

from finishup.mcp.descriptors import TOOL_DESCRIPTORS, McpRouteProfile, descriptor_for

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_GUIDANCE: Final = _REPO_ROOT / "guidance"
_SKILLS: Final = tuple(
    _REPO_ROOT / "skills" / host / "finishup" / "SKILL.md"
    for host in ("claude-code", "codex", "cursor", "portable")
)
_SHIPPED: Final = (
    *sorted(_GUIDANCE.glob("*.md")),
    *_SKILLS,
    *sorted((_REPO_ROOT / "src" / "finishup" / "resources" / "guidance").glob("*.md")),
    *sorted((_REPO_ROOT / "src" / "finishup" / "resources" / "skills").glob("*/finishup/SKILL.md")),
)
_DISCOVER: Final = "## Discover evidence before authoring replacements"

# Each pattern is one phrasing of the retired unfiltered walk or its description match.
_RETIRED: Final = (
    re.compile(r"read every page of `status view=evidence`", re.IGNORECASE),
    re.compile(r"\bbounded description\b", re.IGNORECASE),
    re.compile(r"paginate `?(?:status )?view=evidence`?", re.IGNORECASE),
    re.compile(r"reuse only matching (?:observed|permitted)", re.IGNORECASE),
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


@pytest.mark.parametrize("path", _SHIPPED, ids=lambda path: str(path.relative_to(_REPO_ROOT)))
def test_no_shipped_guidance_prescribes_the_unfiltered_description_walk(path: Path) -> None:
    text = _collapsed(path)
    for pattern in _RETIRED:
        assert pattern.search(text) is None, pattern.pattern


@pytest.mark.parametrize("profile", sorted(TOOL_DESCRIPTORS))
def test_no_tool_description_prescribes_the_unfiltered_walk(profile: McpRouteProfile) -> None:
    for descriptor in TOOL_DESCRIPTORS[profile]:
        for pattern in _RETIRED:
            assert pattern.search(descriptor.description) is None, (descriptor.name, pattern)


@pytest.mark.parametrize("name", ("publication-policy.md", "coverage-and-receipts.md"))
def test_discovery_procedure_uses_published_ids_filters_and_structural_links(name: str) -> None:
    section = _section(_GUIDANCE / name, _DISCOVER)
    for phrase in (
        "Cite the `evidence_id`s you already published",
        "they are in your own `publish_work` requests",
        "`status view=evidence` with `filter.author=mine` lists exactly the items you published",
        "with their descriptions returned to you",
        "Find native captures with `filter.strength=immutable_snapshot`",
        "every row names its `publication_channel`",
        "Host-observed and other writers' descriptions stay omitted unless the owner grants",
        "Preserve the view, filter, frontier and original `limit` with each cursor",
        "Cite a native capture only when a structural link you can read ties it to the claim",
        "a `status view=results` row whose `evidence_refs` names it",
        "if no structural link establishes the relation, leave it unknown",
        "omitted with `local_disclosure_not_authorized` is a privacy setting, not missing evidence",
        "republishing it does not reveal it",
        "match on descriptions only when the current projection shows them",
        "never page through every item to match prose the projection omits",
    ):
        assert phrase in section, phrase


def test_codex_skill_routes_evidence_first_closure_to_the_workflow_topic() -> None:
    text = _collapsed(_REPO_ROOT / "skills" / "codex" / "finishup" / "SKILL.md")
    # Issue #1048: the core is the operating card; other pages are read on demand. Since the
    # tb4n5 startup dedup the card alone names `workflow.md`, where evidence-first closure lives.
    assert "that core is the operating card" in text
    assert "other pages only when a result names them" in text
    card = _collapsed(_GUIDANCE / "agent-instructions.md")
    assert (
        "on demand only: resume/recovery/delegation/capacity `finishup://guidance/workflow.md`"
        in (card)
    )
    assert "\n## Evidence-first closure\n" in (_GUIDANCE / "workflow.md").read_text(
        encoding="utf-8"
    )


def test_agent_instructions_floor_names_the_filtered_discovery() -> None:
    text = _collapsed(_GUIDANCE / "agent-instructions.md")
    for phrase in (
        # Issue #1048: no mandatory status read before a write; discovery stays named.
        "a prior `status` read or `dry_run` is optional",
        "Cite IDs you published; find native captures with `view=evidence` filter "
        "`strength=immutable_snapshot`",
        "reusing only IDs a structural link ties to the claim",
        "Omitted descriptions are a privacy setting, not missing evidence",
    ):
        assert phrase in text, phrase


def test_tool_descriptions_name_published_ids_and_the_snapshot_filter() -> None:
    status = descriptor_for("status").description
    assert "cite IDs you published" in status
    assert "view=evidence filter.author=mine" in status
    assert "filter.strength=immutable_snapshot" in status
    assert "results row's evidence_refs" in status
    assert "Omitted descriptions (privacy)" in status
    assert "cite IDs you published" in descriptor_for("publish_work").description


@pytest.mark.parametrize(
    "runbook",
    ("claude-code-integration.md", "codex-integration.md", "cursor-integration.md"),
)
def test_every_host_runbook_records_the_filtered_discovery(runbook: str) -> None:
    section = _section(_REPO_ROOT / "docs" / "runbooks" / runbook, "### Evidence-first closure")
    assert "`filter.strength=immutable_snapshot`" in section
    assert "`filter.author=mine`" in section
    assert "It no longer asks for an unfiltered walk that matches on descriptions" in section
    for pattern in _RETIRED:
        assert pattern.search(section) is None, pattern.pattern
