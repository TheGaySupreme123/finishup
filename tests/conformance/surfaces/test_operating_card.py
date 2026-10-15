"""The operating card replaces the startup reading list (issue #1048, ADR-047).

tb4n4 D spent a median 2.8 minutes per attempt on guidance (728 calls, a median of 82 KB per
attempt) and 4.1 minutes publishing, 291 of 651 publish calls being dry runs, because the startup
surface sent agents to four large procedure pages and the publication policy prescribed a status
read and a dry run before every material publish. The card is measured here, and the startup
surface and guidance are held to the on-demand rule.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from finishup.mcp.descriptors import (
    CLAUDE_CODE_INITIALIZE_INSTRUCTIONS,
    COMPACT_INITIALIZE_INSTRUCTIONS,
)

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_CARD: Final = _REPO_ROOT / "guidance" / "agent-instructions.md"
_PACKAGED_CARD: Final = (
    _REPO_ROOT / "src" / "finishup" / "resources" / "guidance" / "agent-instructions.md"
)
_CARD_BUDGET_BYTES: Final = 8_192
_PROCEDURE_PAGES: Final = (
    "workflow.md",
    "publication-policy.md",
    "coverage-and-receipts.md",
    "request-templates.md",
)


def _collapsed(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def test_the_card_is_under_8_kib_and_smaller_than_any_procedure_page() -> None:
    size = len(_CARD.read_bytes())
    assert size < _CARD_BUDGET_BYTES, size
    assert _PACKAGED_CARD.read_bytes() == _CARD.read_bytes()
    for page in _PROCEDURE_PAGES:
        assert size * 5 < len((_REPO_ROOT / "guidance" / page).read_bytes()), page


def test_the_card_says_it_is_enough_and_names_the_inspection_check() -> None:
    text = _collapsed(_CARD)
    assert "This card is enough for ordinary work." in text
    assert "a prior `status` read or `dry_run` is optional" in text
    assert "`check` `mode: inspect` (records nothing)" in text
    assert "This card is `finishup://guidance/agent-instructions.md`; on demand only:" in text
    for page in _PROCEDURE_PAGES:
        assert f"finishup://guidance/{page}" in text, page
    # The old mandates are gone.
    assert "Read review/coverage before `check`" not in text
    assert "Before material evidence or a completion claim, read `status`" not in text


def test_the_startup_surface_reads_procedure_pages_only_on_demand() -> None:
    for initialize in (CLAUDE_CODE_INITIALIZE_INSTRUCTIONS, COMPACT_INITIALIZE_INSTRUCTIONS):
        collapsed = " ".join(initialize.split())
        assert "only" in collapsed.partition("After `start`")[2]
        assert "before `publish_work`" not in collapsed
        assert "before `check`" not in collapsed
    for host in ("claude-code", "codex", "cursor", "portable"):
        skill = _collapsed(_REPO_ROOT / "skills" / host / "finishup" / "SKILL.md")
        assert "that core is the operating card" in skill, host
        assert "other pages only when a result names them" in skill, host
        assert "before `publish_work`" not in skill, host
        assert "coverage before `check`" not in skill, host


def test_publication_policy_drops_the_status_and_dry_run_ritual() -> None:
    text = _collapsed(_REPO_ROOT / "guidance" / "publication-policy.md")
    assert "Before a material publish over MCP, read `status view=obligations`" not in text
    assert "A `status` read and a dry run before a publish are optional, not a ritual" in text
    assert "call `check` with `mode: inspect` instead of several status reads" in text
    templates = _collapsed(_REPO_ROOT / "guidance" / "request-templates.md")
    assert "Before a material publication, send the completed `publish_work` request" not in (
        templates
    )
    assert '"mode": "inspect"' in templates


def test_reference_pages_are_on_demand_and_a_rejection_is_not_every_error() -> None:
    """Review of #1048: no page reinstates the reading list or overstates a rejection.

    A rejected write names what stopped it (for drafts, the first rejected draft and field), not
    every error, and the topic and workflow headers read on demand like the card says.
    """

    workflow = _collapsed(_REPO_ROOT / "guidance" / "workflow.md")
    assert "before the first `publish_work`" not in workflow
    assert "Read before the first `start`" not in workflow
    for topic in ("publication.md", "review.md"):
        assert "Read this topic before the first" not in _collapsed(
            _REPO_ROOT / "guidance" / topic
        ), topic
    pages = [*sorted((_REPO_ROOT / "guidance").glob("*.md")), _REPO_ROOT / "CHANGELOG.md"]
    pages.append(_REPO_ROOT / "docs" / "usage" / "six-operations.md")
    for page in pages:
        text = _collapsed(page)
        assert "every validation error" not in text, page.name
        assert "names every error" not in text, page.name


def test_runbooks_record_that_each_host_gates_inspection_as_a_check() -> None:
    """Review of #1048: hosts approve tools, not modes, so an inspection is gated like `check`."""

    for host, name in (("codex", "Codex"), ("claude-code", "Claude Code"), ("cursor", "Cursor")):
        text = _collapsed(_REPO_ROOT / "docs" / "runbooks" / f"{host}-integration.md")
        section = text.partition(f"### Inspection check on {name} (#1048)")[2].partition("### ")[0]
        assert section, host
        assert "runs no review and needs no approval" not in section, host
        assert "no host-specific behavior" not in section, host
        assert "Host approval is per tool, not per mode." in section, host
        assert "Decision: supported behind the `check`" in section, host
