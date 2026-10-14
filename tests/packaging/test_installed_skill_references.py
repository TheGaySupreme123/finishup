"""Every reference the installed skill names must resolve without a repository checkout.

The 2026-07-27 Codex dogfood could not author a `start` request from the installed guidance:
`SKILL.md` linked four `references/*.md` files that were never packaged, and MCP resource
discovery failed, so the agent fell back to reading product source. Guidance that names a file the
installed agent cannot open is worse than no guidance -- it sends the reader somewhere empty.

These cases read only the *packaged* tree under ``src/finishup/resources`` plus the resource registry,
never the repository-root working copy, so they fail exactly the way a real installation would.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

import pytest

from finishup.adapters.integrations.claude_code_integration import render_claude_code_plugin
from finishup.adapters.integrations.codex_skill import load_packaged_skill_members
from finishup.adapters.integrations.cursor_integration import render_cursor_plugin
from finishup.adapters.integrations.portable_plugin import build_portable_plugin_plan
from finishup.mcp.resources import GUIDANCE_RESOURCES, read_resource
from finishup.ports.plugin_artifacts import PluginFormatProfile
from finishup.protocol.guidance_uris import ALL_GUIDANCE_URIS

_PACKAGED_ROOT: Final = Path(__file__).resolve().parents[2] / "src" / "finishup" / "resources"
_PACKAGED_SKILL: Final = _PACKAGED_ROOT / "skills" / "codex" / "finishup" / "SKILL.md"

# `[text](target)` where target is not an absolute URL to somewhere off-product.
_MARKDOWN_LINK: Final = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
_FINISHUP_URI: Final = re.compile(r"`(finishup://[^`]+)`")


def _skill_text() -> str:
    return _PACKAGED_SKILL.read_text(encoding="utf-8")


def _cadence_row(text: str, operation: str) -> str:
    prefix = f"| `{operation}` | "
    matches = [line for line in text.splitlines() if line.startswith(prefix)]
    assert len(matches) == 1, f"expected one cadence row for {operation}, found {len(matches)}"
    return matches[0].removeprefix(prefix).removesuffix(" |")


def test_the_skill_is_packaged_at_all() -> None:
    assert _PACKAGED_SKILL.is_file(), "the installed skill is missing from the packaged resources"
    assert _skill_text().strip(), "the installed skill is empty"


def test_step_zero_stops_on_an_empty_guidance_read() -> None:
    """A missing or clipped guidance body must enter the bounded recovery route."""

    text = _skill_text()
    collapsed = " ".join(text.split())
    safety_floor = " ".join(
        (_PACKAGED_ROOT / "guidance" / "agent-instructions.md").read_text(encoding="utf-8").split()
    )
    combined = f"{collapsed} {safety_floor}"
    assert "resolve without any repository checkout" not in collapsed
    # Compaction (#984 budgets) folded the long recovery prose into one sentence: an empty or
    # clipped body is re-read through ``read_guidance`` (same URI, verified text and byte counts),
    # then the installed reference, and the skill itself says to page and verify before ``start``.
    assert "If a body is empty or clipped, call `read_guidance` with the same URI" in combined
    assert "verify the text and byte counts" in combined
    assert "`page_size` is 4 to 16,384 UTF-8 bytes" in combined
    assert "use installed `references/<name>.md`" in combined
    assert "page and verify empty or clipped guidance" in collapsed
    assert "The first workflow operation is `start`" in collapsed
    assert "do not work without a task" in collapsed
    # The skill routes to the compact core; it does not claim that any full document is already in
    # the host context. Other procedures remain addressable through the topic catalog.
    assert "finishup://guidance/agent-instructions.md" in collapsed
    assert "finishup://guidance/workflow.md#start-and-resume" in collapsed
    assert "already include `agent-instructions.md`" not in collapsed
    assert "Both are already in initialize `instructions`" not in collapsed


def test_step_zero_does_not_use_resources_list_for_discovery() -> None:
    """A failed resources/list is not a missing server (issue #173)."""

    text = _skill_text() + (_PACKAGED_ROOT / "guidance" / "agent-instructions.md").read_text(
        encoding="utf-8"
    )
    collapsed = " ".join(text.split())
    assert "Do not call `resources/list` or `list_mcp_resources`" in collapsed
    assert "The five index URIs are the complete legacy catalog" in collapsed
    assert "a list failure is not a missing server or reason to read product source" in collapsed


def test_every_finishup_uri_the_skill_names_is_a_registered_readable_resource() -> None:
    registered = set(ALL_GUIDANCE_URIS)
    named = set(_FINISHUP_URI.findall(_skill_text()))
    assert named, "the skill names no guidance resources"
    unregistered = sorted(named - registered)
    assert unregistered == [], f"skill names unregistered resource URIs: {unregistered}"
    for uri in sorted(named):
        # Reading proves the bytes are packaged and manifest-verified, not merely listed.
        assert read_resource(uri), f"registered but unreadable: {uri}"


@pytest.mark.parametrize("host", ["codex", "portable", "claude-code", "cursor", "cursor-portable"])
def test_installed_guidance_links_and_explicit_anchors_resolve(host: str, tmp_path: Path) -> None:
    # Render the actual installed artifact. Checking only source links misses a renderer that
    # selects another host's skill or forgets to ship one of its relative references.
    launcher = tmp_path / "finishup"
    launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    launcher.chmod(0o700)
    if host == "codex":
        members = load_packaged_skill_members()
    elif host == "portable":
        members = dict(build_portable_plugin_plan().members)
    elif host == "claude-code":
        members = dict(render_claude_code_plugin(finishup_launcher=launcher).members)
    else:
        members = dict(
            render_cursor_plugin(
                PluginFormatProfile.AGENT_PLUGINS_1
                if host == "cursor-portable"
                else PluginFormatProfile.CURSOR_PLUGIN_NATIVE,
                finishup_launcher=launcher,
            ).members
        )
    documents = {
        name: data.decode("utf-8") for name, data in members.items() if name.endswith(".md")
    }
    for name, text in documents.items():
        for target in _MARKDOWN_LINK.findall(text):
            if target.startswith(("http://", "https://", "finishup://", "mailto:")):
                continue
            relative, _, anchor = target.partition("#")
            resolved = str(Path(name).parent / relative) if relative else name
            assert resolved in documents, f"{name}: missing installed reference {target}"
            if anchor:
                destination = documents[resolved]
                headings = {
                    re.sub(r"[^a-z0-9 -]", "", line.lstrip("# ").lower()).replace(" ", "-")
                    for line in destination.splitlines()
                    if line.startswith("#")
                }
                assert f'id="{anchor}"' in destination or anchor in headings, (name, target)


@pytest.mark.parametrize("resource", GUIDANCE_RESOURCES, ids=lambda item: item.logical_name)
def test_every_registered_guidance_resource_is_readable_offline(resource: object) -> None:
    logical_name = getattr(resource, "logical_name")
    uri = getattr(resource, "uri")
    payload = read_resource(uri)
    assert payload, f"{logical_name} read back empty"
    # The packaged copy is the one an installation actually serves.
    packaged = _PACKAGED_ROOT / logical_name
    assert packaged.is_file(), f"{logical_name} is registered but not packaged"
    assert packaged.read_bytes() == payload


def test_skill_routes_to_the_readable_cadence_owner() -> None:
    """The entrypoint routes to one maintained cadence, rather than copying its whole table."""

    skill = _skill_text()
    safety_floor = (_PACKAGED_ROOT / "guidance" / "agent-instructions.md").read_text(
        encoding="utf-8"
    )
    # The compact skill names the operations it directs (`start`, `check`, `receipt`) and routes to
    # the safety floor plus the workflow owner; the one-line cadence naming `publish_work` lives in
    # the floor the skill tells the agent to read first.
    assert "finishup://guidance/workflow.md" in skill
    assert "finishup://guidance/agent-instructions.md" in skill
    workflow = read_resource("finishup://guidance/workflow.md").decode("utf-8")
    combined = f"{skill} {safety_floor}"
    for operation in ("start", "publish_work", "check", "receipt"):
        assert f"`{operation}`" in combined
        assert _cadence_row(workflow, operation)
    cadence = _cadence_row(workflow, "check")
    assert "A check with no new events since the last one adds nothing" in cadence
    assert "never use the finding's `subject_frontier`" in _cadence_row(workflow, "respond")


def test_the_skill_does_not_promise_that_responding_clears_a_finding() -> None:
    """Receipts keep every actionable finding unresolved, whatever disposition is recorded."""

    text = _skill_text()
    assert "unresolved_findings_remain" in text
    assert "A `respond` does not clear a finding" in text


def test_start_is_authorable_from_guidance_without_reading_product_source() -> None:
    """The workflow guidance must name what a first `start` call needs.

    Two `start` attempts failed in the dogfood: an empty object, then a guessed request-id shape
    and a guessed mode. Both are answerable from guidance alone.
    """

    workflow = read_resource("finishup://guidance/workflow.md").decode("utf-8")
    combined = (
        workflow + read_resource("finishup://guidance/agent-instructions.md").decode("utf-8")
    ).lower()
    for token in ("start", "request_id", "mode"):
        assert token in combined, f"guidance never mentions {token}"
