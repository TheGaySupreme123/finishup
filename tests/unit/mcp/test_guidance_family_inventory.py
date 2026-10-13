"""The family counts guidance and resource descriptions state match the real inventory (#1049).

tb4n5: the request-templates resource description promised "all nine ordinary publication
families" while ``publish_work`` advertises eighteen and the publication policy lists sixteen core
families, and an agent guessed the anchor ``#ordinary-publication`` from that description. Each
count is now checked against the inventory it names.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from yoetz.mcp.descriptors import ORDINARY_MCP_PUBLISH_EVENT_FAMILIES
from yoetz.mcp.resources import GUIDANCE_RESOURCES, resolve_guidance_topic_uri

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_TEMPLATES: Final = _REPO_ROOT / "guidance" / "request-templates.md"
_POLICY: Final = _REPO_ROOT / "guidance" / "publication-policy.md"
_SCHEMA_NAME: Final = re.compile(r'"schema":\s*\{\s*"name":\s*"([a-z_]+)"')
_NINE_ORDINARY: Final = frozenset(
    {
        "plan_published",
        "obligation_published",
        "assignment_recorded",
        "decision_recorded",
        "action_recorded",
        "result_recorded",
        "evidence_recorded",
        "claim_recorded",
        "plan_revised",
    }
)


def _description(name: str) -> str:
    return next(resource.description for resource in GUIDANCE_RESOURCES if resource.name == name)


def test_request_templates_carry_a_body_for_every_advertised_publish_family() -> None:
    templated = frozenset(_SCHEMA_NAME.findall(_TEMPLATES.read_text(encoding="utf-8")))
    assert ORDINARY_MCP_PUBLISH_EVENT_FAMILIES <= templated
    assert len(ORDINARY_MCP_PUBLISH_EVENT_FAMILIES) == 18
    assert _NINE_ORDINARY <= ORDINARY_MCP_PUBLISH_EVENT_FAMILIES
    lifecycle = {
        family
        for family in ORDINARY_MCP_PUBLISH_EVENT_FAMILIES - _NINE_ORDINARY
        if not family.startswith("coordination_")
    }
    coordination = {
        family
        for family in ORDINARY_MCP_PUBLISH_EVENT_FAMILIES
        if family.startswith("coordination_")
    }
    assert (len(lifecycle), len(coordination)) == (7, 2)
    description = _description("request-templates.md")
    assert "all eighteen publish_work families" in description
    assert "(nine ordinary, seven lifecycle, two coordination)" in description
    assert "nine ordinary publication families" not in description


def test_the_policy_lists_sixteen_core_families_and_names_the_publishable_eighteen() -> None:
    text = _POLICY.read_text(encoding="utf-8")
    section = text.partition("## The sixteen event families")[2].partition("\n## ")[0]
    listed = re.findall(r"^- `([a-z_]+)` — ", section, flags=re.MULTILINE)
    assert len(listed) == len(set(listed)) == 16
    assert _NINE_ORDINARY <= set(listed)
    assert "`publish_work` admits eighteen families in all" in " ".join(section.split())
    assert "the sixteen core event families" in _description("publication-policy.md")


def test_the_description_phrase_and_the_family_prefix_read_the_template_overview() -> None:
    overview = "yoetz://guidance/request-templates.md#publication-templates"
    for guessed in ("publish-work", "ordinary-publication"):
        assert (
            resolve_guidance_topic_uri(f"yoetz://guidance/request-templates.md#{guessed}")
            == overview
        )
