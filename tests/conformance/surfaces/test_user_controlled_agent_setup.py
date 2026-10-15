"""Conversational setup keeps recommendations advisory and user choices authoritative."""

from __future__ import annotations

from pathlib import Path

from finishup.protocol.chat_user_authority import agent_chat_attestation_supported
from finishup.service.elevated_bootstrap import catalog_payload

_ROOT = Path(__file__).resolve().parents[3]


def _text(path: str) -> str:
    return (_ROOT / path).read_text(encoding="utf-8")


def test_shared_guidance_makes_conversation_primary_and_user_choice_final() -> None:
    guidance = _text("guidance/agent-instructions.md")
    skill = _text("skills/codex/finishup/SKILL.md")

    # tb4n5 startup dedup (ADR-047): the skill names the operating card, and the card alone routes
    # setup to the request templates instead of every surface repeating the route.
    assert "finishup://guidance/agent-instructions.md" in skill
    assert "publish `#publish-shapes`" in guidance
    assert "setup `finishup://guidance/request-templates.md`" in guidance
    for surface in (_text("guidance/request-templates.md"),):
        collapsed = " ".join(surface.split())
        assert "Normal conversation is the primary" in collapsed
        assert "recommend `expanded_review` first" in collapsed
        assert "`assisted_review` as the lower-disclosure AI-powered" in collapsed
        assert (
            "Recommendations are advisory" in collapsed
            or "A recommendation is advisory" in collapsed
        )
        assert "repository_privacy_preview" in collapsed
        assert "behind the user's back" in collapsed


def test_every_host_runbook_preserves_the_choice_and_names_its_authority_boundary() -> None:
    codex = _text("docs/runbooks/codex-integration.md")
    claude = _text("docs/runbooks/claude-code-integration.md")
    cursor = _text("docs/runbooks/cursor-integration.md")

    assert "recommend Expanded first" in codex
    assert "repository_privacy_preview" in codex
    assert agent_chat_attestation_supported("codex", "explicit_current_chat_user")

    for unsupported, host in ((claude, "claude"), (cursor, "cursor")):
        collapsed = " ".join(unsupported.split())
        assert "recommends Expanded first" in collapsed
        assert "shortest exact trusted-local continuation" in collapsed
        assert "never silently downgrade" in collapsed
        assert not agent_chat_attestation_supported(host, "explicit_current_chat_user")


def test_authorization_docs_do_not_contradict_the_implemented_consent_lane() -> None:
    """A doc that still calls the terminal the only widening authority would be false."""

    usage = " ".join(_text("docs/usage/agent-start.md").split())
    protocol = " ".join(_text("docs/protocol/privacy-setup-wizard.md").split())

    assert "only a reauthenticated local human at the trusted terminal" not in usage
    assert "authorize_command" in usage
    assert "trusted-terminal ceremony is the single authorization" not in protocol
    assert "`finishup consent` lane described above is its only exception" in protocol

    # Issue #553: the shipped README, the architecture overview, the CONTRIBUTING honesty rules,
    # the usage privacy page, and INTERFACES made the same single-authority claim; each must name
    # the consent lane's widening path.
    for path in (
        "README.md",
        "docs/architecture.md",
        "CONTRIBUTING.md",
        "docs/usage/privacy-and-semantic-review.md",
        "docs/INTERFACES.md",
    ):
        surface = " ".join(_text(path).split())
        assert "only a reauthenticated local human can loosen" not in surface, path
        assert "reauthenticated local human" not in surface, path
        assert "reauthenticated decision" in surface, path
        assert "trusted local ceremony" in surface, path
        assert "explicit current-chat" in surface, path
        assert "exact prepared" in surface, path

    # ADR-009 is a record: its original decision-6 sentence stays, but the amendment pointer to
    # ADR-016's consent lane must sit beside it rather than only in the later table.
    adr = " ".join(_text("docs/adr/ADR-009-data-egress-privacy.md").split())
    original = (
        "MCP/agent/LLM calls can request more context but cannot approve or persist the expansion."
    )
    assert original in adr
    tail = adr[adr.index(original) : adr.index(original) + 600]
    assert "Amended by ADR-016 decision 5" in tail
    assert "explicit current-chat" in tail
    assert "cannot independently authenticate" in tail


def test_catalog_exposes_user_control_rules_and_all_named_recipes() -> None:
    catalog = catalog_payload()
    rules = catalog["rules"]
    assert isinstance(rules, dict)
    assert rules["explicit_current_user_outcome_controls_supported_choice"] is True
    assert rules["recommendations_are_advisory"] is True
    assert rules["technical_authority_and_safety_boundaries_remain_enforced"] is True

    operations = catalog["operations"]
    assert isinstance(operations, list)
    grant = next(
        operation
        for operation in operations
        if isinstance(operation, dict) and operation.get("operation") == "repository_privacy_grant"
    )
    hint = grant["prepare_hint"]
    assert isinstance(hint, str)
    for recipe in ("expanded_review", "assisted_review", "metadata_only", "private"):
        assert recipe in hint
