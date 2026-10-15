"""``finishup privacy conversations`` (ADR-049): the owner's setting, its way in and way out."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import finishup.cli.privacy_setup as setup
from builders.privacy_policies import local_only_policy, minimal_external_policy
from finishup.adapters.privacy.catalog import (
    decode_privacy_policy_canonical,
    encode_privacy_policy_json,
)
from finishup.application.privacy_policy import privacy_policy_changes
from finishup.cli.app import app
from finishup.domain.privacy import ConversationReview, PrivacyPolicy
from finishup.domain.values import JsonObject
from finishup.protocol.canonical import canonical_encode

_AUTHORITY = f"sha256:{'3' * 64}"
_NOW = datetime(2026, 10, 14, tzinfo=UTC)
_PROPOSAL = "ppr_10000000-0000-4000-8000-000000000049"


def _snapshot(policy: PrivacyPolicy, grant: str = "granted") -> setup.PrivacySetupSnapshot:
    return setup.PrivacySetupSnapshot(
        policy,
        JsonObject({"kind": "workspace"}),
        _AUTHORITY,
        grant,  # pyright: ignore[reportArgumentType]
        "not_applicable",
    )


def _with(setting: ConversationReview | None) -> PrivacyPolicy:
    return replace(minimal_external_policy(), conversation_review=setting)


def _install(
    monkeypatch: pytest.MonkeyPatch,
    policy: PrivacyPolicy,
    *,
    grant: str = "granted",
    interactive: bool = True,
    decision: str = "committed",
) -> tuple[list[PrivacyPolicy], list[str], list[dict[str, object]]]:
    proposed: list[PrivacyPolicy] = []
    decided: list[str] = []
    walked: list[dict[str, object]] = []

    async def snapshot(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(policy, grant)

    async def propose(candidate: PrivacyPolicy, digest: str, **_: object) -> str | None:
        assert digest == _AUTHORITY
        proposed.append(candidate)
        # A narrowing applies at once (no proposal); anything wider needs the ceremony.
        widening = any(change.widens for change in privacy_policy_changes(policy, candidate))
        return _PROPOSAL if widening else None

    async def decide(proposal_id: str) -> object:
        decided.append(proposal_id)
        return SimpleNamespace(status=decision)

    async def run_setup(**kwargs: object) -> setup.PrivacySetupReport:
        walked.append(kwargs)
        return setup.PrivacySetupReport("configured", "minimal_external", grant_state="granted")

    monkeypatch.setattr(setup, "_interactive_terminal", lambda: interactive)
    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", snapshot)
    monkeypatch.setattr(setup, "_propose", propose)
    monkeypatch.setattr(setup, "_decide", decide)
    monkeypatch.setattr(setup, "run_privacy_setup", run_setup)
    return proposed, decided, walked


def test_the_candidate_changes_only_the_setting_and_names_its_predecessor() -> None:
    current = _with(ConversationReview.LOCAL_ONLY)
    candidate = setup.conversation_review_candidate(
        current, ConversationReview.LOCAL_AGENT_OPT_IN, now=_NOW
    )
    assert candidate.conversation_review is ConversationReview.LOCAL_AGENT_OPT_IN
    assert candidate.version == current.version + 1
    assert candidate.supersedes_policy_digest == current.policy_digest
    changes = privacy_policy_changes(current, candidate)
    assert [(change.field, change.widens) for change in changes] == [("conversation_review", True)]
    back = privacy_policy_changes(candidate, current)
    assert [(change.field, change.widens) for change in back] == [("conversation_review", False)]


@pytest.mark.parametrize(
    ("before", "after", "widens"),
    [
        (ConversationReview.LOCAL_ONLY, ConversationReview.LOCAL_OWNER_APPROVAL, True),
        (ConversationReview.LOCAL_OWNER_APPROVAL, ConversationReview.LOCAL_AGENT_OPT_IN, True),
        (ConversationReview.LOCAL_AGENT_OPT_IN, ConversationReview.AI_POWERED, True),
        (ConversationReview.AI_POWERED, ConversationReview.LOCAL_AGENT_OPT_IN, False),
        (ConversationReview.LOCAL_AGENT_OPT_IN, ConversationReview.LOCAL_ONLY, False),
        # An unset field reads as released: inference on means review on every task.
        (None, ConversationReview.LOCAL_AGENT_OPT_IN, False),
    ],
)
def test_the_diff_widens_only_toward_less_of_the_owner(
    before: ConversationReview | None, after: ConversationReview, widens: bool
) -> None:
    changes = privacy_policy_changes(_with(before), _with(after))
    assert [(change.field, change.widens) for change in changes] == [
        ("conversation_review", widens)
    ]


def test_making_the_released_reading_explicit_is_no_change() -> None:
    assert privacy_policy_changes(_with(None), _with(ConversationReview.AI_POWERED)) == ()


def test_an_unset_setting_keeps_every_existing_policys_bytes_and_digest() -> None:
    """Upgrade rule: a policy written before the field existed is byte-identical."""

    policy = minimal_external_policy()
    assert policy.conversation_review is None
    encoded = encode_privacy_policy_json(policy)
    assert "conversation_review" not in encoded
    decoded = decode_privacy_policy_canonical(canonical_encode(encoded))
    assert decoded == policy
    assert decoded.policy_digest == policy.policy_digest
    assert policy.effective_conversation_review is ConversationReview.AI_POWERED
    assert local_only_policy().effective_conversation_review is ConversationReview.LOCAL_ONLY
    explicit = encode_privacy_policy_json(_with(ConversationReview.LOCAL_AGENT_OPT_IN))
    assert explicit["conversation_review"] == "local_agent_opt_in"
    assert explicit["schema_version"] == "1.2.0"


def test_widening_proposes_and_requires_the_trusted_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proposed, decided, walked = _install(monkeypatch, _with(ConversationReview.LOCAL_ONLY))
    report = asyncio.run(
        setup.run_conversation_review_change(ConversationReview.LOCAL_AGENT_OPT_IN)
    )
    assert report.outcome == "configured"
    assert [policy.conversation_review for policy in proposed] == [
        ConversationReview.LOCAL_AGENT_OPT_IN
    ]
    assert decided == [_PROPOSAL]
    assert walked == []


def test_a_declined_widening_changes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _with(ConversationReview.LOCAL_ONLY), decision="denied")
    report = asyncio.run(setup.run_conversation_review_change(ConversationReview.AI_POWERED))
    assert (report.outcome, report.reason) == ("cancelled", "privacy_decision_not_approved")


def test_widening_needs_a_local_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    proposed, _, _ = _install(monkeypatch, _with(ConversationReview.LOCAL_ONLY), interactive=False)
    report = asyncio.run(
        setup.run_conversation_review_change(ConversationReview.LOCAL_AGENT_OPT_IN)
    )
    assert (report.outcome, report.reason) == ("failed", "local_terminal_required")
    assert proposed == []


def test_narrowing_applies_at_once_without_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    proposed, decided, _ = _install(
        monkeypatch, _with(ConversationReview.LOCAL_AGENT_OPT_IN), interactive=False
    )
    report = asyncio.run(setup.run_conversation_review_change(ConversationReview.LOCAL_ONLY))
    assert report.outcome == "configured"
    assert [policy.conversation_review for policy in proposed] == [ConversationReview.LOCAL_ONLY]
    assert decided == []


def test_the_same_setting_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    proposed, _, _ = _install(monkeypatch, _with(ConversationReview.LOCAL_AGENT_OPT_IN))
    report = asyncio.run(
        setup.run_conversation_review_change(ConversationReview.LOCAL_AGENT_OPT_IN)
    )
    assert report.outcome == "unchanged"
    assert proposed == []


@pytest.mark.parametrize("grant", ["granted", "missing"])
def test_opting_in_where_nothing_may_be_sent_walks_the_one_time_policy_ceremony(
    monkeypatch: pytest.MonkeyPatch, grant: str
) -> None:
    proposed, _, walked = _install(monkeypatch, local_only_policy(), grant=grant)
    report = asyncio.run(
        setup.run_conversation_review_change(ConversationReview.LOCAL_AGENT_OPT_IN)
    )
    assert report.outcome == "configured"
    assert proposed == []
    assert walked == [
        {
            "workspace_locator": walked[0]["workspace_locator"],
            "conversation_review": ConversationReview.LOCAL_AGENT_OPT_IN,
            "ai_review_add_on": True,
        }
    ]


def test_local_only_without_a_grant_records_it_through_the_private_recipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, walked = _install(monkeypatch, local_only_policy(), grant="missing")
    report = asyncio.run(setup.run_conversation_review_change(ConversationReview.LOCAL_ONLY))
    assert report.outcome == "configured"
    assert walked[0]["recipe_hint"] == "private"
    assert walked[0]["conversation_review"] is ConversationReview.LOCAL_ONLY


def test_local_only_without_a_grant_or_terminal_is_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, walked = _install(monkeypatch, local_only_policy(), grant="missing", interactive=False)
    report = asyncio.run(setup.run_conversation_review_change(ConversationReview.LOCAL_ONLY))
    assert (report.outcome, report.reason) == ("unchanged", "repository_privacy_grant_missing")
    assert walked == []


def test_cli_registers_every_setting_and_a_read_only_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[ConversationReview] = []

    async def change(setting: ConversationReview, **_: object) -> setup.PrivacySetupReport:
        seen.append(setting)
        return setup.PrivacySetupReport("configured", "minimal_external")

    async def snapshot(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_with(ConversationReview.LOCAL_AGENT_OPT_IN))

    monkeypatch.setattr(setup, "run_conversation_review_change", change)
    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", snapshot)
    runner = CliRunner()
    for name in ("agent-opt-in", "owner-approval", "local-only", "ai-powered"):
        result = runner.invoke(app, ["privacy", "conversations", name, "--json"])
        assert result.exit_code == 0, result.output
    assert seen == [
        ConversationReview.LOCAL_AGENT_OPT_IN,
        ConversationReview.LOCAL_OWNER_APPROVAL,
        ConversationReview.LOCAL_ONLY,
        ConversationReview.AI_POWERED,
    ]
    status = runner.invoke(app, ["privacy", "conversations", "status"])
    assert status.exit_code == 0, status.output
    assert "an agent may turn on AI-powered review for a task when it helps" in status.output
    assert "finishup privacy conversations" in status.output
    rejected = runner.invoke(app, ["privacy", "conversations", "sometimes"])
    assert rejected.exit_code != 0


def test_status_in_a_repository_without_its_own_grant_says_review_is_not_set_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ADR-049 review round 2: an inherited installation row is not this repository's setting."""

    async def snapshot(_locator: object = None) -> setup.PrivacySetupSnapshot:
        return _snapshot(_with(ConversationReview.LOCAL_AGENT_OPT_IN), grant="missing")

    monkeypatch.setattr(setup, "get_privacy_setup_snapshot", snapshot)
    status = CliRunner().invoke(app, ["privacy", "conversations", "status"])
    assert status.exit_code == 0, status.output
    assert "AI-powered review is not set up for this repository" in status.output
    assert "no privacy grant of its own yet" in status.output
    assert "every task runs with AI-powered review" not in status.output


@pytest.mark.parametrize(
    "setting", [ConversationReview.LOCAL_AGENT_OPT_IN, ConversationReview.LOCAL_OWNER_APPROVAL]
)
def test_an_inherited_setting_without_a_grant_walks_the_grant(
    monkeypatch: pytest.MonkeyPatch, setting: ConversationReview
) -> None:
    """Review round 3 (P2-A): the setting is inherited, so it is no widening; the grant is.

    Another repository's hybrid grant gave the installation row ``local_agent_opt_in``. In this
    repository, with no grant of its own, choosing a setting that sends work must walk this
    repository's grant with the setting drafted in, not report "unchanged".
    """

    inherited = _with(ConversationReview.LOCAL_AGENT_OPT_IN)
    proposed, _, walked = _install(monkeypatch, inherited, grant="missing")
    report = asyncio.run(setup.run_conversation_review_change(setting))
    assert report.outcome == "configured"
    assert proposed == []
    assert walked == [
        {
            "workspace_locator": walked[0]["workspace_locator"],
            "conversation_review": setting,
            "ai_review_add_on": True,
        }
    ]


def test_an_inherited_setting_without_a_grant_or_terminal_needs_the_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, walked = _install(
        monkeypatch,
        _with(ConversationReview.LOCAL_AGENT_OPT_IN),
        grant="missing",
        interactive=False,
    )
    report = asyncio.run(
        setup.run_conversation_review_change(ConversationReview.LOCAL_AGENT_OPT_IN)
    )
    assert (report.outcome, report.reason) == ("failed", "local_terminal_required")
    assert walked == []


def test_the_cli_names_finishup_privacy_when_the_terminal_is_needed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        _with(ConversationReview.LOCAL_AGENT_OPT_IN),
        grant="missing",
        interactive=False,
    )
    result = CliRunner().invoke(app, ["privacy", "conversations", "agent-opt-in"])
    assert result.exit_code == 20
    assert "local_terminal_required" in result.stderr
    assert "finishup --privacy" in result.stderr


def test_a_widening_without_a_terminal_does_not_name_the_grant_setup_where_a_grant_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verification of round 3: `finishup --privacy` is named only where a grant is missing."""

    _install(monkeypatch, _with(ConversationReview.LOCAL_ONLY), grant="granted", interactive=False)
    result = CliRunner().invoke(app, ["privacy", "conversations", "agent-opt-in"])
    assert result.exit_code == 20
    assert "local_terminal_required" in result.stderr
    assert "run this command there." in result.stderr
    assert "finishup --privacy" not in result.stderr


def test_local_only_without_a_grant_or_terminal_names_this_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, local_only_policy(), grant="missing", interactive=False)
    result = CliRunner().invoke(app, ["privacy", "conversations", "local-only"])
    assert result.exit_code == 0, result.output
    assert "run this command in a local terminal" in result.stderr
    assert "finishup --privacy" not in result.stderr
