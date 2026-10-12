"""The agent-facing text must explain standing authority and the nonterminal check outcome.

In the supervised dogfood run the agent, on reaching a pending disclosure, went looking in
Yoetz's SQLite catalog and product source for the pending id, issued a fresh check request, and
told the user the task was complete before AI-powered closure. None of those are things the text
told it to do — they are what an agent does when the text says nothing.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Final

import pytest

from yoetz.mcp.descriptors import descriptor_for

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
_SKILL: Final = _REPO_ROOT / "skills" / "codex" / "yoetz" / "SKILL.md"
_AGENT_INSTRUCTIONS: Final = _REPO_ROOT / "guidance" / "agent-instructions.md"


def _flat(path: Path) -> str:
    """Collapse whitespace before matching.

    These are hand-wrapped markdown files: where a line happens to break is not part of the
    instruction, and a test that depends on it fails on a reflow that changed nothing.
    """

    return " ".join(path.read_text(encoding="utf-8").split()).lower()


def _review_guidance(entrypoint: Path) -> str:
    # Procedures are conditional, but each entrypoint must make their owners reachable. Since the
    # progressive-guidance split (#961) the budgeted skills name only the mandatory core, and the
    # core names the review owner (coverage-and-receipts) and the closure owner (workflow).
    text = _flat(entrypoint)
    if entrypoint != _AGENT_INSTRUCTIONS:
        assert "yoetz://guidance/agent-instructions.md" in text
        text += " " + _flat(_AGENT_INSTRUCTIONS)
    assert "yoetz://guidance/coverage-and-receipts.md" in text
    assert "yoetz://guidance/workflow.md" in text
    return " ".join(
        (
            text,
            _flat(_REPO_ROOT / "guidance/coverage-and-receipts.md"),
            _flat(_REPO_ROOT / "guidance/workflow.md"),
        )
    )


def _skill() -> str:
    return _review_guidance(_SKILL)


def _instructions() -> str:
    return _review_guidance(_AGENT_INSTRUCTIONS)


@pytest.mark.parametrize("source", (_skill, _instructions))
def test_text_states_that_check_cannot_widen_standing_authority(source: Callable[[], str]) -> None:
    text = source()

    assert "cannot widen" in text
    assert "standing" in text
    # The point is that the owner already chose the route during setup.
    assert "setup" in text


@pytest.mark.parametrize("source", (_skill, _instructions))
def test_text_separates_host_authorization_from_a_disclosure_decision(
    source: Callable[[], str],
) -> None:
    text = source()

    assert "disclosure decision" in text
    assert "different things" in text or "two different permissions" in text


@pytest.mark.parametrize("source", (_skill, _instructions))
def test_text_handles_host_auto_review_before_yoetz_runs(source: Callable[[], str]) -> None:
    text = source()

    assert "host auto-review" in text
    assert "not a yoetz result" in text
    assert "yoetz did not run" in text
    assert "exact proposed `check` body" in text
    assert "host approval authorizes this tool invocation only" in text
    assert "do not publish a completion claim" in text
    assert "deterministic_only" in text
    assert "same proposed `check` body and `request_id`" in text


def test_check_descriptor_handles_host_auto_review_before_invocation() -> None:
    description = descriptor_for("check").description

    assert "pre-invocation approval refusal or hold" in description
    assert "not a Yoetz result" in description
    assert "Yoetz did not run" in description
    assert "exact proposed check body and request_id" in description
    assert "does not change Yoetz privacy policy" in description
    assert "Do not publish a completion claim" in description
    assert (
        "continue without AI-powered review only after the user explicitly chooses" in description
    )


@pytest.mark.parametrize("source", (_skill, _instructions))
def test_text_gives_the_awaiting_human_procedure(source: Callable[[], str]) -> None:
    text = source()

    assert "awaiting_human" in text
    assert "nonterminal" in text
    # Do not mint a new request: a fresh one abandons the proposal being decided.
    assert "do not create a new check request" in text
    # Recovery is a protocol read, never a look inside Yoetz's own storage or source.
    assert "view=operation" in text
    assert "request_id" in text


@pytest.mark.parametrize("source", (_skill, _instructions))
def test_text_forbids_reading_yoetz_storage_or_source_to_recover(source: Callable[[], str]) -> None:
    text = source()

    assert "sqlite" in text or "databases" in text
    assert "source" in text


@pytest.mark.parametrize("source", (_skill, _instructions))
def test_text_treats_a_completion_claim_as_an_assertion(source: Callable[[], str]) -> None:
    text = source()

    assert "assertion" in text
    assert "not the output of one" in text or "not a conclusion" in text


@pytest.mark.parametrize("source", (_skill, _instructions))
def test_awaiting_human_is_excluded_from_the_stop_retrying_rules(source: Callable[[], str]) -> None:
    """Without this the agent reads a pending decision as a coverage gap and gives up."""

    text = source()

    assert "neither a gap to disclose nor a retry to spend" in text


@pytest.mark.parametrize("source", (_skill, _instructions))
def test_missing_repository_grant_handoff_stays_in_the_trusted_surface(
    source: Callable[[], str],
) -> None:
    text = source()

    assert "repository grant" in text
    assert "yoetz --privacy" in text
    assert "chat" in text
    assert "standing" in text
    assert "one-use" in text
    assert "no dispatch" in text
    assert "view=operation" in text
    assert "same `request_id`" in text
    assert "never create a fresh request" in text


def test_check_descriptor_states_the_bounded_standing_policy() -> None:
    description = descriptor_for("check").description

    assert "cannot widen privacy authority" in description
    assert "standing" in description
    assert "installed route binding and privacy policy" in description


def test_check_mode_cue_preserves_the_configured_default_and_final_requirement() -> None:
    description = descriptor_for("check").description
    assert "Omit mode to preserve the configured default" in description
    assert "semantic_if_configured only when review is known to be optional" in description
    assert "including subsequent final checks" in description
    assert "Do not downgrade required review to finish" in description


def test_closure_descriptors_require_the_recorded_resolution_and_receipt_counts() -> None:
    assert "not returned is not resolved" in descriptor_for("check").description
    for name in ("check", "status"):
        assert "filter.include_resolved=true" in descriptor_for(name).description
    assert "resolved=false means not returned but unproven" in descriptor_for("status").description
    assert "actual actionable unresolved count" in descriptor_for("receipt").description
    assert (
        "Disposition older findings before the final check" in descriptor_for("respond").description
    )


def test_check_descriptor_gives_the_continuation_procedure() -> None:
    description = descriptor_for("check").description

    assert "awaiting_human and awaiting_input are the nonterminal check results" in description
    assert "do not create a new check request" in description
    assert "same request_id" in description


def test_check_descriptor_keeps_repository_grant_approval_out_of_agent_chat() -> None:
    description = descriptor_for("check").description

    assert "yoetz --privacy" in description
    assert "agent chat" in description
    assert "repository grant" in description
    assert "no dispatch" in description
    assert "operation status" in description
    assert "never a fresh request" in description


@pytest.mark.parametrize("profile", ("policy", "strict"))
def test_check_never_understates_its_reach(profile: str) -> None:
    """The truthful annotation stays truthful.

    The policy route may dispatch outward, so it declares open_world. Weakening that to win an
    auto-review classifier would be a lie told to a safety check.
    """

    annotations = descriptor_for("check", profile).annotations  # pyright: ignore[reportArgumentType]

    assert annotations.open_world is (profile == "policy")
    assert annotations.read_only is False


@pytest.mark.parametrize("source", (_skill, _instructions))
def test_text_distinguishes_stale_runtime_from_a_genuine_route_ceiling(
    source: Callable[[], str],
) -> None:
    text = source()

    assert "activation mismatch" in text
    assert "full_restart_required" in text
    assert "do not mint a fresh ai-powered check" in text
    assert "never authorizes egress" in text
