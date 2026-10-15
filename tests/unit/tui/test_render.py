"""Rendering: exact wording, honest claims, and narrow-terminal behaviour.

These tests are the reason rendering is a pure function. The wording of an
approval screen, a readiness summary, or a privacy disclosure is a product
promise, so it is asserted directly rather than inferred from a screenshot.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

import pytest

import builders.tui as build
from finishup.tui.models import (
    PRIVACY_RECIPES,
    LayerState,
    PrivacyChoice,
    ProviderPosture,
    ReadinessLayer,
)
from finishup.tui.render import (
    MIN_ASCII_WIDTH,
    finishup_mark,
    render_detection,
    render_doctor,
    render_finish,
    render_foreign_entry,
    render_integration_preview,
    render_integration_technical_details,
    render_layers,
    render_project_trust,
    render_provider_endpoint,
    render_provider_failure,
    render_provider_stored,
    render_receipt,
    render_session_header,
    render_status,
    render_welcome,
    render_work_detail,
)

Snapshot = Callable[[str, Sequence[str]], None]

WIDE = 76
NARROW = 40


# ---------------------------------------------------------------------------
# First run
# ---------------------------------------------------------------------------


def test_welcome_shows_the_wordmark_only_when_the_terminal_can_hold_it() -> None:
    assert finishup_mark(MIN_ASCII_WIDTH) != ()
    assert finishup_mark(MIN_ASCII_WIDTH - 1) == ()
    assert "Welcome to FinishUP" in "\n".join(render_welcome(NARROW))


def test_welcome_renders_at_wide_and_narrow_widths(assert_snapshot: Snapshot) -> None:
    assert_snapshot("welcome_wide", render_welcome(WIDE))
    assert_snapshot("welcome_narrow", render_welcome(NARROW))


def test_detection_distinguishes_found_from_not_yet_connected(
    assert_snapshot: Snapshot,
) -> None:
    lines = render_detection(build.detection(), WIDE)
    assert_snapshot("detection", lines)
    # Being detected is never rendered as being connected.
    assert any(line.startswith("✓ Codex Desktop") for line in lines)
    assert "○ FinishUP is not connected yet" in lines


def test_detection_names_why_secure_storage_is_unavailable() -> None:
    lines = render_detection(
        build.detection(
            secure_storage_available=False,
            secure_storage_reason="no credential store is loaded; FinishUP needs macOS Keychain",
        ),
        WIDE,
    )
    # Lines are truncated to the terminal width; the reason follows the fixed statement.
    assert any(
        line.startswith("○ System secure storage is not available here — no credential store")
        for line in lines
    )


def test_detection_without_a_harness_says_so_rather_than_claiming_one() -> None:
    lines = render_detection(build.detection(harnesses=()), WIDE)
    assert "○ No supported agent installation found" in lines
    assert not any(line.startswith("✓ Codex") for line in lines)


def test_project_trust_names_the_repository_root_it_applies_to() -> None:
    lines = render_project_trust(build.detection(), WIDE)
    assert any("You are in" in line for line in lines)
    assert "Do you trust the contents of this project?" in lines


def test_launching_from_a_subdirectory_explains_that_trust_covers_the_root() -> None:
    lines = render_project_trust(
        build.detection(launched_from_subdirectory=True, cwd="/srv/finishup/src"),
        WIDE,
    )
    joined = " ".join(lines)
    assert "subfolder" in joined
    assert "repository root" in joined


def test_integration_preview_states_every_change_and_every_safety_boundary(
    assert_snapshot: Snapshot,
) -> None:
    lines = render_integration_preview(build.plan(), WIDE)
    assert_snapshot("integration_preview", lines)
    joined = "\n".join(lines)
    for promise in (
        "No repository contents are uploaded during setup",
        "No API key is written to the project",
        "External LLM review remains off",
        "A foreign MCP entry will never be replaced",
    ):
        assert promise in joined
    assert "Register MCP server: finishup mcp serve" in joined
    assert "7f8a92bd" in joined


def test_integration_preview_hides_paths_and_digests_behind_technical_details() -> None:
    plan = build.plan()
    friendly = "\n".join(render_integration_preview(plan, WIDE))
    assert plan.executable_path not in friendly
    assert plan.preview_digest not in friendly
    assert plan.skill_preview_digest not in friendly

    technical_lines = render_integration_technical_details(plan, 120)
    technical = "\n".join(technical_lines)
    assert plan.codex_home not in friendly
    assert plan.codex_home in technical
    assert plan.executable_path in technical
    assert plan.preview_digest in technical
    assert plan.skill_preview_digest in technical
    assert plan.mcp_command in technical
    assert any(
        line.startswith("Planned files") and line.endswith(str(plan.planned_file_count))
        for line in technical_lines
    )


def test_preview_names_every_existing_entry_the_approval_rewrites_or_removes() -> None:
    # ADR-048: the activation digest also removes Yoetz-era tables, cache versions and trees, and
    # a re-registration may change the route. Approval covers only what the owner was shown.
    plan = build.plan(
        route_profile="strict",
        route_profile_before="policy",
        legacy_registration="legacy_only",
        activation_legacy_removed_block='[plugins."yoetz@yoetz"]\nenabled = true\n',
        activation_legacy_cache_versions=("0.2.4", "0.2.5"),
        activation_legacy_plugin_tree_planned=True,
        legacy_skill_tree_planned=True,
        policy_ambiguous=True,
    )
    friendly = " ".join(" ".join(render_integration_preview(plan, WIDE)).split())
    for expected in (
        "~ Change the existing MCP registration's review route: policy -> strict",
        "~ Move the MCP registration from the earlier name yoetz to finishup",
        "~ Remove the earlier Yoetz plugin activation from the Codex config",
        "~ Delete earlier Yoetz plugin cache versions: 0.2.4, 0.2.5",
        "~ Delete the earlier Yoetz project skill (.agents/skills/yoetz)",
        "~ Delete the earlier Yoetz plugin sources (.agents/plugins/yoetz)",
        "neither is used until you remove one",
    ):
        assert expected in friendly

    technical = render_integration_technical_details(plan, 240)
    start = technical.index("Earlier Yoetz activation removed by this change")
    assert technical[start + 1 : start + 3] == ('  [plugins."yoetz@yoetz"]', "  enabled = true")
    assert "0.2.4, 0.2.5" in "\n".join(technical[start:])
    assert ".agents/plugins/yoetz (FinishUP-managed" in "\n".join(technical[start:])


def test_a_plan_with_nothing_earlier_names_no_replacement() -> None:
    plan = build.plan()
    assert plan.replacements == ()
    joined = "\n".join(render_integration_preview(plan, WIDE))
    assert "~ " not in joined
    assert "Earlier Yoetz" not in "\n".join(render_integration_technical_details(plan, 240))
    duplicate = build.plan(legacy_registration="duplicate", route_profile_before="policy")
    assert duplicate.replacements == (
        "Remove the duplicate MCP registration under the earlier name yoetz",
    )


def test_long_activation_targets_are_wrapped_without_omitting_any_bytes() -> None:
    plan = build.plan(
        codex_home="/a/very/long/explicit/codex/home/selected/by/the/operator",
        activation_config_path=(
            "/a/very/long/explicit/codex/home/selected/by/the/operator/config.toml"
        ),
    )
    lines = render_integration_technical_details(plan, 32)
    compact = "".join(line.strip() for line in lines)

    assert plan.codex_home in compact
    assert plan.activation_config_path in compact


def test_activation_approval_discloses_every_digest_command_and_cache_effect() -> None:
    plan = build.plan()
    technical = "\n".join(render_integration_technical_details(plan, 240))

    for expected in (
        plan.activation_codex_version,
        plan.activation_executable_digest,
        plan.activation_plugin_source_digest,
        plan.activation_plugin_install_path,
        plan.activation_plugin_install_digest,
        plan.activation_marketplace_preimage_digest,
        plan.activation_config_preimage_digest,
        plan.activation_probe_environment,
        repr((plan.executable_path, *plan.activation_probe_command)),
        repr((plan.executable_path, *plan.activation_inventory_command)),
        repr((plan.executable_path, *plan.activation_install_command)),
    ):
        assert expected in technical
    for name, value in plan.activation_environment:
        assert name in technical
        assert value in technical
    assert "Canonical installed inventory verified before approval\n  no" in technical
    assert "Plugin cache mutation planned\n  yes" in technical


def test_activation_bytes_render_preserves_trailing_newline_as_blank_line() -> None:
    plan = build.plan(
        activation_marketplace_text='{"name":"finishup"}\n',
        activation_config_block='[plugins."finishup@finishup"]\nenabled = true\n',
    )
    lines = render_integration_technical_details(plan, 240)
    tail = lines[lines.index("Exact activation bytes") + 1 :]
    assert tail[0] == '  {"name":"finishup"}'
    assert tail[1] == "  "
    assert tail[2] == '  [plugins."finishup@finishup"]'
    assert tail[3] == "  enabled = true"
    assert tail[4] == "  "


def test_activation_bytes_render_preserves_final_blank_line() -> None:
    plan = build.plan(activation_config_block='[plugins."finishup@finishup"]\nenabled = true\n\n')
    lines = render_integration_technical_details(plan, 240)
    tail = lines[lines.index("Exact activation bytes") + 1 :]
    config_start = tail.index('  [plugins."finishup@finishup"]')
    assert tail[config_start + 1] == "  enabled = true"
    assert tail[config_start + 2] == "  "
    assert tail[config_start + 3] == "  "


def test_a_foreign_entry_is_a_block_that_reports_nothing_was_changed() -> None:
    lines = render_foreign_entry("", WIDE)
    joined = "\n".join(lines)
    assert lines[0].startswith("■")
    assert "Nothing was replaced or removed." in lines
    assert "force" not in joined.lower()
    other_lines = [line for line in lines if line != "Nothing was replaced or removed."]
    assert "replace" not in "\n".join(other_lines).lower()


def test_finish_reports_off_layers_as_off_and_never_as_verified(
    assert_snapshot: Snapshot,
) -> None:
    lines = render_finish(build.snapshot(), WIDE)
    assert_snapshot("finish", lines)
    joined = "\n".join(lines)
    assert "Nothing is being sent to an external review model." in joined
    assert "External review" in joined
    external = next(line for line in lines if line.startswith("External review"))
    assert external.endswith("off")


# ---------------------------------------------------------------------------
# Readiness honesty
# ---------------------------------------------------------------------------


def test_every_readiness_layer_is_rendered_separately(assert_snapshot: Snapshot) -> None:
    lines = render_layers(build.layers(), 100)
    assert_snapshot("layers", lines)
    assert len(lines) == len(build.layers())
    for label in (
        "Harness detected",
        "MCP registered",
        "MCP verified",
        "Guidance installed",
        "Structural hooks installed",
        "Project consent active",
        "Approved-check policy trusted",
        "Local service reachable",
        "Vault ready",
        "Provider binding saved",
        "Credential stored",
        "Provider connection tested",
        "Deeper-review evaluator composed",
        "Privacy permits external review",
        "Deeper review ready",
    ):
        assert any(label in line for line in lines), label


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        (LayerState.VERIFIED, "verified"),
        (LayerState.UNPROVEN, "not proven"),
        (LayerState.NOT_CONFIGURED, "not configured"),
        (LayerState.BLOCKED, "blocked"),
        (LayerState.UNKNOWN, "unknown"),
    ],
)
def test_a_layer_never_reads_stronger_than_its_state(state: LayerState, expected: str) -> None:
    layer = ReadinessLayer("k", "Some layer", state)
    line = render_layers((layer,), 80)[0]
    assert expected in line
    if state is not LayerState.VERIFIED:
        assert "verified" not in line


def test_status_keeps_registration_and_verification_apart(
    assert_snapshot: Snapshot,
) -> None:
    lines = render_status(build.snapshot(), WIDE)
    assert_snapshot("status", lines)
    assert "Nothing is leaving this computer." in lines
    assert any(line.startswith("Open work") for line in lines)


def test_status_reports_unreadable_work_as_unavailable_not_as_zero() -> None:
    lines = render_status(build.snapshot(work_readable=False), WIDE)
    joined = "\n".join(lines)
    assert "unavailable" in joined
    assert "0 tasks" not in joined


def test_status_makes_no_privacy_claim_when_the_policy_cannot_be_read() -> None:
    from finishup.tui.models import PrivacyPosture

    unreadable = PrivacyPosture(profile=None, llm_inference_enabled=None, readable=False)
    lines = render_status(build.snapshot(privacy=unreadable), WIDE)
    joined = "\n".join(lines)
    assert "Nothing is leaving this computer." not in joined
    assert "could not be read" in joined


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


def test_the_endpoint_screen_warns_that_storing_a_key_enables_nothing() -> None:
    joined = "\n".join(render_provider_endpoint(build.OPENAI, "gpt-4.1-mini", WIDE))
    assert "api.openai.com/v1" in joined
    assert "does not switch external review on" in joined


def test_stored_configuration_is_never_reported_as_a_working_provider(
    assert_snapshot: Snapshot,
) -> None:
    lines = render_provider_stored(build.UNTESTED_PROVIDER, WIDE)
    assert_snapshot("provider_stored", lines)
    assert "✓ Provider binding saved" in lines
    assert "✓ API key stored securely" in lines
    assert "! Live provider connection has not been tested" in lines
    assert "! External AI-powered review is not yet proven ready" in lines


def test_a_tested_provider_is_the_only_way_to_earn_the_verified_symbol() -> None:
    tested = ProviderPosture(
        endpoint_bound=True,
        provider_id="openai",
        model="gpt-4.1-mini",
        endpoint_profile_id="openai-responses",
        credential_connected=True,
        llm_inference_enabled=True,
        semantic_enabled=True,
        semantic_ready=True,
        readiness_determinable=True,
        transport_tested=True,
    )
    lines = render_provider_stored(tested, WIDE)
    assert "✓ Live provider connection responded" in lines
    assert not any(line.startswith("!") for line in lines)


def test_a_provider_failure_does_not_downgrade_local_readiness() -> None:
    lines = render_provider_failure("Authentication failed", WIDE)
    joined = "\n".join(lines)
    assert lines[0].startswith("■")
    assert "Local FinishUP verification is still ready." in lines
    assert "Your API key remains stored securely." in lines
    assert "Authentication failed" in joined


# ---------------------------------------------------------------------------
# Privacy
# ---------------------------------------------------------------------------


def test_recipe_names_match_the_command_line_exactly() -> None:
    """One vocabulary for one concept.

    The interface used to offer profile-shaped labels ("Minimal external review") while the
    CLI offered recipe names ("Assisted review"), so the same policy had two names depending
    on where you met it. Only the trusted terminal ceremony renders the actual policy diff, so
    this list is a selector — and a selector whose names do not match the documented ones is a
    way to configure something other than what you thought you chose.
    """

    assert tuple(label for _recipe, label, _description in PRIVACY_RECIPES) == (
        "Private",
        "Metadata only",
        "Assisted review",
        "Expanded review",
        "Custom",
    )
    assert all(description for _recipe, _label, description in PRIVACY_RECIPES)


def test_local_only_is_the_privacy_choice_described_as_the_default() -> None:
    assert "default" in PrivacyChoice.LOCAL_ONLY.description
    assert PrivacyChoice.LOCAL_ONLY.label == "Local only"


# ---------------------------------------------------------------------------
# Work, receipts, diagnosis
# ---------------------------------------------------------------------------


def test_work_detail_shows_every_layer_a_receipt_would_report(
    assert_snapshot: Snapshot,
) -> None:
    lines = render_work_detail(build.work_detail(), 100)
    assert_snapshot("work_detail", lines)
    for label in ("Claims", "Checks", "Coverage", "Findings", "Limitations", "Receipt"):
        assert any(line.startswith(label) or line == label for line in lines), label


def test_work_detail_renders_unknown_count_without_inventing_zero() -> None:
    detail = build.work_detail()
    detail = type(detail)(
        item=detail.item,
        claims=detail.claims,
        evidence_count=None,
        checks=detail.checks,
        coverage=detail.coverage,
        findings=detail.findings,
        limitations=detail.limitations,
        receipt_available=detail.receipt_available,
    )

    assert "Evidence             unknown" in render_work_detail(detail, 100)


def test_receipt_foregrounds_the_verdict_and_what_was_not_verified(
    assert_snapshot: Snapshot,
) -> None:
    lines = render_receipt(build.receipt(), 100)
    assert_snapshot("receipt", lines)
    assert lines[0].startswith("Verdict:")
    joined = "\n".join(lines)
    assert "What was not verified" in joined
    assert "Deeper review: not available for this receipt" in joined


def test_receipt_keeps_the_service_child_section_and_coverage_wording() -> None:
    from finishup.tui.models import ReceiptSummary

    summary = ReceiptSummary(
        subject_id="tsk_53000000-0000-4000-8000-000000000001",
        verdict="insufficient_coverage",
        rendered_lines=(
            "Conclusion: insufficient_coverage",
            "Children",
            "Accepted child: open coverage gap; tested manifest remains unchanged.",
            "Semantic review: contributed at the recorded frontier.",
        ),
    )
    text = "\n".join(render_receipt(summary, 100))
    assert "Accepted child: open coverage gap" in text
    assert "contributed at the recorded frontier" in text
    assert "Open findings: 0" not in text
    assert "not available for this receipt" not in text


def test_doctor_reports_problems_and_never_claims_to_have_fixed_them(
    assert_snapshot: Snapshot,
) -> None:
    lines = render_doctor(build.doctor(), 100)
    assert_snapshot("doctor", lines)
    joined = "\n".join(lines)
    assert "Suggested next steps" in joined
    assert "Nothing above was changed. Diagnosis never repairs on its own." in lines


def test_doctor_keeps_a_remediation_address_whole_and_clickable() -> None:
    from finishup.cli.exits import UPGRADING_FROM_YOETZ_GUIDE
    from finishup.tui.models import DoctorEntry, DoctorReport

    report = DoctorReport(
        entries=(
            DoctorEntry(
                "installation_folders",
                "Installation folders",
                LayerState.VERIFIED,
                "Yoetz-era folders, used in place",
                "nothing to do: keep them. Read more: " + UPGRADING_FROM_YOETZ_GUIDE,
            ),
        )
    )
    for width in (80, 100):
        lines = render_doctor(report, width)
        assert f"  {UPGRADING_FROM_YOETZ_GUIDE}" in lines
        assert "  · nothing to do: keep them. Read more:" in lines


# ---------------------------------------------------------------------------
# Narrow terminals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("width", [30, 40, 52, 80, 120])
def test_no_renderer_ever_overflows_the_width_it_was_given(width: int) -> None:
    renders = (
        render_welcome(width),
        render_detection(build.detection(), width),
        render_project_trust(build.detection(), width),
        render_integration_preview(build.plan(), width),
        render_layers(build.layers(), width),
        render_status(build.snapshot(), width),
        render_finish(build.snapshot(), width),
        render_provider_stored(build.UNTESTED_PROVIDER, width),
        render_receipt(build.receipt(), width),
        render_doctor(build.doctor(), width),
    )
    for lines in renders:
        for line in lines:
            assert len(line) <= width, f"{len(line)} > {width}: {line!r}"


def test_the_session_header_middle_truncates_a_long_project_path() -> None:
    lines = render_session_header(
        version="0.1.0",
        project_root="/srv/projects/deeply/nested/workspace/finishup",
        harness_state="connected",
        privacy_summary="local only",
        width=48,
    )
    joined = "\n".join(lines)
    assert ">_ FinishUP (v0.1.0)" in joined
    assert "…" in joined
    assert "/privacy to change" in joined


def test_privacy_posture_says_review_is_not_set_up_in_a_repository_without_a_grant() -> None:
    """ADR-049 review round 2: `/privacy` reads the repository, not the inherited row."""

    from finishup.tui.models import PrivacyPosture as _Posture

    missing = _Posture(
        profile="assisted_review",
        llm_inference_enabled=True,
        readable=True,
        repository_grant_state="missing",
        conversation_review="ai_powered",
        conversation_review_explicit=False,
    )
    summary = missing.conversation_review_summary or ""
    assert "AI-powered review is not set up for this repository" in summary
    assert "every task runs with AI-powered review" not in summary
    released_off = _Posture(
        profile="private",
        llm_inference_enabled=False,
        readable=True,
        repository_grant_state="granted",
        conversation_review="local_only",
        conversation_review_explicit=False,
    )
    assert "agents may not" not in (released_off.conversation_review_summary or "")


def test_privacy_posture_names_a_pending_carry_forward() -> None:
    from finishup.tui.models import PrivacyPosture as _Posture

    pending = _Posture(
        profile="assisted_review",
        llm_inference_enabled=True,
        readable=True,
        repository_grant_state="missing",
        repository_migration_state="first_repository_available",
        conversation_review="ai_powered",
        conversation_review_explicit=False,
    )
    summary = pending.conversation_review_summary or ""
    assert "carried forward to it when a task first starts" in summary
