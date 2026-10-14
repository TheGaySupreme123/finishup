"""Deterministic value objects for terminal-UI rendering tests."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from yoetz.tui.models import (
    Detection,
    DoctorEntry,
    DoctorReport,
    HarnessOption,
    IntegrationPlan,
    LayerState,
    PrivacyPosture,
    ProviderOption,
    ProviderPosture,
    ReadinessLayer,
    ReceiptSummary,
    StatusSnapshot,
    WorkDetail,
    WorkItem,
)

DESKTOP = HarnessOption(
    executable_path="/Applications/Codex.app/Contents/MacOS/codex",
    reported_version="0.44",
    label="Codex Desktop 0.44",
    description="Application installation · recommended",
    recommended=True,
)

CLI = HarnessOption(
    executable_path="/usr/local/bin/codex",
    reported_version="0.44",
    label="Codex CLI 0.44",
    description="Command-line installation",
)


_DETECTION = Detection(
    project_root="/srv/yoetz",
    project_name="yoetz",
    is_git_repository=True,
    launched_from_subdirectory=False,
    harnesses=(DESKTOP,),
    secure_storage_available=True,
    already_connected=False,
    cwd="/srv/yoetz",
)


def detection(**overrides: Any) -> Detection:
    return replace(_DETECTION, **overrides)


_PLAN = IntegrationPlan(
    harness_label="Codex Desktop",
    executable_path="/Applications/Codex.app/Contents/MacOS/codex",
    codex_home="/tmp/codex",
    reported_version="0.44",
    project_root="/srv/yoetz",
    route_profile="policy",
    mcp_command="yoetz mcp serve",
    mcp_server_name="yoetz",
    policy_digest="7f8a92bd",
    planned_check_ids=("lint", "unit-tests"),
    planned_file_count=6,
    managed_paths=(
        "/srv/yoetz/.agents/skills/yoetz",
        "/srv/yoetz/.agents/plugins/yoetz",
    ),
    state_before="absent",
    already_registered=False,
    foreign_entry=False,
    preview_digest="sha256:abc123",
    skill_preview_digest="sha256:def456",
    activation_preview_digest="sha256:activation",
    activation_marketplace_path="/srv/yoetz/.agents/plugins/marketplace.json",
    activation_config_path="/tmp/codex/config.toml",
    activation_marketplace_text='{"name":"yoetz"}\n',
    activation_config_block='[plugins."yoetz@yoetz"]\nenabled = true\n',
    activation_plugin_source_digest="sha256:plugin-tree",
    activation_inventory_verified=False,
    activation_plugin_install_path="/tmp/codex/plugins/cache/yoetz/yoetz/0.1.0",
    activation_plugin_install_digest="sha256:installed-plugin-tree",
    activation_executable_digest="sha256:codex-executable",
    activation_codex_version="0.148.0-alpha.6",
    activation_probe_command=("--version",),
    activation_inventory_command=("plugin", "list", "--marketplace", "yoetz", "--json"),
    activation_install_command=("plugin", "add", "yoetz@yoetz", "--json"),
    activation_probe_environment="temporary_owner_private_home",
    activation_environment=(("CODEX_HOME", "/tmp/codex"), ("CODEX_TESTING_HOME", "/tmp/codex")),
    activation_marketplace_preimage_digest="sha256:marketplace-before",
    activation_config_preimage_digest="sha256:config-before",
    activation_cache_mutation_planned=True,
)


def plan(**overrides: Any) -> IntegrationPlan:
    return replace(_PLAN, **overrides)


def layers(*, connected: bool = True) -> tuple[ReadinessLayer, ...]:
    verified = LayerState.VERIFIED
    off = LayerState.NOT_CONFIGURED
    return (
        ReadinessLayer("harness_detected", "Harness detected", verified, "Codex Desktop 0.44"),
        ReadinessLayer("mcp_registered", "MCP registered", verified if connected else off),
        ReadinessLayer("mcp_verified", "MCP verified", verified if connected else off),
        ReadinessLayer("plugin_installed", "Guidance installed", verified if connected else off),
        ReadinessLayer(
            "hooks_installed", "Structural hooks installed", verified if connected else off
        ),
        ReadinessLayer("project_consent", "Project consent active", verified if connected else off),
        ReadinessLayer(
            "policy_digest_trusted", "Approved-check policy trusted", verified if connected else off
        ),
        ReadinessLayer("service_reachable", "Local service reachable", verified, "ready"),
        ReadinessLayer("vault_ready", "Vault ready", verified, "os_keyring"),
        ReadinessLayer("local_checks", "Local checks", verified),
        ReadinessLayer("provider_binding", "Provider binding saved", off),
        ReadinessLayer("credential_stored", "Credential stored", off),
        ReadinessLayer(
            "provider_transport_tested",
            "Provider connection tested",
            LayerState.UNPROVEN,
            "no live probe has run",
        ),
        ReadinessLayer("semantic_evaluator", "Deeper-review evaluator composed", off),
        ReadinessLayer("privacy_permission", "Privacy permits external review", off, "local only"),
        ReadinessLayer(
            "semantic_review_ready", "Deeper review ready", off, "external review is off"
        ),
    )


LOCAL_ONLY = PrivacyPosture(
    profile="local_only",
    llm_inference_enabled=False,
    readable=True,
    never_send=("secret_or_cryptographic",),
    enabled_channels=(),
)


def snapshot(**overrides: Any) -> StatusSnapshot:
    base = StatusSnapshot(
        project_root="/srv/yoetz",
        layers=layers(),
        privacy=LOCAL_ONLY,
        open_work=1,
        open_findings=2,
        work_readable=True,
    )
    return replace(base, **overrides)


UNTESTED_PROVIDER = ProviderPosture(
    endpoint_bound=True,
    provider_id="openai",
    model="gpt-4.1-mini",
    endpoint_profile_id="openai-responses",
    credential_connected=True,
    llm_inference_enabled=False,
    semantic_enabled=False,
    semantic_ready=False,
    readiness_determinable=True,
    transport_tested=False,
    blockers=(("llm_inference_channel", "disabled"),),
)

OPENAI = ProviderOption(
    choice="official_openai",
    label="OpenAI",
    provider_id="openai",
    host="api.openai.com",
    base_path_prefix="/v1",
    default_model="gpt-4.1-mini",
    api_style="responses",
    endpoint_profile_id="openai-responses",
    endpoint_profile_version="1.0.0",
)


def work_detail() -> WorkDetail:
    return WorkDetail(
        item=WorkItem(
            subject_id="task_01",
            title="Add rate limiting to the upload endpoint",
            state="current",
            open_findings=2,
            last_check="local only",
            updated="412",
        ),
        claims=("Rate limiting rejects the 11th request in a minute",),
        evidence_count=3,
        checks=("work-integrity/0.3.0",),
        coverage=("no AI-powered review",),
        findings=("P2 unsupported_claim (deterministic): no evidence links the claim",),
        limitations=("semantic_review_unavailable",),
        receipt_available=True,
    )


def receipt() -> ReceiptSummary:
    return ReceiptSummary(
        subject_id="task_01",
        verdict="unresolved_findings_remain",
        coverage=("local checks only",),
        open_findings=2,
        limitations=("semantic_review_unavailable",),
        semantic_available=False,
        freshness="current",
        verified=("Two local policy packs ran against the recorded evidence",),
        not_verified=("No external model reviewed the claims in this task",),
    )


def doctor() -> DoctorReport:
    return DoctorReport(
        entries=(
            DoctorEntry("runtime", "Python runtime", LayerState.VERIFIED, "3.14.6"),
            DoctorEntry("package", "Yoetz version", LayerState.VERIFIED, "0.1.0"),
            DoctorEntry(
                "service_reachable",
                "Local service reachable",
                LayerState.BLOCKED,
                "not running",
                "start the service with 'yoetz service run'",
            ),
            DoctorEntry(
                "provider_binding",
                "Provider binding saved",
                LayerState.NOT_CONFIGURED,
                "",
                "run /provider to choose a provider and model",
            ),
        )
    )
