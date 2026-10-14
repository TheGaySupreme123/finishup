"""A runtime double for driving the terminal UI without touching real services.

Every method mirrors :class:`finishup.tui.runtime.FinishUpRuntime` and records what the
interface asked for, so interaction tests can assert on the *decisions* the UI
made — which plan it applied, whether it asked for a credential at all — without
a Codex installation, a running service, or a vault.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

from finishup.tui.models import (
    CheckMode,
    Detection,
    DoctorReport,
    HarnessOption,
    IntegrationOutcome,
    IntegrationPlan,
    LayerState,
    PrivacyPosture,
    PrivacyRecommendation,
    ProviderOption,
    ProviderPosture,
    ReadinessLayer,
    ReceiptSummary,
    StatusSnapshot,
    TaskStatusPage,
    VaultPosture,
    WorkDetail,
    WorkItem,
)
from finishup.tui.runtime import RuntimeError_

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

PLAN = IntegrationPlan(
    harness_label="Codex Desktop",
    executable_path=DESKTOP.executable_path,
    codex_home="/tmp/codex",
    reported_version="0.44",
    project_root="/tmp/project",
    route_profile="policy",
    mcp_command="finishup mcp serve",
    mcp_server_name="finishup",
    policy_digest="7f8a92bd",
    planned_check_ids=("lint",),
    planned_file_count=6,
    managed_paths=(
        "/tmp/project/.agents/skills/finishup",
        "/tmp/project/.agents/plugins/finishup",
    ),
    state_before="absent",
    already_registered=False,
    foreign_entry=False,
    preview_digest="sha256:abc123",
    skill_preview_digest="sha256:def456",
    activation_preview_digest="sha256:activation",
    activation_marketplace_path="/tmp/project/.agents/plugins/marketplace.json",
    activation_config_path="/tmp/codex/config.toml",
    activation_marketplace_text='{"name":"finishup"}\n',
    activation_config_block='[plugins."finishup@finishup"]\nenabled = true\n',
    activation_plugin_source_digest="sha256:plugin-tree",
    activation_inventory_verified=False,
    activation_plugin_install_path="/tmp/codex/plugins/cache/finishup/finishup/0.1.0",
    activation_plugin_install_digest="sha256:installed-plugin-tree",
    activation_executable_digest="sha256:codex-executable",
    activation_codex_version="0.148.0-alpha.6",
    activation_probe_command=("--version",),
    activation_inventory_command=("plugin", "list", "--marketplace", "finishup", "--json"),
    activation_install_command=("plugin", "add", "finishup@finishup", "--json"),
    activation_probe_environment="temporary_owner_private_home",
    activation_environment=(("CODEX_HOME", "/tmp/codex"), ("CODEX_TESTING_HOME", "/tmp/codex")),
    activation_marketplace_preimage_digest="sha256:marketplace-before",
    activation_config_preimage_digest="sha256:config-before",
    activation_cache_mutation_planned=True,
)

LOCAL_ONLY = PrivacyPosture(profile="local_only", llm_inference_enabled=False, readable=True)
# No external provider is bound by default, so the recommendation is Private — the same rule
# `finishup.cli.privacy_setup.recommended_privacy_recipe` applies.
RECOMMEND_PRIVATE = PrivacyRecommendation(
    "private",
    "No reviewer with current reviewed data-use evidence is set up, so FinishUP runs its local "
    "checks on every task and sends no work for AI-powered review.",
    "Add AI-powered review with /provider when you want it; your agent can then turn it on for "
    "a task when it helps.",
)
# Verbatim from `FinishUpRuntime.privacy_recommendation`. A fake that paraphrases lets a test
# assert wording the product does not actually say.
RECOMMEND_METADATA_ONLY = PrivacyRecommendation(
    "metadata_only",
    "It enables AI-powered review while disclosing the least that still works, and asks before "
    "every provider request.",
    "In exchange, the reviewer sees structural metadata only, so it cannot judge whether a "
    "claim is actually supported.",
)

UNBOUND_PROVIDER = ProviderPosture(
    endpoint_bound=False,
    provider_id=None,
    model=None,
    endpoint_profile_id=None,
    credential_connected=None,
    llm_inference_enabled=False,
    semantic_enabled=False,
    semantic_ready=False,
    readiness_determinable=False,
)


@dataclass
class FakeRuntime:
    """Records interface decisions; never performs a real operation."""

    harnesses: tuple[HarnessOption, ...] = (DESKTOP,)
    plan: IntegrationPlan = PLAN
    mcp: str = "absent"
    secure_storage: bool = True
    privacy: PrivacyPosture = LOCAL_ONLY
    recommendation: PrivacyRecommendation = RECOMMEND_METADATA_ONLY
    provider: ProviderPosture = UNBOUND_PROVIDER
    vault: VaultPosture = VaultPosture(reachable=True, state="ready", vault_mode="os_keyring")
    plan_error: RuntimeError_ | None = None
    apply_result: IntegrationOutcome | None = None
    credential_result: str | None = "stored"
    privacy_setup_grant_state: Literal["granted", "missing"] = "granted"

    applied: list[tuple[str, str | None]] = field(default_factory=lambda: [])
    # Which route each half of the integration asked for, so a test can assert they agree.
    planned_routes: list[str | None] = field(default_factory=lambda: [])
    suggested_codex_home_value: Path | None = None
    planned_codex_homes: list[Path] = field(default_factory=lambda: [])
    applied_routes: list[str] = field(default_factory=lambda: [])
    applied_codex_homes: list[Path] = field(default_factory=lambda: [])
    ceremonies: list[str] = field(default_factory=lambda: [])
    bindings: list[tuple[str, str]] = field(default_factory=lambda: [])
    subscription_actions: list[str] = field(default_factory=lambda: [])
    subscription_setups: list[tuple[str, str, str, str, bool]] = field(default_factory=lambda: [])
    subscription_routine_efforts: list[str | None] = field(default_factory=lambda: [])
    checks: list[tuple[str, CheckMode]] = field(default_factory=lambda: [])
    opened: list[str] = field(default_factory=lambda: [])
    progress_reads: list[str] = field(default_factory=lambda: [])
    task_views: list[tuple[str, str]] = field(default_factory=lambda: [])

    def project_root(self) -> Path:
        return Path("/tmp/project")

    @property
    def cwd(self) -> Path:
        return Path("/tmp/project")

    @property
    def opened_titles(self) -> tuple[str, ...]:
        return tuple(reversed(self.opened))

    def suggested_codex_home(self) -> Path | None:
        return self.suggested_codex_home_value

    def discover_harnesses(self) -> tuple[HarnessOption, ...]:
        return self.harnesses

    async def detect(self) -> Detection:
        return Detection(
            project_root="/tmp/project",
            project_name="project",
            is_git_repository=True,
            launched_from_subdirectory=False,
            harnesses=self.harnesses,
            secure_storage_available=self.secure_storage,
            secure_storage_reason=(
                ""
                if self.secure_storage
                else "no credential store is loaded; FinishUP needs a test"
            ),
            already_connected=self.mcp == "yoetz_owned",
            cwd="/tmp/project",
        )

    async def mcp_state(self, option: HarnessOption) -> str:
        return self.mcp

    async def run_privacy_setup(
        self,
        recipe_hint: str | None,
        *,
        offer_recommended: bool = False,
        conversation_review: str | None = None,
    ) -> object:
        from finishup.cli.privacy_setup import PrivacySetupReport

        # ``None`` means the CLI opens on its recommendation; the fake resolves it the same way
        # the real one does so the interface cannot be tested against a rule of its own.
        recipe = recipe_hint or self.recommendation.recipe
        self.ceremonies.append(
            f"privacy:{recipe}{'+recommended' if offer_recommended else ''}"
            + ("" if conversation_review is None else f"+conversations:{conversation_review}")
        )
        profile = {
            "private": "local_only",
            "metadata_only": "confirm_every_request",
            "assisted_review": "minimal_external",
            "expanded_review": "trusted_provider",
            "custom": "minimal_external",
        }[recipe]
        self.privacy = PrivacyPosture(
            profile=profile,
            llm_inference_enabled=(
                recipe != "private" and self.privacy_setup_grant_state == "granted"
            ),
            readable=True,
            repository_grant_state=self.privacy_setup_grant_state,
            repository_migration_state="not_applicable",
        )
        return PrivacySetupReport(
            "configured",
            profile,
            grant_state=self.privacy_setup_grant_state,
            migration_state="not_applicable",
        )

    def privacy_recommendation(
        self, _posture: PrivacyPosture | None = None
    ) -> PrivacyRecommendation:
        return self.recommendation

    async def integration_plan(
        self,
        option: HarnessOption,
        codex_home: Path,
        route_profile: Literal["policy", "strict"] | None = None,
    ) -> IntegrationPlan:
        if self.plan_error is not None:
            raise self.plan_error
        # Record the requested route and answer on it. The real runtime puts the route inside
        # the preview digest, so a fake that ignored it would let the ordering defect this
        # signature exists to prevent pass unnoticed.
        self.planned_routes.append(route_profile)
        self.planned_codex_homes.append(codex_home)
        route = self.plan.route_profile if route_profile is None else route_profile
        return replace(
            self.plan,
            harness_label=option.label,
            executable_path=option.executable_path,
            codex_home=str(codex_home),
            activation_config_path=str(codex_home / "config.toml"),
            activation_plugin_install_path=str(
                codex_home / "plugins/cache/finishup/finishup/0.1.0"
            ),
            activation_environment=(
                ("CODEX_HOME", str(codex_home)),
                ("CODEX_TESTING_HOME", str(codex_home)),
            ),
            reported_version=option.reported_version,
            route_profile=route,
            mcp_command=(
                "finishup mcp serve --semantic off" if route == "strict" else "finishup mcp serve"
            ),
        )

    async def apply_integration(
        self, option: HarnessOption, plan: IntegrationPlan
    ) -> IntegrationOutcome:
        self.applied.append((plan.preview_digest, plan.policy_digest))
        self.applied_routes.append(plan.route_profile)
        self.applied_codex_homes.append(Path(plan.codex_home))
        if self.apply_result is not None:
            return self.apply_result
        return IntegrationOutcome(
            outcome="registered",
            reason=None,
            layers=(
                ReadinessLayer("mcp_registered", "MCP registered", LayerState.VERIFIED),
                ReadinessLayer("mcp_verified", "MCP verified", LayerState.VERIFIED),
                ReadinessLayer("plugin_installed", "Guidance installed", LayerState.VERIFIED),
            ),
        )

    async def foreign_entry_detail(self, option: HarnessOption) -> tuple[str, ...]:
        return ('An MCP entry named "finishup" already exists.',)

    async def vault_posture(self) -> VaultPosture:
        return self.vault

    async def privacy_posture(self) -> PrivacyPosture:
        return self.privacy

    async def provider_posture(self) -> ProviderPosture:
        return self.provider

    def provider_options(self) -> tuple[ProviderOption, ...]:
        return (
            ProviderOption(
                choice="official_openai",
                label="OpenAI",
                provider_id="openai",
                host="api.openai.com",
                base_path_prefix="/v1",
                default_model="gpt-4.1-mini",
                api_style="responses",
                endpoint_profile_id="openai-responses",
                endpoint_profile_version="1.0.0",
            ),
            ProviderOption(
                choice="anthropic",
                label="Anthropic",
                provider_id="anthropic",
                host="api.anthropic.com",
                base_path_prefix="/v1",
                default_model="claude-sonnet-4-6",
                api_style="chat_completions",
                endpoint_profile_id="anthropic-openai-chat-completions",
                endpoint_profile_version="1.0.0",
            ),
        )

    def save_provider_binding(
        self, option: ProviderOption, model: str, *, https_origin: str | None = None
    ) -> None:
        self.bindings.append((option.choice, model))

    async def store_provider_credential(self) -> str:
        self.ceremonies.append("provider_credential")
        if self.credential_result is None:
            raise RuntimeError_("cancelled", "the credential ceremony did not complete")
        if self.bindings:
            choice, model = self.bindings[-1]
            option = next(item for item in self.provider_options() if item.choice == choice)
            self.provider = ProviderPosture(
                endpoint_bound=True,
                provider_id=option.provider_id,
                model=model,
                endpoint_profile_id=option.endpoint_profile_id,
                credential_connected=True,
                llm_inference_enabled=False,
                semantic_enabled=True,
                semantic_ready=False,
                readiness_determinable=True,
            )
        return self.credential_result

    def codex_subscription_defaults(self) -> tuple[str, str, str, str]:
        return "/opt/codex/codex", "/var/lib/finishup/codex-home", "gpt-5.6-luna", "high"

    subscription_routine_default: str | None = "medium"

    def codex_subscription_routine_default(self) -> str | None:
        return self.subscription_routine_default

    def preview_codex_subscription(
        self,
        executable: str,
        codex_home: str,
        model: str,
        reasoning_effort: str,
        routine_reasoning_effort: str | None = None,
    ) -> dict[str, object]:
        return {
            "executable_path": executable,
            "executable_sha256": "sha256:" + "a" * 64,
            "runtime_version": "0.150.1",
            "capability_cell_sha256": "sha256:" + "b" * 64,
            "capability_evidence_expires_at": "2026-11-30T00:00:00Z",
            "codex_home": codex_home,
            "model": model,
            "reasoning_effort": reasoning_effort,
            "routine_reasoning_effort": routine_reasoning_effort,
        }

    subscription_login_reused: bool = False

    async def setup_codex_subscription(
        self,
        executable: str,
        codex_home: str,
        model: str,
        reasoning_effort: str,
        *,
        switch_account: bool = False,
        routine_reasoning_effort: str | None = None,
    ) -> dict[str, object]:
        action = "switch" if switch_account else "setup"
        self.subscription_routine_efforts.append(routine_reasoning_effort)
        self.subscription_actions.append(action)
        self.subscription_setups.append(
            (executable, codex_home, model, reasoning_effort, switch_account)
        )
        self.ceremonies.append(f"codex_subscription:{action}")
        return {
            "auth_mode": "chatgpt",
            "plan_type": "plus",
            "model_available": True,
            "process_cleanup": "terminated",
            "login_reused": self.subscription_login_reused and not switch_account,
        }

    async def codex_subscription_status(self) -> dict[str, object]:
        self.subscription_actions.append("status")
        return {
            "auth_mode": "chatgpt",
            "plan_type": "plus",
            "model": "gpt-5.6-luna",
            "model_available": True,
            "review_budgets": {
                "routine": {
                    "reasoning_effort": "medium",
                    "output_limit": 4096,
                    "effort_source": "configured",
                },
                "final": {
                    "reasoning_effort": "high",
                    "output_limit": 8192,
                    "effort_source": "configured",
                },
            },
            "process_cleanup": "terminated",
        }

    async def disconnect_codex_subscription(self) -> dict[str, object]:
        self.subscription_actions.append("disconnect")
        self.ceremonies.append("codex_subscription:disconnect")
        return {"binding_removed": True, "process_cleanup": "terminated"}

    async def rollback_codex_subscription(self) -> dict[str, object]:
        self.subscription_actions.append("rollback")
        self.ceremonies.append("codex_subscription:rollback")
        return {"binding_removed": True, "codex_installation_preserved": True}

    async def initialize_passphrase_vault(self) -> None:
        self.ceremonies.append("initialize_vault")

    async def rotate_vault_passphrase(self) -> None:
        self.ceremonies.append("rotate_vault_passphrase")

    async def initialize_system_keyring(self) -> None:
        self.ceremonies.append("initialize_keyring")

    async def unlock_vault(self) -> None:
        self.ceremonies.append("unlock_vault")

    async def service_lock(self) -> str:
        return "locked"

    async def service_stop(self) -> str:
        return "draining"

    async def status_snapshot(self) -> StatusSnapshot:
        return StatusSnapshot(
            project_root="/tmp/project",
            layers=(
                ReadinessLayer("harness_detected", "Harness detected", LayerState.VERIFIED),
                ReadinessLayer("mcp_verified", "MCP verified", LayerState.VERIFIED),
                ReadinessLayer("service_reachable", "Local service reachable", LayerState.VERIFIED),
                ReadinessLayer("vault_ready", "Vault ready", LayerState.VERIFIED),
                ReadinessLayer("local_checks", "Local checks", LayerState.VERIFIED),
                ReadinessLayer(
                    "semantic_review_ready", "Deeper review ready", LayerState.NOT_CONFIGURED
                ),
            ),
            privacy=self.privacy,
            open_work=1,
            open_findings=2,
            work_readable=True,
        )

    async def doctor(self) -> DoctorReport:
        return DoctorReport(entries=())

    async def open_task(self, title: str) -> WorkDetail:
        self.opened.append(title)
        return WorkDetail(
            item=WorkItem(
                subject_id="task_01",
                title=title,
                state="current",
                open_findings=0,
                last_check="not run",
                updated="1",
            )
        )

    async def run_check(self, title: str, mode: CheckMode) -> tuple[str, tuple[str, ...]]:
        self.checks.append((title, mode))
        return "pass", ("Verdict: pass",)

    async def check_progress(self, title: str) -> TaskStatusPage:
        self.progress_reads.append(title)
        return TaskStatusPage(
            (
                "Operation: req_00000000-0000-4000-8000-000000000571 (pending)",
                "Semantic review phase: provider_sampling (attempt 1, active)",
                "Semantic review elapsed: 42s; remaining 858s; deadline 2026-09-22T12:15:00.000Z",
                "Gaps: none",
            ),
            None,
        )

    async def task_status(
        self, title: str, view: str, *, cursor: str | None = None
    ) -> TaskStatusPage:
        del cursor
        self.task_views.append((title, view))
        return TaskStatusPage(
            (
                "[ ] F-1 fnd_00000000-0000-4000-8000-000000000001 open (2/5)",
                "[x] F-2 fnd_00000000-0000-4000-8000-000000000002 verified_resolved",
                "[~] F-3 fnd_00000000-0000-4000-8000-000000000003 acknowledged_not_done",
                "[-] F-4 fnd_00000000-0000-4000-8000-000000000004 rejection_accepted",
                "Gaps: none",
            ),
            None,
        )

    async def build_receipt(self, title: str, output_format: str) -> ReceiptSummary:
        return ReceiptSummary(subject_id="task_01", verdict="no_unresolved_deterministic_findings")
