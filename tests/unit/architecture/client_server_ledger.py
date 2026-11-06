"""Every import that crosses the client/server cut line today, with how it closes.

Seeded by measurement (``test_client_server_boundary.measured_crossings``) at the commit that
introduced the cut line. Each entry is one ``(importer, imported module, enclosing scope)`` with
the number of import statements there. The ledger may only shrink: a new crossing fails the
boundary test, and so does an entry that no longer occurs.

Dispositions (closed):

* ``server_host_only`` — the importing code administers the server host itself (its vault,
  recovery set, provider runtime, privacy ceremonies, observation store, or the service process).
  ``commands`` names the commands that reach it; each is labelled ``server_host`` in
  ``finishup.cli.command_scope`` and is refused on a remote target with ``requires_server_host``.
* ``shared_pure`` — the imported code is pure (types, codecs, catalogs, predicates) and belongs on
  the SHARED side; the crossing closes by reclassifying or extracting it.
* ``to_rpc`` — the importer reads or writes state the other side owns (lock stamps, startup
  failure records, the observation store and outbox, the hook spool, consent handoff files,
  recommendations); the crossing closes when that access moves behind a control method or the
  workspace agent.
* ``client_outbox`` — the importer opens the observation outbox of the client's *own* root to
  deliver what this client's hooks captured to a FinishUP server on another machine. That server
  never opens the root, which holds client state only, so no state crosses hosts: the import
  crosses only because one module (``observation_local``) still holds both the client's outbox
  and the service's observation store. The crossing closes when the outbox moves out of that
  module. It is the one disposition a ``finishup.client`` module may carry.
* ``client_side`` — the importer runs on the client, and the imported module serves whichever
  side holds the workspace and its observation store: the client for a remote target (ADR-051
  decision 12), the server host for a local one. The crossing closes when that module is
  reclassified to the side both use.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

__all__ = ["DISPOSITIONS", "LEDGER", "Crossing", "Disposition"]

type Disposition = Literal[
    "server_host_only", "shared_pure", "to_rpc", "client_outbox", "client_side"
]

DISPOSITIONS: Final[frozenset[str]] = frozenset(
    {"server_host_only", "shared_pure", "to_rpc", "client_outbox", "client_side"}
)


@dataclass(frozen=True, slots=True)
class Crossing:
    """One measured crossing: import statements of ``imported`` inside ``scope`` of ``importer``."""

    importer: str
    imported: str
    scope: str
    statements: int
    disposition: Disposition
    commands: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.importer, self.imported, self.scope)


def _c(
    importer: str,
    imported: str,
    scope: str,
    statements: int,
    disposition: Disposition,
    commands: tuple[str, ...] = (),
) -> Crossing:
    def name(short: str) -> str:
        return short if short == "finishup" else f"finishup.{short}"

    return Crossing(name(importer), name(imported), scope, statements, disposition, commands)


_CODEX_SUBSCRIPTION_COMMANDS: Final = (
    "provider codex-subscription setup",
    "provider codex-subscription status",
    "provider codex-subscription repair",
    "provider codex-subscription rollback",
    "provider codex-subscription disconnect",
    "provider codex-subscription runtime install",
    "provider codex-subscription runtime remove",
    "provider codex-subscription runtime status",
)
_CONSENT_COMMANDS: Final = (
    "consent authorize",
    "consent catalog",
    "consent prepare",
    "consent review",
    "consent status",
    "elevated-bootstrap authorize",
    "elevated-bootstrap catalog",
    "elevated-bootstrap prepare",
    "elevated-bootstrap review",
    "elevated-bootstrap status",
)
_RECOMMEND_COMMANDS: Final = ("recommend accept", "recommend decline", "recommend list")

LEDGER: Final[tuple[Crossing, ...]] = (
    # finishup.adapters.importers.codex_rollout_jsonl
    _c(
        "adapters.importers.codex_rollout_jsonl",
        "adapters.integrations.codex_capability_cells",
        "<module>",
        1,
        "shared_pure",
    ),
    # finishup.adapters.integrations.codex_session_stream
    _c(
        "adapters.integrations.codex_session_stream",
        "adapters.importers.codex_jsonl",
        "<module>",
        1,
        "shared_pure",
    ),
    _c(
        "adapters.integrations.codex_session_stream",
        "adapters.importers.codex_rollout_jsonl",
        "<module>",
        1,
        "shared_pure",
    ),
    _c(
        "adapters.integrations.codex_session_stream",
        "adapters.integrations.observation_local",
        "<module>",
        1,
        "to_rpc",
    ),
    _c(
        "adapters.integrations.codex_session_stream",
        "service.write_scope_admission",
        "_docs_admitted",
        1,
        "shared_pure",
    ),
    # finishup.adapters.integrations.observation_local
    _c(
        "adapters.integrations.observation_local",
        "adapters.integrations.codex_lifecycle",
        "LocalObservationStore._reconcile_pending_session_lifecycle_lanes",
        1,
        "to_rpc",
    ),
    _c(
        "adapters.integrations.observation_local",
        "adapters.integrations.codex_lifecycle",
        "LocalObservationStore.quarantine_ended_unmapped_session",
        1,
        "to_rpc",
    ),
    _c(
        "adapters.integrations.observation_local",
        "adapters.integrations.codex_lifecycle",
        "LocalObservationStore.reconcile_outbox_session_lifecycle",
        1,
        "to_rpc",
    ),
    _c(
        "adapters.integrations.observation_local",
        "adapters.integrations.finishup_call_rejections",
        "<module>",
        1,
        "to_rpc",
    ),
    _c(
        "adapters.integrations.observation_local",
        "adapters.integrations.hook_spool",
        "LocalObservationStore._current_gaps",
        1,
        "to_rpc",
    ),
    _c(
        "adapters.integrations.observation_local",
        "adapters.integrations.observation_admission",
        "<module>",
        1,
        "shared_pure",
    ),
    _c(
        "adapters.integrations.observation_local",
        "adapters.integrations.observation_admission",
        "LocalObservationStore.maintain_selected_admission",
        1,
        "shared_pure",
    ),
    _c(
        "adapters.integrations.observation_local",
        "adapters.integrations.observation_admission",
        "LocalObservationStore.promote_buffered_observation",
        1,
        "shared_pure",
    ),
    _c(
        "adapters.integrations.observation_local",
        "adapters.workspace_fingerprint",
        "LocalObservationStore.revoke",
        1,
        "to_rpc",
    ),
    # finishup.adapters.integrations.observation_task_pending
    _c(
        "adapters.integrations.observation_task_pending",
        "adapters.integrations.observation_local",
        "<module>",
        1,
        "to_rpc",
    ),
    # finishup.adapters.integrations.portable_plugin
    _c(
        "adapters.integrations.portable_plugin",
        "service.elevated_bootstrap",
        "ElevatedPortableArtifactReview.consume_artifact_review",
        1,
        "to_rpc",
    ),
    _c(
        "adapters.integrations.portable_plugin",
        "service.elevated_bootstrap",
        "prepare_portable_artifact_review",
        1,
        "to_rpc",
    ),
    # finishup.adapters.keys.os_keyring
    _c("adapters.keys.os_keyring", "adapters.keys.vault_passphrase", "<module>", 1, "shared_pure"),
    # finishup.application.check
    _c(
        "application.check",
        "application.applied_mcp_route",
        "_strict_ceiling_route_drift",
        1,
        "to_rpc",
    ),
    # finishup.application.host_connection
    _c(
        "application.host_connection",
        "adapters.integrations.observation_local",
        "<module>",
        1,
        "to_rpc",
    ),
    # finishup.application.observation_claims (ADR-051 decision 12: a claim's attested mappings)
    _c(
        "application.observation_claims",
        "adapters.integrations.codex_lifecycle",
        "<module>",
        1,
        "to_rpc",
    ),
    # finishup.application.observation_coordinator
    _c(
        "application.observation_coordinator",
        "adapters.integrations.codex_lifecycle",
        "<module>",
        1,
        "to_rpc",
    ),
    _c(
        "application.observation_coordinator",
        "application.observation_drain",
        "<module>",
        1,
        "shared_pure",
    ),
    # finishup.application.observation_drain
    _c(
        "application.observation_drain",
        "adapters.integrations.observation_local",
        "<module>",
        1,
        "to_rpc",
    ),
    # finishup.application.package_update
    _c(
        "application.package_update", "adapters.privacy.update_checks", "<module>", 1, "shared_pure"
    ),
    # finishup.application.recommendations
    _c("application.recommendations", "application.package_update", "<module>", 1, "shared_pure"),
    # finishup.cli.ai
    _c("cli.ai", "service.vault", "forget_key", 1, "shared_pure"),
    # finishup.cli.app
    _c("cli.app", "adapters.privacy.catalog", "_effective_excerpt_limits_line", 1, "shared_pure"),
    _c(
        "cli.app",
        "adapters.privacy.catalog",
        "privacy_apply_desired._run",
        1,
        "server_host_only",
        ("privacy apply-desired",),
    ),
    _c(
        "cli.app",
        "adapters.privacy.catalog",
        "privacy_export_desired._run",
        1,
        "server_host_only",
        ("privacy export-desired",),
    ),
    _c(
        "cli.app",
        "adapters.providers.codex_app_server",
        "provider_codex_subscription_setup",
        1,
        "server_host_only",
        ("provider codex-subscription setup",),
    ),
    _c(
        "cli.app",
        "adapters.providers.codex_evaluator_runtime",
        "provider_codex_subscription_setup",
        1,
        "server_host_only",
        ("provider codex-subscription setup",),
    ),
    _c(
        "cli.app",
        "application.privacy_policy",
        "privacy_apply_desired._run",
        1,
        "server_host_only",
        ("privacy apply-desired",),
    ),
    _c("cli.app", "service.daemon", "service_run", 1, "server_host_only", ("service run",)),
    _c(
        "cli.app",
        "service.elevated_bootstrap",
        "elevated_authorize",
        1,
        "server_host_only",
        ("consent authorize", "elevated-bootstrap authorize"),
    ),
    _c(
        "cli.app",
        "service.elevated_bootstrap",
        "elevated_prepare",
        1,
        "server_host_only",
        ("consent prepare", "elevated-bootstrap prepare"),
    ),
    _c(
        "cli.app",
        "service.elevated_bootstrap",
        "elevated_review",
        1,
        "server_host_only",
        ("consent review", "elevated-bootstrap review"),
    ),
    _c(
        "cli.app",
        "service.installation_recovery",
        "_installation_recovery_store",
        1,
        "server_host_only",
        ("service recovery status",),
    ),
    _c("cli.app", "service.lifecycle", "<module>", 1, "shared_pure"),
    _c("cli.app", "service.lifecycle", "_singleton_holder_pid", 1, "to_rpc"),
    _c("cli.app", "service.lifecycle", "service_run", 1, "server_host_only", ("service run",)),
    _c(
        "cli.app", "service.startup_failure", "service_run", 1, "server_host_only", ("service run",)
    ),
    _c("cli.app", "service.vault", "_provider_credential_target", 1, "shared_pure"),
    _c("cli.app", "service.vault", "elevated_prepare", 1, "shared_pure"),
    # finishup.cli.bootstrap
    _c("cli.bootstrap", "service.lifecycle", "_holder_identity_json", 1, "to_rpc"),
    _c("cli.bootstrap", "service.lifecycle", "_singleton_holder_pid", 1, "to_rpc"),
    _c("cli.bootstrap", "service.lifecycle", "_with_holder_identity", 1, "to_rpc"),
    _c("cli.bootstrap", "service.startup_failure", "<module>", 1, "shared_pure"),
    _c("cli.bootstrap", "service.startup_failure", "_spawned_startup_failure", 1, "to_rpc"),
    # finishup.cli.claude_code_integration
    _c(
        "cli.claude_code_integration",
        "service.elevated_bootstrap",
        "_artifact_authority",
        1,
        "to_rpc",
    ),
    # finishup.cli.codex_subscription
    _c(
        "cli.codex_subscription",
        "adapters.providers.codex_app_server",
        "<module>",
        1,
        "server_host_only",
        _CODEX_SUBSCRIPTION_COMMANDS,
    ),
    _c(
        "cli.codex_subscription",
        "adapters.providers.codex_capability",
        "<module>",
        1,
        "server_host_only",
        _CODEX_SUBSCRIPTION_COMMANDS,
    ),
    _c(
        "cli.codex_subscription",
        "adapters.providers.codex_evaluator_runtime",
        "<module>",
        1,
        "server_host_only",
        _CODEX_SUBSCRIPTION_COMMANDS,
    ),
    # finishup.cli.cursor_integration
    _c("cli.cursor_integration", "service.elevated_bootstrap", "_artifact_authority", 1, "to_rpc"),
    # finishup.cli.elevated
    _c(
        "cli.elevated",
        "adapters.privacy.catalog",
        "_complete_repository_privacy_grant",
        1,
        "server_host_only",
        ("consent authorize", "elevated-bootstrap authorize"),
    ),
    _c(
        "cli.elevated",
        "service.elevated_bootstrap",
        "<module>",
        1,
        "server_host_only",
        _CONSENT_COMMANDS,
    ),
    # finishup.cli.entry
    _c(
        "cli.entry",
        "service.startup_failure",
        "_record_spawned_service_refusal",
        1,
        "server_host_only",
        ("service run",),
    ),
    # finishup.cli.hooks
    _c("cli.hooks", "adapters.integrations.observation_local", "_local_pending_rows", 1, "to_rpc"),
    # finishup.cli.host_connection
    _c("cli.host_connection", "service.elevated_bootstrap", "<module>", 1, "to_rpc"),
    _c(
        "cli.host_connection",
        "service.elevated_bootstrap",
        "_release_unreviewed_approval",
        1,
        "to_rpc",
    ),
    _c("cli.host_connection", "service.elevated_bootstrap", "apply_selected", 1, "to_rpc"),
    # finishup.cli.instance
    _c("cli.instance", "service.lifecycle", "<module>", 1, "to_rpc"),
    # finishup.cli.menu
    _c("cli.menu", "service.vault", "_provider_menu", 1, "shared_pure"),
    # finishup.cli.observe
    _c("cli.observe", "adapters.integrations.observation_local", "<module>", 1, "client_side"),
    _c("cli.observe", "application.observation_verification", "<module>", 1, "client_side"),
    # finishup.cli.observe_hooks
    _c("cli.observe_hooks", "adapters.integrations.observation_local", "<module>", 1, "to_rpc"),
    _c(
        "cli.observe_hooks",
        "application.recommendations",
        "_cached_recommendation_context",
        1,
        "to_rpc",
    ),
    # finishup.cli.privacy_setup
    _c("cli.privacy_setup", "adapters.privacy.catalog", "<module>", 1, "shared_pure"),
    _c("cli.privacy_setup", "adapters.privacy.catalog", "_propose", 1, "shared_pure"),
    _c("cli.privacy_setup", "adapters.privacy.local_enforcer", "<module>", 1, "shared_pure"),
    _c("cli.privacy_setup", "adapters.providers.data_use_catalog", "<module>", 1, "shared_pure"),
    _c(
        "cli.privacy_setup",
        "adapters.providers.openai_responses_factory",
        "<module>",
        1,
        "shared_pure",
    ),
    # finishup.cli.provider_status
    _c(
        "cli.provider_status",
        "adapters.providers.codex_evaluator_runtime",
        "external_runtime_fact",
        1,
        "shared_pure",
    ),
    # finishup.cli.recommend
    _c(
        "cli.recommend",
        "application.recommendations",
        "<module>",
        1,
        "server_host_only",
        _RECOMMEND_COMMANDS,
    ),
    # finishup.cli.runtime_facts
    _c("cli.runtime_facts", "service.write_scope_admission", "_docs_admitted", 1, "shared_pure"),
    # finishup.cli.setup
    _c(
        "cli.setup",
        "adapters.integrations.observation_local",
        "_activate_check_policy_trust",
        1,
        "to_rpc",
    ),
    _c(
        "cli.setup",
        "adapters.integrations.observation_local",
        "_grant_observation_consent",
        1,
        "to_rpc",
    ),
    _c(
        "cli.setup",
        "adapters.integrations.observation_local",
        "_observation_hook_probe",
        1,
        "to_rpc",
    ),
    _c("cli.setup", "application.recommendations", "_refresh_setup_recommendations", 1, "to_rpc"),
    _c("cli.setup", "service.vault", "_interactive_provider_setup", 1, "shared_pure"),
    # finishup.cli.unlock
    _c("cli.unlock", "adapters.keys.installation_recovery", "_drive_session", 1, "shared_pure"),
    _c(
        "cli.unlock",
        "service.installation_recovery",
        "export_installation_recovery_set",
        1,
        "server_host_only",
        ("service recovery export",),
    ),
    _c(
        "cli.unlock",
        "service.installation_recovery",
        "import_installation_recovery_set",
        1,
        "server_host_only",
        ("service recovery import",),
    ),
    _c(
        "cli.unlock",
        "service.installation_recovery",
        "provision_installation_recovery",
        1,
        "server_host_only",
        ("service recovery provision",),
    ),
    _c(
        "cli.unlock",
        "service.installation_recovery",
        "restore_installation_recovery",
        1,
        "server_host_only",
        ("service recovery restore",),
    ),
    _c("cli.unlock", "service.owner_view", "_owner_view_target_digest", 1, "shared_pure"),
    # finishup.client.observation_outbox
    _c(
        "client.observation_outbox",
        "adapters.integrations.observation_local",
        "<module>",
        1,
        "client_outbox",
    ),
    # finishup.kernel.claim_verification
    _c("kernel.claim_verification", "kernel.acceptance_risk", "<module>", 1, "shared_pure"),
    _c("kernel.claim_verification", "kernel.closure_class", "<module>", 1, "shared_pure"),
    _c("kernel.claim_verification", "kernel.plan_scope", "<module>", 1, "shared_pure"),
    _c("kernel.claim_verification", "kernel.projections", "<module>", 1, "shared_pure"),
    _c("kernel.claim_verification", "kernel.task_facts", "<module>", 1, "shared_pure"),
    _c("kernel.claim_verification", "kernel.verification_link", "<module>", 1, "shared_pure"),
    # finishup.mcp.server
    _c("mcp.server", "service.startup_failure", "_control_error_result", 1, "to_rpc"),
    # finishup.ports.ledger
    _c("ports.ledger", "kernel.closure_readiness", "<module>", 1, "shared_pure"),
    _c("ports.ledger", "kernel.deterministic_checks", "<module>", 1, "shared_pure"),
    _c("ports.ledger", "kernel.finding_todo", "<module>", 1, "shared_pure"),
    _c("ports.ledger", "kernel.lineage", "<module>", 1, "shared_pure"),
    _c("ports.ledger", "kernel.projections", "<module>", 1, "shared_pure"),
    # finishup.ports.observation
    _c("ports.observation", "kernel.policies.observation_advice", "<module>", 1, "shared_pure"),
    # finishup.ports.semantic
    _c("ports.semantic", "kernel.declared_checks", "<module>", 1, "shared_pure"),
    _c("ports.semantic", "kernel.deterministic_checks", "<module>", 1, "shared_pure"),
    _c("ports.semantic", "kernel.policies.research_evidence", "<module>", 1, "shared_pure"),
    _c("ports.semantic", "kernel.policies.work_integrity", "<module>", 1, "shared_pure"),
    # finishup.ports.semantic_budget
    _c("ports.semantic_budget", "kernel.claims", "<module>", 1, "shared_pure"),
    _c("ports.semantic_budget", "kernel.projections", "<module>", 1, "shared_pure"),
    # finishup.service
    _c("service", "service.client", "<module>", 1, "shared_pure"),
    _c("service", "service.client", "__getattr__", 1, "shared_pure"),
    # finishup.service.client
    _c("service.client", "service.lifecycle", "<module>", 1, "shared_pure"),
    _c("service.client", "service.lifecycle", "_singleton_holder_lock_is_held", 1, "to_rpc"),
    _c("service.client", "service.lifecycle", "_singleton_lock_path", 1, "to_rpc"),
    _c("service.client", "service.lifecycle", "service_holder_identity", 1, "to_rpc"),
    _c("service.client", "service.lifecycle", "supersede_incompatible_service", 1, "to_rpc"),
    _c("service.client", "service.lifecycle", "wait_for_singleton_release", 1, "to_rpc"),
    _c(
        "service.client",
        "service.owner_view",
        "ServiceClient.owner_receipt_view_target",
        1,
        "shared_pure",
    ),
    _c("service.client", "service.startup_failure", "_spawned_startup_failure", 1, "to_rpc"),
    # finishup.service.control_protocol
    _c("service.control_protocol", "adapters.repository_identity", "<module>", 1, "shared_pure"),
    # finishup.service.daemon
    _c("service.daemon", "application.observation_drain", "<module>", 1, "shared_pure"),
    # finishup.service.ready_composition
    _c("service.ready_composition", "adapters.integrations.hook_spool", "<module>", 1, "to_rpc"),
    _c(
        "service.ready_composition",
        "adapters.integrations.observation_task_pending",
        "<module>",
        1,
        "to_rpc",
    ),
    _c("service.ready_composition", "application.observation_drain", "<module>", 1, "to_rpc"),
    _c("service.ready_composition", "cli.observe_hooks", "_replay_legacy_hook_spool", 1, "to_rpc"),
    # finishup.tui.runtime
    _c("tui.runtime", "adapters.integrations.observation_local", "<module>", 1, "to_rpc"),
    _c(
        "tui.runtime",
        "adapters.integrations.observation_local",
        "FinishUpRuntime._consent_active",
        1,
        "to_rpc",
    ),
    _c(
        "tui.runtime",
        "adapters.integrations.observation_local",
        "FinishUpRuntime._policy_digest_layer",
        1,
        "to_rpc",
    ),
    _c(
        "tui.runtime",
        "adapters.integrations.observation_local",
        "FinishUpRuntime._workspace_selection_inputs",
        1,
        "to_rpc",
    ),
    _c(
        "tui.runtime",
        "adapters.integrations.observation_local",
        "FinishUpRuntime.observation_selection_status",
        1,
        "to_rpc",
    ),
    _c("tui.runtime", "service.vault", "FinishUpRuntime.credential_target", 1, "shared_pure"),
    # finishup.version
    _c(
        "version",
        "adapters.integrations.codex_capability_cells",
        "_codex_capability_profiles",
        1,
        "shared_pure",
    ),
)
