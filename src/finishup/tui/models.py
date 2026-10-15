"""Presentation-layer value objects shared by the runtime facade and renderers.

These types carry *already-decided* facts out of the application services and
into the views. They deliberately hold no behaviour beyond validation: every
judgement about whether something is registered, verified, trusted, or merely
configured is made by the owning service, and the terminal UI is only allowed to
transcribe it. Keeping the boundary as plain frozen data is what lets the
renderers be tested without a terminal and the runtime be tested without a
screen.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Final, Literal

from finishup.tui.symbols import Level

__all__ = [
    "CheckMode",
    "Detection",
    "DoctorEntry",
    "DoctorReport",
    "HarnessOption",
    "IntegrationOutcome",
    "IntegrationPlan",
    "LayerState",
    "PRIVACY_RECIPES",
    "PrivacyChoice",
    "PrivacyPosture",
    "PrivacyRecommendation",
    "ProviderOption",
    "ProviderPosture",
    "ReadinessLayer",
    "ReceiptSummary",
    "TaskStatusPage",
    "StatusSnapshot",
    "StorageChoice",
    "VaultPosture",
    "WorkItem",
    "WorkDetail",
]


class LayerState(Enum):
    """Certainty of one readiness layer, kept distinct from every other layer."""

    VERIFIED = "verified"
    UNPROVEN = "unproven"
    NOT_CONFIGURED = "not_configured"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"

    @property
    def level(self) -> Level:
        return _LAYER_LEVELS[self]


_LAYER_LEVELS: Final[dict[LayerState, Level]] = {
    LayerState.VERIFIED: Level.VERIFIED,
    LayerState.UNPROVEN: Level.UNPROVEN,
    LayerState.NOT_CONFIGURED: Level.OPTIONAL,
    LayerState.BLOCKED: Level.BLOCKED,
    LayerState.UNKNOWN: Level.UNPROVEN,
}


@dataclass(frozen=True, slots=True)
class ReadinessLayer:
    """One independently observable readiness fact.

    Layers are never collapsed into a single "connected" state: a registered MCP
    entry, a verified one, an installed plugin, and a reachable service are four
    different claims and the interface has to be able to disagree with itself.
    """

    key: str
    label: str
    state: LayerState
    detail: str = ""

    @property
    def level(self) -> Level:
        return self.state.level


@dataclass(frozen=True, slots=True)
class HarnessOption:
    """One discovered agent-harness installation offered for connection."""

    executable_path: str
    reported_version: str | None
    label: str
    description: str
    recommended: bool = False
    host: str = "codex"
    config_root: str | None = None

    @property
    def version_text(self) -> str:
        return self.reported_version or "unknown version"


@dataclass(frozen=True, slots=True)
class Detection:
    """What the first-run flow found on this machine before touching anything."""

    project_root: str | None
    project_name: str | None
    is_git_repository: bool
    launched_from_subdirectory: bool
    harnesses: tuple[HarnessOption, ...] = ()
    secure_storage_available: bool = False
    # Why system secure storage is unavailable, in one fixed sentence (issue #721); empty
    # when it is available.
    secure_storage_reason: str = ""
    already_connected: bool = False
    cwd: str = ""


@dataclass(frozen=True, slots=True)
class IntegrationPlan:
    """The exact proposed project change, in the words shown before approval."""

    harness_label: str
    executable_path: str
    codex_home: str
    reported_version: str | None
    project_root: str
    # The route this plan was previewed on. It is inside ``preview_digest``, so applying on any
    # other route is refused as stale; carrying it here is what keeps preview and apply agreeing.
    route_profile: Literal["policy", "strict"]
    mcp_command: str
    mcp_server_name: str
    policy_digest: str | None
    planned_check_ids: tuple[str, ...]
    planned_file_count: int
    managed_paths: tuple[str, ...]
    state_before: str
    already_registered: bool
    foreign_entry: bool
    preview_digest: str
    skill_preview_digest: str
    activation_preview_digest: str
    activation_marketplace_path: str
    activation_config_path: str
    activation_marketplace_text: str
    activation_config_block: str
    activation_plugin_source_digest: str
    activation_inventory_verified: bool
    activation_plugin_install_path: str
    activation_plugin_install_digest: str
    activation_executable_digest: str
    activation_codex_version: str
    activation_probe_command: tuple[str, ...]
    activation_inventory_command: tuple[str, ...]
    activation_install_command: tuple[str, ...]
    activation_probe_environment: str
    activation_environment: tuple[tuple[str, str], ...]
    activation_marketplace_preimage_digest: str
    activation_config_preimage_digest: str
    activation_cache_mutation_planned: bool
    mcp_isolated_root: str | None = None
    activation_mcp_command: tuple[str, ...] = ()
    # The route the existing owned registration serves now, when known. A differing value means
    # this approval rewrites it.
    route_profile_before: Literal["policy", "strict"] | None = None
    # What the pre-rename ``yoetz`` MCP key holds (ADR-048): ``legacy_only`` is migrated to
    # ``finishup`` and ``duplicate`` removed by this approval; ``foreign`` and ``none`` are kept.
    legacy_registration: str = "none"
    # Yoetz-era activation this approval removes (ADR-048): the exact config tables, the plugin
    # cache versions, the ``.agents/plugins/yoetz`` source tree, and the project skill tree.
    activation_legacy_removed_block: str = ""
    activation_legacy_cache_versions: tuple[str, ...] = ()
    activation_legacy_plugin_tree_planned: bool = False
    legacy_skill_tree_planned: bool = False
    # Both ``.finishup/checks.toml`` and ``.yoetz/checks.toml`` exist, so neither is proposed.
    policy_ambiguous: bool = False
    # The home's FinishUP MCP registration already exists and will be written again (another
    # launcher, isolation root, review mode, or the earlier ``yoetz`` key). It is shared by every
    # project in the home.
    mcp_reregister: bool = False
    # When that rewrite changes the review mode (``route_profile_before`` differs), the other
    # connected projects of this Codex home whose sessions change with it (#1058 review P2-3).
    route_changes_for: tuple[str, ...] = ()
    # Projects that may use the home's shared pieces (not verified connections) whose sessions
    # would change too.
    route_changes_possible_for: tuple[str, ...] = ()

    @property
    def changes(self) -> tuple[str, ...]:
        """Plain-language additions, in the order they are applied."""

        lines = [
            "Install the FinishUP project skill",
            "Install managed FinishUP plugin and hook sources",
            f"Register MCP server: {self.mcp_command}",
            "Allow bounded structural event recording for this project",
        ]
        if self.policy_digest is not None:
            lines.append(f"Trust the exact approved-check policy digest: {self.policy_digest}")
        return tuple(lines)

    @property
    def replacements(self) -> tuple[str, ...]:
        """Existing entries this approval rewrites or removes, so approval covers all of it."""

        lines: list[str] = []
        if self.route_profile_before is not None and self.route_profile_before != (
            self.route_profile
        ):
            lines.append(
                "Change the existing MCP registration's review route: "
                f"{self.route_profile_before} -> {self.route_profile}"
            )
        if self.legacy_registration == "legacy_only":
            lines.append("Move the MCP registration from the earlier name yoetz to finishup")
        elif self.legacy_registration == "duplicate":
            lines.append("Remove the duplicate MCP registration under the earlier name yoetz")
        if self.activation_legacy_removed_block:
            lines.append("Remove the earlier Yoetz plugin activation from the Codex config")
        if self.activation_legacy_cache_versions:
            lines.append(
                "Delete earlier Yoetz plugin cache versions: "
                + ", ".join(self.activation_legacy_cache_versions)
            )
        if self.legacy_skill_tree_planned:
            lines.append("Delete the earlier Yoetz project skill (.agents/skills/yoetz)")
        if self.activation_legacy_plugin_tree_planned:
            lines.append(
                "Delete the earlier Yoetz plugin sources (.agents/plugins/yoetz), last, once "
                "nothing activated here reads them"
            )
        return tuple(lines)


@dataclass(frozen=True, slots=True)
class IntegrationOutcome:
    """Result of applying an integration plan, layer by layer."""

    outcome: str
    reason: str | None
    layers: tuple[ReadinessLayer, ...]
    foreign_entry: bool = False
    existing_entry_detail: str = ""


class StorageChoice(Enum):
    """How the local vault unlocks."""

    SYSTEM_KEYRING = "system_keyring"
    PASSPHRASE = "passphrase"


@dataclass(frozen=True, slots=True)
class VaultPosture:
    """Read-only view of the local service and its vault."""

    reachable: bool
    state: str | None
    vault_mode: str | None

    @property
    def ready(self) -> bool:
        return self.reachable and self.state == "ready"


class PrivacyChoice(Enum):
    """Friendly names for the durable privacy profiles."""

    LOCAL_ONLY = "local_only"
    CONFIRM_EVERY_REQUEST = "confirm_every_request"
    MINIMAL_EXTERNAL = "minimal_external"
    TRUSTED_PROVIDER = "trusted_provider"

    @property
    def label(self) -> str:
        return _PRIVACY_LABELS[self]

    @property
    def description(self) -> str:
        return _PRIVACY_DESCRIPTIONS[self]


_PRIVACY_LABELS: Final[dict[PrivacyChoice, str]] = {
    PrivacyChoice.LOCAL_ONLY: "Local only",
    PrivacyChoice.CONFIRM_EVERY_REQUEST: "Ask every time",
    PrivacyChoice.MINIMAL_EXTERNAL: "Minimal external review",
    PrivacyChoice.TRUSTED_PROVIDER: "Trusted provider",
}

_PRIVACY_DESCRIPTIONS: Final[dict[PrivacyChoice, str]] = {
    PrivacyChoice.LOCAL_ONLY: "No work is sent for AI-powered review. This is the default.",
    PrivacyChoice.CONFIRM_EVERY_REQUEST: "FinishUP asks before anything is sent, every time.",
    PrivacyChoice.MINIMAL_EXTERNAL: "Structural summaries only; no prose and no excerpts.",
    PrivacyChoice.TRUSTED_PROVIDER: "The widest review this provider binding allows.",
}


# The recipe vocabulary is the CLI's, verbatim. A user who reads about "Metadata only" in
# `finishup privacy setup` must find the same name here; two names for one policy is how people
# end up believing they configured something they did not.
PRIVACY_RECIPES: Final[tuple[tuple[str, str, str], ...]] = (
    ("private", "Private", "No work is sent for AI-powered review. This is the default."),
    (
        "metadata_only",
        "Metadata only",
        "Structural metadata and declared file types only, and FinishUP asks before every request.",
    ),
    (
        "assisted_review",
        "Assisted review",
        "Bounded excerpts for problem-specific feedback; needs eligible provider data-use "
        "evidence.",
    ),
    (
        "expanded_review",
        "Expanded review",
        "The most reviewer context this provider binding allows, including broader excerpts.",
    ),
    ("custom", "Custom", "Configure each privacy setting yourself, in five sections."),
)

_PRIVACY_RECIPE_LABELS: Final[dict[str, str]] = {
    recipe: label for recipe, label, _description in PRIVACY_RECIPES
}


@dataclass(frozen=True, slots=True)
class PrivacyRecommendation:
    """The one recommended posture, with what it costs stated next to what it buys."""

    recipe: str
    reason: str
    tradeoff: str

    @property
    def label(self) -> str:
        return _PRIVACY_RECIPE_LABELS.get(self.recipe, self.recipe)


@dataclass(frozen=True, slots=True)
class PrivacyPosture:
    """Current effective privacy policy as the service reports it."""

    profile: str | None
    llm_inference_enabled: bool | None
    readable: bool
    # Whether the composed policy sends the task statement, and the ``privacy show`` sentence that
    # says so (issue #908). ``None`` when the policy document is unreadable.
    task_statement_sent: bool | None = None
    task_statement_disclosure: str | None = None
    never_send: tuple[str, ...] = ()
    enabled_channels: tuple[str, ...] = ()
    network_egress_permitted: bool | None = None
    repository_grant_state: Literal["granted", "missing"] | None = None
    repository_migration_state: str | None = None
    # True when the approved review selection is an earlier version of its recipe (for example
    # Expanded before privacy policy 1.2.0); the newer one needs its own approval (issue #907).
    recipe_outdated: bool = False
    # The external reviewer's possible-credential filter pair (``repository``,
    # ``machine_default``) from the repository setup read, the same derivation status shows
    # (issue #982); ``None`` when it could not be read.
    credential_heuristic: tuple[str, str] | None = None
    # The owner's conversation setting the composed policy means (ADR-049): the explicit token,
    # or the released reading of a policy that predates it; ``None`` when unreadable.
    conversation_review: str | None = None
    # Whether the owner chose that setting; a released ``local_only`` says nothing is set up.
    conversation_review_explicit: bool = True

    @property
    def conversation_review_summary(self) -> str | None:
        """How tasks use AI-powered review, in the shared wording, with the changing command."""

        from finishup.cli.render import conversation_setting_text

        return (
            conversation_setting_text(
                self.conversation_review,
                explicit=self.conversation_review_explicit,
                grant_missing=self.repository_grant_state == "missing",
                migration_pending=self.repository_migration_state
                in {"legacy_route_available", "first_repository_available"},
            )
            or None
        )

    @property
    def credential_heuristic_disabled(self) -> bool:
        return self.credential_heuristic is not None and self.credential_heuristic[0] == "disabled"

    @property
    def credential_heuristic_summary(self) -> str | None:
        """The shared sentence, shown when anything is off or unknown."""

        from finishup.cli.render import credential_heuristic_line

        if self.credential_heuristic is None or self.credential_heuristic == (
            "enforced",
            "enforced",
        ):
            return None
        return credential_heuristic_line(*self.credential_heuristic)

    @property
    def choice(self) -> PrivacyChoice | None:
        try:
            return PrivacyChoice(self.profile)
        except ValueError:
            return None

    @property
    def summary(self) -> str:
        if not self.readable:
            return "unknown"
        choice = self.choice
        return choice.label.lower() if choice is not None else (self.profile or "unknown")

    @property
    def update_checks_permitted(self) -> bool:
        """True when durable policy admits structural package update checks."""

        if not self.readable or self.network_egress_permitted is not True:
            return False
        return "update_checks" in self.enabled_channels

    @property
    def repository_authority_summary(self) -> str:
        if self.repository_grant_state == "granted":
            return "granted for this repository"
        if self.repository_grant_state == "missing":
            return "missing; external review is off for this repository"
        return "unknown; repository authority could not be read"

    @property
    def repository_migration_summary(self) -> str | None:
        if self.repository_migration_state is None:
            return None
        return {
            "legacy_route_available": (
                "Previously accepted permission can be narrowed to this known repository without "
                "reapproval or broader disclosure."
            ),
            "first_repository_available": (
                "Previously accepted permission can be carried forward once to this first "
                "repository without reapproval or broader disclosure."
            ),
            "consumed": (
                "Existing permission was carried forward and narrowed to this repository; no new "
                "disclosure was approved."
            ),
        }.get(self.repository_migration_state)


@dataclass(frozen=True, slots=True)
class ProviderOption:
    """One reviewed provider preset, or the owner-declared endpoint escape hatch."""

    choice: str
    label: str
    provider_id: str
    host: str
    base_path_prefix: str
    default_model: str
    api_style: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    requires_origin: bool = False

    @property
    def endpoint_text(self) -> str:
        if self.requires_origin:
            return "your declared HTTPS origin"
        return f"https://{self.host}{self.base_path_prefix}"


@dataclass(frozen=True, slots=True)
class ProviderPosture:
    """Structural provider readiness. Never a claim about live dispatch."""

    endpoint_bound: bool
    provider_id: str | None
    model: str | None
    endpoint_profile_id: str | None
    credential_connected: bool | None
    llm_inference_enabled: bool | None
    semantic_enabled: bool
    semantic_ready: bool
    readiness_determinable: bool
    credential_authority: str | None = None
    transport_tested: bool = False
    blockers: tuple[tuple[str, str], ...] = ()
    # The Codex agent route is a separate verdict from installation readiness: a strict
    # registration ceilings AI-powered review for that process while CLI and TUI checks can still
    # dispatch. ``None`` means the registration could not be read, never that it is absent.
    agent_route_semantic_ready: bool | None = None
    registered_route_profile: str | None = None
    # True when the durable applied-route record disagrees with the live Codex registration
    # (issue #537): the serving process may be stale rather than intentionally strict.
    route_drift_since_install: bool = False
    # Each host's own project-scoped rule admitting the AI-powered check past its automatic
    # reviewer (issue #467): ``absent|present|partial|foreign|unknown`` per host. Host tool-call
    # authorization only; never a claim that a check dispatched.
    host_admission: tuple[tuple[str, str], ...] = ()
    # The effective ``[observation] semantic_advice_enabled`` switch and its closed reason
    # (issue #888). ``None`` means the report did not carry it, never that advice is on.
    background_advice_enabled: bool | None = None
    background_advice_reason: str | None = None


class CheckMode(Enum):
    """The three check modes, in the words the interface offers them."""

    SEMANTIC_IF_CONFIGURED = "semantic_if_configured"
    SEMANTIC_REQUIRED = "semantic_required"
    DETERMINISTIC_ONLY = "deterministic_only"

    @property
    def label(self) -> str:
        return _CHECK_LABELS[self]

    @property
    def description(self) -> str:
        return _CHECK_DESCRIPTIONS[self]


_CHECK_LABELS: Final[dict[CheckMode, str]] = {
    CheckMode.SEMANTIC_IF_CONFIGURED: "Use deeper review when available",
    CheckMode.SEMANTIC_REQUIRED: "Require deeper review",
    CheckMode.DETERMINISTIC_ONLY: "Local checks only",
}

_CHECK_DESCRIPTIONS: Final[dict[CheckMode, str]] = {
    CheckMode.SEMANTIC_IF_CONFIGURED: (
        "Falls back to local checks and says so when the provider is not ready."
    ),
    CheckMode.SEMANTIC_REQUIRED: "Fails honestly rather than pretending review happened.",
    CheckMode.DETERMINISTIC_ONLY: "FinishUP's local checks; sends no work for AI-powered review.",
}


@dataclass(frozen=True, slots=True)
class WorkItem:
    """One recorded task as the work picker lists it."""

    subject_id: str
    title: str
    state: str
    open_findings: int
    last_check: str
    updated: str


@dataclass(frozen=True, slots=True)
class WorkDetail:
    """One opened task, expanded into the layers a receipt would report."""

    item: WorkItem
    claims: tuple[str, ...] = ()
    evidence_count: int | None = 0
    checks: tuple[str, ...] = ()
    coverage: tuple[str, ...] = ()
    findings: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    receipt_available: bool = False
    # The service's closure checklist lines and state token (issue #913). ``ready`` and
    # ``ready_with_limitations`` mean "nothing further to do", never "verified".
    closure: tuple[str, ...] = ()
    closure_state: str | None = None


@dataclass(frozen=True, slots=True)
class TaskStatusPage:
    """A bounded service-rendered task view and its opaque continuation."""

    lines: tuple[str, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class ReceiptSummary:
    """The human-readable foreground of one receipt."""

    subject_id: str
    verdict: str
    coverage: tuple[str, ...] = ()
    open_findings: int = 0
    limitations: tuple[str, ...] = ()
    semantic_available: bool = False
    freshness: str = "unknown"
    verified: tuple[str, ...] = ()
    not_verified: tuple[str, ...] = ()
    rendered_lines: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DoctorEntry:
    """One bounded diagnostic observation and its safe remediation."""

    key: str
    label: str
    state: LayerState
    detail: str = ""
    remediation: str = ""


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """A read-only diagnosis. Running it never mutates installation state."""

    entries: tuple[DoctorEntry, ...] = field(default_factory=tuple)

    @property
    def blocked(self) -> tuple[DoctorEntry, ...]:
        return tuple(entry for entry in self.entries if entry.state is LayerState.BLOCKED)


@dataclass(frozen=True, slots=True)
class StatusSnapshot:
    """Everything ``/status`` reports, with each layer still separable."""

    project_root: str
    layers: tuple[ReadinessLayer, ...]
    privacy: PrivacyPosture
    open_work: int
    open_findings: int
    work_readable: bool = True

    def layer(self, key: str) -> ReadinessLayer | None:
        for entry in self.layers:
            if entry.key == key:
                return entry
        return None
