"""Codex app-server AI-powered evaluator with Codex-owned ChatGPT OAuth.

The adapter never opens or names Codex credential files.  It launches one capability-checked
native Codex executable (any stable release at or above the floor whose retained bytes passed the
check recorded beside them, ADR-006) with a dedicated owner-private ``CODEX_HOME``, performs
structural readiness over the documented v2 JSONL protocol, discloses only the already-approved
case, and terminates only the process group it spawned.  Codex remains the OAuth and
upstream-request authority; FinishUP records that the upstream OpenAI body is unavailable to it.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import tempfile
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast
from urllib.parse import urlsplit

from finishup.adapters.providers.codex_capability import (
    CODEX_CODE_MODE_HOST_NAME,
    CODEX_EVALUATOR_CAPABILITY_PROFILE,
    CODEX_EVALUATOR_RUNTIME_FLOOR,
    CODEX_PROBE_CLEANUP_UNCONFIRMED,
    CodexCapabilityRecord,
    CodexPlatform,
    codex_bundled_model_catalog,
    codex_version_key,
    host_codex_platform,
    read_capability_record,
    validate_capability_binding,
)
from finishup.adapters.providers.codex_reviewer_catalog import (
    REVIEWER_CATALOG_MODEL,
    REVIEWER_CATALOG_RUNTIME_VERSIONS,
    ReviewerCatalogDecision,
    bundled_entry_sha256,
    packaged_reviewer_catalog_path,
    resolve_reviewer_catalog,
)
from finishup.adapters.providers.data_use_catalog import data_use_record_for_endpoint
from finishup.adapters.providers.openai_responses import (
    SEMANTIC_REVIEW_INSTRUCTION,
    STRICT_JUDGMENT_JSON_SCHEMA,
    JudgmentValidationError,
    normalize_judgment,
)
from finishup.adapters.providers.reviewer_cache_telemetry import record_exchange_cache
from finishup.adapters.providers.reviewer_reply import REVIEWER_REPLY_SCHEMAS
from finishup.adapters.reviewer_artifacts import image_message
from finishup.config.models import (
    CODEX_FINAL_OUTPUT_LIMIT_DEFAULT,
    CODEX_OUTPUT_LIMIT_MAX,
    CODEX_ROUTINE_OUTPUT_LIMIT_DEFAULT,
    ExternalRuntimeProfileConfig,
)
from finishup.config.paths import ensure_owner_only_dir, verify_private_local_bundle
from finishup.domain.findings import (
    RUNTIME_FAILURE_STAGES,
    RuntimeAttemptEvidence,
    RuntimeTokenUsage,
    SamplingParams,
    SemanticFailureClass,
)
from finishup.domain.privacy import (
    ApprovedOutboundCase,
    ApprovedProviderCase,
    ProviderBinding,
    ProviderDataUseProfile,
    RequestCommitment,
)
from finishup.domain.reviewer_cache import ExchangeCacheUsage
from finishup.observability.logging import (
    record_bounded_counts_without_raising,
    record_bounded_event_without_raising,
)
from finishup.observability.semantic_context import report_semantic_progress
from finishup.ports.clock import ClockPort
from finishup.ports.secret_memory import ProviderAttemptAuthBinding
from finishup.ports.semantic import (
    CURRENT_REVIEWER_SESSION,
    Deadline,
    ExternalRuntimeAuthority,
    ProviderAttemptProvenance,
    ReviewerMessage,
    ReviewerReplySchemas,
    ReviewerSession,
    SemanticEvaluatorPort,
    SemanticResult,
    SemanticResultInvalid,
    SemanticResultRefused,
    SemanticResultReply,
    SemanticResultSuccess,
    SemanticResultTimeout,
    SemanticResultUnavailable,
    reviewer_exchange,
)
from finishup.ports.semantic_budget import (
    LEGACY_SEMANTIC_BUDGET_PROFILE,
    SEMANTIC_BUDGET_PROFILES,
    SemanticBudgetProfile,
    current_semantic_background,
    current_semantic_budget_profile,
)
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.models import SemanticProgressPhase, SemanticStatus

__all__ = [
    "CODEX_BACKGROUND_ADVICE_EFFORT",
    "CODEX_CODE_MODE_HOST_NAME",
    "CODEX_EVALUATOR_CAPABILITY_PROFILE",
    "CODEX_EVALUATOR_CONFIG",
    "CODEX_EVALUATOR_CONFIG_SHA256",
    "CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT",
    "CODEX_EVALUATOR_RUNTIME_FLOOR",
    "CodexAppServerExternalFactory",
    "CodexAppServerProfile",
    "CodexLoginChallenge",
    "CodexReviewBudget",
    "CodexRuntimeStatus",
    "codex_account_status",
    "codex_model_listed",
    "codex_binding_from_config",
    "codex_capability_probe",
    "codex_code_mode_host_path",
    "codex_factory_builders_from_config",
    "codex_login",
    "codex_logout",
    "prepare_codex_home",
]

CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT: Final = "2026-11-30T00:00:00Z"
_CAPABILITY_EVIDENCE_EXPIRES_AT: Final = datetime(2026, 11, 30, tzinfo=UTC)
CODEX_EVALUATOR_CONFIG: Final = """approval_policy = "never"
cli_auth_credentials_store = "file"
forced_login_method = "chatgpt"
model_provider = "openai"
project_doc_max_bytes = 0
sandbox_mode = "read-only"
web_search = "disabled"

[analytics]
enabled = false

[otel]
environment = "none"

[features]
apps = false
browser_use = false
browser_use_external = false
browser_use_full_cdp_access = false
computer_use = false
hooks = false
image_generation = false
in_app_browser = false
memories = false
multi_agent = false
plugins = false
recommended_plugins = false
remote_plugin = false
shell_snapshot = false
shell_tool = false
skill_mcp_dependency_install = false
skill_search = false
standalone_web_search = false
tool_suggest = false
view_image = false
workspace_dependencies = false

[tools.experimental_request_user_input]
enabled = false

[tools.update_plan]
enabled = false
"""

_CONFIG_SHA256: Final = "sha256:" + hashlib.sha256(CODEX_EVALUATOR_CONFIG.encode()).hexdigest()
CODEX_EVALUATOR_CONFIG_SHA256: Final = _CONFIG_SHA256
_INSTRUCTION_SHA256: Final = (
    "sha256:" + hashlib.sha256(SEMANTIC_REVIEW_INSTRUCTION.encode()).hexdigest()
)


def codex_code_mode_host_path(executable: Path) -> Path:
    """The code-mode host Codex starts from beside ``executable``; the only location checked."""

    return executable.parent / CODEX_CODE_MODE_HOST_NAME


def _validate_binding_fields(
    *,
    source_identity: str,
    executable_sha256: str,
    runtime_version: str,
    app_server_schema_sha256: str,
    capability_cell_sha256: str,
    capability_profile: str,
    capability_evidence_expires_at: str,
    isolated_config_sha256: str,
) -> CodexPlatform:
    return validate_capability_binding(
        source_identity=source_identity,
        executable_sha256=executable_sha256,
        runtime_version=runtime_version,
        app_server_schema_sha256=app_server_schema_sha256,
        capability_cell_sha256=capability_cell_sha256,
        capability_profile=capability_profile,
        capability_evidence_expires_at=capability_evidence_expires_at,
        isolated_config_sha256=isolated_config_sha256,
        expected_isolated_config_sha256=_CONFIG_SHA256,
        expected_evidence_expires_at=CODEX_EVALUATOR_EVIDENCE_EXPIRES_AT,
    )


def _codex_output_schema(value: JsonValue) -> JsonValue:
    """Remove only constraints the Codex structured-output path rejects.

    The admitted Codex runtime forwards this schema to the Responses structured-output boundary,
    which rejected ``uniqueItems`` when observed on 0.150.1; the omission is kept for every
    admitted release.
    Domain normalization still enforces uniqueness after generation, so omitting that
    provider-side keyword weakens no accepted FinishUP judgment.
    """

    if type(value) is dict:
        return {
            key: _codex_output_schema(item)
            for key, item in cast(dict[str, JsonValue], value).items()
            if key != "uniqueItems"
        }
    if type(value) is list:
        return [_codex_output_schema(item) for item in cast(list[JsonValue], value)]
    return value


_CODEX_JUDGMENT_JSON_SCHEMA: Final = cast(
    dict[str, JsonValue], _codex_output_schema(cast(JsonValue, STRICT_JUDGMENT_JSON_SCHEMA))
)
_MAX_MESSAGE_BYTES: Final = 1_048_576
# Request and pre-disclosure queues retain their count bound. Active turns instead spend a byte
# and work budget: discarded telemetry/deltas do not consume a useful-event allowance (#1141).
_MAX_EVENT_COUNT: Final = 4096
_MAX_TURN_EVENT_WORK: Final = 32 * 1024 * 1024
_MIN_EVENT_WORK: Final = 256
_EFFORT_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}$", re.ASCII)
# Default effort for background observation advice when no routine effort is configured (#888).
CODEX_BACKGROUND_ADVICE_EFFORT: Final = "low"
_EFFORT_ORDER: Final[tuple[str, ...]] = ("none", "minimal", "low", "medium", "high", "xhigh")


def _lower_effort(configured: str, ceiling: str) -> str:
    """Return ``ceiling`` only when both are known efforts and it is strictly lower."""

    if configured in _EFFORT_ORDER and ceiling in _EFFORT_ORDER:
        if _EFFORT_ORDER.index(ceiling) < _EFFORT_ORDER.index(configured):
            return ceiling
    return configured


_MAX_STDERR_BYTES: Final = 65_536
_CLEANUP_GRACE_SECONDS: Final = 2.0
# The AI-powered evaluator's request deadline is carried by ``Deadline`` and is intentionally
# unrelated to the interactive login ceremony.  Keep this legacy name for callers/tests that
# imported it while giving each native Codex login method its full supported window.
_LOGIN_TIMEOUT_SECONDS: Final = 300.0
_LOGIN_TIMEOUT_SECONDS_BY_MODE: Final = {
    "browser": 600.0,
    "device_code": 900.0,
}
_LOGIN_TERMINAL_GRACE_SECONDS: Final = 2.0
_LOGIN_CANCEL_TIMEOUT_SECONDS: Final = 1.0
_LOGIN_READINESS_GRACE_SECONDS: Final = 2.0
_PLAN_TYPE_PATTERN: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)
_SAFE_PLAN_TYPES: Final = frozenset(
    {
        "business",
        "edu",
        "edu_plus",
        "edu_pro",
        "enterprise",
        "enterprise_cbp_automation",
        "enterprise_cbp_usage_based",
        "ent26",
        "free",
        "go",
        "plus",
        "pro",
        "prolite",
        "promax",
        "self_serve_business_prolite",
        "self_serve_business_usage_based",
        "team",
        "unknown",
    }
)
# Items a read-only, tool-less turn may legitimately produce. ``plan`` is the model's own
# checklist and ``contextCompaction`` is Codex re-summarizing its context; neither executes
# anything or touches the workspace. Every command, patch, MCP, web, image, or agent tool item
# stays forbidden and terminates the turn.
_ALLOWED_ITEM_TYPES: Final = frozenset(
    {"agentMessage", "contextCompaction", "plan", "reasoning", "userMessage"}
)
_AGENT_MESSAGE_PHASES: Final = frozenset({"commentary", "final_answer", "partial_answer"})
# Interim narration and stable-but-unfinished answer text (``partial_answer``, Codex 0.162.1) are
# never judgment candidates; they are discarded unread.
_NON_FINAL_PHASES: Final = frozenset({"commentary", "partial_answer"})
# Informational notifications are validated for method only and discarded unread; none of them
# authorizes anything, and none of their bodies is retained. ``model/rerouted`` is the one
# informational event that changes the answer's provenance, so it is handled explicitly.
# ``thread/settings/updated`` (Codex 0.162.1, experimental) echoes the thread's effective
# settings after a ``turn/start`` applies its overrides (``effort``, ``summary``, ...); the
# app-server sends it whenever the snapshot differs from the last one it reported, so the first
# turn on every thread produces it (``codex-rs/app-server/src/bespoke_event_handling.rs``
# ``ThreadSettingsApplied``; ``thread_state.rs`` ``note_thread_settings``). It is bookkeeping
# about settings FinishUP itself sent, never a tool, plan or item event.
# ``model/verification`` (Codex 0.162.1) relays an account-verification recommendation the
# upstream response carried in its metadata (``codex-api/src/sse/responses.rs``
# ``openai_verification_recommendation``; ``bespoke_event_handling.rs``). It needs no tool or
# environment, so a healthy reviewer turn can carry it; the same bound model still answers (a
# changed model is ``model/rerouted``, refused below), and the notification adds no input, tool,
# or authority. It is bookkeeping about the owner's account, discarded unread (#1118 V2). Every
# other 0.162.1 notification outside this set is unreachable under the reviewer's isolated
# configuration or a real capability, and stays refused as ``event_forbidden``.
_ALLOWED_NOTIFICATION_METHODS: Final = frozenset(
    {
        "account/updated",
        "account/rateLimits/updated",
        "configWarning",
        "deprecationNotice",
        "error",
        "item/agentMessage/delta",
        "item/completed",
        "item/plan/delta",
        "item/reasoning/summaryPartAdded",
        "item/reasoning/summaryTextDelta",
        "item/reasoning/textDelta",
        "item/started",
        "model/rerouted",
        "model/safetyBuffering/updated",
        "model/verification",
        "thread/compacted",
        "thread/name/updated",
        "thread/queue/changed",
        "thread/settings/updated",
        "thread/started",
        "thread/status/changed",
        "thread/tokenUsage/updated",
        "turn/completed",
        "turn/moderationMetadata",
        "turn/plan/updated",
        "turn/started",
        "warning",
    }
)
# The request id of the barrier that closes the pre-disclosure window (after ``thread/start``
# 30 and before ``turn/start`` 31 in an attempt; after ``model/list`` in a readiness probe).
_PREDISCLOSURE_BARRIER_REQUEST_ID: Final = 32
_PREDISCLOSURE_NOTIFICATION_METHODS: Final = frozenset(
    {
        "account/updated",
        "account/rateLimits/updated",
        "remoteControl/status/changed",
        "configWarning",
        "thread/started",
        "thread/status/changed",
        "warning",
    }
)
# The two native configuration warnings admitted before disclosure (ADR-006, 2026-10-14). Codex
# 0.162.1 on Linux writes at most one of them at app-server start
# (``codex-rs/sandboxing/src/bwrap.rs`` ``system_bwrap_warning_for_path``):
# - ``USER_NAMESPACE_WARNING``: a system bubblewrap exists but cannot create user namespaces
#   (Docker's default seccomp, gVisor, kernels without unprivileged user namespaces);
# - ``MISSING_BWRAP_WARNING``: no system ``bwrap`` is on ``PATH`` (an official task container
#   without the distribution ``bubblewrap`` package). Codex then attempts its bundled
#   bubblewrap when that resource is present; FinishUP does not retain it (#874), and the warning
#   proves neither a usable sandbox nor user-namespace access, so the sandbox is unverified.
# The evaluator's isolated config exposes no tool that bubblewrap would confine:
# ``features.shell_tool=false`` removes command execution, ``read-only`` with
# ``approval_policy=never`` rejects every patch before it runs, and no MCP server, plugin, app or
# agent is enabled. Either warning therefore widens nothing a review can do; each is admitted only
# with this exact closed shape and recorded as ``codex_sandbox_unavailable`` with its reason. Every
# other ``configWarning`` (including the WSL1 one) stays forbidden.
SandboxUnavailableReason = Literal["user_namespaces_unavailable", "bubblewrap_missing"]
_SANDBOX_UNAVAILABLE_SUMMARY: Final = (
    "Codex's Linux sandbox uses bubblewrap and needs access to create user namespaces."
)
_MISSING_BWRAP_SUMMARY: Final = (
    "Codex could not find bubblewrap on PATH. Install bubblewrap with your OS package manager. "
    "See the sandbox prerequisites: "
    "https://developers.openai.com/codex/concepts/sandboxing#prerequisites. "
    "Codex will use the bundled bubblewrap in the meantime."
)
_SANDBOX_WARNING_REASONS: Final[Mapping[str, SandboxUnavailableReason]] = {
    _SANDBOX_UNAVAILABLE_SUMMARY: "user_namespaces_unavailable",
    _MISSING_BWRAP_SUMMARY: "bubblewrap_missing",
}
# That reasoning was verified against one release's source; no app-server method exposes the
# effective tool registry or patch-approval semantics without a model call, so it cannot be proven
# at runtime. The admission is therefore bound to the releases whose source was reviewed (the
# release ``initialize`` proved). Any other release sending either warning fails closed with
# ``codex_sandbox_unavailable_unreviewed_runtime``; selection then falls back to an older
# reviewed release when one is installed. Extend this set only after re-reviewing the source.
# 0.164.0 (#1228): both warning texts are unchanged. With ``environments: []`` it now advertises
# the catalog's ``apply_patch`` (0.162.1 hid environment tools without an environment), but the
# handler resolves a turn environment first and fails without one, and ``read-only`` with
# ``approval_policy=never`` still refuses the patch (``core/src/tools/handlers/apply_patch.rs``).
SANDBOX_UNAVAILABLE_REVIEWED_RELEASES: Final = frozenset({"0.162.1", "0.164.0"})
_LAUNCH_OVERRIDES: Final = (
    "analytics.enabled=false",
    'approval_policy="never"',
    "features.apps=false",
    "features.hooks=false",
    "features.memories=false",
    "features.multi_agent=false",
    "features.plugins=false",
    "features.shell_tool=false",
    'forced_login_method="chatgpt"',
    'model_provider="openai"',
    'otel.environment="none"',
    'sandbox_mode="read-only"',
    "tools.experimental_request_user_input.enabled=false",
    "tools.update_plan.enabled=false",
    'web_search="disabled"',
)
# Supported keys that remove further built-in tools, bound to the release whose source defined
# and was reviewed for them (``--strict-config`` refuses a key an older release does not know).
# Codex 0.162.1 registers these from the model catalog or a default-on feature even with
# ``environments: []`` (``codex-rs/core/src/tools/spec_plan.rs``, #1118):
# - ``agents.enabled=false``: a catalog ``multi_agent_version`` (``v2`` for gpt-6.1-sol) overrides
#   ``features.multi_agent=false``; only this key disables the collaboration tools
#   (``core/src/config/mod.rs`` ``multi_agent_version_override``);
# - ``features.goals=false``: the default-on goal tools (``get_goal``/``create_goal``/
#   ``update_goal``) and their ``thread/goal/*`` notifications;
# - ``features.sleep_tool=false``: the default-on ``sleep`` tool a catalog ``clock`` entry exposes;
# - ``skills.include_instructions=false``: no skills catalog text in the model's context.
# Not removable by any ordinary key on 0.162.1: a catalog ``tool_mode="code_mode_only"`` forces
# the code-mode ``exec``/``wait`` tools, and the catalog's ``send_user_message_async`` and
# ``clock`` entries force ``request_user_input_async`` and ``clock.curr_time``. When every pin
# holds, the launch replaces the catalog with FinishUP's derived one through the supported
# ``model_catalog_json`` key (``codex_reviewer_catalog``), which removes exactly those three
# fields. Otherwise they stay registered; their items are not admitted, so a call ends the turn.
_RELEASE_LAUNCH_OVERRIDES: Final[Mapping[str, tuple[str, ...]]] = {
    "0.162.1": (
        "agents.enabled=false",
        "features.goals=false",
        "features.sleep_tool=false",
        "skills.include_instructions=false",
    ),
    # 0.164.0 (#1228): the same four keys, each still defined and still removing its tools.
    "0.164.0": (
        "agents.enabled=false",
        "features.goals=false",
        "features.sleep_tool=false",
        "skills.include_instructions=false",
    ),
}
# The bundled reviewer-model entry digest the fence last measured from a launched executable,
# keyed by that executable's SHA-256 (the bundled catalog is compiled into those bytes). Every
# launch of the pinned release and model re-measures it (about 20 ms) before the argv is built.
_BUNDLED_ENTRY_SHA256: dict[str, str | None] = {}
# Fallback reasons already written to the owner-only diagnostics in this process, so a release
# that never gets the catalog records its reason once rather than on every launch.
_RECORDED_CATALOG_FALLBACKS: set[tuple[str, str, str]] = set()
# Releases whose multi-turn reviewer session was reviewed from source (#1118 unit 3); any other
# refuses a reviewer exchange (never falls back). Extend only after a capability cell.
# 0.164.0 (#1228): the app-server schema subset digest equals 0.162.1's; its one new
# notification (``thread/readState/changed``) is never published for an ephemeral thread.
REVIEWER_LOOP_REVIEWED_RELEASES: Final = frozenset({"0.162.1", "0.164.0"})
# A reviewer turn may produce only these items: a plan or a context compaction would replace or
# extend the known linear history with something FinishUP never inspected, so either ends it.
_REVIEWER_ITEM_TYPES: Final = frozenset({"agentMessage", "reasoning", "userMessage"})
_REVIEWER_FORBIDDEN_METHODS: Final = frozenset(
    {"item/plan/delta", "thread/compacted", "turn/plan/updated"}
)


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _object(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("codex_app_server_message_invalid")
    return cast(Mapping[str, object], value)


@dataclass(frozen=True, slots=True)
class CodexRuntimeStatus:
    """Nonsecret readiness returned by structural app-server probes."""

    runtime_ready: bool
    auth_mode: Literal["chatgpt"] | None
    plan_type: str | None
    model_available: bool
    cleanup: Literal["not_started", "terminated", "killed", "failed"]
    # Codex reported (only through an admitted closed warning) that its Linux sandbox cannot
    # create user namespaces, or that no system bubblewrap is installed so the sandbox is
    # unverified. It confines no evaluator tool; it is surfaced with its reason, not refused.
    sandbox_unavailable: bool = False
    sandbox_unavailable_reason: SandboxUnavailableReason | None = None


@dataclass(frozen=True, slots=True)
class CodexLoginChallenge:
    """Transient Codex-owned login UI values; never persisted by FinishUP."""

    mode: Literal["browser", "device_code"]
    url: str
    user_code: str | None


@dataclass(frozen=True, slots=True)
class CodexReviewBudget:
    """The exact per-check effort and output limit selected for one review profile.

    ``output_limit`` counts output tokens. The admitted app-server protocol has no per-turn output
    ceiling, so FinishUP enforces it against the runtime's reported visible (non-reasoning) output
    tokens and records it as ``sampling_params.max_output_tokens``.
    """

    budget_profile: SemanticBudgetProfile
    reasoning_effort: str
    output_limit: int

    def __post_init__(self) -> None:
        if self.budget_profile not in SEMANTIC_BUDGET_PROFILES:
            raise ValueError("codex_budget_profile_invalid")
        if (
            type(self.reasoning_effort) is not str
            or _EFFORT_PATTERN.fullmatch(self.reasoning_effort) is None
        ):
            raise ValueError("codex_runtime_effort_invalid")
        if type(self.output_limit) is not int or not 1 <= self.output_limit <= (
            CODEX_OUTPUT_LIMIT_MAX
        ):
            raise ValueError("codex_runtime_output_limit_invalid")

    def selection_sha256(self, model: str) -> str:
        """Commit to the exact model, effort, output limit, and profile of one attempt."""

        return canonical_digest(
            {
                "budget_profile": self.budget_profile,
                "model": model,
                "output_limit": self.output_limit,
                "reasoning_effort": self.reasoning_effort,
            }
        )


@dataclass(frozen=True, slots=True)
class CodexAppServerProfile:
    provider_id: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    executable_path: Path
    executable_sha256: str
    runtime_version: str
    source_identity: str
    app_server_schema_sha256: str
    capability_cell_sha256: str
    capability_profile: str
    capability_evidence_expires_at: str
    codex_home: Path
    isolated_config_sha256: str
    model: str
    reasoning_effort: str
    timeout_seconds: int
    data_use_profile: ProviderDataUseProfile
    routine_reasoning_effort: str | None = None
    routine_output_limit: int = CODEX_ROUTINE_OUTPUT_LIMIT_DEFAULT
    final_output_limit: int = CODEX_FINAL_OUTPUT_LIMIT_DEFAULT
    # The record a capability check is about to commit. It is held in memory only while that
    # check probes the candidate; every persisted binding reads its record from the retained
    # store, beside the executable, at each launch.
    capability_record: CodexCapabilityRecord | None = None

    @classmethod
    def from_config(cls, config: ExternalRuntimeProfileConfig) -> CodexAppServerProfile:
        if type(config) is not ExternalRuntimeProfileConfig:
            raise TypeError("codex_runtime_config_invalid")
        return cls(
            provider_id=config.provider_id,
            endpoint_profile_id=config.endpoint_profile_id,
            endpoint_profile_version=config.endpoint_profile_version,
            executable_path=Path(config.executable_path),
            executable_sha256=config.executable_sha256,
            runtime_version=config.runtime_version,
            source_identity=config.source_identity,
            app_server_schema_sha256=config.app_server_schema_sha256,
            capability_cell_sha256=config.capability_cell_sha256,
            capability_profile=config.capability_profile,
            capability_evidence_expires_at=config.capability_evidence_expires_at,
            codex_home=Path(config.codex_home),
            isolated_config_sha256=config.isolated_config_sha256,
            model=config.model,
            reasoning_effort=config.reasoning_effort,
            timeout_seconds=config.timeout_seconds,
            data_use_profile=data_use_record_for_endpoint(config.endpoint_profile_id).profile,
            routine_reasoning_effort=config.routine_reasoning_effort,
            routine_output_limit=config.routine_output_limit,
            final_output_limit=config.final_output_limit,
        )

    def __post_init__(self) -> None:
        _validate_binding_fields(
            source_identity=self.source_identity,
            executable_sha256=self.executable_sha256,
            runtime_version=self.runtime_version,
            app_server_schema_sha256=self.app_server_schema_sha256,
            capability_cell_sha256=self.capability_cell_sha256,
            capability_profile=self.capability_profile,
            capability_evidence_expires_at=self.capability_evidence_expires_at,
            isolated_config_sha256=self.isolated_config_sha256,
        )
        if self.capability_record is not None and not self._record_matches(self.capability_record):
            raise ValueError("codex_runtime_capability_record_invalid")
        if not self.executable_path.is_absolute() or not self.codex_home.is_absolute():
            raise ValueError("codex_runtime_path_invalid")
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 3600:
            raise ValueError("codex_runtime_timeout_invalid")
        if type(self.data_use_profile) is not ProviderDataUseProfile:
            raise ValueError("codex_runtime_data_use_invalid")
        for effort in (self.reasoning_effort, self.routine_reasoning_effort):
            if effort is not None and (
                type(effort) is not str or _EFFORT_PATTERN.fullmatch(effort) is None
            ):
                raise ValueError("codex_runtime_effort_invalid")
        for limit in (self.routine_output_limit, self.final_output_limit):
            if type(limit) is not int or not 1 <= limit <= CODEX_OUTPUT_LIMIT_MAX:
                raise ValueError("codex_runtime_output_limit_invalid")

    def review_budget(
        self, budget_profile: SemanticBudgetProfile, *, background: bool = False
    ) -> CodexReviewBudget:
        """Select the exact effort and output limit for one check's budget profile.

        Final reviews use the configured ``reasoning_effort``. Routine reviews use the explicit
        routine effort when the owner set one; a legacy binding without it keeps its single
        configured effort for explicit checks, so no persisted check choice is silently lowered.
        Background observation advice (#888) is advisory only: without an owner routine effort
        it uses ``CODEX_BACKGROUND_ADVICE_EFFORT`` when that is lower than the configured one.
        """

        if budget_profile == "final":
            return CodexReviewBudget("final", self.reasoning_effort, self.final_output_limit)
        if budget_profile == "routine":
            effort = (
                self.reasoning_effort
                if self.routine_reasoning_effort is None
                else self.routine_reasoning_effort
            )
            if background and self.routine_reasoning_effort is None:
                effort = _lower_effort(effort, CODEX_BACKGROUND_ADVICE_EFFORT)
            return CodexReviewBudget("routine", effort, self.routine_output_limit)
        raise ValueError("codex_budget_profile_invalid")

    @property
    def required_reasoning_efforts(self) -> tuple[str, ...]:
        """Every effort a check under this binding may request, final first, deduplicated."""

        efforts = [self.reasoning_effort]
        if (
            self.routine_reasoning_effort is not None
            and self.routine_reasoning_effort != self.reasoning_effort
        ):
            efforts.append(self.routine_reasoning_effort)
        return tuple(efforts)

    def verify_capability_evidence(self, now: datetime) -> None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("codex_runtime_capability_time_invalid")
        if now >= _CAPABILITY_EVIDENCE_EXPIRES_AT:
            raise ValueError("codex_runtime_capability_evidence_stale")

    @property
    def reviewer_model_catalog(self) -> ReviewerCatalogDecision:
        """Whether this launch replaces the model catalog with the derived reviewer catalog.

        It reads the bundled-entry digest the launch fence measured from these exact executable
        bytes (``measure_reviewer_catalog``); before that measurement it never applies.
        """

        return resolve_reviewer_catalog(
            runtime_version=self.runtime_version,
            model=self.model,
            measured_entry_sha256=_BUNDLED_ENTRY_SHA256.get(self.executable_sha256),
            catalog_path=packaged_reviewer_catalog_path(),
        )

    @property
    def launcher_argv(self) -> tuple[str, ...]:
        """The argv the current catalog decision would launch (``launcher_argv_for``)."""

        return self.launcher_argv_for(self.reviewer_model_catalog)

    def launcher_argv_for(self, decision: ReviewerCatalogDecision) -> tuple[str, ...]:
        """The exact argv for one measured catalog *decision*, built once per launch."""

        args: list[str] = [
            str(self.executable_path),
            "app-server",
            "--stdio",
            "--strict-config",
        ]
        overrides = [*_LAUNCH_OVERRIDES, *_RELEASE_LAUNCH_OVERRIDES.get(self.runtime_version, ())]
        catalog = decision.path
        if catalog is not None:
            # A TOML basic string: JSON's escapes are a subset of TOML's.
            overrides.append(f"model_catalog_json={json.dumps(str(catalog))}")
        for override in overrides:
            args.extend(("-c", override))
        return tuple(args)

    def measure_reviewer_catalog(self) -> ReviewerCatalogDecision:
        """Measure the launched bytes' bundled reviewer entry, then decide and record the outcome.

        Runs only for a pinned release and the model, after ``verify_local_binding`` re-hashed the
        executable, under a scratch directory in the home's private ``runtime`` root. A fallback
        writes its closed reason to the owner-only diagnostics once per process.
        """

        if (
            self.runtime_version in REVIEWER_CATALOG_RUNTIME_VERSIONS
            and self.model == REVIEWER_CATALOG_MODEL
        ):
            runtime_root = self.codex_home / "runtime"
            measured: str | None
            try:
                ensure_owner_only_dir(runtime_root)
                catalog = codex_bundled_model_catalog(
                    self.executable_path, scratch_parent=runtime_root
                )
                measured = bundled_entry_sha256(catalog)
            except ValueError as error:
                if str(error) == CODEX_PROBE_CLEANUP_UNCONFIRMED:
                    raise
                measured = None
            except OSError:
                measured = None
            _BUNDLED_ENTRY_SHA256[self.executable_sha256] = measured
        decision = self.reviewer_model_catalog
        key = (self.executable_sha256, self.model, decision.reason)
        if decision.path is None and key not in _RECORDED_CATALOG_FALLBACKS:
            _RECORDED_CATALOG_FALLBACKS.add(key)
            record_bounded_event_without_raising(
                component="codex_app_server",
                operation="codex_reviewer_model_catalog",
                reason=decision.reason,
            )
        return decision

    @property
    def launcher_sha256(self) -> str:
        return launcher_digest(self.launcher_argv)

    def _record_matches(self, record: CodexCapabilityRecord) -> bool:
        return (
            record.current
            and record.digest == self.capability_cell_sha256
            and record.runtime_version == self.runtime_version
            and record.source_identity == self.source_identity
            and record.executable_sha256 == self.executable_sha256
            and record.app_server_schema_sha256 == self.app_server_schema_sha256
            and record.isolated_config_sha256 == self.isolated_config_sha256
            and record.capability_profile == self.capability_profile
        )

    def bound_capability_record(self) -> CodexCapabilityRecord:
        """The record this binding commits to: in memory during a check, else beside the bytes.

        A missing record surfaces as ``FileNotFoundError`` (the retained runtime is incomplete);
        any record that is unreadable or does not match the binding's digest and fields is
        ``codex_runtime_executable_changed``.
        """

        if self.capability_record is not None:
            return self.capability_record
        try:
            record = read_capability_record(self.executable_path.parent)
        except ValueError as error:
            raise ValueError("codex_runtime_executable_changed") from error
        if not self._record_matches(record):
            raise ValueError("codex_runtime_executable_changed")
        return record

    def verify_local_binding(self) -> None:
        """The launch fence: the bytes and record launched are the ones that passed the check.

        It re-hashes the executable and its code-mode host against the committed capability
        record on every launch, so a runtime replaced after its check never starts. It does not
        re-run the capability check itself; ``repair`` and ``setup`` do.
        """

        bound_platform = _validate_binding_fields(
            source_identity=self.source_identity,
            executable_sha256=self.executable_sha256,
            runtime_version=self.runtime_version,
            app_server_schema_sha256=self.app_server_schema_sha256,
            capability_cell_sha256=self.capability_cell_sha256,
            capability_profile=self.capability_profile,
            capability_evidence_expires_at=self.capability_evidence_expires_at,
            isolated_config_sha256=self.isolated_config_sha256,
        )
        if host_codex_platform() != bound_platform:
            raise ValueError("codex_runtime_platform_unsupported")
        facts = self.executable_path.stat()
        if not stat.S_ISREG(facts.st_mode) or not (facts.st_mode & stat.S_IXUSR):
            raise ValueError("codex_runtime_executable_invalid")
        record = self.bound_capability_record()
        if (record.platform_os, record.platform_architecture) != (
            bound_platform.os,
            bound_platform.architecture,
        ):
            raise ValueError("codex_runtime_platform_unsupported")
        if _sha256_file(self.executable_path) != self.executable_sha256:
            raise ValueError("codex_runtime_executable_changed")
        # The sibling code-mode host is checked against the same record: a missing file surfaces
        # as the executable's own FileNotFoundError, and other faults use the executable tokens.
        host = codex_code_mode_host_path(self.executable_path)
        host_facts = host.stat()
        if not stat.S_ISREG(host_facts.st_mode) or not (host_facts.st_mode & stat.S_IXUSR):
            raise ValueError("codex_runtime_executable_invalid")
        if _sha256_file(host) != record.code_mode_host_sha256:
            raise ValueError("codex_runtime_executable_changed")
        verify_private_local_bundle(self.codex_home)
        config_path = self.codex_home / "config.toml"
        config_bytes = config_path.read_bytes()
        if (
            config_bytes != CODEX_EVALUATOR_CONFIG.encode()
            or _sha256_bytes(config_bytes) != self.isolated_config_sha256
        ):
            raise ValueError("codex_runtime_config_changed")


def prepare_codex_home(path: Path) -> None:
    """Create the dedicated owner-private home and exact config without inspecting auth files."""

    if not path.is_absolute():
        raise ValueError("codex_home_invalid")
    ensure_owner_only_dir(path)
    verify_private_local_bundle(path)
    target = path / "config.toml"
    payload = CODEX_EVALUATOR_CONFIG.encode()
    try:
        current = target.read_bytes()
    except FileNotFoundError:
        current = None
    if current is not None:
        if current != payload:
            raise ValueError("codex_runtime_config_conflict")
        return
    descriptor, temporary_name = tempfile.mkstemp(prefix=".config-", dir=path)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


def codex_binding_from_config(config: ExternalRuntimeProfileConfig) -> ProviderBinding:
    return ProviderBinding(
        config.provider_id,
        config.model,
        config.endpoint_profile_id,
        config.endpoint_profile_version,
        "external",
    )


@dataclass(slots=True)
class _CodexProcess:
    profile: CodexAppServerProfile
    process: asyncio.subprocess.Process
    workdir: Path
    stderr_task: asyncio.Task[bool]
    pending_notifications: deque[Mapping[str, object]]
    sandbox_unavailable: bool = False
    sandbox_unavailable_reason: SandboxUnavailableReason | None = None
    # The digest of the argv this process was spawned with, frozen at launch (#1118 V3): a later
    # catalog measurement by another launch must never change what this process's evidence says.
    launcher_sha256: str | None = None
    received_bytes: int = 0

    async def send(self, value: Mapping[str, object]) -> None:
        stdin = self.process.stdin
        if stdin is None:
            raise ValueError("codex_app_server_stdin_unavailable")
        payload = canonical_encode(cast(JsonValue, dict(value))) + b"\n"
        if len(payload) > _MAX_MESSAGE_BYTES:
            raise ValueError("codex_app_server_message_too_large")
        stdin.write(payload)
        await stdin.drain()

    async def read(self, timeout: float) -> Mapping[str, object]:
        if self.stderr_task.done() and self.stderr_task.result():
            raise ValueError("codex_app_server_stderr_limit")
        stdout = self.process.stdout
        if stdout is None:
            raise ValueError("codex_app_server_stdout_unavailable")
        line = await asyncio.wait_for(stdout.readline(), timeout=max(0.001, timeout))
        self.received_bytes += len(line)
        if not line or len(line) > _MAX_MESSAGE_BYTES or not line.endswith(b"\n"):
            raise ValueError("codex_app_server_message_invalid")
        if self.stderr_task.done() and self.stderr_task.result():
            raise ValueError("codex_app_server_stderr_limit")
        try:
            message = _object(strict_json_parse(line[:-1]))
        except (ProtocolValueError, ValueError):
            # A malformed JSONL envelope is transport failure, not a malformed final answer.
            raise ValueError("codex_app_server_message_invalid") from None
        reason = _sandbox_warning_reason(message)
        if reason is not None:
            self.sandbox_unavailable = True
            self.sandbox_unavailable_reason = reason
        return message

    async def request(
        self,
        request_id: int,
        method: str,
        params: Mapping[str, object] | None,
        timeout: float,
    ) -> Mapping[str, object]:
        request: dict[str, object] = {"id": request_id, "method": method}
        if params is not None:
            request["params"] = dict(params)
        request_deadline = asyncio.get_running_loop().time() + timeout
        # The bound covers the write too: a runtime that stops reading stdin cannot hold it.
        await asyncio.wait_for(self.send(request), max(0.001, timeout))
        for _ in range(_MAX_EVENT_COUNT):
            remaining = request_deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError
            message = await self.read(remaining)
            if message.get("id") == request_id and "method" not in message:
                if "error" in message or "result" not in message:
                    raise ValueError("codex_app_server_request_failed")
                return _object(message["result"])
            if "method" in message and "id" in message:
                raise ValueError("codex_app_server_tool_request_forbidden")
            if len(self.pending_notifications) >= _MAX_EVENT_COUNT:
                raise ValueError("codex_app_server_event_limit")
            self.pending_notifications.append(message)
        raise ValueError("codex_app_server_event_limit")


async def _drain_stderr(stream: asyncio.StreamReader | None) -> bool:
    if stream is None:
        return False
    count = 0
    while True:
        chunk = await stream.read(8192)
        if not chunk:
            return False
        count += len(chunk)
        if count > _MAX_STDERR_BYTES:
            return True


def _process_environment(profile: CodexAppServerProfile) -> dict[str, str]:
    return {
        "CODEX_HOME": str(profile.codex_home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "RUST_LOG": "error",
    }


def launcher_digest(argv: Sequence[str]) -> str:
    """The canonical digest runtime evidence records for one launch argv."""

    return canonical_digest({"argv": list(argv), "version": 1})


def _verify_and_measure(profile: CodexAppServerProfile) -> ReviewerCatalogDecision:
    profile.verify_local_binding()
    return profile.measure_reviewer_catalog()


async def _launch(profile: CodexAppServerProfile) -> _CodexProcess:
    # Revalidate every launch, but do not hash the runtime executable on the service loop. The
    # argv is built once from this launch's own measured decision and frozen on the process, so a
    # concurrent launch's measurement can change neither what runs nor what evidence records.
    decision = await asyncio.to_thread(_verify_and_measure, profile)
    argv = profile.launcher_argv_for(decision)
    frozen = launcher_digest(argv)
    runtime_root = profile.codex_home / "runtime"
    ensure_owner_only_dir(runtime_root)
    verify_private_local_bundle(runtime_root)
    workdir: Path | None = None
    try:
        workdir = Path(tempfile.mkdtemp(prefix="attempt-", dir=runtime_root))
        os.chmod(workdir, 0o700)
        spawn_task = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *argv,
                cwd=workdir,
                env=_process_environment(profile),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
                limit=_MAX_MESSAGE_BYTES,
            )
        )
        try:
            process = await asyncio.shield(spawn_task)
        except asyncio.CancelledError as cancellation:
            while not spawn_task.done():
                try:
                    await asyncio.shield(spawn_task)
                except asyncio.CancelledError:
                    continue
            try:
                process = spawn_task.result()
            except BaseException:
                # Retrieve the spawn outcome, but keep cancellation authoritative.
                raise cancellation from None
            owned = _CodexProcess(
                profile=profile,
                process=process,
                workdir=workdir,
                stderr_task=asyncio.create_task(_drain_stderr(process.stderr)),
                pending_notifications=deque(),
                launcher_sha256=frozen,
            )
            try:
                await _cleanup_guaranteed(owned)
            except asyncio.CancelledError:
                # Repeated cancellation cannot interrupt cleanup; preserve the first signal.
                pass
            raise cancellation
        return _CodexProcess(
            profile=profile,
            process=process,
            workdir=workdir,
            stderr_task=asyncio.create_task(_drain_stderr(process.stderr)),
            pending_notifications=deque(),
            launcher_sha256=frozen,
        )
    except BaseException:
        # Spawn cancellation above owns and cleans a returned process before it reaches here.
        # Ordinary launch failures have no returned process handle, so remove their attempt root.
        if workdir is not None:
            try:
                shutil.rmtree(workdir)
            except OSError:
                pass
        raise


async def _cleanup(
    runtime: _CodexProcess | None,
) -> Literal["not_started", "terminated", "killed", "failed"]:
    if runtime is None:
        return "not_started"
    process = runtime.process
    outcome: Literal["terminated", "killed", "failed"] = "terminated"
    process_exited = process.returncode is not None

    def group_exists() -> bool:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    async def await_group_exit(timeout: float) -> bool:
        deadline = asyncio.get_running_loop().time() + timeout
        while group_exists() and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.01)
        return not group_exists()

    try:
        if group_exists():
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                # The child can exit between the existence probe and the signal.  That is a
                # successful group-termination race.  Still await the process object below so
                # the child is reaped and its return code is observed.
                pass
        if process.returncode is None:
            try:
                await asyncio.wait_for(process.wait(), timeout=_CLEANUP_GRACE_SECONDS)
            except TimeoutError:
                pass
            except ProcessLookupError:
                # Without an observed return code, disappearance is not proof of a reap.
                pass
            else:
                process_exited = process.returncode is not None
        if not await await_group_exit(_CLEANUP_GRACE_SECONDS):
            outcome = "killed"
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                # A concurrent child exit can win the kill race; still reap below.
                pass
            if process.returncode is None:
                try:
                    await asyncio.wait_for(process.wait(), timeout=_CLEANUP_GRACE_SECONDS)
                except TimeoutError:
                    pass
                except ProcessLookupError:
                    # Preserve an unconfirmed cleanup result when the process cannot be reaped.
                    pass
                else:
                    process_exited = process.returncode is not None
            if not await await_group_exit(_CLEANUP_GRACE_SECONDS):
                outcome = "failed"
        if process.returncode is None and not process_exited:
            outcome = "failed"
    except Exception:
        outcome = "failed"
    finally:
        runtime.stderr_task.cancel()
        try:
            await runtime.stderr_task
        except BaseException:
            pass
        expected_parent = runtime.profile.codex_home / "runtime"
        if runtime.workdir.parent == expected_parent and runtime.workdir.name.startswith(
            "attempt-"
        ):
            try:
                shutil.rmtree(runtime.workdir)
            except OSError:
                outcome = "failed"
    return outcome


async def _cleanup_guaranteed(
    runtime: _CodexProcess | None,
) -> Literal["not_started", "terminated", "killed", "failed"]:
    """Finish process cleanup even when the caller is cancelled while awaiting it."""

    cleanup_task = asyncio.create_task(_cleanup(runtime))
    cancellation: asyncio.CancelledError | None = None
    try:
        return await asyncio.shield(cleanup_task)
    except asyncio.CancelledError as error:
        cancellation = error

    while not cleanup_task.done():
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            continue

    # Retrieve the bounded cleanup outcome so its failure cannot become an unobserved exception.
    # Outer cancellation remains authoritative for the caller.
    try:
        cleanup_task.result()
    except BaseException:
        pass
    assert cancellation is not None
    raise cancellation


def _remaining(deadline: Deadline, clock: ClockPort) -> float:
    remaining = deadline.monotonic_deadline - clock.monotonic_seconds()
    if remaining <= 0.0:
        raise TimeoutError
    return remaining


_USER_AGENT_VERSION: Final = re.compile(
    r"^[A-Za-z0-9_.-]{1,128}/([0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9})(?: |$)"
)


def _validate_initialize(profile: CodexAppServerProfile, result: Mapping[str, object]) -> None:
    """The runtime must name the exact admitted release it was checked as, and the bound home."""

    if result.get("codexHome") != str(profile.codex_home):
        raise ValueError("codex_home_mismatch")
    agent = result.get("userAgent")
    match = _USER_AGENT_VERSION.match(agent) if type(agent) is str else None
    if (
        match is None
        or match.group(1) != profile.runtime_version
        or codex_version_key(match.group(1)) is None
    ):
        raise ValueError("codex_runtime_version_mismatch")


def _account(result: Mapping[str, object]) -> tuple[Literal["chatgpt"], str | None]:
    raw = result.get("account")
    if not isinstance(raw, Mapping):
        raise PermissionError("codex_login_required")
    account = dict(cast(Mapping[str, object], raw))
    account.pop("email", None)  # discard identity-bearing account data at ingress
    if account.get("type") != "chatgpt":
        raise PermissionError("codex_chatgpt_login_required")
    plan = account.get("planType")
    if plan is not None and (type(plan) is not str or plan not in _SAFE_PLAN_TYPES):
        plan = "unknown"
    return "chatgpt", plan


async def _require_model(
    runtime: _CodexProcess,
    profile: CodexAppServerProfile,
    timeout: float,
    required_efforts: tuple[str, ...] | None = None,
    *,
    require_images: bool = False,
) -> None:
    """Prove the exact model lists every effort this probe or attempt may request.

    Readiness probes require every configured profile effort; one evaluation attempt requires
    only the effort its budget selected.
    """

    required = profile.required_reasoning_efforts if required_efforts is None else required_efforts
    deadline = asyncio.get_running_loop().time() + timeout
    cursor: object = None
    for page in range(8):
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0.0:
            raise TimeoutError
        params: dict[str, object] = {"includeHidden": True, "limit": 100}
        if cursor is not None:
            params["cursor"] = cursor
        result = await runtime.request(10 + page, "model/list", params, remaining)
        raw_data = result.get("data")
        if not isinstance(raw_data, list | tuple):
            raise ValueError("codex_model_catalog_invalid")
        model_items = cast(list[object] | tuple[object, ...], raw_data)
        for raw_model in model_items:
            if not isinstance(raw_model, Mapping):
                raise ValueError("codex_model_catalog_invalid")
            model = cast(Mapping[str, object], raw_model)
            if model.get("model") != profile.model and model.get("id") != profile.model:
                continue
            if require_images:
                modalities = model.get("inputModalities")
                if not isinstance(modalities, list | tuple) or "image" not in modalities:
                    raise ValueError("codex_image_input_unavailable")
            efforts = model.get("supportedReasoningEfforts")
            if not isinstance(efforts, list | tuple):
                raise ValueError("codex_model_catalog_invalid")
            effort_items = cast(list[object] | tuple[object, ...], efforts)
            supported = {
                cast(Mapping[str, object], item).get("reasoningEffort")
                for item in effort_items
                if isinstance(item, Mapping)
            }
            if all(effort in supported for effort in required):
                return
            raise ValueError("codex_reasoning_effort_unavailable")
        cursor = result.get("nextCursor")
        if cursor is None:
            break
        if type(cursor) is not str or not cursor:
            raise ValueError("codex_model_catalog_invalid")
    raise ValueError("codex_model_unavailable")


async def _initialize(
    runtime: _CodexProcess, profile: CodexAppServerProfile, timeout: float = 10.0
) -> None:
    """Initialize within one budget: the request and the notification share ``timeout``."""
    stop = asyncio.get_running_loop().time() + timeout
    result = await runtime.request(
        0,
        "initialize",
        {
            "clientInfo": {
                "name": "finishup_semantic_evaluator",
                "title": "FinishUP bounded AI-powered evaluator",
                "version": "0.1.0",
            },
            "capabilities": {
                "experimentalApi": True,
                "mcpServerOpenaiFormElicitation": False,
                "requestAttestation": False,
            },
        },
        timeout,
    )
    _validate_initialize(profile, result)
    left = stop - asyncio.get_running_loop().time()
    await asyncio.wait_for(runtime.send({"method": "initialized"}), max(0.001, left))


async def codex_account_status(profile: CodexAppServerProfile) -> CodexRuntimeStatus:
    """Probe the bound runtime, login, plan, and model availability without sending task content."""

    runtime: _CodexProcess | None = None
    auth_mode: Literal["chatgpt"] | None = None
    plan_type: str | None = None
    model_available = False
    runtime_ready = False
    try:
        profile.verify_capability_evidence(datetime.now(UTC))
        runtime = await _launch(profile)
        await _initialize(runtime, profile)
        runtime_ready = True
        account = await runtime.request(1, "account/read", {"refreshToken": False}, 10.0)
        try:
            auth_mode, plan_type = _account(account)
        except PermissionError:
            pass
        else:
            try:
                await _require_model(runtime, profile, 10.0)
            except ValueError:
                pass
            else:
                model_available = True
        # The same fail-closed window an attempt applies before disclosure: a runtime that
        # warns or emits an unreviewed event under the authenticated home is not ready, so
        # runtime selection falls back to an older release instead of binding it.
        try:
            await _close_predisclosure_window(runtime, 10.0)
        except _CodexRuntimeWarning as warning:
            raise ValueError("codex_app_server_predisclosure_event_forbidden") from warning
    except Exception as error:
        await _cleanup_or_unconfirmed(runtime, error)
        raise
    except BaseException:
        await _cleanup_guaranteed(runtime)
        raise
    cleanup = await _cleanup_guaranteed(runtime)
    return CodexRuntimeStatus(
        runtime_ready=runtime_ready,
        auth_mode=auth_mode,
        plan_type=plan_type,
        model_available=model_available,
        cleanup=cleanup,
        sandbox_unavailable=_sandbox_unavailable(runtime),
        sandbox_unavailable_reason=_sandbox_unavailable_reason(runtime),
    )


def _thread_start_params(
    runtime: _CodexProcess,
    profile: CodexAppServerProfile,
    instructions: str = SEMANTIC_REVIEW_INSTRUCTION,
) -> dict[str, object]:
    """The one isolated, ephemeral, read-only thread request a review and its probe both send.

    ``environments: []`` (experimental, hence ``experimentalApi``) leaves no environment for shell,
    patch or file tools (#1118 unit 3, ADR-006).
    """

    return {
        "approvalPolicy": "never",
        "approvalsReviewer": "user",
        "baseInstructions": instructions,
        "cwd": str(runtime.workdir),
        "environments": [],
        "ephemeral": True,
        "model": profile.model,
        "modelProvider": "openai",
        "personality": "none",
        "sandbox": "read-only",
        "serviceName": "finishup-semantic-review",
    }


async def codex_capability_probe(profile: CodexAppServerProfile) -> None:
    """Zero-inference capability probe of one candidate runtime (ADR-006 capability admission).

    The candidate starts through the same launch fence, argv, environment and isolated config as
    a review. Before any case could exist it must: report, in ``initialize``, the exact release it
    is being checked as and the bound home; answer ``account/read``; start an ephemeral thread in
    a new empty owner-private cwd whose returned posture is read-only, network-off, with no
    persisted path and no instruction sources; and keep every notification seen so far inside the
    reviewed pre-disclosure allowlist (an unknown event, a native warning, or remote control not
    ``disabled`` fails closed). No ``turn/start`` is sent, so nothing is sampled and no task
    content exists. Any refusal is one closed token; the process group is always cleaned up.
    """

    runtime: _CodexProcess | None = None
    try:
        try:
            profile.verify_capability_evidence(datetime.now(UTC))
            runtime = await _launch(profile)
            await _initialize(runtime, profile)
            await runtime.request(1, "account/read", {"refreshToken": False}, 10.0)
            thread_result = await runtime.request(
                30, "thread/start", _thread_start_params(runtime, profile), 10.0
            )
            _validate_thread(runtime, profile, thread_result)
            await _close_predisclosure_window(runtime, 10.0)
        except _CodexRuntimeWarning as warning:
            raise ValueError("codex_app_server_predisclosure_event_forbidden") from warning
        except TimeoutError as error:
            raise ValueError("codex_capability_probe_timeout") from error
    except Exception as error:
        await _cleanup_or_unconfirmed(runtime, error)
        raise
    except BaseException:
        await _cleanup_guaranteed(runtime)
        raise
    if await _cleanup_guaranteed(runtime) == "failed":
        raise ValueError(CODEX_PROBE_CLEANUP_UNCONFIRMED)


async def _cleanup_or_unconfirmed(runtime: _CodexProcess | None, failure: Exception) -> None:
    """Clean up after a failed probe; an unconfirmed cleanup outranks, and chains, ``failure``.

    The probe's own refusal stays the ``__cause__``, but the raised token is the unconfirmed
    cleanup, which stops runtime selection instead of letting it fall back to another candidate
    while a process group may still be running.
    """

    if await _cleanup_guaranteed(runtime) == "failed":
        raise ValueError(CODEX_PROBE_CLEANUP_UNCONFIRMED) from failure


async def codex_model_listed(profile: CodexAppServerProfile) -> bool:
    """Report whether this runtime's own ``model/list`` offers the exact model and efforts.

    Setup uses it before any sign-in to decide whether its suggested model can be bound on the
    runtime it adopted. It reads no account state and sends no task content: the answer is only
    what the checked Codex lists for this dedicated home (its bundled catalog until the home is
    signed in). Admission is still re-proven at sign-in and before every review.
    """

    runtime: _CodexProcess | None = None
    try:
        profile.verify_capability_evidence(datetime.now(UTC))
        runtime = await _launch(profile)
        await _initialize(runtime, profile)
        try:
            await _require_model(runtime, profile, 10.0)
        except ValueError:
            listed = False
        else:
            listed = True
    except Exception as error:
        await _cleanup_or_unconfirmed(runtime, error)
        raise
    except BaseException:
        await _cleanup_guaranteed(runtime)
        raise
    if await _cleanup_guaranteed(runtime) == "failed":
        raise ValueError("codex_subscription_readiness_unproven")
    return listed


def _login_challenge(result: Mapping[str, object]) -> CodexLoginChallenge:
    response_type = result.get("type")
    if response_type == "chatgpt":
        url = result.get("authUrl")
        user_code = None
        mode: Literal["browser", "device_code"] = "browser"
    elif response_type == "chatgptDeviceCode":
        url = result.get("verificationUrl")
        user_code = result.get("userCode")
        mode = "device_code"
    else:
        raise ValueError("codex_login_response_invalid")
    if type(url) is not str or not 1 <= len(url) <= 8192:
        raise ValueError("codex_login_response_invalid")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("codex_login_response_invalid")
    if user_code is not None and (type(user_code) is not str or not 1 <= len(user_code) <= 256):
        raise ValueError("codex_login_response_invalid")
    return CodexLoginChallenge(mode, url, user_code)


def _validate_predisclosure_notification(
    message: Mapping[str, object],
    *,
    runtime_version: str,
    invalid_token: str = "codex_app_server_predisclosure_event_forbidden",
) -> bool:
    """Validate one reviewed pre-disclosure notification and retain no native payload."""

    if "method" in message and "id" in message:
        raise ValueError("codex_app_server_tool_request_forbidden")
    method = message.get("method")
    if type(method) is not str or method not in _PREDISCLOSURE_NOTIFICATION_METHODS:
        raise ValueError(invalid_token)
    if method == "account/updated":
        return True
    if method == "account/rateLimits/updated":
        _discard_rate_limits_notification(message)
    elif method == "warning":
        raise _runtime_warning(message)
    elif method == "configWarning":
        if _sandbox_warning_reason(message) is None:
            raise ValueError(invalid_token)
        if runtime_version not in SANDBOX_UNAVAILABLE_REVIEWED_RELEASES:
            raise ValueError("codex_sandbox_unavailable_unreviewed_runtime")
    elif method == "remoteControl/status/changed":
        params = _object(message.get("params"))
        if set(params) != {"environmentId", "installationId", "serverName", "status"}:
            raise ValueError("codex_app_server_remote_control_state_invalid")
        if params.get("status") != "disabled":
            raise ValueError("codex_app_server_remote_control_not_disabled")
    return False


def _sandbox_warning_reason(message: Mapping[str, object]) -> SandboxUnavailableReason | None:
    """The reason when ``message`` is exactly one of Codex's reviewed sandbox warnings.

    The wire shape is closed: ``{"method": "configWarning", "params": {"summary": <one reviewed
    text>, "details": null}}`` with an optional integer ``emittedAtMs``. Codex carries no
    structured warning code, so the summary must equal a reviewed constant byte for byte; any
    other summary, detail, path or range is a different warning and is not admitted.
    """

    if message.get("method") != "configWarning":
        return None
    if set(message) not in ({"method", "params"}, {"method", "params", "emittedAtMs"}):
        return None
    if "emittedAtMs" in message and type(message["emittedAtMs"]) is not int:
        return None
    params = message.get("params")
    if type(params) is not dict:
        return None
    fields = cast(dict[str, object], params)
    if set(fields) != {"summary", "details"} or fields["details"] is not None:
        return None
    summary = fields["summary"]
    if type(summary) is not str:
        return None
    return _SANDBOX_WARNING_REASONS.get(summary)


def _login_notification(
    message: Mapping[str, object], login_id: str, *, runtime_version: str
) -> Literal["account_updated", "completed", "predisclosure"]:
    """Validate one login notification without retaining any native payload text."""

    if "method" in message and "id" in message:
        raise ValueError("codex_app_server_tool_request_forbidden")
    method = message.get("method")
    if type(method) is str and method in _PREDISCLOSURE_NOTIFICATION_METHODS:
        try:
            updated = _validate_predisclosure_notification(
                message, runtime_version=runtime_version, invalid_token="codex_login_event_invalid"
            )
        except _CodexRuntimeWarning as warning:
            # A native warning is not a login event. It ends the login with the bounded login
            # token; its free-form body never leaves the adapter.
            raise ValueError("codex_login_event_invalid") from warning
        return "account_updated" if updated else "predisclosure"
    if method != "account/login/completed":
        raise ValueError("codex_login_event_invalid")
    params = _object(message.get("params"))
    returned_id = params.get("loginId")
    if type(returned_id) is not str or returned_id != login_id:
        raise ValueError("codex_login_event_invalid")
    if params.get("success") is not True:
        raise PermissionError("codex_login_failed")
    return "completed"


async def _cancel_login(runtime: _CodexProcess, login_id: str) -> None:
    """Ask Codex to cancel a pending login, never replacing the primary failure."""

    try:
        await asyncio.wait_for(
            runtime.request(
                3,
                "account/login/cancel",
                {"loginId": login_id},
                _LOGIN_CANCEL_TIMEOUT_SECONDS,
            ),
            timeout=_LOGIN_CANCEL_TIMEOUT_SECONDS,
        )
    except BaseException:
        # Cancellation is best effort.  In particular, a task cancellation must remain visible
        # to the caller and a native failure must not mask the timeout or invalid-event token.
        return


def _take_account_updated(runtime: _CodexProcess) -> bool:
    """Consume only the expected post-login readiness notification from buffered events."""

    updated = False
    pending = runtime.pending_notifications
    runtime.pending_notifications = deque()
    for message in pending:
        notification = _login_notification(
            message, "", runtime_version=runtime.profile.runtime_version
        )
        if notification == "account_updated":
            updated = True
            continue
        if notification != "predisclosure":
            raise ValueError("codex_login_event_invalid")
    return updated


async def _wait_for_account_updated(runtime: _CodexProcess, deadline: float) -> bool:
    """Wait briefly for Codex's account projection to catch up after login completion."""

    try:
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0.0:
                return False
            message = await runtime.read(remaining)
            notification = _login_notification(
                message, "", runtime_version=runtime.profile.runtime_version
            )
            if notification == "account_updated":
                return True
            if notification == "predisclosure":
                continue
            raise ValueError("codex_login_event_invalid")
    except TimeoutError:
        return False


async def _account_after_login(
    runtime: _CodexProcess, *, account_updated_seen: bool
) -> tuple[Literal["chatgpt"], str | None]:
    """Read readiness after completion, allowing the account/updated projection to catch up."""

    readiness_deadline = asyncio.get_running_loop().time() + _LOGIN_READINESS_GRACE_SECONDS
    try:
        account = await runtime.request(
            2,
            "account/read",
            {"refreshToken": False},
            min(10.0, max(0.001, readiness_deadline - asyncio.get_running_loop().time())),
        )
        return _account(account)
    except PermissionError as error:
        account_updated_seen = _take_account_updated(runtime) or account_updated_seen
        if not account_updated_seen:
            account_updated_seen = await _wait_for_account_updated(runtime, readiness_deadline)
            if not account_updated_seen:
                raise error
        if asyncio.get_running_loop().time() >= readiness_deadline:
            raise error
        try:
            account = await runtime.request(
                4,
                "account/read",
                {"refreshToken": False},
                min(10.0, max(0.001, readiness_deadline - asyncio.get_running_loop().time())),
            )
            return _account(account)
        except PermissionError:
            raise


async def codex_login(
    profile: CodexAppServerProfile,
    *,
    mode: Literal["browser", "device_code"],
    present_challenge: Callable[[CodexLoginChallenge], None],
) -> CodexRuntimeStatus:
    """Drive only documented Codex login methods after a caller-owned user confirmation."""

    runtime: _CodexProcess | None = None
    auth_mode: Literal["chatgpt"] | None = None
    plan_type: str | None = None
    model_available = False
    runtime_ready = False
    login_id: str | None = None
    try:
        profile.verify_capability_evidence(datetime.now(UTC))
        runtime = await _launch(profile)
        await _initialize(runtime, profile)
        runtime_ready = True
        login_result = await runtime.request(
            1,
            "account/login/start",
            {"type": "chatgpt" if mode == "browser" else "chatgptDeviceCode"},
            10.0,
        )
        login_deadline = asyncio.get_running_loop().time() + _LOGIN_TIMEOUT_SECONDS_BY_MODE[mode]
        login_id = cast(str | None, login_result.get("loginId"))
        if type(login_id) is not str or not login_id:
            raise ValueError("codex_login_response_invalid")
        completion_succeeded = False
        try:
            challenge = _login_challenge(login_result)
            if challenge.mode != mode:
                raise ValueError("codex_login_response_invalid")
            present_challenge(challenge)
            account_updated_seen = False
            completion_seen = False
            events_seen = 0
            for _ in range(_MAX_EVENT_COUNT):
                remaining = login_deadline - asyncio.get_running_loop().time()
                if remaining <= 0.0:
                    break
                try:
                    message = (
                        runtime.pending_notifications.popleft()
                        if runtime.pending_notifications
                        else await runtime.read(remaining)
                    )
                except TimeoutError:
                    break
                events_seen += 1
                notification = _login_notification(
                    message, login_id, runtime_version=runtime.profile.runtime_version
                )
                if notification == "account_updated":
                    account_updated_seen = True
                    continue
                if notification == "predisclosure":
                    continue
                completion_seen = True
                completion_succeeded = True
                break
            else:
                raise ValueError("codex_app_server_event_limit")

            if not completion_seen:
                # A terminal event can be delivered just after the native deadline.  Give the
                # app-server one short, bounded chance to report it before preserving timeout.
                grace_deadline = asyncio.get_running_loop().time() + _LOGIN_TERMINAL_GRACE_SECONDS
                while True:
                    if events_seen >= _MAX_EVENT_COUNT:
                        raise ValueError("codex_app_server_event_limit")
                    remaining = grace_deadline - asyncio.get_running_loop().time()
                    if remaining <= 0.0:
                        raise TimeoutError
                    try:
                        message = (
                            runtime.pending_notifications.popleft()
                            if runtime.pending_notifications
                            else await runtime.read(remaining)
                        )
                    except TimeoutError as error:
                        raise TimeoutError from error
                    events_seen += 1
                    notification = _login_notification(
                        message, login_id, runtime_version=runtime.profile.runtime_version
                    )
                    if notification == "account_updated":
                        account_updated_seen = True
                        continue
                    if notification == "predisclosure":
                        continue
                    completion_seen = True
                    completion_succeeded = True
                    break

            auth_mode, plan_type = await _account_after_login(
                runtime, account_updated_seen=account_updated_seen
            )
            await _require_model(runtime, profile, 10.0)
            model_available = True
        except asyncio.CancelledError:
            await _cancel_login(runtime, login_id)
            raise
        except Exception:
            if not completion_succeeded:
                await _cancel_login(runtime, login_id)
            raise
    finally:
        cleanup = await _cleanup_guaranteed(runtime)
    return CodexRuntimeStatus(
        runtime_ready=runtime_ready,
        auth_mode=auth_mode,
        plan_type=plan_type,
        model_available=model_available,
        cleanup=cleanup,
        sandbox_unavailable=_sandbox_unavailable(runtime),
        sandbox_unavailable_reason=_sandbox_unavailable_reason(runtime),
    )


async def codex_logout(profile: CodexAppServerProfile) -> CodexRuntimeStatus:
    """Ask Codex to remove its dedicated-home login and structurally confirm logout."""

    runtime: _CodexProcess | None = None
    runtime_ready = False
    try:
        profile.verify_capability_evidence(datetime.now(UTC))
        runtime = await _launch(profile)
        await _initialize(runtime, profile)
        runtime_ready = True
        await runtime.request(1, "account/logout", None, 10.0)
        account = await runtime.request(2, "account/read", {"refreshToken": False}, 10.0)
        if account.get("account") is not None:
            raise ValueError("codex_logout_unconfirmed")
    finally:
        cleanup = await _cleanup_guaranteed(runtime)
    return CodexRuntimeStatus(
        runtime_ready,
        None,
        None,
        False,
        cleanup,
        _sandbox_unavailable(runtime),
        _sandbox_unavailable_reason(runtime),
    )


def _sandbox_unavailable(runtime: _CodexProcess | None) -> bool:
    return runtime is not None and getattr(runtime, "sandbox_unavailable", False) is True


def _sandbox_unavailable_reason(runtime: _CodexProcess | None) -> SandboxUnavailableReason | None:
    if runtime is None:
        return None
    reason = getattr(runtime, "sandbox_unavailable_reason", None)
    if reason == "user_namespaces_unavailable":
        return "user_namespaces_unavailable"
    if reason == "bubblewrap_missing":
        return "bubblewrap_missing"
    return None


def _validate_thread(
    runtime: _CodexProcess, profile: CodexAppServerProfile, result: Mapping[str, object]
) -> str:
    thread = _object(result.get("thread"))
    thread_id = thread.get("id")
    instruction_sources = result.get("instructionSources", ())
    sandbox = result.get("sandbox")
    if (
        type(thread_id) is not str
        or not thread_id
        or thread.get("ephemeral") is not True
        or thread.get("path") is not None
        or thread.get("cwd") != str(runtime.workdir)
        or result.get("cwd") != str(runtime.workdir)
        or result.get("model") != profile.model
        or result.get("modelProvider") != "openai"
        or not isinstance(sandbox, Mapping)
        or cast(Mapping[str, object], sandbox).get("type") != "readOnly"
        or cast(Mapping[str, object], sandbox).get("networkAccess") is not False
        or not isinstance(instruction_sources, list | tuple)
        or len(cast(list[object] | tuple[object, ...], instruction_sources)) != 0
    ):
        raise ValueError("codex_thread_isolation_unproven")
    return thread_id


# A Codex wire name is structural (``thread/settings/updated``, ``item/agentMessage/delta``,
# ``mcpToolCall``), never user content, but it is still validated before it reaches a diagnostic:
# at most five slash-separated camelCase segments of ASCII letters and digits.
_RUNTIME_NAME_PATTERN: Final = re.compile(r"[a-z][A-Za-z0-9]{0,31}(?:/[a-z][A-Za-z0-9]{0,31}){0,4}")
_CAMEL_BOUNDARY: Final = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _runtime_name_token(value: object) -> str | None:
    """Encode one validated Codex wire name as a diagnostic token, or ``None`` if malformed.

    ``/`` becomes ``.`` and camelCase becomes snake_case (``item/agentMessage/delta`` ->
    ``item.agent_message.delta``), so the result fits the closed diagnostic token shape
    ``[a-z][a-z0-9_.-]{0,63}``.
    """

    if type(value) is not str or _RUNTIME_NAME_PATTERN.fullmatch(value) is None:
        return None
    token = _CAMEL_BOUNDARY.sub("_", value).lower().replace("/", ".")
    return token if len(token) <= 64 else None


def runtime_event_diagnostic_reason(method: object, item_type: object = None) -> str:
    """The closed, length-bounded reason naming the Codex event an attempt refused.

    ``item/started`` and ``item/completed`` report the refused item type as ``item.<type>``
    instead of the method; a value of any other shape is reported as ``event_name_invalid``.
    """

    if item_type is None:
        token = _runtime_name_token(method)
    else:
        token = _runtime_name_token(f"item/{item_type}") if type(item_type) is str else None
    return "event_name_invalid" if token is None else token


def _record_forbidden_event(operation: str, method: object, item_type: object = None) -> None:
    """Write which Codex event ended an attempt to the owner-only service diagnostics."""

    record_bounded_event_without_raising(
        component="codex_app_server",
        operation=operation,
        reason=runtime_event_diagnostic_reason(method, item_type),
    )


@dataclass(slots=True)
class _TurnEvents:
    """Bound decoding/inspection work, retaining only closed family counts and encoded sizes."""

    work: int = 0
    wire_seen: int = 0
    counts: dict[str, int] = field(default_factory=lambda: dict[str, int]())

    def account(self, message: Mapping[str, object], received_bytes: int = 0) -> None:
        method = message.get("method")
        family = "control"
        if method in ("account/rateLimits/updated", "thread/tokenUsage/updated"):
            family = "telemetry"
        elif type(method) is str and method.endswith("/delta"):
            family = "delta"
        elif method in ("item/started", "item/completed"):
            params = message.get("params")
            item = cast(Mapping[str, object], params).get("item") if type(params) is dict else None
            if type(item) is dict:
                item = cast(Mapping[str, object], item)
                phase = item.get("phase")
                if item.get("type") == "reasoning" or (
                    type(phase) is str and phase in _NON_FINAL_PHASES
                ):
                    family = "intermediate"
        # Telemetry may contain floats or out-of-range counters: accounting must not run the
        # final-answer canonical validator before the telemetry can be discarded.
        size = len(json.dumps(dict(message), ensure_ascii=False, separators=(",", ":")).encode())
        wire_bytes = max(0, received_bytes - self.wire_seen)
        self.wire_seen = received_bytes
        key = "codex_event_wire_bytes"
        self.counts[key] = self.counts.get(key, 0) + wire_bytes
        prefix = f"codex_event_{family}"
        for suffix, amount in (("count", 1), ("bytes", size)):
            key = f"{prefix}_{suffix}"
            self.counts[key] = self.counts.get(key, 0) + amount
        self.work += max(_MIN_EVENT_WORK, size, wire_bytes)
        if self.work > _MAX_TURN_EVENT_WORK:
            raise ValueError("codex_app_server_event_limit")


def _notification_item(
    message: Mapping[str, object],
) -> tuple[str | None, str | None, str | None]:
    """Return the bounded (type, text, phase) triple of one item notification.

    ``phase`` is Codex's own classification of an agent message as interim ``commentary`` or the
    ``final_answer``; providers do not emit it consistently, so ``None`` means unknown.
    """

    params = message.get("params")
    if not isinstance(params, Mapping):
        return None, None, None
    item = cast(Mapping[str, object], params).get("item")
    if not isinstance(item, Mapping):
        return None, None, None
    source = cast(Mapping[str, object], item)
    item_type = source.get("type")
    text = source.get("text")
    phase = source.get("phase")
    return (
        item_type if type(item_type) is str else None,
        text if type(text) is str else None,
        phase if type(phase) is str else None,
    )


def _runtime_token_usages_from_notification(
    message: Mapping[str, object], *, thread_id: str, turn_id: str
) -> tuple[RuntimeTokenUsage, RuntimeTokenUsage] | None:
    """Read one active-turn usage snapshot without retaining native payloads.

    It returns the cumulative total, then the last model request's own breakdown.

    The app-server emits both ``last`` and cumulative ``total`` breakdowns. A fresh ephemeral
    reviewer thread has one active turn, and the cumulative snapshot is the only value that
    remains correct if the turn internally performs more than one model request. Repeated
    notifications replace the prior snapshot at the call site; they are never summed.

    A notification for another thread or turn is unrelated bookkeeping and is ignored before its
    body is inspected. A matching notification is strictly bounded so malformed provider data
    cannot become telemetry or an accepted usage value.
    """

    params = message.get("params")
    if not isinstance(params, Mapping):
        return None
    source = cast(Mapping[str, object], params)
    if source.get("threadId") != thread_id or source.get("turnId") != turn_id:
        return None
    if set(source) != {"threadId", "turnId", "tokenUsage"}:
        raise ValueError("codex_app_server_token_usage_invalid")
    raw_usage = source.get("tokenUsage")
    if not isinstance(raw_usage, Mapping):
        raise ValueError("codex_app_server_token_usage_invalid")
    usage = cast(Mapping[str, object], raw_usage)
    if set(usage) != {"last", "total"} and set(usage) != {
        "last",
        "total",
        "modelContextWindow",
    }:
        raise ValueError("codex_app_server_token_usage_invalid")

    def breakdown(value: object) -> tuple[int, int, int, int, int, int]:
        if not isinstance(value, Mapping):
            raise ValueError("codex_app_server_token_usage_invalid")
        source = cast(Mapping[str, object], value)
        required = {
            "cacheWriteInputTokens",
            "cachedInputTokens",
            "inputTokens",
            "outputTokens",
            "reasoningOutputTokens",
            "totalTokens",
        }
        if set(source) != required:
            raise ValueError("codex_app_server_token_usage_invalid")

        def counter(name: str) -> int:
            raw = source[name]
            if type(raw) is not int or not 0 <= raw <= 2**53 - 1:
                raise ValueError("codex_app_server_token_usage_invalid")
            return raw

        parsed = (
            counter("inputTokens"),
            counter("cachedInputTokens"),
            counter("cacheWriteInputTokens"),
            counter("outputTokens"),
            counter("reasoningOutputTokens"),
            counter("totalTokens"),
        )
        if parsed[1] > parsed[0] or parsed[4] > parsed[3] or parsed[0] + parsed[3] != parsed[5]:
            raise ValueError("codex_app_server_token_usage_invalid")
        return parsed

    # Both provider snapshots are validated. Only the cumulative total is the attempt's usage;
    # ``last`` is never a second aggregate (it would double-count the same turn). It is read only
    # as the one model request that moved the total, for prompt-cache telemetry (#1172).
    last = breakdown(usage["last"])
    total = breakdown(usage["total"])
    context_window = usage.get("modelContextWindow")
    if context_window is not None and (
        type(context_window) is not int or not 0 <= context_window <= 2**53 - 1
    ):
        raise ValueError("codex_app_server_token_usage_invalid")

    def usage_of(parsed: tuple[int, int, int, int, int, int]) -> RuntimeTokenUsage:
        return RuntimeTokenUsage(
            input_tokens=parsed[0],
            cached_input_tokens=parsed[1],
            cache_write_input_tokens=parsed[2],
            output_tokens=parsed[3],
            reasoning_output_tokens=parsed[4],
            total_tokens=parsed[5],
        )

    return usage_of(total), usage_of(last)


type _CacheCounters = tuple[int, int, int, int]  # input, cached input, cache-write input, output


def _cache_counters(usage: RuntimeTokenUsage | None) -> _CacheCounters:
    """A usage snapshot's prompt-cache counters; a thread that has reported nothing is at zero."""

    if usage is None:
        return (0, 0, 0, 0)
    return (
        usage.input_tokens,
        usage.cached_input_tokens,
        usage.cache_write_input_tokens,
        usage.output_tokens,
    )


def _start_before_request(
    total: RuntimeTokenUsage, request: RuntimeTokenUsage
) -> _CacheCounters | None:
    """The thread's total before one reported request: its snapshot's ``total`` less its ``last``."""

    end, own = _cache_counters(total), _cache_counters(request)
    start = (end[0] - own[0], end[1] - own[1], end[2] - own[2], end[3] - own[3])
    return start if min(start) >= 0 else None


def _turn_cache_usage(
    start: _CacheCounters | None,
    after: RuntimeTokenUsage | None,
    requests: int,
    first_cached: int,
    last_input: int,
) -> ExchangeCacheUsage | None:
    """One turn's usage: the thread's cumulative counters across it, or ``None`` if unknown.

    ``start`` is the thread's total before the turn's requests, ``None`` when it is unknown.
    ``first_cached`` and ``last_input`` come from the ``last`` breakdown of the snapshots whose
    total grew, so a turn that made several model requests still names its first request's reuse.
    """

    if start is None or not requests or after is None:
        return None
    end = _cache_counters(after)
    try:
        return ExchangeCacheUsage(
            input_tokens=end[0] - start[0],
            cached_input_tokens=end[1] - start[1],
            output_tokens=end[3] - start[3],
            requests=requests,
            first_cached_tokens=first_cached,
            last_input_tokens=last_input,
            cache_write_input_tokens=end[2] - start[2],
        )
    except ValueError:  # counters the runtime reported inconsistently are not recorded
        return None


class _CodexTurnFailure(Exception):
    def __init__(
        self,
        outcome: Literal["invalid", "refused", "unavailable"],
        failure_class: SemanticFailureClass,
        stage: str = "turn_failed",
    ) -> None:
        super().__init__(outcome)
        self.outcome: Literal["invalid", "refused", "unavailable"] = outcome
        self.failure_class = failure_class
        self.stage = stage


class _CodexRuntimeWarning(Exception):
    """A bounded native warning whose free-form body must not cross the adapter."""


def _discard_rate_limits_notification(message: Mapping[str, object]) -> None:
    """Validate bounded sparse rate-limit bookkeeping and retain no account state.

    Codex 0.157.1 adds the nullable ``normalModelSlug`` (the model a quota alias describes); like
    every other field it is only type- and length-checked, then discarded.
    """

    def invalid() -> None:
        raise ValueError("codex_app_server_rate_limits_invalid")

    def bounded_object(
        value: object, allowed: set[str], required: set[str]
    ) -> Mapping[str, object]:
        if type(value) is not dict:
            invalid()
        source = cast(dict[str, object], value)
        if not required <= set(source) <= allowed:
            invalid()
        return source

    def nullable_text(value: object, limit: int) -> None:
        if value is not None and (type(value) is not str or len(value) > limit):
            invalid()

    def integer(value: object, bits: int) -> None:
        if type(value) is not int or not -(2 ** (bits - 1)) <= value < 2 ** (bits - 1):
            invalid()

    if set(message) not in ({"method", "params"}, {"method", "params", "emittedAtMs"}):
        invalid()
    if "emittedAtMs" in message:
        integer(message["emittedAtMs"], 64)
    params = bounded_object(message.get("params"), {"rateLimits"}, {"rateLimits"})
    allowed = {
        "credits",
        "individualLimit",
        "limitId",
        "limitName",
        "normalModelSlug",
        "planType",
        "primary",
        "rateLimitReachedType",
        "secondary",
        "spendControlReached",
    }
    rate_limits = bounded_object(params["rateLimits"], allowed, set())
    nullable_text(rate_limits.get("limitId"), 128)
    nullable_text(rate_limits.get("limitName"), 128)
    nullable_text(rate_limits.get("normalModelSlug"), 128)
    # Admitted releases add plan names (``promax`` in 0.159.0); the field is discarded unread, so
    # any bounded lowercase identifier is accepted rather than the closed account-plan set.
    plan_type = rate_limits.get("planType")
    if plan_type is not None and (
        type(plan_type) is not str or _PLAN_TYPE_PATTERN.fullmatch(plan_type) is None
    ):
        invalid()
    reached_type = rate_limits.get("rateLimitReachedType")
    if reached_type is not None and (
        type(reached_type) is not str
        or reached_type
        not in {
            "rate_limit_reached",
            "workspace_owner_credits_depleted",
            "workspace_member_credits_depleted",
            "workspace_owner_usage_limit_reached",
            "workspace_member_usage_limit_reached",
        }
    ):
        invalid()
    spend_control = rate_limits.get("spendControlReached")
    if spend_control is not None and type(spend_control) is not bool:
        invalid()

    for name in ("primary", "secondary"):
        window = rate_limits.get(name)
        if window is None:
            continue
        source = bounded_object(
            window, {"resetsAt", "usedPercent", "windowDurationMins"}, {"usedPercent"}
        )
        integer(source["usedPercent"], 32)
        for key in ("resetsAt", "windowDurationMins"):
            if source.get(key) is not None:
                integer(source[key], 64)
    if rate_limits.get("credits") is not None:
        credits = bounded_object(
            rate_limits["credits"],
            {"balance", "hasCredits", "unlimited"},
            {"hasCredits", "unlimited"},
        )
        if type(credits["hasCredits"]) is not bool or type(credits["unlimited"]) is not bool:
            invalid()
        nullable_text(credits.get("balance"), 64)
    if rate_limits.get("individualLimit") is not None:
        keys = {"limit", "remainingPercent", "resetsAt", "used"}
        individual = bounded_object(rate_limits["individualLimit"], keys, keys)
        for key in ("limit", "used"):
            if type(individual[key]) is not str:
                invalid()
            nullable_text(individual[key], 64)
        integer(individual["remainingPercent"], 32)
        integer(individual["resetsAt"], 64)


def _runtime_warning(message: Mapping[str, object]) -> _CodexRuntimeWarning:
    if set(message) not in ({"method", "params"}, {"method", "params", "emittedAtMs"}):
        raise ValueError("codex_app_server_warning_invalid")
    if "emittedAtMs" in message and type(message["emittedAtMs"]) is not int:
        raise ValueError("codex_app_server_warning_invalid")
    params = _object(message.get("params"))
    if set(params) != {"message", "threadId"}:
        raise ValueError("codex_app_server_warning_invalid")
    if type(params.get("threadId")) is not str or type(params.get("message")) is not str:
        raise ValueError("codex_app_server_warning_invalid")
    return _CodexRuntimeWarning()


def _turn_failure(error: object) -> _CodexTurnFailure:
    source = _object(error)
    info = source.get("codexErrorInfo")
    if type(info) is str:
        if info in {"cyberPolicy", "misalignmentPolicyViolation"}:
            return _CodexTurnFailure("refused", SemanticFailureClass.AUTHORIZATION)
        if info in {"contextWindowExceeded", "badRequest"}:
            return _CodexTurnFailure("invalid", SemanticFailureClass.RESPONSE_CONTENT)
        if info in {"sessionBudgetExceeded", "usageLimitExceeded"}:
            return _CodexTurnFailure("unavailable", SemanticFailureClass.QUOTA_EXHAUSTED)
        if info == "rateLimitExceeded":
            # Codex names a native rate limit directly (since 0.157.1), as HTTP 429 is below.
            return _CodexTurnFailure("unavailable", SemanticFailureClass.RATE_LIMITED)
        if info == "unauthorized":
            return _CodexTurnFailure("unavailable", SemanticFailureClass.AUTHENTICATION)
        if info in {"flexUnavailable", "serverOverloaded", "internalServerError"}:
            return _CodexTurnFailure("unavailable", SemanticFailureClass.PROVIDER_OUTAGE)
    elif isinstance(info, Mapping):
        detail = next(
            (
                value
                for key, value in cast(Mapping[str, object], info).items()
                if key
                in {
                    "httpConnectionFailed",
                    "responseStreamConnectionFailed",
                    "responseStreamDisconnected",
                    "responseTooManyFailedAttempts",
                }
            ),
            None,
        )
        status = (
            cast(Mapping[str, object], detail).get("httpStatusCode")
            if isinstance(detail, Mapping)
            else None
        )
        if status == 429:
            return _CodexTurnFailure("unavailable", SemanticFailureClass.RATE_LIMITED)
        if status == 401:
            return _CodexTurnFailure("unavailable", SemanticFailureClass.AUTHENTICATION)
        if status == 403:
            return _CodexTurnFailure("unavailable", SemanticFailureClass.AUTHORIZATION)
        if type(status) is int and 500 <= status <= 599:
            return _CodexTurnFailure("unavailable", SemanticFailureClass.PROVIDER_OUTAGE)
    return _CodexTurnFailure("unavailable", SemanticFailureClass.TRANSPORT)


def _validate_predisclosure_notifications(runtime: _CodexProcess) -> None:
    for message in runtime.pending_notifications:
        _validate_predisclosure_notification(
            message, runtime_version=runtime.profile.runtime_version
        )
    runtime.pending_notifications.clear()


async def _close_predisclosure_window(runtime: _CodexProcess, timeout: float) -> None:
    """Inspect everything Codex has written so far, then every queued notification.

    A request's reply returns as soon as it is read, so an event, warning or server request
    Codex wrote right after that reply can still sit unread in the reader buffer. Codex writes
    stdout in order, so one zero-inference barrier request (``account/read`` without a token
    refresh) is answered only after every line already written: reading up to its reply queues
    each such notification and fails a server request at once. Every queued notification must
    then be inside the reviewed pre-disclosure allowlist. Nothing is disclosed before this
    returns; a native warning is raised as the bounded ``_CodexRuntimeWarning``.
    """

    await runtime.request(
        _PREDISCLOSURE_BARRIER_REQUEST_ID, "account/read", {"refreshToken": False}, timeout
    )
    _validate_predisclosure_notifications(runtime)


async def _interrupt(runtime: _CodexProcess, thread_id: str, turn_id: str) -> None:
    try:
        await runtime.request(
            99,
            "turn/interrupt",
            {"threadId": thread_id, "turnId": turn_id},
            0.5,
        )
    except Exception:
        return


# Adapter-raised tokens → closed ``RUNTIME_FAILURE_STAGES`` members. Every key is a literal this
# module raises itself; a token outside the map falls back to the exception family below.
_FAILURE_STAGE_BY_TOKEN: Final[Mapping[str, str]] = {
    "codex_runtime_capability_time_invalid": "capability_evidence_stale",
    "codex_runtime_capability_evidence_stale": "capability_evidence_stale",
    "codex_runtime_version_mismatch": "initialize_invalid",
    "codex_home_mismatch": "initialize_invalid",
    "codex_login_required": "login_required",
    "codex_chatgpt_login_required": "login_required",
    "codex_model_unavailable": "model_unavailable",
    "codex_image_input_unavailable": "model_unavailable",
    "codex_reasoning_effort_unavailable": "model_unavailable",
    "codex_model_catalog_invalid": "model_unavailable",
    "codex_thread_isolation_unproven": "thread_invalid",
    "codex_app_server_predisclosure_event_forbidden": "predisclosure_event_forbidden",
    "codex_sandbox_unavailable_unreviewed_runtime": "predisclosure_event_forbidden",
    "codex_app_server_remote_control_state_invalid": "predisclosure_event_forbidden",
    "codex_app_server_remote_control_not_disabled": "predisclosure_event_forbidden",
    "codex_runtime_case_invalid": "case_invalid",
    "codex_reviewer_runtime_unreviewed": "capability_evidence_stale",
    "reviewer_schema_unavailable": "capability_evidence_stale",
    "codex_reviewer_session_unknown": "case_invalid",
    "reviewer_exchange_invalid": "case_invalid",
    "reviewer_reply_not_object": "output_not_json",
    "codex_turn_ack_invalid": "turn_ack_invalid",
    "codex_app_server_tool_request_forbidden": "tool_request_forbidden",
    "codex_app_server_event_forbidden": "event_forbidden",
    "codex_app_server_tool_event_forbidden": "tool_event_forbidden",
    "codex_app_server_rate_limits_invalid": "rate_limits_invalid",
    "codex_app_server_token_usage_invalid": "token_usage_invalid",
    "codex_app_server_warning_invalid": "runtime_warning",
    "codex_app_server_completion_invalid": "completion_mismatch",
    "codex_app_server_agent_message_count": "agent_message_count",
    "codex_app_server_output_empty": "output_empty",
    "codex_app_server_output_oversize": "output_oversize",
    "codex_app_server_event_limit": "event_limit",
    "codex_app_server_request_failed": "request_failed",
    "codex_app_server_stdin_unavailable": "transport_failed",
    "codex_app_server_stdout_unavailable": "transport_failed",
    "codex_app_server_stderr_limit": "transport_failed",
    "codex_app_server_message_too_large": "transport_failed",
    "codex_app_server_message_invalid": "transport_failed",
    "semantic_judgment_invalid": "judgment_invariant_invalid",
}


def _visible_output_tokens(usage: RuntimeTokenUsage) -> int:
    """Output tokens outside the reasoning subset: the judgment the runtime emitted."""

    return usage.output_tokens - usage.reasoning_output_tokens


def _failure_stage(error: Exception, *, turn_acknowledged: bool, launched: bool) -> str:
    """Name the closed stage at which one attempt stopped, from the exception family only.

    Only the adapter's own literal tokens and exception types are consulted; provider text never
    reaches the token, and an unrecognized shape is reported as ``unclassified``.
    """

    if isinstance(error, _CodexTurnFailure):
        stage = error.stage
    elif isinstance(error, _CodexRuntimeWarning):
        stage = "runtime_warning"
    elif isinstance(error, JudgmentValidationError):
        stage = f"judgment_{error.stage}"
    elif isinstance(error, ProtocolValueError):
        stage = "output_not_json" if turn_acknowledged else "case_invalid"
    elif isinstance(error, PermissionError):
        stage = _FAILURE_STAGE_BY_TOKEN.get(str(error), "login_required")
    elif isinstance(error, TimeoutError):
        stage = "deadline_expired"
    elif isinstance(error, ValueError):
        stage = _FAILURE_STAGE_BY_TOKEN.get(str(error), "unclassified")
    elif isinstance(error, OSError) and not launched:
        stage = "launch_failed"
    else:
        stage = "unclassified"
    if stage not in RUNTIME_FAILURE_STAGES:
        raise RuntimeError("codex_failure_stage_registry_incomplete")
    return stage


def _classify_runtime_exception(
    error: Exception, *, turn_acknowledged: bool
) -> tuple[
    Literal["timeout", "post_ack_unknown", "invalid", "refused", "unavailable"],
    SemanticFailureClass,
]:
    if isinstance(error, _CodexTurnFailure):
        return error.outcome, error.failure_class
    if isinstance(error, PermissionError):
        return "unavailable", SemanticFailureClass.AUTHENTICATION
    if isinstance(error, TimeoutError):
        return (
            ("post_ack_unknown", SemanticFailureClass.TRANSPORT)
            if turn_acknowledged
            else ("timeout", SemanticFailureClass.TIMEOUT)
        )
    if isinstance(error, ValueError) and not isinstance(error, _CodexRuntimeWarning):
        stage = _failure_stage(error, turn_acknowledged=turn_acknowledged, launched=True)
        if turn_acknowledged and (
            stage.startswith(("output_", "judgment_"))
            or stage in {"completion_mismatch", "agent_message_count"}
        ):
            return "invalid", SemanticFailureClass.RESPONSE_SCHEMA
        if stage not in {
            "transport_failed",
            "request_failed",
            "event_limit",
            "runtime_warning",
            "unclassified",
        }:
            return "unavailable", SemanticFailureClass.UNSUPPORTED_PROFILE
    return (
        ("post_ack_unknown", SemanticFailureClass.TRANSPORT)
        if turn_acknowledged
        else ("unavailable", SemanticFailureClass.TRANSPORT)
    )


@dataclass(eq=False, slots=True)
class _ReviewerThread:
    """The Codex thread one review holds between exchanges, in its ``ReviewerSession`` only."""

    profile: CodexAppServerProfile
    runtime: _CodexProcess
    thread_id: str
    auth_mode: Literal["chatgpt"] | None
    plan_type: str | None
    token_usage: RuntimeTokenUsage | None
    # The histories a next exchange may extend: the thread with its answer, and, after an answer
    # the loop's decoder rejected and left out of its history, the same thread before that answer.
    prefixes: tuple[tuple[ReviewerMessage, ...], ...]
    # Whether ``token_usage`` is the thread's total after its last turn: that turn reported usage
    # and none of it was refused. Only then can the next turn's own usage be told apart (#1172).
    usage_current: bool

    async def aclose(self) -> str:
        return await _cleanup_guaranteed(self.runtime)


@dataclass(slots=True)
class CodexAppServerEvaluator:
    profile: CodexAppServerProfile
    binding: ProviderAttemptAuthBinding
    authority: ExternalRuntimeAuthority
    clock: ClockPort
    # ``None`` is the legacy single-effort selection (the final profile).
    budget: CodexReviewBudget | None = None
    reply_schemas: ReviewerReplySchemas | None = None

    async def evaluate(self, case: ApprovedProviderCase, deadline: Deadline) -> SemanticResult:
        """One attempt; a reviewer exchange runs under its review's session lock (#1118 unit 3)."""

        session = CURRENT_REVIEWER_SESSION.get()
        if session is None:
            return await self._evaluate(case, deadline, None)
        async with session.lock:
            return await self._evaluate(case, deadline, session)

    async def _evaluate(
        self, case: ApprovedProviderCase, deadline: Deadline, session: ReviewerSession | None
    ) -> SemanticResult:
        if (
            type(case) is not ApprovedOutboundCase
            or type(deadline) is not Deadline
            or self.binding.dispatch_id != self.authority.dispatch_id
            or self.binding.request_body_digest != self.authority.request_body_digest
            or self.authority.request_body_digest != _sha256_bytes(case.payload)
            or self.binding.service_generation != self.authority.service_generation
            or self.binding.monotonic_deadline != self.authority.monotonic_deadline
            or deadline.monotonic_deadline != self.authority.monotonic_deadline
        ):
            raise ValueError("codex_runtime_attempt_binding_invalid")
        budget = (
            self.profile.review_budget(LEGACY_SEMANTIC_BUDGET_PROFILE)
            if self.budget is None
            else self.budget
        )
        if type(budget) is not CodexReviewBudget:
            raise ValueError("codex_runtime_attempt_binding_invalid")

        started = self.clock.monotonic_seconds()
        events = _TurnEvents()
        runtime: _CodexProcess | None = None
        auth_mode: Literal["chatgpt"] | None = None
        plan_type: str | None = None
        case_disclosed = False
        turn_acknowledged = False
        thread_id: str | None = None
        turn_id: str | None = None
        judgment = None
        final_output_sha256: str | None = None
        token_usage: RuntimeTokenUsage | None = None
        failure: (
            Literal["timeout", "post_ack_unknown", "invalid", "refused", "unavailable"] | None
        ) = None
        failure_class = SemanticFailureClass.UNSUPPORTED_PROFILE
        failure_stage: str | None = None
        raw_size = 0
        exchange = None
        held: _ReviewerThread | None = None
        reply: dict[str, JsonValue] | None = None
        instruction_sha256 = _INSTRUCTION_SHA256
        output_schema = _CODEX_JUDGMENT_JSON_SCHEMA
        instructions = SEMANTIC_REVIEW_INSTRUCTION
        turn_texts: tuple[str, ...] | None = None
        turn_completed = False
        # Prompt-cache telemetry (#1172): what this turn sent beside its messages, the model
        # requests it made, the first one's cached input and the last one's input.
        turn_settings: dict[str, JsonValue] | None = None
        turn_start_usage: RuntimeTokenUsage | None = None
        # The thread's total before this turn's first reported request: that snapshot's total less
        # its own ``last``. It is the turn's start when the previous turn left no current total.
        first_request_start: _CacheCounters | None = None
        requests = first_cached = last_input = 0
        compacted = usage_refused = False
        try:
            exchange = reviewer_exchange(case.media_type, case.payload, self.reply_schemas)
            if exchange is not None:
                # One reviewer-loop exchange (#1118 unit 3). Only a reviewed release runs it.
                instructions = exchange.history[0][1]
                instruction_sha256 = exchange.prompt_digest
                output_schema = cast(
                    dict[str, JsonValue], _codex_output_schema(cast(JsonValue, exchange.schema))
                )
            self.profile.verify_capability_evidence(self.clock.now_utc())
            if exchange is not None:
                if self.profile.runtime_version not in REVIEWER_LOOP_REVIEWED_RELEASES:
                    raise ValueError("codex_reviewer_runtime_unreviewed")
                # The review's own session, never transcript content, selects the thread; the
                # history must extend exactly what that thread holds, on the same profile.
                held_any = None if session is None else session.held
                held = held_any if isinstance(held_any, _ReviewerThread) else None
                # A new thread takes every user message after the instruction (the packet, then
                # the read catalog). A continuation adds the user messages after the longest
                # history the thread holds: the new read result or repair notice, and before the
                # final turn the loop's final-phase notice (#1172, #1173), each its own text input.
                prefix = (
                    None
                    if held is None
                    else max(
                        (p for p in held.prefixes if exchange.history[: len(p)] == p),
                        key=len,
                        default=None,
                    )
                )
                sent = exchange.history[1:] if prefix is None else exchange.history[len(prefix) :]
                if (
                    session is None
                    or session.closed
                    or session.deadline != deadline
                    or held is not held_any
                    or not sent
                    # At most a read result or repair notice, then the final-phase notice.
                    or (held is not None and len(sent) > 2)
                    or any(role != "user" for role, _ in sent)
                    or (held is not None and held.profile != self.profile)
                    or (held is not None and prefix is None)
                    # A review opens exactly one thread: once its thread is gone, a repair or
                    # continuation must never reopen the conversation and resend the packet.
                    or (held is None and session.opened)
                ):
                    raise ValueError("codex_reviewer_session_unknown")
                turn_texts = tuple(text for _, text in sent)
                if held is not None:
                    session.held = None  # this turn owns the runtime until it retains it again
                    runtime, thread_id = held.runtime, held.thread_id
                    auth_mode, plan_type = held.auth_mode, held.plan_type
                    token_usage = held.token_usage
            if held is None:
                if exchange is not None and session is not None:
                    session.opened = True
                await report_semantic_progress(SemanticProgressPhase.RUNTIME_STARTING)
                # A launch cancelled by the deadline cleans up its own process (``_launch``).
                runtime = await asyncio.wait_for(
                    _launch(self.profile), _remaining(deadline, self.clock)
                )
                await _initialize(runtime, self.profile, _remaining(deadline, self.clock))
                await report_semantic_progress(SemanticProgressPhase.ACCOUNT_MODEL_VALIDATION)
                account_result = await runtime.request(
                    1,
                    "account/read",
                    {"refreshToken": False},
                    _remaining(deadline, self.clock),
                )
                auth_mode, plan_type = _account(account_result)
                await _require_model(
                    runtime,
                    self.profile,
                    _remaining(deadline, self.clock),
                    (budget.reasoning_effort,),
                )
                thread_result = await runtime.request(
                    30,
                    "thread/start",
                    _thread_start_params(
                        runtime,
                        self.profile,
                        instructions,
                    ),
                    _remaining(deadline, self.clock),
                )
                thread_id = _validate_thread(runtime, self.profile, thread_result)
                await _close_predisclosure_window(runtime, _remaining(deadline, self.clock))
            assert runtime is not None and thread_id is not None
            case_texts = (
                (case.payload.decode("utf-8", errors="strict"),)
                if turn_texts is None
                else turn_texts
            )
            strict_json_parse(case.payload)
            # Everything a turn sends beside its input. It stays the same on every turn of a
            # review, so the provider can serve the thread's earlier context from its cache.
            turn_settings = {
                "approvalPolicy": "never",
                "approvalsReviewer": "user",
                "effort": budget.reasoning_effort,
                "model": self.profile.model,
                "outputSchema": output_schema,
                "personality": "none",
                "sandboxPolicy": {"type": "readOnly", "networkAccess": False},
                "summary": "none",
            }
            turn_start_usage = token_usage
            events.wire_seen = getattr(runtime, "received_bytes", 0)
            inputs = [
                part
                for text in case_texts
                for part in (
                    (
                        image_message(text, "codex")
                        if exchange is not None and held is not None
                        else None
                    )
                    or [{"type": "text", "text": text}]
                )
            ]
            if any(isinstance(part, dict) and part.get("type") == "image" for part in inputs):
                await _require_model(
                    runtime,
                    self.profile,
                    _remaining(deadline, self.clock),
                    (budget.reasoning_effort,),
                    require_images=True,
                )
            case_disclosed = True
            turn_result = await runtime.request(
                31 if exchange is None else 100 + len(exchange.history),
                "turn/start",
                {
                    **turn_settings,
                    "input": inputs,
                    "threadId": thread_id,
                },
                _remaining(deadline, self.clock),
            )
            turn = _object(turn_result.get("turn"))
            turn_id = cast(str | None, turn.get("id"))
            if type(turn_id) is not str or not turn_id or turn.get("status") != "inProgress":
                raise ValueError("codex_turn_ack_invalid")
            turn_acknowledged = True
            await report_semantic_progress(SemanticProgressPhase.PROVIDER_SAMPLING)

            # Codex tags each agent message as interim ``commentary``, a ``partial_answer`` or the
            # ``final_answer``. The first two are text the constrained-output schema never
            # governs; they are discarded unread. Legacy models omit the phase, so untagged
            # messages are kept as the fallback candidate set. Exactly one candidate must remain.
            final_texts: list[str] = []
            untagged_texts: list[str] = []
            messages = runtime.pending_notifications
            runtime.pending_notifications = deque()
            while True:
                remaining = _remaining(deadline, self.clock)
                message = messages.popleft() if messages else await runtime.read(remaining)
                events.account(message, getattr(runtime, "received_bytes", 0))
                method = message.get("method")
                if "method" in message and "id" in message:
                    _record_forbidden_event("codex_app_server_tool_request_forbidden", method)
                    raise ValueError("codex_app_server_tool_request_forbidden")
                if method == "thread/compacted":
                    compacted = True  # recorded even where the reviewer refuses it below
                if (
                    type(method) is not str
                    or method not in _ALLOWED_NOTIFICATION_METHODS
                    or (exchange is not None and method in _REVIEWER_FORBIDDEN_METHODS)
                ):
                    _record_forbidden_event("codex_app_server_event_forbidden", method)
                    raise ValueError("codex_app_server_event_forbidden")
                if method == "account/rateLimits/updated":
                    try:
                        _discard_rate_limits_notification(message)
                    except ValueError:
                        # Bookkeeping cannot overrule the eventual answer or authoritative
                        # native error. Keep only this closed diagnostic; a terminal failure
                        # below replaces it. Byte/work and deadline bounds still apply.
                        failure_stage = "rate_limits_invalid"
                    continue
                if method == "thread/tokenUsage/updated":
                    try:
                        observed = _runtime_token_usages_from_notification(
                            message, thread_id=thread_id, turn_id=turn_id
                        )
                    except ValueError:
                        # Usage is telemetry only. A malformed active-turn snapshot must not
                        # turn an otherwise valid AI-powered judgment into a provider failure, and
                        # it must not erase a valid earlier cumulative snapshot.
                        failure_stage = "token_usage_invalid"
                        usage_refused = True
                    else:
                        observed_usage, request_usage = (
                            (None, None) if observed is None else observed
                        )
                        if observed_usage is not None and request_usage is not None:
                            # ``total`` is cumulative for the isolated thread. Replace the
                            # snapshot instead of summing repeated updates or adding ``last``.
                            if token_usage is not None and any(
                                new < old
                                for new, old in zip(
                                    (
                                        observed_usage.input_tokens,
                                        observed_usage.cached_input_tokens,
                                        observed_usage.cache_write_input_tokens,
                                        observed_usage.output_tokens,
                                        observed_usage.reasoning_output_tokens,
                                        observed_usage.total_tokens,
                                    ),
                                    (
                                        token_usage.input_tokens,
                                        token_usage.cached_input_tokens,
                                        token_usage.cache_write_input_tokens,
                                        token_usage.output_tokens,
                                        token_usage.reasoning_output_tokens,
                                        token_usage.total_tokens,
                                    ),
                                    strict=True,
                                )
                            ):
                                failure_stage = "token_usage_invalid"
                                usage_refused = True
                            else:
                                if observed_usage.input_tokens > (
                                    0 if token_usage is None else token_usage.input_tokens
                                ):
                                    # A total that grew is one more model request; a repeated
                                    # snapshot (a rate-limit refresh) is not.
                                    requests += 1
                                    if requests == 1:
                                        first_cached = request_usage.cached_input_tokens
                                        first_request_start = _start_before_request(
                                            observed_usage, request_usage
                                        )
                                    last_input = request_usage.input_tokens
                                token_usage = observed_usage
                                if _visible_output_tokens(token_usage) > budget.output_limit:
                                    # The app-server protocol has no per-turn output ceiling, so
                                    # the selected limit is enforced on the runtime's own
                                    # cumulative counters; the turn is interrupted below.
                                    raise ValueError("codex_app_server_output_oversize")
                    continue
                if method == "warning":
                    raise _runtime_warning(message)
                if method == "error":
                    params = _object(message.get("params"))
                    raise _turn_failure(params.get("error"))
                if method == "model/rerouted":
                    # The bound model did not answer; the provenance this attempt would record
                    # is no longer true, so the turn ends here without reading the reroute body.
                    raise _CodexTurnFailure(
                        "refused", SemanticFailureClass.AUTHORIZATION, stage="model_rerouted"
                    )
                if method in {"item/started", "item/completed"}:
                    item_type, text, phase = _notification_item(message)
                    compacted = compacted or item_type == "contextCompaction"
                    if item_type not in _ALLOWED_ITEM_TYPES:
                        _record_forbidden_event(
                            "codex_app_server_tool_event_forbidden", method, item_type
                        )
                        raise ValueError("codex_app_server_tool_event_forbidden")
                    if exchange is not None and item_type not in _REVIEWER_ITEM_TYPES:
                        _record_forbidden_event(
                            "codex_app_server_event_forbidden", method, item_type
                        )
                        raise ValueError("codex_app_server_event_forbidden")
                    if method == "item/completed" and item_type == "agentMessage":
                        if phase is not None and phase not in _AGENT_MESSAGE_PHASES:
                            raise ValueError("codex_app_server_event_forbidden")
                        if phase in _NON_FINAL_PHASES:
                            continue
                        # An empty answer is still an answer: it is judged only after the
                        # matching ``turn/completed`` proves the turn ended, so a completed empty
                        # turn keeps its thread for the loop's one repair (#1118 V1).
                        (final_texts if phase == "final_answer" else untagged_texts).append(
                            text or ""
                        )
                if method != "turn/completed":
                    continue
                await report_semantic_progress(SemanticProgressPhase.RESPONSE_VALIDATION)
                params = _object(message.get("params"))
                completed = _object(params.get("turn"))
                if params.get("threadId") != thread_id or completed.get("id") != turn_id:
                    raise ValueError("codex_app_server_completion_invalid")
                if completed.get("status") != "completed" or completed.get("error") is not None:
                    raise _turn_failure(completed.get("error"))
                turn_completed = True
                if deadline.expired(self.clock.monotonic_seconds()):
                    raise TimeoutError  # an answer after the review's deadline is never used
                candidates = final_texts if final_texts else untagged_texts
                if len(candidates) != 1:
                    raise ValueError("codex_app_server_agent_message_count")
                raw = candidates[0]
                if not raw:
                    raise ValueError("codex_app_server_output_empty")
                raw_size = len(raw.encode("utf-8"))
                if raw_size > _MAX_MESSAGE_BYTES:
                    raise ValueError("codex_app_server_output_oversize")
                raw_bytes = raw.encode("utf-8")
                final_output_sha256 = _sha256_bytes(raw_bytes)
                if exchange is None:
                    judgment = normalize_judgment(strict_json_parse(raw_bytes), require_part2=True)
                else:
                    # Only the completed final message is a reply; the loop decodes its branch.
                    parsed = strict_json_parse(raw_bytes)
                    if type(parsed) is not dict:
                        raise ValueError("reviewer_reply_not_object")
                    reply = cast(dict[str, JsonValue], parsed)
                break
        except Exception as error:  # noqa: BLE001 - no foreign native exception crosses boundary
            failure, failure_class = _classify_runtime_exception(
                error, turn_acknowledged=turn_acknowledged
            )
            failure_stage = _failure_stage(
                error, turn_acknowledged=turn_acknowledged, launched=runtime is not None
            )
        finally:
            if (
                exchange is not None
                and session is not None
                and not session.closed
                and runtime is not None
                and thread_id is not None
                and turn_completed
                and failure in (None, "invalid")
            ):
                # Only a completed turn keeps the thread in its review's session for the next
                # exchange (never a cancelled or timed-out one); the session closes it on every exit.
                prefixes: tuple[tuple[ReviewerMessage, ...], ...] = (exchange.history,)
                if reply is not None:
                    answer = ("assistant", canonical_encode(reply).decode())
                    prefixes = ((*exchange.history, answer), exchange.history)
                session.held = _ReviewerThread(
                    self.profile,
                    runtime,
                    thread_id,
                    auth_mode,
                    plan_type,
                    token_usage,
                    prefixes,
                    requests > 0 and not usage_refused,
                )
                cleanup = "retained"
            else:
                try:
                    try:
                        if runtime is not None:
                            await report_semantic_progress(SemanticProgressPhase.CLEANUP)
                    finally:
                        if (
                            runtime is not None
                            and thread_id is not None
                            and turn_id is not None
                            and failure
                        ):
                            await _interrupt(runtime, thread_id, turn_id)
                finally:
                    cleanup = await _cleanup_guaranteed(runtime)

        record_bounded_counts_without_raising(
            component="codex_app_server",
            operation="turn_notifications",
            outcome="completed" if turn_completed else "incomplete",
            counts={
                **events.counts,
                "duration_ms": max(0, int((self.clock.monotonic_seconds() - started) * 1000)),
            },
        )
        if turn_settings is not None:
            # A new thread starts at zero, and a continuation at the total its previous turn left.
            # When that turn reported nothing or had a snapshot refused, that total is stale, so
            # the turn starts at the total before its own first reported request: it still records
            # its own requests, never the thread's earlier ones. A turn that had a snapshot refused
            # may be missing a request, so it records no counts.
            start = first_request_start
            if held is None:
                start = _cache_counters(None)
            elif held.usage_current and turn_start_usage is not None:
                start = _cache_counters(turn_start_usage)
            record_exchange_cache(
                component="codex_app_server",
                request_id=case.request_id,
                session=session,
                exchange=exchange,
                settings=turn_settings,
                usage=(
                    None
                    if usage_refused
                    else _turn_cache_usage(start, token_usage, requests, first_cached, last_input)
                ),
                completed=turn_completed,
                compacted=compacted,
            )
        if cleanup == "failed" and failure is None:
            failure = "post_ack_unknown" if turn_acknowledged else "unavailable"
            failure_class = SemanticFailureClass.TRANSPORT
            failure_stage = "cleanup_unconfirmed"

        evidence = RuntimeAttemptEvidence(
            credential_authority="external_runtime_oauth",
            runtime_version=self.profile.runtime_version,
            runtime_source_identity=self.profile.source_identity,
            executable_sha256=self.profile.executable_sha256,
            app_server_schema_sha256=self.profile.app_server_schema_sha256,
            capability_cell_sha256=self.profile.capability_cell_sha256,
            capability_profile=self.profile.capability_profile,
            capability_evidence_expires_at=self.profile.capability_evidence_expires_at,
            # What this attempt's process actually launched with, frozen at its launch; only an
            # attempt that never launched reports the argv its profile would use now.
            launcher_sha256=(
                runtime.launcher_sha256
                if isinstance(runtime, _CodexProcess) and runtime.launcher_sha256 is not None
                else self.profile.launcher_sha256
            ),
            isolated_config_sha256=self.profile.isolated_config_sha256,
            disclosed_case_sha256=_sha256_bytes(case.payload),
            instruction_sha256=instruction_sha256,
            output_schema_sha256=canonical_digest(output_schema),
            selection_sha256=budget.selection_sha256(self.profile.model),
            upstream_body_observability="unavailable",
            auth_mode=auth_mode,
            plan_type=plan_type,
            reasoning_effort=budget.reasoning_effort,
            thread_id=thread_id,
            turn_id=turn_id,
            final_output_sha256=final_output_sha256,
            case_disclosed=case_disclosed,
            turn_acknowledged=turn_acknowledged,
            process_cleanup=cleanup,
            failure_stage=failure_stage,
            token_usage=token_usage,
        )
        latency_ms = max(0, int((self.clock.monotonic_seconds() - started) * 1000))
        status = (
            SemanticStatus.SUCCEEDED
            if failure is None
            else (
                SemanticStatus.TIMEOUT
                if failure == "timeout"
                else (
                    SemanticStatus.INVALID
                    if failure == "invalid"
                    else SemanticStatus.REFUSED
                    if failure == "refused"
                    else SemanticStatus.UNAVAILABLE
                )
            )
        )
        provenance = ProviderAttemptProvenance(
            provider=self.profile.provider_id,
            endpoint_profile_id=self.profile.endpoint_profile_id,
            endpoint_profile_version=self.profile.endpoint_profile_version,
            model=self.profile.model,
            sdk_version=f"codex-app-server-{self.profile.runtime_version}",
            prompt_digest=instruction_sha256,
            schema_digest=canonical_digest(output_schema),
            policy_digest=case.policy_digest,
            privacy_policy_digest=case.policy_digest,
            sampling_params=SamplingParams(budget.output_limit),
            latency_ms=latency_ms,
            status=status,
            provider_request_id=turn_id,
            token_usage=None if token_usage is None else token_usage.aggregate,
            failure_class=None if failure is None else failure_class,
            runtime_evidence=evidence,
        )
        if failure is None and reply is not None:
            return SemanticResultReply(reply, provenance)
        if failure is None:
            assert judgment is not None
            return SemanticResultSuccess(judgment, provenance)
        if failure == "timeout":
            return SemanticResultTimeout(provenance)
        if failure == "invalid":
            return SemanticResultInvalid(provenance, raw_size=raw_size)
        if failure == "refused":
            return SemanticResultRefused(provenance)
        return SemanticResultUnavailable(provenance)


@dataclass
class CodexAppServerExternalFactory:
    profile: CodexAppServerProfile
    clock: ClockPort
    credential_authority: Literal["external_runtime_oauth"] = "external_runtime_oauth"
    reply_schemas: ReviewerReplySchemas | None = None

    def __post_init__(self) -> None:
        self._last_case_digest: str | None = None
        self.profile.verify_local_binding()

    def render(self, case: ApprovedOutboundCase) -> bytes:
        if type(case) is not ApprovedOutboundCase:
            raise TypeError("codex_runtime_case_invalid")
        strict_json_parse(case.payload)
        self._last_case_digest = _sha256_bytes(case.payload)
        return case.payload

    def build_evaluator(
        self,
        binding: ProviderAttemptAuthBinding,
        credential: object,
        request_commitment: RequestCommitment,
    ) -> SemanticEvaluatorPort:
        if (
            type(credential) is not ExternalRuntimeAuthority
            or type(request_commitment) is not RequestCommitment
            or self._last_case_digest is None
            or binding.dispatch_id != credential.dispatch_id
            or binding.request_body_digest != self._last_case_digest
            or credential.request_body_digest != self._last_case_digest
            or binding.service_generation != credential.service_generation
            or binding.monotonic_deadline != credential.monotonic_deadline
            or request_commitment.commitment != credential.request_commitment
        ):
            raise ValueError("codex_runtime_factory_render_required")
        # The service composition exposes the check's frozen budget profile for exactly this
        # dispatch; anything dispatched outside a check keeps the legacy final selection.
        budget = self.profile.review_budget(
            current_semantic_budget_profile(), background=current_semantic_background()
        )
        return CodexAppServerEvaluator(
            self.profile,
            binding,
            credential,
            self.clock,
            budget,
            reply_schemas=self.reply_schemas,
        )


def codex_factory_builders_from_config(
    config: ExternalRuntimeProfileConfig | None, *, clock: ClockPort
) -> dict[ProviderBinding, object]:
    if config is None:
        return {}
    binding = codex_binding_from_config(config)

    def _builder() -> CodexAppServerExternalFactory:
        return CodexAppServerExternalFactory(
            CodexAppServerProfile.from_config(config), clock, reply_schemas=REVIEWER_REPLY_SCHEMAS
        )

    return {binding: _builder}
