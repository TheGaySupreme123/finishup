"""Closed read-only setup status contract (issue #789)."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

type Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
type SetupHost = Literal["codex", "claude", "cursor-ide", "cursor-cli"]
type RegistrationState = Literal["absent", "yoetz_owned", "foreign_present"]
type RouteProfile = Literal["policy", "strict"]
type RegistrationError = Literal[
    "confirmation_required",
    "preview_stale",
    "harness_unavailable",
    "parse_failed",
    "timeout",
    "registration_failed",
    "foreign_entry_present",
    "isolation_invalid",
]
type CueSource = Literal[
    "plugin_hooks", "user_settings", "project_settings", "project_local_settings"
]


class SetupPluginActivation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    reason: Literal["codex_home_required"]
    state: Literal["unknown"]


class SetupDiscoveredBinary(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    compatibility: Literal["supported", "untested"]
    executable_path: str
    harness: SetupHost
    plugin_activation: SetupPluginActivation
    registered_route_profile: RouteProfile | None
    registration_error: RegistrationError | None = None
    registration_state: RegistrationState | None
    reported_version: str | None


class SetupActivationCues(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    cue_sources: list[CueSource]
    host_profile: Literal["generic", "claude"] | None
    mcp_mode: Literal["plugin_managed", "bare_mcp", "dual", "absent", "foreign", "ambiguous"]
    mcp_source: Literal["local", "project", "user", "plugin", "claude_ai_connector"] | None
    notes: list[
        Literal[
            "cue_presence_does_not_prove_hook_ran",
            "file_observation_only",
            "plugin_hooks_require_enabled_plugin",
        ]
    ]
    route_profile: RouteProfile | None
    session_start_cue: Literal["installed", "absent", "unobserved"]


class SetupHostInstallation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    activation_cues: SetupActivationCues | None
    config_root: str
    connection_observed: Literal[False]
    executable: str
    host: SetupHost
    label: str
    support: Literal["supported", "untested"]
    version: str | None


class SetupHooksStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    presence: Literal["absent", "installed_untrusted_unknown", "installed"]
    trust_observable: bool
    trust_state: Literal["observable", "unknown"]


class SetupPluginStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    digest: Digest | None
    presence: Literal["absent", "installed_untrusted_unknown", "installed", "unknown"]
    reason: str | None = None


class SetupSkillStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    automatic_activation_tested: bool
    compatibility: Literal["supported", "unsupported"]
    installed_digest: Digest | None
    presence: Literal[
        "absent", "installed_exact", "modified", "partial", "incompatible", "unsafe", "unknown"
    ]
    source_state: str
    tested_profiles: list[str]


class SetupIntegrationStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    hooks: SetupHooksStatus
    plugin: SetupPluginStatus
    skill: SetupSkillStatus


class SetupPlatformCell(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    cell: str | None
    certified: bool
    certified_cells: list[str]
    machine: str
    os_name: str


class SetupCheckSandbox(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    mechanism: str
    reason: str
    remediation: str
    status: Literal["ready", "unavailable"]


class SetupSecureStorage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    approved: bool
    backend_id: str
    reason: Literal["approved", "backend_not_approved", "keyring_unavailable"]
    requirement: str


class SetupPlatformStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    cell: SetupPlatformCell
    check_sandbox: SetupCheckSandbox
    secure_storage: SetupSecureStorage


class SetupServiceStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    reachable: bool
    state: Literal["starting", "locked", "unlocking", "ready", "draining", "failed"] | None
    vault_mode: Literal["uninitialized", "os_keyring", "passphrase"] | None


class SetupStatus(BaseModel):
    # Frozen legacy text (ADR-048): this docstring is the description of the released
    # setup-status 2.0.0 schema, so it keeps the command's pre-rename spelling. The command is
    # ``finishup setup status --json``; the legacy ``yoetz`` alias prints the same document.
    """The JSON emitted by ``yoetz setup status --json``."""

    model_config = ConfigDict(extra="forbid", strict=True)

    discovered: list[SetupDiscoveredBinary]
    hosts: list[SetupHostInstallation]
    integration: SetupIntegrationStatus
    marker_present: bool
    platform: SetupPlatformStatus
    schema_tag: Literal["yoetz.setup-status/2"] = Field(alias="schema")
    service: SetupServiceStatus
