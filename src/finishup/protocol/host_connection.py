"""Closed outer contracts for desktop connection previews and reports."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, RootModel

type Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
type Request = Annotated[
    str, Field(pattern=r"^req_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
]


class HostConnectionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_tag: Literal["yoetz.host-connection-plan/1"] = Field(alias="schema")
    request_id: Request
    host: Literal["codex", "claude", "cursor-ide", "cursor-cli"]
    host_version: str | None
    executable: str
    config_root: str
    project_root: str
    action: Literal["connect", "disconnect"]
    route_profile: Literal["strict", "policy"]
    preview_digest: Digest
    changes: list[str]
    connection_observed: Literal[False]
    requires_os_presence: bool | None = None
    warnings: list[str] | None = None
    launcher: list[str] | None = None
    isolation_root: str | None = None
    plugin_preview_digest: Digest | None = None
    marketplace_root: str | None = None
    cache_root: str | None = None
    state_before: str | None = None
    enabled_before: bool | None = None
    mcp_preview: dict[str, JsonValue] | None = None
    project_binding: Literal["mcp-roots", "registered-project"] | None = None
    scope: str | None = None
    create_config_root: bool | None = None
    codex_plan: dict[str, JsonValue] | None = None
    mcp_preview_digest: Digest | None = None
    skill_preview_digest: Digest | None = None
    retained: list[str] | None = None


class HostConnectionReport(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_tag: Literal["yoetz.host-connection-report/1"] = Field(alias="schema")
    host: str
    action: Literal["connect", "disconnect"]
    connection_observed: Literal[False]
    outcome: Literal["preview", "completed", "unchanged", "status", "incomplete"]
    plan: HostConnectionPlan | None = None
    status: dict[str, JsonValue] | None = None
    reason: str | None = None
    next_step: str | None = None
    launch: dict[str, JsonValue] | None = None


class HostConnectionContract(RootModel[HostConnectionPlan | HostConnectionReport]):
    pass
