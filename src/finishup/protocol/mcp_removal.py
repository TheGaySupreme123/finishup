"""Versioned, payload-free outcome of an attempted external MCP removal."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel


class CompletedMcpRemoval(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_tag: Literal["yoetz.mcp-removal/1"] = Field(
        alias="schema", default="yoetz.mcp-removal/1"
    )
    outcome: Literal["completed"] = "completed"
    state_after: Literal["absent"] = "absent"
    warnings: list[Literal["host_remove_returned_nonzero"]] = Field(max_length=1)
    next_action: None = None


class UnverifiedMcpRemoval(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_tag: Literal["yoetz.mcp-removal/1"] = Field(
        alias="schema", default="yoetz.mcp-removal/1"
    )
    outcome: Literal["unverified"] = "unverified"
    state_after: Literal["yoetz_owned", "foreign_present"] | None
    warnings: list[Literal["host_remove_returned_nonzero"]] = Field(max_length=1)
    next_action: Literal["inspect_registration"] = "inspect_registration"


class McpRemovalContract(RootModel[CompletedMcpRemoval | UnverifiedMcpRemoval]):
    pass
