"""Closed, nonsecret summary contract for ``finishup ai status`` (issue #1119)."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AIStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)

    schema_tag: Literal["finishup.ai-status/1"] = Field(alias="schema")
    review_mode: (
        Literal["local_only", "local_agent_opt_in", "local_owner_approval", "ai_powered"] | None
    )
    reviewer: str | None
    model: str | None
    key_stored: bool | None
    privacy_permits_sending: bool | None
