"""Stable, concise discovery text for agents installing FinishUP."""

from __future__ import annotations

from typing import Final

__all__ = ["AGENT_START_GUIDE_URL", "AGENT_START_HANDOFF"]

AGENT_START_GUIDE_URL: Final = (
    "https://raw.githubusercontent.com/TheGaySupreme123/finishup/main/docs/usage/agent-start.md"
)
AGENT_START_HANDOFF: Final = (
    "Using an agentic tool? Setup questions require the user's own terminal.\n"
    f"Agent guide: {AGENT_START_GUIDE_URL}"
)
