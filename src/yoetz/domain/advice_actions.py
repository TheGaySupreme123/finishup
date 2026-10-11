"""Dependency-free advice action tokens.

Kept out of ``yoetz.kernel.policies.observation_advice`` (which imports pydantic through the event
models) so the ordinary hook path can read them without loading pydantic. The policy module
re-exports the name.
"""

from __future__ import annotations

from typing import Final

__all__ = ["STANDING_MACHINE_ACTIONS"]

# Next-action tokens naming conditions of the machine/installation, not of the
# work: the agent cannot discharge them, so evidence-sensitivity is the wrong
# redelivery trigger and they get a bounded cadence instead (#241).
# refresh_observation is deliberately excluded: it reflects live coverage
# degradation the agent should hear about once per distinct occurrence.
STANDING_MACHINE_ACTIONS: Final = frozenset(
    {"connect_provider", "renew_provider_sign_in", "repair_semantic_provider", "update_yoetz"}
)
