"""Per-check AI-powered review budget profile (issue #571, ADR-006 amendment).

A check's semantic review runs under exactly one closed budget profile. ``final`` covers a
frontier that carries an effective completion claim, and the closing review a check requests with
``final_review`` (issue #976); every other check is a ``routine`` checkpoint. The profile is a pure
function of the frozen case and the check request, is frozen into the durable
execution snapshot, and is exposed to the provider adapter only for the duration of one physical
dispatch. Adapters map it to their own configured effort and output limit; the profile itself
never widens disclosure, retention, provider authority, deadlines, or retry policy.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Final, Literal

from yoetz.kernel.claims import completion_claim_present
from yoetz.kernel.projections import ProjectionState

__all__ = [
    "LEGACY_SEMANTIC_BUDGET_PROFILE",
    "SEMANTIC_BUDGET_PROFILES",
    "SemanticBudgetProfile",
    "current_semantic_background",
    "current_semantic_budget_profile",
    "enter_semantic_budget_profile",
    "exit_semantic_budget_profile",
    "parse_semantic_budget_profile",
    "select_semantic_budget_profile",
    "semantic_background_scope",
    "semantic_budget_profile_scope",
]

type SemanticBudgetProfile = Literal["routine", "final"]

SEMANTIC_BUDGET_PROFILES: Final[tuple[SemanticBudgetProfile, ...]] = ("routine", "final")
# Unscoped dispatches (credential probes) and execution snapshots
# frozen before profiles existed keep the pre-#571 behavior: the binding's single configured
# effort, which is the final profile. Background observation advice explicitly uses routine.
LEGACY_SEMANTIC_BUDGET_PROFILE: Final[SemanticBudgetProfile] = "final"

_current_profile: ContextVar[SemanticBudgetProfile | None] = ContextVar(
    "semantic_budget_profile", default=None
)
# Background observation advice (#888) is advisory and never gates completion. Adapters that
# expose a reasoning effort select an explicit lower default for it when the owner configured no
# routine effort. Explicit ``check`` dispatches never enter this scope.
_background: ContextVar[bool] = ContextVar("semantic_budget_background", default=False)


def select_semantic_budget_profile(
    projection: ProjectionState, *, final_review: bool = False
) -> SemanticBudgetProfile:
    """Select the closed budget profile for one check from its frozen projection.

    ``final_review`` is the check request's closing-review choice (issue #976). The closing review
    is the final phase whether or not a completion claim is in effect: an agent that stops
    without claiming completion is still judged for completeness before it closes. The request
    is part of the check's idempotent request digest, so a recovered check selects the same
    profile.
    """

    if type(projection) is not ProjectionState or type(final_review) is not bool:
        raise TypeError("semantic_budget_projection_invalid")
    return "final" if final_review or completion_claim_present(projection) else "routine"


def parse_semantic_budget_profile(value: object) -> SemanticBudgetProfile:
    if value == "routine":
        return "routine"
    if value == "final":
        return "final"
    raise ValueError("semantic_budget_profile_invalid")


def enter_semantic_budget_profile(
    profile: SemanticBudgetProfile,
) -> Token[SemanticBudgetProfile | None]:
    """Expose one check's frozen profile to the provider adapter; pair with the exit call."""

    return _current_profile.set(parse_semantic_budget_profile(profile))


def exit_semantic_budget_profile(token: Token[SemanticBudgetProfile | None]) -> None:
    _current_profile.reset(token)


@contextmanager
def semantic_budget_profile_scope(profile: SemanticBudgetProfile) -> Generator[None]:
    """Expose one check's frozen profile to the provider adapter for one dispatch."""

    token = enter_semantic_budget_profile(profile)
    try:
        yield
    finally:
        exit_semantic_budget_profile(token)


def current_semantic_budget_profile() -> SemanticBudgetProfile:
    selected = _current_profile.get()
    return LEGACY_SEMANTIC_BUDGET_PROFILE if selected is None else selected


@contextmanager
def semantic_background_scope() -> Generator[None]:
    """Mark one dispatch as background advisory work for the provider adapter."""

    token = _background.set(True)
    try:
        yield
    finally:
        _background.reset(token)


def current_semantic_background() -> bool:
    return _background.get()
