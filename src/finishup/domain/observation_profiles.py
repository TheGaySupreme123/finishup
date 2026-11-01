"""Versioned host observation profiles.

The native host adapters are allowed to widen their hook subscriptions only
when the exact rendered profile is selected.  Keeping these identifiers in a
small domain module gives the local consent gate and the service the same
closed vocabulary without importing either adapter (and without treating a
host payload's claimed version as trusted).
"""

from __future__ import annotations

from typing import Final

from finishup.protocol.errors import ProtocolValueError

CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID: Final = "claude-code-ordinary-observation-v1"
CLAUDE_CODE_ORDINARY_HOOK_MAPPING_VERSION: Final = "claude-code-hooks-ordinary-v2"
CURSOR_ORDINARY_OBSERVATION_PROFILE_ID: Final = "cursor-ordinary-observation-v1"
CURSOR_ORDINARY_HOOK_MAPPING_VERSION: Final = "cursor-hooks-ordinary-v1"

ORDINARY_CONTENT_CAPTURE_PROFILE_IDS: Final = frozenset(
    {
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    }
)


def validate_content_capture_profile(value: object) -> str:
    """Validate one known, versioned native-host content arm."""

    if type(value) is not str or value not in ORDINARY_CONTENT_CAPTURE_PROFILE_IDS:
        raise ProtocolValueError("invalid_event_value_type")
    return value


def is_content_capture_profile(value: object) -> bool:
    """Return whether ``value`` is one of the closed native profile identifiers."""

    return type(value) is str and value in ORDINARY_CONTENT_CAPTURE_PROFILE_IDS


def content_capture_profile_matches_source(source: object, profile: object) -> bool:
    """Bind a content arm to its native host source at the service boundary."""

    if source == "claude_hook":
        return profile == CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    if source == "cursor_hook":
        return profile == CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
    return False


__all__ = [
    "CLAUDE_CODE_ORDINARY_HOOK_MAPPING_VERSION",
    "CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID",
    "CURSOR_ORDINARY_HOOK_MAPPING_VERSION",
    "CURSOR_ORDINARY_OBSERVATION_PROFILE_ID",
    "ORDINARY_CONTENT_CAPTURE_PROFILE_IDS",
    "is_content_capture_profile",
    "content_capture_profile_matches_source",
    "validate_content_capture_profile",
]
