"""Privacy desired-state TOML encoding (ADR-014).

Desired-state files declare nonsecret policy intent. Apply maps onto existing
``propose`` / ``tighten`` / ``decide`` gates — file edits alone never widen egress.
"""

from __future__ import annotations

import tomllib
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Final, cast

from finishup.config.models import ConfigError
from finishup.domain.privacy import CredentialHeuristic, PrivacyPolicy
from finishup.domain.values import format_rfc3339_millis
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

__all__ = [
    "PRIVACY_DESIRED_SCHEMA",
    "load_privacy_desired_canonical",
    "render_privacy_desired_toml",
    "write_privacy_desired_toml",
]

# Frozen legacy identifier (ADR-048): the schema tag stored in existing desired-privacy files.
PRIVACY_DESIRED_SCHEMA: Final = "yoetz.privacy-desired/1"


def _to_json(value: object) -> object:
    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is bytes:
        return value.hex()
    if isinstance(value, Enum):
        return value.value
    if type(value) is datetime:
        return format_rfc3339_millis(value)
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _to_json(getattr(value, field.name))
            for field in fields(value)
            # ``credential_heuristic`` is written only when the owner turned it off (#982).
            if getattr(value, field.name) is not CredentialHeuristic.ENFORCED
        }
    if type(value) is tuple:
        return [_to_json(member) for member in cast(tuple[object, ...], value)]
    raise TypeError("privacy_desired_value_invalid")


def _escape_basic(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def render_privacy_desired_toml(policy: PrivacyPolicy) -> str:
    """Render durable nonsecret policy desired-state as a documented TOML document."""

    if type(policy) is not PrivacyPolicy:
        raise TypeError("privacy_desired_policy_invalid")
    payload = cast(dict[str, object], _to_json(policy))
    encoded = canonical_encode(cast(JsonValue, payload)).decode("utf-8")
    lines = [
        f'schema = "{PRIVACY_DESIRED_SCHEMA}"',
        "",
        "[privacy.desired]",
        f'policy_json = "{_escape_basic(encoded)}"',
        "",
        "# Ceremony note: editing this file never silently widens egress.",
        "# Run `finishup privacy apply-desired` — tighten may apply; widen requires decide.",
        "",
    ]
    return "\n".join(lines)


def write_privacy_desired_toml(policy: PrivacyPolicy, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_privacy_desired_toml(policy), encoding="utf-8")
    return path


def load_privacy_desired_canonical(path: Path) -> bytes:
    """Load desired-state TOML and return the embedded canonical policy JSON bytes."""

    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError("config_value_invalid") from exc
    if raw.get("schema") != PRIVACY_DESIRED_SCHEMA:
        raise ConfigError("config_schema_unsupported")
    section = raw.get("privacy")
    if type(section) is not dict:
        raise ConfigError("config_value_invalid")
    privacy = cast(dict[str, object], section)
    desired_raw = privacy.get("desired")
    if type(desired_raw) is not dict:
        raise ConfigError("config_value_invalid")
    desired = cast(dict[str, object], desired_raw)
    policy_json = desired.get("policy_json")
    if type(policy_json) is not str:
        raise ConfigError("config_value_invalid")
    try:
        parsed = strict_json_parse(policy_json.encode("utf-8"))
    except Exception as exc:
        raise ConfigError("config_value_invalid") from exc
    return canonical_encode(parsed)
