"""Bounded owner requests that keep upcoming read observations individually.

Read protection is a retention hint.  It never grants content capture, privacy
egress, or a provider route.  The local store supplies the authorization and
session fences when constructing a :class:`ReadProtection`; hook payloads do
not supply either fence or the reference that caused the protection.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, cast

from finishup.domain.observation import (
    ObservationEnvelope,
    validate_observation_protection_reference,
)
from finishup.domain.values import (
    JsonObject,
    JsonValue,
    Timestamp,
    validate_commitment,
    validate_sha256_digest,
)
from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "DEFAULT_READ_PROTECTION_TTL_SECONDS",
    "MAX_READ_PROTECTION_COUNT",
    "MAX_READ_PROTECTIONS",
    "ReadProtection",
    "read_protection_from_json",
    "read_protection_to_json",
    "read_protection_attempt_identity",
    "validate_read_protection_reference",
]


MAX_READ_PROTECTION_COUNT: Final = 32
"""Maximum outstanding logical reads covered by one workspace state."""

MAX_READ_PROTECTIONS: Final = 32
"""Maximum active reference scopes retained in one workspace state."""

DEFAULT_READ_PROTECTION_TTL_SECONDS: Final = 10 * 60
"""Default and maximum lifetime of an explicit read-protection request."""

_MAX_CONSUMED_IDENTITIES: Final = MAX_READ_PROTECTION_COUNT
_MAX_REFERENCE_LENGTH: Final = 40
_MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991


def validate_read_protection_reference(value: object) -> str:
    """Validate one existing-or-future obligation, claim, or finding id.

    The reference is deliberately syntax-checked only.  Protection may be
    requested before a later claim exists, so the local hook boundary must not
    query or infer a task projection here.
    """

    if type(value) is not str or not value or len(value) > _MAX_REFERENCE_LENGTH:
        raise ProtocolValueError("invalid_event_value_type")
    return validate_observation_protection_reference(value)


@dataclass(frozen=True, slots=True)
class ReadProtection:
    """One bounded reference scope tied to consent and a host-session generation."""

    reference: str
    session_commitment: str
    auth_generation: str
    session_generation: int
    remaining: int
    expires_at: Timestamp
    reserved_attempt_ids: tuple[str, ...] = ()
    consumed_attempt_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "reference", validate_read_protection_reference(self.reference))
        try:
            object.__setattr__(
                self, "session_commitment", validate_commitment(self.session_commitment)
            )
            validate_sha256_digest(self.auth_generation)
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise ProtocolValueError("invalid_event_value_type") from exc
        if (
            type(self.auth_generation) is not str
            or type(self.session_generation) is not int
            or isinstance(self.session_generation, bool)
            or not 1 <= self.session_generation <= _MAX_SAFE_INTEGER
            or type(self.remaining) is not int
            or isinstance(self.remaining, bool)
            or not 0 <= self.remaining <= MAX_READ_PROTECTION_COUNT
            or type(self.expires_at) is not Timestamp
            or type(self.reserved_attempt_ids) is not tuple
            or len(self.reserved_attempt_ids) > _MAX_CONSUMED_IDENTITIES
            or self.remaining + len(self.reserved_attempt_ids) > MAX_READ_PROTECTION_COUNT
            or type(self.consumed_attempt_ids) is not tuple
            or len(self.consumed_attempt_ids) > _MAX_CONSUMED_IDENTITIES
            or any(
                type(identity) is not str
                or not identity
                or len(identity) > 128
                or not identity.isascii()
                for identity in (*self.reserved_attempt_ids, *self.consumed_attempt_ids)
            )
            or len(set(self.reserved_attempt_ids)) != len(self.reserved_attempt_ids)
            or len(set(self.consumed_attempt_ids)) != len(self.consumed_attempt_ids)
            or set(self.reserved_attempt_ids) & set(self.consumed_attempt_ids)
        ):
            raise ProtocolValueError("invalid_event_value_type")

    @property
    def active(self) -> bool:
        """Whether this scope still has a logical read to protect."""

        return self.remaining > 0 or bool(self.reserved_attempt_ids)

    def consumed(self, attempt_id: str) -> bool:
        return attempt_id in self.consumed_attempt_ids

    def reserved(self, attempt_id: str) -> bool:
        return attempt_id in self.reserved_attempt_ids

    def reserve(self, attempt_id: str) -> ReadProtection:
        """Reserve one exact native call before its post event arrives."""

        if type(attempt_id) is not str or not attempt_id or len(attempt_id) > 128:
            raise ProtocolValueError("invalid_event_value_type")
        if self.consumed(attempt_id) or self.reserved(attempt_id) or self.remaining <= 0:
            return self
        return ReadProtection(
            reference=self.reference,
            session_commitment=self.session_commitment,
            auth_generation=self.auth_generation,
            session_generation=self.session_generation,
            remaining=self.remaining - 1,
            expires_at=self.expires_at,
            reserved_attempt_ids=(*self.reserved_attempt_ids, attempt_id),
            consumed_attempt_ids=self.consumed_attempt_ids,
        )

    def consume(self, attempt_id: str) -> ReadProtection:
        """Return an immutable copy with one logical post accounted for."""

        if type(attempt_id) is not str or not attempt_id or len(attempt_id) > 128:
            raise ProtocolValueError("invalid_event_value_type")
        if self.consumed(attempt_id):
            return self
        if self.reserved(attempt_id):
            reserved = tuple(
                identity for identity in self.reserved_attempt_ids if identity != attempt_id
            )
            consumed = (*self.consumed_attempt_ids, attempt_id)
            return ReadProtection(
                reference=self.reference,
                session_commitment=self.session_commitment,
                auth_generation=self.auth_generation,
                session_generation=self.session_generation,
                remaining=self.remaining,
                expires_at=self.expires_at,
                reserved_attempt_ids=reserved,
                consumed_attempt_ids=consumed[-_MAX_CONSUMED_IDENTITIES:],
            )
        if self.remaining <= 0:
            return self
        consumed = (*self.consumed_attempt_ids, attempt_id)
        return ReadProtection(
            reference=self.reference,
            session_commitment=self.session_commitment,
            auth_generation=self.auth_generation,
            session_generation=self.session_generation,
            remaining=self.remaining - 1,
            expires_at=self.expires_at,
            reserved_attempt_ids=self.reserved_attempt_ids,
            consumed_attempt_ids=consumed[-_MAX_CONSUMED_IDENTITIES:],
        )


def read_protection_to_json(value: ReadProtection) -> JsonObject:
    """Encode only bounded structural protection facts."""

    if type(value) is not ReadProtection:
        raise ProtocolValueError("invalid_event_value_type")
    return JsonObject(
        {
            "reference": value.reference,
            "session_commitment": value.session_commitment,
            "auth_generation": value.auth_generation,
            "session_generation": value.session_generation,
            "remaining": value.remaining,
            "expires_at": value.expires_at.wire,
            "reserved_attempt_ids": value.reserved_attempt_ids,
            "consumed_attempt_ids": value.consumed_attempt_ids,
        }
    )


def read_protection_from_json(value: object) -> ReadProtection:
    """Decode one bounded protection row, rejecting malformed rows."""

    if not isinstance(value, Mapping):
        raise ProtocolValueError("invalid_event_value_type")
    row = cast(Mapping[str, JsonValue], value)
    raw_consumed = row.get("consumed_attempt_ids", ())
    raw_reserved = row.get("reserved_attempt_ids", ())
    if not isinstance(raw_reserved, (tuple, list)):
        raise ProtocolValueError("invalid_event_value_type")
    if not isinstance(raw_consumed, (tuple, list)):
        raise ProtocolValueError("invalid_event_value_type")
    reserved = tuple(
        item
        for item in cast(tuple[JsonValue, ...] | list[JsonValue], raw_reserved)
        if type(item) is str
    )
    consumed = tuple(
        item
        for item in cast(tuple[JsonValue, ...] | list[JsonValue], raw_consumed)
        if type(item) is str
    )
    if len(reserved) != len(raw_reserved) or len(consumed) != len(raw_consumed):
        raise ProtocolValueError("invalid_event_value_type")
    return ReadProtection(
        reference=row.get("reference"),  # type: ignore[arg-type]
        session_commitment=row.get("session_commitment"),  # type: ignore[arg-type]
        auth_generation=row.get("auth_generation"),  # type: ignore[arg-type]
        session_generation=row.get("session_generation"),  # type: ignore[arg-type]
        remaining=row.get("remaining"),  # type: ignore[arg-type]
        expires_at=Timestamp(row.get("expires_at")),  # type: ignore[arg-type]
        reserved_attempt_ids=reserved,
        consumed_attempt_ids=consumed,
    )


def read_protection_attempt_identity(envelope: ObservationEnvelope) -> str:
    """Derive an opaque, retry-stable logical-post identity from trusted envelope facts."""

    if type(envelope) is not ObservationEnvelope:
        raise ProtocolValueError("invalid_event_value_type")
    structural = envelope.structural_payload
    correlation: str | None = None
    for key in ("tool_call_id", "correlation_id", "parent_tool_call_id"):
        value = structural.get(key)
        if type(value) is str and value:
            correlation = value
            break
    identity: JsonValue = JsonObject(
        {
            "source": envelope.source.value,
            "session_commitment": envelope.session_commitment,
            "source_generation": envelope.cursor.source_generation,
            "logical_id": correlation if correlation is not None else envelope.source_identity,
        }
    )
    from finishup.protocol.canonical import canonical_digest

    return canonical_digest(identity)
