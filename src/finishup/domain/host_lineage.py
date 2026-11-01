"""Host-native subagent identity normalization.

Claude Code, Codex, and Cursor use different names for the identifiers around a
delegated worker.  This module owns the bounded value translation used at the
integration boundary.  It intentionally returns structural identifiers only: task creation,
acceptance, and annotation persistence belong to the service-owned lineage
coordinator.

The host supplied values are useful for correlation, but they are not an
authorship assertion.  Callers must therefore retain ``origin=host_observed``
and ``acceptance=pending`` until a service-side delegation or cooperative
self-registration binds the identity to a child task.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, cast

from finishup.domain.observation import ObservationEnvelope, ObservationSource
from finishup.domain.values import JsonObject, JsonValue
from finishup.protocol.canonical import canonical_digest

__all__ = [
    "HOST_LINEAGE_ACCEPTANCE",
    "HOST_LINEAGE_ORIGIN",
    "HostLineageCorrelation",
    "HostLineageHost",
    "HostLineageObservation",
    "HostLineagePhase",
    "host_lineage_from_envelope",
    "host_lineage_from_payload",
]

HostLineageHost = Literal["claude", "codex", "cursor"]
HostLineagePhase = Literal["start", "stop"]

HOST_LINEAGE_ORIGIN: Final = "host_observed"
HOST_LINEAGE_ACCEPTANCE: Final = "pending"

_TOKEN_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]{0,127}$", re.ASCII)
_HOSTS: Final = frozenset({"claude", "codex", "cursor"})
_PHASES: Final = frozenset({"start", "stop"})
_MAX_SAFE_INTEGER: Final = (1 << 53) - 1


def _token(value: object) -> str | None:
    if type(value) is str and _TOKEN_RE.fullmatch(value) is not None:
        # Host identifiers are structural tokens, never filesystem locators.
        # Keep the same path-like rejection as the observation envelope so an
        # adapter cannot smuggle a transcript/path value into lineage keys.
        if "\x00" in value or "\r" in value or "\n" in value:
            return None
        if value.startswith(("/", "\\", "./", "../", "~/", "~\\")):
            return None
        if len(value) >= 3 and value[1] == ":" and value[0].isalpha() and value[2] in {"/", "\\"}:
            return None
        return value
    return None


def _optional_token(value: object) -> str | None:
    if value is None:
        return None
    return _token(value)


def _consistent_alias_token(
    payload: Mapping[str, JsonValue], names: tuple[str, ...]
) -> tuple[str | None, bool]:
    """Return ``(value, valid)`` when every supplied spelling agrees.

    Host payloads are allowed to evolve their field spelling, but a payload that
    supplies two different identities is not safely attributable. Treating that
    shape as incomplete keeps the observation in the explicit gap path and
    prevents one alias from laundering a contradictory value in another.
    """

    values: list[str] = []
    for name in names:
        if name not in payload:
            continue
        raw = payload.get(name)
        if raw is None:
            continue
        value = _token(raw)
        if value is None:
            return None, False
        values.append(value)
    if any(value != values[0] for value in values[1:]):
        return None, False
    return (values[0] if values else None), True


def _phase(event_kind: object) -> HostLineagePhase | None:
    if type(event_kind) is not str:
        return None
    if event_kind in {"SubagentStart", "subagent_start", "subagentStart"}:
        return "start"
    if event_kind in {"SubagentStop", "subagent_stop", "subagentStop"}:
        return "stop"
    return None


@dataclass(frozen=True, slots=True, repr=False)
class HostLineageCorrelation:
    """Stable host correlation facts for one observed subagent.

    ``parent_tool_call_id`` is optional because some stop payloads carry only
    the child id.  ``correlation_identity`` remains deterministic for all
    shapes; ``aliases`` gives the service coordinator the stronger pair and
    conversation keys when they are available so a late stop can resolve an
    earlier start without creating a second annotation.
    """

    host: HostLineageHost
    subagent_id: str
    parent_tool_call_id: str | None = None
    parent_conversation_id: str | None = None
    conversation_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.host) is not str or self.host not in _HOSTS:
            raise ValueError("host_lineage_host_invalid")
        if _token(self.subagent_id) is None:
            raise ValueError("host_lineage_subagent_id_invalid")
        for name in ("parent_tool_call_id", "parent_conversation_id", "conversation_id"):
            if _optional_token(getattr(self, name)) != getattr(self, name):
                raise ValueError("host_lineage_correlation_invalid")

    @property
    def _identity_material(self) -> JsonObject:
        """Return the strongest portable key for this event.

        The host/profile and child/parent tool pair are the cross-source
        identity.  Conversation ids are useful reconciliation aliases but
        must not make a hook and stream copy disagree when one source omits
        that optional context.
        """

        values: dict[str, JsonValue] = {
            "host": self.host,
            "subagent_id": self.subagent_id,
        }
        if self.parent_tool_call_id is not None:
            values["parent_tool_call_id"] = self.parent_tool_call_id
        return JsonObject(values)

    @property
    def correlation_identity(self) -> str:
        """Return a path-free deterministic alias for transient correlation.

        The digest is intentionally portable so hook and stream materialization
        can agree. A durable annotation registry must key raw host values with
        its installation HMAC before storing or exposing them.
        """

        return "lineage:" + canonical_digest(self._identity_material).removeprefix("sha256:")

    @property
    def logical_identity(self) -> str:
        """Return the strongest portable identity without discarding a supplied parent call.

        Partial host copies reconcile through the service registry's aliases. A pure
        materializer cannot equate a child-only copy with every distinct parent call.
        """

        return self.correlation_identity

    @property
    def legacy_logical_identity(self) -> str:
        """Preserve the pre-1.7 child-only key for explicit historical replay."""

        return "lineage:" + canonical_digest(
            {"host": self.host, "subagent_id": self.subagent_id}
        ).removeprefix("sha256:")

    @property
    def aliases(self) -> tuple[str, ...]:
        """Return stronger and weaker keys for late-event reconciliation.

        The first member is always the full child/parent-tool identity when
        available.  The remaining members are deterministic fallbacks ordered
        from parent context to child-only context.  The service may use these
        to look up an existing provisional annotation, but must still verify
        the full fields before merging and use keyed commitments for durable
        storage.
        """

        candidates: list[JsonObject] = [self._identity_material]
        if self.parent_tool_call_id is not None:
            candidates.append(
                JsonObject(
                    {
                        "host": self.host,
                        "subagent_id": self.subagent_id,
                        "parent_tool_call_id": self.parent_tool_call_id,
                    }
                )
            )
        if self.parent_conversation_id is not None:
            candidates.append(
                JsonObject(
                    {
                        "host": self.host,
                        "subagent_id": self.subagent_id,
                        "parent_conversation_id": self.parent_conversation_id,
                    }
                )
            )
        if self.conversation_id is not None:
            candidates.append(
                JsonObject(
                    {
                        "host": self.host,
                        "subagent_id": self.subagent_id,
                        "conversation_id": self.conversation_id,
                    }
                )
            )
        candidates.append(JsonObject({"host": self.host, "subagent_id": self.subagent_id}))
        result: list[str] = []
        for material in candidates:
            identity = "lineage:" + canonical_digest(material).removeprefix("sha256:")
            if identity not in result:
                result.append(identity)
        return tuple(result)

    def __repr__(self) -> str:
        return (
            "HostLineageCorrelation("
            f"host={self.host!r}, subagent_id=<redacted>, "
            f"correlation_identity={self.correlation_identity!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class HostLineageObservation:
    """One normalized start/stop signal from a host hook or session stream."""

    phase: HostLineagePhase
    correlation: HostLineageCorrelation
    result_status: str | None = None
    duration_ms: int | None = None

    def __post_init__(self) -> None:
        if (
            type(self.phase) is not str
            or self.phase not in _PHASES
            or type(self.correlation) is not HostLineageCorrelation
        ):
            raise ValueError("host_lineage_observation_invalid")
        if self.result_status is not None and _token(self.result_status) != self.result_status:
            raise ValueError("host_lineage_result_status_invalid")
        if self.duration_ms is not None and (
            type(self.duration_ms) is not int
            or isinstance(self.duration_ms, bool)
            or not 0 <= self.duration_ms <= _MAX_SAFE_INTEGER
        ):
            raise ValueError("host_lineage_duration_invalid")

    @property
    def correlation_identity(self) -> str:
        return self.correlation.correlation_identity

    @property
    def logical_identity(self) -> str:
        """Return the source-stable identity used by materialized observations."""

        return self.correlation.logical_identity

    @property
    def origin(self) -> Literal["host_observed"]:
        return HOST_LINEAGE_ORIGIN

    @property
    def acceptance(self) -> Literal["pending"]:
        return HOST_LINEAGE_ACCEPTANCE

    def structural_fields(self) -> JsonObject:
        """Return ingress fields; durable storage must replace IDs with HMAC commitments."""

        fields: dict[str, JsonValue] = {
            "subagent_id": self.correlation.subagent_id,
            "correlation_id": self.correlation_identity,
        }
        if self.correlation.parent_tool_call_id is not None:
            fields["parent_tool_call_id"] = self.correlation.parent_tool_call_id
        if self.result_status is not None:
            fields["result_status"] = self.result_status
        if self.duration_ms is not None:
            fields["duration_ms"] = self.duration_ms
        return JsonObject(fields)

    def __repr__(self) -> str:
        return (
            "HostLineageObservation("
            f"phase={self.phase!r}, host={self.correlation.host!r}, "
            f"correlation_identity={self.correlation_identity!r}, "
            f"origin={self.origin!r}, acceptance={self.acceptance!r})"
        )


def _host_from_source(source: ObservationSource) -> HostLineageHost | None:
    if source is ObservationSource.CLAUDE_HOOK:
        return "claude"
    if source in {ObservationSource.CODEX_HOOK, ObservationSource.CODEX_SESSION_STREAM}:
        return "codex"
    if source is ObservationSource.CURSOR_HOOK:
        return "cursor"
    return None


def host_lineage_from_payload(
    host: HostLineageHost,
    event_kind: str,
    payload: Mapping[str, JsonValue],
) -> HostLineageObservation | None:
    """Normalize one host subagent payload, returning ``None`` when incomplete.

    ``agent_id`` is Claude's native spelling; Codex and Cursor commonly use
    ``subagent_id``.  ``tool_call_id`` is accepted as the parent call alias
    because Cursor's native query names it that way.  Prompt, transcript,
    summary, file, and path fields are deliberately ignored.
    """

    if type(host) is not str or host not in _HOSTS:
        return None
    if not isinstance(payload, Mapping):
        return None
    phase = _phase(event_kind)
    if phase is None:
        return None
    subagent_id, subagent_aliases_valid = _consistent_alias_token(
        payload, ("subagent_id", "agent_id", "agent_thread_id")
    )
    if not subagent_aliases_valid or subagent_id is None:
        return None
    parent_tool_call_id, parent_tool_aliases_valid = _consistent_alias_token(
        payload, ("parent_tool_call_id", "tool_call_id")
    )
    if not parent_tool_aliases_valid:
        return None
    parent_conversation_id, parent_context_valid = _consistent_alias_token(
        payload, ("parent_conversation_id",)
    )
    conversation_id, conversation_valid = _consistent_alias_token(payload, ("conversation_id",))
    if not parent_context_valid or not conversation_valid:
        return None
    status = _token(payload.get("result_status")) or _token(payload.get("status"))
    duration = payload.get("duration_ms")
    if duration is None:
        duration = payload.get("duration")
    duration_ms = (
        duration
        if type(duration) is int
        and not isinstance(duration, bool)
        and 0 <= duration <= _MAX_SAFE_INTEGER
        else None
    )
    return HostLineageObservation(
        phase,
        HostLineageCorrelation(
            host,
            subagent_id,
            parent_tool_call_id,
            parent_conversation_id,
            conversation_id,
        ),
        status if phase == "stop" else None,
        duration_ms if phase == "stop" else None,
    )


def host_lineage_from_envelope(envelope: ObservationEnvelope) -> HostLineageObservation | None:
    """Normalize an admitted observation envelope's host subagent signal."""

    if type(envelope) is not ObservationEnvelope:
        return None
    host = _host_from_source(envelope.source)
    if host is None:
        return None
    return host_lineage_from_payload(
        host,
        envelope.event_kind,
        cast(Mapping[str, JsonValue], envelope.structural_payload),
    )
