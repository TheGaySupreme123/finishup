"""In-memory reference ObservationPort for consent, cursors, and structural envelopes."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace

from finishup.domain.observation import (
    ObservationCaptureBacklog,
    ObservationControlCommand,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestResult,
    ObservationRevokeCommand,
    ObservationSource,
    ObservationStatus,
    ObservationStatusQuery,
)
from finishup.domain.observation_profiles import (
    is_content_capture_profile,
    validate_content_capture_profile,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.errors import PublicErrorCode, PublicOperationError

__all__ = [
    "MemoryObservationConsent",
    "MemoryObservationState",
    "MemoryObservationStore",
]


def _error(code: PublicErrorCode, message: str, *, retryable: bool) -> PublicOperationError:
    return PublicOperationError(code, message, retryable)


@dataclass(frozen=True, slots=True)
class MemoryObservationConsent:
    workspace_commitment: str
    granted_at: Timestamp
    revoked_at: Timestamp | None = None
    paused: bool = False
    content_capture_profiles: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.content_capture_profiles) is not tuple
            or len(self.content_capture_profiles) > 2
        ):
            raise ValueError("invalid_content_capture_profiles")
        if any(not is_content_capture_profile(item) for item in self.content_capture_profiles):
            raise ValueError("invalid_content_capture_profiles")
        if tuple(sorted(set(self.content_capture_profiles), key=str.encode)) != (
            self.content_capture_profiles
        ):
            raise ValueError("invalid_content_capture_profiles")

    @property
    def active(self) -> bool:
        return self.revoked_at is None and not self.paused


@dataclass(frozen=True, slots=True)
class _GapState:
    first_seen: Timestamp
    last_seen: Timestamp
    active: bool = True


@dataclass
class MemoryObservationState:
    consent: dict[str, MemoryObservationConsent] = field(
        default_factory=dict[str, MemoryObservationConsent]
    )
    session_workspaces: dict[str, str] = field(default_factory=dict[str, str])
    cursors: dict[tuple[str, ObservationSource, str], ObservationCursor] = field(
        default_factory=dict[tuple[str, ObservationSource, str], ObservationCursor]
    )
    dedup: set[str] = field(default_factory=set[str])
    envelopes: list[tuple[str, ObservationEnvelope]] = field(
        default_factory=list[tuple[str, ObservationEnvelope]]
    )
    advice_frontier: dict[str, str] = field(default_factory=dict[str, str])
    unsupported_events: dict[str, set[str]] = field(default_factory=dict[str, set[str]])
    gaps: dict[str, dict[str, _GapState]] = field(default_factory=dict[str, dict[str, _GapState]])
    last_receipt: dict[str, Timestamp] = field(default_factory=dict[str, Timestamp])


def _cursor_payload(cursor: ObservationCursor) -> JsonObject:
    return JsonObject(
        {
            "source_generation": cursor.source_generation,
            "byte_position": cursor.byte_position,
            "event_position": cursor.event_position,
            "last_source_commitment": cursor.last_source_commitment,
            "mapping_version": cursor.mapping_version,
        }
    )


def _dedup_key(workspace: str, envelope: ObservationEnvelope) -> str:
    return canonical_digest(
        JsonObject(
            {
                "workspace_commitment": workspace,
                "session_commitment": envelope.session_commitment,
                "source": envelope.source.value,
                "source_identity": envelope.source_identity,
                "event_kind": envelope.event_kind,
                "cursor": _cursor_payload(envelope.cursor),
            }
        )
    )


class MemoryObservationStore:
    """Reference ObservationPort with fail-closed consent and generation-fenced cursors."""

    def __init__(self, state: MemoryObservationState | None = None) -> None:
        self._state = state if state is not None else MemoryObservationState()
        self._lock = asyncio.Lock()

    def grant_consent(
        self,
        workspace_commitment: str,
        granted_at: Timestamp,
        *,
        content_capture_profiles: tuple[str, ...] = (),
    ) -> None:
        if type(content_capture_profiles) is not tuple:
            raise ValueError("invalid_content_capture_profiles")
        for profile in content_capture_profiles:
            validate_content_capture_profile(profile)
        self._state.consent[workspace_commitment] = MemoryObservationConsent(
            workspace_commitment=workspace_commitment,
            granted_at=granted_at,
            revoked_at=None,
            paused=False,
            content_capture_profiles=content_capture_profiles,
        )

    def content_capture_profiles(self, workspace_commitment: str) -> tuple[str, ...]:
        consent = self._state.consent.get(workspace_commitment)
        return () if consent is None else consent.content_capture_profiles

    def capture_backlog(self, workspace: str) -> ObservationCaptureBacklog:
        """Return the empty capture backlog for the structural-only reference store.

        The in-memory adapter intentionally has no encrypted object or native
        capture-ticket implementation. Exposing the same read-only seam keeps
        pressure consumers from guessing at an unavailable backlog and avoids
        making this test adapter look like it retained content.
        """

        del workspace
        return ObservationCaptureBacklog(0, 0, None)

    def capture_ticket_backlog(self, workspace: str) -> ObservationCaptureBacklog:
        return self.capture_backlog(workspace)

    def enable_content_capture(self, workspace_commitment: str, profile: str) -> None:
        """Enable one explicit native-host content arm on a live grant."""

        validate_content_capture_profile(profile)
        consent = self._state.consent.get(workspace_commitment)
        if consent is None:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation consent is missing.",
                retryable=False,
            )
        if consent.revoked_at is not None:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation consent is revoked.",
                retryable=False,
            )
        profiles = tuple(sorted({*consent.content_capture_profiles, profile}, key=str.encode))
        self._state.consent[workspace_commitment] = replace(
            consent, content_capture_profiles=profiles
        )

    def disable_content_capture(
        self, workspace_commitment: str, profile: str | None = None
    ) -> None:
        """Disable one native-host content arm, or all arms when omitted."""

        if profile is not None:
            validate_content_capture_profile(profile)
        consent = self._state.consent.get(workspace_commitment)
        if consent is None:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation consent is missing.",
                retryable=False,
            )
        profiles = (
            ()
            if profile is None
            else tuple(item for item in consent.content_capture_profiles if item != profile)
        )
        self._state.consent[workspace_commitment] = replace(
            consent, content_capture_profiles=profiles
        )

    def bind_session(self, workspace_commitment: str, session_commitment: str) -> None:
        if workspace_commitment not in self._state.consent:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation consent is missing.",
                retryable=False,
            )
        existing = self._state.session_workspaces.get(session_commitment)
        if existing is not None and existing != workspace_commitment:
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "Observation session is already bound.",
                retryable=False,
            )
        self._state.session_workspaces[session_commitment] = workspace_commitment

    async def ingest(self, envelope: ObservationEnvelope) -> ObservationIngestResult:
        if type(envelope) is not ObservationEnvelope:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation envelope is invalid.",
                retryable=False,
            )
        async with self._lock:
            try:
                workspace = self._workspace_for_envelope(envelope)
            except PublicOperationError:
                return ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.CONSENT_MISSING.value,
                    None,
                )
            consent = self._state.consent.get(workspace)
            if consent is None:
                return ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.CONSENT_MISSING.value,
                    None,
                )
            if consent.revoked_at is not None:
                return ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.CONSENT_REVOKED.value,
                    None,
                )
            if consent.paused:
                return ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    "paused",
                    None,
                )
            key = _dedup_key(workspace, envelope)
            if key in self._state.dedup:
                cursor = self._state.cursors.get(
                    (workspace, envelope.source, envelope.session_commitment)
                )
                return ObservationIngestResult(
                    ObservationIngestDisposition.DUPLICATE,
                    "duplicate",
                    cursor,
                )
            cursor_key = (workspace, envelope.source, envelope.session_commitment)
            existing = self._state.cursors.get(cursor_key)
            if existing is not None and envelope.cursor.is_stale_relative_to(existing):
                self._note_gap(
                    workspace, ObservationGapCode.CURSOR_STALE.value, envelope.receipt_time
                )
                return ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.CURSOR_STALE.value,
                    existing,
                )
            if (
                existing is not None
                and envelope.cursor.source_generation < existing.source_generation
            ):
                self._note_gap(
                    workspace, ObservationGapCode.CURSOR_STALE.value, envelope.receipt_time
                )
                return ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.CURSOR_STALE.value,
                    existing,
                )
            self._state.dedup.add(key)
            self._state.cursors[cursor_key] = envelope.cursor
            self._state.envelopes.append((workspace, envelope))
            self._state.last_receipt[workspace] = envelope.receipt_time
            # Successful advancement, rather than the untrusted receipt timestamp, proves that
            # a previously stale cursor is no longer the current ingest condition.
            self._resolve_gap(workspace, ObservationGapCode.CURSOR_STALE.value)
            if envelope.content_object_refs:
                self._resolve_gap(workspace, ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
            for gap in envelope.gap_codes:
                self._note_gap(workspace, gap, envelope.receipt_time)
            if ObservationGapCode.UNSUPPORTED_EVENT.value in envelope.gap_codes:
                self._state.unsupported_events.setdefault(workspace, set()).add(envelope.event_kind)
            # Force encode to keep structural bytes bounded at rest.
            _ = canonical_encode(
                JsonObject(
                    {
                        "structural_payload": envelope.structural_payload,
                        "content_object_refs": envelope.content_object_refs,
                    }
                )
            )
            return ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED,
                None,
                envelope.cursor,
            )

    async def status(self, query: ObservationStatusQuery) -> ObservationStatus:
        if type(query) is not ObservationStatusQuery:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation status query is invalid.",
                retryable=False,
            )
        async with self._lock:
            return self._status_unlocked(query.workspace_commitment)

    async def pause(self, command: ObservationControlCommand) -> ObservationStatus:
        if type(command) is not ObservationControlCommand:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation control command is invalid.",
                retryable=False,
            )
        async with self._lock:
            consent = self._require_consent(command.workspace_commitment)
            if consent.revoked_at is not None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation consent is revoked.",
                    retryable=False,
                )
            self._state.consent[command.workspace_commitment] = MemoryObservationConsent(
                workspace_commitment=consent.workspace_commitment,
                granted_at=consent.granted_at,
                revoked_at=consent.revoked_at,
                paused=True,
                content_capture_profiles=consent.content_capture_profiles,
            )
            return self._status_unlocked(command.workspace_commitment)

    async def resume(self, command: ObservationControlCommand) -> ObservationStatus:
        if type(command) is not ObservationControlCommand:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation control command is invalid.",
                retryable=False,
            )
        async with self._lock:
            consent = self._state.consent.get(command.workspace_commitment)
            if consent is None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation consent is missing.",
                    retryable=False,
                )
            if consent.revoked_at is not None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation consent is revoked.",
                    retryable=False,
                )
            self._state.consent[command.workspace_commitment] = MemoryObservationConsent(
                workspace_commitment=consent.workspace_commitment,
                granted_at=consent.granted_at,
                revoked_at=None,
                paused=False,
                content_capture_profiles=consent.content_capture_profiles,
            )
            return self._status_unlocked(command.workspace_commitment)

    async def revoke(self, command: ObservationRevokeCommand) -> ObservationStatus:
        if type(command) is not ObservationRevokeCommand:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation revoke command is invalid.",
                retryable=False,
            )
        async with self._lock:
            consent = self._require_consent(command.workspace_commitment)
            revoked_at = self._state.last_receipt.get(
                command.workspace_commitment, consent.granted_at
            )
            self._state.consent[command.workspace_commitment] = MemoryObservationConsent(
                workspace_commitment=consent.workspace_commitment,
                granted_at=consent.granted_at,
                revoked_at=revoked_at,
                paused=True,
                content_capture_profiles=(),
            )
            # Evidence retained: envelopes/dedup/cursors remain.
            return self._status_unlocked(command.workspace_commitment)

    def _workspace_for_envelope(self, envelope: ObservationEnvelope) -> str:
        bound = self._state.session_workspaces.get(envelope.session_commitment)
        if bound is not None:
            return bound
        if len(self._state.consent) == 1:
            workspace = next(iter(self._state.consent))
            self._state.session_workspaces[envelope.session_commitment] = workspace
            return workspace
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            "Observation workspace consent is missing.",
            retryable=False,
        )

    def _require_consent(self, workspace_commitment: str) -> MemoryObservationConsent:
        consent = self._state.consent.get(workspace_commitment)
        if consent is None:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation consent is missing.",
                retryable=False,
            )
        return consent

    def _note_gap(self, workspace: str, code: str, seen_at: Timestamp) -> None:
        history = self._state.gaps.setdefault(workspace, {})
        prior = history.get(code)
        history[code] = _GapState(
            seen_at if prior is None else prior.first_seen,
            seen_at,
            True,
        )

    def _resolve_gap(self, workspace: str, code: str) -> None:
        history = self._state.gaps.setdefault(workspace, {})
        prior = history.get(code)
        if prior is not None:
            history[code] = _GapState(prior.first_seen, prior.last_seen, False)

    def _status_unlocked(self, workspace_commitment: str) -> ObservationStatus:
        import time

        from finishup.application.observation_health import (
            DEFAULT_OBSERVATION_HEALTH_THRESHOLDS,
            ObservationHealthSignals,
            compute_observation_lifecycle,
        )

        consent = self._state.consent.get(workspace_commitment)
        coverage = {
            ObservationSource.CLAUDE_HOOK: False,
            ObservationSource.CODEX_HOOK: False,
            ObservationSource.CODEX_SESSION_STREAM: False,
            ObservationSource.CURSOR_HOOK: False,
        }
        for workspace, envelope in self._state.envelopes:
            if workspace == workspace_commitment:
                coverage[envelope.source] = True
        history = self._state.gaps.get(workspace_commitment, {})
        current = {code for code, seen in history.items() if seen.active}
        gaps = tuple(sorted(current, key=str.encode))
        unsupported = tuple(
            sorted(self._state.unsupported_events.get(workspace_commitment, set()), key=str.encode)
        )
        consent_active = consent is not None and consent.revoked_at is None and not consent.paused
        last_receipt = self._state.last_receipt.get(workspace_commitment)
        progress = time.monotonic() if last_receipt is not None and any(coverage.values()) else None
        signals = ObservationHealthSignals(
            consent_active=consent_active,
            mapping_available=workspace_commitment in self._state.session_workspaces.values()
            or workspace_commitment in self._state.consent,
            source_coverage=coverage,
            pending_outbox_count=0,
            lag_events=0,
            gaps=gaps,
            unsupported_events=unsupported,
            advice_frontier=self._state.advice_frontier.get(workspace_commitment),
            last_hook_receipt_monotonic=progress,
            last_stream_advancement_monotonic=None,
            last_successful_drain_monotonic=progress,
            session_ended=False,
        )
        lifecycle = compute_observation_lifecycle(
            signals,
            now_monotonic=time.monotonic(),
            thresholds=DEFAULT_OBSERVATION_HEALTH_THRESHOLDS,
        )
        return ObservationStatus(
            lifecycle=lifecycle,
            workspace_commitment=workspace_commitment,
            source_coverage=coverage,
            last_observation_receipt_time=last_receipt,
            lag_events=0,
            gaps=gaps,
            unsupported_events=unsupported,
            advice_frontier=self._state.advice_frontier.get(workspace_commitment),
        )
