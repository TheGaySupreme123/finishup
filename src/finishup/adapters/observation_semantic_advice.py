"""Optional additive AI-powered advice over minimized observation evidence packets."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final, cast

from finishup.application.observation_advice import (
    ObservationAdviceSemanticAddon,
    SemanticAdvicePort,
    minimized_semantic_evidence_packet,
    stable_advice_finding_id,
)
from finishup.kernel.policies.observation_advice import ObservationAdviceCandidate
from finishup.protocol.canonical import JsonValue, canonical_digest

__all__ = [
    "NullSemanticAdvice",
    "OptionalSemanticAdvice",
    "PrivacyGatedSemanticAdvice",
    "SemanticAdviceAttemptRecord",
    "compose_observation_semantic_advisor",
]

_SEMANTIC_RULE: Final = "semantic_additive_review"
_FORBIDDEN_PACKET_KEYS: Final = frozenset(
    {
        "transcript",
        "stdout",
        "stderr",
        "path",
        "cwd",
        "command",
        "raw_text",
        "reasoning",
        "shell",
        "filesystem",
        "log",
        "logs",
    }
)


@dataclass(frozen=True, slots=True)
class SemanticAdviceAttemptRecord:
    """Durable receipt for one AI-powered observation-advice attempt."""

    provider_identity: str
    outcome: str
    evidence_basis_digest: str
    receipt: str
    failure_reason: str | None = None


@dataclass(frozen=True, slots=True)
class NullSemanticAdvice:
    """Local-only path: AI-powered review is never invoked."""

    def review(
        self, *, evidence_packet: Mapping[str, object]
    ) -> ObservationAdviceSemanticAddon | None:
        _ = evidence_packet
        return None


class OptionalSemanticAdvice:
    """Invoke a configured evaluator only when ready; never required for correctness."""

    def __init__(
        self,
        *,
        configured: bool,
        ready: bool,
        provider_identity: str | None = None,
        evaluator: Callable[[Mapping[str, object]], Mapping[str, object] | None] | None = None,
        on_attempt: Callable[[SemanticAdviceAttemptRecord], None] | None = None,
    ) -> None:
        self._configured = configured
        self._ready = ready
        self._provider_identity = provider_identity or "provider:unspecified"
        self._evaluator = evaluator
        self._on_attempt = on_attempt

    def review(
        self, *, evidence_packet: Mapping[str, object]
    ) -> ObservationAdviceSemanticAddon | None:
        if not self._configured or not self._ready or self._evaluator is None:
            return None
        if any(key in evidence_packet for key in _FORBIDDEN_PACKET_KEYS):
            record = SemanticAdviceAttemptRecord(
                provider_identity=self._provider_identity,
                outcome="rejected_packet",
                evidence_basis_digest=str(
                    evidence_packet.get("evidence_basis_digest") or "sha256:" + ("0" * 64)
                ),
                receipt="semantic-attempt:rejected",
                failure_reason="forbidden_packet_keys",
            )
            if self._on_attempt is not None:
                self._on_attempt(record)
            return None
        try:
            raw = self._evaluator(evidence_packet)
        except Exception as exc:  # noqa: BLE001 - provider failure must not weaken local
            digest = str(evidence_packet.get("evidence_basis_digest") or "sha256:" + ("0" * 64))
            record = SemanticAdviceAttemptRecord(
                provider_identity=self._provider_identity,
                outcome="failed",
                evidence_basis_digest=digest,
                receipt="semantic-attempt:failed",
                failure_reason=type(exc).__name__,
            )
            if self._on_attempt is not None:
                self._on_attempt(record)
            return None
        if raw is None:
            return None
        detail = str(raw.get("detail_token") or "semantic-addon")
        summary = str(raw.get("summary") or "Model-derived observation note")
        digest = canonical_digest(
            cast(JsonValue, {"packet": dict(evidence_packet), "detail": detail})
        )
        finding = stable_advice_finding_id(_SEMANTIC_RULE, detail, digest)
        next_action = raw.get("next_action")
        receipt = f"semantic-attempt:{digest.removeprefix('sha256:')[:24]}"
        record = SemanticAdviceAttemptRecord(
            provider_identity=self._provider_identity,
            outcome="succeeded",
            evidence_basis_digest=digest,
            receipt=receipt,
            failure_reason=None,
        )
        if self._on_attempt is not None:
            self._on_attempt(record)
        return ObservationAdviceSemanticAddon(
            finding_ids=(finding,),
            evidence_digest=digest,
            next_action=str(next_action) if type(next_action) is str else None,
            summaries=(summary[:160],),
            details=(
                str(raw.get("detail") or "Additive AI-powered advice over minimized evidence")[
                    :240
                ],
            ),
            provider_identity=self._provider_identity,
            attempt_receipt=receipt,
            failure_reason=None,
        )


@dataclass(frozen=True, slots=True)
class PrivacyGatedSemanticAdvice:
    """Wrap a SemanticAdvicePort and only forward minimized approved packets."""

    inner: SemanticAdvicePort
    candidates: tuple[ObservationAdviceCandidate, ...]
    basis_digest: str
    coverage_gaps: tuple[str, ...] = ()

    def review(
        self, *, evidence_packet: Mapping[str, object] | None = None
    ) -> ObservationAdviceSemanticAddon | None:
        packet = evidence_packet or minimized_semantic_evidence_packet(
            self.candidates,
            self.basis_digest,
            coverage_gaps=self.coverage_gaps,
            finding_summaries=tuple(str(item.rule_code) for item in self.candidates),
        )
        return self.inner.review(evidence_packet=packet)


def compose_observation_semantic_advisor(
    *,
    semantic_configured: bool,
    semantic_ready: bool,
    provider_identity: str | None = None,
    evaluator: Callable[[Mapping[str, object]], Mapping[str, object] | None] | None = None,
    on_attempt: Callable[[SemanticAdviceAttemptRecord], None] | None = None,
) -> SemanticAdvicePort:
    """Ready-composition helper: privacy-gated when ready, else local-only."""

    if not semantic_configured or not semantic_ready or evaluator is None:
        return NullSemanticAdvice()
    return OptionalSemanticAdvice(
        configured=True,
        ready=True,
        provider_identity=provider_identity,
        evaluator=evaluator,
        on_attempt=on_attempt,
    )
