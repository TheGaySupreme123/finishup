"""Remember why the last AI-powered review attempt needs the user, per provider binding (#819).

Structural readiness proves a configured path exists; it cannot see an expired Codex login, a
rejected API credential, or an exhausted plan. Only a real attempt can. The service therefore
classifies each terminal provider attempt into one closed attention token (or clears it after the
provider answered) and the observation advice composition reads the current token as a standing
machine fact.

The state is deliberately in-memory and scoped to one READY generation: it adds no durable
record, and recomposition after setup, sign-in, disconnect, or restart starts clean. Only the
closed failure class and the adapter's closed runtime failure stage are consulted; provider text
never reaches a token.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final, Literal

from finishup.application.egress import SemanticEgressProviderOutcome, SemanticEgressSuccess
from finishup.domain.findings import SemanticFailureClass
from finishup.domain.privacy import ProviderBinding
from finishup.kernel.policies.observation_advice import SEMANTIC_ATTENTION_TOKENS
from finishup.ports.semantic import (
    SemanticResultInvalid,
    SemanticResultRefused,
    SemanticResultUnavailable,
)

__all__ = ["SemanticAttentionTracker", "semantic_attention_for_outcome"]

type AttentionVerdict = str | Literal["clear"] | None

_CLEAR: Final = "clear"

# Runtime failure stages that name a user-repairable cause regardless of failure class.
_STAGE_ATTENTION: Final = {
    "login_required": "sign_in_required",
    "model_unavailable": "model_unavailable",
    "capability_evidence_stale": "runtime_update_required",
}


def semantic_attention_for_outcome(result: object) -> AttentionVerdict:
    """Classify one terminal egress result.

    Returns an attention token when the attempt stopped for a cause only the user can repair,
    ``"clear"`` when the provider accepted the sign-in and answered, and ``None`` when the
    outcome says nothing either way (timeouts, rate limits, outages, transport, policy blocks,
    or recovery facts), so a transient never raises or hides a notice.
    """

    if type(result) is SemanticEgressSuccess:
        return _CLEAR
    if type(result) is not SemanticEgressProviderOutcome:
        return None
    provider = result.result
    if type(provider) in {SemanticResultInvalid, SemanticResultRefused}:
        # The provider authenticated this account and produced an answer; the answer itself
        # is the check's concern, not the installation's.
        return _CLEAR
    if type(provider) is not SemanticResultUnavailable:
        return None
    provenance = provider.provenance
    runtime = provenance.runtime_evidence
    stage = None if runtime is None else runtime.failure_stage
    if stage is not None and stage in _STAGE_ATTENTION:
        return _STAGE_ATTENTION[stage]
    failure_class = provenance.failure_class
    if failure_class is SemanticFailureClass.AUTHENTICATION:
        # An external runtime owns its OAuth login; an API route owns a stored credential.
        return "sign_in_required" if runtime is not None else "credential_rejected"
    if failure_class is SemanticFailureClass.AUTHORIZATION:
        return "access_denied"
    if failure_class is SemanticFailureClass.QUOTA_EXHAUSTED:
        return "quota_exhausted"
    return None


class SemanticAttentionTracker:
    """Current attention token per configured binding for one READY generation."""

    __slots__ = ("_bindings", "_tokens")

    def __init__(self, bindings: Iterable[ProviderBinding | None]) -> None:
        # Bounded by construction: only the configured primary and fallback are tracked.
        self._bindings = frozenset(item for item in bindings if item is not None)
        self._tokens: dict[ProviderBinding, str] = {}

    def record(self, binding: object, result: object) -> None:
        """Fold one terminal attempt in. Never raises: it must not disturb a check."""

        try:
            if type(binding) is not ProviderBinding or binding not in self._bindings:
                return
            verdict = semantic_attention_for_outcome(result)
            if verdict == _CLEAR:
                self._tokens.pop(binding, None)
            elif verdict is not None and verdict in SEMANTIC_ATTENTION_TOKENS:
                self._tokens[binding] = verdict
        except Exception:  # noqa: BLE001 - attention is advisory; a check must never fail here
            return

    def current(self, *bindings: ProviderBinding | None) -> tuple[str, str] | None:
        """First pending ``(token, provider_id)`` in the given priority order, if any."""

        for binding in bindings:
            if binding is None:
                continue
            token = self._tokens.get(binding)
            if token is not None:
                return token, binding.provider_id
        return None
