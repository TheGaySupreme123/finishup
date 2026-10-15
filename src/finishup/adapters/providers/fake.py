"""Deterministic, network-free scripted AI-powered evaluator for tests only.

This module gives the real privacy gateway, AI-powered review coordinator, and post-validation path a
scripted stand-in for a live provider. It is reachable only from the explicit ``test-fake`` test
composition: production strict-local, denied, and disabled paths construct no evaluator at all and
never fall back to this fake. The fake never contacts a network, never depends on the OpenAI SDK,
and never invents richer provenance than a live adapter would produce.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, replace
from threading import Lock
from typing import Final

import anyio

from finishup.domain.findings import CostFields, SamplingParams, SemanticFailureClass, TokenUsage
from finishup.domain.privacy import ApprovedOutboundCase, ApprovedProviderCase
from finishup.ports.clock import ClockPort
from finishup.ports.semantic import (
    Deadline,
    ProviderAttemptProvenance,
    SemanticJudgment,
    SemanticResult,
    SemanticResultInvalid,
    SemanticResultLate,
    SemanticResultRefused,
    SemanticResultSuccess,
    SemanticResultTimeout,
    SemanticResultUnavailable,
)
from finishup.protocol.models import SemanticStatus

__all__ = [
    "FakeSemanticScript",
    "ScriptedFakeSemanticEvaluator",
    "scripted_invalid",
    "scripted_late",
    "scripted_refusal",
    "scripted_success",
    "scripted_timeout",
    "scripted_unavailable",
]

_FAKE_PROVIDER: Final = "fake"
_FAKE_ENDPOINT_PROFILE_ID: Final = "fake-provider"
_FAKE_ENDPOINT_PROFILE_VERSION: Final = "1.0.0"
_FAKE_MODEL: Final = "fake/scripted-v1"
_FAKE_SDK_VERSION: Final = "0.0.0"
_FAKE_DIGEST: Final = "sha256:" + "0" * 64

_SEMANTIC_RESULT_TYPES: Final = (
    SemanticResultSuccess,
    SemanticResultRefused,
    SemanticResultTimeout,
    SemanticResultInvalid,
    SemanticResultLate,
    SemanticResultUnavailable,
)


def _provenance(
    status: SemanticStatus,
    *,
    latency_ms: int = 1,
    provider_request_id: str | None = None,
    token_usage: TokenUsage | None = None,
    cost_fields: CostFields | None = None,
    failure_class: SemanticFailureClass | None = None,
) -> ProviderAttemptProvenance:
    return ProviderAttemptProvenance(
        provider=_FAKE_PROVIDER,
        endpoint_profile_id=_FAKE_ENDPOINT_PROFILE_ID,
        endpoint_profile_version=_FAKE_ENDPOINT_PROFILE_VERSION,
        model=_FAKE_MODEL,
        sdk_version=_FAKE_SDK_VERSION,
        prompt_digest=_FAKE_DIGEST,
        schema_digest=_FAKE_DIGEST,
        policy_digest=_FAKE_DIGEST,
        privacy_policy_digest=_FAKE_DIGEST,
        sampling_params=SamplingParams(128),
        latency_ms=latency_ms,
        status=status,
        provider_request_id=provider_request_id,
        token_usage=token_usage,
        cost_fields=cost_fields,
        failure_class=failure_class,
    )


def _with_policy_digest(result: SemanticResult, policy_digest: str) -> SemanticResult:
    """Bind a scripted step's provenance to the policy digest that authorized this dispatch.

    A script is authored before any case exists, so the scripted steps carry a placeholder digest.
    Rebinding at dispatch time keeps the fake honest in exactly the way a live adapter is: the
    approved case is the only source of the policy digest, and the fake never asserts one of its
    own. The gateway rebinds this again, authoritatively; doing it here means the fake is never
    wrong even when driven directly.
    """

    return replace(
        result,
        provenance=replace(
            result.provenance, policy_digest=policy_digest, privacy_policy_digest=policy_digest
        ),
    )


@dataclass(frozen=True, slots=True)
class _ScriptedStep:
    """One scripted outcome plus the deterministic delay before it resolves."""

    result: SemanticResult
    delay_seconds: float = 0.0

    def __post_init__(self) -> None:
        if type(self.result) not in _SEMANTIC_RESULT_TYPES:
            raise TypeError("fake_semantic_result_invalid")
        if (
            type(self.delay_seconds) is not float
            or not math.isfinite(self.delay_seconds)
            or self.delay_seconds < 0.0
        ):
            raise ValueError("fake_semantic_delay_invalid")


def scripted_success(
    judgment: SemanticJudgment,
    *,
    delay_seconds: float = 0.0,
    latency_ms: int = 1,
    provider_request_id: str | None = None,
    token_usage: TokenUsage | None = None,
    cost_fields: CostFields | None = None,
) -> _ScriptedStep:
    """Emit a parsed judgment plus provisional provider-attempt provenance."""

    if type(judgment) is not SemanticJudgment:
        raise TypeError("fake_semantic_judgment_invalid")
    provenance = _provenance(
        SemanticStatus.SUCCEEDED,
        latency_ms=latency_ms,
        provider_request_id=provider_request_id,
        token_usage=token_usage,
        cost_fields=cost_fields,
    )
    return _ScriptedStep(SemanticResultSuccess(judgment, provenance), delay_seconds)


def scripted_refusal(*, delay_seconds: float = 0.0, latency_ms: int = 1) -> _ScriptedStep:
    """Emit a refusal result."""

    provenance = _provenance(SemanticStatus.REFUSED, latency_ms=latency_ms)
    return _ScriptedStep(SemanticResultRefused(provenance), delay_seconds)


def scripted_timeout(*, delay_seconds: float = 0.0, latency_ms: int = 1) -> _ScriptedStep:
    """Emit a timeout result at the deadline boundary."""

    provenance = _provenance(
        SemanticStatus.TIMEOUT, latency_ms=latency_ms, failure_class=SemanticFailureClass.TIMEOUT
    )
    return _ScriptedStep(SemanticResultTimeout(provenance), delay_seconds)


def scripted_invalid(
    *, raw_size: int, delay_seconds: float = 0.0, latency_ms: int = 1
) -> _ScriptedStep:
    """Emit malformed or schema-invalid output."""

    provenance = _provenance(
        SemanticStatus.INVALID,
        latency_ms=latency_ms,
        failure_class=SemanticFailureClass.RESPONSE_SCHEMA,
    )
    return _ScriptedStep(SemanticResultInvalid(provenance, raw_size), delay_seconds)


def scripted_late(*, delay_seconds: float = 0.0, latency_ms: int = 1) -> _ScriptedStep:
    """Emit a late-arriving result, distinguishable from a timely success."""

    provenance = _provenance(SemanticStatus.LATE, latency_ms=latency_ms)
    return _ScriptedStep(SemanticResultLate(provenance), delay_seconds)


def scripted_unavailable(
    *,
    failure_class: SemanticFailureClass = SemanticFailureClass.TRANSPORT,
    delay_seconds: float = 0.0,
    latency_ms: int = 1,
) -> _ScriptedStep:
    """Emit a provider-unavailable style failure (auth, quota, outage, or transport)."""

    if type(failure_class) is not SemanticFailureClass:
        raise TypeError("fake_semantic_failure_class_invalid")
    provenance = _provenance(
        SemanticStatus.UNAVAILABLE, latency_ms=latency_ms, failure_class=failure_class
    )
    return _ScriptedStep(SemanticResultUnavailable(provenance), delay_seconds)


@dataclass(frozen=True, slots=True)
class FakeSemanticScript:
    """An immutable, ordered sequence of scripted provider outcomes and delays."""

    steps: tuple[_ScriptedStep, ...]

    def __post_init__(self) -> None:
        if type(self.steps) is not tuple or not self.steps:
            raise ValueError("fake_semantic_script_empty")
        if any(type(step) is not _ScriptedStep for step in self.steps):
            raise TypeError("fake_semantic_script_step_invalid")


@dataclass(slots=True)
class _ScriptCursor:
    remaining: list[_ScriptedStep]
    lock: Lock = field(default_factory=Lock, repr=False, compare=False)


class ScriptedFakeSemanticEvaluator:
    """Scripted :class:`SemanticEvaluatorPort` implementation for the ``test-fake`` composition.

    Only the explicit test-fake composition may register this behind the privacy gateway; it
    accepts exclusively the external ``ApprovedOutboundCase`` variant and consumes its script in
    order. Exhausting the script fails loudly rather than silently repeating the final value.
    """

    __slots__ = ("_clock", "_cursor")

    def __init__(self, script: FakeSemanticScript, *, clock: ClockPort | None = None) -> None:
        if type(script) is not FakeSemanticScript:
            raise TypeError("fake_semantic_script_invalid")
        self._clock = clock
        self._cursor = _ScriptCursor(list(script.steps))

    async def evaluate(self, case: ApprovedProviderCase, deadline: Deadline) -> SemanticResult:
        if type(case) is not ApprovedOutboundCase:
            raise TypeError("fake_semantic_case_invalid")
        if type(deadline) is not Deadline:
            raise TypeError("fake_semantic_deadline_invalid")
        with self._cursor.lock:
            if not self._cursor.remaining:
                raise RuntimeError("fake_semantic_script_exhausted")
            step = self._cursor.remaining.pop(0)
        if self._clock is not None:
            now = self._clock.monotonic_seconds() + step.delay_seconds
            if deadline.expired(now):
                return _with_policy_digest(
                    SemanticResultTimeout(_provenance(SemanticStatus.TIMEOUT)), case.policy_digest
                )
        elif step.delay_seconds:
            await anyio.sleep(step.delay_seconds)
        return _with_policy_digest(step.result, case.policy_digest)
