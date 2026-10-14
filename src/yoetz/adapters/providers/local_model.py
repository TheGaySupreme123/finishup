"""Optional local AF_UNIX AI-powered review model adapter behind one service-approved endpoint profile.

The Yoetz adapter itself opens no network transport, performs no path discovery, DNS,
AF_INET/AF_INET6, proxy lookup, redirect, subprocess launch, or package/model download, and never
falls back to an external provider. It receives only an already-approved
``ApprovedLocalDisclosureCase`` plus a nonserializable, generation-bound socket handle that the
trusted platform resolver already produced during policy reconciliation; this module never resolves
a socket itself. Local execution does not weaken classification, minimization, secret scan,
post-validation, or audit requirements, and output remains untrusted ``semantic_model_derived``
material subject to the same strict post-validation as any external adapter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Protocol

from yoetz.domain.findings import SamplingParams, SemanticFailureClass
from yoetz.domain.privacy import (
    ApprovedLocalDisclosureCase,
    ApprovedProviderCase,
    LocalDisclosureSink,
)
from yoetz.domain.values import validate_sha256_digest
from yoetz.ports.clock import ClockPort
from yoetz.ports.semantic import (
    Deadline,
    ProviderAttemptProvenance,
    SemanticJudgment,
    SemanticResult,
    SemanticResultInvalid,
    SemanticResultSuccess,
    SemanticResultTimeout,
    SemanticResultUnavailable,
)
from yoetz.protocol.canonical import JsonValue, strict_json_parse
from yoetz.protocol.models import SemanticStatus

__all__ = [
    "InstalledLocalModelProfileRegistry",
    "LocalModelEndpointProfile",
    "LocalModelEvaluator",
    "LocalModelSocketHandle",
    "LocalModelSocketResolverPort",
    "normalize_local_response",
]

_IDENTITY_PATTERN: Final = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$", re.ASCII)
_MODEL_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$", re.ASCII)
_MAX_LOCAL_RESPONSE_BYTES: Final = 1_048_576
_MAX_LOCAL_OUTPUT_TOKENS: Final = 2_048


def _identity(value: object) -> str:
    if type(value) is not str or _IDENTITY_PATTERN.fullmatch(value) is None:
        raise ValueError("local_model_profile_identity_invalid")
    return value


@dataclass(frozen=True, slots=True)
class LocalModelEndpointProfile:
    """One release-supported, artifact-owned exact local-model endpoint tuple.

    This is the daemon-owned descriptor: exact profile/endpoint versions, model, protocol/schema
    versions, expected socket identity/owner/peer/mode, a timeout ceiling, the packaged
    release-resource digest, and the exact capability-evidence digest that proves this tuple passed
    a release-time local-runtime capability cell. It carries no generic URL or filesystem path.
    """

    profile_id: str
    profile_version: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    model: str
    protocol_version: str
    judgment_schema_version: str
    timeout_seconds: int
    expected_service_identity: str
    expected_owner_uid: int
    expected_peer_uid: int
    expected_socket_mode: int
    release_resource_digest: str
    capability_evidence_digest: str

    def __post_init__(self) -> None:
        for field_name in (
            "profile_id",
            "profile_version",
            "endpoint_profile_id",
            "endpoint_profile_version",
            "protocol_version",
            "judgment_schema_version",
            "expected_service_identity",
        ):
            object.__setattr__(self, field_name, _identity(getattr(self, field_name)))
        if type(self.model) is not str or _MODEL_PATTERN.fullmatch(self.model) is None:
            raise ValueError("local_model_profile_model_invalid")
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 300:
            raise ValueError("local_model_profile_timeout_invalid")
        for uid_field in ("expected_owner_uid", "expected_peer_uid"):
            uid = getattr(self, uid_field)
            if type(uid) is not int or uid < 0:
                raise ValueError("local_model_profile_identity_invalid")
        if (
            type(self.expected_socket_mode) is not int
            or not 0 <= self.expected_socket_mode <= 0o777
        ):
            raise ValueError("local_model_profile_mode_invalid")
        validate_sha256_digest(self.release_resource_digest)
        validate_sha256_digest(self.capability_evidence_digest)


@dataclass(frozen=True, slots=True)
class InstalledLocalModelProfileRegistry:
    """Immutable, artifact-owned allowlist of exact release-supported local-model tuples.

    A release with no passing exact local-runtime capability cell ships this registry empty and
    reports local AI-powered inference unavailable; the existence of this adapter contract alone
    never advertises support. There is no dynamic discovery or user-extension mapping.
    """

    entries: tuple[LocalModelEndpointProfile, ...] = ()

    def __post_init__(self) -> None:
        if type(self.entries) is not tuple or any(
            type(entry) is not LocalModelEndpointProfile for entry in self.entries
        ):
            raise TypeError("local_model_registry_entries_invalid")
        keys = [(entry.profile_id, entry.profile_version) for entry in self.entries]
        if len(keys) != len(set(keys)):
            raise ValueError("local_model_registry_duplicate_entry")

    def resolve(self, profile_id: str, profile_version: str) -> LocalModelEndpointProfile | None:
        """Resolve an exact installed tuple, or return ``None`` for bounded unavailable."""

        for entry in self.entries:
            if entry.profile_id == profile_id and entry.profile_version == profile_version:
                return entry
        return None


class LocalModelSocketHandle(Protocol):
    """A nonserializable, generation-bound, one-profile AF_UNIX connected handle.

    It exposes only bounded send/receive operations; it never exposes its filesystem path or raw
    socket to callers, and it is bound to the service generation and profile digest that were valid
    when the trusted platform resolver produced it.
    """

    @property
    def service_generation(self) -> int: ...

    @property
    def profile_digest(self) -> str: ...

    async def send(self, payload: bytes) -> None:
        """Write one bounded approved request; the handle owns framing, not this adapter."""

        ...

    async def receive(self, max_bytes: int) -> bytes:
        """Read one bounded response, aborting rather than exceeding ``max_bytes``."""

        ...

    def close(self) -> None: ...


class LocalModelSocketResolverPort(Protocol):
    """Service-internal platform resolver; only the trusted daemon composition implements it.

    Only ``reconcile_policy``, after the effective durable policy proves ``local_model_enabled``
    for the exact binding, may ask this resolver for a socket handle. Neither config nor privacy
    policy supplies a path; the resolver alone maps a profile to the platform-owned endpoint
    locator, opens AF_UNIX with no-follow/replacement protections, verifies owner/mode/socket-type/
    peer credentials and expected runtime identity, and returns a handle bound to the current
    service generation and profile digest.
    """

    def resolve(self, profile: LocalModelEndpointProfile) -> LocalModelSocketHandle: ...


def _provenance(
    profile: LocalModelEndpointProfile,
    status: SemanticStatus,
    *,
    policy_digest: str,
    latency_ms: int,
    failure_class: SemanticFailureClass | None = None,
) -> ProviderAttemptProvenance:
    return ProviderAttemptProvenance(
        provider=profile.expected_service_identity,
        endpoint_profile_id=profile.endpoint_profile_id,
        endpoint_profile_version=profile.endpoint_profile_version,
        model=profile.model,
        sdk_version=profile.protocol_version,
        prompt_digest=profile.capability_evidence_digest,
        schema_digest=profile.capability_evidence_digest,
        policy_digest=policy_digest,
        privacy_policy_digest=policy_digest,
        sampling_params=SamplingParams(_MAX_LOCAL_OUTPUT_TOKENS),
        latency_ms=latency_ms,
        status=status,
        failure_class=failure_class,
    )


def _judgment_from_json(parsed: JsonValue) -> SemanticJudgment:
    # Same provider judgment contract as the external adapters; local output never gets a
    # second hidden schema.
    from yoetz.adapters.providers.openai_responses import normalize_judgment

    return normalize_judgment(parsed, require_part2=True)


def normalize_local_response(
    raw: bytes,
    profile: LocalModelEndpointProfile,
    *,
    policy_digest: str,
    latency_ms: int,
) -> SemanticResult:
    """Parse and validate one bounded local-model response into a closed AI-powered review result.

    Missing installed tuple/socket/resolver/evidence, peer or generation mismatch, unsupported
    schema/model, refusal, or invalid/truncated output all return bounded status with no raw
    response retention beyond this call.

    ``policy_digest`` is the policy digest that authorized this disclosure, carried by the approved
    case. The adapter never mints one of its own; the outbound gateway rebinds it authoritatively
    after this returns.
    """

    if type(raw) is not bytes or not 0 < len(raw) <= _MAX_LOCAL_RESPONSE_BYTES:
        return SemanticResultInvalid(
            _provenance(
                profile,
                SemanticStatus.INVALID,
                policy_digest=policy_digest,
                latency_ms=latency_ms,
                failure_class=SemanticFailureClass.RESPONSE_SCHEMA,
            ),
            raw_size=len(raw) if type(raw) is bytes else 0,
        )
    try:
        parsed = strict_json_parse(raw)
        judgment = _judgment_from_json(parsed)
    except ValueError, TypeError, LookupError:
        return SemanticResultInvalid(
            _provenance(
                profile,
                SemanticStatus.INVALID,
                policy_digest=policy_digest,
                latency_ms=latency_ms,
                failure_class=SemanticFailureClass.RESPONSE_SCHEMA,
            ),
            raw_size=len(raw),
        )
    return SemanticResultSuccess(
        judgment,
        _provenance(
            profile,
            SemanticStatus.SUCCEEDED,
            policy_digest=policy_digest,
            latency_ms=latency_ms,
        ),
    )


class LocalModelEvaluator:
    """``SemanticEvaluatorPort`` implementation for one exact, already-connected local profile.

    Construction happens only inside the same generation-fenced reconciliation candidate that
    verified the socket handle; this class performs no resolve, socket open, or peer probe itself.
    It sends exactly one bounded approved case and parses the exact structured judgment schema, with
    no path discovery, DNS, AF_INET/AF_INET6, proxy lookup, redirect, subprocess launch, or
    package/model download, and no external fallback.
    """

    __slots__ = ("_clock", "_handle", "_profile")

    def __init__(
        self,
        profile: LocalModelEndpointProfile,
        handle: LocalModelSocketHandle,
        clock: ClockPort,
    ) -> None:
        if type(profile) is not LocalModelEndpointProfile:
            raise TypeError("local_model_profile_invalid")
        if handle.profile_digest != profile.capability_evidence_digest:
            raise ValueError("local_model_socket_profile_mismatch")
        self._profile = profile
        self._handle = handle
        self._clock = clock

    async def evaluate(self, case: ApprovedProviderCase, deadline: Deadline) -> SemanticResult:
        if type(case) is not ApprovedLocalDisclosureCase or case.sink is not (
            LocalDisclosureSink.LOCAL_MODEL
        ):
            raise TypeError("local_model_case_invalid")
        if case.binding is None or case.binding.endpoint_profile_id != (
            self._profile.endpoint_profile_id
        ):
            raise ValueError("local_model_case_binding_mismatch")
        if type(deadline) is not Deadline:
            raise TypeError("local_model_deadline_invalid")

        now_monotonic = self._clock.monotonic_seconds()
        if deadline.expired(now_monotonic):
            return SemanticResultTimeout(
                _provenance(
                    self._profile,
                    SemanticStatus.TIMEOUT,
                    policy_digest=case.policy_digest,
                    latency_ms=0,
                )
            )

        try:
            await self._handle.send(case.payload)
            raw = await self._handle.receive(_MAX_LOCAL_RESPONSE_BYTES)
        except Exception:  # noqa: BLE001 - bounded transport failures never leak native text
            elapsed_ms = max(0, int((self._clock.monotonic_seconds() - now_monotonic) * 1_000))
            return SemanticResultUnavailable(
                _provenance(
                    self._profile,
                    SemanticStatus.UNAVAILABLE,
                    policy_digest=case.policy_digest,
                    latency_ms=elapsed_ms,
                    failure_class=SemanticFailureClass.TRANSPORT,
                )
            )

        latency_ms = max(0, int((self._clock.monotonic_seconds() - now_monotonic) * 1_000))
        return normalize_local_response(
            raw, self._profile, policy_digest=case.policy_digest, latency_ms=latency_ms
        )
