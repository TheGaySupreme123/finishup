"""OpenAI-compatible Chat Completions AI-powered evaluation adapter.

Three hosts publish an OpenAI-compatible Chat Completions endpoint but no Responses endpoint, so
:mod:`finishup.adapters.providers.openai_responses` cannot reach them: its profile pins
``/v1/responses`` and its evaluator calls ``client.responses.create``. This module is the sibling
bridge for that protocol cell. It shares the judgment schema, the judgment normalizer, and the
one-attempt credential transport with the Responses adapter, so the security-critical dispatch path
has exactly one implementation; only the request shape and the response-reading differ.

Structured-output enforcement is a per-host capability fact, not an assumption. A host that
documents strict ``response_format`` support receives the schema; a host that documents ignoring it
gets the same instruction in the prompt instead, and an answer that is not the exact judgment shape
degrades to :class:`SemanticResultInvalid` — never a fabricated pass. Until E-007 live evidence is
recorded, every profile here is configured, not live-verified.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import re
from dataclasses import dataclass
from typing import Any, Final, Literal, cast

import httpx

from finishup.adapters.providers.openai_responses import (
    OPENAI_MAX_OUTPUT_TOKENS,
    OPENAI_MAX_RESPONSE_BODY_BYTES,
    SEMANTIC_REVIEW_INSTRUCTION,
    STRICT_JUDGMENT_JSON_SCHEMA,
    OneAttemptCredentialTransport,
    normalize_answer_text,
)
from finishup.adapters.providers.reviewer_cache_telemetry import (
    api_exchange_usage,
    record_exchange_cache,
)
from finishup.adapters.reviewer_artifacts import image_messages
from finishup.domain.findings import SamplingParams, SemanticFailureClass
from finishup.domain.privacy import (
    ApprovedOutboundCase,
    ApprovedProviderCase,
    ProviderDataUseProfile,
)
from finishup.domain.values import validate_sha256_digest
from finishup.ports.clock import ClockPort
from finishup.ports.semantic import (
    CURRENT_REVIEWER_SESSION,
    Deadline,
    ProviderAttemptProvenance,
    ReviewerExchange,
    ReviewerReplySchemas,
    SemanticResult,
    SemanticResultInvalid,
    SemanticResultRefused,
    SemanticResultTimeout,
    SemanticResultUnavailable,
    reviewer_exchange,
)
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.models import SemanticStatus

__all__ = [
    "CHAT_COMPLETIONS_ALLOWED_BASE_PATH_PREFIXES",
    "CHAT_COMPLETIONS_INSTRUCTION",
    "CHAT_COMPLETIONS_JSON_SHAPE_SUFFIX",
    "ChatCompletionsEvaluator",
    "ChatCompletionsProfile",
    "RenderedChatCompletionsRequest",
    "classify_provider_failure",
    "normalize_response",
    "render_case",
]

CHAT_COMPLETIONS_ALLOWED_BASE_PATH_PREFIXES: Final = frozenset({"/v1", "/api/v1", "/v1beta/openai"})

_IDENTITY_PATTERN: Final = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$", re.ASCII)
_MODEL_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$", re.ASCII)
_HOSTNAME_PATTERN: Final = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$",
    re.ASCII,
)

# Whether the host enforces the judgment schema itself or only sees it in the instruction. This is
# an endpoint capability fact recorded per profile, never a guess made at dispatch time.
type StructuredOutputEnforcement = Literal["provider_enforced", "prompt_only"]

# The only Chat Completions-specific part of the instruction. Everything before it is the shared
# reviewer instruction owned by the Responses adapter (issue #906: one source). A hand copy here
# once silently missed every #891 rule; deriving it makes that drift impossible.
CHAT_COMPLETIONS_JSON_SHAPE_SUFFIX: Final = (
    "Reply with one JSON object and nothing else: no "
    'prose, no code fence, no explanation outside it. Its exact shape is {"conclusion": one of '
    '"no_material_discrepancy" | "challenges_returned" | "insufficient_packet", '
    '"review_summary" non-empty, "verified" array of objects with "requirement_or_claim", '
    '"verdict" ("supported" | "not_supported" | "not_assessable"), "cited_refs" and an '
    'exact "snippet" for supported/not_supported entries, '
    '"reviewer_challenges": array of objects with "finding_kind", "summary", "cited_refs", '
    '"discrepancy", "alternative_interpretation", "message_to_main_agent", '
    '"requested_next_step", "uncertainty", "snippet"; "prior_finding_verdicts": array of objects with '
    '"finding_id", "verdict" (one of "fixed" | "still_present" | "answered_not_fixed" | '
    '"unassessable" | "withdrawn"), "cited_refs", "note"}. With "insufficient_packet" add '
    '"missing_for_assessment": one to eight objects with "kind", "target_refs" (refs from '
    'citable_refs only) and a short "reason".'
)
CHAT_COMPLETIONS_INSTRUCTION: Final = (
    f"{SEMANTIC_REVIEW_INSTRUCTION} {CHAT_COMPLETIONS_JSON_SHAPE_SUFFIX}"
)
_SYSTEM_INSTRUCTION: Final = CHAT_COMPLETIONS_INSTRUCTION

_PROMPT_DIGEST: Final = "sha256:" + hashlib.sha256(_SYSTEM_INSTRUCTION.encode("utf-8")).hexdigest()
_SCHEMA_DIGEST: Final = canonical_digest(STRICT_JUDGMENT_JSON_SCHEMA)

_RESPONSE_FORMAT: Final[dict[str, JsonValue]] = {
    "type": "json_schema",
    "json_schema": {
        "name": "finishup_semantic_judgment",
        "strict": True,
        "schema": STRICT_JUDGMENT_JSON_SCHEMA,
    },
}


@dataclass(frozen=True, slots=True)
class ChatCompletionsProfile:
    """Frozen, exact, nonsecret identity/capability profile for a Chat Completions endpoint."""

    provider_id: str
    model: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    timeout_seconds: int
    structured_output_enforcement: StructuredOutputEnforcement
    data_use_profile: ProviderDataUseProfile
    host: str
    port: int = 443
    base_path_prefix: str = "/v1"

    def __post_init__(self) -> None:
        if (
            type(self.provider_id) is not str
            or _IDENTITY_PATTERN.fullmatch(self.provider_id) is None
        ):
            raise ValueError("chat_completions_profile_provider_invalid")
        if type(self.model) is not str or _MODEL_PATTERN.fullmatch(self.model) is None:
            raise ValueError("chat_completions_profile_model_invalid")
        if (
            type(self.endpoint_profile_id) is not str
            or _IDENTITY_PATTERN.fullmatch(self.endpoint_profile_id) is None
        ):
            raise ValueError("chat_completions_profile_endpoint_invalid")
        if type(self.endpoint_profile_version) is not str or not self.endpoint_profile_version:
            raise ValueError("chat_completions_profile_version_invalid")
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 300:
            raise ValueError("chat_completions_profile_timeout_invalid")
        if self.structured_output_enforcement not in {"provider_enforced", "prompt_only"}:
            raise ValueError("chat_completions_profile_capability_invalid")
        if type(self.data_use_profile) is not ProviderDataUseProfile:
            raise ValueError("chat_completions_profile_data_use_invalid")
        if type(self.host) is not str or _HOSTNAME_PATTERN.fullmatch(self.host) is None:
            raise ValueError("chat_completions_profile_host_invalid")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("chat_completions_profile_port_invalid")
        if self.base_path_prefix not in CHAT_COMPLETIONS_ALLOWED_BASE_PATH_PREFIXES:
            raise ValueError("chat_completions_profile_path_invalid")

    @property
    def path(self) -> str:
        return f"{self.base_path_prefix}/chat/completions"

    @property
    def base_url(self) -> str:
        # The OpenAI SDK appends `/chat/completions` to base_url, so the prefix belongs here and
        # the transport-enforced destination stays byte-identical to `path`.
        if self.port == 443:
            return f"https://{self.host}{self.base_path_prefix}"
        return f"https://{self.host}:{self.port}{self.base_path_prefix}"


@dataclass(frozen=True, slots=True)
class RenderedChatCompletionsRequest:
    """The exact final application JSON body plus its digest and nonsecret dispatch binding."""

    body: bytes
    body_sha256: str
    provider_id: str
    model: str
    endpoint_profile_id: str
    endpoint_profile_version: str
    prompt_digest: str
    schema_digest: str

    def __post_init__(self) -> None:
        if type(self.body) is not bytes or not 0 < len(self.body) <= OPENAI_MAX_RESPONSE_BODY_BYTES:
            raise ValueError("chat_completions_rendered_body_invalid")
        expected = "sha256:" + hashlib.sha256(self.body).hexdigest()
        if self.body_sha256 != expected:
            raise ValueError("chat_completions_rendered_digest_mismatch")
        validate_sha256_digest(self.prompt_digest)
        validate_sha256_digest(self.schema_digest)


def _build_body_object(
    case: ApprovedOutboundCase,
    profile: ChatCompletionsProfile,
    exchange: ReviewerExchange | None = None,
) -> dict[str, JsonValue]:
    if exchange is not None:
        # One reviewer-loop exchange (#1118 unit 3): ordinary system/user/assistant messages, the
        # approved history verbatim, no functions or tool calls. A prompt-only endpoint cannot
        # constrain the reply branch, so it is refused rather than relabelled as enforced.
        if profile.structured_output_enforcement != "provider_enforced":
            raise ValueError("chat_completions_reviewer_schema_unavailable")
        return {
            "model": case.provider_binding.model_id,
            "messages": image_messages(exchange.history, "chat"),
            "max_tokens": OPENAI_MAX_OUTPUT_TOKENS,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "finishup_reviewer_reply",
                    "strict": True,
                    "schema": exchange.schema,
                },
            },
        }
    try:
        payload_text = case.payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("chat_completions_case_payload_invalid") from exc
    if not payload_text:
        raise ValueError("chat_completions_case_payload_invalid")
    # Chat Completions message content is text, not a nested JSON value: the approved canonical
    # payload bytes travel verbatim as the user message string. Passing a parsed object here is
    # what makes these endpoints reject the request before any review can happen.
    if case.purpose == "credential-probe":
        body: dict[str, JsonValue] = {
            "model": case.provider_binding.model_id,
            "messages": [{"role": "user", "content": payload_text}],
            "max_tokens": 1,
        }
    else:
        body = {
            "model": case.provider_binding.model_id,
            "messages": [
                {"role": "system", "content": _SYSTEM_INSTRUCTION},
                {"role": "user", "content": payload_text},
            ],
            "max_tokens": OPENAI_MAX_OUTPUT_TOKENS,
        }
    if (
        case.purpose != "credential-probe"
        and profile.structured_output_enforcement == "provider_enforced"
    ):
        body["response_format"] = _RESPONSE_FORMAT
    return body


def render_case(
    case: ApprovedOutboundCase,
    profile: ChatCompletionsProfile,
    reply_schemas: ReviewerReplySchemas | None = None,
) -> RenderedChatCompletionsRequest:
    """Deterministically convert an approved external case into a rendered request.

    Only the already-approved canonical payload bytes are copied into the request; this function
    selects, minimizes, summarizes, redacts, or adds nothing. It recomputes an independent
    reference body/digest so the one-attempt transport can refuse to dispatch anything the pinned
    SDK serializes differently.
    """

    if type(case) is not ApprovedOutboundCase:
        raise TypeError("chat_completions_case_invalid")
    if type(profile) is not ChatCompletionsProfile:
        raise TypeError("chat_completions_profile_invalid")
    return _render(case, profile, reviewer_exchange(case.media_type, case.payload, reply_schemas))


def _render(
    case: ApprovedOutboundCase, profile: ChatCompletionsProfile, exchange: ReviewerExchange | None
) -> RenderedChatCompletionsRequest:
    if case.provider_binding.transport != "external":
        raise ValueError("chat_completions_case_binding_invalid")

    body = canonical_encode(_build_body_object(case, profile, exchange))
    if len(body) > OPENAI_MAX_RESPONSE_BODY_BYTES:
        raise ValueError("chat_completions_rendered_body_too_large")

    prompt_digest, schema_digest = _digests(exchange)
    if case.purpose == "credential-probe":
        prompt_digest = "sha256:" + hashlib.sha256(case.payload).hexdigest()
        schema_digest = canonical_digest({"kind": "credential-probe", "version": 1})
    return RenderedChatCompletionsRequest(
        body=body,
        body_sha256="sha256:" + hashlib.sha256(body).hexdigest(),
        provider_id=case.provider_binding.provider_id,
        model=case.provider_binding.model_id,
        endpoint_profile_id=case.provider_binding.endpoint_profile_id,
        endpoint_profile_version=case.provider_binding.endpoint_profile_version,
        prompt_digest=prompt_digest,
        schema_digest=schema_digest,
    )


def _digests(exchange: ReviewerExchange | None) -> tuple[str, str]:
    if exchange is None:
        return _PROMPT_DIGEST, _SCHEMA_DIGEST
    return exchange.prompt_digest, exchange.schema_digest


def _provenance(
    profile: ChatCompletionsProfile,
    status: SemanticStatus,
    *,
    policy_digest: str,
    latency_ms: int,
    provider_request_id: str | None = None,
    failure_class: SemanticFailureClass | None = None,
    exchange: ReviewerExchange | None = None,
) -> ProviderAttemptProvenance:
    prompt_digest, schema_digest = _digests(exchange)
    return ProviderAttemptProvenance(
        provider=profile.provider_id,
        endpoint_profile_id=profile.endpoint_profile_id,
        endpoint_profile_version=profile.endpoint_profile_version,
        model=profile.model,
        sdk_version="2.46.0",
        prompt_digest=prompt_digest,
        schema_digest=schema_digest,
        policy_digest=policy_digest,
        privacy_policy_digest=policy_digest,
        sampling_params=SamplingParams(OPENAI_MAX_OUTPUT_TOKENS),
        latency_ms=latency_ms,
        status=status,
        provider_request_id=provider_request_id,
        failure_class=failure_class,
    )


def _first_choice(response: object) -> object | None:
    choices = getattr(response, "choices", None)
    if not isinstance(choices, list | tuple):
        return None
    items = tuple(cast(list[object], choices))
    return items[0] if items else None


def normalize_response(
    response: object,
    profile: ChatCompletionsProfile,
    *,
    policy_digest: str,
    latency_ms: int,
    late: bool = False,
    exchange: ReviewerExchange | None = None,
) -> SemanticResult:
    """Classify one provider response into the closed AI-powered review result union.

    Inspection order matches the Responses adapter: explicit refusal surface first, truncation and
    filtering next, parse/schema validity next, and late-arrival state last. A host that ignored
    the requested structure lands in the invalid branch, which is the honest outcome; there is no
    prose-to-judgment repair path.

    ``policy_digest`` is the policy digest that authorized this dispatch, carried by the approved
    case. The adapter never mints one of its own; the outbound gateway rebinds it authoritatively
    after this returns.
    """

    provider_request_id = getattr(response, "id", None)
    if type(provider_request_id) is not str:
        provider_request_id = None

    def prov(
        status: SemanticStatus, failure: SemanticFailureClass | None = None
    ) -> ProviderAttemptProvenance:
        return _provenance(
            profile,
            status,
            policy_digest=policy_digest,
            latency_ms=latency_ms,
            provider_request_id=provider_request_id,
            failure_class=failure,
            exchange=exchange,
        )

    choice = _first_choice(response)
    message = getattr(choice, "message", None)

    refusal = getattr(message, "refusal", None)
    if type(refusal) is str and refusal:
        return SemanticResultRefused(prov(SemanticStatus.REFUSED))

    finish_reason = getattr(choice, "finish_reason", None)
    if finish_reason == "content_filter":
        return SemanticResultRefused(prov(SemanticStatus.REFUSED))
    if finish_reason == "length":
        # Truncated output is the Chat Completions spelling of Responses `incomplete`: content
        # invalidity from the output token cap, not a transport/deadline timeout.
        truncated_text = getattr(message, "content", None)
        truncated_size = len(truncated_text.encode("utf-8")) if type(truncated_text) is str else 0
        return SemanticResultInvalid(
            prov(SemanticStatus.INVALID, SemanticFailureClass.RESPONSE_CONTENT),
            raw_size=truncated_size,
        )

    return normalize_answer_text(
        getattr(message, "content", None), prov, late=late, reply=exchange is not None
    )


def classify_provider_failure(
    error: BaseException,
    profile: ChatCompletionsProfile,
    *,
    policy_digest: str,
    latency_ms: int,
    exchange: ReviewerExchange | None = None,
) -> SemanticResult:
    """Map a native provider/transport failure to the public taxonomy without leaking its text."""

    def prov(status: SemanticStatus, failure: SemanticFailureClass) -> ProviderAttemptProvenance:
        return _provenance(
            profile,
            status,
            policy_digest=policy_digest,
            exchange=exchange,
            latency_ms=latency_ms,
            failure_class=failure,
        )

    if isinstance(error, httpx.TimeoutException | TimeoutError):
        return SemanticResultTimeout(prov(SemanticStatus.TIMEOUT, SemanticFailureClass.TIMEOUT))
    if isinstance(error, httpx.TransportError):
        return SemanticResultUnavailable(
            prov(SemanticStatus.UNAVAILABLE, SemanticFailureClass.TRANSPORT)
        )

    status_code = getattr(error, "status_code", None)
    if type(status_code) is not int:
        response = getattr(error, "response", None)
        status_code = getattr(response, "status_code", None)

    failure_class = SemanticFailureClass.TRANSPORT
    if status_code == 401:
        failure_class = SemanticFailureClass.AUTHENTICATION
    elif status_code == 403:
        failure_class = SemanticFailureClass.AUTHORIZATION
    elif status_code == 429:
        failure_class = SemanticFailureClass.RATE_LIMITED
    elif status_code == 404:
        # An OpenAI-compatible surface that does not serve this path is an unsupported profile,
        # not an outage: retrying the same binding cannot help.
        failure_class = SemanticFailureClass.UNSUPPORTED_PROFILE
    elif type(status_code) is int and status_code >= 500:
        failure_class = SemanticFailureClass.PROVIDER_OUTAGE
    return SemanticResultUnavailable(prov(SemanticStatus.UNAVAILABLE, failure_class))


class ChatCompletionsEvaluator:
    """``SemanticEvaluatorPort`` implementation for an approved OpenAI-compatible Chat endpoint.

    Constructed only behind the privacy gateway for one physical attempt, with a
    ``OneAttemptCredentialTransport`` already bound to a fresh credential handle and the
    precomputed final-body digest. Exactly one physical provider call per :meth:`evaluate`, no
    internal retry, and no credential in any reusable client, header, log, or exception.
    """

    __slots__ = ("_clock", "_profile", "_reply_schemas", "_safety_margin_seconds", "_transport")

    def __init__(
        self,
        profile: ChatCompletionsProfile,
        transport: OneAttemptCredentialTransport,
        clock: ClockPort,
        *,
        safety_margin_seconds: float = 0.0,
        reply_schemas: ReviewerReplySchemas | None = None,
    ) -> None:
        if type(profile) is not ChatCompletionsProfile:
            raise TypeError("chat_completions_profile_invalid")
        if type(transport) is not OneAttemptCredentialTransport:
            raise TypeError("chat_completions_transport_invalid")
        if safety_margin_seconds < 0.0:
            raise ValueError("chat_completions_safety_margin_invalid")
        self._profile = profile
        self._transport = transport
        self._clock = clock
        self._safety_margin_seconds = safety_margin_seconds
        self._reply_schemas = reply_schemas

    async def evaluate(self, case: ApprovedProviderCase, deadline: Deadline) -> SemanticResult:
        if type(case) is not ApprovedOutboundCase:
            raise TypeError("chat_completions_case_invalid")
        if type(deadline) is not Deadline:
            raise TypeError("chat_completions_deadline_invalid")

        exchange = reviewer_exchange(case.media_type, case.payload, self._reply_schemas)
        now_monotonic = self._clock.monotonic_seconds()
        remaining = deadline.remaining_seconds(now_monotonic) - self._safety_margin_seconds
        if deadline.expired(now_monotonic) or remaining <= 0.0:
            return SemanticResultTimeout(
                _provenance(
                    self._profile,
                    SemanticStatus.TIMEOUT,
                    policy_digest=case.policy_digest,
                    latency_ms=0,
                    failure_class=SemanticFailureClass.TIMEOUT,
                    exchange=exchange,
                )
            )

        # The SDK kwargs are the canonical rendering itself, so the one-attempt transport's
        # exact-body comparison sees the bytes the gateway audited (as in the Responses adapter).
        rendered_body = strict_json_parse(_render(case, self._profile, exchange).body)
        if type(rendered_body) is not dict:
            raise ValueError("chat_completions_rendered_body_invalid")
        body_object = cast(dict[str, Any], rendered_body)

        try:
            openai_module = importlib.import_module("openai")
        except ImportError:
            return SemanticResultUnavailable(
                _provenance(
                    self._profile,
                    SemanticStatus.UNAVAILABLE,
                    policy_digest=case.policy_digest,
                    latency_ms=0,
                    failure_class=SemanticFailureClass.UNSUPPORTED_PROFILE,
                    exchange=exchange,
                )
            )

        http_client = httpx.AsyncClient(transport=self._transport, trust_env=False)
        try:
            client: Any = openai_module.AsyncOpenAI(
                api_key="finishup-fixed-nonsecret-sentinel",
                base_url=self._profile.base_url,
                timeout=remaining,
                max_retries=0,
                http_client=http_client,
            )
            try:
                # The whole exchange, not only each HTTP operation, ends at the deadline.
                response = await asyncio.wait_for(
                    client.post(
                        "/chat/completions",
                        cast_to=openai_module.types.chat.ChatCompletion,
                        body=body_object,
                    ),
                    remaining,
                )
            finally:
                await client.close()
        except Exception as exc:  # noqa: BLE001 - classified below, never re-raised raw
            elapsed_ms = max(0, int((self._clock.monotonic_seconds() - now_monotonic) * 1_000))
            return classify_provider_failure(
                exc,
                self._profile,
                policy_digest=case.policy_digest,
                latency_ms=elapsed_ms,
                exchange=exchange,
            )
        finally:
            await http_client.aclose()

        finished = self._clock.monotonic_seconds()
        if case.purpose != "credential-probe":
            record_exchange_cache(
                component="openai_chat_completions",
                request_id=case.request_id,
                session=CURRENT_REVIEWER_SESSION.get(),
                exchange=exchange,
                settings={key: value for key, value in body_object.items() if key != "messages"},
                usage=api_exchange_usage(
                    getattr(response, "usage", None),
                    input_name="prompt_tokens",
                    details_name="prompt_tokens_details",
                    output_name="completion_tokens",
                ),
                # A truncated (``length``) or filtered answer is not a completed generation, as
                # Responses reports its own ``incomplete`` status.
                completed=getattr(_first_choice(response), "finish_reason", None) == "stop",
            )
        return normalize_response(
            response,
            self._profile,
            policy_digest=case.policy_digest,
            latency_ms=max(0, int((finished - now_monotonic) * 1_000)),
            late=deadline.expired(finished),
            exchange=exchange,
        )
