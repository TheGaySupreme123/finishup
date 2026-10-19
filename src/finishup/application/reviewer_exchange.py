"""The reviewer loop's model facade: one admitted gateway dispatch per completion (#1118 unit 3).

``dispatch`` is the service's per-exchange admission and ``PolicyEnforcingOutboundGateway``, so
every continuation gets its own exact-body admission, consume and one-use transport. The facade
serves one review: one provider binding (another route's reply ends the review, never a separately
billed fallback) and one ``ReviewerSession``, which every dispatch carries and ``async with``
closes on every exit.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Final

from finishup.adapters.providers.reviewer_reply import ReviewerReplyInvalid, reviewer_reply_schema
from finishup.application.reviewer_loop import ReviewerModelError, Turn
from finishup.domain.findings import SemanticFailureClass
from finishup.domain.privacy import ProviderBinding
from finishup.ports.semantic import (
    CURRENT_REVIEWER_SESSION,
    REVIEWER_EXCHANGE_MEDIA_TYPES,
    Deadline,
    ReviewerReplySchemas,
    ReviewerSession,
    SemanticResult,
    SemanticResultInvalid,
    SemanticResultReply,
    encode_reviewer_exchange,
)
from finishup.protocol.canonical import JsonValue

__all__ = ["REVIEWER_REPLY_SCHEMAS", "ExchangeDispatch", "ReviewerExchangeModel"]

# The provider-wire reply schemas composition installs on every route's factory.
REVIEWER_REPLY_SCHEMAS: Final = ReviewerReplySchemas(
    turn=reviewer_reply_schema(reads_allowed=True, strict=True),
    final=reviewer_reply_schema(reads_allowed=False, strict=True),
)
# Runtime stages of a completed answer that is not one JSON object.
_MALFORMED_STAGES: Final = frozenset({"output_empty", "output_not_json"})

type ExchangeDispatch = Callable[[bytes, str, Deadline], Awaitable[SemanticResult]]


@dataclass(frozen=True, slots=True)
class ReviewerExchangeModel:
    """``ReviewerModel`` for one review: a reply object, or ``ReviewerModelError`` ending it."""

    binding: ProviderBinding
    dispatch: ExchangeDispatch
    session: ReviewerSession

    async def __aenter__(self) -> ReviewerExchangeModel:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.session.aclose()

    async def complete(
        self, history: Sequence[Turn], schema: dict[str, JsonValue], *, deadline: Deadline
    ) -> JsonValue:
        if schema == REVIEWER_REPLY_SCHEMAS.turn:
            media_type = REVIEWER_EXCHANGE_MEDIA_TYPES["turn"]
        elif schema == REVIEWER_REPLY_SCHEMAS.final:
            media_type = REVIEWER_EXCHANGE_MEDIA_TYPES["final"]
        else:
            raise ReviewerModelError("reviewer_schema_unknown")
        payload = encode_reviewer_exchange(tuple((turn.role, turn.content) for turn in history))
        token = CURRENT_REVIEWER_SESSION.set(self.session)
        try:
            result = await self.dispatch(payload, media_type, deadline)
        finally:
            CURRENT_REVIEWER_SESSION.reset(token)
        provenance = result.provenance
        if (
            provenance.endpoint_profile_id,
            provenance.endpoint_profile_version,
            provenance.model,
        ) != (
            self.binding.endpoint_profile_id,
            self.binding.endpoint_profile_version,
            self.binding.model_id,
        ):
            # Another route answered: the binding changed under the review. It may not continue.
            raise ReviewerModelError("reviewer_exchange_route_mismatch")
        if type(result) is SemanticResultReply:
            return result.reply
        reason = provenance.status.value
        if type(result) is SemanticResultInvalid:
            # Only a completed answer that is not one JSON object earns the loop's one repair.
            # Truncation, output limits and other incomplete turns end with their own reason.
            stage = (
                None
                if provenance.runtime_evidence is None
                else (provenance.runtime_evidence.failure_stage)
            )
            failure = provenance.failure_class
            if stage in _MALFORMED_STAGES or (
                provenance.runtime_evidence is None
                and failure is SemanticFailureClass.RESPONSE_SCHEMA
            ):
                raise ReviewerReplyInvalid("output_not_json")
            reason = stage or (reason if failure is None else failure.value)
        # A failed, refused, late or uncertain turn ends the review; a bare judgment means the
        # route ignored the exchange contract. Neither is retried here.
        raise ReviewerModelError(f"reviewer_exchange_{reason}")
