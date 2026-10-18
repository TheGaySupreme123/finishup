"""The reviewer loop's model facade: one admitted gateway dispatch per completion (#1118 unit 3).

``complete`` renders the canonical history into an exchange payload and hands it to ``dispatch``,
the service's per-exchange admission (proposal, approval, authorization, then
``PolicyEnforcingOutboundGateway``), so every continuation gets its own exact-body admission,
consume and one-use transport. The facade is bound to one provider binding for the whole review:
a reply from any other route ends the review instead of continuing it, so no exchange silently
moves to a separately billed provider.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Final

from finishup.adapters.providers.reviewer_reply import ReviewerReplyInvalid, reviewer_reply_schema
from finishup.application.reviewer_loop import ReviewerModelError, Turn
from finishup.domain.privacy import ProviderBinding
from finishup.ports.semantic import (
    REVIEWER_EXCHANGE_MEDIA_TYPES,
    Deadline,
    ReviewerReplySchemas,
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

type ExchangeDispatch = Callable[[bytes, str, Deadline], Awaitable[SemanticResult]]


@dataclass(frozen=True, slots=True)
class ReviewerExchangeModel:
    """``ReviewerModel`` for the loop: a reply object, or ``ReviewerModelError`` ending it."""

    binding: ProviderBinding
    dispatch: ExchangeDispatch

    async def complete(
        self, history: Sequence[Turn], schema: dict[str, JsonValue], *, deadline: Deadline
    ) -> JsonValue:
        if schema == REVIEWER_REPLY_SCHEMAS.turn:
            mode = "turn"
        elif schema == REVIEWER_REPLY_SCHEMAS.final:
            mode = "final"
        else:
            raise ReviewerModelError("reviewer_schema_unknown")
        payload = encode_reviewer_exchange(tuple((turn.role, turn.content) for turn in history))
        result = await self.dispatch(payload, REVIEWER_EXCHANGE_MEDIA_TYPES[mode], deadline)
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
        if type(result) is SemanticResultInvalid:
            # A completed turn whose output is not one JSON object: the loop's one format repair.
            raise ReviewerReplyInvalid("output_not_json")
        if type(result) is not SemanticResultReply:
            # A failed, refused, late or uncertain turn ends the review; a bare judgment means
            # the route ignored the exchange contract. Neither is retried here.
            raise ReviewerModelError(f"reviewer_exchange_{result.provenance.status.value}")
        return result.reply
