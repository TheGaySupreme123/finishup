"""The reviewer loop's model facade: one admitted gateway dispatch per completion (#1118 unit 3).

``complete`` renders the canonical history into an exchange payload and hands it to ``dispatch``,
the service's per-exchange admission (proposal, approval, authorization, then
``PolicyEnforcingOutboundGateway``), so every continuation gets its own exact-body admission,
consume and one-use transport. The facade is bound to one provider binding for the whole review:
a reply from any other route ends the review instead of continuing it, so no exchange silently
moves to a separately billed provider.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from finishup.domain.privacy import ProviderBinding
from finishup.ports.semantic import (
    REVIEWER_EXCHANGE_MEDIA_TYPES,
    Deadline,
    ReviewerExchangeMode,
    ReviewerMessage,
    SemanticResult,
    SemanticResultSuccess,
    encode_reviewer_exchange,
)

__all__ = ["ExchangeDispatch", "ReviewerExchangeModel"]

type ExchangeDispatch = Callable[[bytes, str, Deadline], Awaitable[SemanticResult]]


@dataclass(frozen=True, slots=True)
class ReviewerExchangeModel:
    binding: ProviderBinding
    dispatch: ExchangeDispatch

    async def complete(
        self,
        history: tuple[ReviewerMessage, ...],
        schema: ReviewerExchangeMode,
        *,
        deadline: Deadline,
    ) -> SemanticResult:
        """One completion: a ``SemanticResultReply`` or the bounded failure of this exchange."""

        payload = encode_reviewer_exchange(history)
        result = await self.dispatch(payload, REVIEWER_EXCHANGE_MEDIA_TYPES[schema], deadline)
        provenance = result.provenance
        if type(result) is SemanticResultSuccess or (
            provenance.endpoint_profile_id,
            provenance.endpoint_profile_version,
            provenance.model,
        ) != (
            self.binding.endpoint_profile_id,
            self.binding.endpoint_profile_version,
            self.binding.model_id,
        ):
            # A bare judgment means the route ignored the exchange contract; another route means
            # the binding changed under the review. Neither may continue the conversation.
            raise ValueError("reviewer_exchange_route_mismatch")
        return result
