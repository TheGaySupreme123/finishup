"""Per-exchange prompt-cache telemetry every reviewer route records (#1172, ADR-006).

Each provider exchange writes one ``exchange_cache`` owner diagnostic: the provider-reported input,
cached input, cache-write (where the provider reports it) and output tokens, the prefix the
exchange could reuse from the review's earlier exchanges, and the closed miss label
``domain.reviewer_cache`` derives. Only integers, that one closed token and the review's first
provider request id are recorded. Telemetry never changes an outcome: any failure here is dropped.
"""

from __future__ import annotations

from collections.abc import Mapping

from finishup.domain.reviewer_cache import (
    ExchangeCacheUsage,
    ReviewerCacheState,
    exchange_cache_counts,
)
from finishup.observability.logging import record_bounded_counts_without_raising
from finishup.ports.semantic import ReviewerExchange, ReviewerSession
from finishup.protocol.canonical import JsonValue, canonical_digest

__all__ = ["api_exchange_usage", "record_exchange_cache"]


def api_exchange_usage(
    usage: object, *, input_name: str, details_name: str, output_name: str
) -> ExchangeCacheUsage | None:
    """One stateless API request's reported usage, or ``None`` unless it is whole.

    Responses reports ``input_tokens``/``input_tokens_details.cached_tokens``/``output_tokens``,
    Chat Completions ``prompt_tokens``/``prompt_tokens_details.cached_tokens``/
    ``completion_tokens``; neither reports cache writes.
    """

    try:
        input_tokens = getattr(usage, input_name, None)
        cached_tokens = getattr(getattr(usage, details_name, None), "cached_tokens", None)
        output_tokens = getattr(usage, output_name, None)
    except Exception:  # noqa: BLE001 - an unexpected SDK shape is no usage, never a failure
        return None
    if type(input_tokens) is not int or type(cached_tokens) is not int:
        return None
    if type(output_tokens) is not int:
        return None
    try:
        return ExchangeCacheUsage(
            input_tokens, cached_tokens, output_tokens, 1, cached_tokens, input_tokens
        )
    except ValueError:
        return None


def record_exchange_cache(
    *,
    component: str,
    request_id: str,
    session: ReviewerSession | None,
    exchange: ReviewerExchange | None,
    settings: Mapping[str, JsonValue],
    usage: ExchangeCacheUsage | None,
    completed: bool,
    compacted: bool = False,
) -> None:
    """Account one exchange in its review's cache state and record it, never raising.

    ``settings`` is what the route sent beside the messages; only its digest is kept, to notice a
    change between a review's exchanges. A one-shot case (no review session) opens its own
    conversation.
    """

    try:
        state = (
            session.cache if exchange is not None and session is not None else ReviewerCacheState()
        )
        review_request, counts = exchange_cache_counts(
            state,
            request_id=request_id,
            settings=canonical_digest(dict(settings)),
            roles=() if exchange is None else tuple(role for role, _text in exchange.history),
            usage=usage,
            compacted=compacted,
        )
        if counts is not None:
            record_bounded_counts_without_raising(
                component=component,
                operation="exchange_cache",
                outcome="completed" if completed else "incomplete",
                counts=counts,
                request_id=review_request,
            )
    except Exception:  # noqa: BLE001 - telemetry is never allowed to change a review
        return
