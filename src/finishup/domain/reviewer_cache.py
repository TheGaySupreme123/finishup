"""Per-exchange prompt-cache accounting for the AI reviewer (#1172, ADR-006).

A review conversation carries its whole history on every exchange: a Codex thread replays it
upstream, a stateless route sends it again. The provider can serve an unchanged prefix of that
input from its prompt cache, so after the first exchange every exchange may reuse all that the
previous model request read. This module counts how much each exchange actually reused and, when
it reused less, names the one structural cause FinishUP can see. It reads integers, message roles
and FinishUP's own digest of the settings it sent; never transcript content.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Literal

__all__ = [
    "CACHE_MISS_TOLERANCE_TOKENS",
    "ExchangeCacheUsage",
    "ReviewerCacheMiss",
    "ReviewerCacheState",
    "exchange_cache_counts",
]

type ReviewerCacheMiss = Literal[
    "none", "first_turn", "schema_or_settings_change", "compaction", "retry", "unexplained"
]

# OpenAI-family prompt caches reuse a prefix from 1,024 tokens on, in whole 128-token blocks, and
# the framing before the next message may differ by a few tokens: a shortfall within one minimum
# block is not a miss.
CACHE_MISS_TOLERANCE_TOKENS: Final = 1_024
_MAX_COUNTER: Final = 2**53 - 1


@dataclass(frozen=True, slots=True)
class ExchangeCacheUsage:
    """What the provider reported for one exchange, over every model request it made.

    ``first_cached_tokens`` is what the exchange's first request read from the cache and
    ``last_input_tokens`` all that its last request read: the prefix the next exchange may reuse.
    ``cache_write_input_tokens`` is ``None`` where the provider does not report cache writes.
    """

    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    requests: int
    first_cached_tokens: int
    last_input_tokens: int
    cache_write_input_tokens: int | None = None

    def __post_init__(self) -> None:
        counters = (
            self.input_tokens,
            self.cached_input_tokens,
            self.output_tokens,
            self.requests,
            self.first_cached_tokens,
            self.last_input_tokens,
            0 if self.cache_write_input_tokens is None else self.cache_write_input_tokens,
        )
        if any(type(value) is not int or not 0 <= value <= _MAX_COUNTER for value in counters):
            raise ValueError("reviewer_cache_usage_invalid")
        if (
            self.requests < 1
            or self.cached_input_tokens > self.input_tokens
            or self.first_cached_tokens > self.cached_input_tokens
            or self.last_input_tokens > self.input_tokens
        ):
            raise ValueError("reviewer_cache_usage_invalid")


@dataclass(slots=True)
class ReviewerCacheState:
    """What one review's last exchange leaves its next exchange for cache accounting.

    A review's ``ReviewerSession`` owns it; a one-shot case uses a fresh one. ``prefix_tokens`` is
    ``None`` after an exchange whose usage the provider never reported.
    """

    exchanges: int = 0
    request_id: str | None = None
    settings: str | None = None
    prefix_tokens: int | None = 0
    messages: int = 0


def exchange_cache_counts(
    state: ReviewerCacheState,
    *,
    request_id: str,
    settings: str,
    roles: Sequence[str],
    usage: ExchangeCacheUsage | None,
    compacted: bool = False,
) -> tuple[str, dict[str, object] | None]:
    """Advance ``state`` past one exchange; the request id and bounded counts it records.

    ``request_id`` is this exchange's provider request id; the record carries the review's first
    one, so every exchange of a review shares it (the attempt's ``provider_request_id``).
    ``settings`` digests what the route sends beside the messages (reply schema, model, effort,
    output limit). ``roles`` are the exchange history's message roles, empty for a one-shot case.
    The counts are ``None`` when the provider reported no usage for the exchange, except that a
    compaction is still recorded, by its index and label alone.
    """

    opened = state.exchanges == 0
    if opened:
        state.request_id = request_id
    prefix = 0 if opened else state.prefix_tokens
    changed = not opened and settings != state.settings
    # The loop keeps an accepted reply in its history and replaces a rejected or malformed one
    # with its one format-repair notice, so a previous answer missing here means a repair.
    repair = not opened and not (
        len(roles) > state.messages and roles[state.messages] == "assistant"
    )
    index = state.exchanges + 1
    state.exchanges, state.settings, state.messages = index, settings, len(roles)
    state.prefix_tokens = None if usage is None else usage.last_input_tokens
    review_request = state.request_id or request_id
    if usage is None:
        # A compaction is labelled even when the turn reported no usage (it can come first).
        if compacted:
            return review_request, {
                "reviewer_exchange_index": index,
                "reviewer_cache_miss": "compaction",
            }
        return review_request, None
    counts: dict[str, object] = {
        "reviewer_exchange_index": index,
        "reviewer_model_requests": usage.requests,
        "reviewer_input_tokens": usage.input_tokens,
        "reviewer_cached_input_tokens": usage.cached_input_tokens,
        "reviewer_output_tokens": usage.output_tokens,
        "reviewer_prefix_cached_tokens": usage.first_cached_tokens,
    }
    if prefix is not None:
        counts["reviewer_prefix_tokens"] = prefix
    if usage.cache_write_input_tokens is not None:
        counts["reviewer_cache_write_input_tokens"] = usage.cache_write_input_tokens
    miss = _miss(
        opened=opened,
        compacted=compacted,
        prefix=prefix,
        cached=usage.first_cached_tokens,
        changed=changed,
        repair=repair,
    )
    if miss is not None:
        counts["reviewer_cache_miss"] = miss
    return review_request, counts


def _miss(
    *,
    opened: bool,
    compacted: bool,
    prefix: int | None,
    cached: int,
    changed: bool,
    repair: bool,
) -> ReviewerCacheMiss | None:
    """The exchange's closed label: ``none`` when its first request reused the whole prefix."""

    if compacted:
        return "compaction"  # the provider rewrote the history, whatever this request reused
    if opened:
        return "first_turn"  # nothing earlier in the review existed to reuse
    if prefix is None:
        return None  # the previous exchange reported no usage, so its prefix is unknown
    if prefix - cached <= CACHE_MISS_TOLERANCE_TOKENS:
        return "none"
    if changed:
        return "schema_or_settings_change"
    if repair:
        return "retry"
    return "unexplained"
