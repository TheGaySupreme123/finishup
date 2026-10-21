"""Per-exchange prompt-cache accounting labels each miss by its one structural cause (#1172)."""

from __future__ import annotations

import pytest

from finishup.domain.reviewer_cache import (
    CACHE_MISS_TOLERANCE_TOKENS,
    ExchangeCacheUsage,
    ReviewerCacheState,
    exchange_cache_counts,
)

_FIRST_ROLES = ("system", "user", "user")
_NEXT_ROLES = (*_FIRST_ROLES, "assistant", "user")
_REPAIR_ROLES = (*_FIRST_ROLES, "user")
_REQUEST = "req_72000000-0000-4000-8000-000000000001"
_LATER = "req_72000000-0000-4000-8000-000000000002"


def _usage(input_tokens: int, cached: int, *, requests: int = 1) -> ExchangeCacheUsage:
    return ExchangeCacheUsage(
        input_tokens=input_tokens,
        cached_input_tokens=cached,
        output_tokens=40,
        requests=requests,
        first_cached_tokens=cached,
        last_input_tokens=input_tokens,
    )


def _opened(state: ReviewerCacheState, input_tokens: int = 90_000) -> None:
    request, counts = exchange_cache_counts(
        state, request_id=_REQUEST, settings="s", roles=_FIRST_ROLES, usage=_usage(input_tokens, 0)
    )
    assert request == _REQUEST and counts is not None
    assert counts["reviewer_cache_miss"] == "first_turn"
    assert (counts["reviewer_exchange_index"], counts["reviewer_prefix_tokens"]) == (1, 0)


def test_the_first_exchange_is_the_cold_start_and_names_the_review_request() -> None:
    state = ReviewerCacheState()
    _opened(state)
    # The next exchange reuses the whole first request, under its own request id: the record
    # still carries the review's first one, so every exchange joins the attempt's row.
    request, counts = exchange_cache_counts(
        state,
        request_id=_LATER,
        settings="s",
        roles=_NEXT_ROLES,
        usage=_usage(92_000, 89_984),
    )
    assert request == _REQUEST and counts == {
        "reviewer_exchange_index": 2,
        "reviewer_model_requests": 1,
        "reviewer_input_tokens": 92_000,
        "reviewer_cached_input_tokens": 89_984,
        "reviewer_output_tokens": 40,
        "reviewer_prefix_cached_tokens": 89_984,
        "reviewer_prefix_tokens": 90_000,
        "reviewer_cache_miss": "none",
    }


@pytest.mark.parametrize(
    ("shortfall", "label"),
    [(CACHE_MISS_TOLERANCE_TOKENS, "none"), (CACHE_MISS_TOLERANCE_TOKENS + 1, "unexplained")],
)
def test_a_shortfall_within_one_minimum_cache_block_is_not_a_miss(
    shortfall: int, label: str
) -> None:
    state = ReviewerCacheState()
    _opened(state)
    _request, counts = exchange_cache_counts(
        state,
        request_id=_LATER,
        settings="s",
        roles=_NEXT_ROLES,
        usage=_usage(92_000, 90_000 - shortfall),
    )
    assert counts is not None and counts["reviewer_cache_miss"] == label


def test_a_changed_schema_or_setting_names_the_miss() -> None:
    state = ReviewerCacheState()
    _opened(state)
    _request, counts = exchange_cache_counts(
        state, request_id=_LATER, settings="final", roles=_NEXT_ROLES, usage=_usage(95_000, 0)
    )
    assert counts is not None and counts["reviewer_cache_miss"] == "schema_or_settings_change"
    # A changed setting that still reused the prefix is no miss at all.
    _request, counts = exchange_cache_counts(
        state,
        request_id=_LATER,
        settings="other",
        roles=(*_NEXT_ROLES, "assistant", "user"),
        usage=_usage(97_000, 95_000),
    )
    assert counts is not None and counts["reviewer_cache_miss"] == "none"


def test_a_format_repair_that_missed_is_a_retry() -> None:
    state = ReviewerCacheState()
    _opened(state)
    # The loop left the rejected answer out and appended its repair notice.
    _request, counts = exchange_cache_counts(
        state, request_id=_LATER, settings="s", roles=_REPAIR_ROLES, usage=_usage(90_100, 0)
    )
    assert counts is not None and counts["reviewer_cache_miss"] == "retry"


def test_compaction_outranks_every_other_cause() -> None:
    state = ReviewerCacheState()
    request, counts = exchange_cache_counts(
        state,
        request_id=_REQUEST,
        settings="s",
        roles=(),
        usage=_usage(250_000, 0, requests=2),
        compacted=True,
    )
    assert request == _REQUEST and counts is not None
    assert counts["reviewer_cache_miss"] == "compaction"
    assert counts["reviewer_model_requests"] == 2


def test_unreported_usage_records_nothing_and_leaves_the_next_prefix_unknown() -> None:
    state = ReviewerCacheState()
    request, counts = exchange_cache_counts(
        state, request_id=_REQUEST, settings="s", roles=_FIRST_ROLES, usage=None
    )
    assert (request, counts) == (_REQUEST, None)
    assert state.prefix_tokens is None and state.exchanges == 1
    _request, counts = exchange_cache_counts(
        state, request_id=_LATER, settings="s", roles=_NEXT_ROLES, usage=_usage(91_000, 0)
    )
    # No label is guessed against a prefix nobody reported.
    assert counts is not None and "reviewer_cache_miss" not in counts
    assert "reviewer_prefix_tokens" not in counts


def test_a_compaction_without_usage_is_still_labelled() -> None:
    state = ReviewerCacheState()
    _opened(state)
    request, counts = exchange_cache_counts(
        state, request_id=_LATER, settings="s", roles=_NEXT_ROLES, usage=None, compacted=True
    )
    # It can come before any usage snapshot: the index and the label still reach the record.
    assert (request, counts) == (
        _REQUEST,
        {"reviewer_exchange_index": 2, "reviewer_cache_miss": "compaction"},
    )


def test_cache_writes_are_recorded_only_where_the_provider_reports_them() -> None:
    usage = ExchangeCacheUsage(10, 0, 1, 1, 0, 10, cache_write_input_tokens=7)
    _request, counts = exchange_cache_counts(
        ReviewerCacheState(), request_id=_REQUEST, settings="s", roles=(), usage=usage
    )
    assert counts is not None and counts["reviewer_cache_write_input_tokens"] == 7
    _request, counts = exchange_cache_counts(
        ReviewerCacheState(), request_id=_REQUEST, settings="s", roles=(), usage=_usage(10, 0)
    )
    assert counts is not None and "reviewer_cache_write_input_tokens" not in counts


@pytest.mark.parametrize(
    "fields",
    [
        (10, 11, 0, 1, 0, 10),  # cached input above input
        (10, 4, 0, 1, 5, 10),  # the first request's reuse above the exchange's
        (10, 0, 0, 1, 0, 11),  # the last request read more than the exchange
        (10, 0, 0, 0, 0, 10),  # no model request
        (-1, 0, 0, 1, 0, 0),
        (True, 0, 0, 1, 0, 0),
    ],
)
def test_incoherent_usage_is_refused(fields: tuple[int, int, int, int, int, int]) -> None:
    with pytest.raises(ValueError, match="^reviewer_cache_usage_invalid$"):
        ExchangeCacheUsage(*fields)
