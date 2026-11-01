"""How much of the reviewer model's context one review conversation may fill (#1118, ADR-006).

The reviewer conversation is one Codex thread: the loop instruction, the packet, the read catalog,
the reviewer's replies and the read results all stay in the model's context, and Codex compacting
the thread is refused on the reviewer path (``thread/compacted``). So the whole conversation, plus
what the model needs to answer each turn, must fit below the point where Codex would compact.

Tokens are estimated, not counted with the model's tokenizer: the reviewer model's tokenizer is not
published, and the closest public one (``o200k_base``) needs a vocabulary FinishUP would have to
download or vendor. The estimate is deterministic, so a recovered review plans the same case:

* every byte at or above ``0x80`` is one token (byte-level BPE never yields more tokens than
  bytes, so this part is a strict upper bound);
* every other byte is 5/9 of a token (1.8 ASCII bytes per token).

Measured against ``o200k_base`` (ADR-006 has the table), the estimate is at least the real count on
the reviewer packets, source, documents and lockfiles measured, overcounting real packets by
1.3-2.0x. It undercounts dense random identifiers (SHA-256 hex, UUIDs) by up to 2.6%,
``\\u``-escaped non-ASCII text by up to 8% and content made entirely of random characters by up
to 27%; the estimation margin below holds back an eighth of the ceiling for that, and anything
beyond it fails closed (Codex reports the context exceeded or compacts, which the reviewer
refuses), never silently truncated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

__all__ = [
    "AUTO_COMPACT_PERCENT",
    "ESTIMATE_MARGIN_DIVISOR",
    "GROWTH_RESERVE_TOKENS",
    "MAX_SIZED_EXCHANGE_BYTES",
    "MESSAGE_OVERHEAD_TOKENS",
    "REVIEWER_FRAME_BYTES",
    "RUNTIME_FRAMING_TOKENS",
    "TURN_RESERVE_TOKENS",
    "UNSIZED_EXCHANGE_BYTES",
    "ReviewerContextWindow",
    "ReviewerExchangeBudget",
    "ReviewerTokenBudget",
    "estimated_model_tokens",
    "reviewer_token_budget",
]

# Codex derives its auto-compact threshold as 90% of the context window when the model entry sets
# none (``codex-rs/protocol/src/openai_models.rs`` ``auto_compact_token_limit``, 0.162.1). It is
# lower than the 95% ``effective_context_window_percent``, so it is the binding ceiling.
AUTO_COMPACT_PERCENT: Final = 90
# Codex's own turn framing beside FinishUP's messages: permission and environment context and the
# reply schema sent with every ``turn/start``.
RUNTIME_FRAMING_TOKENS: Final = 4_096
# What one turn needs beyond its input: reasoning (32,768) plus the largest visible output a
# review budget may set (``CODEX_OUTPUT_LIMIT_MAX``, 8,192).
TURN_RESERVE_TOKENS: Final = 40_960
# One eighth of the ceiling is held back for estimation error (see the module docstring).
ESTIMATE_MARGIN_DIVISOR: Final = 8
# Room the first exchange leaves for what later exchanges add: the reviewer's replies, the read
# results (24,576 bytes at most, under one token per byte) and a format-repair notice.
GROWTH_RESERVE_TOKENS: Final = 16_384
# Each message's role and separators inside the model's input.
MESSAGE_OVERHEAD_TOKENS: Final = 8
# The hard byte bound on one exchange of a sized route. Sized from the token budget: 169,144
# estimated tokens at 1.8 bytes each are 304,459 bytes of message text, and the exchange carries
# that text JSON-escaped once more (1.4x on the most escape-heavy packets measured), about 426 KB.
# It equals ``MAX_EGRESS_CASE_BYTES``, the outbound-document bound proposals and dispatches already
# carry, and stays below Codex's own turn input limit of 1,048,576 characters
# (``MAX_USER_INPUT_TEXT_CHARS``, 0.162.1).
MAX_SIZED_EXCHANGE_BYTES: Final = 524_288
# A route whose model context FinishUP cannot size keeps the exchange bound it always had.
UNSIZED_EXCHANGE_BYTES: Final = 262_144
# #1118: every byte of the reviewer conversation counts against the exchange's byte limit: the loop
# instruction, the packet (sent as a JSON string, so escaping grows it, up to twice for quoted code),
# the read catalog, the reviewer's replies and the read results. The first exchange is measured
# exactly, as ``reviewer_first_exchange`` renders it, and planned below the limit less this frame,
# which keeps room for the reviewer's read actions, their results and a format-repair notice. Each
# result is then fitted to what the exact next exchange leaves (``run_reviewer``'s
# ``exchange_budget``), so no later exchange outgrows the limit either. Disclosure fits the first
# exchange below the same frame (#1242).
REVIEWER_FRAME_BYTES: Final = 8192

_HIGH_BYTES: Final = bytes(range(0x80, 0x100))


def estimated_model_tokens(text: bytes) -> int:
    """The conservative model-token estimate for ``text`` (UTF-8 bytes)."""

    if type(text) is not bytes:
        raise ValueError("model_token_text_invalid")
    high = len(text) - len(text.translate(None, _HIGH_BYTES))
    return (5 * (len(text) - high) + 8) // 9 + high


@dataclass(frozen=True, slots=True)
class ReviewerContextWindow:
    """A reviewer model's context window and the share of it Codex treats as usable."""

    context_window: int
    effective_percent: int

    def __post_init__(self) -> None:
        if type(self.context_window) is not int or not 16_384 <= self.context_window <= 10**8:
            raise ValueError("reviewer_context_window_invalid")
        if type(self.effective_percent) is not int or not 1 <= self.effective_percent <= 100:
            raise ValueError("reviewer_context_window_invalid")


@dataclass(frozen=True, slots=True)
class ReviewerTokenBudget:
    """Estimated-token limits for one reviewer conversation on a sized route.

    ``ceiling`` is where Codex would compact (or the usable window, if lower). Every exchange's
    messages stay at or under ``exchange_tokens``; the first stays at or under
    ``first_exchange_tokens`` so later exchanges have room to grow.
    """

    ceiling: int
    exchange_tokens: int
    first_exchange_tokens: int


def reviewer_token_budget(window: ReviewerContextWindow) -> ReviewerTokenBudget:
    """The token budget of a conversation held in ``window``."""

    ceiling = min(
        window.context_window * window.effective_percent // 100,
        window.context_window * AUTO_COMPACT_PERCENT // 100,
    )
    exchange = (
        ceiling - RUNTIME_FRAMING_TOKENS - TURN_RESERVE_TOKENS - ceiling // ESTIMATE_MARGIN_DIVISOR
    )
    first = exchange - GROWTH_RESERVE_TOKENS
    if first < 1:
        raise ValueError("reviewer_context_window_too_small")
    return ReviewerTokenBudget(ceiling, exchange, first)


@dataclass(frozen=True, slots=True)
class ReviewerExchangeBudget:
    """What one exchange of a review conversation may carry on its route (#1118).

    ``byte_limit`` bounds the exchange's exact bytes: the route's hard bound
    (``MAX_SIZED_EXCHANGE_BYTES`` for a sized route, ``UNSIZED_EXCHANGE_BYTES`` otherwise) within
    the owner's ``max_bytes`` and ``max_tokens`` ceilings. ``token_limit`` bounds the estimated
    tokens of the exchange's messages and ``first_token_limit`` those of the first exchange; both
    are ``None`` on a route whose model context FinishUP cannot size.
    """

    byte_limit: int
    token_limit: int | None = None
    first_token_limit: int | None = None

    def __post_init__(self) -> None:
        if type(self.byte_limit) is not int or not 0 <= self.byte_limit <= MAX_SIZED_EXCHANGE_BYTES:
            raise ValueError("reviewer_exchange_budget_invalid")
        if (self.token_limit is None) != (self.first_token_limit is None):
            raise ValueError("reviewer_exchange_budget_invalid")
        if self.token_limit is not None and (
            type(self.token_limit) is not int
            or type(self.first_token_limit) is not int
            or not 0 <= self.first_token_limit <= self.token_limit
        ):
            raise ValueError("reviewer_exchange_budget_invalid")
