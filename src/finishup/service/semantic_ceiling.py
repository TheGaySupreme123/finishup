"""Plan an AI-powered review case below the channel ceiling (issue #907 Phase 1b).

Privacy policy 1.2.0 lets the Expanded preset carry up to 64 excerpts, so a long session can build
a case whose prepared packet is larger than the channel's ``max_bytes`` or estimated
``max_tokens``. Egress refuses such a packet whole. Before that happens, the case is rebuilt with a
narrower narrative selection before a smaller excerpt byte budget. This only narrows the approved
selection. Cuts are disclosed as ``content_unselected``, and the egress ceiling still decides
every dispatch.

The planner measures the payload the channel will release: items in a category or data class the
channel withholds are removed by local privacy minimization before egress, so they must not cost
eligible excerpts their room.

The reduction is a pure function of the case inputs, so a recovered review rebuilds the same case
and keeps its digest.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Final

from finishup.adapters.privacy.local_enforcer import (
    EGRESS_BYTES_PER_TOKEN_ESTIMATE,
    clean_item_data_class,
)
from finishup.adapters.providers.codex_reviewer_catalog import reviewer_model_context_window
from finishup.adapters.providers.reviewer_reply import REVIEWER_LOOP_INSTRUCTION
from finishup.application.reviewer_run import reviewer_first_exchange
from finishup.application.semantic_case import (
    SemanticCaseTooLarge,
    check_time_change_floor_bytes_carried,
    final_diff_floor,
    primary_material_selection,
    prior_context_selections,
    semantic_case_to_disclosed_payloads,
)
from finishup.config.models import (
    CODEX_SUBSCRIPTION_ENDPOINT_PROFILE_ID,
    CODEX_SUBSCRIPTION_PROVIDER_ID,
)
from finishup.domain.privacy import (
    DataClass,
    EgressChannel,
    PrivacyPolicy,
    ProviderBinding,
    ReviewSelectionPolicy,
)
from finishup.domain.reviewer_context import (
    MAX_SIZED_EXCHANGE_BYTES,
    UNSIZED_EXCHANGE_BYTES,
    ReviewerContextWindow,
    ReviewerExchangeBudget,
    reviewer_token_budget,
)
from finishup.ports.privacy import MAX_MINIMIZED_DISCLOSURE_BYTES
from finishup.ports.semantic import SemanticCase, SemanticCaseItem, reviewer_message_tokens
from finishup.protocol.models import DataCategory

__all__ = [
    "CEILING_PLANNING_GAP",
    "MAX_CEILING_PLANNING_ROUNDS",
    "ChannelAdmission",
    "channel_admission",
    "channel_prepared_limit",
    "plan_under_channel_ceiling",
    "planned_exchange_size",
    "reviewer_exchange_budget",
    "reviewer_exchange_limit",
    "reviewer_exchange_measure",
    "reviewer_route_window",
    "with_ceiling_planning_gap",
]

# At most this many planning rounds plus one fixed-cost probe; unresolved capacity goes to egress.
MAX_CEILING_PLANNING_ROUNDS: Final = 4
# Each later round aims this much further below the ceiling, so a round that lands just over it
# does not repeat the same budget.
_ROUND_MARGIN_BYTES: Final = 2_048
CEILING_PLANNING_GAP: Final = "content_unselected"


# #1118: every byte of the reviewer conversation counts against the exchange's byte limit: the loop
# instruction, the packet (sent as a JSON string, so escaping grows it, up to twice for quoted code),
# the read catalog, the reviewer's replies and the read results. The first exchange is measured
# exactly, as ``reviewer_first_exchange`` renders it, and planned below the limit less this frame,
# which keeps room for the reviewer's read actions, their results and a format-repair notice. Each
# result is then fitted to what the exact next exchange leaves (``run_reviewer``'s
# ``exchange_budget``), so no later exchange outgrows the limit either.
REVIEWER_FRAME_BYTES: Final = 8192


def reviewer_route_window(binding: ProviderBinding | None) -> ReviewerContextWindow | None:
    """The reviewer model context of ``binding``'s route, when FinishUP can size it (#1118).

    Only the Codex subscription route running the pinned reviewer model is sized, from the model
    entry FinishUP ships for it. Every other route (the Responses and Chat Completions APIs, a
    local model, another Codex model) has an owner-chosen model whose context FinishUP does not
    know, so it keeps the unsized exchange bound.
    """

    if (
        binding is None
        or binding.transport != "external"
        or binding.provider_id != CODEX_SUBSCRIPTION_PROVIDER_ID
        or binding.endpoint_profile_id != CODEX_SUBSCRIPTION_ENDPOINT_PROFILE_ID
    ):
        return None
    return reviewer_model_context_window(binding.model_id)


def reviewer_exchange_budget(
    policy: PrivacyPolicy, bindings: Iterable[ProviderBinding | None]
) -> ReviewerExchangeBudget | None:
    """What one exchange may carry to every one of ``bindings`` (#1118).

    The narrowest of the owner's ``max_bytes`` and ``max_tokens`` ceilings (``max_tokens`` at the
    estimate egress compares it with) and the route's hard byte bound, plus the model-token budget
    when every destination's model context is sized; with a primary and a fallback the narrower
    destination binds, so a fallback dispatch never outgrows its own model. ``None`` only without
    an LLM channel.
    """

    present = [binding for binding in bindings if binding is not None]
    windows = [reviewer_route_window(binding) for binding in present]
    sized = [window for window in windows if window is not None]
    if present and len(sized) == len(present):
        budgets = [reviewer_token_budget(window) for window in sized]
        limit = channel_prepared_limit(policy, route_bytes=MAX_SIZED_EXCHANGE_BYTES)
        if limit is None:
            return None
        return ReviewerExchangeBudget(
            limit,
            min(budget.exchange_tokens for budget in budgets),
            min(budget.first_exchange_tokens for budget in budgets),
        )
    limit = channel_prepared_limit(policy)
    return None if limit is None else ReviewerExchangeBudget(limit)


def reviewer_exchange_limit(budget: ReviewerExchangeBudget | None) -> int | None:
    """The size the reviewer conversation's first exchange may reach, in bytes-equivalent."""

    return None if budget is None else max(0, budget.byte_limit - REVIEWER_FRAME_BYTES)


def reviewer_exchange_measure(
    catalog: str, budget: ReviewerExchangeBudget | None = None
) -> Callable[[bytes], int]:
    """The size of the first exchange that carries a prepared packet beside ``catalog``.

    It is the exchange's exact bytes, or, on a sized route, its estimated model tokens scaled so
    that ``first_token_limit`` tokens measure exactly ``reviewer_exchange_limit`` (rounded up):
    one number the planner compares with one limit, and it is within the limit only when both the
    bytes and the tokens are.
    """

    limit = reviewer_exchange_limit(budget)
    first = None if budget is None else budget.first_token_limit
    fixed = reviewer_message_tokens(REVIEWER_LOOP_INSTRUCTION) + reviewer_message_tokens(catalog)

    def measure(packet: bytes) -> int:
        size = len(reviewer_first_exchange(packet, catalog))
        if first is None or limit is None:
            return size
        if first == 0:
            return max(size, limit + 1)
        tokens = fixed + reviewer_message_tokens(packet.decode())
        return max(size, -(-tokens * limit // first))

    return measure


def channel_prepared_limit(
    policy: PrivacyPolicy, *, route_bytes: int = UNSIZED_EXCHANGE_BYTES
) -> int | None:
    """The prepared-payload byte size the AI-powered review channel admits.

    It is the narrowest of ``max_bytes``, ``max_tokens`` at the estimate egress uses, and the
    route's hard bound (``UNSIZED_EXCHANGE_BYTES`` unless the route's model context is sized), so
    an unset (zero) or high Custom ceiling still plans below what egress can send. ``None`` only
    without an LLM channel.
    """

    llm = next(
        (
            channel
            for channel in policy.channel_policies
            if channel.channel is EgressChannel.LLM_INFERENCE
        ),
        None,
    )
    if llm is None:
        return None
    limits = [
        limit
        for limit in (llm.max_bytes, llm.max_tokens * EGRESS_BYTES_PER_TOKEN_ESTIMATE)
        if limit > 0
    ]
    return min([min(route_bytes, MAX_MINIMIZED_DISCLOSURE_BYTES), *limits])


@dataclass(frozen=True, slots=True)
class ChannelAdmission:
    """The categories and data classes the review channel releases after local minimization."""

    categories: frozenset[DataCategory]
    data_classes: frozenset[DataClass]

    def admits(self, item: SemanticCaseItem) -> bool:
        return (
            item.category in self.categories
            and clean_item_data_class(item.category) in self.data_classes
        )


def channel_admission(
    policy: PrivacyPolicy, bindings: Iterable[ProviderBinding | None]
) -> ChannelAdmission | None:
    """What egress would release to any of ``bindings``, or ``None`` without an LLM channel.

    Egress approves an item only when its category and data class are both in the ceiling of the
    transport it is sent over: the LLM channel for an external provider, the local-model ceiling
    for a local one. With a primary and a fallback destination the union is taken, so the planner
    never measures less than either dispatch could release. An item with forbidden data blocks the
    whole packet at egress, so predicting its clean data class cannot under-measure a dispatch.
    """

    llm = next(
        (
            channel
            for channel in policy.channel_policies
            if channel.channel is EgressChannel.LLM_INFERENCE
        ),
        None,
    )
    if llm is None:
        return None
    categories: set[DataCategory] = set()
    data_classes: set[DataClass] = set()
    for binding in bindings:
        if binding is None:
            continue
        if binding.transport == "local_af_unix":
            if policy.local_model_enabled:
                categories.update(policy.local_model_categories)
                data_classes.update(policy.local_model_data_classes)
        else:
            categories.update(llm.allowed_categories)
            data_classes.update(llm.allowed_data_classes)
    data_classes.discard(DataClass.SECRET_OR_CRYPTOGRAPHIC)
    return ChannelAdmission(frozenset(categories), frozenset(data_classes))


def with_ceiling_planning_gap(gaps: Sequence[str]) -> tuple[str, ...]:
    """``gaps`` plus the disclosure a planned reduction adds, without duplicating it."""

    return tuple(sorted({*gaps, CEILING_PLANNING_GAP}, key=str.encode))


def _prepared_size(
    case: SemanticCase, admission: ChannelAdmission | None, measure: Callable[[bytes], int]
) -> int | None:
    released = {item.item_id for item in case.items if admission is None or admission.admits(item)}
    try:
        # #1230: the payload in every shape egress minimization can give it, so a replaced
        # credential-like value that is shorter than its placeholder is measured, not missed.
        return max(
            measure(payload) for payload in semantic_case_to_disclosed_payloads(case, released)
        )
    except SemanticCaseTooLarge:
        return None


def planned_exchange_size(
    case: SemanticCase, admission: ChannelAdmission | None, measure: Callable[[bytes], int]
) -> int | None:
    """What ``plan_under_channel_ceiling`` compares with its limit for ``case``; ``None`` when
    the envelope cannot be bounded at all."""

    return _prepared_size(case, admission, measure)


def _with_excerpt_budget(selection: ReviewSelectionPolicy, budget: int) -> ReviewSelectionPolicy:
    if budget < 1:
        return replace(
            selection,
            excerpt_kinds=(),
            max_excerpts=0,
            max_excerpt_bytes=0,
            max_total_excerpt_bytes=0,
        )
    return replace(
        selection,
        max_excerpt_bytes=min(selection.max_excerpt_bytes, budget),
        max_total_excerpt_bytes=min(selection.max_total_excerpt_bytes, budget),
    )


def plan_under_channel_ceiling(
    case: SemanticCase,
    selection: ReviewSelectionPolicy,
    limit: int | None,
    rebuild: Callable[[ReviewSelectionPolicy], SemanticCase],
    admission: ChannelAdmission | None = None,
    measure: Callable[[bytes], int] = len,
) -> tuple[SemanticCase, ReviewSelectionPolicy, int]:
    """Return the case to review, the selection it was built with, and the rebuilds used.

    Sizes are those of the payload ``admission`` releases (every item when ``None``), so bytes
    local privacy minimization withholds never cost an eligible excerpt its place. ``measure``
    turns that payload into the bytes the limit bounds: the payload itself by default, or the
    exact reviewer exchange that carries it (#1118), so escaping is counted, not estimated.

    ``rebuild`` builds the same case under a narrower selection and adds the planning gap. The
    first rebuild omits lower-priority narrative (the agent's goal and the history) with the
    primary excerpt budget and the obligation and claim rows intact. A
    no-excerpt probe measures the remaining fixed part; it is never returned below the diff floor.
    Later rebuilds
    size the excerpt budget from how many prepared bytes each excerpt byte actually cost, since
    JSON escaping can multiply it. Only when no such plan fits with the diff floor is the whole
    search repeated without the obligation and claim rows (#1245, D22), exactly as every review
    was planned before, so no review that fitted then is refused now. A case whose envelope
    cannot be bounded at all is returned unchanged, and egress decides it as before.
    """

    if limit is None:
        return case, selection, 0
    size = _prepared_size(case, admission, measure)
    if size is None or size <= limit:
        return case, selection, 0
    floor = final_diff_floor(case, selection, limit)
    keep_timeline = "prior-missing-for-assessment" in case.packet.timeline_item_ids
    planned, planned_selection, rounds, fitted = _plan_narrowed(
        primary_material_selection(selection, keep_timeline=keep_timeline),
        limit,
        floor,
        rebuild,
        admission,
        measure,
    )
    if fitted:
        return planned, planned_selection, rounds
    planned, planned_selection, legacy_rounds, _fitted = _plan_narrowed(
        primary_material_selection(
            selection, keep_timeline=keep_timeline, keep_agent_account=False
        ),
        limit,
        floor,
        rebuild,
        admission,
        measure,
    )
    return planned, planned_selection, rounds + legacy_rounds


def _plan_narrowed(
    approved: ReviewSelectionPolicy,
    limit: int,
    floor: int,
    rebuild: Callable[[ReviewSelectionPolicy], SemanticCase],
    admission: ChannelAdmission | None,
    measure: Callable[[bytes], int],
) -> tuple[SemanticCase, ReviewSelectionPolicy, int, bool]:
    """One narrowing search under ``approved``; the flag says whether its plan fits."""

    rounds = 1
    protected = rebuild(approved)
    protected_size = _prepared_size(protected, admission, measure)
    if protected_size is None or protected_size <= limit:
        return protected, approved, rounds, True
    count_rounds = 0
    for candidate_selection in prior_context_selections(protected, approved, floor):
        rounds += 1
        count_rounds += 1
        candidate = rebuild(candidate_selection)
        candidate_size = _prepared_size(candidate, admission, measure)
        if candidate_size is not None and candidate_size <= limit:
            if check_time_change_floor_bytes_carried(candidate) >= floor:
                return candidate, candidate_selection, rounds, True
    size, excerpt_bytes = protected_size, _excerpt_bytes(protected)
    base = rebuild(_with_excerpt_budget(approved, 0))
    base_size = _prepared_size(base, admission, measure)
    if base_size is None or base_size >= limit:
        # Even without excerpts the packet is over the ceiling: egress refuses it as before.
        return (
            (protected, approved, rounds, False)
            if floor
            else (base, _with_excerpt_budget(approved, 0), rounds, False)
        )
    planned, planned_selection = (
        (protected, approved) if floor else (base, _with_excerpt_budget(approved, 0))
    )
    fitted = not floor
    while (
        rounds - count_rounds < MAX_CEILING_PLANNING_ROUNDS and size > base_size and excerpt_bytes
    ):
        rounds += 1
        room = limit - base_size - _ROUND_MARGIN_BYTES * (rounds - count_rounds - 1)
        budget = room * excerpt_bytes // (size - base_size)
        candidate_selection = _with_excerpt_budget(approved, budget)
        candidate = rebuild(candidate_selection)
        candidate_size = _prepared_size(candidate, admission, measure)
        if candidate_size is None:
            break
        if candidate_size <= limit:
            if check_time_change_floor_bytes_carried(candidate) >= floor:
                planned, planned_selection = candidate, candidate_selection
                fitted = True
            break
        size, excerpt_bytes = candidate_size, _excerpt_bytes(candidate)
    return planned, planned_selection, rounds, fitted


def _excerpt_bytes(case: SemanticCase) -> int:
    return sum(item.content_bytes for item in case.items if item.section == "excerpt")
