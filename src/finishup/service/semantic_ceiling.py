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
from finishup.application.semantic_case import (
    SemanticCaseTooLarge,
    check_time_change_bytes_carried,
    final_diff_floor,
    primary_material_selection,
    semantic_case_to_prepared_payload,
)
from finishup.domain.privacy import (
    DataClass,
    EgressChannel,
    PrivacyPolicy,
    ProviderBinding,
    ReviewSelectionPolicy,
)
from finishup.ports.privacy import MAX_MINIMIZED_DISCLOSURE_BYTES
from finishup.ports.semantic import SemanticCase, SemanticCaseItem
from finishup.protocol.models import DataCategory

__all__ = [
    "CEILING_PLANNING_GAP",
    "MAX_CEILING_PLANNING_ROUNDS",
    "ChannelAdmission",
    "channel_admission",
    "channel_prepared_limit",
    "plan_under_channel_ceiling",
    "with_ceiling_planning_gap",
]

# At most this many planning rounds plus one fixed-cost probe; unresolved capacity goes to egress.
MAX_CEILING_PLANNING_ROUNDS: Final = 4
# Each later round aims this much further below the ceiling, so a round that lands just over it
# does not repeat the same budget.
_ROUND_MARGIN_BYTES: Final = 2_048
CEILING_PLANNING_GAP: Final = "content_unselected"


# #1118: every byte of the reviewer conversation counts against the channel ceiling: the loop
# instruction, the packet (sent as a JSON string, so escaping grows it), the read catalog, the
# reviewer's replies and the read results. The packet is planned below the ceiling less this frame
# and a fifth for escaping; the reads get only what the sent conversation leaves.
REVIEWER_FRAME_BYTES: Final = 8192


def reviewer_packet_limit(policy: PrivacyPolicy) -> int | None:
    """The packet size the reviewer conversation's first exchange can carry under the ceiling."""

    limit = channel_prepared_limit(policy)
    return None if limit is None else max(0, (limit - REVIEWER_FRAME_BYTES) * 4 // 5)


def reviewer_read_room(limit: int | None, sent: int) -> int:
    """Read bytes the next exchanges can add after a conversation of ``sent`` bytes."""

    if limit is None:
        return 0
    return max(0, (limit - sent - 2048) * 4 // 5)


def channel_prepared_limit(policy: PrivacyPolicy) -> int | None:
    """The prepared-packet byte size the AI-powered review channel admits.

    It is the narrowest of ``max_bytes``, ``max_tokens`` at the estimate egress uses, and the
    largest disclosure the privacy port carries at all, so an unset (zero) or high Custom ceiling
    still plans below what egress can prepare. ``None`` only without an LLM channel.
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
    return min([MAX_MINIMIZED_DISCLOSURE_BYTES, *limits])


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


def _prepared_size(case: SemanticCase, admission: ChannelAdmission | None) -> int | None:
    released = {item.item_id for item in case.items if admission is None or admission.admits(item)}
    try:
        return len(semantic_case_to_prepared_payload(case, released))
    except SemanticCaseTooLarge:
        return None


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
) -> tuple[SemanticCase, ReviewSelectionPolicy, int]:
    """Return the case to review, the selection it was built with, and the rebuilds used.

    Sizes are those of the payload ``admission`` releases (every item when ``None``), so bytes
    local privacy minimization withholds never cost an eligible excerpt its place.

    ``rebuild`` builds the same case under a narrower selection and adds the planning gap. The
    first rebuild omits lower-priority narrative with the primary excerpt budget intact. A
    no-excerpt probe measures the remaining fixed part; it is never returned below the diff floor.
    Later rebuilds
    size the excerpt budget from how many prepared bytes each excerpt byte actually cost, since
    JSON escaping can multiply it. A case whose envelope cannot be bounded at all is returned
    unchanged, and egress decides it as before.
    """

    if limit is None:
        return case, selection, 0
    size = _prepared_size(case, admission)
    excerpt_bytes = _excerpt_bytes(case)
    if size is None or size <= limit:
        return case, selection, 0
    floor = final_diff_floor(case, selection, limit)
    approved = primary_material_selection(
        selection, keep_timeline="prior-missing-for-assessment" in case.packet.timeline_item_ids
    )
    rounds = 1
    protected = rebuild(approved)
    protected_size = _prepared_size(protected, admission)
    if protected_size is None or protected_size <= limit:
        return protected, approved, rounds
    size, excerpt_bytes = protected_size, _excerpt_bytes(protected)
    base = rebuild(_with_excerpt_budget(approved, 0))
    base_size = _prepared_size(base, admission)
    if base_size is None or base_size >= limit:
        # Even without excerpts the packet is over the ceiling: egress refuses it as before.
        return (
            (protected, approved, rounds)
            if floor
            else (base, _with_excerpt_budget(approved, 0), rounds)
        )
    planned, planned_selection = (
        (protected, approved) if floor else (base, _with_excerpt_budget(approved, 0))
    )
    while rounds < MAX_CEILING_PLANNING_ROUNDS and size > base_size and excerpt_bytes:
        rounds += 1
        room = limit - base_size - _ROUND_MARGIN_BYTES * (rounds - 1)
        budget = room * excerpt_bytes // (size - base_size)
        candidate_selection = _with_excerpt_budget(approved, budget)
        candidate = rebuild(candidate_selection)
        candidate_size = _prepared_size(candidate, admission)
        if candidate_size is None:
            break
        if candidate_size <= limit:
            if check_time_change_bytes_carried(candidate) >= floor:
                planned, planned_selection = candidate, candidate_selection
            break
        size, excerpt_bytes = candidate_size, _excerpt_bytes(candidate)
    return planned, planned_selection, rounds


def _excerpt_bytes(case: SemanticCase) -> int:
    return sum(item.content_bytes for item in case.items if item.section == "excerpt")
