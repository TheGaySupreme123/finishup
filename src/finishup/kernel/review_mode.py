"""A conversation's review mode: local checks only, or AI-powered review (ADR-049).

A conversation is one task. Its review mode starts from the owner's standing conversation setting
(``PrivacyPolicy.conversation_review``) and moves only through ``decision_recorded`` 1.1.0
switches the conversation itself recorded. This module is pure: it reads the frozen projection and
the setting the caller resolved, and says which mode a check in that conversation runs in and why.

A switch is a request. It never grants disclosure: the effective privacy policy still decides
what may leave, and ``local_owner_approval`` still makes every AI-powered review wait for the
owner's per-request decision. Under an explicit ``local_only`` the owner has said agents may not
opt in; a host connection registered on the strict route can never request AI-powered review;
review turned off in the verification settings runs nothing for a check that names no mode; and
where AI-powered review is not set up nothing can run. A switch in any of those leaves the
conversation local and says which one applied. Under ``ai_powered`` the owner reviews every task:
a switch to local is recorded and decides nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from finishup.domain.events import ReviewMode
from finishup.domain.privacy import ConversationReview
from finishup.domain.values import EventId
from finishup.kernel.projections import ProjectionState

__all__ = [
    "ConversationReviewContext",
    "ConversationReviewMode",
    "LocalReason",
    "REQUESTED_BUT_LOCAL_REASONS",
    "ReviewModeSwitch",
    "conversation_review_mode",
    "conversation_review_mode_from_switches",
    "review_mode_switches",
]

type LocalReason = Literal[
    "conversation_default",
    "switched_to_local",
    "owner_local_only",
    "route_local_only",
    "review_disabled",
    "ai_review_not_set_up",
]

# The reasons a conversation that asked for AI-powered review (itself, or through the owner's
# "every task" setting) still runs local. Closed tokens shared by the check's recorded mode and
# status (ADR-049).
REQUESTED_BUT_LOCAL_REASONS: Final = frozenset(
    {"owner_local_only", "route_local_only", "review_disabled", "ai_review_not_set_up"}
)

# A conversation whose owner setting is unknown keeps the released behaviour: every conversation
# may use AI-powered review under the effective privacy policy.
_RELEASED_SETTING: Final = ConversationReview.AI_POWERED


@dataclass(frozen=True, slots=True)
class ConversationReviewContext:
    """What the service knows about a task's repository when a check starts (ADR-049).

    ``setting`` is the owner's effective conversation setting, or ``None`` when it could not be
    read. ``ai_review_available`` is whether AI-powered review is set up for the task: a reviewer
    is configured with its credential or login present, and the repository's privacy grant has its
    inference channel on. ``setting_explicit`` is whether the owner chose ``setting`` (a policy
    written before the field existed has the released reading instead): only an explicit
    ``local_only`` tells an agent the owner chose local checks.
    """

    setting: ConversationReview | None
    ai_review_available: bool
    setting_explicit: bool = False


@dataclass(frozen=True, slots=True)
class ReviewModeSwitch:
    """One recorded switch: which decision, at which ledger sequence, by whose authority."""

    event_id: EventId
    sequence: int
    mode: ReviewMode
    authority: str


@dataclass(frozen=True, slots=True)
class ConversationReviewMode:
    """The mode a check runs in, and the structural reason for it.

    ``requested`` is what the conversation asked for (its default or its latest switch);
    ``mode`` is what runs. They differ only when the owner set the repository to local only, the
    host connection is registered on the strict route, or AI-powered review is not set up
    (``local_reason`` says which).
    """

    mode: ReviewMode
    requested: ReviewMode
    setting: ConversationReview
    switches: tuple[ReviewModeSwitch, ...]
    local_reason: LocalReason | None = None

    @property
    def latest_switch(self) -> ReviewModeSwitch | None:
        return self.switches[-1] if self.switches else None

    @property
    def driven_by_switch(self) -> bool:
        """Whether the conversation's latest switch decides its mode.

        Under the owner's "every task" setting a switch to local is recorded but decides
        nothing: the setting reviews every task (review round 1 of ADR-049).
        """

        latest = self.latest_switch
        return latest is not None and not (
            self.setting is ConversationReview.AI_POWERED and latest.mode is ReviewMode.LOCAL
        )

    @property
    def local_by_choice(self) -> bool:
        """Whether this conversation runs local by a choice its owner's setting allows.

        Such a conversation's checks run on a route that did not require AI-powered review.
        Under ``ai_powered`` a conversation is never local by choice: where it runs local (a
        strict route, review turned off) the configured requirement still decides.
        """

        return self.mode is ReviewMode.LOCAL and self.setting is not ConversationReview.AI_POWERED

    @property
    def owner_approval_required(self) -> bool:
        """Whether each AI-powered review in this conversation waits for the owner."""

        return (
            self.mode is ReviewMode.AI_POWERED
            and self.setting is ConversationReview.LOCAL_OWNER_APPROVAL
        )


def review_mode_switches(projection: ProjectionState) -> tuple[ReviewModeSwitch, ...]:
    """Every standing review-mode switch in ledger order.

    A redacted decision has no payload and switches nothing; a switch a later decision
    superseded is withdrawn.
    """

    switches = [
        ReviewModeSwitch(
            record.source_event_id,
            record.source_frontier,
            record.payload.review_mode,
            record.payload.authority,
        )
        for record in projection.decisions.values()
        if record.payload is not None
        and record.payload.review_mode is not None
        and record.superseded_by_event_id is None
    ]
    return tuple(sorted(switches, key=lambda item: item.sequence))


def conversation_review_mode(
    projection: ProjectionState,
    setting: ConversationReview | None,
    *,
    ai_review_available: bool = True,
    setting_explicit: bool = False,
    route_allows_review: bool = True,
    review_enabled: bool = True,
) -> ConversationReviewMode:
    """The review mode of the conversation at *projection*'s frontier.

    ``setting`` is the owner's effective conversation setting for the task's repository, or
    ``None`` when it could not be read (the released behaviour applies). ``ai_review_available``
    is whether AI-powered review is set up for the task at all (a reviewer and a repository grant
    whose inference channel is on). ``setting_explicit`` is whether the owner chose the setting;
    ``route_allows_review`` is ``False`` on a host connection registered on the strict route;
    ``review_enabled`` is ``False`` where the installation's verification settings turn
    AI-powered review off for checks that name no mode.
    """

    return conversation_review_mode_from_switches(
        review_mode_switches(projection),
        setting,
        ai_review_available=ai_review_available,
        setting_explicit=setting_explicit,
        route_allows_review=route_allows_review,
        review_enabled=review_enabled,
    )


def conversation_review_mode_from_switches(
    switches: tuple[ReviewModeSwitch, ...],
    setting: ConversationReview | None,
    *,
    ai_review_available: bool = True,
    setting_explicit: bool = False,
    route_allows_review: bool = True,
    review_enabled: bool = True,
) -> ConversationReviewMode:
    """``conversation_review_mode`` over switches already read in ledger order.

    Under the owner's "every task" setting (explicit ``ai_powered``, or the released reading of a
    policy that predates the setting) every conversation runs AI-powered review: a switch to local
    is recorded but cannot lower that, so a missing review stays the owner's required-review gap.
    Such a conversation runs local only where review cannot run at all: a strict host connection
    (``route_local_only``) or review turned off in the verification settings
    (``review_disabled``); an unavailable reviewer keeps its honest required-review gap.

    Under the other settings a conversation starts local and a switch decides. One that asked
    for AI-powered review runs local when, in this order, the owner explicitly chose local only
    (``owner_local_only``), the host connection is on the strict route (``route_local_only``),
    review is turned off (``review_disabled``), or AI-powered review is not set up
    (``ai_review_not_set_up``).
    """

    effective = _RELEASED_SETTING if setting is None else setting
    if effective is ConversationReview.AI_POWERED:
        requested = switches[-1].mode if switches else ReviewMode.AI_POWERED
        unavailable: LocalReason | None = (
            "route_local_only"
            if not route_allows_review
            else "review_disabled"
            if not review_enabled
            else None
        )
        if unavailable is not None:
            return ConversationReviewMode(
                ReviewMode.LOCAL, requested, effective, switches, unavailable
            )
        return ConversationReviewMode(ReviewMode.AI_POWERED, requested, effective, switches)
    requested = switches[-1].mode if switches else ReviewMode.LOCAL
    if requested is ReviewMode.LOCAL:
        return ConversationReviewMode(
            ReviewMode.LOCAL,
            requested,
            effective,
            switches,
            "switched_to_local" if switches else "conversation_default",
        )
    reason: LocalReason | None = None
    if effective is ConversationReview.LOCAL_ONLY and (setting_explicit or ai_review_available):
        # The owner chose local checks for this repository: agents may not opt in.
        reason = "owner_local_only"
    elif not route_allows_review:
        # This host connection can never request AI-powered review until it is re-registered.
        reason = "route_local_only"
    elif not review_enabled:
        # The verification settings turn AI-powered review off for checks that name no mode.
        reason = "review_disabled"
    elif not ai_review_available or effective is ConversationReview.LOCAL_ONLY:
        # A conversation that opted in where nothing is set up stays local and says so.
        reason = "ai_review_not_set_up"
    if reason is not None:
        return ConversationReviewMode(ReviewMode.LOCAL, requested, effective, switches, reason)
    return ConversationReviewMode(ReviewMode.AI_POWERED, requested, effective, switches)
