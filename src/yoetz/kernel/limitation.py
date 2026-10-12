"""The reviewer's limitation request and its disclosure (tb4n3 RC-1, issue #1024, ADR-040).

A reviewer who finds a requirement that only a hidden evaluator, a private reference or a
user-only answer can establish asks the agent to *state* that limit instead of doing more work
(``requested_next_step`` ``state_unresolved_limitation``; ``domain.findings.is_limitation_request``).
Until tb4n3 the code minted that request as priority-1 blocking work, so a compliant reviewer and a
non-compliant one produced the same outcome and nine of nine such findings ended
``acknowledged_not_done`` (owner decision RC-1: "why not fixed?").

Owner decision Q4 (DESIGN_RC3 section 8) fixed the lifecycle; the owner's decision of 2026-10-12
(#1024) replaced its reading of ``acknowledged_not_done``: the agent's answer decides what the
request means.

* **requested** (``limitation_requested``): the request is recorded and nothing else. It is a
  to-disclose item whose only next action is to acknowledge it; it is never repair work, never
  receipt-blocking work, and never raises a Stop-gate token beyond the ordinary unanswered-finding
  path.
* **disclosed** (``limitation_disclosed``): the agent says the requirement may be met but cannot be
  verified here. Either a ``respond`` answer with a reason (``acknowledged``, or the agent's
  ``self_verified`` final word) or a recorded ``yoetz-verification-limit:<obligation id>`` decision
  covering an obligation the finding concerns. It is then settled, never clean (the receipt reads
  at best ``insufficient_coverage`` and lists it under "Verification limits"), and a re-raise of
  the same concern folds onto it.
* **acknowledged not done** (``limitation_acknowledged_not_done``): the agent answered
  ``acknowledged_not_done``, which says the requirement is NOT met. It is not a verification limit:
  it is an unmet requirement exactly like one acknowledged as not done (closure class
  ``settled_unmet``, receipt ``unresolved_findings_remain``), and it is not listed under
  "Verification limits". A recorded decision line never turns that answer into a disclosure; the
  agent takes the answer back with ``reopened`` and then discloses.

Guards, each tested:

* **G1** a challenge that asks the agent to ``act`` is never a limitation request, even when the
  obligation carries a ``yoetz-verification-limit`` decision: the reviewer sees an obtainable path.
  The agent's own criterion (``agent_criterion_unmet``, issue #1043) is a limitation request
  whatever next step the reviewer asked for, so the decision line never speaks for it: it neither
  discloses the finding nor marks its obligation externally evaluated. Only the agent's own answer
  to that finding narrows it.
* **G2** nothing here reads the agent's own words. An agent that answers an ``act`` finding
  "I could not find it" does not turn it into a limitation, so the pretrain-shard-corruption rescue
  (the acknowledgement re-check sent the agent back; it recovered the inputs) is kept.
* **G3** the class never touches ``declared_output_emptied``: a delivered file that was emptied is
  independent of any limitation, and that fact stays agent-actionable (the formal-crypto S loss).
* **G4** the class is never clean; a disclosed limitation is a standing disclosure.

Pure and replay-derived: the state is read from the projection only.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, Literal

from yoetz.domain.findings import Finding, FindingKind, ResponseDisposition, is_limitation_request
from yoetz.domain.values import EventId, FindingId, ObligationId
from yoetz.kernel.concern import subject_obligations
from yoetz.kernel.finding_resolution import disclosing_response, finding_is_resolved
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.task_facts import DisclosureDeclaration, disclosure_declarations

__all__ = [
    "DISCLOSED_BY_DECISION",
    "DISCLOSED_BY_RESPONSE",
    "LIMITATION_ACKNOWLEDGED_NOT_DONE",
    "LIMITATION_DISCLOSED",
    "LIMITATION_REQUESTED",
    "UNMET_BY_RESPONSE",
    "LimitationStanding",
    "externally_evaluated_obligations",
    "limitation_disclosed_ids",
    "limitation_requested_ids",
    "limitation_standing",
]

LIMITATION_REQUESTED: Final = "limitation_requested"
LIMITATION_DISCLOSED: Final = "limitation_disclosed"
LIMITATION_ACKNOWLEDGED_NOT_DONE: Final = "limitation_acknowledged_not_done"
DISCLOSED_BY_RESPONSE: Final = "respond_acknowledgement"
DISCLOSED_BY_DECISION: Final = "verification_limit_decision"
# How an unmet standing was reached: the agent's own ``acknowledged_not_done`` answer.
UNMET_BY_RESPONSE: Final = "respond_acknowledged_not_done"


@dataclass(frozen=True, slots=True)
class LimitationStanding:
    """Where one limitation request stands, with the lineage of how it got there."""

    finding_id: FindingId
    state: Literal[
        "limitation_requested", "limitation_disclosed", "limitation_acknowledged_not_done"
    ]
    # How the agent answered it (``DISCLOSED_BY_*`` or ``UNMET_BY_RESPONSE``), ``None`` while only
    # requested.
    basis: str | None
    # The response event or the decision event that answered it (at most one id).
    source_event_ids: tuple[EventId, ...]
    # The ledger sequence of the response that answered it; ``None`` for a decision or while
    # only requested.
    since_frontier: int | None

    @property
    def disclosed(self) -> bool:
        """The agent said the requirement may be met but cannot be verified here."""

        return self.state == LIMITATION_DISCLOSED

    @property
    def unmet(self) -> bool:
        """The agent said the requirement is NOT met (``acknowledged_not_done``)."""

        return self.state == LIMITATION_ACKNOWLEDGED_NOT_DONE


def _decision_speaks_for(finding: Finding) -> bool:
    """Whether a ``yoetz-verification-limit`` decision can stand for this request (guard G1).

    The decision line states a limit only a hidden evaluator can settle; it answers the reviewer's
    request to state that limit. The agent's own criterion is not one: its probe fails here, and
    the agent decides whether to fix it or narrow it, by answering that finding (review of #1043).
    """

    return finding.kind is not FindingKind.AGENT_CRITERION_UNMET


def _verification_limit_decisions(
    projection: ProjectionState,
) -> dict[str, DisclosureDeclaration]:
    return {
        str(item.obligation_id): item
        for item in disclosure_declarations(projection)
        if item.kind == "verification_limit"
    }


def limitation_standing(
    projection: ProjectionState,
    finding_id: FindingId,
    *,
    _decisions: dict[str, DisclosureDeclaration] | None = None,
) -> LimitationStanding | None:
    """The limitation state of one finding, or ``None`` when it is not a live limitation request.

    ``None`` for: an unreadable finding, anything but a reviewer's limitation request (guards G1
    and G2 live in ``is_limitation_request``), and a finding a later qualifying check proved
    absent (resolved findings are history, not limits). The agent's own answer is read first and
    decides what the request means: ``acknowledged_not_done`` is the unmet state (the requirement
    is not met), a reasoned ``acknowledged`` or ``self_verified`` is the disclosed state, and a
    ``yoetz-verification-limit`` decision discloses only a reviewer's request nobody answered yet,
    never the agent's own criterion (guard G1).
    """

    record = projection.findings.get(finding_id)
    if record is None or record.payload is None or record.redacted:
        return None
    finding: Finding = record.payload
    if not is_limitation_request(finding):
        return None
    if finding_is_resolved(projection, finding_id):
        return None
    response = projection.responses.get(finding_id)
    if (
        response is not None
        and response.payload is not None
        and not response.redacted
        and response.payload.disposition is ResponseDisposition.ACKNOWLEDGED_NOT_DONE
    ):
        # The agent's answer decides (owner decision 2026-10-12): "not done" says the requirement
        # is not met, so it is never a verification limit, whatever decision line is recorded.
        return LimitationStanding(
            finding_id,
            LIMITATION_ACKNOWLEDGED_NOT_DONE,
            UNMET_BY_RESPONSE,
            (response.source_event_id,),
            response.source_frontier,
        )
    if disclosing_response(response):
        assert response is not None
        return LimitationStanding(
            finding_id,
            LIMITATION_DISCLOSED,
            DISCLOSED_BY_RESPONSE,
            (response.source_event_id,),
            response.source_frontier,
        )
    if not _decision_speaks_for(finding):
        return LimitationStanding(finding_id, LIMITATION_REQUESTED, None, (), None)
    decisions = _verification_limit_decisions(projection) if _decisions is None else _decisions
    concerned = subject_obligations(projection, (str(ref) for ref in finding.subject_refs))
    covering = sorted(
        (decisions[obligation] for obligation in concerned if obligation in decisions),
        key=lambda item: str(item.decision_event_id).encode(),
    )
    if covering:
        return LimitationStanding(
            finding_id,
            LIMITATION_DISCLOSED,
            DISCLOSED_BY_DECISION,
            (covering[0].decision_event_id,),
            None,
        )
    return LimitationStanding(finding_id, LIMITATION_REQUESTED, None, (), None)


def _standings(
    projection: ProjectionState, finding_ids: Iterable[FindingId] | None
) -> Iterable[LimitationStanding]:
    decisions = _verification_limit_decisions(projection)
    keys = projection.findings if finding_ids is None else finding_ids
    for key in sorted(keys, key=str.encode):
        standing = limitation_standing(projection, key, _decisions=decisions)
        if standing is not None:
            yield standing


def limitation_requested_ids(
    projection: ProjectionState, finding_ids: Iterable[FindingId] | None = None
) -> tuple[FindingId, ...]:
    """Limitation requests the agent has not yet answered (the "to disclose" bucket), sorted."""

    return tuple(
        item.finding_id
        for item in _standings(projection, finding_ids)
        if item.state == LIMITATION_REQUESTED
    )


def limitation_disclosed_ids(
    projection: ProjectionState, finding_ids: Iterable[FindingId] | None = None
) -> tuple[FindingId, ...]:
    """Limitation requests the agent disclosed (the "Verification limits" bucket), sorted."""

    return tuple(item.finding_id for item in _standings(projection, finding_ids) if item.disclosed)


def externally_evaluated_obligations(projection: ProjectionState) -> frozenset[ObligationId]:
    """Obligations marked ``acceptance_externally_evaluated`` (tb4n3 RC-1, owner decision Q4).

    An obligation is externally evaluated when the agent recorded a
    ``yoetz-verification-limit:<obligation id>`` decision for it **and** a live reviewer
    limitation request concerns it (the request names it, or a claim or event it cites does).
    Neither alone qualifies: the decision line alone is the agent's assertion, and a reviewer
    request alone leaves the obligation ordinary work. The agent's own acknowledgement of the
    obligation, or its words in a response, never mark it (guard G2), and neither does the agent's
    own criterion (``agent_criterion_unmet``, guard G1). How the agent answered the
    request does not change the marker: an ``acknowledged_not_done`` answer keeps the *finding*
    unmet (``limitation_acknowledged_not_done``), so the receipt still reads
    ``unresolved_findings_remain`` while the obligation stays disclosed. Derived from the decision
    line and the request, so no event schema changed; a structured field on
    ``obligation_published`` is a separate wire revision.
    """

    decisions = _verification_limit_decisions(projection)
    if not decisions:
        return frozenset()
    concerned: set[str] = set()
    for key in projection.findings:
        if limitation_standing(projection, key, _decisions=decisions) is None:
            continue
        record = projection.findings[key]
        assert record.payload is not None
        if not _decision_speaks_for(record.payload):
            continue
        concerned.update(
            subject_obligations(projection, (str(ref) for ref in record.payload.subject_refs))
        )
    return frozenset(
        ObligationId(obligation) for obligation in sorted(decisions) if obligation in concerned
    )
