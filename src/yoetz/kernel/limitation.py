"""The reviewer's limitation request and its disclosure (tb4n3 RC-1, issue #1024, ADR-040).

A reviewer who finds a requirement that only a hidden evaluator, a private reference or a
user-only answer can establish asks the agent to *state* that limit instead of doing more work
(``requested_next_step`` ``state_unresolved_limitation``; ``domain.findings.is_limitation_request``).
Until tb4n3 the code minted that request as priority-1 blocking work, so a compliant reviewer and a
non-compliant one produced the same outcome and nine of nine such findings ended
``acknowledged_not_done`` (owner decision RC-1: "why not fixed?").

Owner decision Q4 (DESIGN_RC3 section 8) fixes the lifecycle:

* **requested** (``limitation_requested``): the request is recorded and nothing else. It is a
  to-disclose item whose only next action is to acknowledge it; it is never repair work, never
  receipt-blocking work, and never raises a Stop-gate token beyond the ordinary unanswered-finding
  path.
* **disclosed** (``limitation_disclosed``): exactly one agent disclosure settles it. Either a
  ``respond`` answer with a reason (``acknowledged``, ``acknowledged_not_done``, or the agent's
  ``self_verified`` final word) or a recorded ``yoetz-verification-limit:<obligation id>`` decision covering an obligation the finding
  concerns. It is then settled, never clean (the receipt reads at best ``insufficient_coverage``
  and lists it under "Verification limits"), and a re-raise of the same concern folds onto it.

Guards, each tested:

* **G1** a challenge that asks the agent to ``act`` is never a limitation request, even when the
  obligation carries a ``yoetz-verification-limit`` decision: the reviewer sees an obtainable path.
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

from yoetz.domain.findings import Finding, is_limitation_request
from yoetz.domain.values import EventId, FindingId, ObligationId
from yoetz.kernel.concern import subject_obligations
from yoetz.kernel.finding_resolution import disclosing_response, finding_is_resolved
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.task_facts import DisclosureDeclaration, disclosure_declarations

__all__ = [
    "DISCLOSED_BY_DECISION",
    "DISCLOSED_BY_RESPONSE",
    "LIMITATION_DISCLOSED",
    "LIMITATION_REQUESTED",
    "LimitationStanding",
    "externally_evaluated_obligations",
    "limitation_disclosed_ids",
    "limitation_requested_ids",
    "limitation_standing",
]

LIMITATION_REQUESTED: Final = "limitation_requested"
LIMITATION_DISCLOSED: Final = "limitation_disclosed"
DISCLOSED_BY_RESPONSE: Final = "respond_acknowledgement"
DISCLOSED_BY_DECISION: Final = "verification_limit_decision"


@dataclass(frozen=True, slots=True)
class LimitationStanding:
    """Where one limitation request stands, with the lineage of how it got there."""

    finding_id: FindingId
    state: Literal["limitation_requested", "limitation_disclosed"]
    # How the agent disclosed it (``DISCLOSED_BY_*``), ``None`` while only requested.
    basis: str | None
    # The response event or the decision event that disclosed it (at most one id).
    source_event_ids: tuple[EventId, ...]
    # The ledger sequence of the response that disclosed it; ``None`` for a decision or while
    # only requested.
    since_frontier: int | None

    @property
    def disclosed(self) -> bool:
        return self.state == LIMITATION_DISCLOSED


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
    absent (resolved findings are history, not limits).
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
    if disclosing_response(response):
        assert response is not None
        return LimitationStanding(
            finding_id,
            LIMITATION_DISCLOSED,
            DISCLOSED_BY_RESPONSE,
            (response.source_event_id,),
            response.source_frontier,
        )
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
    """Limitation requests the agent has not yet disclosed (the "to disclose" bucket), sorted."""

    return tuple(
        item.finding_id for item in _standings(projection, finding_ids) if not item.disclosed
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
    obligation, or its words in a response, never mark it (guard G2). Derived from the decision
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
        concerned.update(
            subject_obligations(projection, (str(ref) for ref in record.payload.subject_refs))
        )
    return frozenset(
        ObligationId(obligation) for obligation in sorted(decisions) if obligation in concerned
    )
