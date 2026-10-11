"""What counts as new material about a reviewer concern (tb4n3 RC-7, issue #1030, ADR-040).

``check._cites_material_after`` treated any newer ref as new material: another finding's response
event, the latest test run every agent re-runs, the agent's own evidence for its acknowledgement
and its own obligation republishes (formal-crypto S: four ids for one concern; payments S: the
probe evidence behind a give-up defeated the fold). ``concern_material_after`` is the one rule the
dispute, fold and ruling-admission paths share instead.

A cited ref is concern-relevant newer material only when all of these hold:

* it is evidence, a result or an action: never a finding, claim or obligation, and never the
  event that recorded a response, decision, check, finding, claim, obligation or plan (the
  agent restating its position, or Yoetz bookkeeping, says nothing new about the work);
* it was recorded after the frontier (the agent's standing answer, or the reviewer's last
  ruling, whichever is later);
* it is not evidence the agent itself cited in an answer (its own acknowledgement evidence);
* when the concern names obligations, it is *linked* to them: a result of an action that lists
  one of them, evidence that result or a claim over them cites or that an obligation of the
  concern lists as its resolution evidence, an edit action, or an unlinked result that did not
  succeed (a new failing run can show the problem remains; a new passing run cannot).
  A concern with no obligation has nothing to link to, so any such ref counts.

Paths: evidence rows carry no path in the projection, so "cited paths" cannot narrow the link
beyond the obligation rule above. That is disclosed in ADR-040 rather than faked.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, cast

from yoetz.domain.events import ActionKind, ResultOutcome
from yoetz.domain.values import ActionId, EvidenceId, FindingId, ObligationId, ResultId
from yoetz.kernel.concern import ConcernKey
from yoetz.kernel.deterministic_checks import DeterministicCase
from yoetz.kernel.finding_todo import standing_answer_frontier
from yoetz.kernel.projections import ProjectionState

__all__ = [
    "answer_bound",
    "concern_material_after",
    "own_answer_evidence",
]

_BOOKKEEPING_PREFIXES: Final = frozenset({"fnd_", "clm_"})
_MATERIAL_EVENT_SCHEMAS: Final = frozenset(
    {"evidence_recorded", "result_recorded", "action_recorded", "obligation_published"}
)


@dataclass(frozen=True, slots=True)
class _Row:
    kind: str  # "evidence" | "result" | "action" | "obligation"
    ref: str  # the typed id (evd_, res_ or act_)
    sequence: int


class _CaseIndex:
    """Per-case lookups, built once: event id to row, event id to schema, own answer evidence."""

    __slots__ = ("case", "event_rows", "event_schemas", "own_evidence", "_links")

    def __init__(self, case: DeterministicCase) -> None:
        self.case = case
        projection = case.projection
        self.event_rows: dict[str, _Row] = {}
        for evidence_key, evidence_row in projection.evidence.items():
            self.event_rows[str(evidence_row.source_event_id)] = _Row(
                "evidence", str(evidence_key), evidence_row.source_frontier
            )
        for result_key, result_row in projection.results.items():
            self.event_rows[str(result_row.source_event_id)] = _Row(
                "result", str(result_key), result_row.source_frontier
            )
        for action_key, action_row in projection.actions.items():
            self.event_rows[str(action_row.source_event_id)] = _Row(
                "action", str(action_key), action_row.source_frontier
            )
        for obligation_key, obligation_row in projection.obligations.items():
            self.event_rows[str(obligation_row.source_event_id)] = _Row(
                "obligation",
                str(obligation_key),
                obligation_row.introduced_frontier or obligation_row.source_frontier,
            )
        self.event_schemas: dict[str, str] = {
            str(event.event_id): event.schema_name for event in case.history
        }
        own: set[str] = set()
        for response in projection.responses.values():
            if response.payload is not None:
                own.update(str(ref) for ref in response.payload.evidence_refs)
        for event in case.history:
            if event.schema_name != "response_recorded" or not isinstance(event.payload, dict):
                continue
            refs = event.payload.get("evidence_refs")
            if isinstance(refs, (list, tuple)):
                own.update(str(ref) for ref in refs)
        self.own_evidence: frozenset[str] = frozenset(own)
        self._links: dict[frozenset[str], frozenset[str]] = {}

    def row(self, ref: str) -> _Row | None:
        projection = self.case.projection
        if ref.startswith("evd_"):
            evidence = projection.evidence.get(cast(EvidenceId, ref))
            return None if evidence is None else _Row("evidence", ref, evidence.source_frontier)
        if ref.startswith("res_"):
            result = projection.results.get(cast(ResultId, ref))
            return None if result is None else _Row("result", ref, result.source_frontier)
        if ref.startswith("act_"):
            action = projection.actions.get(cast(ActionId, ref))
            return None if action is None else _Row("action", ref, action.source_frontier)
        if ref.startswith("obl_"):
            obligation = projection.obligations.get(cast(ObligationId, ref))
            return (
                None
                if obligation is None
                else _Row(
                    "obligation",
                    ref,
                    obligation.introduced_frontier or obligation.source_frontier,
                )
            )
        if ref.startswith("evt_"):
            return self.event_rows.get(ref)
        return None

    def linked_refs(self, obligations: frozenset[str]) -> frozenset[str]:
        """Evidence and result ids linked to *obligations* through actions, claims and plans."""

        cached = self._links.get(obligations)
        if cached is not None:
            return cached
        projection = self.case.projection
        linked: set[str] = set()
        for result_key, result in projection.results.items():
            if result.payload is None:
                continue
            action = projection.actions.get(result.payload.action_id)
            if action is None or action.payload is None:
                continue
            if obligations & {str(item) for item in action.payload.obligation_refs}:
                linked.add(str(result_key))
                linked.update(str(item) for item in result.payload.evidence_refs)
        for claim in projection.claims.values():
            if claim.payload is None or claim.superseded_by_claim_id is not None:
                continue
            if obligations & {str(item) for item in claim.payload.obligation_refs}:
                linked.update(
                    str(item)
                    for item in claim.payload.supporting_refs
                    if str(item).startswith(("evd_", "res_"))
                )
        for obligation in obligations:
            row = projection.obligations.get(cast(ObligationId, obligation))
            if row is not None and row.payload is not None:
                linked.update(str(item) for item in row.payload.resolution_evidence_refs)
        frozen = frozenset(linked)
        self._links[obligations] = frozen
        return frozen


_last_index: tuple[DeterministicCase, _CaseIndex] | None = None


def _index(case: DeterministicCase) -> _CaseIndex:
    global _last_index
    cached = _last_index
    if cached is not None and cached[0] is case:
        return cached[1]
    built = _CaseIndex(case)
    _last_index = (case, built)
    return built


def own_answer_evidence(case: DeterministicCase) -> frozenset[str]:
    """Every evidence or result id the agent cited in any answer to any finding."""

    return _index(case).own_evidence


def _is_material(index: _CaseIndex, row: _Row, concern: ConcernKey) -> bool:
    projection = index.case.projection
    if row.kind == "obligation":
        # An obligation first published after the agent's answer is new material about the
        # concern it was cited in. A republication (status only: the meaning fields must repeat)
        # keeps its first-publication sequence, so the agent's own bookkeeping never counts.
        return True
    if not concern.obligations:
        return True
    if row.ref in index.linked_refs(concern.obligations):
        return True
    if row.kind == "action":
        action = projection.actions.get(cast(ActionId, row.ref))
        if action is None or action.payload is None:
            return False
        if action.payload.action_kind is ActionKind.EDIT:
            return True
        return bool(concern.obligations & {str(item) for item in action.payload.obligation_refs})
    if row.kind == "result":
        result = projection.results.get(cast(ResultId, row.ref))
        if result is None or result.payload is None:
            return False
        action = projection.actions.get(result.payload.action_id)
        action_obligations = (
            frozenset[str]()
            if action is None or action.payload is None
            else frozenset(str(item) for item in action.payload.obligation_refs)
        )
        if action_obligations:
            # Linked to other obligations only (a link to the concern's own was handled above).
            return bool(concern.obligations & action_obligations)
        # Unlinked (or its action is unknown): only a run that did not succeed can show the
        # problem remains; the latest passing test run every agent re-runs is not new material.
        return result.payload.outcome is not ResultOutcome.SUCCESS
    return False


def concern_material_after(
    case: DeterministicCase,
    concern: ConcernKey,
    refs: Iterable[str],
    frontier: int,
) -> bool:
    """Whether any of *refs* is concern-relevant material recorded after *frontier*."""

    index = _index(case)
    for ref in refs:
        if ref[:4] in _BOOKKEEPING_PREFIXES:
            continue
        if ref in index.own_evidence:
            continue
        row = index.row(ref)
        if row is None:
            continue
        if ref.startswith("evt_"):
            schema = index.event_schemas.get(ref)
            if schema is not None and schema not in _MATERIAL_EVENT_SCHEMAS:
                continue
            if row.ref in index.own_evidence:
                continue
        if row.sequence <= frontier:
            continue
        if _is_material(index, row, concern):
            return True
    return False


def answer_bound(projection: ProjectionState, finding_id: FindingId) -> int | None:
    """The frontier newer material must beat for one finding, or ``None`` with no answer.

    The later of the agent's standing position and the reviewer's last ruling: material the
    reviewer already ruled on is not new the next time it is cited.
    """

    standing = standing_answer_frontier(projection, finding_id)
    if standing is None:
        return None
    record = projection.findings.get(finding_id)
    ruling = (
        0 if record is None or record.last_ruling_frontier is None else record.last_ruling_frontier
    )
    return max(standing, ruling)
