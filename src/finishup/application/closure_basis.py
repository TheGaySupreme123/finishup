"""The one closure basis: the receipt's own context, built for status and the receipt alike (ADR-046).

``receipt_context`` is the function the receipt used to hold privately: it folds the frozen case,
the applicable check, the findings' closures, the gaps and the lineage into the
``ReceiptBuildContext`` the builder reads. Status builds the same context at its own frontier
and asks the same pure ``predict_receipt_conclusion`` over it, so the label status prints before
the receipt is requested is the label the receipt carries.

``load_closure_basis`` is the application-layer loader: it reads the records and projection the
way the receipt does, builds the deterministic case once and returns the context and the basis.
Status degrades to omitting the prediction (never to guessing one) when the case is unreadable.
An unpinned status read retries that load at the latest frontier when a material append lands
between the reads; a caller-pinned frontier is never moved (see ``_closure_basis_or_none``).
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from dataclasses import dataclass, replace
from typing import Final

from finishup.application.ledger_snapshot import projection_for_records, trusted_projection_at
from finishup.domain.events import CheckRecordedPayload, LedgerRecord, is_observation_authored
from finishup.domain.receipts import (
    CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP,
    CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP,
    recorded_semantic_outcome_gap_code,
)
from finishup.domain.values import Frontier
from finishup.kernel.check_standing import check_standing
from finishup.kernel.closure_class import finding_closures
from finishup.kernel.deterministic_checks import CaseGap, build_deterministic_case, case_coverage
from finishup.kernel.finding_resolution import unverified_resolution_finding_ids
from finishup.kernel.finding_todo import (
    FindingTodoState,
    duplicate_link_target,
    finding_todo_state,
)
from finishup.kernel.lineage import evaluate_recorded_lineage
from finishup.kernel.projections import ProjectionState
from finishup.kernel.receipt_builder import (
    CheckSuffixClass,
    ReceiptBuildContext,
    ReceiptFindingState,
    closure_basis_from_context,
)
from finishup.kernel.receipt_capacity import current_receipt_findings
from finishup.kernel.receipt_prediction import ClosureBasis
from finishup.ports.runtime import TaskRuntime
from finishup.protocol.coverage import LedgerFreshness, weakest

__all__ = [
    "ClosureBasisUnavailable",
    "LoadedClosureBasis",
    "check_change_resolution_gaps",
    "clear_closure_basis_memo",
    "finding_states",
    "historical_gaps",
    "load_closure_basis",
    "receipt_context",
]


class ClosureBasisUnavailable(Exception):
    """The ledger or case could not be read, so no honest prediction exists at this frontier."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class LoadedClosureBasis:
    projection: ProjectionState
    records: tuple[LedgerRecord, ...]
    context: ReceiptBuildContext
    basis: ClosureBasis


# A tiny derivation memo (ADR-046). Status is read about once per write and ``closure_prepare``
# reads one page per call at the same frontier, so building the deterministic case on every read
# would multiply the cost of a long task. An entry is a pure function of the ledger prefix; it is
# reused only while the adapter hands back the very projection object it was derived from (the
# adapter replaces that object on any append, redaction or recovery), so it can never be stale.
# It holds derived values for at most ``_MEMO_LIMIT`` frontiers and is not a source of truth.
_MEMO_LIMIT: Final = 8
_MEMO: OrderedDict[tuple[str, int, str], LoadedClosureBasis] = OrderedDict()


def clear_closure_basis_memo() -> None:
    """Forget every memoized basis (tests and diagnostics)."""

    _MEMO.clear()


async def load_closure_basis(runtime: TaskRuntime, frontier: Frontier) -> LoadedClosureBasis:
    """Build the receipt context and the closure basis at exactly ``frontier`` (read-only).

    The same reads the receipt makes: the accepted records through the frontier, the projection
    the adapter vouches for (or a genesis replay), the case availability and the deterministic
    case. Memoized per ``(session, frontier)`` while the adapter's projection object is unchanged.
    """

    key = (runtime.session_id, frontier.sequence, frontier.head_digest)
    trusted = await trusted_projection_at(runtime.ledger, runtime.session_id, frontier)
    if trusted is not None:
        hit = _MEMO.get(key)
        if hit is not None and hit.projection is trusted:
            _MEMO.move_to_end(key)
            return hit
    records = tuple(
        [
            record
            async for record in runtime.ledger.load_events(
                runtime.session_id, through=frontier.sequence
            )
        ]
    )
    try:
        projection = (
            trusted
            if trusted is not None
            else await projection_for_records(runtime.ledger, runtime.session_id, frontier, records)
        )
    except ValueError as exc:
        raise ClosureBasisUnavailable("projection_replay_failed") from exc
    if Frontier(projection.frontier, projection.head_digest) != frontier:
        raise ClosureBasisUnavailable("frontier_changed")
    availability = await runtime.ledger.load_case_availability(
        runtime.session_id, frontier, projection
    )
    try:
        case = await asyncio.to_thread(
            build_deterministic_case,
            projection,
            records,
            availability,
            _projection_validated=True,
        )
        context = receipt_context(projection, frontier, case, records)
        basis = closure_basis_from_context(context)
    except ValueError as exc:
        raise ClosureBasisUnavailable("closure_basis_invalid") from exc
    loaded = LoadedClosureBasis(projection, records, context, basis)
    if trusted is not None:
        _MEMO[key] = loaded
        while len(_MEMO) > _MEMO_LIMIT:
            _MEMO.popitem(last=False)
    return loaded


def finding_states(
    projection: object, records: tuple[LedgerRecord, ...] = ()
) -> tuple[ReceiptFindingState, ...]:
    assert type(projection) is ProjectionState
    # ADR-046: the class, basis and receipt effect of each finding come from the one classifier
    # status reads, so the label this receipt carries is the label status predicted.
    closures = finding_closures(projection, records=records, with_self_verify=False)
    # Resolution is proof-based: the projection carries which later qualifying check, if any,
    # proved each current issue absent, and a response disposition never sets it. Reading the
    # shared rule here is what keeps the receipt and ``receipt_blocking_finding_count`` equal.
    states: list[ReceiptFindingState] = []
    for item in current_receipt_findings(projection):
        todo = finding_todo_state(projection, item.finding_id)
        closure = closures.get(item.finding_id)
        # A limitation request answered ``acknowledged_not_done`` says the requirement is NOT met
        # (owner decision 2026-10-12): it is named once, as acknowledged not done, like any other
        # requirement left undone. Only a disclosure (``acknowledged``) is a verification limit.
        states.append(
            ReceiptFindingState(
                item.finding_id,
                todo is FindingTodoState.VERIFIED_RESOLVED,
                acknowledged_not_done=todo is FindingTodoState.ACKNOWLEDGED_NOT_DONE,
                rejection_accepted=todo is FindingTodoState.REJECTION_ACCEPTED,
                self_verified=todo is FindingTodoState.SELF_VERIFIED,
                disputed_after_rebuttal=todo is FindingTodoState.DISPUTED_AFTER_REBUTTAL,
                # Issue #996: the flags above are derived from the linked earlier finding.
                duplicate_of_finding_id=duplicate_link_target(projection, item.finding_id),
                closure=closure,
            )
        )
    return tuple(states)


def check_change_resolution_gaps(
    projection: ProjectionState, finding_states: tuple[ReceiptFindingState, ...]
) -> list[CaseGap]:
    """Disclose resolutions that compared a legacy raising view by length only (R945-02).

    Such a resolution stands, but a receipt never presents it as content-verified. One task-wide
    marker carries the code however many findings it covers, so the disclosure can never exhaust
    the receipt's 64-gap bound; the receipt builder names the affected findings, boundedly.
    """

    affected = unverified_resolution_finding_ids(
        projection, (state.finding_id for state in finding_states if state.resolved)
    )
    if not affected:
        return []
    return [
        CaseGap(
            CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP,
            CHECK_TIME_CHANGE_RESOLUTION_UNVERIFIED_GAP,
            (),
        )
    ]


def receipt_context(
    projection: object,
    frontier: Frontier,
    case: object,
    records: tuple[LedgerRecord, ...],
) -> ReceiptBuildContext:
    from finishup.kernel.deterministic_checks import DeterministicCase

    assert type(projection) is ProjectionState
    assert type(case) is DeterministicCase
    applicable: CheckRecordedPayload | None = None
    check_suffix: CheckSuffixClass | None = None
    states = finding_states(projection, records)
    gaps = list(case.gaps)
    latest = projection.latest_tested_state
    check_record: LedgerRecord | None = None
    if latest is not None:
        for record in records:
            if record.event_id == latest.source_check_event_id:
                check_record = record
                break
    standing = check_standing(projection, records)
    if latest is None:
        gaps.append(CaseGap("check_not_recorded", "check_not_recorded", ()))
    elif check_record is not None and standing.superseded_by is not None:
        # Applicability follows the material state, not frontier equality: a check applies to
        # this receipt when no material-family event superseded it. Its own events (returned
        # findings plus check_recorded) land atomically right after the tested frontier, so
        # anything later is genuinely newer work, except a response answering a finding the
        # check itself returned, which reports on that check rather than replacing what it read,
        # an acknowledgement of an observation-authored limitation no check returns (#911), and
        # the observations that cannot have changed the work: FinishUP's own calls, exploration and
        # host bookkeeping (tb4n3 RC-6). An observed deliverable or workspace edit supersedes.
        # The gap cites the first superseding record, so the receipt can say what changed.
        gaps.append(
            CaseGap(
                "check_not_applicable",
                "check_not_applicable",
                (standing.superseded_by.event_id,),
            )
        )
    elif check_record is not None and type(check_record.payload) is CheckRecordedPayload:
        applicable = check_record.payload
        # Only the records FinishUP cannot prove harmless keep the disclosure (tb4n3 RC-6): the
        # agent's own status polls, host stream bookkeeping and read-only runs no longer make
        # every receipt "current as of an earlier frontier".
        later_material = standing.counted
        if later_material:
            # Check-answering responses and finding-free observation-authored records can reach
            # here. The verdict still covers the frontier it tested rather than this one, so the
            # receipt names that frontier instead of reading as though the work were re-checked.
            gaps.append(
                CaseGap(
                    CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP,
                    CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP,
                    # A receipt gap cites at most 16 records: the observations that bound come
                    # first (in ledger order), then the answers that followed; the explanation
                    # says how many there were.
                    tuple(
                        sorted(
                            (
                                record.event_id
                                for record in (
                                    *(r for r in later_material if is_observation_authored(r)),
                                    *(r for r in later_material if not is_observation_authored(r)),
                                )[:16]
                            ),
                            key=str.encode,
                        )
                    ),
                )
            )
            # Classify that suffix for the explanation (issue #657). The applicability rule above
            # already proved every later material record is one of the two attributable kinds, so
            # the class is exact here; it is render context, never a wire field or a gap code.
            observed = any(is_observation_authored(record) for record in later_material)
            responded = any(not is_observation_authored(record) for record in later_material)
            if observed and responded:
                check_suffix = CheckSuffixClass.MIXED
            elif observed:
                check_suffix = CheckSuffixClass.OBSERVATIONS_ONLY
            else:
                check_suffix = CheckSuffixClass.RESPONSES_ONLY
    else:
        gaps.append(
            CaseGap(
                f"check_payload_unavailable:{latest.source_check_event_id}",
                "check_payload_unavailable",
                (latest.source_check_event_id,),
            )
        )
    if applicable is None and not any(
        gap.code in {"check_not_recorded", "check_not_applicable", "check_payload_unavailable"}
        for gap in gaps
    ):
        gaps.append(CaseGap("check_not_recorded", "check_not_recorded", ()))
    if applicable is not None:
        semantic_gap = recorded_semantic_outcome_gap_code(
            applicable.semantic_status,
            applicable.semantic_reason,
            route_required=applicable.semantic_route_required,
        )
        if semantic_gap is not None and not any(gap.code == semantic_gap for gap in gaps):
            gaps.append(CaseGap(f"semantic_outcome:{semantic_gap}", semantic_gap, ()))
        for code in applicable.coverage.known_gaps:
            if not any(gap.code == code for gap in gaps):
                gaps.append(CaseGap(f"check_coverage:{code}", code, ()))
    coverage = case_coverage(case)
    if applicable is not None:
        coverage = weakest(coverage, applicable.coverage)
    # Findings are historical material, not merely presentation rows. Observation advice can
    # retain a finding stamped while delivery was stale after the current projection and latest
    # check have recovered. Fold every current retained row before constructing the context so the
    # builder's corruption guard remains strict while the application supplies the honest weakest
    # coverage the receipt document already promises. A resolved row stays in the document as
    # history, but a later qualifying check proved its issue absent, so its coverage no longer
    # lowers the conclusion or adds ``retained_finding_coverage`` gaps (issue #912).
    for state in states:
        if state.resolved:
            continue
        record = projection.findings[state.finding_id]
        assert record.payload is not None
        coverage = weakest(coverage, record.payload.coverage)
    gaps.extend(check_change_resolution_gaps(projection, states))

    # Lineage is replay-only.  The coordinator may have read live children earlier, but a
    # receipt never does: it evaluates the aggregate manifest events already present in this
    # parent prefix.  When a check applies, evaluate the manifest at the check's subject frontier
    # and retain any later recorded aggregate as an uncovered reference.
    lineage = evaluate_recorded_lineage(
        records,
        tested_through_sequence=(
            None if applicable is None else applicable.subject_frontier.sequence
        ),
        base_coverage=coverage,
    )
    coverage = lineage.coverage
    blocking_children = {
        rollup.child_task_id
        for rollup in lineage.children
        if rollup.blocks_clean_completion and rollup.tested_manifest_ref is not None
    }
    # Pending and informational children are annotations.  Keep their full evaluator gaps in
    # the structured child section, but do not project those gaps into receipt coverage: doing so
    # would turn an explicitly non-blocking relationship into an insufficient-completion result.
    for lineage_gap in lineage.gaps:
        if (
            lineage_gap.child_task_id is not None
            and lineage_gap.child_task_id not in blocking_children
        ):
            continue
        event_ref = lineage_gap.manifest_event_id
        child_ref = "" if lineage_gap.child_task_id is None else str(lineage_gap.child_task_id)
        event_token = "" if event_ref is None else str(event_ref)
        marker = ":".join(
            token for token in ("lineage", lineage_gap.code, child_ref, event_token) if token
        )
        subject_refs = () if event_ref is None else (event_ref,)
        candidate = CaseGap(marker, lineage_gap.code, subject_refs)
        if not any(gap.marker == candidate.marker and gap.code == candidate.code for gap in gaps):
            gaps.append(candidate)

    # ReceiptBuildContext requires exact equality between Coverage.known_gaps and CaseGap codes.
    # Check-derived codes were materialized above; a code introduced only by a retained finding
    # receives one task-global structural marker so many historical findings cannot exhaust the
    # receipt's bounded 64-gap surface.
    represented_codes = {gap.code for gap in gaps}
    retained_only_codes: set[str] = set()
    for code in coverage.known_gaps:
        if code not in represented_codes:
            gaps.append(CaseGap(f"retained_finding_coverage:{code}", code, ()))
            represented_codes.add(code)
            retained_only_codes.add(code)
    ordered_gaps = tuple(
        sorted(
            gaps,
            key=lambda gap: (
                gap.marker.encode("ascii"),
                tuple(ref.encode("ascii") for ref in gap.subject_refs),
            ),
        )
    )
    codes = tuple(sorted({gap.code for gap in ordered_gaps}, key=str.encode))
    if codes != coverage.known_gaps:
        freshness = coverage.ledger_freshness
        if codes and freshness is LedgerFreshness.CURRENT:
            freshness = LedgerFreshness.PARTIAL
        coverage = replace(coverage, ledger_freshness=freshness, known_gaps=codes)
    return ReceiptBuildContext(
        projection,
        frontier,
        case.availability,
        coverage,
        ordered_gaps,
        states,
        applicable,
        lineage,
        check_suffix=check_suffix,
        records=records,
        check_standing=standing,
        historical_gaps=historical_gaps(records, check_record, retained_only_codes),
    )


def historical_gaps(
    records: tuple[LedgerRecord, ...],
    latest_check: LedgerRecord | None,
    candidates: set[str],
) -> tuple[tuple[str, Frontier], ...]:
    """Name the retained-only gap codes a later recorded check cleared (issue #1017).

    A code reaches the receipt only through a retained finding's coverage when neither the case
    nor the latest check carries it. If an earlier ``check_recorded`` carried it and a later one
    (through the latest tested check) no longer did, a later check cleared it: the receipt keeps
    it as history, cleared at the subject frontier of the first check after the last one that
    carried it. A code no recorded check ever carried stays live. Replay-only and deterministic.
    """

    if (
        not candidates
        or latest_check is None
        or type(latest_check.payload) is not CheckRecordedPayload
    ):
        return ()
    checks = tuple(
        record.payload
        for record in sorted(records, key=lambda record: record.ledger.ingestion_sequence)
        if type(record.payload) is CheckRecordedPayload
        and record.ledger.ingestion_sequence <= latest_check.ledger.ingestion_sequence
    )
    historical: list[tuple[str, Frontier]] = []
    for code in sorted(candidates, key=str.encode):
        carried = [index for index, check in enumerate(checks) if code in check.coverage.known_gaps]
        if not carried or carried[-1] == len(checks) - 1:
            continue
        historical.append((code, checks[carried[-1] + 1].subject_frontier))
    return tuple(historical)
