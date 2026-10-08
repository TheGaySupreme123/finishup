"""Pure receipt-capacity admission checks for proposed ledger states."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from yoetz.domain.events import CheckRecordedPayload, LedgerRecord
from yoetz.domain.findings import Finding, rank_key
from yoetz.domain.receipts import (
    CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP,
    semantic_coverage_gap_code,
)
from yoetz.kernel.deterministic_checks import (
    build_deterministic_case,
    healthy_storage_availability,
)
from yoetz.kernel.finding_resolution import finding_is_resolved, issue_key
from yoetz.kernel.finding_todo import duplicate_counting_id, finding_blocks_receipt
from yoetz.kernel.projections import ProjectionState, observation_limitation_finding_ids
from yoetz.kernel.reducers import (
    ReplayIndex,
    invalidates_recorded_check,
    is_material_event_family,
)
from yoetz.protocol.coverage import MAX_KNOWN_GAPS

__all__ = [
    "ReceiptCoverageCapacityExceeded",
    "current_receipt_findings",
    "receipt_blocking_finding_count",
    "receipt_gap_codes",
    "validate_receipt_coverage_capacity",
]

_CHECK_NOT_RECORDED: Final = "check_not_recorded"
_CHECK_NOT_APPLICABLE: Final = "check_not_applicable"
_CHECK_PAYLOAD_UNAVAILABLE: Final = "check_payload_unavailable"


@dataclass(frozen=True, slots=True)
class ReceiptCoverageCapacityExceeded(ValueError):
    """The exact proposed receipt gap union exceeds the public coverage bound."""

    count: int
    limit: int = MAX_KNOWN_GAPS

    def __post_init__(self) -> None:
        if type(self.count) is not int or self.count <= self.limit:
            raise ValueError("invalid_receipt_coverage_capacity")
        ValueError.__init__(self, "receipt_coverage_capacity_exceeded")


def current_receipt_findings(projection: ProjectionState) -> tuple[Finding, ...]:
    """Select the newest readable row per receipt issue key in canonical rank order."""

    if type(projection) is not ProjectionState:
        raise ValueError("receipt_coverage_capacity_invalid")
    newest: dict[tuple[object, ...], tuple[int, Finding]] = {}
    for record in projection.findings.values():
        if record.payload is None:
            continue
        key = issue_key(record.payload)
        candidate = (record.source_frontier, record.payload)
        prior = newest.get(key)
        if prior is None or candidate[0] > prior[0]:
            newest[key] = candidate
    return tuple(sorted((item[1] for item in newest.values()), key=rank_key))


def receipt_blocking_finding_count(projection: ProjectionState) -> int:
    """Count current actionable findings that prevent a clean receipt conclusion.

    Responses record a disposition but never resolve a finding for receipt purposes; only a later
    qualifying check does (``kernel/finding_resolution.py``), and a resolved row stays visible as
    history without counting here. Non-actionable findings remain visible and can contribute
    coverage gaps, but they do not by themselves select ``unresolved_findings_remain``. A
    terminal ``rejection_accepted`` row stops counting but stays disclosed; an
    ``acknowledged_not_done`` row keeps counting (issue #905, ``kernel/finding_todo.py``). A
    ``self_verified`` row (issue #984) stops counting as agent work but stays disclosed and keeps
    the receipt from reading clean (``receipt_builder._conclusion``). A linked ``duplicate_of``
    row (issue #996) counts once with the finding it duplicates (``finding_todo.duplicate_counting_id``).
    """

    return len(
        {
            duplicate_counting_id(projection, finding.finding_id)
            for finding in current_receipt_findings(projection)
            if finding_blocks_receipt(projection, finding.finding_id)
        }
    )


def receipt_gap_codes(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
) -> tuple[str, ...]:
    """Return the exact healthy-storage gap union a receipt would need for this state."""

    return _receipt_gap_codes(projection, records, projection_validated=False)


def _receipt_gap_codes_validated(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    *,
    replay_index: ReplayIndex | None = None,
) -> tuple[str, ...]:
    """Return receipt gaps when the caller already replayed the exact record tuple.

    This internal adapter seam skips only the duplicate genesis replay. It retains local
    case construction, reverse-index, availability, history, and coverage validation.
    """

    return _receipt_gap_codes(
        projection,
        records,
        projection_validated=True,
        replay_index=replay_index,
    )


def _receipt_gap_codes(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    *,
    projection_validated: bool,
    replay_index: ReplayIndex | None = None,
) -> tuple[str, ...]:
    """Build receipt gaps, optionally reusing an append-time replay result.

    The validated branch is private to ledger append admission. Its caller has just replayed the
    exact ``records`` tuple and supplies that projection; the local case still performs
    all shape, index, availability, history, and coverage checks below.
    """

    if type(projection) is not ProjectionState or type(records) is not tuple:
        raise ValueError("receipt_coverage_capacity_invalid")
    case = build_deterministic_case(
        projection,
        records,
        healthy_storage_availability(projection, records, _replay_index=replay_index),
        _projection_validated=projection_validated,
        _replay_index=replay_index,
    )
    codes = {gap.code for gap in case.gaps}
    for coverage in case.coverage_by_ref.values():
        codes.update(coverage.known_gaps)

    latest = projection.latest_tested_state
    check_record = None
    if latest is not None:
        check_record = next(
            (record for record in records if record.event_id == latest.source_check_event_id),
            None,
        )
    limitations = observation_limitation_finding_ids(projection, records)
    if latest is None:
        codes.add(_CHECK_NOT_RECORDED)
    elif check_record is not None and any(
        invalidates_recorded_check(
            record,
            check_record.ledger.ingestion_sequence,
            latest.returned_finding_ids,
            limitation_finding_ids=limitations,
        )
        for record in records
    ):
        codes.add(_CHECK_NOT_APPLICABLE)
    elif check_record is not None and type(check_record.payload) is CheckRecordedPayload:
        codes.update(check_record.payload.coverage.known_gaps)
        # The receipt builder folds the AI-powered review outcome's structural gap separately from the
        # recorded coverage. A legacy payload can carry a terminal AI-powered review status whose code is
        # absent from ``known_gaps``; omitting it here would admit a state at exactly the bound
        # that receipt construction then pushes one code over.
        semantic_gap = semantic_coverage_gap_code(
            check_record.payload.semantic_status, check_record.payload.semantic_reason
        )
        if semantic_gap is not None:
            codes.add(semantic_gap)
        if any(
            is_material_event_family(record.schema.name)
            and record.ledger.ingestion_sequence > check_record.ledger.ingestion_sequence
            for record in records
        ):
            codes.add(CHECK_CURRENT_AS_OF_EARLIER_FRONTIER_GAP)
    else:
        codes.add(_CHECK_PAYLOAD_UNAVAILABLE)

    # Resolved rows remain receipt history but no longer fold into its coverage (issue #912).
    for finding in current_receipt_findings(projection):
        if finding_is_resolved(projection, finding.finding_id):
            continue
        codes.update(finding.coverage.known_gaps)
    return tuple(sorted(codes, key=str.encode))


def validate_receipt_coverage_capacity(
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
) -> None:
    """Reject a proposed state whose exact healthy receipt union exceeds the wire bound."""

    codes = receipt_gap_codes(projection, records)
    if len(codes) > MAX_KNOWN_GAPS:
        raise ReceiptCoverageCapacityExceeded(len(codes))


def _validate_receipt_coverage_capacity_validated(  # pyright: ignore[reportUnusedFunction]
    projection: ProjectionState,
    records: tuple[LedgerRecord, ...],
    *,
    replay_index: ReplayIndex | None = None,
) -> None:
    """Validate append capacity after the caller has replayed ``records`` exactly once.

    This is an internal adapter seam; callers must pass the exact immutable tuple used to produce
    ``projection``. Public callers should use :func:`validate_receipt_coverage_capacity`.
    """

    codes = _receipt_gap_codes_validated(
        projection,
        records,
        replay_index=replay_index,
    )
    if len(codes) > MAX_KNOWN_GAPS:
        raise ReceiptCoverageCapacityExceeded(len(codes))
