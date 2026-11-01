"""Shared response-evidence admissibility for local policy packs."""

from __future__ import annotations

from finishup.domain.values import EvidenceId, ResultId
from finishup.kernel.deterministic_checks import DeterministicCase

__all__ = [
    "BASE_RESPONSE_INADMISSIBLE_GAPS",
    "RESEARCH_REJECTION_PRESENT_FACT",
    "WORK_RESPONSE_PRESENT_FACT",
    "response_support_admissible",
]

# Both packs record the responded-to finding, the response event, and the admissible evidence refs
# in this fact, in that order and built from the same inputs. The composition layer keys its
# cross-pack collapse on the pair of facts, so the two names live together here rather than being
# repeated as bare strings in each pack.
WORK_RESPONSE_PRESENT_FACT = "finding_response_present"
RESEARCH_REJECTION_PRESENT_FACT = "finding_rejection_present"

BASE_RESPONSE_INADMISSIBLE_GAPS = frozenset(
    {
        "redacted_event",
        "redacted_object",
        "event_payload_unavailable",
        "captured_object_unavailable",
        "missing_ref",
        "unknown_event",
    }
)


def response_support_admissible(
    case: DeterministicCase,
    refs: tuple[EvidenceId | ResultId, ...],
    *,
    inadmissible_gaps: frozenset[str],
) -> bool:
    """Return whether one readable, allowed ref survives a policy's coverage exclusions."""

    for ref in refs:
        coverage = case.coverage_by_ref.get(ref)
        if (
            ref not in case.allowed_ids
            or coverage is None
            or inadmissible_gaps & set(coverage.known_gaps)
        ):
            continue
        if ref.startswith("evd_"):
            record = case.projection.evidence.get(EvidenceId(ref))
        else:
            record = case.projection.results.get(ResultId(ref))
        if record is not None and record.payload is not None:
            return True
    return False
