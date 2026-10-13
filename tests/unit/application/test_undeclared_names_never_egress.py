"""Undeclared-reference names never reach the AI-powered reviewer (tb4n5, ADR-035 amendment).

tb4n4 #1044 records, on a check's ``deliverable_states``, the root-relative names of files a
delivered file names that no item declares: the one path text a check records. Since tb4n5 those
names may return to the task's own agent (``task_created_file``), locally. The review packet
carries a check's history row as bounded structural metadata, so the row must never carry the
names, and its digest must be of what it does carry: the ledger digest of the full payload would
confirm a guessed name. Only the count travels.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from dataclasses import replace

from builders.policy_cases import evt, obl
from unit.application.test_reduced_scope_included_refs import (
    _case,
    _coverage,
    _offered,
    _provenance,
    _selection,
)
from yoetz.application.semantic_case import (
    build_semantic_case,
    semantic_case_to_prepared_payload,
)
from yoetz.domain.events import (
    CheckMode,
    CheckRecordedPayload,
    DeliverableState,
    PolicyVersion,
    encode_payload,
)
from yoetz.domain.findings import CheckVerdict
from yoetz.domain.privacy import ReviewContextProfile
from yoetz.kernel.deterministic_checks import FrozenHistoryEvent
from yoetz.protocol.canonical import canonical_digest
from yoetz.protocol.models import (
    CheckPolicyExecutionModel,
    CheckScopeModel,
    SemanticReason,
    SemanticStatus,
)

_NAMES = ("checks/case_0/walk.npz", "private_models/english_ngrams.npz")


def _check_row(*, with_names: bool) -> tuple[FrozenHistoryEvent, str]:
    """The history row of one recorded check, and the ledger digest of its full payload."""

    state = DeliverableState(obl(1), 0, basis="delivered")
    if with_names:
        state = replace(
            state,
            undeclared_references=_NAMES,
            undeclared_reference_count=18,
            undeclared_references_created_in_task=True,
        )
    base = _case()
    check = CheckRecordedPayload(
        mode=CheckMode.SEMANTIC_REQUIRED,
        policies=(PolicyVersion("work-integrity", "0.1.0"),),
        scope=CheckScopeModel(claim_ids=(), obligation_ids=()),
        policy_executions=(
            CheckPolicyExecutionModel(
                policy_id="work-integrity",
                policy_version="0.1.0",
                outcome="run",
                reason="completed",
            ),
        ),
        subject_frontier=base.frontier,
        verdict=CheckVerdict.NO_ISSUE_DETECTED,
        returned_finding_ids=(),
        suppressed_count=0,
        coverage=_coverage(),
        semantic_status=SemanticStatus.SUCCEEDED,
        semantic_reason=SemanticReason.SEMANTIC_COMPLETED,
        engine_version="0.1.0",
        projection_version="yoetz/0.1.0",
        semantic_provenance=_provenance(),
        semantic_conclusion="no_material_discrepancy",
        deliverable_states=(state,),
    )
    digest = canonical_digest(encode_payload(check))
    row = FrozenHistoryEvent(
        event_id=evt(901),
        schema_name="check_recorded",
        schema_version="1.4.0",
        ingestion_sequence=9,
        occurred_at="2026-10-13T12:00:00.000Z",
        accepted_at=None,
        occurred_at_consistency=None,
        payload_digest=digest,
        content_visibility="available",
        payload=encode_payload(check),
    )
    return row, digest


def _prepared(row: FrozenHistoryEvent) -> bytes:
    base = _case()
    case = replace(base, history=(*base.history, row), history_availability="available")
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000001044",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=(),
        review_context_profile=ReviewContextProfile.CUSTOM,
        # Every history row travels with its payload, as under the Expanded profile.
        review_selection=_selection(excerpts=False, max_omissions=0),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )
    return semantic_case_to_prepared_payload(semantic, _offered(semantic))


def test_a_check_history_row_carries_the_count_never_the_names_or_their_digest() -> None:
    row, digest = _check_row(with_names=True)
    prepared = _prepared(row)
    for name in _NAMES:
        for part in (name, name.rsplit("/", 1)[1], name.split("/", 1)[0]):
            assert part.encode() not in prepared, part
    assert b"undeclared_references_created_in_task" in prepared
    assert b"undeclared_reference_count" in prepared
    assert b"payload_reduced" in prepared
    assert b"undeclared_reference_names_withheld" in prepared
    # The ledger digest of the payload with the names would let a provider confirm a guess.
    assert digest.encode() not in prepared


def test_a_check_row_without_names_keeps_its_exact_payload_and_digest() -> None:
    row, digest = _check_row(with_names=False)
    prepared = _prepared(row)
    assert digest.encode() in prepared
    assert b"payload_reduced" not in prepared
