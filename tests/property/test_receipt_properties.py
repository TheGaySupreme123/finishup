"""Property checks for receipt frontier, honesty, detail, and redaction invariants."""

from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from finishup.domain.decision_status import find_status_line
from finishup.domain.events import (
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    encode_payload,
)
from finishup.domain.receipts import (
    PolicyVersionEntry,
    ReceiptConclusion,
    ReceiptDocument,
    ReceiptPackageName,
    ReceiptVersionSlice,
    SchemaVersionEntry,
    receipt_document_to_json,
    receipt_weakest_coverage,
    render_receipt_compact,
)
from finishup.domain.values import (
    Frontier,
    event_id,
    freeze_json,
    obligation_id,
    receipt_id,
    session_id,
    task_id,
    timestamp_from_string,
)
from finishup.kernel.deterministic_checks import CaseAvailabilityFacts, CaseGap
from finishup.kernel.projections import (
    ObligationProjectionRecord,
    PlanProjectionRecord,
    ProjectionState,
    empty_projection_state,
)
from finishup.kernel.receipt_builder import ReceiptBuildContext, build_receipt
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from finishup.protocol.models import ReceiptInclude, ReceiptRedactionProfile

_HEAD = "sha256:" + "4" * 64
_FRONTIER = Frontier(2, _HEAD)
_OBLIGATION_ID = obligation_id("obl_00000000-0000-4000-8000-000000000001")


def _coverage() -> Coverage:
    return Coverage(
        publication_channels=(PublicationChannel.ENGINE_DERIVED,),
        authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
        artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
        evidence_immutability=EvidenceImmutability.METADATA_ONLY,
        ledger_freshness=LedgerFreshness.PARTIAL,
        check_types=(CheckType.NONE,),
        known_gaps=("check_not_recorded",),
    )


def _projection(summary: str) -> ProjectionState:
    plan = PlanPublishedPayload(1, "Property plan", (_OBLIGATION_ID,))
    obligation = ObligationPublishedPayload(
        obligation_id=_OBLIGATION_ID,
        description=summary,
        evidence_expectation="A recorded result",
        status=ObligationStatus.OPEN,
    )
    return replace(
        empty_projection_state(),
        frontier=2,
        head_digest=_HEAD,
        plans={
            1: PlanProjectionRecord(
                payload=plan,
                payload_digest=canonical_digest(encode_payload(plan)),
                redacted=False,
                source_event_id=event_id("evt_00000000-0000-4000-8000-000000000001"),
                source_frontier=1,
            )
        },
        obligations={
            _OBLIGATION_ID: ObligationProjectionRecord(
                payload=obligation,
                payload_digest=canonical_digest(encode_payload(obligation)),
                redacted=False,
                source_event_id=event_id("evt_00000000-0000-4000-8000-000000000002"),
                source_frontier=2,
            )
        },
        freshness=LedgerFreshness.CURRENT,
    )


def _versions(
    receipt_schema_version: str = "1.0.0", package_name: ReceiptPackageName = "finishup"
) -> ReceiptVersionSlice:
    return ReceiptVersionSlice(
        package_name=package_name,
        package_version="0.1.0",
        protocol_version="0.1",
        engine_version="0.1.0",
        projection_version="yoetz/0.1.0",
        object_format_version="yoetz-object/1",
        catalog_schema_version="1",
        bundle_schema_version="1",
        policy_versions=(
            PolicyVersionEntry("research-evidence", "0.1.0"),
            PolicyVersionEntry("work-integrity", "0.1.0"),
        ),
        schema_versions=(SchemaVersionEntry("receipts/receipt-document", receipt_schema_version),),
        resource_manifest_digest="sha256:" + "9" * 64,
    )


def _context(summary: str = "A protected obligation summary") -> ReceiptBuildContext:
    return ReceiptBuildContext(
        projection=_projection(summary),
        subject_frontier=_FRONTIER,
        availability=CaseAvailabilityFacts(),
        coverage=_coverage(),
        gaps=(CaseGap("check_not_recorded", "check_not_recorded", ()),),
        finding_states=(),
        applicable_check=None,
    )


def _build(
    context: ReceiptBuildContext,
    profile: ReceiptRedactionProfile,
    include: ReceiptInclude,
    *,
    receipt_schema_version: str = "1.0.0",
    package_name: ReceiptPackageName = "finishup",
) -> ReceiptDocument:
    return build_receipt(
        context,
        receipt_id("rcp_00000000-0000-4000-8000-000000000001"),
        task_id("tsk_00000000-0000-4000-8000-000000000001"),
        session_id("ses_00000000-0000-4000-8000-000000000001"),
        timestamp_from_string("2026-07-19T00:00:00.000Z"),
        _versions(receipt_schema_version, package_name),
        profile,
        include,
    )


def test_no_child_receipt_matches_frozen_pre_lineage_bytes() -> None:
    """The additive 1.3 artifact preserves the frozen 1.1 no-child document byte-for-byte.

    The digest is the independently recorded output of this fixed context from pre-lineage
    commit ``95aa2065`` using the frozen child-free receipt-document 1.1 artifact.  The current
    writer is allowed exactly these changes for the additive artifact: its schema-version entry, an
    empty ``children`` object and, from ADR-046, the ``conclusion_basis`` object that names the rules
    behind the conclusion, each gap's ``effect`` and a Summary that continues the frozen first
    sentence with the counters and one "Why <conclusion>" sentence.
    """

    context = _context()
    historical = receipt_document_to_json(
        _build(
            context,
            ReceiptRedactionProfile.FULL_LOCAL,
            ReceiptInclude.FULL,
            receipt_schema_version="1.1.0",
            # Frozen legacy identifier (ADR-048): the recorded pre-rename package name.
            package_name="yoetz",
        )
    )
    assert canonical_digest(freeze_json(historical)) == (
        "sha256:535dcc44a23541377baead27c6677772c2cc3088636cf869ac569d993a2c11c2"
    )

    current = receipt_document_to_json(
        _build(
            context,
            ReceiptRedactionProfile.FULL_LOCAL,
            ReceiptInclude.FULL,
            receipt_schema_version="1.3.0",
        )
    )
    assert current["children"] == {"children": []}

    compatible = dict(current)
    del compatible["children"]
    assert "conclusion_basis" in compatible
    del compatible["conclusion_basis"]
    compatible["gaps"] = [
        {key: value for key, value in dict(cast(dict[str, object], gap)).items() if key != "effect"}
        for gap in cast(list[object], compatible["gaps"])
    ]
    sections = [
        dict(cast(dict[str, object], item)) for item in cast(list[object], compatible["sections"])
    ]
    frozen_sections = cast(list[dict[str, object]], historical["sections"])
    assert str(sections[0]["body"]).startswith(str(frozen_sections[0]["body"]))
    assert "Why " in str(sections[0]["body"])
    sections[0]["body"] = frozen_sections[0]["body"]
    # #1205/#1139: the 1.3 evidence section also appends the decision-point ledger line
    # (``kernel.evidence_basis.decision_status_line``, short receipt form). Strip exactly that one
    # appended line; the frozen 1.1 sentence before it must stay byte-identical.
    for section in sections:
        if section.get("key") != "evidence_and_claim_basis":
            continue
        body = str(section["body"])
        line = find_status_line(body)
        assert line and body.endswith(" " + line)
        section["body"] = body.removesuffix(" " + line)
    compatible["sections"] = sections
    versions = dict(cast(dict[str, object], compatible["versions"]))
    schema_versions = [
        dict(cast(dict[str, object], item))
        for item in cast(list[object], versions["schema_versions"])
    ]
    for item in schema_versions:
        if item["schema_id"] == "receipts/receipt-document":
            item["schema_version"] = "1.1.0"
    versions["schema_versions"] = schema_versions
    # The writer now names the renamed distribution (ADR-048); the frozen bytes predate it.
    assert versions["package_name"] == "finishup"
    versions["package_name"] = "yoetz"
    compatible["versions"] = versions
    assert canonical_encode(freeze_json(compatible)) == canonical_encode(freeze_json(historical))


@given(st.sampled_from(tuple(ReceiptInclude)))
def test_receipt_frontier_matches_frozen_state(include: ReceiptInclude) -> None:
    document = _build(_context(), ReceiptRedactionProfile.FULL_LOCAL, include)
    assert document.subject_frontier == _FRONTIER
    mismatch = replace(_context().projection, head_digest="sha256:" + "5" * 64)
    with pytest.raises(ValueError, match="receipt_build_context_invalid"):
        ReceiptBuildContext(
            mismatch,
            _FRONTIER,
            CaseAvailabilityFacts(),
            _coverage(),
            (CaseGap("check_not_recorded", "check_not_recorded", ()),),
            (),
            None,
        )


@given(st.sampled_from(tuple(ReceiptRedactionProfile)), st.sampled_from(tuple(ReceiptInclude)))
def test_conclusion_never_outruns_findings(
    profile: ReceiptRedactionProfile, include: ReceiptInclude
) -> None:
    document = _build(_context(), profile, include)
    assert document.conclusion is ReceiptConclusion.INSUFFICIENT_COVERAGE
    assert document.coverage.known_gaps == ("check_not_recorded",)


@given(st.sampled_from(tuple(ReceiptRedactionProfile)), st.sampled_from(tuple(ReceiptInclude)))
def test_weakest_coverage_bounds_the_render(
    profile: ReceiptRedactionProfile, include: ReceiptInclude
) -> None:
    document = _build(_context(), profile, include)
    assert receipt_weakest_coverage(document) == document.coverage
    assert "coverage is insufficient" in render_receipt_compact(document).lower()


@given(st.sampled_from(tuple(ReceiptInclude)))
def test_redaction_profiles_change_canonical_output_without_strengthening_truth(
    include: ReceiptInclude,
) -> None:
    context = _context()
    full = _build(context, ReceiptRedactionProfile.FULL_LOCAL, include)
    exported = _build(context, ReceiptRedactionProfile.DEFAULT_LOCAL_EXPORT, include)
    shared = _build(context, ReceiptRedactionProfile.REDACTED_SHARE, include)
    assert full.obligations[0].summary is not None
    assert exported.obligations[0].summary is None
    assert shared.obligations[0].summary is None
    assert full.conclusion == exported.conclusion == shared.conclusion
    assert full.coverage == exported.coverage == shared.coverage
    full_digest = canonical_digest(freeze_json(receipt_document_to_json(full)))
    exported_digest = canonical_digest(freeze_json(receipt_document_to_json(exported)))
    assert full_digest != exported_digest


def test_explicit_context_is_required() -> None:
    context = _context()
    with pytest.raises(ValueError, match="receipt_build_context_invalid"):
        build_receipt(
            cast(ReceiptBuildContext, object()),
            receipt_id("rcp_00000000-0000-4000-8000-000000000001"),
            task_id("tsk_00000000-0000-4000-8000-000000000001"),
            session_id("ses_00000000-0000-4000-8000-000000000001"),
            timestamp_from_string("2026-07-19T00:00:00.000Z"),
            _versions(),
            ReceiptRedactionProfile.FULL_LOCAL,
            ReceiptInclude.FULL,
        )
    assert context.availability == CaseAvailabilityFacts()
