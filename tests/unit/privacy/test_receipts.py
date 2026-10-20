from __future__ import annotations

from dataclasses import fields, replace
from datetime import UTC, datetime

import pytest

from finishup.domain.privacy import (
    MAX_EGRESS_CASE_BYTES,
    MAX_RECEIPT_FINAL_BYTES,
    MAX_WITHHELD_ITEM_IDS,
    AuthorizationScope,
    AuthorizationScopeKind,
    ConsentSource,
    EgressChannel,
    EgressReceipt,
    LocalDisclosureReceipt,
    LocalDisclosureSink,
    NonLlmDestination,
    PrivacyOutcome,
    PrivacyReason,
    ProviderBinding,
    ReceiptCounts,
    ReceiptPolicyBinding,
    ReceiptSecretScan,
    ReceiptSecretScanStage,
    ReceiptTransformations,
    RequestCommitment,
)
from finishup.protocol.models import DataCategory

_RECEIPT_ID = "egr_00000000-0000-4000-8000-000000000001"
_REQUEST_ID = "req_00000000-0000-4000-8000-000000000002"
_PROPOSAL_ID = "ppr_00000000-0000-4000-8000-000000000003"
_POLICY_ID = "pvy_00000000-0000-4000-8000-000000000004"
_AUTHORIZATION_ID = "aut_00000000-0000-4000-8000-000000000005"
_DISPATCH_ID = "dsp_00000000-0000-4000-8000-000000000006"
_INSTALLATION_ID = "ins_00000000-0000-4000-8000-000000000007"
_DIGEST = "sha256:" + "a" * 64
_COMMITMENT = "hmac-sha256:" + "b" * 64
_STARTED = datetime(2026, 7, 19, 10, 0, 0, tzinfo=UTC)
_FINISHED = datetime(2026, 7, 19, 10, 0, 1, tzinfo=UTC)


def _scope() -> AuthorizationScope:
    return AuthorizationScope(AuthorizationScopeKind.MACHINE, _INSTALLATION_ID)


def _policy() -> ReceiptPolicyBinding:
    return ReceiptPolicyBinding(_POLICY_ID, 3, _DIGEST, _DIGEST)


def _counts(*, attempted: bool) -> ReceiptCounts:
    return ReceiptCounts(2, 1, 1, 1, 1, 100, 80, 20, 90 if attempted else None)


def _transformations() -> ReceiptTransformations:
    return ReceiptTransformations(1, 2, 1)


def _scan(*, passed: bool = True) -> ReceiptSecretScan:
    return ReceiptSecretScan("1.0.0", _DIGEST, 0 if passed else 1, passed)


def _network_receipt() -> EgressReceipt:
    return EgressReceipt(
        "1.0.0",
        _RECEIPT_ID,
        _REQUEST_ID,
        _PROPOSAL_ID,
        EgressChannel.LLM_INFERENCE,
        PrivacyOutcome.COMPLETED,
        _FINISHED,
        _scope(),
        "semantic-review",
        ProviderBinding("openai", "gpt-5", "responses", "1", "external"),
        _policy(),
        ConsentSource.BASELINE_POLICY,
        (DataCategory.FINDING_SUMMARY,),
        (DataCategory.TRANSCRIPT_EXCERPT,),
        _counts(attempted=True),
        _transformations(),
        _scan(),
        None,
        1,
        _AUTHORIZATION_ID,
        _DISPATCH_ID,
        _STARTED,
        RequestCommitment("hmac-sha256/yoetz-privacy-egress-request-v1", _COMMITMENT),
    )


def _local_receipt() -> LocalDisclosureReceipt:
    return LocalDisclosureReceipt(
        "1.0.0",
        _RECEIPT_ID,
        _REQUEST_ID,
        _PROPOSAL_ID,
        LocalDisclosureSink.AGENT_CONTEXT,
        PrivacyOutcome.COMPLETED,
        _FINISHED,
        _scope(),
        "agent-projection",
        _policy(),
        ConsentSource.BASELINE_POLICY,
        (DataCategory.FINDING_SUMMARY,),
        (DataCategory.TRANSCRIPT_EXCERPT,),
        _counts(attempted=False),
        _transformations(),
        _scan(),
        None,
        1,
    )


def test_network_receipt_has_complete_frozen_schema_shape() -> None:
    receipt = _network_receipt()
    assert receipt.counts.request_body_bytes == 90
    assert receipt.request_commitment is not None
    assert {field.name for field in fields(EgressReceipt)} == {
        "schema_version",
        "receipt_id",
        "request_id",
        "privacy_proposal_id",
        "channel",
        "outcome",
        "finished_at",
        "scope",
        "purpose",
        "destination",
        "policy",
        "consent_source",
        "approved_categories",
        "blocked_categories",
        "counts",
        "transformations",
        "secret_scan",
        "safe_failure_reason",
        "audit_store_version",
        "authorization_id",
        "dispatch_id",
        "dispatch_started_at",
        "request_commitment",
        "withheld_item_ids",
        "withheld_item_reason",
        "origin_operation",
    }


def test_local_receipt_has_all_shared_structural_evidence_and_no_attempt_count() -> None:
    receipt = _local_receipt()
    assert receipt.counts.request_body_bytes is None
    assert receipt.secret_scan.passed
    assert receipt.transformations.redacted_spans == 2


def test_attempt_identity_and_count_are_all_or_none() -> None:
    receipt = _network_receipt()
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        replace(receipt, dispatch_id=None)
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        replace(receipt, counts=replace(receipt.counts, request_body_bytes=None))
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        replace(_local_receipt(), counts=replace(_local_receipt().counts, request_body_bytes=1))


def test_authorized_predispatch_failure_may_have_authorization_without_attempt_fields() -> None:
    receipt = replace(
        _network_receipt(),
        outcome=PrivacyOutcome.APPROVAL_EXPIRED,
        safe_failure_reason=PrivacyReason.AUTHORIZATION_STALE,
        counts=replace(_network_receipt().counts, request_body_bytes=None),
        dispatch_id=None,
        dispatch_started_at=None,
        request_commitment=None,
    )
    assert receipt.authorization_id == _AUTHORIZATION_ID
    assert receipt.dispatch_id is None


def test_no_dispatch_forbidden_data_receipt_requires_none_consent_and_failed_scan() -> None:
    receipt = EgressReceipt(
        "1.0.0",
        _RECEIPT_ID,
        _REQUEST_ID,
        _PROPOSAL_ID,
        EgressChannel.CAPABILITY_TESTING,
        PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
        _FINISHED,
        _scope(),
        "capability-probe",
        NonLlmDestination(EgressChannel.CAPABILITY_TESTING, "probe", "1"),
        _policy(),
        ConsentSource.NONE,
        (),
        (DataCategory.DIAGNOSTIC_METADATA,),
        ReceiptCounts(1, 0, 1, 0, 1, 40, 0),
        ReceiptTransformations(0, 1, 1),
        _scan(passed=False),
        PrivacyReason.NEVER_SEND_DETECTED,
        1,
    )
    assert receipt.dispatch_id is None
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        replace(receipt, consent_source=ConsentSource.BASELINE_POLICY)


def test_counts_scan_and_destination_cross_field_invariants_fail_closed() -> None:
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        # Track the constant rather than a literal. The bound is the published receipt
        # vocabulary's, not the outbound document's: it once followed MAX_EGRESS_CASE_BYTES to
        # 512 KiB, which let the store keep receipts the wire refuses (issue #921).
        ReceiptCounts(2, 2, 1, 1, 1, 10, MAX_RECEIPT_FINAL_BYTES + 1)
    # #1118: a reviewer exchange on a sized route carries up to the outbound-document bound.
    assert ReceiptCounts(2, 2, 1, 1, 1, 10, MAX_RECEIPT_FINAL_BYTES).final_bytes == 524_288
    assert MAX_RECEIPT_FINAL_BYTES == MAX_EGRESS_CASE_BYTES
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        ReceiptSecretScan("1", _DIGEST, 1, 1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        replace(
            _network_receipt(),
            destination=NonLlmDestination(EgressChannel.UPDATE_CHECKS, "updates", "1"),
        )


def test_secret_scan_stage_distinguishes_real_scan_from_not_run() -> None:
    candidate = ReceiptSecretScan("1.0.0", _DIGEST, 1, False, ReceiptSecretScanStage.CANDIDATE)
    rendered = ReceiptSecretScan("1.0.0", _DIGEST, 0, True, ReceiptSecretScanStage.RENDERED_BODY)
    not_run = ReceiptSecretScan(
        "1.0.0",
        _DIGEST,
        0,
        False,
        ReceiptSecretScanStage.NOT_RUN,
        PrivacyReason.NEVER_SEND_DETECTED,
    )
    assert candidate.match_count == 1 and not candidate.passed
    assert rendered.match_count == 0 and rendered.passed
    assert not_run.not_run_reason is PrivacyReason.NEVER_SEND_DETECTED
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        ReceiptSecretScan("1.0.0", _DIGEST, 0, True, ReceiptSecretScanStage.NOT_RUN)


def test_receipts_reject_an_oversized_opaque_omission_set() -> None:
    too_many = tuple(f"item-{index:03d}" for index in range(MAX_WITHHELD_ITEM_IDS + 1))

    with pytest.raises(ValueError, match="invalid_privacy_value"):
        replace(
            _network_receipt(),
            schema_version="1.1.0",
            withheld_item_ids=too_many,
        )
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        replace(
            _local_receipt(),
            schema_version="1.1.0",
            withheld_item_ids=too_many,
        )


@pytest.mark.parametrize(
    ("match_count", "passed"),
    [(0, False), (0, True), (2, False)],
    ids=["legacy_blocked_zero", "legacy_clean_zero", "legacy_matches"],
)
def test_legacy_stage_less_scan_keeps_historical_unknown_state(
    match_count: int, passed: bool
) -> None:
    scan = ReceiptSecretScan(
        "1.0.0", _DIGEST, match_count, passed, ReceiptSecretScanStage.LEGACY_UNKNOWN
    )
    assert scan.stage is ReceiptSecretScanStage.LEGACY_UNKNOWN
