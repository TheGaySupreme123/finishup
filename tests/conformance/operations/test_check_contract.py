from __future__ import annotations

from dataclasses import fields

import pytest

from builders.policy_cases import clm, make_case, record
from yoetz.application.check import CheckScope, run_deterministic_policies
from yoetz.domain.events import ClaimKind, ClaimRecordedPayload
from yoetz.ports.ledger import CheckCommitResult
from yoetz.protocol.models import (
    VALID_SEMANTIC_REASONS,
    SemanticReason,
    SemanticStatus,
    validate_semantic_outcome,
)


def test_policy_execution_accounting_is_stable_and_application_owned() -> None:
    claim = ClaimRecordedPayload(clm(1), ClaimKind.MATERIAL, "Unsupported", ())
    case = make_case(claims={clm(1): record(claim, 1)})

    left = run_deterministic_policies(
        case,
        CheckScope((), ()),
        ("research-evidence/0.2.0", "work-integrity/0.3.0"),
    )
    right = run_deterministic_policies(
        case,
        CheckScope((), ()),
        ("research-evidence/0.2.0", "work-integrity/0.3.0"),
    )

    assert left == right
    assert tuple(item.policy_id for item in left[1]) == (
        "research-evidence",
        "work-integrity",
    )


def test_semantic_status_reason_matrix_is_closed() -> None:
    for status, reasons in VALID_SEMANTIC_REASONS.items():
        for reason in reasons:
            validate_semantic_outcome(status, reason)

    with pytest.raises(ValueError):
        validate_semantic_outcome(
            SemanticStatus.NOT_REQUESTED,
            SemanticReason.PROVIDER_TIMEOUT,
        )


def test_persisted_check_result_is_sink_independent() -> None:
    names = {field.name for field in fields(CheckCommitResult)}

    assert not names & {
        "client_kind",
        "local_disclosure_receipt_id",
        "privacy_projection",
        "render_mode",
        "sink",
    }
