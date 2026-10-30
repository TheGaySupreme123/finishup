"""#1129/#1142: a size refusal carries a typed capacity reason on the receipt, check and job side.

Before this, the check reported ``failed/case_capacity_exceeded`` while the privacy receipt only
said ``blocked_by_policy`` / ``policy_denied``, which reads as a policy rule. The receipt now names
the bound it exceeded, in integers only, and no refusal maps to ``network_egress_denied`` unless a
policy actually denied network egress.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Literal, cast

import pytest

import finishup.service.ready_composition as composition
from finishup.adapters.privacy.catalog import (
    _network_receipt_from_bytes,  # pyright: ignore[reportPrivateUsage]
    _receipt_bytes,  # pyright: ignore[reportPrivateUsage]
)
from finishup.application.egress import SemanticEgressBlocked
from finishup.application.privacy_control import encode_privacy_receipt_view
from finishup.cli.app import _receipt_refusal_lines  # pyright: ignore[reportPrivateUsage]
from finishup.domain.privacy import (
    EgressOriginOperation,
    EgressReceipt,
    PrivacyOutcome,
    PrivacyReason,
    ReceiptCapacity,
    ReceiptSecretScan,
    ReceiptSecretScanStage,
    ReviewContextProfile,
)
from finishup.domain.values import JsonObject, freeze_json
from finishup.ports.privacy import NetworkEgressReceiptView
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import SemanticReason, SemanticStatus
from finishup.protocol.schemas import validate_schema_instance
from finishup.service.client import (
    PrivacyReceiptFound,
    _receipt_get_from_wire,  # pyright: ignore[reportPrivateUsage]
)
from unit.application.test_egress_origin_operation import (
    _receipt,  # pyright: ignore[reportPrivateUsage]
    _Store,  # pyright: ignore[reportPrivateUsage]
)
from unit.privacy.test_planted_credentials_semantic_arm import (
    _candidate,  # pyright: ignore[reportPrivateUsage]
    _minimize_everything,  # pyright: ignore[reportPrivateUsage]
    _semantic_case,  # pyright: ignore[reportPrivateUsage]
)
from unit.privacy.test_review_privacy_labels import (
    _DIFF,  # pyright: ignore[reportPrivateUsage]
    _evaluate,  # pyright: ignore[reportPrivateUsage]
)

_ATTEMPT = "sma_00000000-0000-4000-8000-000000000001"


def _capacity_receipt(capacity: ReceiptCapacity | None) -> EgressReceipt:
    return replace(
        _receipt(EgressOriginOperation.SEMANTIC_CHECK),
        safe_failure_reason=PrivacyReason.POLICY_DENIED,
        capacity_exceeded=capacity,
    )


@pytest.mark.anyio
@pytest.mark.parametrize("bound", ("excerpt", "excerpt_total"))
async def test_a_size_refusal_receipt_names_its_bound_and_the_check_its_capacity(
    bound: Literal["excerpt", "excerpt_total"],
) -> None:
    case = _semantic_case(_DIFF, with_aws_key=False)
    selected = sum(item.content_bytes for item in case.items if item.section == "excerpt")
    packet = json.loads(_minimize_everything(_candidate(case)).prepared_bytes)
    (row,) = [item for item in packet["items"] if item["section"] == "excerpt"]
    transformed = cast(int, row["content_bytes"])
    policy = _Store()._policy  # pyright: ignore[reportPrivateUsage]
    selection = replace(
        policy.review_selection,
        max_excerpt_bytes=selected if bound == "excerpt" else 16_384,
        max_total_excerpt_bytes=selected if bound == "excerpt_total" else 131_072,
    )
    policy = replace(
        policy, review_context_profile=ReviewContextProfile.CUSTOM, review_selection=selection
    )
    result, audit = await _evaluate(policy=policy)
    assert isinstance(result, SemanticEgressBlocked)
    (receipt,) = audit.receipts
    # The durable outcome and reason are unchanged; the typed capacity reason says it was size.
    assert (receipt.outcome, receipt.safe_failure_reason) == (
        PrivacyOutcome.BLOCKED_BY_POLICY,
        PrivacyReason.POLICY_DENIED,
    )
    assert receipt.capacity_exceeded == ReceiptCapacity(bound, "bytes", transformed, selected)
    assert receipt.counts.final_bytes == 0
    # Check and job side: the same refusal is ``failed/case_capacity_exceeded``, never network.
    final = composition._map_egress_to_final(  # pyright: ignore[reportPrivateUsage]
        result, attempt_id=_ATTEMPT
    )
    assert (final.status, final.reason) == (
        SemanticStatus.FAILED,
        SemanticReason.CASE_CAPACITY_EXCEEDED,
    )


@pytest.mark.anyio
async def test_a_receipt_that_was_not_a_size_refusal_carries_no_capacity() -> None:
    result, audit = await _evaluate(secret_in_frame=True)
    assert isinstance(result, SemanticEgressBlocked)
    (receipt,) = audit.receipts
    assert receipt.capacity_exceeded is None
    assert b"capacity_exceeded" not in _receipt_bytes(receipt)


def test_the_capacity_reason_round_trips_storage_wire_and_schema() -> None:
    capacity = ReceiptCapacity("excerpt_total", "bytes", 131_074, 131_072)
    receipt = _capacity_receipt(capacity)
    stored = _receipt_bytes(receipt)
    assert b'"capacity_exceeded":{"attempted":131074,"limit":131072' in stored
    assert _network_receipt_from_bytes(stored) == receipt

    view = NetworkEgressReceiptView("network_egress", receipt)
    wire = encode_privacy_receipt_view(view)
    body = cast(dict[str, JsonValue], wire["receipt"])
    assert body["capacity_exceeded"] == {
        "scope": "excerpt_total",
        "unit": "bytes",
        "attempted": "131074",
        "limit": "131072",
    }
    validate_schema_instance("egress-receipt", "1.1.0", cast(JsonValue, body))
    decoded = _receipt_get_from_wire(
        cast(
            JsonObject,
            freeze_json({"schema_version": "1.0.0", "outcome": "found", "receipt": wire}),
        )
    )
    assert isinstance(decoded, PrivacyReceiptFound)
    assert decoded.receipt == view
    # The owner's CLI view says it was size, in closed values and integers only.
    (line,) = _receipt_refusal_lines((view,))
    assert line.startswith("capacity_exceeded: privacy receipt egr_")
    assert "131074 bytes against the excerpt_total limit of 131072; nothing was sent" in line


def test_the_schema_refuses_a_capacity_reason_on_any_other_refusal() -> None:
    receipt = _capacity_receipt(ReceiptCapacity("disclosure", "tokens", 70_000, 65_536))
    view = NetworkEgressReceiptView("network_egress", receipt)
    body = dict(cast(dict[str, JsonValue], encode_privacy_receipt_view(view)["receipt"]))
    validate_schema_instance("egress-receipt", "1.1.0", cast(JsonValue, body))
    body["safe_failure_reason"] = "scope_mismatch"
    with pytest.raises(Exception):  # noqa: B017 - the protocol validation error type
        validate_schema_instance("egress-receipt", "1.1.0", cast(JsonValue, body))
    body["safe_failure_reason"] = "policy_denied"
    # The 1.1.0 document also admits 1.0.0 receipts; a 1.0.0 receipt never carries the reason.
    body["schema_version"] = "1.0.0"
    with pytest.raises(Exception):  # noqa: B017 - the protocol validation error type
        validate_schema_instance("egress-receipt", "1.1.0", cast(JsonValue, body))
    body["schema_version"] = "1.1.0"
    body["capacity_exceeded"] = {
        "scope": "excerpt_total",
        "unit": "tokens",
        "attempted": "2",
        "limit": "1",
    }
    with pytest.raises(Exception):  # noqa: B017 - the protocol validation error type
        validate_schema_instance("egress-receipt", "1.1.0", cast(JsonValue, body))


def test_the_domain_refuses_a_capacity_reason_off_a_policy_denied_size_refusal() -> None:
    capacity = ReceiptCapacity("disclosure", "bytes", 2, 1)
    base = _receipt(EgressOriginOperation.SEMANTIC_CHECK)
    with pytest.raises(ValueError):
        replace(base, capacity_exceeded=capacity)  # insufficient_approved_context
    with pytest.raises(ValueError):
        replace(
            base,
            schema_version="1.0.0",
            origin_operation=None,
            safe_failure_reason=PrivacyReason.POLICY_DENIED,
            secret_scan=ReceiptSecretScan(
                "scanner-v3",
                base.secret_scan.scanner_profile_digest,
                0,
                True,
                ReceiptSecretScanStage.LEGACY_UNKNOWN,
            ),
            capacity_exceeded=capacity,
        )
    for scope, unit, attempted, limit in (
        ("excerpt_total", "excerpts", 2, 1),
        ("disclosure", "bytes", 1, 1),
    ):
        with pytest.raises(ValueError):
            ReceiptCapacity(scope, unit, attempted, limit)  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize("reason", tuple(PrivacyReason))
def test_no_refusal_reads_as_network_denial_unless_a_policy_denied_it(
    reason: PrivacyReason,
) -> None:
    """#1142: the old last arm mapped every unrecognised policy refusal to network denial."""

    final = composition._map_blocked(  # pyright: ignore[reportPrivateUsage]
        PrivacyOutcome.BLOCKED_BY_POLICY, reason
    )
    if final.reason is SemanticReason.NETWORK_EGRESS_DENIED:
        assert reason is PrivacyReason.POLICY_DENIED
    sized = composition._map_egress_to_final(  # pyright: ignore[reportPrivateUsage]
        SemanticEgressBlocked(
            "req_40000000-0000-4000-8000-000000000001",
            PrivacyOutcome.BLOCKED_BY_POLICY,
            PrivacyReason.POLICY_DENIED,
            capacity=(2, 1),
        ),
        attempt_id=_ATTEMPT,
    )
    assert (sized.status, sized.reason) == (
        SemanticStatus.FAILED,
        SemanticReason.CASE_CAPACITY_EXCEEDED,
    )


def test_the_capacity_reason_schema_is_published_on_the_active_receipt() -> None:
    from importlib.resources import files

    document = json.loads(
        files("finishup.resources")
        .joinpath("schemas/privacy/egress-receipt-1.1.0.schema.json")
        .read_bytes()
    )
    assert document["properties"]["capacity_exceeded"] == {"$ref": "#/$defs/capacity_exceeded"}
    legacy = json.loads(
        files("finishup.resources")
        .joinpath("schemas/privacy/egress-receipt-1.0.0.schema.json")
        .read_bytes()
    )
    assert "capacity_exceeded" not in legacy["properties"]
