"""Real privacy receipts survive the control-result envelope (issue #732).

``local_disclosure_receipt.purpose`` referenced the privacy-policy purpose grammar, which is the
external-egress vocabulary and forbids underscores.  The product's own agent-projection purpose is
``client_result_projection``, so every ordinary local receipt failed ``_validated_wire`` and the
whole listing answered ``read_projection_failed`` -- exit 70 at the CLI.

These cases take receipts through the real application handlers and then through
``validate_result``, the exact boundary that refused them.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from tests.builders.privacy_receipts import (
    LOCAL_RECEIPT_ID,
    LOCAL_RECEIPT_PURPOSE,
    NETWORK_RECEIPT_ID,
    NOW,
    local_receipt_view,
    network_receipt_view,
)

from yoetz.application.privacy_control import build_privacy_support_handlers
from yoetz.domain.privacy import (
    _PURPOSE,  # pyright: ignore[reportPrivateUsage]
    MAX_RECEIPT_FINAL_BYTES,
    ReceiptSecretScanStage,
)
from yoetz.domain.values import JsonObject, freeze_json
from yoetz.ports.control import ControlError, ControlMethod, ControlResult
from yoetz.ports.privacy import (
    LocalDisclosureReceiptView,
    NetworkEgressReceiptView,
    PrivacyReceiptAudience,
    PrivacyReceiptPage,
    PrivacyReceiptQuery,
    PrivacyReceiptView,
)
from yoetz.protocol.errors import ProtocolValueError, PublicErrorCode
from yoetz.protocol.schemas import validate_schema_instance
from yoetz.service.client import (
    ListPrivacyReceiptsRequest,
    PrivacyReceiptFound,
    _receipt_get_from_wire,  # pyright: ignore[reportPrivateUsage]
    _receipt_page_from_wire,  # pyright: ignore[reportPrivateUsage]
    _receipt_view_from_wire,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.service.control_protocol import (
    decode_control_frame,
    encode_control_frame,
    parse_control_result,
    public_error_code_for_control_reason,
    validate_result,
)

pytestmark = pytest.mark.anyio

_RPC_ID = "rpc_00000000-0000-4000-8000-000000000001"
_INSTANCE_ID = "svc_00000000-0000-4000-8000-000000000002"
_CURSOR = "AAAA"
_SCHEMA_ROOT = Path(__file__).resolve().parents[3] / "schemas"


class _Audit:
    def __init__(
        self,
        *views: PrivacyReceiptView,
        next_cursor: str | None = None,
        undecodable: tuple[int, tuple[str, ...]] = (0, ()),
    ) -> None:
        self._views = views
        self._next_cursor = next_cursor
        self._undecodable = undecodable

    async def list_receipts(
        self, _query: PrivacyReceiptQuery, _audience: PrivacyReceiptAudience
    ) -> PrivacyReceiptPage:
        return PrivacyReceiptPage(11, self._views, self._next_cursor, *self._undecodable)

    async def get_receipt(
        self, receipt_id: str, _audience: PrivacyReceiptAudience
    ) -> PrivacyReceiptView | None:
        return next((view for view in self._views if view.receipt.receipt_id == receipt_id), None)


class _App:
    def __init__(self, audit: _Audit) -> None:
        self.audit = audit


def _handlers(
    *views: PrivacyReceiptView,
    next_cursor: str | None = None,
    undecodable: tuple[int, tuple[str, ...]] = (0, ()),
) -> dict[ControlMethod, Any]:
    app = _App(_Audit(*views, next_cursor=next_cursor, undecodable=undecodable))
    return dict(build_privacy_support_handlers(app))  # type: ignore[arg-type]


def _validated(method: ControlMethod, body: JsonObject) -> JsonObject:
    """The exact production check: the service validates the typed result before it is framed."""

    result = ControlResult(
        protocol_version="1.0",
        rpc_id=_RPC_ID,
        service_instance_id=_INSTANCE_ID,
        service_generation="1",
        method=method,
        outcome="ok",
        body=cast(JsonObject, freeze_json(body)),
    )
    validate_result(result)
    return cast(JsonObject, result.body)


async def _get(view: PrivacyReceiptView, receipt_id: str) -> JsonObject:
    handlers = _handlers(view)
    body = await handlers[ControlMethod.PRIVACY_RECEIPTS_GET](
        {"schema_version": "1.0.0", "receipt_id": receipt_id}
    )
    return _validated(ControlMethod.PRIVACY_RECEIPTS_GET, body)


async def _list(
    *views: PrivacyReceiptView,
    next_cursor: str | None = None,
    cursor: str | None = None,
    undecodable: tuple[int, tuple[str, ...]] = (0, ()),
) -> JsonObject:
    handlers = _handlers(*views, next_cursor=next_cursor, undecodable=undecodable)
    request = ListPrivacyReceiptsRequest(cursor=cursor)
    body = await handlers[ControlMethod.PRIVACY_RECEIPTS_LIST](
        dict(request._wire())  # pyright: ignore[reportPrivateUsage]
    )
    return _validated(ControlMethod.PRIVACY_RECEIPTS_LIST, body)


async def test_a_real_local_receipt_passes_the_control_result_envelope() -> None:
    body = await _get(local_receipt_view(), LOCAL_RECEIPT_ID)

    receipt = cast(dict[str, Any], dict(cast(Any, body["receipt"]))["receipt"])
    assert body["outcome"] == "found"
    assert receipt["purpose"] == LOCAL_RECEIPT_PURPOSE
    assert receipt["sink"] == "local_human_view"


async def test_a_real_network_receipt_still_passes_unchanged() -> None:
    body = await _get(network_receipt_view(), NETWORK_RECEIPT_ID)

    receipt = cast(dict[str, Any], dict(cast(Any, body["receipt"]))["receipt"])
    assert receipt["purpose"] == "semantic-review"
    assert receipt["channel"] == "llm_inference"


async def test_get_of_an_unknown_receipt_is_a_valid_not_found_result() -> None:
    handlers = _handlers(local_receipt_view())

    body = await handlers[ControlMethod.PRIVACY_RECEIPTS_GET](
        {"schema_version": "1.0.0", "receipt_id": NETWORK_RECEIPT_ID}
    )

    assert dict(_validated(ControlMethod.PRIVACY_RECEIPTS_GET, body)) == {
        "schema_version": "1.0.0",
        "outcome": "not_found",
    }


async def test_an_empty_page_passes_the_envelope() -> None:
    body = await _list()

    assert body["receipts"] == ()
    assert "next_cursor" not in body


@pytest.mark.parametrize(
    ("views", "kinds"),
    [
        ((local_receipt_view(),), ["local_disclosure"]),
        ((network_receipt_view(),), ["network_egress"]),
        (
            (network_receipt_view(), local_receipt_view()),
            ["network_egress", "local_disclosure"],
        ),
    ],
    ids=["local_only", "network_only", "mixed"],
)
async def test_every_page_composition_passes_the_envelope(
    views: tuple[PrivacyReceiptView, ...], kinds: list[str]
) -> None:
    body = await _list(*views)

    receipts = cast(tuple[Any, ...], body["receipts"])
    assert [dict(item)["kind"] for item in receipts] == kinds


async def test_a_paginated_local_page_carries_its_cursor_through_the_envelope() -> None:
    body = await _list(local_receipt_view(), next_cursor=_CURSOR, cursor=_CURSOR)

    assert body["next_cursor"] == _CURSOR
    assert len(cast(tuple[Any, ...], body["receipts"])) == 1


async def test_the_second_page_of_a_mixed_listing_also_validates() -> None:
    earlier = local_receipt_view(
        receipt_id="egr_70000000-0000-4000-8000-00000000000a",
        finished_at=NOW.replace(hour=11),
    )
    body = await _list(network_receipt_view(), local_receipt_view(), earlier)

    assert len(cast(tuple[Any, ...], body["receipts"])) == 3


def test_the_local_purpose_grammar_is_the_one_the_domain_produces() -> None:
    """Reconciliation, not a one-off widening: the wire mirrors its canonical owner."""

    document = json.loads(
        (_SCHEMA_ROOT / "service" / "control-result-2.7.0.schema.json").read_bytes()
    )
    definition = cast(dict[str, Any], document["$defs"]["local_disclosure_purpose"])

    assert definition["pattern"] == _PURPOSE.pattern
    assert re.compile(definition["pattern"]).fullmatch(LOCAL_RECEIPT_PURPOSE) is not None
    assert document["$defs"]["local_disclosure_receipt"]["properties"]["purpose"] == {
        "$ref": "#/$defs/local_disclosure_purpose"
    }


def test_external_egress_purposes_keep_the_stricter_released_vocabulary() -> None:
    """Bullet 1 of #732: widening the local wire must not relax network egress."""

    egress = json.loads(
        (_SCHEMA_ROOT / "privacy" / "egress-receipt-1.0.0.schema.json").read_bytes()
    )
    policy = json.loads(
        (_SCHEMA_ROOT / "privacy" / "privacy-policy-1.0.0.schema.json").read_bytes()
    )

    assert egress["properties"]["purpose"] == {
        "$ref": (
            "https://schemas.yoetz.dev/0.1/privacy/privacy-policy-1.0.0.schema.json#/$defs/purpose"
        )
    }
    assert policy["$defs"]["purpose"]["pattern"] == "^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$"
    assert (
        re.compile(policy["$defs"]["purpose"]["pattern"]).fullmatch("client_result_projection")
        is None
    )


def test_the_frozen_2_6_envelope_is_untouched() -> None:
    """2.6 is released bytes; only the active 2.7 contract moves."""

    document = json.loads(
        (_SCHEMA_ROOT / "service" / "control-result-2.6.0.schema.json").read_bytes()
    )

    assert "local_disclosure_purpose" not in document["$defs"]
    assert document["$defs"]["local_disclosure_receipt"]["properties"]["purpose"] == {
        "$ref": (
            "https://schemas.yoetz.dev/0.1/privacy/privacy-policy-1.0.0.schema.json#/$defs/purpose"
        )
    }


@pytest.mark.parametrize(
    "purpose",
    ["Client_Result", "", "1projection", "a" * 129, "client result projection"],
    ids=["uppercase", "empty", "leading_digit", "too_long", "space"],
)
def test_the_wire_still_refuses_purposes_the_domain_refuses(purpose: str) -> None:
    receipt = dict(
        cast(
            dict[str, Any],
            json.loads(
                json.dumps(
                    _plain(local_receipt_view()),
                )
            ),
        )
    )
    receipt["receipt"]["purpose"] = purpose

    with pytest.raises(ProtocolValueError):
        validate_schema_instance(
            "control-result",
            "2.7.0",
            {
                "protocol_version": "1.0",
                "rpc_id": _RPC_ID,
                "service_instance_id": _INSTANCE_ID,
                "service_generation": "1",
                "method": "privacy_receipts_get",
                "outcome": "ok",
                "body": {"schema_version": "1.0.0", "outcome": "found", "receipt": receipt},
            },
        )


def _plain(view: PrivacyReceiptView) -> dict[str, Any]:
    from yoetz.application.privacy_control import encode_privacy_receipt_view
    from yoetz.protocol.canonical import canonical_encode, strict_json_parse

    return cast(
        dict[str, Any], strict_json_parse(canonical_encode(encode_privacy_receipt_view(view)))
    )


def test_released_v1_receipt_view_omits_additive_scan_and_withheld_fields() -> None:
    wire = _plain(network_receipt_view())
    receipt = cast(dict[str, Any], wire["receipt"])
    scan = cast(dict[str, Any], receipt["secret_scan"])

    assert "stage" not in scan
    assert "not_run_reason" not in scan
    assert "withheld_item_ids" not in receipt
    assert "withheld_item_reason" not in receipt
    validate_schema_instance("egress-receipt", "1.0.0", receipt)


@pytest.mark.parametrize(
    ("match_count", "passed"),
    [(0, True), (0, False), (2, False)],
    ids=["legacy_clean", "legacy_blocked_zero", "legacy_matches"],
)
def test_stage_less_receipts_preserve_legacy_scan_uncertainty(
    match_count: int, passed: bool
) -> None:
    wire = _plain(network_receipt_view())
    receipt = cast(dict[str, Any], wire["receipt"])
    scan = cast(dict[str, Any], receipt["secret_scan"])
    scan.pop("stage", None)
    scan["match_count"] = str(match_count)
    scan["passed"] = passed

    decoded = _receipt_view_from_wire(cast(JsonObject, freeze_json(cast(Any, wire))))
    assert decoded.receipt.secret_scan.stage is ReceiptSecretScanStage.LEGACY_UNKNOWN
    assert decoded.receipt.secret_scan.match_count == match_count
    assert decoded.receipt.secret_scan.passed is passed


def _at_final_bytes(view: PrivacyReceiptView, final_bytes: int) -> PrivacyReceiptView:
    receipt = view.receipt
    counts = replace(receipt.counts, final_bytes=final_bytes)
    if isinstance(view, NetworkEgressReceiptView):
        return NetworkEgressReceiptView("network_egress", replace(view.receipt, counts=counts))
    assert isinstance(view, LocalDisclosureReceiptView)
    return LocalDisclosureReceiptView("local_disclosure", replace(view.receipt, counts=counts))


def test_the_domain_final_bytes_bound_is_the_published_wire_bound() -> None:
    """Issue #921: the domain admitted 512 KiB while the wire stops at 262,144."""

    outbound = json.loads(
        (_SCHEMA_ROOT / "privacy" / "outbound-case-1.0.0.schema.json").read_bytes()
    )
    egress = json.loads(
        (_SCHEMA_ROOT / "privacy" / "egress-receipt-1.0.0.schema.json").read_bytes()
    )
    wire = re.compile(outbound["$defs"]["max_262144_decimal"]["pattern"])

    assert egress["$defs"]["counts"]["properties"]["final_bytes"] == {
        "$ref": "#/$defs/max_262144_decimal"
    }
    assert wire.fullmatch(str(MAX_RECEIPT_FINAL_BYTES)) is not None
    assert wire.fullmatch(str(MAX_RECEIPT_FINAL_BYTES + 1)) is None
    with pytest.raises(ValueError, match="invalid_privacy_value"):
        replace(local_receipt_view().receipt.counts, final_bytes=MAX_RECEIPT_FINAL_BYTES + 1)


@pytest.mark.parametrize(
    "view",
    [local_receipt_view(), network_receipt_view()],
    ids=["local", "network"],
)
async def test_a_receipt_at_the_final_bytes_maximum_round_trips(view: PrivacyReceiptView) -> None:
    maximal = _at_final_bytes(view, MAX_RECEIPT_FINAL_BYTES)

    fetched = await _get(maximal, maximal.receipt.receipt_id)
    listed = await _list(maximal)

    found = _receipt_get_from_wire(fetched)
    assert isinstance(found, PrivacyReceiptFound)
    # The released v1.0 shape has no stage field. Its reader therefore preserves the historical
    # uncertainty marker rather than manufacturing PREPARED_CASE on the way back.
    expected_scan = replace(
        maximal.receipt.secret_scan, stage=ReceiptSecretScanStage.LEGACY_UNKNOWN
    )
    if isinstance(maximal, NetworkEgressReceiptView):
        expected: PrivacyReceiptView = NetworkEgressReceiptView(
            "network_egress", replace(maximal.receipt, secret_scan=expected_scan)
        )
    else:
        expected = LocalDisclosureReceiptView(
            "local_disclosure", replace(maximal.receipt, secret_scan=expected_scan)
        )
    assert found.receipt == expected
    assert _receipt_page_from_wire(listed).receipts == (expected,)


async def test_a_partial_page_passes_the_envelope_with_its_count_and_ids() -> None:
    skipped = "egr_70000000-0000-4000-8000-00000000000b"

    body = await _list(network_receipt_view(), local_receipt_view(), undecodable=(2, (skipped,)))

    assert body["undecodable_count"] == "2"
    assert body["undecodable_receipt_ids"] == (skipped,)
    page = _receipt_page_from_wire(body)
    assert (page.undecodable_count, page.undecodable_receipt_ids) == (2, (skipped,))


@pytest.mark.parametrize(
    "extra",
    [
        {"undecodable_count": "1"},
        {"undecodable_receipt_ids": []},
        {"undecodable_count": "0", "undecodable_receipt_ids": []},
        {"undecodable_count": "101", "undecodable_receipt_ids": []},
        {
            "undecodable_count": "1",
            "undecodable_receipt_ids": ["req_70000000-0000-4000-8000-00000000000b"],
        },
    ],
    ids=["count_alone", "ids_alone", "zero_count", "over_page", "not_a_receipt_id"],
)
def test_the_partial_page_fields_are_closed(extra: dict[str, Any]) -> None:
    with pytest.raises(ProtocolValueError):
        validate_schema_instance(
            "control-result",
            "2.9.0",
            {
                "protocol_version": "1.0",
                "rpc_id": _RPC_ID,
                "service_instance_id": _INSTANCE_ID,
                "service_generation": "1",
                "method": "privacy_receipts_list",
                "outcome": "ok",
                "body": {
                    "schema_version": "1.0.0",
                    "snapshot_generation": "3",
                    "receipts": [],
                    **extra,
                },
            },
        )


def test_the_store_side_reason_is_a_closed_non_retryable_wire_code() -> None:
    correlation_id = "err_70000000-0000-4000-8000-00000000000c"
    result = ControlResult(
        protocol_version="1.0",
        rpc_id=_RPC_ID,
        service_instance_id=_INSTANCE_ID,
        service_generation="1",
        method=ControlMethod.PRIVACY_RECEIPTS_LIST,
        outcome="error",
        body=ControlError("privacy_audit_unreadable", correlation_id=correlation_id),
    )

    parsed = parse_control_result(decode_control_frame(encode_control_frame(result)))

    assert isinstance(parsed.body, ControlError)
    assert parsed.body.reason == "privacy_audit_unreadable"
    assert parsed.body.retryable is False
    assert parsed.body.correlation_id == correlation_id
    assert public_error_code_for_control_reason("privacy_audit_unreadable") is (
        PublicErrorCode.STORAGE_CORRUPT
    )
    with pytest.raises(ValueError, match="privacy_audit_unreadable_must_not_be_retryable"):
        ControlError("privacy_audit_unreadable", retryable=True)
