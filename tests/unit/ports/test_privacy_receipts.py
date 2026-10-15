from __future__ import annotations

from dataclasses import replace

import pytest

from finishup.domain.privacy import EgressReceipt, LocalDisclosureReceipt
from finishup.ports.privacy import (
    LocalDisclosureReceiptView,
    NetworkEgressReceiptView,
    PrivacyReceiptPage,
)


def test_receipt_page_is_positive_generation_and_accepts_only_tagged_views() -> None:
    # Wrapper receipt payload validation is independently owned by domain tests; construction with
    # the wrong payload must fail before a page can expose an untagged receipt.
    with pytest.raises(ValueError, match="invalid_privacy_port_value"):
        NetworkEgressReceiptView("network_egress", object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="invalid_privacy_port_value"):
        LocalDisclosureReceiptView("local_disclosure", object())  # type: ignore[arg-type]
    network = NetworkEgressReceiptView("network_egress", object.__new__(EgressReceipt))
    local = LocalDisclosureReceiptView("local_disclosure", object.__new__(LocalDisclosureReceipt))
    assert network.kind == "network_egress"
    assert local.kind == "local_disclosure"
    assert PrivacyReceiptPage(1, (), None).snapshot_generation == 1
    with pytest.raises(ValueError, match="invalid_privacy_port_value"):
        PrivacyReceiptPage(0, (), None)


def test_wrapper_tags_are_closed() -> None:
    with pytest.raises(ValueError, match="invalid_privacy_port_value"):
        NetworkEgressReceiptView("local_disclosure", object())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="invalid_privacy_port_value"):
        LocalDisclosureReceiptView("network_egress", object())  # type: ignore[arg-type]


def test_page_rejects_raw_or_duplicate_shape_without_wrapper() -> None:
    page = PrivacyReceiptPage(2, (), "YWJjZA")
    assert replace(page, next_cursor=None).receipts == ()
    with pytest.raises(ValueError, match="invalid_privacy_port_value"):
        PrivacyReceiptPage(2, (object(),), None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="invalid_privacy_port_value"):
        PrivacyReceiptPage(2, (), "not+base64")
