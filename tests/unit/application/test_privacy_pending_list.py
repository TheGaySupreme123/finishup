"""Listing pending disclosures names the ceremony to run and nothing it would disclose."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from finishup.application.privacy_control import build_privacy_support_handlers
from finishup.ports.control import ControlMethod
from finishup.ports.privacy import (
    PendingDisclosureEntry,
    PendingDisclosurePage,
    PrivacyReceiptAudience,
)

pytestmark = pytest.mark.anyio

_NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


class _Audit:
    def __init__(self, page: PendingDisclosurePage) -> None:
        self.page = page
        self.audiences: list[PrivacyReceiptAudience] = []

    async def list_pending_disclosures(
        self, audience: PrivacyReceiptAudience
    ) -> PendingDisclosurePage:
        self.audiences.append(audience)
        return self.page


class _App:
    def __init__(self, audit: _Audit) -> None:
        self.audit = audit


def _page(*entries: PendingDisclosureEntry) -> PendingDisclosurePage:
    return PendingDisclosurePage(7, entries)


def _handler(page: PendingDisclosurePage) -> tuple[object, _Audit]:
    audit = _Audit(page)
    handlers = build_privacy_support_handlers(_App(audit))  # type: ignore[arg-type]
    return handlers[ControlMethod.PRIVACY_PENDING_LIST], audit


async def test_a_waiting_proposal_is_named_with_its_expiry() -> None:
    entry = PendingDisclosureEntry("pvp_1", "tsk_1", _NOW + timedelta(minutes=5))
    handler, audit = _handler(_page(entry))

    body = await handler({})  # type: ignore[operator]

    assert body["schema"] == "yoetz.privacy-pending-page/1"
    assert body["snapshot_generation"] == 7
    # Canonical JSON freezes arrays to tuples; the wire form is still a JSON array.
    assert body["pending"] == (
        {
            "pending_id": "pvp_1",
            "task_id": "tsk_1",
            "expires_at": "2026-08-05T12:05:00.000Z",
        },
    )
    assert audit.audiences == [PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL]


async def test_the_listing_carries_no_proposal_content() -> None:
    """Finding the ceremony must not become a way to read what it would disclose.

    The decision preview is bound to the exact prepared case and is the only surface that
    renders destination, categories, or excerpt bytes. A listing that carried any of them would
    be a second, unbound disclosure surface reachable without the ceremony.
    """

    entry = PendingDisclosureEntry("pvp_1", "tsk_1", _NOW + timedelta(minutes=5))
    handler, _ = _handler(_page(entry))

    body = cast("Mapping[str, Any]", await handler({}))  # type: ignore[operator]

    first = cast("Mapping[str, Any]", cast("Sequence[Any]", body["pending"])[0])
    assert set(first) == {"pending_id", "task_id", "expires_at"}
    forbidden = ("provider", "model", "endpoint", "excerpt", "categor", "digest", "sink", "bytes")
    rendered = repr(dict(body)).lower()
    assert not any(token in rendered for token in forbidden)


async def test_no_waiting_proposal_is_an_empty_list_not_an_error() -> None:
    handler, _ = _handler(_page())

    body = await handler({})  # type: ignore[operator]

    assert body["pending"] == ()


async def test_a_proposal_without_a_task_is_still_listed() -> None:
    """A null task must not hide a decision a human can still make."""

    entry = PendingDisclosureEntry("pvp_1", None, _NOW + timedelta(minutes=5))
    handler, _ = _handler(_page(entry))

    body = await handler({})  # type: ignore[operator]

    assert body["pending"][0]["task_id"] is None


async def test_an_unexpected_request_body_is_ignored_rather_than_rejected() -> None:
    """The call takes no parameters, so nothing in a body could change the answer."""

    entry = PendingDisclosureEntry("pvp_1", "tsk_1", _NOW + timedelta(minutes=5))
    handler, _ = _handler(_page(entry))

    body = cast("Mapping[str, Any]", await handler({"unexpected": "value"}))  # type: ignore[operator]

    assert len(cast("Sequence[Any]", body["pending"])) == 1
