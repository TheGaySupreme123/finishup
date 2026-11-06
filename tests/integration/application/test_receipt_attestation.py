"""A receipt's workspace-provenance read happens before it writes, and never drops its block.

ADR-051: a claim-bound task's text and markdown receipts end with the client-attested block,
decided from the session's opening event. These drive the real ``Application`` facade over the
memory and SQLite ledgers of the respond/status/receipt harness.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import replace
from typing import Any, Literal, cast

import pytest

from finishup.domain.events import LedgerRecord
from finishup.domain.receipts import workspace_provenance_unknown_block
from finishup.ports.objects import ObjectKind
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import ReceiptRequest
from integration.application.test_respond_status_receipt import (  # pyright: ignore[reportPrivateUsage]
    _bootstrap_finding,  # pyright: ignore[reportPrivateUsage]
    _build_app,  # pyright: ignore[reportPrivateUsage]
    _receipt_wire,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio


class _UnreadOpening:
    """A task ledger whose session opening event comes back without its payload while ``unread``.

    That is the record a recovering SQLite ledger keeps when it cannot read a payload object it
    holds (finding A6): the envelope still says ``present`` and the payload is None. Every other
    read is the real ledger's.
    """

    def __init__(self, ledger: Any) -> None:  # noqa: ANN401
        self._ledger = ledger
        self.unread = True

    def __getattr__(self, name: str) -> Any:  # noqa: ANN401
        return getattr(self._ledger, name)

    async def _events(self, session_id: str, **kwargs: Any) -> AsyncIterator[LedgerRecord]:  # noqa: ANN401
        async for record in self._ledger.load_events(session_id, **kwargs):
            if self.unread and record.schema.name == "session_opened":
                yield replace(record, payload=None)
            else:
                yield record

    def load_events(self, session_id: str, **kwargs: Any) -> AsyncIterator[LedgerRecord]:  # noqa: ANN401
        return self._events(session_id, **kwargs)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
async def test_an_unread_opening_event_refuses_the_receipt_before_any_write(
    backend: Literal["memory", "sqlite"],
) -> None:
    """The read comes before staging and append, so a refusal leaves nothing recorded."""

    app, runtime, _ = _build_app(seed_offset=47, ledger_backend=backend)
    started, checked, _obligation = await _bootstrap_finding(app, seed=5400)
    ledger, objects = runtime.resources[started.task_id]
    unread = _UnreadOpening(ledger)
    runtime.resources[started.task_id] = (cast(Any, unread), objects)
    receipts_before = objects.refs_for_kind(ObjectKind.RECEIPT)
    payloads_before = objects.refs_for_kind(ObjectKind.EVENT_PAYLOAD)
    head_before = await ledger.load_frontier()
    wire = _receipt_wire(
        5410,
        task_id=started.task_id,
        session=started.session_id,
        writer=started.writer_id,
        frontier=checked.result_frontier,
    )
    request = ReceiptRequest.model_validate({**wire, "format": "text"})

    with pytest.raises(PublicOperationError) as refused:
        await app.receipt(request)
    assert refused.value.code is PublicErrorCode.STORAGE_UNSAFE
    assert refused.value.retryable is True
    assert objects.refs_for_kind(ObjectKind.RECEIPT) == receipts_before
    assert objects.refs_for_kind(ObjectKind.EVENT_PAYLOAD) == payloads_before
    assert await ledger.load_frontier() == head_before
    assert await ledger.lookup_operation(started.writer_id, request.request_id) is None

    # Once the event reads again, the same request records the receipt.
    unread.unread = False
    recorded = await app.receipt(request)
    assert len(objects.refs_for_kind(ObjectKind.RECEIPT)) == len(receipts_before) + 1
    assert recorded.human_text is not None
    assert "Workspace evidence" not in recorded.human_text

    # Its replay reads the event too, and refuses the same way rather than drop the block.
    unread.unread = True
    with pytest.raises(PublicOperationError) as replay_refused:
        await app.receipt(request)
    assert replay_refused.value.code is PublicErrorCode.STORAGE_UNSAFE
    assert replay_refused.value.retryable is True
    unread.unread = False
    replayed = await app.receipt(request)
    assert replayed.receipt_id == recorded.receipt_id
    assert replayed.human_text == recorded.human_text


@pytest.mark.parametrize("receipt_format", ["text", "markdown", "json"])
async def test_an_unknown_binding_ends_a_human_receipt_with_the_fixed_unknown_block(
    receipt_format: Literal["text", "markdown", "json"], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A redacted or unreadable-by-key opening event never leaves the section out silently."""

    from finishup.application import receipt as receipt_module

    unknown = getattr(receipt_module, "_Provenance").UNKNOWN

    async def opening_cannot_say(runtime: object, *, request_id: str | None = None) -> object:
        del runtime, request_id
        return unknown

    monkeypatch.setattr(receipt_module, "_attested_by", opening_cannot_say)
    app, _runtime, _ = _build_app(seed_offset=48)
    started, checked, _obligation = await _bootstrap_finding(app, seed=5500)
    wire = _receipt_wire(
        5510,
        task_id=started.task_id,
        session=started.session_id,
        writer=started.writer_id,
        frontier=checked.result_frontier,
    )
    result = await app.receipt(ReceiptRequest.model_validate({**wire, "format": receipt_format}))
    if receipt_format == "json":
        assert result.human_text is None
        return
    assert result.human_text is not None
    block = workspace_provenance_unknown_block(markdown=receipt_format == "markdown")
    assert result.human_text.endswith("\n\n" + block)
    assert result.human_text.count("Workspace evidence") == 1
